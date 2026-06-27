#!/usr/bin/env python3
"""
Fast screening/formal sweep script for bit-208 fault-model selectivity.

Goal:
    Find a glitch setting that still produces single-bit208 message faults,
    but where those faults correlate with the reconstructed decoder residual sign.

For m_bit = 1, the desired skip-(+q/2) model predicts:
    residual = center(v_i - A_i@s - 1665)
    effective fault should mostly occur when residual < 0.

So we score each parameter by:
    single_bit208_mbit1_count
    residual_negative_rate among those samples
    score = count * max(0, residual_negative_rate - 0.5)

This version also supports fast screening of crash-heavy regions:
    --adc-timeout defaults to 0.2 s
    --fast-rekey-on-crash avoids full R/Z/decode after every crash
    --early-abort-crashy-points skips obviously crash-only points

This script requires debug firmware commands:
    M: return decoded message m_dec
    Z: dump IND-CPA secret key raw bytes
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import chipwhisperer as cw

from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, HS2_GLITCH, DEFAULT_BAUD

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common_cw import flush_target  # noqa: E402
from common_ss2 import validate_response  # noqa: E402
from kyber_target import KyberTarget  # noqa: E402

from collect_host_faults import (  # noqa: E402
    build_host_helper,
    host_encapsulate,
    connect_scope_and_target,
    safe_recover,
    configure_glitch,
    set_prep_mode,
    set_attack_mode,
    ping_alive,
    upload_ct,
    disconnect,
)

from reconstruct_bit208_intermediates import (  # noqa: E402
    build_intermediate_helper,
    output_fieldnames,
    parse_helper_output_line,
)


KYBER_Q = 3329
KYBER_N = 256
KYBER_K = 2
SECRET_DIM = 512

M_LEN = 32
PK_LEN = 800
INDCPA_SK_LEN = 768
SK_CHUNK = 128
PK_CHUNK = 200

MONT_INV = 169
MU_ONE = 1665


def log_debug(args: argparse.Namespace, *items: Any) -> None:
    """Print debug messages only when --debug is enabled."""
    if getattr(args, "debug", False):
        print(*items)


def progress_bar_line(
    *,
    point_id: int,
    total_points: int,
    point_trial: int,
    trials_per_point: int,
    width: float,
    offset: float,
    repeat: int,
    ext_offset: int,
    counts: Counter[str],
    single_bit_target: int,
    single_bit_target_mbit: int,
    residual_negative: int,
    residual_positive_or_zero: int,
    m_bit_filter: int,
) -> str:
    """Return a compact one-line progress bar for the whole sweep.

    The main progress indicator is current point / total points, not merely
    current trial / trials within a single point.  The bar advances smoothly
    within a point using point_trial/trials_per_point, while the label still
    shows the current point index.
    """
    bar_len = 28
    total_points = max(1, total_points)
    trials_per_point = max(1, trials_per_point)
    overall_done = (max(0, point_id - 1) + min(point_trial, trials_per_point) / trials_per_point) / total_points
    overall_done = max(0.0, min(1.0, overall_done))
    done = int(round(bar_len * overall_done))
    bar = "#" * done + "-" * (bar_len - done)
    pct = 100.0 * overall_done
    return (
        f"point={point_id}/{total_points} [{bar}] {pct:5.1f}% "
        f"trial={point_trial}/{trials_per_point} "
        f"w={width} off={offset} rep={repeat} ext={ext_offset} "
        f"wrong={counts['message_wrong']} "
        f"single208={single_bit_target} "
        f"single208_mbit{m_bit_filter}={single_bit_target_mbit} "
        f"neg={residual_negative} pos0={residual_positive_or_zero} "
        f"crash={counts['crash']} host_exc={counts['host_exception']}"
    )


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_hex(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def to_bytes(x: Any) -> bytes:
    """Best-effort conversion for ChipWhisperer response fields.

    Some CW versions return full_response/rv as str instead of bytes-like
    objects. Calling bytes(str_obj) without an encoding raises
    TypeError("string argument without an encoding"), which was previously
    misclassified as a target crash. Use latin-1 for one-to-one byte mapping
    when possible.
    """
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("latin-1", errors="replace")
    if isinstance(x, int):
        if 0 <= x <= 255:
            return bytes([x])
        return str(x).encode("ascii", errors="replace")
    try:
        return bytes(x)
    except Exception:
        return str(x).encode("utf-8", errors="replace")


def center_mod_q_scalar(x: int) -> int:
    y = x % KYBER_Q
    if y > KYBER_Q // 2:
        y -= KYBER_Q
    return int(y)


def parse_float_list(s: str) -> list[float]:
    return [float(x.strip()) for x in s.split(",") if x.strip()]


def parse_int_list(s: str) -> list[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]

def safe_getattr(obj: Any, name: str, default: Any = "") -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return default


def get_glitch_state(scope: Any) -> dict[str, Any]:
    """Return the actual CW glitch/routing state for logging/debugging."""
    g = safe_getattr(scope, "glitch", None)
    io = safe_getattr(scope, "io", None)

    if g is None:
        return {
            "actual_hs2": safe_getattr(io, "hs2", ""),
            "actual_glitch_width": "",
            "actual_glitch_offset": "",
            "actual_glitch_ext_offset": "",
            "actual_glitch_repeat": "",
            "actual_glitch_output": "",
            "actual_glitch_clk_src": "",
            "actual_glitch_trigger_src": "",
        }

    return {
        "actual_hs2": safe_getattr(io, "hs2", ""),
        "actual_glitch_width": safe_getattr(g, "width", ""),
        "actual_glitch_offset": safe_getattr(g, "offset", ""),
        "actual_glitch_ext_offset": safe_getattr(g, "ext_offset", ""),
        "actual_glitch_repeat": safe_getattr(g, "repeat", ""),
        "actual_glitch_output": safe_getattr(g, "output", ""),
        "actual_glitch_clk_src": safe_getattr(g, "clk_src", ""),
        "actual_glitch_trigger_src": safe_getattr(g, "trigger_src", ""),
    }


def force_glitch_route(scope: Any, args: argparse.Namespace) -> dict[str, Any]:
    """
    Make the currently selected parameter point active on the target clock.

    In normal mode this forces HS2 through the glitch module and rewrites the
    current point's width/offset/repeat/ext_offset.  With --no-glitch-route it
    deliberately keeps HS2 on clean clkgen for baseline M/trigger sanity checks.
    """
    if getattr(args, "no_glitch_route", False):
        try:
            scope.io.hs2 = HS2_NORMAL
        except Exception:
            pass
        time.sleep(0.005)
        return get_glitch_state(scope)

    # Re-apply glitch module settings for the current point.
    try:
        scope.glitch.output = args.glitch_output
    except Exception:
        pass

    try:
        scope.glitch.clk_src = "clkgen"
    except Exception:
        pass

    try:
        scope.glitch.trigger_src = "ext_single"
    except Exception:
        pass

    for attr in ("width", "offset", "repeat", "ext_offset"):
        try:
            setattr(scope.glitch, attr, getattr(args, attr))
        except Exception:
            pass

    # This is the critical routing setting: target must receive glitch output.
    try:
        scope.io.hs2 = HS2_GLITCH
    except Exception:
        pass

    time.sleep(0.005)
    return get_glitch_state(scope)


def force_prep_route(scope: Any) -> None:
    """Return target clock routing to normal clkgen for non-glitched commands."""
    try:
        scope.io.hs2 = HS2_NORMAL
    except Exception:
        pass
    time.sleep(0.005)


def manual_connect_scope_and_target(args: argparse.Namespace) -> tuple[Any, Any]:
    """
    Bring up CW-Lite + SimpleSerial2 using the same minimal sequence as the
    hand-tested high-clock P/K script. This intentionally bypasses
    collect_host_faults.connect_scope_and_target(), because that helper can
    touch glitch/MMCM state before the first keypair.
    """
    scope = cw.scope()

    # Match the manual high-clock bring-up first.
    try:
        scope.clock.clkgen_freq = args.clkgen_freq
    except Exception:
        pass
    try:
        scope.clock.adc_src = ADC_SRC
    except Exception:
        pass
    try:
        scope.io.hs2 = HS2_NORMAL
        scope.io.tio1 = "serial_rx"
        scope.io.tio2 = "serial_tx"
    except Exception:
        pass

    # Do not touch ADC/gain/glitch settings before K.
    # The known-good standalone P/K test only configures target clock + UART IO.
    # Capture settings are applied later, immediately before glitched M captures.

    target = cw.target(scope, cw.targets.SimpleSerial2)
    force_target_baud_local(target, DEFAULT_BAUD)

    # Same reset style as the known-good manual ping/K script.
    scope.io.nrst = "low"
    time.sleep(0.1)
    scope.io.nrst = "high_z"
    time.sleep(max(float(getattr(args, "reset_delay", 0.8)), 0.8))

    try:
        flush_target(target)
    except Exception:
        pass

    log_debug(
        args,
        "[manual connect]",
        "clkgen=", safe_getattr(scope.clock, "clkgen_freq", ""),
        "adc=", safe_getattr(scope.clock, "adc_freq", ""),
        "hs2=", safe_getattr(scope.io, "hs2", ""),
        "tio1=", safe_getattr(scope.io, "tio1", ""),
        "tio2=", safe_getattr(scope.io, "tio2", ""),
    )

    return scope, target


def configure_capture_settings(scope: Any, args: argparse.Namespace) -> None:
    """Apply ADC/gain/trigger settings only when we are about to capture/glitch."""
    try:
        scope.gain.mode = "high"
        scope.gain.gain = 30
    except Exception:
        pass
    try:
        scope.adc.samples = args.adc_samples
        scope.adc.timeout = args.adc_timeout
        scope.adc.basic_mode = "rising_edge"
    except Exception:
        pass
    try:
        # CW308_STM32F3 trigger_high()/trigger_low() is routed to TIO4 in
        # the standard ChipWhisperer simpleserial setup.  Explicitly set this
        # here so capture timeout behaviour is not caused by a stale trigger
        # source from previous experiments.
        scope.trigger.triggers = "tio4"
    except Exception:
        pass


def direct_attack_mode(scope: Any, args: argparse.Namespace) -> None:
    """Configure capture/attack mode directly.

    Normal sweep mode routes HS2 through the glitch module.  With
    --no-glitch-route, keep HS2 on the clean clkgen path while still arming
    the scope.  This is useful for C/M/trigger sanity checks because it proves
    the firmware and trigger path work without perturbing the target clock.
    """
    configure_capture_settings(scope, args)
    try:
        scope.clock.clkgen_freq = args.clkgen_freq
    except Exception:
        pass
    try:
        scope.clock.adc_src = ADC_SRC
    except Exception:
        pass

    if getattr(args, "no_glitch_route", False):
        try:
            scope.io.hs2 = HS2_NORMAL
        except Exception:
            pass
        time.sleep(0.005)
        return

    try:
        scope.glitch.output = args.glitch_output
    except Exception:
        pass
    try:
        scope.glitch.clk_src = "clkgen"
    except Exception:
        pass
    try:
        scope.glitch.trigger_src = "ext_single"
    except Exception:
        pass
    try:
        scope.glitch.width = args.width
        scope.glitch.offset = args.offset
        scope.glitch.repeat = args.repeat
        scope.glitch.ext_offset = args.ext_offset
    except Exception:
        pass
    try:
        scope.io.hs2 = HS2_GLITCH
    except Exception:
        pass
    time.sleep(0.005)


def force_target_baud_local(target: Any, baud: int = DEFAULT_BAUD) -> None:
    """
    Robust baud setter for this ChipWhisperer version.

    In the user's current CW version, target.ser.baud is a method rather than a
    simple attribute. This helper tries the method form first and then falls
    back to attribute-style setters.
    """
    try:
        ser = getattr(target, "ser", None)
        if ser is not None:
            baud_obj = getattr(ser, "baud", None)
            if callable(baud_obj):
                baud_obj(baud)
                return
    except Exception:
        pass

    for obj in (getattr(target, "ser", None), target):
        if obj is None:
            continue
        for attr in ("baud", "baudrate"):
            try:
                setattr(obj, attr, baud)
                return
            except Exception:
                pass


def hard_prep_mode(
    scope: Any,
    target: Any,
    args: argparse.Namespace,
    *,
    reset: bool = False,
    delay: float = 0.8,
) -> None:
    """
    Force normal, non-glitch communication state.

    Use reset=True before generating a fresh keypair, because K/Z preparation
    can safely start from a fresh target. Do not use reset=True after a keypair
    has been generated unless you also regenerate the key, since the Kyber
    secret key is stored in target RAM.
    """
    # Intentionally do NOT call collect_host_faults.set_prep_mode() here.
    # The hand-tested high-clock P/K sequence only programs the clock/IO route
    # directly. set_prep_mode() may have side effects from previous glitch code
    # paths, so this helper mirrors the known-good manual bring-up sequence.

    try:
        scope.clock.clkgen_freq = args.clkgen_freq
    except Exception:
        pass
    try:
        scope.clock.adc_src = ADC_SRC
    except Exception:
        pass
    try:
        scope.io.hs2 = HS2_NORMAL
    except Exception:
        pass
    try:
        scope.io.tio1 = "serial_rx"
        scope.io.tio2 = "serial_tx"
    except Exception:
        pass

    force_target_baud_local(target, DEFAULT_BAUD)

    if reset:
        try:
            scope.io.nrst = "low"
            time.sleep(0.1)
            scope.io.nrst = "high_z"
        except Exception:
            pass
        time.sleep(delay)
    else:
        time.sleep(delay)

    try:
        flush_target(target)
    except Exception:
        pass


def soft_prep_no_clock(scope: Any, target: Any, *, delay: float = 0.05) -> None:
    """
    Return to normal command route without touching clkgen_freq/adc_src.

    After K has generated keys in RAM, repeatedly assigning scope.clock.clkgen_freq
    can momentarily disturb the target clock.  Standalone P/K/R tests succeed
    without reprogramming clock before R, so use this lightweight prep for R/Z/C.
    """
    try:
        scope.io.hs2 = HS2_NORMAL
    except Exception:
        pass

    time.sleep(delay)

    try:
        flush_target(target)
    except Exception:
        pass



def ping_once(target: Any, timeout: float = 2.0) -> dict[str, Any]:
    """Send P and return the raw SimpleSerial2 response dictionary."""
    flush_target(target)
    target.simpleserial_write("P", bytearray([]))
    resp = target.simpleserial_read_witherrors("P", 1, glitch_timeout=timeout)
    return resp if isinstance(resp, dict) else {
        "valid": True,
        "payload": to_bytes(resp),
        "full_response": b"",
        "rv": b"",
    }


def glitch_state_short(state: dict[str, Any]) -> str:
    return (
        f"hs2={state.get('actual_hs2')} "
        f"out={state.get('actual_glitch_output')} "
        f"clk={state.get('actual_glitch_clk_src')} "
        f"trig={state.get('actual_glitch_trigger_src')} "
        f"w={state.get('actual_glitch_width')} "
        f"off={state.get('actual_glitch_offset')} "
        f"ext={state.get('actual_glitch_ext_offset')} "
        f"rep={state.get('actual_glitch_repeat')}"
    )



def inclusive_range(start: int, stop: int, step: int) -> list[int]:
    if step == 0:
        raise ValueError("step cannot be 0")
    if start <= stop and step < 0:
        raise ValueError("step must be positive when start <= stop")
    if start >= stop and step > 0:
        return list(range(start, stop - 1, -step))
    return list(range(start, stop + 1, step))


def bit_diff_positions(a: bytes, b: bytes) -> list[int]:
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")

    out: list[int] = []
    for byte_i, (x, y) in enumerate(zip(a, b)):
        d = x ^ y
        for bit_j in range(8):
            if d & (1 << bit_j):
                out.append(byte_i * 8 + bit_j)
    return out


def get_m_bit(m: bytes, bit_index: int) -> int:
    byte_i = bit_index // 8
    bit_j = bit_index % 8
    return (m[byte_i] >> bit_j) & 1


def read_z_chunk(target: Any, offset: int) -> bytes:
    expected = min(SK_CHUNK, INDCPA_SK_LEN - offset)

    payload = bytearray([
        offset & 0xFF,
        (offset >> 8) & 0xFF,
        expected & 0xFF,
    ])

    flush_target(target)
    target.simpleserial_write("Z", payload)

    resp = target.simpleserial_read_witherrors(
        "Z",
        expected,
        glitch_timeout=10.0,
    )

    packet = validate_response(resp, "Z", expected)
    data = bytes(packet.payload)

    if len(data) != expected:
        raise RuntimeError(
            f"bad Z chunk at offset={offset}: got {len(data)}, expected {expected}"
        )

    return data


def dump_indcpa_secret_raw(target: Any) -> bytes:
    chunks = []
    for offset in range(0, INDCPA_SK_LEN, SK_CHUNK):
        chunks.append(read_z_chunk(target, offset))
    raw = b"".join(chunks)
    if len(raw) != INDCPA_SK_LEN:
        raise RuntimeError(f"bad raw sk length: {len(raw)}")
    return raw


def normalize_secret_coeffs(vals: list[int]) -> list[int]:
    """
    decode_indcpa_secret.py may output Montgomery-scaled normal-domain coeffs.
    If values are already in [-3,3], leave them unchanged.
    Otherwise, multiply by MONT_INV=169 modulo q.
    """
    if len(vals) != SECRET_DIM:
        raise RuntimeError(f"expected 512 secret coeffs, got {len(vals)}")

    if max(abs(v) for v in vals) <= 3:
        return vals

    normal = [center_mod_q_scalar(v * MONT_INV) for v in vals]

    if max(abs(v) for v in normal) > 3:
        raise RuntimeError(
            "secret normalization failed: values are still outside [-3,3]"
        )

    return normal


def decode_secret_raw(
    sk_raw_path: Path,
    out_dir: Path,
    args: argparse.Namespace,
) -> np.ndarray:
    decode_script = Path(args.decode_secret_script)
    if not decode_script.is_absolute():
        decode_script = SCRIPT_DIR / decode_script

    if not decode_script.exists():
        raise FileNotFoundError(f"decode secret script not found: {decode_script}")

    cmd = [
        sys.executable,
        str(decode_script),
        "--sk-raw",
        str(sk_raw_path),
        "--out-dir",
        str(out_dir),
        "--impl-dir",
        str(args.impl_dir),
        "--pqm4-root",
        str(args.pqm4_root),
    ]

    res = subprocess.run(cmd, text=True, capture_output=True)

    (out_dir / "decode_stdout.txt").write_text(res.stdout, encoding="utf-8")
    (out_dir / "decode_stderr.txt").write_text(res.stderr, encoding="utf-8")

    if res.returncode != 0:
        raise RuntimeError(
            f"decode_indcpa_secret.py failed; see {out_dir / 'decode_stderr.txt'}"
        )

    normal_txt = out_dir / "secret_coeffs_normal.txt"
    raw_txt = out_dir / "secret_coeffs.txt"

    if normal_txt.exists():
        vals = [int(x) for x in normal_txt.read_text().split()]
        vals = normalize_secret_coeffs(vals)
    elif raw_txt.exists():
        vals = [int(x) for x in raw_txt.read_text().split()]
        vals = normalize_secret_coeffs(vals)
        normal_txt.write_text(" ".join(str(x) for x in vals) + "\n")
    else:
        raise FileNotFoundError(
            f"neither {normal_txt.name} nor {raw_txt.name} was produced"
        )

    arr = np.array(vals, dtype=np.int32)

    counts = Counter(arr.tolist())
    summary = {
        "secret_file": str(normal_txt),
        "num_coefficients": int(arr.size),
        "min": int(arr.min()),
        "max": int(arr.max()),
        "counts": {str(k): int(counts[k]) for k in sorted(counts)},
    }

    (out_dir / "secret_used_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    if arr.size != SECRET_DIM or arr.min() < -3 or arr.max() > 3:
        raise RuntimeError(f"bad decoded secret: {summary}")

    return arr


def read_public_key_chunk_manual(target: Any, offset: int, timeout: float = 10.0, debug: bool = False) -> bytes:
    """
    Read one public-key chunk using the firmware R command directly.

    This mirrors the debug firmware protocol used by Z:
        payload[0] = offset low byte
        payload[1] = offset high byte
        payload[2] = requested length

    We avoid KyberTarget.read_public_key()/common_ss2.read_chunked here because
    that wrapper may not match the current R command payload format.
    """
    expected = min(PK_CHUNK, PK_LEN - offset)
    if expected <= 0:
        return b""

    payload = bytearray([
        offset & 0xFF,
        (offset >> 8) & 0xFF,
        expected & 0xFF,
    ])

    flush_target(target)
    time.sleep(0.02)
    target.simpleserial_write("R", payload)

    resp = target.simpleserial_read_witherrors(
        "R",
        expected,
        glitch_timeout=timeout,
    )

    if debug:
        print(
            f"[DEBUG R chunk] off={offset} len={expected} resp=",
            {
                "valid": resp.get("valid") if isinstance(resp, dict) else True,
                "payload_len": len(resp.get("payload") or b"") if isinstance(resp, dict) else len(resp or b""),
                "full_response": resp.get("full_response") if isinstance(resp, dict) else b"",
                "rv": resp.get("rv") if isinstance(resp, dict) else b"",
            },
        )

    packet = validate_response(resp, "R", expected)
    data = bytes(packet.payload)
    if len(data) != expected:
        raise RuntimeError(
            f"bad R chunk at offset={offset}: got {len(data)}, expected {expected}"
        )
    return data


def read_public_key_manual(target: Any, debug: bool = False) -> bytes:
    chunks: list[bytes] = []
    for offset in range(0, PK_LEN, PK_CHUNK):
        chunks.append(read_public_key_chunk_manual(target, offset, debug=debug))
    pk = b"".join(chunks)
    if len(pk) != PK_LEN:
        raise RuntimeError(f"bad pk length: {len(pk)}")
    return pk


def read_public_key_with_retries(
    scope: Any,
    target: Any,
    kt: KyberTarget,
    args: argparse.Namespace,
    *,
    retries: int = 3,
) -> bytes:
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            # Do not reprogram clkgen/adc_src here.  Standalone R succeeds by
            # only flushing and sending R after K.
            soft_prep_no_clock(scope, target, delay=0.10)
            log_debug(args, f"[DEBUG R/read_pk manual attempt {attempt}]")
            pk = read_public_key_manual(target, debug=getattr(args, "debug", False))
            if len(pk) != PK_LEN:
                raise RuntimeError(f"bad pk length: {len(pk)}")
            return pk
        except Exception as e:
            last_err = e
            log_debug(args, f"[WARN] R/read_pk manual attempt {attempt} failed:", repr(e))

            # Do not reset here: K has already generated pk/sk in RAM.
            # Check that the parser is still alive, then retry R.
            try:
                p = ping_once(target, timeout=2.0)
                log_debug(args, "[DEBUG P after failed R]", p)
            except Exception as pe:
                log_debug(args, "[WARN] P after failed R raised:", repr(pe))

            soft_prep_no_clock(scope, target, delay=0.25)
    raise RuntimeError(f"read_public_key failed after {retries} retries: {last_err!r}")


def dump_indcpa_secret_raw_with_retries(
    scope: Any,
    target: Any,
    args: argparse.Namespace,
    *,
    retries: int = 3,
) -> bytes:
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            # Keep the already-running target clock untouched after K/R.
            soft_prep_no_clock(scope, target, delay=0.10)
            log_debug(args, f"[DEBUG Z/dump_sk attempt {attempt}]")
            raw = dump_indcpa_secret_raw(target)
            if len(raw) != INDCPA_SK_LEN:
                raise RuntimeError(f"bad raw sk length: {len(raw)}")
            return raw
        except Exception as e:
            last_err = e
            log_debug(args, f"[WARN] Z/dump_sk attempt {attempt} failed:", repr(e))
            soft_prep_no_clock(scope, target, delay=0.25)
    raise RuntimeError(f"dump_indcpa_secret_raw failed after {retries} retries: {last_err!r}")


def wait_for_ping_alive(
    scope: Any,
    target: Any,
    args: argparse.Namespace,
    *,
    label: str,
    attempts: int = 5,
    reset_first: bool = False,
    reset_between: bool = False,
    delay: float = 0.2,
) -> None:
    """Wait until P responds. Optionally reset before/between attempts."""
    reset_delay = max(float(getattr(args, "reset_delay", 0.2)), 0.8)
    last_ping = None
    for attempt in range(1, attempts + 1):
        hard_prep_mode(
            scope,
            target,
            args,
            reset=(reset_first and attempt == 1) or (reset_between and attempt > 1),
            delay=reset_delay if ((reset_first and attempt == 1) or (reset_between and attempt > 1)) else delay,
        )
        try:
            last_ping = ping_once(target, timeout=2.0)
            log_debug(args, f"[DEBUG {label} P attempt {attempt}]", last_ping)
            if isinstance(last_ping, dict) and last_ping.get("valid", False):
                hard_prep_mode(scope, target, args, reset=False, delay=0.1)
                return
        except Exception as e:
            last_ping = repr(e)
            log_debug(args, f"[WARN] {label} P attempt {attempt} failed:", repr(e))
    raise RuntimeError(f"P ping failed during {label}; last={last_ping!r}")



def raw_keypair_command(target: Any, timeout: float = 40.0) -> int:
    """Issue K using the exact raw SimpleSerial2 pattern used by standalone tests."""
    flush_target(target)
    target.simpleserial_write("K", bytearray([]))
    resp = target.simpleserial_read_witherrors("K", 1, glitch_timeout=timeout)
    # raw_keypair_command is currently not used in the main flow; keep it quiet by default.
    # Add local prints here if debugging this helper directly.
    packet = validate_response(resp, "K", 1)
    payload = bytes(packet.payload)
    if len(payload) != 1:
        raise RuntimeError(f"bad K payload length: {len(payload)}")
    return int(payload[0])


def generate_keypair_and_secret(
    scope: Any,
    target: Any,
    kt: KyberTarget,
    out_dir: Path,
    keypair_id: int,
    args: argparse.Namespace,
) -> tuple[bytes, str, np.ndarray]:
    """
    Generate a target keypair, read pk, dump raw IND-CPA sk, and decode secret.

    v9 policy:
      - Use the exact standalone-style timing for P/K bring-up.
      - After reset, send only ONE P before K. Do not send repeated P retries,
        because a delayed response from P1 can be mistaken for P2 and leave the
        SimpleSerial stream desynchronized before K.
      - Send raw K once per transaction with a long timeout.
      - If K fails, reset and start a fresh transaction.
      - Once K succeeds, do not reset until R+Z are complete.
    """
    reset_delay = max(float(getattr(args, "reset_delay", 0.2)), 1.0)
    transaction_last_err = None

    for tx_attempt in range(1, 8):
        log_debug(args, f"\n[KEYGEN TX attempt {tx_attempt}/7 - standalone-style]")
        try:
            # Exact standalone style: set clock/io, reset, wait, flush.
            hard_prep_mode(scope, target, args, reset=True, delay=reset_delay)

            log_debug(
                args,
                "[DEBUG before standalone-style K]",
                "clkgen=", safe_getattr(scope.clock, "clkgen_freq", ""),
                "adc=", safe_getattr(scope.clock, "adc_freq", ""),
                "hs2=", safe_getattr(scope.io, "hs2", ""),
                "tio1=", safe_getattr(scope.io, "tio1", ""),
                "tio2=", safe_getattr(scope.io, "tio2", ""),
            )

            # Mirror the known-good standalone test: P once, then K.
            try:
                p1 = ping_once(target, timeout=2.0)
                log_debug(args, "[DEBUG standalone-style P1 before K]", p1)
            except Exception as e:
                p1 = repr(e)
                log_debug(args, "[WARN] standalone-style P1 before K failed:", p1)

            # Do NOT send another P here.  A second P can create a delayed-response
            # ambiguity.  Give the target a quiet gap, then send K.
            time.sleep(0.2)

            flush_target(target)
            target.simpleserial_write("K", bytearray([]))
            t0 = time.perf_counter()
            kresp = target.simpleserial_read_witherrors("K", 1, glitch_timeout=60.0)
            elapsed = time.perf_counter() - t0
            log_debug(args, "[DEBUG standalone-style raw K response]", kresp)
            log_debug(args, "[DEBUG standalone-style K elapsed]", elapsed)

            packet = validate_response(kresp, "K", 1)
            payload = bytes(packet.payload)
            if len(payload) != 1:
                raise RuntimeError(f"bad K payload length: {len(payload)}")
            ret = int(payload[0])
            if ret != 0:
                raise RuntimeError(f"K command returned ret={ret}")

            # Standalone style: wait, then P once after K.
            time.sleep(0.5)
            try:
                p2 = ping_once(target, timeout=2.0)
                log_debug(args, "[DEBUG standalone-style P2 after K]", p2)
            except Exception as e:
                raise RuntimeError(f"P after K raised: {e!r}")
            if not (isinstance(p2, dict) and p2.get("valid", False)):
                raise RuntimeError(f"P after K invalid: {p2!r}")

            # K succeeded.  Do not reset from this point until R+Z are complete.
            # Use conservative retries for R/Z, but never reset inside them.
            time.sleep(0.5)
            pk = read_public_key_with_retries(scope, target, kt, args, retries=5)
            pk_hash = sha256_hex(pk)

            key_dir = out_dir / "keys" / f"keypair_{keypair_id:04d}"
            key_dir.mkdir(parents=True, exist_ok=True)
            (key_dir / "pk.bin").write_bytes(pk)

            raw = dump_indcpa_secret_raw_with_retries(scope, target, args, retries=5)
            raw_path = key_dir / "indcpa_sk_raw.bin"
            raw_path.write_bytes(raw)

            secret = decode_secret_raw(raw_path, key_dir, args)

            print(
                f"[+] Keypair {keypair_id} ready: "
                f"pk_hash={pk_hash[:16]}..., "
                f"secret_range=[{secret.min()}, {secret.max()}]"
            )

            return pk, pk_hash, secret

        except Exception as e:
            transaction_last_err = e
            log_debug(args, f"[WARN] standalone-style keygen transaction attempt {tx_attempt} failed:", repr(e))
            try:
                # Give a possibly-still-running K plenty of time before reset.
                time.sleep(1.0)
                hard_prep_mode(scope, target, args, reset=True, delay=reset_delay)
            except Exception as e2:
                log_debug(args, "[WARN] hard reset after failed keygen transaction failed:", repr(e2))
            time.sleep(0.5)

    raise RuntimeError(
        f"generate_keypair_and_secret failed after standalone-style retries: {transaction_last_err!r}"
    )


def fast_rekey_after_crash(
    scope: Any,
    target: Any,
    args: argparse.Namespace,
    *,
    label: str = "crash",
) -> None:
    """
    Fast crash recovery path for deterministic debug firmware.

    A full generate_keypair_and_secret() performs K, reads pk via R, dumps sk via
    Z, and decodes the secret.  In the current firmware, K after reset produces
    the same pk/sk every time, so crash-heavy screening can reset + run only K
    and reuse the existing pk/secret in host memory.
    """
    reset_delay = max(float(getattr(args, "reset_delay", 0.2)), 0.8)
    hard_prep_mode(scope, target, args, reset=True, delay=reset_delay)

    # Match standalone-style K timing.
    time.sleep(0.2)
    ret = raw_keypair_command(target, timeout=60.0)
    if ret != 0:
        raise RuntimeError(f"fast rekey K returned ret={ret}")

    time.sleep(0.2)
    p = ping_once(target, timeout=2.0)
    if not (isinstance(p, dict) and p.get("valid", False)):
        raise RuntimeError(f"target not alive after fast rekey ({label}): {p!r}")


def read_m_response(target: Any, timeout: float) -> dict[str, Any]:
    resp = target.simpleserial_read_witherrors(
        "M",
        M_LEN,
        glitch_timeout=timeout,
    )

    if isinstance(resp, dict):
        return {
            "valid": bool(resp.get("valid", False)),
            "payload": to_bytes(resp.get("payload")),
            "full_response_hex": to_bytes(resp.get("full_response")).hex(),
            "rv_hex": to_bytes(resp.get("rv")).hex(),
        }

    return {
        "valid": True,
        "payload": to_bytes(resp),
        "full_response_hex": "",
        "rv_hex": "",
    }


def glitched_m_decode(
    scope: Any,
    target: Any,
    m_host: bytes,
    args: argparse.Namespace,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "classification": "",
        "m_dec_hex": "",
        "m_match": "",
        "bit_diff_count": "",
        "bit_diff_positions": "",
        "first_bit_diff": "",
        "trigger_count": "",
        "scope_timeout": "",
        "elapsed_ms": "",
        "full_response_hex": "",
        "rv_hex": "",
        "actual_hs2": "",
        "actual_glitch_width": "",
        "actual_glitch_offset": "",
        "actual_glitch_ext_offset": "",
        "actual_glitch_repeat": "",
        "actual_glitch_output": "",
        "actual_glitch_clk_src": "",
        "actual_glitch_trigger_src": "",
        "error": "",
    }

    t0 = time.perf_counter()

    try:
        direct_attack_mode(scope, args)
        state = force_glitch_route(scope, args)
        row.update(state)

        if args.strict_glitch_route:
            expected_hs2 = HS2_NORMAL if getattr(args, "no_glitch_route", False) else HS2_GLITCH
            if state.get("actual_hs2") != expected_hs2:
                raise RuntimeError(f"hs2 route mismatch: expected {expected_hs2}, state={state}")

        scope.arm()
        target.simpleserial_write("M", bytearray([]))

        scope_timeout = bool(scope.capture())
        row["scope_timeout"] = int(scope_timeout)

        try:
            row["trigger_count"] = int(scope.adc.trig_count)
        except Exception:
            row["trigger_count"] = ""

        resp = read_m_response(target, args.decode_timeout)

        row["elapsed_ms"] = (time.perf_counter() - t0) * 1000.0
        row["full_response_hex"] = resp["full_response_hex"]
        row["rv_hex"] = resp["rv_hex"]

        if not resp["valid"] or len(resp["payload"]) != M_LEN:
            row["classification"] = "invalid_response"
            row["error"] = (
                f"valid={resp['valid']}, payload_len={len(resp['payload'])}"
            )
            return row

        m_dec = resp["payload"]
        bits = bit_diff_positions(m_host, m_dec)

        row["m_dec_hex"] = m_dec.hex()
        row["m_match"] = len(bits) == 0
        row["bit_diff_count"] = len(bits)
        row["bit_diff_positions"] = ";".join(str(x) for x in bits)
        row["first_bit_diff"] = bits[0] if bits else ""

        if scope_timeout:
            row["classification"] = "scope_timeout_with_response"
        elif len(bits) == 0:
            row["classification"] = "message_correct"
        else:
            row["classification"] = "message_wrong"

        return row

    except Exception as e:
        row["elapsed_ms"] = (time.perf_counter() - t0) * 1000.0
        row["classification"] = "timeout_or_exception"
        row["error"] = repr(e)
        return row

    finally:
        # Return only the target clock route to normal. Avoid set_prep_mode()
        # here because manual high-clock communication works without it, and
        # set_prep_mode() can introduce side effects between attack/prep phases.
        try:
            scope.clock.clkgen_freq = args.clkgen_freq
            scope.clock.adc_src = ADC_SRC
        except Exception:
            pass
        force_prep_route(scope)


def start_intermediate_helper(args: argparse.Namespace, out_dir: Path):
    helper = build_intermediate_helper(args, out_dir)

    cmd = [
        str(helper),
        str(args.bit_index),
        "1",  # store A-row
        "0",  # do not store noise vectors
        "0",  # do not copy full hex into output
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    fields = output_fieldnames(args)

    return proc, fields


def parse_coeffs(s: str) -> np.ndarray:
    arr = np.fromstring(s, sep=";", dtype=np.int32)
    if arr.size != KYBER_N:
        raise RuntimeError(f"expected {KYBER_N} coeffs, got {arr.size}")
    return arr


def reconstruct_residual_online(
    proc: subprocess.Popen,
    fields: list[str],
    trial_id: int,
    source_classification: str,
    ct: bytes,
    m: bytes,
    coins: bytes,
    secret: np.ndarray,
    args: argparse.Namespace,
) -> tuple[int, int, int]:
    """
    Return:
        m_bit, residual, v_centered
    """
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("intermediate helper pipe not available")

    ct_hash = sha256_hex(ct)

    line = "\t".join([
        str(trial_id),
        str(trial_id),
        source_classification,
        ct_hash,
        ct.hex(),
        m.hex(),
        coins.hex(),
    ]) + "\n"

    proc.stdin.write(line)
    proc.stdin.flush()

    out_line = proc.stdout.readline()
    if not out_line:
        stderr = ""
        if proc.stderr is not None:
            stderr = proc.stderr.read()
        raise RuntimeError(f"intermediate helper produced no output; stderr={stderr}")

    out = parse_helper_output_line(out_line, fields)

    m_bit = int(out["m_bit"])
    v_centered = int(out["v_centered"])

    a0 = parse_coeffs(out["a_poly0_coeffs"])
    a1 = parse_coeffs(out["a_poly1_coeffs"])
    A = np.concatenate([a0, a1]).astype(np.int32)

    mu = MU_ONE if m_bit == 1 else 0
    raw = int(v_centered - mu - int(A @ secret.astype(np.int32)))
    residual = center_mod_q_scalar(raw)

    return m_bit, residual, v_centered


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sweep bit208 decoder fault selectivity."
    )

    p.add_argument("--trials-per-point", type=int, default=300)

    p.add_argument("--ext-offset-start", type=int, default=2388)
    p.add_argument("--ext-offset-stop", type=int, default=2406)
    p.add_argument("--ext-offset-step", type=int, default=1)

    p.add_argument("--widths", default="8")
    p.add_argument("--offsets", default="-16")
    p.add_argument("--repeats", default="2")

    p.add_argument("--bit-index", type=int, default=208)
    p.add_argument("--m-bit-filter", type=int, default=1, choices=[0, 1])

    p.add_argument("--target-variant", default="kyber512-90s")
    p.add_argument(
        "--impl-dir",
        default="/home/ruixiang/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/crypto_kem/kyber512-90s/clean",
    )
    p.add_argument("--pqm4-root", default="../../pqm4-Round3")
    p.add_argument("--host-helper", default="")
    p.add_argument("--helper-bin", default="")

    p.add_argument("--decode-secret-script", default="decode_indcpa_secret.py")

    p.add_argument("--platform", default="CWLITEARM")
    p.add_argument("--ss-version", default="SS_VER_2_1")
    p.add_argument("--clkgen-freq", type=float, default=CLKGEN_FREQ)
    p.add_argument("--adc-samples", type=int, default=5000)
    p.add_argument("--adc-timeout", type=float, default=0.2)
    p.add_argument("--decode-timeout", type=float, default=10.0)
    p.add_argument("--glitch-output", default="clock_xor")
    p.add_argument(
        "--no-glitch-route",
        action="store_true",
        help=(
            "Baseline mode: keep HS2 on clean clkgen during M decode while still "
            "arming the scope and reading the M response. Use this for C/M/trigger "
            "sanity checks. Normal glitch sweeps should not use this option."
        ),
    )
    p.add_argument(
        "--debug-glitch-config",
        action="store_true",
        help="Print actual glitch/routing state at selected points.",
    )
    p.add_argument(
        "--glitch-debug-every",
        type=int,
        default=100,
        help="When --debug-glitch-config is set, print one point every N points.",
    )
    p.add_argument(
        "--strict-glitch-route",
        action="store_true",
        help="Raise if hs2 is not routed to glitch during a glitched capture.",
    )

    p.add_argument("--out-dir", default="")
    p.add_argument("--progress-interval", type=int, default=1, help="Refresh the one-line whole-sweep progress every N trials; use 0 to disable.")
    p.add_argument("--reset-delay", type=float, default=0.8)

    p.add_argument(
        "--new-key-every-point",
        action="store_true",
        help="Generate and dump a fresh key for every parameter point.",
    )

    p.add_argument(
        "--stop-on-crash",
        action="store_true",
        help="Stop the whole sweep on the first crash instead of recovering.",
    )

    p.add_argument(
        "--fast-rekey-on-crash",
        action="store_true",
        help=(
            "After a crash, reset the target and issue only K to restore the deterministic "
            "target keypair, reusing the previously dumped pk/secret. This avoids slow "
            "R/Z/decode on every crash-heavy trial. Use only when K is deterministic "
            "and pk_hash stays constant after reset, as in the current debug firmware."
        ),
    )
    p.add_argument(
        "--full-rekey-every",
        type=int,
        default=0,
        help=(
            "When --fast-rekey-on-crash is enabled, perform a full K/R/Z/decode every N "
            "crash recoveries as a consistency check. 0 disables periodic full checks."
        ),
    )
    p.add_argument(
        "--early-abort-crashy-points",
        action="store_true",
        help=(
            "During screening, stop the current point early if it is clearly crash-only "
            "after --early-abort-min-trials trials."
        ),
    )
    p.add_argument(
        "--early-abort-min-trials",
        type=int,
        default=10,
        help="Minimum trials before a crash-heavy point can be skipped early.",
    )
    p.add_argument(
        "--early-abort-crash-rate",
        type=float,
        default=0.95,
        help="Crash-rate threshold for --early-abort-crashy-points.",
    )

    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose bring-up, K/R/Z, and retry debug logs.",
    )

    return p


CT_LEN = 768
CT_CHUNK = 128

def upload_ct_manual(target: Any, ct: bytes) -> None:
    if len(ct) != CT_LEN:
        raise RuntimeError(f"bad ct length: {len(ct)}")

    for off in range(0, CT_LEN, CT_CHUNK):
        chunk = ct[off:off + CT_CHUNK]
        payload = bytes([off & 0xff, (off >> 8) & 0xff]) + chunk

        flush_target(target)
        time.sleep(0.01)
        target.simpleserial_write("C", bytearray(payload))

        resp = target.simpleserial_read_witherrors(
            "C",
            1,
            glitch_timeout=10.0,
        )

        packet = validate_response(resp, "C", 1)
        data = bytes(packet.payload)

        if len(data) != 1 or data[0] != 0:
            raise RuntimeError(
                f"C upload failed at off={off}: status={data.hex()}"
            )


def main() -> int:
    args = build_argparser().parse_args()

    widths = parse_float_list(args.widths)
    offsets = parse_float_list(args.offsets)
    repeats = parse_int_list(args.repeats)
    ext_offsets = inclusive_range(
        args.ext_offset_start,
        args.ext_offset_stop,
        args.ext_offset_step,
    )

    total_points = len(widths) * len(offsets) * len(repeats) * len(ext_offsets)

    args.width = widths[0]
    args.offset = offsets[0]
    args.repeat = repeats[0]
    args.ext_offset = ext_offsets[0]

    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()
    else:
        out_dir = Path("data") / "analysis" / f"bit208_selectivity_sweep_{now_stamp()}"

    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = vars(args).copy()
    metadata.update({
        "created_at": datetime.now().isoformat(),
        "script": "sweep_bit208_selectivity_fastscreen_pointprogress.py",
        "widths": widths,
        "offsets": offsets,
        "repeats": repeats,
        "ext_offsets": ext_offsets,
        "total_points": total_points,
        "max_trials_without_early_abort": total_points * args.trials_per_point,
        "score": "single_bit_mbit_count * max(0, residual_negative_rate - 0.5)",
        "keygen_order": "manual_connect -> K/R/Z -> build_host_helper -> start_intermediate_helper -> sweep",
        "speed_features": {
            "adc_timeout_default": 0.2,
            "fast_rekey_on_crash": args.fast_rekey_on_crash,
            "full_rekey_every": args.full_rekey_every,
            "early_abort_crashy_points": args.early_abort_crashy_points,
            "early_abort_min_trials": args.early_abort_min_trials,
            "early_abort_crash_rate": args.early_abort_crash_rate,
        },
        "clock_config": {
            "CLKGEN_FREQ": CLKGEN_FREQ,
            "ADC_SRC": ADC_SRC,
            "HS2_NORMAL": HS2_NORMAL,
            "HS2_GLITCH": HS2_GLITCH,
            "DEFAULT_BAUD": DEFAULT_BAUD,
        },
    })

    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("[+] Output dir:", out_dir)
    print(f"[+] Sweep points: {total_points} ({len(widths)} widths × {len(offsets)} offsets × {len(repeats)} repeats × {len(ext_offsets)} ext_offsets)")
    print(f"[+] Max trials without early abort: {total_points * args.trials_per_point}")
    log_debug(args, "[+] Keygen order: manual connect -> K/R/Z BEFORE host/intermediate helper build")

    row_csv = out_dir / "selectivity_rows.csv"
    summary_csv = out_dir / "selectivity_summary.csv"

    row_fields = [
        "global_trial",
        "point_id",
        "point_trial",
        "keypair_id",
        "pk_hash",
        "width",
        "offset",
        "repeat",
        "ext_offset",
        "classification",
        "trigger_count",
        "scope_timeout",
        "elapsed_ms",
        "m_bit",
        "bit_diff_count",
        "bit_diff_positions",
        "first_bit_diff",
        "is_single_bit_target",
        "is_single_bit_target_mbit",
        "residual",
        "residual_sign",
        "v_centered",
        "ct_sha256",
        "actual_hs2",
        "actual_glitch_width",
        "actual_glitch_offset",
        "actual_glitch_ext_offset",
        "actual_glitch_repeat",
        "actual_glitch_output",
        "actual_glitch_clk_src",
        "actual_glitch_trigger_src",
        "error",
    ]

    summary_fields = [
        "point_id",
        "width",
        "offset",
        "repeat",
        "ext_offset",
        "trials",
        "message_correct",
        "message_wrong",
        "crash",
        "invalid_response",
        "timeout_or_exception",
        "host_exception",
        "single_bit_target",
        "single_bit_target_mbit",
        "residual_negative",
        "residual_positive_or_zero",
        "residual_negative_rate",
        "crash_rate",
        "message_wrong_rate",
        "single_bit_target_rate",
        "score",
        "aborted_early",
    ]

    row_f = None
    summary_f = None
    interm_proc = None
    scope = None
    target = None

    keypair_id = -1
    pk = b""
    pk_hash = ""
    secret = None
    need_key = True
    global_trial = 0
    point_id = 0
    fast_rekey_count = 0

    summary_rows: list[dict[str, Any]] = []

    try:
        # This must be the first hardware action.  Do not build host helpers,
        # start subprocesses, configure ADC/gain, or touch glitch/MMCM before
        # this K/R/Z transaction.  This is intended to match the known-good
        # standalone high-clock P/K/R/Z test as closely as possible.
        scope, target = manual_connect_scope_and_target(args)
        kt = KyberTarget(target)

        hard_prep_mode(
            scope,
            target,
            args,
            reset=True,
            delay=max(float(getattr(args, "reset_delay", 0.2)), 0.8),
        )

        keypair_id = 0
        pk, pk_hash, secret = generate_keypair_and_secret(
            scope=scope,
            target=target,
            kt=kt,
            out_dir=out_dir,
            keypair_id=keypair_id,
            args=args,
        )
        need_key = False

        # Only after the first target keypair is safely generated and dumped do
        # we build host-side helper binaries and start the residual helper.
        host_helper = build_host_helper(args, out_dir)
        print("[+] Host helper:", host_helper)

        interm_proc, interm_fields = start_intermediate_helper(args, out_dir)

        row_f = row_csv.open("w", newline="", buffering=1)
        summary_f = summary_csv.open("w", newline="", buffering=1)

        row_writer = csv.DictWriter(row_f, fieldnames=row_fields)
        summary_writer = csv.DictWriter(summary_f, fieldnames=summary_fields)

        row_writer.writeheader()
        summary_writer.writeheader()

        for width in widths:
            for offset in offsets:
                for repeat in repeats:
                    for ext_offset in ext_offsets:
                        point_id += 1

                        args.width = width
                        args.offset = offset
                        args.repeat = repeat
                        args.ext_offset = ext_offset

                        if args.debug_glitch_config and (
                            point_id <= 5
                            or args.glitch_debug_every <= 1
                            or point_id % args.glitch_debug_every == 0
                        ):
                            # Do not configure or route glitch here: keypair/upload still use prep mode.
                            state = get_glitch_state(scope)
                            print("[point pre-capture cfg]", glitch_state_short(state))

                        # The pre-helper keypair is used for point 1.  If the
                        # user requested a new key every point, regenerate at
                        # the start of subsequent points only.
                        if args.new_key_every_point and point_id > 1:
                            need_key = True

                        if need_key:
                            keypair_id += 1
                            pk, pk_hash, secret = generate_keypair_and_secret(
                                scope=scope,
                                target=target,
                                kt=kt,
                                out_dir=out_dir,
                                keypair_id=keypair_id,
                                args=args,
                            )
                            need_key = False

                        assert secret is not None

                        counts: Counter[str] = Counter()
                        residual_negative = 0
                        residual_positive_or_zero = 0
                        single_bit_target = 0
                        single_bit_target_mbit = 0
                        trials_done = 0
                        point_aborted = False

                        print(
                            f"\npoint={point_id} "
                            f"w={width}, off={offset}, rep={repeat}, ext={ext_offset}"
                        )

                        for point_trial in range(1, args.trials_per_point + 1):
                            global_trial += 1
                            trials_done = point_trial

                            row: dict[str, Any] = {
                                "global_trial": global_trial,
                                "point_id": point_id,
                                "point_trial": point_trial,
                                "keypair_id": keypair_id,
                                "pk_hash": pk_hash,
                                "width": width,
                                "offset": offset,
                                "repeat": repeat,
                                "ext_offset": ext_offset,
                                "classification": "",
                                "trigger_count": "",
                                "scope_timeout": "",
                                "elapsed_ms": "",
                                "m_bit": "",
                                "bit_diff_count": "",
                                "bit_diff_positions": "",
                                "first_bit_diff": "",
                                "is_single_bit_target": 0,
                                "is_single_bit_target_mbit": 0,
                                "residual": "",
                                "residual_sign": "",
                                "v_centered": "",
                                "ct_sha256": "",
                                "actual_hs2": "",
                                "actual_glitch_width": "",
                                "actual_glitch_offset": "",
                                "actual_glitch_ext_offset": "",
                                "actual_glitch_repeat": "",
                                "actual_glitch_output": "",
                                "actual_glitch_clk_src": "",
                                "actual_glitch_trigger_src": "",
                                "error": "",
                            }

                            try:
                                soft_prep_no_clock(scope, target, delay=0.05)

                                host = host_encapsulate(host_helper, pk)
                                ct = host["ct"]
                                m_host = host["m"]
                                coins = host["coins"]

                                soft_prep_no_clock(scope, target, delay=0.05)
                                upload_ct_manual(kt, ct)

                                dec = glitched_m_decode(
                                    scope=scope,
                                    target=target,
                                    m_host=m_host,
                                    args=args,
                                )

                                classification = dec["classification"]

                                if classification in {
                                    "invalid_response",
                                    "timeout_or_exception",
                                    "scope_timeout",
                                }:
                                    if not ping_alive(kt):
                                        classification = "crash"

                                counts[classification] += 1

                                row["classification"] = classification
                                row["trigger_count"] = dec.get("trigger_count", "")
                                row["scope_timeout"] = dec.get("scope_timeout", "")
                                row["elapsed_ms"] = dec.get("elapsed_ms", "")
                                row["actual_hs2"] = dec.get("actual_hs2", "")
                                row["actual_glitch_width"] = dec.get("actual_glitch_width", "")
                                row["actual_glitch_offset"] = dec.get("actual_glitch_offset", "")
                                row["actual_glitch_ext_offset"] = dec.get("actual_glitch_ext_offset", "")
                                row["actual_glitch_repeat"] = dec.get("actual_glitch_repeat", "")
                                row["actual_glitch_output"] = dec.get("actual_glitch_output", "")
                                row["actual_glitch_clk_src"] = dec.get("actual_glitch_clk_src", "")
                                row["actual_glitch_trigger_src"] = dec.get("actual_glitch_trigger_src", "")
                                row["bit_diff_count"] = dec.get("bit_diff_count", "")
                                row["bit_diff_positions"] = dec.get("bit_diff_positions", "")
                                row["first_bit_diff"] = dec.get("first_bit_diff", "")
                                row["ct_sha256"] = sha256_hex(ct)
                                row["error"] = dec.get("error", "")

                                bits = []
                                if dec.get("bit_diff_positions", "") != "":
                                    bits = [
                                        int(x)
                                        for x in str(dec["bit_diff_positions"]).split(";")
                                        if x != ""
                                    ]

                                is_single_target = (
                                    len(bits) == 1 and bits[0] == args.bit_index
                                )

                                if is_single_target:
                                    single_bit_target += 1
                                    row["is_single_bit_target"] = 1

                                    m_bit, residual, v_centered = reconstruct_residual_online(
                                        proc=interm_proc,
                                        fields=interm_fields,
                                        trial_id=global_trial,
                                        source_classification=classification,
                                        ct=ct,
                                        m=m_host,
                                        coins=coins,
                                        secret=secret,
                                        args=args,
                                    )

                                    row["m_bit"] = m_bit
                                    row["residual"] = residual
                                    row["v_centered"] = v_centered

                                    if m_bit == args.m_bit_filter:
                                        single_bit_target_mbit += 1
                                        row["is_single_bit_target_mbit"] = 1

                                        if residual < 0:
                                            residual_negative += 1
                                            row["residual_sign"] = "negative"
                                        else:
                                            residual_positive_or_zero += 1
                                            row["residual_sign"] = "positive_or_zero"

                                row_writer.writerow(row)

                                if classification == "crash":
                                    if args.stop_on_crash:
                                        raise RuntimeError("target crashed")

                                    use_full_rekey = True
                                    if (
                                        args.fast_rekey_on_crash
                                        and not args.new_key_every_point
                                        and pk
                                        and secret is not None
                                    ):
                                        fast_rekey_count += 1
                                        if args.full_rekey_every <= 0 or (fast_rekey_count % args.full_rekey_every) != 0:
                                            use_full_rekey = False

                                    if use_full_rekey:
                                        hard_prep_mode(
                                            scope,
                                            target,
                                            args,
                                            reset=True,
                                            delay=max(float(getattr(args, "reset_delay", 0.2)), 0.8),
                                        )
                                        keypair_id += 1
                                        pk, pk_hash, secret = generate_keypair_and_secret(
                                            scope=scope,
                                            target=target,
                                            kt=kt,
                                            out_dir=out_dir,
                                            keypair_id=keypair_id,
                                            args=args,
                                        )
                                        need_key = False
                                    else:
                                        try:
                                            fast_rekey_after_crash(scope, target, args, label=f"point={point_id},trial={point_trial}")
                                            log_debug(args, f"[DEBUG fast rekey ok] point={point_id} trial={point_trial}")
                                            need_key = False
                                        except Exception as e:
                                            log_debug(args, "[WARN] fast rekey failed; falling back to full keygen:", repr(e))
                                            keypair_id += 1
                                            pk, pk_hash, secret = generate_keypair_and_secret(
                                                scope=scope,
                                                target=target,
                                                kt=kt,
                                                out_dir=out_dir,
                                                keypair_id=keypair_id,
                                                args=args,
                                            )
                                            need_key = False

                            except KeyboardInterrupt:
                                raise

                            except Exception as e:
                                counts["host_exception"] += 1
                                row["classification"] = "host_exception"
                                row["error"] = repr(e)
                                row_writer.writerow(row)

                                if (
                                    args.fast_rekey_on_crash
                                    and not args.new_key_every_point
                                    and pk
                                    and secret is not None
                                ):
                                    try:
                                        fast_rekey_count += 1
                                        fast_rekey_after_crash(scope, target, args, label=f"host_exception point={point_id},trial={point_trial}")
                                        need_key = False
                                    except Exception as rekey_err:
                                        log_debug(args, "[WARN] fast rekey after host_exception failed; falling back to full keygen:", repr(rekey_err))
                                        keypair_id += 1
                                        pk, pk_hash, secret = generate_keypair_and_secret(
                                            scope=scope,
                                            target=target,
                                            kt=kt,
                                            out_dir=out_dir,
                                            keypair_id=keypair_id,
                                            args=args,
                                        )
                                        need_key = False
                                else:
                                    hard_prep_mode(
                                        scope,
                                        target,
                                        args,
                                        reset=True,
                                        delay=max(float(getattr(args, "reset_delay", 0.2)), 0.8),
                                    )

                                    keypair_id += 1
                                    pk, pk_hash, secret = generate_keypair_and_secret(
                                        scope=scope,
                                        target=target,
                                        kt=kt,
                                        out_dir=out_dir,
                                        keypair_id=keypair_id,
                                        args=args,
                                    )
                                    need_key = False

                            if args.progress_interval:
                                if (
                                    point_trial == 1
                                    or point_trial == args.trials_per_point
                                    or point_trial % args.progress_interval == 0
                                ):
                                    print(
                                        "\r" + progress_bar_line(
                                            point_id=point_id,
                                            total_points=total_points,
                                            point_trial=point_trial,
                                            trials_per_point=args.trials_per_point,
                                            width=width,
                                            offset=offset,
                                            repeat=repeat,
                                            ext_offset=ext_offset,
                                            counts=counts,
                                            single_bit_target=single_bit_target,
                                            single_bit_target_mbit=single_bit_target_mbit,
                                            residual_negative=residual_negative,
                                            residual_positive_or_zero=residual_positive_or_zero,
                                            m_bit_filter=args.m_bit_filter,
                                        ),
                                        end="",
                                        flush=True,
                                    )

                            if (
                                args.early_abort_crashy_points
                                and point_trial >= max(1, args.early_abort_min_trials)
                                and counts["message_wrong"] == 0
                                and single_bit_target == 0
                                and (counts["crash"] / max(1, point_trial)) >= args.early_abort_crash_rate
                            ):
                                point_aborted = True
                                if args.progress_interval:
                                    print(
                                        "\r" + progress_bar_line(
                                            point_id=point_id,
                                            total_points=total_points,
                                            point_trial=point_trial,
                                            trials_per_point=args.trials_per_point,
                                            width=width,
                                            offset=offset,
                                            repeat=repeat,
                                            ext_offset=ext_offset,
                                            counts=counts,
                                            single_bit_target=single_bit_target,
                                            single_bit_target_mbit=single_bit_target_mbit,
                                            residual_negative=residual_negative,
                                            residual_positive_or_zero=residual_positive_or_zero,
                                            m_bit_filter=args.m_bit_filter,
                                        ) + "  [early-abort crashy point]",
                                        end="",
                                        flush=True,
                                    )
                                break

                        if args.progress_interval:
                            print()

                        denom = residual_negative + residual_positive_or_zero
                        neg_rate = residual_negative / denom if denom else 0.0
                        score = single_bit_target_mbit * max(0.0, neg_rate - 0.5)

                        summary = {
                            "point_id": point_id,
                            "width": width,
                            "offset": offset,
                            "repeat": repeat,
                            "ext_offset": ext_offset,
                            "trials": trials_done,
                            "message_correct": counts["message_correct"],
                            "message_wrong": counts["message_wrong"],
                            "crash": counts["crash"],
                            "invalid_response": counts["invalid_response"],
                            "timeout_or_exception": counts["timeout_or_exception"],
                            "host_exception": counts["host_exception"],
                            "single_bit_target": single_bit_target,
                            "single_bit_target_mbit": single_bit_target_mbit,
                            "residual_negative": residual_negative,
                            "residual_positive_or_zero": residual_positive_or_zero,
                            "residual_negative_rate": neg_rate,
                            "crash_rate": counts["crash"] / max(1, trials_done),
                            "message_wrong_rate": counts["message_wrong"] / max(1, trials_done),
                            "single_bit_target_rate": single_bit_target / max(1, trials_done),
                            "score": score,
                            "aborted_early": int(point_aborted),
                        }

                        summary_writer.writerow(summary)
                        summary_rows.append(summary)

                        print(
                            f"summary point={point_id}: "
                            f"trials={summary['trials']} "
                            f"aborted={summary['aborted_early']} "
                            f"wrong={summary['message_wrong']} "
                            f"single208={summary['single_bit_target']} "
                            f"single208_mbit{args.m_bit_filter}={summary['single_bit_target_mbit']} "
                            f"neg_rate={summary['residual_negative_rate']:.3f} "
                            f"crash_rate={summary['crash_rate']:.3f} "
                            f"score={summary['score']:.2f}"
                        )

        print("\n===== Top candidate points by score =====")
        top = sorted(summary_rows, key=lambda x: float(x["score"]), reverse=True)[:20]
        for r in top:
            print(
                f"point={r['point_id']} "
                f"w={r['width']} off={r['offset']} rep={r['repeat']} ext={r['ext_offset']} "
                f"single_mbit={r['single_bit_target_mbit']} "
                f"neg_rate={r['residual_negative_rate']:.3f} "
                f"crash_rate={r['crash_rate']:.3f} "
                f"score={r['score']:.2f}"
            )

        print("\n[+] Rows:", row_csv)
        print("[+] Summary:", summary_csv)
        print("[+] Metadata:", out_dir / "metadata.json")

    finally:
        try:
            if row_f is not None:
                row_f.close()
        except Exception:
            pass

        try:
            if summary_f is not None:
                summary_f.close()
        except Exception:
            pass

        try:
            if interm_proc is not None and interm_proc.poll() is None:
                if interm_proc.stdin is not None:
                    interm_proc.stdin.close()
                interm_proc.terminate()
        except Exception:
            pass

        if scope is not None or target is not None:
            try:
                disconnect(scope, target)
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
