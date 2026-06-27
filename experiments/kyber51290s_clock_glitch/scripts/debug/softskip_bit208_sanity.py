#!/usr/bin/env python3
"""
Sweep glitch parameters and measure bit-208 fault-model selectivity.

Goal:
    Find a glitch setting that still produces single-bit208 message faults,
    but where those faults correlate with the reconstructed decoder residual sign.

For m_bit = 1, the desired skip-(+q/2) model predicts:
    residual = center(v_i - A_i@s - 1665)
    effective fault should mostly occur when residual < 0.

So we score each parameter by:
    single_bit208_mbit1_count
    residual_negative_rate among those samples
    score = count * abs(residual_negative_rate - 0.5)

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

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common_cw import flush_target  # noqa: E402
from common_ss2 import validate_response  # noqa: E402
from kyber_target import KyberTarget  # noqa: E402

from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, HS2_GLITCH, DEFAULT_BAUD

from collect_host_faults import (  # noqa: E402
    build_host_helper,
    host_encapsulate,
    connect_scope_and_target,
    safe_recover,
    set_prep_mode,
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

MONT_INV = 169
MU_ONE = 1665


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_hex(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def to_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    return bytes(x)


def center_mod_q_scalar(x: int) -> int:
    y = x % KYBER_Q
    if y > KYBER_Q // 2:
        y -= KYBER_Q
    return int(y)


def parse_float_list(s: str) -> list[float]:
    return [float(x.strip()) for x in s.split(",") if x.strip()]


def parse_int_list(s: str) -> list[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]


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


def generate_keypair_and_secret(
    scope: Any,
    target: Any,
    kt: KyberTarget,
    out_dir: Path,
    keypair_id: int,
    args: argparse.Namespace,
) -> tuple[bytes, str, np.ndarray]:
    set_prep_mode(scope)

    ret = kt.keypair()
    if ret != 0:
        raise RuntimeError(f"K command failed with ret={ret}")

    pk = bytes(kt.read_public_key())
    if len(pk) != PK_LEN:
        raise RuntimeError(f"bad pk length: {len(pk)}")

    pk_hash = sha256_hex(pk)

    key_dir = out_dir / "keys" / f"keypair_{keypair_id:04d}"
    key_dir.mkdir(parents=True, exist_ok=True)

    (key_dir / "pk.bin").write_bytes(pk)

    raw = dump_indcpa_secret_raw(target)
    raw_path = key_dir / "indcpa_sk_raw.bin"
    raw_path.write_bytes(raw)

    secret = decode_secret_raw(raw_path, key_dir, args)

    print(
        f"[+] New keypair_id={keypair_id}, "
        f"pk_hash={pk_hash[:16]}..., "
        f"secret_range=[{secret.min()}, {secret.max()}]"
    )

    return pk, pk_hash, secret


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
    set_prep_mode(scope)

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
        "error": "",
    }

    t0 = time.perf_counter()

    try:
        try:
            target.flush()
        except Exception:
            pass

        target.simpleserial_write("M", bytearray([]))

        row["scope_timeout"] = 0
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
        set_prep_mode(scope)


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
    p.add_argument("--adc-timeout", type=float, default=2.0)
    p.add_argument("--decode-timeout", type=float, default=10.0)
    p.add_argument("--glitch-output", default="clock_xor")

    p.add_argument("--out-dir", default="")
    p.add_argument("--progress-interval", type=int, default=50)
    p.add_argument("--reset-delay", type=float, default=0.2)

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

    return p


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
        "script": "sweep_bit208_selectivity.py",
        "widths": widths,
        "offsets": offsets,
        "repeats": repeats,
        "ext_offsets": ext_offsets,
        "score": "single_bit_mbit_count * abs(residual_negative_rate - 0.5)",
    })

    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("[+] Output dir:", out_dir)

    host_helper = build_host_helper(args, out_dir)
    print("[+] Host helper:", host_helper)

    interm_proc, interm_fields = start_intermediate_helper(args, out_dir)

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
    ]

    row_f = row_csv.open("w", newline="", buffering=1)
    summary_f = summary_csv.open("w", newline="", buffering=1)

    row_writer = csv.DictWriter(row_f, fieldnames=row_fields)
    summary_writer = csv.DictWriter(summary_f, fieldnames=summary_fields)

    row_writer.writeheader()
    summary_writer.writeheader()

    scope = None
    target = None

    keypair_id = -1
    pk = b""
    pk_hash = ""
    secret = None
    need_key = True
    global_trial = 0
    point_id = 0

    summary_rows: list[dict[str, Any]] = []

    try:
        scope, target = connect_scope_and_target(args)
        kt = KyberTarget(target)

        safe_recover(scope, target, args)
        try:
            scope.io.hs2 = HS2_NORMAL
        except Exception:
            pass

        for width in widths:
            for offset in offsets:
                for repeat in repeats:
                    for ext_offset in ext_offsets:
                        point_id += 1

                        args.width = width
                        args.offset = offset
                        args.repeat = repeat
                        args.ext_offset = ext_offset

                        try:
                            scope.io.hs2 = HS2_NORMAL
                        except Exception:
                            pass

                        if args.new_key_every_point:
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

                        print(
                            f"\n===== Point {point_id}: "
                            f"w={width}, off={offset}, rep={repeat}, ext={ext_offset} ====="
                        )

                        for point_trial in range(1, args.trials_per_point + 1):
                            global_trial += 1

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
                                "error": "",
                            }

                            try:
                                set_prep_mode(scope)

                                host = host_encapsulate(host_helper, pk)
                                ct = host["ct"]
                                m_host = host["m"]
                                coins = host["coins"]

                                upload_ct(kt, ct)

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

                                    safe_recover(scope, target, args)
                                    try:
                                        scope.io.hs2 = HS2_NORMAL
                                    except Exception:
                                        pass
                                    need_key = True

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

                                safe_recover(scope, target, args)
                                try:
                                    scope.io.hs2 = HS2_NORMAL
                                except Exception:
                                    pass

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

                            if (
                                args.progress_interval
                                and point_trial % args.progress_interval == 0
                            ):
                                print(
                                    f"  progress {point_trial}/{args.trials_per_point}: "
                                    f"wrong={counts['message_wrong']}, "
                                    f"single208={single_bit_target}, "
                                    f"single208_mbit{args.m_bit_filter}={single_bit_target_mbit}, "
                                    f"neg={residual_negative}, "
                                    f"pos0={residual_positive_or_zero}, "
                                    f"crash={counts['crash']}"
                                )

                        denom = residual_negative + residual_positive_or_zero
                        neg_rate = residual_negative / denom if denom else 0.0
                        score = single_bit_target_mbit * max(0.0, neg_rate - 0.5)

                        summary = {
                            "point_id": point_id,
                            "width": width,
                            "offset": offset,
                            "repeat": repeat,
                            "ext_offset": ext_offset,
                            "trials": args.trials_per_point,
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
                            "crash_rate": counts["crash"] / args.trials_per_point,
                            "message_wrong_rate": counts["message_wrong"] / args.trials_per_point,
                            "single_bit_target_rate": single_bit_target / args.trials_per_point,
                            "score": score,
                        }

                        summary_writer.writerow(summary)
                        summary_rows.append(summary)

                        print("  summary:", summary)

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
            row_f.close()
        except Exception:
            pass

        try:
            summary_f.close()
        except Exception:
            pass

        try:
            if interm_proc.poll() is None:
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