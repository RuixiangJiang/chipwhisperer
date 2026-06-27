#!/usr/bin/env python3
"""
CW-Lite + Kyber512-90s SimpleSerial command integration tests.

Run from:
    ~/chipwhisperer/experiments/kyber51290s_clock_glitch

Example:
    python -m pytest -s -q tests/test_commands_cwlite.py

This file contains two kinds of hardware tests:

1. Direct command tests using raw SimpleSerial:
       P, N, K, R, E, T, C, D, M, Z

2. Exact no-glitch-route baseline test using the real sweep script:
       scripts/sweep_bit208_selectivity.py --no-glitch-route

Current firmware protocol from simpleserial-kyberprobe.c:
    P: request len 0, response len 1, payload 0x42
    N: request len 0, response len 17
    K: request len 0, response len 1, payload ret
    R: request len 3: offset_lo, offset_hi, requested_len
    E: request len 0, response len 33: ret || ss_enc[32]
    T: request len 3: offset_lo, offset_hi, requested_len
    C: request len 130: offset_lo, offset_hi, ct_chunk[128]
    D: request len 0, response len 33: ret || ss_dec[32]
    M: request len 0, response len 32
    Z: request len 3: offset_lo, offset_hi, ignored_compat_byte
       response = up to 128 bytes from sk[0:KYBER_INDCPA_SECRETKEYBYTES]

Important:
    For Kyber512, KYBER_INDCPA_SECRETKEYBYTES is normally 768 bytes.
    This is the serialized IND-CPA secret key, not the decoded int16 coefficient array.
    The decoded coefficient array would be 512 int16 values = 1024 bytes, but that is
    produced host-side after decoding; it is not the raw Z output length.

Environment overrides:
    CW_CLKGEN_FREQ=7372800
    CW_BAUD=115200
    CW_RESET_DELAY=1.5
    CW_ADC_TIMEOUT=0.5
    CW_ADC_SAMPLES=5000

    Z_CHUNK=128
    Z_TOTAL_LEN=768
    Z_THIRD_BYTE=0

Optional:
    SWEEP_SCRIPT=scripts/sweep_bit208_selectivity.py
    SWEEP_BASELINE_OUT=data/analysis/pytest_debug_memload_noglitch_route
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

try:
    import chipwhisperer as cw
except Exception as exc:  # pragma: no cover
    cw = None
    _CW_IMPORT_ERROR = exc
else:
    _CW_IMPORT_ERROR = None


PK_LEN = 800
PK_CHUNK = 200

CT_LEN = 768
CT_CHUNK = 128

SS_LEN = 32
MSG_LEN = 32

# Z returns raw serialized IND-CPA secret key bytes, not decoded int16 coefficients.
# Kyber512: KYBER_INDCPA_SECRETKEYBYTES = 768.
INDCPA_SK_RAW_LEN = int(os.environ.get("Z_TOTAL_LEN", "768"))
Z_CHUNK = int(os.environ.get("Z_CHUNK", "128"))
Z_THIRD_BYTE = int(os.environ.get("Z_THIRD_BYTE", "0"), 0)


def project_root() -> Path:
    # tests/test_commands_cwlite.py -> project root
    return Path(__file__).resolve().parents[1]


def env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, str(default)))


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


CLKGEN_FREQ = env_float("CW_CLKGEN_FREQ", 7_372_800.0)
BAUD = env_int("CW_BAUD", 115200)
RESET_DELAY = env_float("CW_RESET_DELAY", 1.5)
ADC_TIMEOUT = env_float("CW_ADC_TIMEOUT", 0.5)
ADC_SAMPLES = env_int("CW_ADC_SAMPLES", 5000)


def to_bytes(x: Any) -> bytes:
    """Robust conversion for CW response fields."""
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("latin-1", errors="replace")
    if isinstance(x, int):
        return bytes([x & 0xFF])
    return bytes(x)


@dataclass
class Packet:
    cmd: str
    valid: bool
    payload: bytes
    full_response: bytes
    rv: bytes
    raw: Any


def parse_packet(cmd: str, resp: Any) -> Packet:
    if not isinstance(resp, dict):
        raise AssertionError(f"{cmd}: expected dict response, got {type(resp).__name__}: {resp!r}")

    return Packet(
        cmd=cmd,
        valid=bool(resp.get("valid")),
        payload=to_bytes(resp.get("payload")),
        full_response=to_bytes(resp.get("full_response")),
        rv=to_bytes(resp.get("rv")),
        raw=resp,
    )


def packet_summary(pkt: Packet) -> str:
    return (
        f"{pkt.cmd}: valid={pkt.valid} payload_len={len(pkt.payload)} "
        f"payload_head={pkt.payload[:16].hex()} "
        f"rv={pkt.rv.hex()} full_head={pkt.full_response[:32].hex()}"
    )


def require_packet(cmd: str, resp: Any, expected_len: int | None = None) -> Packet:
    pkt = parse_packet(cmd, resp)
    if not pkt.valid:
        raise AssertionError(f"{cmd}: invalid response: {packet_summary(pkt)} raw={resp!r}")
    if expected_len is not None and len(pkt.payload) != expected_len:
        raise AssertionError(
            f"{cmd}: payload length mismatch, got {len(pkt.payload)}, "
            f"expected {expected_len}: {packet_summary(pkt)}"
        )
    return pkt


def reset_target(scope: Any, delay: float = RESET_DELAY) -> None:
    scope.io.nrst = "low"
    time.sleep(0.1)
    scope.io.nrst = "high_z"
    time.sleep(delay)


def connect_cw() -> tuple[Any, Any]:
    if cw is None:
        raise RuntimeError(f"Could not import chipwhisperer: {_CW_IMPORT_ERROR!r}")

    scope = cw.scope()
    scope.clock.clkgen_freq = CLKGEN_FREQ
    scope.clock.adc_src = "clkgen_x4"

    scope.io.hs2 = "clkgen"
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    scope.trigger.triggers = "tio4"
    scope.adc.basic_mode = "rising_edge"
    scope.adc.samples = ADC_SAMPLES
    scope.adc.timeout = ADC_TIMEOUT

    target = cw.target(scope, cw.targets.SimpleSerial2)
    try:
        target.ser.baud(BAUD)
    except Exception:
        # Most recent CW versions use baud as a method. Some versions expose it differently.
        pass

    reset_target(scope)
    return scope, target


def disconnect_cw(scope: Any, target: Any) -> None:
    if target is not None:
        try:
            target.dis()
        except Exception:
            pass
    if scope is not None:
        try:
            scope.dis()
        except Exception:
            pass


def cmd(
    target: Any,
    ch: str,
    payload: bytes = b"",
    expected_len: int | None = None,
    timeout: float = 5.0,
) -> Packet:
    target.flush()
    time.sleep(0.01)
    target.simpleserial_write(ch, bytearray(payload))
    resp = target.simpleserial_read_witherrors(ch, expected_len or 0, glitch_timeout=timeout)
    pkt = require_packet(ch, resp, expected_len)
    print(packet_summary(pkt))
    return pkt


def read_chunked_len3(
    target: Any,
    ch: str,
    total_len: int,
    chunk_len: int,
    timeout: float = 10.0,
) -> bytes:
    """Read commands that use request payload: offset_lo, offset_hi, requested_len."""
    out = bytearray()

    for off in range(0, total_len, chunk_len):
        n = min(chunk_len, total_len - off)
        payload = bytes([off & 0xFF, (off >> 8) & 0xFF, n & 0xFF])
        pkt = cmd(target, ch, payload, expected_len=n, timeout=timeout)
        out += pkt.payload

    assert len(out) == total_len
    return bytes(out)


def read_z_secret(target: Any, total_len: int = INDCPA_SK_RAW_LEN, chunk_len: int = Z_CHUNK) -> bytes:
    """Read Z chunks: offset_lo, offset_hi, ignored third compatibility byte."""
    if not 0 <= Z_THIRD_BYTE <= 255:
        raise AssertionError(f"Z_THIRD_BYTE out of byte range: {Z_THIRD_BYTE}")

    out = bytearray()

    for off in range(0, total_len, chunk_len):
        n = min(chunk_len, total_len - off)

        payload = bytes([off & 0xFF, (off >> 8) & 0xFF, Z_THIRD_BYTE & 0xFF])
        pkt = cmd(target, "Z", payload, expected_len=n, timeout=10.0)
        out += pkt.payload

    assert len(out) == total_len
    return bytes(out)


def upload_ct(target: Any, ct: bytes, timeout: float = 10.0) -> None:
    if len(ct) != CT_LEN:
        raise AssertionError(f"bad ct length: got {len(ct)}, expected {CT_LEN}")

    for off in range(0, CT_LEN, CT_CHUNK):
        chunk = ct[off:off + CT_CHUNK]
        payload = bytes([off & 0xFF, (off >> 8) & 0xFF]) + bytes(chunk)
        pkt = cmd(target, "C", payload, expected_len=1, timeout=timeout)
        if pkt.payload != b"\x00":
            raise AssertionError(f"C upload failed at off={off}: status={pkt.payload.hex()}")


def capture_m(scope: Any, target: Any, timeout: float = 10.0) -> tuple[bytes, int, bool]:
    scope.io.hs2 = "clkgen"
    scope.trigger.triggers = "tio4"
    scope.adc.basic_mode = "rising_edge"
    scope.adc.timeout = ADC_TIMEOUT

    target.flush()
    time.sleep(0.01)

    scope.arm()
    target.simpleserial_write("M", bytearray([]))
    cap_timeout = bool(scope.capture())

    resp = target.simpleserial_read_witherrors("M", MSG_LEN, glitch_timeout=timeout)
    pkt = require_packet("M", resp, expected_len=MSG_LEN)
    trig_count = int(scope.adc.trig_count)

    print(f"M capture_timeout={cap_timeout} trigger_count={trig_count} {packet_summary(pkt)}")

    if cap_timeout:
        raise AssertionError(f"M: scope capture timeout, trigger_count={trig_count}")
    if trig_count <= 0:
        raise AssertionError(f"M: expected trigger_count > 0, got {trig_count}")

    return pkt.payload, trig_count, cap_timeout


@pytest.fixture(scope="function")
def cw_session() -> tuple[Any, Any]:
    scope = target = None
    try:
        scope, target = connect_cw()
        yield scope, target
    finally:
        disconnect_cw(scope, target)


def test_all_firmware_commands(cw_session: tuple[Any, Any]) -> None:
    scope, target = cw_session

    print("\n[1] P ping")
    pkt = cmd(target, "P", b"", expected_len=1, timeout=2.0)
    assert pkt.payload == b"\x42"

    print("\n[2] N randombytes probe")
    pkt = cmd(target, "N", b"", expected_len=17, timeout=5.0)
    assert len(pkt.payload) == 17

    print("\n[3] K keypair")
    pkt = cmd(target, "K", b"", expected_len=1, timeout=30.0)
    assert pkt.payload == b"\x00"

    print("\n[4] R read public key")
    pk = read_chunked_len3(target, "R", PK_LEN, PK_CHUNK)
    assert len(pk) == PK_LEN
    assert any(pk), "public key is all-zero, unexpected"

    print("\n[5] Z read serialized INDCPA secret")
    z = read_z_secret(target)
    assert len(z) == INDCPA_SK_RAW_LEN
    assert any(z), "exported serialized INDCPA secret is all-zero, unexpected"

    print("\n[6] E target encapsulation")
    pkt = cmd(target, "E", b"", expected_len=1 + SS_LEN, timeout=30.0)
    assert pkt.payload[0] == 0
    ss_enc = pkt.payload[1:]
    assert len(ss_enc) == SS_LEN
    assert any(ss_enc), "encapsulated shared secret is all-zero, unexpected"

    print("\n[7] T read target ciphertext")
    ct = read_chunked_len3(target, "T", CT_LEN, CT_CHUNK)
    assert len(ct) == CT_LEN
    assert any(ct), "ciphertext is all-zero, unexpected"

    print("\n[8] D decapsulation of target ciphertext")
    pkt = cmd(target, "D", b"", expected_len=1 + SS_LEN, timeout=30.0)
    assert pkt.payload[0] == 0
    ss_dec = pkt.payload[1:]
    assert ss_dec == ss_enc, "D shared secret does not match E shared secret"

    print("\n[9] C upload the same ciphertext back to target")
    upload_ct(target, ct)

    print("\n[10] D decapsulation after C upload")
    pkt = cmd(target, "D", b"", expected_len=1 + SS_LEN, timeout=30.0)
    assert pkt.payload[0] == 0
    ss_dec_after_upload = pkt.payload[1:]
    assert ss_dec_after_upload == ss_enc, "D shared secret after C upload does not match E shared secret"

    print("\n[11] M debug decode after C upload")
    m, trig_count, cap_timeout = capture_m(scope, target)
    assert len(m) == MSG_LEN
    assert trig_count > 0
    assert not cap_timeout

    print("\n[12] P ping after M")
    pkt = cmd(target, "P", b"", expected_len=1, timeout=2.0)
    assert pkt.payload == b"\x42"


def test_m_after_target_encapsulation_without_c_upload(cw_session: tuple[Any, Any]) -> None:
    """Separate regression test for the E -> M path."""
    scope, target = cw_session

    print("\n[E->M regression] reset + P + K + E + M + P")
    reset_target(scope)

    pkt = cmd(target, "P", b"", expected_len=1, timeout=2.0)
    assert pkt.payload == b"\x42"

    pkt = cmd(target, "K", b"", expected_len=1, timeout=30.0)
    assert pkt.payload == b"\x00"

    pkt = cmd(target, "E", b"", expected_len=1 + SS_LEN, timeout=30.0)
    assert pkt.payload[0] == 0

    m, trig_count, cap_timeout = capture_m(scope, target)
    assert len(m) == MSG_LEN
    assert trig_count > 0
    assert not cap_timeout

    pkt = cmd(target, "P", b"", expected_len=1, timeout=2.0)
    assert pkt.payload == b"\x42"


def test_no_glitch_route_baseline_via_sweep_script() -> None:
    """
    Exact regression for the sweep script's no-glitch-route baseline.

    This intentionally exercises the same high-level path as:
        K/R/Z -> host encapsulate -> C upload -> M decode -> classifier

    It catches bugs that direct command tests cannot catch, for example:
        - calling upload_ct(kt, ct) instead of upload_ct_manual(target, ct)
        - host_exception being hidden by crash_rate=0
        - no-glitch-route accidentally changing clock/ADC settings before M
    """
    root = project_root()
    script_rel = os.environ.get("SWEEP_SCRIPT", "scripts/sweep_bit208_selectivity.py")
    script = root / script_rel
    if not script.exists():
        raise AssertionError(f"sweep script not found: {script}")

    out_rel = os.environ.get(
        "SWEEP_BASELINE_OUT",
        "data/analysis/pytest_debug_memload_noglitch_route",
    )
    out_dir = root / out_rel

    if out_dir.exists():
        shutil.rmtree(out_dir)

    cmdline = [
        sys.executable,
        str(script),
        "--trials-per-point", "5",
        "--clkgen-freq", str(int(CLKGEN_FREQ)),
        "--adc-timeout", str(ADC_TIMEOUT),
        "--ext-offset-start", "0",
        "--ext-offset-stop", "0",
        "--ext-offset-step", "1",
        "--widths=0.0",
        "--offsets=0",
        "--repeats", "1",
        "--progress-interval", "1",
        "--reset-delay", str(RESET_DELAY),
        "--strict-glitch-route",
        "--no-glitch-route",
        "--out-dir", str(out_dir.relative_to(root)),
    ]

    print("\n[no-glitch-route baseline command]")
    print(" ".join(cmdline))

    proc = subprocess.run(
        cmdline,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )

    print("\n[no-glitch-route baseline output]")
    print(proc.stdout)

    assert proc.returncode == 0, f"sweep no-glitch baseline failed with returncode={proc.returncode}"

    rows_path = out_dir / "selectivity_rows.csv"
    summary_path = out_dir / "selectivity_summary.csv"

    assert rows_path.exists(), f"missing rows csv: {rows_path}"
    assert summary_path.exists(), f"missing summary csv: {summary_path}"

    rows = pd.read_csv(rows_path)
    summary = pd.read_csv(summary_path)

    assert len(rows) == 5, f"expected 5 rows, got {len(rows)}"
    assert len(summary) == 1, f"expected 1 summary row, got {len(summary)}"

    print("\n[no-glitch-route baseline rows]")
    keep_cols = [
        "global_trial", "point_id", "classification",
        "trigger_count", "scope_timeout", "actual_hs2",
        "error",
    ]
    keep_cols = [c for c in keep_cols if c in rows.columns]
    print(rows[keep_cols].to_string(index=False))

    vc = rows["classification"].value_counts(dropna=False).to_dict()
    assert vc == {"message_correct": 5}, f"expected all message_correct, got {vc}"

    if "host_exception_rate" in summary.columns:
        assert float(summary.loc[0, "host_exception_rate"]) == 0.0
    if "crash_rate" in summary.columns:
        assert float(summary.loc[0, "crash_rate"]) == 0.0

    assert "actual_hs2" in rows.columns
    assert set(rows["actual_hs2"].dropna()) == {"clkgen"}

    assert "scope_timeout" in rows.columns
    assert int(rows["scope_timeout"].fillna(1).sum()) == 0

    assert "trigger_count" in rows.columns
    assert (rows["trigger_count"].fillna(0).astype(float) > 0).all()

    if "error" in rows.columns:
        bad_errors = rows["error"].dropna().astype(str)
        assert len(bad_errors) == 0 or set(bad_errors) <= {""}, f"unexpected errors: {bad_errors.tolist()}"
