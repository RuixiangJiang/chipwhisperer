#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common_cw import (
    setup_scope_and_target,
    recover_target,
    flush_target,
    disconnect,
)
from common_ss2 import validate_response
from kyber_target import KyberTarget


INDCPA_SK_LEN = 768
SK_CHUNK = 128
PK_LEN = 800


def sha256_hex(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def read_z_chunk(target, offset: int) -> bytes:
    expected = min(SK_CHUNK, INDCPA_SK_LEN - offset)

    payload = bytearray([
        offset & 0xff,
        (offset >> 8) & 0xff,
        expected & 0xff,
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
            f"bad Z chunk length at offset={offset}: "
            f"got {len(data)}, expected {expected}"
        )

    return data


def dump_indcpa_sk(target) -> bytes:
    chunks = []

    for offset in range(0, INDCPA_SK_LEN, SK_CHUNK):
        chunk = read_z_chunk(target, offset)
        chunks.append(chunk)
        print(f"[+] read Z offset={offset:03d}, len={len(chunk)}")

    sk = b"".join(chunks)

    if len(sk) != INDCPA_SK_LEN:
        raise RuntimeError(f"bad total sk length: {len(sk)}")

    return sk


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: data/secrets/indcpa_sk_<timestamp>",
    )
    ap.add_argument("--clkgen-freq", type=float, default=7.3728e6)
    ap.add_argument("--adc-samples", type=int, default=5000)
    ap.add_argument("--adc-timeout", type=float, default=2.0)
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path("data") / "secrets" / f"indcpa_sk_{tag}"

    out_dir.mkdir(parents=True, exist_ok=True)

    scope = None
    target = None

    try:
        scope, target = setup_scope_and_target(
            clkgen_freq=args.clkgen_freq,
            adc_samples=args.adc_samples,
            adc_timeout=args.adc_timeout,
            ss_version="SS_VER_2_1",
        )

        recover_target(scope, target)

        kt = KyberTarget(target)

        print("[+] Generating fresh target keypair with K command")
        k_ret = kt.keypair()
        if k_ret != 0:
            raise RuntimeError(f"K failed with ret={k_ret}")

        print("[+] Reading public key")
        pk = bytes(kt.read_public_key())
        if len(pk) != PK_LEN:
            raise RuntimeError(f"bad pk length: {len(pk)}")

        print("[+] Dumping IND-CPA secret key raw bytes via Z command")
        indcpa_sk = dump_indcpa_sk(target)

        pk_path = out_dir / "pk.bin"
        sk_path = out_dir / "indcpa_sk_raw.bin"

        pk_path.write_bytes(pk)
        sk_path.write_bytes(indcpa_sk)

        print("\n===== Dump summary =====")
        print("out_dir:", out_dir)
        print("pk:", pk_path)
        print("indcpa_sk_raw:", sk_path)
        print("pk_sha256:", sha256_hex(pk))
        print("indcpa_sk_raw_sha256:", sha256_hex(indcpa_sk))

    finally:
        disconnect(scope, target)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())