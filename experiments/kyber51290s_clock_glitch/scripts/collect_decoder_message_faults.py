#!/usr/bin/env python3
"""
Collect decoder message faults using the debug M command.

Purpose:
    Characterize which decoded-message bit is affected by the fixed decoder
    glitch parameter.

Flow:
    1. Target generates/reuses pk/sk.
    2. Host generates Kyber512-90s ct/ss/m/coins using the target pk.
    3. Host uploads ct to target.
    4. Optional no-glitch M verification: m_dec should equal host m.
    5. Glitched M command returns 32-byte decoded message m_dec.
    6. Compare host m and target m_dec at bit level.

Output:
    decoder_message_faults.csv
    bit_position_summary.csv
    bit_diff_count_summary.csv
    metadata.json

Bit indexing:
    bit_index = byte_index * 8 + bit_in_byte
    bit_in_byte is little-endian, i.e., bit 0 is the LSB of msg[0].
    This matches poly_tomsg() using msg[i] |= t << j.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from kyber_target import KyberTarget  # noqa: E402

# Reuse the working host-side helper and CW utility functions.
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


M_LEN = 32
PK_LEN = 800


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def to_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    return bytes(x)


def hex_or_empty(x: Any) -> str:
    if x is None:
        return ""
    try:
        return to_bytes(x).hex()
    except Exception:
        return ""


def sha256_hex(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def parse_ret_only(result: Any) -> int:
    if result is None:
        return 0
    if isinstance(result, int):
        return result
    if isinstance(result, tuple) and len(result) > 0:
        return int(result[0])
    if isinstance(result, dict):
        if "ret" in result:
            return int(result["ret"])
        if "payload" in result and len(to_bytes(result["payload"])) >= 1:
            return to_bytes(result["payload"])[0]
    data = to_bytes(result)
    if len(data) >= 1:
        return data[0]
    return 0


def get_trigger_count(scope: Any) -> int | str:
    for name in ("trig_count", "trigger_count"):
        try:
            value = getattr(scope.adc, name)
            if value is not None:
                return int(value)
        except Exception:
            pass
    return ""


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
            "full_response_hex": hex_or_empty(resp.get("full_response")),
            "rv_hex": hex_or_empty(resp.get("rv")),
            "raw": resp,
        }

    return {
        "valid": True,
        "payload": to_bytes(resp),
        "full_response_hex": "",
        "rv_hex": "",
        "raw": resp,
    }


def bit_diff_positions(a: bytes, b: bytes) -> list[int]:
    """
    Return differing bit positions between two 32-byte messages.

    bit_index = byte_index * 8 + bit_in_byte
    bit_in_byte is little-endian, so bit 0 is LSB.
    """
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")

    positions: list[int] = []
    for byte_i, (x, y) in enumerate(zip(a, b)):
        diff = x ^ y
        if diff == 0:
            continue
        for bit_j in range(8):
            if diff & (1 << bit_j):
                positions.append(byte_i * 8 + bit_j)
    return positions


def byte_diff_positions(a: bytes, b: bytes) -> list[int]:
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def no_glitch_m_decode(target: Any, scope: Any, timeout: float) -> dict[str, Any]:
    set_prep_mode(scope)

    row = {
        "verify_status": "",
        "verify_m_dec": b"",
        "verify_m_match": "",
        "verify_error": "",
        "verify_elapsed_ms": "",
    }

    t0 = time.perf_counter()

    try:
        target.simpleserial_write("M", bytearray([]))
        resp = read_m_response(target, timeout)

        row["verify_elapsed_ms"] = (time.perf_counter() - t0) * 1000.0

        if not resp["valid"] or len(resp["payload"]) != M_LEN:
            row["verify_status"] = "invalid_response"
            row["verify_error"] = (
                f"valid={resp['valid']}, payload_len={len(resp['payload'])}"
            )
            return row

        row["verify_status"] = "ok"
        row["verify_m_dec"] = resp["payload"]
        return row

    except Exception as e:
        row["verify_elapsed_ms"] = (time.perf_counter() - t0) * 1000.0
        row["verify_status"] = "exception"
        row["verify_error"] = repr(e)
        return row


def glitched_m_decode(
    scope: Any,
    target: Any,
    m_host: bytes,
    args: argparse.Namespace,
) -> dict[str, Any]:
    set_attack_mode(scope, args)

    row: dict[str, Any] = {
        "classification": "",
        "m_dec": b"",
        "m_dec_hex": "",
        "m_dec_first8_hex": "",
        "m_match": "",
        "bit_diff_count": "",
        "bit_diff_positions": "",
        "byte_diff_count": "",
        "byte_diff_positions": "",
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
        scope.arm()
        target.simpleserial_write("M", bytearray([]))

        scope_timeout = bool(scope.capture())
        row["scope_timeout"] = int(scope_timeout)
        row["trigger_count"] = get_trigger_count(scope)

        resp = read_m_response(target, args.decode_timeout)

        row["elapsed_ms"] = (time.perf_counter() - t0) * 1000.0
        row["full_response_hex"] = resp["full_response_hex"]
        row["rv_hex"] = resp["rv_hex"]

        if scope_timeout:
            row["classification"] = "scope_timeout"
            if resp["valid"] and len(resp["payload"]) == M_LEN:
                m_dec = resp["payload"]
                row.update(classify_m_dec(m_host, m_dec))
            return row

        if not resp["valid"] or len(resp["payload"]) != M_LEN:
            row["classification"] = "invalid_response"
            row["error"] = (
                f"valid={resp['valid']}, payload_len={len(resp['payload'])}"
            )
            return row

        m_dec = resp["payload"]
        row.update(classify_m_dec(m_host, m_dec))

        return row

    except Exception as e:
        row["elapsed_ms"] = (time.perf_counter() - t0) * 1000.0
        row["classification"] = "timeout_or_exception"
        row["error"] = repr(e)
        return row

    finally:
        set_prep_mode(scope)


def classify_m_dec(m_host: bytes, m_dec: bytes) -> dict[str, Any]:
    bits = bit_diff_positions(m_host, m_dec)
    bytes_diff = byte_diff_positions(m_host, m_dec)

    if len(bits) == 0:
        classification = "message_correct"
    else:
        classification = "message_wrong"

    return {
        "classification": classification,
        "m_dec": m_dec,
        "m_dec_hex": m_dec.hex(),
        "m_dec_first8_hex": m_dec[:8].hex(),
        "m_match": len(bits) == 0,
        "bit_diff_count": len(bits),
        "bit_diff_positions": ";".join(str(x) for x in bits),
        "byte_diff_count": len(bytes_diff),
        "byte_diff_positions": ";".join(str(x) for x in bytes_diff),
        "first_bit_diff": bits[0] if bits else "",
    }


def make_keypair(kt: KyberTarget, run_dir: Path, keypair_id: int) -> tuple[bytes, str]:
    ret = parse_ret_only(kt.keypair())
    if ret != 0:
        raise RuntimeError(f"K command failed with ret={ret}")

    pk = to_bytes(kt.read_public_key())
    if len(pk) != PK_LEN:
        raise RuntimeError(f"unexpected pk length: {len(pk)}")

    pk_hash = sha256_hex(pk)
    (run_dir / f"pk_keypair_{keypair_id:04d}.bin").write_bytes(pk)

    return pk, pk_hash


def open_csv(path: Path) -> tuple[Any, csv.DictWriter]:
    fieldnames = [
        "trial",
        "keypair_id",
        "pk_hash",
        "classification",
        "width",
        "offset",
        "repeat",
        "ext_offset",
        "trigger_count",
        "scope_timeout",
        "elapsed_ms",
        "m_match",
        "bit_diff_count",
        "bit_diff_positions",
        "byte_diff_count",
        "byte_diff_positions",
        "first_bit_diff",
        "m_host_hex",
        "m_dec_hex",
        "m_dec_first8_hex",
        "ct_sha256",
        "ct_hex",
        "ss_host_hex",
        "coins_hex",
        "verify_status",
        "verify_m_match",
        "verify_m_dec_hex",
        "verify_error",
        "full_response_hex",
        "rv_hex",
        "error",
        "reset_after_trial",
    ]

    f = path.open("w", newline="", buffering=1)
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    return f, w


def write_summary_files(
    out_dir: Path,
    rows_written: int,
    counts: Counter[str],
    bit_counter: Counter[int],
    bit_count_counter: Counter[int],
) -> None:
    with (out_dir / "classification_summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["classification", "count", "rate"])
        for cls, cnt in counts.most_common():
            rate = cnt / rows_written if rows_written else 0.0
            w.writerow([cls, cnt, rate])

    with (out_dir / "bit_position_summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bit_index", "count"])
        for bit_i, cnt in bit_counter.most_common():
            w.writerow([bit_i, cnt])

    with (out_dir / "bit_diff_count_summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bit_diff_count", "count"])
        for k, cnt in sorted(bit_count_counter.items()):
            w.writerow([k, cnt])


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect glitched M-command decoded-message faults."
    )

    p.add_argument("--trials", type=int, default=5000)

    p.add_argument("--target-variant", default="kyber512-90s")
    p.add_argument(
        "--impl-dir",
        default="/home/ruixiang/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/crypto_kem/kyber512-90s/clean",
    )
    p.add_argument("--pqm4-root", default="../../pqm4-Round3")
    p.add_argument("--host-helper", default="")

    p.add_argument("--width", type=float, default=8.0)
    p.add_argument("--offset", type=float, default=-16.0)
    p.add_argument("--repeat", type=int, default=2)
    p.add_argument("--ext-offset", type=int, default=2402)

    p.add_argument("--platform", default="CWLITEARM")
    p.add_argument("--ss-version", default="SS_VER_2_1")
    p.add_argument("--clkgen-freq", type=float, default=7.3728e6)
    p.add_argument("--adc-samples", type=int, default=5000)
    p.add_argument("--adc-timeout", type=float, default=2.0)
    p.add_argument("--decode-timeout", type=float, default=10.0)
    p.add_argument("--glitch-output", default="clock_xor")

    p.add_argument("--out-dir", default="")
    p.add_argument("--progress-interval", type=int, default=100)

    p.add_argument("--verify-first", type=int, default=10)
    p.add_argument("--verify-every", type=int, default=500)

    p.add_argument(
        "--abort-on-verify-mismatch",
        action="store_true",
        default=True,
    )

    p.add_argument(
        "--new-key-every",
        type=int,
        default=0,
        help="Generate a new target keypair every N trials. 0 means keep one key unless reset is needed.",
    )

    p.add_argument(
        "--no-store-full-ct",
        action="store_true",
        help="Store only ct_sha256 instead of full ct_hex.",
    )

    p.add_argument(
        "--reset-after-bad",
        action="store_true",
        default=True,
    )

    p.add_argument("--reset-delay", type=float, default=0.2)

    return p


def main() -> int:
    args = build_argparser().parse_args()

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = Path("data") / "collections" / f"decoder_message_faults_{now_stamp()}"

    out_dir.mkdir(parents=True, exist_ok=True)

    helper = build_host_helper(args, out_dir)

    metadata = vars(args).copy()
    metadata.update(
        {
            "created_at": datetime.now().isoformat(),
            "script": "collect_decoder_message_faults.py",
            "mode": "host_side_ciphertext_glitched_M_decode",
            "host_helper": str(helper),
            "bit_index_definition": "bit_index = byte_index * 8 + little_endian_bit_in_byte",
            "notes": (
                "Host generates Kyber512-90s ct/ss/m/coins. "
                "Target runs glitched M command and returns decoded m_dec. "
                "The script compares m_host and m_dec to characterize decoder bit faults."
            ),
        }
    )

    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    csv_file, writer = open_csv(out_dir / "decoder_message_faults.csv")

    print(f"[+] Output directory: {out_dir}")
    print(f"[+] Host helper: {helper}")
    print(
        "[+] Glitch parameters: "
        f"width={args.width}, offset={args.offset}, "
        f"repeat={args.repeat}, ext_offset={args.ext_offset}"
    )

    scope = None
    target = None

    counts: Counter[str] = Counter()
    bit_counter: Counter[int] = Counter()
    bit_count_counter: Counter[int] = Counter()

    keypair_id = -1
    pk = b""
    pk_hash = ""
    need_keypair = True
    rows_written = 0

    try:
        scope, target = connect_scope_and_target(args)
        kt = KyberTarget(target)

        safe_recover(scope, target, args)
        configure_glitch(scope, args)

        for trial in range(1, args.trials + 1):
            reset_after_trial = False

            try:
                if need_keypair or (
                    args.new_key_every > 0 and (trial - 1) % args.new_key_every == 0
                ):
                    keypair_id += 1
                    print(f"[+] Generating keypair_id={keypair_id}")
                    set_prep_mode(scope)
                    pk, pk_hash = make_keypair(kt, out_dir, keypair_id)
                    print(f"    pk_hash={pk_hash[:16]}...")
                    need_keypair = False

                host = host_encapsulate(helper, pk)

                ct = host["ct"]
                ss_host = host["ss"]
                m_host = host["m"]
                coins = host["coins"]

                upload_ct(kt, ct)

                verify_status = "skipped"
                verify_m_match = ""
                verify_m_dec_hex = ""
                verify_error = ""

                should_verify = (
                    trial <= args.verify_first
                    or (args.verify_every > 0 and trial % args.verify_every == 0)
                )

                if should_verify:
                    verify = no_glitch_m_decode(
                        target=target,
                        scope=scope,
                        timeout=args.decode_timeout,
                    )
                    verify_status = verify["verify_status"]
                    verify_error = verify["verify_error"]

                    if verify_status == "ok":
                        verify_m_dec = verify["verify_m_dec"]
                        verify_m_dec_hex = verify_m_dec.hex()
                        verify_m_match = verify_m_dec == m_host

                        if not verify_m_match and args.abort_on_verify_mismatch:
                            raise RuntimeError("no-glitch M decoded message mismatch")
                    else:
                        if args.abort_on_verify_mismatch:
                            raise RuntimeError(
                                f"no-glitch M verify failed: {verify_status}, "
                                f"error={verify_error}"
                            )

                    # Re-upload explicitly before glitched M.
                    upload_ct(kt, ct)

                dec = glitched_m_decode(
                    scope=scope,
                    target=target,
                    m_host=m_host,
                    args=args,
                )

                classification = dec["classification"]

                if classification in {
                    "timeout_or_exception",
                    "invalid_response",
                    "scope_timeout",
                }:
                    if not ping_alive(kt):
                        classification = "crash"
                    if args.reset_after_bad:
                        reset_after_trial = True

                counts[classification] += 1

                if classification == "message_wrong":
                    bits_text = dec.get("bit_diff_positions", "")
                    if bits_text:
                        bits = [int(x) for x in bits_text.split(";") if x != ""]
                        for bit_i in bits:
                            bit_counter[bit_i] += 1

                    try:
                        bit_count_counter[int(dec.get("bit_diff_count", 0))] += 1
                    except Exception:
                        pass

                elif classification == "message_correct":
                    bit_count_counter[0] += 1

                row = {
                    "trial": trial,
                    "keypair_id": keypair_id,
                    "pk_hash": pk_hash,
                    "classification": classification,
                    "width": args.width,
                    "offset": args.offset,
                    "repeat": args.repeat,
                    "ext_offset": args.ext_offset,
                    "trigger_count": dec.get("trigger_count", ""),
                    "scope_timeout": dec.get("scope_timeout", ""),
                    "elapsed_ms": dec.get("elapsed_ms", ""),
                    "m_match": dec.get("m_match", ""),
                    "bit_diff_count": dec.get("bit_diff_count", ""),
                    "bit_diff_positions": dec.get("bit_diff_positions", ""),
                    "byte_diff_count": dec.get("byte_diff_count", ""),
                    "byte_diff_positions": dec.get("byte_diff_positions", ""),
                    "first_bit_diff": dec.get("first_bit_diff", ""),
                    "m_host_hex": m_host.hex(),
                    "m_dec_hex": dec.get("m_dec_hex", ""),
                    "m_dec_first8_hex": dec.get("m_dec_first8_hex", ""),
                    "ct_sha256": sha256_hex(ct),
                    "ct_hex": "" if args.no_store_full_ct else ct.hex(),
                    "ss_host_hex": ss_host.hex(),
                    "coins_hex": coins.hex(),
                    "verify_status": verify_status,
                    "verify_m_match": verify_m_match,
                    "verify_m_dec_hex": verify_m_dec_hex,
                    "verify_error": verify_error,
                    "full_response_hex": dec.get("full_response_hex", ""),
                    "rv_hex": dec.get("rv_hex", ""),
                    "error": dec.get("error", ""),
                    "reset_after_trial": int(reset_after_trial),
                }

                writer.writerow(row)
                rows_written += 1

                if reset_after_trial:
                    safe_recover(scope, target, args)
                    configure_glitch(scope, args)
                    need_keypair = True

            except KeyboardInterrupt:
                raise

            except Exception as e:
                counts["host_exception"] += 1

                writer.writerow(
                    {
                        "trial": trial,
                        "keypair_id": keypair_id,
                        "pk_hash": pk_hash,
                        "classification": "host_exception",
                        "width": args.width,
                        "offset": args.offset,
                        "repeat": args.repeat,
                        "ext_offset": args.ext_offset,
                        "error": repr(e),
                        "reset_after_trial": 1,
                    }
                )
                rows_written += 1

                safe_recover(scope, target, args)
                configure_glitch(scope, args)
                need_keypair = True

            if trial % args.progress_interval == 0 or trial == args.trials:
                total = sum(counts.values())
                print(f"\n===== Progress {trial}/{args.trials} =====")
                for k, v in counts.most_common():
                    print(f"{k}: {v}")
                print(f"total_recorded: {total}")

                if bit_counter:
                    print("Top bit positions:")
                    for bit_i, cnt in bit_counter.most_common(10):
                        print(f"  bit {bit_i}: {cnt}")
                print()

        write_summary_files(
            out_dir=out_dir,
            rows_written=rows_written,
            counts=counts,
            bit_counter=bit_counter,
            bit_count_counter=bit_count_counter,
        )

        print("\n===== Final summary =====")
        for k, v in counts.most_common():
            print(f"{k}: {v}")

        if bit_counter:
            print("\n===== Top bit positions =====")
            for bit_i, cnt in bit_counter.most_common(20):
                print(f"bit {bit_i}: {cnt}")

        print(f"\n[+] CSV saved to: {out_dir / 'decoder_message_faults.csv'}")
        print(f"[+] Metadata saved to: {out_dir / 'metadata.json'}")
        print(f"[+] Bit summary saved to: {out_dir / 'bit_position_summary.csv'}")

    finally:
        try:
            csv_file.close()
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