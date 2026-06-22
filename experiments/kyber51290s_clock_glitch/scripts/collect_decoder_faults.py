#!/usr/bin/env python3
"""
Collect decoder-trigger fault data at fixed glitch parameters.

This script is different from glitch_sweep_coarse.py:
- glitch_sweep_coarse.py searches parameters.
- collect_decoder_faults.py uses one fixed parameter set and collects many trials.

Current target-side collection flow:
    K: target keypair
    E: target encapsulation, returns ss_enc and stores ct
    T: read ct from target
    C: upload the same ct back to target
    D: glitched decapsulation

The collected CSV records:
    classification, ct, ss_enc, ss_dec, trigger_count, timing, keypair_id, etc.

This is not yet the full key-recovery attack, because target-side encapsulation
does not expose r/e1/e2/Delta intermediates. It is a stability/fault-oracle
collection step before moving to host-side encapsulation.
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
from typing import Any, Optional, Tuple


# Allow running from experiments/kyber51290s_clock_glitch
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common_cw import setup_scope_and_target, recover_target, disconnect  # noqa: E402
from kyber_target import KyberTarget  # noqa: E402
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, HS2_GLITCH, DEFAULT_BAUD


SS_LEN = 32
D_RESPONSE_LEN = 33  # ret byte + 32-byte shared secret


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def b(x: Any) -> bytes:
    """Convert ChipWhisperer CWbytearray/bytearray/list/bytes to bytes."""
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
        return b(x).hex()
    except Exception:
        return ""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_ret_data(result: Any) -> Tuple[int, bytes]:
    """
    Accept several possible wrapper return formats:
      (ret, data)
      data
      {"ret": ret, "payload": data}
      {"payload": ret || data}
    """
    if isinstance(result, tuple):
        if len(result) >= 2:
            return int(result[0]), b(result[1])
        if len(result) == 1:
            data = b(result[0])
            if len(data) == SS_LEN + 1:
                return data[0], data[1:]
            return 0, data

    if isinstance(result, dict):
        if "ret" in result and "payload" in result:
            return int(result["ret"]), b(result["payload"])
        if "payload" in result:
            data = b(result["payload"])
            if len(data) == SS_LEN + 1:
                return data[0], data[1:]
            return 0, data

    data = b(result)
    if len(data) == SS_LEN + 1:
        return data[0], data[1:]
    return 0, data


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
        if "payload" in result and len(b(result["payload"])) >= 1:
            return b(result["payload"])[0]
    data = b(result)
    if len(data) >= 1:
        return data[0]
    return 0


def get_trigger_count(scope: Any) -> Optional[int]:
    for name in ("trig_count", "trigger_count"):
        try:
            value = getattr(scope.adc, name)
            if value is not None:
                return int(value)
        except Exception:
            pass
    return None


def configure_glitch(scope: Any, args: argparse.Namespace) -> None:
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = args.glitch_output
    scope.glitch.trigger_src = "manual"

    scope.glitch.width = args.width
    scope.glitch.offset = args.offset
    scope.glitch.repeat = args.repeat
    scope.glitch.ext_offset = args.ext_offset

    # Route target clock through glitch module.
    # With trigger_src="manual", no external-triggered glitch is emitted during prep.
    scope.io.hs2 = HS2_GLITCH


def set_prep_mode(scope: Any) -> None:
    scope.glitch.trigger_src = "manual"


def set_attack_mode(scope: Any, args: argparse.Namespace) -> None:
    scope.glitch.width = args.width
    scope.glitch.offset = args.offset
    scope.glitch.repeat = args.repeat
    scope.glitch.ext_offset = args.ext_offset
    scope.glitch.trigger_src = "ext_single"
    scope.io.hs2 = HS2_GLITCH


def ping_alive(kt: KyberTarget) -> bool:
    try:
        r = kt.ping()
        if isinstance(r, bool):
            return r
        return True
    except Exception:
        return False


def safe_recover(scope: Any, raw_target: Any, args: argparse.Namespace) -> None:
    try:
        recover_target(scope, raw_target, reset_delay=args.reset_delay)
    except TypeError:
        recover_target(scope, raw_target)


def make_keypair(
    kt: KyberTarget,
    run_dir: Path,
    keypair_id: int,
) -> Tuple[str, int]:
    ret = parse_ret_only(kt.keypair())
    if ret != 0:
        raise RuntimeError(f"keypair failed with ret={ret}")

    pk = b(kt.read_public_key())
    pk_hash = sha256_hex(pk)

    pk_path = run_dir / f"pk_keypair_{keypair_id:04d}.bin"
    pk_path.write_bytes(pk)

    return pk_hash, len(pk)


def prepare_ciphertext(kt: KyberTarget, upload_ct: bool) -> Tuple[bytes, bytes]:
    ret, ss_enc = parse_ret_data(kt.encapsulate_target())
    if ret != 0:
        raise RuntimeError(f"encapsulate_target failed with ret={ret}")
    if len(ss_enc) != SS_LEN:
        raise RuntimeError(f"unexpected ss_enc length: {len(ss_enc)}")

    ct = b(kt.read_ciphertext())

    if upload_ct:
        upload_ret = parse_ret_only(kt.upload_ciphertext(ct))
        if upload_ret != 0:
            raise RuntimeError(f"upload_ciphertext failed with ret={upload_ret}")

    return ct, ss_enc


def glitched_decap(
    scope: Any,
    raw_target: Any,
    expected_ss: bytes,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """
    Arm scope, send D, capture the decoder trigger, read S response.

    Returns a dictionary containing classification and raw fields.
    """
    set_attack_mode(scope, args)

    row: dict[str, Any] = {
        "classification": "",
        "d_ret": "",
        "ss_match": "",
        "ss_dec": b"",
        "trigger_count": "",
        "scope_timeout": "",
        "full_response_hex": "",
        "rv_hex": "",
        "error": "",
        "decaps_ms": "",
    }

    t0 = time.perf_counter()

    try:
        scope.arm()
        raw_target.simpleserial_write("D", bytearray([]))

        scope_timeout = bool(scope.capture())
        row["scope_timeout"] = int(scope_timeout)
        row["trigger_count"] = get_trigger_count(scope)

        resp = raw_target.simpleserial_read_witherrors(
            "S",
            D_RESPONSE_LEN,
            glitch_timeout=args.decaps_timeout,
        )

        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0

        if isinstance(resp, dict):
            row["full_response_hex"] = hex_or_empty(resp.get("full_response"))
            row["rv_hex"] = hex_or_empty(resp.get("rv"))

            valid = bool(resp.get("valid", False))
            payload = b(resp.get("payload"))
        else:
            valid = True
            payload = b(resp)

        if scope_timeout:
            row["classification"] = "scope_timeout"
            if len(payload) >= D_RESPONSE_LEN:
                row["d_ret"] = payload[0]
                row["ss_dec"] = payload[1:33]
                row["ss_match"] = row["ss_dec"] == expected_ss
            return row

        if not valid or len(payload) < D_RESPONSE_LEN:
            row["classification"] = "invalid_response"
            row["error"] = f"valid={valid}, payload_len={len(payload)}"
            return row

        d_ret = payload[0]
        ss_dec = payload[1:33]
        ss_match = ss_dec == expected_ss

        row["d_ret"] = d_ret
        row["ss_dec"] = ss_dec
        row["ss_match"] = ss_match

        if d_ret != 0:
            row["classification"] = "ret_error"
        elif ss_match:
            row["classification"] = "normal_correct"
        else:
            row["classification"] = "normal_wrong_ss"

        return row

    except Exception as e:
        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0
        row["classification"] = "timeout_or_exception"
        row["error"] = repr(e)
        return row

    finally:
        set_prep_mode(scope)


def open_csv(path: Path) -> Tuple[Any, csv.DictWriter]:
    fieldnames = [
        "trial",
        "keypair_id",
        "pk_hash",
        "classification",
        "width",
        "offset",
        "repeat",
        "ext_offset",
        "d_ret",
        "ss_match",
        "trigger_count",
        "scope_timeout",
        "decaps_ms",
        "ct_sha256",
        "ct_hex",
        "ss_enc_hex",
        "ss_dec_hex",
        "full_response_hex",
        "rv_hex",
        "error",
        "reset_after_trial",
    ]

    f = path.open("w", newline="", buffering=1)
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    return f, w


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect decoder-trigger Kyber decapsulation fault data."
    )

    p.add_argument("--trials", type=int, default=1000)

    p.add_argument("--width", type=float, default=8.0)
    p.add_argument("--offset", type=float, default=-16.0)
    p.add_argument("--repeat", type=int, default=2)
    p.add_argument("--ext-offset", type=int, default=2402)

    p.add_argument("--ss-version", default="SS_VER_2_1")
    p.add_argument("--clkgen-freq", type=float, default=CLKGEN_FREQ)
    p.add_argument("--adc-samples", type=int, default=5000)
    p.add_argument("--adc-timeout", type=float, default=2.0)
    p.add_argument("--decaps-timeout", type=float, default=10.0)
    p.add_argument("--glitch-output", default="clock_xor")

    p.add_argument("--out-dir", default="")
    p.add_argument("--progress-interval", type=int, default=50)

    p.add_argument(
        "--new-key-every",
        type=int,
        default=0,
        help="Generate a new keypair every N trials. 0 means keep the same key unless reset is needed.",
    )

    p.add_argument(
        "--no-upload-ct",
        action="store_true",
        help="Do not re-upload ct after target-side encapsulation.",
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
        help="Reset target after timeout/invalid/scope_timeout/crash-like outcomes.",
    )

    p.add_argument("--reset-delay", type=float, default=0.2)

    return p


def main() -> int:
    args = build_argparser().parse_args()

    if args.out_dir:
        run_dir = Path(args.out_dir)
    else:
        run_dir = Path("data") / "collections" / f"decoder_faults_{now_stamp()}"

    run_dir.mkdir(parents=True, exist_ok=True)

    metadata = vars(args).copy()
    metadata.update(
        {
            "created_at": datetime.now().isoformat(),
            "script": "collect_decoder_faults.py",
            "mode": "target_side_encapsulation_decoder_trigger",
            "notes": (
                "This collection records ct/ss/classification using target-side "
                "encapsulation. It validates the fault oracle but does not yet "
                "include host-side r/e1/e2/Delta intermediates for key recovery."
            ),
        }
    )
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    csv_file, writer = open_csv(run_dir / "decoder_faults.csv")

    print(f"[+] Output directory: {run_dir}")
    print(
        "[+] Glitch parameters: "
        f"width={args.width}, offset={args.offset}, "
        f"repeat={args.repeat}, ext_offset={args.ext_offset}"
    )

    scope = None
    raw_target = None

    counts: Counter[str] = Counter()
    keypair_id = -1
    pk_hash = ""
    need_keypair = True

    try:
        scope, raw_target = setup_scope_and_target(
            ss_version=args.ss_version,
            clkgen_freq=args.clkgen_freq,
            adc_samples=args.adc_samples,
            adc_timeout=args.adc_timeout,
        )
        kt = KyberTarget(raw_target)

        configure_glitch(scope, args)

        for trial in range(1, args.trials + 1):
            reset_after_trial = False

            try:
                if need_keypair or (
                    args.new_key_every > 0 and (trial - 1) % args.new_key_every == 0
                ):
                    keypair_id += 1
                    print(f"[+] Generating keypair_id={keypair_id}")
                    pk_hash, pk_len = make_keypair(kt, run_dir, keypair_id)
                    print(f"    pk_len={pk_len}, pk_hash={pk_hash[:16]}...")
                    need_keypair = False

                set_prep_mode(scope)
                ct, ss_enc = prepare_ciphertext(
                    kt,
                    upload_ct=(not args.no_upload_ct),
                )

                dec = glitched_decap(scope, raw_target, ss_enc, args)

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

                row = {
                    "trial": trial,
                    "keypair_id": keypair_id,
                    "pk_hash": pk_hash,
                    "classification": classification,
                    "width": args.width,
                    "offset": args.offset,
                    "repeat": args.repeat,
                    "ext_offset": args.ext_offset,
                    "d_ret": dec.get("d_ret", ""),
                    "ss_match": dec.get("ss_match", ""),
                    "trigger_count": dec.get("trigger_count", ""),
                    "scope_timeout": dec.get("scope_timeout", ""),
                    "decaps_ms": dec.get("decaps_ms", ""),
                    "ct_sha256": sha256_hex(ct),
                    "ct_hex": "" if args.no_store_full_ct else ct.hex(),
                    "ss_enc_hex": ss_enc.hex(),
                    "ss_dec_hex": hex_or_empty(dec.get("ss_dec")),
                    "full_response_hex": dec.get("full_response_hex", ""),
                    "rv_hex": dec.get("rv_hex", ""),
                    "error": dec.get("error", ""),
                    "reset_after_trial": int(reset_after_trial),
                }
                writer.writerow(row)

                if reset_after_trial:
                    safe_recover(scope, raw_target, args)
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
                        "d_ret": "",
                        "ss_match": "",
                        "trigger_count": "",
                        "scope_timeout": "",
                        "decaps_ms": "",
                        "ct_sha256": "",
                        "ct_hex": "",
                        "ss_enc_hex": "",
                        "ss_dec_hex": "",
                        "full_response_hex": "",
                        "rv_hex": "",
                        "error": repr(e),
                        "reset_after_trial": 1,
                    }
                )
                safe_recover(scope, raw_target, args)
                configure_glitch(scope, args)
                need_keypair = True

            if trial % args.progress_interval == 0 or trial == args.trials:
                total = sum(counts.values())
                print(f"\n===== Progress {trial}/{args.trials} =====")
                for k, v in counts.most_common():
                    print(f"{k}: {v}")
                print(f"total_recorded: {total}\n")

        print("\n===== Final summary =====")
        for k, v in counts.most_common():
            print(f"{k}: {v}")
        print(f"\n[+] CSV saved to: {run_dir / 'decoder_faults.csv'}")
        print(f"[+] Metadata saved to: {run_dir / 'metadata.json'}")

    finally:
        try:
            csv_file.close()
        except Exception:
            pass

        if scope is not None or raw_target is not None:
            try:
                disconnect(scope, raw_target)
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())