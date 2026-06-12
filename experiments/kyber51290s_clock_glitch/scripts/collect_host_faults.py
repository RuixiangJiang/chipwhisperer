#!/usr/bin/env python3
"""
Collect host-side Kyber512-90s ciphertext fault data.

Purpose:
    1. Read pk from the target.
    2. Generate a valid Kyber512-90s ciphertext on the host.
    3. Save host-side m, coins, ct, ss.
    4. Upload ct to target.
    5. Run glitched decapsulation at the decoder trigger.
    6. Classify target output as normal_correct / normal_wrong_ss / crash / etc.

This script auto-builds a small host helper from the local clean Kyber512-90s
implementation. The helper performs deterministic KEM encapsulation logic and
prints JSON containing:
    ct_hex, ss_hex, m_hex, coins_hex

The saved m and coins are enough to regenerate encryption noises r/e1/e2 later.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import inspect
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common_cw import setup_scope_and_target, recover_target, disconnect  # noqa: E402
from kyber_target import KyberTarget  # noqa: E402


PK_LEN = 800
CT_LEN = 768
SS_LEN = 32
D_RESPONSE_LEN = 33


HOST_HELPER_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "indcpa.h"
#include "symmetric.h"

#ifndef CRYPTO_PUBLICKEYBYTES
#define CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES
#endif

#ifndef CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#endif

#ifndef CRYPTO_BYTES
#define CRYPTO_BYTES KYBER_SSBYTES
#endif

#ifndef indcpa_enc
#define indcpa_enc PQCLEAN_KYBER51290S_CLEAN_indcpa_enc
#endif

static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(uint8_t *out, size_t outlen, const char *hex) {
    size_t hexlen = strlen(hex);
    if (hexlen != 2 * outlen) {
        fprintf(stderr, "bad hex length: got %zu expected %zu\n", hexlen, 2 * outlen);
        return -1;
    }

    for (size_t i = 0; i < outlen; i++) {
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "bad hex character\n");
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void print_hex(const uint8_t *x, size_t n) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar(h[x[i] >> 4]);
        putchar(h[x[i] & 15]);
    }
}

/*
 * pqm4 / Kyber code expects randombytes().
 * For host-side experiment generation, /dev/urandom is sufficient.
 */
void randombytes(uint8_t *out, size_t outlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("fopen /dev/urandom");
        exit(2);
    }
    if (fread(out, 1, outlen, f) != outlen) {
        perror("fread /dev/urandom");
        fclose(f);
        exit(2);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES];

    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t coins[KYBER_SYMBYTES];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <pk_hex>\n", argv[0]);
        return 1;
    }

    if (hex_to_bytes(pk, CRYPTO_PUBLICKEYBYTES, argv[1]) != 0) {
        return 1;
    }

    /*
     * This follows Kyber KEM encapsulation:
     *   random m
     *   m = H(m)
     *   kr = G(m || H(pk))
     *   ct = INDCPA.Enc(pk, m, coins=kr[32:64])
     *   ss = KDF(kr[0:32] || H(ct))
     *
     * Save coins before kr[32:64] is overwritten by H(ct).
     */
    randombytes(buf, KYBER_SYMBYTES);
    hash_h(buf, buf, KYBER_SYMBYTES);
    hash_h(buf + KYBER_SYMBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    memcpy(coins, kr + KYBER_SYMBYTES, KYBER_SYMBYTES);

    indcpa_enc(ct, buf, pk, coins);

    hash_h(kr + KYBER_SYMBYTES, ct, CRYPTO_CIPHERTEXTBYTES);
    kdf(ss, kr, 2 * KYBER_SYMBYTES);

    printf("{\"ct_hex\":\"");
    print_hex(ct, CRYPTO_CIPHERTEXTBYTES);
    printf("\",\"ss_hex\":\"");
    print_hex(ss, CRYPTO_BYTES);
    printf("\",\"m_hex\":\"");
    print_hex(buf, KYBER_SYMBYTES);
    printf("\",\"coins_hex\":\"");
    print_hex(coins, KYBER_SYMBYTES);
    printf("\"}\n");

    return 0;
}
'''


def assert_host_impl_matches_target_variant(impl_dir: Path, target_variant: str) -> None:
    """
    Prevent using SHAKE Kyber host helper against a Kyber-90s target.

    target_variant:
        "kyber512-90s" requires AES/SHA2-based implementation.
        "kyber512" accepts SHAKE/SHA3-based implementation.
    """
    target_variant = target_variant.lower()

    files = {p.name for p in impl_dir.glob("*")}

    has_shake = "symmetric-shake.c" in files
    has_aes90s = (
        "symmetric-aes.c" in files
        or "sha2.c" in files
        or "aes256ctr.c" in files
    )

    if target_variant in {"kyber512-90s", "90s", "kyber-90s"}:
        if has_shake and not has_aes90s:
            raise RuntimeError(
                "The selected host implementation appears to be SHAKE-based Kyber, "
                "but the target firmware is Kyber512-90s. "
                "Do not use third_party/kyber/ref for a kyber512-90s target. "
                "Please provide a host-buildable Kyber512-90s clean implementation "
                "via --impl-dir."
            )


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


def get_trigger_count(scope: Any) -> Optional[int]:
    for name in ("trig_count", "trigger_count"):
        try:
            value = getattr(scope.adc, name)
            if value is not None:
                return int(value)
        except Exception:
            pass
    return None


def connect_scope_and_target(args: argparse.Namespace):
    """
    Compatible with different local versions of common_cw.py.
    """
    candidate_kwargs = {
        "platform": args.platform,
        "target_type": args.platform,
        "platform_name": args.platform,
        "ss_version": args.ss_version,
        "ss_ver": args.ss_version,
        "clkgen_freq": args.clkgen_freq,
        "adc_samples": args.adc_samples,
        "adc_timeout": args.adc_timeout,
    }

    sig = inspect.signature(setup_scope_and_target)
    params = sig.parameters

    accepts_var_kwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )

    if accepts_var_kwargs:
        kwargs = candidate_kwargs
    else:
        kwargs = {k: v for k, v in candidate_kwargs.items() if k in params}

    print(f"[+] setup_scope_and_target signature: {sig}")
    print(f"[+] setup_scope_and_target kwargs used: {kwargs}")

    return setup_scope_and_target(**kwargs)


def safe_recover(scope: Any, raw_target: Any, args: argparse.Namespace) -> None:
    try:
        recover_target(scope, raw_target, reset_delay=args.reset_delay)
    except TypeError:
        recover_target(scope, raw_target)


def configure_glitch(scope: Any, args: argparse.Namespace) -> None:
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = args.glitch_output
    scope.glitch.trigger_src = "manual"

    scope.glitch.width = args.width
    scope.glitch.offset = args.offset
    scope.glitch.repeat = args.repeat
    scope.glitch.ext_offset = args.ext_offset

    scope.io.hs2 = "glitch"


def set_prep_mode(scope: Any) -> None:
    scope.glitch.trigger_src = "manual"


def set_attack_mode(scope: Any, args: argparse.Namespace) -> None:
    scope.glitch.width = args.width
    scope.glitch.offset = args.offset
    scope.glitch.repeat = args.repeat
    scope.glitch.ext_offset = args.ext_offset
    scope.glitch.trigger_src = "ext_single"
    scope.io.hs2 = "glitch"


def ping_alive(kt: KyberTarget) -> bool:
    try:
        kt.ping()
        return True
    except Exception:
        return False


def find_pqm4_root(default_root: str) -> Path:
    root = Path(default_root).resolve()
    if root.exists():
        return root

    candidates = [
        Path("../../pqm4-Round3").resolve(),
        Path("../../pqm4").resolve(),
        Path("~/chipwhisperer/firmware/pqm4-Round3").expanduser().resolve(),
        Path("~/chipwhisperer/firmware/pqm4").expanduser().resolve(),
    ]

    for c in candidates:
        if c.exists():
            return c

    raise FileNotFoundError(
        "Cannot find pqm4 root. Pass --pqm4-root explicitly."
    )


def find_impl_dir(pqm4_root: Path, impl_dir_arg: str) -> Path:
    """
    Find a host-buildable Kyber implementation.

    Important:
        Do NOT use pqm4 m4fstack/m4fspeed here.
        They call Cortex-M4 assembly routines such as ntt_fast,
        matacc_asm, basemul_asm, etc., and cannot be linked by host gcc.

    Use a clean/reference C implementation instead.
    """
    if impl_dir_arg:
        p = Path(impl_dir_arg).expanduser().resolve()
        if p.exists():
            print(f"[+] Using user-specified host impl_dir: {p}")
            return p
        raise FileNotFoundError(f"--impl-dir does not exist: {p}")

    candidates = [
        # Local third-party reference Kyber checkout.
        Path("third_party/kyber/ref").resolve(),
        Path("third_party/kyber512-90s/ref").resolve(),

        # Possible pqm4 clean/ref layout, if present.
        pqm4_root / "crypto_kem" / "kyber512-90s" / "clean",
        pqm4_root / "crypto_kem" / "kyber512-90s" / "ref",

        # Common external locations.
        Path("~/kyber/ref").expanduser().resolve(),
        Path("~/pq-crystals-kyber/ref").expanduser().resolve(),
    ]

    print("[+] Searching host-buildable Kyber implementation candidates:")
    for c in candidates:
        ok = (
            (c / "indcpa.c").exists()
            and (c / "api.h").exists()
            and (c / "params.h").exists()
        )
        print(f"    {c}  exists={ok}")
        if ok:
            print(f"[+] Selected host impl_dir: {c}")
            return c

    raise FileNotFoundError(
        "Cannot find a host-buildable Kyber reference implementation.\n"
        "Do not use pqm4 m4fstack/m4fspeed for host gcc builds.\n"
        "Please provide a clean/reference Kyber path with:\n"
        "    --impl-dir /path/to/kyber/ref\n"
        "For example:\n"
        "    git clone https://github.com/pq-crystals/kyber.git third_party/kyber\n"
        "    --impl-dir third_party/kyber/ref"
    )


def is_bad_common_path(p: Path) -> bool:
    s = str(p).lower()
    bad_tokens = [
        "test",
        "bench",
        "mupq",
        "hal",
        "stm32",
        "mps2",
        "uart",
        "startup",
        "objdir",
    ]
    return any(x in s for x in bad_tokens)


def unique_paths(paths: list[Path]) -> list[Path]:
    out = []
    seen = set()
    for p in paths:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out


def collect_include_dirs(impl_dir: Path, pqm4_root: Path) -> list[Path]:
    pqclean_common = pqm4_root / "mupq" / "pqclean" / "common"

    dirs = [
        impl_dir.resolve(),
        pqclean_common.resolve(),
        (pqm4_root / "common").resolve(),
    ]

    return unique_paths([d for d in dirs if d.exists()])


def find_common_source(pqm4_root: Path, name: str) -> Path | None:
    """
    Prefer pqm4_root/common/name, otherwise search recursively.
    """
    preferred = pqm4_root / "common" / name
    if preferred.exists():
        return preferred.resolve()

    matches = []
    for p in pqm4_root.rglob(name):
        if p.is_file() and not is_bad_common_path(p):
            matches.append(p.resolve())

    if not matches:
        return None

    # Prefer paths containing /common/
    matches.sort(key=lambda x: ("/common/" not in str(x), len(str(x))))
    return matches[0]


def collect_c_sources(impl_dir: Path, pqm4_root: Path) -> list[Path]:
    """
    Collect C sources from a host-buildable PQClean Kyber512-90s clean directory.

    Do not include:
        - kem.c, because the helper manually exposes m and coins.
        - randombytes.c, because the helper defines randombytes().
        - test/KAT files.
    """
    excluded_exact = {
        "kem.c",
        "randombytes.c",
        "rng.c",
        "PQCgenKAT_kem.c",
        "testvectors.c",
        "test_kyber.c",
        "test_speed.c",
        "speed_print.c",
    }

    sources: list[Path] = []

    for p in sorted(impl_dir.glob("*.c")):
        name = p.name
        low = name.lower()

        if name in excluded_exact:
            continue
        if low.startswith("test"):
            continue
        if "kat" in low:
            continue

        sources.append(p.resolve())

    pqclean_common = pqm4_root / "mupq" / "pqclean" / "common"

    for name in ["aes.c", "sha2.c"]:
        p = pqclean_common / name
        if p.exists():
            sources.append(p.resolve())
        else:
            raise FileNotFoundError(f"Required PQClean common source not found: {p}")

    sources = unique_paths(sources)

    print("[+] Host C sources selected:")
    for s in sources:
        print("   ", s)

    return sources


def build_host_helper(args: argparse.Namespace, run_dir: Path) -> Path:
    if args.host_helper:
        helper = Path(args.host_helper).resolve()
        if not helper.exists():
            raise FileNotFoundError(f"--host-helper does not exist: {helper}")
        return helper

    pqm4_root = find_pqm4_root(args.pqm4_root)
    impl_dir = find_impl_dir(pqm4_root, args.impl_dir)
    assert_host_impl_matches_target_variant(impl_dir, args.target_variant)

    helper_dir = run_dir / "host_helper_build"
    helper_dir.mkdir(parents=True, exist_ok=True)

    helper_c = helper_dir / "host_kyber51290s_debug_enc.c"
    helper_bin = helper_dir / "host_kyber51290s_debug_enc"

    helper_c.write_text(HOST_HELPER_C, encoding="utf-8")

    sources = collect_c_sources(impl_dir, pqm4_root)
    include_dirs = collect_include_dirs(impl_dir, pqm4_root)

    include_args = []
    for d in include_dirs:
        include_args += ["-I", str(d)]

    cmd = [
        "gcc",
        "-O2",
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-DKYBER_K=2",
        "-DKYBER_90S",
    ] + include_args + [
        "-o",
        str(helper_bin),
        str(helper_c),
    ] + [str(p) for p in sources]

    print("[+] include dirs:")
    for d in include_dirs:
        print("   ", d)

    print("[+] C sources:")
    for s in sources:
        print("   ", s)

    print("[+] Building host helper")
    print("[+] pqm4_root:", pqm4_root)
    print("[+] impl_dir:", impl_dir)
    print("[+] gcc command:")
    print(" ".join(cmd))

    res = subprocess.run(cmd, text=True, capture_output=True)

    (helper_dir / "build_stdout.txt").write_text(res.stdout, encoding="utf-8")
    (helper_dir / "build_stderr.txt").write_text(res.stderr, encoding="utf-8")

    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr, file=sys.stderr)
        raise RuntimeError(
            f"host helper build failed. See {helper_dir}/build_stderr.txt"
        )

    return helper_bin


def host_encapsulate(helper: Path, pk: bytes) -> dict[str, bytes]:
    res = subprocess.run(
        [str(helper), pk.hex()],
        text=True,
        capture_output=True,
    )

    if res.returncode != 0:
        raise RuntimeError(
            "host helper failed\n"
            f"stdout={res.stdout}\n"
            f"stderr={res.stderr}"
        )

    data = json.loads(res.stdout.strip())

    out = {
        "ct": bytes.fromhex(data["ct_hex"]),
        "ss": bytes.fromhex(data["ss_hex"]),
        "m": bytes.fromhex(data["m_hex"]),
        "coins": bytes.fromhex(data["coins_hex"]),
    }

    if len(out["ct"]) != CT_LEN:
        raise RuntimeError(f"bad ct length from helper: {len(out['ct'])}")
    if len(out["ss"]) != SS_LEN:
        raise RuntimeError(f"bad ss length from helper: {len(out['ss'])}")
    if len(out["m"]) != 32:
        raise RuntimeError(f"bad m length from helper: {len(out['m'])}")
    if len(out["coins"]) != 32:
        raise RuntimeError(f"bad coins length from helper: {len(out['coins'])}")

    return out


def make_keypair(kt: KyberTarget, run_dir: Path, keypair_id: int) -> Tuple[bytes, str]:
    ret = parse_ret_only(kt.keypair())
    if ret != 0:
        raise RuntimeError(f"K command failed with ret={ret}")

    pk = to_bytes(kt.read_public_key())
    if len(pk) != PK_LEN:
        raise RuntimeError(f"unexpected pk length: {len(pk)}")

    pk_hash = sha256_hex(pk)
    (run_dir / f"pk_keypair_{keypair_id:04d}.bin").write_bytes(pk)

    return pk, pk_hash


def upload_ct(kt: KyberTarget, ct: bytes) -> None:
    if len(ct) != CT_LEN:
        raise RuntimeError(f"bad ct length: {len(ct)}")

    ret = parse_ret_only(kt.upload_ciphertext(ct))
    if ret != 0:
        raise RuntimeError(f"C/upload ciphertext failed with ret={ret}")


def read_s_response(raw_target: Any, timeout: float) -> dict[str, Any]:
    resp = raw_target.simpleserial_read_witherrors(
        "S",
        D_RESPONSE_LEN,
        glitch_timeout=timeout,
    )

    if isinstance(resp, dict):
        valid = bool(resp.get("valid", False))
        payload = to_bytes(resp.get("payload"))
        return {
            "valid": valid,
            "payload": payload,
            "full_response_hex": hex_or_empty(resp.get("full_response")),
            "rv_hex": hex_or_empty(resp.get("rv")),
        }

    return {
        "valid": True,
        "payload": to_bytes(resp),
        "full_response_hex": "",
        "rv_hex": "",
    }


def no_glitch_decap(raw_target: Any, scope: Any, timeout: float) -> dict[str, Any]:
    set_prep_mode(scope)

    t0 = time.perf_counter()

    row: dict[str, Any] = {
        "classification": "",
        "d_ret": "",
        "ss_dec": b"",
        "decaps_ms": "",
        "full_response_hex": "",
        "rv_hex": "",
        "error": "",
    }

    try:
        raw_target.simpleserial_write("D", bytearray([]))
        resp = read_s_response(raw_target, timeout)
        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0
        row["full_response_hex"] = resp["full_response_hex"]
        row["rv_hex"] = resp["rv_hex"]

        payload = resp["payload"]
        if not resp["valid"] or len(payload) < D_RESPONSE_LEN:
            row["classification"] = "invalid_response"
            row["error"] = f"valid={resp['valid']}, payload_len={len(payload)}"
            return row

        row["d_ret"] = payload[0]
        row["ss_dec"] = payload[1:33]
        row["classification"] = "ok" if payload[0] == 0 else "ret_error"
        return row

    except Exception as e:
        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0
        row["classification"] = "timeout_or_exception"
        row["error"] = repr(e)
        return row


def glitched_decap(
    scope: Any,
    raw_target: Any,
    expected_ss: bytes,
    args: argparse.Namespace,
) -> dict[str, Any]:
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

        resp = read_s_response(raw_target, args.decaps_timeout)
        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0
        row["full_response_hex"] = resp["full_response_hex"]
        row["rv_hex"] = resp["rv_hex"]

        payload = resp["payload"]

        if scope_timeout:
            row["classification"] = "scope_timeout"
            if len(payload) >= D_RESPONSE_LEN:
                row["d_ret"] = payload[0]
                row["ss_dec"] = payload[1:33]
                row["ss_match"] = row["ss_dec"] == expected_ss
            return row

        if not resp["valid"] or len(payload) < D_RESPONSE_LEN:
            row["classification"] = "invalid_response"
            row["error"] = f"valid={resp['valid']}, payload_len={len(payload)}"
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
        row["classification"] = "timeout_or_exception"
        row["decaps_ms"] = (time.perf_counter() - t0) * 1000.0
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
        "ss_host_hex",
        "ss_target_hex",
        "m_hex",
        "coins_hex",
        "full_response_hex",
        "rv_hex",
        "verify_status",
        "verify_ss_match",
        "verify_error",
        "error",
        "reset_after_trial",
    ]

    f = path.open("w", newline="", buffering=1)
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    return f, w


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect host-side Kyber512-90s ciphertext fault data."
    )

    p.add_argument(
        "--target-variant",
        default="kyber512-90s",
        choices=["kyber512-90s", "kyber512"],
        help="Target algorithm variant. Must match the firmware.",
    )

    p.add_argument("--trials", type=int, default=1000)

    p.add_argument("--width", type=float, default=8.0)
    p.add_argument("--offset", type=float, default=-16.0)
    p.add_argument("--repeat", type=int, default=2)
    p.add_argument("--ext-offset", type=int, default=2402)

    p.add_argument("--platform", default="CWLITEARM")
    p.add_argument("--ss-version", default="SS_VER_2_1")
    p.add_argument("--clkgen-freq", type=float, default=7.3728e6)
    p.add_argument("--adc-samples", type=int, default=5000)
    p.add_argument("--adc-timeout", type=float, default=2.0)
    p.add_argument("--decaps-timeout", type=float, default=10.0)
    p.add_argument("--glitch-output", default="clock_xor")

    p.add_argument("--out-dir", default="")
    p.add_argument("--progress-interval", type=int, default=50)

    p.add_argument("--pqm4-root", default="../../pqm4-Round3")
    p.add_argument("--impl-dir", default="")
    p.add_argument("--host-helper", default="")

    p.add_argument(
        "--verify-first",
        type=int,
        default=10,
        help="Verify the first N host ciphertexts with no-glitch decapsulation.",
    )

    p.add_argument(
        "--verify-every",
        type=int,
        default=0,
        help="Also verify every N trials with no-glitch decapsulation. 0 disables periodic verification.",
    )

    p.add_argument(
        "--abort-on-verify-mismatch",
        action="store_true",
        default=True,
        help="Abort if host-side ss does not match no-glitch target ss.",
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
        help="Reset target after crash-like outcomes.",
    )

    p.add_argument("--reset-delay", type=float, default=0.2)

    return p


def main() -> int:
    args = build_argparser().parse_args()

    if args.out_dir:
        run_dir = Path(args.out_dir)
    else:
        run_dir = Path("data") / "collections" / f"host_faults_{now_stamp()}"

    run_dir.mkdir(parents=True, exist_ok=True)

    helper = build_host_helper(args, run_dir)

    metadata = vars(args).copy()
    metadata.update(
        {
            "created_at": datetime.now().isoformat(),
            "script": "collect_host_faults.py",
            "mode": "host_side_ciphertext_decoder_trigger",
            "host_helper": str(helper),
            "notes": (
                "Host generates valid Kyber512-90s ciphertexts and stores "
                "m/coins/ct/ss. Target performs glitched decapsulation."
            ),
        }
    )
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    csv_file, writer = open_csv(run_dir / "host_faults.csv")

    print(f"[+] Output directory: {run_dir}")
    print(f"[+] Host helper: {helper}")
    print(
        "[+] Glitch parameters: "
        f"width={args.width}, offset={args.offset}, "
        f"repeat={args.repeat}, ext_offset={args.ext_offset}"
    )

    scope = None
    raw_target = None

    counts: Counter[str] = Counter()
    keypair_id = -1
    pk = b""
    pk_hash = ""
    need_keypair = True

    try:
        scope, raw_target = connect_scope_and_target(args)
        kt = KyberTarget(raw_target)

        safe_recover(scope, raw_target, args)
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
                    pk, pk_hash = make_keypair(kt, run_dir, keypair_id)
                    print(f"    pk_hash={pk_hash[:16]}...")
                    need_keypair = False

                host = host_encapsulate(helper, pk)

                ct = host["ct"]
                ss_host = host["ss"]

                verify_status = "skipped"
                verify_ss_match = ""
                verify_error = ""

                should_verify = (
                    trial <= args.verify_first
                    or (
                        args.verify_every > 0
                        and trial % args.verify_every == 0
                    )
                )

                upload_ct(kt, ct)

                if should_verify:
                    ref = no_glitch_decap(raw_target, scope, args.decaps_timeout)
                    verify_status = ref["classification"]

                    if ref["classification"] == "ok":
                        verify_ss_match = ref["ss_dec"] == ss_host
                        if not verify_ss_match:
                            verify_error = (
                                "host ss does not match target no-glitch ss"
                            )
                            if args.abort_on_verify_mismatch:
                                raise RuntimeError(verify_error)
                    else:
                        verify_error = ref.get("error", "")
                        if args.abort_on_verify_mismatch:
                            raise RuntimeError(
                                f"no-glitch verify failed: {verify_status}, "
                                f"error={verify_error}"
                            )

                    # D does not mutate ct, but re-uploading makes the flow explicit.
                    upload_ct(kt, ct)

                dec = glitched_decap(scope, raw_target, ss_host, args)

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
                    "ss_host_hex": ss_host.hex(),
                    "ss_target_hex": hex_or_empty(dec.get("ss_dec")),
                    "m_hex": host["m"].hex(),
                    "coins_hex": host["coins"].hex(),
                    "full_response_hex": dec.get("full_response_hex", ""),
                    "rv_hex": dec.get("rv_hex", ""),
                    "verify_status": verify_status,
                    "verify_ss_match": verify_ss_match,
                    "verify_error": verify_error,
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
                        "ss_host_hex": "",
                        "ss_target_hex": "",
                        "m_hex": "",
                        "coins_hex": "",
                        "full_response_hex": "",
                        "rv_hex": "",
                        "verify_status": "",
                        "verify_ss_match": "",
                        "verify_error": "",
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

        print(f"\n[+] CSV saved to: {run_dir / 'host_faults.csv'}")
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