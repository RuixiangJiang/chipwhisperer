#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from collect_host_faults import (
    find_pqm4_root,
    find_impl_dir,
    collect_include_dirs,
    collect_c_sources,
)


HELPER_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

#ifndef polyvec_frombytes
#define polyvec_frombytes PQCLEAN_KYBER51290S_CLEAN_polyvec_frombytes
#endif

#ifndef polyvec_invntt_tomont
#define polyvec_invntt_tomont PQCLEAN_KYBER51290S_CLEAN_polyvec_invntt_tomont
#endif

#ifndef polyvec_reduce
#define polyvec_reduce PQCLEAN_KYBER51290S_CLEAN_polyvec_reduce
#endif

#ifndef KYBER_INDCPA_SECRETKEYBYTES
#define KYBER_INDCPA_SECRETKEYBYTES 768
#endif

#define MONT_INV 169

static int from_mont_centered(int x) {
    int y = (int)(((int64_t)x * MONT_INV) % KYBER_Q);
    if (y < 0) y += KYBER_Q;
    if (y > KYBER_Q / 2) y -= KYBER_Q;
    return y;
}

void randombytes(uint8_t *out, size_t outlen) {
    memset(out, 0, outlen);
}

static int centered(int x) {
    x %= KYBER_Q;
    if (x < 0) x += KYBER_Q;
    if (x > KYBER_Q / 2) x -= KYBER_Q;
    return x;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <indcpa_sk_raw.bin>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];

    size_t n = fread(sk, 1, sizeof(sk), f);
    fclose(f);

    if (n != sizeof(sk)) {
        fprintf(stderr, "bad sk length: got %zu expected %zu\n", n, sizeof(sk));
        return 1;
    }

    polyvec s;
    polyvec_frombytes(&s, sk);

    /*
     * The IND-CPA secret key is stored in NTT domain.
     * Convert it back to normal coefficient domain.
     */
    polyvec_invntt_tomont(&s);
    polyvec_reduce(&s);

    for (int poly_i = 0; poly_i < KYBER_K; poly_i++) {
        for (int j = 0; j < KYBER_N; j++) {
            if (poly_i != 0 || j != 0) {
                putchar(' ');
            }
            printf("%d", from_mont_centered(s.vec[poly_i].coeffs[j]));
        }
    }

    putchar('\n');
    return 0;
}
'''


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sk-raw", required=True, help="Path to indcpa_sk_raw.bin")
    ap.add_argument("--out-dir", default="", help="Output directory")
    ap.add_argument(
        "--impl-dir",
        default="/home/ruixiang/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/crypto_kem/kyber512-90s/clean",
    )
    ap.add_argument("--pqm4-root", default="../../pqm4-Round3")
    return ap.parse_args()


def build_helper(args, out_dir: Path) -> Path:
    pqm4_root = find_pqm4_root(args.pqm4_root)
    impl_dir = find_impl_dir(pqm4_root, args.impl_dir)

    helper_dir = out_dir / "helper_build"
    helper_dir.mkdir(parents=True, exist_ok=True)

    helper_c = helper_dir / "decode_indcpa_secret_helper.c"
    helper_bin = helper_dir / "decode_indcpa_secret_helper"

    helper_c.write_text(HELPER_C, encoding="utf-8")

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

    print("[+] Building helper:")
    print(" ".join(cmd))

    res = subprocess.run(cmd, text=True, capture_output=True)

    (helper_dir / "build_stdout.txt").write_text(res.stdout, encoding="utf-8")
    (helper_dir / "build_stderr.txt").write_text(res.stderr, encoding="utf-8")

    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr, file=sys.stderr)
        raise RuntimeError(f"helper build failed: {helper_dir / 'build_stderr.txt'}")

    return helper_bin


def main() -> int:
    args = parse_args()

    sk_raw = Path(args.sk_raw).expanduser().resolve()
    if not sk_raw.exists():
        raise FileNotFoundError(sk_raw)

    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()
    else:
        out_dir = sk_raw.parent

    out_dir.mkdir(parents=True, exist_ok=True)

    helper = build_helper(args, out_dir)

    print("[+] Decoding:", sk_raw)

    res = subprocess.run(
        [str(helper), str(sk_raw)],
        text=True,
        capture_output=True,
    )

    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr, file=sys.stderr)
        raise RuntimeError("secret decode helper failed")

    coeff_text = res.stdout.strip()
    coeffs = [int(x) for x in coeff_text.split()]

    if len(coeffs) != 512:
        raise RuntimeError(f"expected 512 coefficients, got {len(coeffs)}")

    counts = Counter(coeffs)

    out_txt = out_dir / "secret_coeffs.txt"
    out_json = out_dir / "secret_coeffs_summary.json"

    out_txt.write_text(coeff_text + "\n", encoding="utf-8")

    summary = {
        "created_at": datetime.now().isoformat(),
        "sk_raw": str(sk_raw),
        "secret_coeffs_txt": str(out_txt),
        "num_coefficients": len(coeffs),
        "min": min(coeffs),
        "max": max(coeffs),
        "counts": {str(k): counts[k] for k in sorted(counts)},
        "note": "normal-domain centered secret coefficients decoded from serialized NTT-domain IND-CPA secret key",
    }

    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n===== Secret decode summary =====")
    print(json.dumps(summary, indent=2))
    print("\n[+] Saved:", out_txt)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())