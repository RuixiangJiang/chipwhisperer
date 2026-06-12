#!/usr/bin/env python3
"""
Reconstruct Kyber512-90s bit-208 intermediates from host-side fault data.

Input CSV should contain at least:
    ct_hex
    m_hex
    coins_hex
    classification

Typical input:
    data/analysis/host_faults_bit208_oracle/bit208_effective_candidates.csv

This script reconstructs, for a selected message bit index, the known row
A such that the target decoder computes approximately:

    mp[bit_index] = v_decompressed[bit_index] - A · s

where s is the secret-key polynomial vector.

The A-row is computed directly from decompressed ciphertext u. This matches the
target-side decapsulation input more directly than reconstructing pre-compression
values.

Bit indexing:
    bit_index = byte_index * 8 + bit_in_byte
    bit_in_byte is little-endian.
    bit 208 = msg[26] bit 0.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from collect_host_faults import (  # noqa: E402
    find_pqm4_root,
    find_impl_dir,
    collect_include_dirs,
    collect_c_sources,
)


BIT_INTERMEDIATE_HELPER_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

#ifndef polyvec_decompress
#define polyvec_decompress PQCLEAN_KYBER51290S_CLEAN_polyvec_decompress
#endif

#ifndef poly_decompress
#define poly_decompress PQCLEAN_KYBER51290S_CLEAN_poly_decompress
#endif

#ifndef poly_getnoise_eta1
#define poly_getnoise_eta1 PQCLEAN_KYBER51290S_CLEAN_poly_getnoise_eta1
#endif

#ifndef poly_getnoise_eta2
#define poly_getnoise_eta2 PQCLEAN_KYBER51290S_CLEAN_poly_getnoise_eta2
#endif

#ifndef KYBER_PUBLICKEYBYTES
#define KYBER_PUBLICKEYBYTES 800
#endif

#ifndef KYBER_CIPHERTEXTBYTES
#define KYBER_CIPHERTEXTBYTES 768
#endif

#ifndef KYBER_SYMBYTES
#define KYBER_SYMBYTES 32
#endif

/*
 * Satisfy possible unused references from linked implementation files.
 * This helper does not call indcpa_keypair().
 */
void randombytes(uint8_t *out, size_t outlen) {
    memset(out, 0, outlen);
}

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
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            fprintf(stderr, "bad hex character\n");
            return -1;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int centered(int x) {
    x %= KYBER_Q;
    if (x < 0) {
        x += KYBER_Q;
    }
    if (x > KYBER_Q / 2) {
        x -= KYBER_Q;
    }
    return x;
}

/*
 * Coefficient of s_t in coeff_idx of s(x) * u(x) mod (x^256 + 1).
 *
 * coeff_idx of product:
 *   sum_{t=0}^{coeff_idx} s[t] * u[coeff_idx - t]
 * - sum_{t=coeff_idx+1}^{255} s[t] * u[256 + coeff_idx - t]
 */
static int a_coeff_for_secret_index(const poly *u, int coeff_idx, int s_idx) {
    int pos;
    int val;

    if (s_idx <= coeff_idx) {
        pos = coeff_idx - s_idx;
        val = centered(u->coeffs[pos]);
    } else {
        pos = KYBER_N + coeff_idx - s_idx;
        val = -centered(u->coeffs[pos]);
    }

    return val;
}

static void print_poly_centered(const poly *p) {
    for (int i = 0; i < KYBER_N; i++) {
        if (i) putchar(';');
        printf("%d", centered(p->coeffs[i]));
    }
}

static void print_a_row_for_poly(const poly *u, int coeff_idx) {
    for (int s_idx = 0; s_idx < KYBER_N; s_idx++) {
        if (s_idx) putchar(';');
        printf("%d", a_coeff_for_secret_index(u, coeff_idx, s_idx));
    }
}

static int split_tabs(char *line, char **fields, int max_fields) {
    int count = 0;
    char *p = line;

    while (count < max_fields) {
        fields[count++] = p;

        char *tab = strchr(p, '\t');
        if (!tab) {
            break;
        }

        *tab = '\0';
        p = tab + 1;
    }

    return count;
}

static void strip_newline(char *s) {
    size_t n = strlen(s);

    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <bit_index> <store_a_row> <store_noise_vectors> <copy_input_hex>\n", argv[0]);
        return 1;
    }

    int bit_index = atoi(argv[1]);
    int store_a_row = atoi(argv[2]);
    int store_noise_vectors = atoi(argv[3]);
    int copy_input_hex = atoi(argv[4]);

    if (bit_index < 0 || bit_index >= KYBER_N) {
        fprintf(stderr, "bit_index must be in [0, 255]\n");
        return 1;
    }

    int byte_index = bit_index / 8;
    int bit_in_byte = bit_index % 8;

    char line[4096];

    while (fgets(line, sizeof(line), stdin)) {
        strip_newline(line);

        if (line[0] == '\0') {
            continue;
        }

        /*
         * Input TSV fields:
         *   0 input_row
         *   1 trial
         *   2 source_classification
         *   3 ct_sha256
         *   4 ct_hex
         *   5 m_hex
         *   6 coins_hex
         */
        char *fields[8] = {0};
        int nf = split_tabs(line, fields, 8);

        if (nf < 7) {
            fprintf(stderr, "bad input line: expected 7 fields, got %d\n", nf);
            continue;
        }

        const char *input_row = fields[0];
        const char *trial = fields[1];
        const char *source_classification = fields[2];
        const char *ct_sha256 = fields[3];
        const char *ct_hex = fields[4];
        const char *m_hex = fields[5];
        const char *coins_hex = fields[6];

        uint8_t ct[KYBER_CIPHERTEXTBYTES];
        uint8_t m[KYBER_SYMBYTES];
        uint8_t coins[KYBER_SYMBYTES];

        if (hex_to_bytes(ct, KYBER_CIPHERTEXTBYTES, ct_hex) != 0) {
            fprintf(stderr, "failed to parse ct_hex for input_row=%s\n", input_row);
            continue;
        }

        if (hex_to_bytes(m, KYBER_SYMBYTES, m_hex) != 0) {
            fprintf(stderr, "failed to parse m_hex for input_row=%s\n", input_row);
            continue;
        }

        if (hex_to_bytes(coins, KYBER_SYMBYTES, coins_hex) != 0) {
            fprintf(stderr, "failed to parse coins_hex for input_row=%s\n", input_row);
            continue;
        }

        polyvec u;
        poly v;

        polyvec_decompress(&u, ct);
        poly_decompress(&v, ct + KYBER_POLYVECCOMPRESSEDBYTES);

        polyvec r;
        polyvec e1;
        poly e2;

        uint8_t nonce = 0;

        for (int i = 0; i < KYBER_K; i++) {
            poly_getnoise_eta1(&r.vec[i], coins, nonce++);
        }

        for (int i = 0; i < KYBER_K; i++) {
            poly_getnoise_eta2(&e1.vec[i], coins, nonce++);
        }

        poly_getnoise_eta2(&e2, coins, nonce++);

        int m_bit = (m[byte_index] >> bit_in_byte) & 1;

        int v_modq = v.coeffs[bit_index];
        int v_ctr = centered(v_modq);
        int e2_ctr = centered(e2.coeffs[bit_index]);

        int u0_ctr = centered(u.vec[0].coeffs[bit_index]);
        int u1_ctr = centered(u.vec[1].coeffs[bit_index]);

        printf("%s\t%s\t%s\t%s\t", input_row, trial, source_classification, ct_sha256);
        printf("%d\t%d\t%d\t", bit_index, byte_index, bit_in_byte);
        printf("%d\t%d\t%d\t%d\t%d\t", m_bit, v_modq, v_ctr, e2_ctr, u0_ctr);
        printf("%d\t", u1_ctr);

        if (store_a_row) {
            print_a_row_for_poly(&u.vec[0], bit_index);
        }
        printf("\t");

        if (store_a_row) {
            print_a_row_for_poly(&u.vec[1], bit_index);
        }
        printf("\t");

        if (store_noise_vectors) {
            print_poly_centered(&r.vec[0]);
        }
        printf("\t");

        if (store_noise_vectors) {
            print_poly_centered(&r.vec[1]);
        }
        printf("\t");

        if (store_noise_vectors) {
            print_poly_centered(&e1.vec[0]);
        }
        printf("\t");

        if (store_noise_vectors) {
            print_poly_centered(&e1.vec[1]);
        }
        printf("\t");

        if (copy_input_hex) {
            printf("%s", m_hex);
        }
        printf("\t");

        if (copy_input_hex) {
            printf("%s", coins_hex);
        }
        printf("\t");

        if (copy_input_hex) {
            printf("%s", ct_hex);
        }

        printf("\n");
        fflush(stdout);
    }

    return 0;
}
'''


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reconstruct bit-208 Kyber intermediates from host-side fault CSV."
    )

    p.add_argument(
        "--input-csv",
        default="data/analysis/host_faults_bit208_oracle/bit208_effective_candidates.csv",
        help="Input CSV with ct_hex, m_hex, coins_hex.",
    )

    p.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: data/analysis/reconstructed_bit208_<timestamp>",
    )

    p.add_argument(
        "--bit-index",
        type=int,
        default=208,
        help="Message bit / coefficient index to reconstruct.",
    )

    p.add_argument(
        "--classification-filter",
        default="",
        help="Optional comma-separated classifications to keep, e.g. normal_wrong_ss,message_wrong.",
    )

    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Limit number of rows. 0 means no limit.",
    )

    p.add_argument(
        "--store-a-row",
        action="store_true",
        default=True,
        help="Store A-row coefficients for both secret polynomials.",
    )

    p.add_argument(
        "--no-store-a-row",
        action="store_false",
        dest="store_a_row",
        help="Do not store A-row coefficients.",
    )

    p.add_argument(
        "--store-noise-vectors",
        action="store_true",
        help="Also store r and e1 full coefficient vectors. This increases output size.",
    )

    p.add_argument(
        "--copy-input-hex",
        action="store_true",
        help="Copy m_hex, coins_hex, and ct_hex into output. This increases output size.",
    )

    p.add_argument(
        "--target-variant",
        default="kyber512-90s",
        help="Kept for compatibility with collect_host_faults helpers.",
    )

    p.add_argument(
        "--impl-dir",
        default="/home/ruixiang/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/crypto_kem/kyber512-90s/clean",
        help="PQClean Kyber512-90s clean implementation directory.",
    )

    p.add_argument(
        "--pqm4-root",
        default="../../pqm4-Round3",
        help="pqm4 root directory.",
    )

    p.add_argument(
        "--helper-bin",
        default="",
        help="Optional prebuilt helper binary.",
    )

    p.add_argument(
        "--progress-interval",
        type=int,
        default=1000,
    )

    return p


def build_intermediate_helper(args: argparse.Namespace, out_dir: Path) -> Path:
    if args.helper_bin:
        helper = Path(args.helper_bin).expanduser().resolve()
        if not helper.exists():
            raise FileNotFoundError(f"--helper-bin does not exist: {helper}")
        return helper

    pqm4_root = find_pqm4_root(args.pqm4_root)
    impl_dir = find_impl_dir(pqm4_root, args.impl_dir)

    helper_dir = out_dir / "helper_build"
    helper_dir.mkdir(parents=True, exist_ok=True)

    helper_c = helper_dir / "bit_intermediate_helper.c"
    helper_bin = helper_dir / "bit_intermediate_helper"

    helper_c.write_text(BIT_INTERMEDIATE_HELPER_C, encoding="utf-8")

    sources = collect_c_sources(impl_dir, pqm4_root)
    include_dirs = collect_include_dirs(impl_dir, pqm4_root)

    include_args: list[str] = []
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

    print("[+] Building intermediate helper")
    print("[+] pqm4_root:", pqm4_root)
    print("[+] impl_dir:", impl_dir)
    print("[+] helper:", helper_bin)
    print("[+] gcc command:")
    print(" ".join(cmd))

    res = subprocess.run(cmd, text=True, capture_output=True)

    (helper_dir / "build_stdout.txt").write_text(res.stdout, encoding="utf-8")
    (helper_dir / "build_stderr.txt").write_text(res.stderr, encoding="utf-8")

    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr, file=sys.stderr)
        raise RuntimeError(
            f"helper build failed. See {helper_dir / 'build_stderr.txt'}"
        )

    return helper_bin


def prepare_input_dataframe(args: argparse.Namespace) -> pd.DataFrame:
    input_csv = Path(args.input_csv).expanduser().resolve()

    if not input_csv.exists():
        raise FileNotFoundError(f"input CSV does not exist: {input_csv}")

    df = pd.read_csv(input_csv)

    required = ["ct_hex", "m_hex", "coins_hex"]
    for col in required:
        if col not in df.columns:
            raise RuntimeError(f"Input CSV missing required column: {col}")

    if "classification" not in df.columns:
        df["classification"] = ""

    if "trial" not in df.columns:
        if "trial_id" in df.columns:
            df["trial"] = df["trial_id"]
        else:
            df["trial"] = ""

    if "ct_sha256" not in df.columns:
        df["ct_sha256"] = ""

    if args.classification_filter:
        keep = {
            x.strip()
            for x in args.classification_filter.split(",")
            if x.strip()
        }
        df = df[df["classification"].isin(keep)].copy()

    if args.max_rows and args.max_rows > 0:
        df = df.head(args.max_rows).copy()

    df = df.reset_index(drop=False).rename(columns={"index": "input_row"})

    return df


def output_fieldnames(args: argparse.Namespace) -> list[str]:
    fields = [
        "input_row",
        "trial",
        "source_classification",
        "ct_sha256",
        "bit_index",
        "byte_index",
        "bit_in_byte",
        "m_bit",
        "v_coeff_modq",
        "v_centered",
        "e2_centered",
        "u0_centered_at_bit",
        "u1_centered_at_bit",
        "a_poly0_coeffs",
        "a_poly1_coeffs",
        "r_poly0_coeffs",
        "r_poly1_coeffs",
        "e1_poly0_coeffs",
        "e1_poly1_coeffs",
        "m_hex",
        "coins_hex",
        "ct_hex",
    ]

    return fields


def parse_helper_output_line(line: str, fields: list[str]) -> dict[str, Any]:
    parts = line.rstrip("\n").split("\t")

    if len(parts) != len(fields):
        raise RuntimeError(
            f"helper output field mismatch: got {len(parts)}, expected {len(fields)}\n"
            f"line={line[:300]}"
        )

    return dict(zip(fields, parts))


def run_reconstruction(args: argparse.Namespace, helper: Path, df: pd.DataFrame, out_dir: Path) -> None:
    output_csv = out_dir / "bit_intermediates.csv"

    fields = output_fieldnames(args)

    cmd = [
        str(helper),
        str(args.bit_index),
        "1" if args.store_a_row else "0",
        "1" if args.store_noise_vectors else "0",
        "1" if args.copy_input_hex else "0",
    ]

    print("[+] Running helper:")
    print(" ".join(cmd))
    print("[+] Output CSV:", output_csv)
    print("[+] Rows to process:", len(df))

    t0 = time.perf_counter()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    rows_written = 0
    m_bit_counts: dict[str, int] = {}

    try:
        assert proc.stdin is not None
        assert proc.stdout is not None

        with output_csv.open("w", newline="", buffering=1) as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()

            for i, row in df.iterrows():
                line = "\t".join(
                    [
                        str(row.get("input_row", "")),
                        str(row.get("trial", "")),
                        str(row.get("classification", "")),
                        str(row.get("ct_sha256", "")),
                        str(row.get("ct_hex", "")),
                        str(row.get("m_hex", "")),
                        str(row.get("coins_hex", "")),
                    ]
                ) + "\n"

                proc.stdin.write(line)
                proc.stdin.flush()

                out_line = proc.stdout.readline()
                if not out_line:
                    stderr_text = proc.stderr.read() if proc.stderr is not None else ""
                    raise RuntimeError(
                        "helper stopped producing output\n"
                        f"stderr={stderr_text}"
                    )

                out_row = parse_helper_output_line(out_line, fields)
                writer.writerow(out_row)
                rows_written += 1

                m_bit = str(out_row.get("m_bit", ""))
                m_bit_counts[m_bit] = m_bit_counts.get(m_bit, 0) + 1

                if args.progress_interval and rows_written % args.progress_interval == 0:
                    elapsed = time.perf_counter() - t0
                    rate = rows_written / elapsed if elapsed > 0 else 0.0
                    print(
                        f"[+] Progress {rows_written}/{len(df)} "
                        f"({rate:.2f} rows/s)"
                    )

        proc.stdin.close()
        ret = proc.wait(timeout=10)

        stderr_text = ""
        if proc.stderr is not None:
            stderr_text = proc.stderr.read()

        (out_dir / "helper_stderr.txt").write_text(stderr_text, encoding="utf-8")

        if ret != 0:
            raise RuntimeError(f"helper exited with code {ret}\nstderr={stderr_text}")

    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

    elapsed = time.perf_counter() - t0

    summary = {
        "rows_input": int(len(df)),
        "rows_written": int(rows_written),
        "elapsed_seconds": elapsed,
        "rows_per_second": rows_written / elapsed if elapsed > 0 else 0.0,
        "m_bit_counts": m_bit_counts,
        "output_csv": str(output_csv),
    }

    (out_dir / "reconstruction_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\n===== Reconstruction summary =====")
    print(json.dumps(summary, indent=2))


def main() -> int:
    args = build_argparser().parse_args()

    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()
    else:
        out_dir = Path("data") / "analysis" / f"reconstructed_bit{args.bit_index}_{now_stamp()}"

    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = vars(args).copy()
    metadata.update(
        {
            "created_at": datetime.now().isoformat(),
            "script": "reconstruct_bit208_intermediates.py",
            "output_definition": (
                "A-row coefficients satisfy coeff(bit_index) of s*u "
                "over Z_q[x]/(x^256+1). Target decoder computes "
                "mp_i = v_i - A*s before poly_tomsg."
            ),
            "bit_index_definition": "bit_index = byte_index * 8 + little-endian bit_in_byte",
        }
    )

    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    df = prepare_input_dataframe(args)

    print("[+] Input CSV:", Path(args.input_csv).expanduser().resolve())
    print("[+] Output dir:", out_dir)
    print("[+] Rows after filtering:", len(df))
    print("[+] bit_index:", args.bit_index)

    if len(df) == 0:
        print("[!] No rows to process.")
        return 0

    helper = build_intermediate_helper(args, out_dir)
    run_reconstruction(args, helper, df, out_dir)

    print("\n[+] Done.")
    print(f"[+] Main output: {out_dir / 'bit_intermediates.csv'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())