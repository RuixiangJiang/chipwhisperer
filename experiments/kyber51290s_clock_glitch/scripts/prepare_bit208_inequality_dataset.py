#!/usr/bin/env python3
"""
Prepare solver-ready inequality dataset from reconstructed bit-208 intermediates.

Input:
    bit_intermediates.csv

Output:
    bit208_effective_mbit1.npz

Constraint form:
    lower <= b - A @ s + q * k <= upper

where:
    q = 3329
    lower = -832
    upper = -1
    s has 512 coefficients:
        s = [s0[0..255], s1[0..255]]
    A has shape n x 512:
        A = [a_poly0_coeffs, a_poly1_coeffs]
    b = v_centered - mu
    mu = 1665 if m_bit=1 else 0
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd


KYBER_Q = 3329
KYBER_N = 256
KYBER_K = 2
KYBER_SECRET_DIM = KYBER_N * KYBER_K
KYBER_ENCODE_ONE = 1665

# Effective skip-addition interval.
# For bit 208 with m_bit=1:
#     center(v - A*s - 1665) in [-832, -1]
LOWER = -832
UPPER = -1


def parse_coeffs(s: str) -> np.ndarray:
    if not isinstance(s, str) or not s:
        raise ValueError("empty coefficient string")
    arr = np.fromstring(s, sep=";", dtype=np.int32)
    if arr.size != KYBER_N:
        raise ValueError(f"expected {KYBER_N} coeffs, got {arr.size}")
    return arr


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Convert bit_intermediates.csv into solver-ready inequality arrays."
    )

    p.add_argument(
        "--input-csv",
        required=True,
        help="Path to bit_intermediates.csv.",
    )

    p.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: input CSV parent / inequality_dataset.",
    )

    p.add_argument(
        "--m-bit",
        type=int,
        default=1,
        choices=[0, 1],
        help="Keep only rows with this message bit. First solver attempt should use 1.",
    )

    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Limit rows for quick testing. 0 means all rows.",
    )

    p.add_argument(
        "--progress-interval",
        type=int,
        default=5000,
    )

    return p


def main() -> int:
    args = build_argparser().parse_args()

    input_csv = Path(args.input_csv).expanduser().resolve()
    if not input_csv.exists():
        raise FileNotFoundError(input_csv)

    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()
    else:
        out_dir = input_csv.parent / f"inequality_dataset_mbit{args.m_bit}"

    out_dir.mkdir(parents=True, exist_ok=True)

    print("[+] Input:", input_csv)
    print("[+] Output dir:", out_dir)

    df = pd.read_csv(input_csv)

    required = [
        "input_row",
        "trial",
        "source_classification",
        "bit_index",
        "m_bit",
        "v_centered",
        "a_poly0_coeffs",
        "a_poly1_coeffs",
    ]

    for col in required:
        if col not in df.columns:
            raise RuntimeError(f"missing required column: {col}")

    df = df[df["m_bit"] == args.m_bit].copy()

    if args.max_rows and args.max_rows > 0:
        df = df.head(args.max_rows).copy()

    df = df.reset_index(drop=True)

    n = len(df)
    print("[+] Rows after m_bit filter:", n)

    if n == 0:
        raise RuntimeError("no rows left after filtering")

    A = np.zeros((n, KYBER_SECRET_DIM), dtype=np.int16)
    b = np.zeros(n, dtype=np.int32)
    m_bit = np.full(n, args.m_bit, dtype=np.int8)
    v_centered = np.zeros(n, dtype=np.int16)
    input_rows = np.zeros(n, dtype=np.int64)

    mu = KYBER_ENCODE_ONE if args.m_bit == 1 else 0

    for i, row in df.iterrows():
        a0 = parse_coeffs(row["a_poly0_coeffs"])
        a1 = parse_coeffs(row["a_poly1_coeffs"])

        A[i, :KYBER_N] = a0.astype(np.int16)
        A[i, KYBER_N:] = a1.astype(np.int16)

        v = int(row["v_centered"])
        v_centered[i] = v
        b[i] = v - mu

        input_rows[i] = int(row["input_row"])

        if args.progress_interval and (i + 1) % args.progress_interval == 0:
            print(f"[+] Parsed {i + 1}/{n}")

    lower = np.full(n, LOWER, dtype=np.int16)
    upper = np.full(n, UPPER, dtype=np.int16)
    q = np.array([KYBER_Q], dtype=np.int32)
    secret_low = np.full(KYBER_SECRET_DIM, -3, dtype=np.int8)
    secret_high = np.full(KYBER_SECRET_DIM, 3, dtype=np.int8)

    out_npz = out_dir / f"bit208_effective_mbit{args.m_bit}.npz"

    np.savez_compressed(
        out_npz,
        A=A,
        b=b,
        lower=lower,
        upper=upper,
        q=q,
        m_bit=m_bit,
        v_centered=v_centered,
        input_rows=input_rows,
        secret_low=secret_low,
        secret_high=secret_high,
    )

    meta_cols = [
        "input_row",
        "trial",
        "source_classification",
        "ct_sha256",
        "bit_index",
        "byte_index",
        "bit_in_byte",
        "m_bit",
        "v_centered",
        "e2_centered",
        "u0_centered_at_bit",
        "u1_centered_at_bit",
    ]

    meta_cols = [c for c in meta_cols if c in df.columns]
    df[meta_cols].to_csv(out_dir / "row_metadata.csv", index=False)

    summary = {
        "created_at": datetime.now().isoformat(),
        "input_csv": str(input_csv),
        "output_npz": str(out_npz),
        "rows": int(n),
        "m_bit": int(args.m_bit),
        "q": KYBER_Q,
        "secret_dimension": KYBER_SECRET_DIM,
        "secret_coeff_range": [-3, 3],
        "constraint_form": "lower <= b - A@s + q*k <= upper",
        "lower": LOWER,
        "upper": UPPER,
        "mu": mu,
        "note": (
            "This dataset uses only effective-fault candidates. "
            "For m_bit=1, the interval corresponds to center(mp - 1665) in [-832, -1]."
        ),
    }

    (out_dir / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\n===== Dataset summary =====")
    print(json.dumps(summary, indent=2))
    print("\n[+] Saved:", out_npz)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())