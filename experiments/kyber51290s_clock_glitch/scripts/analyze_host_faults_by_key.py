#!/usr/bin/env python3
"""
Analyze host-side Kyber fault collection results by keypair_id.

Input:
    data/collections/host_faults_*/host_faults.csv

Purpose:
    Fault samples from different keypair_id values correspond to different
    secret keys and must not be mixed for key-recovery analysis.

This script:
    1. Finds the latest host_faults.csv by default, or uses --csv.
    2. Prints global classification statistics.
    3. Groups results by keypair_id.
    4. Exports per-keypair summaries and fault candidates.
    5. Selects the keypair_id with the most normal_wrong_ss rows.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

import pandas as pd


DEFAULT_COLLECTION_GLOB = "data/collections/host_faults_*/host_faults.csv"


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def find_latest_csv() -> Path:
    candidates = list(Path(".").glob(DEFAULT_COLLECTION_GLOB))
    if not candidates:
        raise FileNotFoundError(
            f"No host_faults.csv found under {DEFAULT_COLLECTION_GLOB}. "
            "Pass --csv explicitly."
        )

    return max(candidates, key=lambda p: p.stat().st_mtime)


def normalize_bool_series(s: pd.Series) -> pd.Series:
    """
    Convert mixed True/False/string/empty values into nullable booleans.
    """
    def conv(x):
        if pd.isna(x):
            return pd.NA
        if isinstance(x, bool):
            return x
        text = str(x).strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        return pd.NA

    return s.map(conv)


def ensure_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for c in columns:
        if c not in df.columns:
            df[c] = pd.NA
    return df


def make_keypair_summary(df: pd.DataFrame) -> pd.DataFrame:
    required = [
        "keypair_id",
        "classification",
        "verify_status",
        "verify_ss_match",
        "pk_hash",
    ]
    df = ensure_columns(df.copy(), required)

    # Drop rows without a usable keypair_id.
    grouped_df = df.dropna(subset=["keypair_id"]).copy()
    grouped_df["keypair_id"] = grouped_df["keypair_id"].astype(int)

    classes = sorted(grouped_df["classification"].dropna().unique())

    rows = []
    for keypair_id, g in grouped_df.groupby("keypair_id", sort=True):
        row = {
            "keypair_id": keypair_id,
            "total_rows": len(g),
            "pk_hash": first_nonempty(g.get("pk_hash")),
        }

        for cls in classes:
            row[cls] = int((g["classification"] == cls).sum())

        normal_correct = row.get("normal_correct", 0)
        normal_wrong_ss = row.get("normal_wrong_ss", 0)
        crash = row.get("crash", 0)
        host_exception = row.get("host_exception", 0)
        invalid_response = row.get("invalid_response", 0)

        valid_returns = normal_correct + normal_wrong_ss

        row["valid_returns"] = valid_returns
        row["normal_wrong_rate_total"] = (
            normal_wrong_ss / len(g) if len(g) else 0.0
        )
        row["normal_wrong_rate_valid"] = (
            normal_wrong_ss / valid_returns if valid_returns else 0.0
        )
        row["crash_rate_total"] = crash / len(g) if len(g) else 0.0
        row["host_exception_rate_total"] = (
            host_exception / len(g) if len(g) else 0.0
        )
        row["invalid_response_rate_total"] = (
            invalid_response / len(g) if len(g) else 0.0
        )

        # Verification statistics.
        verify_rows = g[g["verify_status"].notna() & (g["verify_status"] != "skipped")]
        row["verify_rows"] = len(verify_rows)

        if len(verify_rows) > 0 and "verify_ss_match" in verify_rows:
            vmatch = normalize_bool_series(verify_rows["verify_ss_match"])
            row["verify_match_true"] = int((vmatch == True).sum())
            row["verify_match_false"] = int((vmatch == False).sum())
        else:
            row["verify_match_true"] = 0
            row["verify_match_false"] = 0

        rows.append(row)

    out = pd.DataFrame(rows)

    if len(out) == 0:
        return out

    # Put important columns first.
    first_cols = [
        "keypair_id",
        "total_rows",
        "pk_hash",
        "normal_correct",
        "normal_wrong_ss",
        "crash",
        "host_exception",
        "invalid_response",
        "valid_returns",
        "normal_wrong_rate_total",
        "normal_wrong_rate_valid",
        "crash_rate_total",
        "verify_rows",
        "verify_match_true",
        "verify_match_false",
    ]

    ordered = [c for c in first_cols if c in out.columns]
    ordered += [c for c in out.columns if c not in ordered]

    out = out[ordered]

    out = out.sort_values(
        by=["normal_wrong_ss", "valid_returns", "crash_rate_total"],
        ascending=[False, False, True],
    ).reset_index(drop=True)

    return out


def first_nonempty(s: pd.Series | None) -> str:
    if s is None:
        return ""

    for x in s:
        if pd.isna(x):
            continue
        text = str(x)
        if text:
            return text
    return ""


def export_per_keypair_files(
    df: pd.DataFrame,
    out_dir: Path,
    min_wrong: int,
) -> None:
    per_key_dir = out_dir / "per_keypair"
    per_key_dir.mkdir(parents=True, exist_ok=True)

    if "keypair_id" not in df.columns:
        return

    d = df.dropna(subset=["keypair_id"]).copy()
    if len(d) == 0:
        return

    d["keypair_id"] = d["keypair_id"].astype(int)

    for keypair_id, g in d.groupby("keypair_id", sort=True):
        wrong = g[g["classification"] == "normal_wrong_ss"]
        if len(wrong) < min_wrong:
            continue

        key_dir = per_key_dir / f"keypair_{keypair_id:04d}"
        key_dir.mkdir(parents=True, exist_ok=True)

        g.to_csv(key_dir / "all_rows.csv", index=False)
        wrong.to_csv(key_dir / "fault_candidates.csv", index=False)

        correct = g[g["classification"] == "normal_correct"]
        correct.to_csv(key_dir / "normal_correct.csv", index=False)


def print_global_summary(df: pd.DataFrame) -> None:
    print("\n===== Global classification summary =====")
    print(df["classification"].value_counts(dropna=False).to_string())

    total = len(df)
    wrong = int((df["classification"] == "normal_wrong_ss").sum())
    correct = int((df["classification"] == "normal_correct").sum())
    crash = int((df["classification"] == "crash").sum())

    print("\n===== Global rates =====")
    print(f"total rows:              {total}")
    print(f"normal_correct:          {correct} ({correct / total:.4%})")
    print(f"normal_wrong_ss:         {wrong} ({wrong / total:.4%})")
    print(f"crash:                   {crash} ({crash / total:.4%})")

    valid = correct + wrong
    if valid:
        print(f"valid wrong rate:        {wrong / valid:.4%}")


def print_verification_summary(df: pd.DataFrame) -> None:
    if "verify_status" not in df.columns:
        return

    print("\n===== Verification status =====")
    print(df["verify_status"].value_counts(dropna=False).to_string())

    if "verify_ss_match" in df.columns:
        print("\n===== Verification ss_match =====")
        print(df["verify_ss_match"].value_counts(dropna=False).to_string())


def choose_best_keypair(summary: pd.DataFrame) -> int | None:
    if len(summary) == 0:
        return None

    if "normal_wrong_ss" not in summary.columns:
        return None

    ranked = summary.sort_values(
        by=["normal_wrong_ss", "valid_returns", "crash_rate_total"],
        ascending=[False, False, True],
    )

    best = ranked.iloc[0]

    if int(best.get("normal_wrong_ss", 0)) <= 0:
        return None

    return int(best["keypair_id"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze host-side Kyber fault data by keypair_id."
    )

    parser.add_argument(
        "--csv",
        default="",
        help="Path to host_faults.csv. If omitted, use the latest one.",
    )

    parser.add_argument(
        "--out-dir",
        default="",
        help="Output directory. If omitted, create data/analysis/host_faults_by_key_<timestamp>.",
    )

    parser.add_argument(
        "--min-wrong",
        type=int,
        default=1,
        help="Only export per-keypair directories for keypairs with at least this many normal_wrong_ss rows.",
    )

    parser.add_argument(
        "--print-rows",
        type=int,
        default=20,
        help="Number of summary rows to print.",
    )

    args = parser.parse_args()

    csv_path = Path(args.csv).resolve() if args.csv else find_latest_csv().resolve()

    if args.out_dir:
        out_dir = Path(args.out_dir).resolve()
    else:
        out_dir = Path("data") / "analysis" / f"host_faults_by_key_{now_stamp()}"

    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Input CSV:  {csv_path}")
    print(f"[+] Output dir: {out_dir}")

    df = pd.read_csv(csv_path)

    if "classification" not in df.columns:
        raise RuntimeError("Input CSV does not contain a classification column.")

    print_global_summary(df)
    print_verification_summary(df)

    classification_summary = (
        df["classification"]
        .value_counts(dropna=False)
        .rename_axis("classification")
        .reset_index(name="count")
    )
    classification_summary["rate"] = classification_summary["count"] / len(df)
    classification_summary.to_csv(out_dir / "classification_summary.csv", index=False)

    key_summary = make_keypair_summary(df)
    key_summary.to_csv(out_dir / "keypair_summary.csv", index=False)

    print("\n===== Keypair summary top rows =====")
    if len(key_summary) == 0:
        print("No keypair_id rows found.")
    else:
        print(key_summary.head(args.print_rows).to_string(index=False))

    fault_candidates = df[df["classification"] == "normal_wrong_ss"].copy()
    fault_candidates.to_csv(out_dir / "fault_candidates_all.csv", index=False)

    normal_correct = df[df["classification"] == "normal_correct"].copy()
    normal_correct.to_csv(out_dir / "normal_correct_all.csv", index=False)

    export_per_keypair_files(df, out_dir, min_wrong=args.min_wrong)

    best_keypair = choose_best_keypair(key_summary)

    if best_keypair is not None:
        print(f"\n[+] Best keypair_id by normal_wrong_ss: {best_keypair}")

        best_rows = df[df["keypair_id"] == best_keypair].copy()
        best_faults = best_rows[best_rows["classification"] == "normal_wrong_ss"].copy()
        best_correct = best_rows[best_rows["classification"] == "normal_correct"].copy()

        best_rows.to_csv(out_dir / "best_keypair_all_rows.csv", index=False)
        best_faults.to_csv(out_dir / "best_keypair_fault_candidates.csv", index=False)
        best_correct.to_csv(out_dir / "best_keypair_normal_correct.csv", index=False)

        print(f"[+] Best keypair total rows:      {len(best_rows)}")
        print(f"[+] Best keypair wrong_ss rows:   {len(best_faults)}")
        print(f"[+] Best keypair correct rows:    {len(best_correct)}")

        print("\n===== First fault candidates for best keypair =====")
        cols = [
            "trial",
            "keypair_id",
            "ct_sha256",
            "m_hex",
            "coins_hex",
            "ss_host_hex",
            "ss_target_hex",
        ]
        cols = [c for c in cols if c in best_faults.columns]
        if len(best_faults) > 0:
            print(best_faults[cols].head(10).to_string(index=False))
        else:
            print("No normal_wrong_ss rows for best keypair.")
    else:
        print("\n[!] No keypair has normal_wrong_ss rows.")

    print("\n===== Files written =====")
    for p in sorted(out_dir.rglob("*.csv")):
        print(p)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())