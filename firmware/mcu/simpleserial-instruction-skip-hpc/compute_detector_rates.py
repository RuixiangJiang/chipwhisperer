#!/usr/bin/env python3
"""Compute detector confusion matrices for the instruction-skip-HPC campaigns.

The detector under evaluation is:

    "the DWT cycle count differs from the instruction's no-fault baseline"

used as an alarm for "this run's architectural result was wrong".

  * condition positive  = the run produced a faulty architectural result
  * detector fires      = cycles != baseline_cycles

                          | detector fires | detector silent
    ----------------------+----------------+-----------------
    faulty result (P)     |       TP       |       FN
    correct result (N)    |       FP       |       TN

    TPR = TP / (TP + FN)      FNR = FN / (FN + TP) = 1 - TPR
    FPR = FP / (FP + TN)      TNR = TN / (TN + FP) = 1 - FPR

Only TPR and FPR are independent; the other two are their complements.

Rows whose response could not be parsed (invalid_or_reset, stale_or_corrupt,
metadata_corrupt, host_exception) carry no trustworthy cycle count and are
excluded from the matrix; they are reported separately so the exclusion stays
visible.

By default only rows from glitch phases are scored, because TPR/FPR describe how
the detector behaves while the target is under attack. Pass --include-unarmed to
add the no-fault baseline rows to the negative class as well.

DISCOVERY
---------
With --auto the script globs CSVs in the project directory and reads the
`instruction` column of each to decide what it contains, so campaigns added
later (and, or, lsl, lsr, neg, ...) are picked up with no code change. Each file
is read once: per-instruction cycle histograms are accumulated in a single pass,
then every number in the report is derived from those histograms.

Examples
--------
    python3 compute_detector_rates.py --auto
    python3 compute_detector_rates.py --auto --instruction and --instruction or
    python3 compute_detector_rates.py --auto --glob '*_long_*.csv'
    python3 compute_detector_rates.py --auto --positive any-fault --summary-csv rates.csv
    python3 compute_detector_rates.py add add_hpc_long_10h.csv
"""

from __future__ import annotations

import argparse
import csv as csv_module
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

VERSION = "2.0.0"

BASELINE_PHASES = {"baseline", "baseline_initial", "baseline_refresh"}
UNUSABLE_CLASSES = {"invalid_or_reset", "stale_or_corrupt", "metadata_corrupt", "host_exception"}
SKIP_CLASS = "target_skip_candidate"
OTHER_FAULT_CLASS = "other_fault"
NORMAL_CLASS = "normal"

WANTED_COLUMNS = ["instruction", "classification", "phase", "cycles", "parameter_source"]
REQUIRED_COLUMNS = ["instruction", "classification", "cycles"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument(
        "pairs", nargs="*", metavar="INSTRUCTION CSV",
        help="alternating instruction name and CSV path (optional; --auto finds them)",
    )
    p.add_argument("--auto", action="store_true", help="discover campaign CSVs automatically")
    p.add_argument("--project-dir", type=Path, default=Path.cwd())
    p.add_argument(
        "--glob", action="append", default=None, metavar="PATTERN",
        help="glob(s) used by --auto (default: *.csv); repeatable",
    )
    p.add_argument(
        "--instruction", action="append", default=None, metavar="NAME",
        help="only report these instructions; repeatable (default: all found)",
    )
    p.add_argument(
        "--positive", choices=["skip", "any-fault"], default="skip",
        help="condition-positive class: 'skip' = target_skip_candidate only; "
             "'any-fault' also counts other_fault",
    )
    p.add_argument("--include-unarmed", action="store_true",
                   help="also count no-fault baseline rows as negatives")
    p.add_argument("--baseline-cycles", type=int, default=None,
                   help="override the derived baseline cycle count")
    p.add_argument("--min-skips", type=int, default=1,
                   help="skip reporting an instruction with fewer than this many "
                        "target-skip rows (default 1; use 0 to report everything)")
    p.add_argument("--summary-csv", type=Path, default=None,
                   help="also write the summary table to this CSV")
    p.add_argument("--chunk-size", type=int, default=500_000)
    return p.parse_args()


class FileCounts:
    """Per-instruction cycle histograms accumulated from one CSV in a single pass."""

    def __init__(self) -> None:
        # cycles -> count, over no-fault baseline rows classified normal
        self.baseline: dict[int, int] = defaultdict(int)
        # (classification, cycles) -> count, over armed rows
        self.armed: dict[tuple[str, int], int] = defaultdict(int)
        self.unusable = 0
        self.baseline_unusable = 0


def usable_columns(path: Path) -> list[str]:
    header = pd.read_csv(path, nrows=0)
    missing = [c for c in REQUIRED_COLUMNS if c not in header.columns]
    if missing:
        raise ValueError(f"missing required column(s): {', '.join(missing)}")
    return [c for c in WANTED_COLUMNS if c in header.columns]


def baseline_mask(frame: pd.DataFrame) -> pd.Series:
    mask = pd.Series(False, index=frame.index)
    if "phase" in frame.columns:
        mask |= frame["phase"].isin(BASELINE_PHASES)
    if "parameter_source" in frame.columns:
        mask |= frame["parameter_source"] == "no_fault"
    return mask


def scan_file(path: Path, columns: list[str], chunk_size: int) -> dict[str, FileCounts]:
    """One pass over the CSV, building per-instruction histograms."""
    per_instruction: dict[str, FileCounts] = defaultdict(FileCounts)

    for chunk in pd.read_csv(path, usecols=columns, chunksize=chunk_size, low_memory=False):
        chunk["cycles"] = pd.to_numeric(chunk["cycles"], errors="coerce")
        is_base = baseline_mask(chunk)
        bad = chunk["classification"].isin(UNUSABLE_CLASSES) | chunk["cycles"].isna()

        for instruction, group in chunk.groupby("instruction", sort=False):
            if not isinstance(instruction, str):
                continue
            counts = per_instruction[instruction]
            g_base = is_base.loc[group.index]
            g_bad = bad.loc[group.index]

            counts.baseline_unusable += int((g_base & g_bad).sum())
            counts.unusable += int((~g_base & g_bad).sum())

            good_base = group[g_base & ~g_bad]
            good_base = good_base[good_base["classification"] == NORMAL_CLASS]
            if not good_base.empty:
                for cycles, n in good_base["cycles"].astype(int).value_counts().items():
                    counts.baseline[int(cycles)] += int(n)

            armed = group[~g_base & ~g_bad]
            if not armed.empty:
                pairs = armed.groupby(
                    [armed["classification"], armed["cycles"].astype(int)], sort=False
                ).size()
                for (classification, cycles), n in pairs.items():
                    counts.armed[(str(classification), int(cycles))] += int(n)

    return dict(per_instruction)


def confusion(counts: FileCounts, baseline: int, positive_mode: str,
              include_unarmed: bool) -> dict[str, int]:
    positive_classes = {SKIP_CLASS}
    scored_classes = {NORMAL_CLASS, SKIP_CLASS}
    if positive_mode == "any-fault":
        positive_classes.add(OTHER_FAULT_CLASS)
        scored_classes.add(OTHER_FAULT_CLASS)

    tp = fp = tn = fn = 0
    for (classification, cycles), n in counts.armed.items():
        if classification not in scored_classes:
            continue
        fires = cycles != baseline
        if classification in positive_classes:
            if fires:
                tp += n
            else:
                fn += n
        else:
            if fires:
                fp += n
            else:
                tn += n

    if include_unarmed:
        for cycles, n in counts.baseline.items():
            if cycles != baseline:
                fp += n
            else:
                tn += n

    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn}


def rates(cm: dict[str, int]) -> dict[str, float | None]:
    pos = cm["TP"] + cm["FN"]
    neg = cm["FP"] + cm["TN"]
    tpr = cm["TP"] / pos if pos else None
    fpr = cm["FP"] / neg if neg else None
    return {
        "TPR": tpr,
        "FNR": None if tpr is None else 1.0 - tpr,
        "FPR": fpr,
        "TNR": None if fpr is None else 1.0 - fpr,
    }


def fmt(value: float | None) -> str:
    return "    n/a" if value is None else f"{100.0 * value:7.3f}%"


def discover(args: argparse.Namespace) -> list[tuple[str | None, Path]]:
    """Return (instruction_or_None, path). None means 'score every instruction inside'."""
    found: list[tuple[str | None, Path]] = []

    if args.auto:
        patterns = args.glob or ["*.csv"]
        seen: set[Path] = set()
        for pattern in patterns:
            for path in sorted(args.project_dir.glob(pattern)):
                if path.is_file() and path not in seen:
                    seen.add(path)
                    found.append((None, path))

    if len(args.pairs) % 2 != 0:
        raise ValueError("positional arguments must alternate INSTRUCTION CSV")
    for i in range(0, len(args.pairs), 2):
        path = Path(args.pairs[i + 1])
        if not path.is_absolute():
            path = args.project_dir / path
        found.append((args.pairs[i], path))

    if not found:
        raise ValueError("nothing to score; pass INSTRUCTION CSV pairs or --auto")
    return found


def main() -> int:
    args = parse_args()
    targets = discover(args)
    wanted = set(args.instruction) if args.instruction else None

    rows: list[dict[str, object]] = []

    for only_instruction, path in targets:
        if not path.is_file():
            print(f"[skip] {path} not found", file=sys.stderr)
            continue
        try:
            columns = usable_columns(path)
        except Exception as exc:  # not a campaign CSV
            print(f"[skip] {path.name}: {exc}", file=sys.stderr)
            continue

        try:
            per_instruction = scan_file(path, columns, args.chunk_size)
        except Exception as exc:
            print(f"[skip] {path.name}: could not read ({exc})", file=sys.stderr)
            continue

        for instruction, counts in sorted(per_instruction.items()):
            if only_instruction is not None and instruction != only_instruction:
                continue
            if wanted is not None and instruction not in wanted:
                continue

            n_skip = sum(n for (cls, _), n in counts.armed.items() if cls == SKIP_CLASS)
            if n_skip < args.min_skips:
                continue

            if args.baseline_cycles is not None:
                baseline = args.baseline_cycles
            elif counts.baseline:
                baseline = max(counts.baseline, key=lambda k: counts.baseline[k])
            else:
                print(f"[skip] {path.name}:{instruction}: no no-fault baseline rows "
                      "(pass --baseline-cycles to score anyway)", file=sys.stderr)
                continue

            cm = confusion(counts, baseline, args.positive, args.include_unarmed)
            r = rates(cm)
            total = sum(cm.values())

            skip_hist = {c: n for (cls, c), n in counts.armed.items() if cls == SKIP_CLASS}
            spread = ", ".join(f"{c}:{n}" for c, n in sorted(skip_hist.items())) or "none"
            base_spread = ", ".join(f"{c}:{n}" for c, n in sorted(counts.baseline.items()))

            print(f"\n=== {instruction.upper()}  ({path.name}) ===")
            print(f"baseline cycles = {baseline}   (no-fault: {base_spread or 'none'})")
            print(f"skip cycles     = {spread}")
            print(f"scored rows = {total}   excluded as unusable = "
                  f"{counts.unusable + counts.baseline_unusable}")
            print()
            print("                       detector fires   detector silent")
            print(f"  faulty result   P    {cm['TP']:>14}   {cm['FN']:>15}")
            print(f"  correct result  N    {cm['FP']:>14}   {cm['TN']:>15}")
            print()
            print(f"  TPR = {fmt(r['TPR'])}   FNR = {fmt(r['FNR'])}")
            print(f"  FPR = {fmt(r['FPR'])}   TNR = {fmt(r['TNR'])}")

            rows.append({
                "instruction": instruction, "file": path.name, "baseline_cycles": baseline,
                "TP": cm["TP"], "FP": cm["FP"], "TN": cm["TN"], "FN": cm["FN"],
                "TPR": r["TPR"], "FPR": r["FPR"], "TNR": r["TNR"], "FNR": r["FNR"],
                "unusable": counts.unusable + counts.baseline_unusable,
            })

    if rows:
        print("\n\n=== summary ===")
        print(f"{'instruction':<12}{'base':>6}{'TPR':>10}{'FPR':>10}{'TNR':>10}{'FNR':>10}  file")
        for row in sorted(rows, key=lambda r: (str(r["instruction"]), str(r["file"]))):
            print(f"{row['instruction']:<12}{row['baseline_cycles']:>6}"
                  f"{fmt(row['TPR']):>10}{fmt(row['FPR']):>10}"
                  f"{fmt(row['TNR']):>10}{fmt(row['FNR']):>10}  {row['file']}")
    else:
        print("\nNo instruction met the reporting threshold.", file=sys.stderr)

    if args.summary_csv is not None and rows:
        out = args.summary_csv
        if not out.is_absolute():
            out = args.project_dir / out
        with out.open("w", newline="") as fp:
            writer = csv_module.DictWriter(fp, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nsummary written to {out}")

    print("\npositive class =", args.positive, "| unarmed rows",
          "included" if args.include_unarmed else "excluded")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
