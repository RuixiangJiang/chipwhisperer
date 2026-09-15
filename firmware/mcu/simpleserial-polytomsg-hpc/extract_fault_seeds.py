#!/usr/bin/env python3
"""Extract a reusable seed table of glitch parameters that corrupted program state.

Reads one or more per-run CSVs produced by run_polytomsg_glitch.py and emits every
(offset, width, ext_offset, repeat) combination that produced at least one run with
a differing architectural variable. The output is a compact table suitable for
re-running later: targeted replays, reproducibility checks, or as the seed set for
a focused campaign instead of another full sweep.

Points are aggregated across runs AND across input seeds, because a parameter point
that corrupts under more than one input is far more likely to be a genuine,
reproducible fault location than one that fired once by chance. The table records,
per point:

    runs              how many measured (non-crash) runs landed on this point
    var_hits          runs where >=1 architectural variable differed
    silent_hits       var_hits where the DWT tuple was IDENTICAL (counter-invisible)
    dwt_hits          runs where the DWT tuple differed (with or without var change)
    crashes           runs at this point that produced no valid response
    input_seeds_hit   how many distinct input seeds were corrupted here
    hit_rate          var_hits / runs
    vars              which variables were seen to differ (i/j/t/x/y/msg)
    msg_crcs          distinct corrupted msg checksums observed

Pathological runs (a hung target reporting a nonsense cycle count) are excluded from
the rates by default and counted separately -- see --max-cycle-factor.

Examples
--------
    python3 extract_fault_seeds.py polytomsg_sweep_nodiv.csv
    python3 extract_fault_seeds.py *.csv -o fault_seeds.csv
    python3 extract_fault_seeds.py polytomsg_sweep_nodiv.csv --silent-only
    python3 extract_fault_seeds.py polytomsg_sweep_nodiv.csv --min-seeds 2
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

VERSION = "1.0.0"
VAR_NAMES = ["i", "j", "t", "x", "y", "msg"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("inputs", nargs="+", type=Path, metavar="CSV",
                   help="per-run CSV(s) from run_polytomsg_glitch.py")
    p.add_argument("-o", "--output", type=Path, default=Path("fault_seeds.csv"),
                   help="seed table to write (default fault_seeds.csv)")
    p.add_argument("--silent-only", action="store_true",
                   help="keep only points that produced a COUNTER-INVISIBLE corruption "
                        "(vars differ while the DWT tuple matched the reference)")
    p.add_argument("--min-seeds", type=int, default=1,
                   help="only keep points corrupted under at least this many distinct "
                        "input seeds (2 = reproducible across inputs)")
    p.add_argument("--min-hits", type=int, default=1,
                   help="only keep points with at least this many corrupting runs")
    p.add_argument("--max-cycle-factor", type=float, default=3.0,
                   help="treat a run as pathological (hung target / corrupt DWT read) if "
                        "its cycle count exceeds this multiple of the modal cycle count; "
                        "0 disables the filter")
    p.add_argument("--include-pathological", action="store_true",
                   help="count pathological runs as ordinary corruptions instead of "
                        "excluding them")
    p.add_argument("--top", type=int, default=25,
                   help="how many points to print to the console (0 = all)")
    return p.parse_args()


def truthy(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def to_int(value: object):
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def load_rows(paths: list[Path]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        if not path.is_file():
            print(f"[skip] {path} not found", file=sys.stderr)
            continue
        with path.open(newline="") as fp:
            reader = csv.DictReader(fp)
            if reader.fieldnames is None or "ext_offset" not in reader.fieldnames:
                print(f"[skip] {path.name}: not a per-run CSV", file=sys.stderr)
                continue
            for row in reader:
                row["_src"] = path.name
                rows.append(row)
    if not rows:
        raise ValueError("no usable rows found in the given CSV(s)")
    return rows


def modal_cycles(rows: list[dict]) -> int | None:
    counts: dict[int, int] = defaultdict(int)
    for row in rows:
        c = to_int(row.get("cycles"))
        if c is not None:
            counts[c] += 1
    return max(counts, key=lambda k: counts[k]) if counts else None


class Point:
    __slots__ = ("runs", "var_hits", "silent_hits", "dwt_hits", "crashes",
                 "patho", "seeds_hit", "vars_seen", "crcs", "cycles_seen")

    def __init__(self) -> None:
        self.runs = 0
        self.var_hits = 0
        self.silent_hits = 0
        self.dwt_hits = 0
        self.crashes = 0
        self.patho = 0
        self.seeds_hit: set[str] = set()
        self.vars_seen: set[str] = set()
        self.crcs: set[str] = set()
        self.cycles_seen: set[int] = set()


def main() -> int:
    args = parse_args()
    rows = load_rows(args.inputs)

    base = modal_cycles(rows)
    limit = None
    if base and args.max_cycle_factor > 0:
        limit = int(base * args.max_cycle_factor)
    print(f"loaded {len(rows)} rows from {len(args.inputs)} file(s); "
          f"modal cycle count = {base}"
          + (f"; pathological threshold = >{limit} cycles" if limit else ""))

    points: dict[tuple[str, str, int, int], Point] = defaultdict(Point)

    for row in rows:
        ext = to_int(row.get("ext_offset"))
        rep = to_int(row.get("repeat")) or 1
        if ext is None:
            continue
        key = (str(row.get("offset", "")), str(row.get("width", "")), ext, rep)
        pt = points[key]

        if truthy(row.get("crashed")):
            pt.crashes += 1
            continue

        cycles = to_int(row.get("cycles"))
        is_patho = limit is not None and cycles is not None and cycles > limit
        if is_patho:
            pt.patho += 1
            if not args.include_pathological:
                continue

        pt.runs += 1
        if cycles is not None:
            pt.cycles_seen.add(cycles)

        var_differ = truthy(row.get("any_variable_differ"))
        dwt_differ = truthy(row.get("dwt_differ"))
        if dwt_differ:
            pt.dwt_hits += 1
        if var_differ:
            pt.var_hits += 1
            pt.seeds_hit.add(str(row.get("seed", "?")))
            if not dwt_differ:
                pt.silent_hits += 1
            for name in VAR_NAMES:
                if truthy(row.get(f"{name}_differ")):
                    pt.vars_seen.add(name)
            crc = str(row.get("msg_crc", "")).strip()
            if crc:
                pt.crcs.add(crc)

    # Build and filter the seed table.
    table: list[dict] = []
    for (offset, width, ext, rep), pt in points.items():
        if pt.var_hits < args.min_hits:
            continue
        if len(pt.seeds_hit) < args.min_seeds:
            continue
        if args.silent_only and pt.silent_hits == 0:
            continue
        table.append({
            "offset": offset,
            "width": width,
            "ext_offset": ext,
            "repeat": rep,
            "runs": pt.runs,
            "var_hits": pt.var_hits,
            "silent_hits": pt.silent_hits,
            "dwt_hits": pt.dwt_hits,
            "crashes": pt.crashes,
            "pathological": pt.patho,
            "input_seeds_hit": len(pt.seeds_hit),
            "hit_rate": round(pt.var_hits / pt.runs, 4) if pt.runs else "",
            "vars": "|".join(sorted(pt.vars_seen)),
            "msg_crcs": "|".join(sorted(pt.crcs)),
            "cycles_seen": "|".join(str(c) for c in sorted(pt.cycles_seen)),
        })

    if not table:
        print("\nNo parameter points matched the filters.", file=sys.stderr)
        return 2

    # Most reproducible first: seeds hit, then hits, then silent, then position.
    table.sort(key=lambda r: (-r["input_seeds_hit"], -r["var_hits"],
                              -r["silent_hits"], r["ext_offset"]))

    out = args.output
    with out.open("w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(table[0].keys()))
        writer.writeheader()
        writer.writerows(table)

    # ---- console summary ----
    tot_runs = sum(p.runs for p in points.values())
    tot_hits = sum(p.var_hits for p in points.values())
    tot_silent = sum(p.silent_hits for p in points.values())
    tot_crash = sum(p.crashes for p in points.values())
    tot_patho = sum(p.patho for p in points.values())
    multi = sum(1 for r in table if r["input_seeds_hit"] >= 2)

    print()
    print(f"measured runs            : {tot_runs}")
    print(f"crashed runs             : {tot_crash}")
    print(f"pathological runs        : {tot_patho}"
          + ("" if args.include_pathological else " (excluded from rates)"))
    print(f"corrupting runs          : {tot_hits}")
    print(f"  of which counter-silent: {tot_silent}")
    print(f"distinct parameter points: {len(points)}")
    print(f"points in seed table     : {len(table)}")
    print(f"  corrupting >=2 inputs  : {multi}   <- most reproducible")
    print(f"\nseed table written to {out}")

    n_show = len(table) if args.top == 0 else min(args.top, len(table))
    if n_show:
        print(f"\ntop {n_show} points:")
        print(f"{'ext':>8}{'offset':>9}{'width':>8}{'runs':>6}{'hits':>6}"
              f"{'silent':>8}{'seeds':>7}  vars")
        for r in table[:n_show]:
            print(f"{r['ext_offset']:>8}{r['offset']:>9}{r['width']:>8}"
                  f"{r['runs']:>6}{r['var_hits']:>6}{r['silent_hits']:>8}"
                  f"{r['input_seeds_hit']:>7}  {r['vars']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
