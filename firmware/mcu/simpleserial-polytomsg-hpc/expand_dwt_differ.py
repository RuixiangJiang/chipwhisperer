#!/usr/bin/env python3
"""Expand the "vars identical, DWT differ" rows with pipeline position and DWT deltas.

These are the runs where a glitch left every architectural variable intact but
still perturbed a hardware counter -- the false positives of a counter-based
detector. This script takes them out of the campaign CSV and adds:

  Cycle           = ext_offset (that parameter IS a cycle count from the trigger)
  i, j, Phase     nominal loop position from the Cphase=24 pipeline model
  Pipeline E/D/F  the instructions in Execute / Decode / Fetch at that phase
  Row Type        pure arithmetic/bit, other non-arithmetic, or refill
  CYC|CPI|LSU     the run's three counters, e.g. "12062|183|37"
  diff_DWT        per-counter 1=differs / 0=same vs the reference, e.g. "1|0|0"

MODEL (matches pipeline_window_table_cphase24.xlsx)
--------------------------------------------------
  Cphase = 24, outer iteration = 125 cycles, inner iteration = 15 cycles
      pos   = cycle - Cphase
      i     = pos // 125
      rem   = pos %  125
      j     = rem // 15
      Phase = rem %  15
  Inner body is 11 single-cycle instructions (phases 0..10) plus bne at phase 11;
  phases 12-14 are the taken-branch refill.

Note the loop position here is DERIVED from the cycle, because these runs produced
no corruption -- there is no flipped bit to reveal (i, j) independently. That is
the opposite of the single-bit table, where (i, j) is measured and the cycle model
is what gets tested.

The reference counter triple defaults to the modal value of each counter within
each seed (>95% of runs are clean, so the mode is the no-glitch reference); it can
be overridden with --ref.

Example
-------
    python3 expand_dwt_differ.py polytomsg_sweep_nodiv.csv
    python3 expand_dwt_differ.py polytomsg_sweep_nodiv.csv --ref 12063,183,37
    python3 expand_dwt_differ.py polytomsg_sweep_nodiv.csv -o dwt_differ.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.0.0"

CPHASE = 24
OUTER_CYCLES = 125
INNER_CYCLES = 15

# Instruction occupying each phase of the 15-cycle inner iteration.
PHASE_INSN = {
    0: "ldrsh.w r3, [r6], #2",
    1: "ldrb r5, [r0, #0]",
    2: "lsls r3, r3, #1",
    3: "add.w r3, r3, #1665",
    4: "mul.w r3, ip, r3",
    5: "ubfx r3, r3, #28, #1",
    6: "lsl.w lr, r3, r4",
    7: "adds r4, #1",
    8: "orr.w r5, r5, lr",
    9: "cmp r4, #8",
    10: "strb r5, [r0, #0]",
    11: "bne.n 8000496",
    12: "refill",
    13: "refill",
    14: "refill",
}

# After the branch at phase 11, Decode/Fetch hold the sequentially-next (wrong-path)
# instructions, which are flushed if the branch is taken.
WRONG_PATH = ["adds r2, #8 (wrong-path if taken)",
              "cmp.w r2, #768 (wrong-path if taken)"]

ARITH_PHASES = {2, 3, 4, 5, 6, 7, 8}
REFILL_PHASES = {12, 13, 14}


def pipeline_slots(phase: int) -> tuple[str, str, str]:
    """(Execute, Decode, Fetch) at this phase."""
    if phase in REFILL_PHASES:
        return ("refill", "refill", "refill")
    if phase == 11:
        return (PHASE_INSN[11], WRONG_PATH[0], WRONG_PATH[1])
    if phase == 10:
        return (PHASE_INSN[10], PHASE_INSN[11], WRONG_PATH[0])
    return (PHASE_INSN[phase], PHASE_INSN[phase + 1], PHASE_INSN[phase + 2])


def row_type(phase: int) -> str:
    if phase in REFILL_PHASES:
        return "refill"
    if phase in ARITH_PHASES:
        return "pure arithmetic/bit"
    return "other non-arithmetic"


def locate(cycle: int) -> tuple[int, int, int]:
    """cycle -> (i, j, phase) under the Cphase model."""
    pos = cycle - CPHASE
    if pos < 0:
        return (-1, -1, -1)
    i, rem = divmod(pos, OUTER_CYCLES)
    j, phase = divmod(rem, INNER_CYCLES)
    return (i, j, phase)


def truthy(v) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def to_int(v):
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("csv", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("dwt_differ_expanded.csv"))
    p.add_argument("--ref", default=None, metavar="CYC,CPI,LSU",
                   help="reference counter triple (default: modal value per seed)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    with args.csv.open(newline="") as fp:
        rows = [r for r in csv.DictReader(fp) if not truthy(r.get("crashed"))]
    if not rows:
        raise ValueError("no measured rows in CSV")
    for col in ("cycles", "cpicnt", "lsucnt", "dwt_differ", "any_variable_differ"):
        if col not in rows[0]:
            raise ValueError(f"CSV lacks the '{col}' column; re-run the campaign with "
                             "the version of run_polytomsg_glitch.py that records the "
                             "full DWT tuple")

    fixed_ref = None
    if args.ref:
        parts = [int(x) for x in args.ref.split(",")]
        if len(parts) != 3:
            raise ValueError("--ref needs three integers: CYC,CPI,LSU")
        fixed_ref = tuple(parts)

    by_seed: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_seed[str(r.get("seed"))].append(r)

    out: list[dict] = []
    for seed, srows in sorted(by_seed.items()):
        if fixed_ref:
            ref = fixed_ref
        else:
            ref = tuple(Counter(to_int(r[c]) for r in srows).most_common(1)[0][0]
                        for c in ("cycles", "cpicnt", "lsucnt"))
        print(f"seed {seed}: reference CYC|CPI|LSU = {ref[0]}|{ref[1]}|{ref[2]}"
              + ("  (given)" if fixed_ref else "  (modal)"))

        sel = [r for r in srows
               if truthy(r.get("dwt_differ")) and not truthy(r.get("any_variable_differ"))]
        print(f"  vars identical + DWT differ: {len(sel)} rows")

        for r in sel:
            cycle = to_int(r.get("ext_offset"))
            i, j, phase = locate(cycle) if cycle is not None else (-1, -1, -1)
            e, d, f = pipeline_slots(phase) if phase >= 0 else ("", "", "")
            got = (to_int(r["cycles"]), to_int(r["cpicnt"]), to_int(r["lsucnt"]))
            diff = tuple(0 if g == v else 1 for g, v in zip(got, ref))
            out.append({
                "Input Seed": seed,
                "Cycle": cycle,
                "offset": r.get("offset"),
                "width": r.get("width"),
                "i/j": f"{i}/{j}" if phase >= 0 else "",
                "i": i if phase >= 0 else "",
                "j": j if phase >= 0 else "",
                "Phase": phase if phase >= 0 else "",
                "Pipeline E": e,
                "Pipeline D": d,
                "Pipeline F": f,
                "Row Type": row_type(phase) if phase >= 0 else "before loop",
                "CYC|CPI|LSU": f"{got[0]}|{got[1]}|{got[2]}",
                "diff_DWT": f"{diff[0]}|{diff[1]}|{diff[2]}",
            })

    if not out:
        print("\nNo vars-identical / DWT-differ rows found.", file=sys.stderr)
        return 2

    out.sort(key=lambda r: (r["Input Seed"], r["Cycle"] if r["Cycle"] is not None else -1))
    with args.output.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    print(f"\n{len(out)} rows -> {args.output}")

    print("\ndiff_DWT patterns (which counters moved):")
    for pat, n in Counter(r["diff_DWT"] for r in out).most_common():
        c, p, l = pat.split("|")
        which = ", ".join(nm for nm, bit in (("CYC", c), ("CPI", p), ("LSU", l)) if bit == "1")
        print(f"  {pat}  {n:>5}   {which or 'none'}")

    print("\nRow Type of the glitched cycle:")
    for t, n in Counter(r["Row Type"] for r in out).most_common():
        print(f"  {t:<24}{n:>5}")

    print("\nPhase distribution:")
    ph = Counter(r["Phase"] for r in out)
    for phase in sorted(k for k in ph if k != ""):
        print(f"  phase {phase:>2} ({PHASE_INSN.get(phase,'?'):<22}) {ph[phase]:>5}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
