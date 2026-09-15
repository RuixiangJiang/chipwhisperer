#!/usr/bin/env python3
"""Measure the exact cycle at which every (i, j) iteration of poly_tomsg begins.

No timing model, no glitching, no fitting. The firmware's 'q' probe command runs
poly_tomsg with runtime loop bounds; running (n_outer, n_inner) executes a known
prefix, and the measured cycle count for that prefix IS the start cycle of the
next iteration. Differencing across n gives every boundary directly.

Two quantities are recorded per point:
  * DWT cyccnt  -- cycles of the probed prefix, measured by the target
  * trig_count  -- cycles the trigger was high, measured by the scope, in exactly
                   the same units and from the same origin as ext_offset

Using trig_count means the resulting table is directly comparable to ext_offset,
so the trigger-path offset (B0) is measured rather than inferred.

SWEEP
-----
  outer sweep: (n_outer = 0..96, n_inner = 8)  -> cost of each outer iteration
  inner sweep: (n_outer = 1, n_inner = 0..8)   -> cost of each inner iteration

SELF-CHECK
----------
The probe is only trustworthy if its runtime-bounded loop has the same cycle cost
as the real fixed-bound poly_tomsg. The script therefore compares the probe at
(96, 8) with the real 'g' command's cycle count and refuses to emit a table if
they disagree by more than --tolerance cycles.

Output: cycle_to_ij.csv with one row per cycle -- cycle, i, j -- covering the
whole window, plus boundaries.csv with the measured start cycle of each iteration.

Example
-------
    python3 measure_cycle_map.py
    python3 measure_cycle_map.py --seed 1 --repeats 5 -o cycle_to_ij.csv
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter
from pathlib import Path

try:
    import chipwhisperer as cw
except Exception:  # noqa: BLE001
    cw = None

PROBE_MAGIC = 0x42525048          # "HPRB"
PROBE_LEN = 20
MAIN_MAGIC = 0x33435054           # "TPC3"
MAIN_LEN = 42
KYBER_SYMBYTES = 96


def connect(program: bool, firmware: Path | None):
    if cw is None:
        raise RuntimeError("chipwhisperer not importable; run on the CW host")
    scope = cw.scope()
    scope.default_setup()
    try:
        target = cw.target(scope, cw.targets.SimpleSerial2)
    except Exception:  # noqa: BLE001
        target = cw.target(scope, cw.targets.SimpleSerial)
    if program and firmware is not None:
        cw.program_target(scope, cw.programmers.STM32FProgrammer, str(firmware))
    scope.clock.adc_src = "clkgen_x1"
    scope.adc.samples = 24000
    # No glitching here: leave hs2 on the plain clock so nothing perturbs timing.
    scope.io.nrst = "low"
    import time
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.2)
    try:
        target.reset_comms()
    except Exception:  # noqa: BLE001
        pass
    return scope, target


def _reset(target):
    for m in ("reset_comms", "flush"):
        fn = getattr(target, m, None)
        if fn:
            try:
                fn()
                return
            except Exception:  # noqa: BLE001
                continue


def probe(scope, target, seed: int, n_outer: int, n_inner: int, timeout=2000):
    """One probe run -> (cyccnt, i, j, trig_count)."""
    _reset(target)
    payload = struct.pack("<IHB", seed & 0xFFFFFFFF, n_outer, n_inner)
    scope.arm()
    target.simpleserial_write("q", payload)
    scope.capture()
    try:
        trig = int(scope.adc.trig_count)
    except Exception:  # noqa: BLE001
        trig = None
    raw = target.simpleserial_read("q", PROBE_LEN, timeout=timeout)
    if raw is None or len(raw) < PROBE_LEN:
        return None
    raw = bytes(raw)
    if struct.unpack_from("<I", raw, 0)[0] != PROBE_MAGIC:
        return None
    cyc, i, j = struct.unpack_from("<III", raw, 4)
    return cyc, i, j, trig


def main_run(scope, target, seed: int, timeout=2000):
    """One normal 'g' run -> cyccnt, for the self-check."""
    _reset(target)
    target.simpleserial_write("g", struct.pack("<IB", seed & 0xFFFFFFFF, 0))
    raw = target.simpleserial_read("r", MAIN_LEN, timeout=timeout)
    if raw is None or len(raw) < MAIN_LEN:
        return None
    raw = bytes(raw)
    if struct.unpack_from("<I", raw, 0)[0] != MAIN_MAGIC:
        return None
    return struct.unpack_from("<I", raw, 4)[0]


def median(vals):
    v = sorted(vals)
    return v[len(v) // 2]


def stable(scope, target, seed, n_outer, n_inner, repeats):
    """Repeat a probe point and require agreement.

    Also verifies that the loop bounds actually took effect: the firmware reports
    the final loop indices, so running n_outer outer iterations must return i ==
    n_outer. If it does not, the bounds were compiled away (or not parsed) and the
    whole measurement is meaningless.

    Returns (cyc, trig) or None.
    """
    cycs, trigs, idx = [], [], []
    for _ in range(repeats):
        r = probe(scope, target, seed, n_outer, n_inner)
        if r is None:
            continue
        cycs.append(r[0])
        idx.append((r[1], r[2]))
        if r[3] is not None:
            trigs.append(r[3])
    if not cycs:
        return None
    if len(set(cycs)) != 1:
        print(f"  [warn] ({n_outer},{n_inner}) cyccnt not stable: "
              f"{Counter(cycs).most_common()}", file=sys.stderr)
    got_i, got_j = idx[0]
    if got_i != n_outer:
        raise RuntimeError(
            f"probe({n_outer},{n_inner}) reports final i={got_i}, expected {n_outer}. "
            "The loop bounds are NOT taking effect -- they were most likely compiled "
            "in as constants, or the 7-byte command payload is not being parsed. "
            "Check:  arm-none-eabi-objdump -d <elf> | sed -n '/<poly_tomsg_probe>:/,"
            "/^$/p' | grep cmp\n"
            "  cmp.w r2,#768 / cmp r4,#8  -> bounds are constants (bug)\n"
            "  cmp r2,<reg>               -> bounds are live (parsing issue instead)")
    return median(cycs), (median(trigs) if trigs else None)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", type=lambda s: int(s, 0), default=1)
    p.add_argument("--repeats", type=int, default=3,
                   help="repeats per probe point (should be identical every time)")
    p.add_argument("--program", action="store_true")
    p.add_argument("--firmware", type=Path, default=None)
    p.add_argument("--tolerance", type=int, default=0,
                   help="max allowed cycle difference between probe(96,8) and the "
                        "real poly_tomsg before refusing to emit a table")
    p.add_argument("-o", "--output", type=Path, default=Path("cycle_to_ij.csv"))
    p.add_argument("--boundaries", type=Path, default=Path("iteration_boundaries.csv"))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    scope, target = connect(args.program, args.firmware)
    try:
        # ---- self-check: probe(96,8) must equal the real poly_tomsg ----
        real = main_run(scope, target, args.seed)
        full = stable(scope, target, args.seed, KYBER_SYMBYTES, 8, args.repeats)
        if real is None or full is None:
            raise RuntimeError("no response from target; is the 'q' command registered?")
        print(f"self-check: real poly_tomsg = {real} cycles, "
              f"probe(96,8) = {full[0]} cycles, delta = {full[0]-real:+d}")
        if abs(full[0] - real) > args.tolerance:
            raise RuntimeError(
                f"probe differs from the real loop by {full[0]-real:+d} cycles "
                f"(tolerance {args.tolerance}). The runtime bounds changed the "
                "loop timing, so the probe cannot be used to map the real binary. "
                "Check the disassembly of poly_tomsg_probe against poly_tomsg.")
        print("  probe is timing-identical to the real loop -- proceeding\n")

        # ---- outer sweep: cost of each outer iteration ----
        print("outer sweep (n_inner=8, n_outer=0..96):")
        outer = {}
        for k in range(0, KYBER_SYMBYTES + 1):
            r = stable(scope, target, args.seed, k, 8, args.repeats)
            if r is None:
                raise RuntimeError(f"probe failed at n_outer={k}")
            outer[k] = r
            if k % 16 == 0:
                print(f"  n_outer={k:>3}: cyccnt={r[0]:>6} trig={r[1]}")

        # ---- inner sweep: cost of each inner iteration within one outer ----
        print("\ninner sweep (n_outer=1, n_inner=0..8):")
        inner = {}
        for m in range(0, 9):
            r = stable(scope, target, args.seed, 1, m, args.repeats)
            if r is None:
                raise RuntimeError(f"probe failed at n_inner={m}")
            inner[m] = r
            print(f"  n_inner={m}: cyccnt={r[0]:>6} trig={r[1]}")
    finally:
        try:
            scope.dis()
            target.dis()
        except Exception:  # noqa: BLE001
            pass

    # ---- derive boundaries ----
    use_trig = all(v[1] is not None for v in outer.values())
    pick = (lambda v: v[1]) if use_trig else (lambda v: v[0])
    units = "trig_count (same origin as ext_offset)" if use_trig else "DWT cyccnt"
    print(f"\nbuilding table from {units}")

    outer_costs = [pick(outer[k + 1]) - pick(outer[k]) for k in range(KYBER_SYMBYTES)]
    inner_costs = [pick(inner[m + 1]) - pick(inner[m]) for m in range(8)]
    print(f"outer iteration cost: {Counter(outer_costs).most_common()}")
    print(f"inner iteration cost: {inner_costs}")

    if any(c <= 0 for c in outer_costs) or any(c <= 0 for c in inner_costs):
        raise RuntimeError(
            "measured iteration costs contain non-positive values -- the sweep did "
            "not actually vary the loop. No table written. See the bounds check above.")
    if len(set(inner_costs[:7])) != 1:
        print(f"  [warn] inner iterations j=0..6 are not uniform: {inner_costs[:7]}",
              file=sys.stderr)

    # start cycle of (i, j) = start of outer i, plus the inner prefix within it
    base_outer = [pick(outer[k]) for k in range(KYBER_SYMBYTES + 1)]
    inner_prefix = [pick(inner[m]) - pick(inner[0]) for m in range(9)]

    rows = []
    for i in range(KYBER_SYMBYTES):
        for j in range(8):
            start = base_outer[i] + inner_prefix[j]
            end = base_outer[i] + inner_prefix[j + 1] - 1
            rows.append({"i": i, "j": j, "start_cycle": start, "end_cycle": end,
                         "length": end - start + 1})
    with args.boundaries.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\niteration boundaries -> {args.boundaries} ({len(rows)} iterations)")

    # ---- expand to one row per cycle ----
    lo = min(r["start_cycle"] for r in rows)
    hi = max(r["end_cycle"] for r in rows)
    lookup = {}
    for r in rows:
        for c in range(r["start_cycle"], r["end_cycle"] + 1):
            lookup[c] = (r["i"], r["j"])
    with args.output.open("w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["cycle", "i", "j"])
        for c in range(0, hi + 1):
            i, j = lookup.get(c, ("", ""))
            w.writerow([c, i, j])
    print(f"cycle -> (i,j) table -> {args.output} (cycles 0..{hi}; "
          f"loop occupies {lo}..{hi})")
    print(f"\nB0 (first loop cycle, measured) = {lo}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
