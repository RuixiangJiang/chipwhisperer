#!/usr/bin/env python3
"""Map every ext_offset (= cycle number) to the exact loop position and instruction.

ext_offset IS a cycle count: the ChipWhisperer glitch module fires the pulse
ext_offset target-clock cycles after the trigger rising edge. Because every
instruction in poly_tomsg is fixed-latency (the divide is gone), the entire
execution is a deterministic cycle-by-cycle schedule, identical on every run.
This script emits that schedule and, if given a campaign CSV, validates it.

SCHEDULE (hand-derived from the disassembly, Cortex-M4 timings)
---------------------------------------------------------------
Inner iteration, 15 cycles for j=0..6 (14 for j=7, branch not taken):

    0-1   ldrsh.w r3,[r6],#2     load, 2 cycles
    2     ldrb    r5,[r0,#0]     load right after a load -> pipelined to 1
    3     lsls    r3,r3,#1
    4     addw    r3,r3,#1665
    5     mul.w   r3,ip,r3       single-cycle multiplier
    6     ubfx    r3,r3,#28,#1
    7     lsl.w   lr,r3,r4
    8     adds    r4,#1
    9     orr.w   r5,r5,lr
    10    cmp     r4,#8
    11-12 strb    r5,[r0,#0]     store, 2 cycles
    13-14 bne.n                  taken = 1+P, P=1

Outer iteration, 125 cycles:
    0-1     preamble  strb.w r7,[r0,#1]! / add.w r6,r1,r2,lsl#1 / movs r4,#0
            (2 effective cycles: the taken bne's refill overlaps the first ones)
    2-106   inner j=0..6   (7 x 15)
    107-120 inner j=7      (14)
    121-124 epilogue  adds r2,#8 / cmp.w r2,#768 / bne.n

Iteration (i=0,j=0) starts at cycle B0 after the trigger edge. B0=10 is the unique
integer that places every precisely-located fault inside its own iteration.

VALIDATION
----------
A single-bit msg corruption pins the iteration exactly, with no timing assumption:
msg[i] |= t << j, so the flipped bit number IS j and the byte index IS i. Every
such run is therefore an independent test of the schedule. With a CSV, this script
reconstructs the reference message from the seed, identifies each corruption, and
reports how many land in the predicted (i, j) -- across ALL corrupting runs, not
just the counter-silent ones.

Examples
--------
    python3 map_cycles_to_instructions.py --schedule-only -o schedule.csv
    python3 map_cycles_to_instructions.py polytomsg_sweep_nodiv.csv -o mapped.csv
    python3 map_cycles_to_instructions.py polytomsg_sweep_nodiv.csv --scan-b0
"""

from __future__ import annotations

import argparse
import csv
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.0.0"

KYBER_Q = 3329
KYBER_SYMBYTES = 96
KYBER_N = 8 * KYBER_SYMBYTES

OUTER_CYCLES = 125
PREAMBLE_CYCLES = 2
INNER_TAKEN = 15          # j = 0..6
INNER_LAST = 14           # j = 7, branch not taken
DEFAULT_B0 = 10

# (start cycle within the inner iteration, length, mnemonic)
INNER_LAYOUT = [
    (0, 2, "ldrsh.w r3,[r6],#2"),
    (2, 1, "ldrb r5,[r0,#0]"),
    (3, 1, "lsls r3,r3,#1"),
    (4, 1, "addw r3,r3,#1665"),
    (5, 1, "mul.w r3,ip,r3"),
    (6, 1, "ubfx r3,r3,#28,#1"),
    (7, 1, "lsl.w lr,r3,r4"),
    (8, 1, "adds r4,#1"),
    (9, 1, "orr.w r5,r5,lr"),
    (10, 1, "cmp r4,#8"),
    (11, 2, "strb r5,[r0,#0]"),
    (13, 2, "bne.n (inner, taken)"),
]


def inner_instruction(off: int, j: int) -> str:
    if j == 7 and off >= 13:
        return "bne.n (inner, not taken)"
    for start, length, name in INNER_LAYOUT:
        if start <= off < start + length:
            return name
    return INNER_LAYOUT[-1][2]


def locate(ext: int, b0: int = DEFAULT_B0) -> dict:
    """Map a cycle number (ext_offset) to loop position and instruction."""
    pos = ext - b0
    if pos < 0:
        return dict(phase="before loop", i="", j="", cycle_in_iter=ext,
                    instruction="poly_tomsg prologue / trigger_high")
    i, rem = divmod(pos, OUTER_CYCLES)
    if i >= KYBER_SYMBYTES:
        return dict(phase="after loop", i="", j="", cycle_in_iter=rem,
                    instruction="poly_tomsg epilogue / trigger_low")
    if rem < PREAMBLE_CYCLES:
        return dict(phase="outer preamble", i=i, j="", cycle_in_iter=rem,
                    instruction="strb.w r7,[r0,#1]! / add.w r6 / movs r4,#0")
    inner_zone = PREAMBLE_CYCLES + 7 * INNER_TAKEN          # 2 + 105 = 107
    if rem < inner_zone:
        j, off = divmod(rem - PREAMBLE_CYCLES, INNER_TAKEN)
        return dict(phase="inner", i=i, j=j, cycle_in_iter=off,
                    instruction=inner_instruction(off, j))
    if rem < inner_zone + INNER_LAST:
        off = rem - inner_zone
        return dict(phase="inner", i=i, j=7, cycle_in_iter=off,
                    instruction=inner_instruction(off, 7))
    return dict(phase="outer epilogue", i=i, j="",
                cycle_in_iter=rem - (inner_zone + INNER_LAST),
                instruction="adds r2,#8 / cmp.w r2,#768 / bne.n")


# --------------------------------------------------------------------------
# Reference-message reconstruction (for validation)
# --------------------------------------------------------------------------

def xorshift32(seed: int):
    x = seed & 0xFFFFFFFF or 0xDEADBEEF
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        yield x


def make_coeffs(seed: int, centered: bool) -> list[int]:
    g = xorshift32(seed)
    return [((v := next(g) % KYBER_Q) - KYBER_Q // 2) if centered else next(g) % KYBER_Q
            for _ in range(KYBER_N)] if centered else [next(g) % KYBER_Q for _ in range(KYBER_N)]


def coeffs_centered(seed: int) -> list[int]:
    g = xorshift32(seed)
    return [(next(g) % KYBER_Q) - KYBER_Q // 2 for _ in range(KYBER_N)]


def coeffs_positive(seed: int) -> list[int]:
    g = xorshift32(seed)
    return [next(g) % KYBER_Q for _ in range(KYBER_N)]


def poly_tomsg(coeffs: list[int]) -> bytes:
    msg = bytearray(KYBER_SYMBYTES)
    for i in range(KYBER_SYMBYTES):
        b = 0
        for j in range(8):
            t = coeffs[8 * i + j] & 0xFFFFFFFF
            t = (t << 1) & 0xFFFFFFFF
            t = (t + 1665) & 0xFFFFFFFF
            t = (t * 80635) & 0xFFFFFFFF
            t = (t >> 28) & 1
            b |= t << j
        msg[i] = b
    return bytes(msg)


def crc(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def reference_for(seed: int, want: int):
    for fn in (coeffs_centered, coeffs_positive):
        m = poly_tomsg(fn(seed))
        if crc(m) == want:
            return m
    return None


def single_bit_index(ref: bytes) -> dict[int, tuple[int, int]]:
    """crc -> (byte, bit) for every single-bit flip of the reference message."""
    out: dict[int, tuple[int, int]] = {}
    buf = bytearray(ref)
    for i in range(len(ref)):
        for b in range(8):
            buf[i] ^= 1 << b
            out.setdefault(crc(bytes(buf)), (i, b))
            buf[i] ^= 1 << b
    return out


# --------------------------------------------------------------------------

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
    p.add_argument("csv", nargs="?", type=Path, help="campaign CSV (optional)")
    p.add_argument("-o", "--output", type=Path, default=Path("ext_to_instruction.csv"))
    p.add_argument("--b0", type=int, default=DEFAULT_B0,
                   help=f"cycle at which iteration (0,0) starts (default {DEFAULT_B0})")
    p.add_argument("--schedule-only", action="store_true",
                   help="emit the pure schedule for ext=0..--max-ext, no CSV needed")
    p.add_argument("--max-ext", type=int, default=12048)
    p.add_argument("--scan-b0", action="store_true",
                   help="test every B0 in 0..30 against the data and report match rates")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.schedule_only or args.csv is None:
        rows = []
        for ext in range(0, args.max_ext + 1):
            loc = locate(ext, args.b0)
            rows.append({"ext_offset": ext, "cycle": ext, "phase": loc["phase"],
                         "i": loc["i"], "j": loc["j"],
                         "cycle_in_iter": loc["cycle_in_iter"],
                         "instruction": loc["instruction"]})
        with args.output.open("w", newline="") as fp:
            w = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"schedule for ext 0..{args.max_ext} written to {args.output} "
              f"({len(rows)} rows, B0={args.b0})")
        hist = Counter(r["instruction"] for r in rows)
        print("\ncycles per instruction across the whole window:")
        for name, n in hist.most_common():
            print(f"  {name:<42}{n:>7}")
        return 0

    # ---- with a CSV: emit the mapping and validate ----
    with args.csv.open(newline="") as fp:
        allrows = [r for r in csv.DictReader(fp)]
    measured = [r for r in allrows if not truthy(r.get("crashed"))]

    # reference message + single-bit index per seed
    refs: dict[str, tuple[bytes, dict]] = {}
    for seed_str in sorted({str(r.get("seed")) for r in measured}):
        srows = [r for r in measured if str(r.get("seed")) == seed_str]
        modal = Counter(r["msg_crc"] for r in srows).most_common(1)[0][0]
        ref = reference_for(int(seed_str, 0), int(modal, 16))
        if ref is None:
            print(f"[warn] cannot reconstruct reference for seed {seed_str}; "
                  "validation skipped for it", file=sys.stderr)
            continue
        refs[seed_str] = (ref, single_bit_index(ref))
        print(f"seed {seed_str}: reference reconstructed, CRC {modal} verified")

    def validate(b0: int):
        hit = tot = 0
        for r in measured:
            s = str(r.get("seed"))
            if s not in refs or not truthy(r.get("any_variable_differ")):
                continue
            idx = refs[s][1].get(int(r["msg_crc"], 16))
            if idx is None:
                continue                      # not a single-bit change
            ext = to_int(r.get("ext_offset"))
            if ext is None:
                continue
            loc = locate(ext, b0)
            tot += 1
            if loc["i"] == idx[0] and loc["j"] == idx[1]:
                hit += 1
        return hit, tot

    if args.scan_b0:
        print("\nB0 scan -- fraction of single-bit corruptions landing in the "
              "predicted (i,j):")
        best = None
        for b0 in range(0, 31):
            hit, tot = validate(b0)
            if tot:
                mark = ""
                if best is None or hit > best[1]:
                    best = (b0, hit); mark = ""
                print(f"  B0={b0:>3}: {hit:>5}/{tot} ({hit/tot:>7.2%})")
        if best:
            print(f"\n  best B0 = {best[0]}")
        return 0

    hit, tot = validate(args.b0)
    if tot:
        print(f"\nVALIDATION (B0={args.b0}): {hit}/{tot} single-bit corruptions land "
              f"in the predicted (i,j) = {hit/tot:.2%}")
        print("  each of these is an independent test: the flipped bit number IS j "
              "and the byte index IS i, with no timing assumption.")

    out = []
    for r in measured:
        ext = to_int(r.get("ext_offset"))
        loc = locate(ext, args.b0) if ext is not None else {}
        s = str(r.get("seed"))
        actual_i = actual_j = match = ""
        if s in refs and truthy(r.get("any_variable_differ")):
            idx = refs[s][1].get(int(r["msg_crc"], 16))
            if idx is not None:
                actual_i, actual_j = idx
                match = "yes" if (loc.get("i") == idx[0] and loc.get("j") == idx[1]) else "no"
        out.append({
            "seed": s,
            "ext_offset": ext,
            "cycle": ext,
            "offset": r.get("offset"),
            "width": r.get("width"),
            "i": loc.get("i", ""),
            "j": loc.get("j", ""),
            "cycle_in_iter": loc.get("cycle_in_iter", ""),
            "phase": loc.get("phase", ""),
            "instruction": loc.get("instruction", ""),
            "vars_differ": r.get("any_variable_differ"),
            "dwt_differ": r.get("dwt_differ"),
            "msg_crc": r.get("msg_crc"),
            "actual_i": actual_i,
            "actual_j": actual_j,
            "predicted_matches_actual": match,
        })
    out.sort(key=lambda r: (r["seed"], r["ext_offset"] if r["ext_offset"] is not None else -1))
    with args.output.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"\nfull mapping written to {args.output} ({len(out)} rows)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
