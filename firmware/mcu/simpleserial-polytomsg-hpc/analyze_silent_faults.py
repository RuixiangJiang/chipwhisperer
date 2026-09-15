#!/usr/bin/env python3
"""Identify exactly which msg bytes/bits were corrupted in counter-silent glitch runs.

The firmware reports msg[] as a CRC32 (to fit one SimpleSerial2 frame), so the raw
bytes are not in the CSV. They are recoverable: the reference message is fully
determined by the input seed, so this script

  1. reconstructs the reference msg[] from the seed (xorshift32 PRNG + pqm4
     poly_tomsg), and verifies it against the modal msg_crc found in the CSV;
  2. brute-forces which low-weight change reproduces each corrupted CRC --
     first every single-byte change (96 x 255), then every 2-bit flip across the
     whole buffer (~295k) if no single-byte candidate matches;
  3. reports the identified byte/bit alongside the glitch parameters that caused it.

It also predicts, from ext_offset alone, which loop iteration the pulse landed in,
and reports whether that prediction agrees with the byte the CRC search identified.
Agreement is a strong independent check that the sweep timing model is right.

By default only COUNTER-SILENT runs are analysed (an architectural variable differed
while the full DWT tuple matched the reference) -- the faults no hardware counter
could have caught. Use --all-corruptions to analyse every corrupting run.

Example
-------
    python3 analyze_silent_faults.py polytomsg_sweep_nodiv.csv
    python3 analyze_silent_faults.py polytomsg_sweep_nodiv.csv --all-corruptions
    python3 analyze_silent_faults.py polytomsg_sweep_nodiv.csv -o silent_faults.csv
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
VAR_NAMES = ["i", "j", "t", "x", "y", "msg"]


# --------------------------------------------------------------------------
# Firmware model: reproduce the reference message from the seed
# --------------------------------------------------------------------------

def xorshift32(seed: int):
    x = seed & 0xFFFFFFFF
    if x == 0:
        x = 0xDEADBEEF
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        yield x


def make_coeffs(seed: int, centered: bool) -> list[int]:
    gen = xorshift32(seed)
    out = []
    for _ in range(KYBER_N):
        v = next(gen) % KYBER_Q
        out.append(v - (KYBER_Q // 2) if centered else v)
    return out


def poly_tomsg(coeffs: list[int]) -> bytes:
    """pqm4 ml-kem m4fspeed poly_tomsg: t = ((2c + 1665) * 80635) >> 28, & 1."""
    msg = bytearray(KYBER_SYMBYTES)
    for i in range(KYBER_SYMBYTES):
        byte = 0
        for j in range(8):
            t = coeffs[8 * i + j] & 0xFFFFFFFF     # int16 -> uint32 sign extension
            t = (t << 1) & 0xFFFFFFFF
            t = (t + 1665) & 0xFFFFFFFF
            t = (t * 80635) & 0xFFFFFFFF
            t >>= 28
            t &= 1
            byte |= t << j
        msg[i] = byte
    return bytes(msg)


def crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def reconstruct_reference(seed: int, want_crc: int) -> tuple[bytes, str] | None:
    """Return (reference msg, coefficient convention) that matches want_crc."""
    for centered, tag in ((True, "centered [-1664,1664]"), (False, "positive [0,Q-1]")):
        msg = poly_tomsg(make_coeffs(seed, centered))
        if crc(msg) == want_crc:
            return msg, tag
    return None


# --------------------------------------------------------------------------
# Corruption identification
# --------------------------------------------------------------------------

def single_byte_table(ref: bytes) -> dict[int, tuple]:
    """crc -> (byte_index, old, new) for every single-byte change."""
    table: dict[int, tuple] = {}
    buf = bytearray(ref)
    for idx in range(len(ref)):
        original = buf[idx]
        for value in range(256):
            if value == original:
                continue
            buf[idx] = value
            table.setdefault(crc(bytes(buf)), (idx, original, value))
        buf[idx] = original
    return table


def two_bit_table(ref: bytes) -> dict[int, tuple]:
    """crc -> ((i1,b1),(i2,b2)) for every 2-bit flip across the buffer."""
    table: dict[int, tuple] = {}
    nbits = len(ref) * 8
    buf = bytearray(ref)
    for p in range(nbits):
        i1, b1 = divmod(p, 8)
        buf[i1] ^= 1 << b1
        for q in range(p + 1, nbits):
            i2, b2 = divmod(q, 8)
            buf[i2] ^= 1 << b2
            table.setdefault(crc(bytes(buf)), ((i1, b1), (i2, b2)))
            buf[i2] ^= 1 << b2
        buf[i1] ^= 1 << b1
    return table


def describe_byte_change(idx: int, old: int, new: int) -> str:
    diff = old ^ new
    bits = [b for b in range(8) if diff >> b & 1]
    kind = f"bit {bits[0]}" if len(bits) == 1 else f"{len(bits)} bits {bits}"
    return f"msg[{idx}] 0x{old:02x}->0x{new:02x} ({kind})"


# --------------------------------------------------------------------------
# Cycle model: where in the inner loop body did the pulse land?
# --------------------------------------------------------------------------

# Inner loop body of poly_tomsg (0x8000496..0x80004b8 in the current build),
# with nominal Cortex-M4 cycle costs. The list is scaled to the measured
# cycles-per-iteration, so only the RELATIVE costs matter here. If the firmware
# is rebuilt and the loop body changes, update this table from the disassembly.
INNER_LOOP = [
    ("ldrsh.w r3,[r6],#2", 2),
    ("ldrb r5,[r0,#0]", 2),
    ("lsls r3,r3,#1", 1),
    ("addw r3,r3,#1665", 1),
    ("mul.w r3,ip,r3", 1),
    ("ubfx r3,r3,#28,#1", 1),
    ("lsl.w lr,r3,r4", 1),
    ("adds r4,#1", 1),
    ("orr.w r5,r5,lr", 1),
    ("cmp r4,#8", 1),
    ("strb r5,[r0,#0]", 2),
    ("bne.n (inner loop)", 2),
]


def calibrate(points: list[tuple[int, int]]) -> tuple[float, float, float] | None:
    """Fit ext = a0 + b*n from (ext, iteration) pairs whose iteration is known
    exactly (single-bit corruptions, where the flipped bit number IS j).

    Returns (a0, b, r2): a0 = cycle at which iteration 0 starts, b = cycles per
    inner iteration. a0 is then refined so that every calibration point falls
    inside its own iteration's span.
    """
    if len(points) < 4:
        return None
    xs = [n for n, _ in points]
    ys = [e for _, e in points]
    m = len(xs)
    mx, my = sum(xs) / m, sum(ys) / m
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    a = my - b * mx
    ss = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    tot = sum((y - my) ** 2 for y in ys)
    r2 = 1 - ss / tot if tot else float("nan")

    # Refine the origin so each point sits inside [a0+b*n, a0+b*(n+1)).
    lo = max(e - b * (n + 1) for n, e in points)
    hi = min(e - b * n for n, e in points)
    a0 = (lo + hi) / 2 if lo < hi else a
    return a0, b, r2


def instruction_at(frac: float, b: float) -> str:
    """Which inner-loop instruction occupies cycle offset `frac` of an iteration."""
    total = sum(c for _, c in INNER_LOOP)
    scale = b / total
    acc = 0.0
    for name, cost in INNER_LOOP:
        acc += cost * scale
        if frac < acc:
            return name
    return INNER_LOOP[-1][0]


# --------------------------------------------------------------------------

def truthy(v: object) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def to_int(v: object):
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("csv", type=Path, help="per-run CSV from run_polytomsg_glitch.py")
    p.add_argument("-o", "--output", type=Path, default=Path("silent_faults.csv"))
    p.add_argument("--all-corruptions", action="store_true",
                   help="analyse every corrupting run, not only counter-silent ones")
    p.add_argument("--no-two-bit", action="store_true",
                   help="skip the 2-bit-flip search (faster, may leave rows unresolved)")
    p.add_argument("--trigger-span", type=int, default=None,
                   help="trigger-high cycles, for the loop-position model "
                        "(default: max trig_count in the CSV)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if not args.csv.is_file():
        raise FileNotFoundError(args.csv)
    with args.csv.open(newline="") as fp:
        rows = [r for r in csv.DictReader(fp) if not truthy(r.get("crashed"))]
    if not rows:
        raise ValueError("no measured rows in CSV")

    # Reference CRC per seed = the modal msg_crc (the vast majority of runs are clean).
    by_seed: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_seed[str(r.get("seed"))].append(r)

    spans = [to_int(r.get("trig_count")) for r in rows]
    spans = [s for s in spans if s]
    span = args.trigger_span or (min(spans) if spans else 12049)

    out_rows: list[dict] = []
    for seed_str, srows in sorted(by_seed.items()):
        seed = int(seed_str, 0)
        modal_crc_str, _ = Counter(r["msg_crc"] for r in srows).most_common(1)[0]
        ref_crc = int(modal_crc_str, 16)

        rec = reconstruct_reference(seed, ref_crc)
        print(f"\n=== seed {seed_str} ===")
        if rec is None:
            print(f"  [!] could not reproduce reference CRC {modal_crc_str} from the seed.",
                  file=sys.stderr)
            print("      The firmware's coefficient generation may have changed; "
                  "byte-level identification is unavailable for this seed.", file=sys.stderr)
            continue
        ref_msg, convention = rec
        print(f"  reference msg reconstructed ({convention}), CRC {modal_crc_str} verified")

        print("  building candidate tables ...", flush=True)
        tbl1 = single_byte_table(ref_msg)
        tbl2 = {} if args.no_two_bit else two_bit_table(ref_msg)

        # Select the runs to analyse.
        sel = []
        for r in srows:
            if not truthy(r.get("any_variable_differ")):
                continue
            if not args.all_corruptions and truthy(r.get("dwt_differ")):
                continue
            sel.append(r)
        print(f"  analysing {len(sel)} "
              f"{'corrupting' if args.all_corruptions else 'counter-silent'} runs")

        resolved = 0
        for r in sel:
            ext = to_int(r.get("ext_offset"))
            got_crc = int(r["msg_crc"], 16)
            other_vars = [v for v in VAR_NAMES
                          if v != "msg" and truthy(r.get(f"{v}_differ"))]

            byte_idx = None
            bits: list[int] = []
            if got_crc == ref_crc:
                desc = "msg unchanged"
            elif got_crc in tbl1:
                idx, old, new = tbl1[got_crc]
                byte_idx = idx
                bits = [b for b in range(8) if (old ^ new) >> b & 1]
                desc = describe_byte_change(idx, old, new)
                resolved += 1
            elif got_crc in tbl2:
                (i1, b1), (i2, b2) = tbl2[got_crc]
                byte_idx = i1
                desc = f"msg[{i1}] bit {b1} + msg[{i2}] bit {b2} (2-bit flip)"
                resolved += 1
            else:
                desc = "UNRESOLVED (>1 byte / >2 bits changed)"

            # A SINGLE flipped bit gives the inner index exactly: msg[i] |= t << j,
            # so the bit number IS j. These rows calibrate the cycle model.
            exact_iter = None
            if byte_idx is not None and len(bits) == 1:
                exact_iter = 8 * byte_idx + bits[0]

            out_rows.append({
                "seed": seed_str,
                "ext_offset": ext,
                "offset": r.get("offset"),
                "width": r.get("width"),
                "repeat": r.get("repeat"),
                "cycles": r.get("cycles"),
                "dwt_differ": r.get("dwt_differ"),
                "dwt_tuple": r.get("dwt_tuple"),
                "other_vars_differ": "|".join(other_vars),
                "msg_crc": r.get("msg_crc"),
                "identified_change": desc,
                "msg_byte": "" if byte_idx is None else byte_idx,
                "_exact_iter": exact_iter,
            })

        if sel:
            print(f"  byte-level identification: {resolved}/{len(sel)} resolved")

    if not out_rows:
        print("\nNothing to report.", file=sys.stderr)
        return 2

    # ---- calibrate the cycle model from the exactly-located rows ----
    cal = [(r["_exact_iter"], r["ext_offset"]) for r in out_rows
           if r["_exact_iter"] is not None and r["ext_offset"] is not None]
    fit = calibrate(cal)
    if fit is None:
        print("\n[warn] too few single-bit corruptions to calibrate the cycle model; "
              "instruction column unavailable", file=sys.stderr)
        a0 = b = None
    else:
        a0, b, r2 = fit
        print(f"\ncycle model calibrated from {len(cal)} single-bit corruptions:")
        print(f"  ext = {a0:.2f} + {b:.4f} * n       (n = 8*i + j)")
        print(f"  {b:.3f} cycles per inner iteration, {b*8:.1f} per outer, R^2 = {r2:.6f}")
        print(f"  (iteration index is exact for single-bit rows; for the others it is "
              f"inferred from ext_offset)")

    for r in out_rows:
        ext = r["ext_offset"]
        if a0 is None or ext is None:
            r["iteration"] = r["cycle_in_iter"] = r["instruction"] = ""
            r["iter_source"] = ""
            continue
        if r["_exact_iter"] is not None:
            n, src = r["_exact_iter"], "exact"
        else:
            n = max(0, min(KYBER_SYMBYTES * 8 - 1, int((ext - a0) / b)))
            src = "timing"
        frac = (ext - a0) - b * n
        i, j = divmod(n, 8)
        r["iteration"] = n
        r["iter_i"] = i
        r["iter_j"] = j
        r["iter_source"] = src
        r["cycle_in_iter"] = round(frac, 2)
        r["instruction"] = instruction_at(frac, b)

    for r in out_rows:
        r.pop("_exact_iter", None)

    out_rows.sort(key=lambda r: (r["seed"], r["ext_offset"] if r["ext_offset"] is not None else -1))
    with args.output.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)

    print(f"\n{'seed':>12}{'ext':>7}{'offset':>9}{'width':>8}  "
          f"{'identified change':<42}{'i/j':>8}{'src':>7}{'cyc':>6}  instruction")
    for r in out_rows:
        pos = f"{r.get('iter_i','')}/{r.get('iter_j','')}"
        print(f"{r['seed']:>12}{str(r['ext_offset']):>7}{str(r['offset']):>9}"
              f"{str(r['width']):>8}  {r['identified_change']:<42}{pos:>8}"
              f"{str(r.get('iter_source','')):>7}{str(r.get('cycle_in_iter','')):>6}  "
              f"{r.get('instruction','')}")

    insn_hist = Counter(r["instruction"] for r in out_rows if r.get("instruction"))
    if insn_hist:
        print(f"\nglitched instruction distribution ({sum(insn_hist.values())} runs):")
        for name, cnt in insn_hist.most_common():
            print(f"  {name:<24}{cnt:>4}")

    # Which msg bytes were hit, overall?
    hit_bytes = [r["msg_byte"] for r in out_rows if r["msg_byte"] != ""]
    if hit_bytes:
        c = Counter(hit_bytes)
        print(f"\nmsg bytes corrupted ({len(c)} distinct): "
              + ", ".join(f"msg[{b}]x{n}" if n > 1 else f"msg[{b}]"
                          for b, n in sorted(c.items())))
    print(f"\nwritten to {args.output}")
    print("NOTE: the iteration index is exact for single-bit rows; the instruction "
          "within an iteration is +/-1 (nominal cycle costs, boundary slack, and any "
          "pulse-to-effect delay).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
