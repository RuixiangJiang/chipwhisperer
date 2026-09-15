#!/usr/bin/env python3
"""Table of single-bit msg corruptions, with the loop position they REVEAL.

Every column here is measured, not modelled.

    ext_offset  the glitch parameter used (integer target-clock cycles after the
                trigger rising edge)
    cycle       identical to ext_offset -- ext_offset IS a cycle count
    offset      glitch phase parameter used
    width       glitch width parameter used
    i           outer loop index, recovered from WHICH msg byte changed
    j           inner loop index, recovered from WHICH bit of that byte changed

i and j come from the corruption itself, not from any timing model: poly_tomsg
does msg[i] |= t << j, so a single flipped bit at byte B, bit b means the fault
landed in outer iteration i=B, inner iteration j=b.

The reference message is reconstructed from the input seed (xorshift32 PRNG +
pqm4 poly_tomsg) and verified against the modal msg_crc in the CSV before any
row is emitted. Rows whose CRC does not correspond to exactly one flipped bit
(multi-bit changes, multi-byte changes, unresolved) are omitted, because for
those the corrupted bit does not identify a single (i, j).

Usage
-----
    python3 single_bit_table.py polytomsg_sweep_nodiv.csv
    python3 single_bit_table.py polytomsg_sweep_nodiv.csv -o single_bit.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
import zlib
from collections import Counter
from pathlib import Path

KYBER_Q = 3329
KYBER_SYMBYTES = 96
KYBER_N = 8 * KYBER_SYMBYTES


def xorshift32(seed: int):
    x = (seed & 0xFFFFFFFF) or 0xDEADBEEF
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        yield x


def coeffs_centered(seed: int) -> list[int]:
    g = xorshift32(seed)
    return [(next(g) % KYBER_Q) - KYBER_Q // 2 for _ in range(KYBER_N)]


def coeffs_positive(seed: int) -> list[int]:
    g = xorshift32(seed)
    return [next(g) % KYBER_Q for _ in range(KYBER_N)]


def poly_tomsg(coeffs: list[int]) -> bytes:
    msg = bytearray(KYBER_SYMBYTES)
    for i in range(KYBER_SYMBYTES):
        byte = 0
        for j in range(8):
            t = coeffs[8 * i + j] & 0xFFFFFFFF
            t = (t << 1) & 0xFFFFFFFF
            t = (t + 1665) & 0xFFFFFFFF
            t = (t * 80635) & 0xFFFFFFFF
            byte |= ((t >> 28) & 1) << j
        msg[i] = byte
    return bytes(msg)


def crc(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def reference_for(seed: int, want_crc: int) -> bytes | None:
    for fn in (coeffs_centered, coeffs_positive):
        m = poly_tomsg(fn(seed))
        if crc(m) == want_crc:
            return m
    return None


def single_bit_index(ref: bytes) -> dict[int, tuple[int, int]]:
    """crc -> (byte, bit) for every single-bit flip of the reference."""
    out: dict[int, tuple[int, int]] = {}
    buf = bytearray(ref)
    for i in range(len(ref)):
        for b in range(8):
            buf[i] ^= 1 << b
            out[crc(bytes(buf))] = (i, b)
            buf[i] ^= 1 << b
    return out


def truthy(v) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def to_int(v):
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("single_bit_table.csv"))
    args = p.parse_args()

    with args.csv.open(newline="") as fp:
        rows = [r for r in csv.DictReader(fp) if not truthy(r.get("crashed"))]
    if not rows:
        raise ValueError("no measured rows in CSV")

    out: list[dict] = []
    stats: dict[str, tuple[int, int]] = {}

    for seed_str in sorted({str(r.get("seed")) for r in rows}):
        srows = [r for r in rows if str(r.get("seed")) == seed_str]
        modal = Counter(r["msg_crc"] for r in srows).most_common(1)[0][0]
        ref = reference_for(int(seed_str, 0), int(modal, 16))
        if ref is None:
            print(f"[warn] seed {seed_str}: reference message could not be "
                  f"reconstructed (modal CRC {modal}); skipped", file=sys.stderr)
            continue
        index = single_bit_index(ref)

        corrupted = [r for r in srows if truthy(r.get("any_variable_differ"))]
        kept = 0
        for r in corrupted:
            hit = index.get(int(r["msg_crc"], 16))
            if hit is None:
                continue                      # not a single-bit change -> omitted
            i, j = hit
            ext = to_int(r.get("ext_offset"))
            out.append({
                "ext_offset": ext,
                "cycle": ext,
                "offset": r.get("offset"),
                "width": r.get("width"),
                "i": i,
                "j": j,
            })
            kept += 1
        stats[seed_str] = (kept, len(corrupted))
        print(f"seed {seed_str}: reference verified (CRC {modal}); "
              f"{kept}/{len(corrupted)} corruptions were single-bit")

    if not out:
        print("\nNo single-bit corruptions found.", file=sys.stderr)
        return 2

    out.sort(key=lambda r: (r["ext_offset"] if r["ext_offset"] is not None else -1))
    with args.output.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=["ext_offset", "cycle", "offset", "width", "i", "j"])
        w.writeheader()
        w.writerows(out)

    print(f"\n{'ext_offset':>11}{'cycle':>8}{'offset':>10}{'width':>9}{'i':>5}{'j':>4}")
    for r in out:
        print(f"{r['ext_offset']:>11}{r['cycle']:>8}{str(r['offset']):>10}"
              f"{str(r['width']):>9}{r['i']:>5}{r['j']:>4}")

    total_kept = sum(k for k, _ in stats.values())
    total_corr = sum(c for _, c in stats.values())
    print(f"\n{total_kept} rows ({total_corr - total_kept} multi-bit/unresolved "
          f"corruptions omitted) -> {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
