#!/usr/bin/env python3
"""Full-window stage A. Flags ANY run whose cycle count departs from the
baseline by more than --tol, which is the signature of a round-count fault
(~783 cycles/round, ~1566 per loop iteration) regardless of digest."""
import csv, argparse
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min", type=int, default=0)
ap.add_argument("--ext_max", type=int, default=19900)
ap.add_argument("--step",    type=int, default=1)
ap.add_argument("--width",   type=int, default=275)
ap.add_argument("--offset",  type=int, default=-688)
ap.add_argument("--base_cyc",type=int, default=19806)
ap.add_argument("--tol",     type=int, default=100)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
scope.glitch.width = a.width; scope.glitch.offset = a.offset

rows, crashes, n = [], 0, 0
for eo in range(a.ext_min, a.ext_max + 1, a.step):
    scope.glitch.ext_offset = eo
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=1000))
    n += 1
    if d is None:        crashes += 1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls = classify(d[0]); dcyc = d[1] - a.base_cyc
    if cls == 'normal' and abs(dcyc) <= a.tol: continue
    rows.append((eo, cls, d[0].hex(), d[1], dcyc, d[2], d[3], d[4]))
    tag = "  <<< CYCLE SHIFT" if abs(dcyc) > a.tol else ""
    print(f"  ext={eo:6d} {cls:18s} out={d[0].hex()} cyc={d[1]:6d} "
          f"dcyc={dcyc:+6d}{tag}")
    if n % 2000 == 0: print(f"    ...{n} swept, {len(rows)} hits, {crashes} crashes")

with open("window_sweep.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
shifted = [r for r in rows if abs(r[4]) > a.tol]
print(f"\n=== {n} swept, {len(rows)} hits, {crashes} crashes ===")
print(f"cycle-shifted (round-count candidates): {len(shifted)}")
for r in shifted[:40]:
    print(f"  --ext_offset {r[0]}   dcyc={r[4]:+6d}  rounds~{r[4]/783:+.1f}  {r[1]}")
scope.dis(); target.dis()
