#!/usr/bin/env python3
"""Step 5: >=1000 non-crash glitched runs at fixed params."""
import csv, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_offset", type=int, required=True)
ap.add_argument("--width",      type=int, required=True)
ap.add_argument("--offset",     type=int, required=True)
ap.add_argument("--n",          type=int, default=1000)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
scope.glitch.ext_offset = a.ext_offset
scope.glitch.width      = a.width
scope.glitch.offset     = a.offset

rows, crashes, bad, got = [], 0, 0, 0
while got < a.n:
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=1000))
    if d is None:        crashes += 1; reboot(scope); continue
    if d == 'BAD_FRAME': bad += 1; continue
    rows.append((got, classify(d[0]), d[0].hex(), d[1], d[2], d[3], d[4])); got += 1
    if got % 100 == 0:
        print(f"{got} collected, {crashes} crashes, {bad} bad frames  "
              f"{dict(Counter(x[1] for x in rows))}")

with open("campaign.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["run","class","out8","cyc","cpi","lsu","fold"])
    w.writerows(rows)
print("\n", Counter(x[1] for x in rows))
print(f"crashes excluded: {crashes}   bad frames excluded: {bad}")
scope.dis(); target.dis()
