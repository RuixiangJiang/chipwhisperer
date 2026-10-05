#!/usr/bin/env python3
"""Step 5: >=1000 non-crash glitched runs at fixed params."""
import csv, argparse
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_offset", type=int, required=True)
ap.add_argument("--width", type=int, required=True)
ap.add_argument("--offset", type=int, required=True)
ap.add_argument("--n", type=int, default=1000)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
scope.glitch.ext_offset = a.ext_offset
scope.glitch.width = a.width
scope.glitch.offset = a.offset

rows, crashes, got = [], 0, 0
while got < a.n:
    scope.arm(); target.simpleserial_write('d', b'')
    timeout = scope.capture()
    r = None if timeout else target.simpleserial_read('r', 11, timeout=500)
    d = parse(r)
    if d is None:
        crashes += 1; reboot(scope); continue
    rows.append((got, classify(d[0])) + d); got += 1
    if got % 100 == 0:
        nb = sum(1 for x in rows if x[1] == 'FO_BYPASS')
        print(f"{got} collected, {crashes} crashes, {nb} bypasses")

with open("campaign.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["run","class","fail","cyc","cpi","lsu","fold"]); w.writerows(rows)
from collections import Counter
print("\n", Counter(x[1] for x in rows), f"\ncrashes (excluded): {crashes}")
scope.dis(); target.dis()
