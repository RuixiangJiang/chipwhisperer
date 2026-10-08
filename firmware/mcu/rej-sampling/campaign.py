#!/usr/bin/env python3
"""Entry 5 campaign: >=N non-crash glitched runs at fixed parameters."""
import csv, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify, fingerprint
from cwcommon import safe  # _BADFRAME
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
    d = parse(None if to else target.simpleserial_read('r', 29, timeout=2000))
    if d is None:        crashes += 1; reboot(scope); continue
    if d == 'BAD_FRAME': bad += 1; continue
    d = safe(d, 0)  # _BADFRAME
    rows.append((got, classify(d), d['ctr'], d['n_diff'], d['first_diff'],
                 f"0x{d['bad']:08X}", d['n_sent'], f"0x{d['cksum']:08X}",
                 d['cyc'], d['cpi'], d['lsu'], d['fold'])); got += 1
    if got % 100 == 0:
        print(f"{got} collected, {crashes} crashes, {bad} bad frames  "
              f"{dict(Counter(r[1].split('@')[0] for r in rows))}")

with open("campaign.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["run","class","ctr","n_diff","first_diff","bad","n_sent",
                "cksum","cyc","cpi","lsu","fold"])
    w.writerows(rows)
print("\n", Counter(r[1] for r in rows))
print(f"crashes excluded: {crashes}   bad frames excluded: {bad}")
scope.dis(); target.dis()
