#!/usr/bin/env python3
"""Step 3: 100 clean runs, no glitching."""
import csv
from cwcommon import connect, parse, classify
N = 100
scope, target = connect()
rows = []
for i in range(N):
    target.flush(); target.simpleserial_write('r', b'')
    d = parse(target.simpleserial_read('r', 19, timeout=3000))
    if d is None:        print(i, "no response"); continue
    if d == 'BAD_FRAME': print(i, "BAD_FRAME");   continue
    out8, cyc, cpi, lsu, fold = d
    rows.append((i, classify(out8), out8.hex(), cyc, cpi, lsu, fold))
    print(rows[-1])
with open("baseline.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["run","class","out8","cyc","cpi","lsu","fold"])
    w.writerows(rows)
fp = set((r[3],r[4],r[5],r[6]) for r in rows)
print(f"\nwrote baseline.csv ({len(rows)} runs)")
print(f"distinct fingerprints: {len(fp)} -> {fp}")
print(f"all class 'normal' (24 rounds): {all(r[1]=='normal' for r in rows)}")
