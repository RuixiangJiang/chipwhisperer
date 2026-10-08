#!/usr/bin/env python3
import csv
from cwcommon import connect, parse, classify, fingerprint
from rej import REF
scope, target = connect()
rows=[]
for i in range(100):
    target.flush(); target.simpleserial_write('r', b'')
    d = parse(target.simpleserial_read('r', 29, timeout=3000))
    if d is None or d=='BAD_FRAME': print(i, d); continue
    rows.append((i, classify(d), d['ctr'], d['n_diff'], d['n_sent'],
                 f"0x{d['cksum']:08X}", d['cyc'], d['cpi'], d['lsu'], d['fold']))
    if i < 3 or i == 99: print(rows[-1])
with open("baseline.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["run","class","ctr","n_diff","n_sent","cksum","cyc","cpi","lsu","fold"])
    w.writerows(rows)
fp={r[6:10] for r in rows}
print(f"\n{len(rows)} runs   distinct fingerprints: {len(fp)} -> {fp}")
print(f"classes: {set(r[1] for r in rows)}")
print(f"cksum  : {set(r[5] for r in rows)}   (must be 0x3538ED3E)")
print(f"period estimate: (cyc - overhead)/261 = {(rows[0][6]-30)/261:.2f} cyc/sample")
