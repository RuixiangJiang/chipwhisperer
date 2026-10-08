#!/usr/bin/env python3
"""repeat has been 1 in every campaign so far. Multi-cycle glitches are the
usual route to a conditional-branch skip. Sweep repeat x width x offset over
the inner-loop ladder in block 0."""
import csv, itertools
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
BASE = 45181
scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
rows, crash = [], Counter()
for eo, rep, wd, of in itertools.product(range(45, 201), (1,2,3,4),
                                         (int(0.03*PS), int(0.06*PS)),
                                         (int(-0.15*PS), int(-0.05*PS), int(0.05*PS))):
    scope.glitch.ext_offset=eo; scope.glitch.repeat=rep
    scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=2000))
    if d is None:        crash[(eo,rep)]+=1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls, dcyc = classify(d[0]), d[1]-BASE
    if cls=='normal' and abs(dcyc)<=10: continue
    rows.append((eo,rep,wd,of,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    tag = '  <<< bhi.n SKIP' if cls.startswith('INNER') else ''
    print(f"  ext={eo:4d} rep={rep} w={wd:6d} off={of:6d} {cls:22s} dcyc={dcyc:+7d}{tag}")
with open("repeat_probe.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","repeat","width","offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print(f"\n{len(rows)} hits")
print("INNER_* (bhi.n skip):", sum(1 for r in rows if r[4].startswith('INNER')))
print("crashes by (ext,repeat):", {k:v for k,v in crash.items() if v>=3})
scope.dis(); target.dis()
