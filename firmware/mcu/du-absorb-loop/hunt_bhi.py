#!/usr/bin/env python3
"""Hunt the bhi.n skip (8001dc0) across the width dimensions never swept:
NEGATIVE widths and widths well beyond 0.06*PS.
Covers every cycle in 3 full inner-loop iterations so the bhi.n's phase
within the 32-cycle period cannot be missed.
Flags on BOTH the digest (INNER_*) and the cycle signature (-32*k), in case
the hypothesis model is subtly wrong."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min",  type=int, default=45)
ap.add_argument("--ext_max",  type=int, default=140)   # 3 iterations, all phases
ap.add_argument("--base_cyc", type=int, default=45181)
ap.add_argument("--repeats",  type=str, default="1,2")
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
print(f"phase_shift_steps = {PS}")

def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok

FR = (0.008, 0.03, 0.06, 0.12, 0.25, 0.40)
WIDTHS  = settable('width',  [int(s*f*PS) for f in FR for s in (-1, 1)])
OFFSETS = settable('offset', [int(f*PS) for f in (-0.15, -0.05, 0.05, 0.15)])
REPEATS = [int(x) for x in a.repeats.split(',')]
print(f"widths  ({len(WIDTHS)}): {sorted(WIDTHS)}")
print(f"offsets ({len(OFFSETS)}): {OFFSETS}")
n_total = (a.ext_max-a.ext_min+1)*len(WIDTHS)*len(OFFSETS)*len(REPEATS)
print(f"attempts: {n_total}\n")

rows, crash, n = [], Counter(), 0
for eo, wd, of, rp in itertools.product(range(a.ext_min, a.ext_max+1),
                                        WIDTHS, OFFSETS, REPEATS):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd
    scope.glitch.offset=of;     scope.glitch.repeat=rp
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=2000))
    n += 1
    if d is None:        crash[eo]+=1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls, dcyc = classify(d[0]), d[1]-a.base_cyc
    # truncation signature: a negative multiple of 32, at least one byte lost
    trunc = dcyc < -16 and abs(dcyc % 32) <= 2
    if cls=='normal' and abs(dcyc)<=10 and not trunc: continue
    rows.append((eo,wd,of,rp,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    tag = ''
    if cls.startswith('INNER'): tag = '  <<<<<< bhi.n SKIP'
    elif trunc:                 tag = f'  <<< -32 x {-dcyc//32} bytes'
    if tag or len(rows) % 25 == 0:
        print(f"  ext={eo:4d} w={wd:6d} off={of:5d} rep={rp} {cls:22s} dcyc={dcyc:+7d}{tag}")
    if n % 1000 == 0: print(f"    ...{n}/{n_total}, {len(rows)} hits, {sum(crash.values())} crashes")

with open("hunt_bhi.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","repeat","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
inner = [r for r in rows if r[4].startswith('INNER')]
trunc = [r for r in rows if r[7] < -16 and abs(r[7] % 32) <= 2]
print(f"\n=== {n} attempts, {len(rows)} hits, {sum(crash.values())} crashes ===")
print(f"INNER_* (bhi.n skip)          : {len(inner)}")
print(f"cycle-truncation signature    : {len(trunc)}")
for r in inner[:20]:
    print(f"  --ext_offset {r[0]} --width {r[1]} --offset {r[2]} --repeat {r[3]}  {r[4]}  dcyc={r[7]}")
print("\nnegative widths that produced ANY hit:",
      sorted({r[1] for r in rows if r[1] < 0}))
scope.dis(); target.dis()
