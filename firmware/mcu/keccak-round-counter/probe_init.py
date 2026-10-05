#!/usr/bin/env python3
"""Full width x offset grid over the loop-entry neighbourhood, where the
round-constant pointer is initialised (ldr r3,[pc,#4] / str r3,[sp,#0]).
Skipping the str -> stale pointer -> 1 iteration, dcyc ~ -16258.
Skipping the ldr -> a Keccak lane word becomes the table pointer -> crash.
Crashes are RECORDED here, not discarded."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min", type=int, default=245)
ap.add_argument("--ext_max", type=int, default=285)
ap.add_argument("--base_cyc", type=int, default=19806)
a = ap.parse_args()

WATCH = {'1d815e3b8e2a0a38':'INIT_SKIP (stale=end, RC[24],RC[25])',
         'ddfaa14c7e3b0a00':'INIT_SKIP (stale=&RC[22])  == ROUNDS_2'}

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width',  [int(f*PS) for f in (0.002,0.004,0.008,0.016,0.03,0.06)])
OFFSETS = settable('offset', [int(f*PS) for f in
                              (-.45,-.35,-.25,-.15,-.05,.05,.15,.25,.35,.45)])

rows, crash = [], Counter()
for eo, wd, of in itertools.product(range(a.ext_min, a.ext_max+1), WIDTHS, OFFSETS):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=1000))
    if d is None:        crash[eo]+=1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls, dcyc = classify(d[0]), d[1]-a.base_cyc
    if cls=='normal' and abs(dcyc)<=10: continue
    rows.append((eo,wd,of,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    tag = '  <<< '+WATCH[d[0].hex()] if d[0].hex() in WATCH else (
          '  <<< ONE ITERATION ONLY' if abs(dcyc+16258)<40 else '')
    print(f"  ext={eo:4d} w={wd:6d} off={of:6d} {cls:18s} out={d[0].hex()} dcyc={dcyc:+7d}{tag}")

with open("init_probe.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["ext_offset","width","offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print(f"\n{len(rows)} hits")
print("crashes per ext_offset (a spike = the ldr skip -> wild table pointer):")
for k,v in sorted(crash.items()):
    print(f"  ext={k:4d}  crashes={v:3d}{'   <<< SPIKE' if v>=10 else ''}")
scope.dis(); target.dis()
