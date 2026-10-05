#!/usr/bin/env python3
"""Step 4, two stages.
A: fix width/offset at a known-productive pair, walk ext_offset to locate
   the counter-init cycle cheaply.
B: at each hit cycle, sweep width/offset."""
import csv, itertools, argparse
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_max", type=int, default=200)
ap.add_argument("--width",   type=int, default=275)   # productive on this rig
ap.add_argument("--offset",  type=int, default=229)
a = ap.parse_args()

crashpos = {}
scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
print(f"phase_shift_steps = {PS}")

def attempt():
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=1000))
    if d is None:        return 'crash', None
    if d == 'BAD_FRAME': return 'BAD_FRAME', None
    return classify(d[0]), d

print(f"\n=== stage A: ext_offset 0..{a.ext_max} at width={a.width} offset={a.offset} ===")
scope.glitch.width = a.width; scope.glitch.offset = a.offset
stageA = []
for eo in range(a.ext_max + 1):
    scope.glitch.ext_offset = eo
    cls, d = attempt()
    if cls == 'crash':
        crashpos[eo] = crashpos.get(eo,0)+1; reboot(scope); continue
    if cls in ('normal','BAD_FRAME'): continue
    stageA.append(eo)
    print(f"  {cls:12s} ext={eo:4d}  out={d[0].hex()} cyc={d[1]} "
          f"cpi={d[2]} lsu={d[3]} fold={d[4]}")
print(f"stage A hit cycles: {stageA}")
if not stageA:
    print("no hits -- widen --ext_max, or check the loop is not unrolled"); raise SystemExit

def settable(attr, vals):
    ok = []
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width',  [int(f*PS) for f in (0.002,0.004,0.008,0.016,0.03,0.06)])
OFFSETS = settable('offset', [int(f*PS) for f in
                              (-.45,-.35,-.25,-.15,-.05,.05,.15,.25,.35,.45)])

print(f"\n=== stage B: width x offset at {len(stageA)} hit cycles ===")
hits = []; crashpos = {}
for eo, wd, of in itertools.product(stageA, WIDTHS, OFFSETS):
    scope.glitch.ext_offset = eo; scope.glitch.width = wd; scope.glitch.offset = of
    cls, d = attempt()
    if cls == 'crash':
        crashpos[eo] = crashpos.get(eo,0)+1; reboot(scope); continue
    if cls in ('normal','BAD_FRAME'): continue
    hits.append((eo,wd,of,cls,d[0].hex(),d[1],d[2],d[3],d[4]))
    print(f"  {cls:12s} ext={eo:4d} w={wd:6d} off={of:6d} cyc={d[1]}")

with open("params_search.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","out8","cyc","cpi","lsu","fold"])
    w.writerows(hits)
print("\ncrashes by ext_offset (spike = pointer-init site):")
[print(f"  ext={k:4d}  crashes={v}") for k,v in sorted(crashpos.items()) if v>=2]
print(f"\n=== {len(hits)} hits ===")
from collections import Counter
for cls, n in Counter(h[3] for h in hits).most_common():
    print(f"\n{cls}  ({n}):")
    for h in sorted(set((x[0],x[1],x[2]) for x in hits if x[3]==cls))[:15]:
        print(f"  --ext_offset {h[0]} --width {h[1]} --offset {h[2]}")
scope.dis(); target.dis()
