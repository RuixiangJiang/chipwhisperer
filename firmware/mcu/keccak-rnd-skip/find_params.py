#!/usr/bin/env python3
"""Step 4: sweep for params that skip `bl shake256_inc_absorb`.
Scan only - one attempt per combination."""
import csv, itertools
from cwcommon import connect, arm_glitch, reboot, parse, classify

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
print(f"phase_shift_steps = {PS}")

def settable(attr, vals):
    ok = []
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok

WIDTHS  = settable('width',  [int(f*PS) for f in (0.002,0.004,0.008,0.016,0.03,0.06)])
OFFSETS = settable('offset', [int(f*PS) for f in
                              (-.45,-.35,-.25,-.15,-.05,.05,.15,.25,.35,.45)])
EXT     = range(0, 25)      # bl lands ~cycle 6-12
print(f"widths : {WIDTHS}")
print(f"offsets: {OFFSETS}")
print(f"attempts: {len(WIDTHS)*len(OFFSETS)*len(EXT)}\n")

def attempt():
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=500))
    if d is None:        return 'crash', None
    if d == 'BAD_FRAME': return 'BAD_FRAME', None
    return classify(d[0]), d

hits, n, crashes, bad = [], 0, 0, 0
for eo, wd, of in itertools.product(EXT, WIDTHS, OFFSETS):
    scope.glitch.ext_offset = eo; scope.glitch.width = wd; scope.glitch.offset = of
    cls, d = attempt(); n += 1
    if cls == 'crash':       crashes += 1; reboot(scope)
    elif cls == 'BAD_FRAME': bad += 1
    elif cls != 'normal':
        hits.append((eo,wd,of,cls,d[0].hex(),d[1],d[2],d[3],d[4]))
        print(f"{cls:12s} ext={eo:3d} w={wd:6d} off={of:6d}  "
              f"rho''={d[0].hex()} cyc={d[1]} cpi={d[2]} lsu={d[3]} fold={d[4]}")
    if n % 250 == 0: print(f"  ...{n} attempts, {len(hits)} hits, {crashes} crashes")

with open("params_search.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","rhop8","cyc","cpi","lsu","fold"])
    w.writerows(hits)

print(f"\n=== {len(hits)} hits / {n} attempts  ({crashes} crashes, {bad} bad frames) ===")
for want in ('RND_SKIPPED','other'):
    sel = [h for h in hits if h[3]==want]
    if sel:
        print(f"\n{want}  ({len(sel)}):")
        for h in sorted(set((x[0],x[1],x[2]) for x in sel))[:20]:
            print(f"  --ext_offset {h[0]} --width {h[1]} --offset {h[2]}")
scope.dis(); target.dis()
