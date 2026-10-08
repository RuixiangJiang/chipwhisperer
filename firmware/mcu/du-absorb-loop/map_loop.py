#!/usr/bin/env python3
"""STEP 1: map every cycle of two full inner-loop iterations to its fault
class, printing dead cycles as well as hits, so the bhi.n (last 2 cycles of
each 32-cycle iteration) can be identified rather than guessed.
Clock glitching only."""
import csv, itertools, argparse
from collections import defaultdict, Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min",  type=int, default=60)
ap.add_argument("--ext_max",  type=int, default=124)   # 2 iterations + margin
ap.add_argument("--base_cyc", type=int, default=45181)
ap.add_argument("--tries",    type=int, default=3)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width',  [18, 36, 73, 137, 275, 551])
OFFSETS = settable('offset', [-688, -229, 229])
scope.glitch.repeat = 1

obs, crash, rows = defaultdict(Counter), Counter(), []
for eo,wd,of,_ in itertools.product(range(a.ext_min,a.ext_max+1),
                                    WIDTHS, OFFSETS, range(a.tries)):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=2000))
    if d is None:        crash[eo]+=1; obs[eo]['CRASH']+=1; reboot(scope); continue
    if d == 'BAD_FRAME': obs[eo]['BADFRAME']+=1; continue
    cls, dcyc = classify(d[0]), d[1]-a.base_cyc
    rows.append((eo,wd,of,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    if cls=='normal' and abs(dcyc)<=10: obs[eo]['ok']+=1
    elif cls.startswith('INNER'):       obs[eo][f'BHI_SKIP({cls})']+=1
    elif dcyc < -30 and (dcyc%32) in (30,31,0): obs[eo][f'TRUNC({dcyc})']+=1
    else:                               obs[eo][f'd{dcyc:+d}']+=1

with open("map_loop.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)

print("\n=== per-cycle map (mod 32 shown; bhi.n expected at mod 2-3) ===")
for eo in range(a.ext_min, a.ext_max+1):
    c = obs[eo]
    tag = ' <<< BHI?' if any(k.startswith('BHI_SKIP') or k.startswith('TRUNC') for k in c) else ''
    summary = ', '.join(f'{k}x{v}' for k,v in c.most_common(5)) or '-'
    print(f"  ext={eo:4d} (mod32={eo%32:2d})  {summary}{tag}")
print("\ncycles with NO fault at any setting (candidate bhi.n / dead):")
print(' ', [eo for eo in range(a.ext_min,a.ext_max+1)
            if set(obs[eo]) <= {'ok','CRASH','BADFRAME'}])
scope.dis(); target.dis()
