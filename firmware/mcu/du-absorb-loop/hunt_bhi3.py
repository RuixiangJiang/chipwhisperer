#!/usr/bin/env python3
"""Fine sweep of `offset` -- pulse position WITHIN one clock cycle.
Every prior campaign sampled only 10 of ~4592 phase-shift steps.
Covers one full 32-cycle inner-loop iteration in ext, so the bhi.n's phase
is included wherever it sits."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min",  type=int, default=74)
ap.add_argument("--ext_max",  type=int, default=105)   # one full iteration
ap.add_argument("--off_step", type=int, default=64)
ap.add_argument("--base_cyc", type=int, default=45181)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width', [36, 137])
OFFSETS = settable('offset', list(range(-PS//2, PS//2 + 1, a.off_step)))
scope.glitch.repeat = 1
print(f"phase_shift_steps = {PS}")
print(f"widths  : {WIDTHS}")
print(f"offsets : {len(OFFSETS)} values, {OFFSETS[0]} .. {OFFSETS[-1]} step {a.off_step}")
n_total=(a.ext_max-a.ext_min+1)*len(WIDTHS)*len(OFFSETS)
print(f"attempts: {n_total}\n")

rows, crash, n, clean = [], Counter(), 0, 0
for eo, wd, of in itertools.product(range(a.ext_min,a.ext_max+1), WIDTHS, OFFSETS):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=2000))
    n += 1
    if d is None:        crash[eo]+=1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls, dcyc = classify(d[0]), d[1]-a.base_cyc
    sig = dcyc < -30 and (dcyc % 32) in (30,31,0)
    if cls=='normal' and abs(dcyc)<=10 and not sig: continue
    rows.append((eo,wd,of,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    if cls.startswith('INNER'):
        clean += 1
        j = int(cls.split('stop')[1])
        ok = 'MATCHES' if abs(dcyc-(-32*(136-j)-1))<=2 else 'cycle MISMATCH'
        print(f"  *** CLEAN bhi.n SKIP  ext={eo} w={wd} off={of}  {cls}  dcyc={dcyc:+6d} [{ok}]")
    elif sig:
        print(f"  ladder  ext={eo:4d} w={wd:4d} off={of:6d}  dcyc={dcyc:+6d}"
              f"  -> {(136*32+dcyc+1)//32:3d} bytes  {d[0].hex()}")
    if n % 1000 == 0: print(f"    ...{n}/{n_total}, {len(rows)} hits, {sum(crash.values())} crashes")

with open("hunt_bhi3.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print(f"\n=== {n} attempts, {len(rows)} hits, {sum(crash.values())} crashes ===")
print(f"CLEAN bhi.n skips: {clean}")
offs = sorted({r[2] for r in rows})
print(f"offsets that produced ANY hit ({len(offs)}): {offs}")
scope.dis(); target.dis()
