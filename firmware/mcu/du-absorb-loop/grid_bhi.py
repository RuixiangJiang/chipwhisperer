#!/usr/bin/env python3
"""STEP 2: exhaustive width x offset plane at the cycles where the bhi.n sits
(ext mod 32 in {1,2,3}, from the loop schedule: bhi.n is the last 2 cycles of
each 32-cycle iteration). Clock glitching only."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--exts",     type=str, default="65,66,67,97,98,99")
ap.add_argument("--off_step", type=int, default=48)
ap.add_argument("--base_cyc", type=int, default=45181)
a = ap.parse_args()
EXTS=[int(x) for x in a.exts.split(',')]

scope, target = connect(); arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width', [9,14,18,23,27,32,36,41,45,50,55,64,73,82,91,
                             110,137,165,192,220,275,330,385,440,495,551])
OFFSETS = settable('offset', list(range(-PS//2, PS//2+1, a.off_step)))
scope.glitch.repeat = 1
print(f"exts    : {EXTS}")
print(f"widths  : {len(WIDTHS)} values {WIDTHS[0]}..{WIDTHS[-1]}")
print(f"offsets : {len(OFFSETS)} values step {a.off_step}")
n_total=len(EXTS)*len(WIDTHS)*len(OFFSETS)
print(f"attempts: {n_total}\n")

rows, crash, n, clean = [], Counter(), 0, 0
for eo,wd,of in itertools.product(EXTS, WIDTHS, OFFSETS):
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
        j=int(cls.split('stop')[1])
        ok='MATCHES' if abs(dcyc-(-32*(136-j)-1))<=2 else 'cycle MISMATCH'
        print(f"  *** CLEAN bhi.n SKIP  ext={eo} w={wd} off={of}  {cls}  dcyc={dcyc:+6d} [{ok}]")
    elif sig:
        print(f"  ladder  ext={eo} w={wd} off={of}  dcyc={dcyc:+6d}"
              f"  -> {(136*32+dcyc+1)//32} bytes  {d[0].hex()}")
    else:
        print(f"  hit     ext={eo} w={wd} off={of}  dcyc={dcyc:+6d}  {d[0].hex()}")
    if n % 2000 == 0: print(f"    ...{n}/{n_total}, {len(rows)} hits, {sum(crash.values())} crashes")

with open("grid_bhi.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","out8","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print(f"\n=== {n} attempts, {len(rows)} hits, {sum(crash.values())} crashes ===")
print(f"CLEAN bhi.n skips: {clean}")
for eo in EXTS:
    h=[r for r in rows if r[0]==eo]
    print(f"  ext={eo}: {len(h)} hits, {crash[eo]} crashes"
          + (f", widths {sorted({r[1] for r in h})}" if h else ""))
scope.dis(); target.dis()
