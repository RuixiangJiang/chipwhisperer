#!/usr/bin/env python3
"""Exhaustive width x offset plane at the strls.w cycles (m22 = 1,2 -- the add
is confirmed at m22=5 and the store is 3-4 cycles earlier).
STORE_SKIP = n_diff==1 AND that slot still holds 0xA5A5A5A5."""
import csv, itertools, argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--exts",     type=str, default="23,24,45,46,67,68,89,90")
ap.add_argument("--off_step", type=int, default=48)
ap.add_argument("--base_cyc", type=int, default=5807)
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
n_total=len(EXTS)*len(WIDTHS)*len(OFFSETS)
print(f"exts={EXTS}  widths={len(WIDTHS)}  offsets={len(OFFSETS)}  attempts={n_total}\n")

rows, crash, n, hit = [], Counter(), 0, 0
for eo,wd,of in itertools.product(EXTS, WIDTHS, OFFSETS):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 29, timeout=2000))
    n += 1
    if d is None:        crash[eo]+=1; reboot(scope); continue
    if not isinstance(d, dict): continue          # BAD_FRAME / BAD_COUNTERS
    cls = classify(d); dcyc = d['cyc']-a.base_cyc
    if cls == 'normal': continue
    rows.append((eo,wd,of,cls,d['ctr'],d['n_diff'],d['first_diff'],
                 f"0x{d['bad']:08X}",d['n_sent'],d['cyc'],dcyc,d['cpi'],d['lsu'],d['fold']))
    if cls.startswith('STORE_SKIP'):
        hit += 1
        print(f"  *** STORE SKIP  ext={eo} w={wd} off={of}  {cls}  "
              f"n_diff={d['n_diff']} a[k]=0x{d['bad']:08X} ctr={d['ctr']} dcyc={dcyc:+d}")
    if n % 2500 == 0: print(f"    ...{n}/{n_total}, {len(rows)} hits, {sum(crash.values())} crashes")

with open("grid_store.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","ctr","n_diff","first_diff",
                "bad","n_sent","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print(f"\n=== {n} attempts, {len(rows)} hits, {sum(crash.values())} crashes ===")
print(f"STORE_SKIP: {hit}")
print("classes:", dict(Counter(r[3].split('@')[0] for r in rows)))
for eo in EXTS:
    h=[r for r in rows if r[0]==eo]
    print(f"  ext={eo}: {len(h)} hits" + (f", widths {sorted({r[1] for r in h})}" if h else ""))
scope.dis(); target.dis()
