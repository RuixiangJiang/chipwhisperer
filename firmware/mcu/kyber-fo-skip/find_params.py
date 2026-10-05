#!/usr/bin/env python3
"""Step 4: sweep for params that skip `bl verify`. Scan only - 1 attempt per combo."""
import csv, itertools
from cwcommon import connect, arm_glitch, reboot, parse, classify

scope, target = connect()
arm_glitch(scope)
PS = scope.glitch.phase_shift_steps
print(f"phase_shift_steps = {PS}")
print(f"width={scope.glitch.width} offset={scope.glitch.offset}")

def settable(attr, vals):
    ok = []
    for v in vals:
        try:
            setattr(scope.glitch, attr, v); ok.append(v)
        except Exception:
            pass
    return ok

WIDTHS  = settable('width',  [int(f*PS) for f in (0.002,0.004,0.008,0.016,0.03,0.06)])
OFFSETS = settable('offset', [int(f*PS) for f in
                              (-.45,-.35,-.25,-.15,-.05,.05,.15,.25,.35,.45)])
EXT     = range(0, 26)
print(f"widths  accepted: {WIDTHS}")
print(f"offsets accepted: {OFFSETS}")
print(f"total attempts: {len(WIDTHS)*len(OFFSETS)*len(EXT)}\n")

def attempt():
    scope.arm()
    target.simpleserial_write('d', b'')
    timeout = scope.capture()
    r = None if timeout else target.simpleserial_read('r', 11, timeout=500)
    d = parse(r)
    if d is None: return 'crash', None
    return classify(d[0]), d

hits, n = [], 0
for eo, wd, of in itertools.product(EXT, WIDTHS, OFFSETS):
    scope.glitch.ext_offset = eo
    scope.glitch.width = wd
    scope.glitch.offset = of
    cls, d = attempt(); n += 1
    if cls == 'crash':
        reboot(scope)
    elif cls != 'normal':
        hits.append((eo, wd, of, cls) + d)
        print(f"{cls:14s} ext={eo:3d} w={wd:6d} off={of:6d}  "
              f"fail=0x{d[0]:08X} cyc={d[1]} cpi={d[2]} lsu={d[3]} fold={d[4]}")
    if n % 250 == 0: print(f"  ...{n} attempts, {len(hits)} hits")

with open("params_search.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","fail","cyc","cpi","lsu","fold"])
    w.writerows(hits)

print(f"\n=== {len(hits)} hits / {n} attempts ===")
for want in ('skip_bl','skip_str','skip_ptr_other','other'):
    sel = [h for h in hits if h[3]==want]
    if sel:
        print(f"\n{want}  ({len(sel)}):")
        for h in sorted(set((x[0],x[1],x[2]) for x in sel))[:20]:
            print(f"  --ext_offset {h[0]} --width {h[1]} --offset {h[2]}")
scope.dis(); target.dis()
