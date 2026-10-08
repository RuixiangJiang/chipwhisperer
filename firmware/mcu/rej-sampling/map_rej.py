#!/usr/bin/env python3
"""Map ~3 early iterations of rej_uniform's loop to fault classes.
Dense width/offset: the Du entry's fault only appeared at width 82 /
offset -136, neither of which was in the coarse sets."""
import csv, itertools, argparse
from collections import defaultdict, Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify, fingerprint
from cwcommon import safe  # _BADFRAME
ap = argparse.ArgumentParser()
ap.add_argument("--ext_min",  type=int, default=10)
ap.add_argument("--ext_max",  type=int, default=85)   # ~3 iterations at ~24 cyc
ap.add_argument("--base_cyc", type=int, required=True)
ap.add_argument("--tries",    type=int, default=1)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
def settable(attr, vals):
    ok=[]
    for v in vals:
        try: setattr(scope.glitch, attr, v); ok.append(v)
        except Exception: pass
    return ok
WIDTHS  = settable('width',  [18,36,55,73,82,100,137,192,275,400])
OFFSETS = settable('offset', [-688,-456,-229,-136,-56,56,136,229])
print(f"widths : {WIDTHS}")
print(f"offsets: {OFFSETS}")
n_total=(a.ext_max-a.ext_min+1)*len(WIDTHS)*len(OFFSETS)*a.tries
print(f"attempts: {n_total}\n")

rows, obs, crash, n = [], defaultdict(Counter), Counter(), 0
for eo,wd,of,_ in itertools.product(range(a.ext_min,a.ext_max+1),
                                    WIDTHS, OFFSETS, range(a.tries)):
    scope.glitch.ext_offset=eo; scope.glitch.width=wd; scope.glitch.offset=of
    scope.arm(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 29, timeout=2000))
    n += 1
    if d is None:        crash[eo]+=1; obs[eo]['CRASH']+=1; reboot(scope); continue
    if d == 'BAD_FRAME': obs[eo]['BADFRAME']+=1; continue
    d = safe(d, a.base_cyc)
    cls = classify(d); dcyc = d['cyc']-a.base_cyc
    obs[eo][cls.split('@')[0]] += 1
    if cls=='normal': continue
    rows.append((eo,wd,of,cls,d['ctr'],d['n_diff'],d['first_diff'],
                 f"0x{d['bad']:08X}",d['n_sent'],f"0x{d['cksum']:08X}",
                 d['cyc'],dcyc,d['cpi'],d['lsu'],d['fold']))
    tag = '  <<<<<< STORE SKIP' if cls.startswith('STORE_SKIP') else (
          '  <<< CTR ADD SKIP' if cls.startswith('CTR_INC') else '')
    print(f"  ext={eo:4d} w={wd:4d} off={of:5d}  {cls:24s} dcyc={dcyc:+6d}{tag}")
    if n % 1000 == 0: print(f"    ...{n}/{n_total}")

with open("map_rej.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["ext_offset","width","offset","class","ctr","n_diff","first_diff",
                "bad","n_sent","cksum","cyc","dcyc","cpi","lsu","fold"])
    w.writerows(rows)
print("\n=== per-cycle class map ===")
for eo in range(a.ext_min,a.ext_max+1):
    c=Counter({k:v for k,v in obs[eo].items() if k!='normal'})
    print(f"  ext={eo:4d}  " + (', '.join(f'{k}x{v}' for k,v in c.most_common(4)) or '— dead —'))
print(f"\nSTORE_SKIP hits : {sum(1 for r in rows if r[3].startswith('STORE_SKIP'))}")
print(f"CTR_INC_SKIP    : {sum(1 for r in rows if r[3].startswith('CTR_INC'))}")
print(f"ACCEPT_BAD      : {sum(1 for r in rows if r[3].startswith('ACCEPT_BAD'))}")
scope.dis(); target.dis()
