"""N glitched adds at one fixed (ext,width,offset)."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_safe, classify, safe, SEL

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, required=True)
ap.add_argument('--offset', type=int, required=True)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--n', type=int, default=1000)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--freq', type=int, default=0)
ap.add_argument('--out', default='campaign.csv')
a = ap.parse_args()

scope, target = connect(**({'freq': a.freq} if a.freq else {})); reboot(scope, target)
rows, crashes, got, streak = [], 0, 0, 0
while got < a.n:
    d, crashed = run_safe(scope, target, glitch=(a.ext_offset, a.width, a.offset, a.repeat), sel=a.sel)
    if crashed:
        crashes += 1; streak += 1
        if streak >= 60:
            print(f'\n*** 60 crashes in a row; collected {got}/{a.n}, stopping.', flush=True); break
        continue
    streak = 0; d = safe(d)
    rows.append(dict(run=got, cls=classify(d),
                     res_obs='0x%08X'%d['res_obs'], cres='0x%08X'%d['cres'],
                     nz_obs='0x%X'%d['nz_obs'], cnz='0x%X'%d['cnz'],
                     flags_ok=d['flags_ok'], res_ok=d['res_ok'], dirty=d['dirty'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
    got += 1
    if got % 100 == 0: print(f'  {got}/{a.n}  crashes={crashes}', flush=True)

with open(a.out,'w',newline='') as f:
    w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
for k,v in cls.most_common(): print(f'  {k:16s} {v:5d}  {100*v/got:6.2f}%')
scope.dis()
