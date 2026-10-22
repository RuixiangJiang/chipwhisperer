"""100 unglitched adds: fingerprint, NZCV, and oracle check (host-side)."""
import argparse, collections, csv, sys
from cwcommon import connect, reboot, run_once, classify, fingerprint, SEL, expected_ops

ap = argparse.ArgumentParser()
ap.add_argument('--n', type=int, default=100)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--freq', type=int, default=0)
a = ap.parse_args()
DIAG = "No readable frame. SHORTFRAME+invalid-command -> reflash; BADMAGIC -> wrong firmware."

scope, target = connect(**({'freq': a.freq} if a.freq else {})); reboot(scope, target)
fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None, sel=a.sel)
    if not isinstance(d, dict):
        bad += 1; print(f'  run {i}: {d}')
        if i == 0: print(DIAG); scope.dis(); sys.exit(1)
        continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), a='0x%08X'%d['a'], b='0x%08X'%d['b'],
                     res_obs='0x%08X'%d['res_obs'], cres='0x%08X'%d['cres'],
                     nz_obs='0x%X'%d['nz_obs'], cnz='0x%X'%d['cnz'],
                     flags_ok=d['flags_ok'], res_ok=d['res_ok'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
if not rows:
    print(f'\nvalid=0 unreadable={bad}'); print(DIAG); scope.dis(); sys.exit(1)
with open('baseline.csv','w',newline='') as f:
    w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
ea, eb = expected_ops(a.sel)
print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp,n in fps.most_common(): print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
nzo = collections.Counter(r['nz_obs'] for r in rows)
print(f'operands: a=0x{ea:08X} b=0x{eb:08X}   result={rows[0]["res_obs"]}')
print(f'NZCV observed: {dict(nzo)}   NZCV correct: {rows[0]["cnz"]}')
ok = (len(fps)==1 and bad==0 and
      all(r['flags_ok'] and r['res_ok'] for r in rows) and len(nzo)==1)
print('ORACLE', 'OK -- add correct every run, NZCV matches the correct sum, deterministic'
      if ok else 'MISMATCH -- stop here')
scope.dis()
