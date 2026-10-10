"""100 unglitched signatures at a fixed nonce: fingerprint and oracle check."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, fingerprint, NONCE, N

ap = argparse.ArgumentParser()
ap.add_argument('--n', type=int, default=100)
ap.add_argument('--nonce', type=int, default=NONCE)
a = ap.parse_args()

scope, target = connect(); reboot(scope, target)
fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None, nonce=a.nonce)
    if not isinstance(d, dict):
        bad += 1; print(f'  run {i}: {d}'); continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), iters=d['iters'], ok=d['ok'],
                     n_ok=d['n_ok'], n_yl=d['n_yl'], n_add=d['n_add'], n_ot=d['n_ot'],
                     zck='0x%08X' % d['zck'], cyc=d['cyc'],
                     cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
if not rows:
    print(f'\nNO VALID FRAMES ({bad} unreadable) -- firmware/host frame mismatch?')
    scope.dis(); raise SystemExit(1)
with open('baseline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp, n in fps.most_common():
    print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
it = collections.Counter(r['iters'] for r in rows)
zc = collections.Counter(r['zck'] for r in rows)
nk = collections.Counter(r['n_ok'] for r in rows)
print(f'iters: {dict(it)}   n_ok: {dict(nk)}   z cksums: {dict(zc)}')
ok = (list(nk) == [N] and len(zc) == 1 and len(fps) == 1)
print('ORACLE', 'OK -- every coefficient is y+w and signing is deterministic at this nonce'
      if ok else 'MISMATCH -- stop here')
scope.dis()
