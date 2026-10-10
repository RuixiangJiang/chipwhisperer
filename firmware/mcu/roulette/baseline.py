"""100 unglitched inverse NTTs: fingerprint and oracle self-check."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, fingerprint

ap = argparse.ArgumentParser(); ap.add_argument('--n', type=int, default=100)
a = ap.parse_args()

scope, target = connect(); reboot(scope, target)
fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None)
    if not isinstance(d, dict):
        bad += 1; print(f'  run {i}: {d}'); continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), ndiff=d['ndiff'],
                     ock='0x%08X' % d['ock'], cyc=d['cyc'],
                     cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
with open('baseline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp, n in fps.most_common():
    print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
nd = collections.Counter(r['ndiff'] for r in rows)
ock = collections.Counter(r['ock'] for r in rows)
print('ndiff:', dict(nd), '  output cksums:', dict(ock))
print('ORACLE', 'OK -- invntt is deterministic and matches its own reference'
      if (list(nd) == [0] and len(ock) == 1)
      else 'MISMATCH -- the reference and the live run disagree, stop here')
scope.dis()
