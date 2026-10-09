"""100 unglitched runs: establish the fingerprint and verify the oracle."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, fingerprint, GOOD_CKSUM

ap = argparse.ArgumentParser()
ap.add_argument('--n', type=int, default=100)
a = ap.parse_args()

scope, target = connect()
reboot(scope, target)

fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None)
    if not isinstance(d, dict):
        bad += 1; print(f'  run {i}: {d}'); continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), cksum='0x%08X' % d['cksum'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))

with open('baseline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['run', 'cls', 'cksum', 'cyc', 'cpi', 'lsu', 'fold'])
    w.writeheader(); w.writerows(rows)

print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp, n in fps.most_common():
    print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
cks = collections.Counter(r['cksum'] for r in rows)
print('cksums:', dict(cks))
ok = (len(cks) == 1 and list(cks)[0] == '0x%08X' % GOOD_CKSUM)
print('ORACLE', 'OK -- device reference matches nnuoref.py' if ok
      else 'MISMATCH -- host model and device disagree, stop here')
scope.dis()
