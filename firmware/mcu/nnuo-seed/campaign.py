"""N glitched runs at one fixed (ext_offset,width,offset); writes campaign.csv."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, safe

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, required=True)
ap.add_argument('--offset', type=int, required=True)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--n', type=int, default=1000)
ap.add_argument('--out', default='campaign.csv')
a = ap.parse_args()

scope, target = connect()
reboot(scope, target)

rows, crashes, got = [], 0, 0
while got < a.n:
    try:
        d = run_once(scope, target, glitch=(a.ext_offset, a.width, a.offset, a.repeat))
    except Exception:
        d = None
    if d is None or d == 'NOFRAME':
        crashes += 1; reboot(scope, target); continue
    d = safe(d)
    rows.append(dict(run=got, cls=classify(d),
                     n_diff=d['n_diff'], first_diff=d['first_diff'],
                     n_sent=d['n_sent'], first_sent=d['first_sent'],
                     last_sent=d['last_sent'], shiftn=d['shiftn'],
                     got='0x%02X' % d['got'], exp='0x%02X' % d['exp'],
                     cksum='0x%08X' % d['cksum'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
    got += 1
    if got % 100 == 0:
        print(f'  {got}/{a.n}  crashes={crashes}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)

print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls = collections.Counter(r['cls'] for r in rows)
for k, v in cls.most_common():
    print(f'  {k:28s} {v:5d}  {100*v/got:6.2f}%')
print('\n=== fingerprint per class ===')
per = collections.defaultdict(collections.Counter)
for r in rows:
    per[r['cls']][(r['cyc'], r['cpi'], r['lsu'], r['fold'])] += 1
for k in cls:
    print(f'  {k} (n={cls[k]}):  ' +
          ' + '.join(f'{f} * {n}' for f, n in per[k].most_common()))
scope.dis()
