"""N glitched signatures at one fixed (ext_offset,width,offset)."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, safe, NONCE

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, required=True)
ap.add_argument('--offset', type=int, required=True)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--n', type=int, default=1000)
ap.add_argument('--nonce', type=int, default=NONCE)
ap.add_argument('--out', default='campaign.csv')
a = ap.parse_args()

scope, target = connect(); reboot(scope, target)
rows, crashes, got = [], 0, 0
while got < a.n:
    try:
        d = run_once(scope, target, glitch=(a.ext_offset, a.width, a.offset, a.repeat),
                     nonce=a.nonce)
    except Exception:
        d = None
    if d is None or d == 'NOFRAME':
        crashes += 1; reboot(scope, target); continue
    d = safe(d)
    rows.append(dict(run=got, cls=classify(d), iters=d['iters'], ok=d['ok'],
                     n_ok=d['n_ok'], n_yl=d['n_yl'], n_add=d['n_add'],
                     n_ysh=d['n_ysh'], n_wsh=d['n_wsh'], n_ot=d['n_ot'],
                     f_yl=d['f_yl'], f_add=d['f_add'], f_ot=d['f_ot'],
                     z_ot=d['z_ot'], y_ot=d['y_ot'], w_ot=d['w_ot'],
                     zck='0x%08X' % d['zck'], cyc=d['cyc'],
                     cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
    got += 1
    if got % 100 == 0:
        print(f'  {got}/{a.n}  crashes={crashes}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
for k, v in cls.most_common():
    print(f'  {k:16s} {v:5d}  {100*v/got:6.2f}%')
yl = [r for r in rows if r['cls'].startswith('YLOAD_SKIP')]
print(f"\nYLOAD_SKIP (key recovery): {len(yl)}/{got} = {100*len(yl)/got:.2f}%")
if yl:
    print('  leaked w per coefficient:',
          dict(collections.Counter((r['f_yl'], r['w_ot']) for r in yl).most_common(5)))
    print('  fingerprints:',
          dict(collections.Counter((r['cyc'], r['cpi'], r['lsu'], r['fold']) for r in yl)))
print('\n=== fingerprint per class ===')
fps = collections.defaultdict(collections.Counter)
for r in rows: fps[r['cls'].split('(')[0]][(r['cyc'], r['cpi'], r['lsu'], r['fold'])] += 1
for k in cls:
    print(f'  {k:16s} ' + ' + '.join(f'{f} * {n}' for f, n in fps[k].most_common(4)))
scope.dis()
