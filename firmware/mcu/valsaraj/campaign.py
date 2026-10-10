"""N glitched key generations at one fixed (ext_offset,width,offset)."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, safe, first_bad_poly, SEL

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, required=True)
ap.add_argument('--offset', type=int, required=True)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--n', type=int, default=1000)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--out', default='campaign.csv')
a = ap.parse_args()

scope, target = connect(); reboot(scope, target)
rows, crashes, got = [], 0, 0
while got < a.n:
    try:
        d = run_once(scope, target, glitch=(a.ext_offset, a.width, a.offset, a.repeat),
                     sel=a.sel)
    except Exception:
        d = None
    if d is None or d == 'NOFRAME':
        crashes += 1; reboot(scope, target); continue
    d = safe(d)
    rows.append(dict(run=got, cls=classify(d), poly=first_bad_poly(d),
                     nonce=d['nonce'], shift='0x%04X' % d['shift'], nok=d['nok'],
                     ndup=d['ndup'], fdup=d['fdup'], nsent=d['nsent'],
                     dirty=d['dirty'], mck='0x%08X' % d['mck'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))
    got += 1
    if got % 100 == 0:
        print(f'  {got}/{a.n}  crashes={crashes}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
for k, v in cls.most_common():
    print(f'  {k:22s} {v:5d}  {100*v/got:6.2f}%')
ns = [r for r in rows if r['cls'].startswith('NONCE_REUSE')]
print(f"\nNONCE_REUSE (duplicate noise polynomial): {len(ns)}/{got} = {100*len(ns)/got:.2f}%")
if ns:
    print('  which pair:', dict(collections.Counter(r['cls'].split('(')[0] for r in ns)))
    print('  fingerprints:',
          dict(collections.Counter((r['cyc'], r['cpi'], r['lsu'], r['fold']) for r in ns)))
print('\n=== fingerprint per class ===')
fps = collections.defaultdict(collections.Counter)
for r in rows: fps[r['cls'].split('(')[0]][(r['cyc'], r['cpi'], r['lsu'], r['fold'])] += 1
for k in cls:
    print(f'  {k:22s} ' + ' + '.join(f'{f} * {n}' for f, n in fps[k].most_common(4)))
scope.dis()
