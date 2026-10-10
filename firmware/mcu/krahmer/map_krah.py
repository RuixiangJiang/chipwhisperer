"""Per-cycle class map over the response computation."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, fingerprint, safe, NONCE

QUICK = [(82, -136), (55, 56), (275, -688), (400, -688)]
DENSE = [(w, o) for w in (18, 36, 55, 73, 82, 100, 137, 192, 275, 400)
                for o in (-688, -456, -229, -136, -56, 56, 136, 229)]
ap = argparse.ArgumentParser()
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--ext_min', type=int, default=0)
ap.add_argument('--ext_max', type=int, default=900)
ap.add_argument('--reps', type=int, default=1)
ap.add_argument('--step', type=int, default=1)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--nonce', type=int, default=NONCE)
ap.add_argument('--dense', action='store_true')
ap.add_argument('--out', default='map_krah.csv')
a = ap.parse_args()
GRID = DENSE if a.dense else QUICK

scope, target = connect(); reboot(scope, target)
rows, per_ext, classes, total = [], collections.defaultdict(collections.Counter), collections.Counter(), 0
for ext in range(a.ext_min, a.ext_max + 1, a.step):
    for (w, off) in GRID:
        for _ in range(a.reps):
            total += 1
            try:
                d = run_once(scope, target, glitch=(ext, w, off, a.repeat), nonce=a.nonce)
            except Exception:
                d = None
            if d is None or d == 'NOFRAME':
                per_ext[ext]['CRASH'] += 1; classes['CRASH'] += 1
                reboot(scope, target); continue
            cls = classify(d); per_ext[ext][cls] += 1
            classes[cls.split('(')[0]] += 1
            if cls == 'normal':
                continue
            d = safe(d, a.base_cyc); fp = fingerprint(d)
            rows.append(dict(ext=ext, width=w, offset=off, cls=cls,
                             iters=d['iters'], ok=d['ok'], n_ok=d['n_ok'],
                             n_yl=d['n_yl'], n_add=d['n_add'], n_ysh=d['n_ysh'],
                             n_wsh=d['n_wsh'], n_ot=d['n_ot'],
                             f_yl=d['f_yl'], f_add=d['f_add'], f_ot=d['f_ot'],
                             zck='0x%08X' % d['zck'],
                             z_ot=d['z_ot'], y_ot=d['y_ot'], w_ot=d['w_ot'],
                             delta=d['z_ot'] - (d['y_ot'] + d['w_ot']),
                             cyc=fp[0], dcyc=fp[0] - a.base_cyc,
                             cpi=fp[1], lsu=fp[2], fold=fp[3]))
    if (ext - a.ext_min) % 50 == 0:
        print(f'  ... ext={ext}  attempts={total}  interesting={len(rows)}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['ext'])
    w.writeheader(); w.writerows(rows)
print('\n=== per-cycle class map (absent ext = no effect) ===')
for ext in sorted(per_ext):
    c = per_ext[ext]
    if set(c) <= {'normal'}: continue
    print(f'  ext={ext:4d}  ' + ', '.join(f'{k} x{v}' for k, v in c.most_common() if k != 'normal'))
print('\n=== totals ===')
for k, v in classes.most_common(): print(f'  {k:24s} {v}')
print(f"\nY_SKIP rows (key-recovery condition): {sum(1 for r in rows if r['cls'].startswith('YLOAD_SKIP'))}")
print(f'attempts={total}  rows={len(rows)}  -> {a.out}')
scope.dis()
