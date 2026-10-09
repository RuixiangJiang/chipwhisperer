"""Per-cycle class map over the sampling loop.
Default is a QUICK pass: 4 (width,offset) pairs that were productive in
earlier entries, every ext in range.  --dense widens the grid."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_once, classify, fingerprint

QUICK = [(82, -136), (55, 56), (275, -688), (400, -688)]
DENSE = [(w, o) for w in (18, 36, 55, 73, 82, 100, 137, 192, 275, 400)
                for o in (-688, -456, -229, -136, -56, 56, 136, 229)]

ap = argparse.ArgumentParser()
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--ext_min', type=int, default=0)
ap.add_argument('--ext_max', type=int, default=340)
ap.add_argument('--reps', type=int, default=1)
ap.add_argument('--dense', action='store_true')
ap.add_argument('--out', default='map_seed.csv')
a = ap.parse_args()
GRID = DENSE if a.dense else QUICK

scope, target = connect()
reboot(scope, target)

rows, per_ext, classes = [], collections.defaultdict(collections.Counter), collections.Counter()
total = 0
for ext in range(a.ext_min, a.ext_max + 1):
    for (w, off) in GRID:
        for _ in range(a.reps):
            total += 1
            try:
                d = run_once(scope, target, glitch=(ext, w, off, 1))
            except Exception:
                d = None
            if d is None or d == 'NOFRAME':
                per_ext[ext]['CRASH'] += 1; classes['CRASH'] += 1
                reboot(scope, target); continue
            cls = classify(d)
            per_ext[ext][cls] += 1; classes[cls] += 1
            if cls == 'normal':
                continue
            isd = isinstance(d, dict)
            fp = fingerprint(d) if isd else (0, 0, 0, 0)
            rows.append(dict(ext=ext, width=w, offset=off, cls=cls,
                             n_diff=d['n_diff'] if isd else -1,
                             first_diff=d['first_diff'] if isd else -1,
                             n_sent=d['n_sent'] if isd else -1,
                             first_sent=d['first_sent'] if isd else -1,
                             shiftn=d['shiftn'] if isd else -1,
                             cksum=('0x%08X' % d['cksum']) if isd else '',
                             cyc=fp[0], dcyc=fp[0] - a.base_cyc,
                             cpi=fp[1], lsu=fp[2], fold=fp[3]))
    if (ext - a.ext_min) % 25 == 0:
        print(f'  ... ext={ext}  attempts={total}  interesting={len(rows)}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['ext'])
    w.writeheader(); w.writerows(rows)

print('\n=== per-cycle class map (absent ext = no effect) ===')
for ext in sorted(per_ext):
    c = per_ext[ext]
    if set(c) <= {'normal'}:
        continue
    print(f'  ext={ext:4d}  ' + ', '.join(f'{k}x{v}' for k, v in c.most_common() if k != 'normal'))
print('\n=== totals ===')
for k, v in classes.most_common():
    print(f'  {k:28s} {v}')
print(f'\nattempts={total}  rows written={len(rows)}  -> {a.out}')
scope.dis()
