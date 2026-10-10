"""Re-print a map CSV that is already on disk, and locate the loop boundaries.
Use this instead of re-running a sweep whose summary print crashed."""
import argparse, collections, csv, sys

ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='map_vals.csv')
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--halfwidth', type=int, default=40)
a = ap.parse_args()

rows = list(csv.DictReader(open(a.csvfile)))
if not rows or 'ext' not in rows[0] or len(rows[0]) <= 1:
    print(f'{a.csvfile} has no data rows (the sweep found nothing but normal).')
    sys.exit(0)

per  = collections.defaultdict(collections.Counter)
poly = collections.defaultdict(set)
for r in rows:
    ext = int(r['ext'])
    per[ext][r['cls'].split('(')[0].split('[')[0]] += 1
    p = int(r['poly'])
    if p >= 0: poly[ext].add(p)

print('=== per-ext map (only exts with a non-normal run appear) ===')
for ext in sorted(per):
    ps = sorted(poly[ext])
    print(f'  ext={ext:6d}  poly={str(ps) if ps else "-":10s}  '
          + ', '.join(f'{k} x{v}' for k, v in per[ext].most_common()))

print('\n=== totals ===')
tot = collections.Counter()
for ext in per: tot.update(per[ext])
for k, v in tot.most_common(): print(f'  {k:22s} {v}')

print('\n=== cycle deltas seen ===')
dc = collections.Counter(int(r['dcyc']) for r in rows if r['dcyc'] not in ('', None))
for d_, n in sorted(dc.items()): print(f'  dcyc={d_:+7d}  n={n}')

# Boundaries: the ext at which the lowest corrupted polynomial index steps up.
print('\n=== loop boundaries (lowest corrupted poly index vs ext) ===')
seq = [(ext, min(poly[ext])) for ext in sorted(poly) if poly[ext]]
if not seq:
    print('  no run located a polynomial -- widen the width/offset grid (--dense)')
else:
    bands, cur = [], seq[0][1]
    print(f'  starts at poly {cur} (ext {seq[0][0]})')
    for ext, p in seq:
        if p > cur:
            print(f'  poly {cur} -> {p} between ext {prev} and {ext}')
            bands.append((prev, ext)); cur = p
        prev = ext
    print('\n=== dense passes to run next ===')
    # The nonce increment is computed BEFORE the call (adds r6,r2,#1) and
    # COMMITTED AFTER it (mov r2,r6), so the live site is the commit mov,
    # which sits at the boundary.  Skipping the adds instead leaves a stale
    # register and gives a garbage nonce (POLY_CORRUPT), not a reuse.
    names = ['loop-1 i=0 -> i=1: mov r2,r6  LIVE, skip gives s1==s0',
             'loop-1 exit -> loop-2: the reset mov r2,r4 is a no-op here '
             '(loop 1 already leaves r2=k), and adds r7,r2,#1 has a stale '
             'r7 = pm base, so a skip gives nonce 0x40, not a reuse.  '
             'NO REUSE SITE.',
             'loop-2 i=0 -> i=1: mov r2,r7  LIVE, skip gives e1==e0']
    # Scan the WHOLE uncertainty band between the last ext of one polynomial
    # and the first ext of the next: a narrow window centred on the midpoint
    # can sit entirely on one side of the real transition.
    for i, (lo, hi) in enumerate(bands):
        tag = names[i] if i < len(names) else 'boundary %d' % (i + 1)
        print(f'  # {tag}')
        print(f'  python map_vals.py --base_cyc {a.base_cyc} --step 1 '
              f'--ext_min {lo - 10} --ext_max {hi + 10} --out fine_b{i + 1}.csv')
