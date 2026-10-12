"""Per-cycle class map over BitSlice.

There is no boundary to locate: the region is 160 consecutive OR commits, so
almost every ext inside it sits on a target.  What the map is for is (a) which
width/offset actually SKIPS the orr instead of corrupting the accumulator, and
(b) which ext range belongs to which plane -- the 'zbit' column is read
straight off the oracle, so the plane blocks label themselves.

The inner loop period is ~10 cycles, so never use a step that is a multiple of
10.  Step 1 is exhaustive over a region this small.
"""
import argparse, collections, csv
from cwcommon import connect, reboot, run_safe, classify, fingerprint, safe, site, SEL

QUICK = [(82, -136), (55, 56), (275, -688), (400, -688)]
DENSE = [(w, o) for w in (18, 36, 55, 73, 82, 100, 137, 192, 275, 400)
                for o in (-688, -456, -229, -136, -56, 56, 136, 229)]
ap = argparse.ArgumentParser()
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--ext_min', type=int, default=0)
ap.add_argument('--ext_max', type=int, default=1900)
ap.add_argument('--step', type=int, default=1)
ap.add_argument('--grid', type=int, default=4, help='how many QUICK pairs to use')
ap.add_argument('--reps', type=int, default=1)
ap.add_argument('--repeat', type=int, default=1,
                help='glitch N consecutive cycles')
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--dense', action='store_true')
ap.add_argument('--pairs', default='',
                help='explicit pulse shapes, "w,off;w,off;..." -- use the ones '
                     'a tune run showed actually do something, instead of the '
                     'QUICK defaults')
ap.add_argument('--freq', type=int, default=0,
                help='raise the target clock, e.g. 14740000.  Baud scales '
                     'automatically; widths/offsets need re-tuning.')
ap.add_argument('--max_streak', type=int, default=30,
                help='give up after this many consecutive crashes')
ap.add_argument('--out', default='map_wang.csv')
a = ap.parse_args()
if a.pairs:
    GRID = [tuple(int(v) for v in p.split(',')) for p in a.pairs.split(';') if p.strip()]
elif a.dense:
    GRID = DENSE
else:
    GRID = QUICK[:a.grid]

scope, target = connect(**({'freq': a.freq} if a.freq else {}))
print('grid:', GRID, ' phase_shift_steps =', scope.glitch.phase_shift_steps)
reboot(scope, target)
rows, per_ext, classes = [], collections.defaultdict(collections.Counter), collections.Counter()
total = ncrash = run_crash = 0
abort = False
for ext in range(a.ext_min, a.ext_max + 1, a.step):
    if abort: break
    for (w, off) in GRID:
        if abort: break
        for _ in range(a.reps):
            if abort: break
            total += 1
            d, crashed = run_safe(scope, target,
                                  glitch=(ext, w, off, a.repeat), sel=a.sel)
            if crashed:
                ncrash += 1; run_crash += 1
                per_ext[ext]['CRASH'] += 1; classes['CRASH'] += 1
                if run_crash >= a.max_streak:
                    print(f'\n*** {run_crash} crashes in a row at ext={ext} '
                          f'w={w} off={off}.  The target is not recovering; '
                          f'stopping so the rest of the sweep is not wasted.\n'
                          f'    Try a gentler grid: --grid 1, or --dense with '
                          f'the narrow widths only.', flush=True)
                    abort = True
                    break
                continue
            run_crash = 0
            cls = classify(d)
            per_ext[ext][cls.split('[')[0].split('(')[0]] += 1
            classes[cls.split('[')[0].split('(')[0]] += 1
            if cls == 'normal':
                continue
            d = safe(d, a.base_cyc); fp = fingerprint(d); st = site(d)
            rows.append(dict(ext=ext, width=w, offset=off, cls=cls,
                             plane=st[0] if st else -1, zbit=st[1] if st else -1,
                             lane=st[2] if st else -1, ndiff=d['ndiff'],
                             fdir=d['fdir'], nplane0=d['nplane0'], nset=d['nset'],
                             dirty=d['dirty'], bck='0x%08X' % d['bck'],
                             cyc=fp[0], dcyc=fp[0] - a.base_cyc,
                             cpi=fp[1], lsu=fp[2], fold=fp[3]))
    if abort: break
    if ((ext - a.ext_min) // max(a.step, 1)) % 200 == 0:
        print(f'  ... ext={ext}  attempts={total}  crashes={ncrash} '
              f'({100.0*ncrash/max(total,1):.1f}%)  interesting={len(rows)}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['ext'])
    w.writeheader(); w.writerows(rows)
print('\n=== totals ===')
for k, v in classes.most_common(): print(f'  {k:16s} {v}')
sk = [r for r in rows if r['cls'].startswith('OR_SKIP')]
print(f'\nOR_SKIP rows: {len(sk)} / {total} attempts')
if sk:
    print('=== ext range per plane (OR_SKIP rows only) ===')
    blk = collections.defaultdict(list)
    for r in sk: blk[r['zbit']].append(int(r['ext']))
    for k in sorted(blk):
        e = blk[k]
        print(f'  z{k}:  ext {min(e)}..{max(e)}  n={len(e)}')
    print('=== best (width, offset) by OR_SKIP yield ===')
    wo = collections.Counter((r['width'], r['offset']) for r in sk)
    for k, v in wo.most_common(): print(f'  width={k[0]:4d} offset={k[1]:5d}  {v}')
    print('=== OR_SKIP fingerprints ===')
    for f_, n in collections.Counter((r['cyc'], r['cpi'], r['lsu'], r['fold'])
                                     for r in sk).most_common(8):
        print(f'  {f_}  dcyc={f_[0]-a.base_cyc:+d}  n={n}')
print(f'attempts={total}  crashes={ncrash} ({100.0*ncrash/max(total,1):.1f}%)  '
      f'rows={len(rows)}  -> {a.out}')
scope.dis()
