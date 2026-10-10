"""Two-stage parameter search over the noise-sampling loops.

  stage 1 (coarse, --step 97):  a glitch landing anywhere inside a
      poly_getnoise_eta1() call corrupts THAT polynomial, so the first
      deviating polynomial index printed per ext tells you which call the ext
      is inside.  Read the three ext values where that index steps 0->1->2->3:
      the nonce add sits at each of those boundaries.

  stage 2 (fine, --step 1 --ext_min B-40 --ext_max B+40 for each boundary B):
      a 1-instruction target needs every ext, so never use a coarse step here.
"""
import argparse, collections, csv
from cwcommon import (connect, reboot, run_once, classify, fingerprint, safe,
                      first_bad_poly, SEL)

QUICK = [(82, -136), (55, 56), (275, -688), (400, -688)]
DENSE = [(w, o) for w in (18, 36, 55, 73, 82, 100, 137, 192, 275, 400)
                for o in (-688, -456, -229, -136, -56, 56, 136, 229)]
ap = argparse.ArgumentParser()
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--ext_min', type=int, default=0)
ap.add_argument('--ext_max', type=int, default=27000)
ap.add_argument('--step', type=int, default=97,
                help='97 for the coarse locate pass, 1 for the fine pass')
ap.add_argument('--reps', type=int, default=1)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--dense', action='store_true')
ap.add_argument('--out', default='map_vals.csv')
a = ap.parse_args()
GRID = DENSE if a.dense else QUICK

scope, target = connect(); reboot(scope, target)
rows, per_ext, classes, total = [], collections.defaultdict(collections.Counter), collections.Counter(), 0
for ext in range(a.ext_min, a.ext_max + 1, a.step):
    for (w, off) in GRID:
        for _ in range(a.reps):
            total += 1
            try:
                d = run_once(scope, target, glitch=(ext, w, off, 1), sel=a.sel)
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
                             poly=first_bad_poly(d), nonce=d['nonce'],
                             shift='0x%04X' % d['shift'], nok=d['nok'],
                             ndup=d['ndup'], nsent=d['nsent'], dirty=d['dirty'],
                             mck='0x%08X' % d['mck'], cyc=fp[0],
                             dcyc=fp[0] - a.base_cyc, cpi=fp[1], lsu=fp[2], fold=fp[3]))
    if ((ext - a.ext_min) // max(a.step, 1)) % 25 == 0:
        print(f'  ... ext={ext}  attempts={total}  interesting={len(rows)}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['ext'])
    w.writeheader(); w.writerows(rows)

print('\n=== per-ext map (absent ext = no effect).  poly = first deviating index ===')
for ext in sorted(per_ext):
    c = per_ext[ext]
    if set(c) <= {'normal'}: continue
    polys = sorted({r['poly'] for r in rows if r['ext'] == ext and r['poly'] >= 0})
    print(f'  ext={ext:6d}  poly={str(polys) if polys else "-":12s}  '
          + ', '.join(f'{k} x{v}' for k, v in c.most_common() if k != 'normal'))
print('\n=== totals ===')
for k, v in classes.most_common(): print(f'  {k:22s} {v}')
ns = sum(1 for r in rows if r['cls'].startswith('NONCE_REUSE'))
print(f'\nNONCE_REUSE rows (the Valsaraj condition): {ns}')
print(f'attempts={total}  rows={len(rows)}  -> {a.out}')
scope.dis()
