"""Per-cycle class map over the isolated adds.

The region is a handful of instructions (msr / adds / mrs plus the function
prologue), so the whole map is a short ext range.  What it locates: the ext
where a glitch SKIPS the adds (NZCV left at the sentinel, class SKIP_CAUGHT)
versus corrupts its result (CORRUPT_CAUGHT) versus is caught by neither
(FLAG_BLIND -- the measurement target)."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_safe, classify, fingerprint, safe, SEL

QUICK = [(82,-136),(55,56),(275,-688),(400,-688)]
DENSE = [(w,o) for w in (18,36,55,73,82,100,137,192,275,400)
                for o in (-688,-456,-229,-136,-56,56,136,229)]
ap = argparse.ArgumentParser()
ap.add_argument('--base_cyc', type=int, required=True)
ap.add_argument('--ext_min', type=int, default=0)
ap.add_argument('--ext_max', type=int, default=80)
ap.add_argument('--step', type=int, default=1)
ap.add_argument('--reps', type=int, default=4)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--dense', action='store_true')
ap.add_argument('--pairs', default='')
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--freq', type=int, default=0)
ap.add_argument('--max_streak', type=int, default=40)
ap.add_argument('--out', default='map_flags.csv')
a = ap.parse_args()
if a.pairs:   GRID = [tuple(int(v) for v in p.split(',')) for p in a.pairs.split(';') if p.strip()]
elif a.dense: GRID = DENSE
else:         GRID = QUICK

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
            d, crashed = run_safe(scope, target, glitch=(ext, w, off, a.repeat), sel=a.sel)
            if crashed:
                ncrash += 1; run_crash += 1
                per_ext[ext]['CRASH'] += 1; classes['CRASH'] += 1
                if run_crash >= a.max_streak:
                    print(f'\n*** {run_crash} crashes in a row at ext={ext}; stopping.', flush=True)
                    abort = True
                continue
            run_crash = 0
            cls = classify(d); key = cls.split('(')[0]
            per_ext[ext][key] += 1; classes[key] += 1
            if cls == 'normal': continue
            d = safe(d, a.base_cyc); fp = fingerprint(d)
            rows.append(dict(ext=ext, width=w, offset=off, cls=cls,
                             res_obs='0x%08X'%d['res_obs'], cres='0x%08X'%d['cres'],
                             nz_obs='0x%X'%d['nz_obs'], cnz='0x%X'%d['cnz'],
                             flags_ok=d['flags_ok'], res_ok=d['res_ok'], dirty=d['dirty'],
                             cyc=fp[0], dcyc=fp[0]-a.base_cyc, cpi=fp[1], lsu=fp[2], fold=fp[3]))
    if ((ext-a.ext_min)//max(a.step,1)) % 20 == 0:
        print(f'  ... ext={ext} attempts={total} crashes={ncrash} interesting={len(rows)}', flush=True)

with open(a.out,'w',newline='') as f:
    w=csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['ext'])
    w.writeheader(); w.writerows(rows)
print('\n=== per-ext map ===')
for ext in sorted(per_ext):
    c=per_ext[ext]
    if set(c) <= {'normal'}: continue
    print(f'  ext={ext:4d}  '+', '.join(f'{k} x{v}' for k,v in c.most_common() if k!='normal'))
print('\n=== totals ===')
for k,v in classes.most_common(): print(f'  {k:16s} {v}')
fb = sum(1 for r in rows if r['cls'].startswith('FLAG_BLIND'))
sk = sum(1 for r in rows if r['cls'].startswith('SKIP_CAUGHT'))
cc = sum(1 for r in rows if r['cls'].startswith('CORRUPT_CAUGHT'))
print(f'\nSKIP_CAUGHT={sk}  CORRUPT_CAUGHT={cc}  FLAG_BLIND={fb} (result wrong, flags missed it)')
print(f'attempts={total} crashes={ncrash} rows={len(rows)} -> {a.out}')
scope.dis()
