"""Confusion matrices per counter for a Krahmer campaign CSV.
Positive = an EMITTED signature that differs from the correct one (ok=1, n_ok<256).
Runs with ok=0 emit nothing, so they are reported separately, never scored."""
import argparse, collections, csv
ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--base', default='29490,114,222,180')
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
rows = list(csv.DictReader(open(a.csvfile)))
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))

bad   = [r for r in rows if r['cls'].startswith(('BADFRAME', 'NOFRAME', 'BAD_COUNTERS'))]
nosig = [r for r in rows if r['cls'].startswith(('NO_SIG', 'WREF_DIRTY'))]
valid = [r for r in rows if r not in bad and r not in nosig]
cor   = [r for r in valid if int(r['n_ok']) != 256]
ok    = [r for r in valid if int(r['n_ok']) == 256]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)}  emitted={len(valid)}  no-signature={len(nosig)}  unscorable={len(bad)}')
print(f'  corrupted signature = {len(cor)}   correct signature = {len(ok)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
per = collections.defaultdict(collections.Counter)
for r in rows: per[r['cls'].split('(')[0]][fp(r)] += 1
for k, v in cls.most_common():
    print(f'  {k:16s} {v:5d}  ' + ' + '.join(f'{f} * {n}' for f, n in per[k].most_common(3)))

DET = [('full 4-tuple', lambda r: fp(r) != BASE),
       ('CYCCNT only',  lambda r: int(r['cyc'])  != BASE[0]),
       ('CPICNT only',  lambda r: int(r['cpi'])  != BASE[1]),
       ('LSUCNT only',  lambda r: int(r['lsu'])  != BASE[2]),
       ('FOLDCNT only', lambda r: int(r['fold']) != BASE[3])]

def matrix(pos, neg, title):
    if not pos:
        print(f'\n--- {title}: no positives ---'); return
    print(f'\n--- {title}   (pos={len(pos)}, neg={len(neg)}) ---')
    for name, det in DET:
        TP = sum(1 for r in pos if det(r)); FN = len(pos) - TP
        FP = sum(1 for r in neg if det(r)); TN = len(neg) - FP
        print(f'  {name:14s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  '
              f'TPR={TP/len(pos):.4f} FPR={FP/len(neg) if neg else 0:.4f} '
              f'PREC={TP/(TP+FP) if TP+FP else 0:.4f}')

matrix(cor, ok, 'ALL corrupting faults (emitted signatures)')
yl = [r for r in cor if r['cls'].startswith('YLOAD_SKIP')]
matrix(yl, ok, 'YLOAD_SKIP only (the key-recovery fault)')
u = [r for r in cor if fp(r) == BASE]
print(f'\nundetectable corrupting: {len(u)}/{len(cor)} = {100*len(u)/len(cor) if cor else 0:.2f}%')
uy = [r for r in yl if fp(r) == BASE]
if yl: print(f'undetectable YLOAD_SKIP : {len(uy)}/{len(yl)} = {100*len(uy)/len(yl):.2f}%')
print('\n=== ambiguous fingerprints ===')
t = collections.defaultdict(set)
for r in valid: t[fp(r)].add('corrupt' if int(r['n_ok']) != 256 else 'correct')
for f_, s in sorted(t.items()):
    n = sum(1 for r in valid if fp(r) == f_)
    print(f'  {f_}  n={n:5d}  {"AMBIGUOUS" if len(s) > 1 else sorted(s)[0]}')
