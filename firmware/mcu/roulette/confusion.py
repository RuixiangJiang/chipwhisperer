"""Confusion matrices per counter for one Roulette campaign CSV.
Ground truth = the inverse NTT output changed (ndiff != 0).
Detector = the named counter differs from the unglitched baseline."""
import argparse, collections, csv

ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--base', default='5480,31,4,0')
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
rows = list(csv.DictReader(open(a.csvfile)))
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))

bad   = [r for r in rows if r['cls'].startswith(('BADFRAME', 'NOFRAME', 'BAD_COUNTERS'))]
valid = [r for r in rows if not r['cls'].startswith(('BADFRAME', 'NOFRAME', 'BAD_COUNTERS'))]
cor   = [r for r in valid if int(r['ndiff']) != 0]
ok    = [r for r in valid if int(r['ndiff']) == 0]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)}  valid={len(valid)}  unscorable={len(bad)}')
print(f'  corrupted output = {len(cor)}   correct output = {len(ok)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'] for r in rows)
per = collections.defaultdict(collections.Counter)
for r in rows: per[r['cls']][fp(r)] += 1
for k, v in cls.most_common():
    print(f'  {k[:50]:52s} {v:5d}  ' + ' + '.join(f'{f} * {n}' for f, n in per[k].most_common(3)))

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
        tpr = TP / len(pos); fpr = FP / len(neg) if neg else 0.0
        prec = TP / (TP + FP) if TP + FP else 0.0
        print(f'  {name:14s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  '
              f'TPR={tpr:.4f} FPR={fpr:.4f} PREC={prec:.4f} '
              f'ACC={(TP+TN)/(len(pos)+len(neg)):.4f}')

matrix(cor, ok, 'ALL corrupting faults')
sk = [r for r in cor if r['cls'].startswith('BFLY_SKIP')]
matrix(sk, ok, 'BFLY_SKIP only (the reproduced uadd16 skip)')

print('\n=== undetectable corrupting faults (all four counters == baseline) ===')
u = [r for r in cor if fp(r) == BASE]
uc = collections.Counter(r['cls'].split('(')[0] for r in u)
for k, v in uc.most_common(): print(f'  {k:24s} {v}')
print(f'  {len(u)} / {len(cor)} = {100*len(u)/len(cor) if cor else 0:.2f}%')

print('\n=== ambiguous fingerprints ===')
t = collections.defaultdict(set)
for r in valid: t[fp(r)].add('corrupt' if int(r['ndiff']) else 'correct')
for f_, s in sorted(t.items()):
    n = sum(1 for r in valid if fp(r) == f_)
    print(f'  {f_}  n={n:5d}  {"AMBIGUOUS" if len(s) > 1 else sorted(s)[0]}')
