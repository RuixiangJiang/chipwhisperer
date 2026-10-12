"""Confusion matrices per counter for a Wang campaign CSV.
Positive = the bit-planes differ from the reference (ndiff > 0).
Negative = planes bit-identical, INCLUDING a skipped OR whose bit was already
           0 -- that leaves no trace in the output, so there is nothing for a
           counter to be right or wrong about.
Excluded = INPUT_DIRTY (the glitch moved the coefficients, so the reference
           recomputed after the window is not the one the monitored pass used),
           OVERRUN (wrote past the planes), and unreadable frames."""
import argparse, collections, csv
ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--neg', action='append', default=[],
                help='extra CSV(s) to pool in, e.g. a null-ext campaign that '
                     'supplies glitched-but-correct negatives.  Scoring FPR '
                     'against unglitched runs flatters the detector: the '
                     'attacker is always glitching.')
ap.add_argument('--base', required=True, help='cyc,cpi,lsu,fold of the baseline')
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
rows = list(csv.DictReader(open(a.csvfile)))
for extra in a.neg:
    rows += list(csv.DictReader(open(extra)))
    print(f'pooled negatives from {extra}')
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))

bad   = [r for r in rows if r['cls'].startswith(('BADFRAME', 'NOFRAME', 'SHORTFRAME',
                                                 'BADMAGIC', 'BAD_COUNTERS'))]
dirty = [r for r in rows if r['cls'] in ('INPUT_DIRTY', 'OVERRUN')]
valid = [r for r in rows if r not in bad and r not in dirty]
cor   = [r for r in valid if int(r['ndiff']) > 0]
ok    = [r for r in valid if int(r['ndiff']) == 0]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)}  scorable={len(valid)}  unscorable={len(dirty)}  unreadable={len(bad)}')
print(f'  planes corrupted = {len(cor)}   planes identical = {len(ok)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'].split('[')[0].split('(')[0] for r in rows)
per = collections.defaultdict(collections.Counter)
for r in rows: per[r['cls'].split('[')[0].split('(')[0]][fp(r)] += 1
for k, v in cls.most_common():
    print(f'  {k:14s} {v:5d}  ' + ' + '.join(f'{f} * {n}' for f, n in per[k].most_common(3)))

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
        pr = TP/(TP+FP) if TP+FP else 0.0
        print(f'  {name:13s} TP={TP:5d} FN={FN:5d} FP={FP:5d} TN={TN:5d}  '
              f'TPR={TP/len(pos):.4f} FPR={FP/len(neg) if neg else 0:.4f} '
              f'PREC={pr:.4f} ACC={(TP+TN)/(len(pos)+len(neg)):.4f}')

matrix(cor, ok, 'ALL plane-corrupting faults')
sk = [r for r in cor if r['cls'].startswith('OR_SKIP')]
matrix(sk, ok, 'OR_SKIP only (the Wang target instruction)')
u = [r for r in cor if fp(r) == BASE]
print(f'\nundetectable corrupting: {len(u)}/{len(cor)} = {100*len(u)/len(cor) if cor else 0:.2f}%')
if sk:
    us = [r for r in sk if fp(r) == BASE]
    print(f'undetectable OR_SKIP   : {len(us)}/{len(sk)} = {100*len(us)/len(sk):.2f}%')
    print('OR_SKIP planes hit:', dict(collections.Counter(r['zbit'] for r in sk)))
nb = [r for r in ok if fp(r) != BASE]
if nb:
    print(f'\ncorrect-output runs at a NON-baseline fingerprint: {len(nb)}')
    for f_, n in collections.Counter(fp(r) for r in nb).most_common():
        print(f'    {f_}  dcyc={f_[0]-BASE[0]:+d}  n={n}')
    print('  A skipped OR whose bit was already 0 lands here: a real')
    print('  instruction skip with a correct output.  Any counter delta on')
    print('  these is a false positive that no threshold can remove, because')
    print('  the skip is identical to the one that corrupts a bit.')
print('\n=== ambiguous fingerprints ===')
t = collections.defaultdict(set)
for r in valid: t[fp(r)].add('corrupt' if int(r['ndiff']) > 0 else 'correct')
for f_, s in sorted(t.items()):
    n = sum(1 for r in valid if fp(r) == f_)
    print(f'  {f_}  n={n:5d}  {"AMBIGUOUS" if len(s) > 1 else sorted(s)[0]}')
