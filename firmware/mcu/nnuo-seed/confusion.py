"""Confusion matrices for one campaign CSV, per counter and per fault class.

usage: python confusion.py [campaign.csv] [--base cyc,cpi,lsu,fold]
Ground truth = cksum != the correct-seed cksum.  Detector = counter(s) differ
from the unglitched baseline.  BADFRAME rows carry no functional ground truth
and are reported separately, never scored."""
import argparse, collections, csv
from cwcommon import GOOD_CKSUM

ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--base', help='cyc,cpi,lsu,fold of the unglitched run')
ap.add_argument('--baseline_csv', default='baseline.csv')
a = ap.parse_args()

rows = list(csv.DictReader(open(a.csvfile)))
if a.base:
    BASE = tuple(int(x) for x in a.base.split(','))
else:
    b = list(csv.DictReader(open(a.baseline_csv)))
    fps = collections.Counter((int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold'])) for r in b)
    if len(fps) != 1:
        print('baseline has %d distinct fingerprints: %s' % (len(fps), dict(fps)))
    BASE = fps.most_common(1)[0][0]
print(f'baseline fingerprint = {BASE}')

GOOD = '0x%08X' % GOOD_CKSUM
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))

badframe = [r for r in rows if r['cls'].startswith(('BADFRAME', 'NOFRAME'))]
valid    = [r for r in rows if not r['cls'].startswith(('BADFRAME', 'NOFRAME'))]
corrupt  = [r for r in valid if r['cksum'] != GOOD]
correct  = [r for r in valid if r['cksum'] == GOOD]
print(f'rows={len(rows)}  valid={len(valid)}  unscorable(BADFRAME)={len(badframe)}')
print(f'  corrupted seed = {len(corrupt)}   correct seed = {len(correct)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'] for r in rows)
per = collections.defaultdict(collections.Counter)
for r in rows: per[r['cls']][fp(r)] += 1
for k, v in cls.most_common():
    print(f'  {k:26s} {v:5d}  ' +
          ' + '.join(f'{f} * {n}' for f, n in per[k].most_common()))

DETECTORS = [
    ('full 4-tuple', lambda r: fp(r) != BASE),
    ('CYCCNT only',  lambda r: int(r['cyc'])  != BASE[0]),
    ('CPICNT only',  lambda r: int(r['cpi'])  != BASE[1]),
    ('LSUCNT only',  lambda r: int(r['lsu'])  != BASE[2]),
    ('FOLDCNT only', lambda r: int(r['fold']) != BASE[3]),
]

def matrix(pos, neg, title):
    if not pos:
        print(f'\n--- {title}: no positives, skipped ---'); return
    print(f'\n--- {title}   (pos={len(pos)}, neg={len(neg)}) ---')
    for name, det in DETECTORS:
        TP = sum(1 for r in pos if det(r)); FN = len(pos) - TP
        FP = sum(1 for r in neg if det(r)); TN = len(neg) - FP
        tpr = TP / len(pos)
        fpr = FP / len(neg) if neg else 0.0
        prec = TP / (TP + FP) if TP + FP else 0.0
        acc = (TP + TN) / (len(pos) + len(neg))
        print(f'  {name:14s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  '
              f'TPR={tpr:.4f} FPR={fpr:.4f} PREC={prec:.4f} ACC={acc:.4f}')

matrix(corrupt, correct, 'ALL corrupting faults')
for k in sorted(cls):
    if k == 'normal' or k.startswith(('BADFRAME', 'NOFRAME')):
        continue
    sub = [r for r in valid if r['cls'] == k and r['cksum'] != GOOD]
    if len(sub) >= 5:
        matrix(sub, correct, k)

print('\n=== margins ===')
for k in sorted(cls):
    if k.startswith(('BADFRAME', 'NOFRAME')): continue
    for f, n in per[k].most_common():
        print(f'  {k:26s} {f}  x{n:5d}  delta={tuple(x-y for x,y in zip(f,BASE))}')

print('\n=== undetectable corrupting faults (tuple == baseline exactly) ===')
u = [r for r in corrupt if fp(r) == BASE]
for r in u:
    print(f'  {r["cls"]:26s} cksum={r["cksum"]} n_diff={r["n_diff"]} n_sent={r["n_sent"]}')
print(f'  {len(u)} / {len(corrupt)} = {100*len(u)/len(corrupt) if corrupt else 0:.2f}%')

print('\n=== ambiguous fingerprints (produced by BOTH correct and corrupted seeds) ===')
tup = collections.defaultdict(set)
for r in valid: tup[fp(r)].add('corrupt' if r['cksum'] != GOOD else 'correct')
for f, s in sorted(tup.items()):
    n = sum(1 for r in valid if fp(r) == f)
    tag = 'AMBIGUOUS' if len(s) > 1 else sorted(s)[0]
    print(f'  {f}  n={n:5d}  {tag}')
