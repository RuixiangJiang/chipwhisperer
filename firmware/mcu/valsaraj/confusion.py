"""Confusion matrices per counter for a Valsaraj campaign CSV.
Positive = the emitted key differs from the correct one (nok < NPOLY or a
           polynomial missing entirely).
Negative = the emitted key is correct, INCLUDING NONCE_DEAD_SKIP, where the
           final unused increment was skipped but every polynomial is right.
Excluded = SEED_DIRTY (the glitch moved the seed, so the reference recomputed
           after the window is not the reference the monitored pass used) and
           unreadable frames."""
import argparse, collections, csv
ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--neg', action='append', default=[],
                help='extra campaign CSV(s) to pool in, e.g. a null-ext run that '
                     'supplies glitched-but-correct negatives.  A campaign where '
                     'the fault lands 100%% of the time has no negatives of its '
                     'own, and scoring FPR against unglitched runs flatters the '
                     'detector: the attacker is always glitching.')
ap.add_argument('--base', required=True, help='cyc,cpi,lsu,fold of the baseline')
ap.add_argument('--npoly', type=int, default=4)
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
rows = list(csv.DictReader(open(a.csvfile)))
for extra in a.neg:
    rows += list(csv.DictReader(open(extra)))
    print(f'pooled negatives from {extra}')
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))

bad   = [r for r in rows if r['cls'].startswith(('BADFRAME', 'NOFRAME', 'SHORTFRAME',
                                                 'BADMAGIC', 'BAD_COUNTERS'))]
dirty = [r for r in rows if r['cls'] in ('SEED_DIRTY', 'OVERRUN')]
valid = [r for r in rows if r not in bad and r not in dirty]
cor   = [r for r in valid if int(r['nok']) != a.npoly or int(r['nsent']) != 0]
ok    = [r for r in valid if r not in cor]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)}  scorable={len(valid)}  unscorable(dirty/overrun)={len(dirty)}  unreadable={len(bad)}')
print(f'  corrupted key = {len(cor)}   correct key = {len(ok)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
per = collections.defaultdict(collections.Counter)
for r in rows: per[r['cls'].split('(')[0]][fp(r)] += 1
for k, v in cls.most_common():
    print(f'  {k:22s} {v:5d}  ' + ' + '.join(f'{f} * {n}' for f, n in per[k].most_common(3)))

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
              f'PREC={TP/(TP+FP) if TP+FP else 0:.4f} '
              f'ACC={(TP+TN)/(len(pos)+len(neg)):.4f}')

matrix(cor, ok, 'ALL key-corrupting faults')
ns = [r for r in cor if r['cls'].startswith('NONCE_REUSE')]
matrix(ns, ok, 'NONCE_REUSE only (the Valsaraj key-recovery condition)')
u = [r for r in cor if fp(r) == BASE]
print(f'\nundetectable corrupting: {len(u)}/{len(cor)} = {100*len(u)/len(cor) if cor else 0:.2f}%')
if ns:
    un = [r for r in ns if fp(r) == BASE]
    print(f'undetectable NONCE_REUSE: {len(un)}/{len(ns)} = {100*len(un)/len(ns):.2f}%')
dead = [r for r in ok if fp(r) != BASE]
if dead:
    print(f'\ncorrect-key runs at a NON-baseline fingerprint: {len(dead)}')
    for f_, n in collections.Counter(fp(r) for r in dead).most_common():
        print(f'    {f_}  dcyc={f_[0]-BASE[0]:+d}  n={n}')
    print('  A nonce add skipped on a loop\'s LAST iteration updates a dead')
    print('  value, so the key is correct and only the cycle count moves.')
    print('  These are the entry\'s intrinsic false positives: a real')
    print('  instruction skip that no counter rule can separate from the')
    print('  key-corrupting one, because the signature is identical.')
print('\n=== ambiguous fingerprints ===')
t = collections.defaultdict(set)
for r in valid: t[fp(r)].add('corrupt' if r in cor else 'correct')
for f_, s in sorted(t.items()):
    n = sum(1 for r in valid if fp(r) == f_)
    print(f'  {f_}  n={n:5d}  {"AMBIGUOUS" if len(s) > 1 else sorted(s)[0]}')
