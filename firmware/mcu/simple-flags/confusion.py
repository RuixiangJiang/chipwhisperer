"""Confusion matrices for the Delvaux flag detector, and the HPC detector on
the SAME runs, side by side.

Positive  = the add was corrupted (observed result != correct sum).
Flag detector  : NZCV after the add != the correct NZCV.
HPC detector   : DWT fingerprint != baseline.
Negative class = glitched runs whose result came out correct.
Excluded       = CANARY_DIRTY and unreadable frames."""
import argparse, collections, csv
ap = argparse.ArgumentParser()
ap.add_argument('csvfile', nargs='?', default='campaign.csv')
ap.add_argument('--neg', action='append', default=[])
ap.add_argument('--base', required=True, help='cyc,cpi,lsu,fold baseline')
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
rows = list(csv.DictReader(open(a.csvfile)))
for extra in a.neg:
    rows += list(csv.DictReader(open(extra))); print(f'pooled negatives from {extra}')
def fp(r): return (int(r['cyc']), int(r['cpi']), int(r['lsu']), int(r['fold']))
def I(r,k): return int(r[k])

bad   = [r for r in rows if r['cls'].startswith(('BADFRAME','NOFRAME','SHORTFRAME','BADMAGIC','BAD_COUNTERS'))]
dirty = [r for r in rows if r['cls'] in ('CANARY_DIRTY','FRAME_CORRUPT','STORE_GLITCH')]
valid = [r for r in rows if r not in bad and r not in dirty]
pos   = [r for r in valid if not I(r,'res_ok')]     # the add was corrupted
neg   = [r for r in valid if I(r,'res_ok')]         # glitched but correct
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)} scorable={len(valid)} unscorable={len(dirty)} unreadable={len(bad)}')
print(f'  corrupted add = {len(pos)}   correct add = {len(neg)}')

print('\n=== distribution ===')
cls = collections.Counter(r['cls'].split('(')[0] for r in rows)
for k,v in cls.most_common(): print(f'  {k:16s} {v:5d}  {100*v/len(rows):6.2f}%')

def matrix(name, det):
    TP=sum(1 for r in pos if det(r)); FN=len(pos)-TP
    FP=sum(1 for r in neg if det(r)); TN=len(neg)-FP
    tpr=TP/len(pos) if pos else 0; fpr=FP/len(neg) if neg else 0
    pr=TP/(TP+FP) if TP+FP else 0; acc=(TP+TN)/(len(pos)+len(neg)) if valid else 0
    print(f'  {name:18s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  '
          f'TPR={tpr:.4f} FPR={fpr:.4f} PREC={pr:.4f} ACC={acc:.4f}')

print(f'\n=== detectors, positive = corrupted add (pos={len(pos)}, neg={len(neg)}) ===')
matrix('FLAGS (NZCV)', lambda r: not I(r,'flags_ok'))
matrix('HPC full tuple', lambda r: fp(r) != BASE)
matrix('HPC CYCCNT',     lambda r: int(r['cyc'])  != BASE[0])
matrix('HPC CPICNT',     lambda r: int(r['cpi'])  != BASE[1])
matrix('HPC LSUCNT',     lambda r: int(r['lsu'])  != BASE[2])
matrix('HPC FOLDCNT',    lambda r: int(r['fold']) != BASE[3])

fb = [r for r in pos if I(r,'flags_ok')]
print(f'\nflag-undetectable corrupting runs (result wrong, NZCV unchanged): '
      f'{len(fb)}/{len(pos)} = {100*len(fb)/len(pos) if pos else 0:.2f}%')
if fb:
    print('  their NZCV (== correct NZCV):', dict(collections.Counter(r['nz_obs'] for r in fb)))
    print('  example corrupt results:', [r['res_obs'] for r in fb[:5]], 'vs correct', fb[0]['cres'])
hb = [r for r in pos if fp(r)==BASE]
print(f'HPC-undetectable corrupting runs (fingerprint == baseline): '
      f'{len(hb)}/{len(pos)} = {100*len(hb)/len(pos) if pos else 0:.2f}%')
both = [r for r in pos if I(r,'flags_ok') and fp(r)==BASE]
print(f'undetectable by BOTH flags and HPC: {len(both)}/{len(pos)} = '
      f'{100*len(both)/len(pos) if pos else 0:.2f}%')
