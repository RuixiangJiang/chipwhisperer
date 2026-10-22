"""GE-flag detector vs the four DWT counters, same runs.
Positive = inverse-NTT OUTPUT corrupted (the Delvaux fault).
GE detector = target add GE != correct GE.  HPC = fingerprint != baseline.
Negative  = glitched runs whose output is correct.
Excluded  = CANARY_DIRTY, TARGET_MISSED, unreadable."""
import argparse,collections,csv
ap=argparse.ArgumentParser()
ap.add_argument('csvfile',nargs='?',default='campaign.csv')
ap.add_argument('--neg',action='append',default=[]); ap.add_argument('--base',required=True)
a=ap.parse_args()
BASE=tuple(int(x) for x in a.base.split(','))
rows=list(csv.DictReader(open(a.csvfile)))
for e in a.neg: rows+=list(csv.DictReader(open(e))); print(f'pooled negatives from {e}')
def fp(r): return (int(r['cyc']),int(r['cpi']),int(r['lsu']),int(r['fold']))
def I(r,k): return int(r[k])
bad=[r for r in rows if r['cls'].startswith(('BADFRAME','NOFRAME','SHORTFRAME','BADMAGIC','BAD_COUNTERS'))]
exc=[r for r in rows if r['cls'] in ('CANARY_DIRTY','TARGET_MISSED','FRAME_CORRUPT')]
valid=[r for r in rows if r not in bad and r not in exc]
pos=[r for r in valid if not I(r,'poly_ok')]
neg=[r for r in valid if I(r,'poly_ok')]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)} scorable={len(valid)} excluded={len(exc)} unreadable={len(bad)}')
print(f'  output corrupted = {len(pos)}   output correct = {len(neg)}')
print('\n=== distribution ===')
cls=collections.Counter(r['cls'].split('(')[0] for r in rows)
for k,v in cls.most_common(): print(f'  {k:16s} {v:5d}  {100*v/len(rows):6.2f}%')
def mat(name,det):
    TP=sum(1 for r in pos if det(r)); FN=len(pos)-TP
    FP=sum(1 for r in neg if det(r)); TN=len(neg)-FP
    tpr=TP/len(pos) if pos else 0; fpr=FP/len(neg) if neg else 0
    pr=TP/(TP+FP) if TP+FP else 0; acc=(TP+TN)/(len(pos)+len(neg)) if valid else 0
    print(f'  {name:16s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  TPR={tpr:.4f} FPR={fpr:.4f} PREC={pr:.4f} ACC={acc:.4f}')
print(f'\n=== detectors, positive = corrupted output (pos={len(pos)}, neg={len(neg)}) ===')
mat('GE flags',   lambda r: not I(r,'flags_ok'))
mat('HPC full',   lambda r: fp(r)!=BASE)
mat('HPC CYCCNT', lambda r: int(r['cyc'])!=BASE[0])
mat('HPC CPICNT', lambda r: int(r['cpi'])!=BASE[1])
mat('HPC LSUCNT', lambda r: int(r['lsu'])!=BASE[2])
mat('HPC FOLDCNT',lambda r: int(r['fold'])!=BASE[3])
# --- the scenario of interest: faults HPC CANNOT see (fingerprint==baseline) ---
hpc_blind=[r for r in pos if fp(r)==BASE]
if hpc_blind:
    ge_tp=sum(1 for r in hpc_blind if not I(r,'flags_ok')); ge_fn=len(hpc_blind)-ge_tp
    print(f'\n=== GE detector on the HPC-BLIND subset (fingerprint==baseline, pos={len(hpc_blind)}) ===')
    print(f'  this is the "where HPC fails" population -- every run here is invisible to all 4 counters')
    print(f'  GE: TP={ge_tp} FN={ge_fn}  TPR={ge_tp/len(hpc_blind):.4f}')
    print(f'  GE-blind AND HPC-blind (invisible to both): {ge_fn}/{len(hpc_blind)} = {100*ge_fn/len(hpc_blind):.2f}%')
else:
    print('\n=== no HPC-blind corrupting runs in this campaign ===')
    print('  every corrupting glitch here left a timing footprint; pick an ext whose')
    print('  corrupting rows sit at dcyc=0 (fingerprint==baseline) to study the HPC-blind case.')

at_add=[r for r in pos if not I(r,'res_ok')]
elsewhere=[r for r in pos if I(r,'res_ok')]
print(f'\nof {len(pos)} corrupting runs: {len(at_add)} faulted the target add, {len(elsewhere)} faulted elsewhere')
if at_add:
    TPa=sum(1 for r in at_add if not I(r,'flags_ok'))
    print(f'GE detector on target-add faults only: TP={TPa} FN={len(at_add)-TPa} TPR={TPa/len(at_add):.4f}')
    gba=[r for r in at_add if I(r,'flags_ok')]
    print(f'  GE-blind among target-add faults: {len(gba)}/{len(at_add)} = {100*len(gba)/len(at_add):.2f}%')
    if gba: print('    their GE (== correct GE 0x3):',dict(collections.Counter(r['ge_obs'] for r in gba)))
gb=[r for r in pos if I(r,'flags_ok')]
print(f'overall GE-undetectable corrupting runs: {len(gb)}/{len(pos)} = {100*len(gb)/len(pos) if pos else 0:.2f}%')
hb=[r for r in pos if fp(r)==BASE]
print(f'HPC-undetectable corrupting runs (fingerprint==baseline): {len(hb)}/{len(pos)} = {100*len(hb)/len(pos) if pos else 0:.2f}%')
both=[r for r in pos if I(r,'flags_ok') and fp(r)==BASE]
print(f'undetectable by BOTH: {len(both)}/{len(pos)} = {100*len(both)/len(pos) if pos else 0:.2f}%')
