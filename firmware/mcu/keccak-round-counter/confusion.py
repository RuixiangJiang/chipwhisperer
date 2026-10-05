#!/usr/bin/env python3
"""Step 6: confusion matrix. Positive = any wrong round count."""
import csv
from collections import Counter
load = lambda fn: list(csv.DictReader(open(fn)))
base, camp = load("baseline.csv"), load("campaign.csv")

key = lambda r: (int(r["cyc"]), int(r["cpi"]), int(r["lsu"]), int(r["fold"]))
fps = Counter(key(r) for r in base)
ref = fps.most_common(1)[0][0]
print(f"baseline fingerprint (cyc,cpi,lsu,fold) = {ref}   [{len(base)} runs]")
if len(fps) > 1: print(f"WARNING: baseline not deterministic -> {dict(fps)}")
print()

TP=FP=TN=FN=0
grid = Counter()
for r in base + camp:
    cls = r["class"]; dev = key(r) != ref
    grid[(cls, dev)] += 1
    pos = (cls != 'normal')          # any round count other than 24
    if   pos and dev: TP += 1
    elif pos:         FN += 1
    elif dev:         FP += 1
    else:             TN += 1

tpr  = TP/(TP+FN) if TP+FN else float('nan')
fpr  = FP/(FP+TN) if FP+TN else float('nan')
prec = TP/(TP+FP) if TP+FP else float('nan')
print("                    detected   not detected")
print(f"wrong round count {TP:9d} {FN:14d}")
print(f"correct (24)      {FP:9d} {TN:14d}")
print(f"\nTPR={tpr:.4f}  FPR={fpr:.4f}  precision={prec:.4f}\n")

print("breakdown by recovered round count:")
order = ['normal'] + [f'ROUNDS_{n}' for n in range(22,1,-2)] + ['STATE_UNPERMUTED','other']
for cls in order:
    d, nd = grid[(cls,True)], grid[(cls,False)]
    if d or nd: print(f"  {cls:12s} detected={d:5d}  not detected={nd:5d}")
print("\nROUNDS_n = permutation ran n rounds instead of 24. ROUNDS_0 = identity:")
print("the absorbed message is read straight back out. 'other' = matched no")
print("round count (odd start round, or a data fault inside the permutation).")
