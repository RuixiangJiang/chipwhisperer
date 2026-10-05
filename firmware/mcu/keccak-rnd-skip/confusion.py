#!/usr/bin/env python3
"""Step 6: confusion matrix. Positive = RND_SKIPPED (hedging defeated)."""
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
    pos = (cls == 'RND_SKIPPED')
    if   pos and dev: TP += 1
    elif pos:         FN += 1
    elif dev:         FP += 1
    else:             TN += 1

tpr  = TP/(TP+FN) if TP+FN else float('nan')
fpr  = FP/(FP+TN) if FP+TN else float('nan')
prec = TP/(TP+FP) if TP+FP else float('nan')
print("                  detected   not detected")
print(f"RND_SKIPPED     {TP:9d} {FN:14d}")
print(f"everything else {FP:9d} {TN:14d}")
print(f"\nTPR={tpr:.4f}  FPR={fpr:.4f}  precision={prec:.4f}\n")

print("breakdown by output class:")
for cls in ('normal','RND_SKIPPED','other'):
    d, nd = grid[(cls,True)], grid[(cls,False)]
    if d or nd: print(f"  {cls:12s} detected={d:5d}  not detected={nd:5d}")
print("\n'other' = rho'' matched neither hypothesis: a real fault, but not the")
print("Jendral call-skip. Counted against FPR above only because it is not the")
print("target fault -- report it as its own class, not as detector error.")
print("'normal' + detected = oracle-blind: counters moved, output unchanged.")
