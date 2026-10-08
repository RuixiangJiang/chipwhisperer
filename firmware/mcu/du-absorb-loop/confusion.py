#!/usr/bin/env python3
"""Confusion matrix. Positive = any absorb-loop fault (class != normal)."""
import csv
from collections import Counter
load = lambda fn: list(csv.DictReader(open(fn)))
base, camp = load("baseline.csv"), load("campaign.csv")
key = lambda r: (int(r["cyc"]), int(r["cpi"]), int(r["lsu"]), int(r["fold"]))
fps = Counter(key(r) for r in base); ref = fps.most_common(1)[0][0]
print(f"baseline fingerprint = {ref}   [{len(base)} runs]")
if len(fps) > 1: print(f"WARNING: baseline not deterministic -> {dict(fps)}")
TP=FP=TN=FN=0; grid=Counter()
for r in base + camp:
    cls=r["class"]; dev=key(r)!=ref; grid[(cls,dev)]+=1
    pos = cls!='normal'
    if   pos and dev: TP+=1
    elif pos:         FN+=1
    elif dev:         FP+=1
    else:             TN+=1
f=lambda a,b: a/(a+b) if a+b else float('nan')
print("\n                   detected   not detected")
print(f"absorb fault     {TP:9d} {FN:14d}")
print(f"correct output   {FP:9d} {TN:14d}")
print(f"\nTPR={f(TP,FN):.4f}  FPR={f(FP,TN):.4f}  precision={f(TP,FP):.4f}\n")
print("breakdown by recovered mechanism:")
for cls in sorted({c for c,_ in grid}):
    d,nd = grid[(cls,True)], grid[(cls,False)]
    print(f"  {cls:26s} detected={d:5d}  not detected={nd:5d}")
print("\nA label is only trustworthy if the cycle count agrees: OUTER_SKIP must")
print("drop ~one permutation; an INNER truncation costs ~36 cycles per byte.")
