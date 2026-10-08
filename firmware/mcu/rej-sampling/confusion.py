#!/usr/bin/env python3
"""Entry 5 confusion matrix. Positive = any corrupted output (class != normal).
Also reports the detection MARGIN, since this entry's faults range from
0.4% to 1.8% of the window - unlike the >90% collapses in entries 1-3."""
import csv
from collections import Counter
load = lambda fn: list(csv.DictReader(open(fn)))
base, camp = load("baseline.csv"), load("campaign.csv")
key = lambda r: (int(r["cyc"]), int(r["cpi"]), int(r["lsu"]), int(r["fold"]))
fps = Counter(key(r) for r in base); ref = fps.most_common(1)[0][0]
print(f"baseline fingerprint = {ref}   [{len(base)} runs]")
if len(fps) > 1: print(f"WARNING: baseline not deterministic -> {dict(fps)}")

TP=FP=TN=FN=0; grid=Counter(); marg={}
for r in base + camp:
    cls = r["class"].split('@')[0]; dev = key(r) != ref
    grid[(cls, dev)] += 1
    if cls != 'normal':
        marg.setdefault(cls, set()).add(int(r["cyc"]) - ref[0])
    pos = cls != 'normal'
    if   pos and dev: TP += 1
    elif pos:         FN += 1
    elif dev:         FP += 1
    else:             TN += 1
f = lambda a,b: a/(a+b) if a+b else float('nan')
print("\n                   detected   not detected")
print(f"corrupted output {TP:9d} {FN:14d}")
print(f"correct output   {FP:9d} {TN:14d}")
print(f"\nTPR={f(TP,FN):.4f}  FPR={f(FP,TN):.4f}  precision={f(TP,FP):.4f}\n")
print("breakdown by class, with cycle margin:")
for cls in sorted({c for c,_ in grid}):
    d, nd = grid[(cls,True)], grid[(cls,False)]
    m = sorted(marg.get(cls, []))
    ms = (f"  dcyc={m[0]:+d}..{m[-1]:+d} ({abs(m[0])/ref[0]*100:.2f}%..{abs(m[-1])/ref[0]*100:.2f}%)"
          if m else "")
    print(f"  {cls:22s} detected={d:5d}  missed={nd:5d}{ms}")
print("\nA class with missed>0 at dcyc=0 is invisible to all four counters.")
