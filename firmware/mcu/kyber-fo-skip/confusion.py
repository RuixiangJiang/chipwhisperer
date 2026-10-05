#!/usr/bin/env python3
"""Step 6: confusion matrix. Positive = FO bypass (fail==0)."""
import csv
from collections import Counter
load = lambda fn: list(csv.DictReader(open(fn)))
base, camp = load("baseline.csv"), load("campaign.csv")

key = lambda r: (int(r["cyc"]), int(r["cpi"]), int(r["lsu"]), int(r["fold"]))
ref = Counter(key(r) for r in base).most_common(1)[0][0]
assert len(set(key(r) for r in base)) == 1, "baseline not deterministic!"
print(f"baseline fingerprint (cyc,cpi,lsu,fold) = {ref}  [{len(base)} runs]\n")

TP = FP = TN = FN = 0; blind = 0
for r in base + camp:
    fault = int(r["fail"]) == 0          # ground truth: security-relevant fault
    dev   = key(r) != ref                # detector: any counter deviation
    if   fault and dev: TP += 1
    elif fault:         FN += 1
    elif dev:           FP += 1; blind += 1
    else:               TN += 1

tpr  = TP/(TP+FN) if TP+FN else float('nan')
fpr  = FP/(FP+TN) if FP+TN else float('nan')
prec = TP/(TP+FP) if TP+FP else float('nan')
print("                 detected   not detected")
print(f"FO bypass      {TP:9d} {FN:14d}")
print(f"correct output {FP:9d} {TN:14d}")
print(f"\nTPR={tpr:.4f}  FPR={fpr:.4f}  precision={prec:.4f}")
print(f"\nNOTE: {blind} runs deviated in counters with correct output.")
print("Sticky OR means most in-loop faults cannot change the output once")
print("byte 0 differs -- these are oracle-blind, not detector errors.")
print("Report separately; folding them into FPR measures the oracle, not the rule.")
