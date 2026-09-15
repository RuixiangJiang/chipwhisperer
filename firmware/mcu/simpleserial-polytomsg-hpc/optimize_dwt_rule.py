#!/usr/bin/env python3
"""Search asymmetric DWT tolerance windows for the best glitch detector.

A rule is a subset of counters, each with its own two-sided window:

    no alarm  <=>  for every counter c in S:  base_c - a_c <= test_c <= base_c + b_c
    alarm     <=>  any counter falls outside its window

a_c and b_c are independent, so the window can be asymmetric. That matters here,
because the two directions mean different things physically. A POSITIVE cycle
deviation is consistent with the glitch pulse inserting a spurious clock edge that
CYCCNT counts without anything being corrupted -- the benign case. A NEGATIVE
deviation means a cycle was genuinely removed, which is what an instruction skip
looks like. If that asymmetry is real, the best rule will tolerate one side and
not the other (e.g. a=0, b=2: flag anything short, ignore small overruns).

A symmetric search cannot express that; it forces a_c == b_c.

Search cost: |S| counters x (max_a+1)(max_b+1) windows each. For the full triple
at the default limits that is 16^3 = 4096 combinations, plus the smaller subsets.
Rows are evaluated as bitmasks rather than nested loops, so the whole search runs
in seconds over 20k+ rows.

GROUND TRUTH
------------
A run is faulted if any architectural variable differed (any_variable_differ),
taken from the function's output. That is available during calibration and not in
deployment: you tune the rule once on a labelled campaign, then deploy it fixed.

Example
-------
    python3 optimize_dwt_rule.py polytomsg_sweep_nodiv.csv --per-seed
    python3 optimize_dwt_rule.py polytomsg_sweep_nodiv.csv --max-a 4 --max-b 4
    python3 optimize_dwt_rule.py polytomsg_sweep_nodiv.csv --min-tpr 0.90
    python3 optimize_dwt_rule.py polytomsg_sweep_nodiv.csv --objective cost --miss-cost 20
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "2.0.0"
SHORT = {"cycles": "CYC", "cpicnt": "CPI", "exccnt": "EXC",
         "sleepcnt": "SLP", "lsucnt": "LSU", "foldcnt": "FLD"}


def truthy(v) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def to_int(v):
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def metrics(tp, fp, tn, fn):
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    alarms = tp + fp
    # A rule that never fires has undefined precision and is useless as a
    # detector; score it zero rather than letting it rank highly.
    prec = tp / alarms if alarms else 0.0
    f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, TPR=tpr, FPR=fpr,
                precision=prec, F1=f1, youden=tpr - fpr)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("csv", type=Path)
    p.add_argument("--counters", default="cycles,cpicnt,lsucnt",
                   help="counters available to the search (default: the three with signal)")
    p.add_argument("--max-a", type=int, default=3,
                   help="largest tolerated NEGATIVE deviation (default 3)")
    p.add_argument("--max-b", type=int, default=3,
                   help="largest tolerated POSITIVE deviation (default 3)")
    p.add_argument("--objective", choices=["f1", "youden", "cost"], default="f1")
    p.add_argument("--miss-cost", type=float, default=10.0,
                   help="for --objective cost: how many false alarms one missed fault "
                        "is worth (default 10)")
    p.add_argument("--per-seed", action="store_true")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--min-tpr", type=float, default=None,
                   help="only report rules with at least this TPR, e.g. 0.90")
    p.add_argument("-o", "--output", type=Path, default=None)
    return p.parse_args()


def window_str(subset, win):
    return " ".join(f"{SHORT[c]}[-{win[c][0]},+{win[c][1]}]" for c in subset)


def search(samples, avail, args, label):
    """samples: list of (dev_dict, is_faulted). Returns the full rule list."""
    n = len(samples)
    all_mask = (1 << n) - 1
    pos_mask = 0
    for i, (_, y) in enumerate(samples):
        if y:
            pos_mask |= 1 << i
    neg_mask = all_mask & ~pos_mask
    n_pos = pos_mask.bit_count()
    n_neg = n - n_pos

    # Per counter: bitmask of rows at each distinct signed deviation.
    by_dev: dict[str, dict[int, int]] = {c: defaultdict(int) for c in avail}
    for i, (dev, _) in enumerate(samples):
        for c in avail:
            by_dev[c][dev[c]] |= 1 << i

    # Per counter, per (a,b): bitmask of rows INSIDE that window.
    inwin: dict[str, dict[tuple[int, int], int]] = {c: {} for c in avail}
    for c in avail:
        for a in range(args.max_a + 1):
            for b in range(args.max_b + 1):
                m = 0
                for d, bits in by_dev[c].items():
                    if -a <= d <= b:
                        m |= bits
                inwin[c][(a, b)] = m

    windows = [(a, b) for a in range(args.max_a + 1) for b in range(args.max_b + 1)]
    results = []
    for k in range(1, len(avail) + 1):
        for subset in itertools.combinations(avail, k):
            for combo in itertools.product(windows, repeat=k):
                win = dict(zip(subset, combo))
                ok = all_mask
                for c in subset:
                    ok &= inwin[c][win[c]]
                alarm = all_mask & ~ok
                tp = (alarm & pos_mask).bit_count()
                fp = (alarm & neg_mask).bit_count()
                m = metrics(tp, fp, n_neg - fp, n_pos - tp)
                m.update(group=label, subset="|".join(SHORT[c] for c in subset),
                         window=window_str(subset, win))
                for c in subset:
                    m[f"a_{SHORT[c]}"] = win[c][0]
                    m[f"b_{SHORT[c]}"] = win[c][1]
                results.append(m)
    return results


def main() -> int:
    args = parse_args()
    with args.csv.open(newline="") as fp:
        rows = [r for r in csv.DictReader(fp) if not truthy(r.get("crashed"))]
    if not rows:
        raise ValueError("no measured rows")
    avail = [c.strip() for c in args.counters.split(",") if c.strip()]
    for c in avail:
        if c not in rows[0]:
            raise ValueError(f"CSV lacks column '{c}'")

    by_seed: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_seed[str(r.get("seed"))].append(r)
    baseline = {}
    for seed, srows in by_seed.items():
        baseline[seed] = {c: Counter(to_int(r[c]) for r in srows).most_common(1)[0][0]
                          for c in avail}
        b = "  ".join(f"{SHORT[c]}={baseline[seed][c]}" for c in avail)
        print(f"seed {seed}: baseline {b}   ({len(srows)} runs)")

    samples, seed_of = [], []
    for r in rows:
        seed = str(r.get("seed"))
        dev = {c: to_int(r[c]) - baseline[seed][c] for c in avail}
        samples.append((dev, truthy(r.get("any_variable_differ"))))
        seed_of.append(seed)

    n_pos = sum(1 for _, y in samples if y)
    print(f"\n{len(samples)} runs, {n_pos} faulted ({n_pos/len(samples):.2%}), "
          f"{len(samples)-n_pos} clean")
    print(f"window search: a in 0..{args.max_a}, b in 0..{args.max_b}, "
          f"counters {'|'.join(SHORT[c] for c in avail)}\n")

    # Signed deviation profile -- this is the asymmetry the search can exploit.
    print("signed deviation, faulted/clean counts (only nonzero deviations shown):")
    for c in avail:
        dp = Counter(d[c] for d, y in samples if y)
        dn = Counter(d[c] for d, y in samples if not y)
        keys = [k for k in sorted(set(dp) | set(dn), key=lambda k: (abs(k), k)) if k != 0][:10]
        if keys:
            print(f"  {SHORT[c]}: " + "  ".join(f"{k:+d}:{dp.get(k,0)}/{dn.get(k,0)}"
                                                for k in keys))
        else:
            print(f"  {SHORT[c]}: no nonzero deviations")
    print()

    def score(m):
        if args.objective == "f1":
            return m["F1"]
        if args.objective == "youden":
            return m["youden"]
        return -(args.miss_cost * m["FN"] + m["FP"])

    groups = [("pooled", samples)]
    if args.per_seed:
        for s in sorted(by_seed):
            groups.append((s, [smp for smp, sd in zip(samples, seed_of) if sd == s]))

    all_results = []
    full_subset = "|".join(SHORT[c] for c in avail)
    for gname, gsamples in groups:
        res = search(gsamples, avail, args, gname)
        for m in res:
            m["score"] = score(m)
        all_results.extend(res)

        cur = next(m for m in res if m["subset"] == full_subset
                   and all(m.get(f"a_{SHORT[c]}") == 0 and m.get(f"b_{SHORT[c]}") == 0
                           for c in avail))
        shown = [m for m in res if args.min_tpr is None or m["TPR"] >= args.min_tpr]
        shown.sort(key=lambda m: -m["score"])

        print(f"=== {gname} ===")
        print(f"  current (exact match, every window [-0,+0]):  TPR {cur['TPR']:.2%}  "
              f"FPR {cur['FPR']:.2%}  precision {cur['precision']:.2%}  F1 {cur['F1']:.3f}")
        if args.min_tpr is not None:
            print(f"  showing only rules with TPR >= {args.min_tpr:.0%} "
                  f"({len(shown)} of {len(res)})")
        print(f"\n  {'window':<36}{'TPR':>9}{'FPR':>8}{'prec':>8}{'F1':>7}"
              f"{'TP':>6}{'FP':>6}{'FN':>5}")
        for m in shown[:args.top]:
            print(f"  {m['window']:<36}{m['TPR']:>9.2%}{m['FPR']:>8.2%}"
                  f"{m['precision']:>8.2%}{m['F1']:>7.3f}{m['TP']:>6}{m['FP']:>6}{m['FN']:>5}")
        print()

    if args.output:
        keys = sorted({k for m in all_results for k in m})
        with args.output.open("w", newline="") as fp:
            w = csv.DictWriter(fp, fieldnames=keys, restval="")
            w.writeheader()
            w.writerows(all_results)
        print(f"full rule table ({len(all_results)} rules) -> {args.output}")

    print("\nnote: precision depends on the fault rate of the campaign it was tuned on.")
    print("TPR and FPR transfer; precision does not.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
