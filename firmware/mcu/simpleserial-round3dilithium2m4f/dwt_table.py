#!/usr/bin/env python3
"""
dwt_table.py -- aggregate one or more dwt_detect.py CSVs into a single
summary table of DWT counter behaviour per outcome class.

Classes are reported in a fixed order:
    clean/normal        unglitched reference runs -> defines the baseline
    glitch/hit          data[0] 0x00, rest unchanged  (load returns zero)
    glitch/store_skip   data[0] 0xA5, rest unchanged  (store never executes;
                                                       0xA5 is the harness
                                                       prefill sentinel)
    glitch/normal       pulse delivered, output unchanged -> control
    glitch/other        any wider corruption (r0 clobber, address+4, ...)

The baseline is the modal counter tuple across clean/normal runs. A run is
"flagged" if any counter differs from that baseline, which is the same rule
dwt_detect.py uses, applied uniformly here so every class is scored the
same way.

Detection rates carry Wilson 95% intervals. For clean/normal the rate is a
false positive rate; for every other class it is a true positive rate.

Usage
    python3 dwt_table.py dwt_runs.csv b_miss.csv b_store2.csv
    python3 dwt_table.py *.csv --tag dwt_runs.csv=18155 --tag b_miss.csv=18160 \
                               --tag b_store2.csv=18171
    python3 dwt_table.py *.csv --markdown > counters.md
"""

import argparse
import csv
import math
import os
from collections import Counter, defaultdict

CTR = ["CYCCNT", "CPICNT", "EXCCNT", "SLEEPCNT", "LSUCNT", "FOLDCNT"]
WIDTH = {"CYCCNT": 32, "CPICNT": 8, "EXCCNT": 8,
         "SLEEPCNT": 8, "LSUCNT": 8, "FOLDCNT": 8}

ORDER = [("clean", "normal"),
         ("glitch", "hit"),
         ("glitch", "store_skip"),
         ("glitch", "normal"),
         ("glitch", "other")]

PRETTY = {
    ("clean", "normal"):       "clean / normal",
    ("glitch", "hit"):         "glitch / hit",
    ("glitch", "store_skip"):  "glitch / store_skip",
    ("glitch", "normal"):      "glitch / normal",
    ("glitch", "other"):       "glitch / other",
}

NOTE = {
    ("clean", "normal"):      "unglitched baseline",
    ("glitch", "hit"):        "load returns 0 -- the Sec 6.4 fault",
    ("glitch", "store_skip"): "store never executes (0xA5 sentinel survives)",
    ("glitch", "normal"):     "pulse delivered, no architectural effect",
    ("glitch", "other"):      "wider corruption (r0 clobber, addr+4)",
}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, c - h), 100 * min(1.0, c + h))


def load(paths):
    rows = []
    for p in paths:
        with open(p, newline="") as fh:
            for r in csv.DictReader(fh):
                try:
                    vals = tuple(int(r[c]) for c in CTR)
                except (KeyError, ValueError):
                    continue
                rows.append({"file": os.path.basename(p),
                             "source": r["source"],
                             "label": r["label"],
                             "vals": vals})
    return rows


def fmt_counter(values):
    """Render a counter's distribution compactly."""
    c = Counter(values)
    if len(c) == 1:
        return str(next(iter(c)))
    parts = [f"{v}x{n}" for v, n in sorted(c.items())]
    if len(parts) <= 3:
        return " ".join(parts)
    return f"{min(c)}..{max(c)} ({len(c)} vals)"


def baseline_of(rows):
    clean = [r["vals"] for r in rows
             if r["source"] == "clean" and r["label"] == "normal"]
    if not clean:
        return None
    return Counter(clean).most_common(1)[0][0]


def summarize(rows, base, tags):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["source"], r["label"])].append(r)

    out = []
    for key in ORDER:
        g = groups.get(key, [])
        if not g:
            continue
        n = len(g)
        flagged = sum(1 for r in g if r["vals"] != base)
        lo, hi = wilson(flagged, n)
        cols = {c: fmt_counter([r["vals"][i] for r in g])
                for i, c in enumerate(CTR)}
        offs = sorted({tags[r["file"]] for r in g if r["file"] in tags})
        out.append({
            "key": key, "n": n, "flagged": flagged,
            "rate": 100.0 * flagged / n, "lo": lo, "hi": hi,
            "cols": cols,
            "offsets": ", ".join(str(o) for o in offs) if offs else "-",
        })
    return out


def print_text(summary, base, rows, tags):
    print("=" * 100)
    print("DWT COUNTER SUMMARY BY OUTCOME CLASS")
    print("=" * 100)
    print(f"  baseline (modal clean tuple): "
          + "  ".join(f"{c}={base[i]}" for i, c in enumerate(CTR)))
    print(f"  total runs with counter data: {len(rows)}")
    print("  8-bit counters wrap at 256; CPICNT/LSUCNT/FOLDCNT values are "
          "residues, not absolute counts.")
    print()

    head = (f"{'class':<21}{'off':>7}{'n':>7}  "
            + "".join(f"{c:>14}" for c in CTR)
            + f"{'flagged':>10}{'95% CI':>16}")
    print(head)
    print("-" * len(head))
    for s in summary:
        print(f"{PRETTY[s['key']]:<21}{s['offsets']:>7}{s['n']:>7}  "
              + "".join(f"{s['cols'][c]:>14}" for c in CTR)
              + f"{s['rate']:>9.1f}%"
              + f"{'[' + format(s['lo'], '.1f') + ', ' + format(s['hi'], '.1f') + ']':>16}")
    print()
    for s in summary:
        print(f"  {PRETTY[s['key']]:<21} {NOTE[s['key']]}")

    # Per-file breakdown, since different files are different offsets.
    print()
    print("=" * 100)
    print("BY SOURCE FILE")
    print("=" * 100)
    byfile = defaultdict(lambda: defaultdict(int))
    for r in rows:
        byfile[r["file"]][(r["source"], r["label"])] += 1
    for f in sorted(byfile):
        tag = f" (ext_offset {tags[f]})" if f in tags else ""
        print(f"  {f}{tag}")
        for key in ORDER:
            if byfile[f].get(key):
                sub = [r for r in rows if r["file"] == f
                       and (r["source"], r["label"]) == key]
                fl = sum(1 for r in sub if r["vals"] != base)
                lo, hi = wilson(fl, len(sub))
                print(f"      {PRETTY[key]:<21} n={len(sub):<6} "
                      f"flagged {fl:<6} {100.0*fl/len(sub):5.1f}%  "
                      f"[{lo:.1f}, {hi:.1f}]")
        print()


def print_markdown(summary, base, rows):
    print("**Baseline (modal clean tuple):** "
          + ", ".join(f"`{c}={base[i]}`" for i, c in enumerate(CTR)) + "\n")
    print("| class | n | " + " | ".join(CTR) + " | detected | 95% CI |")
    print("|---|---|" + "---|" * len(CTR) + "---|---|")
    for s in summary:
        print(f"| {PRETTY[s['key']]} | {s['n']} | "
              + " | ".join(f"`{s['cols'][c]}`" for c in CTR)
              + f" | {s['rate']:.1f}% | [{s['lo']:.1f}, {s['hi']:.1f}] |")
    print()
    for s in summary:
        print(f"- **{PRETTY[s['key']]}** — {NOTE[s['key']]}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--tag", action="append", default=[],
                    metavar="FILE=OFFSET",
                    help="label a file with the ext_offset it was run at")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()

    tags = {}
    for t in args.tag:
        if "=" in t:
            k, v = t.split("=", 1)
            tags[os.path.basename(k)] = v

    rows = load(args.csv)
    if not rows:
        print("no rows loaded")
        return
    base = baseline_of(rows)
    if base is None:
        print("no clean/normal rows -- cannot establish a baseline")
        return

    summary = summarize(rows, base, tags)
    if args.markdown:
        print_markdown(summary, base, rows)
    else:
        print_text(summary, base, rows, tags)


if __name__ == "__main__":
    main()