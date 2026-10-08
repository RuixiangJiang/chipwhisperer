#!/usr/bin/env python3
import csv
from collections import Counter, defaultdict
rows = list(csv.DictReader(open('map_rej.csv')))
print(f"hit rows: {len(rows)}")
print("classes:", dict(Counter(r['class'].split('@')[0] for r in rows)))
print()
by = defaultdict(Counter)
for r in rows: by[int(r['ext_offset'])][r['class'].split('@')[0]] += 1
print("=== per-cycle class map (hits only; absent ext = dead) ===")
for eo in sorted(by):
    print(f"  ext={eo:4d} (m22={eo%22:2d})  " +
          ', '.join(f'{k}x{v}' for k,v in by[eo].most_common(4)))
print()
for want in ('STORE_SKIP','CTR_INC_SKIP','ACCEPT_BAD'):
    sel=[r for r in rows if r['class'].startswith(want)]
    print(f"{want}: {len(sel)}")
    for r in sel[:25]:
        print(f"   ext={r['ext_offset']:>4s} w={r['width']:>4s} off={r['offset']:>5s}  "
              f"{r['class']:18s} ctr={r['ctr']} n_diff={r['n_diff']} "
              f"first_diff={r['first_diff']} a[k]={r['bad']} dcyc={r['dcyc']}")
