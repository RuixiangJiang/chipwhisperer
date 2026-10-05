#!/usr/bin/env python3
"""One-time: enumerate every absorb-loop fault outcome -> hyp272.json.
Takes a few seconds (pure-Python Keccak)."""
import json, hashlib
from inc import run
MSG = bytes((i*7+11)&0xFF for i in range(272))
assert run(MSG)[0] == hashlib.shake_256(MSG).digest(64), "model/hashlib mismatch"
hyp = {}
def put(d, label, perms):
    k = d[:8].hex()
    if k not in hyp: hyp[k] = [label, perms]
d,p = run(MSG);                      put(d,'normal',p)
d,p = run(MSG,fault=('outer',1));    put(d,'OUTER_SKIP_after_blk1',p)
for k in (0,1):
    for j in range(136):
        d,p = run(MSG,fault=('inner',k,j)); put(d,f'INNER_blk{k}_stop{j}',p)
json.dump(hyp, open('hyp272.json','w'))
print(f"wrote hyp272.json: {len(hyp)} hypotheses")
print("  normal                :", [k for k,v in hyp.items() if v[0]=='normal'][0])
print("  OUTER_SKIP_after_blk1 :", [k for k,v in hyp.items() if v[0]=='OUTER_SKIP_after_blk1'][0])
