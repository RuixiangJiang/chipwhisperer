#!/usr/bin/env python3
import csv
from cwcommon import connect, parse, classify
N=100
scope, target = connect()
def run_once():
    target.flush(); target.simpleserial_write('d', b'')
    r=target.simpleserial_read('r',11,timeout=2000)
    return parse(r)
rows=[]
for i in range(N):
    res=run_once()
    if res is None: print(i,"no response"); continue
    rows.append((i,)+res); print(i,res)
with open("baseline.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["run","fail","cyc","cpi","lsu","fold"]); w.writerows(rows)
print(f"wrote baseline.csv ({len(rows)} runs)")
scope.dis(); target.dis()
