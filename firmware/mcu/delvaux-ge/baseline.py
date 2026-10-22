import argparse,collections,csv,sys
from cwcommon import connect,reboot,run_once,classify,fingerprint,SEL
ap=argparse.ArgumentParser()
ap.add_argument('--n',type=int,default=100); ap.add_argument('--sel',type=int,default=SEL)
ap.add_argument('--freq',type=int,default=0); a=ap.parse_args()
scope,target=connect(**({'freq':a.freq} if a.freq else {})); reboot(scope,target)
fps,rows,bad=collections.Counter(),[],0
for i in range(a.n):
    d=run_once(scope,target,glitch=None,sel=a.sel)
    if not isinstance(d,dict):
        bad+=1; print(f'  run {i}: {d}')
        if i==0: print('No frame -- reflash / check SS_VER_2_1.'); scope.dis(); sys.exit(1)
        continue
    fps[fingerprint(d)]+=1
    rows.append(dict(run=i,cls=classify(d),ge_obs='0x%X'%d['ge_obs'],ge_ref='0x%X'%d['ge_ref'],
                     lo=d['lo'],hi=d['hi'],poly_ok=d['poly_ok'],hit=d['hit'],
                     fnv='0x%08X'%d['fnv'],cyc=d['cyc'],cyc_at=d['cyc_at'],cpi=d['cpi'],lsu=d['lsu'],fold=d['fold']))
if not rows: print('valid=0'); scope.dis(); sys.exit(1)
with open('baseline.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\nvalid={len(rows)} unreadable={bad}')
print('distinct fingerprints:',len(fps))
for fp,n in fps.most_common(): print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
ge=collections.Counter(r['ge_obs'] for r in rows); fv=collections.Counter(r['fnv'] for r in rows)
print(f'target GE: {dict(ge)}   output checksum: {dict(fv)}')
print(f'target add lanes (lo,hi) = ({rows[0]["lo"]},{rows[0]["hi"]})')
ca=collections.Counter(r.get('cyc_at') for r in rows)
print(f'>>> target add is at cycle {list(ca)[0] if len(ca)==1 else dict(ca)} '
      f'-- glitch ext near this value <<<')
ok=(len(fps)==1 and bad==0 and len(fv)==1 and all(r["hit"] for r in rows))
print('ORACLE','OK -- deterministic output, target reached every run, 1 fingerprint' if ok else 'MISMATCH -- stop here')
scope.dis()
