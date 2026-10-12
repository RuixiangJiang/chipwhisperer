"""N glitched transposes at one fixed (ext_offset,width,offset)."""
import argparse, collections, csv
from cwcommon import connect, reboot, run_safe, classify, safe, site, SEL, NSITE

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, required=True)
ap.add_argument('--offset', type=int, required=True)
ap.add_argument('--repeat', type=int, default=1)
ap.add_argument('--n', type=int, default=1000)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--out', default='campaign.csv')
ap.add_argument('--freq', type=int, default=0,
                help='raise the target clock, e.g. 14740000.  Baud scales\n'
                     'automatically.  DWT counts CYCLES, so the baseline\n'
                     'fingerprint should be UNCHANGED -- if it moves, flash\n'
                     'wait states changed and the comparison is no longer clean.')
a = ap.parse_args()

scope, target = connect(**({'freq': a.freq} if a.freq else {})); reboot(scope, target)
rows, crashes, got, streak = [], 0, 0, 0
while got < a.n:
    d, crashed = run_safe(scope, target, glitch=(a.ext_offset, a.width, a.offset,
                                                 a.repeat), sel=a.sel)
    if crashed:
        crashes += 1; streak += 1
        if streak >= 50:
            print(f'\n*** 50 crashes in a row -- the target is not recovering. '
                  f'Collected {got} of {a.n}; stopping.', flush=True)
            break
        continue
    streak = 0
    d = safe(d); st = site(d)
    rows.append(dict(run=got, cls=classify(d),
                     plane=st[0] if st else -1, zbit=st[1] if st else -1,
                     lane=st[2] if st else -1, ndiff=d['ndiff'], fdir=d['fdir'],
                     nplane0=d['nplane0'], nset=d['nset'], dirty=d['dirty'],
                     bck='0x%08X' % d['bck'], cyc=d['cyc'], cpi=d['cpi'],
                     lsu=d['lsu'], fold=d['fold']))
    got += 1
    if got % 100 == 0:
        print(f'  {got}/{a.n}  crashes={crashes}', flush=True)

with open(a.out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls = collections.Counter(r['cls'].split('[')[0].split('(')[0] for r in rows)
for k, v in cls.most_common():
    print(f'  {k:14s} {v:5d}  {100*v/got:6.2f}%')
sk = [r for r in rows if r['cls'].startswith('OR_SKIP')]
print(f"\nOR_SKIP (the bitwise-OR skip): {len(sk)}/{got} = {100*len(sk)/got:.2f}%")
if sk:
    nset = int(sk[0]['nset'])
    print(f"  observable-site rate at this input: {nset}/{NSITE} = "
          f"{100.0*nset/NSITE:.1f}%, so a skip rate of {100*len(sk)/got:.2f}% "
          f"implies roughly {100*len(sk)/got/(nset/NSITE):.2f}% of runs skipped "
          f"an OR, counting the silent ones.")
    print('  planes hit:', dict(collections.Counter(r['zbit'] for r in sk)))
    print('  lanes hit :', dict(collections.Counter(r['lane'] for r in sk).most_common(8)))
    print('  fingerprints:',
          dict(collections.Counter((r['cyc'], r['cpi'], r['lsu'], r['fold']) for r in sk)))
print('\n=== fingerprint per class ===')
fps = collections.defaultdict(collections.Counter)
for r in rows: fps[r['cls'].split('[')[0].split('(')[0]][(r['cyc'], r['cpi'], r['lsu'], r['fold'])] += 1
for k in cls:
    print(f'  {k:14s} ' + ' + '.join(f'{f} * {n}' for f, n in fps[k].most_common(4)))
scope.dis()
