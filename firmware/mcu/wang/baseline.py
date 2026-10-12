"""100 unglitched transposes: fingerprint and oracle check."""
import argparse, collections, csv, sys
from cwcommon import connect, reboot, run_once, classify, fingerprint, SEL, NSITE

ap = argparse.ArgumentParser()
ap.add_argument('--n', type=int, default=100)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--freq', type=int, default=0,
                help='raise the target clock, e.g. 14740000.  Baud scales\n'
                     'automatically.  DWT counts CYCLES, so the baseline\n'
                     'fingerprint should be UNCHANGED -- if it moves, flash\n'
                     'wait states changed and the comparison is no longer clean.')
a = ap.parse_args()

DIAG = """
No readable frame.  SHORTFRAME with 'invalid command (0x01)' means the hex was
never programmed: make clean PLATFORM=CW308_STM32F4 CRYPTO_TARGET=NONE, make,
python flash.py.  BADMAGIC means another entry's firmware is on the board.
"""
scope, target = connect(**({'freq': a.freq} if a.freq else {})); reboot(scope, target)
fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None, sel=a.sel)
    if not isinstance(d, dict):
        bad += 1; print(f'  run {i}: {d}')
        if i == 0: print(DIAG); scope.dis(); sys.exit(1)
        continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), ndiff=d['ndiff'], nplane0=d['nplane0'],
                     nset=d['nset'], dirty=d['dirty'], bck='0x%08X' % d['bck'],
                     ick='0x%08X' % d['ick'], cyc=d['cyc'], cpi=d['cpi'],
                     lsu=d['lsu'], fold=d['fold']))
if not rows:
    print(f'\nvalid=0 unreadable={bad}'); print(DIAG); scope.dis(); sys.exit(1)
with open('baseline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp, n in fps.most_common(): print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
nd = collections.Counter(r['ndiff'] for r in rows)
ns = collections.Counter(r['nset']  for r in rows)
bc = collections.Counter(r['bck']   for r in rows)
ic = collections.Counter(r['ick']   for r in rows)
print(f'ndiff: {dict(nd)}   plane cksum: {dict(bc)}   input cksum: {dict(ic)}')
nset = list(ns)[0] if len(ns) == 1 else None
print(f'nset (sliced bits that are 1): {dict(ns)}')
if nset is not None:
    print(f'  -> of the {NSITE} OR commits, {nset} are observable if skipped '
          f'({100.0*nset/NSITE:.1f}%); the other {NSITE-nset} write a 0 bit '
          f'and leave the planes identical.')
ok = (list(nd) == [0] and len(bc) == 1 and len(ic) == 1 and len(fps) == 1 and bad == 0)
print('ORACLE', 'OK -- planes match the reference bit for bit and the transpose '
      'is deterministic' if ok else 'MISMATCH -- stop here')
scope.dis()
