"""100 unglitched key generations: fingerprint and oracle check."""
import argparse, collections, csv, sys
from cwcommon import connect, reboot, run_once, classify, fingerprint, SEL, NPOLY, CLEAN_SHIFT

ap = argparse.ArgumentParser()
ap.add_argument('--n', type=int, default=100)
ap.add_argument('--sel', type=int, default=SEL)
a = ap.parse_args()

DIAG = """
No readable frame from the target.  In order of likelihood:

  BADMAGIC / wrong frame length
      the target is running a DIFFERENT firmware (an earlier entry's) that
      answers on this command char.  Reflash:
          make clean PLATFORM=CW308_STM32F4 CRYPTO_TARGET=NONE
          make       PLATFORM=CW308_STM32F4 CRYPTO_TARGET=NONE
          python flash.py

  SHORTFRAME with 'Unexpected start to command 0x65' and 'invalid command (0x01)'
      0x65 is an 'e' error frame and 0x01 is SS_ERR_CMD: the device does not
      have command 'k' registered, i.e. valsaraj.hex was never programmed.
      Same reflash sequence as above.

  NOFRAME / read timed out
      the device hard-faulted or hung inside do_keygen, or SS_VER is wrong.
      Check that the build used SS_VER_2_1 and that connect() opens
      cw.target(scope, cw.targets.SimpleSerial2), not the bare cw.target(scope).
"""

scope, target = connect(); reboot(scope, target)
fps, rows, bad = collections.Counter(), [], 0
for i in range(a.n):
    d = run_once(scope, target, glitch=None, sel=a.sel)
    if not isinstance(d, dict):
        bad += 1
        print(f'  run {i}: {d}')
        if i == 0:                      # fail fast, do not grind through 100
            print(DIAG); scope.dis(); sys.exit(1)
        continue
    fps[fingerprint(d)] += 1
    rows.append(dict(run=i, cls=classify(d), nonce=d['nonce'],
                     shift='0x%04X' % d['shift'], nok=d['nok'], ndup=d['ndup'],
                     nsent=d['nsent'], dirty=d['dirty'],
                     mck='0x%08X' % d['mck'], mh0='0x%08X' % d['mh0'],
                     cyc=d['cyc'], cpi=d['cpi'], lsu=d['lsu'], fold=d['fold']))

if not rows:
    print(f'\nvalid=0  unreadable={bad}'); print(DIAG); scope.dis(); sys.exit(1)

with open('baseline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\nvalid={len(rows)}  unreadable={bad}')
print('distinct fingerprints:', len(fps))
for fp, n in fps.most_common():
    print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
ne = collections.Counter(r['nonce'] for r in rows)
sh = collections.Counter(r['shift'] for r in rows)
mc = collections.Counter(r['mck']   for r in rows)
print(f'nonce_end: {dict(ne)}   shift: {dict(sh)}   key cksums: {dict(mc)}')
ok = (list(ne) == [NPOLY] and list(sh) == ['0x%04X' % CLEAN_SHIFT]
      and len(mc) == 1 and len(fps) == 1 and bad == 0)
print('ORACLE', 'OK -- nonce reaches %d, every polynomial matches its own nonce, '
      'key is deterministic' % NPOLY if ok else 'MISMATCH -- stop here')
scope.dis()
