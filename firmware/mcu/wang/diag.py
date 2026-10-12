"""Measure what ONE parameter point actually does, run by run, with timings.

Use this instead of staring at log spam.  It answers, in about 30 seconds:
  - does the target answer when NOT glitched, before and after?
  - of N glitched runs, how many return a frame, and what class?
  - how long does a lost run cost, and is the loss a trigger timeout
    (device never reached the region) or a serial timeout (device ran the
    region and then hung)?
That distinction is the whole diagnosis and the sweep's log cannot show it.
"""
import argparse, collections, time
from cwcommon import (connect, reboot, drain, run_once, classify, fingerprint,
                      quiet, SEL)

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--width', type=int, default=82)
ap.add_argument('--offset', type=int, default=-136)
ap.add_argument('--n', type=int, default=20)
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--verbose', action='store_true', help='let ChipWhisperer log')
ap.add_argument('--freq', type=int, default=0,
                help='raise the target clock, e.g. 14740000.  Baud scales\n'
                     'automatically.  DWT counts CYCLES, so the baseline\n'
                     'fingerprint should be UNCHANGED -- if it moves, flash\n'
                     'wait states changed and the comparison is no longer clean.')
a = ap.parse_args()

scope, target = connect(**({'freq': a.freq} if a.freq else {}))
quiet(not a.verbose)
reboot(scope, target); drain(target)

def clean(tag):
    good = 0
    for i in range(3):
        t = time.time()
        try:
            d = run_once(scope, target, glitch=None, sel=a.sel)
        except Exception as e:
            d = 'EXC:' + str(e)[:40]
        dt = (time.time() - t) * 1000
        ok = isinstance(d, dict)
        good += ok
        print(f'  {tag} {i}: {classify(d) if ok else d:<28s} {dt:6.0f} ms'
              + (f'  fp={fingerprint(d)}' if ok else ''))
    return good

print('=== unglitched, before ===')
before = clean('clean')

print(f'\n=== glitched at ext={a.ext_offset} w={a.width} off={a.offset} ===')
cls, lost = collections.Counter(), collections.Counter()
times = []
for i in range(a.n):
    t = time.time()
    try:
        d = run_once(scope, target, glitch=(a.ext_offset, a.width, a.offset, 1))
    except Exception as e:
        d = 'EXC:' + str(e)[:40]
    dt = (time.time() - t) * 1000
    times.append(dt)
    ok = isinstance(d, dict)
    label = classify(d) if ok else str(d)
    print(f'  run {i:3d}: {label:<28s} {dt:6.0f} ms'
          + (f'  fp={fingerprint(d)}' if ok else ''))
    if ok:
        cls[label.split('[')[0].split('(')[0]] += 1
    else:
        lost['NOTRIGGER (never reached the region)' if d == 'NOTRIGGER'
             else f'{d} (ran the region, then no frame)'] += 1
        try:
            scope.capture()
        except Exception:
            pass
        reboot(scope, target); drain(target)

print('\n=== unglitched, after ===')
after = clean('clean')

print(f'\nresponded : {sum(cls.values())}/{a.n}')
for k, v in cls.most_common():  print(f'   {k:<36s} {v}')
for k, v in lost.most_common(): print(f'   LOST {k:<31s} {v}')
print(f'run time  : min {min(times):.0f} ms  median {sorted(times)[len(times)//2]:.0f} ms '
      f'max {max(times):.0f} ms')
print(f'unglitched sanity: {before}/3 before, {after}/3 after')
if after < 3:
    print('  -> the target does NOT recover after this parameter point.  The')
    print('     glitch is resetting or bricking it, not faulting an instruction.')
elif sum(cls.values()) == 0:
    print('  -> the target recovers but no glitched run ever returns a frame:')
    print('     this width/offset is too strong.  Try narrower widths.')
scope.dis()
