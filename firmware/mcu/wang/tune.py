"""Search (width, offset) at a FIXED ext for a pulse that SKIPS an instruction.

Sweeping ext is pointless until the pulse shape is right: all 160 OR commits
in BitSlice are equivalent targets, so if a given (width, offset) never skips
anything at one ext it will not at another -- it will just produce 1900 copies
of the same answer.  What distinguishes a usable pulse is the ratio of three
outcomes at one ext:

  normal   the pulse did nothing at all          -> too weak
  LOST     the region ran, then the device died   -> too strong: the glitch
           derails the loop register r1 or the bound r6 instead of the orrs,
           and ldrh.w [r7, r1, lsl #1] faults off the end of a[]
  OR_SKIP  one plane bit failed to be set         -> what we want

Rank by OR_SKIP, then by the fewest LOST.  Husky rejects negative widths, so
the pulse phase is carried by offset, which is swept both signs here.
"""
import argparse, collections, csv, time
from cwcommon import (connect, reboot, drain, run_once, classify, fingerprint,
                      quiet, SEL)

WIDTHS  = (9, 18, 27, 36, 46, 55, 73, 82, 100, 137, 192, 275, 400, 600)
OFFSETS = (-1200, -688, -456, -229, -136, -56, 0, 56, 136, 229, 456, 688)

ap = argparse.ArgumentParser()
ap.add_argument('--ext_offset', type=int, required=True)
ap.add_argument('--reps', type=int, default=6)
ap.add_argument('--base', default='1902,91,195,0')
ap.add_argument('--sel', type=int, default=SEL)
ap.add_argument('--widths', default='', help='comma list to override WIDTHS')
ap.add_argument('--offsets', default='', help='comma list to override OFFSETS')
ap.add_argument('--freq', type=int, default=0, help='raise the target clock')
ap.add_argument('--repeat', type=int, default=1,
                help='glitch N consecutive cycles.  offset only moves the pulse '
                     'WITHIN a cycle, so repeat is the only way to widen which '
                     'instruction the pulse can reach from one ext.')
ap.add_argument('--out', default='tune.csv')
a = ap.parse_args()
BASE = tuple(int(x) for x in a.base.split(','))
W = [int(x) for x in a.widths.split(',')] if a.widths else list(WIDTHS)
O = [int(x) for x in a.offsets.split(',')] if a.offsets else list(OFFSETS)

scope, target = connect(**({'freq': a.freq} if a.freq else {}))
quiet(); reboot(scope, target); drain(target)
print('phase_shift_steps =', scope.glitch.phase_shift_steps)
print(f'ext={a.ext_offset} repeat={a.repeat}  {len(W)}x{len(O)} pairs '
      f'x {a.reps} reps = {len(W)*len(O)*a.reps} runs\n')

rows, t0 = [], time.time()
for w in W:
    for off in O:
        c = collections.Counter(); fps = collections.Counter()
        for _ in range(a.reps):
            try:
                d = run_once(scope, target,
                             glitch=(a.ext_offset, w, off, a.repeat),
                             sel=a.sel)
            except Exception:
                d = None
            if not isinstance(d, dict):
                c['LOST' if d != 'NOTRIGGER' else 'NOTRIG'] += 1
                try: scope.capture()
                except Exception: pass
                reboot(scope, target); drain(target); continue
            k = classify(d).split('[')[0].split('(')[0]
            c[k] += 1; fps[fingerprint(d)] += 1
        rows.append(dict(width=w, offset=off, reps=a.reps,
                         normal=c['normal'], or_skip=c['OR_SKIP'],
                         bit_set=c['BIT_SET'], plane_zero=c['PLANE_ZERO'],
                         multibit=c['MULTIBIT'], indirty=c['INPUT_DIRTY'],
                         overrun=c['OVERRUN'],
                         lost=c['LOST'], notrig=c['NOTRIG'],
                         offbase=sum(n for f, n in fps.items() if f != BASE),
                         fps=' + '.join(f'{f}*{n}' for f, n in fps.most_common(2))))
        tag = ''.join(f'{k}={v} ' for k, v in c.most_common())
        print(f'  w={w:4d} off={off:5d}  {tag}', flush=True)

with open(a.out, 'w', newline='') as f:
    wr = csv.DictWriter(f, fieldnames=list(rows[0].keys())); wr.writeheader(); wr.writerows(rows)

print(f'\nelapsed {time.time()-t0:.0f} s  -> {a.out}')
hit = [r for r in rows if r['or_skip']]
print('\n=== pairs that SKIPPED the OR (ranked: most skips, then fewest lost) ===')
if not hit:
    tot = collections.Counter()
    for r in rows:
        for k in ('normal', 'lost', 'notrig', 'bit_set', 'plane_zero', 'multibit',
                  'indirty', 'overrun'):
            tot[k] += r[k]
    print('  none.')
    print('  outcome totals:', dict(tot.most_common()))
    print('  If almost everything is "normal", every pulse here is too weak:')
    print('    widen the search with --widths 800,1200,1600,2200.')
    print('  If almost everything is "lost", every pulse is too strong:')
    print('    narrow it with --widths 2,4,6,9,13.')
    print('  A mix of normal and lost with no skips in between means this ext')
    print('  has no skippable instruction at any phase -- move ext by a few')
    print('  cycles (the orrs is 1 of 8 instructions in the loop) and repeat.')
else:
    for r in sorted(hit, key=lambda r: (-r['or_skip'], r['lost'])):
        print(f"  w={r['width']:4d} off={r['offset']:5d}  OR_SKIP={r['or_skip']}/{r['reps']}"
              f"  lost={r['lost']}  normal={r['normal']}  fps: {r['fps']}")
    b = sorted(hit, key=lambda r: (-r['or_skip'], r['lost']))[0]
    print(f"\nnext: python map_wang.py --base_cyc {BASE[0]} --step 1 "
          f"--grid 1  # after setting QUICK[0] = ({b['width']}, {b['offset']})")
    print(f"  or: python campaign.py --ext_offset {a.ext_offset} "
          f"--width {b['width']} --offset {b['offset']} "
          f"--repeat {a.repeat} --n 1000")
scope.dis()
