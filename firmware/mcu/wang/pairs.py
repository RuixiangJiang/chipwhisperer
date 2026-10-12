"""Extract the (width, offset) pairs that DID something from a tune CSV and
print the map_wang.py command that sweeps ext with exactly those pulses.

Pairs that only ever returned 'normal' cannot reach the core at all, and
pairs that only ever killed the device are too strong; neither is worth
spending ext sweep time on."""
import csv, sys

f = sys.argv[1] if len(sys.argv) > 1 else 'tune.csv'
base = sys.argv[2] if len(sys.argv) > 2 else '1902'
rows = list(csv.DictReader(open(f)))
EFFECT = ('or_skip', 'bit_set', 'plane_zero', 'multibit', 'overrun', 'indirty', 'dirty')

def eff(r):
    return sum(int(r[k]) for k in EFFECT if k in r)

hit  = [r for r in rows if eff(r)]
lost = [r for r in rows if not eff(r) and int(r['lost'])]
print(f'{len(rows)} pairs: {len(hit)} produced an effect, {len(lost)} only killed '
      f'the target, {len(rows)-len(hit)-len(lost)} did nothing\n')
for r in sorted(hit, key=lambda r: -eff(r)):
    print(f"  w={r['width']:>4s} off={r['offset']:>5s}  effect={eff(r)}/{r['reps']}"
          f"  lost={r['lost']}  normal={r['normal']}"
          + (f"  OR_SKIP={r['or_skip']}" if int(r.get('or_skip', 0)) else '')
          + (f"  fps: {r['fps']}" if r.get('fps') else ''))
if hit:
    ps = ';'.join(f"{r['width']},{r['offset']}" for r in sorted(hit, key=lambda r: -eff(r))[:6])
    print(f'\n--pairs "{ps}"\n')
    print('sweep one full loop period with those pulses:')
    print(f'  python map_wang.py --base_cyc {base} --ext_min 596 --ext_max 620 '
          f'--step 1 --reps 8 --pairs "{ps}" --out ext_period.csv')
else:
    print('\nNo pair reached the core.  Widen the width range before sweeping ext.')
