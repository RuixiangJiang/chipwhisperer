#!/usr/bin/env python3
"""Alternate glitched and un-glitched runs at the campaign parameters.
un-glitched -> 'normal'  : corruption is per-run and glitch-induced (good)
un-glitched -> same wrong digest : something is persistently corrupted
                                   (static msg buffer, heap) -> artifact"""
import argparse
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
ap = argparse.ArgumentParser()
ap.add_argument("--ext_offset", type=int, default=94)
ap.add_argument("--width",      type=int, default=275)
ap.add_argument("--offset",     type=int, default=-688)
ap.add_argument("--pairs",      type=int, default=50)
a = ap.parse_args()

scope, target = connect(); arm_glitch(scope)
scope.glitch.ext_offset = a.ext_offset
scope.glitch.width = a.width; scope.glitch.offset = a.offset

def run(glitched):
    if glitched: scope.arm()
    target.flush(); target.simpleserial_write('r', b'')
    if glitched:
        to = scope.capture()
        r = None if to else target.simpleserial_read('r', 19, timeout=1000)
    else:
        r = target.simpleserial_read('r', 19, timeout=3000)
    return parse(r)

g, c = Counter(), Counter()
for i in range(a.pairs):
    for glitched, tally in ((True, g), (False, c)):
        d = run(glitched)
        if d is None:        tally['crash'] += 1; reboot(scope); continue
        if d == 'BAD_FRAME': tally['BAD_FRAME'] += 1; continue
        tally[(classify(d[0]), d[0].hex(), d[1])] += 1
print("\nGLITCHED:");   [print("  ",k,v) for k,v in g.most_common()]
print("UN-GLITCHED:");  [print("  ",k,v) for k,v in c.most_common()]
scope.dis(); target.dis()
