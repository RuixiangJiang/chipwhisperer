#!/usr/bin/env python3
"""Glitch the FIRST command after reset, 30 times.
store skipped   -> round comes from an uninitialised slot: outcome should
                   VARY across cold boots (zero rounds, partial rounds, or none)
store corrupted -> r3 is overwritten regardless of the slot: outcome is the
                   SAME every time"""
from collections import Counter
from cwcommon import connect, arm_glitch, reboot, parse, classify
scope, target = connect(); arm_glitch(scope)
scope.glitch.ext_offset = 558; scope.glitch.width = 275; scope.glitch.offset = -688
res = Counter()
for i in range(30):
    reboot(scope)
    scope.arm(); target.flush(); target.simpleserial_write('r', b'')
    to = scope.capture()
    d = parse(None if to else target.simpleserial_read('r', 19, timeout=3000))
    res['crash' if d is None else 'BAD_FRAME' if d=='BAD_FRAME'
        else f'{classify(d[0])} cyc={d[1]}'] += 1
for k,v in res.most_common(): print(f'  {k}  x{v}')
scope.dis(); target.dis()
