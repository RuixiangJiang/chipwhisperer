#!/usr/bin/env python3
"""
paintcheck.py -- read the 't' diagnostic from simpleserial-dilithium2-full.

Paints the stack and immediately measures it, with no crypto in between.
A healthy result is a few hundred bytes: just the command handler's own
frame. Anything near the full painted span means the scan is stopping on
something that lives above bss -- most likely the newlib heap starting at
`end` -- and the paint floor needs to move up.
"""

import time
import chipwhisperer as cw

SN = "50203220573555303030343235323038"


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


scope = cw.scope(sn=SN)
scope.default_setup()
scope.clock.clkgen_freq = 7.37e6
scope.io.hs2 = "clkgen"
time.sleep(0.25)

target = cw.target(scope, cw.targets.SimpleSerial2)
target.baud = 230400

# Reset so nothing from a previous command is still on the stack.
scope.io.nrst = "low"
time.sleep(0.05)
scope.io.nrst = "high_z"
time.sleep(0.30)
target.flush()

target.simpleserial_write("t", bytearray([1]))
r = target.simpleserial_read("r", 16, timeout=2000, ack=False)

if r is None or len(r) != 16:
    print(f"no valid response: {r!r}")
else:
    r = bytes(r)
    floor, top, stop, val = u32(r, 0), u32(r, 4), u32(r, 8), u32(r, 12)
    span = top - floor
    used = top - stop
    print(f"  paint_floor  : 0x{floor:08x}")
    print(f"  paint_top    : 0x{top:08x}")
    print(f"  painted span : {span:,} B")
    print(f"  scan stopped : 0x{stop:08x}   ({stop - floor:,} B above floor)")
    print(f"  value found  : 0x{val:08x}")
    print(f"  reported use : {used:,} B")
    print()
    if used < 2048:
        print("  OK -- painting and scanning both work; per-stage numbers")
        print("  from the memtest are trustworthy.")
    else:
        print("  BROKEN -- the scan stops near the floor, so something")
        print("  occupies memory just above bss (heap, most likely).")
        print("  Raise the margin in paint_stack():")
        print("      uint32_t fl = (bss_end() + 16384u + 3u) & ~3u;")

scope.dis()