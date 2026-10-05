"""Shared setup for entry 3. Binds explicitly to the Husky by serial."""
import chipwhisperer as cw, struct, time
from kref import shake256_once

HUSKY_SN = '50203220573555303030343235323038'
FW = "keccak-round-counter-CW308_STM32F4.hex"
MAGIC = bytes([0x5A,0xA5,0x3C,0xC3])

MSG = bytes(range(0x00,0x20))
# hypothesis table: start round k (even) -> 24-k rounds actually executed
HYP = {shake256_once(MSG,64,start=k)[:8]: 24-k for k in range(0,25,2)}
assert len(HYP) == 13, "hypothesis prefixes collided"

def connect(program=True):
    scope = cw.scope(sn=HUSKY_SN)
    scope.default_setup()
    scope.clock.clkgen_freq = 7.37e6
    target = cw.target(scope, cw.targets.SimpleSerial2)
    print("connected:", scope._getNAEUSB().snum)
    if program:
        cw.program_target(scope, cw.programmers.STM32FProgrammer, FW)
    return scope, target

def arm_glitch(scope):
    scope.glitch.enabled = True
    scope.glitch.clk_src = 'pll'
    scope.glitch.output = 'clock_xor'
    scope.glitch.trigger_src = 'ext_single'
    scope.glitch.repeat = 1
    scope.io.hs2 = 'glitch'

def reboot(scope):
    scope.io.nrst = 'low'; time.sleep(0.05)
    scope.io.nrst = 'high_z'; time.sleep(0.1)

def parse(r):
    if r is None or len(r) < 19: return None
    if bytes(r[0:4]) != MAGIC:   return 'BAD_FRAME'
    out8 = bytes(r[4:12])
    cyc  = struct.unpack('<I', bytes(r[12:16]))[0]
    return (out8, cyc, r[16], r[17], r[18])

def classify(out8):
    """ROUNDS_24 = correct. ROUNDS_0 = identity permutation (message leaks).
    'other' = a digest matching no round count: a real fault, different
    mechanism (odd start round, or a data fault inside the permutation)."""
    n = HYP.get(out8)
    if n is None:    return 'other'
    if n == 24:      return 'normal'
    if n == 0:       return 'STATE_UNPERMUTED'   # output == unpermuted state.
        # NOT necessarily 0 rounds: a corrupted state pointer gives the same
        # output at full cycle cost. Check cyc before calling this a round
        # -count fault -- 0 rounds must collapse cyc by ~19,700.
    return f'ROUNDS_{n}'
