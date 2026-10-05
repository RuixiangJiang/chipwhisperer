"""Shared setup for entry 2. Binds explicitly to the Husky by serial."""
import chipwhisperer as cw, struct, time, hashlib

HUSKY_SN = '50203220573555303030343235323038'
FW = "keccak-rnd-skip-CW308_STM32F4.hex"
MAGIC = bytes([0x5A,0xA5,0x3C,0xC3])

KEY = bytes(range(0x00,0x20))
RND = bytes(range(0x80,0xA0))
MU  = bytes(range(0x40,0x80))
EXP_NORMAL = hashlib.shake_256(KEY+RND+MU).digest(64)[:8]   # rnd absorbed
EXP_SKIP   = hashlib.shake_256(KEY+MU   ).digest(64)[:8]    # rnd absorb skipped

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
    """None = crash/no response.  'BAD_FRAME' = magic wrong -> instrumentation
    corrupted, measured nothing; exclude.  else (rhop8, cyc, cpi, lsu, fold)."""
    if r is None or len(r) < 19:          return None
    if bytes(r[0:4]) != MAGIC:            return 'BAD_FRAME'
    rhop = bytes(r[4:12])
    cyc  = struct.unpack('<I', bytes(r[12:16]))[0]
    return (rhop, cyc, r[16], r[17], r[18])

def classify(rhop8):
    if rhop8 == EXP_NORMAL: return 'normal'
    if rhop8 == EXP_SKIP:   return 'RND_SKIPPED'   # <-- the Jendral fault
    return 'other'                                  # some other digest: real
                                                    # fault, not this one
