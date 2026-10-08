"""Shared setup for entry 4 (Du et al., absorb loop-back branch)."""
import chipwhisperer as cw, struct, time, json

HUSKY_SN = '50203220573555303030343235323038'
FW = "du-absorb-loop-CW308_STM32F4.hex"
MAGIC = bytes([0x5A,0xA5,0x3C,0xC3])
HYP = json.load(open('hyp272.json'))        # digest prefix -> [label, permutations]

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
    """Resolves the exact absorb-loop fault. A label is only trustworthy if the
    cycle count agrees: OUTER_SKIP drops one permutation (~-19k), an INNER
    truncation costs ~36 cycles per skipped byte."""
    e = HYP.get(out8.hex())
    return e[0] if e else 'other'

def perms(out8):
    e = HYP.get(out8.hex())
    return e[1] if e else None
