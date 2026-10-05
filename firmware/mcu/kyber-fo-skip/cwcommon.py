"""Shared setup: binds explicitly to the Husky by serial number."""
import chipwhisperer as cw, struct, time

HUSKY_SN = '50203220573555303030343235323038'
FW = "kyber-fo-skip-CW308_STM32F4.hex"

def connect(program=True):
    scope = cw.scope(sn=HUSKY_SN)          # <-- Husky, never the Lite
    scope.default_setup()
    scope.clock.clkgen_freq = 7.37e6
    target = cw.target(scope, cw.targets.SimpleSerial2)
    assert 'Husky' in str(type(scope)) or scope._getNAEUSB().snum == HUSKY_SN
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
    if r is None or len(r) < 11: return None
    fail = struct.unpack('<I', bytes(r[0:4]))[0]
    cyc  = struct.unpack('<I', bytes(r[4:8]))[0]
    return fail, cyc, r[8], r[9], r[10]

def classify(fail):
    """b[0]=0x01 so a != b: correct behaviour is REJECT (1)."""
    if fail == 0x00000001: return 'normal'       # correct reject
    if fail == 0x00000000: return 'FO_BYPASS'    # accept despite difference <-- the attack
    if fail == 0x000000AA: return 'skip_str'
    if 0x08000000 <= fail < 0x08100000: return 'skip_bl'      # &a left in r0 (flash)
    if 0x20000000 <= fail < 0x20020000: return 'skip_bl_ram'  # &b left in r0 (RAM)
    return 'other'
