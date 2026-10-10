"""Harness for Delvaux-2022 Roulette: skipping `uadd16 a0, a0, tmp2`
(fastinvntt.S:34, macro doublebutterfly) inside pqm4 Kyber invntt_fast."""
import time
import chipwhisperer as cw

HUSKY_SN = '50203220573555303030343235323038'
PS       = 4592
MAGIC    = 0x12201E77
FRAME    = 32
N, Q     = 256, 3329
LAYERS   = 7

def connect():
    scope = cw.scope(sn=HUSKY_SN)
    scope.default_setup()
    target = cw.target(scope, cw.targets.SimpleSerial2)
    scope.clock.clkgen_freq = 7370000
    target.baud = 230400
    scope.glitch.enabled     = True
    scope.glitch.clk_src     = 'pll'
    scope.glitch.output      = 'clock_xor'
    scope.glitch.trigger_src = 'ext_single'
    scope.io.hs2             = 'glitch'
    time.sleep(0.2)
    target.flush()
    return scope, target

def reboot(scope, target):
    scope.io.nrst = 'low';    time.sleep(0.05)
    scope.io.nrst = 'high_z'; time.sleep(0.10)
    target.flush()

def arm_glitch(scope, ext_offset, width, offset, repeat=1):
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat     = repeat
    scope.glitch.width      = width
    scope.glitch.offset     = offset
    scope.arm()

def run_once(scope, target, glitch=None):
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write('d', bytearray([0]))
    rb = target.simpleserial_read('r', FRAME, timeout=500)
    if glitch is not None:
        scope.capture()
    return parse(rb)

def _u16(b, o): return b[o] | (b[o+1] << 8)
def _s16(b, o):
    v = _u16(b, o)
    return v - 0x10000 if v >= 0x8000 else v
def _u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def parse(rb):
    if rb is None:          return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:      return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC: return 'BADMAGIC'
    cyc = _u32(b, 20)
    if cyc < 200 or cyc > 1000000:
        return 'BAD_COUNTERS'
    return dict(ndiff=_u16(b, 4), first=_u16(b, 6), second=_u16(b, 8),
                last=_u16(b, 10), dck=_u32(b, 12), ock=_u32(b, 16),
                cyc=cyc, cpi=b[24], lsu=b[25], fold=b[26],
                firstdelta=_s16(b, 28))

def safe(d, base_cyc=0):
    if isinstance(d, dict): return d
    return dict(ndiff=0, first=0xFFFF, second=0xFFFF, last=0xFFFF, dck=0, ock=0,
                cyc=base_cyc, cpi=0, lsu=0, fold=0, firstdelta=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:' + str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

def _pow2(n):
    return n > 0 and (n & (n - 1)) == 0

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    nd = d['ndiff']
    if nd == 0:                 return 'normal'
    if _pow2(nd):
        stride = (d['second'] - d['first']) if d['second'] != 0xFFFF else 0
        lg = nd.bit_length() - 1
        return f'BFLY_SKIP(supp={nd},lg={lg},first={d["first"]},stride={stride})'
    if nd >= N - 4:             return 'POLY_DESTROYED'
    return f'other(nd={nd},first={d["first"]},last={d["last"]})'
