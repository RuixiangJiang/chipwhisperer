"""Harness for Krahmer et al. 2024 correction fault attacks on randomized Dilithium.
Monitored region: z = y + c*s1 plus the norm check, inside the aborts loop."""
import time
import chipwhisperer as cw

HUSKY_SN = '50203220573555303030343235323038'
PS       = 4592
MAGIC    = 0x4B524148
FRAME    = 52
N        = 256
NONCE    = 1

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
    time.sleep(0.2); target.flush()
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

def run_once(scope, target, glitch=None, nonce=NONCE):
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write('s', bytearray([nonce & 0xFF, (nonce >> 8) & 0xFF,
                                              (nonce >> 16) & 0xFF, (nonce >> 24) & 0xFF]))
    rb = target.simpleserial_read('r', FRAME, timeout=600)
    if glitch is not None:
        scope.capture()
    return parse(rb)

def _u16(b, o): return b[o] | (b[o+1] << 8)
def _s32(b, o):
    v = _u32(b, o)
    return v - (1 << 32) if v >= (1 << 31) else v

def _u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def parse(rb):
    if rb is None:          return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:      return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC: return 'BADMAGIC'
    cyc = _u32(b, 32)
    if cyc < 200 or cyc > 2000000:
        return 'BAD_COUNTERS'
    return dict(nonce=_u32(b, 4), iters=b[8], ok=b[9],
                n_ok=_u16(b, 10), n_yl=_u16(b, 12), n_add=_u16(b, 14),
                n_ysh=_u16(b, 16), n_wsh=_u16(b, 18), n_ot=_u16(b, 20),
                f_yl=_u16(b, 22), f_add=_u16(b, 24), f_ot=_u16(b, 26),
                zck=_u32(b, 28), cyc=cyc, cpi=b[36], lsu=b[37], fold=b[38], wdirty=b[39],
                z_ot=_s32(b, 40), y_ot=_s32(b, 44), w_ot=_s32(b, 48))

def safe(d, base_cyc=0):
    if isinstance(d, dict): return d
    return dict(nonce=0, iters=0, ok=0, n_ok=N, n_yl=0, n_add=0, n_ysh=0,
                n_wsh=0, n_ot=0, f_yl=0xFFFF, f_add=0xFFFF, f_ot=0xFFFF,
                zck=0, z_ot=0, y_ot=0, w_ot=0, cyc=base_cyc,
                cpi=0, lsu=0, fold=0, wdirty=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:' + str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    if d.get('wdirty'):         return f"WREF_DIRTY({d['wdirty']})"
    if not d['ok']:             return f"NO_SIG(iters={d['iters']})"
    if d['n_ok'] == N:          return 'normal'
    if d['n_yl']:                                          # <-- key recovery
        return (f"YLOAD_SKIP(n={d['n_yl']},first={d['f_yl']},"
                f"shift={d['n_ysh']},other={d['n_ot']})")
    if d['n_add'] and not d['n_ot']:
        return f"ADD_SKIP(n={d['n_add']},first={d['f_add']})"
    if d['n_wsh'] and not d['n_ot']:
        return f"W_SHIFT(n={d['n_wsh']})"
    if d['n_ot']:
        return f"OTHER_Z(n={d['n_ot']},first={d['f_ot']})"
    return (f"MIXED(yl={d['n_yl']},add={d['n_add']},ysh={d['n_ysh']},"
            f"wsh={d['n_wsh']},ot={d['n_ot']})")

def leaks_key(d):
    """z[k] == z[k-1] + w[k] gives the attacker w[k] = z[k] - z[k-1] from the
    signature alone: one linear equation in s1, no nonce reuse needed."""
    return isinstance(d, dict) and not d.get('_bad') and d['ok'] and d['n_yl'] > 0
