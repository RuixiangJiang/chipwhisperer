"""Harness for the Delvaux 2022 add-skip, FLAG-based detector.

Monitored region: one flag-setting `adds` with known operands, NZCV captured
immediately after via mrs.  Detector under test: the four condition flags
(N,Z,C,V) read after the add, compared to the NZCV the correct sum must set.
DWT counters are captured on the same runs so the HPC detector (the earlier
Delvaux result) and the flag detector are scored on identical faults."""
import logging, time
import chipwhisperer as cw

HUSKY_SN  = '50203220573555303030343235323038'
PS        = 4592
MAGIC     = 0x47414C46
FRAME     = 40
SEL       = 0
CMD       = 's'            # 'k' is reserved by the SS v2 framework
READ_MS   = 80
BASE_FREQ = 7370000
BASE_BAUD = 230400

# The operand table MUST match OPS[] in delvaux_flags.c.  The host computes the
# correct result and NZCV from these, so the oracle is glitch-proof: there is
# no on-device reference to corrupt.
OPS = [
    (0x00000001, 0x00000001),
    (0xFFFFFFFF, 0x00000001),
    (0x7FFFFFFF, 0x00000001),
    (0x80000000, 0x80000000),
    (0xFFFFFFFF, 0xFFFFFFFF),
    (0x12345678, 0x11111111),
]
NOPS = 6

def expected_ops(sel):
    return OPS[sel % NOPS]

def correct_result(a, b):
    return (a + b) & 0xFFFFFFFF

def correct_nzcv(a, b):
    s  = (a + b) & 0xFFFFFFFF
    N  = (s >> 31) & 1
    Z  = 1 if s == 0 else 0
    C  = 1 if (a + b) > 0xFFFFFFFF else 0            # unsigned carry out
    sa = (a >> 31) & 1; sb = (b >> 31) & 1; ss = (s >> 31) & 1
    V  = 1 if (sa == sb and ss != sa) else 0         # signed overflow
    return (N << 3) | (Z << 2) | (C << 1) | V

def quiet(on=True):
    lvl = logging.CRITICAL if on else logging.WARNING
    try:
        cw.set_all_log_levels(lvl); return
    except Exception:
        pass
    names = [n for n in list(logging.root.manager.loggerDict)
             if n.startswith('ChipWhisperer')] + ['ChipWhisperer']
    for n in names:
        logging.getLogger(n).setLevel(lvl)

def connect(adc_timeout=0.1, freq=BASE_FREQ, baud=None):
    scope = cw.scope(sn=HUSKY_SN)
    scope.default_setup()
    quiet()
    try:
        scope.adc.timeout = adc_timeout
    except Exception:
        pass
    target = cw.target(scope, cw.targets.SimpleSerial2)
    scope.clock.clkgen_freq = freq
    target.baud = baud if baud else int(round(BASE_BAUD * freq / BASE_FREQ))
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

def drain(target, settle=0.05, rounds=5):
    for _ in range(rounds):
        time.sleep(settle)
        n = 0
        try: n = target.in_waiting()
        except Exception: pass
        try:
            if n: target.read(n, timeout=10)
            else: target.flush(); return
        except Exception:
            return

def arm_glitch(scope, ext_offset, width, offset, repeat=1):
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat     = repeat
    scope.glitch.width      = width
    scope.glitch.offset     = offset
    scope.arm()

def run_once(scope, target, glitch=None, sel=SEL, cmd=None):
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write(cmd or CMD, bytearray([sel & 0xFF, (sel>>8)&0xFF,
                                                     (sel>>16)&0xFF, (sel>>24)&0xFF]))
    if glitch is not None and scope.capture():
        return 'NOTRIGGER'
    rb = target.simpleserial_read('r', FRAME, timeout=READ_MS)
    return parse(rb)

def run_safe(scope, target, glitch=None, sel=SEL, cmd=None, retries=1):
    for _ in range(retries + 1):
        try:
            d = run_once(scope, target, glitch=glitch, sel=sel, cmd=cmd)
        except Exception:
            d = None
        if isinstance(d, dict):
            return d, False
        try: scope.capture()
        except Exception: pass
        reboot(scope, target); drain(target)
    return None, True

def _u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

def parse(rb):
    if rb is None:          return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:      return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC: return 'BADMAGIC'
    cyc = _u32(b, 24)
    if cyc > 2000000:       return 'BAD_COUNTERS'
    sel = _u32(b, 4); a = _u32(b, 8); bb = _u32(b, 12)
    res1 = _u32(b, 16); res2 = _u32(b, 20)
    nz1 = b[28]; nz2 = b[29]; sentinel = b[30]; dirty = b[31]
    # host-side, glitch-proof oracle
    ea, eb = expected_ops(sel)
    frame_ok  = (a == ea and bb == eb)                  # echoed operands intact
    store_ok  = (res1 == res2 and nz1 == nz2)          # both copies agree
    cres = correct_result(a, bb); cnz = correct_nzcv(a, bb)
    res_ok   = (res1 == cres)
    flags_ok = (nz1 == cnz)
    return dict(sel=sel, a=a, b=bb, res_obs=res1, res2=res2,
                nz_obs=nz1, nz2=nz2, sentinel=sentinel, dirty=dirty,
                cyc=cyc, cpi=b[32], lsu=b[33], fold=b[34],
                cres=cres, cnz=cnz, frame_ok=frame_ok, store_ok=store_ok,
                res_ok=int(res_ok), flags_ok=int(flags_ok))

def safe(d, base_cyc=0):
    if isinstance(d, dict): return d
    return dict(sel=0, a=0, b=0, res_obs=0, res2=0, nz_obs=0, nz2=0,
                sentinel=0xF, dirty=0, cyc=base_cyc, cpi=0, lsu=0, fold=0,
                cres=0, cnz=0, frame_ok=True, store_ok=True, flags_ok=1, res_ok=1,
                _bad=('NOFRAME' if not d else 'BADFRAME:'+str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    if d['dirty']:              return 'CANARY_DIRTY'          # wild store, unscorable
    if not d['frame_ok']:       return 'FRAME_CORRUPT'         # echoed a,b wrong, unscorable
    if not d['store_ok']:       return 'STORE_GLITCH'          # one output copy differs, unscorable
    res_ok, flags_ok = d['res_ok'], d['flags_ok']
    if res_ok and flags_ok:     return 'normal'
    if not res_ok and not flags_ok:
        if d['nz_obs'] == d['sentinel']:
            return f"SKIP_CAUGHT(nz={d['nz_obs']:X})"          # flags left at the sentinel
        return f"CORRUPT_CAUGHT(nz_obs={d['nz_obs']:X},nz_ok={d['cnz']:X})"
    if not res_ok and flags_ok:
        return f"FLAG_BLIND(nz={d['nz_obs']:X})"               # <-- the flag detector's miss
    return f"FLAG_FALSEPOS(nz_obs={d['nz_obs']:X},nz_ok={d['cnz']:X})"

def unscorable(d):
    return (not isinstance(d, dict) or d.get('_bad') or d['dirty']
            or not d['frame_ok'] or not d['store_ok'])

def is_fault(d):
    """The add was corrupted: the observed result differs from the correct sum."""
    return not unscorable(d) and not d['res_ok']

def flag_detects(d):
    """Detector under test: NZCV after the add != the correct NZCV."""
    return not unscorable(d) and not d['flags_ok']
