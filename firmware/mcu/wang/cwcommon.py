"""Harness for Wang et al. 2025, "Secret in OnePiece: Single-Bit Fault Attack
on Kyber" (SAC 2025) -- the instruction-skip target only.

Monitored region: BitSlice (Algorithm 2) of the bit-sliced message decoder,
5 planes x 32 lanes = 160 "acc |= bit << j" commits.  The reproduced fault is
the skip of that bitwise OR.  Nothing downstream (masking, the unmasked flip
probability, the decapsulation oracle, the inequality solver) is in scope."""
import logging
import time
import chipwhisperer as cw

HUSKY_SN = '50203220573555303030343235323038'
PS       = 4592
MAGIC    = 0x474E4157
FRAME    = 32
NC       = 32
NP       = 5
BIT0     = 7
NSITE    = NP * NC          # 160 OR commits
SEL      = 1
CMD      = 's'              # 'k' is reserved by the SS v2 framework
# The monitored region is 1902 cycles = 0.26 ms at 7.37 MHz and a clean run
# round-trips in ~12 ms, so 80 ms is ample.  A longer timeout only makes every
# lost run cost more, and at a 65% loss rate that dominates the sweep.
READ_MS  = 80

def quiet(on=True):
    """ChipWhisperer logs a WARNING per capture timeout and an ERROR per
    desynced frame.  During a sweep that is thousands of lines that hide the
    crash-rate line, so silence them and let the scripts report instead.

    The loggers are named "ChipWhisperer Target", "ChipWhisperer Scope" etc --
    with SPACES, so they are NOT children of "ChipWhisperer" and setting the
    level on that name alone does nothing.  Hit every one of them.
    """
    lvl = logging.CRITICAL if on else logging.WARNING
    try:
        cw.set_all_log_levels(lvl)
        return
    except Exception:
        pass
    names = [n for n in list(logging.root.manager.loggerDict)
             if n.startswith('ChipWhisperer')] + ['ChipWhisperer']
    for n in names:
        logging.getLogger(n).setLevel(lvl)

BASE_FREQ = 7370000
BASE_BAUD = 230400

def connect(adc_timeout=0.1, freq=BASE_FREQ, baud=None):
    """freq raises the TARGET clock.  Wang glitched at 28 MHz; at the CW
    default 7.37 MHz the core has roughly 4x the timing margin, which is the
    usual reason a single-instruction skip will not reproduce while a wide
    pulse still kills the device.  DWT counts CYCLES, so the baseline
    fingerprint is unchanged by this -- but the firmware derives its UART baud
    from the system clock, so the host baud must scale with it, and
    phase_shift_steps changes, so widths/offsets need re-tuning afterwards.
    """
    scope = cw.scope(sn=HUSKY_SN)
    scope.default_setup()
    quiet()
    # The monitored region is ~1900 cycles = 0.26 ms at 7.37 MHz.  The default
    # 2 s ADC timeout turns every crashed run into a 2 s stall.
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

def arm_glitch(scope, ext_offset, width, offset, repeat=1):
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat     = repeat
    scope.glitch.width      = width
    scope.glitch.offset     = offset
    scope.arm()

def drain(target, settle=0.05, rounds=5):
    """Discard anything still in flight.

    After a timed-out run the device still delivers its 'r' frame and then its
    'e' ack.  target.flush() can only discard bytes that have ALREADY arrived,
    so one late frame leaves every later read one frame out of phase, which
    shows up as "Unexpected start to command 0x72, expected 0x65" and never
    recovers on its own.  Keep draining until the line stays quiet.
    """
    for _ in range(rounds):
        time.sleep(settle)
        n = 0
        try:
            n = target.in_waiting()
        except Exception:
            pass
        try:
            if n:
                target.read(n, timeout=10)
            else:
                target.flush()
                return
        except Exception:
            return

def run_once(scope, target, glitch=None, sel=SEL, cmd=None):
    """arm -> write -> capture -> read.

    The capture comes BEFORE the serial read: it is what waits for the trigger,
    so a capture timeout means the device never reached trigger_high() and
    there is no point spending the serial read timeout on it as well.
    """
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write(cmd or CMD, bytearray([sel & 0xFF, (sel >> 8) & 0xFF,
                                                     (sel >> 16) & 0xFF, (sel >> 24) & 0xFF]))
    if glitch is not None and scope.capture():
        return 'NOTRIGGER'          # trigger never fired: the run is lost
    rb = target.simpleserial_read('r', FRAME, timeout=READ_MS)
    return parse(rb)

def _u16(b, o): return b[o] | (b[o+1] << 8)
def _u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def parse(rb):
    if rb is None:          return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:      return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC: return 'BADMAGIC'
    cyc = _u32(b, 8)
    if cyc < 30 or cyc > 2000000:
        return 'BAD_COUNTERS'
    return dict(sel=_u32(b, 4), cyc=cyc, cpi=b[12], lsu=b[13], fold=b[14],
                dirty=b[15], ndiff=_u16(b, 16), fplane=b[18], flane=b[19],
                fdir=b[20], nplane0=b[21], nset=_u16(b, 22),
                bck=_u32(b, 24), ick=_u32(b, 28))

def safe(d, base_cyc=0):
    if isinstance(d, dict): return d
    return dict(sel=0, cyc=base_cyc, cpi=0, lsu=0, fold=0, dirty=0, ndiff=0,
                fplane=0xFF, flane=0xFF, fdir=0xFF, nplane0=0, nset=0,
                bck=0, ick=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:' + str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

def site(d):
    """(plane, z-bit, lane) of the first differing plane bit."""
    if d['fplane'] == 0xFF or d['fplane'] >= NP: return None
    return (d['fplane'], d['fplane'] + BIT0, d['flane'])

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    if d['dirty'] & 2:          return 'OVERRUN'           # unscorable
    if d['dirty'] & 1:          return 'INPUT_DIRTY'       # unscorable
    if d['ndiff'] == 0:
        # A skipped OR whose bit was already 0 leaves the planes bit-identical.
        # Unobservable in principle, so correctly a negative.
        return 'normal'
    if d['nplane0']:
        return f"PLANE_ZERO(n={d['nplane0']},ndiff={d['ndiff']})"
    if d['ndiff'] == 1:
        st = site(d)
        if st is None: return f"BAD_SITE(fplane={d['fplane']},lane={d['flane']})"
        if d['fdir'] == 0:
            return f"OR_SKIP[z{st[1]}.l{st[2]}]"           # <-- the Wang target
        # A skipped orr can only CLEAR a bit that should be set.  A bit set
        # that should be clear came from the shift, the and, or the loaded
        # coefficient, not from the OR.
        return f"BIT_SET[z{st[1]}.l{st[2]}]"
    return f"MULTIBIT(n={d['ndiff']})"

def unscorable(d):
    return not isinstance(d, dict) or d.get('_bad') or d['dirty'] != 0

def corrupt(d):
    """The planes differ from the reference -> positive for the matrix."""
    return not unscorable(d) and d['ndiff'] > 0

def run_safe(scope, target, glitch=None, sel=SEL, cmd=None, retries=1):
    """run_once, but reboot on ANY unreadable result, not just NOFRAME.

    A crashed run leaves the UART desynced, so the device answers the next
    command with an SS_ERR_CMD frame and every later run fails too unless the
    target is reset.  Returns (result_or_None, crashed).
    """
    for _ in range(retries + 1):
        try:
            d = run_once(scope, target, glitch=glitch, sel=sel, cmd=cmd)
        except Exception:
            d = None
        if isinstance(d, dict):
            return d, False
        # Consume any still-armed capture BEFORE resetting: an armed glitch
        # plus the trigger activity of a reboot would fire the pulse during
        # the target's boot, which bricks it for every later run.
        try:
            scope.capture()
        except Exception:
            pass
        reboot(scope, target)
        drain(target)
    return None, True

def is_or_skip(d):
    """Exactly the paper's target: one bit that should be set is clear."""
    return corrupt(d) and d['ndiff'] == 1 and d['fdir'] == 0 and site(d) is not None
