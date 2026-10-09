"""Shared harness for the Ravi-2020 NNUO seed-sampling experiment."""
import time
import chipwhisperer as cw

HUSKY_SN = '50203220573555303030343235323038'
PS       = 4592                 # phase_shift_steps = one target clock cycle
MAGIC    = 0x5A33C0DE
N        = 32                   # SEEDLEN
SENT     = 0xA5
GOOD_CKSUM = 0x9D1324E7         # FNV-1a over the correct 32-byte seed
SENT_CKSUM = 0x2DACB8A5         # FNV-1a over 32 x 0xA5  (full NNUO)
FRAME    = 29

REF = [0xC6,0x7E,0x81,0x6B,0x4B,0xFB,0xE2,0xFB,0x54,0xF6,0xBD,0xDF,0x7C,0x1C,0xE1,0x87,
       0x01,0xBF,0x31,0xDE,0x56,0x72,0x0F,0x47,0x67,0x66,0x87,0x59,0xAA,0x88,0x3C,0x59,
       0xEA]

def connect():
    scope = cw.scope(sn=HUSKY_SN)
    scope.default_setup()
    target = cw.target(scope, cw.targets.SimpleSerial2)
    scope.clock.clkgen_freq = 7370000
    target.baud = 230400
    scope.glitch.enabled    = True
    scope.glitch.clk_src    = 'pll'
    scope.glitch.output     = 'clock_xor'
    scope.glitch.trigger_src= 'ext_single'
    scope.io.hs2            = 'glitch'
    time.sleep(0.2)
    target.flush()
    return scope, target

def reboot(scope, target):
    scope.io.nrst = 'low'
    time.sleep(0.05)
    scope.io.nrst = 'high_z'
    time.sleep(0.10)
    target.flush()

def arm_glitch(scope, ext_offset, width, offset, repeat=1):
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat     = repeat
    scope.glitch.width      = width
    scope.glitch.offset     = offset
    scope.arm()

def run_once(scope, target, glitch=None):
    """glitch = (ext_offset, width, offset, repeat) or None for a clean run."""
    if glitch is not None:
        arm_glitch(scope, *glitch)
    target.simpleserial_write('s', bytearray([0]))
    rb = target.simpleserial_read('r', FRAME, timeout=300)
    if glitch is not None:
        scope.capture()
    return parse(rb)

def _u16(b, o): return b[o] | (b[o + 1] << 8)
def _u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def parse(rb):
    if rb is None:            return 'NOFRAME'
    b = bytes(rb)
    if len(b) < FRAME:        return 'SHORTFRAME'
    if _u32(b, 0) != MAGIC:   return 'BADMAGIC'
    cyc = _u32(b, 22)
    if cyc < 3 or cyc > 50000:
        return 'BAD_COUNTERS'
    return dict(n_diff=_u16(b, 4),  first_diff=_u16(b, 6),
                n_sent=_u16(b, 8),  first_sent=_u16(b, 10),
                last_sent=_u16(b, 12),
                got=b[14], exp=b[15], shiftn=b[16],
                cksum=_u32(b, 18), cyc=cyc,
                cpi=b[26], lsu=b[27], fold=b[28])

def safe(d, base_cyc=0):
    """Coerce a non-dict parse() result into a labelled dict."""
    if isinstance(d, dict): return d
    return dict(n_diff=0, first_diff=0, n_sent=0, first_sent=0, last_sent=0,
                got=0, exp=0, shiftn=0, cksum=0, cyc=base_cyc,
                cpi=0, lsu=0, fold=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:' + str(d)))

def fingerprint(d): return (d['cyc'], d['cpi'], d['lsu'], d['fold'])

# ---- exact cksum -> fault-family table, built from the host model ----------
def _fnv(bs):
    h = 0x811C9DC5
    for b in bs:
        h ^= b
        h = (h * 16777619) % (1 << 32)
    return h

def _build_table():
    t, S = {}, SENT
    def add(c, name): t.setdefault(c, name)
    add(_fnv(REF[:N]), 'normal')
    # loop exited early: bytes k..31 still hold the sentinel  (the NNUO condition)
    for k in range(N):
        add(_fnv(REF[:k] + [S] * (N - k)), 'FULL_BYPASS' if k == 0 else f'TRUNC@{k}')
    # one byte alone never written (only reachable if the store is index-addressed)
    for k in range(N):
        b = REF[:N].copy(); b[k] = S
        add(_fnv(b), f'STORE_SKIP@{k}')
    # post-increment store skipped: one PRNG output lost, tail shifts, nothing unwritten
    for k in range(N):
        add(_fnv(REF[:k] + REF[k+1:N+1]), f'STORE_PTR_SKIP@{k}')
    # PRNG update (mla) skipped: previous output stored again, tail shifts the other way
    for k in range(N):
        prev = REF[k-1] if k >= 1 else 0x00
        add(_fnv(REF[:k] + [prev] + REF[k:N-1]), f'PRNG_STALL@{k}')
    return t

CKSUM_TABLE = _build_table()

def classify(d):
    if not isinstance(d, dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'):           return d['_bad']
    if d['n_diff'] == 0:        return 'normal'

    named = CKSUM_TABLE.get(d['cksum'])
    if named:
        return named

    # structural fallback for anything the table does not cover
    nd, ns = d['n_diff'], d['n_sent']
    k, fs, sh = d['first_diff'], d['first_sent'], d['shiftn']
    if ns == N:                                       return 'FULL_BYPASS'
    if ns >= 2 and ns == N - k and fs == k and d['last_sent'] == N - 1 and sh == 0:
        return f'TRUNC@{k}'
    if nd == 1 and ns == 1 and fs == k:               return f'STORE_SKIP@{k}'
    if ns == 0 and sh == N - k:                       return f'STORE_PTR_SKIP@{k}'
    if fs != 65535 and fs > N - 1:                    return 'ORACLE_CORRUPT'
    if (ns > 0) != (fs <= N - 1):                     return 'ORACLE_CORRUPT'
    if ns == 1 and nd == 2 and fs == k + 1:           return f'CORRUPT+SKIP@{k}'
    if ns == 0 and nd == 1:                           return f'BYTE_CORRUPT@{k}'
    if ns == 0 and sh == 0 and nd >= N - 2 and k == 0:        return 'SEED_CORRUPT'
    if ns == 0 and sh == 0 and nd >= N - k - 2 and k > 0:     return f'PRNG_CORRUPT@{k}'
    return f'other(nd={nd},ns={ns},k={k},sh={sh})'

def corrupted(d):
    """Ground truth: did the seed come out wrong?"""
    return isinstance(d, dict) and not d.get('_bad') and d['cksum'] != GOOD_CKSUM
