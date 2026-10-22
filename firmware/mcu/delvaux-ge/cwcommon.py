"""Harness for Delvaux-GE: GE-flag detector on the uadd16 butterfly add inside
a full inverse NTT (HPC-blind long schedule).  Captures the target add's GE,
its result lanes, and the full-output checksum, scored against a clean
startup reference; DWT counters on the same runs give the HPC side."""
import logging, time
import chipwhisperer as cw

HUSKY_SN='50203220573555303030343235323038'
PS=4592; MAGIC=0x45474454; FRAME=44; SEL=1; CMD='s'; READ_MS=400
BASE_FREQ=7370000; BASE_BAUD=230400

def quiet(on=True):
    lvl=logging.CRITICAL if on else logging.WARNING
    try: cw.set_all_log_levels(lvl); return
    except Exception: pass
    for n in [x for x in list(logging.root.manager.loggerDict) if x.startswith('ChipWhisperer')]+['ChipWhisperer']:
        logging.getLogger(n).setLevel(lvl)

def connect(adc_timeout=0.3, freq=BASE_FREQ, baud=None):
    scope=cw.scope(sn=HUSKY_SN); scope.default_setup(); quiet()
    try: scope.adc.timeout=adc_timeout
    except Exception: pass
    target=cw.target(scope, cw.targets.SimpleSerial2)
    scope.clock.clkgen_freq=freq
    target.baud=baud if baud else int(round(BASE_BAUD*freq/BASE_FREQ))
    scope.glitch.enabled=True; scope.glitch.clk_src='pll'
    scope.glitch.output='clock_xor'; scope.glitch.trigger_src='ext_single'
    scope.io.hs2='glitch'; time.sleep(0.2); target.flush()
    return scope,target

def reboot(scope,target):
    scope.io.nrst='low'; time.sleep(0.05); scope.io.nrst='high_z'; time.sleep(0.10); target.flush()

def drain(target,settle=0.05,rounds=5):
    for _ in range(rounds):
        time.sleep(settle); n=0
        try: n=target.in_waiting()
        except Exception: pass
        try:
            if n: target.read(n,timeout=10)
            else: target.flush(); return
        except Exception: return

def arm_glitch(scope,ext,width,offset,repeat=1):
    scope.glitch.ext_offset=ext; scope.glitch.repeat=repeat
    scope.glitch.width=width; scope.glitch.offset=offset; scope.arm()

def run_once(scope,target,glitch=None,sel=SEL,cmd=None):
    if glitch is not None: arm_glitch(scope,*glitch)
    target.simpleserial_write(cmd or CMD, bytearray([sel&0xFF,(sel>>8)&0xFF,(sel>>16)&0xFF,(sel>>24)&0xFF]))
    if glitch is not None and scope.capture(): return 'NOTRIGGER'
    rb=target.simpleserial_read('r',FRAME,timeout=READ_MS); return parse(rb)

def run_safe(scope,target,glitch=None,sel=SEL,cmd=None,retries=1):
    for _ in range(retries+1):
        try: d=run_once(scope,target,glitch=glitch,sel=sel,cmd=cmd)
        except Exception: d=None
        if isinstance(d,dict): return d,False
        try: scope.capture()
        except Exception: pass
        reboot(scope,target); drain(target)
    return None,True

def _u16(b,o): return b[o]|(b[o+1]<<8)
def _s16(b,o):
    v=_u16(b,o); return v-0x10000 if v&0x8000 else v
def _u32(b,o): return b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24)

def parse(rb):
    if rb is None: return 'NOFRAME'
    b=bytes(rb)
    if len(b)<FRAME: return 'SHORTFRAME'
    if _u32(b,0)!=MAGIC: return 'BADMAGIC'
    cyc=_u32(b,8)
    if cyc<1000 or cyc>5000000: return 'BAD_COUNTERS'
    return dict(sel=_u32(b,4),cyc=cyc,cpi=b[12],lsu=b[13],fold=b[14],dirty=b[15],
                ge_obs=b[16],ge_ref=b[17],sentinel=b[18],hit=b[19],
                lo=_s16(b,20),hi=_s16(b,22),rlo=_s16(b,24),rhi=_s16(b,26),
                fnv=_u32(b,28),rfnv=_u32(b,32),
                flags_ok=b[36],res_ok=b[37],poly_ok=b[38],cyc_at=_u32(b,40))

def safe(d,base_cyc=0):
    if isinstance(d,dict): return d
    return dict(sel=0,cyc=base_cyc,cpi=0,lsu=0,fold=0,dirty=0,ge_obs=0,ge_ref=0,
                sentinel=5,hit=1,lo=0,hi=0,rlo=0,rhi=0,fnv=0,rfnv=0,
                flags_ok=1,res_ok=1,poly_ok=1,cyc_at=0,
                _bad=('NOFRAME' if not d else 'BADFRAME:'+str(d)))

def fingerprint(d): return (d['cyc'],d['cpi'],d['lsu'],d['fold'])

GE_VALID = frozenset((0x0, 0x3, 0x5, 0xC, 0xF))
def frame_sane(d):
    # GE is only ever {0,3,C,F} (uadd16 pairs) or 0x5 (sentinel, on a skip);
    # control bytes are 0/1.  Anything else = glitch scrambled the capture/frame.
    return (d['ge_obs'] in GE_VALID and d['ge_ref'] in GE_VALID
            and d['hit'] in (0,1) and d['flags_ok'] in (0,1)
            and d['res_ok'] in (0,1) and d['poly_ok'] in (0,1))

def classify(d):
    if not isinstance(d,dict): return str(d) if d else 'NOFRAME'
    if d.get('_bad'): return d['_bad']
    if not frame_sane(d): return 'FRAME_CORRUPT'
    if d['dirty']&1: return 'CANARY_DIRTY'
    if d['dirty']&2 or not d['hit']: return 'TARGET_MISSED'
    if d['poly_ok'] and d['res_ok'] and d['flags_ok']: return 'normal'
    if d['poly_ok'] and not d['res_ok']:
        return 'POLY_OK_ADD_BAD'          # add lanes wrong but output recovered (rare)
    # output corrupted = a real fault:
    if d['ge_obs']==d['sentinel']:
        return f"SKIP_CAUGHT(ge={d['ge_obs']:X})"       # target uadd16 skipped (sentinel)
    if not d['flags_ok']:
        return f"CORRUPT_CAUGHT(ge_obs={d['ge_obs']:X},ge_ref={d['ge_ref']:X})"
    return f"GE_BLIND(ge={d['ge_obs']:X})"              # output wrong, GE unchanged -> missed

def unscorable(d):
    if not isinstance(d,dict) or d.get('_bad'): return True
    if not frame_sane(d): return True
    return bool(d['dirty']&1) or bool(d['dirty']&2) or not d['hit']

def is_fault(d):
    """The inverse-NTT OUTPUT differs from the clean reference -- the Delvaux fault."""
    return not unscorable(d) and not d['poly_ok']

def ge_detects(d):
    """Detector under test: the target add's GE != the correct GE."""
    return not unscorable(d) and not d['flags_ok']
