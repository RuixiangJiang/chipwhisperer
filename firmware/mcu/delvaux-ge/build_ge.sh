#!/usr/bin/env bash
# build_ge.sh -- generate the Delvaux-GE experiment (flag-based detector on the
# real uadd16 butterfly add, in the HPC-blind long-schedule regime).
# Run once:  bash build_ge.sh   ->  creates ./delvaux-ge/ with all files.
set -eu
DIR="${1:-delvaux-ge}"
mkdir -p "$DIR/stub"
cd "$DIR"
echo "writing into $(pwd)"

# ---------------------------------------------------------------- stubs -----
cat > stub/hal.h <<'EOF'
void platform_init(void); void init_uart(void); void trigger_setup(void);
void trigger_high(void); void trigger_low(void);
EOF
cat > stub/simpleserial.h <<'EOF'
#include <stdint.h>
void simpleserial_init(void);
int simpleserial_addcmd(char c, unsigned int len, uint8_t (*fp)(uint8_t,uint8_t,uint8_t,uint8_t*));
int simpleserial_put(char c, uint8_t len, uint8_t *buf);
int simpleserial_get(void);
EOF

# ---------------------------------------------------------------- firmware --
cat > delvaux_ge.c <<'EOF'
/* Delvaux 2022 "Roulette" add-skip -- FLAG detector on the REAL uadd16 target,
 * in the regime where HPC fails.
 *
 * The earlier isolated-adds experiment showed a scalar `adds` sets NZCV and a
 * flag check catches a fault with TPR 1.0 -- but it ran in a short routine
 * where the glitch also moved the cycle count, so HPC "worked" too and the
 * comparison was not the HPC-blind regime.
 *
 * This entry puts the fault where HPC provably fails: a single butterfly add
 * inside a full inverse NTT (1024 butterflies, tens of thousands of cycles),
 * so skipping that one add leaves the instruction schedule -- and every DWT
 * counter -- unchanged, exactly as in the original Delvaux HPC campaign
 * (99%+ undetectable).  The target add is a genuine `uadd16` (two packed
 * 16-bit lanes), as pqm4's fastinvntt.S uses, so the only architectural flags
 * it writes are the GE flags, not NZCV.  The detector reads GE after the add
 * and compares it to the GE a correct add produces (snapshotted on a clean
 * run at startup).
 *
 * Why this is self-contained and not a patch into pqm4: the GE of ONE specific
 * butterfly can only be captured by an `mrs` at that instruction, and pqm4's
 * butterfly is a macro that expands at every butterfly -- editing it would
 * capture the last one, not the target.  So the inverse NTT here is a
 * self-consistent negacyclic-style transform (round-trip verified on host)
 * whose butterfly ADD is the real uadd16, with exactly one butterfly
 * instrumented.  The fault (uadd16 add skip -> power-of-two error support) and
 * the regime (long fixed schedule, HPC-blind) are faithful to Delvaux.
 *
 * Sentinel: a `uadd8` sets GE=0x5 before the target.  uadd16 can only produce
 * GE in {0x0,0x3,0xC,0xF} (its two GE-pairs move together), so 0x5 is an
 * impossible-for-uadd16 marker: a skipped target leaves GE=0x5, caught for
 * certain.  A corrupted-but-executed add leaves GE in {0,3,C,F}; the detector
 * catches it only if that differs from the correct GE -- 2 bits of coverage.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <string.h>

#define N          256
#define Q          3329
#define TARGET     128            /* butterfly index to instrument (len>=2 layer) */
#define FRAMELEN   44
#define MAGIC      0x45470000u | 0x4454u      /* "GE" + "DT" -> 0x45474454 */

#define CPACR       (*(volatile uint32_t *)0xE000ED88)
#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

#include "zetas.inc"

static int16_t  work[N];
static uint32_t canary = 0xC0DEu;

/* capture of the instrumented target, this run */
static uint32_t g_ge, g_hit, g_cyc_at;
static int16_t  g_lo, g_hi;
/* clean reference, snapshotted at startup */
static uint32_t r_ge, r_fnv;
static int16_t  r_lo, r_hi;

#define QINV 62209           /* q^{-1} mod 2^16 (Kyber) */
/* Fixed-cost reductions (no udiv), so the schedule is operand-independent and
 * a data fault leaves CYC/CPI/LSU/FOLD unchanged -- the HPC-blind regime. */
static int16_t montgomery_reduce(int32_t a){
    int16_t t=(int16_t)(a*QINV); int32_t r=(a-(int32_t)t*Q)>>16; return (int16_t)r;
}
static int16_t fqmul(int16_t a,int16_t b){ return montgomery_reduce((int32_t)a*b); }
static int16_t barrett_reduce(int16_t a){
    int16_t t=(int16_t)(((int32_t)20159*a+(1<<25))>>26); t=(int16_t)(t*Q); return (int16_t)(a-t);
}
/* centered reduce, used only by make_input (outside the measured window) */
static int16_t to_signed(int32_t x){ x%=Q; if(x<0)x+=Q; if(x>(Q-1)/2)x-=Q; return (int16_t)x; }

/* target: pack two adjacent butterfly adds into one uadd16, GE=0x5 sentinel
 * first (impossible for uadd16).  Returns raw 16-bit lane sums + GE nibble. */
static inline void target_uadd16(int16_t alo,int16_t ahi,int16_t blo,int16_t bhi,
                                 int16_t *rlo,int16_t *rhi,uint32_t *ge)
{
    uint32_t pa = ((uint32_t)(uint16_t)alo) | ((uint32_t)(uint16_t)ahi<<16);
    uint32_t pb = ((uint32_t)(uint16_t)blo) | ((uint32_t)(uint16_t)bhi<<16);
    uint32_t sum, apsr;
#if defined(__arm__)
    uint32_t snk;
    __asm volatile (
        "uadd8  %[k], %[sa], %[sb] \n\t"   /* sentinel: GE <- 0x5 */
        "uadd16 %[s], %[x],  %[y]  \n\t"   /* <<== Delvaux target: the add */
        "mrs    %[f], APSR         \n\t"
        : [k]"=&r"(snk), [s]"=&r"(sum), [f]"=&r"(apsr)
        : [sa]"r"(0x00FF00FFu), [sb]"r"(0x00010001u),
          [x]"r"(pa), [y]"r"(pb)
        : "cc"
    );
#else   /* host emulation for the round-trip / logic check */
    uint32_t a0=pa&0xFFFF,a1=pa>>16,b0=pb&0xFFFF,b1=pb>>16;
    uint32_t s0=a0+b0, s1=a1+b1;
    sum=(s0&0xFFFF)|((s1&0xFFFF)<<16);
    apsr=0; if(s0>=0x10000u)apsr|=0x30000u; if(s1>=0x10000u)apsr|=0xC0000u;
#endif
    *rlo=(int16_t)(sum&0xFFFF); *rhi=(int16_t)(sum>>16);
    *ge=(apsr>>16)&0xFu;
}

/* inverse NTT, Gentleman-Sande; the butterfly at index TARGET (and its pair
 * neighbour) is done by the instrumented uadd16. */
static void inv(int16_t p[N])
{
    long bf=0; int k=N-1;
    g_hit=0;
    for(int len=1; len<N; len<<=1){
        for(int start=0; start<N; start+=2*len){
            int16_t z=ZETAS[k--];
            int j=start;
            while(j<start+len){
                if(bf==TARGET && j+1<start+len){
                    int16_t rlo,rhi; uint32_t ge;
                    g_cyc_at=DWT_CYCCNT;          /* cycle offset of the target add = the ext to glitch */
                    int16_t alo=p[j], blo=p[j+len], ahi=p[j+1], bhi=p[j+1+len];
                    target_uadd16(alo,ahi,blo,bhi,&rlo,&rhi,&ge);
                    g_lo=rlo; g_hi=rhi; g_ge=ge; g_hit=1;
                    p[j]   = barrett_reduce(rlo);   p[j+1] = barrett_reduce(rhi);
                    p[j+len]   = fqmul(z,(int16_t)(alo-blo));
                    p[j+1+len] = fqmul(z,(int16_t)(ahi-bhi));
                    bf+=2; j+=2;
                }else{
                    int16_t t=p[j];
                    p[j]     = barrett_reduce((int16_t)(t+p[j+len]));
                    p[j+len] = fqmul(z,(int16_t)(t-p[j+len]));
                    bf++; j++;
                }
            }
        }
    }
    for(int i=0;i<N;i++) p[i]=fqmul(p[i],(int16_t)NINV_MONT);
}

static uint32_t fnv(const int16_t *p,unsigned n){
    uint32_t h=0x811C9DC5u; for(unsigned i=0;i<n;i++){uint16_t v=(uint16_t)p[i];
        h^=(v&0xFF);h*=16777619u; h^=(v>>8);h*=16777619u;} return h;
}
static void make_input(uint32_t sel){
    uint32_t s=0x5EED0000u ^ sel;
    for(int i=0;i<N;i++){ s=1103515245u*s+12345u; work[i]=to_signed((int32_t)((s>>16)%Q)); }
}

static void dwt_init(void){ DEMCR|=(1u<<24); DWT_CTRL=0; }
static void dwt_reset(void){
    DWT_CTRL &= ~(1u|(1u<<17)|(1u<<20)|(1u<<21));
    DWT_CYCCNT=0;DWT_CPICNT=0;DWT_LSUCNT=0;DWT_FOLDCNT=0;
    DWT_CTRL |= (1u|(1u<<17)|(1u<<20)|(1u<<21));
}
static void put16(uint8_t*f,unsigned o,uint16_t v){f[o]=(uint8_t)v;f[o+1]=(uint8_t)(v>>8);}
static void put32(uint8_t*f,unsigned o,uint32_t v){f[o]=(uint8_t)v;f[o+1]=(uint8_t)(v>>8);f[o+2]=(uint8_t)(v>>16);f[o+3]=(uint8_t)(v>>24);}

static void snapshot_ref(uint32_t sel){
    make_input(sel);
    inv(work);
    r_ge=g_ge; r_lo=g_lo; r_hi=g_hi; r_fnv=fnv(work,N);
}

static uint8_t do_cmd(uint8_t cc,uint8_t sc,uint8_t l,uint8_t *d)
{
    uint32_t sel,cyc,fnvo; uint8_t cpi,lsu,fold,frame[FRAMELEN],dirty=0;
    (void)cc;(void)sc;(void)l;
    sel=(uint32_t)d[0]|((uint32_t)d[1]<<8)|((uint32_t)d[2]<<16)|((uint32_t)d[3]<<24);
    make_input(sel);
    canary=0xC0DEu;

    dwt_reset();
    __asm volatile("cpsid i":::"memory");
    trigger_high();
    inv(work);
    trigger_low();
    cyc=DWT_CYCCNT; cpi=(uint8_t)DWT_CPICNT; lsu=(uint8_t)DWT_LSUCNT; fold=(uint8_t)DWT_FOLDCNT;
    __asm volatile("cpsie i":::"memory");

    if(canary!=0xC0DEu) dirty|=1u;
    if(!g_hit)          dirty|=2u;         /* target butterfly never reached */
    fnvo=fnv(work,N);

    put32(frame,0,MAGIC);
    put32(frame,4,sel);
    put32(frame,8,cyc);
    frame[12]=cpi; frame[13]=lsu; frame[14]=fold; frame[15]=dirty;
    frame[16]=(uint8_t)g_ge; frame[17]=(uint8_t)r_ge; frame[18]=0x5; frame[19]=(uint8_t)g_hit;
    put16(frame,20,(uint16_t)g_lo); put16(frame,22,(uint16_t)g_hi);
    put16(frame,24,(uint16_t)r_lo); put16(frame,26,(uint16_t)r_hi);
    put32(frame,28,fnvo);
    put32(frame,32,r_fnv);
    frame[36]=(uint8_t)(g_ge==r_ge);                       /* flags_ok */
    frame[37]=(uint8_t)(g_lo==r_lo && g_hi==r_hi);         /* res_ok   */
    frame[38]=(uint8_t)(fnvo==r_fnv);                      /* poly_ok  */
    frame[39]=0;
    put32(frame,40,g_cyc_at);
    simpleserial_put('r',FRAMELEN,frame);
    return 0;
}

int main(void)
{
    platform_init(); init_uart(); trigger_setup();
    CPACR |= (0xFu<<20); __asm volatile("dsb":::"memory"); __asm volatile("isb":::"memory");
    dwt_init();
    snapshot_ref(1);                      /* clean reference for sel=1 */
    simpleserial_init();
    simpleserial_addcmd('s',4,do_cmd);
    simpleserial_addcmd('g',4,do_cmd);
    while(1) simpleserial_get();
}
EOF

# zetas (Montgomery domain) + NINV_MONT
cat > zetas.inc <<'EOF'
#define NINV_MONT 256   /* n^{-1} in Montgomery domain: fqmul(x,256)=x*n^{-1} */
static const int16_t ZETAS[256] = {
 -1044,  1044,  -758,   758,  -359,   359, -1517,  1517,
  1493, -1493,  1422, -1422,   287,  -287,   202,  -202,
  -171,   171,   622,  -622,  1577, -1577,   182,  -182,
   962,  -962, -1202,  1202, -1474,  1474,  1468, -1468,
   573,  -573, -1325,  1325,   264,  -264,   383,  -383,
  -829,   829,  1458, -1458, -1602,  1602,  -130,   130,
  -681,   681,  1017, -1017,   732,  -732,   608,  -608,
 -1542,  1542,   411,  -411,  -205,   205, -1571,  1571,
  1223, -1223,   652,  -652,  -552,   552,  1015, -1015,
 -1293,  1293,  1491, -1491,  -282,   282, -1544,  1544,
   516,  -516,    -8,     8,  -320,   320,  -666,   666,
 -1618,  1618, -1162,  1162,   126,  -126,  1469, -1469,
  -853,   853,   -90,    90,  -271,   271,   830,  -830,
   107,  -107, -1421,  1421,  -247,   247,  -951,   951,
  -398,   398,   961,  -961, -1508,  1508,  -725,   725,
   448,  -448, -1065,  1065,   677,  -677, -1275,  1275,
 -1103,  1103,   430,  -430,   555,  -555,   843,  -843,
 -1251,  1251,   871,  -871,  1550, -1550,   105,  -105,
   422,  -422,   587,  -587,   177,  -177,  -235,   235,
  -291,   291,  -460,   460,  1574, -1574,  1653, -1653,
  -246,   246,   778,  -778,  1159, -1159,  -147,   147,
  -777,   777,  1483, -1483,  -602,   602,  1119, -1119,
 -1590,  1590,   644,  -644,  -872,   872,   349,  -349,
   418,  -418,   329,  -329,  -156,   156,   -75,    75,
   817,  -817,  1097, -1097,   603,  -603,   610,  -610,
  1322, -1322, -1285,  1285, -1465,  1465,   384,  -384,
 -1215,  1215,  -136,   136,  1218, -1218, -1335,  1335,
  -874,   874,   220,  -220, -1187,  1187, -1659,  1659,
 -1185,  1185, -1530,  1530, -1278,  1278,   794,  -794,
 -1510,  1510,  -854,   854,  -870,   870,   478,  -478,
  -108,   108,  -308,   308,   996,  -996,   991,  -991,
   958,  -958, -1460,  1460,  1522, -1522,  1628, -1628,
};
EOF

# ---------------------------------------------------------------- Makefile --
cat > Makefile <<'EOF'
TARGET = delvaux_ge
SRC += delvaux_ge.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1
include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
$(OBJDIR)/delvaux_ge.o: delvaux_ge.c zetas.inc
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops $< -o $@
EOF

# ---------------------------------------------------------------- cwcommon --
cat > cwcommon.py <<'EOF'
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
EOF

# ---------------------------------------------------------------- flash -----
cat > flash.py <<'EOF'
import sys, chipwhisperer as cw
from cwcommon import HUSKY_SN
fw=sys.argv[1] if len(sys.argv)>1 else 'delvaux_ge-CW308_STM32F4.hex'
scope=cw.scope(sn=HUSKY_SN); scope.default_setup()
cw.program_target(scope, cw.programmers.STM32FProgrammer, fw)
scope.dis(); print('programmed',fw)
EOF

# ---------------------------------------------------------------- probe -----
cat > probe.py <<'EOF'
import sys,time
from cwcommon import connect,reboot,parse,classify,FRAME,MAGIC,SEL
_f=int(sys.argv[1]) if len(sys.argv)>1 else 0
scope,target=connect(**({'freq':_f} if _f else {}))
print('expected magic 0x%08X frame %d  phase_shift_steps=%d'%(MAGIC,FRAME,scope.glitch.phase_shift_steps))
reboot(scope,target)
for cmd in ('s','g'):
    target.flush(); time.sleep(0.05)
    try:
        target.simpleserial_write(cmd,bytearray([SEL,0,0,0]))
        rb=target.simpleserial_read('r',FRAME,timeout=2000)
    except Exception as e:
        print("cmd '%s': exc %s"%(cmd,e)); reboot(scope,target); continue
    d=parse(rb)
    print("cmd '%s': len=%-3d class=%-14s raw=%s"%(cmd,len(rb) if rb else 0,classify(d),bytes(rb).hex() if rb else None))
    if isinstance(d,dict):
        print("   cyc=%d cpi=%d lsu=%d fold=%d  hit=%d dirty=%d"%(d['cyc'],d['cpi'],d['lsu'],d['fold'],d['hit'],d['dirty']))
        print("   target GE_obs=0x%X GE_ref=0x%X  lanes obs=(%d,%d) ref=(%d,%d)  poly_ok=%d"
              %(d['ge_obs'],d['ge_ref'],d['lo'],d['hi'],d['rlo'],d['rhi'],d['poly_ok']))
        print("   target add at cycle %d  (use this as the glitch ext)"%d['cyc_at'])
    reboot(scope,target)
print("\nraw '01' len 1 = SS_ERR_CMD -> reflash.")
scope.dis()
EOF

# ---------------------------------------------------------------- baseline --
cat > baseline.py <<'EOF'
import argparse,collections,csv,sys
from cwcommon import connect,reboot,run_once,classify,fingerprint,SEL
ap=argparse.ArgumentParser()
ap.add_argument('--n',type=int,default=100); ap.add_argument('--sel',type=int,default=SEL)
ap.add_argument('--freq',type=int,default=0); a=ap.parse_args()
scope,target=connect(**({'freq':a.freq} if a.freq else {})); reboot(scope,target)
fps,rows,bad=collections.Counter(),[],0
for i in range(a.n):
    d=run_once(scope,target,glitch=None,sel=a.sel)
    if not isinstance(d,dict):
        bad+=1; print(f'  run {i}: {d}')
        if i==0: print('No frame -- reflash / check SS_VER_2_1.'); scope.dis(); sys.exit(1)
        continue
    fps[fingerprint(d)]+=1
    rows.append(dict(run=i,cls=classify(d),ge_obs='0x%X'%d['ge_obs'],ge_ref='0x%X'%d['ge_ref'],
                     lo=d['lo'],hi=d['hi'],poly_ok=d['poly_ok'],hit=d['hit'],
                     fnv='0x%08X'%d['fnv'],cyc=d['cyc'],cyc_at=d['cyc_at'],cpi=d['cpi'],lsu=d['lsu'],fold=d['fold']))
if not rows: print('valid=0'); scope.dis(); sys.exit(1)
with open('baseline.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\nvalid={len(rows)} unreadable={bad}')
print('distinct fingerprints:',len(fps))
for fp,n in fps.most_common(): print(f'   (cyc,cpi,lsu,fold)={fp} * {n}')
ge=collections.Counter(r['ge_obs'] for r in rows); fv=collections.Counter(r['fnv'] for r in rows)
print(f'target GE: {dict(ge)}   output checksum: {dict(fv)}')
print(f'target add lanes (lo,hi) = ({rows[0]["lo"]},{rows[0]["hi"]})')
ca=collections.Counter(r.get('cyc_at') for r in rows)
print(f'>>> target add is at cycle {list(ca)[0] if len(ca)==1 else dict(ca)} '
      f'-- glitch ext near this value <<<')
ok=(len(fps)==1 and bad==0 and len(fv)==1 and all(r["hit"] for r in rows))
print('ORACLE','OK -- deterministic output, target reached every run, 1 fingerprint' if ok else 'MISMATCH -- stop here')
scope.dis()
EOF

# ---------------------------------------------------------------- map -------
cat > map_ge.py <<'EOF'
import argparse,collections,csv
from cwcommon import connect,reboot,run_safe,classify,fingerprint,safe,SEL
QUICK=[(82,-136),(55,56),(275,-688),(400,-688)]
DENSE=[(w,o) for w in (18,36,55,73,82,100,137,192,275,400) for o in (-688,-456,-229,-136,-56,56,136,229)]
ap=argparse.ArgumentParser()
ap.add_argument('--base_cyc',type=int,required=True)
ap.add_argument('--ext_min',type=int,default=0); ap.add_argument('--ext_max',type=int,required=True)
ap.add_argument('--step',type=int,default=1); ap.add_argument('--reps',type=int,default=4)
ap.add_argument('--sel',type=int,default=SEL); ap.add_argument('--dense',action='store_true')
ap.add_argument('--pairs',default=''); ap.add_argument('--repeat',type=int,default=1)
ap.add_argument('--freq',type=int,default=0); ap.add_argument('--max_streak',type=int,default=60)
ap.add_argument('--out',default='map_ge.csv'); a=ap.parse_args()
if a.pairs: GRID=[tuple(int(v) for v in p.split(',')) for p in a.pairs.split(';') if p.strip()]
elif a.dense: GRID=DENSE
else: GRID=QUICK
scope,target=connect(**({'freq':a.freq} if a.freq else {}))
print('grid:',GRID,' phase_shift_steps=',scope.glitch.phase_shift_steps); reboot(scope,target)
rows,per,classes=[],collections.defaultdict(collections.Counter),collections.Counter()
total=ncrash=run_crash=0; abort=False
for ext in range(a.ext_min,a.ext_max+1,a.step):
    if abort: break
    for (w,off) in GRID:
        if abort: break
        for _ in range(a.reps):
            if abort: break
            total+=1
            d,crashed=run_safe(scope,target,glitch=(ext,w,off,a.repeat),sel=a.sel)
            if crashed:
                ncrash+=1; run_crash+=1; per[ext]['CRASH']+=1; classes['CRASH']+=1
                if run_crash>=a.max_streak: print(f'\n*** {run_crash} crashes in a row at ext={ext}; stopping.',flush=True); abort=True
                continue
            run_crash=0; cls=classify(d); key=cls.split('(')[0]; per[ext][key]+=1; classes[key]+=1
            if cls=='normal': continue
            d=safe(d,a.base_cyc); fp=fingerprint(d)
            rows.append(dict(ext=ext,width=w,offset=off,cls=cls,ge_obs='0x%X'%d['ge_obs'],
                             ge_ref='0x%X'%d['ge_ref'],poly_ok=d['poly_ok'],flags_ok=d['flags_ok'],
                             res_ok=d['res_ok'],hit=d['hit'],dirty=d['dirty'],
                             cyc=fp[0],dcyc=fp[0]-a.base_cyc,cpi=fp[1],lsu=fp[2],fold=fp[3]))
    if ((ext-a.ext_min)//max(a.step,1))%50==0:
        print(f'  ... ext={ext} attempts={total} crashes={ncrash} interesting={len(rows)}',flush=True)
with open(a.out,'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0].keys()) if rows else ['ext']); w.writeheader(); w.writerows(rows)
print('\n=== per-ext map ===')
for ext in sorted(per):
    c=per[ext]
    if set(c)<={'normal'}: continue
    print(f'  ext={ext:5d}  '+', '.join(f'{k} x{v}' for k,v in c.most_common() if k!='normal'))
print('\n=== totals ==='); 
for k,v in classes.most_common(): print(f'  {k:16s} {v}')
fb=sum(1 for r in rows if r['cls'].startswith('GE_BLIND'))
sk=sum(1 for r in rows if r['cls'].startswith('SKIP_CAUGHT'))
cc=sum(1 for r in rows if r['cls'].startswith('CORRUPT_CAUGHT'))
print(f'\nSKIP_CAUGHT={sk} CORRUPT_CAUGHT={cc} GE_BLIND={fb} (output wrong, GE missed it)')
print(f'attempts={total} crashes={ncrash} rows={len(rows)} -> {a.out}')
scope.dis()
EOF

# ---------------------------------------------------------------- campaign --
cat > campaign.py <<'EOF'
import argparse,collections,csv
from cwcommon import connect,reboot,run_safe,classify,safe,SEL
ap=argparse.ArgumentParser()
ap.add_argument('--ext_offset',type=int,required=True); ap.add_argument('--width',type=int,required=True)
ap.add_argument('--offset',type=int,required=True); ap.add_argument('--repeat',type=int,default=1)
ap.add_argument('--n',type=int,default=1000); ap.add_argument('--sel',type=int,default=SEL)
ap.add_argument('--freq',type=int,default=0); ap.add_argument('--out',default='campaign.csv'); a=ap.parse_args()
scope,target=connect(**({'freq':a.freq} if a.freq else {})); reboot(scope,target)
rows,crashes,got,streak=[],0,0,0
while got<a.n:
    d,crashed=run_safe(scope,target,glitch=(a.ext_offset,a.width,a.offset,a.repeat),sel=a.sel)
    if crashed:
        crashes+=1; streak+=1
        if streak>=80: print(f'\n*** 80 crashes in a row; got {got}/{a.n}, stopping.',flush=True); break
        continue
    streak=0; d=safe(d)
    rows.append(dict(run=got,cls=classify(d),ge_obs='0x%X'%d['ge_obs'],ge_ref='0x%X'%d['ge_ref'],
                     poly_ok=d['poly_ok'],flags_ok=d['flags_ok'],res_ok=d['res_ok'],hit=d['hit'],
                     dirty=d['dirty'],cyc=d['cyc'],cpi=d['cpi'],lsu=d['lsu'],fold=d['fold']))
    got+=1
    if got%100==0: print(f'  {got}/{a.n} crashes={crashes}',flush=True)
with open(a.out,'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f'\n{got} collected, {crashes} crashes -> {a.out}')
cls=collections.Counter(r['cls'].split('(')[0] for r in rows)
for k,v in cls.most_common(): print(f'  {k:16s} {v:5d}  {100*v/got:6.2f}%')
scope.dis()
EOF

# ---------------------------------------------------------------- confusion -
cat > confusion.py <<'EOF'
"""GE-flag detector vs the four DWT counters, same runs.
Positive = inverse-NTT OUTPUT corrupted (the Delvaux fault).
GE detector = target add GE != correct GE.  HPC = fingerprint != baseline.
Negative  = glitched runs whose output is correct.
Excluded  = CANARY_DIRTY, TARGET_MISSED, unreadable."""
import argparse,collections,csv
ap=argparse.ArgumentParser()
ap.add_argument('csvfile',nargs='?',default='campaign.csv')
ap.add_argument('--neg',action='append',default=[]); ap.add_argument('--base',required=True)
a=ap.parse_args()
BASE=tuple(int(x) for x in a.base.split(','))
rows=list(csv.DictReader(open(a.csvfile)))
for e in a.neg: rows+=list(csv.DictReader(open(e))); print(f'pooled negatives from {e}')
def fp(r): return (int(r['cyc']),int(r['cpi']),int(r['lsu']),int(r['fold']))
def I(r,k): return int(r[k])
bad=[r for r in rows if r['cls'].startswith(('BADFRAME','NOFRAME','SHORTFRAME','BADMAGIC','BAD_COUNTERS'))]
exc=[r for r in rows if r['cls'] in ('CANARY_DIRTY','TARGET_MISSED','FRAME_CORRUPT')]
valid=[r for r in rows if r not in bad and r not in exc]
pos=[r for r in valid if not I(r,'poly_ok')]
neg=[r for r in valid if I(r,'poly_ok')]
print(f'baseline fingerprint = {BASE}')
print(f'rows={len(rows)} scorable={len(valid)} excluded={len(exc)} unreadable={len(bad)}')
print(f'  output corrupted = {len(pos)}   output correct = {len(neg)}')
print('\n=== distribution ===')
cls=collections.Counter(r['cls'].split('(')[0] for r in rows)
for k,v in cls.most_common(): print(f'  {k:16s} {v:5d}  {100*v/len(rows):6.2f}%')
def mat(name,det):
    TP=sum(1 for r in pos if det(r)); FN=len(pos)-TP
    FP=sum(1 for r in neg if det(r)); TN=len(neg)-FP
    tpr=TP/len(pos) if pos else 0; fpr=FP/len(neg) if neg else 0
    pr=TP/(TP+FP) if TP+FP else 0; acc=(TP+TN)/(len(pos)+len(neg)) if valid else 0
    print(f'  {name:16s} TP={TP:5d} FN={FN:5d} FP={FP:4d} TN={TN:5d}  TPR={tpr:.4f} FPR={fpr:.4f} PREC={pr:.4f} ACC={acc:.4f}')
print(f'\n=== detectors, positive = corrupted output (pos={len(pos)}, neg={len(neg)}) ===')
mat('GE flags',   lambda r: not I(r,'flags_ok'))
mat('HPC full',   lambda r: fp(r)!=BASE)
mat('HPC CYCCNT', lambda r: int(r['cyc'])!=BASE[0])
mat('HPC CPICNT', lambda r: int(r['cpi'])!=BASE[1])
mat('HPC LSUCNT', lambda r: int(r['lsu'])!=BASE[2])
mat('HPC FOLDCNT',lambda r: int(r['fold'])!=BASE[3])
at_add=[r for r in pos if not I(r,'res_ok')]
elsewhere=[r for r in pos if I(r,'res_ok')]
print(f'\nof {len(pos)} corrupting runs: {len(at_add)} faulted the target add, {len(elsewhere)} faulted elsewhere')
if at_add:
    TPa=sum(1 for r in at_add if not I(r,'flags_ok'))
    print(f'GE detector on target-add faults only: TP={TPa} FN={len(at_add)-TPa} TPR={TPa/len(at_add):.4f}')
    gba=[r for r in at_add if I(r,'flags_ok')]
    print(f'  GE-blind among target-add faults: {len(gba)}/{len(at_add)} = {100*len(gba)/len(at_add):.2f}%')
    if gba: print('    their GE (== correct GE 0x3):',dict(collections.Counter(r['ge_obs'] for r in gba)))
gb=[r for r in pos if I(r,'flags_ok')]
print(f'overall GE-undetectable corrupting runs: {len(gb)}/{len(pos)} = {100*len(gb)/len(pos) if pos else 0:.2f}%')
hb=[r for r in pos if fp(r)==BASE]
print(f'HPC-undetectable corrupting runs (fingerprint==baseline): {len(hb)}/{len(pos)} = {100*len(hb)/len(pos) if pos else 0:.2f}%')
both=[r for r in pos if I(r,'flags_ok') and fp(r)==BASE]
print(f'undetectable by BOTH: {len(both)}/{len(pos)} = {100*len(both)/len(pos) if pos else 0:.2f}%')
EOF

echo "done. files in $(pwd):"
ls -1
