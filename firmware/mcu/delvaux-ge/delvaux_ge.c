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
