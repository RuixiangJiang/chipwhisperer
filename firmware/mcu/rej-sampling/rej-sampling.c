/* Entry 5 - Ravi et al. (2019): skip the store or the counter increment in
 * Dilithium's rejection sampler.  Target: `a[ctr++] = t` in rej_uniform.
 * a[] is pre-filled with SENTINEL, so a skipped store leaves that slot
 * untouched -- a direct, local oracle (unlike a hash). */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stddef.h>

#define DN        256
#define DQ        8380417
#define SENTINEL  0xA5A5A5A5u
#define BUFLEN    900

#define DEMCR       (*(volatile uint32_t*)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t*)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t*)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t*)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t*)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t*)0xE0001018)
#define TRCENA (1u<<24)
#define CYCCNTENA (1u<<0)
#define CPIEVTENA (1u<<17)
#define LSUEVTENA (1u<<20)
#define FOLDEVTENA (1u<<21)

static int32_t  acoef[DN], refc[DN];
static uint8_t  sbuf[BUFLEN];

/* verbatim from Dilithium Round-3 poly.c. It is `static` there, so it cannot
 * be linked; diff this against your tree to confirm fidelity.
 * noinline keeps the call boundary analysable in objdump. */
__attribute__((noinline, noclone))
unsigned int rej_uniform(int32_t *a, unsigned int len,
                                const uint8_t *buf, unsigned int buflen)
{
    unsigned int ctr, pos;
    uint32_t t;
    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t  = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF;
        if (t < DQ)
            a[ctr++] = t;          /* <-- Ravi target: the store and the add */
    }
    return ctr;
}

static void make_buf(void){
    uint32_t x = 0x12345u; unsigned i = 0;
    while (i + 3 <= BUFLEN) {
        unsigned s = i / 3;
        x = (1103515245u * x + 12345u) & 0x7FFFFFu;
        uint32_t t = x;
        if (s==10u||s==50u||s==90u||s==150u||s==200u) t = 0x7FF000u + (s & 0xFFFu);
        sbuf[i++] =  t        & 0xFF;
        sbuf[i++] = (t >>  8) & 0xFF;
        sbuf[i++] = (t >> 16) & 0xFF;
    }
}

static uint32_t fnv32(const int32_t *v, unsigned n){
    uint32_t h = 0x811C9DC5u;
    for (unsigned i=0;i<n;i++)
        for (unsigned s=0;s<32;s+=8){
            h ^= ((uint32_t)v[i] >> s) & 0xFF;
            h *= 0x01000193u;
        }
    return h;
}

static void dwt_reset(void){
    DWT_CYCCNT=0; DWT_CPICNT=0; DWT_LSUCNT=0; DWT_FOLDCNT=0;
}

static uint8_t do_sample(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *b){
    (void)cmd;(void)scmd;(void)len;(void)b;
    uint32_t cyc,cpi,lsu,fold;
    unsigned ctr;

    for (unsigned i=0;i<DN;i++) acoef[i] = (int32_t)SENTINEL;   /* sentinel fill */

    dwt_reset();
    __asm volatile("cpsid i" ::: "memory");
    trigger_high();
    ctr = rej_uniform(acoef, DN, sbuf, BUFLEN);   /* <-- measured region */
    trigger_low();
    cyc=DWT_CYCCNT; cpi=DWT_CPICNT&0xFF; lsu=DWT_LSUCNT&0xFF; fold=DWT_FOLDCNT&0xFF;
    __asm volatile("cpsie i" ::: "memory");

    uint16_t n_diff=0, first_diff=0xFFFF, n_sent=0, first_sent=0xFFFF;
    for (unsigned i=0;i<DN;i++){
        if (acoef[i] != refc[i]) { n_diff++; if (first_diff==0xFFFF) first_diff=i; }
        if ((uint32_t)acoef[i] == SENTINEL) { n_sent++; if (first_sent==0xFFFF) first_sent=i; }
    }
    uint32_t bad = (first_diff==0xFFFF) ? 0 : (uint32_t)acoef[first_diff];
    uint32_t ck  = fnv32(acoef, DN);

    uint8_t o[29];
    o[0]=0x5A; o[1]=0xA5; o[2]=0x3C; o[3]=0xC3;
    o[4]=ctr&0xFF;        o[5]=(ctr>>8)&0xFF;
    o[6]=n_diff&0xFF;     o[7]=(n_diff>>8)&0xFF;
    o[8]=first_diff&0xFF; o[9]=(first_diff>>8)&0xFF;
    o[10]=bad&0xFF; o[11]=(bad>>8)&0xFF; o[12]=(bad>>16)&0xFF; o[13]=(bad>>24)&0xFF;
    o[14]=n_sent&0xFF;    o[15]=(n_sent>>8)&0xFF;
    o[16]=first_sent&0xFF;o[17]=(first_sent>>8)&0xFF;
    o[18]=ck&0xFF; o[19]=(ck>>8)&0xFF; o[20]=(ck>>16)&0xFF; o[21]=(ck>>24)&0xFF;
    o[22]=cyc&0xFF; o[23]=(cyc>>8)&0xFF; o[24]=(cyc>>16)&0xFF; o[25]=(cyc>>24)&0xFF;
    o[26]=cpi; o[27]=lsu; o[28]=fold;
    simpleserial_put('r', 29, o);
    return 0x00;
}

int main(void){
    platform_init(); init_uart(); trigger_setup();
    make_buf();
    for (unsigned i=0;i<DN;i++) refc[i] = (int32_t)SENTINEL;
    rej_uniform(refc, DN, sbuf, BUFLEN);      /* clean reference, pre-glitch */
    DEMCR |= TRCENA;
    DWT_CTRL |= CYCCNTENA|CPIEVTENA|LSUEVTENA|FOLDEVTENA;
    simpleserial_init();
    simpleserial_addcmd('r', 0, do_sample);
    while(1) simpleserial_get();
}
