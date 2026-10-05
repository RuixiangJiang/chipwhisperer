/* Entry 3 - Wang et al. (2025): skip the round-counter initialisation in
 * KeccakF1600_StatePermute.  `for (round = 0; round < 24; round += 2)` left
 * uninitialised starts from garbage, so the permutation runs 24-k rounds
 * using RC[k..23].  Every outcome is enumerable host-side, so the output
 * prefix recovers the exact number of rounds executed.
 * 0 rounds = identity permutation = the absorbed message leaks verbatim. */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stddef.h>
#include "fips202.h"

#define SHA3_CTX      shake256incctx
#define SHA3_INIT     shake256_inc_init
#define SHA3_ABSORB   shake256_inc_absorb
#define SHA3_FINAL    shake256_inc_finalize
#define SHA3_SQUEEZE  shake256_inc_squeeze
#define SHA3_RELEASE  shake256_inc_ctx_release

#define MSGBYTES 32
#define OUTBYTES 64

#define DEMCR       (*(volatile uint32_t*)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t*)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t*)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t*)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t*)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t*)0xE0001018)
#define TRCENA     (1u<<24)
#define CYCCNTENA  (1u<<0)
#define CPIEVTENA  (1u<<17)
#define LSUEVTENA  (1u<<20)
#define FOLDEVTENA (1u<<21)

static uint8_t msg[MSGBYTES];

static void dwt_reset(void){
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
}

static uint8_t do_squeeze(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf){
    (void)cmd;(void)scmd;(void)len;(void)buf;
    SHA3_CTX st;
    uint8_t out64[OUTBYTES];
    uint32_t cyc,cpi,lsu,fold;

    SHA3_INIT(&st);
    SHA3_ABSORB(&st, msg, MSGBYTES);    /* 32 < 136 rate: no permutation yet */
    SHA3_FINAL(&st);                    /* pads only */

    dwt_reset();
    __asm volatile("cpsid i" ::: "memory");
    trigger_high();
    SHA3_SQUEEZE(out64, OUTBYTES, &st); /* <-- the single permutation */
    trigger_low();
    cyc = DWT_CYCCNT; cpi = DWT_CPICNT & 0xFF;
    lsu = DWT_LSUCNT & 0xFF; fold = DWT_FOLDCNT & 0xFF;
    __asm volatile("cpsie i" ::: "memory");

    SHA3_RELEASE(&st);                  /* PQClean ctx is heap-allocated */

    uint8_t out[19];
    out[0]=0x5A; out[1]=0xA5; out[2]=0x3C; out[3]=0xC3;
    for (int i=0;i<8;i++) out[4+i]=out64[i];
    out[12]=cyc&0xFF; out[13]=(cyc>>8)&0xFF;
    out[14]=(cyc>>16)&0xFF; out[15]=(cyc>>24)&0xFF;
    out[16]=cpi; out[17]=lsu; out[18]=fold;
    simpleserial_put('r', 19, out);
    return 0x00;
}

int main(void){
    platform_init();
    init_uart();
    trigger_setup();
    for (int i=0;i<MSGBYTES;i++) msg[i] = (uint8_t)i;   /* 00..1F */
    DEMCR |= TRCENA;
    DWT_CTRL |= CYCCNTENA | CPIEVTENA | LSUEVTENA | FOLDEVTENA;
    simpleserial_init();
    simpleserial_addcmd('r', 0, do_squeeze);
    while(1) simpleserial_get();
}
