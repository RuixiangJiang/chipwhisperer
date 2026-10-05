/* Entry 2 - Jendral (2024): skip shake256_absorb(rnd) in the hedged ML-DSA
 * rho'' derivation.  rho'' = SHAKE256(key || rnd || mu); skipping the rnd
 * absorb yields SHAKE256(key || mu) -> hedged signing collapses to
 * deterministic.  128 bytes absorbed < 136-byte rate, so no Keccak
 * permutation runs inside the measured window. */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stddef.h>
#include "fips202.h"

/* --- pqm4 fips202 incremental API: adjust these 5 lines if your header differs --- */
#define SHA3_CTX      shake256incctx
#define SHA3_INIT     shake256_inc_init
#define SHA3_ABSORB   shake256_inc_absorb
#define SHA3_FINAL    shake256_inc_finalize
#define SHA3_SQUEEZE  shake256_inc_squeeze

#define SEEDBYTES 32
#define RNDBYTES  32
#define MUBYTES   64
#define RHOPBYTES 64

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

/* fixed test vectors - baseline must be bit-reproducible */
static uint8_t key[SEEDBYTES];
static uint8_t rnd[RNDBYTES];
static uint8_t mu [MUBYTES];

static void dwt_reset(void){
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
}

static uint8_t do_rhoprime(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf){
    (void)cmd;(void)scmd;(void)len;(void)buf;
    SHA3_CTX st;
    uint8_t rhop[RHOPBYTES];
    uint32_t cyc,cpi,lsu,fold;

    SHA3_INIT(&st);
    SHA3_ABSORB(&st, key, SEEDBYTES);        /* outside the window */

    dwt_reset();
    __asm volatile("cpsid i" ::: "memory");
    trigger_high();
    SHA3_ABSORB(&st, rnd, RNDBYTES);         /* <-- Jendral target: bl absorb */
    trigger_low();
    cyc = DWT_CYCCNT; cpi = DWT_CPICNT & 0xFF;
    lsu = DWT_LSUCNT & 0xFF; fold = DWT_FOLDCNT & 0xFF;
    __asm volatile("cpsie i" ::: "memory");

    SHA3_ABSORB(&st, mu, MUBYTES);
    SHA3_FINAL(&st);
    SHA3_SQUEEZE(rhop, RHOPBYTES, &st);
    shake256_inc_ctx_release(&st);
    shake256_inc_ctx_release(&st);

    /* 19-byte frame: magic | rho''[0:8] | cyc | cpi | lsu | fold
     * magic is written outside the glitch window, so a corrupted or
     * misaligned frame is detectable instead of silently plausible. */
    uint8_t out[19];
    out[0]=0x5A; out[1]=0xA5; out[2]=0x3C; out[3]=0xC3;
    for (int i=0;i<8;i++) out[4+i]=rhop[i];
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

    for (int i=0;i<SEEDBYTES;i++) key[i] = (uint8_t)(0x00+i);  /* 00..1F */
    for (int i=0;i<RNDBYTES;i++)  rnd[i] = (uint8_t)(0x80+i);  /* 80..9F */
    for (int i=0;i<MUBYTES;i++)   mu [i] = (uint8_t)(0x40+i);  /* 40..7F */

    DEMCR |= TRCENA;
    DWT_CTRL |= CYCCNTENA | CPIEVTENA | LSUEVTENA | FOLDEVTENA;
    simpleserial_init();
    simpleserial_addcmd('r', 0, do_rhoprime);
    while(1) simpleserial_get();
}
