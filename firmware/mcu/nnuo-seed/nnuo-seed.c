/* Ravi et al. 2020, "Number 'Not Used' Once" (NNUO)
 * Target: the store inside the key-generation seed/nonce sampling loop.
 * The buffer is pre-filled with 0xA5 rather than 0x00 so that "never written"
 * is distinguishable from "written as zero"; in the real attack this memory
 * holds zeros or stale data, which is what makes the seed predictable.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>

#define SEEDLEN 32                 /* KYBER_SYMBYTES */
#define SENT    0xA5
#define MAGIC   0x5A33C0DEu
#define SEED0   0x10000001u

#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

static uint8_t sbuf[SEEDLEN];
static uint8_t sref[SEEDLEN + 1];  /* +1: the shift test needs ref[32] */

/* ---------------- the target: keep it a real, separate symbol ------------- */
void sample_seed(uint8_t *out, unsigned int n, uint32_t s);
__attribute__((noinline, noclone))
void sample_seed(uint8_t *out, unsigned int n, uint32_t s)
{
    unsigned int i;
    for (i = 0; i < n; i++) {
        s = 1103515245u * s + 12345u;
        out[i] = (uint8_t)(s >> 16);      /* <<== Ravi 2020 target store */
    }
}

static void dwt_init(void)
{
    DEMCR |= (1u << 24);                  /* TRCENA */
    DWT_CTRL = 0;
}
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static uint32_t fnv32(const uint8_t *p, unsigned int n)
{
    uint32_t h = 0x811C9DC5u;
    unsigned int i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static void put16(uint8_t *f, unsigned int o, uint16_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *f, unsigned int o, uint32_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8);
  f[o+2] = (uint8_t)(v >> 16); f[o+3] = (uint8_t)(v >> 24); }

static uint8_t do_sample(uint8_t c, uint8_t sc, uint8_t l, uint8_t *dp)
{
    uint32_t cyc;
    uint8_t  cpi, lsu, fold;
    uint16_t n_diff = 0, first_diff = 0xFFFF;
    uint16_t n_sent = 0, first_sent = 0xFFFF, last_sent = 0xFFFF;
    uint8_t  got = 0, exp = 0, shiftn = 0, frame[29];
    unsigned int i;
    (void)c; (void)sc; (void)l; (void)dp;

    for (i = 0; i < SEEDLEN; i++) sbuf[i] = SENT;

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    sample_seed(sbuf, SEEDLEN, SEED0);
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    for (i = 0; i < SEEDLEN; i++) {
        if (sbuf[i] != sref[i]) {
            if (n_diff == 0) { first_diff = (uint16_t)i; got = sbuf[i]; exp = sref[i]; }
            n_diff++;
        }
        if (sbuf[i] == SENT) {
            if (n_sent == 0) first_sent = (uint16_t)i;
            last_sent = (uint16_t)i;
            n_sent++;
        }
    }
    /* how far the tail is shifted by one position, counted from first_diff */
    if (n_diff && first_diff < SEEDLEN) {
        for (i = first_diff; i < SEEDLEN; i++) {
            if (sbuf[i] != sref[i + 1]) break;
            shiftn++;
        }
    }

    put32(frame,  0, MAGIC);
    put16(frame,  4, n_diff);
    put16(frame,  6, first_diff);
    put16(frame,  8, n_sent);
    put16(frame, 10, first_sent);
    put16(frame, 12, last_sent);
    frame[14] = got; frame[15] = exp; frame[16] = shiftn; frame[17] = 0;
    put32(frame, 18, fnv32(sbuf, SEEDLEN));
    put32(frame, 22, cyc);
    frame[26] = cpi; frame[27] = lsu; frame[28] = fold;
    simpleserial_put('r', 29, frame);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    dwt_init();
    sample_seed(sref, SEEDLEN + 1, SEED0);   /* reference, computed pre-glitch */
    simpleserial_init();
    simpleserial_addcmd('s', 1, do_sample);
    while (1) simpleserial_get();
}
