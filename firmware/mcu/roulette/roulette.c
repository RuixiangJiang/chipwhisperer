/* Delvaux 2022, "Roulette", instruction-skip variant.
 *
 * Target: Algorithm 8 DoubleGSButterfly line 2,
 *   uadd16 \a0, \a0, \tmp2      -- fastinvntt.S:34, macro `doublebutterfly`
 * as expanded inside pqm4's Kyber inverse NTT, invntt_fast().
 *
 * Skipping it leaves a0 holding its pre-add value, i.e. a' = a instead of
 * a + b*tau, injecting an error of -(b*tau mod q) at that butterfly's 'a'
 * output.  The remaining layers are linear, so the error spreads to a support
 * whose size is a power of two naming the layer.
 *
 * The clean reference is computed on-device at startup, so no host-side model
 * of pqm4's Montgomery/Barrett conventions is needed.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>

#define N      256
#define Q      3329
#define MAGIC  0x12201E77u

#define CPACR       (*(volatile uint32_t *)0xE000ED88)
#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

extern void invntt(int16_t *poly);        /* pqm4 ntt.c -> invntt_fast */

static int16_t seedp[N], work[N], ref[N];

static uint32_t lcg_s;
static uint16_t lcg16(void)
{
    lcg_s = 1103515245u * lcg_s + 12345u;
    return (uint16_t)(lcg_s >> 16);
}

static void make_input(void)
{
    unsigned i;
    lcg_s = 0x5EED0000u;
    for (i = 0; i < N; i++)
        seedp[i] = (int16_t)(((uint32_t)lcg16() << 1 | (lcg16() & 1u)) % Q);
}

/* pqm4's m4fspeed NTT parks twiddles in s0-s15, so the FPU must be on.  CW
 * builds soft-float, so CMSIS SystemInit leaves CP10/CP11 disabled and the
 * first vldm would HardFault. */
static void fpu_enable(void)
{
    CPACR |= (0xFu << 20);
    __asm volatile ("dsb" ::: "memory");
    __asm volatile ("isb" ::: "memory");
}

static void dwt_init(void) { DEMCR |= (1u << 24); DWT_CTRL = 0; }
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static uint32_t fnv16(const int16_t *p, unsigned n)
{
    uint32_t h = 0x811C9DC5u;
    unsigned i;
    for (i = 0; i < n; i++) {
        h ^= (uint32_t)(uint16_t)p[i] & 0xFFu;        h *= 16777619u;
        h ^= ((uint32_t)(uint16_t)p[i] >> 8) & 0xFFu; h *= 16777619u;
    }
    return h;
}

static void put16(uint8_t *f, unsigned o, uint16_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *f, unsigned o, uint32_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8);
  f[o+2] = (uint8_t)(v >> 16); f[o+3] = (uint8_t)(v >> 24); }

static uint8_t do_intt(uint8_t c, uint8_t sc, uint8_t l, uint8_t *d)
{
    uint32_t cyc, dck = 0x811C9DC5u;
    uint8_t  cpi, lsu, fold, frame[32];
    unsigned i, ndiff = 0;
    uint16_t first = 0xFFFF, second = 0xFFFF, last = 0xFFFF;
    int16_t  firstdelta = 0;
    (void)c; (void)sc; (void)l; (void)d;

    for (i = 0; i < N; i++) work[i] = seedp[i];

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    invntt(work);
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    for (i = 0; i < N; i++) {
        int16_t dv = (int16_t)(work[i] - ref[i]);
        if (dv) {
            if (ndiff == 0)      { first = (uint16_t)i; firstdelta = dv; }
            else if (ndiff == 1) { second = (uint16_t)i; }
            last = (uint16_t)i;
            ndiff++;
        }
        dck ^= (uint32_t)(uint16_t)dv & 0xFFu;        dck *= 16777619u;
        dck ^= ((uint32_t)(uint16_t)dv >> 8) & 0xFFu; dck *= 16777619u;
    }

    put32(frame,  0, MAGIC);
    put16(frame,  4, (uint16_t)ndiff);
    put16(frame,  6, first);
    put16(frame,  8, second);
    put16(frame, 10, last);
    put32(frame, 12, dck);
    put32(frame, 16, fnv16(work, N));
    put32(frame, 20, cyc);
    frame[24] = cpi; frame[25] = lsu; frame[26] = fold; frame[27] = 0;
    put16(frame, 28, (uint16_t)firstdelta);
    put16(frame, 30, 0);
    simpleserial_put('r', 32, frame);
    return 0;
}

int main(void)
{
    unsigned i;
    platform_init();
    init_uart();
    trigger_setup();
    fpu_enable();
    dwt_init();
    make_input();
    for (i = 0; i < N; i++) ref[i] = seedp[i];
    invntt(ref);                      /* clean reference, computed pre-glitch */
    simpleserial_init();
    simpleserial_addcmd('d', 1, do_intt);
    while (1) simpleserial_get();
}
