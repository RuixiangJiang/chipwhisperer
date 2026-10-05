/*
    simpleserial-round3dilithium2m4f.c  --  rev 3

    Fault-injection harness for Du et al., "Breaking the Shield" (ACISP 2025),
    Section 6.4, with DWT performance-counter capture for HPC detectability
    analysis.

    Target chain (pqm4 Dilithium2, Round 3):
        poly_uniform_gamma1
          -> stream256_squeezeblocks          <-- trigger + counters wrap this
               -> keccak_inc_squeeze
                    -> KeccakF1600_StatePermute
                    -> KeccakF1600_StateExtractBytes

    The fault under study is at ext_offset = 18155 + 23i: the load
    `ldr.w r5, [r0, r5, lsl #3]` at 0x80014fe returns 0 instead of the state
    lane. It is a DATA fault -- the instruction retires normally -- so the
    hypothesis under test is that no DWT counter distinguishes it from a
    clean run.

    COUNTER CAVEATS
      * CYCCNT is 32-bit. CPICNT, EXCCNT, SLEEPCNT, LSUCNT, FOLDCNT are all
        8-bit and wrap at 256. Over a ~106k-cycle window they wrap many
        times, so the values are (true count mod 256). Small deltas remain
        visible; absolute counts do not.
      * Interrupts are masked across the measured region so EXCCNT stays 0
        and UART activity cannot perturb the other counters.
      * The counters are zeroed immediately before trigger_high() and read
        immediately after trigger_low(), into statics, before any response
        formatting touches the stack.

    Commands (SimpleSerial V2.1)
      's'  set the CRHBYTES seed                  (CRHBYTES bytes in)
      'n'  set the 16-bit nonce, little endian    (2 bytes in)
      'g'  measured squeeze                       (160 bytes out:
                                                   24 B counters + 136 B data)
      'b'  fetch a later 136-byte window          (1 byte in)
      'd'  DWT capability report                  (8 bytes out)
      'i'  build info                             (8 bytes out)

    NOTE: 'k', 'p', 'v', 'w', 'y' are not usable as command letters on this
    SimpleSerial build. Known-good: i r m j s a d f t b g n.
*/

#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <string.h>

#include "params.h"
#include "symmetric.h"
#include "fips202.h"

/* ------------------------------------------------------------------ */
/* Cortex-M4 DWT, poked directly to avoid CMSIS header ambiguity.      */
/* ------------------------------------------------------------------ */
#define SCB_DEMCR    (*(volatile uint32_t *)0xE000EDFCu)
#define DWT_CTRL     (*(volatile uint32_t *)0xE0001000u)
#define DWT_CYCCNT   (*(volatile uint32_t *)0xE0001004u)
#define DWT_CPICNT   (*(volatile uint32_t *)0xE0001008u)
#define DWT_EXCCNT   (*(volatile uint32_t *)0xE000100Cu)
#define DWT_SLEEPCNT (*(volatile uint32_t *)0xE0001010u)
#define DWT_LSUCNT   (*(volatile uint32_t *)0xE0001014u)
#define DWT_FOLDCNT  (*(volatile uint32_t *)0xE0001018u)

#define DEMCR_TRCENA   (1u << 24)
#define DWT_CYCCNTENA  (1u << 0)
#define DWT_NOPRFCNT   (1u << 24)   /* 1 = profiling counters absent */
#define DWT_NOCYCCNT   (1u << 25)   /* 1 = cycle counter absent      */

#define DWT_CPIEVTENA   (1u << 17)
#define DWT_EXCEVTENA   (1u << 18)
#define DWT_SLEEPEVTENA (1u << 19)
#define DWT_LSUEVTENA   (1u << 20)
#define DWT_FOLDEVTENA  (1u << 21)

static void dwt_init(void)
{
    SCB_DEMCR |= DEMCR_TRCENA;
    __asm volatile ("dsb");
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CYCCNTENA | DWT_CPIEVTENA | DWT_EXCEVTENA
              | DWT_SLEEPEVTENA | DWT_LSUEVTENA | DWT_FOLDEVTENA;
}

static void dwt_zero(void)
{
    DWT_CYCCNT   = 0;
    DWT_CPICNT   = 0;
    DWT_EXCCNT   = 0;
    DWT_SLEEPCNT = 0;
    DWT_LSUCNT   = 0;
    DWT_FOLDCNT  = 0;
}

/* Captured out of the measured region into statics, so that response
   formatting cannot perturb what was measured. */
static volatile uint32_t ctr[6];

#define NBLOCKS_DEFAULT \
    ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)

#ifndef POLY_UNIFORM_GAMMA1_NBLOCKS
#define POLY_UNIFORM_GAMMA1_NBLOCKS NBLOCKS_DEFAULT
#endif

#define SQUEEZE_BYTES (POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES)
#define WINDOW        STREAM256_BLOCKBYTES      /* 136 */

static uint8_t seed[CRHBYTES];
static uint16_t nonce = 0;
static uint8_t sbuf[SQUEEZE_BYTES];

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ------------------------------------------------------------------ */
uint8_t set_seed(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l != CRHBYTES) return 0x11;
    memcpy(seed, in, CRHBYTES);
    return 0x00;
}

uint8_t set_nonce(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l != 2) return 0x11;
    nonce = (uint16_t)in[0] | ((uint16_t)in[1] << 8);
    return 0x00;
}

/* ------------------------------------------------------------------
   The measured operation.

   stream256_init stays outside the window: the paper places the trigger
   around stream256_squeezeblocks only, so ext_offset counts cycles from
   the start of the squeeze.

   The 0xA5 prefill distinguishes a skipped store (byte keeps 0xA5) from a
   zeroed load (byte becomes 0x00). Do not change it to zero.
   ------------------------------------------------------------------ */
uint8_t run_squeeze(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;

    stream256_state state;
    uint8_t out[24 + WINDOW];

    memset(sbuf, 0xA5, sizeof(sbuf));
    stream256_init(&state, seed, nonce);

    /* Mask interrupts so EXCCNT stays 0 and nothing else perturbs the
       counters mid-window. */
    __asm volatile ("cpsid i" ::: "memory");
    dwt_zero();
    __asm volatile ("dsb" ::: "memory");

    trigger_high();
    stream256_squeezeblocks(sbuf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
    trigger_low();

    __asm volatile ("dsb" ::: "memory");
    ctr[0] = DWT_CYCCNT;
    ctr[1] = DWT_CPICNT;
    ctr[2] = DWT_EXCCNT;
    ctr[3] = DWT_SLEEPCNT;
    ctr[4] = DWT_LSUCNT;
    ctr[5] = DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    for (int i = 0; i < 6; i++)
        put_u32(out + 4 * i, ctr[i]);
    memcpy(out + 24, sbuf, WINDOW);

    simpleserial_put('r', sizeof(out), out);
    return 0x00;
}

uint8_t get_block(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l != 1) return 0x11;
    uint8_t idx = in[0];
    if (idx >= POLY_UNIFORM_GAMMA1_NBLOCKS) return 0x12;
    simpleserial_put('r', WINDOW, sbuf + (uint32_t)idx * WINDOW);
    return 0x00;
}

/* DWT capability report: NOPRFCNT / NOCYCCNT are implementation-defined,
   so confirm the counters exist rather than assuming. */
uint8_t dwt_report(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[8];
    uint32_t ctrl = DWT_CTRL;
    put_u32(o + 0, ctrl);
    o[4] = (ctrl & DWT_NOPRFCNT) ? 0 : 1;   /* 1 = profiling counters present */
    o[5] = (ctrl & DWT_NOCYCCNT) ? 0 : 1;   /* 1 = cycle counter present      */
    o[6] = (SCB_DEMCR & DEMCR_TRCENA) ? 1 : 0;
    o[7] = 0x03;                            /* harness revision */
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t info(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[8];
    o[0] = (uint8_t)CRHBYTES;
    o[1] = (uint8_t)STREAM256_BLOCKBYTES;
    o[2] = (uint8_t)POLY_UNIFORM_GAMMA1_NBLOCKS;
    o[3] = (uint8_t)(POLYZ_PACKEDBYTES & 0xFF);
    o[4] = (uint8_t)((POLYZ_PACKEDBYTES >> 8) & 0xFF);
    o[5] = (uint8_t)(SQUEEZE_BYTES & 0xFF);
    o[6] = (uint8_t)((SQUEEZE_BYTES >> 8) & 0xFF);
    o[7] = 0x03;
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    dwt_init();

    for (unsigned i = 0; i < CRHBYTES; i++)
        seed[i] = (uint8_t)i;

    simpleserial_init();
    simpleserial_addcmd('s', CRHBYTES, set_seed);
    simpleserial_addcmd('n', 2, set_nonce);
    simpleserial_addcmd('g', 0, run_squeeze);
    simpleserial_addcmd('b', 1, get_block);
    simpleserial_addcmd('d', 0, dwt_report);
    simpleserial_addcmd('i', 0, info);

    while (1)
        simpleserial_get();
}
