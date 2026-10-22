/* Delvaux 2022 "Roulette" add-skip -- FLAG-based detector variant.
 *
 * Monitored region: one flag-setting `adds` with known operands, NZCV captured
 * immediately after.  The detector under test reads NZCV after the add and
 * compares it to the NZCV the correct sum must set -- a data-dependent check,
 * unlike a cycle count, so it can in principle see a corruption HPC is blind
 * to.  DWT counters are captured on the same runs for a side-by-side with the
 * earlier (HPC) Delvaux result.
 *
 * MODELLING NOTE.  NZCV is only readable for an ISOLATED adds; a loop's branch
 * overwrites the flags.  So this is one add, not the add inside the invntt
 * butterfly loop.
 *
 * GLITCH-PROOF ORACLE (this version).  The correct result and correct NZCV are
 * a pure function of (a,b), which the HOST knows from the operand table -- so
 * there is NO on-device reference to corrupt.  The device echoes a,b for a
 * frame-integrity check, and stores the observed result and flags TWICE: a
 * single-cycle glitch on one store leaves the other intact, the host sees the
 * mismatch and excludes the run, so a store corruption can never masquerade as
 * an add fault.  The sentinel (an impossible N=Z=1 NZCV) is loaded before the
 * add, so a clean skip leaves NZCV at the sentinel and is caught by
 * construction; the only evasion is a result corruption that leaves all four
 * flags unchanged.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>

#define FRAMELEN 40
#define MAGIC    0x47414C46u          /* "FLAG" little-endian */
#define SENTINEL 0xF0000000u          /* APSR write: N=Z=C=V=1 (impossible sum) */

#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

static const uint32_t OPS[][2] = {
    {0x00000001u, 0x00000001u},   /* 2            N0 Z0 C0 V0 = 0x0 */
    {0xFFFFFFFFu, 0x00000001u},   /* 0, carry     N0 Z1 C1 V0 = 0x6 */
    {0x7FFFFFFFu, 0x00000001u},   /* INT_MAX+1    N1 Z0 C0 V1 = 0x9 */
    {0x80000000u, 0x80000000u},   /* 0, ovf+carry N0 Z1 C1 V1 = 0x7 */
    {0xFFFFFFFFu, 0xFFFFFFFFu},   /* -2           N1 Z0 C1 V0 = 0xA */
    {0x12345678u, 0x11111111u},   /* 0x23456789   N0 Z0 C0 V0 = 0x0 */
};
#define NOPS 6

static volatile uint32_t canary = 0xC0DEu;

/* The monitored region.  Captures result and flags into registers, then stores
 * each TWICE so a single-cycle store glitch is detectable as a mismatch. */
__attribute__((noinline, noclone))
static void target_add(uint32_t a, uint32_t b,
                       uint32_t *res1, uint32_t *res2,
                       uint32_t *nz1,  uint32_t *nz2)
{
    uint32_t r, n, sent = SENTINEL;
    __asm volatile (
        "msr  apsr_nzcvq, %[s]  \n\t"
        "adds %[r], %[x], %[y]  \n\t"   /* <<== Delvaux target: the add */
        "mrs  %[n], apsr        \n\t"
        : [r]"=&r"(r), [n]"=&r"(n)
        : [x]"r"(a), [y]"r"(b), [s]"r"(sent)
        : "cc"
    );
    n = (n >> 28) & 0xFu;
    *res1 = r; *res2 = r;
    *nz1  = n; *nz2  = n;
}

static void dwt_init(void) { DEMCR |= (1u << 24); DWT_CTRL = 0; }
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static void put32(uint8_t *f, unsigned o, uint32_t v)
{ f[o]=(uint8_t)v; f[o+1]=(uint8_t)(v>>8); f[o+2]=(uint8_t)(v>>16); f[o+3]=(uint8_t)(v>>24); }

static uint8_t do_add(uint8_t cc, uint8_t sc, uint8_t l, uint8_t *d)
{
    uint32_t sel, a, b, cyc;
    uint32_t res1 = 0, res2 = 0, nz1 = 0, nz2 = 0;
    uint8_t  cpi, lsu, fold, frame[FRAMELEN], dirty = 0;
    (void)cc; (void)sc; (void)l;

    sel = (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
    a = OPS[sel % NOPS][0];
    b = OPS[sel % NOPS][1];
    canary = 0xC0DEu;

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    target_add(a, b, &res1, &res2, &nz1, &nz2);
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    if (canary != 0xC0DEu) dirty |= 1u;

    put32(frame,  0, MAGIC);
    put32(frame,  4, sel);
    put32(frame,  8, a);
    put32(frame, 12, b);
    put32(frame, 16, res1);
    put32(frame, 20, res2);
    put32(frame, 24, cyc);
    frame[28] = (uint8_t)nz1;
    frame[29] = (uint8_t)nz2;
    frame[30] = (uint8_t)((SENTINEL >> 28) & 0xFu);
    frame[31] = dirty;
    frame[32] = cpi;
    frame[33] = lsu;
    frame[34] = fold;
    frame[35] = 0; frame[36] = 0; frame[37] = 0; frame[38] = 0; frame[39] = 0;
    simpleserial_put('r', FRAMELEN, frame);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    dwt_init();
    simpleserial_init();
    simpleserial_addcmd('s', 4, do_add);
    simpleserial_addcmd('g', 4, do_add);
    while (1) simpleserial_get();
}
