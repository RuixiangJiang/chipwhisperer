/* Wang et al. 2025, "Secret in OnePiece: Single-Bit Fault Attack on Kyber"
 * (SAC 2025) -- the instruction-skip target only.
 *
 * Monitored region: BitSlice (Algorithm 2) of the bit-sliced message decoder
 * Compress_q(z,1).  It transposes 32 coefficients into bit-planes:
 *
 *     for i:  acc = 0
 *             for j in 0..31:
 *                 bit = (a[j] >> (i + 7)) & 1
 *                 acc |= bit << j             <== THE TARGET: the bitwise OR
 *             b[i] = acc
 *
 * The fault reproduced here is exactly that: the skip of the bitwise OR that
 * commits one coefficient bit into the accumulator.  5 planes x 32 lanes = 160
 * such commits, each a one-cycle register-register orr.
 *
 * SCOPE.  This entry reproduces the OR skip and nothing downstream of it.  The
 * paper's masked decoder, the ~50%% unmasked bit flip that masking turns the
 * skip into, the decapsulation success/failure oracle and the inequality
 * solver are all deliberately out of scope -- they govern how the attacker
 * exploits the skip, not whether the skip is visible to the counters.
 *
 * HOW THE SKIP IS RECOGNISED.  The planes are recomputed by the SAME function
 * after the glitch window closes, so the reference is bit-exact.  A skipped
 * orr can only ever CLEAR a bit that should be set, never set one: observed 0
 * where the reference has 1, at exactly one (plane, lane).  The opposite
 * direction, or more than one bit, is some other fault and is labelled as
 * such.  A skip whose bit was already 0 leaves the planes identical -- it is
 * unobservable in principle, not a measurement failure, so nset (how many
 * sliced bits are 1) is reported to put the hit rate on a correct base.
 *
 * Trip counts are read through volatiles so gcc cannot unroll the transpose
 * and fold the 160 commits into constants.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>

#define NC      32                  /* coefficients (lanes) per transpose */
#define NP       5                  /* planes: z bits 7..11               */
#define BIT0     7
#define NPAD     2                  /* landing pad after the planes       */
#define NPS     (NP + NPAD)
#define KQ    3329
#define SENT  0xA5A5A5A5u
#define FRAMELEN 32
#define MAGIC 0x474E4157u           /* "WANG" little-endian */

#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

static uint16_t a[NC];                   /* coefficients, each in [0, q)   */
static uint32_t bobs[NPS];               /* planes written in the window   */
static uint32_t bref[NPS];               /* planes recomputed after it     */

static volatile unsigned int g_np = NP;  /* opaque trip counts: keep the   */
static volatile unsigned int g_nc = NC;  /* 160 orr commits in the binary  */

/* ---- the monitored region: BitSlice, Algorithm 2 ----------------------- */
__attribute__((noinline, noclone))
static void bitslice(uint32_t *out)
{
    unsigned int i, j;
    unsigned int np = g_np, nc = g_nc;
    for (i = 0; i < np; i++) {
        uint32_t acc = 0;
        for (j = 0; j < nc; j++) {
            uint32_t bit = ((uint32_t)a[j] >> (i + BIT0)) & 1u;
            acc |= bit << j;                  /* <<== Wang target: the OR */
        }
        out[i] = acc;
    }
}

/* --------------------------------------------------------------- plumbing */
static void dwt_init(void) { DEMCR |= (1u << 24); DWT_CTRL = 0; }
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static uint32_t fnv8(const uint8_t *p, unsigned int n)
{
    uint32_t h = 0x811C9DC5u; unsigned int i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static uint32_t lcg_s;
static uint16_t lcg16(void)
{ lcg_s = 1103515245u * lcg_s + 12345u; return (uint16_t)(lcg_s >> 16); }

static void make_input(uint32_t sel)
{
    unsigned int j;
    lcg_s = 0x5A5A0000u ^ sel;
    for (j = 0; j < NC; j++) a[j] = (uint16_t)(lcg16() % KQ);
}

static void put16(uint8_t *f, unsigned int o, uint16_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *f, unsigned int o, uint32_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8);
  f[o+2] = (uint8_t)(v >> 16); f[o+3] = (uint8_t)(v >> 24); }

static uint8_t do_slice(uint8_t cc, uint8_t sc, uint8_t l, uint8_t *d)
{
    uint32_t sel, cyc, ck0, ck1, bck = 0;
    uint8_t  cpi, lsu, fold, frame[FRAMELEN], dirty = 0;
    unsigned int i, j, ndiff = 0, nplane0 = 0, nset = 0;
    uint8_t  fplane = 0xFF, flane = 0xFF, fdir = 0xFF;
    (void)cc; (void)sc; (void)l;

    sel = (uint32_t)d[0] | ((uint32_t)d[1] << 8)
        | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    make_input(sel);
    ck0 = fnv8((const uint8_t *)a, sizeof a);

    for (i = 0; i < NPS; i++) { bobs[i] = SENT; bref[i] = SENT; }

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    bitslice(bobs);
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    ck1 = fnv8((const uint8_t *)a, sizeof a);
    if (ck1 != ck0) dirty |= 1u;                      /* input was moved */
    for (i = NP; i < NPS; i++)
        if (bobs[i] != SENT) dirty |= 2u;             /* wrote past b[]  */

    bitslice(bref);                                   /* same code, after */

    for (i = 0; i < NP; i++) {
        uint32_t o = bobs[i], r = bref[i];
        bck ^= o;
        for (j = 0; j < NC; j++) if ((r >> j) & 1u) nset++;
        if (o == 0 && r != 0) nplane0++;
        if (o != r)
            for (j = 0; j < NC; j++)
                if (((o >> j) & 1u) != ((r >> j) & 1u)) {
                    if (fplane == 0xFF) {
                        fplane = (uint8_t)i;
                        flane  = (uint8_t)j;
                        /* 0 = bit failed to be set, the only thing a skipped
                         *     orr can produce
                         * 1 = bit set that should be clear, i.e. NOT a skip */
                        fdir   = (uint8_t)((o >> j) & 1u);
                    }
                    ndiff++;
                }
    }

    put32(frame,  0, MAGIC);
    put32(frame,  4, sel);
    put32(frame,  8, cyc);
    frame[12] = cpi; frame[13] = lsu; frame[14] = fold; frame[15] = dirty;
    put16(frame, 16, (uint16_t)ndiff);
    frame[18] = fplane; frame[19] = flane; frame[20] = fdir;
    frame[21] = (uint8_t)nplane0;
    put16(frame, 22, (uint16_t)nset);
    put32(frame, 24, bck);
    put32(frame, 28, ck1);
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
    /* 'k' is reserved by the SS v2 framework -- it answers SS_ERR_CMD. */
    simpleserial_addcmd('s', 4, do_slice);
    simpleserial_addcmd('g', 4, do_slice);
    while (1) simpleserial_get();
}
