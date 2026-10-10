/* Valsaraj, Ravi, Bhasin, Wu 2025, "When Randomness Isn't Random: Practical
 * Fault Attack on Post-Quantum Lattice Standards" (ePrint 2025/2009)
 * -- add-skip variant, ML-KEM-512 noise sampling.
 *
 * The paper's single point of failure: in pqm4 / PQClean / libOQS / WolfSSL
 * every noise polynomial of an ML-KEM key is expanded from ONE shared seed
 * pointer, and the only thing separating the polynomials is a one-byte
 * domain-separation nonce that the CALLER increments between calls:
 *
 *     uint8_t nonce = 0;
 *     for (i = 0; i < KYBER_K; i++)
 *         poly_getnoise_eta1(&skpv->vec[i], noiseseed, nonce++);   <== the add
 *     for (i = 0; i < KYBER_K; i++)
 *         poly_getnoise_eta1(&e->vec[i],    noiseseed, nonce++);   <== the add
 *
 * Skip one of those increments and the next call runs on an (seed, nonce) pair
 * that has already been used, so the polynomial it produces is a BIT-EXACT
 * copy of the previous one and every later polynomial is shifted down by one
 * nonce.  For ML-KEM-512 that collapses s = (s0,s1) to (s0,s0): the lattice
 * problem loses a dimension and the key falls out.  No reference key is needed
 * to see it -- the duplicate is visible in the output itself.
 *
 * DEVIATION FROM A STOCK pqm4 BUILD, stated up front: with KYBER_K a literal
 * 2, gcc -O3 fully unrolls both loops and constant-folds the nonce to the
 * literals 0,1,2,3, so a stock build has no nonce add to skip at all.  The
 * trip count here is read through a volatile (g_k) so the loop -- and
 * therefore the paper's target instruction -- survives.  That the fault model
 * only exists when the loop survives is itself a result.
 *
 * cbd3() is verbatim PQClean/pqm4 cbd.c.  xof() is a fixed-cost stand-in for
 * SHAKE-256 (see the comment on it); the faulted instruction is in the caller,
 * so the PRF only has to be deterministic and data-independent in cost.
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <string.h>

#define KN        256                /* KYBER_N        */
#define KK        2                  /* KYBER_K, ML-KEM-512 */
#define NPOLY     (2 * KK)           /* s0,s1,e0,e1    */
#define ETA1      3                  /* KYBER_ETA1     */
#define PRFBYTES  (ETA1 * KN / 4)    /* 192            */
#define SYMBYTES  32                 /* KYBER_SYMBYTES */
#define SENT      0x5A5A             /* out-of-range sentinel prefill */
#define FRAMELEN  32
#define MAGIC     0x534C4156u        /* "VALS" little-endian */

#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

static uint8_t  seed[SYMBYTES];          /* the shared seed -- one pointer */
/* +2 landing-pad slots: if the glitch skips the loop-index add or its compare,
 * the loop can run past NPOLY and write beyond pm.  The pad absorbs that
 * instead of letting it land on the oracle state, and a touched pad is
 * reported so the run is excluded rather than silently misscored. */
#define NPAD      2
static int16_t  pm[NPOLY + NPAD][KN];    /* monitored output + pad */
static int16_t  pv[KN];                  /* post-glitch verify scratch */
static uint32_t mh[NPOLY], rh[NPOLY];
static uint8_t  g_nonce_end;             /* nonce value when the loops exit */
static volatile unsigned int g_k = KK;   /* opaque trip count, see header */

/* ---------------------------------------------------------------- PRF ----- */
/* Fixed-cost, branch-free XOF stand-in for SHAKE-256.  To run the campaign
 * against the real primitive, replace the body with
 *     shake256(out, outlen, in, inlen);
 * and link pqm4 fips202.c + its KeccakF1600 assembly.  The monitored region
 * grows by ~25k cycles per polynomial; nothing in the oracle changes. */
static void xof(uint8_t *out, unsigned int outlen, const uint8_t *in, unsigned int inlen)
{
    uint32_t h0 = 0x6A09E667u, h1 = 0xBB67AE85u, h2 = 0x3C6EF372u, h3 = 0xA54FF53Au;
    unsigned int i;
    for (i = 0; i < inlen; i++) {                       /* absorb */
        h0 ^= in[i];
        h0 += h1; h1 = (h1 << 7)  | (h1 >> 25); h1 ^= h0;
        h2 += h3; h3 = (h3 << 11) | (h3 >> 21); h3 ^= h2;
        h0  = (h0 << 16) | (h0 >> 16);
    }
    for (i = 0; i < outlen; i += 4) {                   /* squeeze */
        uint32_t t;
        h0 += h2; h2 = (h2 << 13) | (h2 >> 19); h2 ^= h0;
        h1 += h3; h3 = (h3 << 17) | (h3 >> 15); h3 ^= h1;
        t = h0 ^ h3;
        out[i]     = (uint8_t)t;
        out[i + 1] = (uint8_t)(t >> 8);
        out[i + 2] = (uint8_t)(t >> 16);
        out[i + 3] = (uint8_t)(t >> 24);
    }
}

/* ------------------------------------------------- PQClean cbd.c, eta=3 --- */
static uint32_t load24_littleendian(const uint8_t x[3])
{
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16);
}

static void cbd3(int16_t *r, const uint8_t *buf)
{
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;
    for (i = 0; i < KN / 4; i++) {
        t  = load24_littleendian(buf + 3 * i);
        d  = t & 0x00249249u;
        d += (t >> 1) & 0x00249249u;
        d += (t >> 2) & 0x00249249u;
        for (j = 0; j < 4; j++) {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            r[4 * i + j] = a - b;
        }
    }
}

/* pqm4 poly_getnoise_eta1(): seed || nonce -> PRF -> CBD */
__attribute__((noinline, noclone))
static void poly_getnoise_eta1(int16_t *r, const uint8_t *s, uint8_t nonce)
{
    uint8_t extseed[SYMBYTES + 1];
    uint8_t buf[PRFBYTES];
    memcpy(extseed, s, SYMBYTES);          /* the shared seed pointer */
    extseed[SYMBYTES] = nonce;             /* the ONLY distinguisher  */
    xof(buf, PRFBYTES, extseed, SYMBYTES + 1);
    cbd3(r, buf);
}

/* ---- the monitored region: indcpa_keypair()'s noise-sampling loops ------- */
__attribute__((noinline, noclone))
static void sample_noise(void)
{
    unsigned int i, k = g_k;
    uint8_t nonce = 0;
    for (i = 0; i < k; i++)
        poly_getnoise_eta1(pm[i],     seed, nonce++);   /* <== Valsaraj target */
    for (i = 0; i < k; i++)
        poly_getnoise_eta1(pm[k + i], seed, nonce++);   /* <== Valsaraj target */
    g_nonce_end = nonce;
}

/* --------------------------------------------------------------- plumbing - */
static void dwt_init(void) { DEMCR |= (1u << 24); DWT_CTRL = 0; }
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static uint32_t fnv8(const uint8_t *p, unsigned int n)
{
    uint32_t h = 0x811C9DC5u;
    unsigned int i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static uint32_t fnv16(const int16_t *p, unsigned int n)
{
    uint32_t h = 0x811C9DC5u;
    unsigned int i;
    for (i = 0; i < n; i++) {
        uint16_t v = (uint16_t)p[i];
        h ^= (uint32_t)(v & 0xFFu);        h *= 16777619u;
        h ^= (uint32_t)((v >> 8) & 0xFFu); h *= 16777619u;
    }
    return h;
}

static void put16(uint8_t *f, unsigned int o, uint16_t v)
{ f[o] = (uint8_t)v; f[o + 1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *f, unsigned int o, uint32_t v)
{ f[o] = (uint8_t)v; f[o + 1] = (uint8_t)(v >> 8);
  f[o + 2] = (uint8_t)(v >> 16); f[o + 3] = (uint8_t)(v >> 24); }

static uint8_t do_keygen(uint8_t cc, uint8_t sc, uint8_t l, uint8_t *d)
{
    uint32_t sel, cyc, ck0, ck1, mck = 0;
    uint8_t  cpi, lsu, fold, frame[FRAMELEN], nonce_end, dirty = 0;
    unsigned int i, j, m, nok = 0, ndup = 0, nsent = 0;
    uint8_t  fdup = 0xFF;
    uint16_t shift = 0;
    (void)cc; (void)sc; (void)l;

    sel = (uint32_t)d[0] | ((uint32_t)d[1] << 8)
        | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);

    for (i = 0; i < SYMBYTES; i++) seed[i] = (uint8_t)(0xA5u ^ (i * 31u));
    seed[0] ^= (uint8_t)sel;         seed[1] ^= (uint8_t)(sel >> 8);
    seed[2] ^= (uint8_t)(sel >> 16); seed[3] ^= (uint8_t)(sel >> 24);
    ck0 = fnv8(seed, SYMBYTES);

    for (j = 0; j < NPOLY + NPAD; j++)
        for (m = 0; m < KN; m++) pm[j][m] = (int16_t)SENT;
    g_nonce_end = 0xFF;

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    sample_noise();
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    nonce_end = g_nonce_end;
    ck1 = fnv8(seed, SYMBYTES);
    if (ck1 != ck0) dirty |= 1u;           /* the glitch moved the seed itself */
    for (j = NPOLY; j < NPOLY + NPAD; j++)
        for (m = 0; m < KN; m++)
            if (pm[j][m] != (int16_t)SENT) { dirty |= 2u; break; }

    /* Reference, recomputed AFTER the window closes: the NPOLY polynomials a
     * correct run must emit, in nonce order 0..NPOLY-1.  Nothing the glitch
     * can touch is live here, and the seed is checksum-guarded above. */
    for (j = 0; j < NPOLY; j++) {
        poly_getnoise_eta1(pv, seed, (uint8_t)j);
        rh[j] = fnv16(pv, KN);
    }
    for (j = 0; j < NPOLY; j++) {
        mh[j] = fnv16(pm[j], KN);
        mck  ^= mh[j];
        if (pm[j][0] == (int16_t)SENT && pm[j][KN - 1] == (int16_t)SENT) nsent++;
    }

    /* shift[j] = which reference nonce poly j actually came from, 0xF = none.
     * correct run      -> 0,1,2,3
     * nonce add skipped at step 1 -> 0,0,1,2   (duplicate, tail shifted down) */
    for (j = 0; j < NPOLY; j++) {
        uint8_t mt = 0xF;
        for (m = 0; m < NPOLY; m++) if (mh[j] == rh[m]) { mt = (uint8_t)m; break; }
        shift |= (uint16_t)(mt & 0xF) << (4 * j);
        if (mt == (uint8_t)j) nok++;
        if (j && mh[j] == mh[j - 1]) { if (fdup == 0xFF) fdup = (uint8_t)j; ndup++; }
    }

    put32(frame,  0, MAGIC);
    put32(frame,  4, sel);
    put32(frame,  8, cyc);
    frame[12] = cpi; frame[13] = lsu; frame[14] = fold; frame[15] = nonce_end;
    put16(frame, 16, shift);
    frame[18] = (uint8_t)nok;
    frame[19] = (uint8_t)ndup;
    frame[20] = fdup;
    frame[21] = dirty;
    frame[22] = (uint8_t)nsent;
    frame[23] = (uint8_t)NPOLY;
    put32(frame, 24, mck);
    put32(frame, 28, mh[0]);
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
    /* Three aliases for one handler.  'k' is ChipWhisperer's conventional
     * set-key command: if the v2 framework registers its own 'k' with a
     * different length, the dispatch loop matches that entry first and the
     * target answers SS_ERR_CMD (0x01) even though this firmware is flashed.
     * 's' is known good on this board from the krahmer entry.  probe.py
     * reports which of the three the target actually accepts. */
    simpleserial_addcmd('s', 4, do_keygen);
    simpleserial_addcmd('g', 4, do_keygen);
    simpleserial_addcmd('k', 4, do_keygen);
    while (1) simpleserial_get();
}
