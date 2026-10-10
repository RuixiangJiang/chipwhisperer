/* Krahmer, Pessl, Land, Gueneysu 2024,
 * "Correction Fault Attacks on Randomized CRYSTALS-Dilithium" -- skip variant.
 *
 * Monitored region: the Fiat-Shamir-with-aborts response computation
 *
 *     z[k] = y[k] + w[k]          with w = c * s1            <-- the add
 *     if (||z||_inf >= GAMMA1 - BETA) reject and resample y
 *
 * Signing is RANDOMIZED: y is drawn fresh per attempt from a host-supplied
 * nonce, so nonce-reuse attacks do not apply and any leak must come from the
 * fault itself.
 *
 * The attack condition: if the y term fails to be added at coefficient k, the
 * emitted z[k] equals w[k] = (c*s1)[k] exactly -- a linear equation in s1 that
 * the attacker reads straight off the signature.  The oracle therefore tests
 * each coefficient against all three candidates (correct / y missing / w
 * missing) rather than merely "differs from reference", because against a
 * randomized scheme there is no reference signature to difference with.
 *
 * Real Dilithium-2 parameters; reduced to one polynomial of s1 (L=4 in full).
 */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>

#define N       256
#define Q       8380417
#define ETA     2
#define GAMMA1  (1 << 17)
#define BETA    78
#define BOUND   (GAMMA1 - BETA)
#define TAU     39
#define MAXITER 8
#define MAGIC   0x4B524148u          /* "KRAH" */

#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t *)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t *)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t *)0xE0001018)

static int32_t  s1[N], wv[N], yv[N], zv[N];
static int32_t  wref[N];   /* immutable copy: wv is live during the glitch */
static uint16_t cpos[TAU];
static int8_t   csgn[TAU];

static uint32_t lcg_s;
static uint16_t lcg16(void)
{
    lcg_s = 1103515245u * lcg_s + 12345u;
    return (uint16_t)(lcg_s >> 16);
}

static void make_key(void)
{
    unsigned i, t, u, seen;
    lcg_s = 0x2468ACE1u;
    for (i = 0; i < N; i++)
        s1[i] = (int32_t)(lcg16() % (2 * ETA + 1)) - ETA;
    lcg_s = 0x13572468u;
    t = 0;
    while (t < TAU) {
        uint16_t p = lcg16() % N;
        seen = 0;
        for (u = 0; u < t; u++) if (cpos[u] == p) { seen = 1; break; }
        if (seen) continue;
        cpos[t] = p;
        csgn[t] = (lcg16() & 1) ? 1 : -1;
        t++;
    }
}

/* w = c * s1, negacyclic; data-independent trip counts */
static void poly_mul(void)
{
    unsigned t, q, k;
    for (k = 0; k < N; k++) wv[k] = 0;
    for (t = 0; t < TAU; t++) {
        unsigned p = cpos[t];
        int32_t  sg = csgn[t];
        for (q = 0; q + p < N; q++) wv[q + p] += sg * s1[q];
        for (q = N - p; q < N; q++) wv[q + p - N] -= sg * s1[q];
    }
}

/* randomized y: fresh per attempt, derived from (nonce, attempt) */
static void gen_y(uint32_t nonce, unsigned it)
{
    unsigned k;
    lcg_s = 0x0BADC0DEu ^ (nonce * 0x9E3779B9u) ^ (it * 0x85EBCA6Bu);
    for (k = 0; k < N; k++) {
        uint32_t hi = lcg16();
        uint32_t lo = lcg16() & 3u;
        yv[k] = (int32_t)(((hi << 2) | lo) % (2u * GAMMA1)) - GAMMA1 + 1;
    }
}

__attribute__((noinline, noclone))
static unsigned chknorm(void)
{
    unsigned k;
    for (k = 0; k < N; k++) {
        int32_t v = zv[k];
        if (v < 0) v = -v;
        if (v >= BOUND) return k;
    }
    return N;
}

/* ---- the monitored region: the response add plus the norm check ---------- */
static unsigned g_iters;
__attribute__((noinline, noclone))
static unsigned do_respond(uint32_t nonce)
{
    unsigned it, k, c = 0;
    for (it = 1; it <= MAXITER; it++) {
        gen_y(nonce, it);
        for (k = 0; k < N; k++)
            zv[k] = yv[k] + wv[k];          /* <<== Krahmer target: the add */
        c = chknorm();
        if (c == N) { g_iters = it; return 1; }
    }
    g_iters = MAXITER;
    return 0;
}

static void dwt_init(void) { DEMCR |= (1u << 24); DWT_CTRL = 0; }
static void dwt_reset(void)
{
    DWT_CTRL &= ~(1u | (1u << 17) | (1u << 20) | (1u << 21));
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
    DWT_CTRL |=  (1u | (1u << 17) | (1u << 20) | (1u << 21));
}

static uint32_t fnv32(const int32_t *p, unsigned n)
{
    uint32_t h = 0x811C9DC5u;
    unsigned i, sh;
    for (i = 0; i < n; i++)
        for (sh = 0; sh < 32; sh += 8) { h ^= ((uint32_t)p[i] >> sh) & 0xFFu; h *= 16777619u; }
    return h;
}

static void put16(uint8_t *f, unsigned o, uint16_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *f, unsigned o, uint32_t v)
{ f[o] = (uint8_t)v; f[o+1] = (uint8_t)(v >> 8);
  f[o+2] = (uint8_t)(v >> 16); f[o+3] = (uint8_t)(v >> 24); }

static uint8_t do_sign(uint8_t cc, uint8_t sc, uint8_t l, uint8_t *d)
{
    uint32_t nonce, cyc;
    uint8_t  cpi, lsu, fold, frame[52], ok;
    unsigned k, n_ok = 0, n_add = 0, n_yl = 0, n_ysh = 0, n_wsh = 0, n_ot = 0;
    uint16_t f_yl = 0xFFFF, f_add = 0xFFFF, f_ot = 0xFFFF;
    (void)cc; (void)sc; (void)l;

    nonce = (uint32_t)d[0] | ((uint32_t)d[1] << 8)
          | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);

    dwt_reset();
    __asm volatile ("cpsid i" ::: "memory");
    trigger_high();
    ok = (uint8_t)do_respond(nonce);
    trigger_low();
    cyc  = DWT_CYCCNT;
    cpi  = (uint8_t)DWT_CPICNT;
    lsu  = (uint8_t)DWT_LSUCNT;
    fold = (uint8_t)DWT_FOLDCNT;
    __asm volatile ("cpsie i" ::: "memory");

    /* yv[] still holds the y of the accepting attempt, wv[] is fixed:
     * classify each coefficient against the three candidates. */
    /* Candidates keyed to the real loop body:
     *   ldr y / ldr w / add / str, all post-incremented.
     *   z[k]==z[k-1]+w[k]  <- the y load was skipped: w[k] = z[k]-z[k-1]
     *   z[k]==y[k-1]+w[k]  <- the shifted tail that follows such a skip
     *   z[k]==y[k]         <- the add itself was skipped (no leak)            */
    for (k = 0; k < N; k++) {
        if      (zv[k] == yv[k] + wref[k])                 n_ok++;
        else if (k && zv[k] == zv[k-1] + wref[k]) { if (!n_yl)  f_yl  = (uint16_t)k; n_yl++;  }
        else if (zv[k] == yv[k])                  { if (!n_add) f_add = (uint16_t)k; n_add++; }
        else if (k && zv[k] == yv[k-1] + wref[k])          n_ysh++;
        else if (k && zv[k] == yv[k] + wref[k-1])          n_wsh++;
        else                                    { if (!n_ot)  f_ot  = (uint16_t)k; n_ot++;  }
    }

    put32(frame,  0, MAGIC);
    put32(frame,  4, nonce);
    frame[8]  = (uint8_t)g_iters;
    frame[9]  = ok;
    put16(frame, 10, (uint16_t)n_ok);
    put16(frame, 12, (uint16_t)n_yl);
    put16(frame, 14, (uint16_t)n_add);
    put16(frame, 16, (uint16_t)n_ysh);
    put16(frame, 18, (uint16_t)n_wsh);
    put16(frame, 20, (uint16_t)n_ot);
    put16(frame, 22, f_yl);
    put16(frame, 24, f_add);
    put16(frame, 26, f_ot);
    put32(frame, 28, fnv32(zv, N));
    put32(frame, 32, cyc);
    {   unsigned i, wd = 0;
        for (i = 0; i < N; i++) if (wv[i] != wref[i]) wd++;
        frame[39] = (uint8_t)(wd > 255 ? 255 : wd);   /* wv clobbered? */
    }
    frame[36] = cpi; frame[37] = lsu; frame[38] = fold;
    {   /* the three values at the first unexplained coefficient, so the host
         * can test any relation offline instead of guessing */
        unsigned q = (f_ot != 0xFFFF) ? f_ot : ((f_yl != 0xFFFF) ? f_yl : 0);
        put32(frame, 40, (uint32_t)zv[q]);
        put32(frame, 44, (uint32_t)yv[q]);
        put32(frame, 48, (uint32_t)wref[q]);
    }
    simpleserial_put('r', 52, frame);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    dwt_init();
    make_key();
    poly_mul();                       /* w = c*s1, fixed across signatures */
    { unsigned i; for (i = 0; i < N; i++) wref[i] = wv[i]; }
    simpleserial_init();
    simpleserial_addcmd('s', 4, do_sign);
    while (1) simpleserial_get();
}
