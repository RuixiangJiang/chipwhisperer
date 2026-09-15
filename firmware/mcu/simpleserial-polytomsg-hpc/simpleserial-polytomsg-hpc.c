/*
 * Cortex-M4 poly_tomsg glitch-characterization firmware.
 *
 * Unlike the instruction-skip firmware (one naked Thumb instruction per target),
 * the target window here is an entire function: a Kyber-style poly_tomsg message
 * extraction over a full nested loop. The intent is not to suppress one named
 * instruction but to observe, for a wide (~10 000-cycle) window, how a single
 * clock-glitch pulse partitions into: no architectural effect, a surviving
 * corruption of one or more program variables, or a crash.
 *
 * Per run:
 *   1. The host supplies a 32-bit seed.
 *   2. The firmware fills a->coeffs[] pseudo-randomly from that seed, OUTSIDE the
 *      trigger window, so the input is reproducible from the seed alone.
 *   3. trigger_high(); poly_tomsg(msg, a); trigger_low();  -- the fault window.
 *   4. The final value of every local (i, j, t, x, y) is frozen into volatile
 *      sinks immediately after the loop, and the full msg[] buffer is captured.
 *   5. All of that, plus the DWT cycle count and event tuple, is streamed back.
 *
 * The host compares each glitched run against a no-glitch reference produced from
 * the same seed and reports, per variable, whether it changed.
 */

#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>

/* ----- DWT ------------------------------------------------------------------ */

#define DEMCR_REG        (*(volatile uint32_t *)0xE000EDFCUL)
#define DWT_CTRL_REG     (*(volatile uint32_t *)0xE0001000UL)
#define DWT_CYCCNT_REG   (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CPICNT_REG   (*(volatile uint32_t *)0xE0001008UL)
#define DWT_EXCCNT_REG   (*(volatile uint32_t *)0xE000100CUL)
#define DWT_SLEEPCNT_REG (*(volatile uint32_t *)0xE0001010UL)
#define DWT_LSUCNT_REG   (*(volatile uint32_t *)0xE0001014UL)
#define DWT_FOLDCNT_REG  (*(volatile uint32_t *)0xE0001018UL)

#define DEMCR_TRCENA         (1UL << 24)
#define DWT_CTRL_CYCCNTENA   (1UL << 0)
#define DWT_CTRL_CPIEVTENA   (1UL << 17)
#define DWT_CTRL_EXCEVTENA   (1UL << 18)
#define DWT_CTRL_SLEEPEVTENA (1UL << 19)
#define DWT_CTRL_LSUEVTENA   (1UL << 20)
#define DWT_CTRL_FOLDEVTENA  (1UL << 21)
#define DWT_CTRL_EVENT_MASK  (DWT_CTRL_CPIEVTENA | DWT_CTRL_EXCEVTENA | \
                              DWT_CTRL_SLEEPEVTENA | DWT_CTRL_LSUEVTENA | \
                              DWT_CTRL_FOLDEVTENA)
#define DWT_CTRL_NOPRFCNT    (1UL << 24)
#define DWT_CTRL_NOCYCCNT    (1UL << 25)

/* ----- Kyber-ish parameters ------------------------------------------------- */

/*
 * KYBER_SYMBYTES controls the window length: the outer loop runs SYMBYTES times,
 * the inner loop 8 times, and each inner iteration is dominated by one udiv. On
 * this STM32F303 (Cortex-M4F) that works out to roughly 12-13 cycles/iteration
 * including loop overhead and the variable-latency divide, so 96*8 = 768
 * iterations lands near ~9 000-10 000 cycles. udiv latency depends on operand
 * values, so the exact count varies slightly with the coefficients; adjust
 * SYMBYTES up or down after a first no-glitch measurement if you need to hit a
 * particular target.
 */
#ifndef KYBER_SYMBYTES
#define KYBER_SYMBYTES   96U
#endif

#ifndef POLY_TOMSG_INNER
#define POLY_TOMSG_INNER 8U
#endif

#define KYBER_Q          3329

/*
 * poly_tomsg indexes coeffs[8*i + j] with i in [0, SYMBYTES) and j in [0, INNER),
 * so the highest index read is 8*(SYMBYTES-1) + INNER-1 and the array must hold one
 * more than that. Real Kyber uses SYMBYTES=32, INNER=8, N=256, where
 * 8*(32-1)+8 = 256 exactly fills coeffs[KYBER_N]; once either bound is changed to
 * measure the cycle schedule, N must follow or the loop reads off the end of the
 * struct and hardfaults (observed as an empty serial response).
 *
 * This is 8*(SYMBYTES-1)+INNER and NOT 8*SYMBYTES: with INNER > 8 the latter is too
 * small (SYMBYTES=96, INNER=10 reads index 769 from a 768-element array). The array
 * lives in .bss so its size does not affect the loop code, and because the PRNG is
 * sequential, coeffs[k] holds the same value for a given k regardless of N -- so
 * changing N does not change the coefficients the loop actually consumes.
 */
#define KYBER_N          (8U * (KYBER_SYMBYTES - 1U) + POLY_TOMSG_INNER)

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

/* ----- protocol ------------------------------------------------------------- */

#define RESPONSE_MAGIC   0x33435054UL /* "TPC3" little-endian: Tomsg Poly Char v3 */
#define PROTOCOL_VERSION 3U

/*
 * The response no longer fits the old 32-byte frame, so it is length-prefixed and
 * streamed. Layout (all multi-byte fields little-endian):
 *
 *   offset  size  field
 *   0       4     magic
 *   4       4     cyccnt (end - start)
 *   8       4     final i
 *   12      4     final j
 *   16      4     final t
 *   20      4     final x
 *   24      4     final y
 *   28      1     cpicnt (low 8 bits)
 *   29      1     exccnt
 *   30      1     sleepcnt
 *   31      1     lsucnt
 *   32      1     foldcnt
 *   33      1     status
 *   34      1     token
 *   35      1     protocol version
 *   36      2     KYBER_SYMBYTES (window length, for reference)
 *   38      4     msg_checksum (CRC32 of the whole msg[] buffer)
 *
 * Total = 42 bytes, independent of KYBER_SYMBYTES. This fits in a single
 * SimpleSerial2 frame, so no chunking is needed. The full loop still runs its
 * ~10 000-cycle length; only the *reported* form of msg[] is compressed. Any
 * corruption of any msg byte changes the checksum, so msg-difference detection
 * is preserved -- we simply cannot see *which* byte changed, only that one did.
 */
#define RESP_HEADER_LEN  38U
#define RESPONSE_LEN     42U   /* header + 4-byte msg checksum; fits one SS2 frame */

#define STATUS_DWT_ENABLED                (1U << 0)
#define STATUS_CYCCNT_AVAILABLE           (1U << 1)
#define STATUS_EVENT_COUNTERS_ENABLED     (1U << 2)
#define STATUS_PROFILE_COUNTERS_AVAILABLE (1U << 3)
#define STATUS_LOOPS_NOMINAL              (1U << 4) /* i==SYMBYTES && j==8 at exit */

#define TARGET_ATTR __attribute__((noinline, used, aligned(16)))

/* ----- state that must live across the trigger window ----------------------- */

static poly           g_poly;
static unsigned char  g_msg[KYBER_SYMBYTES];

/* Volatile sinks: writing each local here after the loop stops the compiler from
 * optimizing the locals away and gives us their true final values to report. */
static volatile unsigned int g_final_i;
static volatile unsigned int g_final_j;
static volatile uint16_t     g_final_t;
static volatile uint32_t     g_final_x;
static volatile uint32_t     g_final_y;

__attribute__((used, aligned(4)))
const char polytomsg_build_id[] = "polytomsg-hpc-v3.1.0";

static inline void retain_build_id_in_elf(void)
{
    __asm volatile ("" : : "r" (polytomsg_build_id) : "memory");
}

static inline void compiler_barrier(void)
{
    __asm volatile ("" ::: "memory");
}

static inline uint32_t irq_save_and_disable(void)
{
    uint32_t primask;
    __asm volatile ("mrs %0, primask\n cpsid i\n" : "=r" (primask) : : "memory");
    return primask;
}

static inline void irq_restore(uint32_t primask)
{
    if ((primask & 1U) == 0U) {
        __asm volatile ("cpsie i" ::: "memory");
    }
}

static inline void dwt_enable(void)
{
    DEMCR_REG |= DEMCR_TRCENA;
    DWT_CTRL_REG |= (DWT_CTRL_CYCCNTENA | DWT_CTRL_EVENT_MASK);
    __asm volatile ("dsb\n\tisb" ::: "memory");
}

static inline void dwt_reset_counters(void)
{
    DWT_CYCCNT_REG = 0U;
    DWT_CPICNT_REG = 0U;
    DWT_EXCCNT_REG = 0U;
    DWT_SLEEPCNT_REG = 0U;
    DWT_LSUCNT_REG = 0U;
    DWT_FOLDCNT_REG = 0U;
    __asm volatile ("dsb\n\tisb" ::: "memory");
}

static inline void put_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 0);
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

static inline void put_u16_le(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value >> 0);
    dst[1] = (uint8_t)(value >> 8);
}

/* Bytewise CRC32 (poly 0xEDB88320). Used to compress msg[] into 4 bytes so the
 * whole response fits one SimpleSerial2 frame while still detecting any change
 * to any msg byte. */
static uint32_t crc32_buf(const unsigned char *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFUL;
    uint32_t i;
    uint8_t bit;
    for (i = 0U; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (bit = 0U; bit < 8U; bit++) {
            if ((crc & 1U) != 0U) {
                crc = (crc >> 1) ^ 0xEDB88320UL;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFUL;
}

/* xorshift32: small, fast, reproducible from a 32-bit seed. Never zero. */
static uint32_t prng_state;

static inline uint32_t prng_next(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return x;
}

static void seed_poly(poly *a, uint32_t seed)
{
    unsigned int k;
    prng_state = (seed == 0U) ? 0xDEADBEEFUL : seed;
    for (k = 0U; k < (unsigned int)KYBER_N; k++) {
        /* Reduce into a signed range around 0, as real Kyber coeffs would be. */
        a->coeffs[k] = (int16_t)((int32_t)(prng_next() % (uint32_t)KYBER_Q) - (KYBER_Q / 2));
    }
}

/*
 * The target window. Kept as its own noinline function so the trigger brackets
 * exactly the call. The final values of i, j, t, x, y are stored to volatile
 * sinks after the loops so a glitch that perturbs loop control or the datapath
 * is observable from the reported state.
 */
TARGET_ATTR void poly_tomsg(unsigned char msg[KYBER_SYMBYTES], poly *a)
{
    unsigned int i, j;
    uint32_t t = 0U;
    uint32_t x = 0U;
    uint32_t y = 0U;

   for (i = 0; i < KYBER_SYMBYTES; i++) {
        msg[i] = 0;
        for (j = 0; j < POLY_TOMSG_INNER; j++) {
            t  = a->coeffs[8*i+j];
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }

    g_final_i = i;
    g_final_j = j;
    g_final_t = t;
    g_final_x = x;
    g_final_y = y;
}

static void measure_polytomsg(uint32_t seed, uint8_t token, uint8_t response[RESPONSE_LEN])
{
    uint32_t start_cycles;
    uint32_t end_cycles;
    uint32_t primask;
    uint8_t status = 0U;
    unsigned int k;

    /* All input setup happens OUTSIDE the fault window. */
    seed_poly(&g_poly, seed);
    for (k = 0U; k < (unsigned int)KYBER_SYMBYTES; k++) {
        g_msg[k] = 0U;
    }
    g_final_i = 0U;
    g_final_j = 0U;
    g_final_t = 0U;
    g_final_x = 0U;
    g_final_y = 0U;
    compiler_barrier();

    dwt_enable();
    if ((DWT_CTRL_REG & DWT_CTRL_CYCCNTENA) != 0U) {
        status |= STATUS_DWT_ENABLED;
    }
    if ((DWT_CTRL_REG & DWT_CTRL_NOCYCCNT) == 0U) {
        status |= STATUS_CYCCNT_AVAILABLE;
    }
    if ((DWT_CTRL_REG & DWT_CTRL_NOPRFCNT) == 0U) {
        status |= STATUS_PROFILE_COUNTERS_AVAILABLE;
    }
    if (((DWT_CTRL_REG & DWT_CTRL_NOPRFCNT) == 0U) &&
        ((DWT_CTRL_REG & DWT_CTRL_EVENT_MASK) == DWT_CTRL_EVENT_MASK)) {
        status |= STATUS_EVENT_COUNTERS_ENABLED;
    }

    primask = irq_save_and_disable();
    dwt_reset_counters();

    start_cycles = DWT_CYCCNT_REG;
    compiler_barrier();
    trigger_high();
    poly_tomsg(g_msg, &g_poly);
    trigger_low();
    compiler_barrier();
    end_cycles = DWT_CYCCNT_REG;

    irq_restore(primask);

    if ((g_final_i == (unsigned int)KYBER_SYMBYTES) && (g_final_j == (unsigned int)POLY_TOMSG_INNER)) {
        status |= STATUS_LOOPS_NOMINAL;
    }

    put_u32_le(&response[0], RESPONSE_MAGIC);
    put_u32_le(&response[4], end_cycles - start_cycles);
    put_u32_le(&response[8], (uint32_t)g_final_i);
    put_u32_le(&response[12], (uint32_t)g_final_j);
    put_u32_le(&response[16], (uint32_t)g_final_t);
    put_u32_le(&response[20], g_final_x);
    put_u32_le(&response[24], g_final_y);
    response[28] = (uint8_t)(DWT_CPICNT_REG & 0xFFU);
    response[29] = (uint8_t)(DWT_EXCCNT_REG & 0xFFU);
    response[30] = (uint8_t)(DWT_SLEEPCNT_REG & 0xFFU);
    response[31] = (uint8_t)(DWT_LSUCNT_REG & 0xFFU);
    response[32] = (uint8_t)(DWT_FOLDCNT_REG & 0xFFU);
    response[33] = status;
    response[34] = token;
    response[35] = PROTOCOL_VERSION;
    put_u16_le(&response[36], (uint16_t)KYBER_SYMBYTES);
    put_u32_le(&response[38], crc32_buf(g_msg, (uint32_t)KYBER_SYMBYTES));
}

#if SS_VER == SS_VER_2_1
static uint8_t run_experiment(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
#else
static uint8_t run_experiment(uint8_t *in, uint8_t len)
#endif
{
    uint8_t response[RESPONSE_LEN];
    uint32_t seed = 0U;
    uint8_t token = 0U;

#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    /* in = [seed:4 LE][token:1]. Single-frame response, no chunking. */
    if ((len >= 4U) && (in != 0)) {
        seed = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
               ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    }
    if ((len >= 5U) && (in != 0)) {
        token = in[4];
    }

    measure_polytomsg(seed, token, response);
    simpleserial_put('r', RESPONSE_LEN, response);
    return 0x00;
}

int main(void)
{
    retain_build_id_in_elf();

    platform_init();
    init_uart();
    trigger_setup();
    dwt_enable();

    simpleserial_init();
    simpleserial_addcmd('g', 5, run_experiment);

    while (1) {
        simpleserial_get();
    }
}
