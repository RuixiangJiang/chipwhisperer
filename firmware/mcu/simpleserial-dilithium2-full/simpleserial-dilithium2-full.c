/*
    simpleserial-dilithium2-full
    ---------------------------------------------------------------------
    Runs the complete pqm4 Round 3 Dilithium2 (m4f) pipeline on an
    STM32F405 to establish whether the part has enough memory, and how
    much headroom is left.

    What it measures
      * peak stack depth per operation, by painting the unused stack with
        a known word and finding how far down it was overwritten
      * cycle count per operation, from DWT CYCCNT
      * static footprint, from the linker's bss end and stack top

    Determinism
      randombytes() is a SHAKE256 DRBG over a fixed seed, so keygen is
      reproducible across resets and across boards. Dilithium signing in
      Round 3 is already deterministic given sk, so a full run should
      produce byte-identical pk/sk/sig every time. The 'd' command
      returns a digest of any buffer to check that cheaply.

    Commands (SimpleSerial V2.1)
      'i'  sizes and build info                       -> 16 bytes
      'r'  memory map report                          -> 16 bytes
      'm'  set message (1..64 bytes)                  -> ack
      'j'  crypto_sign_keypair                        -> 12 bytes
      's'  crypto_sign_signature                      -> 14 bytes
      'x'  crypto_sign_verify                         -> 12 bytes
      'a'  keypair + sign + verify in one go          -> 16 bytes
      'd'  digest of a buffer: in=[which]             -> 32 bytes
      'f'  fetch: in=[which][off_lo][off_hi]          -> 128 bytes
           which: 0=pk 1=sk 2=sig 3=msg
*/

#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "fips202.h"

/* ------------------------------------------------------------------ */
/* Cortex-M4 core peripherals, poked directly so this does not depend  */
/* on which CMSIS headers the ChipWhisperer HAL happens to pull in.    */
/* ------------------------------------------------------------------ */
#define SCB_CPACR   (*(volatile uint32_t *)0xE000ED88u)
#define SCB_DEMCR   (*(volatile uint32_t *)0xE000EDFCu)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000u)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004u)

static void fpu_enable(void)
{
    /* Full access to CP10/CP11. pqm4's m4f assembly uses VFP registers
       as scratch; without this the first VFP instruction HardFaults. */
    SCB_CPACR |= (0xFu << 20);
    __asm volatile ("dsb");
    __asm volatile ("isb");
}

static void dwt_init(void)
{
    SCB_DEMCR |= (1u << 24);        /* TRCENA */
    DWT_CYCCNT = 0;
    DWT_CTRL  |= 1u;                /* CYCCNTENA */
}

/* ------------------------------------------------------------------ */
/* Stack painting                                                      */
/* ------------------------------------------------------------------ */
#define PAINT_WORD 0xDEADBEEFu

/* Provided by the linker script. Declared weak so a script that names
   them differently degrades to the fallback rather than failing to link. */
extern char _ebss     __attribute__((weak));
extern char end       __attribute__((weak));
extern char _estack   __attribute__((weak));

static uint32_t paint_top;      /* highest painted address (exclusive)  */
static uint32_t paint_floor;    /* lowest painted address               */

static uint32_t bss_end(void)
{
    if (&_ebss) return (uint32_t)(uintptr_t)&_ebss;
    if (&end)   return (uint32_t)(uintptr_t)&end;
    return 0x20000000u + 0x2000u;          /* conservative fallback */
}

static uint32_t stack_top(void)
{
    if (&_estack) return (uint32_t)(uintptr_t)&_estack;
    return 0x20000000u + 128u * 1024u;     /* SRAM1 top on F405 */
}

static void paint_stack(void)
{
    volatile uint32_t marker;
    uint32_t sp = ((uint32_t)(uintptr_t)&marker - 64u) & ~3u;
    uint32_t fl = (bss_end() + 1024u + 3u) & ~3u;

    paint_top = sp;
    paint_floor = fl;

    volatile uint32_t *p  = (volatile uint32_t *)(uintptr_t)sp;
    volatile uint32_t *fp = (volatile uint32_t *)(uintptr_t)fl;
    while (p >= fp)
        *p-- = PAINT_WORD;
}

static uint32_t stack_used(void)
{
    volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)paint_floor;
    volatile uint32_t *t = (volatile uint32_t *)(uintptr_t)paint_top;
    while (p < t && *p == PAINT_WORD)
        p++;
    return paint_top - (uint32_t)(uintptr_t)p;
}

/* ------------------------------------------------------------------ */
/* Deterministic randombytes                                           */
/* ------------------------------------------------------------------ */
static uint64_t drbg_ctr = 0;

void randombytes(uint8_t *out, size_t outlen)
{
    uint8_t seed[40] = {
        'C','W','-','D','I','L','2','-','F','4','0','5','-','D','R','B',
        'G',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };
    for (int i = 0; i < 8; i++)
        seed[32 + i] = (uint8_t)(drbg_ctr >> (8 * i));
    drbg_ctr++;
    shake256(out, outlen, seed, sizeof(seed));
}

/* ------------------------------------------------------------------ */
/* Buffers                                                             */
/* ------------------------------------------------------------------ */
static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t sig[CRYPTO_BYTES];
static uint8_t msg[64];
static size_t  msglen = 32;
static size_t  siglen = 0;

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint8_t *which_buf(uint8_t w, uint32_t *len)
{
    switch (w) {
        case 0: *len = CRYPTO_PUBLICKEYBYTES; return pk;
        case 1: *len = CRYPTO_SECRETKEYBYTES; return sk;
        case 2: *len = (uint32_t)siglen;      return sig;
        case 3: *len = (uint32_t)msglen;      return msg;
        default: *len = 0; return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */
uint8_t cmd_info(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[16];
    put_u32(o + 0, CRYPTO_PUBLICKEYBYTES);
    put_u32(o + 4, CRYPTO_SECRETKEYBYTES);
    put_u32(o + 8, CRYPTO_BYTES);
    put_u32(o + 12, (uint32_t)(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES
                               + CRYPTO_BYTES + sizeof(msg)));
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_mem(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[16];
    put_u32(o + 0, bss_end());
    put_u32(o + 4, stack_top());
    put_u32(o + 8, stack_top() - bss_end());   /* RAM left for stack */
    put_u32(o + 12, paint_top ? stack_used() : 0);
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_msg(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l == 0 || l > sizeof(msg)) return 0x11;
    memcpy(msg, in, l);
    msglen = l;
    return 0x00;
}

uint8_t cmd_keypair(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[12];
    drbg_ctr = 0;
    paint_stack();
    DWT_CYCCNT = 0;
    int rc = crypto_sign_keypair(pk, sk);
    uint32_t cyc = DWT_CYCCNT;
    uint32_t st = stack_used();
    put_u32(o + 0, cyc);
    put_u32(o + 4, st);
    put_u32(o + 8, (uint32_t)rc);
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_sign(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[14];
    paint_stack();
    DWT_CYCCNT = 0;
    int rc = crypto_sign_signature(sig, &siglen, msg, msglen, sk);
    uint32_t cyc = DWT_CYCCNT;
    uint32_t st = stack_used();
    put_u32(o + 0, cyc);
    put_u32(o + 4, st);
    o[8]  = (uint8_t)siglen;
    o[9]  = (uint8_t)(siglen >> 8);
    put_u32(o + 10, (uint32_t)rc);
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_verify(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[12];
    paint_stack();
    DWT_CYCCNT = 0;
    int rc = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    uint32_t cyc = DWT_CYCCNT;
    uint32_t st = stack_used();
    put_u32(o + 0, cyc);
    put_u32(o + 4, st);
    put_u32(o + 8, (uint32_t)rc);
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_paintcheck(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    uint8_t o[16];
    uint8_t op = (l == 1) ? in[0] : 0;

    paint_stack();
    switch (op) {
        case 1: drbg_ctr = 0; crypto_sign_keypair(pk, sk); break;
        case 2: crypto_sign_signature(sig, &siglen, msg, msglen, sk); break;
        case 3: crypto_sign_verify(sig, siglen, msg, msglen, pk); break;
        default: break;
    }
    volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)paint_floor;
    volatile uint32_t *t = (volatile uint32_t *)(uintptr_t)paint_top;
    while (p < t && *p == PAINT_WORD) p++;

    put_u32(o + 0, paint_floor);
    put_u32(o + 4, paint_top);
    put_u32(o + 8, (uint32_t)(uintptr_t)p);
    put_u32(o + 12, *p);
    simpleserial_put('r', 16, o);
    return 0x00;
}

/* One command that exercises the whole pipeline and reports the worst
   stack depth across all three stages -- the number that decides
   whether the part is big enough. */
uint8_t cmd_all(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc; (void)l; (void)in;
    uint8_t o[16];
    uint32_t worst = 0, st;

    drbg_ctr = 0;
    paint_stack();
    int rc1 = crypto_sign_keypair(pk, sk);
    st = stack_used(); if (st > worst) worst = st;

    paint_stack();
    int rc2 = crypto_sign_signature(sig, &siglen, msg, msglen, sk);
    st = stack_used(); if (st > worst) worst = st;

    paint_stack();
    int rc3 = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    st = stack_used(); if (st > worst) worst = st;

    put_u32(o + 0, worst);
    put_u32(o + 4, stack_top() - bss_end());
    o[8]  = (uint8_t)siglen;
    o[9]  = (uint8_t)(siglen >> 8);
    o[10] = (uint8_t)(rc1 & 0xFF);
    o[11] = (uint8_t)(rc2 & 0xFF);
    o[12] = (uint8_t)(rc3 & 0xFF);
    o[13] = 0; o[14] = 0; o[15] = 0x02;   /* harness revision */
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_digest(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l != 1) return 0x11;
    uint32_t n;
    uint8_t *b = which_buf(in[0], &n);
    if (!b) return 0x12;
    uint8_t o[32];
    shake256(o, sizeof(o), b, n);
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

uint8_t cmd_fetch(uint8_t c, uint8_t sc, uint8_t l, uint8_t *in)
{
    (void)c; (void)sc;
    if (l != 3) return 0x11;
    uint32_t n;
    uint8_t *b = which_buf(in[0], &n);
    if (!b) return 0x12;
    uint32_t off = (uint32_t)in[1] | ((uint32_t)in[2] << 8);
    uint8_t o[128];
    memset(o, 0, sizeof(o));
    if (off < n) {
        uint32_t k = n - off;
        if (k > sizeof(o)) k = sizeof(o);
        memcpy(o, b + off, k);
    }
    simpleserial_put('r', sizeof(o), o);
    return 0x00;
}

int main(void)
{
    fpu_enable();
    platform_init();
    init_uart();
    trigger_setup();
    trigger_high();                                  /* pin marker */
    putch('R'); putch('D'); putch('Y'); putch('\n'); /* UART marker */
    dwt_init();

    for (unsigned i = 0; i < sizeof(msg); i++)
        msg[i] = (uint8_t)(i * 11 + 3);

    simpleserial_init();
    simpleserial_addcmd('i', 0,  cmd_info);
    simpleserial_addcmd('r', 0,  cmd_mem);
    simpleserial_addcmd('m', 32, cmd_msg);
    simpleserial_addcmd('j', 0,  cmd_keypair);
    simpleserial_addcmd('s', 0,  cmd_sign);
    simpleserial_addcmd('x', 0,  cmd_verify);
    simpleserial_addcmd('a', 0,  cmd_all);
    simpleserial_addcmd('d', 1,  cmd_digest);
    simpleserial_addcmd('f', 3,  cmd_fetch);
    simpleserial_addcmd('t', 1,  cmd_paintcheck);

    while (1)
        simpleserial_get();
}
