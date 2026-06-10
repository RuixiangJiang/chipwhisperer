#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "api.h"

#define PK_CHUNK 200
#define SK_CHUNK 96
#define CT_CHUNK 128

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];


static void enable_fpu(void)
{
    volatile uint32_t *cpacr = (volatile uint32_t *)0xE000ED88U;

    *cpacr |= (0xFU << 20);

    __asm volatile("dsb");
    __asm volatile("isb");
}


static void uart_puts(const char *s)
{
    while (*s) {
        putch(*s++);
    }
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_encaps_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_encaps_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1 + CRYPTO_BYTES];

    trigger_high();
    int ret = crypto_kem_enc(ct, ss_enc, pk);
    trigger_low();

    out[0] = (uint8_t)ret;
    memcpy(out + 1, ss_enc, CRYPTO_BYTES);

    simpleserial_put('E', sizeof(out), out);

    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_decaps_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_decaps_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1 + CRYPTO_BYTES];

#ifdef CW_TRIGGER_DECAPS_FULL
    trigger_high();
#endif

    int ret = crypto_kem_dec(ss_dec, ct, sk);

#ifdef CW_TRIGGER_DECAPS_FULL
    trigger_low();
#endif

    out[0] = (uint8_t)ret;
    memcpy(out + 1, ss_dec, CRYPTO_BYTES);

    simpleserial_put('S', sizeof(out), out);

    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_ct(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_ct(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 3) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    uint8_t outlen = buf[2];

    if (offset >= CRYPTO_CIPHERTEXTBYTES) {
        return 0x02;
    }

    if ((uint32_t)offset + (uint32_t)outlen > CRYPTO_CIPHERTEXTBYTES) {
        return 0x03;
    }

    simpleserial_put('T', outlen, ct + offset);

    return 0x00;
}

#define CT_CHUNK 128

#if SS_VER == SS_VER_2_1
static uint8_t cmd_load_ct(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_load_ct(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 2 + CT_CHUNK) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

    if ((uint32_t)offset + CT_CHUNK > CRYPTO_CIPHERTEXTBYTES) {
        return 0x02;
    }

    memcpy(ct + offset, buf + 2, CT_CHUNK);

    uint8_t out[1] = {0x00};
    simpleserial_put('C', 1, out);

    return 0x00;
}


#if SS_VER == SS_VER_2_1
static uint8_t cmd_ping(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_ping(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1] = {0x42};
    simpleserial_put('P', 1, out);

    return 0x00;
}


#if SS_VER == SS_VER_2_1
static uint8_t cmd_keypair_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_keypair_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[1];

    trigger_high();
    int ret = crypto_kem_keypair(pk, sk);
    trigger_low();

    out[0] = (uint8_t)ret;
    simpleserial_put('K', 1, out);

    return 0x00;
}


#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_pk(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_pk(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if (len != 3) {
        return 0x01;
    }

    uint16_t offset = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    uint8_t outlen = buf[2];

    if (offset >= CRYPTO_PUBLICKEYBYTES) {
        return 0x02;
    }

    if ((uint32_t)offset + (uint32_t)outlen > CRYPTO_PUBLICKEYBYTES) {
        return 0x03;
    }

    simpleserial_put('R', outlen, pk + offset);

    return 0x00;
}

int randombytes(uint8_t *buf, size_t len);

#if SS_VER == SS_VER_2_1
static uint8_t cmd_rng_probe(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_rng_probe(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t out[17];

    int ret = randombytes(out + 1, 16);

    out[0] = (uint8_t)ret;
    simpleserial_put('N', 17, out);

    return 0x00;
}

static void fault_puts(const char *s)
{
    while (*s) {
        putch(*s++);
    }
}


void HardFault_Handler(void)
{
    fault_puts("rHARDFAULT\n");

    while (1) {
        trigger_high();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        trigger_low();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}


void BusFault_Handler(void)
{
    fault_puts("rBUSFAULT\n");

    while (1) {
        trigger_high();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        trigger_low();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}


void UsageFault_Handler(void)
{
    fault_puts("rUSAGEFAULT\n");

    while (1) {
        trigger_high();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        trigger_low();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}


int main(void)
{
    enable_fpu();

    platform_init();
    init_uart();
    trigger_setup();

    uart_puts("rKYBERPROBE_A\n");

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss_enc, 0, sizeof(ss_enc));
    memset(ss_dec, 0, sizeof(ss_dec));

    uart_puts("rKYBERPROBE_B\n");

    simpleserial_init();

    simpleserial_addcmd('P', 0, cmd_ping);
    simpleserial_addcmd('K', 0, cmd_keypair_probe);
    simpleserial_addcmd('R', 3, cmd_read_pk);
    simpleserial_addcmd('N', 0, cmd_rng_probe);
    simpleserial_addcmd('E', 0, cmd_encaps_probe);
    simpleserial_addcmd('D', 0, cmd_decaps_probe);
    simpleserial_addcmd('T', 3, cmd_read_ct);
    simpleserial_addcmd('C', 2 + CT_CHUNK, cmd_load_ct);
    uart_puts("rKYBERPROBE_C\n");

    while (1) {
        simpleserial_get();
    }

    return 0;
}