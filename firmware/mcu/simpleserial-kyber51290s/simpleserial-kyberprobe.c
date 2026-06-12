#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "api.h"

/*
 * Trigger-source selection for firmware experiments.
 *
 * Default for the bit208 inner-trigger experiment:
 *   - command-level K/E/D triggers are disabled;
 *   - fault-handler blink triggers are disabled;
 *   - the visible trigger should come only from lower-level code such as
 *     m4fspeed/poly.c around the selected poly_tomsg() instruction.
 *
 * Re-enable a source at compile time if needed, for example:
 *   -DPROBE_ENABLE_ENCAP_TRIGGER=1
 *   -DPROBE_ENABLE_KEYPAIR_TRIGGER=1
 *   -DPROBE_ENABLE_DECAP_FULL_TRIGGER=1
 *   -DPROBE_ENABLE_FAULT_HANDLER_TRIGGER=1
 *
 * Backward compatibility:
 *   defining CW_TRIGGER_DECAPS_FULL enables the D-command full decapsulation
 *   trigger unless PROBE_ENABLE_DECAP_FULL_TRIGGER is explicitly set.
 */
#ifndef PROBE_ENABLE_ENCAP_TRIGGER
#define PROBE_ENABLE_ENCAP_TRIGGER 0
#endif

#ifndef PROBE_ENABLE_KEYPAIR_TRIGGER
#define PROBE_ENABLE_KEYPAIR_TRIGGER 0
#endif

#ifdef CW_TRIGGER_DECAPS_FULL
#ifndef PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_ENABLE_DECAP_FULL_TRIGGER 1
#endif
#endif

#ifndef PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_ENABLE_DECAP_FULL_TRIGGER 0
#endif

#ifndef PROBE_ENABLE_FAULT_HANDLER_TRIGGER
#define PROBE_ENABLE_FAULT_HANDLER_TRIGGER 0
#endif

#if PROBE_ENABLE_ENCAP_TRIGGER
#define PROBE_ENCAP_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_ENCAP_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_ENCAP_TRIGGER_HIGH() do { } while (0)
#define PROBE_ENCAP_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_KEYPAIR_TRIGGER
#define PROBE_KEYPAIR_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_KEYPAIR_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_KEYPAIR_TRIGGER_HIGH() do { } while (0)
#define PROBE_KEYPAIR_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_DECAP_FULL_TRIGGER
#define PROBE_DECAP_FULL_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_DECAP_FULL_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_DECAP_FULL_TRIGGER_HIGH() do { } while (0)
#define PROBE_DECAP_FULL_TRIGGER_LOW()  do { } while (0)
#endif

#if PROBE_ENABLE_FAULT_HANDLER_TRIGGER
#define PROBE_FAULT_TRIGGER_HIGH() do { trigger_high(); } while (0)
#define PROBE_FAULT_TRIGGER_LOW()  do { trigger_low();  } while (0)
#else
#define PROBE_FAULT_TRIGGER_HIGH() do { } while (0)
#define PROBE_FAULT_TRIGGER_LOW()  do { } while (0)
#endif


#define PK_CHUNK 200
#define SK_CHUNK 96
#define CT_CHUNK 128

#ifndef KYBER_SYMBYTES
#define KYBER_SYMBYTES 32
#endif

#ifndef KYBER_INDCPA_SECRETKEYBYTES
#define KYBER_INDCPA_SECRETKEYBYTES 768
#endif

#define INDCPA_SK_CHUNK 128

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];

extern void indcpa_dec(unsigned char *m, const unsigned char *c, const unsigned char *sk);

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

    PROBE_ENCAP_TRIGGER_HIGH();
    int ret = crypto_kem_enc(ct, ss_enc, pk);
    PROBE_ENCAP_TRIGGER_LOW();

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

    PROBE_DECAP_FULL_TRIGGER_HIGH();

    int ret = crypto_kem_dec(ss_dec, ct, sk);

    PROBE_DECAP_FULL_TRIGGER_LOW();

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

    PROBE_KEYPAIR_TRIGGER_HIGH();
    int ret = crypto_kem_keypair(pk, sk);
    PROBE_KEYPAIR_TRIGGER_LOW();

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

#if SS_VER == SS_VER_2_1
static uint8_t cmd_debug_decode_msg(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_debug_decode_msg(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif
    (void)len;
    (void)buf;

    uint8_t m_dec[KYBER_SYMBYTES];

    /*
     * Debug-only command:
     * Directly run IND-CPA decryption on the current global ciphertext ct.
     *
     * Since the decoder trigger has already been inserted around poly_tomsg()
     * inside m4fspeed/indcpa.c, this command will produce the same decoder
     * trigger, but returns the decoded message instead of the shared secret.
     *
     * The KEM secret key layout starts with the IND-CPA secret key, so passing
     * sk here is consistent with crypto_kem_dec().
     */
    indcpa_dec(m_dec, ct, sk);

    simpleserial_put('M', KYBER_SYMBYTES, m_dec);
    return 0x00;
}

#if SS_VER == SS_VER_2_1
static uint8_t cmd_read_indcpa_sk_chunk(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
#else
static uint8_t cmd_read_indcpa_sk_chunk(uint8_t *buf, uint8_t len)
#endif
{
#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    /*
     * Debug-only command.
     *
     * Payload:
     *   buf[0] = offset low byte
     *   buf[1] = offset high byte
     *   buf[2] = requested length, ignored except for compatibility
     *
     * Response:
     *   command 'Z'
     *   up to 128 bytes from sk[0 : KYBER_INDCPA_SECRETKEYBYTES]
     *
     * Kyber KEM secret-key layout:
     *   sk[0 : KYBER_INDCPA_SECRETKEYBYTES] is the IND-CPA secret key.
     *
     * Important:
     *   This is raw serialized IND-CPA sk, i.e. NTT-domain polyvec bytes.
     *   Host side should decode it with polyvec_frombytes() and apply inverse NTT
     *   before using it as small secret coefficients.
     */

    if (len < 2) {
        uint8_t err = 0xff;
        simpleserial_put('Z', 1, &err);
        return 0x00;
    }

    uint16_t offset = ((uint16_t)buf[0]) | (((uint16_t)buf[1]) << 8);

    if (offset >= KYBER_INDCPA_SECRETKEYBYTES) {
        uint8_t err = 0xfe;
        simpleserial_put('Z', 1, &err);
        return 0x00;
    }

    uint16_t remaining = KYBER_INDCPA_SECRETKEYBYTES - offset;
    uint8_t out_len = INDCPA_SK_CHUNK;

    if (remaining < INDCPA_SK_CHUNK) {
        out_len = (uint8_t)remaining;
    }

    simpleserial_put('Z', out_len, sk + offset);
    return 0x00;
}


void HardFault_Handler(void)
{
    fault_puts("rHARDFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}


void BusFault_Handler(void)
{
    fault_puts("rBUSFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
    }
}


void UsageFault_Handler(void)
{
    fault_puts("rUSAGEFAULT\n");

    while (1) {
        PROBE_FAULT_TRIGGER_HIGH();
        for (volatile uint32_t i = 0; i < 100000; i++) {
            __asm volatile("nop");
        }
        PROBE_FAULT_TRIGGER_LOW();
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
    simpleserial_addcmd('M', 0, cmd_debug_decode_msg);
    simpleserial_addcmd('Z', 3, cmd_read_indcpa_sk_chunk);
    uart_puts("rKYBERPROBE_C\n");

    while (1) {
        simpleserial_get();
    }

    return 0;
}