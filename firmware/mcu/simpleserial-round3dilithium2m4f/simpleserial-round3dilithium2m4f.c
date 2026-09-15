/*
    Fault-injection harness for Du et al., "Breaking the Shield: Novel Fault
    Attacks on CRYSTALS-Dilithium" (ACISP 2025), Section 6.4 / Attack Approach 1
    of Section 5.2.

    Target chain (pqm4 Dilithium2, Round 3):

        poly_uniform_gamma1
          -> stream256_squeezeblocks          <-- trigger wraps this (F2, Fig. 4)
               -> keccak_inc_squeeze
                    -> KeccakF1600_StatePermute
                    -> KeccakF1600_StateExtractBytes   <-- fault target (Fig. 8)

    The paper skips the load at line 13 of Fig. 12, which should place the low
    32 bits of state[0] into r5. When skipped, r5 keeps the 0 left there by
    line 6, and data[0] is written as 0 while every other byte of the extracted
    block is unaffected.

    Success criterion (Section 6.4): of the first SHAKE256_RATE (136) extracted
    bytes, data[0] changes from non-zero to 0 and bytes 1..135 are unchanged.

    Only the squeeze path is compiled in. poly_uniform_gamma1 itself is not
    called: its preamble (stream256_init) and the squeeze are reproduced here
    verbatim, which keeps the instruction stream inside the trigger window
    identical while avoiding a dependency on the NTT assembly.

    Commands (SimpleSerial V2.1)
        's'  set the CRHBYTES seed                        (CRHBYTES bytes in)
        'n'  set the 16-bit nonce, little endian          (2 bytes in)
        'g'  init + trigger_high + squeeze + trigger_low  (136 bytes out)
        'b'  fetch a later 136-byte window of the squeeze buffer (1 byte in)
        'k'  SHAKE256 known-answer test                   (n bytes in, 32 out)
        'i'  report build info                            (8 bytes out)
*/

#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>
#include <string.h>

#include "params.h"
#include "symmetric.h"
#include "fips202.h"

/* Dilithium2 (GAMMA1 = 1 << 17): POLYZ_PACKEDBYTES = 576, so the squeeze
   requests ceil(576/136) = 5 blocks in a single call. The attack lands in the
   first iteration of keccak_inc_squeeze's while loop. */
#ifndef POLY_UNIFORM_GAMMA1_NBLOCKS
#define POLY_UNIFORM_GAMMA1_NBLOCKS \
    ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
#endif

#define SQUEEZE_BYTES (POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES)
#define WINDOW        STREAM256_BLOCKBYTES      /* 136 for SHAKE256 */

static uint8_t seed[CRHBYTES];
static uint16_t nonce = 0;
static uint8_t sbuf[SQUEEZE_BYTES];

static uint8_t reg_status = 0x11;

/* -------------------------------------------------------------------------
   's' : load the seed (rho-prime in Algorithm 1). Fixed across a campaign so
   that every attempt produces the same clean reference block.
   ------------------------------------------------------------------------- */
uint8_t set_seed(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd;
    if (len != CRHBYTES)
        return 0x11;
    memcpy(seed, in, CRHBYTES);
    return 0x00;
}

/* -------------------------------------------------------------------------
   'n' : set the rejection-sampling nonce. Used to search for a seed/nonce pair
   whose clean data[0] is non-zero, which the attack requires.
   ------------------------------------------------------------------------- */
uint8_t set_nonce(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd;
    if (len != 2)
        return 0x11;
    nonce = (uint16_t)in[0] | ((uint16_t)in[1] << 8);
    return 0x00;
}

/* -------------------------------------------------------------------------
   'g' : the measured operation.

   stream256_init is deliberately outside the trigger window: the paper places
   the trigger around stream256_squeezeblocks only, and keeping the absorb out
   of the window means ext_offset counts cycles from the start of the squeeze.
   ------------------------------------------------------------------------- */
uint8_t run_squeeze(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd; (void)len; (void)in;

    stream256_state state;

    memset(sbuf, 0xA5, sizeof(sbuf));
    stream256_init(&state, seed, nonce);

    trigger_high();
    stream256_squeezeblocks(sbuf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
    trigger_low();

    simpleserial_put('r', WINDOW, sbuf);
    return 0x00;
}

/* -------------------------------------------------------------------------
   'b' : page out a later window of the squeeze buffer, for checking whether a
   fault perturbed blocks beyond the first. Not used in the hot loop.
   ------------------------------------------------------------------------- */
uint8_t get_block(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd;
    if (len != 1)
        return 0x11;
    uint8_t idx = in[0];
    if (idx >= POLY_UNIFORM_GAMMA1_NBLOCKS)
        return 0x12;
    simpleserial_put('r', WINDOW, sbuf + (uint32_t)idx * WINDOW);
    return 0x00;
}

/* -------------------------------------------------------------------------
   'k' : SHAKE256(in) truncated to 32 bytes. Validates the whole fips202 chain
   against hashlib.shake_256 on the host before any glitching.
   ------------------------------------------------------------------------- */
uint8_t shake_kat(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd;
    uint8_t out[32];
    shake256(out, sizeof(out), in, len);
    simpleserial_put('r', sizeof(out), out);
    return 0x00;
}

/* -------------------------------------------------------------------------
   'i' : build parameters, so the host can assert the firmware matches what the
   campaign script assumes.
   ------------------------------------------------------------------------- */
uint8_t info(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
{
    (void)cmd; (void)scmd; (void)len; (void)in;
    uint8_t out[8];
    out[0] = (uint8_t)CRHBYTES;
    out[1] = (uint8_t)STREAM256_BLOCKBYTES;
    out[2] = (uint8_t)POLY_UNIFORM_GAMMA1_NBLOCKS;
    out[3] = (uint8_t)(POLYZ_PACKEDBYTES & 0xFF);
    out[4] = (uint8_t)((POLYZ_PACKEDBYTES >> 8) & 0xFF);
    out[5] = (uint8_t)(SQUEEZE_BYTES & 0xFF);
    out[6] = (uint8_t)((SQUEEZE_BYTES >> 8) & 0xFF);
    out[7] = reg_status;
    simpleserial_put('r', sizeof(out), out);
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Deterministic default seed so a bare 'g' works before any 's'. */
    for (unsigned i = 0; i < CRHBYTES; i++)
        seed[i] = (uint8_t)i;

    simpleserial_init();
    uint8_t reg = 0;
    reg |= (simpleserial_addcmd('s', CRHBYTES, set_seed)  != 0) << 0;
    reg |= (simpleserial_addcmd('n', 2,        set_nonce) != 0) << 1;
    reg |= (simpleserial_addcmd('g', 0,        run_squeeze) != 0) << 2;
    reg |= (simpleserial_addcmd('b', 1,        get_block) != 0) << 3;
    reg |= (simpleserial_addcmd('k', 32,       shake_kat) != 0) << 4;
    reg |= (simpleserial_addcmd('i', 0,        info)      != 0) << 5;
    reg_status = reg;

    while (1)
        simpleserial_get();
}
