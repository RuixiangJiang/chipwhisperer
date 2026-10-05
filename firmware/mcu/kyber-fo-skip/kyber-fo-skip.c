/* Entry 1 - Xagawa et al. (2021): skip the FO verify() in ML-KEM-512 decap. */
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stddef.h>

extern int verify(const uint8_t *a, const uint8_t *b, size_t len);
#define KYBER512_CT_BYTES 768

#define DEMCR       (*(volatile uint32_t*)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t*)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t*)0xE0001004)
#define DWT_CPICNT  (*(volatile uint32_t*)0xE0001008)
#define DWT_LSUCNT  (*(volatile uint32_t*)0xE0001014)
#define DWT_FOLDCNT (*(volatile uint32_t*)0xE0001018)
#define TRCENA     (1u<<24)
#define CYCCNTENA  (1u<<0)
#define CPIEVTENA  (1u<<17)
#define LSUEVTENA  (1u<<20)
#define FOLDEVTENA (1u<<21)

static const uint8_t a[KYBER512_CT_BYTES] = {0};
static uint8_t b[KYBER512_CT_BYTES] = {0};

static void dwt_reset(void){
    DWT_CYCCNT = 0; DWT_CPICNT = 0; DWT_LSUCNT = 0; DWT_FOLDCNT = 0;
}

static uint8_t do_decap(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf){
    (void)cmd;(void)scmd;(void)len;(void)buf;
    volatile int fail = 0xAA;
    uint32_t cyc,cpi,lsu,fold;

    dwt_reset();
    __asm volatile("cpsid i" ::: "memory");
    trigger_high();
    fail = verify(a, b, KYBER512_CT_BYTES);
    trigger_low();
    cyc = DWT_CYCCNT; cpi = DWT_CPICNT & 0xFF; lsu = DWT_LSUCNT & 0xFF; fold = DWT_FOLDCNT & 0xFF;
    __asm volatile("cpsie i" ::: "memory");

    uint32_t f = (uint32_t)fail;
    uint8_t out[11];
    out[0]=f&0xFF;   out[1]=(f>>8)&0xFF;   out[2]=(f>>16)&0xFF;   out[3]=(f>>24)&0xFF;
    out[4]=cyc&0xFF; out[5]=(cyc>>8)&0xFF; out[6]=(cyc>>16)&0xFF; out[7]=(cyc>>24)&0xFF;
    out[8]=cpi; out[9]=lsu; out[10]=fold;
    simpleserial_put('r', 11, out);
    return 0x00;
}

int main(void){
    platform_init();
    init_uart();
    trigger_setup();
    DEMCR |= TRCENA;
    DWT_CTRL |= CYCCNTENA | CPIEVTENA | LSUEVTENA | FOLDEVTENA;
    b[0] = 0x01;
    simpleserial_init();
    simpleserial_addcmd('d', 0, do_decap);
    while(1) simpleserial_get();
}
