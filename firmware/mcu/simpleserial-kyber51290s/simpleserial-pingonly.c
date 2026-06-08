#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>


static void uart_puts(const char *s)
{
    while (*s) {
        putch(*s++);
    }
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

    trigger_high();
    trigger_low();

    simpleserial_put('P', 1, out);

    return 0x00;
}

static void enable_fpu(void)
{
    volatile uint32_t *cpacr = (volatile uint32_t *)0xE000ED88U;

    *cpacr |= (0xFU << 20);

    __asm volatile("dsb");
    __asm volatile("isb");
}


int main(void)
{
    enable_fpu();
    
    platform_init();
    init_uart();
    trigger_setup();

    uart_puts("rPINGONLY\n");

    simpleserial_init();
    simpleserial_addcmd('P', 0, cmd_ping);

    while (1) {
        simpleserial_get();
    }

    return 0;
}