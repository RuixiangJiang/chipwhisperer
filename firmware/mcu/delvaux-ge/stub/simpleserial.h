#include <stdint.h>
void simpleserial_init(void);
int simpleserial_addcmd(char c, unsigned int len, uint8_t (*fp)(uint8_t,uint8_t,uint8_t,uint8_t*));
int simpleserial_put(char c, uint8_t len, uint8_t *buf);
int simpleserial_get(void);
