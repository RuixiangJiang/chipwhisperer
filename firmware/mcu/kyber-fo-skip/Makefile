TARGET = kyber-fo-skip
SRC += kyber-fo-skip.c
SRC += verify.c

KYBERDIR = $(HOME)/chipwhisperer/firmware/pqm4-Round3/crypto_kem/kyber512-90s/m4fspeed
EXTRAINCDIRS += $(KYBERDIR)

CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# explicit rule: compile pqm4's verify.c into the object the linker expects,
# bypassing CW's path-derived pattern rule entirely
$(OBJDIR)/verify.o: $(KYBERDIR)/verify.c
	$(CC) -c $(ALL_CFLAGS) $< -o $@
