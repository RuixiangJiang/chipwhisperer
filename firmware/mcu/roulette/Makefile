KDIR = /home/ruixiang/chipwhisperer/firmware/pqm4-Round3/crypto_kem/kyber768/m4fspeed

TARGET = roulette
SRC  += roulette.c
SRC  += ntt_local.c
ASRC += fastinvntt.S
ASRC += fastntt.S
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1
EXTRAINCDIRS += $(KDIR)

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

$(OBJDIR)/fastinvntt.o: $(KDIR)/fastinvntt.S
	$(CC) -c $(ALL_ASFLAGS) -I$(KDIR) -mfpu=fpv4-sp-d16 -mfloat-abi=softfp $< -o $@
$(OBJDIR)/fastntt.o: $(KDIR)/fastntt.S
	$(CC) -c $(ALL_ASFLAGS) -I$(KDIR) -mfpu=fpv4-sp-d16 -mfloat-abi=softfp $< -o $@
