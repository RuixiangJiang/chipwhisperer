TARGET = rej-sampling
SRC += rej-sampling.c

CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# defeat if-conversion so `if (t<Q) a[ctr++]=t;` compiles to a branch over a
# plain str + plain adds, instead of two IT-predicated instructions
$(OBJDIR)/rej-sampling.o: rej-sampling.c
	$(CC) -c $(ALL_CFLAGS) -fno-if-conversion -fno-if-conversion2 $< -o $@

