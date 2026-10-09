TARGET = nnuo-seed
SRC += nnuo-seed.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

$(OBJDIR)/nnuo-seed.o: nnuo-seed.c
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops -fno-if-conversion -fno-if-conversion2 $< -o $@
