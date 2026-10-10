TARGET = krahmer
SRC += krahmer.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

$(OBJDIR)/krahmer.o: krahmer.c
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops -fno-if-conversion -fno-if-conversion2 $< -o $@
