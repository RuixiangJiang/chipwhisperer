TARGET = delvaux_flags
SRC += delvaux_flags.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

$(OBJDIR)/delvaux_flags.o: delvaux_flags.c
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops $< -o $@
