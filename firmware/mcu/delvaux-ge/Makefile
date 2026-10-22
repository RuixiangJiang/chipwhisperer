TARGET = delvaux_ge
SRC += delvaux_ge.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1
include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
$(OBJDIR)/delvaux_ge.o: delvaux_ge.c zetas.inc
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops $< -o $@
