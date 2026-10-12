TARGET = wang
SRC += wang.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# The 320 bit commits only exist if the transpose stays a loop.
$(OBJDIR)/wang.o: wang.c
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops -fno-ivopts \
	      -fno-if-conversion -fno-if-conversion2 $< -o $@
