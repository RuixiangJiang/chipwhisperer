TARGET = valsaraj
SRC += valsaraj.c
CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# -fno-ivopts keeps the nonce as its own induction variable instead of letting
# gcc re-derive it from the loop index, which would delete the target add.
$(OBJDIR)/valsaraj.o: valsaraj.c
	$(CC) -c $(ALL_CFLAGS) -fno-unroll-loops -fno-ivopts \
	      -fno-if-conversion -fno-if-conversion2 $< -o $@
