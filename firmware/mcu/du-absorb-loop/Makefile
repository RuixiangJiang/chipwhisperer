TARGET = du-absorb-loop
SRC += du-absorb-loop.c
SRC += fips202.c

PQM4COMMON = $(HOME)/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/common
EXTRAINCDIRS += $(PQM4COMMON)

CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

$(OBJDIR)/fips202.o: $(PQM4COMMON)/fips202.c
	$(CC) -c $(ALL_CFLAGS) $< -o $@
