TARGET = keccak-rnd-skip
SRC += keccak-rnd-skip.c
SRC += fips202.c

# <-- set from: find ~/chipwhisperer/firmware/pqm4-Round3 -name 'fips202.*'
PQM4COMMON = $(HOME)/chipwhisperer/firmware/pqm4-Round3/mupq/pqclean/common
EXTRAINCDIRS += $(PQM4COMMON)

CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# explicit rule: bypass CW's path-derived pattern rule
$(OBJDIR)/fips202.o: $(PQM4COMMON)/fips202.c
	$(CC) -c $(ALL_CFLAGS) $< -o $@
