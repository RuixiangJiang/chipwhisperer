# Makefile for simpleserial-round3dilithium2m4f
#
# Builds the Section 6.4 harness against the pqm4 Round 3 Dilithium2 m4f tree.
#
#   firmware/mcu/simpleserial-round3dilithium2m4f/   <- this directory
#   firmware/pqm4-Round3/crypto_sign/dilithium2/m4f/ <- DILITHIUM_DIR
#
# Only the SHAKE256 squeeze path is compiled: fips202 (plus the Keccak
# permutation, in assembly where pqm4 provides one) and Dilithium's
# symmetric-shake.c. The NTT assembly is deliberately excluded -- it is never
# called by the harness, and leaving it out avoids the FPU/float-ABI mismatch
# between pqm4's m4f sources and the ChipWhisperer STM32F4 HAL.
#
# Run `make show-config` first: it prints which pqm4 files were located, so a
# tree layout different from the one assumed here fails loudly instead of
# silently linking the wrong Keccak.

TARGET = simpleserial-round3dilithium2m4f

# -Os matches the compilation flag used throughout Du et al.; the assembly in
# their Fig. 12 will not correspond at any other optimization level.
OPT = s
SS_VER ?= SS_VER_2_1

# -----------------------------------------------------------------------------
# pqm4 source discovery
# -----------------------------------------------------------------------------
PQM4_ROOT     ?= ../../pqm4-Round3
DILITHIUM_DIR ?= $(PQM4_ROOT)/crypto_sign/dilithium2/m4f

# fips202.c: keccak_inc_squeeze and KeccakF1600_StateExtractBytes live here.
FIPS202_CANDIDATES = \
	$(DILITHIUM_DIR)/fips202.c \
	$(PQM4_ROOT)/common/fips202.c \
	$(PQM4_ROOT)/mupq/common/fips202.c \
	$(PQM4_ROOT)/crypto_hashes/fips202/fips202.c
FIPS202_C := $(firstword $(wildcard $(FIPS202_CANDIDATES)))

# Keccak-f[1600] permutation: assembly on M4 when present, C otherwise.
KECCAK_ASM_CANDIDATES = \
	$(PQM4_ROOT)/common/keccakf1600.S \
	$(DILITHIUM_DIR)/keccakf1600.S \
	$(PQM4_ROOT)/mupq/common/keccakf1600.S
KECCAK_ASM := $(firstword $(wildcard $(KECCAK_ASM_CANDIDATES)))

KECCAK_C_CANDIDATES = \
	$(PQM4_ROOT)/common/keccakf1600.c \
	$(PQM4_ROOT)/mupq/common/keccakf1600.c
KECCAK_C := $(firstword $(wildcard $(KECCAK_C_CANDIDATES)))

# Dilithium's stream256_* glue (dilithium_shake256_stream_init).
SYMMETRIC_C := $(firstword $(wildcard \
	$(DILITHIUM_DIR)/symmetric-shake.c \
	$(DILITHIUM_DIR)/symmetric.c))

# -----------------------------------------------------------------------------
# assemble the source list
# -----------------------------------------------------------------------------
SRC += $(TARGET).c

ifneq ($(FIPS202_C),)
SRC     += $(notdir $(FIPS202_C))
VPATH   += $(dir $(FIPS202_C))
endif

ifneq ($(SYMMETRIC_C),)
SRC     += $(notdir $(SYMMETRIC_C))
VPATH   += $(dir $(SYMMETRIC_C))
endif

ifneq ($(KECCAK_ASM),)
ASRC    += $(notdir $(KECCAK_ASM))
VPATH   += $(dir $(KECCAK_ASM))
else ifneq ($(KECCAK_C),)
SRC     += $(notdir $(KECCAK_C))
VPATH   += $(dir $(KECCAK_C))
endif

VPATH += $(DILITHIUM_DIR)

EXTRAINCDIRS += $(DILITHIUM_DIR)
EXTRAINCDIRS += $(PQM4_ROOT)/common
EXTRAINCDIRS += $(PQM4_ROOT)/mupq/common
EXTRAINCDIRS += $(dir $(FIPS202_C))

# pqm4 headers occasionally expect these; harmless if already defined.
CDEFS += -DDILITHIUM_MODE=2

CRYPTO_TARGET = NONE

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# -----------------------------------------------------------------------------
# diagnostics
# -----------------------------------------------------------------------------
.PHONY: show-config
show-config:
	@echo "PQM4_ROOT     = $(PQM4_ROOT)"
	@echo "DILITHIUM_DIR = $(DILITHIUM_DIR)"
	@echo "FIPS202_C     = $(if $(FIPS202_C),$(FIPS202_C),*** NOT FOUND ***)"
	@echo "SYMMETRIC_C   = $(if $(SYMMETRIC_C),$(SYMMETRIC_C),*** NOT FOUND ***)"
	@echo "KECCAK_ASM    = $(if $(KECCAK_ASM),$(KECCAK_ASM),(none))"
	@echo "KECCAK_C      = $(if $(KECCAK_C),$(KECCAK_C),(none))"
	@echo "SRC           = $(SRC)"
	@echo "ASRC          = $(ASRC)"
	@echo "VPATH         = $(VPATH)"
	@echo "OPT           = $(OPT)  (must stay 's' to match the paper)"
	@if [ -z "$(FIPS202_C)" ]; then \
		echo ""; \
		echo "fips202.c was not found. Locate it with:"; \
		echo "  find $(PQM4_ROOT) -name fips202.c"; \
		echo "then pass its directory, e.g.:"; \
		echo "  make FIPS202_C=<path>/fips202.c PLATFORM=CW308_STM32F4"; \
		exit 1; \
	fi
