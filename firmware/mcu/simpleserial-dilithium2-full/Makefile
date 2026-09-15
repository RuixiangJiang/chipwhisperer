# Makefile for simpleserial-dilithium2-full
#
# Builds the complete pqm4 Round 3 Dilithium2 (m4f) implementation --
# keygen, sign and verify -- for a CW308 UFO board with an STM32F405.
#
#   firmware/mcu/simpleserial-dilithium2-full/        <- this directory
#   firmware/pqm4-Round3/crypto_sign/dilithium2/m4f/  <- DILITHIUM_DIR
#
# Prerequisite, done once by hand:
#
#   cp ../../pqm4-Round3/crypto_sign/dilithium2/m4f/vector.s vector_asm.S
#
# vector.s holds pqcrystals_dilithium_asm_{reduce32,caddq,rej_uniform,
# pointwise_montgomery,pointwise_acc_montgomery} and is lowercase in the
# pqm4 tree. Makefile.inc's assembly rule derives its listing path with an
# uppercase-only $(<:%.S=%.lst), so feeding it a lowercase .s leaves the
# name unsubstituted and -adhlns writes an assembler listing over another
# object ("file format not recognized; treating as linker script").
# A local .S copy sidesteps that entirely.
#
# Run `make show-config PLATFORM=CW308_STM32F4` first to check discovery.
#
# Two other non-obvious points:
#
#  1. The m4f assembly uses VFP registers as scratch, so an -mfpu is
#     mandatory. Makefile.inc composes ALL_CFLAGS / ALL_ASFLAGS from
#     MCU_FLAGS + CFLAGS / ASFLAGS at include time, so appending to plain
#     CFLAGS / ASFLAGS after the include has no effect -- the appends must
#     go on ALL_CFLAGS / ALL_ASFLAGS, which the recipes expand when they
#     run. GCC takes the last -mfloat-abi, so 'softfp' overrides the HAL's
#     'soft' while keeping the same calling convention.
#
#  2. pqm4's common/ has its own hal.h, which shadows ChipWhisperer's if
#     it lands early on the include path (symptom: implicit-declaration
#     warnings for platform_init / putch / getch). The pqm4 -I paths go on
#     ALL_CFLAGS, appended after the HAL's EXTRAINCDIRS are already in
#     CFLAGS, so ChipWhisperer's headers win.

TARGET = simpleserial-dilithium2-full

# -Os matches the flag Du et al. used and keeps this comparable to the
# Section 6.4 glitch harness.
OPT = s
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE

# -----------------------------------------------------------------------------
# pqm4 source discovery
# -----------------------------------------------------------------------------
PQM4_ROOT     ?= ../../pqm4-Round3
DILITHIUM_DIR ?= $(PQM4_ROOT)/crypto_sign/dilithium2/m4f

FIPS202_C := $(firstword $(wildcard \
	$(PQM4_ROOT)/mupq/common/fips202.c \
	$(PQM4_ROOT)/common/fips202.c \
	$(DILITHIUM_DIR)/fips202.c))

KECCAK_ASM := $(firstword $(wildcard \
	$(PQM4_ROOT)/common/keccakf1600.S \
	$(DILITHIUM_DIR)/keccakf1600.S))

KECCAK_C := $(firstword $(wildcard \
	$(PQM4_ROOT)/common/keccakf1600.c \
	$(PQM4_ROOT)/mupq/common/keccakf1600.c))

# randombytes() is supplied by the harness, so any randombytes.c in the
# tree is excluded to avoid a duplicate definition.
DIL_C   := $(filter-out %randombytes.c,$(wildcard $(DILITHIUM_DIR)/*.c))
DIL_ASM := $(wildcard $(DILITHIUM_DIR)/*.S)

SRC  += $(TARGET).c
SRC  += $(notdir $(DIL_C))
ASRC += $(notdir $(DIL_ASM))

# Local uppercase copy of the pqm4 tree's lowercase vector.s -- see header.
ASRC += vector_asm.S
ASRC += pointwise_mont_asm.S

ifneq ($(FIPS202_C),)
SRC   += $(notdir $(FIPS202_C))
VPATH += $(dir $(FIPS202_C))
endif

ifneq ($(KECCAK_ASM),)
ASRC  += $(notdir $(KECCAK_ASM))
VPATH += $(dir $(KECCAK_ASM))
else ifneq ($(KECCAK_C),)
SRC   += $(notdir $(KECCAK_C))
VPATH += $(dir $(KECCAK_C))
endif

VPATH += $(DILITHIUM_DIR)

# api.h and params.h live here. Safe to put early: no hal.h in this dir.
EXTRAINCDIRS += $(DILITHIUM_DIR)

CDEFS += -DDILITHIUM_MODE=2

# -----------------------------------------------------------------------------
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
# -----------------------------------------------------------------------------

FPU_FLAGS ?= -mfpu=fpv4-sp-d16 -mfloat-abi=softfp

PQM4_INCS = -I$(DILITHIUM_DIR) -I$(dir $(FIPS202_C)) \
            -I$(PQM4_ROOT)/mupq/common -I$(PQM4_ROOT)/common

ALL_CFLAGS  += $(PQM4_INCS)
ALL_ASFLAGS += $(PQM4_INCS)

# VFP only where it is needed: the pqm4 assembly. Applying it globally
# breaks startup -- the HAL and the C runtime must stay plain soft-float.
PQM4_ASM_OBJS = $(OBJDIR)/basemul_257.o $(OBJDIR)/fnt_257.o \
                $(OBJDIR)/ifnt_257.o $(OBJDIR)/ntt.o \
                $(OBJDIR)/vector_asm.o $(OBJDIR)/pointwise_mont_asm.o \
                $(OBJDIR)/keccakf1600.o

$(PQM4_ASM_OBJS): ALL_ASFLAGS += $(FPU_FLAGS)

# -----------------------------------------------------------------------------
.PHONY: show-config
show-config:
	@echo "PQM4_ROOT     = $(PQM4_ROOT)"
	@echo "DILITHIUM_DIR = $(DILITHIUM_DIR)"
	@echo "FIPS202_C     = $(if $(FIPS202_C),$(FIPS202_C),*** NOT FOUND ***)"
	@echo "KECCAK_ASM    = $(if $(KECCAK_ASM),$(KECCAK_ASM),(none))"
	@echo "KECCAK_C      = $(if $(KECCAK_C),$(KECCAK_C),(none))"
	@echo "FPU_FLAGS     = $(FPU_FLAGS)"
	@echo ""
	@echo "dilithium C sources:"
	@for f in $(DIL_C);   do echo "  $$f"; done
	@echo "dilithium ASM sources:"
	@for f in $(DIL_ASM); do echo "  $$f"; done
	@echo ""
	@echo "ASRC = $(ASRC)"
	@echo ""
	@if [ ! -f vector_asm.S ]; then \
		echo "*** vector_asm.S missing. Create it with:"; \
		echo "      cp $(DILITHIUM_DIR)/vector.s vector_asm.S"; \
		exit 1; \
	else echo "vector_asm.S present ($$(wc -l < vector_asm.S) lines)"; fi
	@if [ -z "$(FIPS202_C)" ]; then \
		echo ""; echo "fips202.c not found; try: find $(PQM4_ROOT) -name fips202.c"; \
		exit 1; fi

.PHONY: memreport
memreport:
	@arm-none-eabi-size -A $(TARGET)-$(PLATFORM).elf | head -20
	@echo ""
	@echo "Largest symbols:"
	@arm-none-eabi-nm --size-sort -S -td $(TARGET)-$(PLATFORM).elf | tail -15