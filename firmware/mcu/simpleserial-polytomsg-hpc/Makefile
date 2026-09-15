# ChipWhisperer configurable instruction-skip / DWT-counter experiment
TARGET = simpleserial-polytomsg-hpc
SRC += simpleserial-polytomsg-hpc.c

CRYPTO_TARGET = NONE
SS_VER ?= SS_VER_2_1

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
