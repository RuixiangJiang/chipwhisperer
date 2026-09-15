# Configurable Cortex-M instruction-skip vs. DWT counters

Generated project version: `3.1.1`; wire protocol: `HPC3`.

This project tests whether a successful clock-glitch outcome consistent with a
selected Thumb instruction not taking effect has a stable hardware-counter
signature on a Cortex-M target.

The default target platform is ChipWhisperer-Lite ARM / CW308 STM32F3
(`PLATFORM=CWLITEARM`, Cortex-M4).

## Supported target instructions

| CLI name | Target Thumb instruction | Normal result | Target-skip result |
|---|---|---:|---:|
| `add` | `adds r0, r0, r1` | 17 | 10 |
| `sub` | `subs r0, r0, r1` | 17 | 20 |
| `xor` | `eors r0, r1` | `0x55` | `0x5a` |
| `and` | `ands r0, r1` | `0x18` | `0x5a` |
| `or` | `orrs r0, r1` | `0x5f` | `0x52` |
| `mul` | `muls r0, r1` | 63 | 7 |
| `lsl` | `lsls r0, r1` | 12 | 3 |
| `lsr` | `lsrs r0, r1` | 5 | 40 |
| `neg` | `rsbs r0, r0, #0` | `0xfffffff9` | 7 |
| `mov` | `mov r0, r1` | 42 | 17 |
| `load` | `ldr r0, [r1, #0]` | 42 | 17 |
| `store` | `str r1, [r0, #0]` | 42 | 17 |

List the same information from the host script:

```bash
python3 run_clock_glitch_hpc.py --list-instructions
```

All target functions are compiled into one firmware. Select one at runtime:

```bash
python3 run_clock_glitch_hpc.py --instruction load
python3 run_clock_glitch_hpc.py --instruction store
python3 run_clock_glitch_hpc.py --instruction mul
```

## Why LOAD and STORE have observable skip outputs

For `load`, memory contains 42 before the trigger window, while `r0` enters the
target function with sentinel 17. Normal execution loads 42; if the labeled
`ldr` does not take effect, `r0` remains 17.

For `store`, memory contains sentinel 17 and `r1` contains 42 before the trigger
window. Normal execution stores 42. The firmware lowers the trigger and then
reads the memory location; if the labeled `str` did not take effect, memory
remains 17. The post-store observation is therefore outside the injected-fault
window.

For arithmetic targets, operands are passed in `r0` and `r1`, so each naked
target function consists of the selected arithmetic instruction followed by
`bx lr`.

A physical clock glitch can cause more than a clean architectural instruction
skip. A matching result is therefore classified as a **target-skip candidate**,
not absolute proof that exactly one instruction was omitted.

## Counters

The firmware reports:

- `CYCCNT`: core cycles
- `CPICNT`: additional CPI cycles
- `EXCCNT`: exception overhead
- `SLEEPCNT`: sleep cycles
- `LSUCNT`: load/store-unit overhead
- `FOLDCNT`: folded instructions

Cortex-M4 does not provide the same generic retired-instruction PMU event used
on many x86 or application-class Arm systems. This experiment asks whether the
available DWT counters change stably for each selected successful fault outcome.

## Build

```bash
cd firmware/mcu/simpleserial-instruction-skip-hpc
make PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 -j
```

Inspect every target function before glitching:

```bash
arm-none-eabi-objdump -d \
  simpleserial-instruction-skip-hpc-CWLITEARM.elf \
  | grep -E '<(target_|instruction_skip_site_|instruction_skip_hpc_build_id)'
```

You should see labels named `instruction_skip_site_add`,
`instruction_skip_site_load`, `instruction_skip_site_store`, and so on. Verify
that every label points directly at the intended instruction. Toolchain changes
must be followed by another disassembly check.

## Run

```bash
python3 run_clock_glitch_hpc.py \
  --instruction add \
  --program \
  --baseline 200 \
  --success-target 50
```

Examples for memory instructions:

```bash
python3 run_clock_glitch_hpc.py --instruction load --program \
  --csv instruction_skip_hpc_load.csv

python3 run_clock_glitch_hpc.py --instruction store --program \
  --csv instruction_skip_hpc_store.csv
```

The default scan uses a fine CW-Lite window (`offset=-45..-30`, step 1; `width=0.10..0.60`, step 0.05; `ext_offset=0..40`). Override these ranges when your board has a different stable glitch window.

The script collects an instruction-specific no-glitch baseline and then scans
clock-glitch parameters. Every target-skip candidate is printed with the full
DWT tuple and whether its cycle value or full tuple appeared in the baseline.

Glitch offsets differ across target functions because their addresses differ.
Do not assume that a parameter found for `add` will target `load` or `store`.
Search each target independently, then fix promising parameters for repeated
measurement:

```bash
python3 run_clock_glitch_hpc.py \
  --instruction store \
  --offset-start 12 --offset-stop 12 \
  --width-start -18 --width-stop -18 \
  --ext-start 9 --ext-stop 9 \
  --trials-per-point 1000 \
  --success-target 0 \
  --max-attempts 1000 \
  --csv fixed_store_setting.csv
```

Replace the example parameters with values found on your board. Results depend
on device, board, target clock, temperature, supply voltage, firmware layout,
and compiler/toolchain version.
