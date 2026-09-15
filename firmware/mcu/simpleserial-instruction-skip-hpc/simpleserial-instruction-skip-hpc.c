/*
 * Configurable Cortex-M instruction-skip / DWT-counter experiment.
 *
 * The firmware contains one naked Thumb function per target instruction. The
 * operands and memory sentinel are prepared before trigger_high(), while the
 * target function and its call/return execute inside the trigger window.
 *
 * A returned target-skip value is evidence consistent with the selected
 * instruction not taking effect; a physical clock glitch can also produce
 * other microarchitectural or architectural effects.
 */

#include "hal.h"
#include "simpleserial.h"

#include <stdint.h>

#define DEMCR_REG        (*(volatile uint32_t *)0xE000EDFCUL)
#define DWT_CTRL_REG     (*(volatile uint32_t *)0xE0001000UL)
#define DWT_CYCCNT_REG   (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CPICNT_REG   (*(volatile uint32_t *)0xE0001008UL)
#define DWT_EXCCNT_REG   (*(volatile uint32_t *)0xE000100CUL)
#define DWT_SLEEPCNT_REG (*(volatile uint32_t *)0xE0001010UL)
#define DWT_LSUCNT_REG   (*(volatile uint32_t *)0xE0001014UL)
#define DWT_FOLDCNT_REG  (*(volatile uint32_t *)0xE0001018UL)

#define DEMCR_TRCENA         (1UL << 24)
#define DWT_CTRL_CYCCNTENA   (1UL << 0)
#define DWT_CTRL_CPIEVTENA   (1UL << 17)
#define DWT_CTRL_EXCEVTENA   (1UL << 18)
#define DWT_CTRL_SLEEPEVTENA (1UL << 19)
#define DWT_CTRL_LSUEVTENA   (1UL << 20)
#define DWT_CTRL_FOLDEVTENA  (1UL << 21)
#define DWT_CTRL_EVENT_MASK  (DWT_CTRL_CPIEVTENA | DWT_CTRL_EXCEVTENA | \
                              DWT_CTRL_SLEEPEVTENA | DWT_CTRL_LSUEVTENA | \
                              DWT_CTRL_FOLDEVTENA)
#define DWT_CTRL_NOPRFCNT    (1UL << 24)
#define DWT_CTRL_NOCYCCNT    (1UL << 25)

#define RESPONSE_LEN   32U
#define RESPONSE_MAGIC 0x33435048UL /* "HPC3" in little endian */
#define PROTOCOL_VERSION 3U

#define STATUS_DWT_ENABLED                 (1U << 0)
#define STATUS_CYCCNT_AVAILABLE            (1U << 1)
#define STATUS_EXPECTED_RESULT             (1U << 2)
#define STATUS_TARGET_SKIP_RESULT          (1U << 3)
#define STATUS_EVENT_COUNTERS_ENABLED      (1U << 4)
#define STATUS_PROFILE_COUNTERS_AVAILABLE  (1U << 5)
#define STATUS_VALID_INSTRUCTION           (1U << 6)

#define INSN_ADD   0U
#define INSN_SUB   1U
#define INSN_XOR   2U
#define INSN_AND   3U
#define INSN_OR    4U
#define INSN_MUL   5U
#define INSN_LSL   6U
#define INSN_LSR   7U
#define INSN_NEG   8U
#define INSN_MOV   9U
#define INSN_LOAD  10U
#define INSN_STORE 11U

#define SLOT_SKIP_VALUE   17U
#define SLOT_NORMAL_VALUE 42U

#define TARGET_ATTR __attribute__((naked, noinline, used, aligned(16)))

typedef uint32_t (*target_fn_t)(uint32_t arg0, uint32_t arg1);

typedef struct {
    target_fn_t fn;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t slot_initial;
    uint32_t expected_result;
    uint32_t target_skip_result;
    uint8_t result_from_slot;
} target_spec_t;

static volatile uint32_t memory_slot;

/*
 * Keep a human-readable build marker in the linked ELF.  Merely applying
 * __attribute__((used)) to an unreferenced static object is not sufficient
 * when the ChipWhisperer linker uses --gc-sections: the compiler emits the
 * object, but the linker may still discard its section.  This object has
 * external linkage and main() contains an assembler reference to it.
 */
__attribute__((used, aligned(4)))
const char instruction_skip_hpc_build_id[] =
    "instruction-skip-hpc-v3.1.1";

static inline void retain_build_id_in_elf(void)
{
    __asm volatile ("" : : "r" (instruction_skip_hpc_build_id) : "memory");
}

static inline void compiler_barrier(void)
{
    __asm volatile ("" ::: "memory");
}

static inline uint32_t irq_save_and_disable(void)
{
    uint32_t primask;
    __asm volatile (
        "mrs %0, primask\n"
        "cpsid i\n"
        : "=r" (primask)
        :
        : "memory"
    );
    return primask;
}

static inline void irq_restore(uint32_t primask)
{
    if ((primask & 1U) == 0U) {
        __asm volatile ("cpsie i" ::: "memory");
    }
}

static inline void dwt_enable(void)
{
    DEMCR_REG |= DEMCR_TRCENA;
    DWT_CTRL_REG |= (DWT_CTRL_CYCCNTENA | DWT_CTRL_EVENT_MASK);
    __asm volatile ("dsb\n\tisb" ::: "memory");
}

static inline void dwt_reset_counters(void)
{
    DWT_CYCCNT_REG = 0U;
    DWT_CPICNT_REG = 0U;
    DWT_EXCCNT_REG = 0U;
    DWT_SLEEPCNT_REG = 0U;
    DWT_LSUCNT_REG = 0U;
    DWT_FOLDCNT_REG = 0U;
    __asm volatile ("dsb\n\tisb" ::: "memory");
}

static inline void put_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 0);
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

/*
 * For arithmetic targets, arg0 and arg1 arrive in r0/r1. Therefore each
 * function contains only the selected instruction followed by BX LR.
 *
 * LOAD uses r0 as the preloaded skip sentinel and r1 as the memory address.
 * STORE uses r0 as the address and r1 as the value. Its architectural result
 * is read from memory after trigger_low(), outside the fault window.
 */

TARGET_ATTR uint32_t target_add(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_add\n"
        "instruction_skip_site_add:\n"
        "adds r0, r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_sub(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_sub\n"
        "instruction_skip_site_sub:\n"
        "subs r0, r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_xor(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_xor\n"
        "instruction_skip_site_xor:\n"
        "eors r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_and(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_and\n"
        "instruction_skip_site_and:\n"
        "ands r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_or(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_or\n"
        "instruction_skip_site_or:\n"
        "orrs r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_mul(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_mul\n"
        "instruction_skip_site_mul:\n"
        "muls r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_lsl(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_lsl\n"
        "instruction_skip_site_lsl:\n"
        "lsls r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_lsr(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_lsr\n"
        "instruction_skip_site_lsr:\n"
        "lsrs r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_neg(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_neg\n"
        "instruction_skip_site_neg:\n"
        "rsbs r0, r0, #0\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_mov(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_mov\n"
        "instruction_skip_site_mov:\n"
        "mov r0, r1\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_load(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_load\n"
        "instruction_skip_site_load:\n"
        "ldr r0, [r1, #0]\n"
        "bx lr\n"
    );
}

TARGET_ATTR uint32_t target_store(uint32_t arg0, uint32_t arg1)
{
    __asm volatile (
        ".syntax unified\n"
        ".thumb\n"
        ".global instruction_skip_site_store\n"
        "instruction_skip_site_store:\n"
        "str r1, [r0, #0]\n"
        "bx lr\n"
    );
}

static uint8_t select_target(uint8_t instruction_id, target_spec_t *spec)
{
    spec->result_from_slot = 0U;
    spec->slot_initial = 0U;

    switch (instruction_id) {
    case INSN_ADD:
        spec->fn = target_add;
        spec->arg0 = 10U;
        spec->arg1 = 7U;
        spec->expected_result = 17U;
        spec->target_skip_result = 10U;
        return 1U;
    case INSN_SUB:
        spec->fn = target_sub;
        spec->arg0 = 20U;
        spec->arg1 = 3U;
        spec->expected_result = 17U;
        spec->target_skip_result = 20U;
        return 1U;
    case INSN_XOR:
        spec->fn = target_xor;
        spec->arg0 = 0x5AU;
        spec->arg1 = 0x0FU;
        spec->expected_result = 0x55U;
        spec->target_skip_result = 0x5AU;
        return 1U;
    case INSN_AND:
        spec->fn = target_and;
        spec->arg0 = 0x5AU;
        spec->arg1 = 0x3CU;
        spec->expected_result = 0x18U;
        spec->target_skip_result = 0x5AU;
        return 1U;
    case INSN_OR:
        spec->fn = target_or;
        spec->arg0 = 0x52U;
        spec->arg1 = 0x0DU;
        spec->expected_result = 0x5FU;
        spec->target_skip_result = 0x52U;
        return 1U;
    case INSN_MUL:
        spec->fn = target_mul;
        spec->arg0 = 7U;
        spec->arg1 = 9U;
        spec->expected_result = 63U;
        spec->target_skip_result = 7U;
        return 1U;
    case INSN_LSL:
        spec->fn = target_lsl;
        spec->arg0 = 3U;
        spec->arg1 = 2U;
        spec->expected_result = 12U;
        spec->target_skip_result = 3U;
        return 1U;
    case INSN_LSR:
        spec->fn = target_lsr;
        spec->arg0 = 40U;
        spec->arg1 = 3U;
        spec->expected_result = 5U;
        spec->target_skip_result = 40U;
        return 1U;
    case INSN_NEG:
        spec->fn = target_neg;
        spec->arg0 = 7U;
        spec->arg1 = 0U;
        spec->expected_result = 0xFFFFFFF9UL;
        spec->target_skip_result = 7U;
        return 1U;
    case INSN_MOV:
        spec->fn = target_mov;
        spec->arg0 = SLOT_SKIP_VALUE;
        spec->arg1 = SLOT_NORMAL_VALUE;
        spec->expected_result = SLOT_NORMAL_VALUE;
        spec->target_skip_result = SLOT_SKIP_VALUE;
        return 1U;
    case INSN_LOAD:
        spec->fn = target_load;
        spec->slot_initial = SLOT_NORMAL_VALUE;
        spec->arg0 = SLOT_SKIP_VALUE;
        spec->arg1 = (uint32_t)&memory_slot;
        spec->expected_result = SLOT_NORMAL_VALUE;
        spec->target_skip_result = SLOT_SKIP_VALUE;
        return 1U;
    case INSN_STORE:
        spec->fn = target_store;
        spec->slot_initial = SLOT_SKIP_VALUE;
        spec->arg0 = (uint32_t)&memory_slot;
        spec->arg1 = SLOT_NORMAL_VALUE;
        spec->expected_result = SLOT_NORMAL_VALUE;
        spec->target_skip_result = SLOT_SKIP_VALUE;
        spec->result_from_slot = 1U;
        return 1U;
    default:
        /* A deterministic fallback lets the host receive diagnostic metadata. */
        spec->fn = target_add;
        spec->arg0 = 10U;
        spec->arg1 = 7U;
        spec->expected_result = 17U;
        spec->target_skip_result = 10U;
        return 0U;
    }
}

static void measure_target(uint8_t instruction_id, uint8_t token,
                           uint8_t response[RESPONSE_LEN])
{
    target_spec_t spec;
    uint32_t start_cycles;
    uint32_t end_cycles;
    uint32_t raw_result;
    uint32_t result;
    uint32_t primask;
    uint8_t status = 0U;
    uint8_t valid_instruction;
    uint8_t i;

    valid_instruction = select_target(instruction_id, &spec);
    if (valid_instruction != 0U) {
        status |= STATUS_VALID_INSTRUCTION;
    }

    /* All operand/memory setup is outside the fault window. */
    memory_slot = spec.slot_initial;
    compiler_barrier();

    dwt_enable();
    if ((DWT_CTRL_REG & DWT_CTRL_CYCCNTENA) != 0U) {
        status |= STATUS_DWT_ENABLED;
    }
    if ((DWT_CTRL_REG & DWT_CTRL_NOCYCCNT) == 0U) {
        status |= STATUS_CYCCNT_AVAILABLE;
    }
    if ((DWT_CTRL_REG & DWT_CTRL_NOPRFCNT) == 0U) {
        status |= STATUS_PROFILE_COUNTERS_AVAILABLE;
    }
    if (((DWT_CTRL_REG & DWT_CTRL_NOPRFCNT) == 0U) &&
        ((DWT_CTRL_REG & DWT_CTRL_EVENT_MASK) == DWT_CTRL_EVENT_MASK)) {
        status |= STATUS_EVENT_COUNTERS_ENABLED;
    }

    primask = irq_save_and_disable();
    dwt_reset_counters();

    start_cycles = DWT_CYCCNT_REG;
    compiler_barrier();
    trigger_high();
    raw_result = spec.fn(spec.arg0, spec.arg1);
    trigger_low();
    compiler_barrier();
    end_cycles = DWT_CYCCNT_REG;

    /* STORE is observed through memory only after the trigger goes low. */
    result = (spec.result_from_slot != 0U) ? memory_slot : raw_result;

    if (result == spec.expected_result) {
        status |= STATUS_EXPECTED_RESULT;
    }
    if (result == spec.target_skip_result) {
        status |= STATUS_TARGET_SKIP_RESULT;
    }

    put_u32_le(&response[0], RESPONSE_MAGIC);
    put_u32_le(&response[4], result);
    put_u32_le(&response[8], spec.expected_result);
    put_u32_le(&response[12], spec.target_skip_result);
    put_u32_le(&response[16], end_cycles - start_cycles);
    response[20] = (uint8_t)(DWT_CPICNT_REG & 0xFFU);
    response[21] = (uint8_t)(DWT_EXCCNT_REG & 0xFFU);
    response[22] = (uint8_t)(DWT_SLEEPCNT_REG & 0xFFU);
    response[23] = (uint8_t)(DWT_LSUCNT_REG & 0xFFU);
    response[24] = (uint8_t)(DWT_FOLDCNT_REG & 0xFFU);
    response[25] = token;
    response[26] = status;
    response[27] = instruction_id;
    response[28] = PROTOCOL_VERSION;
    response[29] = 1U; /* firmware ABI minor */
    response[30] = 0U;
    response[31] = 0U;

    irq_restore(primask);
}

#if SS_VER == SS_VER_2_1
static uint8_t run_experiment(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *in)
#else
static uint8_t run_experiment(uint8_t *in, uint8_t len)
#endif
{
    uint8_t response[RESPONSE_LEN];
    uint8_t instruction_id = INSN_ADD;
    uint8_t token = 0U;

#if SS_VER == SS_VER_2_1
    (void)cmd;
    (void)scmd;
#endif

    if ((len >= 2U) && (in != 0)) {
        instruction_id = in[0];
        token = in[1];
    }

    measure_target(instruction_id, token, response);
    simpleserial_put('r', RESPONSE_LEN, response);
    return 0x00;
}

int main(void)
{
    /* Create a live relocation so --gc-sections cannot discard the build ID. */
    retain_build_id_in_elf();

    platform_init();
    init_uart();
    trigger_setup();
    dwt_enable();

    simpleserial_init();
    simpleserial_addcmd('g', 2, run_experiment);

    while (1) {
        simpleserial_get();
    }
}
