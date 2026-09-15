#!/usr/bin/env python3
"""Clock-glitch a selected Thumb instruction and compare Cortex-M DWT counters.

Examples:

    python3 run_clock_glitch_hpc.py --instruction add --program
    python3 run_clock_glitch_hpc.py --instruction load --program
    python3 run_clock_glitch_hpc.py --instruction store --program

The firmware returns both the architectural result and the normal/skip reference
values. A matching skip result is a target-skip candidate, not proof that the
physical fault was an ideal single-instruction omission.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import itertools
from pathlib import Path
import random
import statistics
import struct
import sys
import time
from typing import Optional

import chipwhisperer as cw

RESPONSE_LEN = 32
RESPONSE_MAGIC = 0x33435048
PROTOCOL_VERSION = 3
PROJECT_VERSION = "3.1.1"
DEFAULT_INSTRUCTION = "add"

INSTRUCTIONS = {
    "add": 0,
    "sub": 1,
    "xor": 2,
    "and": 3,
    "or": 4,
    "mul": 5,
    "lsl": 6,
    "lsr": 7,
    "neg": 8,
    "mov": 9,
    "load": 10,
    "store": 11,
}

REFERENCE_RESULTS = {
    "add": (17, 10),
    "sub": (17, 20),
    "xor": (0x55, 0x5A),
    "and": (0x18, 0x5A),
    "or": (0x5F, 0x52),
    "mul": (63, 7),
    "lsl": (12, 3),
    "lsr": (5, 40),
    "neg": (0xFFFFFFF9, 7),
    "mov": (42, 17),
    "load": (42, 17),
    "store": (42, 17),
}


@dataclass(frozen=True)
class Sample:
    result: int
    expected_result: int
    target_skip_result: int
    cycles: int
    cpi: int
    exc: int
    sleep: int
    lsu: int
    fold: int
    token: int
    status: int
    instruction_id: int
    protocol_version: int

    @property
    def event_tuple(self) -> tuple[int, int, int, int, int, int]:
        return (self.cycles, self.cpi, self.exc, self.sleep, self.lsu, self.fold)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    p.add_argument(
        "--instruction",
        choices=tuple(INSTRUCTIONS),
        default=DEFAULT_INSTRUCTION,
        help=f"target instruction (default: {DEFAULT_INSTRUCTION})",
    )
    p.add_argument("--list-instructions", action="store_true", help="print targets and exit")
    p.add_argument("--program", action="store_true", help="program firmware before the experiment")
    p.add_argument("--firmware", type=Path, default=None, help="path to the .hex file")
    p.add_argument("--platform", default="CWLITEARM", help="firmware platform suffix")
    p.add_argument("--baseline", type=int, default=200, help="number of no-fault samples")
    p.add_argument("--success-target", type=int, default=50, help="stop after this many target-skip samples; 0 disables")
    p.add_argument("--trials-per-point", type=int, default=3)
    p.add_argument("--max-attempts", type=int, default=50000)
    # Fine CW-Lite defaults: the useful clock-glitch window is often much
    # narrower than a five-unit grid. All values remain CLI-overridable.
    p.add_argument("--offset-start", type=float, default=-45.0)
    p.add_argument("--offset-stop", type=float, default=-30.0)
    p.add_argument("--offset-step", type=float, default=1.0)
    p.add_argument("--width-start", type=float, default=0.10)
    p.add_argument("--width-stop", type=float, default=0.60)
    p.add_argument("--width-step", type=float, default=0.05)
    p.add_argument("--ext-start", type=int, default=0)
    p.add_argument("--ext-stop", type=int, default=40)
    p.add_argument("--ext-step", type=int, default=1)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--randomize", action="store_true", help="shuffle the parameter grid")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--csv", type=Path, default=None, help="CSV path; defaults to instruction-specific name")
    p.add_argument("--adc-timeout", type=float, default=0.25)
    p.add_argument("--serial-timeout", type=float, default=0.25)
    p.add_argument("--reset-delay", type=float, default=0.05)
    return p.parse_args()


def print_instruction_table() -> None:
    print("instruction  id  normal_result  target_skip_result")
    for name, instruction_id in INSTRUCTIONS.items():
        normal, skipped = REFERENCE_RESULTS[name]
        print(f"{name:11s} {instruction_id:2d}  0x{normal:08x}     0x{skipped:08x}")


def inclusive_float_range(start: float, stop: float, step: float) -> list[float]:
    if step <= 0:
        raise ValueError("step must be positive")
    values: list[float] = []
    x = start
    epsilon = abs(step) * 1e-9
    while x <= stop + epsilon:
        values.append(round(x, 10))
        x += step
    return values


def inclusive_int_range(start: int, stop: int, step: int) -> list[int]:
    if step <= 0:
        raise ValueError("step must be positive")
    return list(range(start, stop + 1, step))


def project_dir() -> Path:
    return Path(__file__).resolve().parent


def default_firmware(platform: str) -> Path:
    return project_dir() / f"simpleserial-instruction-skip-hpc-{platform}.hex"


def reset_target(scope, target, delay: float) -> None:
    scope.io.nrst = "low"
    time.sleep(0.02)
    scope.io.nrst = "high_z"
    time.sleep(delay)
    target.flush()


def read_response(target, timeout: float) -> Optional[Sample]:
    response = target.simpleserial_read_witherrors(
        "r", RESPONSE_LEN, glitch_timeout=timeout
    )
    if not response or not response.get("valid", False):
        return None

    payload = response.get("payload", b"")
    if payload is None or len(payload) != RESPONSE_LEN:
        return None

    magic, result, expected, skipped, cycles = struct.unpack_from("<IIIII", payload, 0)
    if magic != RESPONSE_MAGIC:
        return None

    cpi, exc, sleep, lsu, fold, token, status, instruction_id = payload[20:28]
    protocol_version = payload[28]
    if protocol_version != PROTOCOL_VERSION:
        return None
    return Sample(
        result,
        expected,
        skipped,
        cycles,
        cpi,
        exc,
        sleep,
        lsu,
        fold,
        token,
        status,
        instruction_id,
        protocol_version,
    )


def classify(sample: Optional[Sample], expected_token: int, instruction_name: str) -> str:
    if sample is None:
        return "invalid_or_reset"

    instruction_id = INSTRUCTIONS[instruction_name]
    reference_expected, reference_skipped = REFERENCE_RESULTS[instruction_name]
    if (
        sample.protocol_version != PROTOCOL_VERSION
        or sample.token != expected_token
        or sample.instruction_id != instruction_id
    ):
        return "stale_or_corrupt"
    if (
        sample.expected_result != reference_expected
        or sample.target_skip_result != reference_skipped
    ):
        return "metadata_corrupt"
    if sample.result == sample.expected_result:
        return "normal"
    if sample.result == sample.target_skip_result:
        return "target_skip_candidate"
    return "other_fault"


def send_no_fault(target, instruction_id: int, token: int, timeout: float) -> Optional[Sample]:
    target.simpleserial_write("g", bytearray([instruction_id, token]))
    return read_response(target, timeout)


def send_glitch(scope, target, instruction_id: int, token: int, timeout: float) -> tuple[Optional[Sample], bool]:
    scope.arm()
    target.simpleserial_write("g", bytearray([instruction_id, token]))
    capture_timed_out = bool(scope.capture())
    if capture_timed_out:
        return None, True
    return read_response(target, timeout), False


def print_distribution(name: str, samples: list[Sample]) -> None:
    if not samples:
        print(f"[{name}] no valid samples")
        return

    cycles = [s.cycles for s in samples]
    tuples = [s.event_tuple for s in samples]
    modes = statistics.multimode(cycles)
    stdev = statistics.pstdev(cycles) if len(cycles) > 1 else 0.0
    print(
        f"[{name}] n={len(samples)} cycles: min={min(cycles)} max={max(cycles)} "
        f"median={statistics.median(cycles)} mode={modes} pstdev={stdev:.3f} "
        f"unique_cycle_values={sorted(set(cycles))} unique_event_tuples={len(set(tuples))}"
    )


def main() -> int:
    args = parse_args()
    if args.list_instructions:
        print_instruction_table()
        return 0
    if args.baseline <= 0:
        raise ValueError("--baseline must be positive")
    if args.trials_per_point <= 0:
        raise ValueError("--trials-per-point must be positive")

    instruction_id = INSTRUCTIONS[args.instruction]
    expected_result, target_skip_result = REFERENCE_RESULTS[args.instruction]
    firmware = (args.firmware or default_firmware(args.platform)).resolve()
    if args.program and not firmware.is_file():
        raise FileNotFoundError(f"firmware not found: {firmware}")

    csv_path = args.csv or Path(f"instruction_skip_hpc_{args.instruction}.csv")
    csv_path = csv_path.resolve()
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[host] project_version={PROJECT_VERSION} protocol={PROTOCOL_VERSION}")
    print(f"[firmware] path={firmware}")
    print(
        f"[target] instruction={args.instruction} id={instruction_id} "
        f"normal=0x{expected_result:08x} target_skip=0x{target_skip_result:08x}"
    )

    scope = None
    target = None
    baseline_samples: list[Sample] = []
    target_skip_samples: list[Sample] = []
    counters = {
        "normal": 0,
        "target_skip_candidate": 0,
        "other_fault": 0,
        "invalid_or_reset": 0,
        "stale_or_corrupt": 0,
        "metadata_corrupt": 0,
    }

    fieldnames = [
        "phase", "instruction", "instruction_id", "attempt", "offset", "width",
        "ext_offset", "repeat", "classification", "result", "expected_result",
        "target_skip_result", "cycles", "cpi", "exc", "sleep", "lsu", "fold",
        "token", "status", "protocol_version", "capture_timeout",
    ]

    try:
        scope = cw.scope()
        target = cw.target(scope, cw.targets.SimpleSerial2)
        scope.default_setup()
        scope.adc.timeout = args.adc_timeout

        if args.program:
            print(f"[program] {firmware}")
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(firmware))
            time.sleep(0.2)

        scope.io.hs2 = "clkgen"
        reset_target(scope, target, args.reset_delay)

        with csv_path.open("w", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=fieldnames)
            writer.writeheader()

            print(f"[baseline] collecting {args.baseline} no-fault samples")
            token = 0
            baseline_attempts = 0
            baseline_attempt_limit = max(args.baseline * 20, args.baseline + 20)
            while len(baseline_samples) < args.baseline:
                baseline_attempts += 1
                if baseline_attempts > baseline_attempt_limit:
                    raise RuntimeError(
                        "Unable to collect a stable no-fault baseline. Check the firmware, "
                        "SimpleSerial version, target clock, and reset wiring."
                    )
                token = (token + 1) & 0xFF
                sample = send_no_fault(target, instruction_id, token, args.serial_timeout)
                label = classify(sample, token, args.instruction)
                if sample is None or label in {
                    "invalid_or_reset", "stale_or_corrupt", "metadata_corrupt"
                }:
                    reset_target(scope, target, args.reset_delay)
                    continue

                writer.writerow({
                    "phase": "baseline",
                    "instruction": args.instruction,
                    "instruction_id": instruction_id,
                    "attempt": len(baseline_samples),
                    "offset": "",
                    "width": "",
                    "ext_offset": "",
                    "repeat": "",
                    "classification": label,
                    "result": sample.result,
                    "expected_result": sample.expected_result,
                    "target_skip_result": sample.target_skip_result,
                    "cycles": sample.cycles,
                    "cpi": sample.cpi,
                    "exc": sample.exc,
                    "sleep": sample.sleep,
                    "lsu": sample.lsu,
                    "fold": sample.fold,
                    "token": sample.token,
                    "status": sample.status,
                    "protocol_version": sample.protocol_version,
                    "capture_timeout": 0,
                })
                if label != "normal":
                    print(
                        f"[baseline warning] instruction={args.instruction} "
                        f"unexpected result=0x{sample.result:08x}; retaining it in CSV"
                    )
                else:
                    baseline_samples.append(sample)

            fp.flush()
            print_distribution(f"baseline-{args.instruction}", baseline_samples)

            scope.glitch.clk_src = "clkgen"
            scope.glitch.output = "clock_xor"
            scope.glitch.trigger_src = "ext_single"
            scope.glitch.repeat = args.repeat
            scope.io.hs2 = "glitch"
            reset_target(scope, target, args.reset_delay)

            offsets = inclusive_float_range(args.offset_start, args.offset_stop, args.offset_step)
            widths = inclusive_float_range(args.width_start, args.width_stop, args.width_step)
            ext_offsets = inclusive_int_range(args.ext_start, args.ext_stop, args.ext_step)
            params = list(itertools.product(offsets, widths, ext_offsets))
            if args.randomize:
                random.Random(args.seed).shuffle(params)

            baseline_cycle_set = {s.cycles for s in baseline_samples}
            baseline_tuple_set = {s.event_tuple for s in baseline_samples}
            attempt = 0
            stop = False

            print(
                f"[scan] {len(params)} parameter points x {args.trials_per_point} trials; "
                f"max_attempts={args.max_attempts}, success_target={args.success_target}"
            )

            for offset, width, ext_offset in params:
                scope.glitch.offset = offset
                scope.glitch.width = width
                scope.glitch.ext_offset = ext_offset
                scope.glitch.repeat = args.repeat

                for _ in range(args.trials_per_point):
                    if args.max_attempts > 0 and attempt >= args.max_attempts:
                        stop = True
                        break
                    if args.success_target > 0 and len(target_skip_samples) >= args.success_target:
                        stop = True
                        break

                    attempt += 1
                    token = (token + 1) & 0xFF
                    sample, capture_timeout = send_glitch(
                        scope, target, instruction_id, token, args.serial_timeout
                    )
                    label = classify(sample, token, args.instruction)
                    counters[label] += 1

                    row = {
                        "phase": "glitch",
                        "instruction": args.instruction,
                        "instruction_id": instruction_id,
                        "attempt": attempt,
                        "offset": offset,
                        "width": width,
                        "ext_offset": ext_offset,
                        "repeat": args.repeat,
                        "classification": label,
                        "result": "",
                        "expected_result": expected_result,
                        "target_skip_result": target_skip_result,
                        "cycles": "",
                        "cpi": "",
                        "exc": "",
                        "sleep": "",
                        "lsu": "",
                        "fold": "",
                        "token": token,
                        "status": "",
                        "protocol_version": "",
                        "capture_timeout": int(capture_timeout),
                    }
                    if sample is not None:
                        row.update({
                            "result": sample.result,
                            "expected_result": sample.expected_result,
                            "target_skip_result": sample.target_skip_result,
                            "cycles": sample.cycles,
                            "cpi": sample.cpi,
                            "exc": sample.exc,
                            "sleep": sample.sleep,
                            "lsu": sample.lsu,
                            "fold": sample.fold,
                            "token": sample.token,
                            "status": sample.status,
                            "instruction_id": sample.instruction_id,
                            "protocol_version": sample.protocol_version,
                        })
                    writer.writerow(row)

                    if label == "target_skip_candidate" and sample is not None:
                        target_skip_samples.append(sample)
                        cycle_overlap = sample.cycles in baseline_cycle_set
                        tuple_overlap = sample.event_tuple in baseline_tuple_set
                        print(
                            "[TARGET-SKIP] "
                            f"instruction={args.instruction} n={len(target_skip_samples)} "
                            f"attempt={attempt} offset={offset} width={width} "
                            f"ext_offset={ext_offset} result=0x{sample.result:08x} "
                            f"cycles={sample.cycles} cpi={sample.cpi} exc={sample.exc} "
                            f"sleep={sample.sleep} lsu={sample.lsu} fold={sample.fold} "
                            f"cycle_seen_in_baseline={cycle_overlap} "
                            f"full_tuple_seen_in_baseline={tuple_overlap}"
                        )
                        fp.flush()

                    if label in {
                        "invalid_or_reset", "stale_or_corrupt", "metadata_corrupt"
                    }:
                        scope.io.hs2 = "clkgen"
                        reset_target(scope, target, args.reset_delay)
                        scope.io.hs2 = "glitch"
                        reset_target(scope, target, args.reset_delay)

                if stop:
                    break

            fp.flush()

        print("\n[summary]")
        print(f"instruction={args.instruction} attempts={sum(counters.values())}")
        for key, value in counters.items():
            print(f"  {key}: {value}")
        print_distribution(f"target-skip-{args.instruction}", target_skip_samples)

        if target_skip_samples:
            baseline_cycle_set = {s.cycles for s in baseline_samples}
            baseline_tuple_set = {s.event_tuple for s in baseline_samples}
            cycle_overlap_count = sum(s.cycles in baseline_cycle_set for s in target_skip_samples)
            tuple_overlap_count = sum(s.event_tuple in baseline_tuple_set for s in target_skip_samples)
            baseline_median = statistics.median(s.cycles for s in baseline_samples)
            skip_median = statistics.median(s.cycles for s in target_skip_samples)
            print(
                f"cycle overlap with baseline: {cycle_overlap_count}/{len(target_skip_samples)} "
                f"({100.0 * cycle_overlap_count / len(target_skip_samples):.1f}%)"
            )
            print(
                f"full DWT tuple overlap with baseline: {tuple_overlap_count}/{len(target_skip_samples)} "
                f"({100.0 * tuple_overlap_count / len(target_skip_samples):.1f}%)"
            )
            print(f"median cycle delta (skip - baseline): {skip_median - baseline_median}")
        else:
            print(
                f"No {args.instruction} target-skip samples were found. Narrow the "
                "parameter ranges around promising faults or increase --max-attempts."
            )

        print(f"CSV: {csv_path}")
        return 0

    finally:
        if target is not None:
            try:
                target.dis()
            except Exception:
                pass
        if scope is not None:
            try:
                scope.io.hs2 = "clkgen"
            except Exception:
                pass
            try:
                scope.dis()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        raise SystemExit(130)
