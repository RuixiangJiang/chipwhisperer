#!/usr/bin/env python3
"""Focused long-duration clock-glitch experiment seeded by prior successful samples.

Place this file next to ``run_clock_glitch_hpc.py`` in the generated
``simpleserial-instruction-skip-hpc`` project. It reuses the firmware protocol
and helper functions from that script.

Typical use:

    python3 run_clock_glitch_hpc_long.py \
        --instruction add \
        --seed-csv instruction_skip_hpc_add.csv \
        --duration-hours 10 \
        --baseline 1000 \
        --output-csv add_hpc_long_10h.csv

The seed CSV is never modified. Exact successful points are sampled most often,
with a smaller fraction of attempts spent in a configurable local neighborhood.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random
import statistics
import sys
import time
from typing import Iterable, Optional

try:
    import run_clock_glitch_hpc as base
except ImportError as exc:
    raise SystemExit(
        "run_clock_glitch_hpc.py was not found. Place this script in the same "
        "simpleserial-instruction-skip-hpc directory."
    ) from exc


LONG_RUN_VERSION = "1.0.0"


@dataclass(frozen=True)
class GlitchPoint:
    offset: float
    width: float
    ext_offset: int
    repeat: int


@dataclass(frozen=True)
class ScheduledPoint:
    point: GlitchPoint
    source: str
    seed_index: int
    weight: float


@dataclass
class Connection:
    scope: object
    target: object


CLASSIFICATIONS = (
    "normal",
    "target_skip_candidate",
    "other_fault",
    "invalid_or_reset",
    "stale_or_corrupt",
    "metadata_corrupt",
    "host_exception",
)


FIELDNAMES = [
    "phase",
    "utc_time",
    "elapsed_s",
    "instruction",
    "instruction_id",
    "attempt",
    "parameter_source",
    "seed_index",
    "offset",
    "width",
    "ext_offset",
    "repeat",
    "classification",
    "result",
    "expected_result",
    "target_skip_result",
    "cycles",
    "cpi",
    "exc",
    "sleep",
    "lsu",
    "fold",
    "token",
    "status",
    "protocol_version",
    "capture_timeout",
    "error",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {LONG_RUN_VERSION}")
    parser.add_argument(
        "--instruction",
        choices=tuple(base.INSTRUCTIONS),
        default=base.DEFAULT_INSTRUCTION,
    )
    parser.add_argument(
        "--seed-csv",
        type=Path,
        default=None,
        help="prior CSV containing target_skip_candidate rows; auto-detected if omitted",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="new long-run CSV; defaults to a timestamped filename",
    )
    parser.add_argument("--append", action="store_true", help="append to an existing output CSV")
    parser.add_argument("--program", action="store_true", help="program firmware at startup")
    parser.add_argument("--firmware", type=Path, default=None)
    parser.add_argument("--platform", default="CWLITEARM")

    parser.add_argument("--duration-hours", type=float, default=10.0)
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=0,
        help="additional stop condition; 0 means no attempt limit",
    )
    parser.add_argument(
        "--success-target",
        type=int,
        default=0,
        help="additional stop condition; 0 means no success limit",
    )

    parser.add_argument("--baseline", type=int, default=1000)
    parser.add_argument(
        "--baseline-refresh-minutes",
        type=float,
        default=60.0,
        help="collect periodic no-fault probes; 0 disables",
    )
    parser.add_argument("--baseline-refresh-samples", type=int, default=100)

    parser.add_argument(
        "--exact-probability",
        type=float,
        default=0.70,
        help="fraction of attempts allocated to exact prior-hit points",
    )
    parser.add_argument(
        "--neighbor-probability",
        type=float,
        default=0.30,
        help="fraction allocated to local-neighbor points",
    )
    parser.add_argument("--offset-radius", type=float, default=1.0)
    parser.add_argument("--offset-step", type=float, default=0.25)
    parser.add_argument("--width-radius", type=float, default=0.10)
    parser.add_argument("--width-step", type=float, default=0.025)
    parser.add_argument("--ext-radius", type=int, default=2)
    parser.add_argument("--ext-step", type=int, default=1)
    parser.add_argument(
        "--seed-top-k",
        type=int,
        default=8,
        help="maximum number of unique successful points used as seeds; 0 uses all",
    )
    parser.add_argument("--random-seed", type=int, default=20260727)

    parser.add_argument("--report-minutes", type=float, default=10.0)
    parser.add_argument("--flush-seconds", type=float, default=15.0)
    parser.add_argument("--summary-json", type=Path, default=None)
    parser.add_argument("--adc-timeout", type=float, default=0.25)
    parser.add_argument("--serial-timeout", type=float, default=0.25)
    parser.add_argument("--reset-delay", type=float, default=0.05)
    parser.add_argument(
        "--reconnect-after-failures",
        type=int,
        default=10,
        help="fully reconnect after this many consecutive invalid/error attempts; 0 disables",
    )
    parser.add_argument(
        "--reprogram-on-reconnect",
        action="store_true",
        help="reflash the firmware after a full reconnect",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show detected seeds and sampled points without connecting to hardware",
    )
    return parser.parse_args()


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_float(value: float) -> float:
    return round(float(value), 10)


def float_values(center: float, radius: float, step: float) -> list[float]:
    if radius < 0 or step <= 0:
        raise ValueError("radius must be nonnegative and step must be positive")
    count = int(math.floor(radius / step + 1e-9))
    values = {normalize_float(center)}
    for index in range(1, count + 1):
        delta = index * step
        values.add(normalize_float(center - delta))
        values.add(normalize_float(center + delta))
    return sorted(values)


def int_values(center: int, radius: int, step: int) -> list[int]:
    if radius < 0 or step <= 0:
        raise ValueError("radius must be nonnegative and step must be positive")
    values = {int(center)}
    for delta in range(step, radius + 1, step):
        values.add(int(center) - delta)
        values.add(int(center) + delta)
    return sorted(value for value in values if value >= 0)


def parse_point(row: dict[str, str]) -> Optional[GlitchPoint]:
    try:
        return GlitchPoint(
            offset=normalize_float(float(row["offset"])),
            width=normalize_float(float(row["width"])),
            ext_offset=int(float(row["ext_offset"])),
            repeat=int(float(row.get("repeat", "1") or "1")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def seed_hits_from_csv(path: Path, instruction: str) -> Counter[GlitchPoint]:
    hits: Counter[GlitchPoint] = Counter()
    with path.open(newline="") as file_pointer:
        for row in csv.DictReader(file_pointer):
            if row.get("instruction") != instruction:
                continue
            if row.get("classification") != "target_skip_candidate":
                continue
            point = parse_point(row)
            if point is not None:
                hits[point] += 1
    return hits


def auto_detect_seed_csv(instruction: str, excluded: Optional[Path]) -> Path:
    candidates: list[tuple[float, int, Path]] = []
    for path in Path.cwd().glob("*.csv"):
        resolved = path.resolve()
        if excluded is not None and resolved == excluded.resolve():
            continue
        try:
            hits = seed_hits_from_csv(resolved, instruction)
        except (OSError, csv.Error, UnicodeError):
            continue
        if hits:
            candidates.append((resolved.stat().st_mtime, sum(hits.values()), resolved))
    if not candidates:
        raise FileNotFoundError(
            f"No CSV with {instruction!r} target_skip_candidate rows was found. "
            "Specify --seed-csv explicitly."
        )
    candidates.sort(reverse=True)
    return candidates[0][2]


def select_seed_points(
    hit_counts: Counter[GlitchPoint], top_k: int
) -> list[tuple[GlitchPoint, int]]:
    ranked = sorted(
        hit_counts.items(),
        key=lambda item: (-item[1], item[0].offset, item[0].width, item[0].ext_offset),
    )
    if top_k > 0:
        ranked = ranked[:top_k]
    return ranked


def build_schedule(
    seeds: list[tuple[GlitchPoint, int]], args: argparse.Namespace
) -> tuple[list[ScheduledPoint], list[float]]:
    if not seeds:
        raise ValueError("At least one successful seed point is required")
    if args.exact_probability < 0 or args.neighbor_probability < 0:
        raise ValueError("probabilities must be nonnegative")
    total_probability = args.exact_probability + args.neighbor_probability
    if total_probability <= 0:
        raise ValueError("exact and neighbor probabilities cannot both be zero")

    exact_mass = args.exact_probability / total_probability
    neighbor_mass = args.neighbor_probability / total_probability

    scheduled: list[ScheduledPoint] = []
    weights: list[float] = []
    total_hits = sum(hit_count for _, hit_count in seeds)

    for seed_index, (seed, hit_count) in enumerate(seeds, start=1):
        seed_share = hit_count / total_hits
        exact_weight = exact_mass * seed_share
        scheduled.append(ScheduledPoint(seed, "seed_exact", seed_index, exact_weight))
        weights.append(exact_weight)

        neighbors: dict[GlitchPoint, float] = {}
        for offset in float_values(seed.offset, args.offset_radius, args.offset_step):
            for width in float_values(seed.width, args.width_radius, args.width_step):
                # CW-Lite percentage representation is nominally constrained to about +/-49.8.
                if not (-49.8 <= offset <= 49.8 and -49.8 <= width <= 49.8):
                    continue
                for ext_offset in int_values(seed.ext_offset, args.ext_radius, args.ext_step):
                    point = GlitchPoint(offset, width, ext_offset, seed.repeat)
                    if point == seed:
                        continue
                    normalized_distance = (
                        abs(offset - seed.offset) / max(args.offset_step, 1e-12)
                        + abs(width - seed.width) / max(args.width_step, 1e-12)
                        + abs(ext_offset - seed.ext_offset) / max(args.ext_step, 1)
                    )
                    # Favor the nearest points without starving the outer neighborhood.
                    neighbors[point] = 1.0 / (1.0 + normalized_distance)

        if neighbor_mass > 0 and neighbors:
            raw_sum = sum(neighbors.values())
            for point, raw_weight in sorted(
                neighbors.items(),
                key=lambda item: (
                    item[0].offset,
                    item[0].width,
                    item[0].ext_offset,
                    item[0].repeat,
                ),
            ):
                weight = neighbor_mass * seed_share * raw_weight / raw_sum
                scheduled.append(ScheduledPoint(point, "seed_neighbor", seed_index, weight))
                weights.append(weight)

    return scheduled, weights


def choose_point(
    rng: random.Random,
    scheduled: list[ScheduledPoint],
    weights: list[float],
) -> ScheduledPoint:
    return rng.choices(scheduled, weights=weights, k=1)[0]


def firmware_path(args: argparse.Namespace) -> Path:
    return (args.firmware or base.default_firmware(args.platform)).resolve()


def connect(args: argparse.Namespace, program: bool) -> Connection:
    scope = base.cw.scope()
    target = base.cw.target(scope, base.cw.targets.SimpleSerial2)
    scope.default_setup()
    scope.adc.timeout = args.adc_timeout
    if program:
        firmware = firmware_path(args)
        if not firmware.is_file():
            raise FileNotFoundError(f"firmware not found: {firmware}")
        print(f"[program] {firmware}")
        base.cw.program_target(
            scope,
            base.cw.programmers.STM32FProgrammer,
            str(firmware),
        )
        time.sleep(0.2)
    scope.io.hs2 = "clkgen"
    base.reset_target(scope, target, args.reset_delay)
    return Connection(scope=scope, target=target)


def disconnect(connection: Optional[Connection]) -> None:
    if connection is None:
        return
    try:
        connection.scope.io.hs2 = "clkgen"
    except Exception:
        pass
    try:
        connection.target.dis()
    except Exception:
        pass
    try:
        connection.scope.dis()
    except Exception:
        pass


def configure_glitch(connection: Connection, point: GlitchPoint) -> None:
    scope = connection.scope
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_single"
    scope.glitch.offset = point.offset
    scope.glitch.width = point.width
    scope.glitch.ext_offset = point.ext_offset
    scope.glitch.repeat = point.repeat
    scope.io.hs2 = "glitch"


def sample_to_row(
    *,
    phase: str,
    elapsed_s: float,
    instruction: str,
    instruction_id: int,
    attempt: int,
    parameter_source: str,
    seed_index: int | str,
    point: Optional[GlitchPoint],
    classification: str,
    expected_result: int,
    target_skip_result: int,
    token: int,
    capture_timeout: bool,
    sample: Optional[base.Sample],
    error: str = "",
) -> dict[str, object]:
    row: dict[str, object] = {
        "phase": phase,
        "utc_time": utc_now_text(),
        "elapsed_s": f"{elapsed_s:.3f}",
        "instruction": instruction,
        "instruction_id": instruction_id,
        "attempt": attempt,
        "parameter_source": parameter_source,
        "seed_index": seed_index,
        "offset": "" if point is None else point.offset,
        "width": "" if point is None else point.width,
        "ext_offset": "" if point is None else point.ext_offset,
        "repeat": "" if point is None else point.repeat,
        "classification": classification,
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
        "error": error,
    }
    if sample is not None:
        row.update(
            {
                "instruction_id": sample.instruction_id,
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
            }
        )
    return row


def collect_baseline(
    *,
    connection: Connection,
    writer: csv.DictWriter,
    file_pointer,
    args: argparse.Namespace,
    count: int,
    phase: str,
    token: int,
    attempt: int,
    start_time: float,
    baseline_samples: list[base.Sample],
) -> int:
    instruction_id = base.INSTRUCTIONS[args.instruction]
    expected_result, target_skip_result = base.REFERENCE_RESULTS[args.instruction]
    scope, target = connection.scope, connection.target
    scope.io.hs2 = "clkgen"
    base.reset_target(scope, target, args.reset_delay)

    collected = 0
    failed = 0
    failure_limit = max(count * 20, count + 20)
    while collected < count:
        if failed > failure_limit:
            raise RuntimeError(f"Unable to collect {phase} baseline")
        token = (token + 1) & 0xFF
        sample = base.send_no_fault(target, instruction_id, token, args.serial_timeout)
        label = base.classify(sample, token, args.instruction)
        if sample is None or label in {
            "invalid_or_reset",
            "stale_or_corrupt",
            "metadata_corrupt",
        }:
            failed += 1
            base.reset_target(scope, target, args.reset_delay)
            continue

        elapsed_s = time.monotonic() - start_time
        writer.writerow(
            sample_to_row(
                phase=phase,
                elapsed_s=elapsed_s,
                instruction=args.instruction,
                instruction_id=instruction_id,
                attempt=attempt,
                parameter_source="no_fault",
                seed_index="",
                point=None,
                classification=label,
                expected_result=expected_result,
                target_skip_result=target_skip_result,
                token=token,
                capture_timeout=False,
                sample=sample,
            )
        )
        if label == "normal":
            baseline_samples.append(sample)
            collected += 1
        else:
            failed += 1
    file_pointer.flush()
    return token


def counter_summary(counter: Counter[str]) -> dict[str, int]:
    return {name: int(counter.get(name, 0)) for name in CLASSIFICATIONS}


def cycle_summary(samples: Iterable[base.Sample]) -> dict[str, object]:
    sample_list = list(samples)
    if not sample_list:
        return {"n": 0}
    cycles = [sample.cycles for sample in sample_list]
    return {
        "n": len(cycles),
        "min": min(cycles),
        "max": max(cycles),
        "median": statistics.median(cycles),
        "mode": statistics.multimode(cycles),
        "pstdev": statistics.pstdev(cycles) if len(cycles) > 1 else 0.0,
        "unique": sorted(set(cycles)),
    }


def write_summary(
    path: Path,
    *,
    args: argparse.Namespace,
    seed_csv: Path,
    output_csv: Path,
    elapsed_s: float,
    attempts: int,
    counters: Counter[str],
    baseline_samples: list[base.Sample],
    target_samples: list[base.Sample],
    parameter_counts: Counter[GlitchPoint],
    parameter_successes: Counter[GlitchPoint],
) -> None:
    baseline_cycle_set = {sample.cycles for sample in baseline_samples}
    baseline_tuple_set = {sample.event_tuple for sample in baseline_samples}
    cycle_overlap = sum(sample.cycles in baseline_cycle_set for sample in target_samples)
    tuple_overlap = sum(sample.event_tuple in baseline_tuple_set for sample in target_samples)

    ranked_points = []
    for point, count in parameter_counts.most_common():
        successes = parameter_successes[point]
        if successes == 0 and len(ranked_points) >= 20:
            continue
        ranked_points.append(
            {
                "offset": point.offset,
                "width": point.width,
                "ext_offset": point.ext_offset,
                "repeat": point.repeat,
                "attempts": count,
                "successes": successes,
                "success_rate": successes / count if count else 0.0,
            }
        )
        if len(ranked_points) >= 50:
            break

    payload = {
        "long_run_version": LONG_RUN_VERSION,
        "base_project_version": base.PROJECT_VERSION,
        "updated_utc": utc_now_text(),
        "instruction": args.instruction,
        "seed_csv": str(seed_csv),
        "output_csv": str(output_csv),
        "elapsed_s": elapsed_s,
        "attempts": attempts,
        "counters": counter_summary(counters),
        "baseline_cycles": cycle_summary(baseline_samples),
        "target_skip_cycles": cycle_summary(target_samples),
        "target_cycle_overlap_count": cycle_overlap,
        "target_tuple_overlap_count": tuple_overlap,
        "parameter_results": ranked_points,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def print_progress(
    *,
    instruction: str,
    elapsed_s: float,
    attempts: int,
    counters: Counter[str],
    baseline_samples: list[base.Sample],
    target_samples: list[base.Sample],
) -> None:
    hours = elapsed_s / 3600.0
    target_count = counters["target_skip_candidate"]
    rate = target_count / attempts if attempts else 0.0
    print(
        f"[progress] elapsed={hours:.2f}h attempts={attempts} "
        f"target_skip={target_count} rate={rate:.6%} "
        f"invalid={counters['invalid_or_reset']} "
        f"metadata_corrupt={counters['metadata_corrupt']}"
    )
    base.print_distribution(f"baseline-{instruction}", baseline_samples)
    base.print_distribution("target-skip-long-run", target_samples)


def validate_args(args: argparse.Namespace) -> None:
    if args.duration_hours <= 0:
        raise ValueError("--duration-hours must be positive")
    if args.baseline <= 0:
        raise ValueError("--baseline must be positive")
    if args.baseline_refresh_minutes < 0 or args.baseline_refresh_samples < 0:
        raise ValueError("baseline refresh values cannot be negative")
    if args.report_minutes <= 0 or args.flush_seconds <= 0:
        raise ValueError("report and flush intervals must be positive")
    if args.max_attempts < 0 or args.success_target < 0:
        raise ValueError("stop limits cannot be negative")


def main() -> int:
    args = parse_args()
    validate_args(args)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_csv = (
        args.output_csv
        or Path(f"instruction_skip_hpc_{args.instruction}_long_{timestamp}.csv")
    ).resolve()
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if output_csv.exists() and not args.append:
        raise FileExistsError(
            f"Output already exists: {output_csv}. Choose another name or use --append."
        )

    seed_csv = (
        args.seed_csv.resolve()
        if args.seed_csv is not None
        else auto_detect_seed_csv(args.instruction, output_csv)
    )
    if not seed_csv.is_file():
        raise FileNotFoundError(f"seed CSV not found: {seed_csv}")
    if seed_csv.resolve() == output_csv.resolve():
        raise ValueError("--seed-csv and --output-csv must be different files")

    hit_counts = seed_hits_from_csv(seed_csv, args.instruction)
    seeds = select_seed_points(hit_counts, args.seed_top_k)
    if not seeds:
        raise RuntimeError(
            f"No {args.instruction} target_skip_candidate parameters in {seed_csv}"
        )
    scheduled, weights = build_schedule(seeds, args)

    print(f"[long-run] version={LONG_RUN_VERSION} base_project={base.PROJECT_VERSION}")
    print(f"[seed-csv] {seed_csv}")
    print(f"[output-csv] {output_csv}")
    print(
        f"[budget] duration={args.duration_hours:.3f}h "
        f"max_attempts={args.max_attempts or 'unlimited'} "
        f"success_target={args.success_target or 'unlimited'}"
    )
    print("[seed points]")
    for index, (point, hits) in enumerate(seeds, start=1):
        print(
            f"  #{index}: offset={point.offset} width={point.width} "
            f"ext_offset={point.ext_offset} repeat={point.repeat} prior_hits={hits}"
        )
    print(
        f"[schedule] entries={len(scheduled)} exact_probability={args.exact_probability} "
        f"neighbor_probability={args.neighbor_probability}"
    )

    rng = random.Random(args.random_seed)
    if args.dry_run:
        print("[dry-run] first 20 scheduled selections:")
        for _ in range(20):
            selected = choose_point(rng, scheduled, weights)
            point = selected.point
            print(
                f"  {selected.source} seed={selected.seed_index} "
                f"offset={point.offset} width={point.width} "
                f"ext_offset={point.ext_offset} repeat={point.repeat}"
            )
        return 0

    instruction_id = base.INSTRUCTIONS[args.instruction]
    expected_result, target_skip_result = base.REFERENCE_RESULTS[args.instruction]
    summary_path = (
        args.summary_json.resolve()
        if args.summary_json is not None
        else output_csv.with_suffix(".summary.json")
    )

    connection: Optional[Connection] = None
    counters: Counter[str] = Counter()
    parameter_counts: Counter[GlitchPoint] = Counter()
    parameter_successes: Counter[GlitchPoint] = Counter()
    baseline_samples: list[base.Sample] = []
    target_samples: list[base.Sample] = []
    token = 0
    attempts = 0
    consecutive_failures = 0
    start_time = time.monotonic()
    deadline = start_time + args.duration_hours * 3600.0
    next_report = start_time + args.report_minutes * 60.0
    next_flush = start_time + args.flush_seconds
    next_baseline_refresh = (
        start_time + args.baseline_refresh_minutes * 60.0
        if args.baseline_refresh_minutes > 0 and args.baseline_refresh_samples > 0
        else math.inf
    )

    file_mode = "a" if args.append else "w"
    write_header = not args.append or not output_csv.exists() or output_csv.stat().st_size == 0

    try:
        connection = connect(args, program=args.program)
        with output_csv.open(file_mode, newline="") as file_pointer:
            writer = csv.DictWriter(file_pointer, fieldnames=FIELDNAMES)
            if write_header:
                writer.writeheader()

            print(f"[baseline] collecting {args.baseline} initial no-fault samples")
            token = collect_baseline(
                connection=connection,
                writer=writer,
                file_pointer=file_pointer,
                args=args,
                count=args.baseline,
                phase="baseline_initial",
                token=token,
                attempt=attempts,
                start_time=start_time,
                baseline_samples=baseline_samples,
            )
            base.print_distribution(f"baseline-{args.instruction}", baseline_samples)

            while True:
                now = time.monotonic()
                if now >= deadline:
                    print("[stop] duration budget reached")
                    break
                if args.max_attempts > 0 and attempts >= args.max_attempts:
                    print("[stop] max-attempts reached")
                    break
                if args.success_target > 0 and len(target_samples) >= args.success_target:
                    print("[stop] success-target reached")
                    break

                if now >= next_baseline_refresh:
                    print(
                        f"[baseline-refresh] collecting "
                        f"{args.baseline_refresh_samples} samples"
                    )
                    token = collect_baseline(
                        connection=connection,
                        writer=writer,
                        file_pointer=file_pointer,
                        args=args,
                        count=args.baseline_refresh_samples,
                        phase="baseline_refresh",
                        token=token,
                        attempt=attempts,
                        start_time=start_time,
                        baseline_samples=baseline_samples,
                    )
                    next_baseline_refresh = (
                        time.monotonic() + args.baseline_refresh_minutes * 60.0
                    )
                    continue

                selected = choose_point(rng, scheduled, weights)
                point = selected.point
                configure_glitch(connection, point)
                attempts += 1
                parameter_counts[point] += 1
                token = (token + 1) & 0xFF
                capture_timeout = False
                sample: Optional[base.Sample] = None
                error = ""

                try:
                    sample, capture_timeout = base.send_glitch(
                        connection.scope,
                        connection.target,
                        instruction_id,
                        token,
                        args.serial_timeout,
                    )
                    label = base.classify(sample, token, args.instruction)
                except Exception as exc:  # Keep a long unattended run alive on transient I/O errors.
                    label = "host_exception"
                    error = f"{type(exc).__name__}: {exc}"

                counters[label] += 1
                elapsed_s = time.monotonic() - start_time
                writer.writerow(
                    sample_to_row(
                        phase="glitch_long",
                        elapsed_s=elapsed_s,
                        instruction=args.instruction,
                        instruction_id=instruction_id,
                        attempt=attempts,
                        parameter_source=selected.source,
                        seed_index=selected.seed_index,
                        point=point,
                        classification=label,
                        expected_result=expected_result,
                        target_skip_result=target_skip_result,
                        token=token,
                        capture_timeout=capture_timeout,
                        sample=sample,
                        error=error,
                    )
                )

                if label == "target_skip_candidate" and sample is not None:
                    target_samples.append(sample)
                    parameter_successes[point] += 1
                    baseline_cycle_set = {item.cycles for item in baseline_samples}
                    baseline_tuple_set = {item.event_tuple for item in baseline_samples}
                    print(
                        "[TARGET-SKIP] "
                        f"n={len(target_samples)} attempt={attempts} "
                        f"source={selected.source} seed={selected.seed_index} "
                        f"offset={point.offset} width={point.width} "
                        f"ext_offset={point.ext_offset} repeat={point.repeat} "
                        f"cycles={sample.cycles} cpi={sample.cpi} exc={sample.exc} "
                        f"sleep={sample.sleep} lsu={sample.lsu} fold={sample.fold} "
                        f"cycle_seen_in_baseline={sample.cycles in baseline_cycle_set} "
                        f"tuple_seen_in_baseline={sample.event_tuple in baseline_tuple_set}"
                    )
                    file_pointer.flush()
                    consecutive_failures = 0
                elif label in {
                    "invalid_or_reset",
                    "stale_or_corrupt",
                    "metadata_corrupt",
                    "host_exception",
                }:
                    consecutive_failures += 1
                    try:
                        connection.scope.io.hs2 = "clkgen"
                        base.reset_target(
                            connection.scope,
                            connection.target,
                            args.reset_delay,
                        )
                        connection.scope.io.hs2 = "glitch"
                    except Exception:
                        pass
                else:
                    consecutive_failures = 0

                if (
                    args.reconnect_after_failures > 0
                    and consecutive_failures >= args.reconnect_after_failures
                ):
                    print(
                        f"[reconnect] {consecutive_failures} consecutive failures; "
                        "reopening scope and target"
                    )
                    disconnect(connection)
                    connection = None
                    time.sleep(0.5)
                    connection = connect(
                        args,
                        program=args.reprogram_on_reconnect,
                    )
                    consecutive_failures = 0

                now = time.monotonic()
                if now >= next_flush:
                    file_pointer.flush()
                    write_summary(
                        summary_path,
                        args=args,
                        seed_csv=seed_csv,
                        output_csv=output_csv,
                        elapsed_s=now - start_time,
                        attempts=attempts,
                        counters=counters,
                        baseline_samples=baseline_samples,
                        target_samples=target_samples,
                        parameter_counts=parameter_counts,
                        parameter_successes=parameter_successes,
                    )
                    next_flush = now + args.flush_seconds

                if now >= next_report:
                    print_progress(
                        instruction=args.instruction,
                        elapsed_s=now - start_time,
                        attempts=attempts,
                        counters=counters,
                        baseline_samples=baseline_samples,
                        target_samples=target_samples,
                    )
                    next_report = now + args.report_minutes * 60.0

            file_pointer.flush()

    except KeyboardInterrupt:
        print("\n[stop] interrupted by user", file=sys.stderr)
    finally:
        elapsed_s = time.monotonic() - start_time
        try:
            write_summary(
                summary_path,
                args=args,
                seed_csv=seed_csv,
                output_csv=output_csv,
                elapsed_s=elapsed_s,
                attempts=attempts,
                counters=counters,
                baseline_samples=baseline_samples,
                target_samples=target_samples,
                parameter_counts=parameter_counts,
                parameter_successes=parameter_successes,
            )
        except Exception as exc:
            print(f"[warning] failed to write final summary: {exc}", file=sys.stderr)
        disconnect(connection)

    print("\n[final summary]")
    print(f"elapsed={elapsed_s / 3600.0:.3f}h attempts={attempts}")
    for name in CLASSIFICATIONS:
        print(f"  {name}: {counters[name]}")
    base.print_distribution(f"baseline-{args.instruction}", baseline_samples)
    base.print_distribution(f"target-skip-{args.instruction}", target_samples)

    if target_samples and baseline_samples:
        baseline_cycle_set = {sample.cycles for sample in baseline_samples}
        baseline_tuple_set = {sample.event_tuple for sample in baseline_samples}
        cycle_overlap = sum(sample.cycles in baseline_cycle_set for sample in target_samples)
        tuple_overlap = sum(sample.event_tuple in baseline_tuple_set for sample in target_samples)
        baseline_median = statistics.median(sample.cycles for sample in baseline_samples)
        target_median = statistics.median(sample.cycles for sample in target_samples)
        print(
            f"cycle overlap with baseline: {cycle_overlap}/{len(target_samples)} "
            f"({100.0 * cycle_overlap / len(target_samples):.1f}%)"
        )
        print(
            f"full DWT tuple overlap with baseline: {tuple_overlap}/{len(target_samples)} "
            f"({100.0 * tuple_overlap / len(target_samples):.1f}%)"
        )
        print(f"median cycle delta (skip - baseline): {target_median - baseline_median}")

    print("\n[top successful parameter points]")
    successful_points = sorted(
        parameter_successes,
        key=lambda point: (
            -parameter_successes[point],
            -(parameter_successes[point] / parameter_counts[point]),
            point.offset,
            point.width,
            point.ext_offset,
        ),
    )
    if not successful_points:
        print("  none")
    else:
        for point in successful_points[:20]:
            successes = parameter_successes[point]
            total = parameter_counts[point]
            print(
                f"  offset={point.offset} width={point.width} "
                f"ext_offset={point.ext_offset} repeat={point.repeat}: "
                f"{successes}/{total} ({100.0 * successes / total:.4f}%)"
            )

    print(f"CSV: {output_csv}")
    print(f"Summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
