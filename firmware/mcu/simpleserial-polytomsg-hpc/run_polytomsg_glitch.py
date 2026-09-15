#!/usr/bin/env python3
"""Characterize a full-function target window (poly_tomsg) under CW-Lite clock glitching.

For each of two pseudo-random coefficient inputs (selected by a 32-bit seed sent to
the firmware):

  1. Run the target window N_REF times with NO glitch and record the DWT cycle count.
     The first no-glitch run also becomes the reference: the "correct" value of every
     reported variable (i, j, t, x, y, and the whole msg[] buffer).

  2. Inject a single clock-glitch pulse per run, discard crashes (no/!invalid frame),
     and keep going until --no-crash-runs valid runs have been collected. For each
     surviving run, report the cycle count and, for every variable, whether it differs
     from the no-glitch reference.

The goal is not to skip a named instruction but to measure how a single glitch in a
~10 000-cycle window partitions into: no architectural effect, a surviving corruption
of one or more variables, or a crash (filtered out).

This script drives the firmware in simpleserial-polytomsg-hpc.c. It does not import
the instruction-skip runners; it is self-contained.
"""

from __future__ import annotations

import argparse
import csv
import random
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import chipwhisperer as cw
except Exception:  # noqa: BLE001
    cw = None

RESPONSE_MAGIC = 0x33435054  # "TPC3"
RESP_HEADER_LEN = 38
RESPONSE_LEN = 42  # header + 4-byte msg CRC32; whole response fits one SS2 frame
VARIABLE_NAMES = ["i", "j", "t", "x", "y", "msg"]


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

@dataclass
class Response:
    cycles: int
    i: int
    j: int
    t: int
    x: int
    y: int
    cpicnt: int
    exccnt: int
    sleepcnt: int
    lsucnt: int
    foldcnt: int
    status: int
    token: int
    version: int
    symbytes: int
    msg_crc: int  # CRC32 of the msg[] buffer (msg reported as a checksum, not raw)

    def variables(self) -> dict[str, object]:
        # "msg" difference detection uses the checksum: any changed msg byte
        # changes msg_crc, so this still flags msg corruption (without saying
        # which byte changed).
        return {"i": self.i, "j": self.j, "t": self.t, "x": self.x, "y": self.y,
                "msg": self.msg_crc}

    def dwt_tuple(self) -> tuple[int, int, int, int, int, int]:
        """The full DWT hardware-counter signature for this run.

        CYCCNT is included: a glitch may perturb cycle count, an event counter, or
        both, so the tuple as a whole is the microarchitectural signature. Note the
        event counters are reported by the firmware as low 8 bits only.
        """
        return (self.cycles, self.cpicnt, self.exccnt,
                self.sleepcnt, self.lsucnt, self.foldcnt)


def parse_response(raw: bytes) -> Response | None:
    if raw is None or len(raw) < RESPONSE_LEN:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != RESPONSE_MAGIC:
        return None
    (cycles, i, j, t, x, y) = struct.unpack_from("<IIIIII", raw, 4)
    cpicnt, exccnt, sleepcnt, lsucnt, foldcnt = raw[28], raw[29], raw[30], raw[31], raw[32]
    status, token, version = raw[33], raw[34], raw[35]
    symbytes = struct.unpack_from("<H", raw, 36)[0]
    msg_crc = struct.unpack_from("<I", raw, 38)[0]
    return Response(cycles, i, j, t, x, y, cpicnt, exccnt, sleepcnt, lsucnt, foldcnt,
                    status, token, version, symbytes, msg_crc)


# ---------------------------------------------------------------------------
# Hardware wrappers
# ---------------------------------------------------------------------------

def connect(platform: str, firmware: Path | None, program: bool):
    if cw is None:
        raise RuntimeError("chipwhisperer module not importable; run on the CW host environment")
    scope = cw.scope()
    scope.default_setup()
    try:
        target = cw.target(scope, cw.targets.SimpleSerial2)
    except Exception:  # noqa: BLE001
        target = cw.target(scope, cw.targets.SimpleSerial)

    if program and firmware is not None:
        prog = cw.programmers.STM32FProgrammer
        cw.program_target(scope, prog, str(firmware))

    scope.clock.adc_src = "clkgen_x1"
    scope.adc.samples = 24000
    scope.io.hs2 = "glitch"
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_single"

    # The STM32 can come up halted/wedged after programming or between sessions;
    # default_setup() does not reset it. An explicit nRST pulse puts it into a
    # clean run-state. Without this the target is silent until reset (confirmed
    # by direct probing: no bytes before an nRST pulse, a valid frame after).
    reset_target(scope)
    try:
        target.reset_comms()
    except Exception:  # noqa: BLE001
        pass
    return scope, target


def reset_target(scope, settle: float = 0.2) -> None:
    """Pulse nRST low then release, giving the target time to boot."""
    try:
        scope.io.nrst = "low"
        time.sleep(0.05)
        scope.io.nrst = "high_z"
        time.sleep(settle)
    except Exception:  # noqa: BLE001
        pass


def arm_glitch(scope, offset: float, width: float, ext_offset: int, repeat: int) -> None:
    scope.glitch.offset = offset
    scope.glitch.width = width
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat = repeat


def disable_glitch(scope) -> None:
    # A no-glitch run is achieved by never calling scope.arm(); we must NOT set
    # scope.glitch.repeat = 0 because CW-Lite rejects it (legal range [1, 8192]).
    # Move the pulse fully outside any plausible window and leave repeat legal so
    # that even an accidental trigger has no effect.
    try:
        scope.glitch.ext_offset = 0
        scope.glitch.repeat = 1
    except Exception:  # noqa: BLE001
        pass


def _reset_comms(target) -> None:
    """Clear stale framing bytes (notably a leading 0x00) left in the serial
    buffer between commands. The SS2 parser errors with 'Cannot unstuff buffer
    beginning with 0x00' when such a byte precedes an otherwise-valid frame, so we
    reset before every read. Uses reset_comms() if available, else a manual flush."""
    for method in ("reset_comms", "flush"):
        fn = getattr(target, method, None)
        if fn is not None:
            try:
                fn()
                return
            except Exception:  # noqa: BLE001
                continue


def run_once(scope, target, seed: int, token: int, armed: bool,
             resp_len: int, timeout_ms: int = 2000, debug: bool = False):
    """Returns (Response|None, trig_count|None). trig_count is the number of target
    cycles the trigger was HIGH during this capture -- i.e. the true extent of the
    fault window, measured by hardware. A glitch is inside poly_tomsg iff its
    ext_offset is less than this value."""
    _reset_comms(target)
    payload = struct.pack("<IB", seed & 0xFFFFFFFF, token & 0xFF)
    trig_count = None
    if armed:
        scope.arm()
        target.simpleserial_write("g", payload)
        scope.capture()
        # Hardware-measured trigger-high duration, in target cycles (adc_src is
        # clkgen_x1, so ADC cycles == target cycles).
        try:
            trig_count = int(scope.adc.trig_count)
        except Exception:  # noqa: BLE001
            trig_count = None
    else:
        # No-glitch run: never arm, so no pulse can be delivered regardless of the
        # current glitch settings. This makes phase 1 a trustworthy reference.
        target.simpleserial_write("g", payload)
    raw = _read_response(target, resp_len, timeout_ms, debug=debug)
    if raw is None:
        return None, trig_count
    parsed = parse_response(bytes(raw))
    if parsed is None and debug:
        print(f"    [debug] parse_response failed on {len(raw)} bytes: {bytes(raw).hex()}",
              flush=True)
    return parsed, trig_count


def _read_response(target, resp_len: int, timeout_ms: int, debug: bool = False) -> bytes | None:
    """Read one 'r' frame, preferring the glitch-tolerant witherrors variant."""
    fn = getattr(target, "simpleserial_read_witherrors", None)
    if fn is not None:
        try:
            resp = fn("r", resp_len, timeout=timeout_ms)
            if debug:
                print(f"    [debug] witherrors returned: {resp!r}", flush=True)
            if isinstance(resp, dict):
                if resp.get("valid") and resp.get("payload") is not None:
                    return bytes(resp["payload"])
                # Some CW versions put the data in 'payload' even when 'valid' is
                # loosely set; accept a correctly-sized payload regardless.
                pl = resp.get("payload")
                if pl is not None and len(pl) >= resp_len:
                    return bytes(pl)
                return None
            if resp is not None:
                return bytes(resp)
        except Exception as exc:  # noqa: BLE001
            if debug:
                print(f"    [debug] witherrors raised: {exc!r}", flush=True)
    # Fallback: plain read.
    try:
        raw = target.simpleserial_read("r", resp_len, timeout=timeout_ms)
        if debug:
            print(f"    [debug] plain read returned: {raw!r}", flush=True)
        return None if raw is None else bytes(raw)
    except Exception as exc:  # noqa: BLE001
        if debug:
            print(f"    [debug] plain read raised: {exc!r}", flush=True)
        return None


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------

@dataclass
class InputResult:
    seed: int
    no_glitch_cycles: Counter = field(default_factory=Counter)
    reference: Response | None = None
    reference_modal: dict = field(default_factory=dict)
    reference_deviation: dict = field(default_factory=dict)
    reference_sets: dict = field(default_factory=dict)
    reference_dwt_set: set = field(default_factory=set)
    reference_dwt_counter: Counter = field(default_factory=Counter)
    no_crash_rows: list[dict] = field(default_factory=list)
    crash_rows: list[dict] = field(default_factory=list)
    attempts: int = 0
    crashes: int = 0


def diff_flags(ref: Response, got: Response) -> dict[str, bool]:
    r, g = ref.variables(), got.variables()
    return {name: (r[name] != g[name]) for name in VARIABLE_NAMES}


def diff_flags_modal(modal: dict, got: Response) -> dict[str, bool]:
    g = got.variables()
    return {name: (modal[name] != g[name]) for name in VARIABLE_NAMES}


def diff_flags_set(ref_sets: dict, got: Response) -> dict[str, bool]:
    """A variable 'differs' only if its glitched value was never seen unglitched.
    Consistent with how cycle count is judged, and robust to background bimodality
    (a variable that legitimately took two values without any glitch is not flagged
    when a glitched run lands on either of them)."""
    g = got.variables()
    return {name: (g[name] not in ref_sets.get(name, set())) for name in VARIABLE_NAMES}


def run_no_glitch(scope, target, seed: int, n_ref: int, resp_len: int, timeout_ms: int,
                  reset_each: bool = False, strict: bool = True) -> InputResult:
    """Collect no-glitch reference runs.

    strict=True: require every architectural variable identical across runs, else
    raise (the original contract).

    strict=False: tolerate a jittery target. Take the MOST COMMON value of each
    variable across the runs as the reference, and report how often each variable
    deviated (the background instability rate). This is the mode to use when the
    unglitched target itself occasionally flips a bit -- it quantifies the noise
    floor that phase 2 must clear instead of failing outright.
    """
    disable_glitch(scope)
    result = InputResult(seed=seed)
    samples: list[Response] = []
    for k in range(n_ref):
        if reset_each and k > 0:
            reset_target(scope)
            try:
                target.reset_comms()
            except Exception:  # noqa: BLE001
                pass
        resp, _ = run_once(scope, target, seed, token=k & 0xFF, armed=False,
                           resp_len=resp_len, timeout_ms=timeout_ms, debug=(k == 0))
        if resp is None:
            raise RuntimeError(
                f"no-glitch run {k} for seed 0x{seed:08x} returned no/invalid response; "
                "cannot establish a reference"
            )
        samples.append(resp)
        result.no_glitch_cycles[resp.cycles] += 1

    # Build the reference from the modal value of each architectural variable.
    ref0 = samples[0]
    modal: dict[str, object] = {}
    deviations: dict[str, int] = {}
    for name in VARIABLE_NAMES:
        vals = Counter(s.variables()[name] for s in samples)
        best, best_n = vals.most_common(1)[0]
        modal[name] = best
        deviations[name] = len(samples) - best_n

    unstable = {n: (dev, len(samples)) for n, dev in deviations.items() if dev > 0}
    if unstable:
        detail = ", ".join(f"{n}: {dev}/{tot} runs differ" for n, (dev, tot) in unstable.items())
        if strict:
            first_bad = next((k for k, s in enumerate(samples)
                              if any(s.variables()[n] != modal[n] for n in VARIABLE_NAMES)), 1)
            raise RuntimeError(
                f"no-glitch runs for seed 0x{seed:08x} are not reproducible ({detail}). "
                "The unglitched target's output varies run-to-run -- most likely the target "
                "is running off the (unlocked) glitch-module clock, so udiv occasionally "
                "returns a corrupted result and flips an msg bit. Re-run with "
                "--tolerant-reference to measure this background rate and proceed, or "
                "investigate the target clock (scope.io.hs2 / glitch MMCM lock). "
                f"First divergent run: {first_bad}."
            )
        print(f"  [reference] seed 0x{seed:08x}: background instability without glitch -> "
              f"{detail}", flush=True)

    # Use ref0's scalar fields but overwrite the variable fields with modal values
    # so the reference reflects the most common architectural state.
    result.reference = ref0
    result.reference_modal = modal  # type: ignore[attr-defined]
    result.reference_deviation = deviations  # type: ignore[attr-defined]
    # The full set of values each architectural variable took across the no-glitch
    # runs. A glitched run's variable counts as "differing" only if its value was
    # never seen unglitched -- consistent with how cycle count is judged, and
    # robust to background bimodality (e.g. msg taking two values at ~50/50).
    result.reference_sets = {  # type: ignore[attr-defined]
        name: {s.variables()[name] for s in samples} for name in VARIABLE_NAMES
    }
    # Every full DWT tuple observed with no glitch. A glitched run's DWT signature
    # counts as "differing" only if it was never seen unglitched -- same
    # set-membership rule used for cycle count and the architectural variables.
    result.reference_dwt_set = {s.dwt_tuple() for s in samples}  # type: ignore[attr-defined]
    result.reference_dwt_counter = Counter(s.dwt_tuple() for s in samples)  # type: ignore[attr-defined]
    return result


def build_schedule(args) -> list[tuple[float, float, int]] | None:
    """Deterministic parameter schedule, or None for the original random sampling.

    --ext-list     : glitch exactly the ext_offsets given, --runs-per-point times
                     each, at the fixed offset/width. This is the targeted-replay
                     mode: it answers how reproducible a given cycle position is,
                     which a one-run-per-cycle sweep cannot.
    sweep='ext'    : fix offset and width, step ext_offset over every cycle in
                     [ext_start, ext_stop]. ext_offset is the cycle selector (how
                     many cycles after the trigger the pulse fires).
    sweep='offset' : fix ext_offset and width, step the intra-cycle phase offset.
                     This probes pulse placement WITHIN one cycle; it does NOT
                     cover different cycles.
    """
    reps = max(1, args.runs_per_point)

    if getattr(args, "ext_list", None):
        return [(args.fixed_offset, args.fixed_width, e)
                for e in args.ext_list for _ in range(reps)]

    if args.sweep == "none":
        return None

    if args.sweep == "ext":
        if args.ext_step < 1:
            raise ValueError("--ext-step must be >= 1")
        exts = range(args.ext_start, args.ext_stop + 1, args.ext_step)
        return [(args.fixed_offset, args.fixed_width, e) for e in exts for _ in range(reps)]

    if args.sweep == "offset":
        if args.offset_step <= 0:
            raise ValueError("--offset-step must be > 0")
        offs: list[float] = []
        v = args.offset_start
        while v <= args.offset_stop + 1e-9:
            offs.append(round(v, 4))
            v += args.offset_step
        return [(o, args.fixed_width, args.fixed_ext) for o in offs for _ in range(reps)]

    raise ValueError(f"unknown --sweep mode {args.sweep!r}")


def run_glitch_until(scope, target, result: InputResult, args) -> None:
    ref = result.reference
    assert ref is not None
    # Compare glitched runs against the modal (most-common) no-glitch state, which
    # is robust to any background instability measured during the reference phase.
    modal = result.reference_modal or ref.variables()
    reference_sets = result.reference_sets or {n: {modal[n]} for n in VARIABLE_NAMES}
    # The set of cycle counts ever seen WITHOUT a glitch. A glitched run's cycle
    # count counts as "differing" only if it falls outside this set.
    reference_cycle_set = set(result.no_glitch_cycles)
    # Full DWT signatures seen without a glitch; membership test as for cycles.
    reference_dwt_set = result.reference_dwt_set or {ref.dwt_tuple()}
    rng = random.Random(args.param_seed ^ result.seed)
    kept = 0
    token = 0

    schedule = build_schedule(args)
    if schedule is not None:
        total_planned = len(schedule)
        secs = total_planned * args.est_seconds_per_run
        print(f"  [sweep] {args.sweep}: {total_planned} planned runs "
              f"(fixed offset={args.fixed_offset}, width={args.fixed_width}, "
              f"repeat={args.repeat}); rough estimate {secs / 60:.0f} min", flush=True)
        point_iter = iter(schedule)
    else:
        total_planned = None
        point_iter = None

    while True:
        if schedule is not None:
            nxt = next(point_iter, None)
            if nxt is None:
                break  # sweep complete
            offset, width, ext = nxt
        else:
            if kept >= args.no_crash_runs:
                break
            offset = rng.uniform(args.offset_start, args.offset_stop)
            width = rng.uniform(args.width_start, args.width_stop)
            ext = rng.randint(args.ext_start, args.ext_stop)

        if args.max_attempts and result.attempts >= args.max_attempts:
            print(f"  [warn] hit --max-attempts={args.max_attempts}", file=sys.stderr)
            break

        arm_glitch(scope, offset, width, ext, args.repeat)

        token = (token + 1) & 0xFF
        result.attempts += 1
        resp, trig_count = run_once(scope, target, result.seed, token=token, armed=True,
                                    resp_len=args.resp_len, timeout_ms=args.timeout_ms)

        if resp is None:
            result.crashes += 1
            # In a coverage sweep, WHICH cycles crash is itself a result, so record
            # the crashed point rather than silently retrying it.
            result.crash_rows.append({
                "seed": f"0x{result.seed:08x}", "attempt": result.attempts,
                "offset": f"{offset:.4f}", "width": f"{width:.4f}",
                "ext_offset": ext, "repeat": args.repeat, "crashed": True,
            })
            # A crash can leave the target wedged; direct probing showed only an
            # nRST pulse reliably recovers it (a plain buffer flush does not).
            reset_target(scope, settle=args.crash_sleep + 0.1)
            try:
                target.reset_comms()
            except Exception:  # noqa: BLE001
                pass
            continue

        kept += 1
        flags = diff_flags_set(reference_sets, resp)
        # Cycle count is judged against the WHOLE no-glitch distribution, not a
        # single reference run. udiv is variable-latency, so the unglitched window
        # already spans several cycle values (e.g. 13738 and 13739); a glitched run
        # only "differs" if its cycle count was NEVER seen without a glitch. This
        # avoids the arbitrary outcome of comparing to whichever value run 0
        # happened to land on.
        cycles_differ = resp.cycles not in reference_cycle_set
        dwt = resp.dwt_tuple()
        dwt_differ = dwt not in reference_dwt_set
        row = {
            "seed": f"0x{result.seed:08x}",
            "attempt": result.attempts,
            "offset": f"{offset:.3f}",
            "width": f"{width:.4f}",
            "ext_offset": ext,
            "repeat": args.repeat,
            "cycles": resp.cycles,
            "cycles_differ": cycles_differ,
            "cpicnt": resp.cpicnt,
            "exccnt": resp.exccnt,
            "sleepcnt": resp.sleepcnt,
            "lsucnt": resp.lsucnt,
            "foldcnt": resp.foldcnt,
            "dwt_tuple": "|".join(str(v) for v in dwt),
            "dwt_differ": dwt_differ,
            "trig_count": trig_count if trig_count is not None else "",
            # Hardware verification: the glitch fired ext_offset cycles after the
            # trigger rose, and the trigger stayed high for trig_count cycles, so
            # the pulse landed inside poly_tomsg iff ext_offset < trig_count.
            "in_window": ("" if trig_count is None else bool(ext < trig_count)),
            "status": resp.status,
            "loops_nominal": bool(resp.status & (1 << 4)),
            "i": resp.i, "j": resp.j, "t": resp.t, "x": resp.x, "y": resp.y,
            "msg_crc": f"0x{resp.msg_crc:08x}",
        }
        for name in VARIABLE_NAMES:
            row[f"{name}_differ"] = flags[name]
        row["any_variable_differ"] = any(flags.values())
        result.no_crash_rows.append(row)

        if kept % max(1, args.progress_every) == 0:
            planned = f"/{total_planned}" if total_planned else f"/{args.no_crash_runs}"
            print(f"  [{result.seed:#010x}] kept={kept}{planned} ext={ext} "
                  f"attempts={result.attempts} crashes={result.crashes}", flush=True)


def summarize(result: InputResult) -> None:
    ref = result.reference
    print(f"\n=== input seed 0x{result.seed:08x} ===")
    ng = result.no_glitch_cycles
    ng_str = ", ".join(f"{c}:{n}" for c, n in sorted(ng.items()))
    print(f"no-glitch cycle count over {sum(ng.values())} runs: {ng_str}")
    if ref is not None:
        modal = result.reference_modal or ref.variables()
        print(f"  reference (modal): i={modal['i']} j={modal['j']} t={modal['t']} "
              f"x={modal['x']} y={modal['y']} msg_crc=0x{int(modal['msg']):08x} "
              f"(window {ref.symbytes} symbytes)")
        noise = {n: d for n, d in (result.reference_deviation or {}).items() if d > 0}
        if noise:
            total = sum(result.no_glitch_cycles.values())
            noise_str = ", ".join(f"{n}: {d}/{total}" for n, d in noise.items())
            print(f"  NO-GLITCH BACKGROUND INSTABILITY: {noise_str} -- phase-2 difference "
                  f"rates at or below this level are noise, not glitch effects.")
        # Reference DWT signatures. Order: (CYCCNT, CPICNT, EXCCNT, SLEEPCNT, LSUCNT, FOLDCNT)
        dwtc = result.reference_dwt_counter
        if dwtc:
            print(f"  reference DWT tuples (CYC|CPI|EXC|SLEEP|LSU|FOLD), "
                  f"{len(dwtc)} distinct over {sum(dwtc.values())} runs:")
            for tup, cnt in dwtc.most_common():
                print(f"    {'|'.join(str(v) for v in tup)}  x{cnt}")

    rows = result.no_crash_rows
    n = len(rows)
    print(f"\nglitched no-crash runs: {n}   "
          f"(attempts={result.attempts}, crashes={result.crashes}, "
          f"crash_rate={result.crashes / result.attempts:.3%})"
          if result.attempts else "no attempts")
    if n == 0:
        return

    cyc = Counter(r["cycles"] for r in rows)
    cyc_str = ", ".join(f"{c}:{k}" for c, k in sorted(cyc.items()))
    print(f"  cycle-count distribution: {cyc_str}")

    # Hardware verification that each glitch landed inside poly_tomsg.
    tcs = [r["trig_count"] for r in rows if isinstance(r.get("trig_count"), int)]
    if tcs:
        lo, hi = min(tcs), max(tcs)
        inw = [r for r in rows if r.get("in_window") is True]
        outw = [r for r in rows if r.get("in_window") is False]
        print(f"  trigger-high span (hardware-measured): {lo}..{hi} target cycles")
        print(f"  glitches verified INSIDE poly_tomsg: {len(inw)}/{len(rows)}"
              + (f"   OUTSIDE: {len(outw)} <-- lower --ext-stop to {lo - 1}" if outw else ""))
        if outw:
            bad = sorted(int(r["ext_offset"]) for r in outw)
            print(f"    out-of-window ext_offsets: {bad[:10]}{' ...' if len(bad) > 10 else ''}")
    else:
        print("  [warn] trig_count unavailable; cannot verify glitches were in-window")

    # === vars x DWT contingency table ===
    # Each glitched run is classified two ways: did any architectural variable
    # change, and did the full DWT tuple change (both judged by set membership
    # against the no-glitch reference).
    vi_di = sum(1 for r in rows if not r["any_variable_differ"] and not r["dwt_differ"])
    vd_di = sum(1 for r in rows if r["any_variable_differ"] and not r["dwt_differ"])
    vi_dd = sum(1 for r in rows if not r["any_variable_differ"] and r["dwt_differ"])
    vd_dd = sum(1 for r in rows if r["any_variable_differ"] and r["dwt_differ"])

    print()
    print("  vars x DWT breakdown (both vs the no-glitch reference sets):")
    print(f"    {'':<22}{'DWT identical':>16}{'DWT differ':>14}")
    print(f"    {'vars identical':<22}{vi_di:>16}{vi_dd:>14}")
    print(f"    {'vars differ':<22}{vd_di:>16}{vd_dd:>14}")
    print(f"    (total {vi_di + vd_di + vi_dd + vd_dd}/{n})")
    print(f"    vars identical + DWT identical : {vi_di}/{n} ({vi_di / n:.2%})  "
          "-- glitch had no observable effect")
    print(f"    vars differ    + DWT identical : {vd_di}/{n} ({vd_di / n:.2%})  "
          "-- SILENT data corruption (invisible to counters)")
    print(f"    vars identical + DWT differ    : {vi_dd}/{n} ({vi_dd / n:.2%})  "
          "-- timing/event perturbation, output intact")
    print(f"    vars differ    + DWT differ    : {vd_dd}/{n} ({vd_dd / n:.2%})  "
          "-- corruption detectable from counters")

    # Legacy cycle-only view, kept because CYCCNT alone is the weaker detector.
    only_cycles = sum(1 for r in rows if r["cycles_differ"] and not r["any_variable_differ"])
    any_var = sum(1 for r in rows if r["any_variable_differ"])
    identical = sum(1 for r in rows
                    if not r["any_variable_differ"] and not r["cycles_differ"])
    print()
    print(f"  (cycle-count-only view: identical={identical}/{n}, "
          f"only-cycles-differ={only_cycles}/{n}, >=1 var differs={any_var}/{n})")

    print("  per-variable change counts:")
    for name in VARIABLE_NAMES:
        c = sum(1 for r in rows if r[f"{name}_differ"])
        print(f"    {name:<4}: {c}/{n} ({c / n:.2%})")

    print("  per-DWT-counter change counts (vs the values seen unglitched):")
    ref_counter_sets: dict[str, set] = {}
    for idx, cname in enumerate(["cycles", "cpicnt", "exccnt", "sleepcnt", "lsucnt", "foldcnt"]):
        ref_counter_sets[cname] = {t[idx] for t in result.reference_dwt_set}
    for cname in ["cycles", "cpicnt", "exccnt", "sleepcnt", "lsucnt", "foldcnt"]:
        allowed = ref_counter_sets[cname]
        c = sum(1 for r in rows if r[cname] not in allowed) if allowed else 0
        print(f"    {cname:<9}: {c}/{n} ({c / n:.2%})")

    # ---- per-ext_offset breakdown: how repeatable is each cycle position? ----
    per_ext: dict[int, list[dict]] = defaultdict(list)
    for r in rows:
        per_ext[int(r["ext_offset"])].append(r)
    crash_per_ext: Counter = Counter(int(r["ext_offset"]) for r in result.crash_rows)
    if len(per_ext) <= 64 and (crash_per_ext or len(per_ext) > 1):
        print("\n  per-ext_offset repeatability "
              "(runs = surviving; crash = no valid response):")
        print(f"    {'ext':>8}{'runs':>6}{'crash':>7}{'vars!=':>8}{'dwt!=':>7}   "
              f"{'distinct msg_crc seen':<40}cycles seen")
        for ext in sorted(set(per_ext) | set(crash_per_ext)):
            rs = per_ext.get(ext, [])
            nv = sum(1 for r in rs if r["any_variable_differ"])
            nd = sum(1 for r in rs if r["dwt_differ"])
            crcs = Counter(r["msg_crc"] for r in rs)
            cycs = Counter(r["cycles"] for r in rs)
            crc_s = ", ".join(f"{c}x{k}" if k > 1 else f"{c}"
                              for c, k in crcs.most_common(3))
            if len(crcs) > 3:
                crc_s += f", +{len(crcs)-3} more"
            cyc_s = ", ".join(f"{c}x{k}" if k > 1 else f"{c}"
                              for c, k in sorted(cycs.items()))
            print(f"    {ext:>8}{len(rs):>6}{crash_per_ext.get(ext,0):>7}"
                  f"{nv:>8}{nd:>7}   {crc_s:<40}{cyc_s}")
        print("    (one msg_crc repeated across every corrupting run at an ext means the")
        print("     fault is reproducible at that cycle; several means it is not)")


def write_csv(path: Path, results: list[InputResult]) -> None:
    all_rows = [dict(row, crashed=False) for r in results for row in r.no_crash_rows]
    crash_rows = [row for r in results for row in r.crash_rows]
    if not all_rows and not crash_rows:
        print(f"[warn] no rows to write to {path}", file=sys.stderr)
        return
    # Union of keys so crashed rows (which lack measurement fields) still line up.
    fieldnames: list[str] = []
    for row in all_rows + crash_rows:
        for k in row:
            if k not in fieldnames:
                fieldnames.append(k)
    with path.open("w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames, restval="")
        w.writeheader()
        w.writerows(all_rows)
        w.writerows(crash_rows)
    print(f"\nper-run CSV written to {path} "
          f"({len(all_rows)} measured, {len(crash_rows)} crashed)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--platform", default="CWLITEARM")
    p.add_argument("--firmware", type=Path, default=None)
    p.add_argument("--program", action="store_true", help="flash firmware before running")

    p.add_argument("--no-crash-runs", type=int, default=100,
                   help="number of surviving (non-crash) glitched runs to collect per input")
    p.add_argument("--ref-runs", type=int, default=10,
                   help="number of no-glitch runs per input (default 10)")
    p.add_argument("--seeds", type=lambda s: [int(x, 0) for x in s.split(",")],
                   default=[0x00000001, 0x00000002],
                   help="comma-separated 32-bit coeff seeds; exactly the inputs to test "
                        "(default two inputs: 0x1,0x2)")

    # Glitch search space. Reused from the instruction-skip campaigns' stable window.
    p.add_argument("--offset-start", type=float, default=-45.0)
    p.add_argument("--offset-stop", type=float, default=-30.0)
    p.add_argument("--width-start", type=float, default=0.10)
    p.add_argument("--width-stop", type=float, default=0.60)
    p.add_argument("--ext-start", type=int, default=0)
    p.add_argument("--ext-stop", type=int, default=20000,
                   help="ext_offset upper bound; a ~10k-cycle window needs a wide range "
                        "so the pulse can land anywhere inside the function")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--param-seed", type=int, default=20260810,
                   help="RNG seed for glitch-parameter sampling (reproducibility)")

    p.add_argument("--max-attempts", type=int, default=0,
                   help="give up on an input after this many glitch attempts (0 = unlimited)")
    p.add_argument("--crash-sleep", type=float, default=0.02,
                   help="seconds to wait after a crash before the next attempt")
    p.add_argument("--timeout-ms", type=int, default=2000,
                   help="serial read timeout in MILLISECONDS (default 2000)")
    p.add_argument("--ext-list", type=lambda s: [int(x, 0) for x in s.replace(",", " ").split()],
                   default=None, metavar="E1,E2,...",
                   help="glitch exactly these ext_offsets, --runs-per-point times each, "
                        "at --fixed-offset/--fixed-width. Overrides --sweep.")
    p.add_argument("--sweep", choices=["none", "ext", "offset"], default="none",
                   help="'ext': fix offset/width and step ext_offset over EVERY cycle in "
                        "[--ext-start, --ext-stop] -- this is the cycle-coverage sweep. "
                        "'offset': fix ext/width and step the intra-cycle phase. "
                        "'none' (default): the original random sampling.")
    p.add_argument("--fixed-offset", type=float, default=-40.0,
                   help="offset held constant during --sweep ext (percent)")
    p.add_argument("--fixed-width", type=float, default=0.35,
                   help="width held constant during any sweep (percent)")
    p.add_argument("--fixed-ext", type=int, default=0,
                   help="ext_offset held constant during --sweep offset")
    p.add_argument("--ext-step", type=int, default=1,
                   help="cycle step for --sweep ext (1 = every cycle)")
    p.add_argument("--offset-step", type=float, default=0.5,
                   help="phase step for --sweep offset")
    p.add_argument("--runs-per-point", type=int, default=1,
                   help="repeats at each swept point (raises confidence per cycle)")
    p.add_argument("--est-seconds-per-run", type=float, default=0.06,
                   help="only used to print a rough duration estimate for a sweep")
    p.add_argument("--progress-every", type=int, default=10)
    p.add_argument("--tolerant-reference", action="store_true",
                   help="if the unglitched target is not perfectly reproducible, take the "
                        "most-common value of each variable as the reference and report the "
                        "background instability rate instead of aborting")
    p.add_argument("--reset-each-ref", action="store_true",
                   help="nRST-reset the target before every reference run (diagnostic)")
    p.add_argument("--output-csv", type=Path, default=Path("polytomsg_glitch.csv"))
    args = p.parse_args()
    # Response is a fixed 42-byte frame (header + msg CRC32), independent of the
    # firmware's KYBER_SYMBYTES window length.
    args.resp_len = RESPONSE_LEN
    return args


def main() -> int:
    args = parse_args()
    if len(args.seeds) < 1:
        raise ValueError("need at least one seed")

    scope, target = connect(args.platform, args.firmware, args.program)
    results: list[InputResult] = []
    try:
        for seed in args.seeds:
            print(f"\n########## input seed 0x{seed:08x} ##########", flush=True)
            print("[phase 1] no-glitch reference", flush=True)
            result = run_no_glitch(scope, target, seed, args.ref_runs,
                                   args.resp_len, args.timeout_ms,
                                   reset_each=args.reset_each_ref,
                                   strict=not args.tolerant_reference)
            print(f"[phase 2] glitching until {args.no_crash_runs} no-crash runs", flush=True)
            run_glitch_until(scope, target, result, args)
            results.append(result)
            summarize(result)
    finally:
        try:
            disable_glitch(scope)
            scope.dis()
            target.dis()
        except Exception:  # noqa: BLE001
            pass

    write_csv(args.output_csv, results)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
