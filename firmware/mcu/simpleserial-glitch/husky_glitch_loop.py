#!/usr/bin/env python3
"""
husky_f405_glitch.py -- end-to-end clock glitch campaign against glitch_loop()
from simpleserial-glitch.c, on a CW308 UFO board with an STM32F405 target,
driven by ChipWhisperer-Husky.

Three stages, each independently selectable:
  1. build    invoke make in the simpleserial-glitch firmware directory
  2. program  flash the resulting hex via the STM32 serial bootloader
  3. glitch   sweep clock glitch parameters and record every outcome

Target under attack (compiled -O0, i/j/cnt volatile):

    cnt = 0;
    trigger_high();
    for(i=0; i<50; i++) for(j=0; j<50; j++) cnt++;
    trigger_low();
    simpleserial_put('r', 4, &cnt);

Any returned cnt != 2500 is a fault.

Outcome classes
    normal   response received, cnt == 2500
    success  response received, cnt != 2500          <-- the goal
    mute     no response within timeout (hang / crash / reset)
    invalid  malformed response

Examples
    # everything, coarse map of the phase plane
    python3 husky_f405_glitch.py --all --scan

    # rebuild and reflash only
    python3 husky_f405_glitch.py --build --program

    # refine around a productive region, 5 attempts per point
    python3 husky_f405_glitch.py --glitch \
        --width-min 1200 --width-max 1500 --width-step 8 \
        --offset-min 900 --offset-max 1200 --offset-step 8 \
        --ext-min 0 --ext-max 60 --repeats 5
"""

import argparse
import csv
import itertools
import os
import subprocess
import sys
import time

PLATFORM = "CW308_STM32F4"
FW_NAME = "simpleserial-glitch"
DEFAULT_FW_DIR = os.path.expanduser(
    "~/chipwhisperer/firmware/mcu/simpleserial-glitch")

# Baud rates the SimpleSerial firmware picks at the stock 7.37 MHz target clock.
# The target derives its UART divisor from its core clock, so if the clock is
# changed the host baud must be scaled by the same ratio or the link goes mute.
BASE_FREQ = 7.37e6
BASE_BAUD = {1: 38400, 2: 230400}

OK = "  [ OK ]"
BAD = "  [FAIL]"
WARN = "  [warn]"


def hdr(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


# --------------------------------------------------------------------------
# stage 1: build
# --------------------------------------------------------------------------
def stage_build(args):
    hdr("STAGE 1 -- build firmware")
    fw_dir = args.fw_dir
    if not os.path.isdir(fw_dir):
        print(f"{BAD} firmware directory not found: {fw_dir}")
        sys.exit(1)

    ss_ver = "SS_VER_2_1" if args.ssver == 2 else "SS_VER_1_1"
    make_args = [f"PLATFORM={PLATFORM}", "CRYPTO_TARGET=NONE",
                 f"SS_VER={ss_ver}"]
    print(f"    dir      : {fw_dir}")
    print(f"    make args: {' '.join(make_args)}")

    # A stale build tree silently keeps the previous SS_VER, which then shows
    # up as a mute target. Always clean when the version could have changed.
    subprocess.run(["make", "clean"] + make_args, cwd=fw_dir,
                   check=False, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)

    proc = subprocess.run(["make", "-j4"] + make_args, cwd=fw_dir,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-4000:])
        print(proc.stderr[-4000:])
        print(f"{BAD} make failed (exit {proc.returncode})")
        sys.exit(1)

    # Echo the size report, which is the useful part of the make output.
    for line in proc.stdout.splitlines():
        if any(k in line for k in ("text", "data", "bss", "dec", "Size after",
                                   "Assembling", "error", "warning: ")):
            print("    " + line.rstrip())

    hexpath = hex_path(args)
    if not os.path.exists(hexpath):
        print(f"{BAD} expected hex not produced: {hexpath}")
        sys.exit(1)
    print(f"{OK} built {os.path.basename(hexpath)} "
          f"({os.path.getsize(hexpath)} bytes)")
    return hexpath


def hex_path(args):
    return os.path.join(args.fw_dir, f"{FW_NAME}-{PLATFORM}.hex")


# --------------------------------------------------------------------------
# connection
# --------------------------------------------------------------------------
def find_husky_sn(explicit=None):
    import chipwhisperer as cw
    if explicit:
        return explicit
    try:
        devices = cw.list_devices()
    except Exception:
        return None
    sns = [d.get("sn") for d in devices if "husky" in str(d).lower()]
    if len(sns) == 1:
        return sns[0]
    if not sns:
        print(f"{WARN} no Husky enumerated; attempting a blind open.")
        return None
    print(f"{WARN} {len(sns)} Huskys found; pass --sn to disambiguate.")
    return sns[0]


def connect(args):
    import chipwhisperer as cw
    sn = find_husky_sn(args.sn)
    scope = cw.scope(sn=sn) if sn else cw.scope()
    if not getattr(scope, "_is_husky", False):
        scope.dis()
        raise RuntimeError("connected device is not a Husky")
    scope.default_setup()
    scope.clock.clkgen_freq = args.freq
    scope.io.hs2 = "clkgen"          # clean clock until the campaign starts
    time.sleep(0.25)
    return scope


def make_target(scope, args):
    import chipwhisperer as cw
    cls = cw.targets.SimpleSerial2 if args.ssver == 2 else cw.targets.SimpleSerial
    target = cw.target(scope, cls)
    baud = int(round(BASE_BAUD[args.ssver] * args.freq / BASE_FREQ))
    target.baud = baud
    print(f"    target clock {args.freq/1e6:.4f} MHz -> baud {baud}")
    return target


def reset_target(scope, target, settle=0.08):
    scope.io.nrst = "low"
    time.sleep(0.03)
    scope.io.nrst = "high_z"
    time.sleep(settle)
    target.flush()


# --------------------------------------------------------------------------
# stage 2: program
# --------------------------------------------------------------------------
def stage_program(scope, args, hexpath):
    hdr("STAGE 2 -- program target")
    import chipwhisperer as cw

    if not os.path.exists(hexpath):
        print(f"{BAD} hex not found: {hexpath}  (run with --build first)")
        sys.exit(1)

    # The STM32 serial bootloader needs a clean clock and the normal UART
    # routing; a glitched clock here will corrupt the flash write.
    scope.io.hs2 = "clkgen"
    time.sleep(0.1)
    print(f"    hex: {hexpath}")
    cw.program_target(scope, cw.programmers.STM32FProgrammer, hexpath)
    print(f"{OK} programmed.")


# --------------------------------------------------------------------------
# stage 3: glitch campaign
# --------------------------------------------------------------------------
def arm_glitch_module(scope, args):
    # Husky powers the glitch MMCM down by default.
    scope.glitch.enabled = True
    scope.glitch.clk_src = "pll"
    scope.glitch.output = "clock_xor"
    # 'ext_single' can probabilistically emit no glitch at all on Husky
    # (newaetech/chipwhisperer#566). glitch_loop raises the trigger exactly
    # once per command, so 'ext_continuous' still gives one glitch per attempt.
    scope.glitch.trigger_src = "ext_continuous"
    scope.glitch.repeat = args.repeat
    scope.glitch.width = 0
    scope.glitch.offset = 0
    scope.glitch.ext_offset = 0
    scope.io.hs2 = "glitch"
    time.sleep(0.25)


def attempt(scope, target, ssver, timeout_ms=80):
    """One glitched invocation of 'g'. Returns (outcome, cnt)."""
    target.flush()
    scope.arm()
    target.simpleserial_write("g", bytearray([]))
    scope.capture()

    try:
        val = target.simpleserial_read("r", 4, timeout=timeout_ms, ack=False)
    except Exception:
        val = None

    if val is None:
        return "mute", None
    try:
        cnt = int.from_bytes(bytes(val), byteorder="little")
    except Exception:
        return "invalid", None

    try:
        target.simpleserial_wait_ack(timeout=20)
    except Exception:
        pass

    return ("normal", cnt) if cnt == 2500 else ("success", cnt)


def frange(lo, hi, step):
    vals, v = [], lo
    while v <= hi:
        vals.append(int(v))
        v += step
    return vals


def build_grid(scope, args):
    psteps = scope.glitch.phase_shift_steps
    if args.scan:
        step = max(1, psteps // args.scan_points)
        widths = frange(0, psteps - 1, step)
        offsets = frange(0, psteps - 1, step)
    else:
        wmax = args.width_max if args.width_max is not None else psteps - 1
        omax = args.offset_max if args.offset_max is not None else psteps - 1
        widths = frange(args.width_min, wmax, args.width_step)
        offsets = frange(args.offset_min, omax, args.offset_step)
    exts = frange(args.ext_min, args.ext_max, args.ext_step)
    return psteps, widths, offsets, exts


def stage_glitch(scope, target, args):
    hdr("STAGE 3 -- glitch campaign")
    arm_glitch_module(scope, args)

    psteps, widths, offsets, exts = build_grid(scope, args)
    print(f"    phase_shift_steps : {psteps}")
    print(f"    width             : {len(widths)} values "
          f"[{widths[0]} .. {widths[-1]}]")
    print(f"    offset            : {len(offsets)} values "
          f"[{offsets[0]} .. {offsets[-1]}]")
    print(f"    ext_offset        : {len(exts)} values "
          f"[{exts[0]} .. {exts[-1]}]")
    print(f"    glitch.repeat     : {args.repeat}")
    print(f"    attempts/point    : {args.repeats}")

    grid = list(itertools.product(exts, widths, offsets))
    total = len(grid) * args.repeats
    print(f"    total attempts    : {total}")

    # Baseline with the pulse parked at zero width.
    reset_target(scope, target)
    scope.glitch.width = 0
    scope.glitch.offset = 0
    scope.glitch.ext_offset = 0
    outcome, cnt = attempt(scope, target, args.ssver, timeout_ms=args.timeout)
    if outcome != "normal":
        print(f"{BAD} baseline returned {outcome} cnt={cnt}; expected cnt=2500.")
        print("      Nothing below is meaningful until this is clean. Check")
        print("      SS_VER match, UFO board jumpers, and target seating.")
        if not args.force:
            return
    else:
        print(f"{OK} baseline clean: cnt=2500")

    new_file = not os.path.exists(args.csv)
    fh = open(args.csv, "a", newline="")
    writer = csv.writer(fh)
    if new_file:
        writer.writerow(["ts", "ext_offset", "width", "offset", "repeat",
                         "outcome", "cnt"])

    tally = {"normal": 0, "success": 0, "mute": 0, "invalid": 0}
    hits = []
    t0, done = time.time(), 0

    try:
        for ext, w, off in grid:
            scope.glitch.ext_offset = ext
            scope.glitch.width = w
            scope.glitch.offset = off

            for _ in range(args.repeats):
                outcome, cnt = attempt(scope, target, args.ssver,
                                       timeout_ms=args.timeout)
                tally[outcome] += 1
                done += 1
                writer.writerow([f"{time.time():.3f}", ext, w, off,
                                 args.repeat, outcome,
                                 "" if cnt is None else cnt])

                if outcome == "success":
                    hits.append((ext, w, off, cnt))
                    print(f"  HIT  ext={ext:5d} w={w:5d} off={off:5d} "
                          f"-> cnt={cnt} (delta {cnt-2500:+d})")
                elif outcome in ("mute", "invalid"):
                    reset_target(scope, target)

                if done % args.progress == 0:
                    rate = done / max(1e-9, time.time() - t0)
                    print(f"  ... {done}/{total}  {rate:5.1f} att/s  "
                          f"n={tally['normal']} s={tally['success']} "
                          f"m={tally['mute']} i={tally['invalid']}")
                    fh.flush()
    except KeyboardInterrupt:
        print("\n  interrupted by user.")
    finally:
        fh.close()
        summary(tally, hits, time.time() - t0, args.csv)


def summary(tally, hits, elapsed, csv_path):
    hdr("SUMMARY")
    total = sum(tally.values())
    for k in ("normal", "success", "mute", "invalid"):
        pct = 100.0 * tally[k] / total if total else 0.0
        print(f"    {k:<8}: {tally[k]:7d}  ({pct:5.2f}%)")
    print(f"    elapsed : {elapsed:.1f} s")
    print(f"    csv     : {csv_path}")

    if not hits:
        print("\n    No faults observed. Next things to try:")
        print("      - full phase sweep: --scan --scan-points 60")
        print("      - --repeat 2..8 (consecutive glitched cycles)")
        print("      - raise the target clock (--freq 10e6 or higher) to cut")
        print("        the timing margin the glitch has to violate; the script")
        print("        rescales the UART baud automatically")
        return

    print(f"\n    {len(hits)} fault(s). Productive ranges:")
    print(f"      width      : {min(h[1] for h in hits)} .. "
          f"{max(h[1] for h in hits)}")
    print(f"      offset     : {min(h[2] for h in hits)} .. "
          f"{max(h[2] for h in hits)}")
    print(f"      ext_offset : {min(h[0] for h in hits)} .. "
          f"{max(h[0] for h in hits)}")
    seen = {}
    for _, _, _, cnt in hits:
        seen[cnt] = seen.get(cnt, 0) + 1
    print("      cnt values (value: occurrences):")
    for cnt, n in sorted(seen.items()):
        print(f"        {cnt:<12d} {n}")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true",
                    help="run build, program and glitch")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--program", action="store_true")
    ap.add_argument("--glitch", action="store_true")

    ap.add_argument("--fw-dir", default=DEFAULT_FW_DIR)
    ap.add_argument("--sn", default=None, help="Husky serial number")
    ap.add_argument("--ssver", type=int, choices=(1, 2), default=1)
    ap.add_argument("--freq", type=float, default=7.37e6)
    ap.add_argument("--csv", default="f405_glitch_results.csv")
    ap.add_argument("--force", action="store_true",
                    help="continue even if the baseline check fails")

    ap.add_argument("--scan", action="store_true",
                    help="coarse sweep of the whole width/offset plane")
    ap.add_argument("--scan-points", type=int, default=40)
    ap.add_argument("--width-min", type=int, default=0)
    ap.add_argument("--width-max", type=int, default=None)
    ap.add_argument("--width-step", type=int, default=40)
    ap.add_argument("--offset-min", type=int, default=0)
    ap.add_argument("--offset-max", type=int, default=None)
    ap.add_argument("--offset-step", type=int, default=40)
    ap.add_argument("--ext-min", type=int, default=0)
    ap.add_argument("--ext-max", type=int, default=40)
    ap.add_argument("--ext-step", type=int, default=1)

    ap.add_argument("--repeat", type=int, default=1,
                    help="scope.glitch.repeat: consecutive glitched cycles")
    ap.add_argument("--repeats", type=int, default=1,
                    help="attempts per parameter point")
    ap.add_argument("--timeout", type=int, default=80)
    ap.add_argument("--progress", type=int, default=200)
    args = ap.parse_args()

    if args.all:
        args.build = args.program = args.glitch = True
    if not (args.build or args.program or args.glitch):
        ap.error("pick at least one of --build / --program / --glitch / --all")

    hexpath = hex_path(args)
    if args.build:
        hexpath = stage_build(args)

    scope = None
    try:
        if args.program or args.glitch:
            hdr("CONNECT")
            scope = connect(args)
            print(f"    Husky sn {scope.sn}")
            print(f"    clkgen   {scope.clock.clkgen_freq/1e6:.4f} MHz")
            target = make_target(scope, args)

            if args.program:
                stage_program(scope, args, hexpath)
                reset_target(scope, target)

            if args.glitch:
                stage_glitch(scope, target, args)
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if scope is not None:
            try:
                # Park the ADC clock at its default before disconnecting;
                # reconnecting with a high ADC clock resets FPGA logic
                # improperly (newaetech/chipwhisperer#559).
                scope.io.hs2 = "clkgen"
                scope.default_setup()
                scope.dis()
                print("\n    scope disconnected.")
            except Exception:
                pass


if __name__ == "__main__":
    main()