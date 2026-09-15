#!/usr/bin/env python3
"""
Clock-glitch campaign against simpleserial-glitch.c on CW-Lite + STM32F303.

Steps:
  1. Build the firmware by running program.sh.
  2. Flash simpleserial-glitch-CWLITEARM.hex to the target.
  3. Sweep glitch width and offset with ext_offset fixed, recording every result.

Target command 'g' (glitch_loop) runs a 50x50 nested loop and returns a
uint32 counter. cnt == 2500 means the loop ran correctly.

Usage:
    python3 run_glitch_campaign.py --fw-dir /path/to/simpleserial-glitch
    python3 run_glitch_campaign.py --skip-build --attempts 3
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from collections import Counter

import chipwhisperer as cw

EXPECTED_CNT = 2500


# --------------------------------------------------------------------------
# 1. Build
# --------------------------------------------------------------------------

def build_firmware(fw_dir):
    script = os.path.join(fw_dir, "program.sh")
    if not os.path.isfile(script):
        sys.exit(f"program.sh not found in {fw_dir}")

    print(f"[build] running program.sh in {fw_dir}")
    result = subprocess.run(
        ["bash", "program.sh"],
        cwd=fw_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # Only show the tail unless something went wrong.
    lines = result.stdout.splitlines()
    if result.returncode != 0:
        print("\n".join(lines))
        sys.exit(f"[build] FAILED with exit code {result.returncode}")
    print("\n".join(lines[-12:]))
    print("[build] ok")


# --------------------------------------------------------------------------
# 2. Connect and flash
# --------------------------------------------------------------------------

def connect_and_flash(fw_dir, hex_name, skip_flash=False):
    scope = cw.scope()
    scope.default_setup()

    target = cw.target(scope, cw.targets.SimpleSerial2)

    if not skip_flash:
        hex_path = os.path.join(fw_dir, hex_name)
        if not os.path.isfile(hex_path):
            scope.dis()
            sys.exit(f"hex not found: {hex_path}")
        print(f"[flash] programming {hex_path}")
        cw.program_target(scope, cw.programmers.STM32FProgrammer, hex_path)
        print("[flash] ok")

    return scope, target


def reset_target(scope, settle=0.05):
    scope.io.nrst = "low"
    time.sleep(settle)
    scope.io.nrst = "high_z"
    time.sleep(settle)


# --------------------------------------------------------------------------
# 3. Glitch sweep
# --------------------------------------------------------------------------

def configure_glitch(scope, ext_offset, repeat):
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_single"
    scope.glitch.ext_offset = ext_offset
    scope.glitch.repeat = repeat
    scope.io.hs2 = "glitch"
    print(f"[glitch] ext_offset={scope.glitch.ext_offset} "
          f"repeat={scope.glitch.repeat} output={scope.glitch.output}")


def try_glitch(scope, target, timeout_ms=50):
    """Fire one glitch. Returns (classification, cnt_or_None)."""
    target.flush()
    scope.arm()

    target.simpleserial_write("g", bytearray())

    if scope.capture():          # True == trigger never fired
        return "no_trigger", None

    payload = target.simpleserial_read("r", 4, timeout=timeout_ms, ack=False)
    if payload is None:
        return "reset", None

    cnt = int.from_bytes(payload[:4], byteorder="little")
    if cnt == EXPECTED_CNT:
        return "normal", cnt
    return "success", cnt


def sweep(scope, target, args, writer):
    tally = Counter()
    successes = []

    widths = frange(args.width_min, args.width_max, args.step)
    offsets = frange(args.offset_min, args.offset_max, args.step)
    total = len(widths) * len(offsets) * args.attempts
    done = 0

    reset_target(scope)

    for width in widths:
        scope.glitch.width = width
        for offset in offsets:
            scope.glitch.offset = offset

            # Read back what the hardware actually programmed -- the CW-Lite
            # quantises these percentages, so the request is not the setting.
            w_act = scope.glitch.width
            o_act = scope.glitch.offset

            for attempt in range(args.attempts):
                result, cnt = try_glitch(scope, target)
                done += 1

                writer.writerow({
                    "width_req": width,
                    "offset_req": offset,
                    "width_actual": round(w_act, 4),
                    "offset_actual": round(o_act, 4),
                    "ext_offset": scope.glitch.ext_offset,
                    "repeat": scope.glitch.repeat,
                    "attempt": attempt,
                    "result": result,
                    "cnt": "" if cnt is None else cnt,
                })

                tally[result] += 1
                if result == "success":
                    successes.append((w_act, o_act, cnt))
                    print(f"  SUCCESS  width={w_act:7.3f} offset={o_act:7.3f} "
                          f"cnt={cnt} (expected {EXPECTED_CNT})")

                # A crashed or desynced target has to be brought back before
                # the next point, or every later result is contaminated.
                if result in ("reset", "no_trigger"):
                    reset_target(scope)

            if done % 200 < args.attempts:
                pct = 100.0 * done / total
                print(f"[sweep] {done}/{total} ({pct:5.1f}%)  "
                      f"width={width} offset={offset}  {dict(tally)}")

    return tally, successes


def frange(lo, hi, step):
    vals, v = [], lo
    while v <= hi + 1e-9:
        vals.append(round(v, 4))
        v += step
    return vals


# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fw-dir", default=".",
                   help="directory holding program.sh and the makefile")
    p.add_argument("--hex-name", default="simpleserial-glitch-CWLITEARM.hex")
    p.add_argument("--out", default="glitch_results.csv")

    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--skip-flash", action="store_true")

    p.add_argument("--ext-offset", type=int, default=8)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--width-min", type=float, default=0)
    p.add_argument("--width-max", type=float, default=48)
    p.add_argument("--offset-min", type=float, default=-48)
    p.add_argument("--offset-max", type=float, default=48)
    p.add_argument("--step", type=float, default=1.0,
                   help="step for both width and offset (default 1)")
    p.add_argument("--attempts", type=int, default=1,
                   help="glitch attempts per (width, offset) point")

    args = p.parse_args()
    fw_dir = os.path.abspath(args.fw_dir)

    if not args.skip_build:
        build_firmware(fw_dir)

    scope, target = connect_and_flash(fw_dir, args.hex_name, args.skip_flash)

    try:
        configure_glitch(scope, args.ext_offset, args.repeat)

        fields = ["width_req", "offset_req", "width_actual", "offset_actual",
                  "ext_offset", "repeat", "attempt", "result", "cnt"]

        with open(args.out, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            tally, successes = sweep(scope, target, args, writer)

        print("\n===== summary =====")
        grand = sum(tally.values())
        for k in ("normal", "success", "reset", "no_trigger"):
            n = tally.get(k, 0)
            print(f"  {k:<11} {n:6d}  ({100.0 * n / grand:5.2f}%)")
        print(f"  total       {grand:6d}")
        print(f"\nresults written to {args.out}")

        if successes:
            print(f"\n{len(successes)} successful glitches. First few:")
            for w, o, c in successes[:10]:
                print(f"    width={w:7.3f}  offset={o:7.3f}  cnt={c}")
        else:
            print("\nNo successful glitches. Try a different --ext-offset, "
                  "a wider --step sweep, or --attempts 3.")

    finally:
        scope.dis()
        target.dis()


if __name__ == "__main__":
    main()
