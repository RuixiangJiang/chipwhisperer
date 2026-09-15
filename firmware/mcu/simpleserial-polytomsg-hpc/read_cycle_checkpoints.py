#!/usr/bin/env python3
"""Read the DWT cycle checkpoints and decompose the measured window.

Sends the firmware's 'p' command, which timestamps six points with DWT_CYCCNT:

    t0  before trigger_high()
    t1  after  trigger_high()
    t2  inside poly_tomsg_instr, immediately before the outer loop
    t3  inside poly_tomsg_instr, immediately after the outer loop
    t4  after the function returns
    t5  after trigger_low()

and prints each segment. This turns the ~64 cycles of non-loop overhead in the
measured window from a fitted constant into measured parts.

Two things to keep in mind when reading the output:

  * t2-t1 is an UPPER bound on call+prologue. The read at t2 has to materialise
    the DWT address before it can load, and those cycles land inside the segment.
    The real poly_tomsg does not pay them.

  * None of this locates the trigger's rising edge as the FPGA sees it. Between
    the GPIO store inside trigger_high() and that edge sit an APB write latency
    and the FPGA synchroniser, invisible to any CPU-side counter. So this gives
    the CPU timeline exactly, but converting it to ext_offset's origin needs a
    separate calibration.

Example
-------
    python3 read_cycle_checkpoints.py
    python3 read_cycle_checkpoints.py --seeds 0x1,0x2 --repeats 3
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from collections import Counter

try:
    import chipwhisperer as cw
except Exception:  # noqa: BLE001
    cw = None

CKPT_MAGIC = 0x344B4348
CKPT_LEN = 32
MAIN_MAGIC = 0x33435054
MAIN_LEN = 42


def connect():
    if cw is None:
        raise RuntimeError("chipwhisperer not importable; run on the CW host")
    scope = cw.scope()
    scope.default_setup()
    try:
        target = cw.target(scope, cw.targets.SimpleSerial2)
    except Exception:  # noqa: BLE001
        target = cw.target(scope, cw.targets.SimpleSerial)
    scope.clock.adc_src = "clkgen_x1"
    scope.adc.samples = 24000
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.2)
    try:
        target.reset_comms()
    except Exception:  # noqa: BLE001
        pass
    return scope, target


def _reset(target):
    for m in ("reset_comms", "flush"):
        fn = getattr(target, m, None)
        if fn:
            try:
                fn()
                return
            except Exception:  # noqa: BLE001
                continue


def read_checkpoints(scope, target, seed: int, timeout=2000):
    _reset(target)
    scope.arm()
    target.simpleserial_write("p", struct.pack("<I", seed & 0xFFFFFFFF))
    scope.capture()
    try:
        trig = int(scope.adc.trig_count)
    except Exception:  # noqa: BLE001
        trig = None
    raw = target.simpleserial_read("p", CKPT_LEN, timeout=timeout)
    if raw is None or len(raw) < CKPT_LEN:
        return None
    raw = bytes(raw)
    if struct.unpack_from("<I", raw, 0)[0] != CKPT_MAGIC:
        return None
    t = struct.unpack_from("<IIIIII", raw, 4)
    sym = struct.unpack_from("<H", raw, 30)[0]
    return dict(t=t, status=raw[28], symbytes=sym, trig=trig)


def read_main(target, seed: int, timeout=2000):
    """Returns (cycles, symbytes) from the plain 'g' command."""
    _reset(target)
    target.simpleserial_write("g", struct.pack("<IB", seed & 0xFFFFFFFF, 0))
    raw = target.simpleserial_read("r", MAIN_LEN, timeout=timeout)
    if raw is None or len(raw) < MAIN_LEN:
        return None
    raw = bytes(raw)
    if struct.unpack_from("<I", raw, 0)[0] != MAIN_MAGIC:
        return None
    return (struct.unpack_from("<I", raw, 4)[0],
            struct.unpack_from("<H", raw, 36)[0])


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seeds", type=lambda s: [int(x, 0) for x in s.split(",")],
                   default=[1, 2])
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--firmware", default=None,
                   help="path to the .hex to flash. Giving this IMPLIES programming.")
    p.add_argument("--no-program", action="store_true",
                   help="use the binary already on the board instead of flashing")
    p.add_argument("--expect-symbytes", type=int, default=96,
                   help="KYBER_SYMBYTES the running build should report (0 to skip)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    scope, target = connect()
    try:
        if args.firmware and not args.no_program:
            if not str(args.firmware).endswith(".hex"):
                print(f"[warn] {args.firmware} is not a .hex -- the STM32 programmer "
                      "expects the .hex, not the .elf", file=sys.stderr)
            print(f"programming {args.firmware} ...")
            cw.program_target(scope, cw.programmers.STM32FProgrammer, args.firmware)
            scope.io.nrst = "low"; time.sleep(0.05)
            scope.io.nrst = "high_z"; time.sleep(0.2)
            _reset(target)
        elif not args.firmware:
            print("[note] no --firmware given: using whatever is already flashed")

        got = read_main(target, args.seeds[0])
        if got is None:
            raise RuntimeError("no valid 'g' response from the target")
        real, sym = got
        print(f"running build reports KYBER_SYMBYTES={sym}; "
              f"real poly_tomsg ('g') = {real} cycles\n")
        if args.expect_symbytes and sym != args.expect_symbytes:
            raise RuntimeError(
                f"the board is running a build with KYBER_SYMBYTES={sym}, not "
                f"{args.expect_symbytes}. This is almost certainly a stale flash left "
                "over from the loop-bound sweep. Rebuild with\n"
                "    make clean && make PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 -j\n"
                "(PLATFORM is required, even for clean), check the two #define defaults "
                "in the source are back at 96 and 8, and pass --firmware <...>.hex. "
                "Use --expect-symbytes 0 to bypass this check.")

        for seed in args.seeds:
            samples = []
            for _ in range(args.repeats):
                r = read_checkpoints(scope, target, seed)
                if r is None:
                    raise RuntimeError("no valid 'p' response; is the command registered?")
                samples.append(r)
            tset = {s["t"] for s in samples}
            if len(tset) != 1:
                print(f"  [warn] seed {seed:#x}: checkpoints not stable across repeats: "
                      f"{Counter(s['t'] for s in samples).most_common()}", file=sys.stderr)
            s = samples[0]
            t0, t1, t2, t3, t4, t5 = s["t"]

            if t2 == 0 or t3 == 0 or t3 <= t2:
                raise RuntimeError(
                    "t2/t3 are unset or non-increasing -- poly_tomsg_instr is missing its "
                    "DWT reads (it was probably edited into an exact copy of poly_tomsg). "
                    "Restore the two `g_t_preloop = DWT_CYCCNT_REG;` lines.")

            print(f"=== seed 0x{seed:08x}  (SYMBYTES={s['symbytes']}, "
                  f"trig_count={s['trig']}) ===")
            print(f"  t0 before trigger_high : {t0:>7}")
            print(f"  t1 after  trigger_high : {t1:>7}     trigger_high      = {t1-t0:>6}")
            print(f"  t2 before outer loop   : {t2:>7}     call + prologue   = {t2-t1:>6}"
                  "   (upper bound; includes the t2 read's own setup)")
            print(f"  t3 after  outer loop   : {t3:>7}     THE LOOP          = {t3-t2:>6}")
            print(f"  t4 after  function     : {t4:>7}     epilogue + return = {t4-t3:>6}")
            print(f"  t5 after  trigger_low  : {t5:>7}     trigger_low       = {t5-t4:>6}")
            print(f"  instrumented total     : {t5-t0:>7}"
                  + (f"   (real = {real}, instrumentation adds {t5-t0-real:+d})"
                     if real else ""))
            print(f"  pre-loop from t0       : {t2-t0:>7}"
                  "   <- cycles before the i-loop, CPU timeline")
            print()

        print("note: ext_offset is counted from the trigger's rising edge as the FPGA")
        print("sees it, which lags the GPIO store inside trigger_high() by an APB write")
        print("latency plus synchroniser delay -- not visible to any CPU counter. The")
        print("numbers above are the CPU timeline; mapping them onto ext_offset needs")
        print("that offset calibrated separately.")
    finally:
        try:
            scope.dis()
            target.dis()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
