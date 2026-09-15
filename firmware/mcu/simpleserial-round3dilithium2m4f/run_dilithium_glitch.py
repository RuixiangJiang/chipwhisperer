#!/usr/bin/env python3
"""
run_dilithium_glitch.py -- reproduce Section 6.4 of Du et al., "Breaking the
Shield: Novel Fault Attacks on CRYSTALS-Dilithium" (ACISP 2025) on a
ChipWhisperer-Husky driving a CW308 UFO board with an STM32F405 target.

Attack target
    The load at line 13 of the paper's Fig. 12, inside
    KeccakF1600_StateExtractBytes, which should place the low 32 bits of
    state[0] into r5. Skipping it leaves r5 holding 0, so data[0] is written
    as 0 while the rest of the extracted block is untouched.

Outcome classes (the paper's criterion is `hit`)
    normal   136-byte block identical to the clean reference
    hit      byte 0 became 0, bytes 1..135 unchanged
    zero_other  some byte other than 0 was zeroed, rest unchanged
    other    block differs in some other way
    mute     no response (hang / crash / reset)

Stages
    --build     make in this directory
    --program   flash the hex over the STM32 serial bootloader
    --glitch    run the campaign

Typical session
    python3 run_dilithium_glitch.py --build --program
    python3 run_dilithium_glitch.py --glitch --locate            # find ext_offset
    python3 run_dilithium_glitch.py --glitch \
        --ext-min 16000 --ext-max 16100 --ext-step 1 \
        --width-center 4449 --offset-center 2350 --span 200 --step 8 --repeats 3

Paper's fault parameters were width = -3.125%, offset = -48.828125%,
ext_offset = 16048 on a ChipWhisperer-Lite. Husky expresses width and offset
as integer phase-shift steps rather than percentages of a clock period, so the
percentages are converted by scaling with scope.glitch.phase_shift_steps. The
conversion is a search centre, not an equivalence: on Husky width=0 is the
minimum pulse width, whereas on the Lite it means no pulse. ext_offset counts
target clock cycles on both and is the more transferable number, but it still
shifts with compiler version, so --locate exists to find it on your binary.
"""

import argparse
import binascii
import csv
import hashlib
import itertools
import os
import subprocess
import sys
import time

PLATFORM = "CW308_STM32F4"
FW_NAME = "simpleserial-round3dilithium2m4f"
SS_VER = "SS_VER_2_1"

BASE_FREQ = 7.37e6
BASE_BAUD = 230400          # SimpleSerial 2.1 at 7.37 MHz
RATE = 136                  # SHAKE256 rate, one extracted block

# Paper's CW-Lite parameters, as fractions of a clock period.
PAPER_WIDTH_FRAC = -0.03125
PAPER_OFFSET_FRAC = -0.48828125
PAPER_EXT_OFFSET = 16048

OK = "  [ OK ]"
BAD = "  [FAIL]"
WARN = "  [warn]"


def hdr(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


# --------------------------------------------------------------------------
# build / program
# --------------------------------------------------------------------------
def stage_build(args):
    hdr("STAGE 1 -- build")
    d = args.fw_dir
    margs = [f"PLATFORM={PLATFORM}", "CRYPTO_TARGET=NONE", f"SS_VER={SS_VER}"]

    cfg = subprocess.run(["make", "show-config"] + margs, cwd=d,
                         capture_output=True, text=True)
    print(cfg.stdout.rstrip())
    if cfg.returncode != 0:
        print(cfg.stderr.rstrip())
        print(f"{BAD} source discovery failed; fix the paths above first.")
        sys.exit(1)

    subprocess.run(["make", "clean"] + margs, cwd=d, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.run(["make", "-j4"] + margs, cwd=d,
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout[-6000:])
        print(p.stderr[-6000:])
        print(f"{BAD} make failed (exit {p.returncode})")
        sys.exit(1)
    for line in p.stdout.splitlines():
        if any(k in line for k in ("text", "data", "bss", "dec", "error",
                                   "warning: ")):
            print("    " + line.rstrip())

    hexp = hex_path(args)
    if not os.path.exists(hexp):
        print(f"{BAD} hex not produced: {hexp}")
        sys.exit(1)
    print(f"{OK} {os.path.basename(hexp)} ({os.path.getsize(hexp)} bytes)")
    return hexp


def hex_path(args):
    return os.path.join(args.fw_dir, f"{FW_NAME}-{PLATFORM}.hex")


def stage_program(scope, hexp):
    hdr("STAGE 2 -- program")
    import chipwhisperer as cw
    scope.io.hs2 = "clkgen"          # never flash through a glitched clock
    time.sleep(0.1)
    print(f"    {hexp}")
    cw.program_target(scope, cw.programmers.STM32FProgrammer, hexp)
    print(f"{OK} programmed")


# --------------------------------------------------------------------------
# scope / target
# --------------------------------------------------------------------------
def find_husky_sn(explicit=None):
    import chipwhisperer as cw
    if explicit:
        return explicit
    try:
        devs = cw.list_devices()
    except Exception:
        return None
    sns = [d.get("sn") for d in devs if "husky" in str(d).lower()]
    if len(sns) == 1:
        return sns[0]
    if not sns:
        print(f"{WARN} no Husky enumerated; trying a blind open.")
        return None
    print(f"{WARN} {len(sns)} Huskys found; pass --sn.")
    return sns[0]


def connect(args):
    import chipwhisperer as cw
    scope = cw.scope(sn=find_husky_sn(args.sn)) if True else None
    if not getattr(scope, "_is_husky", False):
        scope.dis()
        raise RuntimeError("connected device is not a Husky")
    scope.default_setup()
    scope.clock.clkgen_freq = args.freq
    scope.io.hs2 = "clkgen"
    time.sleep(0.25)
    return scope


def make_target(scope, args):
    import chipwhisperer as cw
    t = cw.target(scope, cw.targets.SimpleSerial2)
    t.baud = int(round(BASE_BAUD * args.freq / BASE_FREQ))
    print(f"    clock {args.freq/1e6:.4f} MHz -> baud {t.baud}")
    return t


def arm_glitch(scope, args):
    scope.glitch.enabled = True
    scope.glitch.clk_src = "pll"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_continuous"   # see chipwhisperer#566
    scope.glitch.repeat = args.repeat
    scope.glitch.width = 0
    scope.glitch.offset = 0
    scope.glitch.ext_offset = 0
    scope.io.hs2 = "glitch"
    time.sleep(0.25)


def reset_target(scope, target):
    scope.io.nrst = "low"
    time.sleep(0.03)
    scope.io.nrst = "high_z"
    time.sleep(0.10)
    target.flush()


# --------------------------------------------------------------------------
# firmware commands
# --------------------------------------------------------------------------
def cmd(target, c, payload=b"", rlen=None, timeout=200):
    target.flush()
    target.simpleserial_write(c, bytearray(payload))
    if rlen is None:
        try:
            target.simpleserial_wait_ack(timeout=timeout)
        except Exception:
            return None
        return b""
    try:
        v = target.simpleserial_read("r", rlen, timeout=timeout, ack=False)
    except Exception:
        return None
    if v is None:
        return None
    try:
        target.simpleserial_wait_ack(timeout=50)
    except Exception:
        pass
    return bytes(v)


def check_firmware(target):
    info = cmd(target, "i", rlen=8)
    print(f"    reg_status=0b{info[7]:08b}  (bit set = addcmd failed: "
          f"s/n/g/b/k/i = bits 0..5)")
    if info is None:
        print(f"{BAD} no response to 'i' -- firmware not running, or SS_VER "
              "mismatch.")
        return None
    crh, rate, nblocks = info[0], info[1], info[2]
    polyz = info[3] | (info[4] << 8)
    total = info[5] | (info[6] << 8)
    print(f"    CRHBYTES={crh}  STREAM256_BLOCKBYTES={rate}  "
          f"NBLOCKS={nblocks}  POLYZ_PACKEDBYTES={polyz}  squeeze={total}B")
    if rate != RATE:
        print(f"{BAD} expected a SHAKE256 rate of {RATE}, got {rate}.")
        return None
    if crh != 48:
        print(f"{WARN} CRHBYTES={crh}; Round 3 Dilithium uses 48. Check that "
              "DILITHIUM_DIR really points at the Round 3 tree.")
    return {"crh": crh, "rate": rate, "nblocks": nblocks}


def set_seed_nonce(target, crh, seed, nonce):
    if cmd(target, "s", seed[:crh]) is None:
        return False
    if cmd(target, "n", bytes([nonce & 0xFF, (nonce >> 8) & 0xFF])) is None:
        return False
    return True


def squeeze(target, timeout=200):
    return cmd(target, "g", rlen=RATE, timeout=timeout)


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------
def classify(ref, got):
    if got is None or len(got) != RATE:
        return "mute", None
    if got == ref:
        return "normal", None
    diff = [i for i in range(RATE) if got[i] != ref[i]]
    if diff == [0] and got[0] == 0:
        return "hit", diff
    if len(diff) == 1 and got[diff[0]] == 0:
        return "zero_other", diff
    return "other", diff


# --------------------------------------------------------------------------
# campaign
# --------------------------------------------------------------------------
def frange(lo, hi, step):
    out, v = [], lo
    while v <= hi:
        out.append(int(v))
        v += step
    return out


def paper_params(psteps):
    """Convert the paper's CW-Lite percentages to Husky phase-shift steps."""
    w = int(round(PAPER_WIDTH_FRAC * psteps))
    o = int(round(PAPER_OFFSET_FRAC * psteps))
    return w % psteps, o % psteps


def stage_glitch(scope, target, args):
    hdr("STAGE 3 -- campaign")
    arm_glitch(scope, args)
    psteps = scope.glitch.phase_shift_steps
    pw, po = paper_params(psteps)
    print(f"    phase_shift_steps = {psteps}")
    print(f"    paper width  {PAPER_WIDTH_FRAC*100:+.6f}%  -> {pw} steps")
    print(f"    paper offset {PAPER_OFFSET_FRAC*100:+.6f}%  -> {po} steps")
    print(f"    paper ext_offset = {PAPER_EXT_OFFSET} target cycles")

    fw = check_firmware(target)
    if fw is None:
        return

    # Fixed seed; pick a nonce whose clean data[0] is non-zero, since the
    # attack is defined as data[0] going non-zero -> 0.
    seed = bytes((i * 7 + 1) & 0xFF for i in range(64))
    ref = None
    nonce = args.nonce
    for _ in range(16):
        if not set_seed_nonce(target, fw["crh"], seed, nonce):
            print(f"{BAD} could not set seed/nonce")
            return
        ref = squeeze(target)
        if ref is None:
            print(f"{BAD} no response to 'g'")
            return
        if ref[0] != 0:
            break
        print(f"{WARN} clean data[0] == 0 at nonce {nonce}; trying next")
        nonce += 1
    if ref is None or ref[0] == 0:
        print(f"{BAD} could not find a nonce with non-zero data[0]")
        return

    print(f"{OK} reference block at nonce {nonce}: "
          f"data[0]=0x{ref[0]:02x}  sha256={hashlib.sha256(ref).hexdigest()[:16]}")

    expect = hashlib.shake_256(
        seed[:fw["crh"]] + nonce.to_bytes(2, "little")).digest(RATE)
    if ref != expect:
        print(f"{BAD} squeeze does not match host SHAKE256(seed || nonce)")
        print(f"      device {ref[:16].hex()}")
        print(f"      host   {expect[:16].hex()}")
        if not args.force:
            return
    else:
        print(f"{OK} 'g' matches host SHAKE256(seed || nonce)")

    # Reference stability: any drift here means the classifier will misfire.
    for _ in range(5):
        if squeeze(target) != ref:
            print(f"{BAD} reference block is not reproducible; stop and fix "
                  "this before sweeping.")
            if not args.force:
                return
    print(f"{OK} reference stable over 5 repeats")

    # ---- parameter grid ---------------------------------------------------
    if args.locate:
        widths = [pw]
        offsets = [po]
        exts = frange(args.ext_min if args.ext_min is not None
                      else PAPER_EXT_OFFSET - 400,
                      args.ext_max if args.ext_max is not None
                      else PAPER_EXT_OFFSET + 400,
                      args.ext_step)
    else:
        wc = args.width_center if args.width_center is not None else pw
        oc = args.offset_center if args.offset_center is not None else po
        widths = frange(wc - args.span, wc + args.span, args.step)
        offsets = frange(oc - args.span, oc + args.span, args.step)
        exts = frange(args.ext_min if args.ext_min is not None
                      else PAPER_EXT_OFFSET - 40,
                      args.ext_max if args.ext_max is not None
                      else PAPER_EXT_OFFSET + 40,
                      args.ext_step)

    widths = [w % psteps for w in widths]
    offsets = [o % psteps for o in offsets]
    grid = list(itertools.product(exts, widths, offsets))
    total = len(grid) * args.repeats
    print(f"\n    ext_offset : {len(exts)} values "
          f"[{exts[0]} .. {exts[-1]}]")
    print(f"    width      : {len(widths)} values")
    print(f"    offset     : {len(offsets)} values")
    print(f"    attempts   : {total}")

    new = not os.path.exists(args.csv)
    fh = open(args.csv, "a", newline="")
    w = csv.writer(fh)
    if new:
        w.writerow(["ts", "ext_offset", "width", "offset", "repeat",
                    "outcome", "diff_idx", "diff_vals", "data0",
                    "block_sha256"])

    tally = {"normal": 0, "hit": 0, "zero_other": 0, "other": 0, "mute": 0}
    hits = []
    t0, done = time.time(), 0

    try:
        for ext, gw, go in grid:
            scope.glitch.ext_offset = ext
            scope.glitch.width = gw
            scope.glitch.offset = go

            for _ in range(args.repeats):
                got = squeeze(target, timeout=args.timeout)
                outcome, diff = classify(ref, got)
                tally[outcome] += 1
                done += 1

                w.writerow([f"{time.time():.3f}", ext, gw, go, args.repeat,
                            outcome,
                            "" if not diff else ";".join(map(str, diff[:8])),
                            "" if not diff or got is None else
                                ";".join(f"{got[i]:02x}" for i in diff[:8]),
                            "" if got is None else got[0],
                            "" if got is None
                            else hashlib.sha256(got).hexdigest()[:16]])

                if outcome == "hit":
                    hits.append((ext, gw, go))
                    print(f"  HIT  ext={ext:6d} w={gw:5d} off={go:5d}  "
                          f"data[0] 0x{ref[0]:02x} -> 0x00, rest intact")
                elif outcome == "mute":
                    reset_target(scope, target)
                    set_seed_nonce(target, fw["crh"], seed, nonce)
                elif outcome in ("zero_other", "other") and args.verbose:
                    n = len(diff)
                    vals = ";".join(f"{got[i]:02x}" for i in diff[:4])
                    print(f"  {outcome:10s} ext={ext:6d} w={gw:5d} off={go:5d} "
                          f"({n} byte{'s' if n != 1 else ''} differ, "
                          f"first at {diff[0]}, vals {vals})")

                if done % args.progress == 0:
                    r = done / max(1e-9, time.time() - t0)
                    print(f"  ... {done}/{total}  {r:5.1f} att/s  " +
                          "  ".join(f"{k}={v}" for k, v in tally.items()))
                    fh.flush()
    except KeyboardInterrupt:
        print("\n  interrupted.")
    finally:
        fh.close()
        summary(tally, hits, time.time() - t0, args.csv)


def summary(tally, hits, elapsed, csv_path):
    hdr("SUMMARY")
    total = sum(tally.values())
    for k in ("normal", "hit", "zero_other", "other", "mute"):
        pct = 100.0 * tally[k] / total if total else 0.0
        print(f"    {k:<11}: {tally[k]:7d}  ({pct:5.2f}%)")
    print(f"    elapsed    : {elapsed:.1f} s")
    print(f"    csv        : {csv_path}")

    denom = tally["hit"] + tally["normal"] + tally["zero_other"] + tally["other"]
    if denom:
        print(f"\n    success rate (hits / responded) = "
              f"{100.0*tally['hit']/denom:.1f}%   "
              f"(paper reports 39.0%)")

    if not hits:
        print("\n    No hits. Order of things to try:")
        print("      1. --locate to find the real ext_offset for your binary;")
        print("         16048 is the paper's value for their compiler.")
        print("      2. widen --span, or sweep the full phase plane at the")
        print("         located ext_offset.")
        print("      3. --repeat 2..4 (consecutive glitched cycles).")
        print("      4. confirm the target runs directly off the CW clock with")
        print("         no internal PLL; otherwise the glitch never lands.")
        if tally["other"]:
            print("\n    'other' outcomes did occur, so glitches are reaching")
            print("    the target -- this is a targeting problem, not a")
            print("    delivery problem.")
        return

    print(f"\n    {len(hits)} hit(s). Productive ranges:")
    print(f"      ext_offset : {min(h[0] for h in hits)} .. "
          f"{max(h[0] for h in hits)}")
    print(f"      width      : {min(h[1] for h in hits)} .. "
          f"{max(h[1] for h in hits)}")
    print(f"      offset     : {min(h[2] for h in hits)} .. "
          f"{max(h[2] for h in hits)}")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--program", action="store_true")
    ap.add_argument("--glitch", action="store_true")

    ap.add_argument("--fw-dir", default=".")
    ap.add_argument("--sn", default=None)
    ap.add_argument("--freq", type=float, default=BASE_FREQ)
    ap.add_argument("--csv", default="dilithium_sec64_results.csv")
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--verbose", action="store_true")

    ap.add_argument("--locate", action="store_true",
                    help="sweep ext_offset only, at the paper's width/offset")
    ap.add_argument("--ext-min", type=int, default=None)
    ap.add_argument("--ext-max", type=int, default=None)
    ap.add_argument("--ext-step", type=int, default=1)
    ap.add_argument("--width-center", type=int, default=None)
    ap.add_argument("--offset-center", type=int, default=None)
    ap.add_argument("--span", type=int, default=150,
                    help="+/- range around the centres, in phase steps")
    ap.add_argument("--step", type=int, default=10)

    ap.add_argument("--repeat", type=int, default=1,
                    help="scope.glitch.repeat: consecutive glitched cycles")
    ap.add_argument("--repeats", type=int, default=1,
                    help="attempts per parameter point")
    ap.add_argument("--timeout", type=int, default=200)
    ap.add_argument("--progress", type=int, default=200)
    args = ap.parse_args()

    if args.all:
        args.build = args.program = args.glitch = True
    if not (args.build or args.program or args.glitch):
        ap.error("pick at least one of --build / --program / --glitch / --all")

    hexp = hex_path(args)
    if args.build:
        hexp = stage_build(args)

    scope = None
    try:
        if args.program or args.glitch:
            hdr("CONNECT")
            scope = connect(args)
            print(f"    Husky sn {scope.sn}")
            target = make_target(scope, args)
            if args.program:
                stage_program(scope, hexp)
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
                scope.io.hs2 = "clkgen"
                scope.default_setup()      # park ADC clock before dis()
                scope.dis()
                print("\n    scope disconnected.")
            except Exception:
                pass


if __name__ == "__main__":
    main()
