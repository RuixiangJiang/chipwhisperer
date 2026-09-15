#!/usr/bin/env python3
"""
run_dilithium2_memtest.py -- build, flash, and exercise the full pqm4
Round 3 Dilithium2 pipeline on a CW308 / STM32F405, to establish whether
the part has enough memory and how much headroom remains.

No glitching. The Husky is used only as a programmer and clock source.

Reports, per stage: cycle count, peak stack depth (by stack painting),
and return code. Also reports the static footprint and the RAM left for
the stack, and checks that keygen and signing are reproducible across
resets.

Usage
    python3 run_dilithium2_memtest.py --build --program
    python3 run_dilithium2_memtest.py --run
    make clean PLATFORM=CW308_STM32F4 SS_VER=SS_VER_2_1 && make PLATFORM=CW308_STM32F4 SS_VER=SS_VER_2_1
    python3 run_dilithium2_memtest.py --all
    python3 run_dilithium2_memtest.py --run --dump sig.bin
"""

import argparse
import os
import subprocess
import sys
import time

PLATFORM = "CW308_STM32F4"
FW_NAME = "simpleserial-dilithium2-full"
SS_VER = "SS_VER_2_1"
BASE_FREQ = 7.37e6
BASE_BAUD = 230400

BUFS = {"pk": 0, "sk": 1, "sig": 2, "msg": 3}

OK = "  [ OK ]"
BAD = "  [FAIL]"
WARN = "  [warn]"


def hdr(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


# --------------------------------------------------------------------------
def stage_build(args):
    hdr("BUILD")
    margs = [f"PLATFORM={PLATFORM}", "CRYPTO_TARGET=NONE", f"SS_VER={SS_VER}"]
    cfg = subprocess.run(["make", "show-config"] + margs, cwd=args.fw_dir,
                         capture_output=True, text=True)
    print(cfg.stdout.rstrip())
    if cfg.returncode != 0:
        print(cfg.stderr.rstrip())
        sys.exit(1)

    subprocess.run(["make", "clean"] + margs, cwd=args.fw_dir, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.run(["make", "-j4"] + margs, cwd=args.fw_dir,
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout[-8000:])
        print(p.stderr[-8000:])
        print(f"{BAD} build failed")
        sys.exit(1)

    for line in p.stdout.splitlines():
        if any(k in line for k in ("text", "data", "bss", "dec", "error",
                                   "warning: ")):
            print("    " + line.rstrip())

    hexp = hex_path(args)
    if not os.path.exists(hexp):
        print(f"{BAD} no hex produced")
        sys.exit(1)
    print(f"{OK} {os.path.basename(hexp)}")
    return hexp


def hex_path(args):
    return os.path.join(args.fw_dir, f"{FW_NAME}-{PLATFORM}.hex")


# --------------------------------------------------------------------------
def connect(args):
    import chipwhisperer as cw
    sn = args.sn
    if sn is None:
        try:
            sns = [d.get("sn") for d in cw.list_devices()
                   if "husky" in str(d).lower()]
            sn = sns[0] if sns else None
        except Exception:
            sn = None
    scope = cw.scope(sn=sn) if sn else cw.scope()
    scope.default_setup()
    scope.clock.clkgen_freq = args.freq
    scope.io.hs2 = "clkgen"
    time.sleep(0.25)
    target = cw.target(scope, cw.targets.SimpleSerial2)
    target.baud = int(round(BASE_BAUD * args.freq / BASE_FREQ))
    return scope, target


def reset(scope, target):
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.30)
    target.flush()


def cmd(target, c, payload=b"", rlen=None, timeout=8000):
    target.flush()
    target.simpleserial_write(c, bytearray(payload))
    if rlen is None:
        try:
            return target.simpleserial_wait_ack(timeout=timeout)
        except Exception:
            return None
    try:
        v = target.simpleserial_read("r", rlen, timeout=timeout, ack=False)
    except Exception:
        return None
    if v is None or len(v) != rlen:
        return None
    try:
        target.simpleserial_wait_ack(timeout=200)
    except Exception:
        pass
    return bytes(v)


def fetch(target, which, length):
    out = bytearray()
    off = 0
    while off < length:
        b = cmd(target, "f", bytes([BUFS[which], off & 0xFF, (off >> 8) & 0xFF]),
                rlen=128)
        if b is None:
            return None
        out += b
        off += 128
    return bytes(out[:length])


# --------------------------------------------------------------------------
def stage_run(scope, target, args):
    hdr("DILITHIUM2 FULL PIPELINE")
    reset(scope, target)

    info = cmd(target, "i", rlen=16)
    if info is None:
        print(f"{BAD} no response to 'i' -- firmware not running.")
        return False
    pk_len, sk_len, sig_len, static_total = (u32(info, 0), u32(info, 4),
                                             u32(info, 8), u32(info, 12))
    print(f"    CRYPTO_PUBLICKEYBYTES : {pk_len}")
    print(f"    CRYPTO_SECRETKEYBYTES : {sk_len}")
    print(f"    CRYPTO_BYTES          : {sig_len}")
    print(f"    static buffers        : {static_total} B")

    mem = cmd(target, "r", rlen=16)
    bss, stop, avail = u32(mem, 0), u32(mem, 4), u32(mem, 8)
    print(f"    bss end               : 0x{bss:08x}")
    print(f"    stack top             : 0x{stop:08x}")
    print(f"    RAM available to stack: {avail} B ({avail/1024:.1f} KiB)")

    freq = scope.clock.clkgen_freq

    hdr("PER-STAGE MEASUREMENTS")
    results = {}
    for label, c, rlen in (("keypair", "j", 12),
                           ("sign", "s", 14),
                           ("verify", "x", 12)):
        r = cmd(target, c, rlen=rlen, timeout=args.timeout)
        if r is None:
            print(f"{BAD} {label}: no response (timeout or hard fault)")
            return False
        cyc, stk = u32(r, 0), u32(r, 4)
        if label == "sign":
            slen = r[8] | (r[9] << 8)
            rc = u32(r, 10)
        else:
            slen = None
            rc = u32(r, 8)
        results[label] = (cyc, stk, rc, slen)
        ms = 1000.0 * cyc / freq
        extra = f"  siglen={slen}" if slen is not None else ""
        print(f"    {label:<8} cycles={cyc:>10,}  ({ms:7.1f} ms @ "
              f"{freq/1e6:.2f} MHz)  stack={stk:>7,} B  rc={rc}{extra}")

    hdr("VERDICT")
    peak = max(v[1] for v in results.values())
    print(f"    peak stack across stages : {peak:,} B ({peak/1024:.1f} KiB)")
    print(f"    RAM available to stack   : {avail:,} B ({avail/1024:.1f} KiB)")
    head = avail - peak
    print(f"    headroom                 : {head:,} B ({head/1024:.1f} KiB, "
          f"{100.0*head/avail:.1f}%)")

    ok = True
    if results["verify"][2] != 0:
        print(f"{BAD} verify returned {results['verify'][2]}; the signature "
              "does not check out.")
        ok = False
    else:
        print(f"{OK} verify accepted the signature")

    if results["sign"][3] != sig_len:
        print(f"{WARN} siglen {results['sign'][3]} != CRYPTO_BYTES {sig_len}")

    if head < 0:
        print(f"{BAD} stack overflowed the available RAM.")
        ok = False
    elif head < 8 * 1024:
        print(f"{WARN} under 8 KiB of headroom; tight but running.")
    else:
        print(f"{OK} comfortable headroom")

    # Reproducibility: keygen is seeded deterministically, signing is
    # deterministic given sk, so a reset-and-repeat must match exactly.
    hdr("REPRODUCIBILITY")
    d1 = {k: cmd(target, "d", bytes([v]), rlen=32) for k, v in
          (("pk", 0), ("sk", 1), ("sig", 2))}
    reset(scope, target)
    cmd(target, "j", rlen=12, timeout=args.timeout)
    cmd(target, "s", rlen=14, timeout=args.timeout)
    d2 = {k: cmd(target, "d", bytes([v]), rlen=32) for k, v in
          (("pk", 0), ("sk", 1), ("sig", 2))}
    for k in ("pk", "sk", "sig"):
        if d1[k] is None or d2[k] is None:
            print(f"{WARN} {k}: digest unavailable")
        elif d1[k] == d2[k]:
            print(f"{OK} {k} reproducible  {d1[k][:8].hex()}")
        else:
            print(f"{BAD} {k} differs across runs")
            ok = False

    if args.dump:
        blob = fetch(target, "sig", results["sign"][3] or sig_len)
        if blob:
            with open(args.dump, "wb") as fh:
                fh.write(blob)
            print(f"\n{OK} signature written to {args.dump} ({len(blob)} B)")

    return ok


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--program", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--fw-dir", default=".")
    ap.add_argument("--sn", default=None)
    ap.add_argument("--freq", type=float, default=BASE_FREQ)
    ap.add_argument("--timeout", type=int, default=20000,
                    help="ms to wait for a stage (signing is slow at 7.37 MHz)")
    ap.add_argument("--dump", default=None, help="write the signature to a file")
    args = ap.parse_args()

    if args.all:
        args.build = args.program = args.run = True
    if not (args.build or args.program or args.run):
        ap.error("pick --build / --program / --run / --all")

    hexp = hex_path(args)
    if args.build:
        hexp = stage_build(args)

    scope = None
    try:
        if args.program or args.run:
            import chipwhisperer as cw
            scope, target = connect(args)
            print(f"\n    Husky sn {scope.sn}   clock "
                  f"{scope.clock.clkgen_freq/1e6:.4f} MHz   baud {target.baud}")
            if args.program:
                hdr("PROGRAM")
                cw.program_target(scope, cw.programmers.STM32FProgrammer, hexp)
                print(f"{OK} programmed")
                reset(scope, target)
            if args.run:
                ok = stage_run(scope, target, args)
                sys.exit(0 if ok else 2)
    except SystemExit:
        raise
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if scope is not None:
            try:
                scope.default_setup()
                scope.dis()
            except Exception:
                pass


if __name__ == "__main__":
    main()
