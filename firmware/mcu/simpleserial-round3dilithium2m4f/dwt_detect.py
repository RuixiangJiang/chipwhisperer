#!/usr/bin/env python3
"""
dwt_detect.py -- measure whether the DWT performance counters can detect the
Section 6.4 load-zeroing fault on a ChipWhisperer-Husky / STM32F405 target.

Design
    Collect N clean runs (glitch module disabled entirely) and M glitched
    runs at the known fault parameters. Every run yields six DWT counters
    plus the 136-byte extracted block. The block gives ground truth:

        hit         data[0] 0x00, rest unchanged   -> the load-zeroing fault
        store_skip  data[0] 0xA5, rest unchanged   -> skipped strb.w
        other       any other difference
        normal      identical to the clean reference
        mute        no response

    Clean runs are split into a CALIBRATION half, which defines a
    [min, max] range per counter, and an EVALUATION half, which is scored
    against those ranges. Deriving the range and measuring the false
    positive rate on the same runs would force FPR to zero by construction.

    A run is predicted FAULTED if any counter falls outside its clean range.

Metrics
    TPR   hits flagged / hits
    FPR   held-out clean runs flagged / held-out clean runs
    Precision, F1, MCC, plus per-counter flag rates.

    Glitched-but-normal runs are reported separately. A glitch was delivered
    but had no architectural effect, so there is nothing for a detector to
    catch; their flag rate says whether the detector is responding to the
    pulse rather than to the fault.

Counter caveat
    CPICNT, EXCCNT, SLEEPCNT, LSUCNT, FOLDCNT are 8-bit and wrap at 256
    over the ~106k-cycle window, so values are (true count mod 256). Small
    deltas stay visible; a clean value near 0 or 255 makes a small delta
    straddle the wrap and look enormous. Such counters are flagged.

Usage
    python3 dwt_detect.py --clean 500 --glitch 1500
    python3 dwt_detect.py --clean 500 --glitch 1500 --csv dwt_runs.csv
    python3 dwt_detect.py --analyze dwt_runs.csv
"""

import argparse
import csv
import hashlib
import math
import os
import sys
import time
from collections import Counter

SN_DEFAULT = None
BASE_FREQ = 7.37e6
BASE_BAUD = 230400
RATE = 136
NCTR = 6
CTR_NAMES = ["CYCCNT", "CPICNT", "EXCCNT", "SLEEPCNT", "LSUCNT", "FOLDCNT"]
CTR_WIDTH = [32, 8, 8, 8, 8, 8]

# Tuned fault parameters: 64.2% of all attempts, 93.6% of responders.
FAULT_EXT = 18155
FAULT_WIDTH = 4512
FAULT_OFFSET = 2348

OK = "  [ OK ]"
BAD = "  [FAIL]"
WARN = "  [warn]"


def hdr(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


# --------------------------------------------------------------------------
# device
# --------------------------------------------------------------------------
def find_husky_sn(explicit=None):
    import chipwhisperer as cw
    if explicit:
        return explicit
    try:
        sns = [d.get("sn") for d in cw.list_devices()
               if "husky" in str(d).lower()]
        return sns[0] if sns else None
    except Exception:
        return None


def connect(args):
    import chipwhisperer as cw
    sn = find_husky_sn(args.sn)
    scope = cw.scope(sn=sn) if sn else cw.scope()
    if not getattr(scope, "_is_husky", False):
        scope.dis()
        raise RuntimeError("connected device is not a Husky")
    scope.default_setup()
    scope.clock.clkgen_freq = args.freq
    scope.io.hs2 = "clkgen"
    time.sleep(0.25)
    target = cw.target(scope, cw.targets.SimpleSerial2)
    target.baud = int(round(BASE_BAUD * args.freq / BASE_FREQ))
    return scope, target


def reset(scope, target):
    scope.io.nrst = "low"
    time.sleep(0.03)
    scope.io.nrst = "high_z"
    time.sleep(0.12)
    target.flush()


def cmd(target, c, payload=b"", rlen=None, timeout=300):
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
        target.simpleserial_wait_ack(timeout=100)
    except Exception:
        pass
    return bytes(v)


def squeeze(target, timeout=300):
    """Returns (counters[6], block[136]) or (None, None)."""
    r = cmd(target, "g", rlen=24 + RATE, timeout=timeout)
    if r is None:
        return None, None
    return [u32(r, 4 * i) for i in range(NCTR)], r[24:]


def enable_glitch(scope, ext, width, offset, repeat=1):
    scope.glitch.enabled = True
    scope.glitch.clk_src = "pll"
    scope.glitch.output = "clock_xor"
    scope.glitch.trigger_src = "ext_continuous"
    scope.glitch.repeat = repeat
    scope.glitch.ext_offset = ext
    scope.glitch.width = width
    scope.glitch.offset = offset
    scope.io.hs2 = "glitch"
    time.sleep(0.2)


def disable_glitch(scope):
    """Fully disarm: clean runs must see no pulse at all, so the clock path
    itself goes back to clkgen. Glitch parameters are only writable while
    the module is enabled and locked, so park them first, then disable."""
    scope.io.hs2 = "clkgen"
    if getattr(scope.glitch, "enabled", False):
        try:
            scope.glitch.width = 0
            scope.glitch.offset = 0
            scope.glitch.ext_offset = 0
        except Exception:
            pass
        try:
            scope.glitch.enabled = False
        except Exception:
            pass
    time.sleep(0.2)


# --------------------------------------------------------------------------
# labelling
# --------------------------------------------------------------------------
def classify(ref, got):
    if got is None:
        return "mute"
    if got == ref:
        return "normal"
    diff = [i for i in range(RATE) if got[i] != ref[i]]
    if diff == [0] and got[0] == 0x00:
        return "hit"
    if diff == [0] and got[0] == 0xA5:
        return "store_skip"
    return "other"


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
def collect(args):
    scope, target = connect(args)
    try:
        hdr("SETUP")
        info = cmd(target, "i", rlen=8)
        if info is None:
            print(f"{BAD} no response to 'i'")
            return None
        print(f"    rate={info[1]}  nblocks={info[2]}  CRHBYTES={info[0]}")

        d = cmd(target, "d", rlen=8)
        if d is None:
            print(f"{BAD} no response to 'd' -- firmware lacks DWT support")
            return None
        print(f"    DWT_CTRL=0x{u32(d,0):08x}  profiling={'yes' if d[4] else 'NO'}"
              f"  cyccnt={'yes' if d[5] else 'NO'}  trcena={'yes' if d[6] else 'NO'}")
        if not d[4]:
            print(f"{BAD} profiling counters not implemented on this part.")
            return None

        disable_glitch(scope)
        reset(scope, target)

        _, ref = squeeze(target)
        if ref is None:
            print(f"{BAD} no response to 'g'")
            return None
        if ref[0] == 0:
            print(f"{WARN} clean data[0] is 0; the fault would be invisible. "
                  "Change the nonce.")
        print(f"{OK} reference data[0]=0x{ref[0]:02x} "
              f"sha={hashlib.sha256(ref).hexdigest()[:16]}")

        rows = []

        hdr(f"CLEAN RUNS (n={args.clean})")
        t0 = time.time()
        for k in range(args.clean):
            c, b = squeeze(target)
            lab = classify(ref, b)
            if lab == "mute":
                reset(scope, target)
                continue
            if lab != "normal":
                print(f"{WARN} clean run {k} classified {lab} -- glitch not "
                      "fully disabled?")
            rows.append(("clean", lab, c))
            if (k + 1) % 200 == 0:
                print(f"    {k+1}/{args.clean}  "
                      f"{(k+1)/(time.time()-t0):.1f}/s")

        hdr(f"GLITCHED RUNS (n={args.glitch}) at ext={args.ext} "
            f"w={args.width} off={args.offset}")
        enable_glitch(scope, args.ext, args.width, args.offset, args.repeat)
        reset(scope, target)
        t0 = time.time()
        tally = Counter()
        for k in range(args.glitch):
            c, b = squeeze(target)
            lab = classify(ref, b)
            tally[lab] += 1
            if lab == "mute":
                reset(scope, target)
                continue
            rows.append(("glitch", lab, c))
            if (k + 1) % 200 == 0:
                print(f"    {k+1}/{args.glitch}  "
                      f"{(k+1)/(time.time()-t0):.1f}/s  {dict(tally)}")
        print(f"    outcomes: {dict(tally)}")

        if args.csv:
            new = not os.path.exists(args.csv)
            with open(args.csv, "a", newline="") as fh:
                w = csv.writer(fh)
                if new:
                    w.writerow(["source", "label"] + CTR_NAMES)
                for src, lab, c in rows:
                    w.writerow([src, lab] + list(c))
            print(f"{OK} wrote {len(rows)} rows to {args.csv}")

        return rows
    finally:
        try:
            scope.io.hs2 = "clkgen"
            scope.default_setup()
            scope.dis()
        except Exception:
            pass


def load_csv(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append((r["source"], r["label"],
                         [int(r[n]) for n in CTR_NAMES]))
    return rows


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------
def describe(name, vals):
    if not vals:
        return f"    {name:<9} (no samples)"
    lo, hi = min(vals), max(vals)
    mean = sum(vals) / len(vals)
    uniq = len(set(vals))
    return (f"    {name:<9} n={len(vals):<6} min={lo:<10} max={hi:<10} "
            f"mean={mean:<12.1f} distinct={uniq}")


def analyze(rows, args):
    clean = [c for s, l, c in rows if s == "clean" and l == "normal"]
    hits = [c for s, l, c in rows if s == "glitch" and l == "hit"]
    gnorm = [c for s, l, c in rows if s == "glitch" and l == "normal"]
    gstore = [c for s, l, c in rows if s == "glitch" and l == "store_skip"]
    gother = [c for s, l, c in rows if s == "glitch" and l == "other"]

    hdr("SAMPLE COUNTS")
    print(f"    clean/normal      : {len(clean)}")
    print(f"    glitch/hit        : {len(hits)}      <- positives")
    print(f"    glitch/normal     : {len(gnorm)}     (pulse, no effect)")
    print(f"    glitch/store_skip : {len(gstore)}")
    print(f"    glitch/other      : {len(gother)}")

    if len(clean) < 20 or len(hits) < 20:
        print(f"\n{BAD} too few samples for meaningful rates.")
        return

    hdr("PER-COUNTER DISTRIBUTIONS")
    for i, n in enumerate(CTR_NAMES):
        print(f"  {n}  ({CTR_WIDTH[i]}-bit)")
        print(describe("clean", [c[i] for c in clean]))
        print(describe("hit", [c[i] for c in hits]))
        if gnorm:
            print(describe("g/normal", [c[i] for c in gnorm]))

    # Wrap hazard: an 8-bit counter whose clean values sit near a boundary.
    hdr("WRAP CHECK")
    for i, n in enumerate(CTR_NAMES):
        if CTR_WIDTH[i] != 8:
            continue
        vals = [c[i] for c in clean]
        lo, hi = min(vals), max(vals)
        if lo <= 3 or hi >= 252:
            print(f"{WARN} {n}: clean range [{lo},{hi}] sits at a wrap "
                  "boundary; small deltas may appear as large jumps.")
        else:
            print(f"{OK} {n}: clean range [{lo},{hi}], clear of wrap.")

    # Calibration / evaluation split.
    k = len(clean) // 2
    calib, evalc = clean[:k], clean[k:]
    lo = [min(c[i] for c in calib) for i in range(NCTR)]
    hi = [max(c[i] for c in calib) for i in range(NCTR)]

    hdr("CLEAN RANGES (from calibration half)")
    for i, n in enumerate(CTR_NAMES):
        print(f"    {n:<9} [{lo[i]}, {hi[i]}]"
              + ("   (degenerate: single value)" if lo[i] == hi[i] else ""))

    def flagged(c):
        return any(c[i] < lo[i] or c[i] > hi[i] for i in range(NCTR))

    def per_counter(c):
        return [1 if (c[i] < lo[i] or c[i] > hi[i]) else 0 for i in range(NCTR)]

    tp = sum(1 for c in hits if flagged(c))
    fn = len(hits) - tp
    fp = sum(1 for c in evalc if flagged(c))
    tn = len(evalc) - fp

    tpr = tp / len(hits) if hits else 0.0
    fpr = fp / len(evalc) if evalc else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tpr
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0

    hdr("DETECTION PERFORMANCE")
    print("    predicted FAULTED if any counter is outside its clean range")
    print(f"\n                  flagged    not flagged")
    print(f"    hit  (P={len(hits):<5})  {tp:<10} {fn}")
    print(f"    clean(N={len(evalc):<5})  {fp:<10} {tn}")
    print()
    print(f"    TPR (recall)  : {tpr:.4f}")
    print(f"    FPR           : {fpr:.4f}")
    print(f"    TNR           : {1-fpr:.4f}")
    print(f"    Precision     : {prec:.4f}")
    print(f"    F1            : {f1:.4f}")
    print(f"    MCC           : {mcc:.4f}")

    hdr("PER-COUNTER FLAG RATES")
    print(f"    {'counter':<10} {'hit':>10} {'clean(eval)':>13} "
          f"{'g/normal':>10}")
    for i, n in enumerate(CTR_NAMES):
        h = sum(per_counter(c)[i] for c in hits) / len(hits)
        e = sum(per_counter(c)[i] for c in evalc) / len(evalc)
        g = (sum(per_counter(c)[i] for c in gnorm) / len(gnorm)) if gnorm else float('nan')
        print(f"    {n:<10} {h:>10.4f} {e:>13.4f} {g:>10.4f}")

    if gnorm:
        gf = sum(1 for c in gnorm if flagged(c)) / len(gnorm)
        print(f"\n    glitch/normal flag rate: {gf:.4f}")
        print("    (a pulse was delivered but had no architectural effect;")
        print("     a high rate here means the detector responds to the")
        print("     glitch itself rather than to the fault)")
    if gstore:
        sf = sum(1 for c in gstore if flagged(c)) / len(gstore)
        print(f"    store_skip flag rate   : {sf:.4f}")
        print("    (this one IS an instruction skip -- expected to be")
        print("     detectable where the load-zeroing fault is not)")

    hdr("READING")
    if tpr < 0.1 and fpr < 0.1:
        print("    The counters do not separate the fault from clean runs.")
        print("    Consistent with a data-only fault: the load executes and")
        print("    retires, only its returned value is wrong, so no counter")
        print("    that measures retirement, stalls or LSU activity moves.")
    elif tpr > 0.8 and fpr < 0.1:
        print("    The counters separate the two classes cleanly. Check which")
        print("    counter carries the signal and whether it is the fault")
        print("    itself or a side effect of the glitch on timing.")
    else:
        print("    Partial separation. Inspect the per-counter table before")
        print("    drawing conclusions; a single counter may carry all of it.")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--analyze", metavar="CSV",
                    help="skip collection, analyze an existing CSV")
    ap.add_argument("--clean", type=int, default=500)
    ap.add_argument("--glitch", type=int, default=1500)
    ap.add_argument("--ext", type=int, default=FAULT_EXT)
    ap.add_argument("--width", type=int, default=FAULT_WIDTH)
    ap.add_argument("--offset", type=int, default=FAULT_OFFSET)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--sn", default=SN_DEFAULT)
    ap.add_argument("--freq", type=float, default=BASE_FREQ)
    ap.add_argument("--csv", default="dwt_runs.csv")
    args = ap.parse_args()

    if args.analyze:
        rows = load_csv(args.analyze)
        print(f"loaded {len(rows)} rows from {args.analyze}")
    else:
        rows = collect(args)
        if rows is None:
            sys.exit(1)

    analyze(rows, args)


if __name__ == "__main__":
    main()
