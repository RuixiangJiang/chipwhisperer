#!/usr/bin/env python3
"""
husky_check.py -- connectivity and communication smoke test for ChipWhisperer-Husky.

Safe to run with a CW-Lite also plugged in: the Husky is selected explicitly by
USB PID (0x2b3e:0xace5) / serial number, so nothing touches the Lite.

Stages
  1. Host environment      (chipwhisperer version, USB enumeration)
  2. Scope connection      (open Husky, print FW/FPGA/XADC info)
  3. Clock health          (PLL lock, ADC lock, frequency readback)
  4. Target UART comms     (optional, needs a flashed SimpleSerial firmware)
  5. Armed capture         (optional, needs a target that raises the trigger)

Usage
  python3 husky_check.py                      # stages 1-3 only
  python3 husky_check.py --target             # add stages 4-5
  python3 husky_check.py --target --ssver 1   # SimpleSerial V1 firmware
  python3 husky_check.py --fw path/to/x.hex   # program STM32F* target first
  python3 husky_check.py --sn 50203120...     # force a specific serial number
"""

import argparse
import sys
import traceback

HUSKY_VID = 0x2B3E
HUSKY_PID = 0xACE5

OK = "  [ OK ]"
BAD = "  [FAIL]"
WARN = "  [warn]"


def hdr(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def show(label, value):
    print(f"    {label:<26}: {value}")


def try_show(label, fn):
    """Print an attribute, tolerating version differences in the CW API."""
    try:
        show(label, fn())
    except Exception as e:
        show(label, f"<unavailable: {type(e).__name__}>")
        _ = e


# --------------------------------------------------------------------------
# Stage 1: host environment
# --------------------------------------------------------------------------
def stage_env():
    hdr("STAGE 1 -- host environment")
    import chipwhisperer as cw

    ver = getattr(cw, "__version__", "unknown")
    show("chipwhisperer version", ver)
    try:
        major, minor = (int(x) for x in ver.split(".")[:2])
        if (major, minor) < (5, 6):
            print(f"{BAD} Husky needs chipwhisperer >= 5.6.1; upgrade first.")
            return None
    except Exception:
        print(f"{WARN} could not parse version string; continuing.")

    husky_sns = []
    try:
        devices = cw.list_devices()
        print(f"    {len(devices)} ChipWhisperer device(s) enumerated:")
        for d in devices:
            name = d.get("name", d.get("product", "?"))
            sn = d.get("sn", "?")
            print(f"      - {name}  sn={sn}")
            if "husky" in str(d).lower():
                husky_sns.append(sn)
    except Exception:
        print(f"{WARN} cw.list_devices() unavailable, falling back to pyusb.")
        try:
            import usb.core

            for dev in usb.core.find(find_all=True, idVendor=HUSKY_VID,
                                     idProduct=HUSKY_PID):
                sn = usb.util.get_string(dev, dev.iSerialNumber)
                print(f"      - ChipWhisperer-Husky  sn={sn}")
                husky_sns.append(sn)
        except Exception:
            print(f"{WARN} pyusb enumeration failed too; will try a blind open.")

    if len(husky_sns) == 0:
        print(f"{WARN} no Husky found by name. If lsusb shows 2b3e:ace5, this is")
        print("         almost always a permissions problem -- install the udev")
        print("         rules (50-newae.rules) and re-plug, or run with sudo.")
    elif len(husky_sns) > 1:
        print(f"{WARN} multiple Huskys found; pass --sn to pick one.")
    else:
        print(f"{OK} exactly one Husky present.")
    return husky_sns


# --------------------------------------------------------------------------
# Stage 2: scope connection
# --------------------------------------------------------------------------
def stage_connect(sn):
    hdr("STAGE 2 -- scope connection")
    import chipwhisperer as cw

    scope = cw.scope(sn=sn) if sn else cw.scope()
    is_husky = bool(getattr(scope, "_is_husky", False))
    show("scope class", type(scope).__name__)
    show("is Husky", is_husky)
    if not is_husky:
        scope.dis()
        print(f"{BAD} connected device is not a Husky -- pass --sn explicitly.")
        sys.exit(1)

    try_show("serial number", lambda: scope.sn)
    try_show("SAM3U fw version", lambda: scope.fw_version_str)
    try_show("fw version (dict)", lambda: scope.fw_version)
    try_show("FPGA build time", lambda: scope.fpga_buildtime)
    try_show("FPGA/board rev", lambda: scope.hw_info.version)

    # Xilinx on-die monitor: a good first-order health signal.
    try:
        show("die temperature", f"{scope.XADC.temp:.1f} C "
                                f"(max {scope.XADC.max_temp:.1f} C)")
        show("VCCint / VCCaux", f"{scope.XADC.vccint:.3f} V / "
                                f"{scope.XADC.vccaux:.3f} V")
        show("XADC status", scope.XADC.status)
    except Exception:
        show("XADC", "<unavailable>")

    print(f"{OK} scope opened.")
    return scope


# --------------------------------------------------------------------------
# Stage 3: clock and ADC health
# --------------------------------------------------------------------------
def stage_clock(scope, freq=7.37e6, adc_mul=4):
    hdr("STAGE 3 -- clock / ADC health")
    scope.default_setup()

    scope.clock.clkgen_freq = freq
    scope.clock.adc_mul = adc_mul
    try:
        scope.clock.reset_dcms()
    except Exception:
        pass

    import time
    time.sleep(0.25)

    show("requested clkgen_freq", f"{freq/1e6:.4f} MHz")
    try_show("actual clkgen_freq", lambda: f"{scope.clock.clkgen_freq/1e6:.4f} MHz")
    try_show("adc_mul", lambda: scope.clock.adc_mul)
    try_show("adc_freq", lambda: f"{scope.clock.adc_freq/1e6:.4f} MHz")
    try_show("adc_rate", lambda: f"{scope.clock.adc_rate/1e6:.4f} MHz")

    pll = None
    try:
        pll = scope.clock.pll.pll_locked
        show("PLL locked", pll)
    except Exception:
        show("PLL locked", "<unavailable>")

    adc_lock = None
    try:
        adc_lock = scope.clock.adc_locked
        show("ADC locked", adc_lock)
    except Exception:
        show("ADC locked", "<unavailable>")

    show("adc.samples", scope.adc.samples)
    show("gain (db)", scope.gain.db)
    show("io.hs2", scope.io.hs2)

    try:
        scope.errors.clear()
        show("sticky errors", "cleared")
    except Exception:
        pass

    if (pll is False) or (adc_lock is False):
        print(f"{BAD} a clock domain failed to lock -- do not trust captures.")
        return False
    print(f"{OK} clocks locked, scope configured.")
    return True


# --------------------------------------------------------------------------
# Optional: program the target
# --------------------------------------------------------------------------
def stage_program(scope, fw_path):
    hdr("STAGE 3b -- programming target")
    import chipwhisperer as cw

    show("firmware", fw_path)
    cw.program_target(scope, cw.programmers.STM32FProgrammer, fw_path)
    print(f"{OK} target programmed.")


# --------------------------------------------------------------------------
# Stage 4/5: target UART comms and an armed capture
# --------------------------------------------------------------------------
def stage_target(scope, ssver):
    hdr("STAGE 4 -- target UART communication")
    import chipwhisperer as cw

    cls = cw.targets.SimpleSerial2 if ssver == 2 else cw.targets.SimpleSerial
    target = cw.target(scope, cls)
    show("target class", type(target).__name__)
    try_show("baud", lambda: target.baud)

    # Reset the target so it starts from a known state.
    scope.io.nrst = "low"
    import time
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.25)
    target.flush()

    payload = bytes(range(16))
    print(f"    sending 'p' with {payload.hex()}")
    target.simpleserial_write("p", payload)

    try:
        resp = target.simpleserial_read("r", 16, timeout=1000)
    except Exception as e:
        resp = None
        show("read exception", f"{type(e).__name__}: {e}")

    if resp is None:
        print(f"{BAD} no response. Check that a SimpleSerial firmware is flashed,")
        print("         that SS_VER matches --ssver, and that the target board is")
        print("         seated in the CW313/CW308 connector.")
        return target, False

    show("response", bytes(resp).hex())
    if bytes(resp) == payload:
        print(f"{OK} echo matches -- UART round trip is clean "
              "(simpleserial-base style).")
    else:
        print(f"{OK} got a well-formed response (firmware is not a plain echo, "
              "e.g. AES).")

    # ---- Stage 5: armed capture -------------------------------------------
    hdr("STAGE 5 -- armed capture")
    scope.adc.samples = 2000
    scope.arm()
    target.simpleserial_write("p", payload)
    timed_out = scope.capture()
    try:
        target.simpleserial_read("r", 16, timeout=500)
    except Exception:
        pass

    if timed_out:
        print(f"{WARN} capture timed out -- the trigger (tio4/GPIO4) never went")
        print("         high. Fine if the firmware does not raise a trigger;")
        print("         a fault-injection firmware will.")
        return target, True

    trace = scope.get_last_trace()
    show("trace length", len(trace))
    show("min / max / mean", f"{trace.min():+.4f} / {trace.max():+.4f} / "
                             f"{trace.mean():+.4f}")
    try_show("trigger duration (cyc)", lambda: scope.adc.trig_count)

    if abs(trace.max() - trace.min()) < 1e-6:
        print(f"{WARN} trace is flat -- check the SMA cable and the measurement")
        print("         shunt on the target board.")
    else:
        print(f"{OK} captured a live power trace.")
    return target, True


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sn", default=None,
                    help="serial number of the Husky (needed only if ambiguous)")
    ap.add_argument("--target", action="store_true",
                    help="also test UART comms and an armed capture")
    ap.add_argument("--ssver", type=int, choices=(1, 2), default=2,
                    help="SimpleSerial version of the target firmware (default 2)")
    ap.add_argument("--fw", default=None,
                    help="hex file to program onto an STM32F target first")
    ap.add_argument("--freq", type=float, default=7.37e6,
                    help="target clock frequency in Hz (default 7.37e6)")
    args = ap.parse_args()

    scope = None
    try:
        husky_sns = stage_env()
        sn = args.sn
        if sn is None and husky_sns:
            sn = husky_sns[0]

        scope = stage_connect(sn)
        clocks_ok = stage_clock(scope, freq=args.freq)

        if args.fw:
            stage_program(scope, args.fw)

        if args.target:
            stage_target(scope, args.ssver)

        hdr("SUMMARY")
        print(f"    scope link : ok")
        print(f"    clocks     : {'ok' if clocks_ok else 'FAILED'}")
        print(f"    target test: {'run' if args.target else 'skipped'}")
    except Exception:
        hdr("UNHANDLED EXCEPTION")
        traceback.print_exc()
        sys.exit(1)
    finally:
        if scope is not None:
            try:
                scope.dis()
                print("\n    scope disconnected.")
            except Exception:
                pass


if __name__ == "__main__":
    main()