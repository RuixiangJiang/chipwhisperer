#!/usr/bin/env python3

from __future__ import annotations

import time
from typing import Optional, Tuple

import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, HS2_GLITCH, DEFAULT_BAUD

DEFAULT_CLKGEN_FREQ = CLKGEN_FREQ
DEFAULT_ADC_SAMPLES = 5000
DEFAULT_ADC_TIMEOUT = 2.0


def force_target_baud(target, baud=DEFAULT_BAUD):
    """
    Force SimpleSerial UART baud for different ChipWhisperer versions.

    Important:
    In some CW versions, target.ser.baud is a method, so we must call
    target.ser.baud(baud), not assign target.ser.baud = baud.
    """
    # Top-level target baud, if available.
    for attr in ("baud", "baudrate"):
        try:
            setattr(target, attr, baud)
        except Exception:
            pass

    # Underlying serial object.
    ser = getattr(target, "ser", None)
    if ser is not None:
        for attr in ("baud", "baudrate"):
            try:
                obj = getattr(ser, attr)
            except Exception:
                continue

            try:
                if callable(obj):
                    obj(baud)
                else:
                    setattr(ser, attr, baud)
            except Exception:
                pass

    return target


def print_target_baud(target):
    print("target.baud:", getattr(target, "baud", None))

    ser = getattr(target, "ser", None)
    if ser is None:
        print("target.ser: None")
        return

    for attr in ("baud", "baudrate"):
        try:
            obj = getattr(ser, attr)
            if callable(obj):
                print(f"target.ser.{attr}():", obj())
            else:
                print(f"target.ser.{attr}:", obj)
        except Exception as e:
            print(f"target.ser.{attr}: <unavailable> {repr(e)}")


def list_devices():
    """Return the list of connected ChipWhisperer devices."""
    return cw.list_devices()


def setup_scope(
    clkgen_freq: float = DEFAULT_CLKGEN_FREQ,
    adc_samples: int = DEFAULT_ADC_SAMPLES,
    adc_timeout: float = DEFAULT_ADC_TIMEOUT,
):
    """Create and configure a ChipWhisperer scope for CW-Lite/STM32F3."""
    scope = cw.scope()
    scope.default_setup()

    scope.clock.clkgen_freq = clkgen_freq
    time.sleep(0.1)
    scope.clock.adc_src = ADC_SRC
    time.sleep(0.1)
    scope.io.hs2 = HS2_NORMAL
    time.sleep(0.1)

    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    scope.adc.samples = adc_samples
    scope.adc.timeout = adc_timeout

    return scope


def connect_target(scope, ss_version: str = "SS_VER_2_1"):
    """Connect to the target using the selected SimpleSerial version."""

    if ss_version in ("SS_VER_2_1", "SS_VER_2_0", "ss2", "SS2"):
        try:
            target = cw.target(scope, cw.targets.SimpleSerial2, baud=DEFAULT_BAUD)
        except TypeError:
            target = cw.target(scope, cw.targets.SimpleSerial2)

        target = force_target_baud(target, DEFAULT_BAUD)
        return target

    if ss_version in ("SS_VER_1_1", "ss1", "SS1"):
        try:
            target = cw.target(scope, cw.targets.SimpleSerial, baud=DEFAULT_BAUD)
        except TypeError:
            target = cw.target(scope, cw.targets.SimpleSerial)

        target = force_target_baud(target, DEFAULT_BAUD)
        return target

    raise ValueError(f"Unsupported SimpleSerial version: {ss_version}")


def reset_target(scope, delay_s: float = 0.5, settle_time=None, reset_delay=None):
    """
    Reset STM32 after changing clkgen.

    Backward-compatible aliases:
    - settle_time: used by older recover_target()
    - reset_delay: used by collect_host_faults.safe_recover()
    """
    if reset_delay is not None:
        delay_s = reset_delay
    elif settle_time is not None:
        delay_s = settle_time

    try:
        scope.io.nrst = "low"
        time.sleep(0.05)
        scope.io.nrst = "high_z"
        time.sleep(delay_s)
    except Exception as e:
        print("reset_target warning:", repr(e))


def flush_target(target) -> None:
    """Flush pending target UART data."""
    try:
        target.flush()
    except Exception:
        pass


def read_boot_banner(target, num_char: int = 300, timeout: int = 1000) -> str:
    """Read raw UART output after reset."""
    raw = target.read(num_char=num_char, timeout=timeout)
    return raw if raw is not None else ""


def recover_target(scope, target=None, settle_time: float = 0.5, reset_delay=None):
    """
    Recover target after crash/timeout.

    Compatible with both:
    - recover_target(scope, target)
    - recover_target(scope, target, reset_delay=...)
    - recover_target(scope, target, settle_time=...)
    """
    if reset_delay is not None:
        settle_time = reset_delay

    try:
        if target is not None:
            force_target_baud(target, DEFAULT_BAUD)
    except Exception:
        pass

    reset_target(scope, delay_s=settle_time)

    try:
        if target is not None:
            force_target_baud(target, DEFAULT_BAUD)
            flush_target(target)
    except Exception as e:
        print("recover_target flush warning:", repr(e))

    return target


def disconnect(scope=None, target=None) -> None:
    """Disconnect target and scope safely."""
    if target is not None:
        try:
            target.dis()
        except Exception:
            pass

    if scope is not None:
        try:
            scope.dis()
        except Exception:
            pass


def setup_scope_and_target(
    clkgen_freq: float = DEFAULT_CLKGEN_FREQ,
    adc_samples: int = DEFAULT_ADC_SAMPLES,
    adc_timeout: float = DEFAULT_ADC_TIMEOUT,
    ss_version: str = "SS_VER_2_1",
) -> Tuple[object, object]:
    """Create a scope and target pair with the standard Kyber experiment setup."""
    scope = setup_scope(
        clkgen_freq=clkgen_freq,
        adc_samples=adc_samples,
        adc_timeout=adc_timeout,
    )

    # Important: after changing clkgen_freq, reset the STM32 so UART and firmware
    # start under the new target clock.
    target = connect_target(scope, ss_version=ss_version)
    target = force_target_baud(target, DEFAULT_BAUD)

    reset_target(scope, delay_s=0.5)
    flush_target(target)

    return scope, target


def disable_glitch(scope) -> None:
    """Disable glitch output if the current scope exposes the glitch module."""
    try:
        scope.glitch.output = "disabled"
    except Exception:
        pass


def arm_capture(scope) -> bool:
    """
    Arm and capture once.

    Returns:
        True if capture timed out.
        False if capture completed.
    """
    scope.arm()
    ret = scope.capture()
    return bool(ret)