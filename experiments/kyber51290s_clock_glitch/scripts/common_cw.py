#!/usr/bin/env python3

from __future__ import annotations

import time
from typing import Optional, Tuple

import chipwhisperer as cw


DEFAULT_CLKGEN_FREQ = 7.3728e6
DEFAULT_ADC_SAMPLES = 5000
DEFAULT_ADC_TIMEOUT = 2.0


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
    scope.io.hs2 = "clkgen"

    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    scope.adc.samples = adc_samples
    scope.adc.timeout = adc_timeout

    return scope


def connect_target(scope, ss_version: str = "SS_VER_2_1"):
    """Connect to the target using the selected SimpleSerial version."""
    if ss_version in ("SS_VER_2_1", "SS_VER_2_0", "ss2", "SS2"):
        return cw.target(scope, cw.targets.SimpleSerial2)

    if ss_version in ("SS_VER_1_1", "ss1", "SS1"):
        return cw.target(scope, cw.targets.SimpleSerial)

    raise ValueError(f"Unsupported SimpleSerial version: {ss_version}")


def reset_target(scope, hold_time: float = 0.05, settle_time: float = 0.8) -> None:
    """Reset the STM32 target through nRST."""
    scope.io.nrst = "low"
    time.sleep(hold_time)
    scope.io.nrst = "high_z"
    time.sleep(settle_time)


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


def recover_target(scope, target, settle_time: float = 0.8) -> None:
    """Reset and flush the target after a timeout, crash, or invalid response."""
    reset_target(scope, settle_time=settle_time)
    flush_target(target)


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
    target = connect_target(scope, ss_version=ss_version)
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