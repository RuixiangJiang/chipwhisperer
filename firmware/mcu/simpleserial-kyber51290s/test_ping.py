#!/usr/bin/env python3

import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD


def reset_target(scope) -> None:
    """Reset the STM32 target through nRST."""
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.8)


def configure_scope(scope) -> None:
    """Configure clock, UART pins, and reset the target."""
    scope.default_setup()

    scope.clock.clkgen_freq = CLKGEN_FREQ
    scope.clock.adc_src = ADC_SRC
    scope.io.hs2 = HS2_NORMAL

    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    reset_target(scope)


def test_ss2(scope) -> None:
    """Test SimpleSerial v2.1."""
    print("Testing SimpleSerial2...")

    target = cw.target(scope, cw.targets.SimpleSerial2, baud=DEFAULT_BAUD)
    target.flush()

    target.simpleserial_write("P", bytearray([]))
    val = target.simpleserial_read_witherrors("P", 1, glitch_timeout=5)

    print("SS2 response:")
    print(val)

    try:
        target.dis()
    except Exception:
        pass


def test_ss1(scope) -> None:
    """Test SimpleSerial v1.1 as a fallback check."""
    print("Testing SimpleSerial1...")

    target = cw.target(scope, cw.targets.SimpleSerial, baud=DEFAULT_BAUD)
    target.flush()

    target.simpleserial_write("P", bytearray([]))
    resp = target.simpleserial_read("P", 1, timeout=5000)

    print("SS1 response:")
    print(resp)

    try:
        target.dis()
    except Exception:
        pass


def main() -> None:
    print("Available ChipWhisperer devices:")
    print(cw.list_devices())

    scope = cw.scope()
    configure_scope(scope)

    test_ss2(scope)

    reset_target(scope)
    test_ss1(scope)

    try:
        scope.dis()
    except Exception:
        pass


if __name__ == "__main__":
    main()