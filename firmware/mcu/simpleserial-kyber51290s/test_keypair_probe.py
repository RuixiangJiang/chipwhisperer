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


def main() -> None:
    print("Available ChipWhisperer devices:")
    print(cw.list_devices())

    scope = cw.scope()
    scope.default_setup()

    scope.clock.clkgen_freq = CLKGEN_FREQ
    scope.clock.adc_src = ADC_SRC
    scope.io.hs2 = HS2_NORMAL

    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    target = cw.target(scope, cw.targets.SimpleSerial2, baud=DEFAULT_BAUD)
    target.flush()

    reset_target(scope)

    raw = target.read(num_char=200, timeout=1000)
    print("Raw UART after reset:")
    print(repr(raw))

    target.flush()

    print("Sending K command...")
    target.flush()
    target.simpleserial_write("K", bytearray([]))

    result = target.simpleserial_read_witherrors("K", 1, glitch_timeout=60)

    print("Keypair result packet:")
    print(result)

    if result.get("valid", False):
        ret = bytes(result["payload"])[0]
        print(f"crypto_kem_keypair() returned: {ret}")
    else:
        print("No valid K response.")

    try:
        target.dis()
    except Exception:
        pass

    try:
        scope.dis()
    except Exception:
        pass


if __name__ == "__main__":
    main()