#!/usr/bin/env python3

import time
import chipwhisperer as cw


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

    scope.clock.clkgen_freq = 7.3728e6
    scope.io.hs2 = "clkgen"

    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"

    target = cw.target(scope, cw.targets.SimpleSerial2)
    target.flush()

    reset_target(scope)

    raw = target.read(num_char=300, timeout=1000)
    print("Raw UART after reset:")
    print(repr(raw))

    target.flush()

    print("Sending N command...")
    target.simpleserial_write("N", bytearray([]))

    result = target.simpleserial_read_witherrors("N", 17, glitch_timeout=10)

    print("RNG result packet:")
    print(result)

    extra = target.read(num_char=300, timeout=1000)
    print("Extra raw UART:")
    print(repr(extra))

    if result.get("valid", False):
        payload = bytes(result["payload"])
        ret = payload[0]
        rnd = payload[1:]

        print(f"randombytes() returned: {ret}")
        print(f"random bytes: {rnd.hex()}")
    else:
        print("No valid RNG response.")

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