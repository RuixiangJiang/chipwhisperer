#!/usr/bin/env python3

import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD


def reset_target(scope) -> None:
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.2)


def read_raw_for(target, seconds: float = 3.0) -> str:
    end_time = time.time() + seconds
    data = ""

    while time.time() < end_time:
        chunk = target.read(num_char=100, timeout=100)
        if chunk:
            data += chunk
        time.sleep(0.02)

    return data


def main() -> None:
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

    raw = read_raw_for(target, seconds=3.0)

    print("Raw UART after reset:")
    print(repr(raw))
    print("Raw UART hex:")
    print(raw.encode("latin-1").hex())

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