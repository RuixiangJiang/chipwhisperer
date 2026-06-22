#!/usr/bin/env python3

import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD


PK_LEN = 800
PK_CHUNK = 200


def reset_target(scope) -> None:
    """Reset the STM32 target through nRST."""
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.8)


def read_public_key(target) -> bytes:
    """Read the Kyber public key in chunks."""
    pk = bytearray()

    for offset in range(0, PK_LEN, PK_CHUNK):
        request = bytearray()
        request += offset.to_bytes(2, "little")
        request += bytes([PK_CHUNK])

        target.flush()
        target.simpleserial_write("R", request)

        part = target.simpleserial_read_witherrors("R", PK_CHUNK, glitch_timeout=10)

        print(f"R offset {offset}:")
        print(part)

        if not part.get("valid", False):
            raise RuntimeError(f"Invalid R response at offset {offset}")

        payload = bytes(part["payload"])

        if len(payload) != PK_CHUNK:
            raise RuntimeError(
                f"Unexpected chunk length at offset {offset}: {len(payload)}"
            )

        pk += payload

    return bytes(pk)


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

    print("Running keypair...")
    target.flush()
    target.simpleserial_write("K", bytearray([]))

    result = target.simpleserial_read_witherrors("K", 1, glitch_timeout=60)

    print("Keypair result:")
    print(result)

    if not result.get("valid", False):
        raise RuntimeError("Keypair did not return a valid response")

    ret = bytes(result["payload"])[0]
    print(f"crypto_kem_keypair() returned: {ret}")

    if ret != 0:
        raise RuntimeError(f"crypto_kem_keypair() failed with return code {ret}")

    print("Reading public key...")
    pk = read_public_key(target)

    print(f"Public key length: {len(pk)}")
    print(f"Public key first 32 bytes: {pk[:32].hex()}")

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