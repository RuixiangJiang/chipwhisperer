#!/usr/bin/env python3

import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD


SS_LEN = 32


def reset_target(scope) -> None:
    """Reset the STM32 target through nRST."""
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.8)


def send_cmd_read(target, cmd: str, response_cmd: str, response_len: int, timeout: int):
    """Send one SimpleSerial2 command and read one response packet."""
    target.flush()
    target.simpleserial_write(cmd, bytearray([]))

    result = target.simpleserial_read_witherrors(
        response_cmd,
        response_len,
        glitch_timeout=timeout,
    )

    print(f"{cmd} -> {response_cmd} result:")
    print(result)

    if not result.get("valid", False):
        raise RuntimeError(f"Invalid response for command {cmd}")

    payload = bytes(result["payload"])

    if len(payload) != response_len:
        raise RuntimeError(
            f"Unexpected payload length for command {cmd}: {len(payload)}"
        )

    return payload


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

    raw = target.read(num_char=300, timeout=1000)
    print("Raw UART after reset:")
    print(repr(raw))

    print("Running keypair...")
    k_payload = send_cmd_read(target, "K", "K", 1, timeout=60)
    k_ret = k_payload[0]
    print(f"crypto_kem_keypair() returned: {k_ret}")

    if k_ret != 0:
        raise RuntimeError(f"Keypair failed with return code {k_ret}")

    print("Running encapsulation...")
    e_payload = send_cmd_read(target, "E", "E", 1 + SS_LEN, timeout=60)
    e_ret = e_payload[0]
    ss_enc = e_payload[1:]

    print(f"crypto_kem_enc() returned: {e_ret}")
    print(f"ss_enc: {ss_enc.hex()}")

    if e_ret != 0:
        raise RuntimeError(f"Encapsulation failed with return code {e_ret}")

    print("Running decapsulation...")
    d_payload = send_cmd_read(target, "D", "S", 1 + SS_LEN, timeout=60)
    d_ret = d_payload[0]
    ss_dec = d_payload[1:]

    print(f"crypto_kem_dec() returned: {d_ret}")
    print(f"ss_dec: {ss_dec.hex()}")

    if d_ret != 0:
        raise RuntimeError(f"Decapsulation failed with return code {d_ret}")

    if ss_enc == ss_dec:
        print("SUCCESS: ss_enc == ss_dec")
    else:
        print("FAILURE: ss_enc != ss_dec")

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