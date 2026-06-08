#!/usr/bin/env python3

import time
import chipwhisperer as cw


SS_LEN = 32
CT_LEN = 768
CT_CHUNK = 128


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


def read_ct(target) -> bytes:
    """Read ciphertext from target in chunks."""
    ct = bytearray()

    for offset in range(0, CT_LEN, CT_CHUNK):
        request = offset.to_bytes(2, "little") + bytes([CT_CHUNK])

        target.flush()
        target.simpleserial_write("T", request)

        result = target.simpleserial_read_witherrors(
            "T",
            CT_CHUNK,
            glitch_timeout=10,
        )

        print(f"T offset {offset}:")
        print(result)

        if not result.get("valid", False):
            raise RuntimeError(f"Invalid T response at offset {offset}")

        ct += bytes(result["payload"])

    return bytes(ct)


def upload_ct(target, ct: bytes) -> None:
    """Upload ciphertext to target in chunks."""
    if len(ct) != CT_LEN:
        raise ValueError(f"Unexpected ciphertext length: {len(ct)}")

    for offset in range(0, CT_LEN, CT_CHUNK):
        chunk = ct[offset:offset + CT_CHUNK]
        request = offset.to_bytes(2, "little") + chunk

        target.flush()
        target.simpleserial_write("C", request)

        result = target.simpleserial_read_witherrors(
            "C",
            1,
            glitch_timeout=10,
        )

        print(f"C offset {offset}:")
        print(result)

        if not result.get("valid", False):
            raise RuntimeError(f"Invalid C response at offset {offset}")

        ret = bytes(result["payload"])[0]
        if ret != 0:
            raise RuntimeError(f"C command failed at offset {offset}, ret={ret}")


def main() -> None:
    NUM_TRIALS = 100

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

    success_count = 0
    failure_count = 0
    failures = []

    try:
        for trial in range(NUM_TRIALS):
            print(f"\n===== Trial {trial + 1}/{NUM_TRIALS} =====")

            try:
                print("Running keypair...")
                k_payload = send_cmd_read(target, "K", "K", 1, timeout=60)
                k_ret = k_payload[0]

                if k_ret != 0:
                    raise RuntimeError(f"Keypair failed with return code {k_ret}")

                print("Running target-side encapsulation...")
                e_payload = send_cmd_read(target, "E", "E", 1 + SS_LEN, timeout=60)
                e_ret = e_payload[0]

                if e_ret != 0:
                    raise RuntimeError(f"Encapsulation failed with return code {e_ret}")

                ss_enc = e_payload[1:]

                print("Reading target-generated ciphertext...")
                ct = read_ct(target)

                if len(ct) != CT_LEN:
                    raise RuntimeError(f"Unexpected ciphertext length: {len(ct)}")

                print("Uploading ciphertext back to target...")
                upload_ct(target, ct)

                print("Running decapsulation...")
                d_payload = send_cmd_read(target, "D", "S", 1 + SS_LEN, timeout=60)
                d_ret = d_payload[0]

                if d_ret != 0:
                    raise RuntimeError(f"Decapsulation failed with return code {d_ret}")

                ss_dec = d_payload[1:]

                if ss_enc != ss_dec:
                    raise RuntimeError(
                        "Shared secret mismatch: "
                        f"ss_enc={ss_enc.hex()} ss_dec={ss_dec.hex()}"
                    )

                success_count += 1
                print(f"Trial {trial + 1}: SUCCESS")

            except Exception as exc:
                failure_count += 1
                failures.append((trial + 1, str(exc)))

                print(f"Trial {trial + 1}: FAILURE")
                print(f"Reason: {exc}")

                # Reset after a failed trial to avoid carrying a bad state forward.
                reset_target(scope)
                target.flush()

        print("\n===== Summary =====")
        print(f"Total trials: {NUM_TRIALS}")
        print(f"Successes: {success_count}")
        print(f"Failures: {failure_count}")

        if failures:
            print("\nFailure details:")
            for trial_id, reason in failures:
                print(f"Trial {trial_id}: {reason}")

        if success_count == NUM_TRIALS:
            print("\nSUCCESS: All uploaded ciphertext decapsulation trials matched.")
        else:
            print("\nWARNING: Some trials failed. Check failure details above.")

    finally:
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