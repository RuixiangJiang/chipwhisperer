#!/usr/bin/env python3

from common_cw import setup_scope_and_target, recover_target, disconnect
from kyber_target import KyberTarget


def to_bytes(x):
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    return bytes(x)


def read_m(raw_target, timeout=10.0):
    raw_target.simpleserial_write("M", bytearray([]))
    resp = raw_target.simpleserial_read_witherrors("M", 32, glitch_timeout=timeout)

    if isinstance(resp, dict):
        valid = bool(resp.get("valid", False))
        payload = to_bytes(resp.get("payload"))
        if not valid or len(payload) != 32:
            raise RuntimeError(
                f"Invalid M response: valid={valid}, len={len(payload)}, resp={resp}"
            )
        return payload

    payload = to_bytes(resp)
    if len(payload) != 32:
        raise RuntimeError(f"Invalid M response length: {len(payload)}")
    return payload


def main():
    scope, raw_target = setup_scope_and_target()
    kt = KyberTarget(raw_target)

    try:
        recover_target(scope, raw_target)

        print("[+] K")
        kt.keypair()

        print("[+] E")
        ret, ss_enc = kt.encapsulate_target()
        print("enc ret:", ret)

        print("[+] T")
        ct = kt.read_ciphertext()
        print("ct len:", len(ct))

        print("[+] C")
        kt.upload_ciphertext(ct)

        print("[+] M")
        m_dec = read_m(raw_target)
        print("m_dec len:", len(m_dec))
        print("m_dec hex:", m_dec.hex())

        print("[+] D")
        ret, ss_dec = kt.decapsulate()
        print("dec ret:", ret)
        print("ss_dec len:", len(ss_dec))

        print("[+] M command works.")

    finally:
        disconnect(scope, raw_target)


if __name__ == "__main__":
    main()
