#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from common_ss2 import send_cmd_read, read_chunked, write_chunked


KYBER512_90S_PK_LEN = 800
KYBER512_90S_SK_LEN = 1632
KYBER512_90S_CT_LEN = 768
KYBER512_90S_SS_LEN = 32

DEFAULT_PK_CHUNK = 200
DEFAULT_CT_CHUNK = 128


@dataclass
class KyberConstants:
    """Kyber512-90s sizes used by the target firmware."""
    pk_len: int = KYBER512_90S_PK_LEN
    sk_len: int = KYBER512_90S_SK_LEN
    ct_len: int = KYBER512_90S_CT_LEN
    ss_len: int = KYBER512_90S_SS_LEN
    pk_chunk: int = DEFAULT_PK_CHUNK
    ct_chunk: int = DEFAULT_CT_CHUNK


class KyberTarget:
    """Host-side wrapper for the Kyber SimpleSerial2 target firmware."""

    def __init__(self, target, constants: KyberConstants | None = None):
        self.target = target
        self.constants = constants if constants is not None else KyberConstants()

    def ping(self, timeout: int = 5) -> bool:
        """Run the P command and check for payload 0x42."""
        payload = send_cmd_read(
            target=self.target,
            cmd="P",
            response_cmd="P",
            response_len=1,
            timeout=timeout,
        )
        return payload == b"\x42"

    def rng_probe(self, timeout: int = 10) -> Tuple[int, bytes]:
        """Run the N command to test pqm4 randombytes()."""
        payload = send_cmd_read(
            target=self.target,
            cmd="N",
            response_cmd="N",
            response_len=1 + 16,
            timeout=timeout,
        )
        return payload[0], payload[1:]

    def keypair(self, timeout: int = 60) -> int:
        """Run crypto_kem_keypair(pk, sk) on the target."""
        payload = send_cmd_read(
            target=self.target,
            cmd="K",
            response_cmd="K",
            response_len=1,
            timeout=timeout,
        )
        return payload[0]

    def read_public_key(self, timeout: int = 10) -> bytes:
        """Read the 800-byte public key from the target."""
        return read_chunked(
            target=self.target,
            request_cmd="R",
            response_cmd="R",
            total_len=self.constants.pk_len,
            chunk_len=self.constants.pk_chunk,
            timeout=timeout,
        )

    def encapsulate_target(self, timeout: int = 60) -> Tuple[int, bytes]:
        """Run crypto_kem_enc(ct, ss_enc, pk) on the target."""
        payload = send_cmd_read(
            target=self.target,
            cmd="E",
            response_cmd="E",
            response_len=1 + self.constants.ss_len,
            timeout=timeout,
        )
        return payload[0], payload[1:]

    def read_ciphertext(self, timeout: int = 10) -> bytes:
        """Read the current target-side ciphertext buffer."""
        return read_chunked(
            target=self.target,
            request_cmd="T",
            response_cmd="T",
            total_len=self.constants.ct_len,
            chunk_len=self.constants.ct_chunk,
            timeout=timeout,
        )

    def upload_ciphertext(self, ct: bytes, timeout: int = 10) -> None:
        """Upload a ciphertext into the target-side ct[] buffer."""
        ct = bytes(ct)

        if len(ct) != self.constants.ct_len:
            raise ValueError(
                f"Unexpected ciphertext length: expected={self.constants.ct_len}, actual={len(ct)}"
            )

        write_chunked(
            target=self.target,
            request_cmd="C",
            response_cmd="C",
            data=ct,
            chunk_len=self.constants.ct_chunk,
            timeout=timeout,
        )

    def decapsulate(self, timeout: int = 60) -> Tuple[int, bytes]:
        """Run crypto_kem_dec(ss_dec, ct, sk) on the target."""
        payload = send_cmd_read(
            target=self.target,
            cmd="D",
            response_cmd="S",
            response_len=1 + self.constants.ss_len,
            timeout=timeout,
        )
        return payload[0], payload[1:]

    def keypair_encaps_decaps_self_test(self) -> Tuple[bool, bytes, bytes]:
        """
        Run target-side K -> E -> D.

        Returns:
            (match, ss_enc, ss_dec)
        """
        k_ret = self.keypair()
        if k_ret != 0:
            raise RuntimeError(f"Keypair failed with return code {k_ret}")

        e_ret, ss_enc = self.encapsulate_target()
        if e_ret != 0:
            raise RuntimeError(f"Encapsulation failed with return code {e_ret}")

        d_ret, ss_dec = self.decapsulate()
        if d_ret != 0:
            raise RuntimeError(f"Decapsulation failed with return code {d_ret}")

        return ss_enc == ss_dec, ss_enc, ss_dec

    def upload_ct_decapsulation_self_test(self) -> Tuple[bool, bytes, bytes, bytes]:
        """
        Run K -> E -> T -> C -> D.

        Returns:
            (match, ss_enc, ss_dec, ct)
        """
        k_ret = self.keypair()
        if k_ret != 0:
            raise RuntimeError(f"Keypair failed with return code {k_ret}")

        e_ret, ss_enc = self.encapsulate_target()
        if e_ret != 0:
            raise RuntimeError(f"Encapsulation failed with return code {e_ret}")

        ct = self.read_ciphertext()
        self.upload_ciphertext(ct)

        d_ret, ss_dec = self.decapsulate()
        if d_ret != 0:
            raise RuntimeError(f"Decapsulation failed with return code {d_ret}")

        return ss_enc == ss_dec, ss_enc, ss_dec, ct