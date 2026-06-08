#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class SimpleSerialError(RuntimeError):
    """Raised when a SimpleSerial transaction fails."""


@dataclass
class SimpleSerialPacket:
    """Validated SimpleSerial response packet."""
    command: str
    payload: bytes
    raw: object
    rv: Optional[bytes]


def _to_bytearray(payload) -> bytearray:
    """Convert payload-like objects to bytearray."""
    if payload is None:
        return bytearray()

    if isinstance(payload, bytearray):
        return payload

    if isinstance(payload, bytes):
        return bytearray(payload)

    return bytearray(payload)


def _rv_to_bytes(rv) -> Optional[bytes]:
    """Convert a ChipWhisperer rv field to bytes."""
    if rv is None:
        return None

    return bytes(rv)


def validate_response(result, response_cmd: str, response_len: int) -> SimpleSerialPacket:
    """Validate a SimpleSerial2 read_witherrors() response."""
    if result is None:
        raise SimpleSerialError(f"No response for command {response_cmd}")

    if not result.get("valid", False):
        raise SimpleSerialError(
            f"Invalid response for command {response_cmd}: "
            f"full_response={result.get('full_response')!r}, rv={result.get('rv')!r}"
        )

    payload = result.get("payload", None)

    if payload is None:
        raise SimpleSerialError(f"Missing payload for command {response_cmd}")

    payload_bytes = bytes(payload)

    if len(payload_bytes) != response_len:
        raise SimpleSerialError(
            f"Unexpected payload length for command {response_cmd}: "
            f"expected={response_len}, actual={len(payload_bytes)}"
        )

    return SimpleSerialPacket(
        command=response_cmd,
        payload=payload_bytes,
        raw=result,
        rv=_rv_to_bytes(result.get("rv")),
    )


def send_cmd_read(
    target,
    cmd: str,
    response_cmd: str,
    response_len: int,
    timeout: int,
    payload=None,
    flush: bool = True,
    print_result: bool = False,
) -> bytes:
    """
    Send one SimpleSerial2 command and read one response packet.

    Do not call simpleserial_wait_ack() after this function.
    The ACK is already consumed by simpleserial_read_witherrors().
    """
    if flush:
        target.flush()

    target.simpleserial_write(cmd, _to_bytearray(payload))

    result = target.simpleserial_read_witherrors(
        response_cmd,
        response_len,
        glitch_timeout=timeout,
    )

    if print_result:
        print(f"{cmd} -> {response_cmd}:")
        print(result)

    packet = validate_response(result, response_cmd, response_len)
    return packet.payload


def read_chunked(
    target,
    request_cmd: str,
    response_cmd: str,
    total_len: int,
    chunk_len: int,
    timeout: int,
    print_result: bool = False,
) -> bytes:
    """Read a target buffer using offset-based chunk commands."""
    out = bytearray()

    for offset in range(0, total_len, chunk_len):
        current_len = min(chunk_len, total_len - offset)

        request = bytearray()
        request += offset.to_bytes(2, "little")
        request += bytes([current_len])

        payload = send_cmd_read(
            target=target,
            cmd=request_cmd,
            response_cmd=response_cmd,
            response_len=current_len,
            timeout=timeout,
            payload=request,
            flush=True,
            print_result=print_result,
        )

        out += payload

    return bytes(out)


def write_chunked(
    target,
    request_cmd: str,
    response_cmd: str,
    data: bytes,
    chunk_len: int,
    timeout: int,
    print_result: bool = False,
) -> None:
    """Write a target buffer using offset-based chunk commands."""
    data = bytes(data)

    for offset in range(0, len(data), chunk_len):
        chunk = data[offset:offset + chunk_len]

        if len(chunk) != chunk_len:
            raise ValueError(
                f"Final chunk length is {len(chunk)}, expected fixed chunk length {chunk_len}"
            )

        request = bytearray()
        request += offset.to_bytes(2, "little")
        request += chunk

        payload = send_cmd_read(
            target=target,
            cmd=request_cmd,
            response_cmd=response_cmd,
            response_len=1,
            timeout=timeout,
            payload=request,
            flush=True,
            print_result=print_result,
        )

        status = payload[0]

        if status != 0:
            raise SimpleSerialError(
                f"Chunk write failed for {request_cmd} at offset {offset}, status={status}"
            )