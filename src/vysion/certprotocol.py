"""Bounded length-prefixed JSON framing shared by the application and the root helper.

One frame is a 4-byte big-endian length followed by a UTF-8 JSON **object**.
Everything a peer controls is constrained before anything is allocated: an
explicit maximum length, duplicate-key rejection and refusal of the non-JSON
constants ``NaN``/``Infinity`` that Python's decoder would otherwise accept.

This module is dependency-free on purpose: it is imported both by the
container and by the root helper running under the host's plain ``python3``.
"""

from __future__ import annotations

import json
import struct
from typing import Any

PROTOCOL_VERSION = 1
HEADER_BYTES = 4
# A validation carries a certificate plus a private key, base64-encoded:
# bound above that, but never unbounded.
MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Answers carry metadata only — never key material.
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
ACTIONS = frozenset({"ping", "status", "validate", "activate"})


class ProtocolError(RuntimeError):
    """The peer sent something this protocol will not process."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate key in message")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ProtocolError("non-JSON constant in message")


def decode_payload(payload: bytes) -> dict[str, Any]:
    """Strictly decode one complete frame body."""
    try:
        message = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("message is not readable JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    return message


def encode_message(message: dict[str, Any], *, max_bytes: int) -> bytes:
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    try:
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError("message is not JSON-serializable") from exc
    if len(payload) > max_bytes:
        raise ProtocolError("message exceeds the frame bound")
    return struct.pack(">I", len(payload)) + payload


def send_message(
    socket_object: Any,
    message: dict[str, Any],
    *,
    max_bytes: int = MAX_REQUEST_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    socket_object.settimeout(timeout)
    socket_object.sendall(encode_message(message, max_bytes=max_bytes))


def _recv_exact(socket_object: Any, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = socket_object.recv(remaining)
        if not chunk:
            raise ProtocolError("stream ended before the frame was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(
    socket_object: Any,
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    socket_object.settimeout(timeout)
    header = _recv_exact(socket_object, HEADER_BYTES)
    (length,) = struct.unpack(">I", header)
    # Refused before a single byte of the body is read: the bound is checked
    # against the peer's own claim first.
    if length == 0 or length > max_bytes:
        raise ProtocolError("advertised frame length is out of bounds")
    return decode_payload(_recv_exact(socket_object, length))


def expect_version(message: dict[str, Any]) -> None:
    if message.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")


def expect_action(message: dict[str, Any], action: str, keys: set[str]) -> None:
    """One action, one exact shape: unknown and extra keys are refused."""
    expect_version(message)
    if message.get("action") != action:
        raise ProtocolError("unexpected action")
    if set(message) != keys:
        raise ProtocolError("unexpected fields for this action")
