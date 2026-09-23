"""Bounded socket framing shared by the application and the root helper.

A length prefix, a strict JSON object, explicit bounds and duplicate-key
rejection: nothing an untrusted peer sends may make the reader allocate
without a limit, read twice the same key, or smuggle a non-JSON constant.
"""

from __future__ import annotations

import socket
import struct

import pytest

from vysion.certprotocol import (
    HEADER_BYTES,
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    decode_payload,
    encode_message,
    receive_message,
    send_message,
)


def test_a_message_round_trips_through_the_length_prefix() -> None:
    encoded = encode_message({"v": 1, "action": "ping"}, max_bytes=1024)
    (length,) = struct.unpack(">I", encoded[:HEADER_BYTES])
    assert length == len(encoded) - HEADER_BYTES
    assert decode_payload(encoded[HEADER_BYTES:]) == {"v": 1, "action": "ping"}


def test_a_non_object_top_level_is_refused() -> None:
    for payload in (b"[]", b'"text"', b"42", b"true", b"null"):
        with pytest.raises(ProtocolError):
            decode_payload(payload)


def test_duplicate_keys_are_refused_instead_of_silently_kept() -> None:
    with pytest.raises(ProtocolError):
        decode_payload(b'{"action":"ping","action":"activate"}')


def test_non_json_constants_are_refused() -> None:
    for payload in (b'{"v":NaN}', b'{"v":Infinity}', b'{"v":-Infinity}'):
        with pytest.raises(ProtocolError):
            decode_payload(payload)


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(ProtocolError):
        decode_payload(b'{"a":"\xff\xfe"}')


def test_an_oversized_message_never_leaves_the_encoder() -> None:
    with pytest.raises(ProtocolError):
        encode_message({"v": 1, "payload": "x" * 4096}, max_bytes=512)


def test_an_advertised_length_beyond_the_bound_is_refused_before_reading() -> None:
    peer, other = socket.socketpair()
    try:
        peer.sendall(struct.pack(">I", MAX_REQUEST_BYTES + 1))
        with pytest.raises(ProtocolError):
            receive_message(other, max_bytes=MAX_REQUEST_BYTES, timeout=1.0)
    finally:
        peer.close()
        other.close()


def test_a_zero_length_frame_is_refused() -> None:
    peer, other = socket.socketpair()
    try:
        peer.sendall(struct.pack(">I", 0))
        with pytest.raises(ProtocolError):
            receive_message(other, timeout=1.0)
    finally:
        peer.close()
        other.close()


def test_a_truncated_stream_is_refused() -> None:
    peer, other = socket.socketpair()
    try:
        encoded = encode_message({"v": 1, "action": "ping"}, max_bytes=1024)
        peer.sendall(encoded[:-3])
        peer.close()
        with pytest.raises(ProtocolError):
            receive_message(other, timeout=1.0)
    finally:
        other.close()


def test_a_message_travels_over_a_real_socket_pair() -> None:
    sender, receiver = socket.socketpair()
    try:
        send_message(sender, {"v": PROTOCOL_VERSION, "action": "status"}, timeout=1.0)
        assert receive_message(receiver, timeout=1.0) == {
            "v": PROTOCOL_VERSION,
            "action": "status",
        }
    finally:
        sender.close()
        receiver.close()


def test_a_peer_that_answers_garbage_is_reported_as_a_protocol_error() -> None:
    peer, other = socket.socketpair()
    try:
        peer.sendall(struct.pack(">I", 3) + b"{{{")
        with pytest.raises(ProtocolError):
            receive_message(other, timeout=1.0)
    finally:
        peer.close()
        other.close()
