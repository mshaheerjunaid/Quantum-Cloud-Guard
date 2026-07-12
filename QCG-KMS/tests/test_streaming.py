"""Streaming file-crypto tests (the client-side path)."""

from __future__ import annotations

import io
import os

import pytest
from cryptography.exceptions import InvalidTag

from qcg_kms import crypto


def _roundtrip(data: bytes, chunk_size: int = 64) -> bytes:
    dek = os.urandom(32)
    enc = io.BytesIO()
    prefix = crypto.encrypt_file_stream(dek, io.BytesIO(data), enc,
                                        base_aad=b"hdr", chunk_size=chunk_size)
    dec = io.BytesIO()
    crypto.decrypt_file_stream(dek, io.BytesIO(enc.getvalue()), dec, prefix,
                               base_aad=b"hdr", chunk_size=chunk_size)
    return dec.getvalue()


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 200, 4096])
def test_stream_round_trip_various_sizes(size):
    data = os.urandom(size)
    assert _roundtrip(data, chunk_size=64) == data


def test_stream_large_multichunk():
    data = os.urandom(1024 * 1024 + 12345)  # > 1 chunk at default size
    assert _roundtrip(data, chunk_size=crypto.CHUNK_SIZE) == data


def test_stream_tamper_detected():
    dek = os.urandom(32)
    enc = io.BytesIO()
    prefix = crypto.encrypt_file_stream(dek, io.BytesIO(b"A" * 200), enc, chunk_size=64)
    blob = bytearray(enc.getvalue())
    blob[10] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.decrypt_file_stream(dek, io.BytesIO(bytes(blob)), io.BytesIO(),
                                   prefix, chunk_size=64)


def test_stream_truncation_detected():
    # Dropping the final chunk must fail: the last chunk is authenticated as last.
    dek = os.urandom(32)
    enc = io.BytesIO()
    prefix = crypto.encrypt_file_stream(dek, io.BytesIO(b"B" * 200), enc, chunk_size=64)
    full = enc.getvalue()
    truncated = full[: (64 + 16) * 2]   # drop the last chunk
    with pytest.raises(InvalidTag):
        crypto.decrypt_file_stream(dek, io.BytesIO(truncated), io.BytesIO(),
                                   prefix, chunk_size=64)
