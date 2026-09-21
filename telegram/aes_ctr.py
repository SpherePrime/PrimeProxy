"""
Streaming AES-CTR using the `cryptography` package (port). Requires a 32-byte
key and 16-byte IV, matching the MTProto obfuscation spec.

Replaces the original ZapretGUI implementation that required `tgcrypto`.
"""
from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AesCtrStream:
    """Streaming AES-CTR over `cryptography`.

    `cryptography` keeps counter state inside its own context, so we hold
    nothing mutable here and behave statelessly from the caller's perspective.
    """

    __slots__ = ("_ctx",)

    def __init__(self, key: bytes, iv: bytes):
        key_bytes = bytes(key)
        iv_bytes = bytes(iv)
        if len(key_bytes) != 32:
            raise ValueError("AES-CTR key must be exactly 32 bytes")
        if len(iv_bytes) != 16:
            raise ValueError("AES-CTR IV must be exactly 16 bytes")
        self._ctx = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes)).encryptor()

    def update(self, data: bytes) -> bytes:
        chunk = bytes(data or b"")
        if not chunk:
            return b""
        return self._ctx.update(chunk)


def aes_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AesCtrStream(key, iv).update(data)


def aes_ctr_keystream(key: bytes, iv: bytes, size: int) -> bytes:
    if size <= 0:
        return b""
    return aes_ctr_crypt(key, iv, b"\x00" * int(size))


__all__ = ["AesCtrStream", "aes_ctr_crypt", "aes_ctr_keystream"]