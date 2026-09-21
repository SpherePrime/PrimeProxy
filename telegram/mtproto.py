from __future__ import annotations

import logging
import struct
from typing import Optional

from telegram.aes_ctr import AesCtrStream, aes_ctr_keystream

log = logging.getLogger("tg_proxy")


def dc_from_init(data: bytes) -> tuple[Optional[int], bool]:
    """Extract DC id from the 64-byte MTProto obfuscation init packet."""
    if len(data) < 64:
        return None, False

    try:
        key = bytes(data[8:40])
        iv = bytes(data[40:56])
        keystream = aes_ctr_keystream(key, iv, 64)
        plain = bytes(a ^ b for a, b in zip(data[56:64], keystream[56:64]))

        proto = struct.unpack("<I", plain[0:4])[0]
        dc_raw = struct.unpack("<h", plain[4:6])[0]

        log.debug("dc_from_init: proto=0x%08X dc_raw=%d", proto, dc_raw)

        if proto in (0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD):
            dc = abs(dc_raw)
            if 1 <= dc <= 1000:
                return dc, (dc_raw < 0)
    except ImportError:
        log.warning("tgcrypto library not installed -- cannot parse MTProto init")
    except Exception as exc:
        log.debug("DC extraction failed: %s", exc)

    return None, False


def patch_init_dc(data: bytes, dc: int) -> bytes:
    """Patch dc_id in the 64-byte MTProto init packet."""
    if len(data) < 64:
        return data
    try:
        new_dc = struct.pack("<h", dc)
        key_raw = bytes(data[8:40])
        iv = bytes(data[40:56])
        ks = aes_ctr_keystream(key_raw, iv, 64)
        patched = bytearray(data[:64])
        patched[60] = ks[60] ^ new_dc[0]
        patched[61] = ks[61] ^ new_dc[1]
        log.debug("init patched: dc_id -> %d", dc)
        if len(data) > 64:
            return bytes(patched) + data[64:]
        return bytes(patched)
    except Exception:
        return data


def is_http_transport(data: bytes) -> bool:
    """Check if data looks like HTTP, not MTProto."""
    return (
        data[:5] == b"POST "
        or data[:4] == b"GET "
        or data[:5] == b"HEAD "
        or data[:8] == b"OPTIONS "
    )


class MsgSplitter:
    """Split batched MTProto abridged messages into separate WS frames."""

    def __init__(self, init_data: bytes):
        key_raw = bytes(init_data[8:40])
        iv = bytes(init_data[40:56])
        self._dec = AesCtrStream(key_raw, iv)
        self._dec.update(b"\x00" * 64)

    def split(self, chunk: bytes) -> list[bytes]:
        plain = self._dec.update(chunk)
        boundaries: list[int] = []
        pos = 0
        while pos < len(plain):
            first = plain[pos]
            if first == 0x7F:
                if pos + 4 > len(plain):
                    break
                msg_len = (
                    struct.unpack_from("<I", plain, pos + 1)[0] & 0xFFFFFF
                ) * 4
                pos += 4
            else:
                msg_len = first * 4
                pos += 1
            if msg_len == 0 or pos + msg_len > len(plain):
                break
            pos += msg_len
            boundaries.append(pos)

        if len(boundaries) <= 1:
            return [chunk]

        parts: list[bytes] = []
        prev = 0
        for i, boundary in enumerate(boundaries):
            if i == len(boundaries) - 1:
                parts.append(chunk[prev:])
            else:
                parts.append(chunk[prev:boundary])
            prev = boundary
        return parts


__all__ = ["MsgSplitter", "dc_from_init", "is_http_transport", "patch_init_dc"]
