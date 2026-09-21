from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import random
import struct
import time
from dataclasses import dataclass


log = logging.getLogger("tg_proxy.fake_tls")

TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_CCS = 0x14
TLS_RECORD_APPDATA = 0x17

TLS_APPDATA_MAX = 16384
CLIENT_RANDOM_OFFSET = 11
CLIENT_RANDOM_LEN = 32
TIMESTAMP_TOLERANCE = 120
MT_PROXY_INIT_LEN = 64

_CCS_FRAME = b"\x14\x03\x03\x00\x01\x01"
_SERVER_HELLO_TEMPLATE = bytearray(
    b"\x16\x03\x03\x00\x7a"
    b"\x02\x00\x00\x76"
    b"\x03\x03"
    + b"\x00" * 32
    + b"\x20"
    + b"\x00" * 32
    + b"\x13\x01\x00"
    + b"\x00\x2e"
    + b"\x00\x33\x00\x24\x00\x1d\x00\x20"
    + b"\x00" * 32
    + b"\x00\x2b\x00\x02\x03\x04"
)
_SH_RANDOM_OFF = 11
_SH_SESSID_OFF = 44
_SH_PUBKEY_OFF = 89


@dataclass(frozen=True, slots=True)
class FakeTlsClientInit:
    init: bytes
    reader: object
    writer: object
    label: str


def normalize_fake_tls_domain(value: object) -> str:
    text = str(value or "").strip().strip(".").lower()
    if not text or len(text) > 253:
        return ""
    labels = text.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return ""
        if any(ch not in allowed for ch in label):
            return ""
    return text


def build_fake_tls_secret(secret: str, domain: str) -> str:
    clean_secret = str(secret or "").strip().lower()
    clean_domain = normalize_fake_tls_domain(domain)
    if len(clean_secret) != 32 or not clean_domain:
        return clean_secret
    if not all(ch in "0123456789abcdef" for ch in clean_secret):
        return ""
    return "ee" + clean_secret + clean_domain.encode("ascii").hex()


def build_fake_tls_nginx_config(
    *,
    fake_tls_domain: object = "",
    upstream_host: object = "127.0.0.1",
    upstream_port: object = 8446,
) -> str:
    domain = normalize_fake_tls_domain(fake_tls_domain) or "example.com"
    host = str(upstream_host or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(upstream_port or 8446)
    except (TypeError, ValueError):
        port = 8446
    if port < 1 or port > 65535:
        port = 8446
    return (
        "upstream mtproxy {\n"
        f"    server {host}:{port};\n"
        "}\n\n"
        "map $ssl_preread_server_name $sni_name {\n"
        "    hostnames;\n"
        f"    {domain} mtproxy;\n"
        "}\n\n"
        "server {\n"
        "    listen 443;\n"
        "    proxy_protocol on;\n"
        "    set_real_ip_from unix:;\n"
        "    proxy_pass $sni_name;\n"
        "    ssl_preread on;\n"
        "}\n"
    )


def _secret_bytes(secret: object) -> bytes:
    if isinstance(secret, bytes):
        return secret
    text = str(secret or "").strip().lower()
    if len(text) != 32:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def verify_client_hello(data: bytes, secret: object) -> tuple[bytes, bytes, int] | None:
    secret_bytes = _secret_bytes(secret)
    if len(data or b"") < 43 or not secret_bytes:
        return None
    if data[0] != TLS_RECORD_HANDSHAKE or data[5] != 0x01:
        return None

    client_random = bytes(data[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN])
    zeroed = bytearray(data)
    zeroed[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] = b"\x00" * CLIENT_RANDOM_LEN
    expected = hmac.new(secret_bytes, bytes(zeroed), hashlib.sha256).digest()
    if not hmac.compare_digest(expected[:28], client_random[:28]):
        return None

    ts_raw = bytes(client_random[28 + idx] ^ expected[28 + idx] for idx in range(4))
    timestamp = struct.unpack("<I", ts_raw)[0]
    if abs(int(time.time()) - timestamp) > TIMESTAMP_TOLERANCE:
        return None

    session_id = b"\x00" * 32
    if len(data) >= 76 and data[43] == 0x20:
        session_id = bytes(data[44:76])
    return client_random, session_id, timestamp


def build_server_hello(secret: object, client_random: bytes, session_id: bytes) -> bytes:
    secret_bytes = _secret_bytes(secret)
    hello = bytearray(_SERVER_HELLO_TEMPLATE)
    hello[_SH_SESSID_OFF:_SH_SESSID_OFF + 32] = bytes(session_id or b"\x00" * 32)[:32]
    hello[_SH_PUBKEY_OFF:_SH_PUBKEY_OFF + 32] = os.urandom(32)

    encrypted_size = random.randint(1900, 2100)
    app_record = b"\x17\x03\x03" + struct.pack(">H", encrypted_size) + os.urandom(encrypted_size)
    response = bytes(hello) + _CCS_FRAME + app_record
    server_random = hmac.new(secret_bytes, bytes(client_random) + response, hashlib.sha256).digest()

    final = bytearray(response)
    final[_SH_RANDOM_OFF:_SH_RANDOM_OFF + 32] = server_random
    return bytes(final)


def wrap_tls_record(data: bytes) -> bytes:
    payload = bytes(data or b"")
    if not payload:
        return b"\x17\x03\x03\x00\x00"
    parts: list[bytes] = []
    for offset in range(0, len(payload), TLS_APPDATA_MAX):
        chunk = payload[offset:offset + TLS_APPDATA_MAX]
        parts.append(b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk)
    return b"".join(parts)


class FakeTlsStream:
    __slots__ = ("_reader", "_writer", "_read_buf", "_read_left")

    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer
        self._read_buf = bytearray()
        self._read_left = 0

    async def readexactly(self, size: int) -> bytes:
        while len(self._read_buf) < size:
            payload = await self._read_tls_payload()
            if not payload:
                raise asyncio.IncompleteReadError(bytes(self._read_buf), size)
            self._read_buf.extend(payload)
        result = bytes(self._read_buf[:size])
        del self._read_buf[:size]
        return result

    async def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = TLS_APPDATA_MAX
        if self._read_buf:
            result = bytes(self._read_buf[:size])
            del self._read_buf[:size]
            return result
        payload = await self._read_tls_payload()
        if len(payload) > size:
            self._read_buf.extend(payload[size:])
            return payload[:size]
        return payload

    async def _read_tls_payload(self) -> bytes:
        if self._read_left > 0:
            data = await self._reader.read(self._read_left)
            self._read_left -= len(data)
            return data

        while True:
            header = await self._reader.readexactly(5)
            record_type = header[0]
            record_len = struct.unpack(">H", header[3:5])[0]

            if record_type == TLS_RECORD_CCS:
                if record_len:
                    await self._reader.readexactly(record_len)
                continue
            if record_type != TLS_RECORD_APPDATA:
                return b""

            data = await self._reader.read(record_len)
            if not data:
                return b""
            self._read_left = record_len - len(data)
            return data

    def write(self, data: bytes) -> None:
        self._writer.write(wrap_tls_record(data))

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self._writer.get_extra_info(name, default)

    @property
    def transport(self):
        return self._writer.transport

    def is_closing(self):
        return self._writer.is_closing()


async def _send_fake_tls_redirect(writer, domain: str) -> None:
    redirect = (
        "HTTP/1.1 301 Moved Permanently\r\n"
        f"Location: https://{domain}/\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="replace")
    writer.write(redirect)
    await writer.drain()


async def read_mtproxy_client_init(
    reader,
    writer,
    secret: str,
    label: str,
    *,
    fake_tls_domain: str = "",
    proxy_protocol: bool = False,
) -> FakeTlsClientInit | None:
    clean_domain = normalize_fake_tls_domain(fake_tls_domain)
    current_label = str(label or "?")

    if proxy_protocol:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        except asyncio.IncompleteReadError:
            return None
        text = line.decode("ascii", errors="replace").strip()
        parts = text.split()
        if len(parts) >= 6 and parts[0] == "PROXY":
            current_label = f"{parts[2]}:{parts[4]}"

    try:
        first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=10.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None

    if first_byte[0] == TLS_RECORD_HANDSHAKE and clean_domain:
        try:
            header_rest = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            tls_header = first_byte + header_rest
            record_len = struct.unpack(">H", tls_header[3:5])[0]
            record_body = await asyncio.wait_for(reader.readexactly(record_len), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None

        client_hello = tls_header + record_body
        verified = verify_client_hello(client_hello, secret)
        if verified is None:
            await _send_fake_tls_redirect(writer, clean_domain)
            return None

        client_random, session_id, _timestamp = verified
        writer.write(build_server_hello(secret, client_random, session_id))
        await writer.drain()

        tls_stream = FakeTlsStream(reader, writer)
        try:
            init = await asyncio.wait_for(tls_stream.readexactly(MT_PROXY_INIT_LEN), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        return FakeTlsClientInit(init=init, reader=tls_stream, writer=tls_stream, label=current_label)

    if clean_domain:
        await _send_fake_tls_redirect(writer, clean_domain)
        return None

    try:
        rest = await asyncio.wait_for(reader.readexactly(MT_PROXY_INIT_LEN - 1), timeout=10.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None
    return FakeTlsClientInit(init=first_byte + rest, reader=reader, writer=writer, label=current_label)


__all__ = [
    "FakeTlsClientInit",
    "FakeTlsStream",
    "TLS_RECORD_APPDATA",
    "TLS_RECORD_CCS",
    "TLS_RECORD_HANDSHAKE",
    "build_fake_tls_secret",
    "build_fake_tls_nginx_config",
    "build_server_hello",
    "normalize_fake_tls_domain",
    "read_mtproxy_client_init",
    "verify_client_hello",
    "wrap_tls_record",
]
