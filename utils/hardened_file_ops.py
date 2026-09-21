from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional, Union

CHUNK_SIZE = 1024 * 1024


def sha256_file(path, chunk_size: int = CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(max(int(chunk_size), 1))
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_bytes(path, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f"{target.name}_", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(tmp_name, str(target))
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def atomic_write_bytes(path, data: Union[bytes, bytearray, memoryview]) -> None:
    _atomic_write_bytes(path, bytes(data))


def atomic_write_text(path, text: str, encoding: str = "utf-8") -> None:
    data = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    if data and not data.endswith("\n"):
        data += "\n"
    _atomic_write_bytes(path, data.encode(encoding))


def replace_file_safe(src, dst) -> None:
    src_path = Path(src)
    dst_path = Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if dst_path.exists():
        dst_path.unlink()
    os.replace(str(src_path), str(dst_path))


def safe_join(base, *parts) -> Path:
    base_path = Path(base).resolve()
    joined = base_path.joinpath(*parts)
    resolved = joined.resolve()
    if resolved != base_path and base_path not in resolved.parents:
        raise ValueError(f"path escapes base: {parts!r}")
    return joined


def verify_file_sha256(path, expected: Optional[str]) -> bool:
    if not expected:
        return False
    expected = str(expected).strip().lower()
    try:
        actual = sha256_file(path)
    except OSError:
        return False
    return actual == expected


def compare_bytes(a: bytes, b: bytes) -> bool:
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    if len(a) != len(b):
        return False
    result = 0
    for left, right in zip(a, b):
        result |= left ^ right
    return result == 0


def file_size(path) -> int:
    return Path(path).stat().st_size