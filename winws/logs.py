# winws/logs.py
"""Хвост журнала winws (файл winws.log в папке приложения)."""
from __future__ import annotations

import os
from typing import Dict, List

from .paths import log_path


def tail(limit_chars: int = 8000) -> str:
    """Последние ``limit_chars`` символов лога winws (строки не режутся)."""
    path = log_path()
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    chunk = max(0, size - max(limit_chars, 1024))
    try:
        with open(path, "rb") as f:
            f.seek(chunk)
            data = f.read()
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if chunk > 0 and lines and not lines[0].startswith("["):
        lines = lines[1:]
    return "\n".join(lines)


def recent_crashes() -> List[str]:
    """Последние строки с критическими ошибками winws (для диагностики)."""
    text = tail(12000)
    out: List[str] = []
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in ("error", "failed", "windivert", "winsock", "cannot", "fatal")):
            out.append(line.strip())
    return out[-15:]