from __future__ import annotations

import os
import time
from typing import Optional, Set

from ._log import log
from utils.windows_process_probe import _iter_process_name_records_winapi

_KASPERSKY_PROCESS_NAMES: Set[str] = {
    "avp.exe",
    "avpui.exe",
    "kavsvc.exe",
    "kis.exe",
    "kavtray.exe",
}

_KASPERSKY_NAME_MARKERS: Set[str] = {
    "kaspersky",
    "kav",
    "kfa",
    "kis",
    "kaspersky free",
    "kaspersky security cloud",
}

_CACHE_TTL_SECONDS = 120.0

_present_cache: Optional[bool] = None
_present_cache_time: float = 0.0


def _lazy_kaspersky_probe() -> bool:
    try:
        records = list(_iter_process_name_records_winapi())
    except Exception:
        return False
    for record in records:
        name = str(record.get("name", "")).lower()
        if name in _KASPERSKY_PROCESS_NAMES:
            return True
    return False


def is_kaspersky_present(force_refresh: bool = False) -> bool:
    """Проверяет, активен ли Kaspersky (кэшируется на 120 секунд)."""
    global _present_cache, _present_cache_time
    now = time.monotonic()
    if not force_refresh and _present_cache is not None and (now - _present_cache_time) < _CACHE_TTL_SECONDS:
        return _present_cache
    result = _lazy_kaspersky_probe()
    _present_cache = result
    _present_cache_time = now
    return result


def invalidate_kaspersky_cache() -> None:
    global _present_cache, _present_cache_time
    _present_cache = None
    _present_cache_time = 0.0

def _kaspersky_cached_probe() -> bool:
    return is_kaspersky_present()


def _is_kaspersky_present_safe() -> bool:
    try:
        return is_kaspersky_present()
    except Exception:
        return False


def is_kaspersky_detected_in_path(path: str) -> bool:
    lowered = str(path).lower()
    return any(marker in lowered for marker in _KASPERSKY_NAME_MARKERS)