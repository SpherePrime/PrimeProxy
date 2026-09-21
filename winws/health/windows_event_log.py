from __future__ import annotations

import re
import subprocess
from typing import Dict, List, Optional

from ._log import log

_DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
_DEFENDER_DETECTION_EVENT_IDS = (1116, 1117)
_DEFENDER_CHANNEL_OVERRIDES: Dict[str, str] = {}
_DEFENDER_DATA_RE = re.compile(r"(?:File:\s*(?P<file>[^\r\n]+)|файл.*?:\s*(?P<file_ru>[^\r\n]+))", re.IGNORECASE)


def _query_defender_events(timeout: float = 12.0) -> List[Dict[str, object]]:
    """Читает свежие события обнаружения Defender через PowerShell (без сторонних модулей)."""
    ids = ", ".join(str(_id) for _id in _DEFENDER_DETECTION_EVENT_IDS)
    ps = (
        "Get-WinEvent -FilterHashtable @{LogName='" + _DEFENDER_CHANNEL + "'; Id=" + ids + "} "
        "-MaxEvents 5 -ErrorAction SilentlyContinue | "
        "ForEach-Object { '" + "{0}|{1}|{2}" + "' }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        ).stdout
    except Exception:
        return []
    events: List[Dict[str, object]] = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        event_id, _, message = (p.strip() for p in parts)
        if not message:
            continue
        events.append({
            "event_id": event_id,
            "severity": _severity_for_event(event_id),
            "message": message,
            "sources": [],
            "paths": _extract_kaspersky_paths(message),
        })
    return events


def _severity_for_event(event_id: str) -> str:
    try:
        _id = int(event_id)
    except (TypeError, ValueError):
        return "info"
    if _id == 1117:
        return "error"
    return "warning"


def _extract_kaspersky_paths(message: str) -> List[str]:
    matches = _DEFENDER_DATA_RE.findall(message)
    paths = []
    for file, file_ru in matches:
        paths.append((file or file_ru or "").strip())
    return [p for p in paths if p]


def _summarize_defender_event(record: Dict[str, object]) -> Optional[str]:
    event_id = str(record.get("event_id", ""))
    paths = record.get("paths") or []
    target = ", ".join(paths[:3]) if paths else "цель не указана"
    action = "обнаружена угроза" if event_id == "1116" else "угроза обработана"
    return f"Defender: {action} — {target}"


def list_defender_detections(timeout: float = 12.0) -> List[Dict[str, object]]:
    """Возвращает список свежих событий Defender о блокировках (может ловить WinDivert.dll/winws.exe)."""
    try:
        return _query_defender_events(timeout=timeout)
    except Exception:
        return []


def recent_defender_flag_points() -> List[Dict[str, object]]:
    """Короткий отчёт для UI: события, где целью выглядит winws/WinDivert."""
    recents = list_defender_detections(timeout=8.0)
    flagged = []
    for record in recents:
        paths = record.get("paths") or []
        if any(_looks_like_winws_path(p) for p in paths):
            summary = _summarize_defender_event(record)
            flagged.append({"event_id": record.get("event_id"), "summary": summary, "targets": paths})
    return flagged


def _looks_like_winws_path(path: str) -> bool:
    lowered = str(path).lower()
    return "winws" in lowered or "windivert" in lowered or "monkey" in lowered