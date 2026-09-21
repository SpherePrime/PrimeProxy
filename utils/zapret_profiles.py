# utils/zapret_profiles.py
"""Каталог winws-профилей, импортированный из ZapretGUI (resources/zapret).

Раздел «Профили» в SwiftProxy — справочник: список стратегий winws1/winws2
с фильтрами и просмотром полной команды профиля. Профили не выполняются
движком SwiftProxy, а показываются как источник параметров.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from config.paths import resources_dir

_GROUPS = ("winws1", "winws2")


def _load_text(path: Path, limit: int = 0) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    return text if limit <= 0 else text[:limit]


def _tags(name: str) -> List[str]:
    low = name.lower()
    tags = []
    if "alt" in low:
        tags.append("alt")
    if "game filter" in low:
        tags.append("game")
    if "circular" in low:
        tags.append("circular")
    if low.startswith("default"):
        tags.append("default")
    if "ytdisbystro" in low:
        tags.append("youtube")
    if "discord" in low:
        tags.append("discord")
    if not tags:
        tags.append("other")
    return tags


def list_profiles(group: str = "winws2", lang: str = "ru") -> List[Dict[str, Any]]:
    if group not in _GROUPS:
        group = "winws2"
    root = resources_dir() / "zapret" / group
    out = []
    if root.is_dir():
        for path in sorted(root.glob("*.txt"), key=lambda p: p.name.lower()):
            out.append({
                "id": path.stem,
                "file": path.name,
                "group": group,
                "title": path.stem,
                "tags": _tags(path.name),
                "size": path.stat().st_size if path.is_file() else 0,
            })
    return out


def get_profile_text(group: str, file_name: str) -> Dict[str, Any]:
    if group not in _GROUPS:
        group = "winws2"
    root = resources_dir() / "zapret" / group
    path = root / str(file_name or "")
    if not path.is_file() or path.suffix.lower() != ".txt":
        return {"ok": False, "error": "not_found"}
    text = _load_text(path)
    return {"ok": True, "group": group, "file": path.name, "text": text}


def list_strategies() -> List[Dict[str, Any]]:
    """Описания стратегий из strategy_catalogs (winws2)."""
    root = resources_dir() / "zapret" / "strategies"
    out = []
    if root.is_dir():
        for path in sorted(root.glob("*.txt"), key=lambda p: p.name.lower()):
            out.append({
                "id": path.stem,
                "title": path.stem,
                "text": _load_text(path),
            })
    return out


def _title_key(item: Dict[str, Any]) -> str:
    return (item.get("title") or "").lower()


def search_profiles(group: str, query: str = "", tags: List[str] | None = None) -> List[Dict[str, Any]]:
    items = list_profiles(group)
    q = (query or "").strip().lower()
    want = set(tags or [])
    result = []
    for it in items:
        if q and q not in it["title"].lower() and q not in " ".join(it["tags"]):
            continue
        if want and not want & set(it["tags"]):
            continue
        result.append(it)
    return result