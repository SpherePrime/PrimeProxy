# winws/paths.py
"""Поиск zapret-дистрибутива рядом с приложением (папка ``exe/``)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

from config.paths import app_dir, exe_dir


def engine_dir() -> Optional[Path]:
    """Папка ``exe/`` рядом с приложением, либо None, если её нет."""
    base = exe_dir()
    if base is None:
        return None
    exe_folder = base / "exe"
    return exe_folder if exe_folder.is_dir() else None


def find_engine() -> Dict:
    """Определяет доступные движки zapret в папке ``exe/``.

    Returns:
        {"ok": bool, "dir": str, "found": {mode: path}, "candidates": [...]}
        mode — "winws2" | "winws1". Пустой found — движок не установлен.
    """
    folder = engine_dir()
    found: Dict[str, str] = {}
    if folder is not None:
        for mode, name in (("winws2", "winws2.exe"), ("winws1", "winws.exe")):
            p = folder / name
            if p.is_file():
                found[mode] = str(p)
    return {
        "ok": bool(found),
        "dir": str(folder) if folder else "",
        "found": found,
        "candidates": _candidates(),
    }


def _candidates() -> Dict[str, str]:
    """Какие исполняемые файлы ожидаются (для подсказки пользователю)."""
    return {"winws2": "exe/winws2.exe", "winws1": "exe/winws.exe"}


def preferred_mode(cfg_mode: str = "auto") -> Optional[str]:
    """Выбирает движок: явно заданный, иначе winws2, иначе winws1."""
    probe = find_engine()
    found = probe.get("found") or {}
    if not found:
        return None
    if cfg_mode in found:
        return cfg_mode
    if "winws2" in found:
        return "winws2"
    if "winws1" in found:
        return "winws1"
    return None


def user_profiles_dir() -> Path:
    d = app_dir() / "zapret" / "profiles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def tmp_dir() -> Path:
    d = app_dir() / "zapret" / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_path() -> Path:
    return app_dir() / "zapret" / "winws.log"


def resolve_mode_exe(mode: str) -> Optional[str]:
    """Возвращает путь к exe для режима, нормализуя mode (auto → winws2)."""
    probe = find_engine()
    found = probe.get("found") or {}
    if mode == "auto":
        mode = "winws2"
    if mode in found:
        return found[mode]
    # fallback: любой доступный движок
    if found:
        return next(iter(found.values()), None)
    return None