"""
Хранилище профилей winws в ``<app_dir>/zapret/profiles`` (+ рекомендуемый профиль).
Сохраняет обратную совместимость публичного API старого модуля
(``list_user_profiles`` и т.д.) и добавляет profile-подсистему редактора.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import winws.paths as _wp
from config.paths import resources_dir

from .serializer import validate_profile

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-\.\(\) ]{1,80}$")
_GROUPS = ("winws1", "winws2")


def _recommended_name() -> str:
    from tools import RECOMMENDED_PROFILE
    return RECOMMENDED_PROFILE


def profile_dir() -> Path:
    return _wp.user_profiles_dir()


def _bundled_recommended() -> Optional[Path]:
    path = resources_dir() / "zapret" / "winws2" / _recommended_name()
    return path if path.is_file() else None


def is_recommended(name: str) -> bool:
    n = (name or "").strip()
    return n == _recommended_name() or n == _recommended_name()[:-4]


def ensure_recommended() -> Optional[Path]:
    src = _bundled_recommended()
    if src is None:
        return None
    dst = profile_dir() / _recommended_name()
    try:
        if not dst.is_file():
            dst.write_bytes(src.read_bytes())
    except OSError:
        return None
    return dst


def list_user_profiles() -> List[Dict[str, Any]]:
    d = profile_dir()
    out = []
    if d.is_dir():
        for p in sorted(d.glob("*.txt"), key=lambda x: x.name.lower()):
            try:
                size = p.stat().st_size
                mtime = p.stat().st_mtime
            except OSError:
                size, mtime = 0, 0.0
            out.append({
                "id": p.stem,
                "name": p.stem,
                "file": p.name,
                "kind": "user",
                "size": size,
                "mtime": mtime,
                "is_recommended": is_recommended(p.name),
            })
    return out


def _read(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _normalize_name(name: str) -> str:
    n = (name or "").strip()
    if n.lower().endswith(".txt"):
        n = n[:-4]
    return n


def _safe_user_path(name: str) -> Optional[Path]:
    name = _normalize_name(name)
    if not name:
        return None
    if os.sep in name or "/" in name or ".." in name:
        return None
    return profile_dir() / f"{name}.txt"


def get_user_profile_text(name: str) -> Dict[str, Any]:
    path = _safe_user_path(name)
    if path is None or not path.is_file():
        return {"ok": False, "error": "not_found"}
    return {
        "ok": True,
        "name": path.stem,
        "text": _read(path),
        "kind": "user",
        "is_recommended": is_recommended(path.name),
    }


def save_user_profile(name: str, text: str) -> Dict[str, Any]:
    name = _normalize_name(name)
    if not _PROFILE_NAME_RE.match(name):
        return {"ok": False, "error": "bad_name"}
    path = profile_dir() / f"{name}.txt"
    try:
        path.write_text(text or "", encoding="utf-8", newline="\n")
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "detail": str(exc)}
    return {"ok": True, "name": name}


def delete_user_profile(name: str) -> Dict[str, Any]:
    path = _safe_user_path(name)
    if path is None or not path.is_file():
        return {"ok": False, "error": "not_found"}
    try:
        path.unlink()
    except OSError as exc:
        return {"ok": False, "error": "delete_failed", "detail": str(exc)}
    return {"ok": True, "name": name}


def _active_from_store(cfg: dict) -> Dict[str, Any]:
    return {
        "group": cfg.get("profile_group", "winws2"),
        "profile": cfg.get("profile", ""),
        "enabled": bool(cfg.get("enabled", False)),
        "is_user": cfg.get("profile_group") == "user",
        "is_recommended": bool(cfg.get("profile_group") == "user" and is_recommended(cfg.get("profile", ""))),
    }


def get_active_profile() -> Dict[str, Any]:
    from config import get_store as _store
    return _active_from_store(_store().get("zapret") or {})


def set_active_profile(name: str, group: str = "user") -> Dict[str, Any]:
    name = (name or "").strip()
    if not _PROFILE_NAME_RE.match(name):
        return {"ok": False, "error": "bad_name"}
    from config import get_store as _store
    _store().set_section("zapret", {"profile_group": group or "user", "profile": name})
    return {"ok": True, "name": name, "group": group or "user"}


def profile_list() -> Dict[str, Any]:
    ensure_recommended()
    return {
        "ok": True,
        "profiles": list_user_profiles(),
        "recommended": _recommended_name(),
        "active": get_active_profile(),
    }


def profile_read(name: str) -> Dict[str, Any]:
    ensure_recommended()
    res = get_user_profile_text(name)
    if not res.get("ok"):
        if is_recommended(name):
            return {"ok": False, "error": "recommended_missing"}
        return res
    verdict = validate_profile(res["text"])
    return {
        "ok": True,
        "name": res["name"],
        "is_recommended": res.get("is_recommended", False),
        "content": res["text"],
        "validation": verdict,
    }


def profile_write(name: str, content: str) -> Dict[str, Any]:
    name = (name or "").strip()
    if not _PROFILE_NAME_RE.match(name):
        return {"ok": False, "error": "bad_name"}
    text = "" if content is None else str(content)
    verdict = validate_profile(text)
    saved = save_user_profile(name, text)
    if not saved.get("ok"):
        return saved
    return {
        "ok": True,
        "name": name,
        "is_recommended": is_recommended(name),
        "validation": verdict,
    }


def profile_reset(name: str) -> Dict[str, Any]:
    if not is_recommended(name):
        return {"ok": False, "error": "not_recommended"}
    src = _bundled_recommended()
    if src is None:
        return {"ok": False, "error": "bundle_missing"}
    rec = _recommended_name()
    path = profile_dir() / rec
    try:
        path.write_bytes(src.read_bytes())
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "detail": str(exc)}
    text = _read(path)
    return {
        "ok": True,
        "name": rec,
        "is_recommended": True,
        "content": text,
        "validation": validate_profile(text),
    }


def profile_delete(name: str) -> Dict[str, Any]:
    if is_recommended(name):
        return {"ok": False, "error": "protected_recommended"}
    active = get_active_profile()
    if active.get("group") == "user" and active.get("profile") == _normalize_name(name):
        return {"ok": False, "error": "protected_active"}
    return delete_user_profile(name)


def resolve_profile(group: str, file_name: str) -> Dict[str, Any]:
    if group == "user":
        return get_user_profile_text(file_name)
    if group not in _GROUPS:
        return {"ok": False, "error": "bad_group"}
    from utils.zapret_profiles import get_profile_text as _builtin_text
    res = _builtin_text(group, file_name)
    if not res.get("ok"):
        return {"ok": False, "error": "not_found"}
    return {
        "ok": True,
        "kind": "builtin",
        "group": group,
        "file": res["file"],
        "text": res["text"],
    }


def engine_mode_for(group: str, cfg_mode: str = "auto") -> str:
    if group in ("winws2",):
        return "winws2"
    if group in ("winws1",):
        return "winws1"
    return cfg_mode if cfg_mode in ("winws1", "winws2") else "auto"