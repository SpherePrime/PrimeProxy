# utils/updater.py
"""Скачивание и установка обновлений PrimeProxy.

Стратегия установки:
- Windows (frozen/exe): свежий исполняемый файл скачивается рядом с текущим
  как ``<имя_экс>.new``; при следующем запуске ``apply_pending_restart()``
  подменяет исполняемый файл. Это позволяет не перезаписывать запущенный exe.
- macOS / Linux / режим исходников: дистрибутив скачивается в каталог загрузок
  приложения; GUI показывает путь и кнопку «Открыть папку» (самоустановка
  требует прав администратора вне зоны ответственности приложения).
"""
from __future__ import annotations

import logging
import os
import platform
import shutil
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError

from proxy.utils import build_github_opener

log = logging.getLogger("swift-updater")

REPO = "SpherePrime/PrimeProxy"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"

DOWNLOAD_DIR_NAME = "downloads"

_job_lock = threading.Lock()
_job: Dict[str, Any] = {
    "state": "idle",        # idle | downloading | done | error | check
    "target": None,          # tag id
    "asset": None,           # asset file name
    "percent": 0.0,
    "download_path": None,
    "message": None,
    "finished_at": 0.0,
}


# ── Каталоги ────────────────────────────────────────────────────────────────

def _app_dir() -> Path:
    from utils.tray_common import APP_DIR
    return Path(APP_DIR)


def _downloads_dir() -> Path:
    d = _app_dir() / DOWNLOAD_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def install_dir() -> Optional[Path]:
    """Каталог с исполняемым файлом (для frozen-сборок), иначе None."""
    if not is_frozen():
        return None
    try:
        return Path(sys.executable).resolve().parent
    except OSError:
        return None


def current_exe_name() -> str:
    if is_frozen():
        try:
            return Path(sys.executable).name
        except OSError:
            return "PrimeProxy.exe"
    return "PrimeProxy"


# ── Выбор ассета под платформу ─────────────────────────────────────────────

def default_asset_name() -> str:
    """Имя ассета дистрибутива для текущей платформы."""
    platform_name = sys.platform.lower()
    if platform_name.startswith("win"):
        try:
            is_modern = sys.getwindowsversion().major >= 10
        except Exception:
            is_modern = True
        is_arm64 = platform.machine().lower() in ("arm64", "aarch64")
        is_64 = struct.calcsize("P") * 8 == 64
        if is_arm64:
            return "PrimeProxy_windows_arm64.exe"
        if is_modern:
            return "PrimeProxy_windows.exe"
        if is_64:
            return "PrimeProxy_windows_7_64bit.exe"
        return "PrimeProxy_windows_7_32bit.exe"
    if platform_name.startswith("darwin"):
        return "PrimeProxy_macos_universal.dmg"
    if platform_name.startswith("linux"):
        return "PrimeProxy_linux_amd64.deb"
    return ""


# ── GitHub API ──────────────────────────────────────────────────────────────

def _api_request(url: str, timeout: float = 15.0):
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "prime-proxy-updater"},
        method="GET",
    )
    return build_github_opener().open(req, timeout=timeout)


def list_releases(limit: int = 10) -> List[Dict[str, Any]]:
    """Список релизов с тегами и ассетами (для отката)."""
    try:
        with _api_request(f"{RELEASES_API}?per_page={limit}") as resp:
            import json
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        out = []
        for rel in data if isinstance(data, list) else []:
            assets = [
                {"name": a.get("name", ""), "url": a.get("browser_download_url", "")}
                for a in (rel.get("assets") or [])
                if a.get("name") and a.get("browser_download_url")
            ]
            out.append({
                "tag": rel.get("tag_name", ""),
                "name": rel.get("name") or rel.get("tag_name", ""),
                "published_at": rel.get("published_at", ""),
                "prerelease": bool(rel.get("prerelease")),
                "html_url": rel.get("html_url") or RELEASES_PAGE,
                "assets": assets,
            })
        return out
    except Exception as exc:
        log.warning("list_releases failed: %s", repr(exc))
        return []


def release_by_tag(tag: str) -> Optional[Dict[str, Any]]:
    releases = list_releases(limit=30)
    for rel in releases:
        if (rel.get("tag") or "").lstrip("v") == str(tag).lstrip("v"):
            return rel
    return None


def find_asset(release: Dict[str, Any], asset_name: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Возвращает (url, имя) подходящего ассета из релиза."""
    assets = release.get("assets") or []
    want = asset_name or default_asset_name()
    if want:
        for a in assets:
            if a.get("name") == want:
                return a["url"], a["name"]
    for a in assets:
        return a["url"], a["name"]
    return None


# ── Скачивание ──────────────────────────────────────────────────────────────

def download(url: str, dest: Path, on_progress: Optional[Callable[[float], None]] = None) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "prime-proxy-updater"})
    with build_github_opener().open(req, timeout=20.0) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total and on_progress:
                    on_progress(done / total * 100.0)
    os.replace(tmp, dest)
    return True


def _set_job(**fields: Any) -> None:
    with _job_lock:
        for k, v in fields.items():
            _job[k] = v


def get_job() -> Dict[str, Any]:
    with _job_lock:
        return dict(_job)


def stage_update(
    asset_url: str,
    asset_name: str,
    *,
    on_progress: Optional[Callable[[float], None]] = None,
) -> Dict[str, Any]:
    """Скачивает дистрибутив и раскладывает его для установки при перезапуске.

    Возвращает dict с состоянием: ``{"ok", "path", "staged", "download_only"}``.
    """
    _set_job(state="downloading", asset=asset_name, percent=0.0,
             download_path=None, message=None)
    try:
        dest = _downloads_dir() / asset_name
        download(asset_url, dest, on_progress=on_progress)
        exe_dir = install_dir()
        staged_path: Optional[str] = None
        download_only = True
        if exe_dir is not None and exe_dir.is_dir() and asset_name.endswith(".exe"):
            import shutil
            new_exe = exe_dir / f"{current_exe_name()}.new"
            shutil.copy2(dest, new_exe)
            staged_path = str(new_exe)
            download_only = False
        _set_job(state="done", percent=100.0,
                 download_path=str(dest), message="downloaded")
        return {
            "ok": True,
            "path": str(dest),
            "staged": staged_path,
            "download_only": download_only,
        }
    except (HTTPError, URLError, OSError, ValueError) as exc:
        log.exception("stage_update failed")
        _set_job(state="error", message=str(exc))
        return {"ok": False, "error": str(exc)}


def stage_release_update(release: Dict[str, Any], asset_name: Optional[str] = None) -> Dict[str, Any]:
    found = find_asset(release, asset_name)
    if found is None:
        return {"ok": False, "error": "asset not found in release"}
    url, name = found
    return stage_update(url, name)


# ── Применение отложенной установки ────────────────────────────────────────

def pending_restart_path() -> Optional[Path]:
    exe_dir = install_dir()
    if exe_dir is None:
        return None
    cand = exe_dir / f"{current_exe_name()}.new"
    return cand if cand.is_file() else None


def apply_pending_restart() -> Dict[str, Any]:
    """Подменяет текущий exe на ``.new`` при следующем запуске (frozen)."""
    pending = pending_restart_path()
    if pending is None:
        return {"ok": False, "reason": "no_pending"}
    target = pending.with_name(pending.name[: -len(".new")])
    try:
        target.unlink(missing_ok=True)
        os.replace(pending, target)
        return {"ok": True, "path": str(target)}
    except OSError as exc:
        log.warning("apply_pending_restart failed: %s", repr(exc))
        return {"ok": False, "error": str(exc)}


def restart_pending() -> bool:
    return pending_restart_path() is not None


# ── Утилиты для интерфейса ─────────────────────────────────────────────────

def version_available_on_disk() -> Optional[Path]:
    """Возвращает путь к последнему скачанному дистрибутиву, если он есть."""
    d = _downloads_dir()
    if not d.is_dir():
        return None
    files = [p for p in d.iterdir() if p.is_file() and not p.name.endswith(".part")]
    if not files:
        return None
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0]


def clear_job() -> None:
    _set_job(state="idle", target=None, asset=None, percent=0.0,
             download_path=None, message=None, finished_at=0.0)