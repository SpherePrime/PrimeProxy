from __future__ import annotations

import os
import subprocess
from typing import Dict, List, Optional, Tuple

from ._log import log

_SYSTEM32_WLANAPI_CAPABILITY = "WLAN-Services~~~~0.0.1.0"

_wlanapi_missing_message_template = (
    "В этой редакции Windows отсутствует компонент wlanapi.dll (обычно на Windows Server). "
    "WinDivert может не получать доступ к беспроводным адаптерам."
)


def get_system32_path() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def is_windows_server_os() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        try:
            value, _ = winreg.QueryValueEx(key, "ProductName")
            return str(value).lower() in ("windows server 2008", "windows server 2008 r2") or "server" in str(value).lower()
        finally:
            key.Close()
    except Exception:
        return False


def has_wlanapi_missing(files: List[str]) -> bool:
    return any(str(f).lower() == "wlanapi.dll" for f in (files or []))


def should_offer_windows_server_wlanapi_install(
    missing_files: List[str],
    is_windows_server: Optional[bool] = None,
) -> bool:
    if not missing_files:
        return False
    if not has_wlanapi_missing(missing_files):
        return False
    server = is_windows_server_os() if is_windows_server is None else bool(is_windows_server)
    return server


def mark_windows_server_wlanapi_message(files: List[str]) -> str:
    if should_offer_windows_server_wlanapi_install(files):
        return _wlanapi_missing_message_template
    return ""


def run_windows_server_wlanapi_install() -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "Установка компонента доступна только на Windows Server"
    if not is_windows_server_os():
        return False, "Операционная система не является Windows Server"
    if not _is_admin():
        return False, "Требуются права администратора"
    try:
        result = subprocess.run(
            ["dism", "/online", "/add-capability", f"/capabilityname:{_SYSTEM32_WLANAPI_CAPABILITY}"],
            capture_output=True, text=True, timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            return True, "wlanapi.dll успешно установлен"
        return False, f"dism завершился с кодом {result.returncode}: {result.stderr.strip()}"
    except Exception as exc:
        return False, str(exc)


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        if not hasattr(ctypes, "windll"):
            return False
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _preflight_bfe() -> Dict[str, object]:
    try:
        from utils.service_manager import get_service_state
        state = get_service_state("BFE")
        ok = state == 4
        return {
            "ok": ok,
            "state": state,
            "detail": "служба BFE (Base Filtering Engine) работает" if ok else "служба BFE не запущена",
        }
    except Exception:
        return {"ok": True, "state": None, "detail": "проверка службы BFE недоступна"}


def _preflight_wlanapi() -> Dict[str, object]:
    path = os.path.join(get_system32_path(), "wlanapi.dll")
    ok = os.path.isfile(path)
    detail = "wlanapi.dll найден" if ok else "wlanapi.dll отсутствует (возможно, Windows Server)"
    if not ok and is_windows_server_os():
        detail = f"{detail}; доступна установка компонента"
    return {"ok": ok, "detail": detail}


def _preflight_driver() -> Dict[str, object]:
    candidates: List[str] = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    for name in ("Monkey64.sys", "WinDivert64.sys"):
        candidates.append(os.path.join(system_root, "System32", "drivers", name))
    try:
        from winws.paths import engine_dir
        folder = engine_dir()
        if folder is not None:
            for name in ("Monkey64.sys", "WinDivert64.sys"):
                candidates.append(str(folder / name))
    except Exception:
        pass
    existing = [p for p in candidates if os.path.isfile(p)]
    ok = bool(existing) or _preflight_windivert_service_exists()
    return {
        "ok": ok,
        "detail": "драйвер WinDivert доступен" if ok else "драйвер WinDivert (Monkey64.sys/WinDivert64.sys) не найден",
        "driver_files": sorted(set(existing)),
    }


def _preflight_windivert_service_exists() -> bool:
    try:
        from .system_ops import _get_windivert_service_states
        return bool(_get_windivert_service_states())
    except Exception:
        return False


def preflight_dependencies(timeout: float = 8.0) -> Dict[str, object]:
    checks = {
        "bfe": _preflight_bfe(),
        "wlanapi": _preflight_wlanapi(),
        "driver": _preflight_driver(),
    }
    all_ok = bool(checks["bfe"].get("ok")) and bool(checks["wlanapi"].get("ok")) and bool(checks["driver"].get("ok"))
    return {"ok": all_ok, "checks": checks}