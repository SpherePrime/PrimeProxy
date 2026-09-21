from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from . import nssm_service, service_api
from .model import StartEntry

__all__ = [
    "StartEntry",
    "SCOPES",
    "PROVIDERS",
    "build_entry_for",
    "default_entries",
    "get_autostart_status",
    "install",
    "remove",
    "start_service",
    "stop_service",
    "is_admin",
    "nssm_missing_result",
]

SCOPES = ("app", "winws")
PROVIDERS = ("nssm", "task", "shortcut")

DEFAULT_APP_NAME = "SwiftProxy Autostart"
DEFAULT_WINWS_NAME = "SwiftProxy winws"


def nssm_missing_result() -> Dict[str, Any]:
    return {"ok": False, "error": "nssm_missing",
            "detail": "nssm.exe не найден рядом с приложением"}


def _python_command() -> Tuple[str, list]:
    if getattr(sys, "frozen", False):
        return sys.executable, []
    script = sys.argv[0] or ""
    if script and Path(script).is_file():
        return sys.executable, [os.path.abspath(script)]
    return sys.executable, []


def _app_working_dir() -> str:
    try:
        from config.paths import exe_dir
        exe = exe_dir()
        if exe and Path(exe).is_dir():
            return str(Path(exe).resolve())
    except Exception:
        pass
    try:
        return str(Path(__file__).resolve().parents[1])
    except Exception:
        return ""


def build_entry_for(scope: str) -> StartEntry:
    if scope not in SCOPES:
        raise ValueError(f"unknown scope: {scope}")
    cmd, base_args = _python_command()
    work_dir = _app_working_dir()
    if scope == "app":
        return StartEntry(
            name=DEFAULT_APP_NAME,
            command=cmd,
            args=[*base_args, "--no-tray"],
            working_dir=work_dir,
            run_level="highest",
            display_name="SwiftProxy",
            description="Автозапуск SwiftProxy при входе в Windows",
        )
    return StartEntry(
        name=DEFAULT_WINWS_NAME,
        command=cmd,
        args=[*base_args, "--headless", "--autostart-winws"],
        working_dir=work_dir,
        run_level="highest",
        display_name="SwiftProxy winws",
        description="Запуск winws (обход DPI) при входе в Windows",
    )


def default_entries() -> Tuple[StartEntry, StartEntry]:
    return build_entry_for("app"), build_entry_for("winws")


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _empty_status() -> Dict[str, Any]:
    return {"installed": False, "running": None, "details": None}


def _safe_status(provider: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        return service_api.get_status(provider, entry)
    except Exception:
        return _empty_status()


def get_autostart_status() -> Dict[str, Any]:
    unsupported = os.name != "nt"
    app_entry, winws_entry = default_entries()
    result: Dict[str, Any] = {
        "unsupported": unsupported,
        "platform": sys.platform,
        "is_admin": is_admin(),
    }
    for key in PROVIDERS:
        if unsupported:
            result[key] = {"present": False,
                           "app": _empty_status(), "winws": _empty_status()}
            continue
        present = nssm_service.nssm_present() if key == "nssm" else True
        result[key] = {
            "present": present,
            "app": _safe_status(key, app_entry),
            "winws": _safe_status(key, winws_entry),
        }
    return result


def install(method: str, scope: str) -> Dict[str, Any]:
    method = (method or "").strip()
    scope = (scope or "").strip()
    if method not in PROVIDERS:
        return {"ok": False, "error": "unknown_method"}
    if scope not in SCOPES:
        return {"ok": False, "error": "unknown_scope"}
    return _switch(method, build_entry_for(scope))


def _switch(method: str, entry: StartEntry) -> Dict[str, Any]:
    result = service_api.install_service(method, entry)
    if not result.get("ok"):
        return result
    for other in PROVIDERS:
        if other != method:
            try:
                service_api.remove_service(other, entry)
            except Exception:
                pass
    return result


def remove(method: str, scope: str) -> Dict[str, Any]:
    method = (method or "").strip()
    scope = (scope or "").strip()
    if method not in PROVIDERS:
        return {"ok": False, "error": "unknown_method"}
    if scope not in SCOPES:
        return {"ok": False, "error": "unknown_scope"}
    try:
        return service_api.remove_service(method, build_entry_for(scope))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def start_service(scope: str = "app") -> Dict[str, Any]:
    scope = (scope or "").strip()
    if scope not in SCOPES:
        return {"ok": False, "error": "unknown_scope"}
    try:
        return service_api.start_service("nssm", build_entry_for(scope))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def stop_service(scope: str = "app") -> Dict[str, Any]:
    scope = (scope or "").strip()
    if scope not in SCOPES:
        return {"ok": False, "error": "unknown_scope"}
    try:
        return service_api.stop_service("nssm", build_entry_for(scope))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}