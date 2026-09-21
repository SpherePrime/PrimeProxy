from __future__ import annotations

import logging
from typing import Any, Dict

from . import nssm_service, scheduled_task_api, startup_shortcut_api
from .model import StartEntry

log = logging.getLogger("swift-autostart")

PROVIDERS = ("nssm", "task", "shortcut")


def _task_status(entry: StartEntry) -> Dict[str, Any]:
    info = scheduled_task_api.get_task_info(task_name=entry.name)
    return {
        "installed": info is not None,
        "running": None,
        "details": info,
    }


def _shortcut_status(entry: StartEntry) -> Dict[str, Any]:
    shortcut_path = startup_shortcut_api.get_startup_shortcut_path(shortcut_name=entry.name)
    info = startup_shortcut_api.get_startup_shortcut_info(shortcut_path=shortcut_path)
    return {
        "installed": info is not None,
        "running": None,
        "details": info,
    }


def _nssm_status(entry: StartEntry) -> Dict[str, Any]:
    return nssm_service.get_service_status_nssm(entry.name)


def _status(method: str, entry: StartEntry) -> Dict[str, Any]:
    if method == "nssm":
        return _nssm_status(entry)
    if method == "task":
        return _task_status(entry)
    if method == "shortcut":
        return _shortcut_status(entry)
    return {"installed": False, "running": None, "details": None}


def get_status(method: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        return _status(method, entry)
    except Exception as exc:
        log.debug("status for %s failed: %s", method, exc)
        return {"installed": False, "running": None, "details": None}


def install_service(method: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        if method == "nssm":
            return nssm_service.create_service_with_nssm(entry)
        if method == "task":
            ok = scheduled_task_api.create_or_update_autostart_task(entry, task_name=entry.name)
            return {"ok": ok}
        if method == "shortcut":
            shortcut_path = startup_shortcut_api.get_startup_shortcut_path(shortcut_name=entry.name)
            return startup_shortcut_api.create_startup_shortcut(entry, shortcut_path=shortcut_path)
        return {"ok": False, "error": "unknown_provider"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def remove_service(method: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        if method == "nssm":
            return nssm_service.remove_service_with_nssm(entry.name)
        if method == "task":
            ok = scheduled_task_api.delete_autostart_task(task_name=entry.name)
            return {"ok": ok}
        if method == "shortcut":
            shortcut_path = startup_shortcut_api.get_startup_shortcut_path(shortcut_name=entry.name)
            ok = startup_shortcut_api.delete_startup_shortcut(shortcut_path=shortcut_path)
            return {"ok": ok}
        return {"ok": False, "error": "unknown_provider"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def start_service(method: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        if method == "nssm":
            return nssm_service.start_service_with_nssm(entry.name)
        return {"ok": False, "error": "unsupported_provider"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def stop_service(method: str, entry: StartEntry) -> Dict[str, Any]:
    try:
        if method == "nssm":
            return nssm_service.stop_service_with_nssm(entry.name)
        return {"ok": False, "error": "unsupported_provider"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}