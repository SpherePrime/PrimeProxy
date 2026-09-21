from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .model import StartEntry

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _exe_dir() -> str:
    try:
        from config.paths import exe_dir
        result = exe_dir()
        if result:
            return str(result)
    except Exception:
        pass
    return str(Path(__file__).resolve().parents[1])


def _engine_dir() -> str:
    try:
        from winws.paths import engine_dir
        result = engine_dir()
        if result:
            return str(result)
    except Exception:
        pass
    return _exe_dir()


def _app_dir() -> str:
    return _exe_dir()


def _path_candidates() -> list:
    candidates = []
    for base in (_exe_dir(), _engine_dir(), _app_dir()):
        candidates.append(str(Path(base) / "nssm.exe"))
    found = shutil.which("nssm.exe")
    if found:
        candidates.append(found)
    return candidates


def get_nssm_path() -> Optional[str]:
    for candidate in _path_candidates():
        try:
            if Path(candidate).is_file():
                return os.path.normpath(candidate)
        except OSError:
            continue
    return None


def nssm_present() -> bool:
    return get_nssm_path() is not None


def _missing() -> Dict[str, Any]:
    return {"ok": False, "error": "nssm_missing",
            "detail": "nssm.exe не найден рядом с приложением"}


def _decode_output(data: Optional[bytes]) -> str:
    if not data:
        return ""
    for encoding in ("utf-16-le", "utf-8-sig", "utf-8", "mbcs", "cp866"):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _run_nssm(arguments: list) -> "subprocess.CompletedProcess[bytes]":
    nssm = get_nssm_path()
    command = [nssm, *[str(a) for a in arguments]]
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        creationflags=_NO_WINDOW,
    )


def _create_log_directory() -> None:
    try:
        from config.paths import log_file
        log_path = Path(str(log_file()))
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def create_service_with_nssm(entry: StartEntry) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    nssm = get_nssm_path()
    if not nssm:
        return _missing()

    service_name = entry.name
    command = str(entry.command or "").strip()
    if not command:
        return {"ok": False, "error": "no_command"}

    if service_exists(service_name):
        params = set_service_app_params(entry)
        if params.get("ok"):
            return {"ok": True, "installed": True}
        return params

    install = _run_nssm(["install", service_name, command])
    if install.returncode != 0:
        return {"ok": False, "error": _decode_output(install.stderr).strip() or "nssm install failed"}
    params = set_service_app_params(entry)
    return params


def set_service_app_params(entry: StartEntry) -> Dict[str, Any]:
    nssm = get_nssm_path()
    if not nssm:
        return _missing()
    service_name = entry.name
    work_dir = str(Path(entry.working_dir or "").resolve())
    _create_log_directory()
    if work_dir:
        result = _run_nssm(["set", service_name, "AppDirectory", work_dir])
        if result.returncode != 0:
            return {"ok": False, "error": _decode_output(result.stderr).strip() or "nssm set failed"}
    args = subprocess.list2cmdline([str(a) for a in (entry.args or [])])
    result = _run_nssm(["set", service_name, "AppParameters", args])
    if result.returncode != 0:
        return {"ok": False, "error": _decode_output(result.stderr).strip() or "nssm set failed"}
    return {"ok": True, "installed": True}


def service_exists(service_name: str) -> bool:
    try:
        from utils.service_manager import service_exists as _exists
        return _exists(service_name)
    except Exception:
        nssm = get_nssm_path()
        if not nssm:
            return False
        result = _run_nssm(["status", service_name])
        return result.returncode == 0


def get_service_status_nssm(service_name: str) -> Dict[str, Any]:
    nssm = get_nssm_path()
    if not nssm or not service_exists(service_name):
        return {"installed": False, "running": None, "service_name": service_name}
    result = _run_nssm(["status", service_name])
    output = _decode_output(result.stdout if result.returncode == 0 else result.stderr).strip()
    return {
        "installed": True,
        "running": bool(output) and output.lower().startswith("service_run"),
        "service_name": service_name,
        "status": output,
    }


def start_service_with_nssm(service_name: str) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    nssm = get_nssm_path()
    if not nssm:
        return _missing()
    if not service_exists(service_name):
        return {"ok": False, "error": "service_not_found"}
    result = _run_nssm(["start", service_name])
    if result.returncode == 0:
        return {"ok": True}
    return {"ok": False, "error": _decode_output(result.stderr).strip() or "nssm start failed"}


def stop_service_with_nssm(service_name: str) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    nssm = get_nssm_path()
    if not nssm:
        return _missing()
    if not service_exists(service_name):
        return {"ok": False, "error": "service_not_found"}
    result = _run_nssm(["stop", service_name])
    if result.returncode == 0:
        return {"ok": True}
    return {"ok": False, "error": _decode_output(result.stderr).strip() or "nssm stop failed"}


def remove_service_with_nssm(service_name: str) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    nssm = get_nssm_path()
    if not nssm:
        return _missing()
    if service_exists(service_name):
        result = _run_nssm(["remove", service_name, "confirm"])
        if result.returncode != 0:
            return {"ok": False, "error": _decode_output(result.stderr).strip() or "nssm remove failed"}
    return {"ok": True}


def kill_winws_processes() -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    try:
        import psutil
    except ImportError:
        return {"ok": False, "error": "psutil недоступен"}
    killed = 0
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info.get("name") or "").lower() == "winws.exe":
                proc.kill()
                killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"ok": True, "killed": killed}


start_service = start_service_with_nssm
stop_service = stop_service_with_nssm
remove_service = remove_service_with_nssm
get_service_status = get_service_status_nssm