from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
from ctypes import wintypes
from typing import Dict, List, Optional

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

SERVICE_QUERY_STATUS = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_STOP = 0x0020
SERVICE_START = 0x0010
DELETE = 0x00010000
SERVICE_ALL_ACCESS = 0xF01FF

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ALL_ACCESS = 0xF003F

SERVICE_CONTROL_STOP = 0x00000001

ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_SERVICE_DISABLED = 1058

_START_TYPE_TOKEN = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}
_START_TYPE_CODE = {v: k for k, v in _START_TYPE_TOKEN.items()}

_ENABLE_WINAPI = True
_WINAPI_INITIALIZED = False

_OpenSCManagerW = None
_OpenServiceW = None
_CloseServiceHandle = None
_ControlService = None
_QueryServiceStatus = None
_DeleteService = None
_ChangeServiceConfigW = None
_QueryServiceConfigW = None
_advapi32 = None


class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class _QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


def _init_winapi() -> bool:
    global _WINAPI_INITIALIZED, _advapi32, _OpenSCManagerW, _OpenServiceW, _CloseServiceHandle
    global _ControlService, _QueryServiceStatus, _DeleteService, _ChangeServiceConfigW
    if _WINAPI_INITIALIZED:
        return bool(_OpenSCManagerW)
    _WINAPI_INITIALIZED = True
    if os.name != "nt" or not hasattr(ctypes, "windll"):
        return False
    try:
        _advapi32 = ctypes.windll.advapi32
        _OpenSCManagerW = _advapi32.OpenSCManagerW
        _OpenServiceW = _advapi32.OpenServiceW
        _CloseServiceHandle = _advapi32.CloseServiceHandle
        _ControlService = _advapi32.ControlService
        _QueryServiceStatus = _advapi32.QueryServiceStatus
        _DeleteService = _advapi32.DeleteService
        _ChangeServiceConfigW = _advapi32.ChangeServiceConfigW

        _OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        _OpenSCManagerW.restype = wintypes.HANDLE
        _OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        _OpenServiceW.restype = wintypes.HANDLE
        _CloseServiceHandle.argtypes = [wintypes.HANDLE]
        _CloseServiceHandle.restype = wintypes.BOOL
        _ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(_SERVICE_STATUS)]
        _ControlService.restype = wintypes.BOOL
        _QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(_SERVICE_STATUS)]
        _QueryServiceStatus.restype = wintypes.BOOL
        _DeleteService.argtypes = [wintypes.HANDLE]
        _DeleteService.restype = wintypes.BOOL
        _ChangeServiceConfigW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID, wintypes.LPCWSTR,
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        ]
        _ChangeServiceConfigW.restype = wintypes.BOOL
        return True
    except Exception:
        return False


def _winapi_available() -> bool:
    return bool(_ENABLE_WINAPI and _init_winapi() and _OpenSCManagerW)


def _open_sc_manager(access: int = SC_MANAGER_CONNECT):
    if not _winapi_available():
        return None
    return _OpenSCManagerW(None, None, access)


def _open_service(scm, name: str, access: int):
    if not _winapi_available():
        return None
    return _OpenServiceW(scm, name, access)


def _close_handle(handle) -> None:
    if handle and _CloseServiceHandle is not None:
        try:
            _CloseServiceHandle(handle)
        except Exception:
            pass


def _query_service_status_winapi(service_handle, status) -> bool:
    return bool(_QueryServiceStatus is not None and _QueryServiceStatus(service_handle, status))


def _get_service_state_winapi(name: str) -> Optional[int]:
    if not _winapi_available():
        return None
    scm = _open_sc_manager(SC_MANAGER_CONNECT)
    if not scm:
        return None
    try:
        svc = _open_service(scm, name, SERVICE_QUERY_STATUS)
        if not svc:
            return None
        try:
            status = _SERVICE_STATUS()
            if not _query_service_status_winapi(svc, status):
                return None
            return int(status.dwCurrentState)
        finally:
            _close_handle(svc)
    finally:
        _close_handle(scm)


def _stop_service_winapi(name: str) -> bool:
    if not _winapi_available():
        return False
    scm = _open_sc_manager(SC_MANAGER_CONNECT)
    if not scm:
        return False
    try:
        svc = _open_service(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        if not svc:
            return False
        try:
            status = _SERVICE_STATUS()
            return bool(_ControlService(svc, SERVICE_CONTROL_STOP, status))
        finally:
            _close_handle(svc)
    finally:
        _close_handle(scm)


def _delete_service_winapi(name: str) -> bool:
    if not _winapi_available():
        return False
    scm = _open_sc_manager(SC_MANAGER_CONNECT)
    if not scm:
        return False
    try:
        svc = _open_service(scm, name, DELETE | SERVICE_QUERY_STATUS)
        if not svc:
            return False
        try:
            return bool(_DeleteService(svc))
        finally:
            _close_handle(svc)
    finally:
        _close_handle(scm)


def _change_service_start_type_winapi(name: str, start_type: int) -> bool:
    if not _winapi_available():
        return False
    scm = _open_sc_manager(SC_MANAGER_CONNECT)
    if not scm:
        return False
    try:
        svc = _open_service(scm, name, SERVICE_CHANGE_CONFIG)
        if not svc:
            return False
        try:
            return bool(_ChangeServiceConfigW(svc, 0xFFFFFFFF, start_type, 0xFFFFFFFF, None, None, None, None, None, None, None))
        finally:
            _close_handle(svc)
    finally:
        _close_handle(scm)


def _sc_run(args: List[str], timeout: float = 8.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["sc.exe", *args],
            capture_output=True, text=True, timeout=timeout, creationflags=_NO_WINDOW,
        )
    except Exception as exc:
        result = subprocess.CompletedProcess(["sc.exe", *args], 1, stdout="", stderr=str(exc))
        return result


def _registry_services_key_path() -> str:
    return "SYSTEM\\CurrentControlSet\\Services"


def service_registry_exists(name: str) -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _registry_services_key_path() + "\\" + name)
        key.Close()
        return True
    except OSError:
        return False
    except Exception:
        return False


def get_service_registry_flags(name: str) -> Dict[str, object]:
    if os.name != "nt":
        return {"start": None, "delete_flag": None}
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _registry_services_key_path() + "\\" + name)
        try:
            start = None
            delete_flag = None
            try:
                start, _ = winreg.QueryValueEx(key, "Start")
            except OSError:
                pass
            try:
                delete_flag, _ = winreg.QueryValueEx(key, "DeleteFlag")
            except OSError:
                pass
            return {
                "start": int(start) if start is not None else None,
                "delete_flag": int(delete_flag) if delete_flag is not None else None,
            }
        finally:
            key.Close()
    except OSError:
        return {"start": None, "delete_flag": None}
    except Exception:
        return {"start": None, "delete_flag": None}


def _registry_start_type(name: str) -> Optional[int]:
    return get_service_registry_flags(name).get("start")


def service_exists(name: str) -> bool:
    if service_registry_exists(name):
        return True
    if _winapi_available() and _get_service_state_winapi(name) is not None:
        return True
    result = _sc_run(["query", name])
    return result.returncode == 0 and "does not exist" not in ((result.stdout or "") + (result.stderr or "")).lower()


def _state_from_sc_stdout(text: str) -> Optional[int]:
    match = re.search(r"STATE\s*:\s*(\d+)", text)
    return int(match.group(1)) if match else None


def query_service(name: str) -> Optional[Dict[str, object]]:
    if _winapi_available():
        state = _get_service_state_winapi(name)
        if state is not None:
            return {
                "name": name,
                "exists": True,
                "state": state,
                "state_text": _state_text(state),
                "start_type": _registry_start_type(name),
            }
    result = _sc_run(["query", name])
    text = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 or "does not exist" in text.lower():
        if service_registry_exists(name):
            return {
                "name": name,
                "exists": True,
                "state": None,
                "state_text": "",
                "start_type": _registry_start_type(name),
            }
        return None
    state = _state_from_sc_stdout(result.stdout or "")
    return {
        "name": name,
        "exists": True,
        "state": state,
        "state_text": _state_text(state) if state is not None else "",
        "start_type": _registry_start_type(name),
    }


def get_service_state(name: str) -> Optional[int]:
    if _winapi_available():
        state = _get_service_state_winapi(name)
        if state is not None:
            return state
    result = _sc_run(["query", name])
    if result.returncode != 0:
        return None
    return _state_from_sc_stdout(result.stdout or "")


def get_service_start_type(name: str) -> Optional[int]:
    reg_type = _registry_start_type(name)
    if reg_type is not None:
        return reg_type
    result = _sc_run(["qc", name])
    if result.returncode != 0:
        return None
    match = re.search(r"START_TYPE\s*:\s*\d+\s+(\S+)", result.stdout or "")
    if not match:
        return None
    return _START_TYPE_CODE.get(match.group(1).lower())


def _state_text(state: int) -> str:
    return {
        SERVICE_STOPPED: "stopped",
        SERVICE_START_PENDING: "start pending",
        SERVICE_STOP_PENDING: "stop pending",
        SERVICE_RUNNING: "running",
        SERVICE_CONTINUE_PENDING: "continue pending",
        SERVICE_PAUSE_PENDING: "pause pending",
        SERVICE_PAUSED: "paused",
    }.get(state, "")


def stop_service(service_name: str) -> bool:
    if not service_exists(service_name):
        return True
    if _winapi_available():
        if _get_service_state_winapi(service_name) == SERVICE_STOPPED:
            return True
        if _stop_service_winapi(service_name):
            return True
    result = _sc_run(["stop", service_name])
    return result.returncode == 0


def delete_service(service_name: str) -> bool:
    if _winapi_available() and _delete_service_winapi(service_name):
        return not service_exists(service_name) or True
    if not service_exists(service_name):
        return True
    result = _sc_run(["delete", service_name])
    if result.returncode == 0:
        return True
    clear_service_delete_flag(service_name)
    return not service_exists(service_name)


def stop_and_delete_service(service_name: str, retry_count: int = 3) -> bool:
    if not service_exists(service_name):
        return True
    stop_service(service_name)
    successful = False
    for _ in range(max(1, int(retry_count))):
        if delete_service(service_name):
            successful = True
            break
        time.sleep(0.3)
    if successful:
        return True
    return not service_exists(service_name)


def set_service_start_type(service_name: str, start_type: int) -> bool:
    if _winapi_available():
        try:
            if _change_service_start_type_winapi(service_name, start_type):
                return True
        except Exception:
            pass
    token = _START_TYPE_TOKEN.get(start_type)
    if token is None:
        return False
    result = _sc_run(["config", service_name, f"start={token}"])
    return result.returncode == 0


def set_service_demand_start(service_name: str) -> bool:
    if set_service_start_type(service_name, 3):
        return True
    return set_service_registry_start_type(service_name, 3)


def set_service_registry_start_type(service_name: str, start_type: int) -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _registry_services_key_path() + "\\" + service_name, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(start_type))
            return True
        finally:
            key.Close()
    except Exception:
        return False


def clear_service_delete_flag(service_name: str) -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _registry_services_key_path() + "\\" + service_name, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "DeleteFlag", 0, winreg.REG_DWORD, 0)
            return True
        finally:
            key.Close()
    except Exception:
        return False


def unload_driver(driver_name: str) -> bool:
    try:
        stop_service(driver_name)
        if delete_service(driver_name):
            return True
        return set_service_registry_start_type(driver_name, 3)
    except Exception:
        return False


def register_service(
    service_name: str,
    display_name: str,
    image_path: str,
    start_type: int = 3,
) -> bool:
    result = _sc_run(
        ["create", service_name, f"start={_START_TYPE_TOKEN.get(start_type, 'demand')}", f"binPath={image_path}", f"DisplayName={display_name}", "type=own"],
    )
    return result.returncode == 0 and "SUCCESS" in ((result.stdout or "").upper())


def cleanup_windivert_services() -> bool:
    names = ("WinDivert", "WinDivert14", "WinDivert64", "windivert", "Monkey")
    success = True
    for name in names:
        if not stop_and_delete_service(name, retry_count=2):
            success = False
    return success


def _parse_sc_query_all(text: str) -> List[Dict[str, object]]:
    services: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    for line in text.splitlines():
        if line.startswith("SERVICE_NAME"):
            if current is not None:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "state": None}
        elif current is not None and re.search(r"STATE\s*:\s*(\d+)", line):
            current["state"] = int(re.search(r"STATE\s*:\s*(\d+)", line).group(1))
    if current is not None:
        services.append(current)
    return services


def enumerate_services(pattern: Optional[str] = None) -> List[Dict[str, object]]:
    result = _sc_run(["query", "type=", "service", "state=", "all"], timeout=15.0)
    services = _parse_sc_query_all(result.stdout or "")
    if pattern:
        lowered = str(pattern).lower()
        services = [s for s in services if lowered in str(s.get("name") or "").lower()]
    for service in services:
        service["start_type"] = _registry_start_type(str(service.get("name") or ""))
    return services