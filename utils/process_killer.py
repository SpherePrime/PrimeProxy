from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from typing import Dict, List, Optional

EXE_NAME_WINWS1 = "winws.exe"
EXE_NAME_WINWS2 = "winws2.exe"
ALL_WINWS_EXE_NAMES = (EXE_NAME_WINWS1, EXE_NAME_WINWS2)

_use_winapi = os.name == "nt" and hasattr(ctypes, "windll")

_OpenProcess = None
_TerminateProcess = None
_WaitForSingleObject = None
_CloseHandle = None
_GetExitCodeProcess = None

_PROCESS_TERMINATE = 0x0001
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000


if _use_winapi:
    _kernel32 = ctypes.windll.kernel32
    _OpenProcess = _kernel32.OpenProcess
    _TerminateProcess = _kernel32.TerminateProcess
    _WaitForSingleObject = _kernel32.WaitForSingleObject
    _CloseHandle = _kernel32.CloseHandle
    _GetExitCodeProcess = _kernel32.GetExitCodeProcess

    _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenProcess.restype = wintypes.HANDLE
    _TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _TerminateProcess.restype = wintypes.BOOL
    _WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _WaitForSingleObject.restype = wintypes.DWORD
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
    _GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _GetExitCodeProcess.restype = wintypes.BOOL


def get_process_pids(name: str) -> List[int]:
    try:
        from utils.windows_process_probe import get_process_ids_by_name
        return list(get_process_ids_by_name(name))
    except Exception:
        return []


def is_process_running(pid) -> bool:
    try:
        from utils.windows_process_probe import process_exists
        return bool(process_exists(pid))
    except Exception:
        return False


def kill_process_by_pid_winapi(pid, proc_name: Optional[str] = None, wait_timeout_ms: int = 3000) -> bool:
    if not _use_winapi or not _OpenProcess:
        return False
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    handle = _OpenProcess(_PROCESS_TERMINATE | _SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        if not _TerminateProcess(handle, 1):
            return False
        if _WaitForSingleObject(handle, max(0, wait_timeout_ms)) == _WAIT_OBJECT_0:
            return True
        return True
    finally:
        _CloseHandle(handle)


def kill_process_by_pid(pid) -> bool:
    try:
        return kill_process_by_pid_winapi(int(pid), wait_timeout_ms=3000)
    except Exception:
        return False


def kill_process_by_name(name: str, processes: Optional[List[Dict[str, object]]] = None) -> int:
    if processes is None:
        try:
            from utils.windows_process_probe import iter_process_records
            records = list(iter_process_records())
        except Exception:
            records = []
    else:
        records = list(processes)
    lowered = str(name).lower()
    killed = 0
    for record in records:
        rec_name = str(record.get("name") or record.get("exe") or "").lower()
        if rec_name != lowered:
            continue
        pid = record.get("pid")
        if pid is None:
            continue
        if kill_process_by_pid_winapi(int(pid), proc_name=name):
            killed += 1
    return killed


def kill_winws(process_name: str = EXE_NAME_WINWS1) -> int:
    return kill_process_by_name(process_name)


def kill_winws_all(restart: bool = False) -> int:
    total = 0
    for name in ALL_WINWS_EXE_NAMES:
        total += kill_winws(name)
    if restart:
        time.sleep(0.5)
    return total


def kill_winws_force() -> bool:
    try:
        total = kill_winws_all(restart=True)
        return total > 0
    except Exception:
        return False