from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Dict, Iterator, List, Optional

MAX_PATH = 260
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_use_winapi = os.name == "nt" and hasattr(ctypes, "windll")

_CreateToolhelp32Snapshot = None
_Process32FirstW = None
_Process32NextW = None
_Module32FirstW = None
_Module32NextW = None
_OpenProcess = None
_CloseHandle = None
_GetLastError = None


class _ProcessEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class _ModuleEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


if _use_winapi:
    _kernel32 = ctypes.windll.kernel32
    _CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
    _Process32FirstW = _kernel32.Process32FirstW
    _Process32NextW = _kernel32.Process32NextW
    _Module32FirstW = _kernel32.Module32FirstW
    _Module32NextW = _kernel32.Module32NextW
    _OpenProcess = _kernel32.OpenProcess
    _CloseHandle = _kernel32.CloseHandle
    _GetLastError = _kernel32.GetLastError

    _CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32)]
    _Process32FirstW.restype = wintypes.BOOL
    _Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32)]
    _Process32NextW.restype = wintypes.BOOL
    _Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ModuleEntry32)]
    _Module32FirstW.restype = wintypes.BOOL
    _Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ModuleEntry32)]
    _Module32NextW.restype = wintypes.BOOL
    _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenProcess.restype = wintypes.HANDLE
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL


def _initialized() -> bool:
    return bool(_use_winapi and _CreateToolhelp32Snapshot and _Process32FirstW and _Process32NextW)


def iter_process_records_winapi() -> Iterator[Dict[str, object]]:
    if not _initialized():
        return
    entry = _ProcessEntry32()
    entry.dwSize = ctypes.sizeof(_ProcessEntry32)
    snapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or snapshot is None:
        return
    try:
        ok = bool(_Process32FirstW(snapshot, ctypes.byref(entry)))
        while ok:
            yield {
                "pid": int(entry.th32ProcessID),
                "name": str(entry.szExeFile),
                "exe": str(entry.szExeFile),
            }
            ok = bool(_Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        _CloseHandle(snapshot)


def _iter_process_name_records_winapi() -> Iterator[Dict[str, object]]:
    try:
        for record in iter_process_records_winapi():
            yield {"pid": record.get("pid"), "name": record.get("name")}
    except Exception:
        return


def iter_process_records() -> List[Dict[str, object]]:
    return list(iter_process_records_winapi())


_iter_process_records_winapi = iter_process_records_winapi


def get_processes_by_name(name: str) -> List[Dict[str, object]]:
    lowered = str(name).lower()
    return [r for r in iter_process_records_winapi() if str(r.get("name") or "").lower() == lowered]


def get_process_ids_by_name(name: str) -> List[int]:
    return [int(r["pid"]) for r in get_processes_by_name(name)]


def process_exists(pid) -> bool:
    if not _use_winapi or not _OpenProcess:
        return False
    handle = _OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    _CloseHandle(handle)
    return True


def get_process_name(pid) -> Optional[str]:
    for record in iter_process_records_winapi():
        if int(record["pid"]) == int(pid):
            return str(record["name"])
    return None


def iter_process_module_paths(pid: int) -> Iterator[str]:
    if not _initialized():
        return
    entry = _ModuleEntry32()
    entry.dwSize = ctypes.sizeof(_ModuleEntry32)
    snapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, int(pid))
    if snapshot == INVALID_HANDLE_VALUE or snapshot is None:
        return
    try:
        ok = bool(_Module32FirstW(snapshot, ctypes.byref(entry)))
        while ok:
            yield str(entry.szExePath)
            ok = bool(_Module32NextW(snapshot, ctypes.byref(entry)))
    finally:
        _CloseHandle(snapshot)


def _iter_process_module_paths_winapi(buffer_size: int = 1048576, **kwargs) -> Iterator[Dict[str, object]]:
    for record in iter_process_records_winapi():
        pid = int(record["pid"])
        try:
            for path in iter_process_module_paths(pid):
                yield {"pid": pid, "name": record.get("name"), "module_path": path}
        except Exception:
            continue