# tools/windows_tools.py
"""Системные действия Windows: сброс сети, исключения Защитника, статус.

Часть действий требует прав администратора. Команды сбрасывают сеть (побочки
с DPI часто лечатся именно этим), аналогично "Internet cleanup" в ZapretGUI.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Dict, List

from config.paths import app_dir, exe_dir

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DEFAULT_TIMEOUT = 45


def _run_hidden(args: List[str], timeout: int = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=False,
        timeout=timeout,
        shell=False,
        creationflags=_NO_WINDOW,
    )


def admin_status() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _sid_in_token(sid_544: int) -> bool:
    """Прямое наличие S-1-5-32-544 в группах токена текущего процесса.

    CheckTokenMembership не засчитывает deny-only SID, а именно так в токене
    представлена группа «Администраторы» у неэлевированного админ-процесса
    (штатный фильтр UAC). Поэтому при отрицательном ответе проверяем сырой
    список групп через GetTokenInformation(TokenGroups).
    """
    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_ulong)]

    try:
        windll = ctypes.windll
        windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        windll.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        windll.advapi32.OpenProcessToken.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        windll.advapi32.OpenProcessToken.restype = ctypes.c_int
        windll.advapi32.GetTokenInformation.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong)]
        windll.advapi32.GetTokenInformation.restype = ctypes.c_int
        windll.advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        windll.advapi32.EqualSid.restype = ctypes.c_int
        TOKEN_QUERY = 0x0008
        TokenGroups = 2
        h = ctypes.c_void_p()
        if not windll.advapi32.OpenProcessToken(
                windll.kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h)):
            return False
        try:
            size = ctypes.c_ulong()
            windll.advapi32.GetTokenInformation(
                h, TokenGroups, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if not windll.advapi32.GetTokenInformation(
                    h, TokenGroups, ctypes.cast(buf, ctypes.c_void_p),
                    size.value, ctypes.byref(size)):
                return False
            offset = ctypes.sizeof(ctypes.c_size_t)
            count = int.from_bytes(buf.raw[:4], "little")
            stride = ctypes.sizeof(_SidAndAttributes)
            base = offset
            for i in range(count):
                raw = buf.raw[base + i * stride: base + (i + 1) * stride]
                psid = int.from_bytes(raw[: ctypes.sizeof(ctypes.c_size_t)], "little")
                if windll.advapi32.EqualSid(sid_544, psid):
                    return True
            return False
        finally:
            windll.kernel32.CloseHandle(h)
    except Exception:
        return False


def _admin_capable_for(membership: bool, sid_present: bool) -> bool:
    return membership or sid_present


def _admin_capable() -> bool:
    """Может ли текущий пользователь фактически получить админ-права (UAC).

    Пользователь считается способным, если группа BUILTIN\\Administrators
    (S-1-5-32-544) есть в токене процесса — в т.ч. как deny-only (фильтрованный
    UAC-токен обычного админа). Если группы нет, элевация ограничена чужим
    паролем. При ошибке проверки считаем "способен" (True), чтобы не
    блокировать UAC без необходимости.
    """
    if sys.platform != "win32":
        return True
    try:
        windll = ctypes.windll
        sid = ctypes.c_void_p()
        if not windll.advapi32.ConvertStringSidToSidW(
                ctypes.c_wchar_p("S-1-5-32-544"), ctypes.byref(sid)):
            return True
        try:
            is_member = ctypes.c_int()
            membership = bool(windll.advapi32.CheckTokenMembership(
                None, sid, ctypes.byref(is_member)) and is_member.value)
            return _admin_capable_for(membership, _sid_in_token(sid))
        finally:
            windll.kernel32.LocalFree(sid)
    except Exception:
        return True


def ensure_elevated(argv: List[str] | None = None) -> str:
    """Обеспечить запуск процесса от имени администратора (winws/WinDivert).

    Если процесс уже под админом (или ОС не Windows) — никак не трогает.
    Иначе перезапускает себя через UAC (`runas`) и возвращает:
      - "already" — права уже есть / нечего делать
      - "started" — UAC-перезапуск инициирован, текущий процесс должен выйти
      - "cancel"  — пользователь отклонил UAC (или ошибка) — можно жить без админа
      - "no"      — у пользователя нет прав на админ вообще: элевация невозможна
    """
    if sys.platform != "win32":
        return "already"
    if admin_status():
        return "already"
    if not _admin_capable():
        return "no"
    try:
        rest = sys.argv[1:] if argv is None else argv
        cmdline = subprocess.list2cmdline([sys.argv[0], *rest])
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, cmdline, os.getcwd(), 1
        )
    except Exception:
        return "cancel"
    if result <= 32:
        return "cancel"
    return "started"


def windivert_presence() -> Dict:
    """WinDivert: установленный драйвер в системе и/или драйвер в комплекте (exe/)."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system_driver = os.path.join(system_root, r"System32\drivers\WinDivert.sys")
    system_present = os.path.isfile(system_driver)
    engine = exe_dir()
    bundled_driver = ""
    driver_files = []
    engine_files = {}
    if engine is not None and engine.is_dir():
        for name in ("winws.exe", "winws2.exe"):
            engine_files[name] = (engine / name).is_file()
        for name in ("Monkey64.sys", "WinDivert.sys", "WinDivert64.sys", "aaaaaaaaa1"):
            p = engine / name
            if p.is_file():
                driver_files.append(name)
                bundled_driver = bundled_driver or str(p)
    return {
        "driver": {
            "present": system_present or bool(bundled_driver),
            "system": system_present,
            "bundled": bundled_driver,
            "files": driver_files,
            "path": system_driver if system_present else bundled_driver,
        },
        "engine": {"dir": str(engine) if engine else "", "files": engine_files},
        "admin": admin_status(),
    }


def windows_cleanup() -> Dict:
    """Комплексный сброс сети Windows (netsh + flush DNS)."""
    netsh = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\netsh.exe")
    commands = [
        ("winhttp_proxy", [netsh, "winhttp", "reset", "proxy"]),
        ("winsock", [netsh, "winsock", "reset"]),
        ("tcpip", [netsh, "int", "ip", "reset"]),
        ("ipv4", [netsh, "interface", "ipv4", "reset"]),
        ("ipv6", [netsh, "interface", "ipv6", "reset"]),
        ("dynamic_ports", [netsh, "int", "ipv4", "set", "dynamicport", "tcp", "start=10000", "num=30000"]),
    ]
    performed: List[str] = []
    failed: List[str] = []
    for key, args in commands:
        try:
            completed = _run_hidden(args)
        except Exception as exc:
            failed.append(f"{key}: {exc}")
            continue
        if completed.returncode == 0:
            performed.append(key)
        else:
            failed.append(f"{key}: код {completed.returncode}")
    # Очистка DNS-кэша
    try:
        from dns import flush_dns_cache
        flush_dns_cache()
        performed.append("flush_dns")
    except Exception:
        failed.append("flush_dns")

    if not failed:
        return {"ok": True, "level": "success", "performed": performed, "failed": []}
    if performed:
        return {"ok": True, "level": "warning", "performed": performed, "failed": failed}
    return {"ok": False, "level": "error", "performed": [], "failed": failed}


def defender_exclude(path: str = "") -> Dict:
    """Добавить папку приложения в исключения Windows Defender (нужны права админа)."""
    target = os.path.abspath(path or str(app_dir()))
    if not admin_status():
        return {"ok": False, "error": "admin_required", "path": target}
    ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                      r"System32\WindowsPowerShell\v1.0\powershell.exe")
    cmd = (
        "try { Add-MpPreference -ExclusionPath '" + target.replace("'", "''") +
        "' -ErrorAction Stop; 'OK' } catch { $_.Exception.Message }"
    )
    try:
        completed = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=60, creationflags=_NO_WINDOW,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc), "path": target}
    text = (completed.stdout + completed.stderr).strip()
    ok = completed.returncode == 0 and "OK" in text
    return {"ok": ok, "output": text[:300], "path": target}


def get_windows_tool_status() -> Dict:
    """Сводный статус для карточки «Windows tools»."""
    info = windivert_presence()
    try:
        from dns.check import get_system_dns_servers
        system_dns = get_system_dns_servers()
    except Exception:
        system_dns = []
    return {
        "admin": info["admin"],
        "admin_required": ["internet_cleanup", "defender_exclude"],
        "driver": info["driver"],
        "engine": info["engine"],
        "system_dns": system_dns,
        "app_dir": str(app_dir()),
    }