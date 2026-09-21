from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ._log import log

try:
    import winreg
except ImportError:
    winreg = None

_KNOWN_WINDIVERT_DRIVERS: Tuple[str, ...] = (
    "WinDivert",
    "WinDivert14",
    "WinDivert64",
    "Monkey",
)

_KNOWN_WINDIVERT_SERVICES: Tuple[str, ...] = (
    "WinDivert",
    "WinDivert14",
    "WinDivert64",
    "windivert",
    "Monkey",
)

_KNOWN_DRIVER_LOAD_ORDER: Tuple[str, ...] = (
    "Monkey",
    "WinDivert",
    "WinDivert14",
    "WinDivert64",
    "windivert",
)

_EXE_NAME_WINWS1 = "winws.exe"
_EXE_NAME_WINWS2 = "winws2.exe"
_ALL_WINWS_EXE_NAMES: Tuple[str, ...] = (_EXE_NAME_WINWS1, _EXE_NAME_WINWS2)

_SERVICE_DISABLED = 0x00000004
_SERVICE_DEMAND_START = 0x00000003
_SERVICE_WIN32_OWN_PROCESS = 0x00000010
_SERVICE_ERROR_NORMAL = 0x00000001

ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_SERVICE_DISABLED = 1058


@dataclass
class WinDivertRuntimeProbeResult:
    ready: bool
    installed: bool
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    wait_for_recovery_after_cleanup: bool = False
    stage: Optional[str] = None
    state: Optional[int] = None
    driver_ver: Optional[str] = None
    dll_ver: Optional[str] = None
    dyndriver_dll_exists: bool = False
    dyndriver_dll_path: Optional[str] = None
    dyn_driver_required: bool = False
    driver_path: Optional[str] = None
    installed_service_names: Tuple[str, ...] = ()
    installed_driver_names: Tuple[str, ...] = ()
    found_foreign_windivert_service_paths: Tuple[str, ...] = ()
    no_filter_arp_driver: bool = False
    is_ably_ready: bool = False
    special: Optional[str] = None
    verdict: Optional[str] = None


def _engine_dir_safe() -> Optional[str]:
    try:
        from winws.paths import engine_dir
        folder = engine_dir()
        if folder is None:
            return None
        return str(folder)
    except Exception:
        return None


def _iter_windivert_dll_candidates_runtime() -> List[str]:
    candidates: List[str] = []
    folder = _engine_dir_safe()
    if folder:
        candidates.append(os.path.join(folder, "WinDivert.dll"))
    system_root = os.environ.get("SystemRoot")
    if system_root:
        candidates.append(os.path.join(system_root, "System32", "WinDivert.dll"))
    return candidates


def _get_windivert_service_states() -> Dict[str, Dict[str, object]]:
    if os.name != "nt":
        return {}
    states: Dict[str, Dict[str, object]] = {}
    if winreg is None:
        return states
    for name in _KNOWN_WINDIVERT_SERVICES:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}")
        except OSError:
            continue
        try:
            start = _read_dword(key, "Start")
            image_path = _read_str(key, "ImagePath")
            delete_flag = _read_dword(key, "DeleteFlag")
            states[name] = {"start": start, "image_path": image_path, "delete_flag": delete_flag}
        finally:
            try:
                key.Close()
            except OSError:
                pass
    return states


def _read_dword(key, name):
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return int(value)
    except Exception:
        return None


def _read_str(key, name):
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value)
    except Exception:
        return None


def _image_path_target(image_path: Optional[str]) -> Optional[str]:
    if not image_path:
        return None
    path = str(image_path)
    path = path.replace("\\SystemRoot\\", os.environ.get("SystemRoot", r"C:\Windows") + "\\")
    path = path.replace("System32\\drivers\\", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers") + "\\", 1)
    path = path.replace("??\\", "")
    path = os.path.expandvars(path)
    return path


def probe_windivert_state_runtime(
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
    timeout_ms: int = 30000,
    search_verdict: Optional[str] = None,
    include_install_actions: bool = False,
    log_enabled: bool = True,
) -> WinDivertRuntimeProbeResult:
    """Недиструктивная проба готовности WinDivert по драйверу/службе/библиотеке."""
    states = _get_windivert_service_states()
    dll_candidates = _iter_windivert_dll_candidates_runtime()
    dll_found = [p for p in dll_candidates if os.path.isfile(p)]

    installed_service_names = tuple(states.keys())
    installed_driver_names = tuple(
        name for name, st in states.items() if st.get("image_path")
    )
    driver_path = None
    for st in states.values():
        if st.get("image_path"):
            driver_path = _image_path_target(st.get("image_path"))
            break

    href = list(states.values())
    marked = any(bool(st.get("delete_flag")) for st in href)
    disabled = any(st.get("start") == _SERVICE_DISABLED for st in href)
    required_driver_ok = bool(driver_path) or os.path.isfile(driver_path) if driver_path else False

    installed = bool(installed_service_names) or bool(dll_found)
    ready = False
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    wait_for_recovery_after_cleanup = False
    special: Optional[str] = None

    if not installed:
        error_code = 1060
        error_message = "Служба WinDivert не установлена или драйвер не найден"
        stage = "ready"
        result = WinDivertRuntimeProbeResult(
            ready=False, installed=False, error_code=error_code, error_message=error_message,
            wait_for_recovery_after_cleanup=False, stage=stage,
            installed_service_names=installed_service_names,
            installed_driver_names=installed_driver_names,
            driver_path=driver_path,
        )
        if log_enabled:
            log.info(f"WinDivert: не установлен (код {error_code})")
        return result

    if marked:
        error_code = ERROR_SERVICE_MARKED_FOR_DELETE
        error_message = "Служба WinDivert помечена на удаление"
        special = "delete-pending"
        ready = False
        wait_for_recovery_after_cleanup = True
    elif disabled:
        error_code = ERROR_SERVICE_DISABLED
        error_message = "Служба WinDivert отключена"
        ready = False
    elif not dll_found:
        error_code = 161
        error_message = "Библиотека WinDivert.dll не найдена"
        ready = False
    else:
        ready = True
        error_code = None
        error_message = None

    verdict = "готов" if ready else f"ошибка {error_code}"
    result = WinDivertRuntimeProbeResult(
        ready=ready, installed=installed, error_code=error_code, error_message=error_message,
        wait_for_recovery_after_cleanup=wait_for_recovery_after_cleanup, stage="ready",
        state=next((st.get("start") for st in href if st.get("start") is not None), None),
        driver_path=driver_path,
        installed_service_names=installed_service_names,
        installed_driver_names=installed_driver_names,
        special=special,
        verdict=verdict,
    )
    if log_enabled:
        if ready:
            log.info("WinDivert готов")
        elif error_code is not None:
            log.warn(f"WinDivert: {error_message} (код {error_code})")
    return result


def wait_for_windivert_spawn_ready_runtime(
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
    timeout_ms: int = 60000,
    search_verdict: Optional[str] = None,
    wait_between_attempts_ms: int = 300,
) -> WinDivertRuntimeProbeResult:
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    while True:
        probe = probe_windivert_state_runtime(
            exe_path=exe_path, preferred_driver_dir=preferred_driver_dir,
            executable_args=executable_args, search_verdict=search_verdict,
        )
        if probe.ready:
            return probe
        if not probe.installed:
            if time.monotonic() >= deadline:
                return probe
            time.sleep(wait_between_attempts_ms / 1000.0)
            continue
        return probe


def _is_transient_recovery(error_code: Optional[int]) -> bool:
    if error_code is None:
        return True
    try:
        from .windivert_diagnostics import WINDIVERT_ERROR_TABLE
        entry = WINDIVERT_ERROR_TABLE.get(int(error_code))
        if entry:
            return bool(entry["transient"])
    except Exception:
        pass
    return True


def retry_windivert_spawn_readiness_after_recovery(
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
    search_verdict: Optional[str] = None,
    readier: Optional[str] = None,
    wait_between_attempts_ms: int = 500,
    wait_after_cleanup_ms: int = 2500,
    timeout_ms: int = 45000,
) -> Tuple[bool, WinDivertRuntimeProbeResult]:
    probe = probe_windivert_state_runtime(
        exe_path=exe_path, preferred_driver_dir=preferred_driver_dir,
        executable_args=executable_args, search_verdict=search_verdict,
    )
    if probe.ready:
        return True, probe
    if not _is_transient_recovery(probe.error_code):
        return False, probe
    if readier:
        try:
            readier(probe)
        except Exception as exc:
            log.warn(f"Процедура восстановления не выполнена: {exc}")
    time.sleep(wait_after_cleanup_ms / 1000.0)
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    fresh = probe
    while time.monotonic() < deadline:
        fresh = probe_windivert_state_runtime(
            exe_path=exe_path, preferred_driver_dir=preferred_driver_dir,
            executable_args=executable_args, search_verdict=search_verdict,
        )
        if fresh.ready:
            return True, fresh
        time.sleep(wait_between_attempts_ms / 1000.0)
    return False, fresh


def probe_windivert_state_error_code_runtime(**kwargs) -> Optional[int]:
    return probe_windivert_state_runtime(**kwargs).error_code


def force_kill_all_winws_processes() -> bool:
    try:
        from utils.process_killer import kill_winws_force
        return bool(kill_winws_force())
    except Exception as exc:
        log.warn(f"Не удалось принудительно завершить winws: {exc}")
        return False


def kill_process_by_pid_runtime(pid, *, wait_timeout_ms: int = 3000) -> bool:
    try:
        from utils.process_killer import kill_process_by_pid_winapi
        return bool(kill_process_by_pid_winapi(int(pid), wait_timeout_ms=wait_timeout_ms))
    except Exception:
        return False


def get_process_pids_by_name(name: str) -> List[int]:
    try:
        from utils.process_killer import get_process_pids
        return list(get_process_pids(name))
    except Exception:
        return []


def get_all_winws_process_pids() -> List[int]:
    pids: List[int] = []
    for exe in _ALL_WINWS_EXE_NAMES:
        pids.extend(get_process_pids_by_name(exe))
    return sorted(set(pids))


def has_any_winws_process() -> bool:
    return bool(get_all_winws_process_pids())


def find_windivert_holder_processes_runtime(dll_basename: str = "windivert.dll") -> List[Dict[str, str]]:
    holders: List[Dict[str, str]] = []
    try:
        from utils.windows_process_probe import _iter_process_module_paths_winapi
        for record in _iter_process_module_paths_winapi(buffer_size=1048576):
            pid = record.get("pid")
            name = record.get("name")
            module_path = record.get("module_path")
            if not module_path or not pid:
                continue
            if dll_basename in str(module_path).lower():
                holders.append({
                    "pid": str(pid),
                    "name": str(name or "?") if name else "?",
                    "module_path": str(module_path),
                })
    except Exception as exc:
        log.warn(f"Сканирование модулей процессов недоступно: {exc}")
    return holders


def _own_windivert_partitions() -> List[str]:
    partitions: List[str] = []
    for candidate in _iter_windivert_dll_candidates_runtime():
        if candidate:
            partitions.append(os.path.splitdrive(candidate)[0].lower())
    folder = _engine_dir_safe()
    if folder:
        partitions.append(os.path.splitdrive(folder)[0].lower())
    return sorted(set(p for p in partitions if p))


def find_foreign_windivert_service_paths_runtime() -> List[str]:
    foreign: List[str] = []
    states = _get_windivert_service_states()
    own = _own_windivert_partitions()
    drivers_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers").lower()
    for name, st in states.items():
        image = str(st.get("image_path") or "").lower()
        if not image:
            continue
        target = _image_path_target(image).lower()
        if target and os.path.isfile(target):
            continue
        if "systemroot" in image or "system32" in image or image.startswith(drivers_dir):
            continue
        if own and any(image.startswith(part) for part in own):
            continue
        foreign.append(image)
    return foreign


def find_stale_windivert_delete_pending_services_runtime() -> List[str]:
    stale: List[str] = []
    states = _get_windivert_service_states()
    for name, st in states.items():
        if st.get("delete_flag"):
            stale.append(name)
    return stale


def _set_service_start_registry(name: str, start: int) -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}", 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, start)
            return True
        finally:
            key.Close()
    except Exception as exc:
        log.warn(f"Не удалось изменить тип запуска службы {name}: {exc}")
        return False


def restore_known_windivert_services_demand_start_runtime() -> List[str]:
    restored: List[str] = []
    states = _get_windivert_service_states()
    for name, st in states.items():
        if st.get("start") == _SERVICE_DISABLED:
            if _set_service_start_registry(name, _SERVICE_DEMAND_START):
                restored.append(name)
    return restored


def _stop_and_delete_known_runtime_services(services) -> None:
    for name in services:
        try:
            from utils.service_manager import stop_and_delete_service
            stop_and_delete_service(name, retry_count=2)
        except Exception as exc:
            log.warn(f"Очистка службы {name} не выполнена: {exc}")


def wait_for_windivert_cleanup_settle_runtime(
    attempts: int = 3,
    wait_between_attempts_ms: int = 5000,
) -> None:
    for _ in range(attempts):
        time.sleep(wait_between_attempts_ms / 1000.0)


def unload_known_windivert_drivers_runtime() -> List[str]:
    unloaded: List[str] = []
    for name in _KNOWN_DRIVER_LOAD_ORDER:
        try:
            from utils.service_manager import unload_driver
            if unload_driver(name):
                unloaded.append(name)
        except Exception as exc:
            log.warn(f"Выгрузка драйвера {name} не выполнена: {exc}")
    return unloaded


def standard_windivert_cleanup_runtime(
    allow_reboot: bool = False,
    log_enabled: bool = True,
    sfc_notices: bool = False,
    force: bool = False,
    post_cleanup_sleep_ms: int = 1200,
    attempt_cleanup_pending: bool = True,
) -> bool:
    if log_enabled:
        log.info("Стандартная очистка WinDivert")
    try:
        force_kill_all_winws_processes()
        restored = restore_known_windivert_services_demand_start_runtime()
        if log_enabled and restored:
            log.info(f"Службы WinDivert переведены в ручной тип запуска: {', '.join(restored)}")
        if attempt_cleanup_pending:
            stale = find_stale_windivert_delete_pending_services_runtime()
            if stale:
                _stop_and_delete_known_runtime_services(stale)
        if post_cleanup_sleep_ms > 0:
            time.sleep(post_cleanup_sleep_ms / 1000.0)
        return True
    except Exception as exc:
        if log_enabled:
            log.error(f"Стандартная очистка WinDivert не выполнена: {exc}")
        return False


def aggressive_windivert_cleanup_runtime(
    allow_reboot: bool = False,
    log_enabled: bool = True,
    sfc_notices: bool = False,
) -> bool:
    if log_enabled:
        log.info("Агрессивная очистка WinDivert")
    try:
        from .antivirus_probe import _is_kaspersky_present_safe
        if _is_kaspersky_present_safe():
            if log_enabled:
                log.warn("Агрессивная очистка пропущена: активен Kaspersky (должен быть вручную выключен)")
            return False
        force_kill_all_winws_processes()
        wait_for_windivert_cleanup_settle_runtime()
        unload_known_windivert_drivers_runtime()
        _stop_and_delete_known_runtime_services(_KNOWN_WINDIVERT_SERVICES)
        return True
    except Exception as exc:
        if log_enabled:
            log.error(f"Агрессивная очистка WinDivert не выполнена: {exc}")
        return False


cleanup_windivert_services_runtime = _stop_and_delete_known_runtime_services


# Совместимые имена без суффикса _runtime (используются UI/API).
probe_windivert_state = probe_windivert_state_runtime
wait_for_windivert_spawn_ready = wait_for_windivert_spawn_ready_runtime
standard_windivert_cleanup = standard_windivert_cleanup_runtime
aggressive_windivert_cleanup = aggressive_windivert_cleanup_runtime
wait_for_windivert_cleanup_settle = wait_for_windivert_cleanup_settle_runtime
force_kill_all_winws = force_kill_all_winws_processes
find_stale_windivert_delete_pending_services = find_stale_windivert_delete_pending_services_runtime
restore_known_windivert_services_demand_start = restore_known_windivert_services_demand_start_runtime
find_windivert_holder_processes = find_windivert_holder_processes_runtime
find_foreign_windivert_service_paths = find_foreign_windivert_service_paths_runtime
unload_known_windivert_drivers = unload_known_windivert_drivers_runtime
stop_and_delete_named_service = None

_KNOWN_WINDIVERT_SERVICE_NAMES = _KNOWN_WINDIVERT_SERVICES