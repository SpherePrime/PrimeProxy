from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from ._log import log
from .windivert_diagnostics import (
    ERROR_SERVICE_DISABLED,
    ERROR_SERVICE_MARKED_FOR_DELETE,
    FWP_E_IN_USE,
    WINDIVERT_ERROR_TABLE,
    describe_windivert_error,
    format_windows_error_code,
)

_STAGE_READY = "ready"
_STAGE_SPAWN = "spawn"
_STAGE_EXECUTION = "execution"

_win32_error_pairs = {
    6: "invalid handle",
    34: 1058,
    87: 87,
    122: 122,
    161: 161,
    999: 999,
    1008: 577,
    1009: 1058,
    1058: 1058,
    1060: 1060,
    1068: 1068,
    1072: 1072,
    1067: 1067,
    1722: 1722,
    1753: 1753,
    225: 225,
    238: 238,
    1222: 1222,
}

_win32_error_textual = {
    "access is denied": 5,
    "отказано в доступе": 5,
    "ошибка 5": 5,
    "error 5": 5,
    "net err": 5,
    "the handle is invalid": 6,
    "неверный дескриптор": 6,
    "the device is not ready": 21,
    "the device attached to the system is not functioning": 31,
    "a device attached to the system is not functioning": 31,
    "система не может найти указанный файл": 2,
    "the parameter is incorrect": 87,
    "неверный параметр": 87,
    "the service does not exist": 1060,
    "служба не существует": 1060,
    "the specified service does not exist": 1060,
    "service does not exist": 1060,
    "the service cannot be started": 1058,
    "служба не может быть запущена": 1058,
    "cannot be started": 1058,
    "the dependency service does not exist": 1068,
    "dependency service": 1068,
    "зависимая служба": 1068,
    "the service has marked for deletion": 1072,
    "marked for deletion": 1072,
    "помечена на удаление": 1072,
    "the rpc server is unavailable": 1722,
    "rpc server": 1722,
    "rpc": 1722,
    "the specified module could not be found": 126,
    "модуль не найден": 126,
    "windivert: handle is in use": FWP_E_IN_USE,
    "windivert handle is in use": FWP_E_IN_USE,
    "unable to load the specified module": 126,
    "ошибка (код 5)": 5,
    "error (code 5)": 5,
}

_last_diag_context: Dict[str, Optional[object]] = {}


def _first_relevant_output_line(lines: List[str]) -> Optional[str]:
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("<<"):
            continue
        return stripped
    return None


def _is_empty_output(output: Optional[str]) -> bool:
    return not output or len(str(output).strip()) == 0


def _split_output_lines(output: Optional[str]) -> List[str]:
    return str(output).splitlines()


def _detect_error_code_from_line(line: Optional[str]) -> Optional[int]:
    if not line:
        return None
    code_re = re.search(r"(?:код|code)\s*[\s:=]*(\d+)", line, re.IGNORECASE)
    win_re = re.search(r"(?:win32|windows)\s*(?:error|ошибка)?\s*[:\s=]*(\d+)", line, re.IGNORECASE)
    if code_re and win_re:
        code, win = int(code_re.group(1)), int(win_re.group(1))
        return win if code != win else code
    if code_re:
        return int(code_re.group(1))
    if win_re:
        return int(win_re.group(1))
    lowered = line.lower()
    for marker, value in _win32_error_textual.items():
        if marker in lowered:
            return value
    return None


def _iter_relevant_lines(lines: List[str]):
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("<<"):
            continue
        yield stripped


def _find_windivert_warning_line(lines: List[str]) -> Optional[str]:
    for line in lines:
        lowered = line.lower()
        if "windivert" in lowered and any(tok in lowered for tok in ("warn", "warning", "предупрежд")):
            return line.strip()
    return None


def _analyze_win_hex_error(line: Optional[str]) -> Optional[int]:
    if not line:
        return None
    match = re.search(r"0x[0-9a-fA-F]{8}", line)
    if match:
        value = int(match.group(0), 16)
        if value > 0x7FFFFFFF:
            return value
    return None


def _probe_service_disabled_cause(
    win32_error: int,
    hint_operator_version: Optional[str] = None,
    stderr: str = "",
) -> Optional[str]:
    findings: List[str] = []
    missing_files = _check_windivert_files()
    if missing_files:
        findings.append("не найдены файлы драйвера: " + ", ".join(missing_files))
    if not _check_bfe_service():
        findings.append("служба BFE (Base Filtering Engine) не запущена")
    disabled_service = _find_disabled_windivert_driver_service()
    if disabled_service:
        findings.append(f"служба отключена: {disabled_service}")
    if not _check_network_adapters():
        findings.append("нет подключённых сетевых адаптеров")
    if not _check_secure_boot():
        findings.append("Secure Boot может блокировать драйвер WinDivert")
    try:
        from .antivirus_detection import _detect_active_antivirus
        antivirus = _detect_active_antivirus()
        if antivirus and antivirus != "Microsoft Defender":
            findings.append(f"активный антивирус {antivirus} может блокировать драйвер")
    except Exception:
        pass
    return "; ".join(findings) if findings else None


def _check_windivert_files() -> List[str]:
    missing: List[str] = []
    folder = _engine_dir_of_interest()
    driver_candidates = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    for name in ("Monkey64.sys", "WinDivert64.sys"):
        driver_candidates.append(os.path.join(system_root, "System32", "drivers", name))
        if folder:
            driver_candidates.append(os.path.join(folder, name))
    if folder and not os.path.isfile(os.path.join(folder, "WinDivert.dll")):
        missing.append("WinDivert.dll")
    if not any(os.path.isfile(p) for p in driver_candidates):
        missing.append("Monkey64.sys/WinDivert64.sys")
    return missing


def _engine_dir_of_interest() -> Optional[str]:
    try:
        from winws.paths import engine_dir
        folder = engine_dir()
        return None if folder is None else str(folder)
    except Exception:
        return None


def _check_bfe_service() -> bool:
    try:
        from utils.service_manager import get_service_state
        return get_service_state("BFE") == 4
    except Exception:
        return True


def _find_disabled_windivert_driver_service() -> Optional[str]:
    try:
        from .system_ops import _SERVICE_DISABLED, _get_windivert_service_states
        states = _get_windivert_service_states()
        for name, st in states.items():
            if st.get("start") == _SERVICE_DISABLED:
                image = str(st.get("image_path") or "").lower()
                if "monkey" in image or "windivert" in image:
                    return name
    except Exception:
        pass
    return None


def _check_network_adapters() -> bool:
    try:
        from dns.check import _windows_connected_adapters
        return bool(_windows_connected_adapters())
    except Exception:
        return True


def _check_secure_boot() -> bool:
    if os.name != "nt":
        return True
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State")
        try:
            value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            return int(value) != 1
        finally:
            key.Close()
    except OSError:
        return True
    except Exception:
        return True


def _base_diagnosis(
    cause: str,
    *,
    building: int = 1,
    solution: Optional[str] = None,
    auto_fix: Optional[str] = None,
    win32_error: Optional[int] = None,
    stage: str = _STAGE_READY,
    next_steps: Optional[List[str]] = None,
    emphasized: bool = True,
    confirmation: Optional[str] = None,
    is_unexpected_exit: bool = False,
    hint_kind: Optional[str] = None,
    wait_for_recovery_after_cleanup: bool = False,
) -> Dict[str, object]:
    return {
        "cause": cause,
        "building": building,
        "solution": solution or "",
        "auto_fix": auto_fix or "",
        "win32_error": win32_error,
        "stage": stage,
        "next_steps": next_steps or [],
        "emphasized": emphasized,
        "confirmation": confirmation or "",
        "is_unexpected_exit": is_unexpected_exit,
        "hint_kind": hint_kind,
        "wait_for_recovery_after_cleanup": wait_for_recovery_after_cleanup,
    }


def _handle_install_failure_46(win32_error: Optional[int], kick_driver_verdict: Optional[str]) -> Optional[Dict[str, object]]:
    if win32_error != 46:
        return None
    return _base_diagnosis(
        "Ошибка установки драйвера WinDivert",
        solution=(
            "Убедись, что виртуализация Hyper-V не блокирует установку, и очисти WinDivert стандартной очисткой."
        ),
        win32_error=win32_error,
        auto_fix="Очистка WinDivert (standard)",
    )


def _handle_access_denied(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error not in (5, 34):
        return None
    is_admin = False
    try:
        import ctypes
        if hasattr(ctypes, "windll"):
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    cause = "Отказано в доступе при запуске winws"
    if not is_admin:
        cause = "winws запущен без прав администратора (доступ к драйверу WinDivert запрещён)"
        solution = "Запусти Zapat (или winws) от имени администратора."
    else:
        solution = "Антивирус или защитник может блокировать доступ. Запусти от имени администратора и проверь исключения."
    return _base_diagnosis(
        cause,
        solution=solution,
        auto_fix="Перезапуск с правами администратора",
        win32_error=win32_error,
    )


def _handle_device_in_use(win32_error: Optional[int], holder_processes: List[str]) -> Optional[Dict[str, object]]:
    if win32_error != 31:
        return None
    if holder_processes:
        names = ", ".join(holder_processes[:3])
        cause = f"Сетевое устройство занято драйвером WinDivert (используется процессами: {names})"
    else:
        cause = "Сетевое устройство занято — драйвер WinDivert перехвачен другой программой"
    return _base_diagnosis(
        cause,
        solution="Закрой конфликтующие программы с сетевыми фильтрами (GoodbyeDPI и т.п.).",
        auto_fix="Автоматически закрыть конфликтующие процессы",
        win32_error=win32_error,
    )


def _handle_old_version(win32_error: Optional[int], kick_driver_verdict: Optional[str]) -> Optional[Dict[str, object]]:
    if win32_error != 577:
        return None
    return _base_diagnosis(
        "Устаревшая или повреждённая версия драйвера WinDivert",
        solution="Выполни агрессивную очистку WinDivert и переустанови драйвер.",
        auto_fix="Агрессивная очистка WinDivert",
        win32_error=win32_error,
    )


def _handle_service_not_found(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error not in (1060,):
        return None
    return _base_diagnosis(
        "Служба WinDivert не существует, однако загрузка продолжается (нединамический режим)",
        solution="Если winws работает — ошибку можно игнорировать.",
        win32_error=win32_error,
        is_unexpected_exit=True,
    )


def _handle_service_disabled(win32_error: Optional[int], stderr: str = "", hint_operator_version: Optional[str] = None) -> Optional[Dict[str, object]]:
    if win32_error not in (ERROR_SERVICE_DISABLED,):
        return None
    base = WINDIVERT_ERROR_TABLE.get(ERROR_SERVICE_DISABLED, {})
    refiner = _probe_service_disabled_cause(win32_error, hint_operator_version, stderr)
    cause = "Служба WinDivert отключена — " + str(base.get("cause") or "WinDivert не может быть запущен")
    if refiner:
        cause = f"{cause}. Установлено: {refiner}"
    return _base_diagnosis(
        cause,
        solution=str(base.get("solution") or ""),
        auto_fix=str(base.get("auto_fix") or "Автоматически включить службу WinDivert"),
        win32_error=win32_error,
    )


def _handle_dependency_fail(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error not in (1068, 1058):
        return None
    if win32_error == 1058:
        return None
    return _base_diagnosis(
        "Не запущена зависимая служба WinDivert (обычно BFE)",
        solution="Проверь службу BFE (Base Filtering Engine) и запусти её.",
        auto_fix="Автоматически запустить BFE",
        win32_error=win32_error,
    )


def _handle_invalid_parameter(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error != 87:
        return None
    return _base_diagnosis(
        "Служба WinDivert нарушена (конфликт разрядностей) — драйвер несовместим с системой",
        solution="Очисти WinDivert стандартной очисткой и переустанови драйвер из корректной сборки.",
        auto_fix="Очистка WinDivert (standard)",
        win32_error=win32_error,
    )


def _handle_device_not_found(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error != 433:
        return None
    return _base_diagnosis(
        "WinDivert не может получить доступ к сетевому стеку — сетевое устройство не найдено",
        solution="Убедись, что драйвер зарегистрирован, и проверь Hyper-V/сторонние сетевые стеки.",
        auto_fix="Автоматически переконфигурировать драйвер",
        win32_error=win32_error,
    )


def _handle_marked_for_delete(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error not in (ERROR_SERVICE_MARKED_FOR_DELETE,):
        return None
    return _base_diagnosis(
        "Служба WinDivert помечена на удаление, но ещё не удалена полностью",
        solution="Выполни агрессивную очистку WinDivert.",
        auto_fix="[agressive cleanup]",
        win32_error=win32_error,
        wait_for_recovery_after_cleanup=True,
    )


def _handle_no_such_interface(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    unreachable = _check_network_adapters()
    if win32_error != 1222 or not unreachable:
        return None
    return _base_diagnosis(
        "Нет интерфейса сетевого адаптера (возможно, все сетевые адаптеры отключены)",
        solution="Подключи сетевой адаптер и повтори запуск.",
        win32_error=win32_error,
    )


def _handle_server_unavailable(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error not in (1722, 1753):
        return None
    return _base_diagnosis(
        "Служба WinDivert ещё не зарегистрирована (RPC)", 
        solution="Подожди несколько секунд и перезапусти winws.",
        auto_fix="Автоматическая чистка и перезапуск",
        win32_error=win32_error,
    )


def _handle_fwp_in_use(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error != FWP_E_IN_USE:
        return None
    return _base_diagnosis(
        "WinDivert переведён в состояние «Используется» (диагностическая ошибка)",
        solution="Если winws работает — игнорируй.",
        auto_fix="Автоматически закрыть конфликтующие процессы",
        win32_error=win32_error,
        is_unexpected_exit=True,
    )


def _handle_exited_0(exit_code: Optional[int]) -> Optional[Dict[str, object]]:
    if (exit_code or 0) != 0:
        return None
    return _base_diagnosis(
        "winws завершился с кодом 0 (успешный выход)",
        solution="Обычно означает штатное завершение. Дополнительная диагностика не требуется.",
        win32_error=None,
        emphasized=False,
    )


def _handle_dev_io_error(win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error != 238:
        return None
    return _base_diagnosis(
        "Драйвер WinDivert вернул ошибку ввода-вывода (несовместимость/сброс стека)",
        solution="Проверь режим адаптера и стабильность сетевого стека; рассмотри агрессивную очистку.",
        auto_fix="Агрессивная очистка WinDivert",
        win32_error=win32_error,
    )


def _fallback_diagnosis(exit_code: int, win32_error: Optional[int]) -> Optional[Dict[str, object]]:
    if win32_error and win32_error in _win32_error_pairs:
        entry = WINDIVERT_ERROR_TABLE.get(win32_error)
        if entry:
            return _base_diagnosis(
                str(entry["cause"]),
                solution=str(entry["solution"]),
                auto_fix=(entry.get("auto_fix") or ""),
                win32_error=win32_error,
            )
    return _base_diagnosis(
        f"Неизвестная ошибка winws (код {exit_code})",
        solution="Проверь журнал winws и попробуй перезапустить.",
        win32_error=win32_error,
    )


def _adjust_deprecated_winws(exit_code: int, win32_error: Optional[int]) -> Tuple[int, Optional[int], Optional[str]]:
    if win32_error == 1058 and (exit_code in (34, 1009)):
        return exit_code, 1058, None
    return exit_code, win32_error, None


def _wrap_diagnosis(entry: Dict[str, object], exit_code: int) -> Dict[str, object]:
    return entry


def _found_suspect_windivert_service_image() -> Optional[str]:
    driver_name = None
    try:
        from .system_ops import _get_windivert_service_states
        states = _get_windivert_service_states()
        for name, st in states.items():
            image = str(st.get("image_path") or "").lower()
            if "windivert" in image or "monkey" in image:
                driver_name = name
                break
    except Exception:
        pass
    return driver_name


def diagnose_winws_exit(
    exit_code: int,
    output: Optional[str] = None,
    *,
    hint_operator_version: Optional[str] = None,
    hint_auto_clean: bool = False,
) -> Optional[Dict[str, object]]:
    if exit_code is None:
        return None
    if int(exit_code) == 0:
        return None
    lines = _split_output_lines(output)
    relevant_line = _first_relevant_output_line(lines)
    inferred = _detect_error_code_from_line(relevant_line) or _analyze_win_hex_error(relevant_line)
    win32_error = inferred if inferred is not None else int(exit_code)
    if win32_error not in _win32_error_pairs and int(exit_code) not in _win32_error_pairs:
        win32_error = win32_error or int(exit_code)
    stderr = relevant_line or (output or "")

    if int(exit_code) == 46:
        handler = _handle_install_failure_46
    elif win32_error in (5, 34):
        handler = _handle_access_denied
    elif win32_error == 31:
        holder_processes: List[str] = []
        try:
            from .system_ops import find_windivert_holder_processes_runtime
            holder_processes = [p.get("name", "?") for p in find_windivert_holder_processes_runtime()][:3]
        except Exception:
            pass
        return _handle_device_in_use(win32_error, holder_processes)
    elif win32_error == 577:
        handler = _handle_old_version
    elif win32_error == 1060:
        handler = _handle_service_not_found
    elif win32_error == ERROR_SERVICE_DISABLED:
        handler = lambda e, s=stderr, v=hint_operator_version: _handle_service_disabled(e, s, v)
    elif win32_error == 1068:
        handler = _handle_dependency_fail
    elif win32_error == 87:
        handler = _handle_invalid_parameter
    elif win32_error == 433:
        handler = _handle_device_not_found
    elif win32_error == ERROR_SERVICE_MARKED_FOR_DELETE:
        handler = _handle_marked_for_delete
    elif win32_error == 1222:
        handler = _handle_no_such_interface
    elif win32_error in (1722, 1753):
        handler = _handle_server_unavailable
    elif win32_error == FWP_E_IN_USE:
        handler = _handle_fwp_in_use
    elif win32_error == 238:
        handler = _handle_dev_io_error
    else:
        handler = None

    entry: Optional[Dict[str, object]] = None
    if handler is not None:
        entry = handler(win32_error)
    if entry is None:
        entry = _fallback_diagnosis(int(exit_code), win32_error)
    entry["exit_code"] = int(exit_code)
    entry["win32_error"] = win32_error
    return entry


def build_winws_exit_diagnosis_entry(
    exit_code: int,
    output: Optional[str] = None,
    *,
    hint_operator_version: Optional[str] = None,
    hint_auto_clean: bool = False,
) -> Dict[str, object]:
    entry = diagnose_winws_exit(exit_code, output, hint_operator_version=hint_operator_version)
    if entry is not None:
        return entry
    if int(exit_code or 0) == 0:
        success = _handle_exited_0(0)
        if success:
            return success
    return _base_diagnosis("Не удалось определить причину завершения winws")


def make_exit_code_suggestion(exit_code: Optional[int]) -> Optional[str]:
    if exit_code is None:
        return None
    entry = diagnose_winws_exit(int(exit_code), None)
    if not entry:
        return None
    cause = entry.get("cause")
    solution = entry.get("solution")
    suggestion = cause or ""
    if solution:
        suggestion = f"{suggestion} ({solution})"
    return suggestion


def suggest_verified_operation(entry: Dict[str, object]) -> Optional[str]:
    auto_fix = entry.get("auto_fix") or ""
    if not auto_fix:
        return None
    if "agressive cleanup" in auto_fix or "Агрессивная очистка" in auto_fix:
        return "aggressive_windivert_cleanup"
    return auto_fix


def build_exit_code_suggestion_chain(
    exit_code: int,
    diagnostic_output: str = "",
    *,
    operator_version: Optional[str] = None,
    trigger: Optional[str] = None,
) -> List[Tuple[str, str]]:
    entry = diagnose_winws_exit(exit_code, diagnostic_output, hint_operator_version=operator_version)
    if not entry:
        return []
    chain: List[Tuple[str, str]] = []
    if entry.get("cause"):
        chain.append(("причина", str(entry["cause"])))
    if entry.get("solution"):
        chain.append(("рекомендация", str(entry["solution"])))
    for step in entry.get("next_steps") or []:
        chain.append(("действие", str(step)))
    return chain


def build_operator_exit_code_suggestion(exit_code: int, diagnostic_output: str = "") -> List[Tuple[str, str]]:
    return build_exit_code_suggestion_chain(exit_code, diagnostic_output, trigger="operator")


_last_diag_context["last_entry"] = None


def describe_windivert_exit_diagnosis(entry: Dict[str, object]) -> str:
    cause = entry.get("cause") or "без причин"
    solution = entry.get("solution")
    if solution:
        return f"{cause} Рекомендация: {solution}"
    return str(cause)