from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._log import log
from .system_ops import (
    find_foreign_windivert_service_paths_runtime,
    find_windivert_holder_processes_runtime,
    kill_process_by_pid_runtime,
)
from .windivert_diagnostics import describe_windivert_conflict_hint
from utils.windows_process_probe import _iter_process_records_winapi

CONFLICTING_PROCESSES: Dict[str, str] = {
    "ProcessHacker.exe": "может держать сокеты/драйверы занятыми и помешать запуску WinDivert",
    "procexp.exe": "Process Explorer может держать драйвер WinDivert занятым",
    "procexp64.exe": "Process Explorer (64-bit) может держать драйвер WinDivert занятым",
    "GoodbyeDPI.exe": "конфликтует с WinDivert: обе программы перехватывают сетевой стек",
    "SpoofDPI.exe": "конфликтует с WinDivert: обе программы перехватывают сетевой стек",
}

_own_windivert_dir_markers = ()


def _own_driver_dirs_resolver() -> List[str]:
    markers: List[str] = []
    try:
        from winws.paths import engine_dir
        folder = engine_dir()
        if folder is not None:
            markers.append(str(folder).lower())
    except Exception:
        pass
    return markers


def _is_own_driver_dir(path: str) -> bool:
    lowered = str(path).lower()
    return any(lowered.startswith(marker) for marker in _own_driver_dirs_resolver())


def _find_windivert_conflicts() -> List[Dict[str, Optional[object]]]:
    conflicts: List[Dict[str, Optional[object]]] = []
    try:
        records = list(_iter_process_records_winapi())
    except Exception:
        return conflicts
    for record in records:
        name = str(record.get("name") or record.get("exe") or "").lower()
        for exe_name, reason in CONFLICTING_PROCESSES.items():
            if name == exe_name.lower():
                conflicts.append({
                    "name": str(record.get("name") or record.get("exe")),
                    "exe": exe_name,
                    "pid": record.get("pid"),
                    "reason": reason,
                })
                break
    return conflicts


def check_conflicting_processes() -> List[Dict[str, Optional[object]]]:
    return _find_windivert_conflicts()


def get_conflicting_processes_report() -> str:
    conflicts = _find_windivert_conflicts()
    if not conflicts:
        return "Конфликтующие с WinDivert процессы не найдены"
    lines = ["Обнаружены процессы, способные конфликтовать с WinDivert:"]
    for item in conflicts:
        lines.append(f"  {item['name']} (pid {item['pid']}): {item['reason']}")
    return "\n".join(lines)


def try_kill_conflicting_processes(auto_kill: bool = False) -> bool:
    conflicts = _find_windivert_conflicts()
    if not conflicts:
        return True
    if not auto_kill:
        return False
    failed = False
    for item in conflicts:
        pid = item.get("pid")
        if pid is None:
            continue
        if not kill_process_by_pid_runtime(int(pid)):
            failed = True
    return not failed


def build_windivert_conflict_hint() -> Optional[str]:
    holders = find_windivert_holder_processes_runtime()
    foreign = list(find_foreign_windivert_service_paths_runtime())
    if not holders and not foreign:
        return None
    return describe_windivert_conflict_hint(holders, foreign)


def build_launch_conflict_advice(
    exit_code: int,
    log_region: str = "",
    hint_operator_version: Optional[str] = None,
) -> Optional[Tuple[str, str]]:
    conflicts = _find_windivert_conflicts()
    if exit_code in (9, 31):
        return ("конфликт WinDivert", "закрой программы, держащие сетевой стек, и перезапусти winws")
    if conflicts:
        names = ", ".join(str(item["name"]) for item in conflicts[:3])
        return ("блокировка WinDivert сторонними процессами", f"закрой: {names}")
    return None