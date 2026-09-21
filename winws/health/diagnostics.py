from __future__ import annotations

import re
from typing import Dict, List, Optional

from ._log import log
from .winws_exit_diagnosis import build_winws_exit_diagnosis_entry, diagnose_winws_exit
from .windivert_diagnostics import WINDIVERT_ERROR_TABLE

_EXIT_RE = re.compile(r"exited(?: immediately)? \(code (\d+)\)", re.IGNORECASE)


def _engine_present() -> bool:
    try:
        from winws.paths import find_engine
        return bool(find_engine().get("ok"))
    except Exception:
        return False


def _winws_running() -> bool:
    try:
        from winws.runner import status
        return str(status().get("state", "")).lower() == "running"
    except Exception:
        return False


def _iter_exit_lines(text: str) -> List[str]:
    return [line.strip() for line in (text or "").splitlines() if _EXIT_RE.search(line)]


def _exit_code_from_line(line: str) -> Optional[int]:
    match = _EXIT_RE.search(line)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def diagnose_log_text(text: str) -> Dict[str, object]:
    findings: List[Dict[str, object]] = []
    windivert_error: Optional[Dict[str, object]] = None
    for line in _iter_exit_lines(text):
        code = _exit_code_from_line(line)
        if code is None or code == 0:
            continue
        entry = build_winws_exit_diagnosis_entry(code, line)
        findings.append({
            "exit_code": code,
            "cause": entry.get("cause"),
            "solution": entry.get("solution"),
            "win32_error": entry.get("win32_error"),
        })
        if code in WINDIVERT_ERROR_TABLE and windivert_error is None:
            windivert_error = {
                "code": code,
                "meaning": WINDIVERT_ERROR_TABLE[code]["meaning"],
                "cause": WINDIVERT_ERROR_TABLE[code]["cause"],
                "solution": WINDIVERT_ERROR_TABLE[code]["solution"],
            }
    return {
        "findings": findings,
        "exit_codes": [f.get("exit_code") for f in findings],
        "last_crash": findings[-1] if findings else None,
        "windivert_error": windivert_error,
    }


def _winws_log_text() -> str:
    chunks: List[str] = []
    try:
        from winws.logs import tail, recent_crashes
        tail_text = tail()
        if tail_text:
            chunks.append(tail_text)
        crash_text = recent_crashes()
        if crash_text:
            chunks.append(crash_text)
    except Exception:
        pass
    return "\n".join(chunks)


def run_winws_diagnostics() -> Dict[str, object]:
    text = _winws_log_text()
    analysis = diagnose_log_text(text)
    last_crash = analysis.get("last_crash")
    exit_analysis: List[Dict[str, object]] = []
    for line in _iter_exit_lines(text):
        code = _exit_code_from_line(line)
        if code is None or code == 0:
            continue
        entry = build_winws_exit_diagnosis_entry(code, line)
        exit_analysis.append({
            "code": code,
            "cause": entry.get("cause"),
            "solution": entry.get("solution"),
            "win32_error": entry.get("win32_error"),
        })
    suggestions: List[str] = []
    if last_crash:
        if last_crash.get("solution"):
            suggestions.append(str(last_crash["solution"]))
        code = last_crash.get("exit_code")
        if code in WINDIVERT_ERROR_TABLE:
            auto_fix = WINDIVERT_ERROR_TABLE.get(code, {}).get("auto_fix")
            if auto_fix:
                suggestions.append(str(auto_fix))
    return {
        "engine_present": _engine_present(),
        "running": _winws_running(),
        "last_crash_diagnosis": last_crash,
        "exit_analysis": exit_analysis,
        "windivert_error": analysis.get("windivert_error"),
        "suggestions": suggestions,
    }


def _probe_to_plain(probe) -> Dict[str, object]:
    return {
        "ready": bool(getattr(probe, "ready", False)),
        "installed": bool(getattr(probe, "installed", False)),
        "error_code": getattr(probe, "error_code", None),
        "error_message": getattr(probe, "error_message", None),
        "stage": getattr(probe, "stage", None),
        "driver_path": getattr(probe, "driver_path", None),
        "verdict": getattr(probe, "verdict", None),
    }


def get_windivert_health() -> Dict[str, object]:
    from .system_ops import probe_windivert_state_runtime
    probe = probe_windivert_state_runtime()
    error_entries: List[Dict[str, object]] = []
    for code in sorted(WINDIVERT_ERROR_TABLE):
        entry = WINDIVERT_ERROR_TABLE[code]
        error_entries.append({
            "code": code,
            "meaning": entry["meaning"],
            "cause": entry["cause"],
            "solution": entry["solution"],
            "auto_fix": entry["auto_fix"],
            "transient": entry["transient"],
        })
    conflict_processes: List[Dict[str, object]] = []
    foreign_services: List[str] = []
    conflict_finding: Optional[str] = None
    try:
        from .launch_conflicts import (
            build_windivert_conflict_hint,
            check_conflicting_processes,
        )
        conflict_processes = [
            {
                "name": str(item.get("name") or "?"),
                "pid": item.get("pid"),
                "reason": item.get("reason") or "",
            }
            for item in check_conflicting_processes()
        ]
        foreign_services = list_from_system_ops_foreign()
        conflict_finding = build_windivert_conflict_hint()
    except Exception:
        pass
    dependencies: Dict[str, object] = {}
    try:
        from .windows_system_dependencies import preflight_dependencies
        dependencies = preflight_dependencies()
    except Exception:
        pass
    system_driver: Optional[object] = None
    bundled: Optional[object] = None
    try:
        from tools.windows_tools import windivert_presence
        presence = windivert_presence() or {}
        system_driver = presence.get("driver")
        bundled = presence.get("bundled")
    except Exception:
        pass
    return {
        "readiness_probe": _probe_to_plain(probe),
        "error_codes": error_entries,
        "conflict_report": {
            "finding": conflict_finding,
            "processes": conflict_processes,
            "foreign_services": foreign_services,
        },
        "dependencies": dependencies,
        "system_driver": system_driver,
        "bundled": bundled,
    }


def list_from_system_ops_foreign() -> List[str]:
    try:
        from .system_ops import find_foreign_windivert_service_paths_runtime
        return list(find_foreign_windivert_service_paths_runtime())
    except Exception:
        return []


def _is_admin() -> bool:
    try:
        import ctypes
        if not hasattr(ctypes, "windll"):
            return False
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def windivert_cleanup(level: str = "standard") -> Dict[str, object]:
    from .system_ops import (
        aggressive_windivert_cleanup_runtime,
        standard_windivert_cleanup_runtime,
    )
    if level == "aggressive":
        ok = aggressive_windivert_cleanup_runtime()
    else:
        ok = standard_windivert_cleanup_runtime()
    performed = [f"cleanup_{level}"] if ok else []
    failed = [] if ok else [f"cleanup_{level}"]
    return {
        "ok": ok,
        "performed": performed,
        "failed": failed,
        "requires_admin": not _is_admin(),
    }


def kill_conflicting_processes() -> Dict[str, object]:
    try:
        from .launch_conflicts import check_conflicting_processes, try_kill_conflicting_processes
        before = [str(item.get("name") or "?") for item in check_conflicting_processes()]
        ok = try_kill_conflicting_processes(auto_kill=True)
        after = [str(item.get("name") or "?") for item in check_conflicting_processes()]
        killed = [name for name in before if name not in after]
        return {"ok": ok, "killed": killed}
    except Exception as exc:
        return {"ok": False, "killed": [], "error": str(exc)}


def _last_diagnostic_error_line(text: str) -> Optional[str]:
    from .winws_output import relevant_error_line
    return relevant_error_line((text or "").splitlines())


def get_winws_health() -> Dict[str, object]:
    from .windivert_auto_fix import is_windivert_ready
    conflicts = 0
    recent_crashes_count = 0
    last_error: Optional[str] = None
    driver_present = False
    bundled_driver: str = ""
    try:
        from .launch_conflicts import check_conflicting_processes
        conflicts = len(check_conflicting_processes())
    except Exception:
        pass
    text = _winws_log_text()
    try:
        from winws.logs import recent_crashes as _recent_crashes
        crash_text = _recent_crashes() or ""
        recent_crashes_count = len([ln for ln in crash_text.splitlines() if ln.strip()])
    except Exception:
        pass
    last_error = _last_diagnostic_error_line(text)
    try:
        from tools.windows_tools import windivert_presence
        presence = windivert_presence() or {}
        driver = presence.get("driver") or {}
        driver_present = bool(driver.get("present"))
        bundled_driver = str(driver.get("path") or "")
    except Exception:
        pass
    return {
        "engine_present": _engine_present(),
        "running": _winws_running(),
        "windivert_ready": is_windivert_ready(),
        "driver_present": driver_present,
        "bundled_driver": bundled_driver,
        "conflicts": conflicts,
        "recent_crashes": recent_crashes_count,
        "last_error": last_error,
    }