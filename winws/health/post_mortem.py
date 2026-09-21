from __future__ import annotations

from typing import Dict, List, Optional

from ._log import log
from .silent_exit_probe import (
    SilentExitReport,
    format_silent_exit_message,
    probe_silent_exit,
)
from .winws_exit_diagnosis import build_winws_exit_diagnosis_entry


def _first_relevant_output_line(lines: List[str]) -> Optional[str]:
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("<<"):
            return stripped
    return None


def diagnose_unexpected_winws_exit(
    exe_path: str,
    exit_code: Optional[int],
    run_output: str = "",
    *,
    use_silent_exit_probe: bool = True,
    is_quiet: bool = False,
) -> Dict[str, object]:
    entry = build_winws_exit_diagnosis_entry(exit_code, run_output)
    report: Optional[SilentExitReport] = None
    if use_silent_exit_probe:
        try:
            report = probe_silent_exit(exe_path, exit_code=exit_code, output_region=run_output, is_quiet=is_quiet)
        except Exception as exc:
            log.warn(f"Проба «молчаливого» завершения недоступна: {exc}")
    entry["silent_exit"] = bool(report and report.confirmed)
    if report is not None and report.confirmed:
        entry["silent_exit_message"] = format_silent_exit_message(report)
    if entry.get("is_unexpected_exit"):
        entry["is_unexpected_exit"] = True
    return entry