from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

from ._log import log

_PROBE_CACHE_TTL_SECONDS = 15.0
_APPLICATION_ERROR_WINDOW_MINUTES = 2
_DEFENDER_WINDOW_MINUTES = 5


class _ProbeUnavailable(Exception):
    pass


@dataclass
class SilentExitFinding:
    kind: str
    detail: str
    confirmed: bool


@dataclass
class SilentExitReport:
    confirmed: bool
    findings: List[SilentExitFinding] = field(default_factory=list)
    source_exe_missing: bool = False
    source_present_exit_code_mismatch: bool = False
    detector_triggered: bool = False
    antivirus_detection_window: bool = False
    boot_time_window: bool = False


_last_defender_check = 0.0
_last_defender_hit = False


def _recent_defender_detection_within() -> bool:
    global _last_defender_check, _last_defender_hit
    now = time.monotonic()
    if (now - _last_defender_check) < _PROBE_CACHE_TTL_SECONDS:
        return _last_defender_hit
    try:
        from .windows_event_log import recent_defender_flag_points
        flagged = recent_defender_flag_points(timeout=5.0)
        hit = bool(flagged)
    except Exception:
        hit = False
    _last_defender_check = now
    _last_defender_hit = hit
    return hit


def probe_silent_exit(
    exe_path: str,
    context: str = "",
    is_quiet: bool = False,
    output_region: str = "",
    exit_code: Optional[int] = None,
) -> SilentExitReport:
    findings: List[SilentExitFinding] = []
    confirmed = False

    exe_missing = not os.path.isfile(exe_path)
    if exe_missing:
        findings.append(SilentExitFinding("executable_missing", f"исполняемый файл отсутствует: {exe_path}", True))
        confirmed = True

    code_mismatch = exit_code is not None
    if code_mismatch:
        findings.append(SilentExitFinding("exit_code_provided", f"получен код завершения {exit_code}", True))

    defender_hit = _recent_defender_detection_within()
    if defender_hit:
        findings.append(SilentExitFinding(
            "defender_detection",
            f"обнаружены блокировки Defender в последние {_DEFENDER_WINDOW_MINUTES} минут",
            True,
        ))
        confirmed = True
    else:
        findings.append(SilentExitFinding("defender_detection", "свежих блокировок Defender не обнаружено", False))

    if output_region and not is_quiet:
        from .winws_output import has_diagnostic_output
        if has_diagnostic_output(output_region):
            confirmed = False
            findings.append(SilentExitFinding("diagnostic_output", "в выводе есть диагностическая информация", True))

    report = SilentExitReport(
        confirmed=confirmed,
        findings=findings,
        source_exe_missing=exe_missing,
        source_present_exit_code_mismatch=code_mismatch,
        detector_triggered=defender_hit,
        antivirus_detection_window=defender_hit,
    )
    return report


def format_silent_exit_message(report: SilentExitReport) -> str:
    if not report.confirmed:
        confirmed_text = "Подозрение на «молчаливое» завершение не подтверждено"
    else:
        confirmed_text = "Подтверждено «молчаливое» завершение winws"
    lines = [confirmed_text]
    for finding in report.findings:
        tag = "да" if finding.confirmed else "нет"
        lines.append(f"- {finding.detail} ({tag})")
    return "\n".join(lines)


def invalidate_silent_exit_cache() -> None:
    global _last_defender_check, _last_defender_hit
    _last_defender_check = 0.0
    _last_defender_hit = False