"""winws log analyzer: сессии запусков, вердикт и ошибки из winws.log.

Файл журнала winws (путь берётся из winws.paths.log_path) пишется двумя
потоками: раннер SwiftProxy (маркеры ``Starting...``/``winws exited
immediately``/``winws process exited``/``winws stopped``) и сам winws
(вывод stdout/stderr). Модуль разбирает маркеры раннера, собирает сессии
запусков, классифицирует последний запуск и возвращает вердикт.

Никакие функции не бросают исключений: отсутствующий/занятый файл
трактуется как ``no_log``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MAX_SCAN_CHARS = 2_000_000
_MAX_LISTED_SESSIONS = 20
_MAX_ISSUES = 50

_TIMESTAMP_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*(.*)$")
_START_RE = re.compile(r"^Starting (.*?)\.\.\. \(mode=([^,]+), pid=(\d+), cwd=(.*)\)$")
_IMMEDIATE_EXIT_RE = re.compile(r"^winws exited immediately \(code (-?\d+)\): (.*)$")
_EXIT_RE = re.compile(r"^winws process exited \(code (-?\d+)\)$")
_STOPPED_RE = re.compile(r"^winws stopped \(pid (\d+)\)$")

_BANNER_PREFIXES = ("<<", ">=>>>")

_WORKING_MARKERS = (
    "sleeping",
    "listening",
    "bound to",
    "speaking",
    "warp",
    "captured",
    "main loop",
    "waiting",
    "ready",
    "started forward",
    "engine running",
)

_NO_CONFIG_MARKERS = (
    "config not found",
    "no config",
    "no configuration",
    "can't open config",
    "cannot open config",
    "can't read config",
    "cannot read config",
    "unable to open config",
    "не найден конфиг",
    "конфиг не найден",
    "конфигурация не найден",
    "нет конфиг",
    "не может открыть конфиг",
    "не удалось прочитать конфиг",
    "не удалось открыть конфиг",
    "отсутствует конфиг",
    "profile_empty",
)

_LOAD_FAILED_MARKERS = (
    "failed to load",
    "unable to load",
    "can't load",
    "cannot load",
    "load failed",
    "error loading",
    "не удалось загрузить",
    "не может загрузить",
    "не смог загрузить",
    "ошибка загрузки",
    "не загрузи",
)

_PF_MARKERS = (
    "pfcalc",
    "расчёт",
    "comput",
    "фрагментац",
    "fragment policy",
    "политик фрагмента",
    "pattern calc",
    "pf: ",
)

_ERROR_MARKERS = (
    "error",
    "ошиб",
    "fail",
    "fatal",
    "не найд",
    "недоступ",
    "отказан",
    "can't",
    "cannot",
    "unable",
    "код 5",
    "code 5",
    "windivert:",
    "требует",
)

_WARNING_MARKERS = (
    "warn",
    "warning",
    "предупрежд",
    "careful",
    "осторожн",
    "attention",
    "вниман",
    "recommend",
    "рекоменд",
)


class Verdict(str, Enum):
    NO_LOG = "no_log"
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"


REASON_NO_LOG = "no_log"
REASON_NO_CONTENT = "no_content"
REASON_EXTERNAL = "external"
REASON_STOPPED = "stopped"
REASON_CLEAN_EXIT = "clean_exit"
REASON_WAITING = "waiting"
REASON_BOOTING = "booting"
REASON_PF_CALC = "pf_calc"
REASON_NO_CONFIG = "no_config"
REASON_LOAD_FAILED = "load_failed"
REASON_NOT_APPEARED = "not_appeared"
REASON_APPEARED_DISAPPEARED = "appeared_disappeared"

_PHASE_WAITING = "waiting"
_PHASE_NO_CONFIG = "no_config"
_PHASE_LOAD_FAILED = "load_failed"
_PHASE_PF_CALC = "pf_calc"

_PHASE_DICT: Dict[str, Tuple[Verdict, str]] = {
    _PHASE_NO_CONFIG: (Verdict.ERROR, REASON_NO_CONFIG),
    _PHASE_LOAD_FAILED: (Verdict.ERROR, REASON_LOAD_FAILED),
    _PHASE_PF_CALC: (Verdict.WARNING, REASON_PF_CALC),
    _PHASE_WAITING: (Verdict.OK, REASON_WAITING),
}


@dataclass
class Session:
    started_at: Optional[str] = None
    mode: str = ""
    pid: Optional[int] = None
    cwd: str = ""
    ended_at: Optional[str] = None
    exit_code: Optional[int] = None
    stopped_by_app: bool = False
    immediate_exit: bool = False
    output: str = ""
    content_lines: List[str] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.ended_at is None


@dataclass
class Analysis:
    has_log: bool
    lines_total: int
    sessions: List[Session]
    errors: List[str]
    warnings: List[str]
    status: str
    reason: str
    detail: str


def _read_lines(log_path: Any) -> Tuple[bool, List[str]]:
    try:
        path = Path(log_path)
        if not path.is_file():
            return False, []
        size = path.stat().st_size
        with open(path, "rb") as handle:
            if size > _MAX_SCAN_CHARS:
                handle.seek(size - _MAX_SCAN_CHARS)
            data = handle.read()
    except OSError:
        return False, []
    text = data.decode("utf-8", errors="replace")
    return True, text.splitlines()


def _strip_label(raw: str, last_ts: str) -> str:
    stripped = raw.rstrip()
    if not stripped.strip():
        return ""
    match = _TIMESTAMP_RE.match(stripped)
    if match:
        return match.group(2).strip()
    return stripped


def _classify_content(line: str) -> Optional[str]:
    lowered = line.lower()
    if any(prefix in lowered for prefix in _BANNER_PREFIXES):
        return None
    if any(marker in lowered for marker in _NO_CONFIG_MARKERS):
        return _PHASE_NO_CONFIG
    if any(marker in lowered for marker in _LOAD_FAILED_MARKERS):
        return _PHASE_LOAD_FAILED
    if any(marker in lowered for marker in _PF_MARKERS):
        return _PHASE_PF_CALC
    if any(marker in lowered for marker in _WORKING_MARKERS):
        return _PHASE_WAITING
    return None


def _is_error_line(lowered: str) -> bool:
    return any(marker in lowered for marker in _ERROR_MARKERS)


def _is_warning_line(lowered: str) -> bool:
    return any(marker in lowered for marker in _WARNING_MARKERS)


def _parse(lines: List[str]) -> Tuple[List[Session], List[str], List[str]]:
    sessions: List[Session] = []
    errors: List[str] = []
    warnings: List[str] = []
    current: Optional[Session] = None
    last_ts = ""

    for raw in lines:
        match = _TIMESTAMP_RE.match(raw)
        if match:
            last_ts = match.group(1)
            body = match.group(2).strip()
        else:
            body = _strip_label(raw, last_ts)
        if not body:
            continue

        start = _START_RE.match(body)
        if start:
            current = Session(
                started_at=last_ts,
                mode=start.group(2),
                pid=int(start.group(3)),
                cwd=start.group(4),
            )
            sessions.append(current)
            continue

        immediate = _IMMEDIATE_EXIT_RE.match(body)
        if immediate:
            if current is not None:
                current.immediate_exit = True
                current.exit_code = int(immediate.group(1))
                current.ended_at = last_ts
                current.output = immediate.group(2)
            continue

        exited = _EXIT_RE.match(body)
        if exited:
            if current is not None:
                current.exit_code = int(exited.group(1))
                current.ended_at = last_ts
            continue

        stopped = _STOPPED_RE.match(body)
        if stopped:
            if current is not None:
                current.stopped_by_app = True
                current.ended_at = last_ts
            continue

        if current is not None:
            current.content_lines.append(body)
        lowered = body.lower()
        label = f"[{last_ts}] {body}" if last_ts else body
        if _is_error_line(lowered):
            errors.append(label)
        elif _is_warning_line(lowered):
            warnings.append(label)

    return sessions, errors[-_MAX_ISSUES:], warnings[-_MAX_ISSUES:]


def _find_phase(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    if any(marker in lowered for marker in _NO_CONFIG_MARKERS):
        return _PHASE_NO_CONFIG
    if any(marker in lowered for marker in _LOAD_FAILED_MARKERS):
        return _PHASE_LOAD_FAILED
    if any(marker in lowered for marker in _PF_MARKERS):
        return _PHASE_PF_CALC
    if any(marker in lowered for marker in _WORKING_MARKERS):
        return _PHASE_WAITING
    return None


def _detail_text(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _classify_session(session: Session) -> Tuple[Verdict, str, str]:
    content = "\n".join(session.content_lines)
    scan = (session.output + "\n" + content).strip()
    phase = _find_phase(content)
    scan_phase = _find_phase(scan) or phase

    if session.ended_at is not None:
        if session.stopped_by_app:
            if scan_phase == _PHASE_NO_CONFIG:
                return Verdict.ERROR, REASON_NO_CONFIG, _detail_text(scan)
            if scan_phase == _PHASE_LOAD_FAILED:
                return Verdict.ERROR, REASON_LOAD_FAILED, _detail_text(scan)
            if session.immediate_exit or session.exit_code not in (None, 0):
                return Verdict.ERROR, REASON_APPEARED_DISAPPEARED, _detail_text(scan)
            return Verdict.OK, REASON_STOPPED, _detail_text(scan)
        if session.immediate_exit or session.exit_code not in (None, 0):
            return _failed_session(scan, scan_phase)
        if scan_phase == _PHASE_WAITING:
            return Verdict.OK, REASON_CLEAN_EXIT, _detail_text(scan)
        return Verdict.WARNING, REASON_APPEARED_DISAPPEARED, _detail_text(scan)

    if scan_phase == _PHASE_WAITING:
        return Verdict.OK, REASON_WAITING, _detail_text(scan)
    if scan_phase == _PHASE_NO_CONFIG:
        return Verdict.ERROR, REASON_NO_CONFIG, _detail_text(scan)
    if scan_phase == _PHASE_LOAD_FAILED:
        return Verdict.ERROR, REASON_LOAD_FAILED, _detail_text(scan)
    if scan_phase == _PHASE_PF_CALC:
        return Verdict.WARNING, REASON_PF_CALC, _detail_text(scan)
    if session.content_lines:
        return Verdict.WARNING, REASON_BOOTING, _detail_text(scan)
    return Verdict.ERROR, REASON_NOT_APPEARED, ""


def _failed_session(scan: str, phase: Optional[str]) -> Tuple[Verdict, str, str]:
    if phase == _PHASE_NO_CONFIG:
        return Verdict.ERROR, REASON_NO_CONFIG, _detail_text(scan)
    if phase == _PHASE_LOAD_FAILED:
        return Verdict.ERROR, REASON_LOAD_FAILED, _detail_text(scan)
    if not scan:
        return Verdict.ERROR, REASON_NOT_APPEARED, ""
    if phase == _PHASE_PF_CALC:
        return Verdict.WARNING, REASON_PF_CALC, _detail_text(scan)
    if phase == _PHASE_WAITING:
        return Verdict.OK, REASON_WAITING, _detail_text(scan)
    return Verdict.ERROR, REASON_APPEARED_DISAPPEARED, _detail_text(scan)


def _session_plain(session: Session) -> Dict[str, Any]:
    return {
        "started_at": session.started_at,
        "mode": session.mode,
        "pid": session.pid,
        "cwd": session.cwd,
        "ended_at": session.ended_at,
        "exit_code": session.exit_code,
        "stopped_by_app": session.stopped_by_app,
        "immediate_exit": session.immediate_exit,
        "lifetime_seconds": _lifetime_seconds(session),
        "ok": _classify_session(session)[0] == Verdict.OK,
    }


def _lifetime_seconds(session: Session) -> Optional[int]:
    if not session.started_at or not session.ended_at:
        return None
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        start = datetime.strptime(session.started_at, fmt)
        end = datetime.strptime(session.ended_at, fmt)
        return max(0, int((end - start).total_seconds()))
    except ValueError:
        return None


def _analyze(log_path: Any) -> Analysis:
    has_log, lines = _read_lines(log_path)
    if not has_log:
        return Analysis(False, 0, [], [], [], Verdict.NO_LOG.value, REASON_NO_LOG, "")
    if not any(line.strip() for line in lines):
        return Analysis(True, 0, [], [], [], Verdict.NO_LOG.value, REASON_NO_CONTENT, "")
    sessions, errors, warnings = _parse(lines)
    status, reason, detail = _verdict_of(sessions)
    return Analysis(True, len(lines), sessions, errors, warnings, status, reason, detail)


def _verdict_of(sessions: List[Session]) -> Tuple[str, str, str]:
    if not sessions:
        return Verdict.WARNING.value, REASON_EXTERNAL, ""
    level, reason, detail = _classify_session(sessions[-1])
    return level.value, reason, detail


def detect_run_status(log_path: Any) -> Dict[str, Any]:
    analysis = _analyze(log_path)
    return {
        "has_log": analysis.has_log,
        "status": analysis.status,
        "reason": analysis.reason,
        "detail": analysis.detail,
        "lines_total": analysis.lines_total,
    }


def parse_session(log_path: Any) -> Dict[str, Any]:
    analysis = _analyze(log_path)
    sessions = analysis.sessions
    ok_count = fail_count = warn_count = open_count = 0
    for session in sessions:
        level, _, _ = _classify_session(session)
        if level == Verdict.OK:
            ok_count += 1
        elif level == Verdict.ERROR:
            fail_count += 1
        else:
            warn_count += 1
        if session.is_open:
            open_count += 1
    plain = [_session_plain(session) for session in sessions[-_MAX_LISTED_SESSIONS:]]
    return {
        "has_log": analysis.has_log,
        "lines_total": analysis.lines_total,
        "sessions_count": len(sessions),
        "ok_count": ok_count,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "open_count": open_count,
        "sessions": plain,
        "errors": analysis.errors,
        "warnings": analysis.warnings,
        "last_session": plain[-1] if plain else None,
    }


def summarize_log(log_path: Any) -> Dict[str, Any]:
    parsed = parse_session(log_path)
    parsed["verdict"] = detect_run_status(log_path)
    return parsed


__all__ = [
    "Analysis",
    "Session",
    "Verdict",
    "detect_run_status",
    "parse_session",
    "summarize_log",
]