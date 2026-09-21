from __future__ import annotations

from typing import Optional, Tuple

from ._log import log

STATUS_DLL_INIT_FAILED = 0xC0000142
_FWP_E_IN_USE = 0x80320010

_WINDIVERT_CONFLICT_EXIT_CODES = frozenset({9, _FWP_E_IN_USE})

_WINDIVERT_CONFLICT_SIGNATURES = frozenset({
    "windivert: handle is in use",
    "windivert: permission denied",
    "windivert: no ports available",
})

_INI_FAILED_PATTERNS = ("status 0xc0000142", "dll init failed", "0xc0000142")


def classify_spawn_failure(exit_code: Optional[int], stderr: str = "") -> Optional[str]:
    """Классифицирует причину мгновенного завершения winws; None — причина не найдена."""
    if exit_code is None:
        if _contains_any(stderr, _WINDIVERT_CONFLICT_SIGNATURES):
            return "windivert_conflict"
        if _contains_any(stderr, _INI_FAILED_PATTERNS):
            return "dll_init_failed"
        return None
    code = int(exit_code)
    if code in _WINDIVERT_CONFLICT_EXIT_CODES:
        return "windivert_conflict"
    if code == STATUS_DLL_INIT_FAILED:
        return "dll_init_failed"
    if _contains_any(stderr, _WINDIVERT_CONFLICT_SIGNATURES):
        return "windivert_conflict"
    if _contains_any(stderr, _INI_FAILED_PATTERNS):
        return "dll_init_failed"
    return None


def is_silent_exit(exit_code: Optional[int], stderr: str) -> bool:
    """True, если процесс завершился без диагностического вывода (молча)."""
    if (exit_code or 0) == 0:
        return False
    lowered = (stderr or "").strip().lower()
    if not lowered:
        return True
    from .winws_output import has_diagnostic_output
    if has_diagnostic_output(lowered):
        return False
    return not _contains_any(lowered, ("error", "code", "status"))


def failure_hint(kind: Optional[str]) -> Optional[Tuple[str, str]]:
    """Возвращает (короткий заголовок, совет) по классификации отказа."""
    if kind is None:
        return None
    if kind == "windivert_conflict":
        return ("конфликт WinDivert", "закрой приложения, держащие WinDivert, и перезапусти winws")
    if kind == "dll_init_failed":
        return ("ошибка инициализации DLL", "проверь целостность файлов winws и перезапусти процесс")
    return None


def _contains_any(text: str, signatures) -> bool:
    lowered = (text or "").lower()
    return any(sig.lower() in lowered for sig in signatures)