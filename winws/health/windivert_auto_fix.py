from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from ._log import log
from .system_ops import (
    WinDivertRuntimeProbeResult,
    retry_windivert_spawn_readiness_after_recovery,
    wait_for_windivert_spawn_ready_runtime,
)

_AUTO_FIX_AGGRESSIVE_CODES = frozenset({577, 1072, 1275})


def _suggested_cleanup_level(error_code: Optional[int]) -> str:
    if error_code in _AUTO_FIX_AGGRESSIVE_CODES:
        return "aggressive"
    return "standard"


def _run_recovery(probe: WinDivertRuntimeProbeResult) -> None:
    level = _suggested_cleanup_level(probe.error_code)
    log.info(f"WinDivert не готов (код {probe.error_code}); применяется {level}-очистка")
    try:
        if level == "aggressive":
            from .system_ops import aggressive_windivert_cleanup_runtime
            aggressive_windivert_cleanup_runtime()
        else:
            from .system_ops import standard_windivert_cleanup_runtime
            standard_windivert_cleanup_runtime(post_cleanup_sleep_ms=500)
    except Exception as exc:
        log.warn(f"Автовосстановление WinDivert не выполнено: {exc}")


def windivert_driver_ready_with_fix(
    readier: Optional[Callable[[WinDivertRuntimeProbeResult], None]] = None,
    readier_verdict: Optional[str] = None,
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
    wait_between_attempts_ms: int = 500,
    wait_after_cleanup_ms: int = 2500,
    timeout_ms: int = 45000,
) -> Tuple[bool, WinDivertRuntimeProbeResult]:
    if readier is None:
        readier = _run_recovery
    ok, probe = retry_windivert_spawn_readiness_after_recovery(
        exe_path=exe_path,
        preferred_driver_dir=preferred_driver_dir,
        executable_args=executable_args,
        search_verdict=readier_verdict,
        readier=readier,
        wait_between_attempts_ms=wait_between_attempts_ms,
        wait_after_cleanup_ms=wait_after_cleanup_ms,
        timeout_ms=timeout_ms,
    )
    return ok, probe


def ensure_windivert_ready_before_spawn(
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
) -> Tuple[bool, WinDivertRuntimeProbeResult]:
    return windivert_driver_ready_with_fix(
        exe_path=exe_path,
        preferred_driver_dir=preferred_driver_dir,
        executable_args=executable_args,
    )


def ensure_windivert_ready(
    exe_path: Optional[str] = None,
    preferred_driver_dir: Optional[str] = None,
    executable_args: Optional[List[str]] = None,
) -> WinDivertRuntimeProbeResult:
    probe = wait_for_windivert_spawn_ready_runtime(
        exe_path=exe_path, preferred_driver_dir=preferred_driver_dir,
        executable_args=executable_args,
    )
    return probe


def is_windivert_ready() -> bool:
    try:
        from .system_ops import probe_windivert_state_runtime
        return bool(probe_windivert_state_runtime().ready)
    except Exception:
        return False


def clear_ensured_windivert_ready_cache() -> None:
    pass