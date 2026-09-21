from .antivirus_detection import _detect_active_antivirus, _is_windows_defender_active
from .antivirus_probe import is_kaspersky_present, is_kaspersky_detected_in_path
from .launch_conflicts import (
    CONFLICTING_PROCESSES,
    build_launch_conflict_advice,
    build_windivert_conflict_hint,
    check_conflicting_processes,
    get_conflicting_processes_report,
    try_kill_conflicting_processes,
)
from .post_mortem import diagnose_unexpected_winws_exit
from .process_monitor import ProcessMonitor
from .silent_exit_probe import format_silent_exit_message, probe_silent_exit
from .spawn_failure import classify_spawn_failure, is_silent_exit
from .system_ops import (
    _KNOWN_WINDIVERT_DRIVERS,
    _KNOWN_WINDIVERT_SERVICES,
    WinDivertRuntimeProbeResult,
    aggressive_windivert_cleanup,
    aggressive_windivert_cleanup_runtime,
    find_foreign_windivert_service_paths,
    find_foreign_windivert_service_paths_runtime,
    find_stale_windivert_delete_pending_services,
    find_stale_windivert_delete_pending_services_runtime,
    find_windivert_holder_processes,
    find_windivert_holder_processes_runtime,
    force_kill_all_winws,
    force_kill_all_winws_processes,
    get_all_winws_process_pids,
    get_process_pids_by_name,
    has_any_winws_process,
    kill_process_by_pid_runtime,
    probe_windivert_state,
    probe_windivert_state_runtime,
    restore_known_windivert_services_demand_start,
    restore_known_windivert_services_demand_start_runtime,
    standard_windivert_cleanup,
    standard_windivert_cleanup_runtime,
    unload_known_windivert_drivers,
    unload_known_windivert_drivers_runtime,
    wait_for_windivert_cleanup_settle,
    wait_for_windivert_cleanup_settle_runtime,
    wait_for_windivert_spawn_ready,
    wait_for_windivert_spawn_ready_runtime,
)
from .windivert_auto_fix import (
    clear_ensured_windivert_ready_cache,
    ensure_windivert_ready,
    ensure_windivert_ready_before_spawn,
    is_windivert_ready,
    windivert_driver_ready_with_fix,
)
from .windivert_diagnostics import (
    WINDIVERT_ERROR_TABLE,
    describe_windivert_conflict_hint,
    describe_windivert_error,
    format_windows_error_code,
    is_windivert_ready_stage,
)
from .winws_exit_diagnosis import (
    build_exit_code_suggestion_chain,
    build_winws_exit_diagnosis_entry,
    diagnose_winws_exit,
    make_exit_code_suggestion,
    suggest_verified_operation,
)
from .windows_event_log import list_defender_detections, recent_defender_flag_points
from .windows_system_dependencies import (
    has_wlanapi_missing,
    mark_windows_server_wlanapi_message,
    preflight_dependencies,
    run_windows_server_wlanapi_install,
    should_offer_windows_server_wlanapi_install,
)

__all__ = [
    "CONFLICTING_PROCESSES",
    "WINDIVERT_ERROR_TABLE",
    "WinDivertRuntimeProbeResult",
]