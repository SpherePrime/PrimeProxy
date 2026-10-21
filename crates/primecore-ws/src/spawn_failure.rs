//! Единая классификация сбоев запуска winws/winws2.
//!
//! Порт `winws_runtime/runners/spawn_failure.py`. Единственный источник правды
//! для «что это за сбой и стоит ли повторять запуск». Раннеры и их retry-
//! оркестрация спрашивают этот модуль вместо собственных разрозненных
//! предикатов по коду выхода и stderr. Классификация чистая относительно
//! бюджета ретраев: счётчики попыток остаются у вызывающего кода.

use crate::health::{diagnose_winws_exit, SystemProbes};
use crate::output::has_diagnostic_output;
use crate::windivert::{
    ERROR_DRIVER_BLOCKED, ERROR_DRIVER_FAILED_PRIOR_UNLOAD, ERROR_INVALID_IMAGE_HASH,
    ERROR_SERVICE_DEPENDENCY_FAIL, ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST,
    FWP_E_ALREADY_EXISTS, FWP_E_IN_USE,
};
use serde::{Deserialize, Serialize};

/// STATUS_DLL_INIT_FAILED: Windows killed the process before main() because one
/// of its DLLs failed to initialize. For winws this is a transient race right
/// after another winws/WinDivert instance exited, not a persistent breakage.
pub const STATUS_DLL_INIT_FAILED: i64 = 0xC000_0142_u32 as i64;

/// Фильтры WFP прошлого экземпляра ещё не убраны Windows (FWP_E_ALREADY_EXISTS,
/// FWP_E_IN_USE): остаточное состояние, которое проходит само или после
/// восстановления, а не действием пользователя. 9 — младший байт
/// FWP_E_ALREADY_EXISTS: столько отдаёт кодом завершения сборка winws на Cygwin.
/// Младший байт FWP_E_IN_USE (10) сюда не внесён: winws всегда печатает текст
/// этой ошибки, и она опознаётся по нему.
const WINDIVERT_CONFLICT_EXIT_CODES: [i64; 3] = [9, FWP_E_ALREADY_EXISTS, FWP_E_IN_USE];

const WINDIVERT_CONFLICT_SIGNATURES: [&str; 4] = [
    "guid or luid already exists",
    "object with that guid",
    "already running with the same filter",
    "referenced by other objects",
];

/// Errors that require user action (Secure Boot, AV, disabled service, ...)
/// and must not be retried. Codes 577, 1058, 1060, 1068, 1275, 654.
const WINDIVERT_SYSTEM_EXIT_CODES: [i64; 6] = [
    ERROR_INVALID_IMAGE_HASH,
    ERROR_SERVICE_DISABLED,
    ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_DEPENDENCY_FAIL,
    ERROR_DRIVER_BLOCKED,
    ERROR_DRIVER_FAILED_PRIOR_UNLOAD,
];

const WINDIVERT_SYSTEM_SIGNATURES: [&str; 6] = [
    "the service cannot be started",
    "service is disabled",
    "invalid image hash",
    "driver blocked",
    "disable secure boot",
    "driver failed prior unload",
];

/// Процесс, умерший с кодом 1 и не сказавший ни слова: собственные сбои
/// winws/winws2 всегда сопровождаются диагностикой в выводе, поэтому здесь
/// причину придётся искать вне процесса. Классификация фиксирует только сам
/// факт «умер молча»; чем это вызвано, устанавливает silent_exit_probe по
/// проверяемым признакам — угадывать причину на этом уровне нельзя.
const SILENT_EXIT_EXIT_CODES: [i64; 1] = [1];

/// Формулировка для пользователя, когда причина молчаливой смерти неизвестна.
pub const SILENT_EXIT_STATEMENT: &str = "процесс завершился без единого сообщения о причине";

/// diagnose_winws_exit() causes that mark a 1058 as a real system problem
/// rather than a residual stop/start race.
const HARD_1058_CAUSE_MARKERS: [&str; 6] = [
    "base filtering engine",
    "служба windivert отключена",
    "отсутствуют файлы windivert",
    "secure boot",
    "подпись драйвера",
    "политика безопасности",
];

/// Род сбоя запуска; значения строк — python-имена `SpawnFailureKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpawnFailureKind {
    TransientDllInit,
    WindivertConflict,
    WindivertServiceTransient,
    WindivertSystem,
    SilentExit,
    Unknown,
}

impl SpawnFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SpawnFailureKind::TransientDllInit => "transient_dll_init",
            SpawnFailureKind::WindivertConflict => "windivert_conflict",
            SpawnFailureKind::WindivertServiceTransient => "windivert_service_transient",
            SpawnFailureKind::WindivertSystem => "windivert_system",
            SpawnFailureKind::SilentExit => "silent_exit",
            SpawnFailureKind::Unknown => "unknown",
        }
    }
}

/// Классификация одного неудачного запуска.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnFailureClassification {
    pub kind: SpawnFailureKind,
    pub retryable: bool,
    pub needs_aggressive_cleanup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    /// Raw predicate flags. A failure can match several categories at once
    /// (e.g. 1058 is a system code AND may be a transient service race);
    /// retry orchestration checks these in its own historical order.
    pub is_transient_dll_init: bool,
    pub is_conflict: bool,
    pub is_system: bool,
    pub is_service_transient: bool,
    #[serde(default)]
    pub is_silent_exit: bool,
}

/// True when a 1058-family failure looks like a residual stop/start race.
///
/// WinDivert code 1058/34 sometimes surfaces right after stop/start even
/// though BFE, the service, and the driver are all healthy. Those cases are
/// worth one retry through a heavier cleanup. When diagnosis points at a real
/// system cause (BFE off, driver files missing, service disabled, Secure
/// Boot / driver signature / security policy) a retry cannot help.
fn is_soft_windivert_1058(exit_code: i64, stderr: &str, probes: &dyn SystemProbes) -> bool {
    let diag = diagnose_winws_exit(exit_code, stderr, probes);

    let win32_error = diag
        .as_ref()
        .and_then(|diag| diag.win32_error)
        .unwrap_or(exit_code);
    if win32_error != ERROR_SERVICE_DISABLED {
        return false;
    }

    let cause = diag
        .map(|diag| diag.cause.trim().to_lowercase())
        .unwrap_or_default();
    !HARD_1058_CAUSE_MARKERS
        .iter()
        .any(|marker| cause.contains(marker))
}

/// True для «умер молча с кодом 1».
///
/// Пустого вывода у winws2 не бывает — он всегда печатает баннер версии,
/// поэтому предикат опирается на наличие *диагностических* строк, а не на
/// непустой текст.
pub fn is_silent_exit(exit_code: i64, stderr: &str) -> bool {
    if !SILENT_EXIT_EXIT_CODES.contains(&exit_code) {
        return false;
    }
    !has_diagnostic_output(stderr)
}

/// Классифицирует неудачный запуск по коду выхода и stderr.
pub fn classify_spawn_failure(
    exit_code: i64,
    stderr: &str,
    probes: &dyn SystemProbes,
) -> SpawnFailureClassification {
    let stderr_text = stderr;
    let stderr_lower = stderr_text.to_lowercase();

    let is_transient_dll_init = exit_code == STATUS_DLL_INIT_FAILED;
    let is_conflict = WINDIVERT_CONFLICT_EXIT_CODES.contains(&exit_code)
        || WINDIVERT_CONFLICT_SIGNATURES
            .iter()
            .any(|sig| stderr_lower.contains(sig));
    let is_system = WINDIVERT_SYSTEM_EXIT_CODES.contains(&exit_code)
        || WINDIVERT_SYSTEM_SIGNATURES
            .iter()
            .any(|sig| stderr_lower.contains(sig));
    let is_service_transient = is_soft_windivert_1058(exit_code, stderr_text, probes);
    let silent_exit = is_silent_exit(exit_code, stderr_text);

    let kind = if is_transient_dll_init {
        SpawnFailureKind::TransientDllInit
    } else if is_service_transient {
        SpawnFailureKind::WindivertServiceTransient
    } else if is_system {
        SpawnFailureKind::WindivertSystem
    } else if is_conflict {
        SpawnFailureKind::WindivertConflict
    } else if silent_exit {
        SpawnFailureKind::SilentExit
    } else {
        SpawnFailureKind::Unknown
    };

    // SILENT_EXIT намеренно не retryable: чистка WinDivert к причине молчаливой
    // смерти отношения не имеет. Одноразовый повтор запуска (на случай разовой
    // гонки) остаётся решением конкретного раннера.
    let retryable = matches!(
        kind,
        SpawnFailureKind::TransientDllInit
            | SpawnFailureKind::WindivertServiceTransient
            | SpawnFailureKind::WindivertConflict
    );

    SpawnFailureClassification {
        kind,
        retryable,
        needs_aggressive_cleanup: retryable,
        user_message: if kind == SpawnFailureKind::SilentExit {
            Some(SILENT_EXIT_STATEMENT.to_string())
        } else {
            None
        },
        is_transient_dll_init,
        is_conflict,
        is_system,
        is_service_transient,
        is_silent_exit: silent_exit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::AssumedHealthyProbes;

    const BANNER: &str =
        "github version v1.0.3 (b78b52c4cd7f843da3ff0848a3430afbd401bdf2) lua_compat_ver 6";
    const WINDIVERT_ERROR: &str = "windivert: error opening filter: The service cannot be started";

    #[test]
    fn code_one_without_diagnostics_is_silent_exit() {
        assert!(is_silent_exit(1, ""));
        assert!(is_silent_exit(1, BANNER));
        assert!(is_silent_exit(1, format!("{BANNER}\n").as_str()));
    }

    #[test]
    fn other_failures_are_not_silent_exit() {
        assert!(!is_silent_exit(
            1,
            format!("{BANNER}\n{WINDIVERT_ERROR}").as_str()
        ));
        assert!(!is_silent_exit(9, ""));
        assert!(!is_silent_exit(0, ""));
        assert!(!is_silent_exit(STATUS_DLL_INIT_FAILED, BANNER));
    }

    #[test]
    fn classification_marks_silent_exit_without_retry_or_cleanup() {
        let classification = classify_spawn_failure(1, BANNER, &AssumedHealthyProbes);
        assert_eq!(classification.kind, SpawnFailureKind::SilentExit);
        assert!(classification.is_silent_exit);
        assert!(!classification.retryable);
        assert!(!classification.needs_aggressive_cleanup);
    }

    #[test]
    fn classification_never_guesses_a_cause() {
        // Уровень классификации не вправе называть виновника.
        let message = classify_spawn_failure(1, BANNER, &AssumedHealthyProbes)
            .user_message
            .unwrap_or_default()
            .to_lowercase();
        assert!(!message.contains("антивирус"));
        assert!(!message.contains("оптимизатор"));
    }

    #[test]
    fn conflict_output_still_wins_over_silent_exit() {
        let classification = classify_spawn_failure(
            1,
            &format!("{BANNER}\nA copy of winws2 is already running with the same filter"),
            &AssumedHealthyProbes,
        );
        assert_eq!(classification.kind, SpawnFailureKind::WindivertConflict);
        assert!(!classification.is_silent_exit);
        assert!(classification.retryable);
    }

    #[test]
    fn truncated_fwp_low_bytes_are_conflicts() {
        let classification = classify_spawn_failure(9, "", &AssumedHealthyProbes);
        assert_eq!(classification.kind, SpawnFailureKind::WindivertConflict);
        assert!(classification.retryable);
    }

    #[test]
    fn system_codes_are_not_retryable() {
        for code in [
            ERROR_INVALID_IMAGE_HASH,
            ERROR_SERVICE_DOES_NOT_EXIST,
            ERROR_SERVICE_DEPENDENCY_FAIL,
            ERROR_DRIVER_BLOCKED,
            ERROR_DRIVER_FAILED_PRIOR_UNLOAD,
        ] {
            let classification = classify_spawn_failure(code, "", &AssumedHealthyProbes);
            assert_eq!(
                classification.kind,
                SpawnFailureKind::WindivertSystem,
                "код {code}"
            );
            assert!(!classification.retryable, "код {code}");
        }
        // 1058 без вывода — мягкий остаточный сбой службы: классификация даёт
        // transient-категорию (один retry), хотя is_system тоже поднят.
        let classification =
            classify_spawn_failure(ERROR_SERVICE_DISABLED, "", &AssumedHealthyProbes);
        assert_eq!(
            classification.kind,
            SpawnFailureKind::WindivertServiceTransient
        );
        assert!(classification.retryable);
        assert!(classification.is_system);
    }

    #[test]
    fn dll_init_failure_is_transient() {
        let classification =
            classify_spawn_failure(STATUS_DLL_INIT_FAILED, BANNER, &AssumedHealthyProbes);
        assert_eq!(classification.kind, SpawnFailureKind::TransientDllInit);
        assert!(classification.retryable);
    }

    #[test]
    fn unknown_failures_are_unknown() {
        let classification = classify_spawn_failure(42, "misc", &AssumedHealthyProbes);
        assert_eq!(classification.kind, SpawnFailureKind::Unknown);
        assert!(!classification.retryable);
        assert!(classification.user_message.is_none());
    }
}
