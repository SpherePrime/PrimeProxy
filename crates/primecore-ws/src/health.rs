//! Диагностика кодов завершения winws/winws2 и молчаливых смертей процесса.
//!
//! Порт `winws_runtime/health/winws_exit_diagnosis.py` и чистой части
//! `winws_runtime/health/silent_exit_probe.py`. Handler-функции берут базовые
//! тексты причин/решений из единой таблицы [`windivert::WINDIVERT_ERROR_TABLE`]
//! и дополняют их динамическими probe-уточнениями (BFE, Secure Boot, файлы
//! драйвера, антивирус, сетевые адаптеры).
//!
//! Сами пробы — платформенные (реестр, диспетчер служб, журналы Windows), поэтому
//! в крейте они описаны трейтом [`SystemProbes`] с «оптимистичными» значениями по
//! умолчанию: как и в python, любая неудавшаяся проба трактуется как «всё в
//! норме», чтобы диагностика не слепала целиком из-за одного сбоя чтения.

use crate::output::{has_diagnostic_output, relevant_error_line, FallbackLine};
use crate::windivert::{
    windivert_error_record, ERROR_ACCESS_DENIED, ERROR_BAD_PATHNAME, ERROR_DRIVER_BLOCKED,
    ERROR_DRIVER_FAILED_PRIOR_UNLOAD, ERROR_GEN_FAILURE, ERROR_INVALID_IMAGE_HASH,
    ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_PROCESS_ABORTED,
    ERROR_SERVICE_DEPENDENCY_FAIL, ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST,
    FWP_E_ALREADY_EXISTS, FWP_E_IN_USE,
};
use serde::{Deserialize, Serialize};

/// Строгость диагноза: python-строки «critical»/«warning».
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    #[default]
    Critical,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
        }
    }
}

/// Structured result of WinDivert error diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDivertDiagnosis {
    /// Human-readable cause.
    pub cause: String,
    /// What the user should do.
    pub solution: String,
    /// Action ID: "enable_adapters", "enable_bfe", "cleanup_driver", None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_fix: Option<String>,
    #[serde(default)]
    pub severity: Severity,
    /// Original exit code.
    #[serde(default)]
    pub exit_code: i64,
    /// Mapped Win32 error (may differ from exit_code).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<i64>,
    /// True, когда win32_error не измерен, а восстановлен эвристикой из
    /// усечённого кода завершения (34 → 1058). Такой код и построенная на нём
    /// причина обязаны показываться пользователю как предположение.
    #[serde(default)]
    pub win32_error_inferred: bool,
    /// False, когда известен сам тип сбоя, но исходный Win32-код уже потерян
    /// внутри winws2. В таком случае нельзя писать пользователю «Найдена причина».
    #[serde(default = "default_true")]
    pub cause_is_exact: bool,
}

fn default_true() -> bool {
    true
}

impl WinDivertDiagnosis {
    pub fn new(cause: impl Into<String>, solution: impl Into<String>, severity: Severity) -> Self {
        Self {
            cause: cause.into(),
            solution: solution.into(),
            auto_fix: None,
            severity,
            exit_code: 0,
            win32_error: None,
            win32_error_inferred: false,
            cause_is_exact: true,
        }
    }
}

/// Платформенные пробы для диагностики падения winws.
///
/// Значения по умолчанию повторяют поведение python-кода «проба не удалась»:
/// проверка считается пройденной (или неприменимой), чтобы диагноз не исчезал
/// целиком из-за одного сбоя чтения состояния системы.
pub trait SystemProbes {
    /// Отсутствующие критичные файлы WinDivert (пусто — всё на месте).
    fn windivert_files_missing(&self) -> Vec<String> {
        Vec::new()
    }

    /// Служба Base Filtering Engine запущена.
    fn bfe_running(&self) -> bool {
        true
    }

    /// Secure Boot включён (через реестр).
    fn secure_boot_enabled(&self) -> bool {
        false
    }

    /// Программа запущена с правами администратора. `None` — проверить не удалось.
    fn is_user_admin(&self) -> Option<bool> {
        None
    }

    /// Запись службы драйвера, застрявшая после остановки.
    fn stuck_windivert_driver_service(&self) -> Option<String> {
        None
    }

    /// Совет о конфликте запуска (чужой процесс/программа на WinDivert).
    fn launch_conflict_advice(&self) -> Option<(String, String)> {
        None
    }

    /// Активный сторонний антивирус, если найден.
    fn detect_active_antivirus(&self) -> Option<String> {
        None
    }

    /// Хотя бы один сетевой адаптер включён.
    fn network_adapter_connected(&self) -> bool {
        true
    }

    /// Состояние WinDivert после probe-запуска: `None` — проба недоступна.
    fn windivert_probe_state(&self) -> Option<WindivertProbeState> {
        None
    }

    /// Файл `lua/<файл>`, в котором определена функция `--lua-desync`, если она
    /// известна каталогу (`None` — функции нет ни в одном файле).
    fn lua_function_file(&self, _name: &str) -> Option<String> {
        None
    }

    /// Похожие имена lua-функций для подсказки об опечатке.
    fn lua_function_suggestions(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Состояние службы/фильтра WinDivert из probe-запуска.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindivertProbeState {
    pub installed: bool,
    pub ready: bool,
    pub error_code: Option<i64>,
}

/// Системные пробы «всё в норме» — python-ветки `except Exception: return True`.
pub struct AssumedHealthyProbes;

impl SystemProbes for AssumedHealthyProbes {}

/// Собирает подробную, но понятную ошибку для верхнего InfoBar.
///
/// Код завершения процесса Windows иногда обрезает до одного байта: например,
/// WinDivert возвращает 1058, а `winws2.exe` завершается с кодом 34. Поэтому
/// пользователю важно показать оба значения и не подменять причину первой
/// служебной строкой вывода `winws`.
///
/// Измеренное и предположенное разделены: если Win32-код не получен от
/// процесса, а восстановлен эвристикой (`win32_error_inferred`), он
/// показывается как предположение и стоит после фактического кода завершения,
/// а причина подаётся как вероятная, а не как установленная.
pub fn format_winws_exit_diagnosis(diagnosis: &WinDivertDiagnosis, exe_name: &str) -> String {
    let executable = {
        let trimmed = exe_name.trim();
        if trimmed.is_empty() {
            "winws"
        } else {
            trimmed
        }
    };
    let cause = diagnosis.cause.trim().trim_end_matches('.').to_string();
    let solution = diagnosis.solution.trim().trim_end_matches('.').to_string();
    let inferred = diagnosis.win32_error_inferred;
    let cause_is_exact = diagnosis.cause_is_exact;

    let exit_code = diagnosis.exit_code;
    let win32_error = diagnosis.win32_error;

    let mut code_parts: Vec<String> = Vec::new();
    if let Some(win32_error) = win32_error {
        let win32_text = crate::windivert::format_windows_error_code(win32_error);
        if exit_code != 0 && exit_code != win32_error {
            let exit_text = crate::windivert::format_windows_error_code(exit_code);
            if inferred {
                // Измеренный факт первым, восстановленный код — как догадка.
                code_parts.push(format!("код завершения процесса {exit_text}"));
                code_parts.push(format!("предположительно код ошибки Windows {win32_text}"));
            } else {
                code_parts.push(format!("код ошибки Windows {win32_text}"));
                code_parts.push(format!("код завершения процесса {exit_text}"));
            }
        } else {
            code_parts.push(format!("код ошибки {win32_text}"));
        }
    } else if exit_code != 0 {
        code_parts.push(format!(
            "код завершения процесса {}",
            crate::windivert::format_windows_error_code(exit_code)
        ));
    }

    let mut message = format!("{executable} не запустился");
    if !cause.is_empty() {
        let cause_label = if !cause_is_exact {
            "Что известно"
        } else if inferred {
            "Вероятная причина"
        } else {
            "Найдена причина"
        };
        message = format!("{message}. {cause_label}: {cause}");
    }
    if !code_parts.is_empty() {
        message = format!("{message} ({})", code_parts.join("; "));
    }
    if !solution.is_empty() {
        message = format!("{message}. Что сделать: {solution}");
    }

    let auto_fix = diagnosis
        .auto_fix
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    if !auto_fix.is_empty() {
        message = format!("[AUTOFIX:{auto_fix}]{message}");
    }
    message
}

/// Базовый диагноз из единой таблицы кодов (без динамических уточнений).
fn diagnosis_from_table(code: i64, severity: Severity) -> Option<WinDivertDiagnosis> {
    windivert_error_record(code).map(|record| WinDivertDiagnosis {
        cause: record.cause.to_string(),
        solution: record.solution.to_string(),
        auto_fix: record.auto_fix_action.map(str::to_string),
        severity,
        exit_code: 0,
        win32_error: None,
        win32_error_inferred: false,
        cause_is_exact: true,
    })
}

/// stderr patterns → Win32 error mapping (for when exit code is truncated).
const STDERR_TO_WIN32: [(&str, i64); 20] = [
    ("the service cannot be started", ERROR_SERVICE_DISABLED),
    ("service is disabled", ERROR_SERVICE_DISABLED),
    ("no enabled devices", ERROR_SERVICE_DISABLED),
    ("access is denied", ERROR_ACCESS_DENIED),
    ("access denied", ERROR_ACCESS_DENIED),
    ("hash for file is not valid", ERROR_INVALID_IMAGE_HASH),
    ("invalid image hash", ERROR_INVALID_IMAGE_HASH),
    ("disable secure boot", ERROR_INVALID_IMAGE_HASH),
    ("driver blocked", ERROR_DRIVER_BLOCKED),
    ("blocked from loading", ERROR_DRIVER_BLOCKED),
    (
        "driver failed prior unload",
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD,
    ),
    // Остатки фильтров WFP от прошлого запуска. Сборка winws на Cygwin отдаёт
    // кодом завершения только младший байт (9 и 10), поэтому опознаём по тексту.
    ("guid or luid already exists", FWP_E_ALREADY_EXISTS),
    ("object with that guid", FWP_E_ALREADY_EXISTS),
    ("referenced by other objects", FWP_E_IN_USE),
    ("bad pathname", ERROR_BAD_PATHNAME),
    ("service does not exist", ERROR_SERVICE_DOES_NOT_EXIST),
    ("dependency service", ERROR_SERVICE_DEPENDENCY_FAIL),
    ("process terminated unexpectedly", ERROR_PROCESS_ABORTED),
    ("not enough memory", ERROR_NOT_ENOUGH_MEMORY),
    ("insufficient resources", ERROR_NOT_ENOUGH_MEMORY),
    // ("parameter is incorrect", ERROR_INVALID_PARAMETER) — добавляется ниже,
    // чтобы сохранить порядок python-списка.
];

const STDERR_TO_WIN32_TAIL: [(&str, i64); 2] = [
    ("parameter is incorrect", ERROR_INVALID_PARAMETER),
    (
        "a device attached to the system is not functioning",
        ERROR_GEN_FAILURE,
    ),
];

fn stderr_to_win32_pairs() -> impl Iterator<Item = (&'static str, i64)> {
    STDERR_TO_WIN32
        .iter()
        .chain(STDERR_TO_WIN32_TAIL.iter())
        .copied()
}

/// Самая содержательная строка вывода (см. output — единый разбор).
fn extract_relevant_error_line(stderr: &str) -> String {
    relevant_error_line(stderr, FallbackLine::First)
}

/// Diagnose winws2 exit code + stderr and return structured result.
///
/// The exit code of winws2 equals the raw Win32 GetLastError() value after
/// WinDivertOpen() fails. However, the exit code may be truncated to 8 bits
/// in some scenarios (e.g. 1058 → 34). Therefore stderr text is parsed first
/// as the primary signal, and exit_code is used as fallback.
///
/// Returns `None` if exit_code is 0 (success) or diagnosis is not applicable.
pub fn diagnose_winws_exit(
    exit_code: i64,
    stderr: &str,
    probes: &dyn SystemProbes,
) -> Option<WinDivertDiagnosis> {
    if exit_code == 0 {
        return None;
    }

    let stderr_lower = stderr.to_lowercase();

    // В zapret2 v1.0.3 и в текущем upstream после неудачного
    // GetOverlappedResult() не сохраняется новый GetLastError(). В результате
    // остаётся предыдущее штатное ERROR_IO_PENDING (997), а Cygwin-процесс
    // завершает работу усечённым кодом 229. Это не ERROR_PIPE_LOCAL и не
    // самостоятельная причина WinDivert — исходный Win32-код уже утрачен.
    if exit_code == 229
        && stderr_lower.contains("windivert: recv failed")
        && stderr_lower.contains("errno 5")
    {
        return Some(WinDivertDiagnosis {
            exit_code,
            win32_error: None,
            cause_is_exact: false,
            cause:
                ("winws2 сообщил «windivert: recv failed. errno 5»: асинхронное чтение пакетов \
                 из WinDivert завершилось ошибкой, но winws2 потерял исходный код Windows. \
                 Код 229 — усечённый остаток штатного ERROR_IO_PENDING (997), а не причина \
                 сбоя WinDivert")
                    .to_string(),
            solution: ("Закройте другие программы, использующие WinDivert, и повторите запуск. \
                 Если активен только один winws2, перезагрузите Windows. \
                 Полный вывод winws2 сохранён в журнале программы")
                .to_string(),
            auto_fix: None,
            severity: Severity::Critical,
            win32_error_inferred: false,
        });
    }

    // 1. Resolve the real Win32 error from stderr text (more reliable)
    let mut win32_error = exit_code;
    let mut win32_error_inferred = false;
    for (pattern, code) in stderr_to_win32_pairs() {
        if stderr_lower.contains(pattern) {
            win32_error = code;
            break;
        }
    }

    // Winws2 can return the raw Win32 error truncated to one byte.
    // ERROR_SERVICE_DISABLED 1058 becomes process exit code 34, often without
    // stderr in GUI launch mode. Treat that as the same driver-service failure.
    // «Без stderr» здесь означает «без диагностики»: служебный баннер версии
    // winws2 печатает всегда, и раньше он один ломал эту ветку.
    // Это единственная ветка, где Win32-код не измерен, а угадан, поэтому она
    // помечает диагноз как предположительный.
    if win32_error == 34 && !has_diagnostic_output(stderr) {
        win32_error = ERROR_SERVICE_DISABLED;
        win32_error_inferred = true;
    }

    // 2. Dispatch to specific handlers
    if let Some(mut diag) = dispatch_exit_code_handler(win32_error, exit_code, stderr, probes) {
        diag.exit_code = exit_code;
        diag.win32_error = Some(win32_error);
        diag.win32_error_inferred = win32_error_inferred;
        return Some(diag);
    }

    // 3. Fallback: generic WinDivert error
    if stderr_lower.contains("windivert") || stderr_lower.contains("error opening filter") {
        let first_line = extract_relevant_error_line(stderr);
        let first_line = first_line.chars().take(200).collect::<String>();
        return Some(WinDivertDiagnosis {
            cause: format!(
                "Ошибка WinDivert (код {})",
                crate::windivert::format_windows_error_code(exit_code)
            ),
            solution: if first_line.is_empty() {
                "Перезагрузите компьютер и попробуйте снова".to_string()
            } else {
                first_line
            },
            severity: Severity::Critical,
            exit_code,
            win32_error: Some(win32_error),
            win32_error_inferred,
            auto_fix: None,
            cause_is_exact: true,
        });
    }

    None
}

fn dispatch_exit_code_handler(
    win32_error: i64,
    exit_code: i64,
    stderr: &str,
    probes: &dyn SystemProbes,
) -> Option<WinDivertDiagnosis> {
    match win32_error {
        ERROR_SERVICE_DISABLED => Some(handle_service_disabled(probes)),
        ERROR_INVALID_IMAGE_HASH => Some(handle_invalid_image_hash(probes)),
        ERROR_ACCESS_DENIED => Some(handle_access_denied(probes)),
        ERROR_DRIVER_BLOCKED => diagnosis_from_table(ERROR_DRIVER_BLOCKED, Severity::Critical),
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD => {
            diagnosis_from_table(ERROR_DRIVER_FAILED_PRIOR_UNLOAD, Severity::Critical)
        }
        ERROR_SERVICE_DOES_NOT_EXIST => Some(handle_service_not_exist(probes)),
        ERROR_SERVICE_DEPENDENCY_FAIL => Some(handle_dependency_fail(probes)),
        ERROR_NOT_ENOUGH_MEMORY => diagnosis_from_table(ERROR_NOT_ENOUGH_MEMORY, Severity::Warning),
        ERROR_GEN_FAILURE => Some(handle_gen_failure(probes)),
        ERROR_INVALID_PARAMETER => Some(handle_invalid_parameter(exit_code, stderr, probes)),
        ERROR_BAD_PATHNAME => Some(handle_bad_pathname(probes)),
        ERROR_PROCESS_ABORTED => diagnosis_from_table(ERROR_PROCESS_ABORTED, Severity::Critical),
        FWP_E_ALREADY_EXISTS => Some(diagnose_wfp_leftovers(FWP_E_ALREADY_EXISTS, probes)),
        FWP_E_IN_USE => Some(diagnose_wfp_leftovers(FWP_E_IN_USE, probes)),
        _ => None,
    }
}

/// ERROR_SERVICE_DISABLED (1058) — the most common WinDivert error.
fn handle_service_disabled(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    // Run sub-checks to narrow down the cause
    let (cause, solution, auto_fix) = probe_service_disabled_cause(probes);
    WinDivertDiagnosis {
        cause,
        solution,
        auto_fix,
        severity: Severity::Critical,
        exit_code: 0,
        win32_error: None,
        win32_error_inferred: false,
        cause_is_exact: true,
    }
}

fn handle_invalid_image_hash(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    if probes.secure_boot_enabled() {
        return WinDivertDiagnosis::new(
            "Secure Boot блокирует загрузку драйвера WinDivert",
            "Отключите Secure Boot в BIOS/UEFI настройках",
            Severity::Critical,
        );
    }
    diagnosis_from_table(ERROR_INVALID_IMAGE_HASH, Severity::Critical)
        .expect("код 577 есть в таблице")
}

fn handle_access_denied(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    if probes.is_user_admin() == Some(false) {
        return WinDivertDiagnosis::new(
            "Программа запущена без прав администратора",
            "Запустите программу от имени администратора",
            Severity::Critical,
        );
    }
    if let Some((cause, solution)) = probes.launch_conflict_advice() {
        return WinDivertDiagnosis::new(cause, solution, Severity::Critical);
    }
    diagnosis_from_table(ERROR_ACCESS_DENIED, Severity::Critical).expect("код 5 есть в таблице")
}

fn handle_service_not_exist(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    // Check if WinDivert files exist
    let missing = probes.windivert_files_missing();
    if !missing.is_empty() {
        return WinDivertDiagnosis::new(
            format!("Отсутствуют файлы WinDivert: {}", missing.join(", ")),
            "Переустановите программу или восстановите файлы из архива",
            Severity::Critical,
        );
    }
    diagnosis_from_table(ERROR_SERVICE_DOES_NOT_EXIST, Severity::Critical)
        .expect("код 1060 есть в таблице")
}

fn handle_dependency_fail(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    if !probes.bfe_running() {
        return WinDivertDiagnosis {
            cause: "Служба Base Filtering Engine (BFE) не запущена".to_string(),
            solution: "Включите BFE: sc config BFE start= auto && net start BFE".to_string(),
            auto_fix: Some("enable_bfe".to_string()),
            severity: Severity::Critical,
            exit_code: 0,
            win32_error: None,
            win32_error_inferred: false,
            cause_is_exact: true,
        };
    }
    diagnosis_from_table(ERROR_SERVICE_DEPENDENCY_FAIL, Severity::Critical)
        .expect("код 1068 есть в таблице")
}

fn handle_gen_failure(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    if !probes.network_adapter_connected() {
        return WinDivertDiagnosis {
            cause: "Все сетевые адаптеры отключены".to_string(),
            solution: "Включите хотя бы один сетевой адаптер".to_string(),
            auto_fix: Some("enable_adapters".to_string()),
            severity: Severity::Critical,
            exit_code: 0,
            win32_error: None,
            win32_error_inferred: false,
            cause_is_exact: true,
        };
    }
    diagnosis_from_table(ERROR_GEN_FAILURE, Severity::Critical).expect("код 31 есть в таблице")
}

fn handle_invalid_parameter(
    exit_code: i64,
    stderr: &str,
    probes: &dyn SystemProbes,
) -> WinDivertDiagnosis {
    let stderr_lower = stderr.to_lowercase();

    if stderr_lower.contains("incompatible nfqws2_compat_ver") {
        return WinDivertDiagnosis::new(
            "winws2.exe и Lua-скрипты от разных версий",
            "Обновите папку lua вместе с winws2.exe или переустановите программу",
            Severity::Critical,
        );
    }

    if stderr_lower.contains("windivert") && stderr_lower.contains("error opening filter") {
        if stderr_lower.contains("the service cannot be started")
            || stderr_lower.contains("service is disabled")
        {
            return handle_service_disabled(probes);
        }
        return WinDivertDiagnosis::new(
            "WinDivert не смог открыть фильтр",
            {
                let line = extract_relevant_error_line(stderr);
                if line.is_empty() {
                    "Проверьте состояние драйвера WinDivert".to_string()
                } else {
                    line
                }
            },
            Severity::Critical,
        );
    }

    if let Some(func_name) = missing_lua_function_name(stderr) {
        return diagnose_missing_lua_function(&func_name, probes);
    }

    // Lua script syntax/runtime error
    if stderr_lower.contains("lua")
        && (stderr_lower.contains("error") || stderr_lower.contains("syntax"))
    {
        return WinDivertDiagnosis::new(
            "Ошибка в Lua-скрипте",
            "Переустановите программу или проверьте файлы в папке lua/",
            Severity::Critical,
        );
    }

    let _ = exit_code;
    diagnosis_from_table(ERROR_INVALID_PARAMETER, Severity::Warning).expect("код 87 есть в таблице")
}

/// Имя функции из сообщения «desync function 'X' does not exist».
fn missing_lua_function_name(stderr: &str) -> Option<String> {
    const PREFIX: &str = "desync function '";
    let start = stderr.find(PREFIX)? + PREFIX.len();
    let rest = &stderr[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// winws2: «desync function 'X' does not exist» — функции X нет в загруженных lua.
///
/// Отсутствующий на диске lua-файл winws2 сообщает раньше и другим текстом
/// (LUA file ... not accessible), поэтому здесь две причины: функция из
/// известного файла, который пресет не подключил, или опечатка в имени.
/// Справочник функций приходит через [`SystemProbes`] (в python —
/// `profile.winws2_language.lua_catalog`).
fn diagnose_missing_lua_function(func_name: &str, probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    if let Some(file) = probes.lua_function_file(func_name) {
        let lua_init = format!("--lua-init=@lua/{file}");
        return WinDivertDiagnosis::new(
            format!(
                "Lua-функция «{func_name}» есть в файле lua/{file}, но пресет этот файл не подключает"
            ),
            format!(
                "Добавьте в начало пресета строку {lua_init} — в редакторе пресета это сделает Ctrl+. \
                 на подчёркнутой строке. Если такая строка уже есть, файл повреждён: переустановите программу"
            ),
            Severity::Critical,
        );
    }
    let suggestions = probes.lua_function_suggestions(func_name);
    if let Some(first) = suggestions.first() {
        return WinDivertDiagnosis::new(
            format!(
                "В пресете опечатка: Lua-функции «{func_name}» не существует. \
                 Возможно, имелось в виду «{first}»"
            ),
            format!(
                "Исправьте в строке --lua-desync имя «{func_name}» на «{first}» — \
                 в редакторе пресета строка подчёркнута, Ctrl+. исправит её"
            ),
            Severity::Critical,
        );
    }
    WinDivertDiagnosis::new(
        format!("Lua-функции «{func_name}» нет ни в одном lua-файле программы"),
        "Проверьте имя функции в строке --lua-desync или подключите свой lua-файл \
         с этой функцией через --lua-init",
        Severity::Critical,
    )
}

fn handle_bad_pathname(probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    let missing = probes.windivert_files_missing();
    let mut diagnosis = diagnosis_from_table(ERROR_BAD_PATHNAME, Severity::Critical)
        .expect("код 161 есть в таблице");
    if !missing.is_empty() {
        diagnosis.cause = format!("{}: {}", diagnosis.cause, missing.join(", "));
    }
    diagnosis
}

/// Фильтры WFP от прошлого запуска ещё не убраны или их держит чужая программа.
///
/// Базовый текст общий, а подсказка о конфликте называет виновника по имени,
/// если его удалось найти.
fn diagnose_wfp_leftovers(code: i64, probes: &dyn SystemProbes) -> WinDivertDiagnosis {
    let mut diagnosis = diagnosis_from_table(code, Severity::Critical)
        .unwrap_or_else(|| WinDivertDiagnosis::new("Ошибка WinDivert", "", Severity::Critical));
    let hint = launch_conflict_hint(probes);
    if !hint.is_empty() {
        diagnosis.solution = format!("{hint}. {}", diagnosis.solution);
    }
    diagnosis
}

/// Подсказка о конфликте WinDivert — только в ветке ошибки (python
/// `describe_windivert_conflict_hint` через `launch_conflicts`). Здесь это
/// причина из [`SystemProbes::launch_conflict_advice`].
fn launch_conflict_hint(probes: &dyn SystemProbes) -> String {
    probes
        .launch_conflict_advice()
        .map(|(cause, _)| cause)
        .unwrap_or_default()
}

/// Narrow down why «service cannot be started» (1058).
///
/// Returns (cause, solution, auto_fix_action).
fn probe_service_disabled_cause(probes: &dyn SystemProbes) -> (String, String, Option<String>) {
    // Check 1: WinDivert files missing (AV quarantine)
    let missing = probes.windivert_files_missing();
    if !missing.is_empty() {
        return (
            format!(
                "Файлы WinDivert отсутствуют (возможно удалены антивирусом): {}",
                missing.join(", ")
            ),
            "Добавьте папку программы в исключения антивируса и переустановите".to_string(),
            None,
        );
    }

    // Check 2: BFE service
    if !probes.bfe_running() {
        return (
            "Служба Base Filtering Engine (BFE) отключена — WinDivert зависит от неё".to_string(),
            "Включите BFE: sc config BFE start= auto && net start BFE".to_string(),
            Some("enable_bfe".to_string()),
        );
    }

    // Check 3: запись службы драйвера застряла после остановки
    if let Some(stuck_driver) = probes.stuck_windivert_driver_service() {
        return (
            format!(
                "Запись службы драйвера WinDivert ({stuck_driver}) осталась после остановки: \
                 её держит открытой другая программа"
            ),
            "Закройте окно «Службы», Process Hacker, Process Explorer и другие программы \
             обхода блокировок и повторите запуск; если не поможет — перезагрузите компьютер"
                .to_string(),
            None,
        );
    }

    // Check 4: конфликт запуска (в python — Kaspersky и другие программы обхода)
    if let Some((cause, solution)) = probes.launch_conflict_advice() {
        return (cause, solution, None);
    }

    // Check 5: Antivirus
    if let Some(av) = probes.detect_active_antivirus() {
        return (
            format!("Антивирус ({av}) может блокировать загрузку драйвера WinDivert"),
            "Добавьте папку программы в исключения антивируса".to_string(),
            None,
        );
    }

    // Check 6: Network adapters. This check must be late because Win32 1058
    // is a generic service-disabled error and otherwise easily turns into a
    // ложный диагноз про адаптеры.
    if !probes.network_adapter_connected() {
        return (
            "Не найден ни один активный сетевой адаптер — WinDivert не к чему привязаться"
                .to_string(),
            "Включите хотя бы один сетевой адаптер в системе и повторите запуск".to_string(),
            Some("enable_adapters".to_string()),
        );
    }

    // Check 7: драйвер зарегистрирован, но фильтр открыть нельзя.
    //
    // Проверка стоит последней намеренно. Probe выполняется уже после смерти
    // winws2 и с флагом NO_INSTALL, а WinDivert по умолчанию снимает свою
    // службу при закрытии последнего дескриптора. Поэтому «службы нет»
    // (ERROR_SERVICE_DOES_NOT_EXIST) — это обычное состояние покоя, а не
    // причина отказа: раньше эта ветка стояла четвёртой, срабатывала почти на
    // каждом падении 34/1058 и глушила проверки Kaspersky/антивируса/адаптеров.
    // Диагностическую ценность имеет только обратный случай: служба есть, а
    // NETWORK layer всё равно не открывается.
    if let Some(probe) = probes.windivert_probe_state() {
        if probe.installed && !probe.ready {
            let probe_code_suffix = probe
                .error_code
                .map(|code| format!(" (код {code})"))
                .unwrap_or_default();
            return (
                format!(
                    "WinDivert ещё не готов после предыдущего запуска или очистки{probe_code_suffix}"
                ),
                "Подождите пару секунд и попробуйте снова. Если повторяется — перезапустите \
                 программу или ПК"
                    .to_string(),
                None,
            );
        }
    }

    // Fallback: базовый текст 1058 из единой таблицы.
    let record = windivert_error_record(ERROR_SERVICE_DISABLED).expect("код 1058 в таблице");
    (
        record.cause.to_string(),
        record.solution.to_string(),
        record.auto_fix_action.map(str::to_string),
    )
}

// ---------------------------------------------------------------------------
//  Молчаливое завершение: пробы по проверяемым фактам (silent_exit_probe)
// ---------------------------------------------------------------------------

/// Окна поиска в журналах: авария процесса ищется вокруг только что случившегося
/// отказа, срабатывание антивируса могло произойти чуть раньше — при подготовке
/// запуска.
pub const APPLICATION_ERROR_WINDOW_MINUTES: u32 = 2;
pub const DEFENDER_WINDOW_MINUTES: u32 = 5;

/// Одна находка. `confirmed` — установленный факт, иначе подозрение.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilentExitFinding {
    pub fact: String,
    #[serde(default)]
    pub solution: String,
    #[serde(default)]
    pub confirmed: bool,
}

/// Отчёт проб молчаливого отказа: находки и то, что проверено и в норме.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilentExitReport {
    #[serde(default)]
    pub findings: Vec<SilentExitFinding>,
    #[serde(default)]
    pub verified: Vec<String>,
}

impl SilentExitReport {
    pub fn confirmed(&self) -> Vec<&SilentExitFinding> {
        self.findings.iter().filter(|f| f.confirmed).collect()
    }

    pub fn suspected(&self) -> Vec<&SilentExitFinding> {
        self.findings.iter().filter(|f| !f.confirmed).collect()
    }

    pub fn log_summary(&self) -> String {
        let facts = self
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{}: {}",
                    if finding.confirmed { "FACT" } else { "SUSPECT" },
                    finding.fact
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let checked = self.verified.join("; ");
        match (!facts.is_empty(), !checked.is_empty()) {
            (true, true) => format!("{facts} | проверено и в норме: {checked}"),
            (true, false) => facts,
            (false, true) => format!("проверено и в норме: {checked}"),
            (false, false) => "проверок не выполнено".to_string(),
        }
    }
}

/// Результат одной пробы: находка, «чисто» или «проверить не удалось».
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Проба не состоялась: ни находки, ни права сказать «здесь всё в норме».
    Unavailable,
    /// Проверено, проблем нет.
    Clean,
    Finding(SilentExitFinding),
}

/// Платформенные пробы молчаливой смерти процесса (журналы Windows).
///
/// Проверки файлов — обычный `std::fs`, они реализованы в самой функции
/// [`run_silent_exit_probes`]; здесь остаются только журнал Windows и антивирус.
pub trait SilentExitProbes {
    /// Отсутствующие критичные файлы WinDivert (пусто — всё на месте).
    fn windivert_files_missing(&self) -> Vec<String> {
        Vec::new()
    }

    /// Запись Application Error/WER о недавней аварии процесса.
    fn application_error_event(&self, _process_name: &str) -> ProbeResult {
        ProbeResult::Unavailable
    }

    /// Недавние срабатывания Defender по файлам программы.
    fn defender_detection(&self, _exe_path: &str) -> ProbeResult {
        ProbeResult::Unavailable
    }

    /// Активный сторонний антивирус, если найден.
    fn active_antivirus(&self) -> Option<String> {
        None
    }
}

/// Пробы «всё в норме»: как python-ветки `except Exception`, отчёт без находок.
pub struct SilentExitProbesUnavailable;

impl SilentExitProbes for SilentExitProbesUnavailable {}

fn probe_executable_missing(exe_path: &str) -> Option<SilentExitFinding> {
    let path = exe_path.trim();
    if path.is_empty() {
        return None;
    }
    if std::path::Path::new(path).is_file() {
        return None;
    }
    let base = std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let shown = if base.is_empty() { path } else { &base };
    Some(SilentExitFinding {
        fact: format!("исполняемый файл исчез с диска ({shown})"),
        solution: ("Восстановите файл из карантина антивируса, добавьте папку программы \
             в исключения и переустановите программу")
            .to_string(),
        confirmed: true,
    })
}

fn probe_windivert_files_missing(probes: &dyn SilentExitProbes) -> Option<SilentExitFinding> {
    let missing = probes.windivert_files_missing();
    if missing.is_empty() {
        return None;
    }
    Some(SilentExitFinding {
        fact: format!("отсутствуют файлы WinDivert: {}", missing.join(", ")),
        solution: ("Восстановите файлы из карантина антивируса, добавьте папку программы \
             в исключения и переустановите программу")
            .to_string(),
        confirmed: true,
    })
}

/// Запись Application Error/WER = процесс упал сам, а не был закрыт извне.
fn probe_application_error_event(
    probes: &dyn SilentExitProbes,
    process_name: &str,
) -> Option<SilentExitFinding> {
    let name = process_name.trim();
    if name.is_empty() {
        return None;
    }
    match probes.application_error_event(name) {
        ProbeResult::Clean => None,
        ProbeResult::Finding(finding) => Some(finding),
        ProbeResult::Unavailable => None,
    }
}

fn probe_antivirus_present(probes: &dyn SilentExitProbes) -> Option<SilentExitFinding> {
    let antivirus = probes.active_antivirus()?;
    Some(SilentExitFinding {
        fact: format!("в системе активен антивирус ({antivirus}) — он мог закрыть процесс"),
        solution: "Проверьте карантин антивируса и добавьте папку программы в его исключения"
            .to_string(),
        confirmed: false,
    })
}

/// Собирает факты о молчаливом отказе по проверяемым признакам.
///
/// Неприменимую пробу нельзя записывать в «проверено и в норме»: без пути к exe
/// мы не знаем, на месте ли он, и обязаны молчать об этом.
pub fn run_silent_exit_probes(
    probes: &dyn SilentExitProbes,
    exe_path: &str,
    process_name: &str,
) -> SilentExitReport {
    let exe_path = exe_path.trim();
    let mut findings: Vec<SilentExitFinding> = Vec::new();
    let mut verified: Vec<String> = Vec::new();

    let mut checks: Vec<(&str, ProbeResult)> = Vec::new();
    if !exe_path.is_empty() {
        let result = match probe_executable_missing(exe_path) {
            Some(finding) => ProbeResult::Finding(finding),
            None => ProbeResult::Clean,
        };
        checks.push(("файлы программы на месте", result));
    }
    checks.push((
        "файлы WinDivert на месте",
        match probe_windivert_files_missing(probes) {
            Some(finding) => ProbeResult::Finding(finding),
            None => ProbeResult::Clean,
        },
    ));
    if !process_name.is_empty() {
        checks.push((
            "в журнале Windows нет записи об аварийном завершении",
            match probe_application_error_event(probes, process_name) {
                Some(finding) => ProbeResult::Finding(finding),
                None => ProbeResult::Clean,
            },
        ));
    }
    if !exe_path.is_empty() {
        checks.push((
            "Defender по файлам программы не срабатывал",
            probes.defender_detection(exe_path),
        ));
    }
    checks.push((
        "сторонний антивирус не обнаружен",
        match probe_antivirus_present(probes) {
            Some(finding) => ProbeResult::Finding(finding),
            None => ProbeResult::Clean,
        },
    ));

    for (verified_text, result) in checks {
        match result {
            // Не смогли проверить — эта проверка просто не существует в отчёте.
            ProbeResult::Unavailable => {}
            ProbeResult::Clean => verified.push(verified_text.to_string()),
            ProbeResult::Finding(finding) => findings.push(finding),
        }
    }

    SilentExitReport { findings, verified }
}

/// Строит текст для пользователя строго по тому, что удалось установить.
pub fn format_silent_exit_message(
    report: &SilentExitReport,
    exe_name: &str,
    exit_code: i64,
    lifetime_seconds: Option<f64>,
) -> String {
    let executable = {
        let trimmed = exe_name.trim();
        if trimmed.is_empty() {
            "winws"
        } else {
            trimmed
        }
    };

    let lifetime = lifetime_seconds
        .map(|value| format!(", прожив {value:.1} с"))
        .unwrap_or_default();

    let base = format!(
        "{executable} завершился с кодом {exit_code}{lifetime}, не выдав ни одного сообщения"
    );

    if let Some(finding) = report.confirmed().first().copied() {
        let mut message = format!("{base}. Найдена причина: {}", finding.fact);
        if !finding.solution.is_empty() {
            message = format!("{message}. Что сделать: {}", finding.solution);
        }
        return message;
    }

    let checked = report.verified.join(", ");
    if let Some(finding) = report.suspected().first().copied() {
        let mut message = base;
        if !checked.is_empty() {
            message = format!("{message}. Проверено: {checked}");
        }
        message = format!("{message}. Вероятная причина: {}", finding.fact);
        if !finding.solution.is_empty() {
            message = format!("{message}. Что сделать: {}", finding.solution);
        }
        return message;
    }

    let mut message = format!("{base}. Причина не установлена");
    if !checked.is_empty() {
        message = format!("{message} — проверено: {checked}");
    }
    format!(
        "{message}. Полный вывод winws и диагностика сохранены в логе программы. \
         Что сделать: попробуйте запустить ещё раз, а при повторе пришлите лог разработчику"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const BANNER: &str =
        "github version v1.0.3 (b78b52c4cd7f843da3ff0848a3430afbd401bdf2) lua_compat_ver 6";
    const WINDIVERT_ERROR: &str = "windivert: error opening filter: The service cannot be started";

    /// Настраиваемая система проб для тестов.
    #[derive(Default)]
    struct FakeProbes {
        missing_files: Vec<String>,
        bfe: bool,
        secure_boot: bool,
        admin: Option<bool>,
        conflict: Option<(String, String)>,
        antivirus: Option<String>,
        adapters: bool,
        windivert_state: Option<WindivertProbeState>,
        lua_file: Option<(String, String)>, // (имя, файл)
        lua_suggestions: Vec<String>,
    }

    impl SystemProbes for FakeProbes {
        fn windivert_files_missing(&self) -> Vec<String> {
            self.missing_files.clone()
        }
        fn bfe_running(&self) -> bool {
            self.bfe
        }
        fn secure_boot_enabled(&self) -> bool {
            self.secure_boot
        }
        fn is_user_admin(&self) -> Option<bool> {
            self.admin
        }
        fn launch_conflict_advice(&self) -> Option<(String, String)> {
            self.conflict.clone()
        }
        fn detect_active_antivirus(&self) -> Option<String> {
            self.antivirus.clone()
        }
        fn network_adapter_connected(&self) -> bool {
            self.adapters
        }
        fn windivert_probe_state(&self) -> Option<WindivertProbeState> {
            self.windivert_state
        }
        fn lua_function_file(&self, name: &str) -> Option<String> {
            self.lua_file
                .iter()
                .find(|(func, _)| func == name)
                .map(|(_, file)| file.clone())
        }
        fn lua_function_suggestions(&self, name: &str) -> Vec<String> {
            let _ = name;
            self.lua_suggestions.clone()
        }
    }

    impl FakeProbes {
        fn healthy() -> Self {
            Self {
                bfe: true,
                adapters: true,
                ..Self::default()
            }
        }
    }

    #[test]
    fn zero_exit_code_has_no_diagnosis() {
        assert!(diagnose_winws_exit(0, "", &AssumedHealthyProbes).is_none());
    }

    #[test]
    fn truncated_34_without_diagnostics_is_inferred_1058() {
        let probes = FakeProbes::healthy();
        let diag = diagnose_winws_exit(34, BANNER, &probes).expect("есть диагноз");
        assert_eq!(diag.exit_code, 34);
        assert_eq!(diag.win32_error, Some(ERROR_SERVICE_DISABLED));
        assert!(diag.win32_error_inferred);
        assert!(diag.cause_is_exact);
        // С «живой» диагностикой в выводе код измерен по тексту, а не угадан.
        let diag = diagnose_winws_exit(34, WINDIVERT_ERROR, &probes).expect("есть диагноз");
        assert_eq!(diag.win32_error, Some(ERROR_SERVICE_DISABLED));
        assert!(!diag.win32_error_inferred);
    }

    #[test]
    fn exit_229_with_recv_failed_is_not_a_windivert_cause() {
        let probes = FakeProbes::healthy();
        let stderr = "windivert: recv failed. errno 5";
        let diag = diagnose_winws_exit(229, stderr, &probes).expect("есть диагноз");
        assert!(diag.cause.contains("потерял исходный код Windows"));
        assert_eq!(diag.win32_error, None);
        assert!(!diag.cause_is_exact);
    }

    #[test]
    fn stderr_text_maps_to_win32_error() {
        let probes = FakeProbes::healthy();
        let diag = diagnose_winws_exit(
            2,
            "github version 1\nwindivert: error opening filter: Access is denied",
            &probes,
        )
        .expect("есть диагноз");
        assert_eq!(diag.win32_error, Some(ERROR_ACCESS_DENIED));
        assert_eq!(diag.exit_code, 2);
        assert!(!diag.win32_error_inferred);
    }

    #[test]
    fn bfe_down_offers_auto_fix() {
        let mut probes = FakeProbes::healthy();
        probes.bfe = false;
        let diag = diagnose_winws_exit(1068, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("Base Filtering Engine"));
        assert_eq!(diag.auto_fix.as_deref(), Some("enable_bfe"));
    }

    #[test]
    fn disabled_adapters_offers_auto_fix_on_gen_failure() {
        let mut probes = FakeProbes::healthy();
        probes.adapters = false;
        let diag = diagnose_winws_exit(31, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("адаптеры"));
        assert_eq!(diag.auto_fix.as_deref(), Some("enable_adapters"));
    }

    #[test]
    fn service_disabled_falls_back_to_table_without_causes() {
        let probes = FakeProbes::healthy();
        let diag = diagnose_winws_exit(1058, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("не может запустить службу"));
        assert!(diag.auto_fix.is_none());
    }

    #[test]
    fn service_disabled_probe_order_respects_python_checks() {
        // Check 1: файлы исчезли — антивирус.
        let mut probes = FakeProbes::healthy();
        probes.missing_files = vec!["WinDivert.dll".to_string()];
        let diag = diagnose_winws_exit(1058, "", &probes).expect("есть диагноз");
        assert!(
            diag.cause.contains("отсутствуют") || diag.cause.contains("отсутствуют"),
            "{}",
            diag.cause
        );
        assert!(diag.cause.contains("WinDivert.dll"));

        // Check 5: антивирус — до проверки адаптеров.
        let mut probes = FakeProbes::healthy();
        probes.antivirus = Some("Kaspersky".to_string());
        let diag = diagnose_winws_exit(1058, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("Kaspersky"), "{}", diag.cause);

        // Check 6: адаптеры проверяются позже антивируса.
        let mut probes = FakeProbes::healthy();
        probes.adapters = false;
        probes.antivirus = Some("Kaspersky".to_string());
        let diag = diagnose_winws_exit(1058, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("Kaspersky"), "{}", diag.cause);

        // Check 7: служба есть, но фильтр не открывается.
        let mut probes = FakeProbes::healthy();
        probes.windivert_state = Some(WindivertProbeState {
            installed: true,
            ready: false,
            error_code: Some(5),
        });
        let diag = diagnose_winws_exit(1058, "", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("ещё не готов"), "{}", diag.cause);
        assert!(diag.cause.contains("(код 5)"), "{}", diag.cause);
    }

    #[test]
    fn fwp_leftovers_get_conflict_hint_in_solution() {
        let mut probes = FakeProbes::healthy();
        probes.conflict = Some((
            "Виновник: GoodbyeDPI".to_string(),
            "Закройте его".to_string(),
        ));
        let diag = diagnose_winws_exit(9, "object with that guid", &probes).expect("есть диагноз");
        assert_eq!(diag.win32_error, Some(FWP_E_ALREADY_EXISTS));
        assert!(
            diag.solution.starts_with("Виновник: GoodbyeDPI."),
            "{}",
            diag.solution
        );
    }

    #[test]
    fn invalid_parameter_paths() {
        let probes = FakeProbes::healthy();

        let diag = diagnose_winws_exit(87, "incompatible nfqws2_compat_ver 7", &probes)
            .expect("есть диагноз");
        assert!(diag.cause.contains("разных версий"));

        let diag = diagnose_winws_exit(
            87,
            "windivert: error opening filter: The service cannot be started",
            &probes,
        )
        .expect("есть диагноз");
        assert!(
            diag.cause.contains("службу") || diag.cause.contains("Base Filtering"),
            "{}",
            diag.cause
        );

        let diag = diagnose_winws_exit(87, "desync function 'fake' does not exist", &probes)
            .expect("есть диагноз");
        assert!(
            diag.cause.contains("нет ни в одном lua-файле"),
            "{}",
            diag.cause
        );

        let diag =
            diagnose_winws_exit(87, "lua: error loading script", &probes).expect("есть диагноз");
        assert!(diag.cause.contains("Lua-скрипте"), "{}", diag.cause);
    }

    #[test]
    fn missing_lua_function_uses_catalog_and_suggestions() {
        let mut probes = FakeProbes::healthy();
        probes.lua_file = Some(("fake".to_string(), "custom.lua".to_string()));
        let diag = diagnose_winws_exit(87, "desync function 'fake' does not exist", &probes)
            .expect("есть диагноз");
        assert!(diag.cause.contains("lua/custom.lua"), "{}", diag.cause);
        assert!(
            diag.solution.contains("--lua-init=@lua/custom.lua"),
            "{}",
            diag.solution
        );

        probes.lua_file = None;
        probes.lua_suggestions = vec!["fake_http".to_string()];
        let diag = diagnose_winws_exit(87, "desync function 'fake' does not exist", &probes)
            .expect("есть диагноз");
        assert!(
            diag.cause.contains("имелось в виду «fake_http»"),
            "{}",
            diag.cause
        );
    }

    #[test]
    fn generic_windivert_fallback_uses_relevant_line() {
        let probes = FakeProbes::healthy();
        let diag = diagnose_winws_exit(2, "windivert: driver failure code 2", &probes)
            .expect("есть диагноз");
        assert!(
            diag.cause.starts_with("Ошибка WinDivert (код 2)"),
            "{}",
            diag.cause
        );
        assert_eq!(diag.solution, "windivert: driver failure code 2");
    }

    #[test]
    fn unknown_exit_code_without_windivert_text_is_none() {
        let probes = FakeProbes::healthy();
        assert!(diagnose_winws_exit(3, "some plain failure", &probes).is_none());
    }

    #[test]
    fn format_diagnosis_matches_python_wording() {
        let diag = WinDivertDiagnosis::new("Причина.", "Решение.", Severity::Critical);
        diag_ref_helper(&diag);
    }

    fn diag_ref_helper(diag: &WinDivertDiagnosis) {
        let mut diag = diag.clone();
        diag.exit_code = 1058;
        diag.win32_error = Some(1058);
        let text = format_winws_exit_diagnosis(&diag, "winws2");
        assert_eq!(
            text,
            "winws2 не запустился. Найдена причина: Причина (код ошибки 1058). Что сделать: Решение"
        );
    }

    #[test]
    fn format_diagnosis_marks_inferred_code_as_guess() {
        let mut diag = WinDivertDiagnosis::new("Служба отключена", "Решение", Severity::Critical);
        diag.exit_code = 34;
        diag.win32_error = Some(ERROR_SERVICE_DISABLED);
        diag.win32_error_inferred = true;
        let text = format_winws_exit_diagnosis(&diag, "winws2");
        assert_eq!(
            text,
            "winws2 не запустился. Вероятная причина: Служба отключена (код завершения процесса 34; предположительно код ошибки Windows 1058). Что сделать: Решение"
        );
    }

    #[test]
    fn format_diagnosis_without_exact_cause_says_what_is_known() {
        let mut diag = WinDivertDiagnosis::new("Код потерян", "", Severity::Critical);
        diag.exit_code = 229;
        diag.cause_is_exact = false;
        let text = format_winws_exit_diagnosis(&diag, "winws2");
        assert!(
            text.starts_with("winws2 не запустился. Что известно: Код потерян"),
            "{text}"
        );
        assert!(text.contains("код завершения процесса 229"));
        assert!(!text.contains("Что сделать"));
    }

    #[test]
    fn format_diagnosis_adds_autofix_marker() {
        let mut diag = WinDivertDiagnosis::new("BFE", "Включить", Severity::Critical);
        diag.auto_fix = Some("enable_bfe".to_string());
        let text = format_winws_exit_diagnosis(&diag, "winws");
        assert!(text.starts_with("[AUTOFIX:enable_bfe]"), "{text}");
    }

    // --- silent exit probes -------------------------------------------------

    #[derive(Default)]
    struct FakeSilentProbes {
        missing_files: Vec<String>,
        app_error: Option<String>,
        defender: RefCell<Option<Option<String>>>, // None = недоступен
        antivirus: Option<String>,
    }

    impl SilentExitProbes for FakeSilentProbes {
        fn windivert_files_missing(&self) -> Vec<String> {
            self.missing_files.clone()
        }
        fn application_error_event(&self, _process_name: &str) -> ProbeResult {
            match &self.app_error {
                None => ProbeResult::Clean,
                Some(fact) => ProbeResult::Finding(SilentExitFinding {
                    fact: fact.clone(),
                    solution: String::new(),
                    confirmed: true,
                }),
            }
        }
        fn defender_detection(&self, _exe_path: &str) -> ProbeResult {
            match self.defender.borrow().clone() {
                None => ProbeResult::Unavailable,
                Some(None) => ProbeResult::Clean,
                Some(Some(fact)) => ProbeResult::Finding(SilentExitFinding {
                    fact,
                    solution: String::new(),
                    confirmed: true,
                }),
            }
        }
        fn active_antivirus(&self) -> Option<String> {
            self.antivirus.clone()
        }
    }

    #[test]
    fn missing_executable_is_a_confirmed_fact() {
        let report = run_silent_exit_probes(
            &SilentExitProbesUnavailable,
            "/tmp/definitely/gone.exe",
            "winws2.exe",
        );
        let confirmed = report.confirmed();
        assert_eq!(confirmed.len(), 1);
        assert!(
            confirmed[0].fact.contains("исчез с диска"),
            "{}",
            confirmed[0].fact
        );
        assert!(confirmed[0].solution.contains("карантин"));
    }

    #[test]
    fn clean_system_yields_no_findings_but_records_checks() {
        let dir = std::env::temp_dir().join("primecore-ws-clean-probe");
        std::fs::create_dir_all(&dir).expect("создать каталог");
        let exe = dir.join("winws2.exe");
        std::fs::write(&exe, b"MZ").expect("записать файл");

        let report = run_silent_exit_probes(
            &SilentExitProbesUnavailable,
            exe.to_string_lossy().as_ref(),
            "winws2.exe",
        );
        assert!(report.findings.is_empty());
        // 5 проверок: файлы программы, файлы WinDivert, журнал аварий,
        // Defender (недоступен — не пишется), антивирус.
        assert_eq!(report.verified.len(), 4, "{:?}", report.verified);
        assert!(report
            .verified
            .contains(&"файлы программы на месте".to_string()));
        assert!(report
            .verified
            .contains(&"файлы WinDivert на месте".to_string()));
        assert!(report
            .verified
            .contains(&"в журнале Windows нет записи об аварийном завершении".to_string()));
        assert!(report
            .verified
            .contains(&"сторонний антивирус не обнаружен".to_string()));
    }

    #[test]
    fn unreadable_defender_log_is_not_reported_as_clean() {
        let dir = std::env::temp_dir().join("primecore-ws-defender-probe");
        std::fs::create_dir_all(&dir).expect("создать каталог");
        let exe = dir.join("winws2.exe");
        std::fs::write(&exe, b"MZ").expect("записать файл");

        let probes = FakeSilentProbes {
            defender: RefCell::new(None),
            ..FakeSilentProbes::default()
        };
        let report = run_silent_exit_probes(&probes, exe.to_string_lossy().as_ref(), "");
        assert!(report.findings.is_empty());
        assert!(!report
            .verified
            .contains(&"Defender по файлам программы не срабатывал".to_string()));
        assert!(report
            .verified
            .contains(&"файлы программы на месте".to_string()));
        assert!(report
            .verified
            .contains(&"файлы WinDivert на месте".to_string()));
    }

    #[test]
    fn unknown_executable_path_is_not_reported_as_checked() {
        let report = run_silent_exit_probes(&SilentExitProbesUnavailable, "", "");
        assert!(!report
            .verified
            .contains(&"файлы программы на месте".to_string()));
        assert!(report
            .verified
            .contains(&"файлы WinDivert на месте".to_string()));
    }

    #[test]
    fn antivirus_is_only_a_suspicion() {
        let dir = std::env::temp_dir().join("primecore-ws-av-probe");
        std::fs::create_dir_all(&dir).expect("создать каталог");
        let exe = dir.join("winws2.exe");
        std::fs::write(&exe, b"MZ").expect("записать файл");

        let probes = FakeSilentProbes {
            antivirus: Some("Kaspersky".to_string()),
            ..FakeSilentProbes::default()
        };
        let report = run_silent_exit_probes(&probes, exe.to_string_lossy().as_ref(), "");
        assert!(report.confirmed().is_empty());
        let suspected = report.suspected();
        assert_eq!(suspected.len(), 1);
        assert!(
            suspected[0].fact.contains("Kaspersky"),
            "{}",
            suspected[0].fact
        );
    }

    fn report_with(finding: SilentExitFinding, verified: &[&str]) -> SilentExitReport {
        SilentExitReport {
            findings: vec![finding],
            verified: verified.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn confirmed_fact_is_stated_as_the_cause() {
        let report = report_with(
            SilentExitFinding {
                fact: "исполняемый файл исчез с диска (winws2.exe)".to_string(),
                solution: "Восстановите файл из карантина".to_string(),
                confirmed: true,
            },
            &["файлы программы на месте"],
        );
        let message = format_silent_exit_message(&report, "winws2", 1, None);
        assert!(
            message.contains("Найдена причина: исполняемый файл исчез с диска"),
            "{message}"
        );
        assert!(message.contains("Восстановите файл из карантина"));
        assert!(!message.contains("Вероятная причина"));
        assert!(!message.contains("не установлена"));
    }

    #[test]
    fn suspicion_is_marked_as_probable_and_lists_checks() {
        let report = report_with(
            SilentExitFinding {
                fact: "антивирус".to_string(),
                solution: String::new(),
                confirmed: false,
            },
            &["файлы программы на месте"],
        );
        let message = format_silent_exit_message(&report, "winws2", 1, None);
        assert!(message.contains("Вероятная причина"), "{message}");
        assert!(
            message.contains("Проверено: файлы программы на месте"),
            "{message}"
        );
        assert!(!message.contains("Найдена причина"));
    }

    #[test]
    fn without_findings_the_message_admits_it_does_not_know() {
        let report = SilentExitReport {
            findings: Vec::new(),
            verified: vec!["файлы программы на месте".to_string()],
        };
        let message = format_silent_exit_message(&report, "winws2", 1, Some(0.42));
        assert!(message.contains("Причина не установлена"), "{message}");
        assert!(
            message.contains("проверено: файлы программы на месте"),
            "{message}"
        );
        assert!(message.contains("прожив 0.4 с"), "{message}");
        assert!(message.contains("лог"), "{message}");
        assert!(!message.to_lowercase().contains("антивирус"));
    }

    #[test]
    fn message_never_leaks_the_banner() {
        let report = SilentExitReport::default();
        let message = format_silent_exit_message(&report, "winws2", 1, None);
        assert!(!message.contains("github version"));
        assert!(message.contains("winws2"));
        assert!(message.contains("кодом 1"));
    }
}
