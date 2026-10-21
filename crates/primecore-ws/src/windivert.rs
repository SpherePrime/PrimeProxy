//! Единый центр диагностики WinDivert.
//!
//! Порт `winws_runtime/health/windivert_diagnostics.py`. Здесь живут:
//! - канонические определения Win32-кодов ошибок WinDivert (единственная точка
//!   определения числовых литералов, остальные модули используют имена);
//! - декларативная таблица код → (причина, решение, auto-fix действие);
//! - [`describe_windivert_error`] — пользовательский текст с номером кода.
//!
//! Проверка службы драйвера перед запуском (`ensure_windivert_ready_before_spawn`)
//! в python ходила в диспетчер служб Windows; здесь остаётся только структура
//! результата [`WinDivertReadinessResult`], а само чтение состояния службы —
//! платформенное и остаётся за вызывающим кодом (см. [`health::SystemProbes`]).

use serde::{Deserialize, Serialize};

// --- Канонические Win32-коды ошибок WinDivert (единственная точка определения) ---
pub const ERROR_ACCESS_DENIED: i64 = 5;
pub const ERROR_NOT_ENOUGH_MEMORY: i64 = 8;
pub const ERROR_GEN_FAILURE: i64 = 31;
pub const ERROR_INVALID_PARAMETER: i64 = 87;
pub const ERROR_BAD_PATHNAME: i64 = 161;
/// ERROR_NO_SUCH_DEVICE: сетевой стек/WFP ещё переинициализируется — типично
/// сразу после переключения сети или выхода из сна.
pub const ERROR_NO_SUCH_DEVICE: i64 = 433;
pub const ERROR_INVALID_IMAGE_HASH: i64 = 577;
pub const ERROR_DRIVER_FAILED_PRIOR_UNLOAD: i64 = 654;
pub const ERROR_SERVICE_DISABLED: i64 = 1058;
pub const ERROR_SERVICE_DOES_NOT_EXIST: i64 = 1060;
pub const ERROR_PROCESS_ABORTED: i64 = 1067;
pub const ERROR_SERVICE_DEPENDENCY_FAIL: i64 = 1068;
pub const ERROR_SERVICE_MARKED_FOR_DELETE: i64 = 1072;
pub const ERROR_DRIVER_BLOCKED: i64 = 1275;
/// EPT_S_NOT_REGISTERED: плавающая гонка SCM сразу после stop/cleanup.
pub const ERROR_EPT_S_NOT_REGISTERED: i64 = 1753;
// Коды платформы фильтрации Windows (WFP), значения — из winerror.h.
// Каждый winws открывает в WFP свой сеанс и ставит в нём фильтры; когда процесс
// завершается, Windows убирает эти фильтры сама и не мгновенно. Пока они не
// убраны (или пока их держит чужая программа на WinDivert), новый запуск
// получает один из двух кодов:
// - FWP_E_ALREADY_EXISTS: "An object with that GUID or LUID already exists";
// - FWP_E_IN_USE: "The object is referenced by other objects so cannot be deleted".
// Сборка winws на Cygwin отдаёт кодом завершения только младший байт: 9 и 10.
pub const FWP_E_ALREADY_EXISTS: i64 = 0x8032_0009;
pub const FWP_E_IN_USE: i64 = 0x8032_000A;

const WFP_LEFTOVERS_SOLUTION: &str = "Подождите несколько секунд и запустите снова. Если не помогает — закройте другие программы обхода блокировок (GoodbyeDPI, другой Zapret, VPN на базе WinDivert) или перезагрузите компьютер";

/// Сколько ждать перед запуском, пока служба драйвера закончит выгружаться.
pub const WINDIVERT_PRESPAWN_WAIT_SECONDS: f64 = 3.0;

/// Декларативное описание одного Win32-кода ошибки WinDivert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDivertErrorRecord {
    pub code: i64,
    /// Базовая причина (для diagnose_winws_exit fallback).
    pub cause: &'static str,
    /// Базовое решение.
    pub solution: &'static str,
    /// Безопасное авто-действие или None.
    pub auto_fix_action: Option<&'static str>,
}

const fn record(
    code: i64,
    cause: &'static str,
    solution: &'static str,
    auto_fix_action: Option<&'static str>,
) -> WinDivertErrorRecord {
    WinDivertErrorRecord {
        code,
        cause,
        solution,
        auto_fix_action,
    }
}

/// Таблица код → (причина, решение, auto-fix). Порядок значений как в python.
pub const WINDIVERT_ERROR_TABLE: [WinDivertErrorRecord; 17] = [
    record(
        ERROR_ACCESS_DENIED,
        "Отказано в доступе к WinDivert",
        "Проверьте антивирус и запустите от имени администратора",
        None,
    ),
    record(
        ERROR_NOT_ENOUGH_MEMORY,
        "Недостаточно системной памяти для WinDivert",
        "Закройте лишние программы и перезагрузите компьютер",
        None,
    ),
    record(
        ERROR_GEN_FAILURE,
        "Общая ошибка устройства",
        "Перезагрузите компьютер и проверьте сетевые адаптеры",
        None,
    ),
    record(
        ERROR_INVALID_PARAMETER,
        "Ошибка в параметрах фильтра или Lua-скрипта",
        "Проверьте настройки стратегии — возможно повреждён пресет",
        None,
    ),
    record(
        ERROR_BAD_PATHNAME,
        "Не найден файл драйвера WinDivert",
        "Переустановите программу или проверьте антивирус",
        None,
    ),
    record(
        ERROR_NO_SUCH_DEVICE,
        "Сетевое устройство для WinDivert временно недоступно",
        "Подождите несколько секунд после смены сети и повторите запуск. Если не помогает — перезагрузите компьютер",
        None,
    ),
    record(
        ERROR_INVALID_IMAGE_HASH,
        "Подпись драйвера WinDivert не прошла проверку",
        "Отключите Secure Boot или включите тестовый режим: bcdedit /set testsigning on",
        None,
    ),
    record(
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD,
        "Старая версия драйвера WinDivert всё ещё загружена в память",
        "Перезагрузите компьютер для выгрузки старого драйвера",
        None,
    ),
    record(
        ERROR_SERVICE_DISABLED,
        "WinDivert не может запустить службу драйвера",
        "Перезагрузите компьютер. Если не помогает — проверьте Secure Boot и антивирус",
        None,
    ),
    record(
        ERROR_SERVICE_DOES_NOT_EXIST,
        "Служба WinDivert не найдена в системе",
        "Переустановите программу",
        None,
    ),
    record(
        ERROR_PROCESS_ABORTED,
        "Драйвер WinDivert аварийно завершился при запуске",
        "Переустановите программу и перезагрузите компьютер",
        None,
    ),
    record(
        ERROR_SERVICE_DEPENDENCY_FAIL,
        "Зависимая служба Windows Filtering Platform не запущена",
        "Перезагрузите компьютер",
        None,
    ),
    record(
        ERROR_SERVICE_MARKED_FOR_DELETE,
        "Служба WinDivert помечена на удаление",
        "Подождите несколько секунд и повторите запуск, либо перезагрузите компьютер",
        None,
    ),
    record(
        ERROR_DRIVER_BLOCKED,
        "Политика безопасности Windows блокирует загрузку драйвера",
        "Проверьте настройки Device Guard / WDAC или отключите Secure Boot",
        None,
    ),
    record(
        FWP_E_ALREADY_EXISTS,
        "Windows ещё не убрала фильтры WinDivert от прошлого запуска, либо их держит другая программа",
        WFP_LEFTOVERS_SOLUTION,
        None,
    ),
    record(
        FWP_E_IN_USE,
        "Фильтры WinDivert от прошлого запуска ещё заняты: Windows не успела их убрать, либо их держит другая программа",
        WFP_LEFTOVERS_SOLUTION,
        None,
    ),
    record(
        ERROR_EPT_S_NOT_REGISTERED,
        "Служба WinDivert ещё не зарегистрирована в системе (временная гонка SCM)",
        "Подождите пару секунд и повторите запуск",
        None,
    ),
];

/// Запись таблицы для кода или `None`, если коду не сопоставлен текст.
pub fn windivert_error_record(code: i64) -> Option<&'static WinDivertErrorRecord> {
    WINDIVERT_ERROR_TABLE
        .iter()
        .find(|record| record.code == code)
}

/// Код Windows в виде, пригодном для показа пользователю.
///
/// Обычные Win32-коды остаются десятичными, а HRESULT/NTSTATUS (FWP_E_*,
/// STATUS_*) дополняются шестнадцатеричной записью: в таком виде их узнают и
/// ищут в документации, тогда как голое «2151092249» не говорит ничего.
pub fn format_windows_error_code(code: i64) -> String {
    if !(0..=0xFFFF).contains(&code) {
        return format!("{code} / 0x{:08X}", code & 0xFFFF_FFFF);
    }
    code.to_string()
}

/// Пользовательский текст (ru) для Win32-кода ошибки WinDivert.
///
/// Всегда содержит номер кода.
pub fn describe_windivert_error(code: i64) -> String {
    let code_text = format_windows_error_code(code);
    match windivert_error_record(code) {
        Some(record) => {
            format!("{} (код {code_text}). {}", record.cause, record.solution)
        }
        None => format!("Ошибка WinDivert (код {code_text})"),
    }
}

/// Итог проверки службы драйвера WinDivert перед запуском движка.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDivertReadinessResult {
    pub ready: bool,
    /// Что мешает: stop_pending / stuck_entry.
    #[serde(default)]
    pub blocker: String,
    /// Имя службы драйвера, если она мешает.
    #[serde(default)]
    pub service: String,
    /// Человеко-читаемое описание провала.
    #[serde(default)]
    pub description: String,
    /// Подсказка о найденном конфликте, если есть.
    #[serde(default)]
    pub conflict_hint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_codes_stay_decimal() {
        assert_eq!(format_windows_error_code(1058), "1058");
        assert_eq!(format_windows_error_code(5), "5");
    }

    #[test]
    fn hresult_codes_get_hex_suffix() {
        // Сверено с python: format_windows_error_code(0x80320009)
        let expected = format!("{} / 0x{:08X}", FWP_E_ALREADY_EXISTS, FWP_E_ALREADY_EXISTS);
        assert_eq!(format_windows_error_code(FWP_E_ALREADY_EXISTS), expected);
    }

    #[test]
    fn table_covers_all_canonical_codes() {
        for code in [
            ERROR_ACCESS_DENIED,
            ERROR_NOT_ENOUGH_MEMORY,
            ERROR_GEN_FAILURE,
            ERROR_INVALID_PARAMETER,
            ERROR_BAD_PATHNAME,
            ERROR_NO_SUCH_DEVICE,
            ERROR_INVALID_IMAGE_HASH,
            ERROR_DRIVER_FAILED_PRIOR_UNLOAD,
            ERROR_SERVICE_DISABLED,
            ERROR_SERVICE_DOES_NOT_EXIST,
            ERROR_PROCESS_ABORTED,
            ERROR_SERVICE_DEPENDENCY_FAIL,
            ERROR_SERVICE_MARKED_FOR_DELETE,
            ERROR_DRIVER_BLOCKED,
            FWP_E_ALREADY_EXISTS,
            FWP_E_IN_USE,
            ERROR_EPT_S_NOT_REGISTERED,
        ] {
            assert!(windivert_error_record(code).is_some(), "код {code}");
        }
        assert!(windivert_error_record(12345).is_none());
    }

    #[test]
    fn describe_contains_code_and_text() {
        let text = describe_windivert_error(ERROR_SERVICE_DISABLED);
        assert!(text.contains("1058"), "{text}");
        assert!(text.contains("службу драйвера"), "{text}");
        assert_eq!(
            describe_windivert_error(99999),
            "Ошибка WinDivert (код 99999 / 0x0001869F)"
        );
    }
}
