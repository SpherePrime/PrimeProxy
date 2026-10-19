//! Порт `src/utils/net_failure.py` — виды сетевого сбоя.
//!
//! Проверка записывает не текст ошибки (на Windows он зависит от локали),
//! а её вид: «сервер молчит», «порт закрыт» и т. д. Виды те же, что в
//! python — их читают отчёты и выводы проверок сети.

pub const FAILURE_TIMEOUT: &str = "timeout";
pub const FAILURE_REFUSED: &str = "refused";
pub const FAILURE_RESET: &str = "reset";
pub const FAILURE_CLOSED: &str = "closed";
pub const FAILURE_UNREACHABLE: &str = "unreachable";
pub const FAILURE_TLS: &str = "tls";
pub const FAILURE_CERT: &str = "cert";
pub const FAILURE_HTTP: &str = "http";
pub const FAILURE_MALFORMED: &str = "malformed";
pub const FAILURE_CANCELLED: &str = "cancelled";
pub const FAILURE_OTHER: &str = "other";

/// Коды Winsock: python переводит в TimeoutError/ResetError не все из них.
const WINERROR: &[(i32, &str)] = &[
    (10060, FAILURE_TIMEOUT),     // WSAETIMEDOUT
    (10061, FAILURE_REFUSED),     // WSAECONNREFUSED
    (10054, FAILURE_RESET),       // WSAECONNRESET (у UDP — ICMP «порт закрыт»)
    (10053, FAILURE_RESET),       // WSAECONNABORTED
    (10050, FAILURE_UNREACHABLE), // WSAENETDOWN
    (10051, FAILURE_UNREACHABLE), // WSAENETUNREACH
    (10065, FAILURE_UNREACHABLE), // WSAEHOSTUNREACH
];

/// errno-значения как в errno-модуле той системы, где собран крейт
/// (python берёт их от runtime).
#[cfg(target_os = "linux")]
const ERRNO: &[(i32, &str)] = &[
    (110, FAILURE_TIMEOUT),     // ETIMEDOUT
    (111, FAILURE_REFUSED),     // ECONNREFUSED
    (104, FAILURE_RESET),       // ECONNRESET
    (103, FAILURE_RESET),       // ECONNABORTED
    (32, FAILURE_RESET),        // EPIPE
    (100, FAILURE_UNREACHABLE), // ENETDOWN
    (101, FAILURE_UNREACHABLE), // ENETUNREACH
    (113, FAILURE_UNREACHABLE), // EHOSTUNREACH
];

#[cfg(target_os = "macos")]
const ERRNO: &[(i32, &str)] = &[
    (60, FAILURE_TIMEOUT),      // ETIMEDOUT
    (61, FAILURE_REFUSED),      // ECONNREFUSED
    (54, FAILURE_RESET),        // ECONNRESET
    (53, FAILURE_RESET),        // ECONNABORTED
    (32, FAILURE_RESET),        // EPIPE
    (50, FAILURE_UNREACHABLE),  // ENETDOWN
    (51, FAILURE_UNREACHABLE),  // ENETUNREACH
    (65, FAILURE_UNREACHABLE),  // EHOSTUNREACH
];

#[cfg(target_family = "windows")]
const ERRNO: &[(i32, &str)] = &[
    // ECONNRESET=10054 и прочие уже в WINERROR; errno-модуль Windows
    // отдельных сетевых видов не добавляет.
];

fn lookup(table: &'static [(i32, &'static str)], code: i32) -> Option<&'static str> {
    table
        .iter()
        .find(|entry| entry.0 == code)
        .map(|entry| entry.1)
}

/// Вид сбоя по коду ошибки системы (Winsock или errno), когда исключения нет.
/// Так приходит ошибка из чужой сетевой библиотеки (libcurl → OS_ERRNO).
/// Пусто — код ни о чём определённом не говорит.
pub fn classify_code(code: i64) -> &'static str {
    let code = if code > 0 {
        code.min(i32::MAX as i64) as i32
    } else {
        0
    };
    if let Some(failure) = lookup(WINERROR, code) {
        return failure;
    }
    lookup(ERRNO, code).unwrap_or("")
}

/// Вид сбоя по классу сетевой ошибки Rust (аналог classify на OSError).
///
/// СТОИ осмысленно: rust io::Error::RawOsError даёт errno — по той таблице;
/// kind'ы без кода приводит «как python по классам исключений».
pub fn classify_os_error(error: &std::io::Error) -> &'static str {
    if let Some(code) = error.raw_os_error() {
        if let Some(failure) = lookup(WINERROR, code).or_else(|| lookup(ERRNO, code)) {
            return failure;
        }
    }
    match error.kind() {
        std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::WouldBlock => FAILURE_TIMEOUT,
        std::io::ErrorKind::ConnectionRefused => FAILURE_REFUSED,
        std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof => FAILURE_RESET,
        _ => FAILURE_OTHER,
    }
}
