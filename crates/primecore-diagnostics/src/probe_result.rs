//! Порт `src/diagnostics/tls_probe.py` — итог HTTPS-запроса (`ProbeResult`)
//! и виды исхода `KIND_*` / этапы `STAGE_*`.
//!
//! Сам запрос «открывается ли сайт» идёт как у Chrome — через `chrome_https`:
//! то же рукопожатие и тот же HTTP/2, что у браузера, потому что фильтр
//! провайдера различает программы по первому пакету соединения, а стратегии
//! обхода режут именно его. Здесь остались общие для всех проб вещи:
//!
//! - `ProbeResult` и виды исхода `KIND_*` / этапы `STAGE_*` — выводы
//!   диагностики и подбора стратегий опираются только на них;
//! - `client_context` — контекст TLS с проверкой сертификата для проб,
//!   которым нужен свой сокет (портируется вместе с сетевой частью).

use primecore_netfailure::{FAILURE_REFUSED, FAILURE_TIMEOUT};

/// Виды исхода запроса. Выводы диагностики опираются только на них.
pub const KIND_OK: &str = "ok";
pub const KIND_CERT: &str = "cert";
pub const KIND_TLS: &str = "tls";
pub const KIND_RESET: &str = "reset";
pub const KIND_TIMEOUT: &str = "timeout";
pub const KIND_CONNECT: &str = "connect";
pub const KIND_CANCELLED: &str = "cancelled";
pub const KIND_ERROR: &str = "error";

/// Почему не соединились — вид сбоя из общего словаря `utils.net_failure`.
pub const CONNECT_TIMEOUT: &str = FAILURE_TIMEOUT;
pub const CONNECT_REFUSED: &str = FAILURE_REFUSED;

pub const STAGE_CONNECT: &str = "connect";
pub const STAGE_TLS: &str = "tls";
pub const STAGE_READ: &str = "read";

/// причина неустановления соединения (`utils.net_failure`): "timeout" —
/// ответа нет вовсе, "refused" — адрес сам отказал, "unreachable" — до адреса нет
/// дороги, "other" — прочая ошибка системы (например, запрет сетевого экрана).
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    pub ip: String,
    pub kind: String,
    pub stage: &'static str,
    pub status: Option<i64>,
    pub body_size: u64,
    /// Ответ начал приходить, но оборвался (таймаут или сброс посреди тела).
    pub body_cut: bool,
    pub cert_problem: String,
    pub tls_version: String,
    pub elapsed_ms: f64,
    pub detail: String,
    pub body: Vec<u8>,
    pub connect_fail: &'static str,
}

impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            ip: String::new(),
            kind: String::new(),
            stage: "",
            status: None,
            body_size: 0,
            body_cut: false,
            cert_problem: String::new(),
            tls_version: String::new(),
            elapsed_ms: 0.0,
            detail: String::new(),
            body: Vec::new(),
            connect_fail: "",
        }
    }
}

impl ProbeResult {
    pub fn ok(&self) -> bool {
        self.kind == KIND_OK
    }

    /// python dataclass-конструктор с именованными аргументами;
    /// в Rust — билдитер-хелпер: `ProbeResult::new(ip, kind)`.
    pub fn new(ip: impl Into<String>, kind: impl Into<String>) -> Self {
        Self { ip: ip.into(), kind: kind.into(), ..Default::default() }
    }
}
