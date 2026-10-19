//! Порт `src/utils/windows_dns_query.py` — ответ DNS и статусы Windows DNS API.
//!
//! Сетевая часть (сами запросы через `dnsapi`, `system_dns_servers`,
//! `hosts_file_addresses`) — платформенно-специфичная (Windows), портируется
//! отдельно. Здесь — данные и тексты статусов.

/// Статусы, по которым можно судить, что сайт «отсутствует».
pub const DNS_STATUS_NAME_ERROR: i64 = 9003;
/// Ответ «успешен», но адресов IPv4 нет.
pub const DNS_STATUS_NO_RECORDS: i64 = 9501;
/// Запрос отменён «Стоп»/сроком.
pub const ERROR_CANCELLED: i64 = 995;

/// python `_STATUS_TEXT` — подписи статусов в отчёте.
pub const STATUS_TEXT: [(&str, &str); 4] = [
    ("0", "ответ получен"),
    ("9003", "DNS-сервер ответил, что такого домена нет"),
    ("9005", "DNS-сервер отказал в ответе"),
    ("9501", "у домена нет IPv4-адресов"),
];

pub fn status_text(status: i64) -> String {
    for (code, text) in STATUS_TEXT {
        if code.parse::<i64>().ok() == Some(status) {
            return text.to_string();
        }
    }
    format!("ошибка DNS {status}")
}

/// Ответ DNS: адреса IPv4 из секции ответа и код результата Windows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsAnswer {
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
    pub status: i64,
    pub detail: String,
    pub elapsed_ms: f64,
}

impl DnsAnswer {
    pub fn ok(&self) -> bool {
        !self.ips.is_empty()
    }
}
