//! Порт `src/dns/domain_lookup.py` — проверка одного домена или адреса:
//! пинг, ответы разных DNS, соседи по адресу.
//!
//! Пользователь вводит домен или IP. Проверка:
//!
//! 1. спрашивает адреса домена у каждого DNS-сервера из списка программы (и у
//!    системного) напрямую — так видно, кто что отвечает и не подставляет ли
//!    провайдер заглушку;
//! 2. пингует полученный адрес и замеряет подключение к порту 443 (сайт может
//!    не отвечать на пинг, но работать);
//! 3. выясняет, чей это адрес и какие ещё домены на нём живут: обратное имя
//!    (PTR), имена из сертификата сайта, владелец сети и — по желанию — внешний
//!    сервис со списком соседей.
//!
//! Здесь нет интерфейса: только данные и решения по ним. Сеть целиком
//! переносится замыканиями — типы ввода и шаги прогона в
//! [`crate::domain_lookup_steps`] и [`crate::domain_lookup_run`]; этот файл —
//! типы отчёта и чистый разбор ответов.

use primecore_diagnostics::address_kinds::{address_kind, block_stub_owner, AddressKind};
use primecore_diagnostics::levels::{worst, FAIL, OK, UNKNOWN, WARN};
use serde_json::Value;

pub const KIND_DOMAIN: &str = "domain";
pub const KIND_IP: &str = "ip";
pub const KIND_INVALID: &str = "invalid";

/// Уровни строк — общие для всех проверок (diagnostics.levels).
pub const LEVEL_OK: &str = OK;
pub const LEVEL_WARN: &str = WARN;
pub const LEVEL_FAIL: &str = FAIL;
pub const LEVEL_UNKNOWN: &str = UNKNOWN;

pub const SERVER_WINDOWS: &str = "windows";
pub const SERVER_SYSTEM: &str = "system";
pub const SERVER_PROVIDER: &str = "provider";
pub const SERVER_CUSTOM: &str = "custom";
pub const SERVER_DOH: &str = "doh";

pub const SOURCE_PTR: &str = "ptr";
pub const SOURCE_CERT_NAMED: &str = "cert_named";
pub const SOURCE_CERT_DEFAULT: &str = "cert_default";
pub const SOURCE_THC: &str = "thc";
pub const SOURCE_SHODAN: &str = "shodan";
pub const SOURCE_HACKERTARGET: &str = "hackertarget";
pub const EXTERNAL_SOURCES: [&str; 3] = [SOURCE_THC, SOURCE_HACKERTARGET, SOURCE_SHODAN];

pub const SOURCE_OK: &str = "ok";
pub const SOURCE_EMPTY: &str = "empty";
pub const SOURCE_ERROR: &str = "error";
pub const SOURCE_LIMIT: &str = "limit";
pub const SOURCE_SKIPPED: &str = "skipped";

pub const RUN_DEADLINE_S: f64 = 40.0;
pub const DNS_TIMEOUT_S: f64 = 2.0;
pub const PING_COUNT: u32 = 4;
pub const PING_TIMEOUT_MS: u32 = 2000;
pub const TCP_TIMEOUT_S: f64 = 3.0;
pub const EXTERNAL_TIMEOUT_S: f64 = 8.0;
/// Дальше этого узла место фильтра не ищем: он стоит в сети провайдера, близко.
pub const PATH_MAX_TTL: u32 = 20;
pub const MAX_PARALLEL: usize = 16;
/// Независимые открытые DNS-серверы в дополнение к списку программы: чем больше
/// разных владельцев, тем виднее, кто отвечает не как все. Mullvad сюда не годится:
/// обычным запросом он называет только адреса собственных серверов, а на остальные
/// имена отвечает отказом (проверено 2026-10-13). UltraDNS уже есть в списке программы.
pub const EXTRA_SERVERS: [(&str, &str); 6] = [
    ("Яндекс DNS", "77.88.8.8"),
    ("Level3", "4.2.2.2"),
    ("Hurricane Electric", "74.82.42.42"),
    ("DNS.Watch", "84.200.69.80"),
    ("Control D", "76.76.2.0"),
    ("Comodo", "8.26.56.26"),
];
/// Запасные серверы для служебных запросов (обратное имя, владелец сети).
pub const HELPER_SERVERS: [&str; 3] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
pub const THC_URL: &str = "https://ip.thc.org/api/v1/lookup";
pub const THC_PAGE_SIZE: i64 = 100;
pub const THC_MAX_PAGES: usize = 3;
pub const SHODAN_URL: &str = "https://internetdb.shodan.io/{ip}";
pub const HACKERTARGET_URL: &str = "https://api.hackertarget.com/reverseiplookup/?q={ip}";
pub const RIPESTAT_URL: &str =
    "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=primebypass";
pub const USER_AGENT: &str = "PrimeBypass domain lookup";

/// Сколько адресов из «Редактора hosts» пробовать, пока один не откроет сайт.
pub const HOSTS_ROAD_TRIES: usize = 2;
/// Пауза между попытками адресов из «Редактора hosts», с.
pub const HOSTS_ROAD_PAUSE_S: f64 = 1.5;
/// Если первая попытка шла дольше этого, фильтр молча глушит имя: вторая кончится
/// так же, а ждать её долго.
pub const HOSTS_ROAD_SLOW_S: f64 = 6.0;
/// Запас времени на эту пробу: она идёт после остальных и не должна выглядеть
/// как «проверки не успели».
pub const HOSTS_ROAD_BUDGET_S: f64 = 14.0;

pub const ROAD_DEAD: &str = "dead";
pub const ROAD_BLOCKED: &str = "blocked";

/// python `NOTE_WINDOWS_BLIND`.
pub const NOTE_WINDOWS_BLIND: &str =
    "у DNS-серверов адрес есть, а Windows его не получила — браузер и программы сайт не найдут";
/// python `NOTE_FORGED`.
pub const NOTE_FORGED: &str =
    "тот же сервер по шифрованному каналу адрес называет — обычный ответ подменён по дороге";
/// python `NOTE_FORGED_MARK`.
pub const NOTE_FORGED_MARK: &str =
    "ответ подставной: настоящий сервер так не отвечает (в отказе нет обязательной служебной записи) — \
     его прислал фильтр по дороге";
/// python `NOTE_FORGED_TCP` — с подстановкой адреса из TCP-ответа.
pub const NOTE_FORGED_TCP: &str =
    "по TCP тот же сервер адрес называет ({ip}) — ответ на обычный запрос подменён по дороге";

/// Кого спрашивают всегда: Windows, DNS компьютера, свои серверы человека и
/// шифрованный эталон — столько же запросов делает и сам компьютер. Остальные
/// (провайдеры и общедоступные) — во второй волне.
pub const QUICK_SERVER_KINDS: [&str; 3] = [SERVER_SYSTEM, SERVER_CUSTOM, SERVER_DOH];

/// python `DnsServer` — один DNS-сервер списка программы.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsServer {
    pub label: String,
    pub address: String,
    pub kind: String,
}

impl DnsServer {
    #[must_use]
    pub fn new(label: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            address: address.into(),
            kind: SERVER_PROVIDER.to_string(),
        }
    }

    #[must_use]
    pub fn with_kind(label: impl Into<String>, address: impl Into<String>, kind: &str) -> Self {
        Self {
            label: label.into(),
            address: address.into(),
            kind: kind.to_string(),
        }
    }
}

/// python `ResolverAnswer` — что ответил один DNS-сервер.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResolverAnswer {
    pub server: DnsServer,
    pub status: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub cnames: Vec<String>,
    pub elapsed_ms: Option<f64>,
    pub level: String,
    pub note: String,
    /// Сколько секунд ответ считается свежим (наименьшее из адресных записей).
    /// Настоящий сервер отдаёт убывающий остаток, заглушки часто ставят ноль
    /// или круглое число. None — в ответе адресов нет.
    pub ttl: Option<u32>,
    /// «Домена нет» с подписью подставного ответа (`DnsQueryResult.forged_denial`).
    pub forged: bool,
    /// Что тот же сервер ответил по TCP, когда на обычный запрос (UDP) пришло
    /// «домена нет». Фильтр подделывает только UDP, поэтому адреса здесь —
    /// прямое доказательство подмены.
    pub tcp_ipv4: Vec<String>,
    /// Только у строки Windows: адрес, который система ставит первым, — на него
    /// программы идут сначала.
    pub first: String,
}

impl ResolverAnswer {
    #[must_use]
    pub fn addresses(&self) -> Vec<String> {
        let mut all = self.ipv4.clone();
        all.extend(self.ipv6.iter().cloned());
        all
    }
}

/// python `PingReport`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PingReport {
    pub ip: String,
    pub supported: bool,
    pub sent: i64,
    pub received: i64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub ttl: Option<i64>,
    pub error_code: String,
}

impl PingReport {
    #[must_use]
    pub fn lost_percent(&self) -> i64 {
        if self.sent <= 0 {
            return 0;
        }
        (100.0 * (self.sent - self.received) as f64 / self.sent as f64).round_ties_even() as i64
    }
}

/// python `TcpReport` — результат соединения с портом (status: ok/refused/timeout/error).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TcpReport {
    pub ip: String,
    pub port: u16,
    pub status: String,
    pub elapsed_ms: Option<f64>,
    pub detail: String,
}

/// python `ProgramRoad` — дорога, которой на самом деле идут программы, когда
/// Windows ставит первым адрес IPv6.
///
/// Сайт проверяется по IPv4, а Windows при живом IPv6 ведёт программы на адрес
/// IPv6. Если по нему связи нет или имя сайта на этой дороге режут, сайт
/// «открывается» в проверке и не открывается в браузере — пока эту дорогу не
/// проверить отдельно.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProgramRoad {
    pub ip: String,
    pub tcp: TcpReport,
    /// Пробы с настоящим именем сайта по этому адресу: (название, состояние ok/fail/unknown, текст).
    pub lines: Vec<(String, String, String)>,
    /// Дошло ли до сервера приветствие с именем сайта (обычное или как у Chrome).
    /// None — не проверяли.
    pub opens: Option<bool>,
}

/// python `NetworkInfo` — чья это сеть: номер автономной системы, диапазон,
/// страна, владелец.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkInfo {
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub owner: String,
    /// Все сети, которые объявляют этот адрес: (номер, владелец). Их бывает несколько.
    pub origins: Vec<(String, String)>,
}

/// python `NeighborSource` — один источник сведений «какие домены на этом адресе».
#[derive(Debug, Clone, PartialEq)]
pub struct NeighborSource {
    pub key: String,
    pub status: String,
    pub names: Vec<String>,
    pub detail: String,
    /// Сколько доменов знает сам источник (он отдаёт только первую часть списка).
    pub total: Option<i64>,
    /// Дополнительная строка от источника, например открытые порты.
    pub extra: String,
}

impl NeighborSource {
    #[must_use]
    pub fn new(key: &str, status: &str) -> Self {
        Self {
            key: key.to_string(),
            status: status.to_string(),
            names: Vec::new(),
            detail: String::new(),
            total: None,
            extra: String::new(),
        }
    }
}

/// python `HostsHelp` — что о сайте знает «Редактор hosts» и что уже записано в файле.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostsHelp {
    pub service: String,
    pub offered: Vec<String>,
    pub rows: Vec<String>,
    pub managed: Vec<String>,
}

/// python `DomainLookupReport` — итог всей проверки домена или адреса.
#[derive(Debug, Clone, Default)]
pub struct DomainLookupReport {
    pub target: String,
    pub kind: String,
    pub error: String,
    pub answers: Vec<ResolverAnswer>,
    pub intercepted: bool,
    pub primary_ip: String,
    pub ping: Option<PingReport>,
    pub ping6: Option<PingReport>,
    pub tcp: Option<TcpReport>,
    /// Адрес IPv6, который Windows отдаёт программам первым, и что по нему получается.
    pub road: Option<ProgramRoad>,
    /// Сервис «Редактора hosts», тумблер которого даёт этому имени адрес IPv4 (пусто — такого нет).
    pub hosts_service: String,
    /// Адреса имени в файле hosts: все и те из них, что записала программа (в своём блоке).
    pub hosts_rows: Vec<String>,
    pub hosts_managed: Vec<String>,
    /// Адреса IPv4, которые этот сервис записал бы имени.
    pub hosts_offered: Vec<String>,
    /// Что получается по адресу из «Редактора hosts», пока его тумблер выключен. None — не пробовали.
    pub hosts_road: Option<ProgramRoad>,
    pub network: Option<NetworkInfo>,
    pub sources: Vec<NeighborSource>,
    /// Путь до адреса по узлам. None — ещё не готов.
    pub route: Option<primecore_diagnostics::path_trace::RouteTrace>,
    /// Проходит ли QUIC к этому сайту (только для доменов).
    pub quic: Option<primecore_diagnostics::quic_probe::QuicVerdict>,
    /// Где стоит фильтр; ищется, только если QUIC блокируют по имени.
    pub filter_facts: Option<primecore_diagnostics::path_trace::FilterFacts>,
    /// Как сайт открывается: TLS 1.2 и 1.3, «как Chrome», HTTP, QUIC, способ блокировки, реестр РКН.
    /// Та же запись сервиса, что в отчёте BlockCheck (`diagnostics.engine.check_site`); только для доменов.
    pub site: Option<Value>,
    /// Запись этой проверки в истории вкладки — та самая, что сохранена в настройки (с путём
    /// к файлу полного текста). None — проверку прервали, в историю она не попала.
    pub history_entry: Option<Value>,
    pub finished: bool,
    pub stopped: bool,
    pub timed_out: bool,
    pub elapsed_s: f64,
}

/// python `_SCHEME_RE` — префикс ссылки вида `https://`.
fn strip_scheme(text: &str) -> &str {
    let Some(pos) = text.find("://") else {
        return text;
    };
    let prefix = &text[..pos];
    let mut chars = prefix.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    if first_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-') {
        &text[pos + 3..]
    } else {
        text
    }
}

/// python `_HOSTNAME_RE` — вид имени: метки из букв, цифр и «_» (в последней
/// метке подчёркивания нет), длина до 253.
#[must_use]
pub fn hostname_matches(text: &str) -> bool {
    if text.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = text.split('.').collect();
    let Some((last, middle)) = labels.split_last() else {
        return false;
    };
    let last = *last;
    // Последняя метка: [a-z0-9-]{2,63}.
    if last.is_empty() || last.len() > 63 {
        return false;
    }
    if !last
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return false;
    }
    if middle.is_empty() {
        return false;
    }
    for label in middle.iter() {
        let label: &str = label;
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let chars: Vec<char> = label.chars().collect();
        let allowed =
            |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_';
        let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        if !edge(chars[0]) || !edge(chars[chars.len() - 1]) || !chars.iter().copied().all(allowed) {
            return false;
        }
    }
    true
}

/// python `normalize_target` — ввод пользователя → (вид, очищенное значение,
/// текст ошибки).
///
/// Принимает домен, адрес, ссылку (`https://site.ru/page`) и `host:port`.
#[must_use]
pub fn normalize_target(value: &str) -> (String, String, String) {
    let raw = value.trim();
    if raw.is_empty() {
        return (
            KIND_INVALID.to_string(),
            String::new(),
            "Введите домен или IP-адрес.".to_string(),
        );
    }
    let mut raw = strip_scheme(raw).to_string();
    raw = raw
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if raw.starts_with('[') {
        if let Some(end) = raw.find(']') {
            raw = raw[1..end].to_string();
        }
    }

    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return (KIND_IP.to_string(), ip.to_string(), String::new());
    }

    if raw.matches(':').count() == 1 {
        if let Some((host, port)) = raw.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                let host = host.to_string();
                match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => return (KIND_IP.to_string(), ip.to_string(), String::new()),
                    Err(_) => raw = host,
                }
            }
        }
    }

    let host = raw.trim_end_matches('.').to_lowercase();
    let ascii_host = if host.is_empty() {
        String::new()
    } else {
        idna::domain_to_ascii(&host).unwrap_or_default()
    };
    if ascii_host.is_empty() || !hostname_matches(&ascii_host) {
        return (
            KIND_INVALID.to_string(),
            String::new(),
            "Не похоже на домен или IP-адрес. Пример: example.com или 1.2.3.4".to_string(),
        );
    }
    (KIND_DOMAIN.to_string(), host, String::new())
}

/// python-правда значения словаря (bool, число, строка, список).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// python `_KIND_NOTES` — оценка адреса по его виду.
fn kind_note(kind: AddressKind) -> (&'static str, &'static str) {
    match kind.value() {
        "public" => (LEVEL_OK, ""),
        "fake_ip" => (LEVEL_WARN, "адрес VPN-клиента (fake-ip)"),
        "self" => (LEVEL_FAIL, "заглушка (адрес самого компьютера)"),
        "local" => (LEVEL_WARN, "локальный адрес"),
        "carrier" => (LEVEL_WARN, "адрес внутренней сети провайдера"),
        "service" => (LEVEL_WARN, "служебный адрес"),
        // Заглушки разбираются отдельно (python `classify_ip`); остальное — «непонятно».
        _ => (LEVEL_UNKNOWN, "непонятный адрес"),
    }
}

/// python `classify_ip` — оценка адреса из DNS-ответа: (уровень, пояснение).
/// Обычный адрес — ("ok", "").
#[must_use]
pub fn classify_ip(ip: &str) -> (String, String) {
    let kind = address_kind(ip);
    if kind == AddressKind::BLOCK_STUB {
        return (
            LEVEL_FAIL.to_string(),
            format!("заглушка ({})", block_stub_owner(ip)),
        );
    }
    let (level, note) = kind_note(kind);
    (level.to_string(), note.to_string())
}

/// python `pick_ipv6` — IPv6-адрес домена для отдельного пинга (если основной
/// адрес — IPv4).
#[must_use]
pub fn pick_ipv6(answers: &[ResolverAnswer], primary_ip: &str) -> String {
    for item in answers {
        for ip in &item.ipv6 {
            if ip != primary_ip && classify_ip(ip).0 == LEVEL_OK {
                return ip.clone();
            }
        }
    }
    String::new()
}

/// python `ipaddress.ip_address(ip).is_global` — адрес виден из интернета.
fn ip_is_global(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || octets[0] == 0      // python is_private: «эта сеть» 0.0.0.0/8
                || octets[0] >= 240) // python is_reserved: 240.0.0.0/4
        }
        std::net::IpAddr::V6(v6) => ipv6_is_global(&v6),
    }
}

/// python `IPv6Address.is_global` — основные исключения из глобальных.
fn ipv6_is_global(v6: &std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    if v6.is_unspecified() || v6.is_loopback() {
        return false;
    }
    // fe80::/10 link-local и fec0::/10 (устаревший site-local).
    if (segments[0] & 0xffc0) == 0xfe80 || (segments[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    if (segments[0] & 0xff00) == 0xff00 {
        // multicast: глобальные — только ff0e::/16 и ff1e::/16.
        return segments[1] == 0x000e || segments[1] == 0x010e;
    }
    // 2001:db8::/32 — документация.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    // ::ffff:0:0/96 — адрес IPv4 внутри.
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        let v4 = std::net::Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return ip_is_global(std::net::IpAddr::V4(v4));
    }
    true
}

/// python `is_public_ip` — адрес виден из интернета.
#[must_use]
pub fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(parsed) => ip_is_global(parsed),
        Err(_) => false,
    }
}

/// python `program_ipv6` — адрес IPv6, на который Windows ведёт программы
/// первым. Пусто — первым идёт IPv4.
#[must_use]
pub fn program_ipv6(answers: &[ResolverAnswer]) -> String {
    for item in answers {
        if item.server.kind == SERVER_WINDOWS && item.status == primecore_dnswire::STATUS_OK {
            if item.first.contains(':') && classify_ip(&item.first).0 == LEVEL_OK {
                return item.first.clone();
            }
            return String::new();
        }
    }
    String::new()
}

/// python `road_trouble` — беда на дороге программ: [`ROAD_DEAD`] — по IPv6 нет
/// связи, [`ROAD_BLOCKED`] — связь есть, а имя сайта не проходит. Пусто — беды
/// нет или сравнить не с чем.
///
/// Вывод делается только из сравнения: по IPv4 то же самое работает. Если не
/// работает и там, это обычная блокировка или лежащий сайт — о них говорят
/// другие строки.
#[must_use]
pub fn road_trouble(report: &DomainLookupReport) -> String {
    let (Some(road), Some(tcp)) = (&report.road, &report.tcp) else {
        return String::new();
    };
    if tcp.status != "ok" || tcp.ip.contains(':') {
        return String::new();
    }
    if road.tcp.status != "ok" {
        return ROAD_DEAD.to_string();
    }
    let level = report
        .site
        .as_ref()
        .and_then(|site| site.get("level"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if road.opens == Some(false) && (level == "ok" || level == "warn") {
        return ROAD_BLOCKED.to_string();
    }
    String::new()
}

/// python `road_is_the_only_way` — Windows отдаёт программам одни адреса IPv6:
/// перейти на IPv4 им некуда.
///
/// Так бывает, когда в файле hosts у имени записаны только адреса IPv6: про
/// IPv4 Windows тогда у DNS уже не спрашивает (проверено на стенде 2026-10-14).
#[must_use]
pub fn road_is_the_only_way(report: &DomainLookupReport) -> bool {
    for item in &report.answers {
        if item.server.kind == SERVER_WINDOWS && item.status == primecore_dnswire::STATUS_OK {
            return !item.ipv6.is_empty() && item.ipv4.is_empty();
        }
    }
    false
}

/// python `hosts_road_wanted` — стоит ли пробовать адреса из «Редактора hosts»:
/// сайт закрыт, сервис для имени есть, его тумблер выключен.
#[must_use]
pub fn hosts_road_wanted(report: &DomainLookupReport) -> bool {
    let level = report
        .site
        .as_ref()
        .and_then(|site| site.get("level"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if level != "fail" || report.hosts_service.is_empty() || report.hosts_offered.is_empty() {
        return false;
    }
    !report
        .hosts_offered
        .iter()
        .any(|address| report.hosts_rows.contains(address))
}

/// python `_is_placeholder_name` — имя из зоны, которой в интернете нет по
/// стандарту (RFC 6761): это не сайт, а заглушка в сертификате.
#[must_use]
pub fn is_placeholder_name(name: &str) -> bool {
    let trimmed = name.trim_end_matches('.').to_lowercase();
    match trimmed.rsplit_once('.') {
        Some((_, tail)) => tail == "invalid" || tail == "localhost",
        None => false,
    }
}

/// python `_clean_names` — имена из ответа внешнего сервиса: без пробелов,
/// точек на конце и повторов, только похожие на домены.
#[must_use]
pub fn clean_names(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for value in values {
        let name = value.trim().trim_end_matches('.').to_lowercase();
        if hostname_matches(&name) && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// python `parse_thc_answer` — ответ ip.thc.org → (источник, метка следующей
/// страницы).
#[must_use]
pub fn parse_thc_answer(status_code: i32, text: &str) -> (NeighborSource, String) {
    if status_code == 429 {
        return (
            NeighborSource {
                detail: "слишком много запросов, попробуйте позже".to_string(),
                ..NeighborSource::new(SOURCE_THC, SOURCE_LIMIT)
            },
            String::new(),
        );
    }
    let data: Option<Value> = serde_json::from_str(text).ok();
    if status_code != 200 || !data.as_ref().is_some_and(Value::is_object) {
        return (
            NeighborSource {
                detail: format!("сервис ответил кодом {status_code}"),
                ..NeighborSource::new(SOURCE_THC, SOURCE_ERROR)
            },
            String::new(),
        );
    }
    let data = data.expect("dict проверен выше");
    if data.get("status").and_then(Value::as_str) == Some("error") {
        let detail = data
            .get("error")
            .or_else(|| data.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("ошибка сервиса");
        return (
            NeighborSource {
                detail: detail.chars().take(120).collect(),
                ..NeighborSource::new(SOURCE_THC, SOURCE_ERROR)
            },
            String::new(),
        );
    }
    let rows: Vec<&Value> = data
        .get("domains")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter(|row| row.is_object()).collect())
        .unwrap_or_default();
    let names = clean_names(
        rows.iter()
            .filter_map(|row| row.get("domain"))
            .filter_map(Value::as_str)
            .map(str::to_string),
    );
    let mut total = data.get("matching_records").and_then(Value::as_i64);
    if data.get("count_unavailable").is_some_and(truthy)
        || total.is_none_or(|count| count < names.len() as i64)
    {
        total = None;
    }
    let status = if names.is_empty() {
        SOURCE_EMPTY
    } else {
        SOURCE_OK
    };
    let next = data
        .get("next_page_state")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    (
        NeighborSource {
            names,
            total,
            ..NeighborSource::new(SOURCE_THC, status)
        },
        next,
    )
}

/// python `parse_hackertarget_answer` — ответ HackerTarget: по домену в строке
/// либо строка с отказом (код при этом 200).
#[must_use]
pub fn parse_hackertarget_answer(status_code: i32, text: &str) -> NeighborSource {
    let body = text.trim();
    let lowered = body.to_lowercase();
    if status_code == 429 || lowered.contains("api count exceeded") {
        return NeighborSource {
            detail: "исчерпан дневной лимит бесплатных запросов".to_string(),
            ..NeighborSource::new(SOURCE_HACKERTARGET, SOURCE_LIMIT)
        };
    }
    if status_code != 200 {
        return NeighborSource {
            detail: format!("сервис ответил кодом {status_code}"),
            ..NeighborSource::new(SOURCE_HACKERTARGET, SOURCE_ERROR)
        };
    }
    let names = clean_names(body.lines().map(str::to_string));
    if !names.is_empty() {
        return NeighborSource {
            names,
            ..NeighborSource::new(SOURCE_HACKERTARGET, SOURCE_OK)
        };
    }
    if body.is_empty() || lowered.contains("no dns a records") || lowered.contains("no records") {
        return NeighborSource::new(SOURCE_HACKERTARGET, SOURCE_EMPTY);
    }
    NeighborSource {
        detail: body.chars().take(120).collect(),
        ..NeighborSource::new(SOURCE_HACKERTARGET, SOURCE_ERROR)
    }
}

/// python `parse_shodan_answer` — имена и открытые порты по базе Shodan.
#[must_use]
pub fn parse_shodan_answer(status_code: i32, text: &str) -> NeighborSource {
    let data: Option<Value> = serde_json::from_str(text).ok();
    let has_detail_only = data.as_ref().is_some_and(|data| {
        data.is_object() && data.get("detail").is_some() && data.get("hostnames").is_none()
    });
    if status_code == 404 || has_detail_only {
        return NeighborSource::new(SOURCE_SHODAN, SOURCE_EMPTY);
    }
    if status_code == 429 {
        return NeighborSource {
            detail: "слишком много запросов, попробуйте позже".to_string(),
            ..NeighborSource::new(SOURCE_SHODAN, SOURCE_LIMIT)
        };
    }
    if status_code != 200 || !data.as_ref().is_some_and(Value::is_object) {
        return NeighborSource {
            detail: format!("сервис ответил кодом {status_code}"),
            ..NeighborSource::new(SOURCE_SHODAN, SOURCE_ERROR)
        };
    }
    let data = data.expect("dict проверен выше");
    let names = clean_names(
        data.get("hostnames")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );
    let ports: Vec<String> = data
        .get("ports")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_i64)
                .map(|port| port.to_string())
                .collect()
        })
        .unwrap_or_default();
    let extra = if ports.is_empty() {
        String::new()
    } else {
        format!(
            "открытые порты: {}",
            ports
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let status = if names.is_empty() && extra.is_empty() {
        SOURCE_EMPTY
    } else {
        SOURCE_OK
    };
    NeighborSource {
        names,
        extra,
        ..NeighborSource::new(SOURCE_SHODAN, status)
    }
}

/// python `parse_ripestat_answer` — официальные данные RIPE: подсеть и все
/// сети, которые её объявляют.
#[must_use]
pub fn parse_ripestat_answer(status_code: i32, text: &str) -> Option<NetworkInfo> {
    let data: Value = serde_json::from_str(text).ok()?;
    if status_code != 200 || !data.is_object() {
        return None;
    }
    let payload = data.get("data")?;
    if !payload.is_object() {
        return None;
    }
    let mut origins: Vec<(String, String)> = Vec::new();
    let empty_rows: Vec<Value> = Vec::new();
    for item in payload
        .get("asns")
        .and_then(Value::as_array)
        .unwrap_or(&empty_rows)
    {
        if let Some(asn) = item.get("asn").filter(|asn| !asn.is_null()) {
            origins.push((
                match asn {
                    Value::Number(number) => number.to_string(),
                    other => other.as_str().unwrap_or_default().to_string(),
                },
                item.get("holder")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            ));
        }
    }
    let prefix = if payload.get("announced").is_some_and(truthy) {
        payload
            .get("resource")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    if origins.is_empty() && prefix.is_empty() {
        return None;
    }
    Some(NetworkInfo {
        prefix,
        origins,
        ..NetworkInfo::default()
    })
}

/// python `merge_network` — склеивает сведения о сети из двух источников:
/// непустое поле не затирается пустым.
#[must_use]
pub fn merge_network(
    current: Option<NetworkInfo>,
    update: Option<NetworkInfo>,
) -> Option<NetworkInfo> {
    match (current, update) {
        (None, other) | (other, None) => other,
        (Some(current), Some(update)) => Some(NetworkInfo {
            asn: if current.asn.is_empty() {
                update.asn
            } else {
                current.asn
            },
            prefix: if current.prefix.is_empty() {
                update.prefix
            } else {
                current.prefix
            },
            country: if current.country.is_empty() {
                update.country
            } else {
                current.country
            },
            owner: if current.owner.is_empty() {
                update.owner
            } else {
                current.owner
            },
            origins: if current.origins.is_empty() {
                update.origins
            } else {
                current.origins
            },
        }),
    }
}

/// python `encrypted_known` — адреса серверов, которые по шифрованному каналу
/// назвали адрес сайта.
#[must_use]
pub fn encrypted_known(answers: &[ResolverAnswer]) -> Vec<String> {
    answers
        .iter()
        .filter(|item| {
            item.server.kind == SERVER_DOH
                && item.status == primecore_dnswire::STATUS_OK
                && !item.addresses().is_empty()
        })
        .map(|item| item.server.address.clone())
        .collect()
}

/// python `forged_answers` — подставные ответы «домена нет» на обычный запрос.
/// Три независимых признака.
///
/// Первый и второй — сравнение сервера с самим собой: по TCP или по
/// шифрованному каналу он адрес назвал, а на обычный запрос (UDP) «ответил»,
/// что домена нет. Настоящий сервер так не может, значит обычный ответ прислал
/// кто-то по дороге.
///
/// Третий — подпись самого ответа (`ResolverAnswer.forged`). Она встречается и
/// у домашних фильтров рекламы, поэтому учитывается только когда другие серверы
/// адрес назвали: тогда ясно, что сайт существует, а отказ придуман.
#[must_use]
pub fn forged_answers(answers: &[ResolverAnswer]) -> Vec<ResolverAnswer> {
    forged_indices(answers)
        .into_iter()
        .map(|index| answers[index].clone())
        .collect()
}

/// Те же ответы номерами в списке — для пометки в [`annotate_answers`].
fn forged_indices(answers: &[ResolverAnswer]) -> Vec<usize> {
    let known = encrypted_known(answers);
    let someone_resolved = answers.iter().any(|item| {
        item.server.kind != SERVER_WINDOWS
            && item.status == primecore_dnswire::STATUS_OK
            && !item.addresses().is_empty()
    });
    let mut found = Vec::new();
    for (index, item) in answers.iter().enumerate() {
        if item.server.kind == SERVER_DOH || item.server.kind == SERVER_WINDOWS {
            continue;
        }
        let denied = item.status == primecore_dnswire::STATUS_NXDOMAIN
            || item.status == primecore_dnswire::STATUS_EMPTY;
        let named_otherwise = !item.tcp_ipv4.is_empty() || known.contains(&item.server.address);
        let marked =
            item.status == primecore_dnswire::STATUS_NXDOMAIN && item.forged && someone_resolved;
        if (denied && named_otherwise) || marked {
            found.push(index);
        }
    }
    found
}

/// python `windows_blind` — Windows адрес не получила, хотя DNS-серверы его
/// знают: программы на компьютере сайт не найдут.
#[must_use]
pub fn windows_blind(answers: &[ResolverAnswer]) -> bool {
    let windows: Vec<&ResolverAnswer> = answers
        .iter()
        .filter(|item| item.server.kind == SERVER_WINDOWS)
        .collect();
    let others: Vec<&ResolverAnswer> = answers
        .iter()
        .filter(|item| item.server.kind != SERVER_WINDOWS)
        .collect();
    !windows.is_empty()
        && windows
            .iter()
            .all(|item| item.status != primecore_dnswire::STATUS_OK)
        && others
            .iter()
            .any(|item| item.status == primecore_dnswire::STATUS_OK && !item.addresses().is_empty())
}

/// python `_forged_note` — чем доказана подмена — самым прямым из сработавших
/// признаков.
#[must_use]
pub fn forged_note(item: &ResolverAnswer, answers: &[ResolverAnswer]) -> String {
    if let Some(ip) = item.tcp_ipv4.first() {
        return NOTE_FORGED_TCP.replace("{ip}", ip);
    }
    if encrypted_known(answers).contains(&item.server.address) {
        return NOTE_FORGED.to_string();
    }
    NOTE_FORGED_MARK.to_string()
}

/// python `annotate_answers` — проставляет уровень и пояснение каждому ответу.
///
/// Разные адреса у разных серверов — норма (у крупных сайтов серверы по всему
/// миру), поэтому помечаются только явные признаки: заглушка, локальный адрес,
/// «домена нет» там, где у других он есть.
#[must_use]
pub fn annotate_answers(answers: Vec<ResolverAnswer>) -> Vec<ResolverAnswer> {
    let someone_resolved = answers.iter().any(|item| {
        item.server.kind != SERVER_WINDOWS
            && item.status == primecore_dnswire::STATUS_OK
            && !item.addresses().is_empty()
    });
    let forged = forged_indices(&answers);
    let mut result = Vec::with_capacity(answers.len());
    for index in 0..answers.len() {
        let item = answers[index].clone();
        let mut level = LEVEL_OK.to_string();
        let mut note = String::new();
        if item.server.kind == SERVER_WINDOWS && item.status != primecore_dnswire::STATUS_OK {
            // Строка Windows — то, что получают браузер и программы. Если серверы адрес
            // знают, а Windows нет, это главная находка, а не «не узнали».
            if someone_resolved {
                level = LEVEL_WARN.to_string();
                note = NOTE_WINDOWS_BLIND.to_string();
            } else {
                level = LEVEL_UNKNOWN.to_string();
            }
        } else if forged.contains(&index) {
            level = LEVEL_WARN.to_string();
            note = forged_note(&item, &answers);
        } else if item.status == primecore_dnswire::STATUS_OK {
            let mut notes: Vec<String> = Vec::new();
            for ip in item.addresses() {
                let (ip_level, ip_note) = classify_ip(&ip);
                level = worst(&[level.as_str(), ip_level.as_str()]);
                if !ip_note.is_empty() && !notes.contains(&ip_note) {
                    notes.push(ip_note);
                }
            }
            note = notes.join(", ");
        } else if item.status == primecore_dnswire::STATUS_NXDOMAIN
            || item.status == primecore_dnswire::STATUS_EMPTY
        {
            if someone_resolved {
                level = LEVEL_WARN.to_string();
                note = "у других серверов адрес есть".to_string();
            } else {
                level = LEVEL_UNKNOWN.to_string();
            }
        } else {
            // Отказ сервера или сбой запроса: о самом адресе это ничего не говорит.
            level = LEVEL_UNKNOWN.to_string();
            note = item.note.clone();
        }
        result.push(ResolverAnswer {
            level,
            note,
            ..item
        });
    }
    result
}

/// python `pick_primary_ip` — адрес для пинга и поиска соседей.
///
/// Сначала тот, которым реально пользуются программы на компьютере (строка
/// Windows), затем ответ DNS-серверов системы, затем шифрованный ответ (по нему
/// же проверяется, как открывается сайт) и только потом самый частый среди
/// остальных. Иначе у крупного сайта «самым частым» оказывается далёкий
/// зарубежный узел, на который этот компьютер никогда не попадёт. Заглушки
/// берём в последнюю очередь: если других адресов нет, полезно увидеть, что
/// отвечает именно она.
#[must_use]
pub fn pick_primary_ip(answers: &[ResolverAnswer]) -> String {
    let clean = |addresses: &[String]| -> Vec<String> {
        addresses
            .iter()
            .filter(|ip| classify_ip(ip).0 == LEVEL_OK)
            .cloned()
            .collect()
    };
    for kind in [SERVER_WINDOWS, SERVER_SYSTEM, SERVER_DOH] {
        for item in answers {
            if item.server.kind != kind {
                continue;
            }
            // У сервера с подставным «домена нет» настоящий ответ — тот, что он дал по TCP.
            let good = clean(&item.ipv4);
            let good = if good.is_empty() {
                clean(&item.tcp_ipv4)
            } else {
                good
            };
            if let Some(first) = good.first() {
                return first.clone();
            }
        }
    }
    let most_common = |lists: Vec<Vec<String>>| -> Option<String> {
        let mut counter: Vec<(String, usize)> = Vec::new();
        for list in lists {
            for ip in list {
                match counter.iter_mut().find(|(known, _)| *known == ip) {
                    Some((_, count)) => *count += 1,
                    None => counter.push((ip, 1)),
                }
            }
        }
        counter
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, _)| ip.clone())
    };
    let ipv4_lists: Vec<Vec<String>> = answers.iter().map(|item| clean(&item.ipv4)).collect();
    if let Some(ip) = most_common(ipv4_lists) {
        return ip;
    }
    let ipv6_lists: Vec<Vec<String>> = answers.iter().map(|item| clean(&item.ipv6)).collect();
    if let Some(ip) = most_common(ipv6_lists) {
        return ip;
    }
    for item in answers {
        let addresses = item.addresses();
        if let Some(first) = addresses.first() {
            return first.clone();
        }
    }
    String::new()
}

/// python `_unique_servers` — список без повторов и без адресов, не похожих на IP.
#[must_use]
pub fn unique_servers(servers: &[DnsServer]) -> Vec<DnsServer> {
    let mut seen: Vec<String> = Vec::new();
    let mut result: Vec<DnsServer> = Vec::new();
    for server in servers {
        let address = server.address.trim().to_string();
        let key = format!(
            "{}:{address}",
            if server.kind == SERVER_DOH {
                "doh"
            } else {
                "udp"
            }
        );
        if address.is_empty() || seen.contains(&key) {
            continue;
        }
        if address.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        seen.push(key);
        result.push(server.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_lookup_steps::test_fixtures as fx;

    #[test]
    fn links_ports_and_case_are_cleaned() {
        let cases: Vec<(&str, &str, &str)> = vec![
            ("https://Example.COM/page?x=1", KIND_DOMAIN, "example.com"),
            ("example.com:8443", KIND_DOMAIN, "example.com"),
            (" 8.8.8.8 ", KIND_IP, "8.8.8.8"),
            ("1.2.3.4:443", KIND_IP, "1.2.3.4"),
            ("[2001:db8::1]:443", KIND_IP, "2001:db8::1"),
            ("2001:db8::1", KIND_IP, "2001:db8::1"),
            ("пример.рф", KIND_DOMAIN, "пример.рф"),
        ];
        for (raw, kind, value) in cases {
            let (got_kind, got_value, error) = normalize_target(raw);
            assert_eq!(
                (got_kind.as_str(), got_value.as_str()),
                (kind, value),
                "{raw}"
            );
            assert!(error.is_empty(), "{raw}");
        }
    }

    #[test]
    fn garbage_is_rejected_with_explanation() {
        for raw in [
            "",
            "   ",
            "localhost",
            "exa mple.com",
            "http://",
            "-bad-.com",
        ] {
            let (kind, _value, error) = normalize_target(raw);
            assert_eq!(kind, KIND_INVALID, "{raw}");
            assert!(!error.is_empty(), "{raw}");
        }
    }

    #[test]
    fn address_classes() {
        assert_eq!(
            classify_ip("93.184.216.34"),
            (LEVEL_OK.to_string(), String::new())
        );
        let (level, note) = classify_ip("195.82.146.214");
        assert_eq!(level, LEVEL_FAIL);
        assert!(note.contains("Ростелеком"), "{note}");
        assert_eq!(classify_ip("127.0.0.1").0, LEVEL_FAIL);
        assert_eq!(classify_ip("192.168.1.1").0, LEVEL_WARN);
        assert!(classify_ip("198.18.0.5").1.contains("VPN"));
    }

    #[test]
    fn different_addresses_are_not_marked() {
        let answers = annotate_answers(vec![
            fx::answer_with_ipv4(&fx::good(), &["1.1.1.1"]),
            fx::answer_with_ipv4(&fx::secure(), &["8.8.8.8"]),
        ]);
        assert_eq!(
            answers
                .iter()
                .map(|item| item.level.as_str())
                .collect::<Vec<_>>(),
            vec![LEVEL_OK, LEVEL_OK]
        );
    }

    #[test]
    fn nxdomain_is_suspicious_only_when_others_resolve() {
        let lonely = annotate_answers(vec![fx::denied(&fx::good())]);
        let mixed = annotate_answers(vec![
            fx::answer_with_ipv4(&fx::good(), &["1.1.1.1"]),
            fx::denied(&fx::stub()),
        ]);
        assert_eq!(lonely[0].level, LEVEL_UNKNOWN);
        assert_eq!(mixed[1].level, LEVEL_WARN);
    }

    #[test]
    fn primary_ip_prefers_windows_and_skips_stubs() {
        let windows = DnsServer::with_kind("Windows", "", SERVER_WINDOWS);
        let answers = vec![
            fx::answer_with_ipv4(&fx::stub(), &["195.82.146.214"]),
            fx::answer_with_ipv4(&fx::good(), &["1.1.1.1"]),
            fx::answer_with_ipv4(&windows, &["195.82.146.214", "2.2.2.2"]),
        ];
        assert_eq!(pick_primary_ip(&answers), "2.2.2.2");
        assert_eq!(pick_primary_ip(&answers[..2]), "1.1.1.1");
        assert_eq!(pick_primary_ip(&answers[..1]), "195.82.146.214");
        assert_eq!(pick_primary_ip(&[]), "");
    }

    #[test]
    fn primary_ip_goes_windows_then_system_then_encrypted_then_most_common() {
        // У крупного сайта «самый частый» адрес — далёкий зарубежный узел: компьютер на него не попадёт.
        let far: Vec<ResolverAnswer> = (1..=3)
            .map(|n| {
                fx::answer_with_ipv4(
                    &DnsServer::new(format!("Дальний {n}"), format!("203.0.113.{n}")),
                    &["5.5.5.5"],
                )
            })
            .collect();
        let system = fx::answer_with_ipv4(
            &DnsServer::with_kind("", "8.8.4.4", SERVER_SYSTEM),
            &["3.3.3.3"],
        );
        let secure = fx::answer_with_ipv4(&fx::secure(), &["4.4.4.4"]);
        let windows = fx::denied(&DnsServer::with_kind("Windows", "", SERVER_WINDOWS));

        assert_eq!(
            pick_primary_ip(
                &[
                    far.clone(),
                    vec![system.clone()],
                    vec![secure.clone()],
                    vec![windows.clone()]
                ]
                .concat()
            ),
            "3.3.3.3"
        );
        assert_eq!(
            pick_primary_ip(&[far.clone(), vec![secure], vec![windows.clone()]].concat()),
            "4.4.4.4"
        );
        assert_eq!(pick_primary_ip(&[far, vec![windows]].concat()), "5.5.5.5");
    }

    #[test]
    fn primary_ip_takes_tcp_answer_of_system_server_with_forged_denial() {
        let system = ResolverAnswer {
            tcp_ipv4: vec!["3.3.3.3".to_string()],
            ..fx::denied(&DnsServer::with_kind("", "8.8.8.8", SERVER_SYSTEM))
        };
        let far = fx::answer_with_ipv4(&fx::good(), &["5.5.5.5"]);
        assert_eq!(pick_primary_ip(&[far, system]), "3.3.3.3");
    }

    #[test]
    fn windows_without_address_is_a_finding_when_servers_know_the_site() {
        let windows = DnsServer::with_kind("Windows", "", SERVER_WINDOWS);
        let blind = annotate_answers(vec![
            fx::denied(&windows),
            fx::answer_with_ipv4(&fx::good(), &["1.1.1.1"]),
        ]);
        let nobody = annotate_answers(vec![fx::denied(&windows), fx::denied(&fx::good())]);

        assert_eq!(blind[0].level, LEVEL_WARN);
        assert_eq!(blind[0].note, NOTE_WINDOWS_BLIND);
        assert!(windows_blind(&blind));
        // Домена и правда нет: Windows не виновата.
        assert_eq!(nobody[0].level, LEVEL_UNKNOWN);
        assert!(!windows_blind(&nobody));
    }

    #[test]
    fn denial_is_forged_when_the_same_server_names_the_address_over_tcp() {
        let plain = DnsServer::with_kind("Google", "8.8.8.8", SERVER_SYSTEM);
        let answers = annotate_answers(vec![ResolverAnswer {
            tcp_ipv4: vec!["64.233.165.93".to_string()],
            ..fx::denied(&plain)
        }]);
        assert_eq!(forged_answers(&answers), answers);
        assert_eq!(answers[0].level, LEVEL_WARN);
        assert!(
            answers[0]
                .note
                .contains("по TCP тот же сервер адрес называет (64.233.165.93)"),
            "{}",
            answers[0].note
        );
    }

    #[test]
    fn denial_is_forged_when_the_same_server_names_the_address_encrypted() {
        let plain = DnsServer::new("OpenDNS", "208.67.222.222");
        let secure = DnsServer::with_kind("OpenDNS (шифрованный)", "208.67.222.222", SERVER_DOH);
        let other = DnsServer::new("Чужой", "203.0.113.5");
        let answers = annotate_answers(vec![
            fx::answer_with_ipv4(&secure, &["142.251.142.238"]),
            fx::denied(&plain),
            fx::denied(&other),
        ]);
        assert_eq!(
            forged_answers(&answers)
                .iter()
                .map(|item| item.server.label.as_str())
                .collect::<Vec<_>>(),
            vec!["OpenDNS"]
        );
        assert_eq!(answers[1].note, NOTE_FORGED);
        // У сервера без шифрованной пары доказательства нет: он просто отвечает не как остальные.
        assert_eq!(answers[2].note, "у других серверов адрес есть");
    }

    #[test]
    fn forged_mark_counts_only_next_to_honest_answers() {
        let marked = ResolverAnswer {
            forged: true,
            ..fx::denied(&fx::good())
        };
        let honest = fx::answer_with_ipv4(&fx::dead(), &["1.1.1.1"]);

        assert!(forged_answers(std::slice::from_ref(&marked)).is_empty());
        assert_eq!(
            forged_answers(&[marked.clone(), honest.clone()]),
            vec![marked.clone()]
        );
        assert_eq!(
            annotate_answers(vec![marked, honest])[0].note,
            NOTE_FORGED_MARK
        );
    }

    #[test]
    fn extra_servers_have_no_resolver_that_refuses_everyone() {
        // Mullvad обычным запросом отвечает только про собственные имена; UltraDNS уже есть в списке программы.
        let labels: Vec<&str> = EXTRA_SERVERS.iter().map(|(label, _)| *label).collect();
        assert!(!labels.contains(&"Mullvad"));
        assert!(!labels.contains(&"UltraDNS"));
    }

    #[test]
    fn external_answers_are_parsed() {
        let ok =
            parse_hackertarget_answer(200, "API count exceeded - Increase Quota with Membership");
        assert_eq!(ok.status, SOURCE_LIMIT);

        let listed =
            parse_hackertarget_answer(200, "A.example.com\nb.example.com\nb.example.com\n");
        assert_eq!(listed.names, vec!["a.example.com", "b.example.com"]);
        assert_eq!(parse_hackertarget_answer(200, "").status, SOURCE_EMPTY);
        assert_eq!(
            parse_hackertarget_answer(200, "error check your search parameter").status,
            SOURCE_ERROR
        );
        assert_eq!(parse_hackertarget_answer(503, "oops").status, SOURCE_ERROR);

        let body = r#"{"matching_records": 97, "domains": [{"domain": "a.example"}], "next_page_state": "abc"}"#;
        let (source, state) = parse_thc_answer(200, body);
        assert_eq!(
            (
                source.status.as_str(),
                source.names.as_slice(),
                source.total,
                state.as_str()
            ),
            (
                SOURCE_OK,
                vec!["a.example".to_string()].as_slice(),
                Some(97),
                "abc"
            )
        );

        let (error, _) = parse_thc_answer(200, r#"{"status": "error", "error": "invalid ip"}"#);
        assert_eq!(
            (error.status.as_str(), error.detail.as_str()),
            (SOURCE_ERROR, "invalid ip")
        );
        assert_eq!(parse_thc_answer(200, "<html>").0.status, SOURCE_ERROR);
        assert_eq!(parse_thc_answer(429, "").0.status, SOURCE_LIMIT);

        let source =
            parse_shodan_answer(200, r#"{"hostnames": ["a.example"], "ports": [443, 80]}"#);
        assert_eq!(
            (source.names.as_slice(), source.extra.as_str()),
            (
                vec!["a.example".to_string()].as_slice(),
                "открытые порты: 443, 80"
            )
        );
        let empty = parse_shodan_answer(404, r#"{"detail": "No information available"}"#);
        assert_eq!(empty.status, SOURCE_EMPTY);

        let body = r#"{"data": {"resource": "5.255.255.0/24", "announced": true, "asns": [{"asn": 1, "holder": "A"}, {"asn": 2, "holder": "B"}]}}"#;
        let info = parse_ripestat_answer(200, body).expect("сети есть");
        assert_eq!(
            info.origins,
            vec![
                ("1".to_string(), "A".to_string()),
                ("2".to_string(), "B".to_string())
            ]
        );
        assert!(parse_ripestat_answer(200, "not json").is_none());

        let merged = merge_network(
            Some(NetworkInfo {
                asn: "1".to_string(),
                owner: "Cymru".to_string(),
                ..NetworkInfo::default()
            }),
            Some(info),
        )
        .expect("склеилось");
        assert_eq!(
            (
                merged.asn.as_str(),
                merged.owner.as_str(),
                merged.prefix.as_str(),
                merged.origins.len()
            ),
            ("1", "Cymru", "5.255.255.0/24", 2)
        );
    }

    #[test]
    fn placeholder_certificate_name_is_recognized() {
        assert!(is_placeholder_name("invalid2.invalid"));
        assert!(!is_placeholder_name("example.com"));
    }

    #[test]
    fn unique_servers_drop_duplicates_and_non_addresses() {
        let servers = vec![
            DnsServer::new("A", "9.9.9.9"),
            DnsServer::with_kind("B", "9.9.9.9", SERVER_DOH),
            DnsServer::with_kind("C", "9.9.9.9", SERVER_DOH),
            DnsServer::new("имя", "dns.example"),
            DnsServer::new("пустой", "  "),
        ];
        let unique = unique_servers(&servers);
        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0].label, "A");
        assert_eq!(unique[1].label, "B");
    }
}
