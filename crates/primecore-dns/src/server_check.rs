//! Порт `src/dns/server_check.py` — проверка DNS-серверов: каждый адрес
//! каждым способом и перехват по дороге.
//!
//! Что собирается (наблюдения): по каждому адресу каждого сервера независимо
//! друг от друга — пинг (ICMP), обычный DNS по UDP и по TCP (порт 53),
//! шифрованный DNS DoT (порт 853) и DoH (порт 443). Провайдер может закрыть
//! любой из способов отдельно и для отдельного адреса (8.8.8.8 закрыт,
//! 8.8.4.4 работает), поэтому проверяется каждая пара.
//!
//! Сервер только с шифрованием (`encrypted_only`) обычный DNS не принимает
//! сам: обычным путём его не спрашивают вовсе.
//!
//! Каждым способом сервер спрашивается несколько раз подряд
//! ([`PROBE_ATTEMPTS`]), каждый раз новым соединением: блокировка иногда
//! включается не с первого запроса. Способ, который ответил лишь на часть
//! запросов, остаётся рабочим, но помечается как «отвечает через раз».
//!
//! Затем у того же адреса спрашивается, **кто на самом деле отвечает**:
//! имя `whoami.akamai.net` возвращает адрес сервера, который пришёл за
//! ответом. Вопрос задаётся дважды — обычным путём и шифрованным. И наконец
//! несколько часто блокируемых сайтов спрашиваются обоими путями.
//!
//! Выводы считаются отдельно от сбора (`judge_row`, `judge_report` —
//! [`crate::server_check_verdicts`]) и опираются на противоречия, а не на
//! догадки. Здесь — типы, сбор серии ([`series`]) и цели проверки
//! ([`build_targets`]).

use primecore_dnswire::doh::query_doh;
use primecore_dnswire::dot::query_dot;
use primecore_dnswire::net::{query_tcp, query_udp};
use primecore_dnswire::{
    DnsQueryResult, FAILURE_CANCELLED, FAILURE_CLOSED, FAILURE_RESET, FAILURE_TIMEOUT, FAILURE_TLS,
    TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_TCP, TRANSPORT_UDP, TYPE_A,
};
use serde::{Deserialize, Serialize};

pub use primecore_dnswire::TYPE_AAAA;

// Порядок столбцов таблицы.
pub const TRANSPORT_ICMP: &str = "icmp";
pub const TRANSPORTS: [&str; 5] = [
    TRANSPORT_ICMP,
    TRANSPORT_UDP,
    TRANSPORT_TCP,
    TRANSPORT_DOT,
    TRANSPORT_DOH,
];

pub const STATE_OK: &str = "ok";
pub const STATE_FAIL: &str = "fail";
pub const STATE_SKIP: &str = "skip";
pub const STATE_UNKNOWN: &str = "unknown";

pub const LEVEL_OK: &str = "ok";
pub const LEVEL_INFO: &str = "info";
pub const LEVEL_WARN: &str = "warn";
pub const LEVEL_FAIL: &str = "fail";

pub const CODE_INTERCEPTED: &str = "intercepted";
pub const CODE_SPOOFED: &str = "spoofed";
pub const CODE_FOREIGN_ANSWERS: &str = "foreign_answers";
pub const CODE_DEAD: &str = "dead";
pub const CODE_UDP_BLOCKED: &str = "udp_blocked";
pub const CODE_TCP_BLOCKED: &str = "tcp_blocked";
pub const CODE_DOT_BLOCKED: &str = "dot_blocked";
pub const CODE_DOH_BLOCKED: &str = "doh_blocked";
pub const CODE_DOH_NAME_BLOCKED: &str = "doh_name_blocked";
pub const CODE_UNSTABLE: &str = "unstable";
pub const CODE_SELF_FILTER: &str = "self_filter";
pub const CODE_BEST: &str = "best";
pub const CODE_BYPASS_RUNNING: &str = "bypass_running";
pub const CODE_ALL_FINE: &str = "all_fine";

pub const PROBE_DOMAIN: &str = "example.com";
pub const WHOAMI_DOMAIN: &str = "whoami.akamai.net";

/// Часто блокируемые сайты: спрашиваются обоими путями.
pub const SENSITIVE_DOMAINS: [&str; 3] = ["rutor.info", "flibusta.is", "rezka.ag"];

pub const UDP_TIMEOUT_S: f64 = 1.5;
pub const TCP_TIMEOUT_S: f64 = 4.0;
pub const ENCRYPTED_TIMEOUT_S: f64 = 4.0;
pub const DOH_WITHOUT_NAME_AFTER_S: f64 = 1.0;
pub const PING_COUNT: u32 = 2;
pub const PING_TIMEOUT_MS: u32 = 1500;

/// Сколько раз каждым способом спрашивается сервер.
pub const PROBE_ATTEMPTS: usize = 3;

/// Срок поиска владельцев сетей: эталоны бывают закрыты и молчат подолгу.
pub const OWNERS_BUDGET_S: f64 = 10.0;
/// Срок всей проверки.
pub const RUN_DEADLINE_S: f64 = 75.0;

/// Сбои, при которых DoH по имени считают закрытым по имени (python
/// `_NAME_BLOCK_FAILURES`).
pub fn name_block_failure(failure: &str) -> bool {
    [FAILURE_TIMEOUT, FAILURE_RESET, FAILURE_CLOSED, FAILURE_TLS].contains(&failure)
}

/// python `CheckTarget` — один адрес сервера и то, что нужно для шифрованных
/// запросов к нему.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckTarget {
    pub provider: String,
    pub address: String,
    #[serde(default)]
    pub dot_host: String,
    #[serde(default)]
    pub doh_host: String,
    #[serde(default)]
    pub doh_port: u16,
    #[serde(default = "default_doh_path")]
    pub doh_path: String,
    /// Сервер сам не отвечает на обычный DNS (порт 53): только DoT и DoH.
    #[serde(default)]
    pub encrypted_only: bool,
    /// Значок и цвет сервера из каталога — только для показа.
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub color: String,
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

/// python `Cell` — итог одного способа связи с одним адресом.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    pub state: String,
    pub elapsed_ms: Option<f64>,
    /// У ответившего способа — причина сорвавшихся запросов серии, если такие были.
    pub failure: String,
    pub reason: String,
    /// Чем закончился каждый запрос серии, по порядку. Пусто, если серии не
    /// было (пинг).
    #[serde(default)]
    pub trail: Vec<bool>,
}

impl Cell {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.state == STATE_OK
    }

    #[must_use]
    pub fn attempts(&self) -> usize {
        self.trail.len()
    }

    #[must_use]
    pub fn answered(&self) -> usize {
        self.trail.iter().filter(|answered| **answered).count()
    }

    /// Способ работает, но часть запросов серии сорвалась.
    #[must_use]
    pub fn unstable(&self) -> bool {
        self.state == STATE_OK && !self.trail.iter().all(|answered| *answered)
    }

    /// Первые запросы прошли, а дальше связь закрылась: так включается блокировка.
    #[must_use]
    pub fn fades(&self) -> bool {
        self.unstable()
            && self.trail.first().copied().unwrap_or(false)
            && !self.trail.last().copied().unwrap_or(true)
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.state == STATE_FAIL
    }
}

/// python `DomainFact` — что один и тот же сервер ответил про сайт обычным и
/// шифрованным путём.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DomainFact {
    pub domain: String,
    #[serde(default)]
    pub udp_status: String,
    #[serde(default)]
    pub udp_ips: Vec<String>,
    #[serde(default)]
    pub secure_status: String,
    #[serde(default)]
    pub secure_ips: Vec<String>,
}

/// python `Finding` — вывод проверки. `text` — фраза целиком, для журнала и
/// текстового отчёта.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub level: String,
    pub code: String,
    pub text: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub servers: Vec<(String, String)>,
    #[serde(default)]
    pub note: String,
}

/// python `Observation` — все факты об одном адресе. Выводов здесь нет.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub target: CheckTarget,
    #[serde(default)]
    pub cells: Vec<(String, Cell)>,
    /// DoH без имени сервера: проверяется, только если по имени он не ответил.
    #[serde(default)]
    pub doh_by_address: Option<Cell>,
    /// Кто выполнил запрос «кто ты»: обычным путём и шифрованным.
    #[serde(default)]
    pub udp_egress: String,
    #[serde(default)]
    pub secure_egress: String,
    /// Каким шифрованным (или хотя бы не UDP) путём сервер отвечал на
    /// контрольные вопросы.
    #[serde(default)]
    pub secure_via: String,
    #[serde(default)]
    pub domains: Vec<DomainFact>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Observation {
    /// python `cell(transport)` — ячейка способа; неизвестный способ —
    /// пустая ячейка.
    #[must_use]
    pub fn cell(&self, transport: &str) -> Cell {
        self.cells
            .iter()
            .find(|(name, _)| name == transport)
            .map(|(_, cell)| cell.clone())
            .unwrap_or_default()
    }
}

/// python `IpOwner` — тот же вид, что в dns.answering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpOwner {
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub owner: String,
}

/// python `ServerCheckReport`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerCheckReport {
    pub rows: Vec<Observation>,
    pub total: usize,
    /// Ответил ли адрес, где DNS-сервера нет. None — ещё не проверено.
    pub canary: Option<bool>,
    #[serde(default)]
    pub owners: Vec<(String, IpOwner)>,
    /// Программы обхода и VPN, работавшие во время проверки (вместе с Zapret).
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub finished: bool,
    #[serde(default)]
    pub stopped: bool,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub elapsed_s: f64,
    /// Запись этой проверки в истории вкладки (с путём к файлу отчёта). None —
    /// в историю не попала.
    #[serde(default)]
    pub history_entry: Option<serde_json::Value>,
}

impl ServerCheckReport {
    /// python `owner_of(ip)` — владелец сети адреса.
    #[must_use]
    pub fn owner_of(&self, ip: &str) -> Option<&IpOwner> {
        self.owners
            .iter()
            .find(|(address, _)| address == ip)
            .map(|(_, owner)| owner)
    }
}

/// python `build_targets` — адреса для проверки из списка серверов программы
/// (со своими серверами пользователя).
#[must_use]
pub fn build_targets(
    providers: &serde_json::Map<String, serde_json::Value>,
    ipv6: bool,
) -> Vec<CheckTarget> {
    let mut targets: Vec<CheckTarget> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for group in providers.values() {
        let Some(group) = group.as_object() else {
            continue;
        };
        for (name, data) in group {
            let (doh_host, doh_port, doh_path) = doh_parts(data);
            let mut addresses: Vec<String> = strings(data, "ipv4");
            if ipv6 {
                addresses.extend(strings(data, "ipv6"));
            }
            for raw in addresses {
                let address = raw.trim().to_string();
                if address.is_empty() || seen.contains(&address) {
                    continue;
                }
                seen.push(address.clone());
                targets.push(CheckTarget {
                    provider: name.clone(),
                    address,
                    dot_host: strings_text(data, "dot"),
                    doh_host: doh_host.clone(),
                    doh_port,
                    doh_path: doh_path.clone(),
                    encrypted_only: data
                        .get("encrypted_only")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    icon: strings_text(data, "icon"),
                    color: strings_text(data, "color"),
                });
            }
        }
    }
    targets
}

/// (имя для сертификата, порт, путь) из шаблона DoH плитки (python urlsplit).
fn doh_parts(data: &serde_json::Value) -> (String, u16, String) {
    let doh = data
        .get("doh")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    let (scheme, rest) = match doh.split_once("://") {
        Some(parts) => parts,
        None => return (String::new(), 443, "/dns-query".to_string()),
    };
    if scheme != "https" {
        return (String::new(), 443, "/dns-query".to_string());
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = rest.get(authority_end..).unwrap_or("");
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        match rest.split_once(']') {
            Some((host, after)) => (
                host,
                after
                    .strip_prefix(':')
                    .and_then(|port| port.parse().ok())
                    .unwrap_or(443),
            ),
            None => (authority, 443),
        }
    } else if authority.matches(':').count() == 1 {
        match authority.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() => {
                (host, port.parse().expect("проверено"))
            }
            _ => (authority, 443),
        }
    } else {
        (authority, 443)
    };
    (
        host.to_string(),
        port,
        if path.is_empty() {
            "/dns-query".to_string()
        } else {
            path.to_string()
        },
    )
}

fn strings(data: &serde_json::Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn strings_text(data: &serde_json::Value, key: &str) -> String {
    data.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// python `_cell(result)` — ячейка из одного ответа.
#[must_use]
pub fn cell_of(result: &DnsQueryResult) -> Cell {
    if result.answered() {
        return Cell {
            state: STATE_OK.to_string(),
            elapsed_ms: result.elapsed_ms,
            ..Cell::default()
        };
    }
    if result.failure == FAILURE_CANCELLED {
        return Cell::default();
    }
    Cell {
        state: STATE_FAIL.to_string(),
        failure: result.failure.clone(),
        reason: result.failure_text(),
        ..Cell::default()
    }
}

/// python `_twice` — запрос с одним повтором после молчания: одиночная потеря
/// — ещё не «закрыто».
fn twice(ask: &mut dyn FnMut() -> DnsQueryResult) -> DnsQueryResult {
    let result = ask();
    if !result.answered() && result.failure == FAILURE_TIMEOUT {
        return ask();
    }
    result
}

/// python `_series` — несколько запросов подряд одним способом, каждый —
/// новым соединением.
///
/// Ответивший способ спрашивается [`PROBE_ATTEMPTS`] раз — так видна
/// блокировка, которая включается со второго или третьего запроса. После
/// сорвавшегося запроса серия продолжается: если следующий прошёл, это была
/// случайная потеря, а если нет — связь действительно закрылась.
///
/// `retry_silence` — повторить первый запрос, если на него промолчали. Нужно
/// только для UDP: там потерянный пакет никто не пересылает. В TCP, DoT и DoH
/// потери за срок ожидания исправляет сама система, и молчание там — уже
/// ответ.
#[must_use]
pub fn series(
    mut ask: impl FnMut() -> DnsQueryResult,
    retry_silence: bool,
    on_first: Option<&mut dyn FnMut(&DnsQueryResult)>,
) -> Cell {
    let mut results = vec![ask()];
    if let Some(on_first) = on_first {
        on_first(&results[0]);
    }
    if !results[0].answered() {
        if retry_silence && results[0].failure == FAILURE_TIMEOUT {
            results.push(ask());
        }
        if !results[results.len() - 1].answered() {
            let failed = cell_of(&results[results.len() - 1]);
            if failed.failed() {
                return Cell {
                    trail: vec![false; results.len()],
                    ..failed
                };
            }
            return failed;
        }
    }
    while results.len() < PROBE_ATTEMPTS {
        let result = ask();
        if result.failure == FAILURE_CANCELLED {
            break;
        }
        results.push(result);
    }
    let times: Vec<f64> = results
        .iter()
        .filter(|result| result.answered())
        .filter_map(|result| result.elapsed_ms)
        .collect();
    let lost = results.iter().rev().find(|result| !result.answered());
    Cell {
        state: STATE_OK.to_string(),
        elapsed_ms: median(&times),
        failure: lost.map_or(String::new(), |result| result.failure.clone()),
        reason: lost.map_or(String::new(), DnsQueryResult::failure_text),
        trail: results.iter().map(DnsQueryResult::answered).collect(),
    }
}

/// python `statistics.median` — середина или среднее двух середин.
#[must_use]
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).expect("без NaN"));
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[middle])
    } else {
        Some((sorted[middle - 1] + sorted[middle]) / 2.0)
    }
}

/// python `_once_udp` — один обычный запрос (UDP, порт 53).
#[must_use]
pub fn once_udp(
    address: &str,
    domain: &str,
    cancel: &primecore_socketcancel::SocketCancel,
) -> DnsQueryResult {
    query_udp(address, domain, TYPE_A, UDP_TIMEOUT_S, 53, Some(cancel))
}

/// python `_ask_udp` — тот же с одним повтором после молчания.
#[must_use]
pub fn ask_udp(
    address: &str,
    domain: &str,
    cancel: &primecore_socketcancel::SocketCancel,
) -> DnsQueryResult {
    twice(&mut || once_udp(address, domain, cancel))
}

/// python `_once_doh` — один запрос DoH; `by_name` — с именем сервера для
/// сертификата (по адресу — без: имя в запросе «?dns=example.com» всё равно
/// есть, но сертификат проверяется по адресу).
#[must_use]
pub fn once_doh(
    target: &CheckTarget,
    domain: &str,
    cancel: &primecore_socketcancel::SocketCancel,
    by_name: bool,
) -> DnsQueryResult {
    query_doh(
        &target.address,
        domain,
        TYPE_A,
        if by_name { &target.doh_host } else { "" },
        target.doh_port,
        &target.doh_path,
        ENCRYPTED_TIMEOUT_S,
        Some(cancel),
    )
}

/// python `_once_dot` — один запрос DoT (порт 853).
#[must_use]
pub fn once_dot(
    target: &CheckTarget,
    domain: &str,
    cancel: &primecore_socketcancel::SocketCancel,
) -> DnsQueryResult {
    query_dot(
        &target.address,
        domain,
        TYPE_A,
        &target.dot_host,
        ENCRYPTED_TIMEOUT_S,
        853,
        Some(cancel),
    )
}

/// python `_once_tcp` — один обычный запрос по TCP.
#[must_use]
pub fn once_tcp(
    target: &CheckTarget,
    domain: &str,
    cancel: &primecore_socketcancel::SocketCancel,
) -> DnsQueryResult {
    query_tcp(
        &target.address,
        domain,
        TYPE_A,
        TCP_TIMEOUT_S,
        53,
        Some(cancel),
    )
}

/// python `_secure_path` — самый надёжный из ответивших путей в обход обычного
/// UDP: (имя пути, чем спрашивать).
///
/// Запрос этим путём не повторяется: потери в TCP исправляет сама система, а
/// второй срок ожидания на каждый контрольный вопрос удваивал время проверки.
#[must_use]
pub fn secure_path(observation: &Observation) -> (&'static str, Option<SecureAsk>) {
    if observation.cell(TRANSPORT_DOH).ok() {
        return (TRANSPORT_DOH, Some(SecureAsk::Doh));
    }
    if observation.doh_by_address.as_ref().is_some_and(Cell::ok) {
        return (TRANSPORT_DOH, Some(SecureAsk::DohByAddress));
    }
    if observation.cell(TRANSPORT_DOT).ok() {
        return (TRANSPORT_DOT, Some(SecureAsk::Dot));
    }
    if observation.cell(TRANSPORT_TCP).ok() {
        return (TRANSPORT_TCP, Some(SecureAsk::Tcp));
    }
    ("", None)
}

/// Выбранный шифрованный (или хотя бы не UDP) путь.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureAsk {
    Doh,
    DohByAddress,
    Dot,
    Tcp,
}

impl SecureAsk {
    /// Один запрос этим путём (python-замыкание `ask_secure`).
    #[must_use]
    pub fn ask(
        self,
        target: &CheckTarget,
        domain: &str,
        cancel: &primecore_socketcancel::SocketCancel,
    ) -> DnsQueryResult {
        match self {
            Self::Doh => once_doh(target, domain, cancel, true),
            Self::DohByAddress => once_doh(target, domain, cancel, false),
            Self::Dot => once_dot(target, domain, cancel),
            Self::Tcp => once_tcp(target, domain, cancel),
        }
    }
}

/// python `_first_address` — первый A-адрес ответа или пустая строка.
#[must_use]
pub fn first_address(result: &DnsQueryResult) -> String {
    result.values(TYPE_A).first().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(ips: &[&str]) -> DnsQueryResult {
        let mut records: Vec<primecore_dnswire::DnsRecord> = Vec::new();
        for ip in ips {
            records.push(primecore_dnswire::DnsRecord {
                name: "example.com".to_string(),
                rtype: TYPE_A,
                ttl: 60,
                value: (*ip).to_string(),
            });
        }
        primecore_dnswire::answered_result(
            TRANSPORT_UDP,
            primecore_dnswire::DnsMessage {
                answers: records,
                ..Default::default()
            },
            12.0,
        )
    }

    fn silent(failure: &str) -> DnsQueryResult {
        DnsQueryResult {
            transport: TRANSPORT_UDP.to_string(),
            failure: failure.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn cells_from_results() {
        assert_eq!(cell_of(&answered(&["1.2.3.4"])).state, STATE_OK);
        assert_eq!(cell_of(&answered(&["1.2.3.4"])).elapsed_ms, Some(12.0));
        // Снятый запрос — пустая ячейка.
        assert_eq!(cell_of(&silent(FAILURE_CANCELLED)), Cell::default());
        let failed = cell_of(&silent(FAILURE_TIMEOUT));
        assert_eq!(failed.state, STATE_FAIL);
        assert_eq!(failed.failure, FAILURE_TIMEOUT);
        assert!(!failed.reason.is_empty(), "причина словами");
    }

    #[test]
    fn cell_properties() {
        let mut cell = Cell {
            state: STATE_OK.to_string(),
            trail: vec![true, false, true],
            ..Cell::default()
        };
        assert!(cell.ok());
        assert_eq!(cell.attempts(), 3);
        assert_eq!(cell.answered(), 2);
        assert!(cell.unstable());
        assert!(!cell.fades(), "первый запрос прошёл");
        cell.trail = vec![true, false, false];
        assert!(
            cell.fades(),
            "прошёл и закрылся — так включается блокировка"
        );
        cell.trail = vec![false, true, true];
        assert!(!cell.fades());
        cell.trail = vec![true, true, true];
        assert!(!cell.unstable());
        // Пустой след: пинг — серии не было.
        let ping = Cell {
            state: STATE_OK.to_string(),
            ..Cell::default()
        };
        assert!(!ping.unstable());
        assert_eq!(ping.attempts(), 0);
    }

    #[test]
    fn series_tracks_trail_and_median() {
        let answers = [
            silent(FAILURE_TIMEOUT),
            answered(&["1.1.1.1"]),
            answered(&["1.1.1.2"]),
        ];
        let mut index = 0usize;
        let cell = series(
            || {
                let value = answers[index % answers.len()].clone();
                index += 1;
                value
            },
            true,
            None,
        );
        // Первое молчание повторено (retry_silence), дальше серия до трёх.
        assert_eq!(cell.state, STATE_OK);
        assert_eq!(cell.trail, vec![false, true, true]);
        assert!(cell.unstable());
        assert_eq!(cell.elapsed_ms, Some(12.0), "медиана ответивших");
        assert_eq!(cell.failure, FAILURE_TIMEOUT);
        assert!(!cell.reason.is_empty());
    }

    #[test]
    fn series_all_silent_marks_fail_with_trail() {
        let mut index = 0usize;
        let cell = series(
            || {
                index += 1;
                silent(FAILURE_TIMEOUT)
            },
            true,
            None,
        );
        assert_eq!(cell.state, STATE_FAIL);
        assert_eq!(cell.trail, vec![false, false]);
    }

    #[test]
    fn series_cancelled_breaks() {
        let answers = [
            answered(&["1.1.1.1"]),
            silent(FAILURE_CANCELLED),
            answered(&["1.1.1.2"]),
        ];
        let mut index = 0usize;
        let cell = series(
            || {
                let value = answers[index % answers.len()].clone();
                index += 1;
                value
            },
            false,
            None,
        );
        assert_eq!(cell.trail, vec![true], "после снятия серия не продолжается");
        assert!(cell.ok());
        assert!(!cell.unstable());
    }

    #[test]
    fn series_calls_on_first() {
        let mut seen: Vec<bool> = Vec::new();
        let mut note = |result: &DnsQueryResult| seen.push(result.answered());
        let _ = series(|| answered(&["1.1.1.1"]), false, Some(&mut note));
        assert_eq!(seen, vec![true]);
    }

    #[test]
    fn targets_built_from_catalog() {
        let providers: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r##"{
            "Шифрованные": {
                "DNSCrypt": {"ipv4": ["127.0.0.1"], "local_proxy": "dnscrypt"}
            },
            "Популярные": {
                "Cloudflare": {
                    "ipv4": ["1.1.1.1", "1.0.0.1"],
                    "ipv6": ["2606:4700:4700::1111"],
                    "doh": "https://cloudflare-dns.com/dns-query",
                    "dot": "cloudflare-dns.com",
                    "encrypted_only": false,
                    "icon": "simple:cloudflare:CF",
                    "color": "#f48120"
                },
                "Заглушка": {
                    "ipv4": ["1.1.1.1"],
                    "encrypted_only": true
                }
            }
        }"##,
        )
        .expect("каталог разобран");
        let targets = build_targets(&providers, false);
        // 127.0.0.1 в списке есть (режимы не выкидываются — их фильтрует UI),
        // но повторы адресов выкидываются: «Заглушка» с тем же 1.1.1.1 не попала.
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|item| item.provider != "Заглушка"));
        assert_eq!(targets[1].provider, "Cloudflare");
        assert_eq!(targets[1].doh_host, "cloudflare-dns.com");
        assert_eq!(targets[1].doh_port, 443);
        assert_eq!(targets[1].doh_path, "/dns-query");
        assert_eq!(targets[1].dot_host, "cloudflare-dns.com");
        assert_eq!(targets[1].icon, "simple:cloudflare:CF");
        // IPv6 добавляется только по флагу.
        let with_ipv6 = build_targets(&providers, true);
        assert_eq!(with_ipv6.len(), 4);
        assert!(with_ipv6
            .iter()
            .any(|item| item.address == "2606:4700:4700::1111"));
        // Пустой адрес не проверяется.
        let providers: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r##"{"Группа": {"X": {"ipv4": ["", "  ", "5.5.5.5"]}}}"##)
                .expect("каталог разобран");
        assert_eq!(build_targets(&providers, false).len(), 1);
    }

    #[test]
    fn doh_parts_from_template() {
        let data: serde_json::Value =
            serde_json::json!({"doh": "https://dns.quad9.net:8443/private"});
        assert_eq!(
            doh_parts(&data),
            ("dns.quad9.net".to_string(), 8443, "/private".to_string())
        );
        let data: serde_json::Value = serde_json::json!({"doh": ""});
        assert_eq!(
            doh_parts(&data),
            (String::new(), 443, "/dns-query".to_string())
        );
        let data: serde_json::Value = serde_json::json!({"doh": "https://[2606::1]:53/q"});
        assert_eq!(
            doh_parts(&data),
            ("2606::1".to_string(), 53, "/q".to_string())
        );
    }

    #[test]
    fn median_like_python() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[3.0]), Some(3.0));
        assert_eq!(median(&[1.0, 5.0]), Some(3.0));
        assert_eq!(median(&[5.0, 1.0, 3.0]), Some(3.0));
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), Some(2.5));
    }

    #[test]
    fn secure_path_precedence() {
        let mut observation = Observation::default();
        assert_eq!(secure_path(&observation), ("", None));
        observation.cells = vec![(
            TRANSPORT_TCP.to_string(),
            Cell {
                state: STATE_OK.to_string(),
                ..Cell::default()
            },
        )];
        assert_eq!(
            secure_path(&observation),
            (TRANSPORT_TCP, Some(SecureAsk::Tcp))
        );
        observation.cells = vec![(
            TRANSPORT_DOT.to_string(),
            Cell {
                state: STATE_OK.to_string(),
                ..Cell::default()
            },
        )];
        assert_eq!(
            secure_path(&observation),
            (TRANSPORT_DOT, Some(SecureAsk::Dot))
        );
        observation.cells = vec![(
            TRANSPORT_DOH.to_string(),
            Cell {
                state: STATE_OK.to_string(),
                ..Cell::default()
            },
        )];
        assert_eq!(
            secure_path(&observation),
            (TRANSPORT_DOH, Some(SecureAsk::Doh))
        );
        // DoH по имени не ответил, а по адресу — ответил.
        observation.cells = vec![(TRANSPORT_DOH.to_string(), cell_of(&silent(FAILURE_TIMEOUT)))];
        observation.doh_by_address = Some(Cell {
            state: STATE_OK.to_string(),
            ..Cell::default()
        });
        assert_eq!(
            secure_path(&observation),
            (TRANSPORT_DOH, Some(SecureAsk::DohByAddress))
        );
    }

    #[test]
    fn name_block_failures() {
        assert!(name_block_failure(FAILURE_TIMEOUT));
        assert!(name_block_failure(FAILURE_TLS));
        assert!(name_block_failure(FAILURE_CLOSED));
        assert!(name_block_failure(FAILURE_RESET));
        assert!(!name_block_failure(primecore_dnswire::FAILURE_REFUSED));
        assert!(!name_block_failure(""));
    }

    #[test]
    fn first_address_takes_a_record() {
        assert_eq!(first_address(&answered(&["1.2.3.4", "5.6.7.8"])), "1.2.3.4");
        assert_eq!(first_address(&answered(&[])), "");
        assert_eq!(first_address(&silent(FAILURE_TIMEOUT)), "");
    }
}
