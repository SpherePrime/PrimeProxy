//! Порт `src/dns/domain_lookup.py` — отдельные проверки (каждая сама держит
//! свой таймаут) и подстановки сети.
//!
//! В python вся сеть вызывается по именам этого модуля, поэтому в тестах она
//! подменяется целиком. Здесь так же: каждая проверка получает сеть замыканием
//! (`Box<dyn Fn>`), а живые замыкания собирает движок — как в
//! [`crate::doh_lookup::LookupIo::live`]. Прогона (двух волн) касаются
//! [`crate::domain_lookup_run`]; типы отчёта и чистый разбор —
//! [`crate::domain_lookup`].

use primecore_diagnostics::ip_owner::lookup_ip_owner;
use primecore_diagnostics::path_trace::FilterFacts;
use primecore_diagnostics::protocol_probe::{
    ProtocolLine, PROTO_TLS12, PROTO_TLS13, STATE_FAIL, STATE_OK,
};
use primecore_diagnostics::quic_probe::{
    judge as judge_quic, quic_hello, QuicFacts, QuicVerdict, ATTEMPTS, ATTEMPT_TIMEOUT_S,
    NEUTRAL_NAME, QUIC_PORT,
};
use primecore_dnswire::{
    DnsQueryResult, STATUS_ERROR, STATUS_NXDOMAIN, STATUS_OK, STATUS_TIMEOUT, TYPE_A, TYPE_AAAA,
    TYPE_CNAME, TYPE_PTR,
};
use primecore_socketcancel::SocketCancel;
use serde_json::Value;

use crate::domain_lookup::is_placeholder_name;
use crate::domain_lookup::ProgramRoad;
use crate::domain_lookup::{
    DnsServer, HostsHelp, NeighborSource, NetworkInfo, PingReport, ResolverAnswer, TcpReport,
    DNS_TIMEOUT_S, HACKERTARGET_URL, RIPESTAT_URL, SERVER_DOH, SHODAN_URL, SOURCE_EMPTY,
    SOURCE_ERROR, SOURCE_HACKERTARGET, SOURCE_OK, SOURCE_PTR, SOURCE_SHODAN, SOURCE_SKIPPED,
    SOURCE_THC, THC_MAX_PAGES, THC_PAGE_SIZE, THC_URL, USER_AGENT,
};

/// python `utils.cert_names.CertNames` — что вернул сертификат сервера.
/// Проверка сертификата тут выключена нарочно: интересен как раз чужой или
/// подменённый сертификат.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CertLookup {
    /// ok / timeout / refused / tls / error (python `KIND_*`).
    pub kind: String,
    pub names: Vec<String>,
    pub common_name: String,
    pub detail: String,
}

impl CertLookup {
    /// python `CertNames.ok`.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.kind == "ok"
    }
}

/// python `_http`-сбой, превращённый в слова (python `_unavailable_text`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpFailure {
    /// python `requests.exceptions.Timeout`.
    Timeout,
    /// python `requests.exceptions.SSLError`.
    Ssl,
    /// python `requests.exceptions.ConnectionError`.
    Connection,
    /// Всё остальное.
    Other,
}

/// python `_unavailable_text` — почему внешний сервис не ответил — словами, а
/// не названием ошибки.
#[must_use]
pub fn unavailable_text(failure: &HttpFailure) -> &'static str {
    match failure {
        HttpFailure::Timeout => "сервис не ответил вовремя",
        HttpFailure::Ssl => "защищённое соединение с сервисом не установилось",
        HttpFailure::Connection => {
            "с сервисом не удалось соединиться — возможно, он закрыт для вашей сети"
        }
        HttpFailure::Other => "сервис недоступен",
    }
}

/// python `_unavailable` — источник, до которого не дошли.
#[must_use]
pub fn unavailable(key: &str, failure: &HttpFailure) -> NeighborSource {
    NeighborSource {
        detail: unavailable_text(failure).to_string(),
        ..NeighborSource::new(key, SOURCE_ERROR)
    }
}

/// python `resolve_addrinfo` — один адрес из ответа системы: семейство и адрес.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedAddr {
    /// Адрес IPv6 (python `info[0] == socket.AF_INET6`).
    pub ipv6: bool,
    pub address: String,
}

/// python-сбой `resolve_addrinfo`: молчание системы, прямой ответ «имени нет»
/// или что-то другое.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveFailure {
    /// python `DNSTimeoutError` — DNS просто не ответил.
    Timeout,
    /// python `gaierror` с кодом «имени нет» (EAI_NONAME, EAI_NODATA, Winsock
    /// 11001 и 11004): система получила от DNS прямой ответ.
    Missing,
    /// Всё остальное.
    Other,
}

/// python `query_server(address, name, rtype, timeout_s, attempts)` — обычный
/// DNS-запрос (UDP, порт 53).
pub type AskServerFn<'a> = Box<dyn Fn(&str, &str, u16, f64, u32) -> DnsQueryResult + 'a>;
/// python `query_doh(address, name, rtype)` — шифрованный запрос по адресу.
pub type AskDohFn<'a> = Box<dyn Fn(&str, &str, u16) -> DnsQueryResult + 'a>;
/// python `query_tcp(address, name, rtype, timeout_s)` — тот же вопрос по TCP.
pub type AskTcpFn<'a> = Box<dyn Fn(&str, &str, u16, f64) -> DnsQueryResult + 'a>;
/// python `canary_answered(domain)` — ответил ли контрольный адрес без DNS.
pub type CanaryFn<'a> = Box<dyn Fn(&str) -> bool + 'a>;
/// python `resolve_addrinfo(domain, timeout)` — как имя видит система.
pub type ResolveWindowsFn<'a> = Box<dyn Fn(&str) -> Result<Vec<ResolvedAddr>, ResolveFailure> + 'a>;
/// python `_ping(ip, should_stop)` — пинг адреса (Windows ICMP под капотом).
pub type PingFn<'a> = Box<dyn Fn(&str) -> PingReport + 'a>;
/// python `_tcp_connect(ip, port=443)` — соединение с портом.
pub type TcpConnectFn<'a> = Box<dyn Fn(&str, u16) -> TcpReport + 'a>;
/// python `protocol_probe.collect` + `judge` — пробы с именем сайта по адресу.
pub type ProtocolProbeFn<'a> = Box<dyn Fn(&str, &str) -> Vec<ProtocolLine> + 'a>;
/// python `_check_site(domain, should_stop)` — сайт теми же пробами, что в BlockCheck.
pub type SiteCheckFn<'a> = Box<dyn Fn(&str) -> Option<Value> + 'a>;
/// python `_hosts_help(domain)` — что знает «Редактор hosts».
pub type HostsHelpFn<'a> = Box<dyn Fn(&str) -> HostsHelp + 'a>;
/// python `_program_road(domain, ip, cancel)` — что по адресу получается.
pub type RoadFn<'a> = Box<dyn Fn(Option<&str>, &str) -> crate::domain_lookup::ProgramRoad + 'a>;
/// python `trace_route(ip, should_stop)` — путь до адреса по узлам.
pub type RouteFn<'a> = Box<dyn Fn(&str) -> primecore_diagnostics::path_trace::RouteTrace + 'a>;
/// python `_inspect_quic(domain, ip, max_ttl, cancel)` — QUIC и место фильтра.
pub type QuicInspectFn<'a> =
    Box<dyn Fn(&str, &str) -> (Option<QuicVerdict>, Option<FilterFacts>) + 'a>;
/// python `fetch_cert_names(ip, server_name)` — имена из сертификата.
pub type CertFetchFn<'a> = Box<dyn Fn(&str, Option<&str>) -> CertLookup + 'a>;
/// python `_http(method, url, json=...)` — запрос к внешнему сервису напрямую,
/// мимо системного прокси (его может выставить winws).
pub type HttpFn<'a> =
    Box<dyn Fn(&str, &str, Option<&Value>) -> Result<(i32, String), HttpFailure> + 'a>;

/// DNS-запросы движка (python `query_server` / `query_doh` / `query_tcp`).
pub struct AskIo<'a> {
    pub server: AskServerFn<'a>,
    pub doh: AskDohFn<'a>,
    pub tcp: AskTcpFn<'a>,
}

/// python `_ask_server` — что ответил один DNS-сервер: адрес IPv4, адрес IPv6,
/// псевдонимы и проверка подмены по TCP.
#[must_use]
pub fn ask_server(server: &DnsServer, domain: &str, io: &AskIo<'_>) -> ResolverAnswer {
    let first = if server.kind == SERVER_DOH {
        (io.doh)(&server.address, domain, TYPE_A)
    } else {
        (io.server)(&server.address, domain, TYPE_A, DNS_TIMEOUT_S, 2)
    };
    if !first.answered() {
        return ResolverAnswer {
            server: server.clone(),
            status: first.status.clone(),
            level: crate::domain_lookup::LEVEL_UNKNOWN.to_string(),
            note: first.failure_text(),
            ..ResolverAnswer::default()
        };
    }
    if server.kind != SERVER_DOH && first.status == STATUS_NXDOMAIN {
        // «Домена нет» перепроверяется у того же сервера по TCP: подставной ответ
        // приходит только по UDP.
        return ResolverAnswer {
            server: server.clone(),
            status: STATUS_NXDOMAIN.to_string(),
            elapsed_ms: first.elapsed_ms,
            forged: first.forged_denial(),
            tcp_ipv4: (io.tcp)(&server.address, domain, TYPE_A, DNS_TIMEOUT_S).values(TYPE_A),
            ..ResolverAnswer::default()
        };
    }
    let second = if server.kind == SERVER_DOH {
        (io.doh)(&server.address, domain, TYPE_AAAA)
    } else {
        (io.server)(&server.address, domain, TYPE_AAAA, DNS_TIMEOUT_S, 1)
    };
    let ipv4 = first.values(TYPE_A);
    let ipv6 = second.values(TYPE_AAAA);
    let mut cnames = first.values(TYPE_CNAME);
    if cnames.is_empty() {
        cnames = second.values(TYPE_CNAME);
    }
    let status = if !ipv4.is_empty() || !ipv6.is_empty() {
        STATUS_OK.to_string()
    } else if first.status == STATUS_OK {
        // Ответ есть, но адресов в нём нет (например, одни псевдонимы).
        primecore_dnswire::STATUS_EMPTY.to_string()
    } else {
        first.status.clone()
    };
    let ttls: Vec<u32> = [
        (first.records.as_slice(), TYPE_A),
        (second.records.as_slice(), TYPE_AAAA),
    ]
    .iter()
    .flat_map(|(records, rtype)| {
        records
            .iter()
            .filter(|record| record.rtype == *rtype)
            .map(|record| record.ttl)
    })
    .collect();
    ResolverAnswer {
        server: server.clone(),
        status,
        ipv4,
        ipv6,
        cnames,
        elapsed_ms: first.elapsed_ms,
        ttl: ttls.iter().copied().min(),
        ..ResolverAnswer::default()
    }
}

/// python `_ask_windows` — как имя видят обычные программы: с учётом файла hosts
/// и шифрованного DNS Windows.
///
/// Важно не только «адреса нет», но и почему: «такого имени нет» — это ответ
/// DNS, которому Windows поверила, а молчание — DNS просто не ответил.
#[must_use]
pub fn ask_windows(domain: &str, resolve: &ResolveWindowsFn<'_>) -> ResolverAnswer {
    let server = DnsServer::with_kind("Windows", "", crate::domain_lookup::SERVER_WINDOWS);
    let started = std::time::Instant::now();
    let mut status = STATUS_ERROR.to_string();
    let infos: Vec<ResolvedAddr> = match resolve(domain) {
        Ok(infos) => infos,
        Err(ResolveFailure::Timeout) => {
            status = STATUS_TIMEOUT.to_string();
            Vec::new()
        }
        Err(ResolveFailure::Missing) => {
            // Система получила от DNS прямой ответ «имени нет» или «адресов нет». В Windows это
            // коды 11001 (WSAHOST_NOT_FOUND) и 11004 (WSANO_DATA); названия EAI_* там равны им не все.
            status = STATUS_NXDOMAIN.to_string();
            Vec::new()
        }
        Err(ResolveFailure::Other) => Vec::new(),
    };
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    let unique = |ipv6: bool| -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for info in &infos {
            if info.ipv6 == ipv6 && !info.address.is_empty() && !seen.contains(&info.address) {
                seen.push(info.address.clone());
            }
        }
        seen
    };
    let ipv4 = unique(false);
    let ipv6 = unique(true);
    if ipv4.is_empty() && ipv6.is_empty() {
        return ResolverAnswer {
            server,
            status,
            level: crate::domain_lookup::LEVEL_UNKNOWN.to_string(),
            elapsed_ms: Some(elapsed),
            ..ResolverAnswer::default()
        };
    }
    let first = infos
        .iter()
        .find(|info| !info.address.is_empty())
        .map(|info| info.address.clone())
        .unwrap_or_default();
    ResolverAnswer {
        server,
        status: STATUS_OK.to_string(),
        ipv4,
        ipv6,
        elapsed_ms: Some(elapsed),
        first,
        ..ResolverAnswer::default()
    }
}

/// python `_ask_helpers` — служебный запрос: спрашиваем серверы по очереди, пока
/// кто-то не ответит.
#[must_use]
pub fn ask_helpers(
    name: &str,
    rtype: u16,
    servers: &[String],
    ask: &AskServerFn<'_>,
) -> Option<DnsQueryResult> {
    let mut last = None;
    for server in servers {
        let result = ask(server, name, rtype, DNS_TIMEOUT_S, 1);
        let answered = result.answered();
        last = Some(result);
        if answered {
            return last;
        }
    }
    last
}

/// python `_lookup_ptr` — обратное имя адреса.
#[must_use]
pub fn lookup_ptr(ip: &str, servers: &[String], ask: &AskServerFn<'_>) -> NeighborSource {
    let pointer = match primecore_dnswire::reverse_name(ip) {
        Ok(pointer) => pointer,
        Err(_) => {
            return NeighborSource {
                detail: "DNS-серверы не ответили".to_string(),
                ..NeighborSource::new(SOURCE_PTR, SOURCE_ERROR)
            }
        }
    };
    let result = ask_helpers(&pointer, TYPE_PTR, servers, ask);
    let Some(result) = result.filter(|result| result.answered()) else {
        return NeighborSource {
            detail: "DNS-серверы не ответили".to_string(),
            ..NeighborSource::new(SOURCE_PTR, SOURCE_ERROR)
        };
    };
    let names: Vec<String> = result
        .values(TYPE_PTR)
        .iter()
        .map(|name| name.trim_end_matches('.').to_string())
        .collect();
    let status = if names.is_empty() {
        SOURCE_EMPTY
    } else {
        SOURCE_OK
    };
    NeighborSource {
        names,
        ..NeighborSource::new(SOURCE_PTR, status)
    }
}

/// python `_lookup_network` — владелец сети через DNS-службу Team Cymru: без
/// сайтов и ключей, одним DNS-запросом.
#[must_use]
pub fn lookup_network(ip: &str, servers: &[String], ask: &AskServerFn<'_>) -> Option<NetworkInfo> {
    let found = lookup_ip_owner(ip, |name, rtype| ask_helpers(name, rtype, servers, ask))?;
    Some(NetworkInfo {
        asn: found.asn,
        prefix: found.prefix,
        country: found.country,
        owner: found.owner,
        ..NetworkInfo::default()
    })
}

/// python `_lookup_cert` — имена из сертификата: с именем сайта и без него.
#[must_use]
pub fn lookup_cert(
    ip: &str,
    key: &str,
    server_name: Option<&str>,
    fetch: &CertFetchFn<'_>,
) -> NeighborSource {
    let result = fetch(ip, server_name);
    if !result.ok() {
        if result.kind == "tls" && server_name.is_none() {
            // Сети доставки (Cloudflare и подобные) без имени сайта сертификат не отдают.
            return NeighborSource {
                detail: "сервер не отдаёт сертификат без имени сайта".to_string(),
                ..NeighborSource::new(key, SOURCE_SKIPPED)
            };
        }
        if let Some(name) = server_name {
            if matches!(result.kind.as_str(), "timeout" | "tls" | "error") {
                // Порт открыт, а защищённое соединение с именем сайта не складывается.
                return NeighborSource {
                    detail: format!(
                        "соединение с именем {name} не установилось — так бывает, когда сайт блокируют по имени"
                    ),
                    ..NeighborSource::new(key, SOURCE_ERROR)
                };
            }
        }
        return NeighborSource {
            detail: result.detail.clone(),
            ..NeighborSource::new(key, SOURCE_ERROR)
        };
    }
    let mut names = result.names.clone();
    let common = result.common_name.to_lowercase();
    if !result.common_name.is_empty() && !names.iter().any(|name| name.to_lowercase() == common) {
        names.insert(0, common);
    }
    let placeholders: Vec<String> = names
        .iter()
        .filter(|name| is_placeholder_name(name))
        .cloned()
        .collect();
    names.retain(|name| !placeholders.contains(name));
    if !placeholders.is_empty() && names.is_empty() {
        // Google и подобные на запрос без имени сайта отдают сертификат на несуществующее имя.
        return NeighborSource {
            detail: format!(
                "без имени сайта сервер отдаёт сертификат-пустышку ({}), имён сайтов в нём нет",
                placeholders[0]
            ),
            ..NeighborSource::new(key, SOURCE_SKIPPED)
        };
    }
    let status = if names.is_empty() {
        SOURCE_EMPTY
    } else {
        SOURCE_OK
    };
    NeighborSource {
        names,
        ..NeighborSource::new(key, status)
    }
}

/// python `_lookup_thc` — домены на адресе по базе ip.thc.org: без ключа, до
/// трёх страниц по сто записей.
#[must_use]
pub fn lookup_thc(ip: &str, halted: &dyn Fn() -> bool, http: &HttpFn<'_>) -> NeighborSource {
    let mut source: Option<NeighborSource> = None;
    let mut page_state = String::new();
    for _page in 0..THC_MAX_PAGES {
        let mut body = serde_json::json!({"ip_address": ip, "limit": THC_PAGE_SIZE});
        if !page_state.is_empty() {
            body["page_state"] = Value::String(page_state.clone());
        }
        let (status_code, text) = match http("POST", THC_URL, Some(&body)) {
            Ok(response) => response,
            Err(failure) => return source.unwrap_or_else(|| unavailable(SOURCE_THC, &failure)),
        };
        let (page, next_state) = crate::domain_lookup::parse_thc_answer(status_code, &text);
        match &source {
            None => source = Some(page.clone()),
            Some(found) if page.status == SOURCE_OK => {
                let mut names = found.names.clone();
                for name in &page.names {
                    if !names.contains(name) {
                        names.push(name.clone());
                    }
                }
                source = Some(NeighborSource {
                    names,
                    ..found.clone()
                });
            }
            _ => {}
        }
        page_state = next_state;
        if page.status != SOURCE_OK || page_state.is_empty() || halted() {
            break;
        }
    }
    let Some(mut source) = source else {
        return NeighborSource::new(SOURCE_THC, SOURCE_EMPTY);
    };
    if page_state.is_empty() {
        // Список получен целиком: «всего в базе» больше не нужно (там считаются и повторы).
        source.total = None;
    }
    source
}

/// python `_lookup_hackertarget` — запасной источник соседей.
#[must_use]
pub fn lookup_hackertarget(ip: &str, http: &HttpFn<'_>) -> NeighborSource {
    let url = HACKERTARGET_URL.replace("{ip}", ip);
    let Ok((status_code, text)) = http("GET", &url, None) else {
        return unavailable(SOURCE_HACKERTARGET, &HttpFailure::Other);
    };
    crate::domain_lookup::parse_hackertarget_answer(status_code, &text)
}

/// python `_lookup_neighbors` — основной источник — THC. HackerTarget (всего
/// ~20 запросов в сутки) — только если THC не помог.
#[must_use]
pub fn lookup_neighbors(
    ip: &str,
    halted: &dyn Fn() -> bool,
    http: &HttpFn<'_>,
) -> Vec<NeighborSource> {
    let primary = lookup_thc(ip, halted, http);
    if primary.status == SOURCE_OK || halted() {
        return vec![primary];
    }
    vec![primary, lookup_hackertarget(ip, http)]
}

/// python `_lookup_shodan` — имена и открытые порты.
#[must_use]
pub fn lookup_shodan(ip: &str, http: &HttpFn<'_>) -> NeighborSource {
    let url = SHODAN_URL.replace("{ip}", ip);
    let Ok((status_code, text)) = http("GET", &url, None) else {
        return unavailable(SOURCE_SHODAN, &HttpFailure::Other);
    };
    crate::domain_lookup::parse_shodan_answer(status_code, &text)
}

/// python `_lookup_ripestat` — подсеть и объявляющие её сети.
#[must_use]
pub fn lookup_ripestat(ip: &str, http: &HttpFn<'_>) -> Option<NetworkInfo> {
    let url = RIPESTAT_URL.replace("{ip}", ip);
    let Ok((status_code, text)) = http("GET", &url, None) else {
        return None;
    };
    crate::domain_lookup::parse_ripestat_answer(status_code, &text)
}

/// python `_http` — заголовок запроса к внешнему сервису.
#[must_use]
pub fn http_headers() -> Vec<(&'static str, &'static str)> {
    vec![("User-Agent", USER_AGENT)]
}

/// python: приветственные строки, по которым судят, дошло ли имя сайта.
fn hello_line_state(lines: &[ProtocolLine]) -> Option<bool> {
    let hello: Vec<&ProtocolLine> = lines
        .iter()
        .filter(|line| line.key == PROTO_TLS12 || line.key == PROTO_TLS13)
        .collect();
    if hello.iter().any(|line| line.state == STATE_OK) {
        return Some(true);
    }
    if hello.iter().any(|line| line.state == STATE_FAIL) {
        return Some(false);
    }
    None
}

/// python `_program_road` — что получается по адресу, на который Windows ведёт
/// программы: соединение и пробы с именем сайта.
///
/// Вывод «связи нет» делается по соединению, а не по пингу (на пинг многие узлы
/// не отвечают), и только после второй попытки: одна несостоявшаяся — ещё не
/// доказательство. Пробы с именем шлются только когда соединение есть.
/// «Не проходит» — только когда приветствие именно оборвали; несостоявшаяся
/// проба ничего не доказывает.
#[must_use]
pub fn program_road(
    domain: Option<&str>,
    ip: &str,
    tcp_connect: &TcpConnectFn<'_>,
    probe: &ProtocolProbeFn<'_>,
) -> ProgramRoad {
    let mut tcp = tcp_connect(ip, 443);
    if tcp.status != "ok" {
        tcp = tcp_connect(ip, 443);
    }
    if tcp.status != "ok" {
        return ProgramRoad {
            ip: ip.to_string(),
            tcp,
            ..ProgramRoad::default()
        };
    }
    let Some(domain) = domain else {
        return ProgramRoad {
            ip: ip.to_string(),
            tcp,
            ..ProgramRoad::default()
        };
    };
    let lines = probe(domain, ip);
    ProgramRoad {
        ip: ip.to_string(),
        tcp,
        lines: lines
            .iter()
            .map(|line| (line.title.clone(), line.state.clone(), line.text.clone()))
            .collect(),
        opens: hello_line_state(&lines),
    }
}

/// python `_hosts_road` — адреса из «Редактора hosts» настоящим именем сайта —
/// по очереди, до первого, по которому сайт открылся.
#[allow(clippy::too_many_arguments)] // все параметры python-функции и её подмены
///
/// Идёт после основной проверки сайта и с паузами: пачка одновременных
/// соединений с одним именем сама бывает поводом для фильтра оборвать их все, и
/// проба мешала бы основной проверке. `now()` — монотонные секунды (python
/// `time.monotonic`); возвращается последняя проба, `None` — до проб не дошло.
#[must_use]
pub fn hosts_road(
    domain: &str,
    offered: &[String],
    cancel: &SocketCancel,
    tries: usize,
    pause_s: f64,
    slow_s: f64,
    now: &dyn Fn() -> f64,
    road: &RoadFn<'_>,
) -> Option<ProgramRoad> {
    let mut road_result: Option<ProgramRoad> = None;
    for address in offered.iter().take(tries) {
        if !cancel.sleep(pause_s) {
            break;
        }
        let started = now();
        road_result = Some(road(Some(domain), address));
        let opened = road_result
            .as_ref()
            .is_some_and(|road| road.opens == Some(true));
        if opened || now() - started > slow_s {
            break;
        }
    }
    road_result
}

/// python `collect` из `diagnostics.quic_probe` — пробы QUIC к сайту. В Rust
/// порт спрашивает пакеты по порядку (параллельный залп — слой запуска движка):
/// на вывод это не влияет, важны только сами времена ответа.
#[must_use]
pub fn collect_quic(ip: &str, host: &str, cancel: &SocketCancel) -> QuicFacts {
    let real_ms = quic_hello(
        ip,
        Some(host),
        QUIC_PORT,
        ATTEMPTS,
        ATTEMPT_TIMEOUT_S,
        cancel,
    );
    if real_ms.is_some() || cancel.cancelled() {
        return QuicFacts {
            host: host.to_string(),
            real_ms,
            cancelled: cancel.cancelled(),
            ..QuicFacts::default()
        };
    }
    let neutral_ms = quic_hello(
        ip,
        Some(NEUTRAL_NAME),
        QUIC_PORT,
        ATTEMPTS,
        ATTEMPT_TIMEOUT_S,
        cancel,
    );
    let nameless_ms = quic_hello(ip, None, QUIC_PORT, ATTEMPTS, ATTEMPT_TIMEOUT_S, cancel);
    let mut real_again_ms = None;
    if (neutral_ms.is_some() || nameless_ms.is_some()) && !cancel.cancelled() {
        real_again_ms = quic_hello(
            ip,
            Some(host),
            QUIC_PORT,
            ATTEMPTS,
            ATTEMPT_TIMEOUT_S,
            cancel,
        );
    }
    QuicFacts {
        host: host.to_string(),
        real_ms: real_ms.or(real_again_ms),
        neutral_ms,
        nameless_ms,
        real_again_ms,
        cancelled: cancel.cancelled(),
    }
}

/// python `_inspect_quic` — QUIC к сайту, а если его блокируют по имени — ещё и
/// место фильтра.
///
/// `collect` отдаёт готовый вывод (python `judge_quic(collect_quic(...))`),
/// `locate` ищет место фильтра — оба замыкания, живые собирает движок.
#[must_use]
pub fn inspect_quic(
    domain: &str,
    ip: &str,
    max_ttl: u32,
    cancel: &SocketCancel,
    collect: &dyn Fn(&str, &str, &SocketCancel) -> Option<QuicVerdict>,
    locate: &dyn Fn(&str, &str, u32, &SocketCancel) -> Option<FilterFacts>,
) -> (Option<QuicVerdict>, Option<FilterFacts>) {
    let verdict = collect(domain, ip, cancel);
    let Some(verdict) = verdict else {
        return (None, None);
    };
    if verdict.code != primecore_diagnostics::quic_probe::QUIC_BLOCKED_BY_NAME {
        return (Some(verdict), None);
    }
    (Some(verdict), locate(ip, domain, max_ttl, cancel))
}

/// python `judge` над собранными фактами QUIC — удобно живому замыканию:
/// collect + judge одной строкой.
#[must_use]
pub fn judge_collected_quic(ip: &str, host: &str, cancel: &SocketCancel) -> Option<QuicVerdict> {
    judge_quic(&collect_quic(ip, host, cancel))
}

/// python `collect_quic` в тестах — QUIC-проба по (хост, адрес, отмена).
pub type CollectQuic<'a> = Box<dyn Fn(&str, &str, &SocketCancel) -> Option<QuicVerdict> + 'a>;
/// python `locate_filter` в тестах — поиск фильтра по (хост, адрес, порт, отмена).
pub type LocateFilter<'a> = Box<dyn Fn(&str, &str, u32, &SocketCancel) -> Option<FilterFacts> + 'a>;

#[cfg(test)]
pub mod test_fixtures {
    //! Подмены сети для тестов крейта (python `_fake_query` и подмены `_Network`).

    use crate::domain_lookup::{
        DnsServer, NeighborSource, ResolverAnswer, SERVER_DOH, SERVER_SYSTEM, SOURCE_EMPTY,
        SOURCE_OK,
    };
    use primecore_dnswire::{
        DnsQueryResult, DnsRecord, STATUS_EMPTY, STATUS_NXDOMAIN, STATUS_OK, STATUS_TIMEOUT,
        TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_PTR, TYPE_TXT,
    };

    /// python-тестовые серверы: `GOOD`, `STUB`, `DEAD`, `SECURE`.
    pub const GOOD_ADDRESS: &str = "9.9.9.9";
    pub const STUB_ADDRESS: &str = "10.0.0.53";
    pub const DEAD_ADDRESS: &str = "203.0.113.9";
    pub const SECURE_ADDRESS: &str = "1.1.1.1";

    #[must_use]
    pub fn good() -> DnsServer {
        DnsServer::new("Хороший", GOOD_ADDRESS)
    }

    #[must_use]
    pub fn stub() -> DnsServer {
        DnsServer::with_kind("Провайдер", STUB_ADDRESS, SERVER_SYSTEM)
    }

    #[must_use]
    pub fn dead() -> DnsServer {
        DnsServer::new("Молчун", DEAD_ADDRESS)
    }

    #[must_use]
    pub fn secure() -> DnsServer {
        DnsServer::with_kind("Шифрованный", SECURE_ADDRESS, SERVER_DOH)
    }

    /// python `_answer` — удачный ответ с записями одного типа.
    #[must_use]
    pub fn answer(rtype: u16, values: &[&str]) -> DnsQueryResult {
        DnsQueryResult {
            status: STATUS_OK.to_string(),
            rcode: Some(0),
            records: values
                .iter()
                .map(|value| DnsRecord {
                    name: "x".to_string(),
                    rtype,
                    ttl: 60,
                    value: (*value).to_string(),
                })
                .collect(),
            elapsed_ms: Some(12.0),
            ..DnsQueryResult::default()
        }
    }

    #[must_use]
    pub fn empty() -> DnsQueryResult {
        DnsQueryResult {
            status: STATUS_EMPTY.to_string(),
            rcode: Some(0),
            ..DnsQueryResult::default()
        }
    }

    /// python `_fake_query` — подмена всех DNS-запросов.
    #[must_use]
    pub fn fake_query(
        server: &str,
        name: &str,
        rtype: u16,
        _timeout: f64,
        _attempts: u32,
    ) -> DnsQueryResult {
        if server == DEAD_ADDRESS {
            return DnsQueryResult {
                status: STATUS_TIMEOUT.to_string(),
                ..DnsQueryResult::default()
            };
        }
        if name.ends_with(".in-addr.arpa") {
            return answer(TYPE_PTR, &["host.example.net."]);
        }
        if name.ends_with(".origin.asn.cymru.com") {
            return answer(
                TYPE_TXT,
                &["64500 | 93.184.216.0/24 | US | arin | 2020-01-01"],
            );
        }
        if name.starts_with("AS64500.") {
            return answer(
                TYPE_TXT,
                &["64500 | US | arin | 2020-01-01 | EXAMPLE-NET, US"],
            );
        }
        if server == STUB_ADDRESS {
            return if rtype == TYPE_A {
                answer(TYPE_A, &["195.82.146.214"])
            } else {
                empty()
            };
        }
        match rtype {
            TYPE_A => answer(TYPE_A, &["93.184.216.34"]),
            TYPE_AAAA => answer(TYPE_AAAA, &["2606:2800:220:1::1"]),
            _ => empty(),
        }
    }

    /// Ответ с адресом IPv4.
    #[must_use]
    pub fn answer_with_ipv4(server: &DnsServer, ipv4: &[&str]) -> ResolverAnswer {
        ResolverAnswer {
            server: server.clone(),
            status: STATUS_OK.to_string(),
            ipv4: ipv4.iter().map(|value| (*value).to_string()).collect(),
            ..ResolverAnswer::default()
        }
    }

    /// Ответ «такого домена нет».
    #[must_use]
    pub fn denied(server: &DnsServer) -> ResolverAnswer {
        ResolverAnswer {
            server: server.clone(),
            status: STATUS_NXDOMAIN.to_string(),
            ..ResolverAnswer::default()
        }
    }

    /// Источник соседей с именами.
    #[must_use]
    pub fn source_with_names(key: &str, names: &[&str]) -> NeighborSource {
        NeighborSource {
            names: names.iter().map(|name| (*name).to_string()).collect(),
            ..NeighborSource::new(
                key,
                if names.is_empty() {
                    SOURCE_EMPTY
                } else {
                    SOURCE_OK
                },
            )
        }
    }

    /// CNAME-запись для проверки TTL (python `with_ttl`).
    #[must_use]
    pub fn answer_with_cname_and_ttls() -> DnsQueryResult {
        DnsQueryResult {
            status: STATUS_OK.to_string(),
            rcode: Some(0),
            records: vec![
                DnsRecord {
                    name: "x".to_string(),
                    rtype: TYPE_CNAME,
                    ttl: 5,
                    value: "alias.example".to_string(),
                },
                DnsRecord {
                    name: "x".to_string(),
                    rtype: TYPE_A,
                    ttl: 1693,
                    value: "93.184.216.34".to_string(),
                },
                DnsRecord {
                    name: "x".to_string(),
                    rtype: TYPE_A,
                    ttl: 300,
                    value: "93.184.216.35".to_string(),
                },
            ],
            elapsed_ms: Some(12.0),
            ..DnsQueryResult::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_lookup::{
        SOURCE_CERT_DEFAULT, SOURCE_CERT_NAMED, SOURCE_ERROR, SOURCE_SKIPPED,
    };
    use primecore_diagnostics::protocol_probe::ProtocolLine;

    fn ask_io<'a>(server: AskServerFn<'a>, doh: AskDohFn<'a>, tcp: AskTcpFn<'a>) -> AskIo<'a> {
        AskIo { server, doh, tcp }
    }

    #[test]
    fn denial_over_udp_is_rechecked_over_tcp() {
        let denial = DnsQueryResult {
            status: STATUS_NXDOMAIN.to_string(),
            rcode: Some(3),
            elapsed_ms: Some(6.0),
            authoritative: true,
            authority_count: 0,
            ..DnsQueryResult::default()
        };
        let io = ask_io(
            Box::new(|_s, _n, _t, _to, _at| denial.clone()),
            Box::new(|_s, _n, _t| DnsQueryResult::default()),
            Box::new(|_s, _n, _t, _to| test_fixtures::answer(TYPE_A, &["64.233.165.93"])),
        );
        let answer = ask_server(&test_fixtures::good(), "youtube.com", &io);

        assert_eq!(answer.status, STATUS_NXDOMAIN);
        assert!(answer.forged);
        assert_eq!(answer.tcp_ipv4, vec!["64.233.165.93".to_string()]);
    }

    #[test]
    fn honest_answer_is_not_rechecked() {
        let io = ask_io(
            Box::new(test_fixtures::fake_query),
            Box::new(|_s, _n, t| test_fixtures::fake_query(_s, _n, t, 0.0, 1)),
            Box::new(|_s, _n, _t, _to| panic!("лишний запрос по TCP")),
        );
        let answer = ask_server(&test_fixtures::good(), "example.com", &io);

        assert_eq!(answer.ipv4, vec!["93.184.216.34".to_string()]);
        assert!(answer.tcp_ipv4.is_empty());
    }

    #[test]
    fn windows_says_why_there_is_no_address() {
        let cases: Vec<(ResolveFailure, &str)> = vec![
            (ResolveFailure::Missing, STATUS_NXDOMAIN),
            (ResolveFailure::Timeout, STATUS_TIMEOUT),
            (ResolveFailure::Other, STATUS_ERROR),
        ];
        for (failure, expected) in cases {
            let resolve: ResolveWindowsFn<'_> = Box::new(move |_host| Err(failure.clone()));
            assert_eq!(ask_windows("youtube.com", &resolve).status, expected);
        }
    }

    #[test]
    fn windows_answer_keeps_both_families() {
        let infos = vec![
            ResolvedAddr {
                ipv6: false,
                address: "1.2.3.4".to_string(),
            },
            ResolvedAddr {
                ipv6: true,
                address: "2001:db8::1".to_string(),
            },
            ResolvedAddr {
                ipv6: false,
                address: "1.2.3.4".to_string(),
            },
        ];
        let resolve: ResolveWindowsFn<'_> = Box::new(move |_host| Ok(infos.clone()));
        let answer = ask_windows("example.com", &resolve);

        assert_eq!(
            (
                answer.status.as_str(),
                answer.ipv4.as_slice(),
                answer.ipv6.as_slice()
            ),
            (
                STATUS_OK,
                ["1.2.3.4".to_string()].as_slice(),
                ["2001:db8::1".to_string()].as_slice()
            )
        );
        assert_eq!(answer.first, "1.2.3.4");
    }

    #[test]
    fn windows_answer_remembers_which_address_goes_first() {
        let infos = vec![
            ResolvedAddr {
                ipv6: true,
                address: "2a00:1450:4010:c08::88".to_string(),
            },
            ResolvedAddr {
                ipv6: false,
                address: "93.184.216.34".to_string(),
            },
        ];
        let resolve: ResolveWindowsFn<'_> = Box::new(move |_host| Ok(infos.clone()));
        let answer = ask_windows("www.youtube.com", &resolve);
        assert_eq!(answer.first, "2a00:1450:4010:c08::88");
        assert_eq!(
            crate::domain_lookup::program_ipv6(&[answer]),
            "2a00:1450:4010:c08::88"
        );

        let reversed: ResolveWindowsFn<'_> = Box::new(move |_host| {
            Ok(vec![
                ResolvedAddr {
                    ipv6: false,
                    address: "93.184.216.34".to_string(),
                },
                ResolvedAddr {
                    ipv6: true,
                    address: "2a00:1450:4010:c08::88".to_string(),
                },
            ])
        });
        let answer = ask_windows("www.youtube.com", &reversed);
        assert_eq!(crate::domain_lookup::program_ipv6(&[answer]), "");
    }

    #[test]
    fn placeholder_certificate_is_not_a_neighbour() {
        // Google на запрос без имени сайта отдаёт сертификат на несуществующее имя invalid2.invalid.
        let fetch: CertFetchFn<'_> = Box::new(|_ip, _name| CertLookup {
            kind: "ok".to_string(),
            names: Vec::new(),
            common_name: "invalid2.invalid".to_string(),
            ..CertLookup::default()
        });
        let source = lookup_cert("142.251.110.190", SOURCE_CERT_DEFAULT, None, &fetch);

        assert_eq!(
            (source.status.as_str(), source.names.is_empty()),
            (SOURCE_SKIPPED, true)
        );
        assert!(
            source
                .detail
                .contains("сертификат-пустышку (invalid2.invalid)"),
            "{}",
            source.detail
        );
    }

    #[test]
    fn unreachable_service_is_explained_in_words() {
        let cases = [
            (HttpFailure::Timeout, "не ответил вовремя"),
            (HttpFailure::Ssl, "защищённое соединение"),
            (HttpFailure::Connection, "не удалось соединиться"),
            (HttpFailure::Other, "сервис недоступен"),
        ];
        for (failure, expected) in cases {
            let detail = unavailable(SOURCE_SHODAN, &failure).detail;
            assert!(detail.contains(expected), "{detail}");
            assert!(!detail.contains("Error"), "{detail}");
        }
    }

    #[test]
    fn ptr_lookup_uses_helper_servers_in_turn() {
        let asked: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let asked_sink = std::sync::Arc::clone(&asked);
        let ask: AskServerFn<'_> = Box::new(move |server, name, rtype, timeout, attempts| {
            asked_sink.lock().expect("замок").push(server.to_string());
            test_fixtures::fake_query(server, name, rtype, timeout, attempts)
        });
        let source = lookup_ptr("93.184.216.34", &["8.8.8.8".to_string()], &ask);
        assert_eq!(source.key, SOURCE_PTR);
        assert_eq!(source.names, vec!["host.example.net".to_string()]);
        assert_eq!(*asked.lock().expect("замок"), vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn network_lookup_keeps_cymru_fields() {
        let ask: AskServerFn<'_> = Box::new(|server, name, rtype, timeout, attempts| {
            test_fixtures::fake_query(server, name, rtype, timeout, attempts)
        });
        let info =
            lookup_network("93.184.216.34", &["1.1.1.1".to_string()], &ask).expect("владелец");
        assert_eq!(
            (info.asn.as_str(), info.prefix.as_str()),
            ("64500", "93.184.216.0/24")
        );
        assert_eq!(info.owner, "EXAMPLE-NET, US");
        assert_eq!(info.country, "US");
    }

    #[test]
    fn cert_without_name_from_delivery_network_is_skipped() {
        let fetch: CertFetchFn<'_> = Box::new(|_ip, _name| CertLookup {
            kind: "tls".to_string(),
            detail: "рукопожатие оборвано".to_string(),
            ..CertLookup::default()
        });
        let source = lookup_cert("1.2.3.4", SOURCE_CERT_DEFAULT, None, &fetch);
        assert_eq!(source.status, SOURCE_SKIPPED);

        let named = lookup_cert("1.2.3.4", SOURCE_CERT_NAMED, Some("example.com"), &fetch);
        assert_eq!(named.status, SOURCE_ERROR);
        assert!(
            named
                .detail
                .contains("соединение с именем example.com не установилось"),
            "{}",
            named.detail
        );
    }

    #[test]
    fn thc_pages_are_merged_until_done() {
        let calls: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
        let http: HttpFn<'_> = Box::new(move |_method, _url, body| {
            calls
                .lock()
                .expect("замок")
                .push(body.cloned().unwrap_or(Value::Null));
            let page = body.and_then(|value| {
                value
                    .get("page_state")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            let rows = if page.is_some() {
                r#"[{"domain": "second.example"}]"#
            } else {
                r#"[{"domain": "first.example"}, {"domain": "bad name"}]"#
            };
            let text =
                format!(r#"{{"matching_records": 2, "domains": {rows}, "next_page_state": ""}}"#);
            Ok((
                200,
                if page.is_some() {
                    text
                } else {
                    text.replace("\"next_page_state\": \"\"", "\"next_page_state\": \"next\"")
                },
            ))
        });
        let source = lookup_thc("93.184.216.34", &|| false, &http);
        assert_eq!(
            source.names,
            vec!["first.example".to_string(), "second.example".to_string()]
        );
        assert_eq!(source.status, SOURCE_OK);
        // Список получен целиком: «всего в базе» больше не нужно.
        assert!(source.total.is_none());
    }

    #[test]
    fn hackertarget_is_only_a_fallback() {
        let http: HttpFn<'_> = Box::new(|_method, url, _body| {
            if url.contains("thc.org") {
                return Err(HttpFailure::Other);
            }
            Ok((200, "fallback.example\n".to_string()))
        });
        let sources = lookup_neighbors("93.184.216.34", &|| false, &http);
        assert_eq!(sources[0].key, SOURCE_THC);
        assert_eq!(sources[0].status, SOURCE_ERROR);
        assert_eq!(sources[1].key, SOURCE_HACKERTARGET);
        assert_eq!(sources[1].names, vec!["fallback.example".to_string()]);
    }

    #[test]
    fn road_probe_uses_the_real_site_name_and_judges_only_cut_greetings() {
        let line = |key: &str, state: &str| ProtocolLine {
            key: key.to_string(),
            title: key.to_string(),
            state: state.to_string(),
            text: "текст".to_string(),
            ..ProtocolLine::default()
        };
        let asked: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());
        let tcp: TcpConnectFn<'_> = Box::new(|ip, port| TcpReport {
            ip: ip.to_string(),
            port,
            status: "ok".to_string(),
            elapsed_ms: Some(5.0),
            ..TcpReport::default()
        });
        let cases: Vec<(Vec<ProtocolLine>, Option<bool>)> = vec![
            (
                vec![
                    line(PROTO_TLS12, STATE_FAIL),
                    line(PROTO_TLS13, STATE_OK),
                    line("http", "ok"),
                ],
                Some(true),
            ),
            (
                vec![
                    line(PROTO_TLS12, STATE_FAIL),
                    line(PROTO_TLS13, STATE_FAIL),
                    line("http", "ok"),
                ],
                Some(false),
            ),
            (
                vec![
                    line(PROTO_TLS12, "unknown"),
                    line(PROTO_TLS13, "unknown"),
                    line("http", "ok"),
                ],
                None,
            ),
        ];
        // Программы ходят простым приветствием: по нему и судим, строки «Как Chrome» тут нет.
        for (lines, expected) in cases {
            let asked = &asked;
            let lines_for_probe = lines.clone();
            let probe_here: ProtocolProbeFn<'_> = Box::new(move |host, ip| {
                asked
                    .lock()
                    .expect("замок")
                    .push((host.to_string(), ip.to_string()));
                lines_for_probe.clone()
            });
            let road = program_road(
                Some("www.youtube.com"),
                "2a00:1450:4010:c08::88",
                &tcp,
                &probe_here,
            );
            assert_eq!(road.opens, expected);
            // Пробы идут с настоящим именем сайта.
            assert_eq!(
                asked.lock().expect("замок").last(),
                Some(&(
                    "www.youtube.com".to_string(),
                    "2a00:1450:4010:c08::88".to_string()
                ))
            );
        }

        // Без соединения пробы с именем не шлются.
        let silent_probe: ProtocolProbeFn<'_> =
            Box::new(|_host, _ip| panic!("пробы с именем не должно быть без соединения"));
        let silent_tcp: TcpConnectFn<'_> = Box::new(|ip, port| TcpReport {
            ip: ip.to_string(),
            port,
            status: "timeout".to_string(),
            ..TcpReport::default()
        });
        let road = program_road(
            Some("www.youtube.com"),
            "2a00:1450:4010:c08::88",
            &silent_tcp,
            &silent_probe,
        );
        assert!(road.lines.is_empty());
    }

    #[test]
    fn hosts_addresses_are_tried_one_by_one_until_the_site_opens() {
        let tried: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let road: RoadFn<'_> = {
            let tried = std::sync::Arc::clone(&tried);
            Box::new(move |_domain, ip| {
                tried.lock().expect("замок").push(ip.to_string());
                ProgramRoad {
                    ip: ip.to_string(),
                    tcp: TcpReport {
                        ip: ip.to_string(),
                        port: 443,
                        status: "ok".to_string(),
                        elapsed_ms: Some(5.0),
                        ..TcpReport::default()
                    },
                    opens: Some(ip == "2.2.2.2"),
                    ..ProgramRoad::default()
                }
            })
        };
        let cancel = SocketCancel::new();
        let found = hosts_road(
            "www.youtube.com",
            &[
                "1.1.1.1".to_string(),
                "2.2.2.2".to_string(),
                "3.3.3.3".to_string(),
            ],
            &cancel,
            3,
            0.0,
            crate::domain_lookup::HOSTS_ROAD_SLOW_S,
            &|| 0.0,
            &road,
        )
        .expect("проба была");
        assert_eq!(found.ip, "2.2.2.2");
        assert_eq!(found.opens, Some(true));
        assert_eq!(
            tried.lock().expect("замок").as_slice(),
            ["1.1.1.1".to_string(), "2.2.2.2".to_string()].as_slice()
        );

        // Первая попытка шла долго — фильтр глушит имя молча, вторая кончилась бы так же: не ждём её.
        let step = std::cell::Cell::new(0);
        let slow_road: RoadFn<'_> = Box::new(move |_domain, ip| ProgramRoad {
            ip: ip.to_string(),
            tcp: TcpReport {
                ip: ip.to_string(),
                port: 443,
                status: "ok".to_string(),
                ..TcpReport::default()
            },
            opens: Some(false),
            ..ProgramRoad::default()
        });
        let slow_now = || {
            let value = if step.get() == 0 { 0.0 } else { 9.0 };
            step.set(step.get() + 1);
            value
        };
        let found = hosts_road(
            "www.youtube.com",
            &["1.1.1.1".to_string(), "3.3.3.3".to_string()],
            &SocketCancel::new(),
            crate::domain_lookup::HOSTS_ROAD_TRIES,
            0.0,
            crate::domain_lookup::HOSTS_ROAD_SLOW_S,
            &slow_now,
            &slow_road,
        )
        .expect("первая проба была");
        assert_eq!(found.ip, "1.1.1.1");

        // Проверку сняли — дальше не идём.
        let stopped = SocketCancel::new();
        stopped.cancel();
        let none = hosts_road(
            "www.youtube.com",
            &["1.1.1.1".to_string()],
            &stopped,
            crate::domain_lookup::HOSTS_ROAD_TRIES,
            0.0,
            crate::domain_lookup::HOSTS_ROAD_SLOW_S,
            &|| 0.0,
            &slow_road,
        );
        assert!(none.is_none());
    }

    #[test]
    fn filter_place_is_searched_only_when_quic_is_blocked_by_name() {
        let located: std::sync::Mutex<Vec<(String, String, u32)>> =
            std::sync::Mutex::new(Vec::new());
        let facts = FilterFacts {
            control_ok: Some(true),
            stateful: Some(true),
            first_blocked_ttl: Some(6),
            checked_up_to: 6,
            ..FilterFacts::default()
        };
        let collect: CollectQuic = Box::new(|_domain, _ip, _cancel| {
            Some(QuicVerdict {
                code: "ok".to_string(),
                text: "отвечает".to_string(),
            })
        });
        let locate: LocateFilter = Box::new(|ip, name, max_ttl, _cancel| {
            located
                .lock()
                .expect("замок")
                .push((ip.to_string(), name.to_string(), max_ttl));
            Some(facts.clone())
        });

        let (verdict, facts) = inspect_quic(
            "example.com",
            "203.0.113.5",
            20,
            &SocketCancel::new(),
            &collect,
            &locate,
        );
        assert!(verdict.is_some());
        assert!(facts.is_none());
        assert!(located.lock().expect("замок").is_empty());

        let collect_none: CollectQuic = Box::new(|_domain, _ip, _cancel| None);
        let (verdict, facts) = inspect_quic(
            "example.com",
            "203.0.113.5",
            20,
            &SocketCancel::new(),
            &collect_none,
            &locate,
        );
        assert!(verdict.is_none() && facts.is_none());

        let collect_blocked: CollectQuic = Box::new(|_domain, _ip, _cancel| {
            Some(QuicVerdict {
                code: primecore_diagnostics::quic_probe::QUIC_BLOCKED_BY_NAME.to_string(),
                text: "блокируется".to_string(),
            })
        });
        let (verdict, facts) = inspect_quic(
            "example.com",
            "203.0.113.5",
            20,
            &SocketCancel::new(),
            &collect_blocked,
            &locate,
        );
        assert_eq!(
            verdict.expect("verdict").code,
            primecore_diagnostics::quic_probe::QUIC_BLOCKED_BY_NAME
        );
        assert!(facts.is_some());
        assert_eq!(
            located.lock().expect("замок").as_slice(),
            [("203.0.113.5".to_string(), "example.com".to_string(), 20_u32)].as_slice()
        );
    }
}
