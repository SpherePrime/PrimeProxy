//! Порт `src/dns/domain_lookup.py` — прогон проверки: две волны.
//!
//! Первая волна — то, что делает и браузер: адрес у Windows, у DNS компьютера
//! и у шифрованного эталона, затем сайт открывается так, как его открыл бы
//! Chrome. Вторая волна — подробный разбор: десятки DNS-серверов, пинг, путь
//! до сервера, сертификаты, сведения о сети и соседи по адресу. Она идёт
//! всегда, даже когда сайт открылся и DNS честный: человек сам нажал кнопку, и
//! ему удобнее видеть полную картину (решение пользователя от 2026-10-17).
//!
//! Вся сеть приходит замыканиями в [`LookupIo`] (python подменяет её по именам
//! модуля). Отличие от python: вопросы идут по порядку, а не из пула потоков —
//! параллельный залп остаётся слою запуска движка (как в
//! [`crate::doh_lookup`]); порядок ответов, выводы и тексты от этого не
//! меняются, «Стоп» и общий срок [`RUN_DEADLINE_S`] проверяются перед каждым
//! шагом. `on_stage` получает промежуточный отчёт каждый раз, когда готова
//! очередная часть, — страница показывает результаты по мере появления.

use primecore_socketcancel::SocketCancel;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::domain_lookup::{
    annotate_answers, hosts_road_wanted, is_public_ip, normalize_target, pick_ipv6,
    pick_primary_ip, program_ipv6, unique_servers, DnsServer, DomainLookupReport, NeighborSource,
    ResolverAnswer, HOSTS_ROAD_BUDGET_S, HOSTS_ROAD_PAUSE_S, HOSTS_ROAD_SLOW_S, HOSTS_ROAD_TRIES,
    KIND_DOMAIN, KIND_INVALID, QUICK_SERVER_KINDS, RUN_DEADLINE_S, SERVER_SYSTEM,
    SOURCE_CERT_DEFAULT, SOURCE_CERT_NAMED, SOURCE_PTR, SOURCE_SHODAN, SOURCE_SKIPPED, SOURCE_THC,
};
use crate::domain_lookup_steps::{
    ask_server, ask_windows, hosts_road, lookup_cert, lookup_neighbors, lookup_network, lookup_ptr,
    lookup_ripestat, lookup_shodan, AskIo, CanaryFn, CertFetchFn, HostsHelpFn, HttpFn,
    QuicInspectFn, ResolveWindowsFn, RoadFn, RouteFn, SiteCheckFn, TcpConnectFn,
};

/// Типы шагов и подстановки сети — здесь, чтобы собрать всё вместе.
pub use crate::domain_lookup_steps::PingFn;

/// Вся сеть проверки (python подменяет `_ping`, `_tcp_connect`, `_http`… по
/// именам модуля). Живую сборку делает слой запуска; тесты подставляют свои.
pub struct LookupIo<'a> {
    /// DNS-запросы к серверам.
    pub ask: AskIo<'a>,
    /// Перехват обычных запросов (python `canary_answered`).
    pub canary: CanaryFn<'a>,
    /// Как имя видит система (python `resolve_addrinfo`).
    pub resolve_windows: ResolveWindowsFn<'a>,
    /// Пинг адреса (python `_ping`).
    pub ping: PingFn<'a>,
    /// Соединение с портом 443 (python `_tcp_connect`).
    pub tcp_connect: TcpConnectFn<'a>,
    /// Дорога программ с пробами имени (python `_program_road`).
    pub road: RoadFn<'a>,
    /// Сайт теми же пробами, что в BlockCheck (python `_check_site`).
    pub site: SiteCheckFn<'a>,
    /// Что знает «Редактор hosts» (python `_hosts_help`).
    pub hosts_help: HostsHelpFn<'a>,
    /// Путь до адреса по узлам (python `trace_route`).
    pub route: RouteFn<'a>,
    /// QUIC и место фильтра (python `_inspect_quic`); срок и «Стоп» внутри.
    pub quic: QuicInspectFn<'a>,
    /// Имена из сертификата (python `fetch_cert_names`).
    pub cert: CertFetchFn<'a>,
    /// Запросы к внешним сервисам (python `_http`).
    pub http: HttpFn<'a>,
}

/// python `_Run` — кнопка «Стоп» и общий предел времени на всю проверку.
///
/// Пул потоков python здесь не нужен: вопросы идут по порядку (см. шапку
/// модуля), [`MAX_PARALLEL`] остаётся справочной константой.
struct Run<'a> {
    should_stop: Option<&'a dyn Fn() -> bool>,
    deadline: Instant,
    /// Снимает пробы, когда проверку остановили или вышло время.
    cancel: Arc<SocketCancel>,
}

impl<'a> Run<'a> {
    fn new(should_stop: Option<&'a dyn Fn() -> bool>) -> Self {
        Self {
            should_stop,
            deadline: Instant::now() + Duration::from_secs_f64(RUN_DEADLINE_S),
            cancel: Arc::new(SocketCancel::new()),
        }
    }

    fn stopped(&self) -> bool {
        self.should_stop.is_some_and(|check| check())
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn halted(&self) -> bool {
        self.stopped() || self.expired()
    }

    /// Даёт время на шаг, который идёт после всех остальных.
    fn extend(&mut self, seconds: f64) {
        let now = Instant::now();
        self.deadline = self.deadline.max(now) + Duration::from_secs_f64(seconds.max(0.0));
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

/// python `run_domain_lookup` — проверка домена или адреса двумя волнами.
#[must_use]
pub fn run_domain_lookup(
    target: &str,
    servers: &[DnsServer],
    use_external: bool,
    on_stage: Option<&dyn Fn(&DomainLookupReport)>,
    should_stop: Option<&dyn Fn() -> bool>,
    io: &LookupIo<'_>,
) -> DomainLookupReport {
    let started = Instant::now();
    let (kind, value, error) = normalize_target(target);
    if kind == KIND_INVALID {
        return DomainLookupReport {
            target: target.trim().to_string(),
            kind,
            error,
            finished: true,
            ..DomainLookupReport::default()
        };
    }

    let mut report = DomainLookupReport {
        target: value.clone(),
        kind: kind.clone(),
        ..DomainLookupReport::default()
    };
    let server_list = unique_servers(servers);
    let mut run = Run::new(should_stop);

    let publish = |report: &DomainLookupReport| -> DomainLookupReport {
        let mut updated = report.clone();
        updated.elapsed_s = started.elapsed().as_secs_f64();
        if let Some(on_stage) = on_stage {
            on_stage(&updated);
        }
        updated
    };

    let quick: Vec<DnsServer> = server_list
        .iter()
        .filter(|server| QUICK_SERVER_KINDS.contains(&server.kind.as_str()))
        .cloned()
        .collect();
    let rest: Vec<DnsServer> = server_list
        .iter()
        .filter(|server| !QUICK_SERVER_KINDS.contains(&server.kind.as_str()))
        .cloned()
        .collect();

    let primary_ip = if kind == KIND_DOMAIN {
        report = resolve_stage(&run, report, &quick, &publish, false, io);
        pick_primary_ip(&report.answers)
    } else {
        value.clone()
    };
    report.primary_ip = primary_ip.clone();
    report = publish(&report);

    if !primary_ip.is_empty() && !run.halted() {
        report = browser_stage(&run, report, &publish, io);
    }
    if !run.halted() {
        if kind == KIND_DOMAIN {
            report = resolve_stage(&run, report, &rest, &publish, true, io);
        }
        if !report.primary_ip.is_empty() && !run.halted() {
            report = address_stage(&mut run, report, &server_list, use_external, &publish, io);
        }
    }
    run.close();

    report.finished = true;
    report.stopped = run.stopped();
    report.timed_out = run.expired() && !run.stopped();
    report.elapsed_s = started.elapsed().as_secs_f64();
    report
}

/// python `_resolve_stage` — ответы DNS-серверов `servers`; прежние ответы
/// отчёта остаются первыми.
fn resolve_stage(
    run: &Run<'_>,
    mut report: DomainLookupReport,
    servers: &[DnsServer],
    publish: &dyn Fn(&DomainLookupReport) -> DomainLookupReport,
    canary: bool,
    io: &LookupIo<'_>,
) -> DomainLookupReport {
    let domain = report.target.clone();
    let earlier = report.answers.len();
    let mut collected: Vec<ResolverAnswer> = report.answers.clone();
    if earlier == 0 && !run.halted() {
        collected.push(ask_windows(&domain, &io.resolve_windows));
        report.answers = annotate_answers(collected.clone());
        report = publish(&report);
    }
    for server in servers {
        if run.halted() {
            break;
        }
        collected.push(ask_server(server, &domain, &io.ask));
        report.answers = annotate_answers(collected.clone());
        report = publish(&report);
    }
    if canary && !run.halted() {
        report.intercepted = (io.canary)(&domain);
        report = publish(&report);
    }
    report
}

/// python `_browser_stage` — первая волна по адресу: сайт открывается так, как
/// его открыл бы Chrome, и QUIC — как у браузера.
///
/// Разбор причины внутри обеих проб — только когда сайт не открылся
/// (`diagnostics.engine`, `diagnostics.quic_probe`).
fn browser_stage(
    run: &Run<'_>,
    mut report: DomainLookupReport,
    publish: &dyn Fn(&DomainLookupReport) -> DomainLookupReport,
    io: &LookupIo<'_>,
) -> DomainLookupReport {
    let domain = if report.kind == KIND_DOMAIN {
        report.target.clone()
    } else {
        String::new()
    };
    if domain.is_empty() || !is_public_ip(&report.primary_ip) {
        return report;
    }
    let ip = report.primary_ip.clone();
    // Соединение с портом 443 браузер открывает и сам; по нему сравнивается дорога IPv6.
    if !run.halted() {
        report.tcp = Some((io.tcp_connect)(&ip, 443));
        report = publish(&report);
    }
    if !run.halted() {
        report.site = (io.site)(&domain);
        report = publish(&report);
    }
    if !run.halted() {
        let help = (io.hosts_help)(&domain);
        report.hosts_service = help.service;
        report.hosts_rows = help.rows;
        report.hosts_managed = help.managed;
        report.hosts_offered = help.offered;
        report = publish(&report);
    }
    if !ip.contains(':') && !run.halted() {
        let (verdict, facts) = (io.quic)(&domain, &ip);
        report.quic = verdict;
        report.filter_facts = facts;
        report = publish(&report);
    }
    // Windows ставит первым IPv6 — по нему и пойдёт браузер: эта дорога — часть первой волны.
    let road_ip = if !ip.contains(':') {
        program_ipv6(&report.answers)
    } else {
        String::new()
    };
    if !road_ip.is_empty() && !run.halted() {
        report.road = Some((io.road)(Some(&domain), &road_ip));
        report = publish(&report);
    }
    report
}

/// python `_address_stage` — вторая волна по адресу: пинг, путь, сертификаты,
/// сеть и соседи (сайт и QUIC уже проверены).
fn address_stage(
    run: &mut Run<'_>,
    mut report: DomainLookupReport,
    servers: &[DnsServer],
    use_external: bool,
    publish: &dyn Fn(&DomainLookupReport) -> DomainLookupReport,
    io: &LookupIo<'_>,
) -> DomainLookupReport {
    let ip = report.primary_ip.clone();
    let public = is_public_ip(&ip);
    let mut helpers: Vec<String> = servers
        .iter()
        .filter(|server| server.kind == SERVER_SYSTEM)
        .map(|server| server.address.clone())
        .collect();
    for address in crate::domain_lookup::HELPER_SERVERS {
        if !helpers.contains(&address.to_string()) {
            helpers.push(address.to_string());
        }
    }
    let domain = if report.kind == KIND_DOMAIN {
        Some(report.target.clone())
    } else {
        None
    };

    let mut order: Vec<String> = vec![SOURCE_PTR.to_string()];
    let mut sources: std::collections::HashMap<String, NeighborSource> =
        std::collections::HashMap::new();
    let ordered_sources = |sources: &std::collections::HashMap<String, NeighborSource>,
                           order: &[String]|
     -> Vec<NeighborSource> {
        order
            .iter()
            .filter_map(|key| sources.get(key).cloned())
            .collect()
    };

    if !run.halted() {
        report.ping = Some((io.ping)(&ip));
        report = publish(&report);
    }
    if !run.halted() {
        sources.insert(
            SOURCE_PTR.to_string(),
            lookup_ptr(&ip, &helpers, &io.ask.server),
        );
        report.sources = ordered_sources(&sources, &order);
        report = publish(&report);
    }
    if report.tcp.is_none() && !run.halted() {
        report.tcp = Some((io.tcp_connect)(&ip, 443));
        report = publish(&report);
    }
    // Пингуется тот IPv6, на который Windows ведёт программы; нет такого — любой адрес IPv6 сайта.
    let road_ip = if !ip.contains(':') {
        program_ipv6(&report.answers)
    } else {
        String::new()
    };
    let ipv6 = if road_ip.is_empty() {
        pick_ipv6(&report.answers, &ip)
    } else {
        road_ip.clone()
    };
    if !ipv6.is_empty() && !run.halted() {
        report.ping6 = Some((io.ping)(&ipv6));
        report = publish(&report);
    }
    if !road_ip.is_empty() && report.road.is_none() && !run.halted() {
        report.road = Some((io.road)(domain.as_deref(), &road_ip));
        report = publish(&report);
    }
    if !ip.contains(':') && !run.halted() {
        report.route = Some((io.route)(&ip));
        report = publish(&report);
    }
    if let Some(domain) = &domain {
        order.push(SOURCE_CERT_NAMED.to_string());
        if !run.halted() {
            sources.insert(
                SOURCE_CERT_NAMED.to_string(),
                lookup_cert(&ip, SOURCE_CERT_NAMED, Some(domain), &io.cert),
            );
            report.sources = ordered_sources(&sources, &order);
            report = publish(&report);
        }
    }
    order.push(SOURCE_CERT_DEFAULT.to_string());
    if !run.halted() {
        sources.insert(
            SOURCE_CERT_DEFAULT.to_string(),
            lookup_cert(&ip, SOURCE_CERT_DEFAULT, None, &io.cert),
        );
        report.sources = ordered_sources(&sources, &order);
        report = publish(&report);
    }
    for key in crate::domain_lookup::EXTERNAL_SOURCES {
        order.push(key.to_string());
    }

    if public && !run.halted() {
        if let Some(network) = lookup_network(&ip, &helpers, &io.ask.server) {
            report.network =
                crate::domain_lookup::merge_network(report.network.take(), Some(network));
            report = publish(&report);
        }
    }
    let mut skip_reason = if use_external {
        String::new()
    } else {
        "выключено".to_string()
    };
    if !public {
        skip_reason = "локальный адрес наружу не отправляется".to_string();
    }
    if !skip_reason.is_empty() {
        for key in [SOURCE_THC, SOURCE_SHODAN] {
            sources.insert(
                key.to_string(),
                NeighborSource {
                    detail: skip_reason.clone(),
                    ..NeighborSource::new(key, SOURCE_SKIPPED)
                },
            );
        }
        report.sources = ordered_sources(&sources, &order);
    } else if !run.halted() {
        for source in lookup_neighbors(&ip, &|| run.halted(), &io.http) {
            sources.insert(source.key.clone(), source);
        }
        report.sources = ordered_sources(&sources, &order);
        report = publish(&report);
        if !run.halted() {
            sources.insert(SOURCE_SHODAN.to_string(), lookup_shodan(&ip, &io.http));
            report.sources = ordered_sources(&sources, &order);
            report = publish(&report);
        }
        if !run.halted() {
            if let Some(network) = lookup_ripestat(&ip, &io.http) {
                report.network =
                    crate::domain_lookup::merge_network(report.network.take(), Some(network));
                report = publish(&report);
            }
        }
    }
    report.sources = ordered_sources(&sources, &order);

    if let Some(domain) = &domain {
        if hosts_road_wanted(&report) && !run.halted() {
            // Сайт закрыт, а у «Редактора hosts» есть для него свои адреса: откроется ли он по ним.
            run.extend(HOSTS_ROAD_BUDGET_S);
            let run_started = Instant::now();
            let now = move || run_started.elapsed().as_secs_f64();
            report.hosts_road = hosts_road(
                domain,
                &report.hosts_offered,
                &run.cancel,
                HOSTS_ROAD_TRIES,
                HOSTS_ROAD_PAUSE_S,
                HOSTS_ROAD_SLOW_S,
                &now,
                &io.road,
            );
            report = publish(&report);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_lookup::{classify_ip, road_trouble};
    use crate::domain_lookup::{
        HostsHelp, PingReport, ProgramRoad, TcpReport, LEVEL_FAIL, LEVEL_OK, LEVEL_UNKNOWN,
    };
    use crate::domain_lookup_steps::test_fixtures as fx;
    use crate::domain_lookup_steps::{CertLookup, HttpFailure, ResolveFailure, ResolvedAddr};
    use primecore_diagnostics::icmp::{HOP_ROUTER, HOP_SILENT, HOP_TARGET};
    use primecore_diagnostics::path_trace::{FilterFacts, Hop, RouteTrace};
    use primecore_diagnostics::quic_probe::{QuicVerdict, QUIC_BLOCKED_BY_NAME, QUIC_OK};
    use primecore_dnswire::{
        DnsQueryResult, STATUS_NXDOMAIN, STATUS_OK, STATUS_TIMEOUT, TYPE_A, TYPE_AAAA,
    };
    use serde_json::json;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    const V6: &str = "2a00:1450:4010:c08::88";
    const V4: &str = "93.184.216.34";

    type HttpFake = Box<dyn Fn(&str, &str, Option<&Value>) -> Result<(i32, String), HttpFailure>>;
    type RouteFake = Box<dyn Fn(&str) -> RouteTrace>;
    type QuicFake = Box<dyn Fn(&str, &str) -> (Option<QuicVerdict>, Option<FilterFacts>)>;
    type RoadFake = Box<dyn Fn(Option<&str>, &str) -> ProgramRoad>;

    /// Подмены сети по умолчанию — из python `_Network`: тесты не выходят в интернет.
    struct Net {
        site: Arc<Mutex<Option<Value>>>,
        site_calls: Arc<Mutex<Vec<String>>>,
        http_calls: Arc<Mutex<Vec<String>>>,
        road_calls: Arc<Mutex<Vec<String>>>,
        http: Arc<HttpFake>,
        route: Arc<RouteFake>,
        quic: Arc<QuicFake>,
        resolve: Arc<Vec<ResolvedAddr>>,
        tcp: Arc<(String, String)>,
        hosts_help: Arc<HostsHelp>,
        hosts_road: Arc<Option<ProgramRoad>>,
        road: Arc<RoadFake>,
    }

    impl Net {
        fn new() -> Self {
            Self {
                site: Arc::new(Mutex::new(None)),
                site_calls: Arc::new(Mutex::new(Vec::new())),
                http_calls: Arc::new(Mutex::new(Vec::new())),
                road_calls: Arc::new(Mutex::new(Vec::new())),
                http: Arc::new(Box::new(fake_http)),
                route: Arc::new(Box::new(|ip| RouteTrace {
                    target: ip.to_string(),
                    supported: false,
                    ..RouteTrace::default()
                })),
                quic: Arc::new(Box::new(|_domain, _ip| (None, None))),
                resolve: Arc::new(vec![ResolvedAddr {
                    ipv6: false,
                    address: V4.to_string(),
                }]),
                tcp: Arc::new(("timeout".to_string(), "ok".to_string())),
                hosts_help: Arc::new(HostsHelp::default()),
                hosts_road: Arc::new(None),
                road: Arc::new(Box::new(|_domain, ip| ProgramRoad {
                    ip: ip.to_string(),
                    tcp: TcpReport {
                        ip: ip.to_string(),
                        port: 443,
                        status: "ok".to_string(),
                        elapsed_ms: Some(5.0),
                        ..TcpReport::default()
                    },
                    ..ProgramRoad::default()
                })),
            }
        }

        fn io(&self) -> LookupIo<'static> {
            let site_calls = Arc::clone(&self.site_calls);
            let site_value = Arc::clone(&self.site);
            let site: SiteCheckFn<'static> = Box::new(move |domain| {
                site_calls.lock().expect("замок").push(domain.to_string());
                site_value.lock().expect("замок").clone()
            });
            let http_calls = Arc::clone(&self.http_calls);
            let http_fake = Arc::clone(&self.http);
            let http: HttpFn<'static> = Box::new(move |method, url, body| {
                http_calls.lock().expect("замок").push(url.to_string());
                http_fake(method, url, body)
            });
            let route_fake = Arc::clone(&self.route);
            let route: RouteFn<'static> = Box::new(move |ip| route_fake(ip));
            let quic_fake = Arc::clone(&self.quic);
            let quic: QuicInspectFn<'static> = Box::new(move |domain, ip| quic_fake(domain, ip));
            let resolve = Arc::clone(&self.resolve);
            let resolve: ResolveWindowsFn<'static> =
                Box::new(move |_host| Ok(resolve.as_ref().clone()));
            let tcp_statuses = Arc::clone(&self.tcp);
            let tcp: TcpConnectFn<'static> = Box::new(move |ip, port| {
                let status = if ip.contains(':') {
                    tcp_statuses.0.as_str()
                } else {
                    tcp_statuses.1.as_str()
                };
                TcpReport {
                    ip: ip.to_string(),
                    port,
                    status: status.to_string(),
                    elapsed_ms: (status == "ok").then_some(5.0),
                    ..TcpReport::default()
                }
            });
            let hosts_help = Arc::clone(&self.hosts_help);
            let hosts_help: HostsHelpFn<'static> =
                Box::new(move |_domain| hosts_help.as_ref().clone());
            let road_calls = Arc::clone(&self.road_calls);
            let road_fake = Arc::clone(&self.road);
            let hosts_road_value = Arc::clone(&self.hosts_road);
            let road: RoadFn<'static> = Box::new(move |domain, ip| {
                road_calls.lock().expect("замок").push(ip.to_string());
                if let Some(road) = hosts_road_value.as_ref() {
                    return road.clone();
                }
                road_fake(domain, ip)
            });
            LookupIo {
                ask: AskIo {
                    server: Box::new(|server, name, rtype, timeout, attempts| {
                        fx::fake_query(server, name, rtype, timeout, attempts)
                    }),
                    doh: Box::new(|server, name, rtype| {
                        fx::fake_query(server, name, rtype, 0.0, 1)
                    }),
                    tcp: Box::new(|server, name, rtype, _timeout| {
                        fx::fake_query(server, name, rtype, 0.0, 1)
                    }),
                },
                canary: Box::new(|_domain| false),
                resolve_windows: resolve,
                ping: Box::new(|ip| PingReport {
                    ip: ip.to_string(),
                    supported: true,
                    sent: 4,
                    received: 3,
                    min_ms: Some(10.0),
                    avg_ms: Some(20.0),
                    max_ms: Some(30.0),
                    ttl: Some(57),
                    ..PingReport::default()
                }),
                tcp_connect: tcp,
                road,
                site,
                hosts_help,
                route,
                quic,
                cert: Box::new(|_ip, _name| CertLookup {
                    kind: "ok".to_string(),
                    names: vec!["cert.example".to_string()],
                    common_name: "cn.example".to_string(),
                    ..CertLookup::default()
                }),
                http,
            }
        }

        fn run(
            &self,
            target: &str,
            servers: &[DnsServer],
            use_external: bool,
        ) -> DomainLookupReport {
            let io = self.io();
            run_domain_lookup(target, servers, use_external, None, None, &io)
        }

        fn run_with_stages(
            &mut self,
            target: &str,
            servers: &[DnsServer],
            use_external: bool,
        ) -> (DomainLookupReport, Vec<DomainLookupReport>) {
            let stages: Arc<Mutex<Vec<DomainLookupReport>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&stages);
            let io = self.io();
            let report = run_domain_lookup(
                target,
                servers,
                use_external,
                Some(&move |report| sink.lock().expect("замок").push(report.clone())),
                None,
                &io,
            );
            drop(io);
            (
                report,
                Arc::try_unwrap(stages)
                    .ok()
                    .map(|mutex| mutex.into_inner().expect("замок"))
                    .expect("этапы"),
            )
        }
    }

    /// python `_fake_http`.
    fn fake_http(
        _method: &str,
        url: &str,
        body: Option<&Value>,
    ) -> Result<(i32, String), HttpFailure> {
        if url.contains("thc.org") {
            let page = body
                .and_then(|value| value.get("page_state"))
                .and_then(Value::as_str)
                .is_some();
            let rows = if page {
                r#"[{"domain": "second.example"}]"#
            } else {
                r#"[{"domain": "first.example"}, {"domain": "bad name"}]"#
            };
            let next = if page { "" } else { "next" };
            return Ok((
                200,
                format!(
                    r#"{{"matching_records": 2, "domains": {rows}, "next_page_state": "{next}"}}"#
                ),
            ));
        }
        if url.contains("shodan") {
            return Ok((
                200,
                r#"{"hostnames": ["shodan.example"], "ports": [80, 443]}"#.to_string(),
            ));
        }
        if url.contains("ripe.net") {
            return Ok((
                200,
                r#"{"data": {"resource": "93.184.216.0/24", "announced": true, "asns": [{"asn": 64500, "holder": "EXAMPLE"}]}}"#
                    .to_string(),
            ));
        }
        panic!("{url}");
    }

    fn all_servers() -> Vec<DnsServer> {
        vec![fx::secure(), fx::good(), fx::stub(), fx::dead()]
    }

    /// Трасса из python `_route`: семь узлов, дошли до адреса.
    fn full_route(ip: &str) -> RouteTrace {
        let hops: Vec<Hop> = (1..=6)
            .map(|ttl| Hop {
                ttl,
                kind: HOP_ROUTER,
                address: format!("10.0.0.{ttl}"),
                rtt_ms: Some(f64::from(ttl)),
            })
            .collect();
        RouteTrace {
            target: ip.to_string(),
            hops: [
                hops,
                vec![Hop {
                    ttl: 7,
                    kind: HOP_TARGET,
                    address: ip.to_string(),
                    rtt_ms: Some(40.0),
                }],
            ]
            .concat(),
            reached: true,
            supported: true,
        }
    }

    fn wave_run(site_level: &str) -> (DomainLookupReport, Net, Vec<String>, Vec<String>) {
        let net = Net::new();
        *net.site.lock().expect("замок") =
            Some(json!({"level": site_level, "headline": "example.com"}));
        let asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let canary: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut io = net.io();
        let asked_sink = Arc::clone(&asked);
        io.ask.server = Box::new(move |server, name, rtype, timeout, attempts| {
            asked_sink.lock().expect("замок").push(server.to_string());
            fx::fake_query(server, name, rtype, timeout, attempts)
        });
        let canary_sink = Arc::clone(&canary);
        io.canary = Box::new(move |domain| {
            canary_sink.lock().expect("замок").push(domain.to_string());
            false
        });
        let servers = vec![fx::secure(), fx::good()];
        let report = run_domain_lookup("example.com", &servers, true, None, None, &io);
        drop(io);
        let asked = Arc::try_unwrap(asked)
            .ok()
            .map(|m| m.into_inner().expect("замок"))
            .expect("спрошены");
        let canary = Arc::try_unwrap(canary)
            .ok()
            .map(|m| m.into_inner().expect("замок"))
            .expect("canary");
        (report, net, asked, canary)
    }

    #[test]
    fn open_site_with_honest_dns_still_gets_the_full_check() {
        let (report, net, asked, canary) = wave_run("ok");

        assert_eq!(
            net.site_calls.lock().expect("замок").as_slice(),
            ["example.com".to_string()].as_slice()
        );
        // Подробный разбор идёт всегда (решение пользователя 2026-10-17): общедоступные
        // DNS-серверы, пробный запрос, пинг и путь — даже когда сайт открылся.
        assert!(asked.iter().any(|address| address == fx::GOOD_ADDRESS));
        assert_eq!(canary, vec!["example.com".to_string()]);
        assert!(report.ping.is_some());
        assert!(report.route.is_some());
    }

    #[test]
    fn closed_site_gets_the_full_check() {
        let (report, _net, asked, canary) = wave_run("fail");

        assert!(asked.iter().any(|address| address == fx::GOOD_ADDRESS));
        assert_eq!(canary, vec!["example.com".to_string()]);
        assert!(report.ping.is_some());
        assert!(report.route.is_some());
    }

    #[test]
    fn address_typed_by_hand_is_checked_in_full() {
        let net = Net::new();
        let report = net.run("93.184.216.34", &[fx::secure(), fx::good()], true);
        assert!(report.ping.is_some());
    }

    #[test]
    fn domain_run_collects_everything() {
        let mut net = Net::new();
        net.http = Arc::new(Box::new(fake_http));
        let stages_sink: Arc<Mutex<Vec<DomainLookupReport>>> = Arc::new(Mutex::new(Vec::new()));
        let io = net.io();
        let sink = Arc::clone(&stages_sink);
        let report = run_domain_lookup(
            "https://example.com/",
            &all_servers(),
            true,
            Some(&move |report| sink.lock().expect("замок").push(report.clone())),
            None,
            &io,
        );
        drop(io);
        let stages = Arc::try_unwrap(stages_sink)
            .ok()
            .map(|m| m.into_inner().expect("замок"))
            .expect("этапы");

        assert!(report.finished);
        assert!(!report.stopped);
        assert_eq!(report.primary_ip, V4);
        let by_label = |label: &str| {
            report
                .answers
                .iter()
                .find(|item| item.server.label == label)
                .unwrap_or_else(|| panic!("нет ответа от {label}"))
                .clone()
        };
        assert_eq!(
            by_label("Хороший").ipv6,
            vec!["2606:2800:220:1::1".to_string()]
        );
        assert_eq!(by_label("Провайдер").level, LEVEL_FAIL);
        assert_eq!(by_label("Молчун").status, STATUS_TIMEOUT);
        assert_eq!(by_label("Windows").ipv4, vec![V4.to_string()]);
        assert!(!report.intercepted);
        let ping = report.ping.expect("пинг");
        assert_eq!((ping.sent, ping.received, ping.ttl), (4, 3, Some(57)));
        assert_eq!(
            report.ping6.as_ref().expect("пинг6").ip,
            "2606:2800:220:1::1"
        );
        assert_eq!(report.tcp.as_ref().expect("tcp").status, "ok");
        let network = report.network.as_ref().expect("сеть");
        assert_eq!(
            (network.asn.as_str(), network.prefix.as_str()),
            ("64500", "93.184.216.0/24")
        );
        assert_eq!(network.owner, "EXAMPLE-NET, US");
        assert_eq!(
            network.origins,
            vec![("64500".to_string(), "EXAMPLE".to_string())]
        );
        let sources: std::collections::HashMap<&str, &NeighborSource> = report
            .sources
            .iter()
            .map(|source| (source.key.as_str(), source))
            .collect();
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_PTR].names,
            vec!["host.example.net".to_string()]
        );
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_CERT_NAMED].names,
            vec!["cn.example".to_string(), "cert.example".to_string()]
        );
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_THC].names,
            vec!["first.example".to_string(), "second.example".to_string()]
        );
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_SHODAN].names,
            vec!["shodan.example".to_string()]
        );
        // THC ответил — запасной HackerTarget с его маленьким лимитом не трогаем.
        assert!(!sources.contains_key(crate::domain_lookup::SOURCE_HACKERTARGET));
        assert!(!net
            .http_calls
            .lock()
            .expect("замок")
            .iter()
            .any(|url| url.contains("hackertarget")));
        assert!(stages.len() > 3);
        assert!(!stages[0].finished);
    }

    #[test]
    fn hackertarget_is_only_a_fallback() {
        let mut net = Net::new();
        net.http = Arc::new(Box::new(|_method, url, _body| {
            if url.contains("thc.org") {
                return Err(HttpFailure::Other);
            }
            if url.contains("hackertarget") {
                return Ok((200, "fallback.example\n".to_string()));
            }
            fake_http("GET", url, None)
        }));

        let report = net.run("93.184.216.34", &[fx::good()], true);

        let sources: std::collections::HashMap<&str, &NeighborSource> = report
            .sources
            .iter()
            .map(|source| (source.key.as_str(), source))
            .collect();
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_THC].status,
            crate::domain_lookup::SOURCE_ERROR
        );
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_HACKERTARGET].names,
            vec!["fallback.example".to_string()]
        );
        assert!(report.answers.is_empty());
        assert!(!sources.contains_key(crate::domain_lookup::SOURCE_CERT_NAMED));
    }

    #[test]
    fn external_services_are_not_called_when_disabled() {
        let mut net = Net::new();
        net.http = Arc::new(Box::new(fake_http));

        let report = net.run("93.184.216.34", &[fx::good()], false);

        assert!(net.http_calls.lock().expect("замок").is_empty());
        let sources: std::collections::HashMap<&str, &NeighborSource> = report
            .sources
            .iter()
            .map(|source| (source.key.as_str(), source))
            .collect();
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_THC].status,
            crate::domain_lookup::SOURCE_SKIPPED
        );
        // Владелец сети узнаётся DNS-запросом, внешние сайты для этого не нужны.
        assert_eq!(report.network.as_ref().expect("сеть").asn, "64500");
    }

    #[test]
    fn private_address_is_never_sent_out() {
        let mut net = Net::new();
        net.http = Arc::new(Box::new(fake_http));

        let report = net.run("192.168.1.1", &[fx::good()], true);

        assert!(net.http_calls.lock().expect("замок").is_empty());
        assert!(report.network.is_none());
        let sources: std::collections::HashMap<&str, &NeighborSource> = report
            .sources
            .iter()
            .map(|source| (source.key.as_str(), source))
            .collect();
        assert_eq!(
            sources[crate::domain_lookup::SOURCE_THC].status,
            crate::domain_lookup::SOURCE_SKIPPED
        );
    }

    #[test]
    fn domain_is_also_checked_like_a_site_in_blockcheck_and_an_address_is_not() {
        let mut net = Net::new();
        *net.site.lock().expect("замок") = Some(json!({
            "key": "user:example.com",
            "label": "example.com",
            "level": "ok",
            "headline": "example.com открывается",
            "targets": []
        }));
        let (report, stages) = net.run_with_stages("example.com", &[fx::good()], false);
        // Домен проверен не только по адресу: в отчёте лежит запись сайта, как в BlockCheck.
        assert_eq!(
            net.site_calls.lock().expect("замок").as_slice(),
            ["example.com".to_string()].as_slice()
        );
        assert_eq!(report.site, net.site.lock().expect("замок").clone());
        assert!(stages.iter().any(|stage| stage.site == report.site));
        let text = crate::domain_lookup_plans::build_text_report(&report);
        assert!(text.contains("=== Как открывается сайт ==="));

        // У голого адреса имени сайта нет — такой проверки не бывает; локальный адрес тоже не трогаем.
        net.site_calls.lock().expect("замок").clear();
        let plain = net.run("93.184.216.34", &[fx::good()], false);
        assert!(plain.site.is_none());
        assert!(net.site_calls.lock().expect("замок").is_empty());
    }

    #[test]
    fn path_quic_and_filter_place_reach_the_report() {
        let blocked = QuicVerdict {
            code: QUIC_BLOCKED_BY_NAME.to_string(),
            text: "блокируется по имени сайта".to_string(),
        };
        let asked: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let mut net = Net::new();
        net.route = Arc::new(Box::new(full_route));
        let asked_sink = Arc::clone(&asked);
        net.quic = Arc::new(Box::new(move |domain, ip| {
            asked_sink
                .lock()
                .expect("замок")
                .push((domain.to_string(), ip.to_string()));
            (
                Some(blocked.clone()),
                Some(FilterFacts {
                    control_ok: Some(true),
                    stateful: Some(true),
                    first_blocked_ttl: Some(6),
                    checked_up_to: 6,
                    ..FilterFacts::default()
                }),
            )
        }));

        let report = net.run("example.com", &[fx::good()], false);

        assert_eq!(
            asked.lock().expect("замок").as_slice(),
            [("example.com".to_string(), V4.to_string())].as_slice()
        );
        assert!(report.route.as_ref().expect("трасса").reached);
        assert_eq!(
            report.quic.as_ref().expect("quic").code,
            QUIC_BLOCKED_BY_NAME
        );
        let lines = crate::domain_lookup_plans::build_path_lines(&report);
        assert_eq!(lines[0].text, "До сервера 7 узлов, ответили 7.");
        assert_eq!(lines[1].text, "QUIC (UDP 443): блокируется по имени сайта.");
        assert_eq!(
            lines[2].text,
            "Фильтр стоит между узлом 5 (10.0.0.5) и узлом 6 (10.0.0.6)."
        );
        assert_eq!(lines[2].tone, crate::domain_lookup_plans::TONE_ERROR);
        let table = crate::domain_lookup_plans::build_path_text(&report);
        let table: Vec<&str> = table.lines().collect();
        // Отметка стоит между пятым и шестым узлом.
        assert_eq!(
            table
                .iter()
                .position(|row| *row == "    ── здесь стоит фильтр ──"),
            Some(5)
        );
        assert!(table[4].starts_with(" 5  10.0.0.5"));
        assert!(table[6].starts_with(" 6  10.0.0.6"));
        let text = crate::domain_lookup_plans::build_text_report(&report);
        assert!(text.contains("=== Путь до сервера ==="));
        assert!(text.contains(crate::domain_lookup_plans::FILTER_MARK));
    }

    #[test]
    fn open_site_has_path_and_quic_but_no_filter_line() {
        let mut net = Net::new();
        net.route = Arc::new(Box::new(full_route));
        net.quic = Arc::new(Box::new(|_domain, _ip| {
            (
                Some(QuicVerdict {
                    code: QUIC_OK.to_string(),
                    text: "отвечает за 12 мс".to_string(),
                }),
                None,
            )
        }));
        let report = net.run("example.com", &[fx::good()], false);

        let lines = crate::domain_lookup_plans::build_path_lines(&report);
        assert_eq!(
            lines
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            vec![
                "До сервера 7 узлов, ответили 7.",
                "QUIC (UDP 443): отвечает за 12 мс."
            ]
        );
        assert_eq!(lines[1].tone, crate::domain_lookup_plans::TONE_SUCCESS);
        assert!(!crate::domain_lookup_plans::build_path_text(&report)
            .contains(crate::domain_lookup_plans::FILTER_MARK));
    }

    #[test]
    fn plain_address_gets_path_but_no_quic() {
        let asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut net = Net::new();
        net.route = Arc::new(Box::new(full_route));
        let asked_sink = Arc::clone(&asked);
        net.quic = Arc::new(Box::new(move |domain, _ip| {
            asked_sink.lock().expect("замок").push(domain.to_string());
            (None, None)
        }));
        let report = net.run("93.184.216.34", &[fx::good()], false);

        assert!(asked.lock().expect("замок").is_empty());
        assert!(report.route.as_ref().expect("трасса").reached);
        assert!(report.quic.is_none());
    }

    #[test]
    fn unreached_target_is_explained_without_alarm() {
        let mut net = Net::new();
        net.route = Arc::new(Box::new(|ip| RouteTrace {
            target: ip.to_string(),
            hops: vec![
                Hop {
                    ttl: 1,
                    kind: HOP_ROUTER,
                    address: "10.0.0.1".to_string(),
                    rtt_ms: Some(1.0),
                },
                Hop {
                    ttl: 2,
                    kind: HOP_SILENT,
                    address: String::new(),
                    rtt_ms: None,
                },
                Hop {
                    ttl: 3,
                    kind: HOP_ROUTER,
                    address: "10.0.0.3".to_string(),
                    rtt_ms: Some(2.0),
                },
            ],
            supported: true,
            ..RouteTrace::default()
        }));
        let report = net.run("example.com", &[fx::good()], false);

        let line = &crate::domain_lookup_plans::build_path_lines(&report)[0];
        assert!(
            line.text
                .contains("последний ответивший узел — 3-й (10.0.0.3)"),
            "{}",
            line.text
        );
        assert!(line.text.contains("это ещё не блокировка"));
        assert_eq!(line.tone, crate::domain_lookup_plans::TONE_MUTED);
        assert!(crate::domain_lookup_plans::build_path_text(&report).contains(" 2  не ответил"));
    }

    #[test]
    fn no_path_section_when_tracing_is_unavailable() {
        let net = Net::new();
        let report = net.run("example.com", &[fx::good()], false);

        assert!(crate::domain_lookup_plans::build_path_lines(&report).is_empty());
        assert_eq!(crate::domain_lookup_plans::build_path_text(&report), "");
        assert!(!crate::domain_lookup_plans::build_text_report(&report).contains("Путь до сервера"));
    }

    #[test]
    fn lowest_ttl_of_address_records_is_kept_and_shown() {
        let net = Net::new();
        let mut io = net.io();
        // И AAAA-записи нужен свой TTL 1332 — отдельная подмена.
        io.ask.server = Box::new(|_server, _name, rtype, _timeout, _attempts| {
            if rtype == TYPE_A {
                fx::answer_with_cname_and_ttls()
            } else {
                DnsQueryResult {
                    status: STATUS_OK.to_string(),
                    rcode: Some(0),
                    records: vec![primecore_dnswire::DnsRecord {
                        name: "x".to_string(),
                        rtype: TYPE_AAAA,
                        ttl: 1332,
                        value: "2606:2800:220:1::1".to_string(),
                    }],
                    elapsed_ms: Some(12.0),
                    ..DnsQueryResult::default()
                }
            }
        });
        let report = run_domain_lookup(
            "example.com",
            &[fx::good(), fx::dead()],
            false,
            None,
            None,
            &io,
        );

        let good = report
            .answers
            .iter()
            .find(|item| item.server.label == "Хороший")
            .expect("ответ");
        // Берётся наименьшее время адресных записей; у псевдонима оно своё и не в счёт.
        assert_eq!(good.ttl, Some(300));
        let row = crate::domain_lookup_plans::build_answer_rows(&report)
            .into_iter()
            .find(|row| row.server == "Хороший")
            .expect("строка");
        assert!(
            row.tooltip
                .contains("Ответ считается свежим ещё 300 с (TTL)"),
            "{}",
            row.tooltip
        );
        let text = crate::domain_lookup_plans::build_text_report(&report);
        assert!(text.contains("TTL 300 с"));
        assert!(text.contains("CNAME: alias.example"));
    }

    #[test]
    fn intercepted_dns_is_detected_by_canary() {
        let net = Net::new();
        let mut io = net.io();
        io.canary = Box::new(|_domain| true);
        let report = run_domain_lookup("example.com", &[fx::good()], false, None, None, &io);

        assert!(report.intercepted);
        assert_eq!(
            crate::domain_lookup_plans::build_dns_summary(&report).tone,
            crate::domain_lookup_plans::TONE_WARNING
        );
    }

    #[test]
    fn stop_before_start_returns_quickly() {
        let net = Net::new();
        let io = net.io();
        let report = run_domain_lookup(
            "example.com",
            &[fx::good()],
            true,
            None,
            Some(&|| true),
            &io,
        );

        assert!(report.finished);
        assert!(report.stopped);
        assert!(report.ping.is_none());
        assert!(crate::domain_lookup_plans::build_status(&report)
            .text
            .contains("Остановлено"));
    }

    #[test]
    fn invalid_input_does_not_touch_network() {
        let net = Net::new();
        let mut io = net.io();
        io.ask.server = Box::new(|_s, _n, _t, _to, _at| panic!("сеть не должна вызываться"));
        let report = run_domain_lookup("not a domain", &[], true, None, None, &io);

        assert_eq!(report.kind, KIND_INVALID);
        assert_eq!(
            crate::domain_lookup_plans::build_status(&report).tone,
            crate::domain_lookup_plans::TONE_ERROR
        );
    }

    // ------------------------------------------------------------------
    // Дорога программ (python ProgramRoadTests)
    // ------------------------------------------------------------------

    struct RoadCase {
        first: &'static str,
        only_v6: bool,
        tcp_v6: &'static str,
        tcp_v4: &'static str,
        site_level: &'static str,
        road: Option<ProgramRoad>,
        hosts_help: HostsHelp,
        hosts_road: Option<ProgramRoad>,
    }

    impl Default for RoadCase {
        fn default() -> Self {
            Self {
                first: V6,
                only_v6: false,
                tcp_v6: "timeout",
                tcp_v4: "ok",
                site_level: "ok",
                road: None,
                hosts_help: HostsHelp {
                    service: "YouTube".to_string(),
                    ..HostsHelp::default()
                },
                hosts_road: None,
            }
        }
    }

    fn road_run(case: RoadCase) -> DomainLookupReport {
        let mut net = Net::new();
        *net.site.lock().expect("замок") = Some(json!({
            "level": case.site_level,
            "headline": "www.youtube.com открывается"
        }));
        let mut infos = vec![
            ResolvedAddr {
                ipv6: true,
                address: V6.to_string(),
            },
            ResolvedAddr {
                ipv6: false,
                address: V4.to_string(),
            },
        ];
        if case.first == V4 {
            infos.reverse();
        }
        if case.only_v6 {
            infos.truncate(1);
        }
        net.resolve = Arc::new(infos);
        net.tcp = Arc::new((case.tcp_v6.to_string(), case.tcp_v4.to_string()));
        net.hosts_help = Arc::new(case.hosts_help);
        net.hosts_road = Arc::new(case.hosts_road.clone());
        // Проба дороги по адресу подменяется готовой записью (python patch _program_road),
        // без подмены дорога собирается из статусов соединения.
        let injected = case.road;
        let v6 = V6.to_string();
        let tcp_v6 = case.tcp_v6.to_string();
        net.road = Arc::new(Box::new(move |_domain, ip| {
            if let Some(road) = &injected {
                return road.clone();
            }
            ProgramRoad {
                ip: ip.to_string(),
                tcp: TcpReport {
                    ip: ip.to_string(),
                    port: 443,
                    status: if ip == v6 {
                        tcp_v6.clone()
                    } else {
                        "ok".to_string()
                    },
                    elapsed_ms: if ip == v6 && tcp_v6 != "ok" {
                        None
                    } else {
                        Some(5.0)
                    },
                    ..TcpReport::default()
                },
                ..ProgramRoad::default()
            }
        }));
        let io = net.io();
        run_domain_lookup(
            "www.youtube.com",
            &[fx::secure(), fx::good()],
            true,
            None,
            None,
            &io,
        )
    }

    #[test]
    fn only_ipv6_from_windows_and_it_is_dead_is_the_red_headline() {
        let report = road_run(RoadCase {
            only_v6: true,
            ..RoadCase::default()
        });

        // Проверен именно тот адрес, на который идут программы, а не только адрес IPv4.
        let road = report.road.as_ref().expect("дорога");
        assert_eq!(
            (road.ip.as_str(), road.tcp.status.as_str()),
            (V6, "timeout")
        );
        assert_eq!(report.ping6.as_ref().expect("пинг6").ip, V6);
        assert_eq!(road_trouble(&report), crate::domain_lookup::ROAD_DEAD);
        assert!(crate::domain_lookup_plans::road_is_fatal(&report));

        let status = crate::domain_lookup_plans::build_status(&report);
        assert_eq!(status.tone, crate::domain_lookup_plans::TONE_ERROR);
        assert!(
            status
                .text
                .contains("Windows отдаёт программам только адреса IPv6, а соединение по IPv6 не устанавливается"),
            "{}",
            status.text
        );
        let first = &crate::domain_lookup_plans::build_ping_lines(&report)[0];
        assert_eq!(first.tone, crate::domain_lookup_plans::TONE_ERROR);
        assert!(
            first.text.contains("Программам некуда идти"),
            "{}",
            first.text
        );
        assert!(first.text.contains(V6));
        // Вывод сделан по соединению, а не по пингу, — и это сказано.
        assert!(first.text.contains("пинг в этом выводе не участвует"));
        // И сказано, что делать: у YouTube есть тумблер, который пишет адреса IPv4.
        assert!(first
            .text
            .contains("Включите тумблер «YouTube» на странице «Редактор hosts»"));
        let entry = crate::domain_lookup_plans::build_history_entry(&report).expect("запись");
        assert_eq!(entry["level"], json!("fail"));
        assert!(entry["headline"]
            .as_str()
            .expect("текст")
            .contains("Windows отдаёт программам только адреса IPv6"));
        assert!(crate::domain_lookup_plans::build_text_report(&report)
            .contains("Программам некуда идти"));
    }

    #[test]
    fn dead_ipv6_next_to_a_working_ipv4_is_a_warning_not_a_broken_site() {
        let report = road_run(RoadCase::default());

        assert_eq!(road_trouble(&report), crate::domain_lookup::ROAD_DEAD);
        assert!(!crate::domain_lookup_plans::road_is_fatal(&report));
        assert_eq!(
            crate::domain_lookup_plans::build_status(&report).tone,
            crate::domain_lookup_plans::TONE_WARNING
        );
        let first = &crate::domain_lookup_plans::build_ping_lines(&report)[0];
        assert_eq!(first.tone, crate::domain_lookup_plans::TONE_WARNING);
        assert!(
            first.text.contains("Браузер обычно сам переходит на IPv4"),
            "{}",
            first.text
        );
        let entry = crate::domain_lookup_plans::build_history_entry(&report).expect("запись");
        assert_eq!(entry["level"], json!("warn"));
    }

    #[test]
    fn name_cut_on_the_ipv6_road_is_found_when_ipv4_opens() {
        let road = ProgramRoad {
            ip: V6.to_string(),
            tcp: TcpReport {
                ip: V6.to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(20.0),
                ..TcpReport::default()
            },
            lines: vec![(
                "Как Chrome".to_string(),
                "fail".to_string(),
                "на приветствие ответа нет".to_string(),
            )],
            opens: Some(false),
        };
        let report = road_run(RoadCase {
            tcp_v6: "ok",
            road: Some(road),
            ..RoadCase::default()
        });

        assert_eq!(road_trouble(&report), crate::domain_lookup::ROAD_BLOCKED);
        let lines: Vec<String> = crate::domain_lookup_plans::build_ping_lines(&report)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(
            lines[0].contains("по нему сайт не открывается"),
            "{}",
            lines[0]
        );
        assert!(lines
            .iter()
            .any(|text| text == "По IPv6 · Как Chrome: на приветствие ответа нет."));
        assert!(crate::domain_lookup_plans::build_status(&report)
            .text
            .contains("а по IPv6 сайт не открывается"));
    }

    #[test]
    fn no_alarm_without_a_working_ipv4_to_compare_with() {
        let cases: Vec<(&str, RoadCase)> = vec![
            (
                "Windows ставит первым IPv4",
                RoadCase {
                    first: V4,
                    ..RoadCase::default()
                },
            ),
            (
                "по IPv6 сайт открывается",
                RoadCase {
                    tcp_v6: "ok",
                    road: Some(ProgramRoad {
                        ip: V6.to_string(),
                        tcp: TcpReport {
                            ip: V6.to_string(),
                            port: 443,
                            status: "ok".to_string(),
                            elapsed_ms: Some(9.0),
                            ..TcpReport::default()
                        },
                        opens: Some(true),
                        ..ProgramRoad::default()
                    }),
                    ..RoadCase::default()
                },
            ),
            (
                "проба по IPv6 ничего не доказала",
                RoadCase {
                    tcp_v6: "ok",
                    road: Some(ProgramRoad {
                        ip: V6.to_string(),
                        tcp: TcpReport {
                            ip: V6.to_string(),
                            port: 443,
                            status: "ok".to_string(),
                            elapsed_ms: Some(9.0),
                            ..TcpReport::default()
                        },
                        opens: None,
                        ..ProgramRoad::default()
                    }),
                    ..RoadCase::default()
                },
            ),
            (
                "не отвечает и IPv4 — это не про IPv6",
                RoadCase {
                    tcp_v4: "timeout",
                    ..RoadCase::default()
                },
            ),
            (
                "сайт закрыт и по IPv4 — это обычная блокировка",
                RoadCase {
                    tcp_v6: "ok",
                    site_level: "fail",
                    road: Some(ProgramRoad {
                        ip: V6.to_string(),
                        tcp: TcpReport {
                            ip: V6.to_string(),
                            port: 443,
                            status: "ok".to_string(),
                            elapsed_ms: Some(9.0),
                            ..TcpReport::default()
                        },
                        opens: Some(false),
                        ..ProgramRoad::default()
                    }),
                    ..RoadCase::default()
                },
            ),
        ];
        for (name, case) in cases {
            let report = road_run(case);
            assert_eq!(road_trouble(&report), "", "{name}");
            assert_eq!(
                crate::domain_lookup_plans::road_problem(&report),
                "",
                "{name}"
            );
            assert!(
                !crate::domain_lookup_plans::build_ping_lines(&report)[0]
                    .text
                    .contains("идут не туда"),
                "{name}"
            );
        }
    }

    #[test]
    fn closed_site_that_opens_by_the_hosts_address_gets_the_advice_to_turn_the_tile_on() {
        let offered = vec!["64.233.162.198".to_string(), "74.125.205.198".to_string()];
        let opens = ProgramRoad {
            ip: "64.233.162.198".to_string(),
            tcp: TcpReport {
                ip: "64.233.162.198".to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(20.0),
                ..TcpReport::default()
            },
            opens: Some(true),
            ..ProgramRoad::default()
        };
        let mut net = Net::new();
        *net.site.lock().expect("замок") =
            Some(json!({"level": "fail", "headline": "www.youtube.com не открывается"}));
        net.resolve = Arc::new(vec![
            ResolvedAddr {
                ipv6: false,
                address: V4.to_string(),
            },
            ResolvedAddr {
                ipv6: true,
                address: V6.to_string(),
            },
        ]);
        net.tcp = Arc::new(("timeout".to_string(), "ok".to_string()));
        net.hosts_help = Arc::new(HostsHelp {
            service: "YouTube".to_string(),
            offered: offered.clone(),
            ..HostsHelp::default()
        });
        net.hosts_road = Arc::new(Some(opens));
        let io = net.io();
        let report = run_domain_lookup(
            "www.youtube.com",
            &[fx::secure(), fx::good()],
            true,
            None,
            None,
            &io,
        );

        // Проба идёт после остальных проверок и не выдаёт себя за «проверки не успели».
        assert!(!report.timed_out);
        let advice = crate::domain_lookup_plans::hosts_advice(&report);
        assert!(
            advice
                .contains("По адресу из «Редактора hosts» (64.233.162.198) этот сайт открывается"),
            "{}",
            advice
        );
        assert!(advice.contains("тумблер «YouTube»"));
        assert!(crate::domain_lookup_plans::build_status(&report)
            .text
            .contains(&advice));
        let entry = crate::domain_lookup_plans::build_history_entry(&report).expect("запись");
        let problems: Vec<String> = entry["problems"]
            .as_array()
            .expect("список")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        assert!(problems.contains(&advice));
        assert!(crate::domain_lookup_plans::build_text_report(&report)
            .contains(&format!("Что поможет: {advice}")));
        assert_eq!(crate::domain_lookup_plans::hosts_try_note(&report), "");
    }

    #[test]
    fn failed_hosts_try_is_shown_instead_of_silence() {
        let cut = ProgramRoad {
            ip: "64.233.162.198".to_string(),
            tcp: TcpReport {
                ip: "64.233.162.198".to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(20.0),
                ..TcpReport::default()
            },
            lines: vec![(
                "Как Chrome".to_string(),
                "fail".to_string(),
                "соединение сбрасывают".to_string(),
            )],
            opens: Some(false),
        };
        let mut net = Net::new();
        *net.site.lock().expect("замок") = Some(json!({"level": "fail", "headline": "закрыт"}));
        net.resolve = Arc::new(vec![
            ResolvedAddr {
                ipv6: false,
                address: V4.to_string(),
            },
            ResolvedAddr {
                ipv6: true,
                address: V6.to_string(),
            },
        ]);
        net.tcp = Arc::new(("timeout".to_string(), "ok".to_string()));
        net.hosts_help = Arc::new(HostsHelp {
            service: "YouTube".to_string(),
            offered: vec!["64.233.162.198".to_string()],
            ..HostsHelp::default()
        });
        net.hosts_road = Arc::new(Some(cut));
        let io = net.io();
        let report = run_domain_lookup(
            "www.youtube.com",
            &[fx::secure(), fx::good()],
            true,
            None,
            None,
            &io,
        );

        assert_eq!(crate::domain_lookup_plans::hosts_advice(&report), "");
        let note = crate::domain_lookup_plans::hosts_try_note(&report);
        assert!(
            note.contains("Адрес из «Редактора hosts» (64.233.162.198) тоже проверен — приветствие с именем сайта тоже оборвали"),
            "{}",
            note
        );
        assert!(note.contains("тумблер «YouTube» в этот раз не помог бы"));
        let text = crate::domain_lookup_plans::build_text_report(&report);
        assert!(text.contains(&note));
        assert!(text.contains("    Как Chrome: соединение сбрасывают"));
    }

    #[test]
    fn hosts_addresses_are_tried_only_for_a_closed_site_with_the_tile_off() {
        let offered = vec!["64.233.162.198".to_string()];
        let cases: Vec<(&str, &str, HostsHelp)> = vec![
            (
                "сайт открывается — пробовать незачем",
                "ok",
                HostsHelp {
                    service: "YouTube".to_string(),
                    offered: offered.clone(),
                    ..HostsHelp::default()
                },
            ),
            ("сервиса для имени нет", "fail", HostsHelp::default()),
            (
                "тумблер уже включён",
                "fail",
                HostsHelp {
                    service: "YouTube".to_string(),
                    offered: offered.clone(),
                    rows: offered.clone(),
                    managed: offered.clone(),
                },
            ),
        ];
        for (name, site_level, help) in cases {
            let mut net = Net::new();
            *net.site.lock().expect("замок") =
                Some(json!({"level": site_level, "headline": "закрыт"}));
            net.resolve = Arc::new(vec![
                ResolvedAddr {
                    ipv6: false,
                    address: V4.to_string(),
                },
                ResolvedAddr {
                    ipv6: true,
                    address: V6.to_string(),
                },
            ]);
            net.tcp = Arc::new(("timeout".to_string(), "ok".to_string()));
            net.hosts_help = Arc::new(help);
            let io = net.io();
            let report = run_domain_lookup(
                "www.youtube.com",
                &[fx::secure(), fx::good()],
                true,
                None,
                None,
                &io,
            );
            assert!(net.road_calls.lock().expect("замок").is_empty(), "{name}");
            assert!(report.hosts_road.is_none(), "{name}");
            assert_eq!(
                crate::domain_lookup_plans::hosts_try_note(&report),
                "",
                "{name}"
            );
        }
    }

    // Маленькие проверки классификации уровней (используются в тестах выше).
    #[test]
    fn classify_levels_match_python() {
        assert_eq!(classify_ip(V4).0, LEVEL_OK);
        assert_eq!(classify_ip("195.82.146.214").0, LEVEL_FAIL);
        assert_eq!(classify_ip("127.0.0.1").0, LEVEL_FAIL);
        assert_eq!(classify_ip("8.8.8.8").0, LEVEL_OK);
        assert_eq!(STATUS_NXDOMAIN, "nxdomain");
        assert_eq!(STATUS_TIMEOUT, "timeout");
        assert_eq!(LEVEL_UNKNOWN, "unknown");
        let _ = ResolveFailure::Timeout;
    }
}
