//! Дымовой тест движка: весь прогон BlockCheck и проверка DNS подмены на
//! подставном транспорте — без сети, без взаимных блокировок.
//!
//! Замыкания возвращают готовые факты (как настоящий транспорт), поэтому тест
//! проверяет связку машины прогона (`Run`), порядка разделов и словарь отчёта.

use primecore_diagnostics::block_cause::{CauseFacts, HELLO_OK};
use primecore_diagnostics::engine::{self, EngineIo, SystemIo};
use primecore_diagnostics::name_speed::NameRun;
use primecore_diagnostics::probe_result::ProbeResult;
use primecore_diagnostics::quic_probe::QuicFacts;
use primecore_diagnostics::run_context::TaskError;
use primecore_diagnostics::services::{build_services, SCOPE_MAIN};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn ok_result(ip: &str) -> ProbeResult {
    ProbeResult {
        ip: ip.to_string(),
        kind: primecore_diagnostics::probe_result::KIND_OK.to_string(),
        body: b"hello".to_vec(),
        body_size: 100_000,
        ..Default::default()
    }
}

fn connect_result(ip: &str) -> ProbeResult {
    ProbeResult {
        ip: ip.to_string(),
        kind: primecore_diagnostics::probe_result::KIND_CONNECT.to_string(),
        ..Default::default()
    }
}

fn answered(ips: Vec<String>) -> primecore_dnswire::DnsQueryResult {
    use primecore_dnswire::{DnsRecord, RCODE_OK, TYPE_A};
    primecore_dnswire::DnsQueryResult {
        status: RCODE_OK.to_string(),
        rcode: Some(RCODE_OK),
        records: ips
            .iter()
            .map(|ip| DnsRecord {
                name: String::new(),
                rtype: TYPE_A,
                ttl: 60,
                value: ip.clone(),
            })
            .collect(),
        ..Default::default()
    }
}

#[allow(clippy::type_complexity)]
fn mock_io() -> EngineIo {
    let dns_ip = "203.0.113.10";
    let reference_ip = "203.0.113.10"; // совпадает с DNS — подмены нет
    EngineIo {
        system: SystemIo {
            environment_lines: Arc::new(|| vec!["🌐 DNS-серверы системы: 8.8.8.8".to_string()]),
            zapret_status: Arc::new(|| (Some(false), "❌ Zapret не запущен".to_string())),
            running_bypass_tools: Arc::new(Vec::new),
            routed_adapters: Arc::new(|| None),
            tools_in_path: Arc::new(|_tools, _routed| Vec::new()),
            tools_line: Arc::new(|_tools, _path| String::new()),
            clock_label: Arc::new(|| "01.01.2026 12:00:00".to_string()),
        },
        system_dns: Arc::new({
            let ip = dns_ip.to_string();
            move |_host| primecore_diagnostics::windows_dns_query::DnsAnswer {
                ips: vec![ip.clone()],
                ..Default::default()
            }
        }),
        hosts: Arc::new(|_host| Vec::new()),
        doh_query: Arc::new(Mutex::new({
            let ip = reference_ip.to_string();
            move |_resolver: &primecore_diagnostics::dns_reference::ReferenceResolver| -> primecore_dnswire::DnsQueryResult { answered(vec![ip.clone()]) }
        })),
        doh_ask_query: Arc::new(Mutex::new({
            let ip = reference_ip.to_string();
            move |_resolver: &primecore_diagnostics::dns_reference::ReferenceResolver,
                  _name: &str,
                  _rtype: u16|
                  -> primecore_dnswire::DnsQueryResult { answered(vec![ip.clone()]) }
        })),
        doh_aaaa: Arc::new({
            let ip = reference_ip.to_string();
            move |_host| vec![ip.clone()]
        }),
        chrome_get: Arc::new(Mutex::new(
            move |host: &str,
                  ip: &str,
                  _path: &str,
                  _t: f64,
                  _l: usize,
                  _rt: f64,
                  _done: Option<&dyn Fn(&[u8]) -> bool>,
                  _decode: bool|
                  -> ProbeResult {
                let _ = host;
                if ip == dns_ip {
                    ok_result(ip)
                } else {
                    connect_result(ip)
                }
            },
        )),
        ping: Arc::new(|_ip| Some(true)),
        quic_collect: Arc::new(|_host, _ip, _cancel| {
            Ok(QuicFacts {
                cancelled: false,
                ..Default::default()
            })
        }),
        protocols_collect: Arc::new(|_host, _ip, _cancel| {
            Ok(primecore_diagnostics::protocol_probe::ProtocolFacts {
                ..Default::default()
            })
        }),
        cause_collect: Arc::new(|_host, _result, _cancel| {
            Ok(CauseFacts {
                ..Default::default()
            })
        }),
        volume_collect: Arc::new(|_host, _ip, _path, _cancel| {
            Ok(primecore_diagnostics::volume_probe::VolumeFacts::default())
        }),
        cert_collect: Arc::new(|_host, _ip, _cancel| {
            Err(TaskError::Failed("нет сертификата в дыму".to_string()))
        }),
        googlevideo_extract: Arc::new(|_text| Vec::new()),
        freeze_targets: Arc::new(Vec::new),
        voice_collect: Arc::new(|_run| Ok(Vec::new())),
        burst_collect: Arc::new(|_run| Err(TaskError::Failed("дымо-сбой серии".to_string()))),
        freeze_check: Arc::new(|_run, _every, _on_server| Ok(Vec::new())),
        telegram_collect: Arc::new(|_run| Ok(Vec::new())),
        ipv6_check: Arc::new(|_run| {
            Ok(primecore_diagnostics::ipv6_check::Ipv6Verdict {
                code: primecore_diagnostics::ipv6_check::IPV6_UNKNOWN.to_string(),
                text: "IPv6 не проверен".to_string(),
            })
        }),
        system_check: Arc::new(|_run, _services, _zapret, _intercept| Ok(Vec::new())),
        subnets_check: Arc::new(|_run| Ok(None)),
        network_check: Arc::new(
            |_run, _tools| serde_json::json!({"external_ip": "198.51.100.2", "asn": "AS12345", "lines": []}),
        ),
        registry_start: Arc::new(|| {
            Arc::new(
                |_seconds: f64, _cancel: &primecore_socketcancel::SocketCancel| {
                    primecore_diagnostics::registry::Index::default()
                },
            )
        }),
        outside_answers: Arc::new(|_hosts| BTreeMap::new()),
        habit_send: Arc::new(|_ip, _parts, _pause| HELLO_OK.to_string()),
        habit_rests: Arc::new(|_seconds| {}),
        trace_route: Arc::new(|_ip| None),
        path_pair: Arc::new(|_method, _ip, _host, _name, _ttl| None),
        path_connects: Arc::new(|_ip, _ttl| false),
        dns_place_ask: Arc::new(|_ttl| None),
        speed_download: Arc::new(|_server| None),
        name_speed_download: Arc::new(|_ip, name, _cancel| {
            NameRun::run(name, primecore_diagnostics::name_speed::FINE)
        }),
        crowd_hello: Arc::new(|_host, _ip| String::new()),
        crowd_together: Arc::new(Vec::new),
    }
}

#[test]
fn run_dns_check_smoke() {
    let io = mock_io();
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let report = engine::run_dns_check(
        None,
        &mut move |line: &str| sink.lock().expect("журнал").push(line.to_string()),
        &io,
    );
    assert_eq!(report["summary"]["dns_poisoning_detected"], false);
    assert!(report["domains"].is_object());
    let domains = report["domains"].as_object().expect("домены");
    assert!(
        !domains.is_empty(),
        "основной список сервисов даёт хоть один домен"
    );
    let journal = lines.lock().expect("журнал");
    assert!(journal
        .iter()
        .any(|line| line.contains("ПРОВЕРКА DNS ПОДМЕНЫ")));
    assert!(journal
        .iter()
        .any(|line| line.contains("DNS работает честно")));
}

#[test]
fn run_blockcheck_main_scope_smoke() {
    let io = mock_io();
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let progress_seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let progress_sink = Arc::clone(&progress_seen);
    let report = engine::run_blockcheck(
        SCOPE_MAIN,
        &[],
        None,
        &mut move |line: &str| sink.lock().expect("журнал").push(line.to_string()),
        Some(Arc::new(move |name: &str, _done: u32, _total: u32| {
            progress_sink.lock().expect("ход").push(name.to_string());
        })),
        None,
        None,
        None,
        false,
        &io,
    );
    assert_eq!(report["partial"], false);
    assert!(report["services"].as_array().expect("сервисы").len() >= 2);
    assert!(report.get("reference").is_some());
    assert!(report["problems"].is_array());
    let journal = lines.lock().expect("журнал");
    assert!(journal
        .iter()
        .any(|line| line.contains("BlockCheck: Discord и YouTube")));
    assert!(journal.iter().any(|line| line.contains("Проверка заняла")));
    // Шаг «sites» дойдёт до экрана: значит, пробы реально выполнялись и одна из
    // задач завершилась.
    let progress = progress_seen.lock().expect("ход");
    assert!(
        progress.iter().any(|name| name == "sites"),
        "шаги: {progress:?}"
    );
}

#[test]
fn smoke_services_build() {
    let services = build_services(SCOPE_MAIN, &[]);
    assert!(!services.is_empty());
}
