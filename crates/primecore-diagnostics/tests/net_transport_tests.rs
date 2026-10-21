//! Золотые и живые тесты транспорта: STUN-кодек против python, строки шапки
//! против python, TCP/UDP-пробы против локальных подставных серверов.

use primecore_diagnostics::net_transport::{
    build_stun_request, check_bursts, check_telegram, check_voice, collect_groups,
    parse_stun_response, send_burst, tcp_connect, telegram_connect, test_stun, TcpOutcome,
};
use primecore_diagnostics::run_context::{Run, TaskError};
use primecore_diagnostics::voice_check::{describe, parse_target, StunOutcome};
use primecore_socketcancel::SocketCancel;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
struct Golden {
    #[allow(dead_code)]
    stun_request: StunRequest,
    stun_parse: Vec<StunCase>,
    environment_lines: Vec<EnvCase>,
    tools_line: Vec<ToolCase>,
    describe: Vec<DescribeCase>,
    parse_target: Vec<TargetCase>,
}

#[derive(Deserialize)]
struct StunRequest {
    len: usize,
    #[serde(rename = "type")]
    kind: u16,
    cookie: bool,
    txid_len: usize,
}

#[derive(Deserialize)]
struct StunCase {
    name: String,
    hex: String,
    expected: Option<StunExpected>,
}

#[derive(Deserialize, Debug)]
struct StunExpected {
    ip: String,
    port: u16,
    family: String,
}

#[derive(Deserialize)]
struct EnvCase {
    name: String,
    servers: Vec<String>,
    providers: BTreeMap<String, Vec<String>>,
    expected: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ToolCase {
    name: String,
    kinds: BTreeMap<String, String>,
    other: Vec<String>,
    #[serde(rename = "in_path")]
    in_path: Vec<String>,
    expected: String,
}

#[derive(Deserialize)]
struct DescribeCase {
    name: String,
    status: String,
    code: String,
    detail: String,
    expected: Vec<bool_or_string::Value>,
}

mod bool_or_string {
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    #[serde(untagged)]
    pub enum Value {
        Flag(bool),
        Text(String),
    }
}

use bool_or_string::Value as RowValue;

#[derive(Deserialize)]
struct TargetCase {
    value: String,
    expected: Vec<String>,
}

fn golden() -> Golden {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/transport_golden.json"),
    )
    .expect("fixture");
    serde_json::from_str(&text).expect("fixture json")
}

#[test]
fn stun_request_shape() {
    let golden = golden().stun_request;
    let request = build_stun_request();
    assert_eq!(request.len(), golden.len);
    assert_eq!(u16::from_be_bytes([request[0], request[1]]), golden.kind);
    assert!(golden.cookie);
    assert_eq!(u16::from_be_bytes([request[0], request[1]]), 0x0001);
    assert_eq!(&request[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    // Номер транзакции случайный, но всегда 12 байт.
    assert_eq!(golden.txid_len, 12);
    let second = build_stun_request();
    assert_eq!(second.len(), 20);
    assert_eq!(&second[4..8], &[0x21, 0x12, 0xA4, 0x42]);
}

#[test]
#[allow(clippy::type_complexity)]
fn stun_parse_matches_python() {
    let data = golden();
    for case in &data.stun_parse {
        let bytes = hex_to_bytes(&case.hex);
        let parsed = parse_stun_response(&bytes);
        match (&case.expected, parsed) {
            (None, None) => {}
            (Some(expected), Some(actual)) => {
                assert_eq!(actual.ip, expected.ip, "сценарий {}", case.name);
                assert_eq!(actual.port, expected.port, "сценарий {}", case.name);
                assert_eq!(actual.family, expected.family, "сценарий {}", case.name);
            }
            (expected, actual) => panic!(
                "сценарий {}: ожидалось {expected:?}, получено {actual:?}",
                case.name
            ),
        }
    }
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn environment_lines_match_python() {
    let data = golden();
    for case in &data.environment_lines {
        let Some(expected) = &case.expected else {
            continue;
        };
        let providers = Arc::new(case.providers.clone());
        let provider_of = move |ip: &str| -> (String, String, String) {
            let entry = providers.get(ip).cloned().unwrap_or_default();
            let mut items = entry.into_iter();
            (
                items.next().unwrap_or_default(),
                items.next().unwrap_or_default(),
                items.next().unwrap_or_default(),
            )
        };
        let lines = primecore_diagnostics::sections::environment_lines(&case.servers, &provider_of);
        assert_eq!(lines, *expected, "сценарий {}", case.name);
    }
}

#[test]
fn tools_line_matches_python() {
    let data = golden();
    for case in &data.tools_line {
        let kinds = Arc::new(case.kinds.clone());
        let kind_of = move |name: &str| -> String { kinds.get(name).cloned().unwrap_or_default() };
        let line =
            primecore_diagnostics::sections::tools_line(&case.other, &case.in_path, &kind_of);
        assert_eq!(line, case.expected, "сценарий {}", case.name);
    }
}

#[test]
fn describe_matches_python() {
    let data = golden();
    for case in &data.describe {
        let outcome = StunOutcome {
            status: case.status.clone(),
            error_code: case.code.clone(),
            detail: case.detail.clone(),
        };
        let (answered, text, decided) = describe(&outcome);
        let got = vec![
            RowValue::Flag(answered),
            RowValue::Text(text),
            RowValue::Flag(decided),
        ];
        assert_eq!(got, case.expected, "сценарий {}", case.name);
    }
}

#[test]
fn parse_target_matches_python() {
    let data = golden();
    for case in &data.parse_target {
        let (host, port) = parse_target(&case.value);
        assert_eq!(host, case.expected[0], "сценарий {}", case.value);
        assert_eq!(
            port.to_string(),
            case.expected[1],
            "сценарий {}",
            case.value
        );
    }
}

// ---------------------------------------------------------------------------
// Живые пробы на локальных сокетах
// ---------------------------------------------------------------------------

/// STUN-ответ с XOR-MAPPED-ADDRESS на IPv4: тот же алгоритм, что в python.
fn stun_success(txid: [u8; 12], ip: [u8; 4], port: u16) -> Vec<u8> {
    let cookie: u32 = 0x2112A442;
    let xored_port = port ^ ((cookie >> 16) as u16);
    let xored_ip = u32::from_be_bytes(ip) ^ cookie;
    let mut body = Vec::new();
    body.extend_from_slice(&0x0020u16.to_be_bytes());
    body.extend_from_slice(&8u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x01]);
    body.extend_from_slice(&xored_port.to_be_bytes());
    body.extend_from_slice(&xored_ip.to_be_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&cookie.to_be_bytes());
    out.extend_from_slice(&txid);
    out.extend_from_slice(&body);
    out
}

#[test]
fn tcp_outcomes_on_localhost() {
    let cancel = SocketCancel::new();
    // Ответивший порт: соединение установилось.
    let listener = TcpListener::bind("127.0.0.1:0").expect("слушать");
    let address = listener.local_addr().expect("адрес");
    let accept = std::thread::spawn(move || {
        let _stream = listener.accept();
    });
    let outcome = tcp_connect(address, 2.0, &cancel);
    assert!(matches!(outcome, TcpOutcome::Connected(_)), "{outcome:?}");
    accept.join().expect("поток");

    // Отказавший порт: адрес сам ответил отказом (RST).
    let free = free_port();
    let outcome = tcp_connect(
        SocketAddr::new("127.0.0.1".parse().unwrap(), free),
        2.0,
        &cancel,
    );
    assert_eq!(outcome, TcpOutcome::Refused, "{outcome:?}");

    // python-контракты по одному исходу:
    assert_eq!(
        telegram_connect("127.0.0.1", free, &cancel),
        (Some(false), None)
    );
    assert!(primecore_diagnostics::net_transport::subnet_reachable(
        "127.0.0.1",
        &cancel
    ));
    let facts = primecore_diagnostics::net_transport::self_check_now(&cancel);
    assert_eq!(facts.accepted, Some(false), "отказ — норма, тревоги нет");
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("слушать");
    listener.local_addr().expect("адрес").port()
}

#[test]
fn tcp_cancelled_before_start() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    let outcome = tcp_connect(
        SocketAddr::new("127.0.0.1".parse().unwrap(), free_port()),
        2.0,
        &cancel,
    );
    assert_eq!(outcome, TcpOutcome::Cancelled);
    assert_eq!(telegram_connect("127.0.0.1", 443, &cancel), (None, None));
    let facts = primecore_diagnostics::net_transport::self_check_now(&cancel);
    assert_eq!(facts.accepted, None, "сняли — ничего не утверждаем");
}

/// Эхо-STUN сервер: отвечает на каждый запрос ответом привязки.
fn spawn_stun_responder(port: u16, answer_every: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("слушать UDP");
    let address = socket.local_addr().expect("адрес");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 256];
        loop {
            let Ok((size, from)) = socket.recv_from(&mut buffer) else {
                return;
            };
            if size < 20 {
                continue;
            }
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if answer_every > 0 && count > answer_every {
                continue; // после порога молчим — имитация заморозки
            }
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&buffer[8..20]);
            let reply = stun_success(txid, [203, 0, 113, 7], 4242);
            let _ = socket.send_to(&reply, from);
        }
    });
    (address, seen)
}

#[test]
fn test_stun_answers_on_localhost() {
    let cancel = SocketCancel::new();
    let (address, seen) = spawn_stun_responder(0, 0);
    let result = test_stun(&address.ip().to_string(), address.port(), 3.0, 2, &cancel);
    assert_eq!(result.code, "OK", "{result:?}");
    assert_eq!(result.resolved.as_ref().expect("адрес").ip, "203.0.113.7");
    assert_eq!(result.resolved.as_ref().expect("адрес").port, 4242);
    assert!(result.ms >= 0.0);
    assert!(seen.load(Ordering::SeqCst) >= 1);
}

#[test]
fn test_stun_timeout_when_silent() {
    // Порт, где никто не слушает UDP: ответа не будет — TIMEOUT.
    let cancel = SocketCancel::new();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("занять порт");
    let address = udp.local_addr().expect("адрес");
    drop(udp);
    let result = test_stun(&address.ip().to_string(), address.port(), 1.0, 1, &cancel);
    assert_eq!(result.code, "TIMEOUT", "{result:?}");
}

#[test]
fn test_stun_cancelled() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    let result = test_stun("127.0.0.1", 1, 1.0, 1, &cancel);
    assert_eq!(result.code, "CANCELLED");
}

#[test]
fn send_burst_counts_answers() {
    let cancel = SocketCancel::new();
    let (address, _seen) = spawn_stun_responder(0, 0);
    let answered = send_burst(&address.ip().to_string(), address.port(), &cancel).expect("серия");
    assert_eq!(answered.len(), 30);
    assert!(answered.iter().all(|flag| *flag), "{answered:?}");
}

#[test]
fn send_burst_detects_freeze() {
    let cancel = SocketCancel::new();
    // Сервер отвечает на первые 15 запросов, дальше молчит: обрыв.
    let (address, _seen) = spawn_stun_responder(0, 15);
    let answered = send_burst(&address.ip().to_string(), address.port(), &cancel).expect("серия");
    let answered_count = answered.iter().filter(|flag| **flag).count();
    assert!(
        (10..=18).contains(&answered_count),
        "ожидали обрыв около 15, серия: {answered:?}"
    );
}

#[test]
fn send_burst_cancelled() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    let (address, _seen) = spawn_stun_responder(0, 0);
    assert!(send_burst(&address.ip().to_string(), address.port(), &cancel).is_none());
}

#[test]
#[allow(clippy::type_complexity)]
fn check_voice_reports_servers() {
    let run = Run::new(None, 4, None);
    let cancel = Arc::clone(&run.probe_cancel);
    // Подставная проба: Telegram-серверы молчат, общие отвечают.
    let probe: Arc<dyn Fn(&str, u16, &SocketCancel) -> StunOutcome + Send + Sync> =
        Arc::new(|host, _port, _cancel| {
            if host.contains("telegram") {
                StunOutcome {
                    status: String::new(),
                    error_code: "TIMEOUT".to_string(),
                    detail: "UDP timeout".to_string(),
                }
            } else {
                StunOutcome {
                    status: "OK".to_string(),
                    error_code: String::new(),
                    detail: String::new(),
                }
            }
        });
    let servers = check_voice(&run, &cancel, probe);
    assert_eq!(
        servers.len(),
        primecore_diagnostics::voice_check::STUN_TARGETS.len()
    );
    let report = primecore_diagnostics::voice_check::summarize_voice(&servers);
    // Не ответили только Telegram-серверы: предупреждение про звонки Telegram.
    assert_eq!(report.level, primecore_diagnostics::verdict::Level::Warn);
    assert!(report.headline.contains("Telegram"));
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn check_bursts_collects_series() {
    let run = Run::new(None, 4, None);
    let cancel = Arc::clone(&run.probe_cancel);
    let (address, _seen) = spawn_stun_responder(0, 0);
    let host = address.ip().to_string();
    let port = address.port();
    let send: Arc<dyn Fn(&str, u16, &SocketCancel) -> Option<Vec<bool>> + Send + Sync> = Arc::new(
        move |called_host: &str, called_port: u16, cancel: &SocketCancel| {
            // Оба «сервера» — одна и та же локальная подставка.
            let _ = called_host;
            let _ = called_port;
            send_burst(&host, port, cancel)
        },
    );
    let facts = check_bursts(&run, &cancel, send);
    assert_eq!(facts.len(), 2);
    for (_name, series) in &facts {
        assert_eq!(series.len(), 2);
        for run_series in series {
            let answers = run_series.as_ref().expect("серия");
            assert!(answers.iter().all(|flag| *flag));
        }
    }
    let verdict = primecore_diagnostics::udp_burst::judge(&facts).expect("вердикт");
    assert_eq!(verdict.code, primecore_diagnostics::udp_burst::BURST_OK);
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn check_telegram_retries_once() {
    let run = Run::new(None, 4, None);
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let pauses = Arc::new(AtomicUsize::new(0));
    let connect_calls = Arc::clone(&calls);
    let connect: Arc<dyn Fn(&str, u16) -> (Option<bool>, Option<f64>) + Send + Sync> =
        Arc::new(move |address, _port| {
            let mut seen = connect_calls.lock().expect("журнал соединений");
            let count = seen.iter().filter(|known| known == &address).count();
            seen.push(address.to_string());
            drop(seen);
            if count == 0 {
                (Some(false), None) // первая попытка — отказ
            } else {
                (Some(true), Some(3.5))
            }
        });
    let pause_calls = Arc::clone(&pauses);
    let pause: Arc<dyn Fn(f64) + Send + Sync> = Arc::new(move |_seconds| {
        pause_calls.fetch_add(1, Ordering::SeqCst);
    });
    let results = check_telegram(&run, Arc::clone(&connect), Arc::clone(&pause));
    assert_eq!(
        results.len(),
        primecore_diagnostics::telegram_check::DATA_CENTERS.len()
    );
    for result in &results {
        assert_eq!(result.attempts, 2, "{result:?}");
        assert_eq!(result.connected, Some(true));
        assert_eq!(result.ms, Some(3.5));
    }
    assert_eq!(pauses.load(Ordering::SeqCst), results.len());
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn check_telegram_connected_first_try() {
    let run = Run::new(None, 4, None);
    let connect: Arc<dyn Fn(&str, u16) -> (Option<bool>, Option<f64>) + Send + Sync> =
        Arc::new(|_address, _port| (Some(true), Some(0.4)));
    let pause: Arc<dyn Fn(f64) + Send + Sync> = Arc::new(|_seconds| panic!("пауза не нужна"));
    let results = check_telegram(&run, connect, pause);
    assert!(results.iter().all(|result| result.attempts == 1));
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn collect_groups_retries_closed() {
    let run = Run::new(None, 8, None);
    let cancel = Arc::clone(&run.probe_cancel);
    let attempts = Arc::new(AtomicUsize::new(0));
    let connect_attempts = Arc::clone(&attempts);
    let connect: Arc<dyn Fn(&str, &SocketCancel) -> bool + Send + Sync> =
        Arc::new(move |_ip, _cancel| {
            let count = connect_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            count > 35 // первый залп всё закрыл, после паузы всё открылось
        });
    let facts = collect_groups(&run, &cancel, connect);
    assert!(!facts.cancelled);
    assert!(facts
        .groups
        .iter()
        .all(|(_label, _region, answered)| *answered));
    assert!(
        attempts.load(Ordering::SeqCst)
            > primecore_diagnostics::subnet_catalog::SUBNET_GROUPS.len()
    );
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn collect_groups_cancelled_skips_retry() {
    let run = Run::new(None, 8, None);
    let cancel = Arc::clone(&run.probe_cancel);
    cancel.cancel();
    let connect: Arc<dyn Fn(&str, &SocketCancel) -> bool + Send + Sync> =
        Arc::new(|_ip, _cancel| false);
    let facts = collect_groups(&run, &cancel, connect);
    assert!(facts.cancelled);
    // Сняли: ничего не утверждаем.
    assert!(primecore_diagnostics::subnet_whitelist::judge(&facts).is_none());
    run.close();
}

#[test]
fn collect_facts_without_windows_reads_nothing() {
    use primecore_diagnostics::net_transport::{collect_facts, NullSystemReader};
    let facts = collect_facts(&NullSystemReader, &["a.example".to_string()], Some(2.5));
    assert_eq!(facts.clock_skew_s, Some(2.5));
    assert_eq!(facts.is_admin, None);
    assert_eq!(facts.windows_build, None);
    assert_eq!(facts.hosts_overrides, None);
}

#[test]
#[allow(clippy::type_complexity)]
fn transports_wire_into_engine_shapes() {
    // Готовые транспорты подходят под поля EngineIo и не паникуют на пустом прогоне.
    use primecore_diagnostics::engine::{
        BurstCollect, CauseCollect, CertCollect, ProtocolsCollect, SubnetsCheck, SystemCheck,
        TelegramCollect, VoiceCollect, VolumeCollect,
    };
    use primecore_diagnostics::net_transport::NullSystemReader;
    use primecore_diagnostics::net_transport::{
        burst_transport, cause_transport, cert_transport, protocols_transport, subnets_transport,
        system_transport, telegram_transport, voice_transport, volume_transport,
    };
    let run = Run::new(None, 4, None);
    // Только совместимость типов с полями EngineIo: наружу тесты не стучатся.
    let _voice: VoiceCollect = voice_transport();
    let _telegram: TelegramCollect = telegram_transport();
    let _burst: BurstCollect = burst_transport();
    let _subnets: SubnetsCheck = subnets_transport();
    let _system: SystemCheck = system_transport(Arc::new(NullSystemReader), None);
    let _cause: CauseCollect = cause_transport();
    let _protocols: ProtocolsCollect = protocols_transport();
    let _volume: VolumeCollect = volume_transport();
    let _cert: CertCollect = cert_transport();
    run.close();
}

#[test]
#[allow(clippy::type_complexity)]
fn stopped_run_stops_transports() {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let run = Run::new(Some(Arc::new(move || flag.load(Ordering::SeqCst))), 4, None);
    let cancel = Arc::clone(&run.probe_cancel);
    stop.store(true, Ordering::SeqCst);
    // Отмена сразу: серии и пробы возвращают «сняли», а не висят.
    let (address, _seen) = spawn_stun_responder(0, 0);
    assert!(send_burst(&address.ip().to_string(), address.port(), &cancel).is_none());
    run.close();
    let _ = TaskError::Stopped; // тип существует
}
