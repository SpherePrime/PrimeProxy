//! Сетевой транспорт проб, которым не нужен TLS: TCP-соединения, STUN (UDP)
//! и серия UDP-пакетов.
//!
//! Приватность: пробы шлют только сами запросы — пустое TCP-соединение
//! (SYN без данных), STUN-запрос из 20 случайных байт (RFC 5389, никаких
//! сведений о пользователе) и DNS-вопрос об имени проверяемого сервера.
//! Ответы читаются и выбрасываются; ничего не сохраняется и не отсылается
//! на серверы проекта. Единственная необязательная передача со данными —
//! «Сверить с сервером в Нидерландах» (`sections::ask_outside`): она включается
//! галочкой человека и передаёт только имена неоткрывшихся сайтов.
//!
//! Отличие от python в отмене: блокирующий сокет std нельзя прервать закрытием
//! из другого потока, поэтому «Стоп» проверяется между короткими отрезками
//! ожидания (как в primecore-dnswire) и до/после соединения.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;

use crate::engine::{BurstCollect, SubnetsCheck, SystemCheck, TelegramCollect, VoiceCollect};

/// python `check_voice`-проба: (хост, порт, «Стоп») → снимок результата STUN.
pub type StunProbe =
    Arc<dyn Fn(&str, u16, &SocketCancel) -> crate::voice_check::StunOutcome + Send + Sync>;
/// python `send`-проба серии: (хост, порт, «Стоп») → ответы по номерам пакетов.
pub type BurstSend = Arc<dyn Fn(&str, u16, &SocketCancel) -> Option<Vec<bool>> + Send + Sync>;
/// python `connect`-проба дата-центра: (адрес, порт) → (соединился, мс).
pub type DcConnect = Arc<dyn Fn(&str, u16) -> (Option<bool>, Option<f64>) + Send + Sync>;
/// python `pause(seconds)` — пауза между попытками.
pub type DcPause = Arc<dyn Fn(f64) + Send + Sync>;
/// python `connect(ip, cancel)` — дошёл ли пакет до адреса.
pub type SubnetConnect = Arc<dyn Fn(&str, &SocketCancel) -> bool + Send + Sync>;
use crate::run_context::{Handle, Run, TaskError};

/// python `socket.settimeout` при чтении разбит на отрезки: как часто между
/// ними проверяется «Стоп».
const POLL_SLICE_S: f64 = 0.2;

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// Исход TCP-соединения (python различает их по классам `OSError`).
#[derive(Debug, Clone, PartialEq)]
pub enum TcpOutcome {
    /// Соединение установилось; сколько миллисекунд оно шло.
    Connected(f64),
    /// Адрес сам отказал (RST): пакет дошёл, соединения нет.
    Refused,
    /// Ответа нет вовсе: тишина (python `timeout`).
    TimedOut,
    /// До адреса нет дороги (нет сети, нет маршрута).
    Unreachable,
    /// Проверку сняли.
    Cancelled,
    /// Прочая ошибка системы.
    Error(String),
}

/// python `sock.connect((address, port))` с общим сроком и «Стопом».
///
/// Отмена видна до начала и после соединения: у python «Стоп» закрывает сокет
/// и connect падает — итог тот же «сняли».
pub fn tcp_connect(target: SocketAddr, timeout: f64, cancel: &SocketCancel) -> TcpOutcome {
    if cancel.cancelled() {
        return TcpOutcome::Cancelled;
    }
    let started = Instant::now();
    let result = TcpStream::connect_timeout(&target, Duration::from_secs_f64(timeout.max(0.001)));
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    if cancel.cancelled() {
        return TcpOutcome::Cancelled;
    }
    match result {
        Ok(_stream) => TcpOutcome::Connected(ms),
        Err(error) => match error.kind() {
            std::io::ErrorKind::ConnectionRefused => TcpOutcome::Refused,
            std::io::ErrorKind::TimedOut => TcpOutcome::TimedOut,
            std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable => TcpOutcome::Unreachable,
            _ => TcpOutcome::Error(error.to_string()),
        },
    }
}

/// python `telegram_check.connect_once` — (соединились ли, за сколько мс);
/// (None, None) — проверку сняли.
#[must_use]
pub fn telegram_connect(
    address: &str,
    port: u16,
    cancel: &SocketCancel,
) -> (Option<bool>, Option<f64>) {
    let Ok(ip) = address.parse::<std::net::Ipv4Addr>() else {
        return (None, None);
    };
    match tcp_connect(
        SocketAddr::new(std::net::IpAddr::V4(ip), port),
        crate::telegram_check::CONNECT_TIMEOUT_S,
        cancel,
    ) {
        TcpOutcome::Connected(ms) => (Some(true), Some(ms)),
        TcpOutcome::Cancelled => (None, None),
        _ => (Some(false), None),
    }
}

/// python `subnet_whitelist.connect` — дошёл ли пакет до адреса: соединение
/// или отказ (RST) — да, молчание и «нет дороги» — нет.
pub fn subnet_reachable(ip: &str, cancel: &SocketCancel) -> bool {
    let Ok(parsed) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    matches!(
        tcp_connect(
            SocketAddr::new(std::net::IpAddr::V4(parsed), 443),
            crate::subnet_whitelist::TIMEOUT_S,
            cancel,
        ),
        TcpOutcome::Connected(_) | TcpOutcome::Refused
    )
}

// ---------------------------------------------------------------------------
// STUN (RFC 5389)
// ---------------------------------------------------------------------------

/// Чей это адрес ответил STUN-сервер (python `parse_stun_response`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMapped {
    pub ip: String,
    pub port: u16,
    pub family: String,
}

/// python `build_stun_request` — запрос привязки: заголовок 20 байт со случайным
/// номером транзакции. Никаких данных о пользователе внутри нет.
#[must_use]
pub fn build_stun_request() -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes());
    request[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    for byte in request[8..20].iter_mut() {
        *byte = fastrand::u8(..);
    }
    request
}

fn be_u16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// python `_parse_xor_mapped_address` / `_parse_mapped_address`.
fn parse_address_attribute(
    kind: u16,
    value: &[u8],
    cookie: u32,
    txid: &[u8],
) -> Option<StunMapped> {
    if value.len() < 4 {
        return None;
    }
    let family_code = value[1];
    match (kind, family_code) {
        (0x0020, 0x01) if value.len() >= 8 => {
            let port = be_u16(value, 2) ^ ((cookie >> 16) as u16);
            let ip = be_u32(value, 4) ^ cookie;
            let octets = ip.to_be_bytes();
            Some(StunMapped {
                ip: format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
                port,
                family: "IPv4".to_string(),
            })
        }
        (0x0020, 0x02) if value.len() >= 20 => {
            let port = be_u16(value, 2) ^ ((cookie >> 16) as u16);
            let mut key = Vec::with_capacity(16);
            key.extend_from_slice(&cookie.to_be_bytes());
            key.extend_from_slice(&txid[..12.min(txid.len())]);
            let mut octets = [0u8; 16];
            for (index, byte) in value[4..20].iter().enumerate() {
                octets[index] = byte ^ key.get(index).copied().unwrap_or(0);
            }
            let segments: Vec<String> = octets
                .chunks(2)
                .map(|pair| format!("{}", u16::from_be_bytes([pair[0], pair[1]])))
                .collect();
            Some(StunMapped {
                ip: segments.join(":"),
                port,
                family: "IPv6".to_string(),
            })
        }
        (0x0001, 0x01) if value.len() >= 8 => {
            let octets = [value[4], value[5], value[6], value[7]];
            Some(StunMapped {
                ip: format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
                port: be_u16(value, 2),
                family: "IPv4".to_string(),
            })
        }
        (0x0001, 0x02) if value.len() >= 20 => {
            let segments: Vec<String> = value[4..20]
                .chunks(2)
                .map(|pair| format!("{}", u16::from_be_bytes([pair[0], pair[1]])))
                .collect();
            Some(StunMapped {
                ip: segments.join(":"),
                port: be_u16(value, 2),
                family: "IPv6".to_string(),
            })
        }
        _ => None,
    }
}

/// python `parse_stun_response` — разобрать ответ привязки. None — не похоже.
#[must_use]
pub fn parse_stun_response(data: &[u8]) -> Option<StunMapped> {
    if data.len() < 20 || be_u16(data, 0) != 0x0101 {
        return None;
    }
    let cookie = be_u32(data, 4);
    let txid = &data[8..20];
    let body_end = data.len().min(20 + be_u16(data, 2) as usize);
    let mut offset = 20;
    while offset + 4 <= body_end {
        let attr_type = be_u16(data, offset);
        let attr_length = be_u16(data, offset + 2) as usize;
        offset += 4;
        if offset + attr_length > body_end {
            break;
        }
        if attr_type == 0x0020 || attr_type == 0x0001 {
            if let Some(mapped) = parse_address_attribute(
                attr_type,
                &data[offset..offset + attr_length],
                cookie,
                txid,
            ) {
                return Some(mapped);
            }
        }
        offset += attr_length;
        if !attr_length.is_multiple_of(4) {
            offset += 4 - (attr_length % 4);
        }
    }
    None
}

/// Итог пробы STUN — те же коды, что у python `error_code`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StunResult {
    pub code: String,
    pub ms: f64,
    pub detail: String,
    pub family: String,
    pub resolved: Option<StunMapped>,
}

impl StunResult {
    /// python `SingleTestResult` для `voice_check::StunOutcome`.
    #[must_use]
    pub fn outcome(&self) -> crate::voice_check::StunOutcome {
        crate::voice_check::StunOutcome {
            status: if self.code == "OK" {
                "OK".to_string()
            } else {
                String::new()
            },
            error_code: if self.code == "OK" {
                String::new()
            } else {
                self.code.clone()
            },
            detail: self.detail.clone(),
        }
    }
}

/// Чтение UDP в буфер нужного размера с отменой между короткими отрезками.
fn recv_into(
    socket: &UdpSocket,
    buffer: &mut [u8],
    deadline: Instant,
    cancel: &SocketCancel,
) -> Option<usize> {
    loop {
        if cancel.cancelled() {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let slice = remaining.min(Duration::from_secs_f64(POLL_SLICE_S));
        socket
            .set_read_timeout(Some(slice))
            .expect("срок чтения сокета");
        match socket.recv_from(buffer) {
            Ok((size, _from)) => return Some(size),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return None,
        }
    }
}

/// python `_resolve_udp_addresses` — уникальные адреса сервера. Без срока:
/// `to_socket_addrs` блокирует, как и вызов без обёртки у python.
fn resolve_udp(host: &str, port: u16, ipv4_only: bool) -> Option<Vec<SocketAddr>> {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return None;
    };
    let mut seen: HashSet<(bool, String, u16)> = HashSet::new();
    let mut resolved = Vec::new();
    for addr in addrs {
        let is_v4 = addr.is_ipv4();
        if ipv4_only && !is_v4 {
            continue;
        }
        if seen.insert((is_v4, addr.ip().to_string(), addr.port())) {
            resolved.push(addr);
        }
    }
    (!resolved.is_empty()).then_some(resolved)
}

/// python `test_stun` — проба STUN-сервера с повторами: UDP теряет пакеты,
/// одному молчанию не верят.
pub fn test_stun(
    host: &str,
    port: u16,
    timeout: f64,
    retries: u32,
    cancel: &SocketCancel,
) -> StunResult {
    let start = Instant::now();
    let Some(addresses) = resolve_udp(host, port, false) else {
        return StunResult {
            code: "DNS_ERR".to_string(),
            ms: elapsed_ms(start),
            detail: format!("DNS resolution failed for {host}"),
            ..Default::default()
        };
    };
    if addresses.is_empty() {
        return StunResult {
            code: "DNS_ERR".to_string(),
            ms: elapsed_ms(start),
            detail: format!("No usable UDP address for {host}"),
            ..Default::default()
        };
    }

    let mut last = StunResult {
        code: "TIMEOUT".to_string(),
        detail: "UDP timeout".to_string(),
        ..Default::default()
    };
    let retry_rounds = retries.max(1);
    let budget = timeout.max(1.0);
    let total_attempts = (retry_rounds as usize * addresses.len()).max(1);
    let per_attempt = (budget / total_attempts as f64).max(1.0);
    let deadline = start + Duration::from_secs_f64(budget);

    let stop_scan = false;
    'rounds: for retry in 1..=retry_rounds {
        for target in &addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let family = if target.is_ipv4() { "IPv4" } else { "IPv6" };
            last.family = family.to_string();
            let bind_target: SocketAddr = if target.is_ipv4() {
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            };
            let Ok(socket) = UdpSocket::bind(bind_target) else {
                last = StunResult {
                    code: "ERROR".to_string(),
                    detail: "сокет не открылся".to_string(),
                    family: family.to_string(),
                    ..Default::default()
                };
                break;
            };
            if cancel.cancelled() {
                return StunResult {
                    code: "CANCELLED".to_string(),
                    ms: elapsed_ms(start),
                    detail: "Проверку сняли".to_string(),
                    family: family.to_string(),
                    ..Default::default()
                };
            }
            let attempt_deadline = Instant::now()
                + Duration::from_secs_f64(per_attempt.min(remaining.as_secs_f64().max(0.5)));
            let request = build_stun_request();
            if socket.send_to(&request, target).is_err() {
                last = StunResult {
                    code: "ERROR".to_string(),
                    detail: format!("запрос не ушёл ({family})"),
                    family: family.to_string(),
                    ..Default::default()
                };
                break;
            }
            let mut buffer = [0u8; 1024];
            let got = recv_into(&socket, &mut buffer, attempt_deadline, cancel);
            let Some(size) = got else {
                if cancel.cancelled() {
                    return StunResult {
                        code: "CANCELLED".to_string(),
                        ms: elapsed_ms(start),
                        detail: "Проверку сняли".to_string(),
                        family: family.to_string(),
                        ..Default::default()
                    };
                }
                last = StunResult {
                    code: "TIMEOUT".to_string(),
                    ms: elapsed_ms(start),
                    detail: format!("UDP timeout ({family}, попытка {retry}/{retry_rounds})"),
                    family: family.to_string(),
                    ..Default::default()
                };
                continue;
            };
            let parsed = parse_stun_response(&buffer[..size]);
            let ms = elapsed_ms(start);
            if let Some(mapped) = parsed {
                return StunResult {
                    code: "OK".to_string(),
                    ms,
                    detail: format!("Public IP: {}:{} ({family})", mapped.ip, mapped.port),
                    family: family.to_string(),
                    resolved: Some(mapped),
                };
            }
            last = StunResult {
                code: "PARSE_ERR".to_string(),
                ms,
                detail: format!("Failed to parse STUN response ({family})"),
                family: family.to_string(),
                ..Default::default()
            };
            break 'rounds;
        }
        if stop_scan || cancel.cancelled() {
            break;
        }
    }

    if cancel.cancelled() {
        return StunResult {
            code: "CANCELLED".to_string(),
            ms: elapsed_ms(start),
            detail: "Проверку сняли".to_string(),
            family: last.family.clone(),
            ..Default::default()
        };
    }
    last.ms = elapsed_ms(start);
    last
}

fn elapsed_ms(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Серия UDP-пакетов (udp_burst)
// ---------------------------------------------------------------------------

/// python `send_burst` — серия запросов с одного сокета: на какие по счёту
/// пришёл ответ. None — сервер недоступен или проверку сняли.
#[must_use]
pub fn send_burst(host: &str, port: u16, cancel: &SocketCancel) -> Option<Vec<bool>> {
    use crate::udp_burst::{GAP_S, PACKETS, TAIL_WAIT_S};
    let mut addresses = resolve_udp(host, port, true)?;
    let target = addresses.pop()?;
    let socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).ok()?;
    socket.connect(target).ok()?;
    let mut sent: Vec<([u8; 12], usize)> = Vec::with_capacity(PACKETS);
    let mut answered = vec![false; PACKETS];

    let drain = |socket: &UdpSocket,
                 sent: &[([u8; 12], usize)],
                 answered: &mut [bool],
                 until: Instant| {
        loop {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            let slice = remaining.min(Duration::from_secs_f64(GAP_S.max(0.01)));
            socket.set_read_timeout(Some(slice)).expect("срок чтения");
            let mut buffer = [0u8; 2048];
            match socket.recv_from(&mut buffer) {
                Ok((size, _from)) => {
                    if size >= 20 {
                        let mut txid = [0u8; 12];
                        txid.copy_from_slice(&buffer[8..20]);
                        if let Some((_key, index)) = sent.iter().find(|(known, _)| *known == txid) {
                            answered[*index] = true;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return,
                Err(_) => return, // «порт недоступен» от сети — просто отсутствие ответа
            }
        }
    };

    for index in 0..PACKETS {
        let request = build_stun_request();
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&request[8..20]);
        sent.push((txid, index));
        // Ошибка отправки не выводит серию из строя: пакет мог и не дойти.
        let _ = socket.send(&request);
        drain(
            &socket,
            &sent,
            &mut answered,
            Instant::now() + Duration::from_secs_f64(GAP_S),
        );
        if cancel.cancelled() {
            return None;
        }
    }
    drain(
        &socket,
        &sent,
        &mut answered,
        Instant::now() + Duration::from_secs_f64(TAIL_WAIT_S),
    );
    if cancel.cancelled() {
        return None;
    }
    Some(answered)
}

// ---------------------------------------------------------------------------
// Планировщики на машине прогона
// ---------------------------------------------------------------------------

/// Ждать итог задания без проверки «Стоп» — как python `future.result()`.
fn await_value<T: Send + 'static>(handle: &Handle<T>) -> Result<T, TaskError> {
    loop {
        if let Some(result) = handle.poll(Duration::from_secs_f64(POLL_SLICE_S)) {
            return result;
        }
    }
}

/// python `check_voice` — опрашивает все STUN-серверы параллельно.
///
/// `probe(host, port, cancel)` — сама проба (настоящая — `stun_probe()`).
pub fn check_voice(
    run: &Run,
    cancel: &Arc<SocketCancel>,
    probe: StunProbe,
) -> Vec<crate::voice_check::VoiceServer> {
    let plan = crate::voice_check::STUN_TARGETS
        .iter()
        .map(|(name, value, group)| {
            let (host, port) = crate::voice_check::parse_target(value);
            (name.to_string(), host, port, group.to_string())
        })
        .collect::<Vec<_>>();
    let mut handles: Vec<Handle<crate::voice_check::StunOutcome>> = Vec::new();
    for (_name, host, port, _group) in &plan {
        let probe = Arc::clone(&probe);
        let cancel = Arc::clone(cancel);
        let host = host.clone();
        let port = *port;
        handles.push(run.submit(move || Ok(probe(&host, port, &cancel))));
    }
    // Отдельный сервер не должен ронять отчёт (python `except Exception`).
    let mut servers = Vec::with_capacity(plan.len());
    for (index, (name, host, _port, group)) in plan.iter().enumerate() {
        let outcome = match await_value(&handles[index]) {
            Ok(outcome) => outcome,
            Err(error) => crate::voice_check::StunOutcome {
                status: String::new(),
                error_code: String::new(),
                detail: format!("ошибка проверки ({error})"),
            },
        };
        let (answered, text, decided) = crate::voice_check::describe(&outcome);
        servers.push(crate::voice_check::VoiceServer {
            name: name.clone(),
            host: host.clone(),
            answered,
            text,
            decided,
            group: group.clone(),
        });
    }
    servers
}

/// Настоящая проба STUN: `test_stun` с сроком из конфига (python `STUN_TIMEOUT`).
pub fn stun_probe() -> StunProbe {
    Arc::new(|host: &str, port: u16, cancel: &SocketCancel| {
        test_stun(host, port, crate::voice_check::STUN_TIMEOUT_S, 2, cancel).outcome()
    })
}

/// python `check_bursts` — серверы одновременно, серии к одному серверу
/// по очереди (каждая с нового сокета, то есть с другого порта).
pub fn check_bursts(
    run: &Run,
    cancel: &Arc<SocketCancel>,
    send: BurstSend,
) -> Vec<(String, Vec<Option<Vec<bool>>>)> {
    let mut handles = Vec::new();
    for (name, host, port) in crate::udp_burst::SERVERS {
        let send = Arc::clone(&send);
        let cancel = Arc::clone(cancel);
        handles.push((
            name.to_string(),
            run.submit(move || {
                let mut series = Vec::new();
                for _attempt in 0..crate::udp_burst::REPEATS {
                    series.push(send(host, port, &cancel));
                }
                Ok(series)
            }),
        ));
    }
    let mut facts = Vec::new();
    for (name, handle) in handles {
        let series = await_value(&handle).unwrap_or_default();
        facts.push((name, series));
    }
    facts
}

/// python `check_telegram` — все дата-центры одновременно; неудачное
/// соединение повторяется после паузы.
pub fn check_telegram(
    run: &Run,
    connect: DcConnect,
    pause: DcPause,
) -> Vec<crate::telegram_check::DcResult> {
    let mut handles = Vec::new();
    for center in &crate::telegram_check::DATA_CENTERS {
        let connect = Arc::clone(&connect);
        let pause = Arc::clone(&pause);
        let address = center.address.to_string();
        let port = center.port;
        handles.push(run.submit(move || {
            let (connected, ms) = connect(&address, port);
            if connected == Some(false) {
                // Потерянный пакет не должен выглядеть блокировкой.
                pause(crate::telegram_check::RETRY_PAUSE_S);
                let (connected, ms) = connect(&address, port);
                return Ok(crate::telegram_check::DcResult {
                    name: center.name.to_string(),
                    address: address.clone(),
                    connected,
                    ms,
                    attempts: 2,
                });
            }
            Ok(crate::telegram_check::DcResult {
                name: center.name.to_string(),
                address: address.clone(),
                connected,
                ms,
                attempts: 1,
            })
        }));
    }
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = await_value(&handle) {
            results.push(result);
        }
    }
    results
}

/// Настоящее соединение с дата-центром: `telegram_connect` на адресе.
pub fn telegram_transport() -> TelegramCollect {
    Arc::new(move |run: &std::sync::Arc<Run>| {
        let connect_cancel = Arc::clone(&run.probe_cancel);
        let pause_run = Arc::clone(run);
        let results = check_telegram(
            run,
            Arc::new(move |address: &str, port: u16| {
                telegram_connect(address, port, &connect_cancel)
            }),
            Arc::new(move |seconds: f64| {
                let _ = pause_run.pause(seconds);
            }),
        );
        if results.is_empty() && run.dns_cancelled() {
            return Err(TaskError::Stopped);
        }
        Ok(results)
    })
}

/// Настоящая проверка звонков: `test_stun` по всем STUN-серверам.
pub fn voice_transport() -> VoiceCollect {
    Arc::new(move |run: &std::sync::Arc<Run>| {
        let probe = stun_probe();
        let cancel = Arc::clone(&run.probe_cancel);
        Ok(check_voice(run, &cancel, probe))
    })
}

/// Настоящая серия пакетов UDP: `send_burst` по двум серверам.
pub fn burst_transport() -> BurstCollect {
    Arc::new(move |run: &std::sync::Arc<Run>| {
        let send: BurstSend = Arc::new(move |host: &str, port: u16, cancel: &SocketCancel| {
            send_burst(host, port, cancel)
        });
        let cancel = Arc::clone(&run.probe_cancel);
        let facts = check_bursts(run, &cancel, send);
        if run.dns_cancelled() {
            return Ok(None);
        }
        Ok(crate::udp_burst::judge(&facts))
    })
}

/// Настоящее подтверждение «белых списков»: TCP-пробы по десяткам сетей.
pub fn subnets_transport() -> SubnetsCheck {
    Arc::new(move |run: &std::sync::Arc<Run>| {
        let connect: SubnetConnect =
            Arc::new(|ip: &str, cancel: &SocketCancel| subnet_reachable(ip, cancel));
        let cancel = Arc::clone(&run.probe_cancel);
        let facts = collect_groups(run, &cancel, connect);
        Ok(crate::subnet_whitelist::judge(&facts))
    })
}

/// python `subnet_whitelist.collect` — все сети разом (через общий предел
/// прогона); закрытые ещё раз после паузы.
pub fn collect_groups(
    run: &Run,
    cancel: &Arc<SocketCancel>,
    connect: SubnetConnect,
) -> crate::subnet_whitelist::SubnetFacts {
    let ask = |chosen: Vec<(String, String, Vec<String>)>,
               connect: SubnetConnect,
               cancel: &Arc<SocketCancel>|
     -> Vec<bool> {
        let mut opened = Vec::with_capacity(chosen.len());
        for (_label, _region, ips) in chosen {
            let mut handles = Vec::new();
            for ip in ips {
                let connect = Arc::clone(&connect);
                let cancel = Arc::clone(cancel);
                handles.push(run.net_lane.submit(move || Ok(connect(&ip, &cancel))));
            }
            let mut any_open = false;
            for handle in &handles {
                if let Ok(true) = await_value(handle) {
                    any_open = true;
                }
            }
            opened.push(any_open);
        }
        opened
    };

    let groups: Vec<(String, String, Vec<String>)> = crate::subnet_catalog::SUBNET_GROUPS
        .iter()
        .map(|(label, region, ips)| {
            (
                label.to_string(),
                region.to_string(),
                ips.iter().map(|ip| ip.to_string()).collect(),
            )
        })
        .collect();
    let mut opened = ask(groups.clone(), Arc::clone(&connect), cancel);
    let closed: Vec<usize> = opened
        .iter()
        .enumerate()
        .filter(|(_index, answered)| !**answered)
        .map(|(index, _)| index)
        .collect();
    if !closed.is_empty()
        && !cancel.cancelled()
        && cancel.sleep(crate::subnet_whitelist::RETRY_PAUSE_S)
    {
        let retry: Vec<(String, String, Vec<String>)> =
            closed.iter().map(|index| groups[*index].clone()).collect();
        let again = ask(retry, Arc::clone(&connect), cancel);
        for (index, answered) in closed.iter().zip(again) {
            opened[*index] = answered;
        }
    }
    crate::subnet_whitelist::SubnetFacts {
        groups: groups
            .iter()
            .zip(opened)
            .map(|((label, region, _ips), answered)| (label.clone(), region.clone(), answered))
            .collect(),
        cancelled: cancel.cancelled(),
    }
}

// ---------------------------------------------------------------------------
// Состояние системы
// ---------------------------------------------------------------------------

/// python-чтения о системе (Windows): реестр, WMI, файл hosts. На другой
/// системе python ничего не читает — здесь то же самое.
pub trait SystemReader: Send + Sync {
    fn is_admin(&self) -> Option<bool> {
        None
    }
    fn windows_build(&self) -> Option<i64> {
        None
    }
    fn in_temp_folder(&self) -> Option<bool> {
        None
    }
    fn in_onedrive(&self) -> Option<bool> {
        None
    }
    fn free_mb(&self) -> Option<i64> {
        None
    }
    fn integrity(&self) -> Option<(bool, Vec<String>, Vec<String>)> {
        None
    }
    fn bfe_running(&self) -> Option<bool> {
        None
    }
    fn conflicts(&self) -> Option<Vec<String>> {
        None
    }
    fn goodbyedpi_services(&self) -> Option<Vec<String>> {
        None
    }
    fn bypass_tools(&self) -> Option<Vec<String>> {
        None
    }
    fn antivirus(&self) -> Option<String> {
        None
    }
    fn proxy(&self) -> Option<(String, String)> {
        None
    }
    fn tunnels(&self) -> Option<Vec<String>> {
        None
    }
    fn tunnels_routed(&self) -> Option<Vec<String>> {
        None
    }
    fn hosts_readable(&self) -> Option<bool> {
        None
    }
    fn hosts_overrides(&self, _check_hosts: &[String]) -> Option<Vec<(String, String)>> {
        None
    }
    fn hosts_managed(&self) -> Option<Vec<(String, String)>> {
        None
    }
}

/// Читатель для систем без Windows: все факты неизвестны (python `sys.platform != "win32"`).
#[derive(Debug, Default)]
pub struct NullSystemReader;

impl SystemReader for NullSystemReader {}

/// python `collect_facts` — читает всё, что можно узнать о системе, ничего
/// в ней не меняя.
///
/// `clock_skew` — расхождение часов; для него нужна сеть (HTTPS), поэтому
/// движок подаёт `None`, пока не перенесён TLS-слой.
#[must_use]
pub fn collect_facts(
    reader: &dyn SystemReader,
    check_hosts: &[String],
    clock_skew: Option<f64>,
) -> crate::system_state::SystemFacts {
    if std::env::consts::OS != "windows" {
        // На другой системе читать нечего: все факты остаются неизвестными.
        return crate::system_state::SystemFacts {
            clock_skew_s: clock_skew,
            ..Default::default()
        };
    }
    let proxy = reader.proxy();
    crate::system_state::SystemFacts {
        is_admin: reader.is_admin(),
        windows_build: reader.windows_build(),
        in_temp_folder: reader.in_temp_folder(),
        in_onedrive: reader.in_onedrive(),
        free_mb: reader.free_mb(),
        integrity: reader.integrity(),
        bfe_running: reader.bfe_running(),
        conflicts: reader.conflicts(),
        goodbyedpi_services: reader.goodbyedpi_services(),
        bypass_tools: reader.bypass_tools(),
        antivirus: reader.antivirus(),
        proxy_server: proxy.as_ref().map(|(server, _script)| server.clone()),
        proxy_script: proxy.as_ref().map(|(_server, script)| script.clone()),
        tunnels: reader.tunnels(),
        tunnels_routed: reader.tunnels_routed(),
        hosts_readable: reader.hosts_readable(),
        hosts_overrides: reader.hosts_overrides(check_hosts),
        hosts_managed: reader.hosts_managed(),
        clock_skew_s: clock_skew,
    }
}

/// python `check_system` — состояние компьютера; `intercept` — ещё и
/// самопроверка перехвата.
///
/// `reader` — Windows-чтения (на другой системе достаточно `NullSystemReader`);
/// расхождение часов здесь не меряется: для него нужен HTTPS-запрос.
pub fn system_transport(reader: Arc<dyn SystemReader>) -> SystemCheck {
    Arc::new(
        move |run: &std::sync::Arc<Run>,
              services: &[(String, crate::services::Service)],
              zapret_running: Option<bool>,
              intercept: bool|
              -> Result<Vec<crate::system_state::SystemItem>, TaskError> {
            let mut hosts: Vec<String> = Vec::new();
            for (_key, service) in services {
                for target in &service.targets {
                    if !hosts.contains(&target.host) {
                        hosts.push(target.host.clone());
                    }
                }
            }
            // Самопроверка идёт рядом с чтением системы: перехват соединений
            // на компьютере — тоже «Компьютер».
            let pending: Option<Handle<crate::self_check::SelfFacts>> = if intercept {
                let cancel = Arc::clone(&run.probe_cancel);
                Some(run.submit(move || Ok(self_check_now(&cancel))))
            } else {
                None
            };
            let facts = collect_facts(reader.as_ref(), &hosts, None);
            let mut items = crate::system_state::judge(&facts, zapret_running);
            if let Some(pending) = pending {
                let facts = await_value(&pending)?;
                if let Some(extra) = crate::self_check::judge(&facts) {
                    items.push(extra);
                }
            }
            Ok(items)
        },
    )
}

/// python `self_check.collect` — реальное соединение с адресом-пустышкой.
#[must_use]
pub fn self_check_now(cancel: &SocketCancel) -> crate::self_check::SelfFacts {
    let Some(target) = crate::self_check::try_target() else {
        return crate::self_check::SelfFacts { accepted: None };
    };
    match tcp_connect(target, crate::self_check::TIMEOUT_S, cancel) {
        TcpOutcome::Connected(_) => crate::self_check::SelfFacts {
            accepted: Some(true),
        },
        TcpOutcome::Cancelled => crate::self_check::SelfFacts { accepted: None },
        _ => crate::self_check::SelfFacts {
            accepted: Some(false),
        },
    }
}
