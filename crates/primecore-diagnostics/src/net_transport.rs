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

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;

use crate::engine::{
    BurstCollect, CauseCollect, CertCollect, ChromeGetMut, FreezeCheck, FreezeTargetsFn,
    NetworkCheck, ProtocolsCollect, QuicCollect, SubnetsCheck, SystemCheck, TelegramCollect,
    VoiceCollect, VolumeCollect,
};

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

/// Настоящая проверка QUIC: пакеты Initial по UDP с настоящим шифрованием
/// ([`crate::quic_initial`]).
pub fn quic_transport() -> QuicCollect {
    Arc::new(move |host: &str, ip: &str, run: &std::sync::Arc<Run>| {
        quic_collect_with(
            host,
            ip,
            crate::quic_probe::QUIC_PORT,
            run,
            crate::quic_probe::ATTEMPTS,
            crate::quic_probe::ATTEMPT_TIMEOUT_S,
        )
    })
}

/// Настоящее уточнение причины: приветствия с шагом и порт 80; проба пинга
/// приходит из движка при вызове.
pub fn cause_transport() -> CauseCollect {
    Arc::new(
        move |host: &str, result: &crate::probe_result::ProbeResult, run, ping| {
            crate::block_cause::collect(host, result, run, Some(ping))
        },
    )
}

/// Настоящие дороги: TLS 1.2, TLS 1.3 и порт 80 по тому же адресу.
pub fn protocols_transport() -> ProtocolsCollect {
    Arc::new(move |host: &str, ip: &str, run| crate::protocol_probe::collect(host, ip, run))
}

/// Настоящий замер объёма: запросы по одному соединению «как Chrome».
pub fn volume_transport() -> VolumeCollect {
    Arc::new(move |host: &str, ip: &str, path: &str, cancel| {
        Ok(crate::volume_probe::collect(host, ip, path, cancel))
    })
}

/// Настоящий сбор сертификата без проверки: кто ответил вместо сайта.
pub fn cert_transport() -> CertCollect {
    Arc::new(move |host: &str, ip: &str, cancel| Ok(crate::cert_owner::collect(host, ip, cancel)))
}

// ---------------------------------------------------------------------------
// HTTPS «как браузер» и надстройки над ним (python sections поверх net_access)
// ---------------------------------------------------------------------------

/// Настоящий `chrome_get` (utils/chrome_https.py): HTTPS-запрос «как браузер»
/// к `ip:443` с общим на прогон отменой.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn chrome_get_transport(cancel: Arc<SocketCancel>) -> Arc<Mutex<ChromeGetMut>> {
    Arc::new(Mutex::new(
        move |host: &str,
              ip: &str,
              path: &str,
              timeout: f64,
              read_limit: usize,
              read_timeout: f64,
              body_done: Option<&dyn Fn(&[u8]) -> bool>,
              decode_body: bool| {
            crate::chrome_https::chrome_get(
                host,
                ip,
                path,
                timeout,
                443,
                read_limit,
                read_timeout,
                body_done,
                decode_body,
                Arc::clone(&cancel),
            )
        },
    ))
}

/// python `sections._CLOCK_HOST` — чей сервер отвечает часами.
pub const CLOCK_HOST: &str = "www.google.com";
/// python `/generate_204` — ответ без тела, зато с заголовком `Date`.
pub const CLOCK_PATH: &str = "/generate_204";

/// python `sections.clock_skew(run)` — расхождение часов с сервером.
pub type ClockSkewFn = Arc<dyn Fn(&Arc<Run>) -> Option<f64> + Send + Sync>;

/// Настоящее расхождение часов: эталонные адреса через DoH, затем запрос
/// `/generate_204` и чтение заголовка `Date` из ответа.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn clock_skew_transport(
    chrome_get: Arc<Mutex<ChromeGetMut>>,
    doh_query: crate::engine::DohQueryFn,
) -> ClockSkewFn {
    Arc::new(move |run: &Arc<Run>| {
        // Эталонные адреса (python net_access.doh_lookup): опоздавшие ответы
        // тоже попадают в отчёт прогона.
        let noting = Arc::downgrade(run);
        let mut note = |resolver: &crate::dns_reference::ReferenceResolver,
                        result: &primecore_dnswire::DnsQueryResult| {
            if let Some(run) = noting.upgrade() {
                let index = crate::dns_reference::REFERENCE_RESOLVERS
                    .iter()
                    .position(|item| {
                        item.label == resolver.label && item.address == resolver.address
                    })
                    .unwrap_or(0);
                run.note_reference(index, result);
            }
        };
        let (_, addresses) = {
            let mut query = doh_query.lock().expect("замок эталонных вопросов");
            crate::net_access::doh_lookup(&mut *query, &mut note)
        };
        let ip = addresses.first()?;
        let mut chrome = chrome_get.lock().expect("замок chrome_get");
        let result = crate::net_access::get(CLOCK_HOST, ip, CLOCK_PATH, 1, &mut *chrome);
        clock_skew_from_body(unix_now(), &result.body)
    })
}

/// python `time.time()` — секунды от эпохи (для сравнения с часами сервера).
#[must_use]
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_secs_f64())
        .unwrap_or_default()
}

/// Заголовок `Date` из ответа и расхождение часов: локальное время минус время
/// сервера. None — ответа нет или дату разобрать не удалось.
#[must_use]
pub fn clock_skew_from_body(local: f64, body: &[u8]) -> Option<f64> {
    let end = body
        .windows(4)
        .position(|part| {
            part == b"

"
        })
        .unwrap_or(body.len());
    // Строки заголовков: первая — строка состояния (python [1:]).
    for line in body[..end].split(|byte| *byte == b'\n').skip(1) {
        let line: &[u8] = strip_byte(line, b'\r');
        let (name, value) = split_header(line)?;
        if name.eq_ignore_ascii_case(b"date") {
            let server = http_date_timestamp(&String::from_utf8_lossy(value))?;
            return Some(local - server);
        }
    }
    None
}

fn strip_byte(line: &[u8], byte: u8) -> &[u8] {
    match line.strip_suffix(&[byte]) {
        Some(stripped) => stripped,
        None => line,
    }
}

/// `Имя: значение` из строки заголовка; пробелы по краям убраны.
fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = line.iter().position(|byte| *byte == b':')?;
    let name = &line[..at];
    let value = strip_byte(&line[at + 1..], b' ');
    Some((name, value))
}

/// python `email.utils.parsedate_to_datetime(...).timestamp()` — дата в
/// формате RFC 1123 («Tue, 15 Nov 1994 08:12:31 GMT»).
#[must_use]
pub fn http_date_timestamp(value: &str) -> Option<f64> {
    let mut parts: Vec<&str> = value.split_whitespace().collect();
    // Имя дня недели с запятой — убрать (python parsedate гибче, но серверы
    // шлют ровно этот формат).
    if parts.first().is_some_and(|item| item.ends_with(',')) {
        parts.remove(0);
    }
    if parts.len() < 5 {
        return None;
    }
    let day: i64 = parts[0].parse().ok()?;
    let month = match parts[1].to_ascii_uppercase().as_str() {
        "JAN" => 1,
        "FEB" => 2,
        "MAR" => 3,
        "APR" => 4,
        "MAY" => 5,
        "JUN" => 6,
        "JUL" => 7,
        "AUG" => 8,
        "SEP" => 9,
        "OCT" => 10,
        "NOV" => 11,
        "DEC" => 12,
        _ => return None,
    };
    let year: i64 = parts[2].parse().ok()?;
    let mut clock = parts[3].split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next().unwrap_or("0").parse().ok()?;
    let offset = match parts[4].to_ascii_uppercase().as_str() {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        zone if zone.len() == 5 && (zone.starts_with('+') || zone.starts_with('-')) => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let hours: i64 = zone[1..3].parse().ok()?;
            let minutes: i64 = zone[3..5].parse().ok()?;
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    // python проверяет день по длине месяца (ValueError на 32 ноября).
    if day < 1 || day > month_days(year, month) {
        return None;
    }
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some(seconds as f64)
}

/// Дней в месяце с учётом високосного года.
fn month_days(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Дни от «эпохи» (алгоритм days_from_civil): год, месяц (1–12), день.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted = i64::from(month <= 2);
    let y = year - shifted;
    let m = if month > 2 { month } else { month + 12 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let day_of_year = (153 * (m - 3) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// python `my_network.collect`-проба пинга: (ttl) → (адрес, время).
pub type HopProbe = Arc<dyn Fn(u32) -> Option<(String, Option<f64>)> + Send + Sync>;

/// Настоящая «Ваша сеть» (python `sections.check_network`): внешний адрес по
/// ответам Cloudflare, владелец сети — шифрованным вопросом к эталону, пинг —
/// как его наладит система.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn network_transport(
    chrome_get: Arc<Mutex<ChromeGetMut>>,
    doh_ask_query: crate::engine::DohAskQueryFn,
    hops: Option<HopProbe>,
) -> NetworkCheck {
    Arc::new(move |run: &Run, bypass_tools: &[String]| {
        let fetch_server = |server: &str| -> Option<Vec<u8>> {
            let mut chrome = chrome_get.lock().expect("замок chrome_get");
            let result = crate::net_access::fetch(
                crate::my_network::TRACE_HOST,
                server,
                crate::my_network::TRACE_PATH,
                crate::limits::HTTPS_TIMEOUT,
                2048,
                crate::limits::READ_TIMEOUT,
                None,
                false,
                &mut *chrome,
            );
            if result.ok() && !result.body.is_empty() {
                Some(result.body)
            } else {
                None
            }
        };
        let owner_of = |ip: &str| -> Option<crate::ip_owner::IpOwner> {
            let mut ask = doh_ask_query.lock().expect("замок вопросов эталона");
            crate::ip_owner::lookup_ip_owner(ip, |name, record_type| {
                crate::net_access::doh_ask(name, record_type, &mut *ask)
            })
        };
        let probe = |ttl: u32| -> Option<(String, Option<f64>)> {
            if run.dns_cancelled() {
                return None;
            }
            hops.as_ref().and_then(|hops| hops(ttl))
        };
        let hop_probe = Some(&probe as &dyn Fn(u32) -> Option<(String, Option<f64>)>);
        crate::sections::check_network(
            &fetch_server,
            &owner_of,
            &crate::my_network::local_address,
            hop_probe,
            bypass_tools,
        )
    })
}

/// python `sections.upload` — проверка отправки на том же сервере.
pub type UploadFn =
    Arc<dyn Fn(&Run, &str, &str) -> Option<crate::upload_probe::UploadVerdict> + Send + Sync>;

/// Замыкание проверки отправки, привязанное к прогону: срок жизни явный,
/// потому что аннотация `'_` у trait object подразумевала бы `'static`.
fn upload_with<'r>(
    upload: UploadFn,
    run: &'r Run,
) -> impl Fn(&str, &str) -> Option<crate::upload_probe::UploadVerdict> + 'r {
    move |host: &str, path: &str| upload(run, host, path)
}

/// Замыкание как trait object с тем же сроком жизни, что у ссылки.
fn as_upload<'a, F>(call: &'a F) -> &'a crate::freeze_check::UploadCheck<'a>
where
    F: Fn(&str, &str) -> Option<crate::upload_probe::UploadVerdict> + 'a,
{
    call
}

/// Настоящая проверка обрыва (python движок + `sections.download`): адреса
/// провайдеров проверяются запросами «как Chrome» по 64 КБ.
///
/// `resolve(host)` — адреса, которыми воспользовался бы браузер; кэш адресов
/// живёт внутри проверки, как у python на прогоне.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn freeze_transport(
    chrome_get: Arc<Mutex<ChromeGetMut>>,
    targets: FreezeTargetsFn,
    resolve: Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>,
    upload: Option<UploadFn>,
) -> FreezeCheck {
    Arc::new(
        move |run: &Run,
              every: bool,
              on_server: &dyn Fn(&crate::freeze_check::FreezeServer, u32, u32)| {
            let cache: Arc<Mutex<BTreeMap<String, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
            // Внутреннее move-замыкание не может забрать владение у внешнего
            // Fn-замыкания: общие части клонируются заранее.
            let resolve = Arc::clone(&resolve);
            let chrome_get = Arc::clone(&chrome_get);
            let download =
                move |host: &str, path: &str| -> Option<crate::probe_result::ProbeResult> {
                    let known = cache.lock().expect("замок адресов").get(host).cloned();
                    let address =
                        crate::net_access::known_address(known, &mut |name| resolve(name), host);
                    if address.is_empty() {
                        return None;
                    }
                    cache
                        .lock()
                        .expect("замок адресов")
                        .insert(host.to_string(), address.clone());
                    let mut chrome = chrome_get.lock().expect("замок chrome_get");
                    Some(crate::net_access::fetch(
                        host,
                        &address,
                        path,
                        crate::limits::HTTPS_TIMEOUT,
                        usize::try_from(crate::freeze_check::READ_LIMIT).expect("лимит чтения"),
                        crate::limits::FREEZE_READ_TIMEOUT,
                        None,
                        false,
                        &mut *chrome,
                    ))
                };
            let upload_call = upload
                .as_ref()
                .map(|upload| upload_with(Arc::clone(upload), run));
            let upload_server = upload_call.as_ref().map(as_upload);
            let on_each =
                |server: &crate::freeze_check::FreezeServer, done: usize, total: usize| {
                    on_server(
                        server,
                        u32::try_from(done).unwrap_or(u32::MAX),
                        u32::try_from(total).unwrap_or(u32::MAX),
                    )
                };
            Ok(crate::freeze_check::check_freeze(
                &targets(),
                every,
                download,
                upload_server,
                Some(&on_each),
                crate::run_context::clock_now,
            ))
        },
    )
}

/// python `quic_probe.collect(host, ip, submit, cancel)` — сначала пакет с
/// именем сайта, как у браузера. Только если сервер промолчал, уходят пакеты
/// с посторонним именем и без имени — параллельно: они нужны, чтобы назвать
/// причину, а браузер таких не шлёт. Затем настоящее имя ещё раз.
pub fn quic_collect_with(
    host: &str,
    ip: &str,
    port: u16,
    run: &Arc<Run>,
    attempts: u32,
    timeout: f64,
) -> Result<crate::quic_probe::QuicFacts, TaskError> {
    let cancel = Arc::clone(&run.probe_cancel);
    let real_ms = crate::quic_probe::quic_hello(ip, Some(host), port, attempts, timeout, &cancel);
    if real_ms.is_some() || cancel.cancelled() {
        return Ok(crate::quic_probe::QuicFacts {
            host: host.to_string(),
            real_ms,
            cancelled: cancel.cancelled(),
            ..crate::quic_probe::QuicFacts::default()
        });
    }
    let neutral_name = crate::quic_probe::NEUTRAL_NAME.to_string();
    let neutral_ip = ip.to_string();
    let neutral_cancel = Arc::clone(&cancel);
    let neutral = run.submit(move || {
        Ok(crate::quic_probe::quic_hello(
            &neutral_ip,
            Some(&neutral_name),
            port,
            attempts,
            timeout,
            &neutral_cancel,
        ))
    });
    let nameless_ip = ip.to_string();
    let nameless_cancel = Arc::clone(&cancel);
    let nameless = run.submit(move || {
        Ok(crate::quic_probe::quic_hello(
            &nameless_ip,
            None,
            port,
            attempts,
            timeout,
            &nameless_cancel,
        ))
    });
    let neutral_ms = run.wait(&neutral)?;
    let nameless_ms = run.wait(&nameless)?;
    let mut real_again_ms = None;
    if (neutral_ms.is_some() || nameless_ms.is_some()) && !cancel.cancelled() {
        real_again_ms =
            crate::quic_probe::quic_hello(ip, Some(host), port, attempts, timeout, &cancel);
    }
    Ok(crate::quic_probe::QuicFacts {
        host: host.to_string(),
        real_ms: real_ms.or(real_again_ms),
        neutral_ms,
        nameless_ms,
        real_again_ms,
        cancelled: cancel.cancelled(),
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
/// `clock_skew` — расхождение часов (для него нужен HTTPS-запрос —
/// [`clock_skew_transport`]); None — не меряется.
pub fn system_transport(
    reader: Arc<dyn SystemReader>,
    clock_skew: Option<ClockSkewFn>,
) -> SystemCheck {
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
            let skew = clock_skew.as_ref().and_then(|measure| measure(run));
            let facts = collect_facts(reader.as_ref(), &hosts, skew);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Эталон — python `parsedate_to_datetime(...).timestamp()`:
    /// `Tue, 15 Nov 1994 08:12:31 GMT` = 784887151 unix-секунд.
    #[test]
    fn http_date_is_parsed() {
        assert_eq!(
            http_date_timestamp("Tue, 15 Nov 1994 08:12:31 GMT"),
            Some(784_887_151.0)
        );
        assert_eq!(
            http_date_timestamp("15 Nov 1994 08:12:31 GMT"),
            Some(784_887_151.0)
        );
        // Смещение зоны вычитается: 12:00+02:00 = 10:00 GMT.
        assert_eq!(
            http_date_timestamp("Tue, 15 Nov 1994 12:00:00 +0200"),
            Some(784_893_600.0)
        );
        assert_eq!(http_date_timestamp("не дата"), None);
        assert_eq!(http_date_timestamp("Tue, 32 Nov 1994 08:12:31 GMT"), None);
    }

    #[test]
    fn date_header_found_in_body() {
        let body =
            b"HTTP/1.1 204 No Content\r\nDate: Tue, 15 Nov 1994 08:12:31 GMT\r\nServer: t\r\n\r\n";
        // Локальное время на 10 секунд впереди серверного.
        assert_eq!(clock_skew_from_body(784_887_161.0, body), Some(10.0));
        // Заголовка нет — и расхождения нет.
        assert_eq!(
            clock_skew_from_body(784_887_161.0, b"HTTP/1.1 204\r\n\r\n"),
            None
        );
    }

    #[test]
    fn leap_years_counted() {
        // Эталоны python: високосные 2000 и 2024 принимают 29 февраля,
        // невисокосный 1900 — нет (ValueError → None).
        assert_eq!(
            http_date_timestamp("Wed, 01 Mar 2000 00:00:00 GMT"),
            Some(951_868_800.0)
        );
        assert_eq!(
            http_date_timestamp("Tue, 29 Feb 2000 00:00:00 GMT"),
            Some(951_782_400.0)
        );
        assert_eq!(
            http_date_timestamp("Wed, 29 Feb 2024 00:00:00 GMT"),
            Some(1_709_164_800.0)
        );
        assert_eq!(http_date_timestamp("Tue, 29 Feb 1900 00:00:00 GMT"), None);
        assert_eq!(http_date_timestamp("Tue, 31 Nov 1994 08:12:31 GMT"), None);
    }
}
