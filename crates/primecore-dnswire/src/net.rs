//! Сетевой слой `utils/dns_wire.py` — UDP, TCP, общий лимит времени, «Стоп».
//!
//! Отличия от python (осознанные, для Rust):
//! * «Стоп» не закрывает сокет из другого потока (std не даёт без unsafe);
//!   вместо этого чтение идёт короткими отрезками (read timeout) и между
//!   ними проверяется признак отмены — вид сбоя тот же.
//! * тексты ошибок ОС (`detail`) у Rust другие, чем у python, — вид сбоя
//!   (`failure`) сохранён; `detail` — человеческий текст, выводы по нему
//!   не строятся (иллюстрации в migration-map).

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use primecore_netfailure::{
    classify_os_error, FAILURE_CANCELLED, FAILURE_CLOSED, FAILURE_MALFORMED, FAILURE_OTHER,
    FAILURE_REFUSED, FAILURE_TIMEOUT,
};
use primecore_socketcancel::SocketCancel;

use crate::{
    build_query, parse_response, DnsMessage, DnsQueryResult, RCODE_NXDOMAIN, RCODE_OK,
    STATUS_EMPTY, STATUS_ERROR, STATUS_NXDOMAIN, STATUS_OK, STATUS_REFUSED, STATUS_TIMEOUT,
    TRANSPORT_TCP, TRANSPORT_UDP,
};

/// «Стоп» нажали до начала запроса (python _Cancelled).
#[derive(Debug)]
pub struct Cancelled;

/// Сервер закрыл соединение, не ответив (python _ConnectionClosed).
#[derive(Debug)]
pub enum NetError {
    Cancelled,
    ConnectionClosed,
    DnsWire(String),
    Io(std::io::Error),
    /// Ушли за общий предел времени запроса (python socket.timeout).
    Deadline,
    /// TLS: шифрование не установилось (`tls`) или сертификат чужой (`cert`).
    Encrypted {
        failure: &'static str,
        detail: String,
    },
}

/// Вид сбоя по управляющей ошибке (python _failure_for).
fn failure_for(error: &NetError) -> &'static str {
    match error {
        NetError::Cancelled => FAILURE_CANCELLED,
        NetError::ConnectionClosed => FAILURE_CLOSED,
        NetError::DnsWire(_) => FAILURE_MALFORMED,
        // python: класс ConnectionRefusedError → refused; Reset/Aborted/
        // BrokenPipe → reset; socket.timeout → timeout; прочее — other.
        NetError::Io(io_error) => classify_os_error(io_error),
        NetError::Deadline => FAILURE_TIMEOUT,
        NetError::Encrypted { failure, .. } => failure,
    }
}

/// Человеческий текст ошибки (python «str(exc) or type(exc).__name__»).
fn error_detail(error: &NetError) -> String {
    match error {
        NetError::Cancelled => String::new(),
        NetError::ConnectionClosed => "сервер закрыл соединение".to_string(),
        NetError::DnsWire(message) => message.clone(),
        // str(OSError) у python всегда непустой, «как класс» не срабатывает.
        NetError::Io(io_error) => io_error.to_string(),
        // socket.timeout под общий лимит попадает в ранний return без detail.
        NetError::Deadline => String::new(),
        NetError::Encrypted { detail, .. } => detail.clone(),
    }
}

pub fn failed(transport: &str, error: &NetError, cancel: Option<&SocketCancel>) -> DnsQueryResult {
    // Отмена прерывает чтение обычной сетевой ошибкой: без этого «Стоп»
    // выглядел бы сбросом соединения.
    let interrupted = cancel.map(SocketCancel::cancelled).unwrap_or(false);
    let failure = if interrupted {
        FAILURE_CANCELLED
    } else {
        failure_for(error)
    };
    if failure == FAILURE_TIMEOUT {
        return DnsQueryResult {
            status: STATUS_TIMEOUT.to_string(),
            transport: transport.to_string(),
            failure: FAILURE_TIMEOUT.to_string(),
            ..DnsQueryResult::default()
        };
    }
    let detail = if failure == FAILURE_CANCELLED {
        String::new()
    } else {
        error_detail(error)
    };
    DnsQueryResult {
        status: STATUS_ERROR.to_string(),
        transport: transport.to_string(),
        failure: failure.to_string(),
        detail,
        ..DnsQueryResult::default()
    }
}

pub fn answered(transport: &str, message: DnsMessage, started: &Instant) -> DnsQueryResult {
    let rcode_accepted = message.rcode == RCODE_OK || message.rcode == RCODE_NXDOMAIN;
    DnsQueryResult {
        status: status_for(&message),
        failure: String::new(),
        rcode: Some(message.rcode),
        records: message.answers.clone(),
        elapsed_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
        detail: if rcode_accepted {
            String::new()
        } else {
            format!("rcode {}", message.rcode)
        },
        transport: transport.to_string(),
        truncated: message.truncated,
        authoritative: message.authoritative,
        authority_count: message.authority_count,
    }
}

pub(crate) fn status_for(message: &DnsMessage) -> String {
    if message.rcode == RCODE_NXDOMAIN {
        return STATUS_NXDOMAIN.to_string();
    }
    if message.rcode != RCODE_OK {
        return STATUS_REFUSED.to_string();
    }
    if message.answers.is_empty() {
        STATUS_EMPTY.to_string()
    } else {
        STATUS_OK.to_string()
    }
}

/// Проверка адреса: должен быть IP (python _family / ip_address).
/// Строка ошибки — как у python ipaddress, чтобы совпадали detail.
pub fn parse_server_ip(server: &str) -> Result<IpAddr, NetError> {
    server.parse::<IpAddr>().map_err(|_| {
        NetError::DnsWire(format!(
            "'{server}' does not appear to be an IPv4 or IPv6 address"
        ))
    })
}

/// Общий предел времени на запрос: каждый шаг получает только остаток
/// (python _Deadline.remaining() поднимает socket.timeout).
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    until: Instant,
}

impl Deadline {
    pub fn new(timeout_s: f64) -> Self {
        Self {
            until: Instant::now() + Duration::from_secs_f64(timeout_s.max(0.0)),
        }
    }

    pub fn remaining(&self) -> Result<Duration, NetError> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(NetError::Deadline);
        }
        Ok(left)
    }
}

/// Отрезок ожидания для std: не больше остатка, но и не ноль
/// (std не любит нулевой read timeout).
fn wait_slice(remaining: Duration) -> Duration {
    remaining
        .min(Duration::from_millis(200))
        .max(Duration::from_millis(1))
}

fn query_id_random() -> u16 {
    // os.urandom(2) у python; std без unsafe = лёгкий псевдослучайный id:
    // время + счётчик; анти-спуфинг здесь не цель, нужен только разброс.
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    nanos ^ COUNTER.fetch_add(0x9E37, Ordering::Relaxed)
}

/// Подготовка: адрес и пакет запроса (python _prepare).
pub fn prepare_query(
    server: &str,
    name: &str,
    rtype: u16,
    transport: &str,
) -> Result<(u16, Vec<u8>), DnsQueryResult> {
    if let Err(error) = parse_server_ip(server) {
        // python: except (ValueError, DnsWireError): failure=other, detail=str(exc).
        return Err(DnsQueryResult {
            status: STATUS_ERROR.to_string(),
            transport: transport.to_string(),
            failure: FAILURE_OTHER.to_string(),
            detail: error_detail(&error),
            ..DnsQueryResult::default()
        });
    }
    let query_id = query_id_random();
    match build_query(query_id, name, rtype) {
        Ok(query) => Ok((query_id, query)),
        Err(message) => Err(DnsQueryResult {
            status: STATUS_ERROR.to_string(),
            transport: transport.to_string(),
            failure: FAILURE_OTHER.to_string(),
            detail: message,
            ..DnsQueryResult::default()
        }),
    }
}

/// «Стоп» перед началом запроса (python _open track→_Cancelled).
pub fn check_not_cancelled(cancel: Option<&SocketCancel>) -> Result<(), NetError> {
    if let Some(token) = cancel {
        if token.cancelled() {
            return Err(NetError::Cancelled);
        }
    }
    Ok(())
}

/// Проверка между отрезками ожидания: «Стоп» уже нажали?
fn check_interrupt(cancel: Option<&SocketCancel>) -> Result<(), NetError> {
    check_not_cancelled(cancel)
}

fn wildcard_addrs(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(
        match ip {
            IpAddr::V4(_) => IpAddr::from([0, 0, 0, 0]),
            IpAddr::V6(_) => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        },
        port,
    )
}

/// Один запрос по UDP, без перехода на TCP.
///
/// Усечённый ответ (флаг TC) возвращается как есть, с `truncated=true`:
/// проверке способов связи важно знать, что ответил именно UDP.
pub fn query_udp(
    server: &str,
    name: &str,
    rtype: u16,
    timeout_s: f64,
    port: u16,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    let transport = TRANSPORT_UDP;
    let (query_id, query) = match prepare_query(server, name, rtype, transport) {
        Ok(prep) => prep,
        Err(result) => return result,
    };
    let ip = match parse_server_ip(server) {
        Ok(ip) => ip,
        Err(error) => return failed(transport, &error, cancel),
    };
    let started = Instant::now();
    let deadline = Deadline::new(timeout_s);
    if let Err(error) = check_not_cancelled(cancel) {
        return failed(transport, &error, cancel);
    }
    let socket = match UdpSocket::bind(wildcard_addrs(ip, 0)) {
        Ok(sock) => sock,
        Err(error) => return failed(transport, &NetError::Io(error), cancel),
    };
    finish_udp_query(
        &socket,
        SocketAddr::new(ip, port),
        &query,
        query_id,
        &deadline,
        cancel,
    )
    .map_or_else(
        // Пауза замера только на удачном ответе (как в python _answered).
        |error| udp_error(transport, &error, cancel),
        |answer| {
            let _ = &started;
            with_elapsed(answered(transport, answer, &started), &started)
        },
    )
}

/// Так Windows/Linux сообщают об отказе прямо в recvfrom (ICMP «порт закрыт»).
fn udp_error(transport: &str, error: &NetError, cancel: Option<&SocketCancel>) -> DnsQueryResult {
    // python: except ConnectionResetError здесь особый отказ — refused
    // (а при отмене — обычный путь).
    if let NetError::Io(io_error) = error {
        if matches!(
            io_error.kind(),
            ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
        ) {
            return DnsQueryResult {
                status: STATUS_ERROR.to_string(),
                transport: transport.to_string(),
                failure: FAILURE_REFUSED.to_string(),
                detail: io_error.to_string(),
                ..DnsQueryResult::default()
            };
        }
    }
    failed(transport, error, cancel)
}

/// Посылает запрос и ждёт свой ответ; None — пришёл чужой пакет, цикл идёт.
fn finish_udp_query(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    query: &[u8],
    query_id: u16,
    deadline: &Deadline,
    cancel: Option<&SocketCancel>,
) -> Result<DnsMessage, NetError> {
    if let Err(error) = check_not_cancelled(cancel) {
        return Err(error);
    }
    if let Err(error) = socket.send_to(query, server_addr) {
        return Err(NetError::Io(error));
    }
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = deadline.remaining()?;
        // Проверка отмены и внутри отрезка: срез маленький, «Стоп» бодрый.
        if let Err(error) = check_interrupt(cancel) {
            return Err(error);
        }
        socket
            .set_read_timeout(Some(wait_slice(remaining)))
            .map_err(NetError::Io)?;
        match socket.recv_from(&mut buffer) {
            Ok((size, _addr)) => {
                let message = match parse_response(&buffer[..size]) {
                    Ok(message) => message,
                    Err(_) => continue,
                };
                // Чужой или опоздавший пакет: ждём свой, пока есть время.
                if message.query_id == query_id && message.is_response {
                    return Ok(message);
                }
            }
            Err(error) => match error.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
                    if let Err(cancel_error) = check_interrupt(cancel) {
                        return Err(cancel_error);
                    }
                    // Прошёл отрезок: общий лимит проверит следующий remaining().
                    deadline.remaining()?;
                }
                _ => return Err(NetError::Io(error)),
            },
        }
    }
}

/// Вычитывает ровно `size` байт или объявляет соединение закрытым (python _recv_exact).
pub(crate) fn recv_exact<S: Read>(
    stream: &mut S,
    size: usize,
    deadline: &Deadline,
    cancel: Option<&SocketCancel>,
) -> Result<Vec<u8>, NetError> {
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        if let Err(error) = check_interrupt(cancel) {
            return Err(error);
        }
        let mut chunk = [0u8; 4096];
        let want = (size - data.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return Err(NetError::ConnectionClosed),
            Ok(got) => data.extend_from_slice(&chunk[..got]),
            Err(error) => match error.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
                    if let Err(cancel_error) = check_interrupt(cancel) {
                        return Err(cancel_error);
                    }
                    deadline.remaining()?;
                }
                _ => return Err(NetError::Io(error)),
            },
        }
    }
    Ok(data)
}

/// Запрос и ответ с двухбайтовой длиной впереди: так DNS идёт по TCP и по TLS.
pub fn exchange_framed<S: Read + Write>(
    stream: &mut S,
    query: &[u8],
    query_id: u16,
    deadline: &Deadline,
    cancel: Option<&SocketCancel>,
) -> Result<DnsMessage, NetError> {
    let mut packet = Vec::with_capacity(query.len() + 2);
    packet.extend_from_slice(&(query.len() as u16).to_be_bytes());
    packet.extend_from_slice(query);
    // Отдельные write: соединение может принять не всё за раз.
    let mut sent = 0;
    while sent < packet.len() {
        if let Err(error) = check_interrupt(cancel) {
            return Err(error);
        }
        match stream.write(&packet[sent..]) {
            Ok(n) => sent += n,
            Err(error) => match error.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
                    deadline.remaining()?;
                }
                _ => return Err(NetError::Io(error)),
            },
        }
    }
    let size_header = recv_exact(stream, 2, deadline, cancel)?;
    let size = u16::from_be_bytes([size_header[0], size_header[1]]) as usize;
    let message =
        parse_response(&recv_exact(stream, size, deadline, cancel)?).map_err(NetError::DnsWire)?;
    if message.query_id != query_id || !message.is_response {
        return Err(NetError::DnsWire("ответ не на наш запрос".to_string()));
    }
    Ok(message)
}

/// Один запрос по TCP (порт 53), без UDP.
///
/// На Windows отказ «порт закрыт» приходит не сразу: система сама повторяет
/// попытку соединения около двух секунд. При меньшем `timeout_s` закрытый
/// порт выглядит как молчание.
pub fn query_tcp(
    server: &str,
    name: &str,
    rtype: u16,
    timeout_s: f64,
    port: u16,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    let transport = TRANSPORT_TCP;
    let (query_id, query) = match prepare_query(server, name, rtype, transport) {
        Ok(prep) => prep,
        Err(result) => return result,
    };
    let ip = match parse_server_ip(server) {
        Ok(ip) => ip,
        Err(error) => return failed(transport, &error, cancel),
    };
    let started = Instant::now();
    let deadline = Deadline::new(timeout_s);
    if let Err(error) = check_not_cancelled(cancel) {
        return failed(transport, &error, cancel);
    }
    let mut stream = match TcpStream::connect_timeout(
        &SocketAddr::new(ip, port),
        deadline.remaining().unwrap_or_default(),
    ) {
        Ok(stream) => stream,
        Err(error) => return failed(transport, &NetError::Io(error), cancel),
    };
    // Потолок времени для одного блокирующего шага чтения/записи;
    // общие отрезки отсекает deadline в циклах.
    if let Ok(remaining) = deadline.remaining() {
        let _ = stream.set_read_timeout(Some(wait_slice(remaining)));
        let _ = stream.set_write_timeout(Some(wait_slice(remaining)));
    }
    exchange_framed(&mut stream, &query, query_id, &deadline, cancel).map_or_else(
        |error| failed(transport, &error, cancel),
        |message| with_elapsed(answered(transport, message, &started), &started),
    )
}

/// Успешные замеры ходят с elapsed_ms; ошибки — без него (python-паритет).
fn with_elapsed(mut result: DnsQueryResult, started: &Instant) -> DnsQueryResult {
    result.elapsed_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
    result
}

/// Запрос так, как его делает обычная программа: UDP, а при усечённом
/// ответе — TCP (python query_server).
///
/// Для проверки самих способов связи есть `query_udp` и `query_tcp`: здесь
/// важен ответ сервера, а не то, каким путём он пришёл.
pub fn query_server(
    server: &str,
    name: &str,
    rtype: u16,
    timeout_s: f64,
    attempts: usize,
    port: u16,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    let mut last = DnsQueryResult {
        status: STATUS_TIMEOUT.to_string(),
        transport: TRANSPORT_UDP.to_string(),
        failure: FAILURE_TIMEOUT.to_string(),
        ..DnsQueryResult::default()
    };
    for _attempt in 0..attempts.max(1) {
        // Время считается от удачной попытки: повтор после молчания — не скорость сервера.
        let mut result = query_udp(server, name, rtype, timeout_s, port, cancel);
        if result.answered() && result.truncated {
            result = query_tcp(server, name, rtype, timeout_s, port, cancel);
        }
        if result.answered()
            || result.failure == FAILURE_CANCELLED
            || result.failure == FAILURE_OTHER
        {
            return result;
        }
        if result.status == STATUS_ERROR || last.status != STATUS_ERROR {
            last = result;
        }
    }
    last
}
