//! Шифрованные запросы DNS поверх HTTPS — `utils/dns_wire.py::query_doh`
//! (RFC 8484, порт 443, путь `/dns-query`).
//!
//! Отличия от python: HTTP/2 и HTTP/1.1 ведёт reqwest (rustls) вместо
//! ручного http2_post; «Стоп» из другого потока прерывает ожидание
//! результата, а сам HTTP-запрос (в потоке-потомке) доигрывает и погибает
//! безвозвратно. Подключение прямо по адресу `server`, системный DNS не
//! участвует — как у python.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;

use crate::net::{answered, failed, parse_server_ip, prepare_query, Deadline, NetError};
use crate::{DnsQueryResult, ENCRYPTED_TIMEOUT_S, TRANSPORT_DOH};

/// DoH-тип содержимого (python _DOH_CONTENT_TYPE).
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// Ошибки HTTP-поста (аналог python исключений http.client/http2_post):
/// вид сбоя выбирает `failure_of_post`.
enum PostError {
    /// HTTP != 200: failure=http, detail «HTTP {код}».
    Status(u16),
    /// Сбой сети/TLS/HTTP-протокола: деталь — текст reqwest.
    Network(String),
}

/// Вид сбоя и деталь по ошибке поста (аналог python-ветки except).
fn failure_of_post(error: &PostError) -> (&'static str, String) {
    match error {
        PostError::Status(code) => ("http", format!("HTTP {code}")),
        PostError::Network(detail) => post_network_failure(detail),
    }
}

/// ход reqwest-ошибки по цепочке источников: TLS → cert/tls, код ОС →
/// refused/unreachable/…, тайм-аут → timeout, прочее → http.
pub fn post_network_failure(detail: &str) -> (&'static str, String) {
    static HINTS: [(&str, &str); 6] = [
        ("certificate verify failed", "cert"),
        ("CertError", "cert"),
        ("InvalidCertificate", "cert"),
        ("invalid peer certificate", "cert"),
        ("error reading a body", "malformed"),
        ("timed out", "timeout"),
    ];
    for (needle, failure) in HINTS {
        if detail.contains(needle) {
            return (failure, detail.to_string());
        }
    }
    if detail.contains("Connection refused") {
        return ("refused", detail.to_string());
    }
    if detail.contains("timeout") {
        return ("timeout", detail.to_string());
    }
    // Без кода ОС и узнаваемых маркеров — python бы поднял HTTPException:
    // протокол/http-слой дал сбой.
    ("http", detail.to_string())
}

/// Родитель ждёт результат частями: запрос целиком в отдельном потоке.
fn wait_result(
    receiver: mpsc::Receiver<Result<Vec<u8>, PostError>>,
    cancel: Option<&SocketCancel>,
    deadline: &Deadline,
) -> Result<Vec<u8>, NetError> {
    loop {
        let remaining = deadline.remaining()?;
        let slice = remaining
            .min(Duration::from_millis(200))
            .max(Duration::from_millis(1));
        if cancel.map(SocketCancel::cancelled).unwrap_or(false) {
            return Err(NetError::Cancelled);
        }
        match receiver.recv_timeout(slice) {
            Ok(Ok(body)) => return Ok(body),
            Ok(Err(post_error)) => {
                let (failure, detail) = failure_of_post(&post_error);
                return Err(NetError::Encrypted { failure, detail });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Отрезок прошёл: общий deadline отдаст "" или Cancelled.
                deadline.remaining()?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Поток-потомок должен был отдать результат; упал без него.
                return Err(NetError::ConnectionClosed);
            }
        }
    }
}

/// Рабочий поток: строит блокирующий reqwest-клиент, шлёт POST, ждёт тело.
///
/// HTTP-продуктивный вызов прервать нечем (без unsafe): при отмене зёрна
/// погибают сами; главное — что «Стоп» останавливает ожидание у родителя.
fn spawn_post(
    address: SocketAddr,
    url: String,
    host: String,
    query: Vec<u8>,
    timeout: f64,
) -> (JoinHandle<()>, mpsc::Receiver<Result<Vec<u8>, PostError>>) {
    let (sender, receiver) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        let _ = started;
        let client = reqwest::blocking::Client::builder()
            // Подключение прямо по адресу server (система на DNS не смотрит).
            .resolve(&host, address)
            .timeout(Duration::from_secs_f64(timeout.max(0.0)))
            .connect_timeout(Duration::from_secs_f64(timeout.max(0.0)))
            .build();
        let client = match client {
            Ok(client) => client,
            Err(error) => {
                let _ = sender.send(Err(PostError::Network(error.to_string())));
                return;
            }
        };
        let response = client
            .post(&url)
            .header("content-type", DOH_CONTENT_TYPE)
            .header("accept", DOH_CONTENT_TYPE)
            .body(query)
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let _ = sender.send(Err(PostError::Network(error.to_string())));
                return;
            }
        };
        let status = response.status();
        if status.as_u16() != 200 {
            let _ = sender.send(Err(PostError::Status(status.as_u16())));
            return;
        }
        match response.bytes() {
            Ok(bytes) => {
                let _ = sender.send(Ok(bytes.to_vec()));
            }
            Err(error) => {
                let _ = sender.send(Err(PostError::Network(error.to_string())));
            }
        }
    });
    (handle, receiver)
}

/// Хост для заголовка и SNI: IPv6 держится в скобках (python host_header).
fn host_authority(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port != 443 {
        format!("{host}:{port}")
    } else {
        host
    }
}

/// Шифрованный запрос DNS поверх HTTPS (RFC 8484).
///
/// Подключение идёт прямо по адресу `server`: сертификат проверяется для
/// `tls_host`, а без него — по самому адресу. Такой ответ провайдер не
/// может незаметно подменить.
pub fn query_doh(
    server: &str,
    name: &str,
    rtype: u16,
    tls_host: &str,
    port: u16,
    path: &str,
    timeout_s: f64,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    let transport = TRANSPORT_DOH;
    let timeout_s = if timeout_s > 0.0 {
        timeout_s
    } else {
        ENCRYPTED_TIMEOUT_S
    };
    let (query_id, query) = match prepare_query(server, name, rtype, transport) {
        Ok(prepared) => prepared,
        Err(result) => return result,
    };
    let _ = query_id;
    let ip = match parse_server_ip(server) {
        Ok(ip) => ip,
        Err(error) => return failed(transport, &error, cancel),
    };
    let started = Instant::now();
    let deadline = Deadline::new(timeout_s);
    if let Err(error) = crate::net::check_not_cancelled(cancel) {
        return failed(transport, &error, cancel);
    }
    let host = if tls_host.is_empty() {
        server
    } else {
        tls_host
    };
    let authority = host_authority(host, port);
    let dns_path = if path.is_empty() { "/dns-query" } else { path };
    let url = format!("https://{authority}{dns_path}");
    let (handle, receiver) = spawn_post(
        SocketAddr::new(ip, port),
        url,
        host.to_string(),
        query.clone(),
        timeout_s,
    );
    let body = match wait_result(receiver, cancel, &deadline) {
        Ok(body) => body,
        Err(net_error) => return failed(transport, &net_error, cancel),
    };
    // Как в python: query_id DoH не проверяется, важен только признак ответа.
    let message = match crate::parse_response(&body) {
        Ok(message) => message,
        Err(detail) => {
            return failed(transport, &NetError::DnsWire(detail), cancel);
        }
    };
    if !message.is_response {
        return failed(
            transport,
            &NetError::DnsWire("ответ не на наш запрос".to_string()),
            cancel,
        );
    }
    answered(transport, message, &started)
}
