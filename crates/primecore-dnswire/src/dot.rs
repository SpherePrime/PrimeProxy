//! Шифрованные запросы DNS поверх TLS — `utils/dns_wire.py::query_dot`
//! (RFC 7858, порт 853). DoH — следом; руки TLS и обмен здесь уже те же.
//!
//! Отличия от python: контекст TLS у rustls (корневые — из webpki-roots,
//! аналог certifi); «Стоп» не закрывает сокет, а прерывается проверкой
//! признака отмены между отрезками ожидания (см. net.rs).

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use primecore_socketcancel::SocketCancel;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};

use crate::net::{answered, check_not_cancelled, failed, parse_server_ip, prepare_query, Deadline, NetError};
use crate::{DnsQueryResult, ENCRYPTED_TIMEOUT_S, TRANSPORT_DOT};

/// rustls-ошибка → вид сбоя: чужой сертификат — cert, остальное — tls.
fn tls_net_error(error: &rustls::Error) -> NetError {
    let (failure, detail) = match error {
        rustls::Error::InvalidCertificate(message) => ("cert", format!("InvalidCertificate: {message}")),
        _ => ("tls", error.to_string()),
    };
    NetError::Encrypted { failure, detail }
}

/// io::Error от rustls-потока вскрываем: внутри может быть rustls::Error.
fn tls_io_error(error: std::io::Error) -> NetError {
    let inner = error.get_ref().and_then(|value| value.downcast_ref::<rustls::Error>());
    if let Some(rust_error) = inner {
        return tls_net_error(rust_error);
    }
    if error.kind() == ErrorKind::WouldBlock {
        return NetError::Deadline;
    }
    NetError::Io(error)
}

/// Контекст с проверкой сертификата: один на процесс, корневые — из
/// webpki-roots (python берёт certifi). ALPN для DoT не нужен.
fn tls_config() -> &'static Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        let _ = roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
}

/// Имя SNI/SAN: у python — server_hostname (IP оборачивается в IP-имя).
fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    // IP-адрес — как есть; прочее — DNS-имя (check по сертификату).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip)));
    }
    ServerName::try_from(host.to_string()).map_err(|_| {
        format!("{host} is not a valid DNS name")
    })
}

/// Шифрованный запрос DNS поверх TLS, порт 853.
///
/// Подключение идёт по адресу `server`, а сертификат проверяется для
/// имени `tls_host` (например, `dns.google`). Без имени сертификат
/// проверяется по самому адресу: так умеют только серверы, у которых
/// адрес вписан в сертификат.
pub fn query_dot(
    server: &str,
    name: &str,
    rtype: u16,
    tls_host: &str,
    timeout_s: f64,
    port: u16,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    let transport = TRANSPORT_DOT;
    let timeout_s = if timeout_s > 0.0 { timeout_s } else { ENCRYPTED_TIMEOUT_S };
    let (query_id, query) = match prepare_query(server, name, rtype, transport) {
        Ok(prepared) => prepared,
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
    // У python: connect по адресу, сертификат проверяется для имени.
    let host = if tls_host.is_empty() { server } else { tls_host };
    let identity = match server_name(host) {
        Ok(identity) => identity,
        Err(detail) => {
            return failed(transport, &NetError::Encrypted { failure: "tls", detail }, cancel);
        }
    };
    let raw = match TcpStream::connect_timeout(
        &SocketAddr::new(ip, port),
        deadline.remaining().unwrap_or_default(),
    ) {
        Ok(raw) => raw,
        Err(error) => return failed(transport, &NetError::Io(error), cancel),
    };
    // Потолок одного шага чтения/записи; общий deadline идёт поверх.
    if let Ok(remaining) = deadline.remaining() {
        let _ = raw.set_read_timeout(Some(std::cmp::min(remaining, std::time::Duration::from_millis(200))));
        let _ = raw.set_write_timeout(Some(std::cmp::min(remaining, std::time::Duration::from_millis(200))));
    }
    if let Err(error) = check_not_cancelled(cancel) {
        return failed(transport, &error, cancel);
    }
    let connection = match ClientConnection::new(Arc::clone(tls_config()), identity) {
        Ok(connection) => connection,
        Err(error) => return failed(transport, &tls_net_error(&error), cancel),
    };
    let mut tls_stream = StreamOwned::new(connection, raw);
    let result = match crate::net::exchange_framed(&mut tls_stream, &query, query_id, &deadline, cancel) {
        Ok(message) => answered(transport, message, &started),
        Err(net_error) => failed(transport, &coerce_tls(net_error), cancel),
    };
    result
}

/// io-ошибки rustls-потока приводим к видам tls/cert, как это делает python
/// (у него поднимается ssl.* исключение и classify находит CERT/TLS).
fn coerce_tls(net_error: NetError) -> NetError {
    match net_error {
        NetError::Io(io_error) => tls_io_error(io_error),
        other => other,
    }
}
