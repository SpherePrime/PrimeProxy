//! WebSocket-клиент для маршрутов Telegram: чистая часть.
//!
//! Порт `telegram_proxy/proxy/ws.py` без сети. Upgrade написан вручную в
//! python-версии, потому что фронтам Cloudflare нужен повтор запроса на том же
//! TLS-соединении (503/429 без тела, повтор через ~25 мс проходит). Здесь —
//! цели подключения, кадры, запрос upgrade и разбор ответа; само подключение
//! (TCP/TLS) остаётся на стороне вызывающего кода.

use crate::crypto::{base64_encode, sha1};

pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const TCP_CONNECT_TIMEOUT: f64 = 2.5;
pub const UPGRADE_TIMEOUT: f64 = 8.0;
pub const BUSY_RETRIES: usize = 8;
pub const BUSY_RETRY_DELAY: f64 = 0.025;
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const MAX_HEADER: usize = 32 * 1024;

pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
pub const ORIGIN: &str = "https://web.telegram.org";

pub const STAGE_TCP: &str = "tcp";
pub const STAGE_TLS: &str = "tls";
pub const STAGE_UPGRADE: &str = "upgrade";

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Куда подключаться: адрес для TCP, имя для TLS/Host и путь.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsTarget {
    pub connect_host: String,
    pub sni: String,
    pub path: String,
    pub port: i64,
}

impl Default for WsTarget {
    fn default() -> Self {
        Self {
            connect_host: String::new(),
            sni: String::new(),
            path: "/apiws".to_string(),
            port: 443,
        }
    }
}

/// Ошибка подключения WebSocket: `stage` — на каком этапе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsConnectError {
    pub stage: String,
    pub message: String,
    pub status_code: i64,
}

impl WsConnectError {
    /// Ошибка с кодом HTTP (0 — кода нет).
    #[must_use]
    pub fn new(stage: &str, message: impl Into<String>, status_code: i64) -> Self {
        Self {
            stage: stage.to_string(),
            message: message.into(),
            status_code,
        }
    }

    /// TCP-этап — единственный, где соединение даже не открылось.
    #[must_use]
    pub fn tcp_reached(&self) -> bool {
        self.stage != STAGE_TCP
    }
}

impl std::fmt::Display for WsConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Ошибка протокола WebSocket после upgrade: текст — для журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsProtocolError(pub String);

impl std::fmt::Display for WsProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WsConnectError {}
impl std::error::Error for WsProtocolError {}

/// Кадр от клиента: FIN, маска обязательна.
#[must_use]
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let size = payload.len();
    let mut result = Vec::with_capacity(size + 14);
    result.push(0x80 | (opcode & 0x0F));
    if size < 126 {
        result.push(0x80 | size as u8);
    } else if size < 65536 {
        result.push(0x80 | 126);
        result.extend_from_slice(&(size as u16).to_be_bytes());
    } else {
        result.push(0x80 | 127);
        result.extend_from_slice(&(size as u64).to_be_bytes());
    }
    let mut key = [0_u8; 4];
    fastrand::fill(&mut key);
    result.extend_from_slice(&key);
    for (index, byte) in payload.iter().enumerate() {
        result.push(byte ^ key[index % 4]);
    }
    result
}

/// Ожидаемое значение Sec-WebSocket-Accept для ключа.
#[must_use]
pub fn accept_value(key: &str) -> String {
    base64_encode(&sha1(&[key.as_bytes(), WS_GUID]))
}

/// Запрос upgrade на уже открытом TLS-соединении.
#[must_use]
pub fn build_request(target: &WsTarget, key: &str) -> Vec<u8> {
    let host = if target.port == 443 {
        target.sni.clone()
    } else {
        format!("{}:{}", target.sni, target.port)
    };
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\
         Origin: {}\r\nUser-Agent: {}\r\n\r\n",
        target.path, host, key, ORIGIN, USER_AGENT
    )
    .into_bytes()
}

/// Разобранный заголовок ответа upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: i64,
    pub status_line: String,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Значение заголовка в нижнем регистре имени.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Разбор головы ответа HTTP (до `\r\n\r\n`).
///
/// # Errors
/// Возвращает [`WsConnectError`] этапа upgrade: не HTTP или слишком длинно.
pub fn parse_response_head(raw: &[u8]) -> Result<ResponseHead, WsConnectError> {
    if raw.len() > MAX_HEADER {
        return Err(WsConnectError::new(
            STAGE_UPGRADE,
            "слишком длинный ответ upgrade",
            0,
        ));
    }
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_string();
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 || !parts[0].starts_with("HTTP/1.") {
        return Err(WsConnectError::new(
            STAGE_UPGRADE,
            format!("не HTTP-ответ: {:?}", short(&status_line)),
            0,
        ));
    }
    let Ok(status) = parts[1].parse::<i64>() else {
        return Err(WsConnectError::new(
            STAGE_UPGRADE,
            format!("не HTTP-ответ: {:?}", short(&status_line)),
            0,
        ));
    };
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_string()));
        }
    }
    Ok(ResponseHead {
        status,
        status_line,
        headers,
    })
}

fn short(text: &str) -> String {
    text.chars().take(80).collect()
}

/// Фронт «занят»: 503/429 без тела и без закрытия соединения.
#[must_use]
pub fn is_busy_retryable(status: i64, headers: &ResponseHead) -> bool {
    if status != 429 && status != 503 {
        return false;
    }
    if headers
        .header("connection")
        .is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return false;
    }
    headers
        .header("content-length")
        .map_or(true, |value| value == "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_value_matches_python() {
        // python3 -c "
        // import base64, hashlib
        // key='dGhlIHNhbXBsZSBub25jZQ=='
        // print(base64.b64encode(hashlib.sha1(key.encode()+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()).decode())"
        assert_eq!(
            accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frame_is_masked_and_roundtrips() {
        let frame = encode_frame(OP_BINARY, b"hello world");
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1] & 0x80, 0x80, "маска обязательна");
        assert_eq!(frame[1] & 0x7F, 11);
        let key = &frame[2..6];
        let payload: Vec<u8> = frame[6..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % 4])
            .collect();
        assert_eq!(payload, b"hello world");
        // Крупный кадр уходит в 16-битной длине (после байта с битом маски).
        let big = encode_frame(OP_BINARY, &vec![0_u8; 1000]);
        assert_eq!(&big[2..4], &1000_u16.to_be_bytes());
        let huge = encode_frame(OP_PING, &vec![0_u8; 70000]);
        assert_eq!(&huge[2..10], &70_000_u64.to_be_bytes());
    }

    #[test]
    fn request_contains_required_headers() {
        let target = WsTarget {
            connect_host: "127.0.0.1".into(),
            sni: "kws2.web.telegram.org".into(),
            path: "/apiws".into(),
            port: 8443,
        };
        let request = String::from_utf8(build_request(&target, "KEY")).unwrap();
        assert!(request.starts_with("GET /apiws HTTP/1.1\r\n"));
        assert!(request.contains("Host: kws2.web.telegram.org:8443\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: KEY\r\n"));
        assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(request.contains("Sec-WebSocket-Protocol: binary\r\n"));
        assert!(request.contains(&format!("Origin: {ORIGIN}\r\n")));
        assert!(request.ends_with("\r\n\r\n"));
        // Порт 443 не пишется в Host.
        let mut default_port = target.clone();
        default_port.port = 443;
        let request = String::from_utf8(build_request(&default_port, "KEY")).unwrap();
        assert!(request.contains("Host: kws2.web.telegram.org\r\n"));
    }

    #[test]
    fn response_head_parses_status_and_headers() {
        let head = parse_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: abc\r\n\r\n",
        )
        .unwrap();
        assert_eq!(head.status, 101);
        assert_eq!(head.header("upgrade"), Some("websocket"));
        assert_eq!(head.header("sec-websocket-accept"), Some("abc"));

        let error = parse_response_head(b"NOT HTTP\r\n\r\n").unwrap_err();
        assert_eq!(error.stage, STAGE_UPGRADE);
        let error = parse_response_head(b"HTTP/1.1 oops\r\n\r\n").unwrap_err();
        assert_eq!(error.stage, STAGE_UPGRADE);
        assert!(error.message.contains("не HTTP-ответ"));
    }

    #[test]
    fn busy_front_is_retryable_only_without_body() {
        let busy = ResponseHead {
            status: 503,
            status_line: "HTTP/1.1 503".into(),
            headers: vec![
                ("content-length".into(), "0".into()),
                ("connection".into(), "keep-alive".into()),
            ],
        };
        assert!(is_busy_retryable(503, &busy));
        assert!(is_busy_retryable(429, &busy));
        let mut closing = busy.clone();
        closing.headers[1].1 = "close".into();
        assert!(!is_busy_retryable(503, &closing));
        let mut with_body = busy.clone();
        with_body.headers[0].1 = "12".into();
        assert!(!is_busy_retryable(503, &with_body));
        assert!(!is_busy_retryable(200, &busy));
    }

    #[test]
    fn stage_constants_and_tcp_reached() {
        let tcp_error = WsConnectError::new(STAGE_TCP, "refused", 0);
        assert!(!tcp_error.tcp_reached());
        let upgrade_error = WsConnectError::new(STAGE_UPGRADE, "HTTP 503", 503);
        assert!(upgrade_error.tcp_reached());
        assert_eq!(upgrade_error.status_code, 503);
    }
}
