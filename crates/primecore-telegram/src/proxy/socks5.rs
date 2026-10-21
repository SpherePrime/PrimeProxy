//! SOCKS5 (RFC 1928) ровно в том объёме, что нужен Telegram.
//!
//! Порт чистой части `telegram_proxy/proxy/socks5.py`. Сервер (вход прокси):
//! без пароля, CONNECT и UDP ASSOCIATE, адреса IPv4/IPv6/домен. Клиент
//! (внешний SOCKS5): CONNECT и UDP ASSOCIATE, вход без пароля или по логину и
//! паролю (RFC 1929), по желанию поверх TLS. Сам обмен с сокетом идёт через
//! трейт [`Socks5Io`] — крейт сокетов не открывает.

pub const SOCKS_VER: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_USERPASS: u8 = 0x02;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Ошибка SOCKS5-протокола: тексты совпадают с python-версией.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Error {
    /// Протокол нарушен (сервером или клиентом).
    Protocol(String),
    /// Живой сервер отклонил команду или цель.
    Reply {
        command_name: String,
        reply_code: u8,
    },
}

impl Socks5Error {
    /// Ошибка протокола с сообщением.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// Текст ошибки (как `str(exception)` в python).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Protocol(text) => text.clone(),
            Self::Reply {
                command_name,
                reply_code,
            } => format!("Upstream proxy {command_name} failed (REP=0x{reply_code:02X})"),
        }
    }
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for Socks5Error {}

/// Ошибка обмена через поток: чтение, запись или закрытие.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5FlowError {
    /// Конец потока: ответ оборвался.
    Incomplete,
    /// Ошибка ввода-вывода или таймаут (текст от замыкания сети).
    Io(String),
}

/// Минимальный поток для рукопожатия SOCKS5.
pub trait Socks5Io {
    /// Читает ровно `len` байт или возвращает ошибку.
    ///
    /// # Errors
    /// [`Socks5FlowError`] при обрыве или ошибке ввода-вывода.
    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, Socks5FlowError>;

    /// Записывает данные целиком.
    ///
    /// # Errors
    /// [`Socks5FlowError`] при ошибке ввода-вывода.
    fn write_all(&mut self, data: &[u8]) -> Result<(), Socks5FlowError>;
}

/// Запрос UDP ASSOCIATE от клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAssociateRequest {
    pub client_host: String,
    pub client_port: u16,
}

/// Итог рукопожатия сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5ServerResult {
    /// Клиент просит CONNECT к цели.
    Connect { host: String, port: u16 },
    /// Клиент просит UDP ASSOCIATE (нужен зарегистрированный обработчик).
    UdpAssociate(UdpAssociateRequest),
}

/// Привязка UDP-релея для ответа клиенту.
pub type UdpBind = dyn Fn() -> Result<(String, u16), String>;

/// Рукопожатие сервера (вход прокси).
///
/// # Errors
/// [`Socks5Error`] — нарушение протокола или отклонённая команда.
pub fn handshake(
    stream: &mut dyn Socks5Io,
    allow_udp_associate: bool,
    on_udp_associate: Option<&UdpBind>,
) -> Result<Socks5ServerResult, Socks5Error> {
    // --- фаза 1: приветствие ---
    let header = stream
        .read_exact(2)
        .map_err(|_| Socks5Error::protocol("handshake interrupted"))?;
    if header[0] != SOCKS_VER {
        return Err(Socks5Error::protocol(format!(
            "Bad SOCKS version: {}",
            header[0]
        )));
    }
    let methods = stream
        .read_exact(header[1] as usize)
        .map_err(|_| Socks5Error::protocol("handshake interrupted"))?;
    if !methods.contains(&AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VER, 0xFF])
            .map_err(|_| Socks5Error::protocol("handshake interrupted"))?;
        return Err(Socks5Error::protocol("Client doesn't support no-auth"));
    }
    stream
        .write_all(&[SOCKS_VER, AUTH_NONE])
        .map_err(|_| Socks5Error::protocol("handshake interrupted"))?;

    // --- фаза 2: запрос ---
    let request = stream
        .read_exact(4)
        .map_err(|_| Socks5Error::protocol("handshake interrupted"))?;
    if request[0] != SOCKS_VER {
        return Err(Socks5Error::protocol(format!(
            "Bad version in request: {}",
            request[0]
        )));
    }
    let (host, port) = read_address(stream, request[3])?;

    if request[1] == CMD_UDP_ASSOCIATE && allow_udp_associate {
        let bind = match on_udp_associate {
            Some(bind) => match bind() {
                Ok((host, port)) => (host, port),
                Err(_) => {
                    let _ = send_reply(stream, REP_GENERAL_FAILURE, "0.0.0.0", 0);
                    return Err(Socks5Error::protocol("udp relay failed"));
                }
            },
            None => ("0.0.0.0".to_string(), 0),
        };
        let _ = send_reply(stream, REP_SUCCESS, &bind.0, bind.1);
        return Ok(Socks5ServerResult::UdpAssociate(UdpAssociateRequest {
            client_host: host,
            client_port: port,
        }));
    }
    if request[1] != CMD_CONNECT {
        let _ = send_reply(stream, REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0);
        return Err(Socks5Error::protocol(format!(
            "Unsupported command: {}",
            request[1]
        )));
    }
    let _ = send_reply(stream, REP_SUCCESS, "0.0.0.0", 0);
    Ok(Socks5ServerResult::Connect { host, port })
}

/// Читает адрес из потока (IPv4/домен/IPv6 + порт).
///
/// # Errors
/// [`Socks5Error`] при неизвестном ATYP или обрыве.
pub fn read_address(stream: &mut dyn Socks5Io, atyp: u8) -> Result<(String, u16), Socks5Error> {
    let host = match atyp {
        ATYP_IPV4 => {
            let raw = stream
                .read_exact(4)
                .map_err(|_| Socks5Error::protocol("address interrupted"))?;
            raw.iter()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(".")
        }
        ATYP_DOMAIN => {
            let length = stream
                .read_exact(1)
                .map_err(|_| Socks5Error::protocol("address interrupted"))?[0]
                as usize;
            let domain = stream
                .read_exact(length)
                .map_err(|_| Socks5Error::protocol("address interrupted"))?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        ATYP_IPV6 => {
            let raw = stream
                .read_exact(16)
                .map_err(|_| Socks5Error::protocol("address interrupted"))?;
            format_ipv6(&raw)
        }
        other => return Err(Socks5Error::protocol(format!("Unknown ATYP: {other}"))),
    };
    let raw_port = stream
        .read_exact(2)
        .map_err(|_| Socks5Error::protocol("address interrupted"))?;
    Ok((host, u16::from_be_bytes([raw_port[0], raw_port[1]])))
}

/// IPv6 в каноническом виде (как `str(IPv6Address(...))` в python).
#[must_use]
pub fn format_ipv6(bytes: &[u8]) -> String {
    let groups: Vec<String> = bytes
        .chunks(2)
        .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
        .collect();
    // Самая длинная серия нулей сжимается в ::.
    let mut best_start = 0;
    let mut best_len = 0;
    let mut start = 0;
    let mut length = 0;
    for (index, group) in groups.iter().enumerate() {
        if group == "0" {
            if length == 0 {
                start = index;
            }
            length += 1;
            if length > best_len {
                best_start = start;
                best_len = length;
            }
        } else {
            length = 0;
        }
    }
    if best_len < 2 {
        return groups.join(":");
    }
    let head = groups[..best_start].join(":");
    let tail = groups[best_start + best_len..].join(":");
    match (head.is_empty(), tail.is_empty()) {
        (true, true) => "::".into(),
        (true, false) => format!("::{tail}"),
        (false, true) => format!("{head}::"),
        (false, false) => format!("{head}::{tail}"),
    }
}

/// Кодировка адреса в пакете: тип и байты.
///
/// # Errors
/// [`Socks5Error`], если домен длиннее 255 байт.
pub fn encode_address(host: &str) -> Result<(u8, Vec<u8>), Socks5Error> {
    if let Some(address) = crate::proxy::dc_map::parse_ipv4(host) {
        return Ok((ATYP_IPV4, address.to_be_bytes().to_vec()));
    }
    if !host.contains(':') && crate::proxy::dc_map::parse_ipv6(host).is_none() {
        // Домен: ascii, не длиннее 255 байт.
        let mut encoded = vec![u8::try_from(host.len())
            .map_err(|_| Socks5Error::protocol("Domain name is too long for SOCKS5"))?];
        encoded.extend_from_slice(host.as_bytes());
        return Ok((ATYP_DOMAIN, encoded));
    }
    if let Some(address) = crate::proxy::dc_map::parse_ipv6(host) {
        return Ok((ATYP_IPV6, address.to_be_bytes().to_vec()));
    }
    Err(Socks5Error::protocol(format!("Unknown address: {host}")))
}

/// Ответ сервера с привязанным адресом.
///
/// # Errors
/// [`Socks5Error`], если адрес не кодируется.
pub fn send_reply(
    stream: &mut dyn Socks5Io,
    reply: u8,
    bind_host: &str,
    bind_port: u16,
) -> Result<(), Socks5Error> {
    let (atyp, encoded) = encode_address(bind_host)?;
    let mut packet = vec![SOCKS_VER, reply, 0x00, atyp];
    packet.extend_from_slice(&encoded);
    packet.extend_from_slice(&bind_port.to_be_bytes());
    stream
        .write_all(&packet)
        .map_err(|_| Socks5Error::protocol("reply interrupted"))
}

/// Разобранный UDP-пакет SOCKS5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub target_host: String,
    pub target_port: u16,
    pub payload: Vec<u8>,
}

/// Разбор UDP-пакета релея.
///
/// # Errors
/// [`Socks5Error`] для коротких, фрагментированных или неизвестных пакетов.
pub fn parse_udp_packet(data: &[u8]) -> Result<UdpPacket, Socks5Error> {
    if data.len() < 4 {
        return Err(Socks5Error::protocol("UDP packet is too short"));
    }
    let (rsv, frag, atyp) = (u16::from_be_bytes([data[0], data[1]]), data[2], data[3]);
    if rsv != 0 {
        return Err(Socks5Error::protocol("Bad UDP reserved field"));
    }
    if frag != 0 {
        return Err(Socks5Error::protocol(
            "Fragmented SOCKS5 UDP packets are not supported",
        ));
    }
    let mut offset = 4;
    let target_host = match atyp {
        ATYP_IPV4 => {
            if data.len() < offset + 4 + 2 {
                return Err(Socks5Error::protocol("UDP IPv4 packet is too short"));
            }
            let host = data[offset..offset + 4]
                .iter()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(".");
            offset += 4;
            host
        }
        ATYP_IPV6 => {
            if data.len() < offset + 16 + 2 {
                return Err(Socks5Error::protocol("UDP IPv6 packet is too short"));
            }
            let host = format_ipv6(&data[offset..offset + 16]);
            offset += 16;
            host
        }
        ATYP_DOMAIN => {
            if data.len() < offset + 1 {
                return Err(Socks5Error::protocol("UDP domain packet is too short"));
            }
            let domain_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + domain_len + 2 {
                return Err(Socks5Error::protocol("UDP domain packet is too short"));
            }
            let host = String::from_utf8_lossy(&data[offset..offset + domain_len]).into_owned();
            offset += domain_len;
            host
        }
        other => return Err(Socks5Error::protocol(format!("Unknown UDP ATYP: {other}"))),
    };
    if data.len() < offset + 2 {
        return Err(Socks5Error::protocol("UDP packet is too short"));
    }
    let target_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    Ok(UdpPacket {
        target_host,
        target_port,
        payload: data[offset..].to_vec(),
    })
}

/// Сборка UDP-пакета релея.
///
/// # Errors
/// [`Socks5Error`], если адрес не кодируется.
pub fn build_udp_packet(
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Socks5Error> {
    let (atyp, encoded) = encode_address(target_host)?;
    // python: struct.pack("!HBB", 0, 0, atyp) — rsv (2 байта) и frag.
    let mut packet = vec![0x00, 0x00, 0x00, atyp];
    packet.extend_from_slice(&encoded);
    packet.extend_from_slice(&target_port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Результат согласования клиента с внешним SOCKS5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamNegotiated {
    /// Согласованный метод (мог потребовать отдельного подтверждения).
    pub auth_used: bool,
}

/// Согласование методов (фаза приветствия) с внешним SOCKS5.
///
/// # Errors
/// [`Socks5Error`] — нарушение протокола или отклонённые методы.
pub fn client_negotiate(
    stream: &mut dyn Socks5Io,
    username: &str,
    password: &str,
) -> Result<UpstreamNegotiated, Socks5Error> {
    let has_creds = !username.is_empty();
    let greeting: Vec<u8> = if has_creds {
        vec![SOCKS_VER, 2, AUTH_NONE, AUTH_USERPASS]
    } else {
        vec![SOCKS_VER, 1, AUTH_NONE]
    };
    stream
        .write_all(&greeting)
        .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
    let reply = stream
        .read_exact(2)
        .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
    if reply[0] != SOCKS_VER {
        return Err(Socks5Error::protocol(format!(
            "Upstream proxy bad SOCKS version: {}",
            reply[0]
        )));
    }
    match reply[1] {
        AUTH_USERPASS => {
            if !has_creds {
                return Err(Socks5Error::protocol(
                    "Upstream proxy requires auth but no credentials provided",
                ));
            }
            let mut auth_request = vec![0x01, username.len() as u8];
            auth_request.extend_from_slice(username.as_bytes());
            auth_request.push(password.len() as u8);
            auth_request.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth_request)
                .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
            let auth_reply = stream
                .read_exact(2)
                .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
            if auth_reply[1] != 0x00 {
                return Err(Socks5Error::protocol(format!(
                    "Upstream proxy auth failed (status=0x{:02X})",
                    auth_reply[1]
                )));
            }
            Ok(UpstreamNegotiated { auth_used: true })
        }
        AUTH_NONE => Ok(UpstreamNegotiated { auth_used: false }),
        0xFF => Err(Socks5Error::protocol(
            "Upstream proxy rejected all auth methods",
        )),
        other => Err(Socks5Error::protocol(format!(
            "Upstream proxy selected unsupported method 0x{other:02X}"
        ))),
    }
}

fn upstream_io_text(error: &Socks5FlowError) -> String {
    match error {
        Socks5FlowError::Incomplete => "upstream proxy closed connection".to_string(),
        Socks5FlowError::Io(text) => text.clone(),
    }
}

/// Ответ внешнего SOCKS5 на команду: адрес в ответе.
///
/// # Errors
/// [`Socks5Error`] — неуспешный REP или нарушение протокола.
pub fn read_reply_address(
    stream: &mut dyn Socks5Io,
    command_name: &str,
) -> Result<(String, u16), Socks5Error> {
    let response = stream
        .read_exact(4)
        .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
    if response[0] != SOCKS_VER {
        return Err(Socks5Error::protocol(format!(
            "Upstream proxy bad reply version: {}",
            response[0]
        )));
    }
    if response[1] != REP_SUCCESS {
        return Err(Socks5Error::Reply {
            command_name: command_name.to_string(),
            reply_code: response[1],
        });
    }
    read_address(stream, response[3])
}

/// Запрос CONNECT к цели через уже согласованный поток.
///
/// # Errors
/// [`Socks5Error`] — нарушение протокола или отклонение сервером.
pub fn client_connect(
    stream: &mut dyn Socks5Io,
    target_host: &str,
    target_port: u16,
) -> Result<(), Socks5Error> {
    let (atyp, encoded) = encode_address(target_host)?;
    let mut request = vec![SOCKS_VER, CMD_CONNECT, 0x00, atyp];
    request.extend_from_slice(&encoded);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| Socks5Error::protocol(upstream_io_text(&error)))?;
    read_reply_address(stream, "CONNECT").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Поток-двусторонняя труба для тестов рукопожатия.
    struct Pipe {
        to_reader: std::sync::mpsc::Receiver<Vec<u8>>,
        from_writer: std::sync::mpsc::Sender<Vec<u8>>,
        buffer: Vec<u8>,
    }

    impl Socks5Io for Pipe {
        fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, Socks5FlowError> {
            while self.buffer.len() < len {
                match self
                    .to_reader
                    .recv_timeout(std::time::Duration::from_millis(200))
                {
                    Ok(data) => self.buffer.extend_from_slice(&data),
                    Err(_) => return Err(Socks5FlowError::Incomplete),
                }
            }
            let result = self.buffer[..len].to_vec();
            self.buffer.drain(..len);
            Ok(result)
        }

        fn write_all(&mut self, data: &[u8]) -> Result<(), Socks5FlowError> {
            self.from_writer
                .send(data.to_vec())
                .map_err(|_| Socks5FlowError::Io("closed".into()))
        }
    }

    /// Возвращает (запись клиентом, поток сервера, чтение ответов сервера).
    fn pipe() -> (
        std::sync::mpsc::Sender<Vec<u8>>,
        Pipe,
        std::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let (client_tx, server_rx) = std::sync::mpsc::channel();
        let (server_tx, client_rx) = std::sync::mpsc::channel();
        let server_pipe = Pipe {
            to_reader: server_rx,
            from_writer: server_tx,
            buffer: Vec::new(),
        };
        (client_tx, server_pipe, client_rx)
    }

    #[test]
    fn server_handshake_accepts_connect() {
        let (client_tx, mut server, server_rx) = pipe();
        client_tx.send(vec![0x05, 0x01, 0x00]).unwrap();
        client_tx
            .send(vec![0x05, 0x01, 0x00, 0x01, 149, 154, 167, 51, 0x01, 0xBB])
            .unwrap();
        let result = handshake(&mut server, false, None).unwrap();
        assert_eq!(
            result,
            Socks5ServerResult::Connect {
                host: "149.154.167.51".into(),
                port: 443
            }
        );
        assert_eq!(
            server_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .unwrap(),
            vec![0x05, 0x00]
        );
        // Ответ об успехе с привязкой 0.0.0.0:0.
        let reply = server_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert_eq!(reply, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn server_handshake_rejects_wrong_version() {
        let (client_tx, mut server, _server_rx) = pipe();
        client_tx.send(vec![0x04, 0x01, 0x00]).unwrap();
        let error = handshake(&mut server, false, None).unwrap_err();
        assert_eq!(error.message(), "Bad SOCKS version: 4");
    }

    #[test]
    fn server_handshake_rejects_unknown_command() {
        let (client_tx, mut server, server_rx) = pipe();
        client_tx.send(vec![0x05, 0x01, 0x00]).unwrap();
        client_tx
            .send(vec![0x05, 0x07, 0x00, 0x01, 1, 2, 3, 4, 0, 1])
            .unwrap();
        let error = handshake(&mut server, false, None).unwrap_err();
        assert_eq!(error.message(), "Unsupported command: 7");
        // Сначала ответ на выбор метода, затем отказ по команде.
        assert_eq!(
            server_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .unwrap(),
            vec![0x05, 0x00]
        );
        assert_eq!(
            server_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .unwrap(),
            vec![0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn udp_associate_needs_permission_and_returns_request() {
        let (client_tx, mut server, server_rx) = pipe();
        client_tx.send(vec![0x05, 0x01, 0x00]).unwrap();
        client_tx
            .send(vec![0x05, 0x03, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90])
            .unwrap();
        // Без разрешения — команда не поддерживается.
        let error = handshake(&mut server, false, None).unwrap_err();
        assert_eq!(error.message(), "Unsupported command: 3");

        client_tx.send(vec![0x05, 0x01, 0x00]).unwrap();
        client_tx
            .send(vec![0x05, 0x03, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90])
            .unwrap();
        let result =
            handshake(&mut server, true, Some(&|| Ok(("10.0.0.1".into(), 51820)))).unwrap();
        assert_eq!(
            result,
            Socks5ServerResult::UdpAssociate(UdpAssociateRequest {
                client_host: "192.168.0.1".into(),
                client_port: 8080,
            })
        );
        let reply = server_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert_eq!(reply, vec![0x05, 0x00]);
        let reply = server_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert_eq!(reply, vec![0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        client_tx.send(vec![0x05, 0x01, 0x00]).unwrap();
        client_tx
            .send(vec![0x05, 0x03, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90])
            .unwrap();
        let result =
            handshake(&mut server, true, Some(&|| Ok(("10.0.0.1".into(), 51820)))).unwrap();
        assert_eq!(
            result,
            Socks5ServerResult::UdpAssociate(UdpAssociateRequest {
                client_host: "192.168.0.1".into(),
                client_port: 8080,
            })
        );
        let reply = server_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert_eq!(reply, vec![0x05, 0x00]);
        let reply = server_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert_eq!(reply[..4], [0x05, 0x00, 0x00, 0x01]);
        // python3 -c "print(51820.to_bytes(2, 'big').hex())" → ca6c
        assert_eq!(&reply[4..10], &[10, 0, 0, 1, 0xCA, 0x6C]);
    }

    #[test]
    fn udp_packets_parse_and_build() {
        // python3: build_udp_packet → struct.pack("!HBB", 0, 0, atyp) + адрес + порт
        let packet = build_udp_packet("149.154.167.51", 443, b"data").unwrap();
        assert_eq!(packet[..7], [0x00, 0x00, 0x00, 0x01, 149, 154, 167]);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.target_host, "149.154.167.51");
        assert_eq!(parsed.target_port, 443);
        assert_eq!(parsed.payload, b"data");

        let domain_packet = [0, 0, 0, 3, 3, b'a', b'.', b'b', 0, 1, 5, 5].as_slice();
        let parsed = parse_udp_packet(domain_packet).unwrap();
        assert_eq!(parsed.target_host, "a.b");
        assert_eq!(parsed.payload, vec![5, 5]);

        assert!(parse_udp_packet(&[0, 0]).is_err());
        assert!(
            parse_udp_packet(&[1, 0, 1, 1, 2, 3, 4, 0, 1]).is_err(),
            "rsv != 0"
        );
        assert!(
            parse_udp_packet(&[0, 1, 1, 1, 2, 3, 4, 0, 1]).is_err(),
            "frag != 0"
        );
        assert!(
            parse_udp_packet(&[0, 0, 0, 9, 0, 1]).is_err(),
            "unknown atyp"
        );
    }

    #[test]
    fn client_negotiation_with_and_without_password() {
        // python3: Socks5Error("Upstream proxy auth failed (status=0x01)")
        struct Scripted {
            steps: Vec<ScriptStep>,
            input: Vec<u8>,
        }
        enum ScriptStep {
            Expect(Vec<u8>),
            Send(Vec<u8>),
        }
        impl Socks5Io for Scripted {
            fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, Socks5FlowError> {
                while self.input.len() < len {
                    match self.steps.remove(0) {
                        ScriptStep::Send(data) => self.input.extend_from_slice(&data),
                        ScriptStep::Expect(_) => return Err(Socks5FlowError::Incomplete),
                    }
                }
                Ok(self.input.drain(..len).collect())
            }
            fn write_all(&mut self, data: &[u8]) -> Result<(), Socks5FlowError> {
                match self.steps.remove(0) {
                    ScriptStep::Expect(expected) => assert_eq!(data, expected),
                    ScriptStep::Send(_) => panic!("unexpected send"),
                }
                Ok(())
            }
        }

        let mut no_auth = Scripted {
            steps: vec![
                ScriptStep::Expect(vec![0x05, 0x01, 0x00]),
                ScriptStep::Send(vec![0x05, 0x00]),
            ],
            input: Vec::new(),
        };
        assert!(!client_negotiate(&mut no_auth, "", "").unwrap().auth_used);

        let mut with_auth = Scripted {
            steps: vec![
                ScriptStep::Expect(vec![0x05, 0x02, 0x00, 0x02]),
                ScriptStep::Send(vec![0x05, 0x02]),
                ScriptStep::Expect(vec![
                    0x01, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's',
                ]),
                ScriptStep::Send(vec![0x01, 0x00]),
            ],
            input: Vec::new(),
        };
        assert!(
            client_negotiate(&mut with_auth, "user", "pass")
                .unwrap()
                .auth_used
        );

        let mut rejected = Scripted {
            steps: vec![
                ScriptStep::Expect(vec![0x05, 0x02, 0x00, 0x02]),
                ScriptStep::Send(vec![0x05, 0xFF]),
            ],
            input: Vec::new(),
        };
        let error = client_negotiate(&mut rejected, "user", "pass").unwrap_err();
        assert_eq!(error.message(), "Upstream proxy rejected all auth methods");

        let mut auth_failed = Scripted {
            steps: vec![
                ScriptStep::Expect(vec![0x05, 0x01, 0x00]),
                ScriptStep::Send(vec![0x05, 0x02]),
            ],
            input: Vec::new(),
        };
        let error = client_negotiate(&mut auth_failed, "", "").unwrap_err();
        assert_eq!(
            error.message(),
            "Upstream proxy requires auth but no credentials provided"
        );
    }

    #[test]
    fn client_connect_raises_reply_error() {
        struct Rejected;
        impl Socks5Io for Rejected {
            fn read_exact(&mut self, _len: usize) -> Result<Vec<u8>, Socks5FlowError> {
                Ok(vec![0x05, 0x04])
            }
            fn write_all(&mut self, _data: &[u8]) -> Result<(), Socks5FlowError> {
                Ok(())
            }
        }
        let error = client_connect(&mut Rejected, "91.105.192.100", 443).unwrap_err();
        assert_eq!(error.message(), "Upstream proxy CONNECT failed (REP=0x04)");
        match error {
            Socks5Error::Reply { reply_code, .. } => assert_eq!(reply_code, 0x04),
            _ => panic!("другой вид ошибки"),
        }
    }

    #[test]
    fn ipv6_formatting_matches_python() {
        // python3 -c "
        // from ipaddress import IPv6Address
        // print(IPv6Address(b'\x20\x01\x06\x7c\x04\xe8' + b'\x00'*8 + b'\x00\x01'),
        //       IPv6Address(bytes(16)))"
        assert_eq!(
            format_ipv6(&[0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:67c:4e8::1"
        );
        assert_eq!(format_ipv6(&[0; 16]), "::");
        assert_eq!(
            format_ipv6(&[0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]),
            "1:1:1:1:1:1:1:1"
        );
    }

    #[test]
    fn address_encoding_types() {
        assert_eq!(
            encode_address("1.2.3.4").unwrap(),
            (ATYP_IPV4, vec![1, 2, 3, 4])
        );
        assert_eq!(encode_address("a.b").unwrap().0, ATYP_DOMAIN);
        assert_eq!(encode_address("2001:67c:4e8::1").unwrap().0, ATYP_IPV6);
        let long = "a".repeat(300);
        assert_eq!(
            encode_address(&long).unwrap_err().message(),
            "Domain name is too long for SOCKS5"
        );
    }
}
