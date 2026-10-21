//! Порт `src/utils/http2_post.py` — один запрос POST по HTTP/2 на уже
//! установленном шифрованном соединении.
//!
//! Часть серверов шифрованного DNS (например, Quad9) отвечает только по
//! HTTP/2, а в стандартной библиотеке его нет. Здесь ровно столько
//! протокола, сколько нужно для одного короткого запроса и ответа:
//! приветствие, заголовки запроса, тело, чтение кадров ответа. Ни
//! сжатия заголовков по словарю, ни нескольких потоков, ни управления
//! окном: ответ DNS заведомо меньше окна по умолчанию (64 КБ).
//!
//! Из заголовков ответа читается только код состояния: он всегда идёт
//! первым.
//!
//! Сокет — платформенный:_trait [`Http2Socket`] (send/recv/тайм-аут);
//! [`post`] работает над любым его исполнением, [`read_status`] и
//! сборка запроса — чистые.

use std::io;

/// python `Http2Error(OSError)` — сервер нарушил протокол или сам
/// оборвал обмен; тайм-аут отделяется от порчи протокола.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2Error {
    /// Сервер закрыл соединение.
    Closed,
    /// Время обмена вышло (python socket.timeout).
    Timeout,
    /// Нарушение протокола с текстом (python Http2Error с сообщением).
    Protocol(String),
    /// Прочая ошибка ввода-вывода.
    Io(String),
}

impl core::fmt::Display for Http2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => write!(f, "сервер закрыл соединение"),
            Self::Timeout => write!(f, "истекло время обмена"),
            Self::Protocol(message) => write!(f, "{message}"),
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

/// Абстракция сокета над [`post`] (python принимал `socket.socket`).
pub trait Http2Socket {
    /// python `sock.settimeout(...)` — пусть не падает для исполнений
    /// без тайм-аутов.
    fn set_timeout(&mut self, seconds: f64) -> Result<(), Http2Error>;
    /// python `sock.sendall(...)`.
    fn send_all(&mut self, data: &[u8]) -> Result<(), Http2Error>;
    /// python `sock.recv(size)` — короткое чтение допустимо, пустой
    /// вектор означает «сервер закрыл соединение».
    fn recv(&mut self, size: usize) -> Result<Vec<u8>, Http2Error>;
}

pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const STREAM: u32 = 1;
const MAX_BODY: usize = 64 * 1024;

/// Готовые строки таблицы заголовков HTTP/2 (RFC 7541, приложение A).
fn status_by_index(index: u64) -> Option<i64> {
    match index {
        8 => Some(200),
        9 => Some(204),
        10 => Some(206),
        11 => Some(304),
        12 => Some(400),
        13 => Some(404),
        14 => Some(500),
        _ => None,
    }
}

/// Сжатые коды цифр (RFC 7541, приложение B): «0–2» по пять бит,
/// «3–9» по шесть.
fn digit_by_bits(code: u64, bits: u32) -> Option<char> {
    match bits {
        5 => match code {
            0b00000 => Some('0'),
            0b00001 => Some('1'),
            0b00010 => Some('2'),
            _ => None,
        },
        6 => {
            if (0b011001..0b011001 + 7).contains(&code) {
                Some(char::from(b'3' + (code - 0b011001) as u8))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// python `_frame` — кадр HTTP/2: длина (3 байта), тип, флаги, поток.
#[must_use]
pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    let length = payload.len() as u32;
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// python `_integer` — целое HPACK с префиксом `prefix_bits` бит.
fn integer(value: u64, prefix_bits: u32, first: u8) -> Vec<u8> {
    let limit = (1_u64 << prefix_bits) - 1;
    if value < limit {
        return vec![first | value as u8];
    }
    let mut out = vec![first | limit as u8];
    let mut rest = value - limit;
    while rest >= 128 {
        out.push((rest % 128) as u8 + 128);
        rest /= 128;
    }
    out.push(rest as u8);
    out
}

/// python `_text` — строка HPACK: длина (7 бит) + ascii-байты.
fn text(value: &str) -> Vec<u8> {
    let raw = value.as_bytes();
    let mut out = integer(raw.len() as u64, 7, 0);
    out.extend_from_slice(raw);
    out
}

/// python `_literal` — заголовок с именем из готовой таблицы и значением
/// открытым текстом.
fn literal(name_index: u64, value: &str) -> Vec<u8> {
    let mut out = integer(name_index, 4, 0x40);
    out.extend(text(value));
    out
}

/// python `_request_headers` — заголовки запроса POST.
fn request_headers(authority: &str, path: &str, content_type: &str, length: usize) -> Vec<u8> {
    let mut out = vec![0x83_u8]; // :method POST
    out.push(0x87); // :scheme https
    out.extend(literal(4, path)); // :path
    out.extend(literal(1, authority)); // :authority
    out.extend(literal(31, content_type)); // content-type
    out.extend(literal(19, content_type)); // accept
    out.extend(literal(28, &length.to_string())); // content-length
    out
}

/// python `_read_integer` — чтение целого HPACK; возвращает (значение,
/// новая позиция). Порченый блок даёт выход за границы — обрабатывается
/// в [`read_status`] как «не прочитать».
fn read_integer(block: &[u8], mut position: usize, prefix_bits: u32) -> Result<(u64, usize), ()> {
    let limit = (1_u64 << prefix_bits) - 1;
    let byte = *block.get(position).ok_or(())?;
    let mut value = u64::from(byte & limit as u8);
    position += 1;
    if value < limit {
        return Ok((value, position));
    }
    let mut shift = 0_u32;
    loop {
        let byte = *block.get(position).ok_or(())?;
        position += 1;
        value += u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, position));
        }
    }
}

/// python `_decode_digits` — распаковка HPACK-кода Хаффмана для цифр.
fn decode_digits(raw: &[u8]) -> String {
    let mut bits = String::with_capacity(raw.len() * 8);
    for byte in raw {
        bits.push_str(&format!("{byte:08b}"));
    }
    let mut digits = String::new();
    let mut position = 0;
    while bits.len() - position >= 5 {
        let five = u64::from_str_radix(&bits[position..position + 5], 2).unwrap_or(u64::MAX);
        let mut digit = digit_by_bits(five, 5);
        if digit.is_some() {
            position += 5;
        } else if bits.len() - position >= 6 {
            let six = u64::from_str_radix(&bits[position..position + 6], 2).unwrap_or(u64::MAX);
            digit = digit_by_bits(six, 6);
            position += 6;
        }
        let Some(digit) = digit else {
            break;
        };
        digits.push(digit);
    }
    digits
}

/// python `read_status` — код состояния из начала блока заголовков
/// ответа или `None`, если он записан иначе.
#[must_use]
pub fn read_status(block: &[u8]) -> Option<i64> {
    (|| -> Result<Option<i64>, ()> {
        let mut position = 0;
        // Сервер может начать с сообщения о размере своего словаря.
        while *block.get(position).ok_or(())? & 0xE0 == 0x20 {
            let (_size, next) = read_integer(block, position, 5)?;
            position = next;
        }
        let first = *block.get(position).ok_or(())?;
        if first & 0x80 != 0 {
            return Ok(status_by_index(u64::from(first) & 0x7F));
        }
        let (index, next) = read_integer(block, position, if first & 0x40 != 0 { 6 } else { 4 })?;
        position = next;
        status_by_index(index).ok_or(())?;
        let compressed = *block.get(position).ok_or(())? & 0x80 != 0;
        let (size, next) = read_integer(block, position, 7)?;
        position = next;
        let end = position.saturating_add(size as usize);
        let raw = block.get(position..end).ok_or(())?;
        let text = if compressed {
            decode_digits(raw)
        } else {
            String::from_utf8(raw.to_vec()).map_err(|_| ())?
        };
        if text.len() == 3 {
            Ok(text.parse().ok())
        } else {
            Ok(None)
        }
    })()
    .ok()
    .flatten()
}

/// python `_strip_padding` — снятие паддинга кадра (флаг 0x8).
fn strip_padding(payload: &[u8], flags: u8) -> Result<&[u8], Http2Error> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let Some(&pad) = payload.first() else {
        return Err(Http2Error::Protocol("неверное выравнивание кадра".into()));
    };
    if usize::from(pad) >= payload.len() {
        return Err(Http2Error::Protocol("неверное выравнивание кадра".into()));
    }
    Ok(&payload[1..payload.len() - usize::from(pad)])
}

/// python `_recv_exact` — накопление ровно `size` байт; тайм-аут перед
/// каждым куском выставляет `remaining`.
fn recv_exact(
    sock: &mut dyn Http2Socket,
    size: usize,
    remaining: &dyn Fn() -> Result<f64, Http2Error>,
) -> Result<Vec<u8>, Http2Error> {
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        sock.set_timeout(remaining()?)?;
        let chunk = sock.recv(size - data.len())?;
        if chunk.is_empty() {
            return Err(Http2Error::Closed);
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

/// python `post` — отправляет запрос и возвращает (код состояния или
/// None, тело ответа).
///
/// `remaining` — сколько секунд осталось на весь обмен; когда время
/// вышло, она сама отдаёт [`Http2Error::Timeout`] (python бросал
/// `socket.timeout`).
pub fn post(
    sock: &mut dyn Http2Socket,
    authority: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
    remaining: &dyn Fn() -> Result<f64, Http2Error>,
) -> Result<(Option<i64>, Vec<u8>), Http2Error> {
    sock.set_timeout(remaining()?)?;
    let mut request = PREFACE.to_vec();
    request.extend(frame(SETTINGS, 0, 0, &[]));
    request.extend(frame(
        HEADERS,
        FLAG_END_HEADERS,
        STREAM,
        &request_headers(authority, path, content_type, body.len()),
    ));
    request.extend(frame(DATA, FLAG_END_STREAM, STREAM, body));
    sock.send_all(&request)?;

    let mut status: Option<i64> = None;
    let mut got_headers = false;
    let mut received = Vec::new();
    loop {
        let header = recv_exact(sock, 9, remaining)?;
        let size = u32::from(header[0]) << 16 | u32::from(header[1]) << 8 | u32::from(header[2]);
        let kind = header[3];
        let flags = header[4];
        let stream = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7FFF_FFFF;
        let payload = if size == 0 {
            Vec::new()
        } else {
            recv_exact(sock, size as usize, remaining)?
        };

        if kind == SETTINGS && flags & FLAG_ACK == 0 {
            sock.set_timeout(remaining()?)?;
            sock.send_all(&frame(SETTINGS, FLAG_ACK, 0, &[]))?;
        } else if kind == PING && flags & FLAG_ACK == 0 {
            sock.set_timeout(remaining()?)?;
            sock.send_all(&frame(PING, FLAG_ACK, 0, &payload))?;
        } else if kind == GOAWAY {
            return Err(Http2Error::Protocol("сервер завершил соединение".into()));
        } else if stream != STREAM {
            continue;
        } else if kind == RST_STREAM {
            return Err(Http2Error::Protocol("сервер отклонил запрос".into()));
        } else if kind == HEADERS {
            let mut block = strip_padding(&payload, flags)?.to_vec();
            if flags & FLAG_PRIORITY != 0 {
                block.drain(..5.min(block.len()));
            }
            // Завершающие заголовки после тела кода состояния не несут.
            if !got_headers {
                status = read_status(&block);
                got_headers = true;
            }
            if flags & FLAG_END_STREAM != 0 {
                return Ok((status, received));
            }
        } else if kind == DATA {
            let chunk = strip_padding(&payload, flags)?;
            received.extend_from_slice(chunk);
            if received.len() > MAX_BODY {
                return Err(Http2Error::Protocol("ответ слишком большой".into()));
            }
            if flags & FLAG_END_STREAM != 0 {
                return Ok((status, received));
            }
        }
    }
}

/// Исполнение [`Http2Socket`] для unix-сокетов (socketpair в тестах,
/// TLS-поток — позже через адаптер).
#[cfg(unix)]
impl Http2Socket for std::os::unix::net::UnixStream {
    fn set_timeout(&mut self, seconds: f64) -> Result<(), Http2Error> {
        let duration = core::time::Duration::from_secs_f64(seconds.max(0.0));
        self.set_read_timeout(Some(duration))
            .and_then(|()| self.set_write_timeout(Some(duration)))
            .map_err(|error| Http2Error::Io(error.to_string()))
    }

    fn send_all(&mut self, data: &[u8]) -> Result<(), Http2Error> {
        io::Write::write_all(self, data).map_err(map_io)
    }

    fn recv(&mut self, size: usize) -> Result<Vec<u8>, Http2Error> {
        let mut chunk = vec![0_u8; size.max(1)];
        let read = io::Read::read(self, &mut chunk).map_err(map_io)?;
        chunk.truncate(read);
        Ok(chunk)
    }
}

#[cfg(unix)]
fn map_io(error: io::Error) -> Http2Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Http2Error::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => Http2Error::Closed,
        _ => Http2Error::Io(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    /// python `_read_frames_until_end_of_request` — серверная сторона.
    fn read_frames_until_end_of_request(sock: &mut UnixStream) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut frames = Vec::new();
        loop {
            let mut header = [0_u8; 9];
            sock.read_exact(&mut header).unwrap();
            let size =
                u32::from(header[0]) << 16 | u32::from(header[1]) << 8 | u32::from(header[2]);
            let mut payload = vec![0_u8; size as usize];
            if size > 0 {
                sock.read_exact(&mut payload).unwrap();
            }
            let stream = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
            frames.push((header[3], header[4], stream, payload));
            if header[3] == 0 && header[4] & 0x1 != 0 {
                return frames;
            }
        }
    }

    /// python `_exchange`: пара сокетов, сервер в отдельном потоке,
    /// клиентский обмен с общим лимитом времени.
    fn exchange(
        serve: impl FnOnce(&mut UnixStream) + Send + 'static,
        timeout: f64,
    ) -> Result<(Option<i64>, Vec<u8>), Http2Error> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || serve(&mut server));
        let until = Instant::now() + Duration::from_secs_f64(timeout);
        let result = post(
            &mut client,
            "dns.test",
            "/dns-query",
            b"QUERY",
            "application/dns-message",
            &|| {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(Http2Error::Timeout)
                } else {
                    Ok(left.as_secs_f64())
                }
            },
        );
        let _ = handle.join();
        result
    }

    #[test]
    fn ready_made_status_lines() {
        assert_eq!(read_status(b"\x88"), Some(200));
        assert_eq!(read_status(b"\x8d"), Some(404));
    }

    #[test]
    fn status_written_as_plain_text() {
        assert_eq!(read_status(b"\x48\x03505"), Some(505));
        assert_eq!(read_status(b"\x08\x03403"), Some(403));
    }

    #[test]
    fn status_written_compressed() {
        // «505»: 5 → 011011, 0 → 00000, 5 → 011011, остаток добит единицами.
        assert_eq!(read_status(b"\x48\x83\x6c\x0d\xff"), Some(505));
        // «429»: 4 → 011010, 2 → 00010, 9 → 011111.
        assert_eq!(read_status(b"\x48\x83\x68\x4f\xff"), Some(429));
    }

    #[test]
    fn dictionary_size_notice_before_status_is_skipped() {
        assert_eq!(read_status(b"\x20\x88"), Some(200));
        assert_eq!(read_status(b"\x3f\xe1\x1f\x88"), Some(200));
    }

    #[test]
    fn unreadable_block_is_none_not_error() {
        for block in [
            &b""[..],
            &b"\x40\x03abc\x03def"[..],
            &b"\x48"[..],
            &b"\x48\x03ab"[..],
        ] {
            assert_eq!(read_status(block), None, "блок {block:?}");
        }
    }

    #[test]
    fn request_is_sent_and_answer_is_read() {
        let saw = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let saw_in_thread = std::sync::Arc::clone(&saw);
        let result = exchange(
            move |sock| {
                let mut header = [0_u8; 24];
                sock.read_exact(&mut header).unwrap();
                let preface = &header[..PREFACE.len()];
                let mut frames = read_frames_until_end_of_request(sock);
                let mut reply = frame(4, 0, 0, &[]);
                reply.extend(frame(6, 0, 0, b"12345678"));
                reply.extend(frame(1, 0x4, 1, b"\x88"));
                reply.extend(frame(0, 0, 1, b"ANS"));
                reply.extend(frame(0, 0x1, 1, b"WER"));
                sock.send_all(&reply).unwrap();
                // Клиент должен подтвердить настройки и ответить на пинг.
                let mut replies = [0_u8; 9 + 9 + 8];
                sock.read_exact(&mut replies).unwrap();
                *saw_in_thread.lock().unwrap() =
                    vec![preface.to_vec(), frames.remove(1).3, replies.to_vec()];
            },
            3.0,
        )
        .unwrap();
        assert_eq!(result, (Some(200), b"ANSWER".to_vec()));
        let saw = saw.lock().unwrap().clone();
        assert_eq!(saw[0], PREFACE);
        let headers = &saw[1];
        for part in [
            &b"\x83"[..],
            &b"\x87"[..],
            b"/dns-query",
            b"dns.test",
            b"application/dns-message",
            b"5",
        ] {
            assert!(
                headers.windows(part.len()).any(|w| w == part),
                "нет {part:?}"
            );
        }
        // Клиент подтвердил настройки сервера и ответил на проверку связи.
        let mut expected_replies = frame(4, 0x1, 0, &[]);
        expected_replies.extend(frame(6, 0x1, 0, b"12345678"));
        assert_eq!(saw[2], expected_replies);
    }

    #[test]
    fn padded_data_and_error_status() {
        let result = exchange(
            |sock| {
                let mut reply = frame(1, 0x4, 1, b"\x8d");
                reply.extend(frame(0, 0x1 | 0x8, 1, b"\x03no\x00\x00\x00"));
                sock.send_all(&reply).unwrap();
            },
            3.0,
        )
        .unwrap();
        assert_eq!(result, (Some(404), b"no".to_vec()));
    }

    #[test]
    fn headers_only_answer_ends_exchange() {
        let result = exchange(
            |sock| sock.send_all(&frame(1, 0x4 | 0x1, 1, b"\x8e")).unwrap(),
            3.0,
        )
        .unwrap();
        assert_eq!(result, (Some(500), Vec::new()));
    }

    #[test]
    fn refused_stream_and_goaway_are_errors() {
        let rst = frame(3, 0, 1, &[0, 0, 0, 7]);
        let result = exchange(move |sock| sock.send_all(&rst).unwrap(), 3.0);
        assert_eq!(
            result.unwrap_err(),
            Http2Error::Protocol("сервер отклонил запрос".into())
        );

        let goaway = frame(7, 0, 0, &[0; 8]);
        let result = exchange(move |sock| sock.send_all(&goaway).unwrap(), 3.0);
        assert_eq!(
            result.unwrap_err(),
            Http2Error::Protocol("сервер завершил соединение".into())
        );
    }

    #[test]
    fn server_that_hangs_up_is_error_and_silent_server_is_timeout() {
        let result = exchange(
            |sock| {
                // Закрыть серверную половину: клиент увидит разрыв.
                let _ = sock.shutdown(std::net::Shutdown::Both);
            },
            3.0,
        );
        assert!(matches!(
            result.unwrap_err(),
            Http2Error::Closed | Http2Error::Io(_)
        ));
        let result = exchange(|_sock| std::thread::sleep(Duration::from_secs(1)), 0.3);
        assert_eq!(result.unwrap_err(), Http2Error::Timeout);
    }

    #[test]
    fn frames_of_other_streams_are_ignored() {
        let result = exchange(
            |sock| {
                let mut reply = frame(0, 0x1, 3, b"other");
                reply.extend(frame(1, 0x4, 1, b"\x88"));
                reply.extend(frame(0, 0x1, 1, b"ok"));
                sock.send_all(&reply).unwrap();
            },
            3.0,
        )
        .unwrap();
        assert_eq!(result, (Some(200), b"ok".to_vec()));
    }

    #[test]
    fn frame_and_integer_helpers_match_python() {
        // Эталонные байты от python _frame/_integer/_request_headers.
        assert_eq!(
            frame(0, 0x1, 1, b"abc"),
            b"\x00\x00\x03\x00\x01\x00\x00\x00\x01abc"
        );
        assert_eq!(integer(5, 7, 0), b"\x05");
        assert_eq!(integer(127, 7, 0), b"\x7f\x00");
        assert_eq!(integer(128, 7, 0), b"\x7f\x01");
        // Эталон от python _integer(300, 7, 0) → [127, 173, 1].
        assert_eq!(integer(300, 7, 0), [127, 173, 1]);
        let headers = request_headers("dns.test", "/dns-query", "application/dns-message", 5);
        // Построено только из статических заголовков — при расшифровке
        // те же части, что ждёт python-тест обмена.
        assert!(headers.starts_with(&[0x83, 0x87]));
    }
}
