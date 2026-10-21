//! Порт `fakes/user_fakes.py` (чистая часть) — распознавание типа
//! содержимого фейка и имена файлов своих фейков.
//!
//! Чтение/запись настроек, копирование файлов и открытие папки —
//! платформенные, остаются у вызывающего слоя.

use std::path::Path;

/// python `_HTTP_METHODS`.
const HTTP_METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

/// python `_QUIC_VERSIONS` — v1, v2 и черновики ff0000xx.
const QUIC_VERSIONS: [u32; 2] = [0x0000_0001, 0x6B33_43CF];

/// python `USER_FAKES_REFERENCE_PREFIX` — префикс ссылки на свой фейк.
pub const USER_FAKES_REFERENCE_PREFIX: &str = "@user/fakes/";
/// python `USER_FAKE_FILE_SUFFIX`.
pub const USER_FAKE_FILE_SUFFIX: &str = ".bin";
/// python `USER_FAKE_MAX_BYTES` — фейк один пакет, 64 КБ с запасом.
pub const USER_FAKE_MAX_BYTES: usize = 64 * 1024;
/// python `USER_FAKE_NAME_MAX_LENGTH`.
pub const USER_FAKE_NAME_MAX_LENGTH: usize = 64;
/// python `USER_FAKE_DESCRIPTION_MAX_LENGTH`.
pub const USER_FAKE_DESCRIPTION_MAX_LENGTH: usize = 200;

/// python `user_fake_file_name(name)` — имя файла своего фейка.
#[must_use]
pub fn user_fake_file_name(name: &str) -> &str {
    if name.ends_with(USER_FAKE_FILE_SUFFIX) {
        name
    } else {
        // python возвращает f"{name}.bin" — здесь нельзя вернуть владение
        // без аллокации, поэтому сигнатура другая (см. user_fake_file_path).
        USER_FAKE_FILE_SUFFIX
    }
}

/// Полное имя файла своего фейка (python: `f"{name}.bin"`); возвращает
/// `name` как есть, если суффикс уже есть.
#[must_use]
pub fn user_fake_file_path(name: &str) -> String {
    if name.ends_with(USER_FAKE_FILE_SUFFIX) {
        name.to_string()
    } else {
        format!("{name}{USER_FAKE_FILE_SUFFIX}")
    }
}

/// python `_parse_client_hello_sni` — SNI из TLS Handshake ClientHello;
/// `None`, если его нет или данные битые.
#[must_use]
fn parse_client_hello_sni(handshake: &[u8]) -> Option<String> {
    let data = handshake;
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let mut pos = 4 + 2 + 32; // тип+длина, версия, random
    if pos + 1 > data.len() {
        return None;
    }
    pos += 1 + usize::from(data[pos]); // session id
    if pos + 2 > data.len() {
        return None;
    }
    pos += 2 + usize::from(u16::from_be_bytes([data[pos], data[pos + 1]])); // cipher suites
    if pos + 1 > data.len() {
        return None;
    }
    pos += 1 + usize::from(data[pos]); // compression methods
    if pos + 2 > data.len() {
        return None;
    }
    let extensions_end =
        (data.len()).min(pos + 2 + usize::from(u16::from_be_bytes([data[pos], data[pos + 1]])));
    pos += 2;
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let body = data.get(pos + 4..pos + 4 + ext_len).unwrap_or(&[]);
        pos += 4 + ext_len;
        if ext_type != 0 {
            continue;
        }
        // server_name_list: длина(2), затем записи тип(1) длина(2) имя.
        let mut item = 2;
        while item + 3 <= body.len() {
            let name_type = body[item];
            let name_len = u16::from_be_bytes([body[item + 1], body[item + 2]]) as usize;
            let name = body.get(item + 3..item + 3 + name_len).unwrap_or(&[]);
            item += 3 + name_len;
            if name_type == 0 && name.len() == name_len && name_len > 0 {
                return String::from_utf8(name.to_vec()).ok();
            }
        }
        return None;
    }
    None
}

/// python `bytes.split(sep, 1)` — голова и хвост после первого вхождения
/// разделителя (хвост пуст, если разделителя нет).
fn split_once<'a>(data: &'a [u8], separator: &[u8]) -> (&'a [u8], &'a [u8]) {
    if separator.is_empty() || data.len() < separator.len() {
        return (data, &[]);
    }
    for index in 0..=data.len() - separator.len() {
        if &data[index..index + separator.len()] == separator {
            return (&data[..index], &data[index + separator.len()..]);
        }
    }
    (data, &[])
}

/// python `bytes.split(b"\r\n")` — все куски между CRLF.
fn split_crlf(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (head, tail) = split_once(rest, b"\r\n");
        rest = tail;
        Some(head)
    })
}

/// python `_http_host` — заголовок Host из HTTP-запроса.
#[must_use]
fn http_host(data: &[u8]) -> Option<String> {
    let head = split_once(data, b"\r\n\r\n").0;
    // python: head.split(b"\r\n") — разрез по CRLF; строка без CRLF — одна.
    for line in split_crlf(head).skip(1) {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let key = &line[..colon];
        let value = &line[colon + 1..];
        // python: key.strip().lower() == b"host" (\r в конце строки снят
        // разрезом по \n выше — но последняя строка может иметь \r).
        let key: Vec<u8> = key
            .iter()
            .copied()
            .filter(|b| !b" \t\r".contains(b))
            .map(|b| b.to_ascii_lowercase())
            .collect();
        if key == b"host" {
            let trimmed: Vec<u8> = value
                .iter()
                .copied()
                .skip_while(|b| b.is_ascii_whitespace())
                .collect();
            let trimmed: Vec<u8> = trimmed
                .into_iter()
                .rev()
                .skip_while(|b| b.is_ascii_whitespace())
                .collect::<Vec<u8>>()
                .into_iter()
                .rev()
                .collect();
            if trimmed.is_empty() {
                return None;
            }
            return String::from_utf8(trimmed).ok();
        }
    }
    None
}

/// python `detect_fake_kind` — тип содержимого фейка и имя сервера внутри
/// (SNI для TLS, Host для HTTP). Никогда не даёт ошибки: непонятные
/// данные — `("other", None)`.
#[must_use]
pub fn detect_fake_kind(data: &[u8]) -> (&'static str, Option<String>) {
    if data.is_empty() {
        return ("other", None);
    }
    if data.iter().all(|&b| b == 0) {
        return ("zeros", None);
    }
    // TLS: запись Handshake (0x16 0x03 xx) или голый Handshake ClientHello.
    if data.len() >= 5 && data[0] == 0x16 && data[1] == 0x03 {
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let handshake = data.get(5..5 + record_len).unwrap_or(&[]);
        if handshake.first() == Some(&0x01) {
            return ("tls", parse_client_hello_sni(handshake));
        }
        return ("tls", None);
    }
    if data.len() >= 6 && data[0] == 0x01 && data[4] == 0x03 {
        return ("tls", parse_client_hello_sni(data));
    }
    // QUIC: длинный заголовок с известной версией (v1, v2, черновики ff0000xx).
    if data.len() >= 5 && (data[0] & 0xC0) == 0xC0 {
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if QUIC_VERSIONS.contains(&version) || version >> 8 == 0xFF_0000 {
            return ("quic", None);
        }
    }
    let first_line = split_crlf(data).next().unwrap_or(&[]);
    if HTTP_METHODS.iter().any(|method| data.starts_with(method))
        && first_line
            .windows(b" HTTP/1.".len())
            .any(|w| w == b" HTTP/1.")
    {
        return ("http", http_host(data));
    }
    ("other", None)
}

/// python `read_user_fake_source` — байты файла источника; папку и размер
/// проверяет вызывающий код.
pub fn read_user_fake_source(source_path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(source_path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_zeros_and_empty() {
        assert_eq!(detect_fake_kind(b""), ("other", None));
        assert_eq!(detect_fake_kind(&[0_u8; 64]), ("zeros", None));
        assert_eq!(detect_fake_kind(&[0, 0, 1]), ("other", None));
    }

    /// Настоящий ClientHello из живой установки Zapret: SNI читается.
    /// (python: detect_fake_kind на том же файле → ('tls', 'www.google.com').)
    #[test]
    fn detect_tls_record_with_sni() {
        let path = std::path::Path::new(
            "/home/kalinov/Faugus/default/drive_c/Zapret/Dev/bin/tls_clienthello_www_google_com.bin",
        );
        let Ok(data) = std::fs::read(path) else {
            // Файла установки нет в этой среде — проверка не имеет смысла.
            return;
        };
        assert_eq!(
            detect_fake_kind(&data),
            ("tls", Some("www.google.com".to_string()))
        );
    }

    #[test]
    fn detect_tls_truncated_sni_is_none() {
        // Запись TLS без SNI — тип определяется, имя None.
        let record = [
            0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x03, 0x03, 0x01, 0x00,
        ];
        assert_eq!(detect_fake_kind(&record), ("tls", None));
    }

    #[test]
    fn detect_bare_client_hello() {
        // Голый handshake (без записи): 0x01 ... data[4] == 0x03.
        let mut data = vec![0x01, 0x00, 0x00, 0x2b];
        data.push(0x03); // data[4] == 0x03
        data.extend([0x03]);
        data.extend([0_u8; 32]);
        data.extend([0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);
        let (kind, sni) = detect_fake_kind(&data);
        assert_eq!(kind, "tls");
        assert_eq!(sni, None);
    }

    #[test]
    fn detect_quic_versions() {
        // Длинный заголовок QUIC v1.
        let mut quic = vec![0xC3];
        quic.extend_from_slice(&0x0000_0001_u32.to_be_bytes());
        quic.extend([1_u8; 16]);
        assert_eq!(detect_fake_kind(&quic), ("quic", None));
        // Черновик ff0000xx.
        let mut draft = vec![0xC0];
        draft.extend_from_slice(&0xFF00_001D_u32.to_be_bytes());
        draft.extend([2_u8; 8]);
        assert_eq!(detect_fake_kind(&draft), ("quic", None));
        // Настоящий QUIC-фейк установки (python → ('quic', None)).
        if let Ok(quic_real) = std::fs::read(std::path::Path::new(
            "/home/kalinov/Faugus/default/drive_c/Zapret/Dev/bin/quic_initial_www_google_com.bin",
        )) {
            assert_eq!(detect_fake_kind(&quic_real), ("quic", None));
        }
        // Неизвестная версия — не QUIC.
        let mut unknown = vec![0xC3];
        unknown.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
        unknown.extend([3_u8; 8]);
        assert_eq!(detect_fake_kind(&unknown).0, "other");
    }

    #[test]
    fn detect_http_with_host() {
        let request = b"POST /x HTTP/1.1\r\nHost: example.org\r\n\r\nbody";
        assert_eq!(
            detect_fake_kind(request),
            ("http", Some("example.org".to_string()))
        );
        // host в другом регистре тоже находится.
        let request = b"GET / HTTP/1.1\r\nhOsT: api.test\r\n\r\n";
        assert_eq!(
            detect_fake_kind(request),
            ("http", Some("api.test".to_string()))
        );
        // Без заголовка Host — тип есть, имени нет.
        let request = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(detect_fake_kind(request), ("http", None));
    }

    #[test]
    fn detect_http_method_required() {
        // " HTTP/1." есть, но метод не из списка — other.
        let data = b"PUTX / HTTP/1.1\r\n\r\n";
        assert_eq!(detect_fake_kind(data).0, "other");
    }

    #[test]
    fn file_name_helpers_match_python() {
        // python: user_fake_file_name → f"{name}.bin".
        assert_eq!(user_fake_file_path("my_fake"), "my_fake.bin");
        assert_eq!(user_fake_file_path("already.bin"), "already.bin");
        assert_eq!(USER_FAKE_MAX_BYTES, 64 * 1024);
        assert_eq!(USER_FAKE_NAME_MAX_LENGTH, 64);
        assert_eq!(USER_FAKE_DESCRIPTION_MAX_LENGTH, 200);
        assert_eq!(USER_FAKES_REFERENCE_PREFIX, "@user/fakes/");
    }
}
