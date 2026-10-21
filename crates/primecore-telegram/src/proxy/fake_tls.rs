//! Fake TLS для MTProxy: маскировка MTProxy под обычный TLS-сайт.
//!
//! Порт чистой части `telegram_proxy/proxy/fake_tls.py`. Проверка
//! ClientHello и сборка ServerHello идут поверх HMAC-SHA256 с секретом
//! MTProxy; поток TLS-записей (`FakeTlsStream`) и чтение инициализации —
//! сетевой слой, он остаётся на стороне вызывающего кода.

use crate::crypto::{hmac_sha256, sha256};

/// Типы TLS-записей, которые различает Fake TLS.
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

pub const TLS_APPDATA_MAX: usize = 16384;
pub const CLIENT_RANDOM_OFFSET: usize = 11;
pub const CLIENT_RANDOM_LEN: usize = 32;
/// На сколько секунд может расходиться часы клиента и прокси.
pub const TIMESTAMP_TOLERANCE: u64 = 120;
pub const MT_PROXY_INIT_LEN: usize = 64;

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const SERVER_HELLO_TEMPLATE_LEN: usize = 122 + 5;
const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const SH_PUBKEY_OFF: usize = 89;

/// Приводит домен Fake TLS к каноническому виду; пусто, если домен не подходит.
#[must_use]
pub fn normalize_fake_tls_domain(value: &str) -> String {
    let text = value.trim().trim_end_matches('.').to_lowercase();
    if text.is_empty() || text.len() > 253 {
        return String::new();
    }
    let allowed = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
    for label in text.split('.') {
        if label.is_empty() || label.len() > 63 {
            return String::new();
        }
        if label.starts_with('-') || label.ends_with('-') {
            return String::new();
        }
        if !label.bytes().all(allowed) {
            return String::new();
        }
    }
    text
}

/// Секрет MTProxy для Fake TLS: `ee` + секрет + домен в hex.
///
/// Пустой домен или неверный секрет возвращают пустую строку (для ссылки
/// секрет dd), а нормализованный секрет без домена возвращается как dd.
#[must_use]
pub fn build_fake_tls_secret(secret: &str, domain: &str) -> String {
    let clean_secret = secret.trim().to_lowercase();
    let clean_domain = normalize_fake_tls_domain(domain);
    if clean_secret.len() != 32 || clean_domain.is_empty() {
        return clean_secret;
    }
    if !clean_secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return String::new();
    }
    let domain_hex: String = clean_domain
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("ee{clean_secret}{domain_hex}")
}

/// Конфиг nginx перед MTProxy с Fake TLS (для тех, кто открывает 443 сам).
#[must_use]
pub fn build_fake_tls_nginx_config(
    fake_tls_domain: &str,
    upstream_host: &str,
    upstream_port: i64,
) -> String {
    let domain = {
        let normalized = normalize_fake_tls_domain(fake_tls_domain);
        if normalized.is_empty() {
            "example.com".to_string()
        } else {
            normalized
        }
    };
    let host = {
        let trimmed = upstream_host.trim();
        if trimmed.is_empty() {
            "127.0.0.1"
        } else {
            trimmed
        }
    };
    let port = if (1..=65535).contains(&upstream_port) {
        upstream_port
    } else {
        8446
    };
    format!(
        "upstream mtproxy {{\n    server {host}:{port};\n}}\n\n\
         map $ssl_preread_server_name $sni_name {{\n    hostnames;\n    {domain} mtproxy;\n}}\n\n\
         server {{\n    listen 443;\n    proxy_protocol on;\n    set_real_ip_from unix:;\n    \
         proxy_pass $sni_name;\n    ssl_preread on;\n}}\n"
    )
}

/// Байты секрета MTProxy; пусто, если секрет не подходит.
#[must_use]
fn secret_bytes(secret: &str) -> Vec<u8> {
    let text = secret.trim().to_lowercase();
    if text.len() != 32 {
        return Vec::new();
    }
    hex_to_bytes(&text)
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(
                std::str::from_utf8(&bytes[index * 2..index * 2 + 2]).unwrap_or("zz"),
                16,
            )
            .unwrap_or(0)
        })
        .collect()
}

/// Результат проверки ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHello {
    pub client_random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub timestamp: u32,
}

/// Проверяет ClientHello против секрета MTProxy.
///
/// Первые 28 байт client random — HMAC от секрета и записи без random;
/// последние 4 байта — XOR с хвостом HMAC, там спрятан unix-время клиента.
/// `now_unix` — текущее время для проверки допуска.
#[must_use]
pub fn verify_client_hello(data: &[u8], secret: &str, now_unix: u64) -> Option<VerifiedHello> {
    let secret_bytes = secret_bytes(secret);
    if data.len() < 43 || secret_bytes.is_empty() {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }
    let client_random =
        data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].to_vec();
    let mut zeroed = data.to_vec();
    for byte in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *byte = 0;
    }
    let expected = hmac_sha256(&secret_bytes, &zeroed);
    if expected[..28] != client_random[..28] {
        return None;
    }
    let mut ts_raw = [0_u8; 4];
    for index in 0..4 {
        ts_raw[index] = client_random[28 + index] ^ expected[28 + index];
    }
    let timestamp = u32::from_le_bytes(ts_raw);
    let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
    let stamp = i64::from(timestamp);
    if (now - stamp).unsigned_abs() > TIMESTAMP_TOLERANCE {
        return None;
    }
    let session_id = if data.len() >= 76 && data[43] == 0x20 {
        data[44..76].to_vec()
    } else {
        vec![0_u8; 32]
    };
    Some(VerifiedHello {
        client_random,
        session_id,
        timestamp,
    })
}

/// Собирает ServerHello + ChangeCipherSpec + app-data, как их отдаёт MTProxy.
#[must_use]
pub fn build_server_hello(secret: &str, client_random: &[u8], session_id: &[u8]) -> Vec<u8> {
    let secret_bytes = secret_bytes(secret);
    let mut hello = vec![0_u8; SERVER_HELLO_TEMPLATE_LEN];
    // Шаблон из python-версии: фиксированные поля записи TLS и расширений.
    let template: [u8; SERVER_HELLO_TEMPLATE_LEN] = [
        0x16, 0x03, 0x03, 0x00, 0x7a, // record header
        0x02, 0x00, 0x00, 0x76, // handshake: ServerHello
        0x03, 0x03, // legacy version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // server random (перезаписывается)
        0x20, // session id length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // session id
        0x13, 0x01, 0x00, // cipher suite + compression
        0x00, 0x2e, // extensions length
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key share extension
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // key share data
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported versions
    ];
    hello.copy_from_slice(&template);
    let session = if session_id.len() >= 32 {
        &session_id[..32]
    } else {
        session_id
    };
    hello[SH_SESSID_OFF..SH_SESSID_OFF + session.len()].copy_from_slice(session);
    let mut pubkey = [0_u8; 32];
    fastrand::fill(&mut pubkey);
    hello[SH_PUBKEY_OFF..SH_PUBKEY_OFF + 32].copy_from_slice(&pubkey);

    // Объём «зашифрованных» данных — случайный в диапазоне python-версии.
    let encrypted_size = 1900 + fastrand::u32(..201);
    let mut app_record = Vec::with_capacity(5 + encrypted_size as usize);
    app_record.extend_from_slice(&[0x17, 0x03, 0x03]);
    app_record.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    let mut noise = vec![0_u8; encrypted_size as usize];
    fastrand::fill(&mut noise);
    app_record.extend_from_slice(&noise);

    let mut response = hello.clone();
    response.extend_from_slice(&CCS_FRAME);
    response.extend_from_slice(&app_record);
    let mut hmac_message = client_random.to_vec();
    hmac_message.extend_from_slice(&response);
    let server_random = hmac_sha256(&secret_bytes, &hmac_message);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    response
}

/// Заворачивает данные в TLS-записи app-data по 16 КиБ.
#[must_use]
pub fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x17, 0x03, 0x03, 0x00, 0x00];
    }
    let mut result = Vec::with_capacity(data.len() + data.len() / TLS_APPDATA_MAX * 5 + 5);
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        result.extend_from_slice(&[0x17, 0x03, 0x03]);
        result.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        result.extend_from_slice(chunk);
    }
    result
}

/// SHA-256 секретной derivation, экспортированный для тестов соответствия.
#[must_use]
pub fn sha256_of(data: &[u8]) -> [u8; 32] {
    sha256(&[data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalization_follows_python_rules() {
        assert_eq!(
            normalize_fake_tls_domain(" Front.Example.Com. "),
            "front.example.com"
        );
        assert_eq!(normalize_fake_tls_domain(""), "");
        assert_eq!(normalize_fake_tls_domain("bad domain"), "");
        assert_eq!(normalize_fake_tls_domain("-bad.example.com"), "");
        assert_eq!(normalize_fake_tls_domain("bad-.example.com"), "");
        // python3 -c "
        // from telegram_proxy.proxy.fake_tls import normalize_fake_tls_domain
        // print(normalize_fake_tls_domain('a'*63 + '.com'), repr(normalize_fake_tls_domain('a'*64 + '.com')))"
        assert_eq!(
            normalize_fake_tls_domain(&format!("{}.com", "a".repeat(63))),
            format!("{}.com", "a".repeat(63))
        );
        assert_eq!(
            normalize_fake_tls_domain(&format!("{}.com", "a".repeat(64))),
            ""
        );
        assert_eq!(normalize_fake_tls_domain("a.b"), "a.b");
    }

    #[test]
    fn fake_tls_secret_appends_domain_hex() {
        assert_eq!(
            build_fake_tls_secret("aabbccddeeff00112233445566778899", "front.example.com"),
            "eeaabbccddeeff0011223344556677889966726f6e742e6578616d706c652e636f6d"
        );
        assert_eq!(build_fake_tls_secret("bad", "front.example.com"), "bad");
        assert_eq!(
            build_fake_tls_secret("aabbccddeeff00112233445566778899", ""),
            "aabbccddeeff00112233445566778899"
        );
        assert_eq!(
            build_fake_tls_secret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "front.example.com"),
            ""
        );
    }

    #[test]
    fn nginx_config_contains_preread_map() {
        let config = build_fake_tls_nginx_config("Front.Example.Com", "127.0.0.1", 8446);
        assert!(config.contains("upstream mtproxy"));
        assert!(config.contains("server 127.0.0.1:8446;"));
        assert!(config.contains("front.example.com mtproxy;"));
        assert!(config.contains("proxy_protocol on;"));
        assert!(config.contains("ssl_preread on;"));
    }

    #[test]
    fn nginx_config_falls_back_to_example_com_and_default_port() {
        let config = build_fake_tls_nginx_config("bad domain", "", 0);
        assert!(config.contains("example.com mtproxy;"));
        assert!(config.contains("server 127.0.0.1:8446;"));
    }

    #[test]
    fn client_hello_verification_checks_hmac_and_time() {
        // Собираем ClientHello так, как это делает тест python-версии.
        let secret = "aabbccddeeff00112233445566778899";
        let secret_bytes = hex_to_bytes(secret);
        let mut hello = vec![0_u8; 101];
        hello[0] = 0x16;
        hello[1..3].copy_from_slice(&97_u16.to_be_bytes());
        hello[5] = 0x01;
        hello[6..9].copy_from_slice(&93_u32.to_be_bytes()[1..]);
        hello[9..11].copy_from_slice(&[0x03, 0x03]);
        let now: u32 = 1_700_000_000;
        let expected = hmac_sha256(&secret_bytes, &hello);
        let mut random = expected[..28].to_vec();
        let tail: Vec<u8> = (0..4)
            .map(|index| (now.to_le_bytes()[index]) ^ expected[28 + index])
            .collect();
        random.extend_from_slice(&tail);
        hello[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].copy_from_slice(&random);
        // Время внутри допуска.
        let verified = verify_client_hello(&hello, secret, u64::from(now)).expect("verified");
        assert_eq!(verified.timestamp, now);
        assert_eq!(verified.session_id, vec![0_u8; 32]);
        // Не то время — отказ.
        assert!(
            verify_client_hello(&hello, secret, u64::from(now) + TIMESTAMP_TOLERANCE + 1).is_none()
        );
        // Не тот секрет — отказ.
        assert!(
            verify_client_hello(&hello, "00112233445566778899aabbccddeeff", u64::from(now))
                .is_none()
        );
        // Подменённый random — отказ.
        let mut broken = hello.clone();
        broken[CLIENT_RANDOM_OFFSET] ^= 1;
        assert!(verify_client_hello(&broken, secret, u64::from(now)).is_none());
    }

    #[test]
    fn server_hello_starts_with_tls_record() {
        let response =
            build_server_hello("aabbccddeeff00112233445566778899", &[0_u8; 32], &[1_u8; 32]);
        assert!(response.starts_with(&[0x16, 0x03, 0x03]));
        assert!(response.len() > 2000);
        // ChangeCipherSpec идёт сразу после ServerHello (127 байт шаблона).
        assert_eq!(&response[127..133], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn wrap_tls_record_splits_at_16k() {
        assert_eq!(wrap_tls_record(&[]), vec![0x17, 0x03, 0x03, 0x00, 0x00]);
        let data = vec![7_u8; TLS_APPDATA_MAX + 3];
        let wrapped = wrap_tls_record(&data);
        assert_eq!(wrapped.len(), 5 + TLS_APPDATA_MAX + 5 + 3);
        assert_eq!(&wrapped[..3], &[0x17, 0x03, 0x03]);
        let first_len = u16::from_be_bytes([wrapped[3], wrapped[4]]) as usize;
        assert_eq!(first_len, TLS_APPDATA_MAX);
    }
}
