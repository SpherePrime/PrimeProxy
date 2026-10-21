//! Настройки MTProxy: секрет и ссылка tg://proxy.
//!
//! Порт `telegram_proxy/proxy/mtproxy.py`. Разбор заголовка клиента и шифры —
//! в [`crate::proxy::obfs`].

use crate::crypto::sha256;
use crate::proxy::fake_tls::build_fake_tls_secret;

/// Приводит секрет MTProxy к виду секрета: 32 шестнадцатеричные буквы.
#[must_use]
pub fn normalize_secret(value: &str) -> String {
    let text = value.trim().to_lowercase();
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return String::new();
    }
    text
}

/// Случайный секрет MTProxy: 32 шестнадцатеричные буквы.
#[must_use]
pub fn generate_secret() -> String {
    let mut bytes = [0_u8; 16];
    fastrand::fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Собирает ссылку tg://proxy для настроек Telegram.
///
/// Для Fake TLS (секрет вида `ee...`) ссылка уходит с секретом ee; если домен
/// не подходит, остаётся обычный секрет dd.
#[must_use]
pub fn build_mtproxy_link(host: &str, port: u32, secret: &str, fake_tls_domain: &str) -> String {
    let normalized_secret = normalize_secret(secret);
    let mut link_secret = format!("dd{normalized_secret}");
    if !fake_tls_domain.is_empty() {
        let fake_tls_secret = build_fake_tls_secret(&normalized_secret, fake_tls_domain);
        if fake_tls_secret.starts_with("ee") {
            link_secret = fake_tls_secret;
        }
    }
    let server = if host.trim().is_empty() {
        "127.0.0.1"
    } else {
        host.trim()
    };
    format!(
        "tg://proxy?server={}&port={}&secret={}",
        urlencode(server),
        port,
        urlencode(&link_secret),
    )
}

/// Кодирование значения query-строки как `urllib.parse.urlencode`:
/// пробел становится плюсом, остальные небезопасные символы — процентами.
#[must_use]
pub fn urlencode(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                result.push(byte as char)
            }
            b' ' => result.push('+'),
            _ => result.push_str(&format!("%{byte:02X}")),
        }
    }
    result
}

/// SHA-256 как вспомогательный экспорт для тестов сцепления с python.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(&[data])
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_secret_trims_and_lowers_exactly_32_hex() {
        assert_eq!(
            normalize_secret(" AABBCCDDEEFF00112233445566778899 "),
            "aabbccddeeff00112233445566778899"
        );
        assert_eq!(normalize_secret("bad"), "");
        assert_eq!(normalize_secret(""), "");
        assert_eq!(normalize_secret("AABB"), "");
    }

    #[test]
    fn generated_secret_is_32_hex_chars() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32);
        assert_eq!(normalize_secret(&secret), secret);
    }

    #[test]
    fn link_uses_dd_secret_by_default() {
        assert_eq!(
            build_mtproxy_link("127.0.0.1", 1443, "aabbccddeeff00112233445566778899", ""),
            "tg://proxy?server=127.0.0.1&port=1443&secret=ddaabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn link_uses_ee_secret_for_fake_tls_domain() {
        assert_eq!(
            build_mtproxy_link(
                "proxy.example.com",
                443,
                "aabbccddeeff00112233445566778899",
                "front.example.com"
            ),
            "tg://proxy?server=proxy.example.com&port=443&secret=eeaabbccddeeff0011223344556677889966726f6e742e6578616d706c652e636f6d"
        );
        // Домен не подходит — остаётся секрет dd.
        assert_eq!(
            build_mtproxy_link(
                "proxy.example.com",
                443,
                "aabbccddeeff00112233445566778899",
                "bad domain"
            ),
            "tg://proxy?server=proxy.example.com&port=443&secret=ddaabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn empty_host_falls_back_to_loopback() {
        assert_eq!(
            build_mtproxy_link("", 443, "aabbccddeeff00112233445566778899", ""),
            "tg://proxy?server=127.0.0.1&port=443&secret=ddaabbccddeeff00112233445566778899"
        );
    }
}
