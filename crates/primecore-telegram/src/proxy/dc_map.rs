//! Адреса датацентров Telegram: IP → DC, прямые TCP-адреса, диапазоны Telegram.
//!
//! Порт `telegram_proxy/dc_map.py`. Маршруты WSS (релеи, фронты, туннель)
//! описаны в [`crate::proxy::route_catalog`] и [`crate::proxy::routes`].

/// IP → (dc, media) для известных адресов Telegram.
#[must_use]
pub fn ip_to_dc_entry(ip: &str) -> Option<(i32, bool)> {
    let entry = match ip {
        // DC1
        "149.154.175.50" | "149.154.175.51" | "149.154.175.53" | "149.154.175.54" => (1, false),
        "149.154.175.52" => (1, true),
        // DC2
        "149.154.167.41" | "149.154.167.50" | "149.154.167.51" | "149.154.167.220"
        | "95.161.76.100" => (2, false),
        "149.154.167.151" | "149.154.167.222" | "149.154.167.223" | "149.154.162.123" => (2, true),
        // DC3
        "149.154.175.100" | "149.154.175.101" => (3, false),
        "149.154.175.102" => (3, true),
        // DC4
        "149.154.167.91" | "149.154.167.92" => (4, false),
        "149.154.164.250" | "149.154.166.120" | "149.154.166.121" | "149.154.167.118"
        | "149.154.165.111" => (4, true),
        // DC5
        "91.108.56.100" | "91.108.56.101" | "91.108.56.116" | "91.108.56.126" | "149.154.171.5" => {
            (5, false)
        }
        "91.108.56.102" | "91.108.56.128" | "91.108.56.151" => (5, true),
        // DC203
        "91.105.192.100" => (203, false),
        _ => return None,
    };
    Some(entry)
}

/// Прямой TCP-адрес DC (запасной путь).
#[must_use]
pub fn tcp_endpoint(dc: i32) -> (&'static str, u16) {
    match dc {
        1 => ("149.154.175.50", 443),
        2 => ("149.154.167.51", 443),
        3 => ("149.154.175.100", 443),
        4 => ("149.154.167.91", 443),
        5 => ("91.108.56.100", 443),
        203 => ("91.105.192.100", 443),
        _ => ("149.154.167.51", 443),
    }
}

/// Прямой TCP-адрес медиа-кластера DC.
#[must_use]
pub fn tcp_media_endpoint(dc: i32) -> (&'static str, u16) {
    match dc {
        1 => ("149.154.175.52", 443),
        2 => ("149.154.167.151", 443),
        3 => ("149.154.175.102", 443),
        4 => ("149.154.164.250", 443),
        5 => ("91.108.56.102", 443),
        203 => ("91.105.192.100", 443),
        _ => ("149.154.167.151", 443),
    }
}

/// Диапазон IPv4: адрес сети, маска, DC.
const SUBNETS: &[(u32, u32, i32)] = &[
    // DC2
    subnet("91.108.4.0", 22, 2),
    subnet("91.105.192.0", 23, 2),
    subnet("185.76.151.0", 24, 2),
    // DC1
    subnet("91.108.20.0", 22, 1),
    // DC4
    subnet("91.108.8.0", 22, 4),
    subnet("91.108.12.0", 22, 4),
    // DC5
    subnet("91.108.16.0", 22, 5),
    subnet("91.108.56.0", 22, 5),
    // 149.154.160.0/20 — сначала самые узкие известные диапазоны.
    subnet("149.154.175.0", 24, 1),
    subnet("149.154.167.0", 24, 2),
    subnet("149.154.160.0", 22, 1),
    subnet("149.154.164.0", 22, 4),
    subnet("149.154.168.0", 22, 2),
    subnet("149.154.172.0", 22, 1),
    // Запас на весь блок /20
    subnet("149.154.160.0", 20, 2),
];

const fn subnet(address: &str, prefix: u32, dc: i32) -> (u32, u32, i32) {
    let parsed = parse_ipv4_const(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (parsed & mask, mask, dc)
}

const fn parse_ipv4_const(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let mut value = 0_u32;
    let mut octet = 0_u32;
    let mut digits = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'.' {
            value = (value << 8) | octet;
            octet = 0;
            digits = 0;
        } else {
            octet = octet * 10 + (byte - b'0') as u32;
            digits += 1;
        }
        index += 1;
        let _ = digits;
    }
    (value << 8) | octet
}

/// Все официальные диапазоны IPv4 Telegram (core.telegram.org/resources/cidr.txt).
const TELEGRAM_CIDRS: &[(u32, u32)] = &[
    network("91.108.56.0", 22),
    network("91.108.4.0", 22),
    network("91.108.8.0", 22),
    network("91.108.16.0", 22),
    network("91.108.12.0", 22),
    network("149.154.160.0", 20),
    network("91.105.192.0", 23),
    network("91.108.20.0", 22),
    network("185.76.151.0", 24),
];

const fn network(address: &str, prefix: u32) -> (u32, u32) {
    let mask = u32::MAX << (32 - prefix);
    (parse_ipv4_const(address) & mask, prefix)
}

/// Соответствие префиксов IPv6 номерам DC (самые узкие — впереди).
fn v6_subnets() -> &'static [(u128, u32, i32)] {
    static TABLE: std::sync::OnceLock<Vec<(u128, u32, i32)>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (v6("2001:67c:4e8:f002::"), 64, 2),
            (v6("2001:67c:4e8:f003::"), 64, 3),
            (v6("2001:67c:4e8:f004::"), 64, 4),
            (v6("2001:67c:4e8:f001::"), 64, 1),
            (v6("2001:67c:4e8:f005::"), 64, 5),
            (v6("2001:b28:f23d:f003::"), 64, 3),
            (v6("2001:b28:f23f:f005::"), 64, 5),
            (v6("2a0a:f280:203::"), 48, 203),
            // Запас на целые диапазоны
            (v6("2001:67c:4e8::"), 48, 2),
            (v6("2001:b28:f23c::"), 46, 2),
            (v6("2a0a:f280::"), 32, 2),
        ]
    })
}

/// Все официальные диапазоны IPv6 Telegram.
fn v6_cidrs() -> &'static [(u128, u32)] {
    static TABLE: std::sync::OnceLock<Vec<(u128, u32)>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (v6("2001:67c:4e8::"), 48),
            (v6("2001:b28:f23c::"), 46),
            (v6("2a0a:f280::"), 32),
        ]
    })
}

fn v6(text: &str) -> u128 {
    parse_ipv6_groups(text)
}

/// Разбор IPv6-адреса со сжатием `::` в 128-битное число.
fn parse_ipv6_groups(text: &str) -> u128 {
    let bytes = text.as_bytes();
    let mut groups: [u16; 8] = [0; 8];
    let mut group_count: usize = 0;
    let mut current: u32 = 0;
    let mut has_current = false;
    let mut compression_at: usize = usize::MAX;
    let mut index = 0;
    // В этих константах префиксы только в нижнем регистре и без лишних знаков.
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b':' {
            if index > 0 && bytes[index - 1] == b':' {
                compression_at = group_count;
                index += 1;
                continue;
            }
            let _ = &group_count;
            if has_current {
                groups[group_count] = current as u16;
                group_count += 1;
                current = 0;
                has_current = false;
            }
            index += 1;
            continue;
        }
        let digit = if byte.is_ascii_digit() {
            (byte - b'0') as u32
        } else if byte.is_ascii_lowercase() {
            (byte - b'a') as u32 + 10
        } else if byte.is_ascii_uppercase() {
            (byte - b'A') as u32 + 10
        } else {
            // Мусорный символ не должен паниковать: parse_ipv6 отбракует строку.
            0
        };
        current = current.wrapping_mul(16).wrapping_add(digit);
        has_current = true;
        index += 1;
    }
    if has_current {
        groups[group_count] = current as u16;
        group_count += 1;
    }
    if compression_at != usize::MAX {
        let tail = group_count - compression_at;
        let fill = 8 - group_count;
        let mut shifted = [0_u16; 8];
        // Головные группы до `::` сохраняются, хвост сдвигается вправо.
        shifted[..compression_at].copy_from_slice(&groups[..compression_at]);
        for offset in 0..tail {
            shifted[compression_at + fill + offset] = groups[compression_at + offset];
        }
        groups = shifted;
    }
    let mut value = 0_u128;
    for group in groups {
        value = (value << 16) | u128::from(group);
    }
    value
}

/// Номер DC для адреса Telegram; неизвестные адреса идут в DC2 (самый частый).
#[must_use]
pub fn ip_to_dc(ip: &str) -> i32 {
    if ip.contains(':') {
        if let Some(address) = parse_ipv6(ip) {
            for (network_address, prefix, dc) in v6_subnets() {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                if address & mask == *network_address {
                    return *dc;
                }
            }
        }
        return 2;
    }
    let Some(address) = parse_ipv4(ip) else {
        return 2;
    };
    for (network_address, mask, dc) in SUBNETS {
        if address & mask == *network_address {
            return *dc;
        }
    }
    2
}

/// Адрес из официальных диапазонов Telegram.
#[must_use]
pub fn is_telegram_ip(ip: &str) -> bool {
    if ip.contains(':') {
        if let Some(address) = parse_ipv6(ip) {
            for (network_address, prefix) in v6_cidrs() {
                let mask = u128::MAX << (128 - prefix);
                if address & mask == *network_address {
                    return true;
                }
            }
        }
        return false;
    }
    let Some(address) = parse_ipv4(ip) else {
        return false;
    };
    TELEGRAM_CIDRS
        .iter()
        .any(|(network_address, prefix)| address & mask_of(*prefix) == *network_address)
}

fn mask_of(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Разбор IPv4-адреса; `None` — не адрес.
#[must_use]
pub fn parse_ipv4(text: &str) -> Option<u32> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut value = 0_u32;
    for part in parts {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        value = (value << 8) | octet;
    }
    Some(value)
}

/// Разбор IPv6-адреса (со сжатием `::`); `None` — не адрес.
#[must_use]
pub fn parse_ipv6(text: &str) -> Option<u128> {
    let value = parse_ipv6_groups(text);
    // Константный разбор не отличает мусор: проверяем канонический вид строкой.
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
    {
        return None;
    }
    if text.contains(":::") {
        return None;
    }
    let groups = text.split(':').filter(|part| !part.is_empty()).count();
    if !text.contains("::") && groups != 8 {
        return None;
    }
    if text.contains("::") && groups > 7 {
        return None;
    }
    Some(value)
}

/// Переопределения адресов DC вида «2:149.154.167.220».
///
/// Принимает элементы как python: одна строка с любыми разделителями или
/// список строк. Возвращает пары в порядке первого появления DC.
#[must_use]
pub fn parse_dc_endpoint_overrides(items: &[String]) -> Vec<(i32, String)> {
    let mut raw_items: Vec<String> = Vec::new();
    for item in items {
        for piece in item.replace([',', ';'], " ").split(' ') {
            if !piece.is_empty() {
                raw_items.push(piece.to_string());
            }
        }
    }
    let mut overrides: Vec<(i32, String)> = Vec::new();
    for item in raw_items {
        let Some((dc_text, ip_text)) = item.split_once(':') else {
            continue;
        };
        let Ok(dc) = dc_text.trim().parse::<i32>() else {
            continue;
        };
        let Some(parsed) = parse_ipv4(ip_text.trim()) else {
            continue;
        };
        if !matches!(dc, 1..=5 | 203) {
            continue;
        }
        let ip = format!(
            "{}.{}.{}.{}",
            parsed >> 24,
            (parsed >> 16) & 0xFF,
            (parsed >> 8) & 0xFF,
            parsed & 0xFF
        );
        if let Some(entry) = overrides.iter_mut().find(|(known, _)| *known == dc) {
            entry.1 = ip;
        } else {
            overrides.push((dc, ip));
        }
    }
    overrides
}

/// Прямой TCP-адрес DC с учётом переопределений пользователя.
#[must_use]
pub fn dc_to_tcp_endpoint(dc: i32, overrides: &[(i32, String)], is_media: bool) -> (String, u16) {
    if let Some((_, ip)) = overrides.iter().find(|(known, _)| *known == dc) {
        return (ip.clone(), 443);
    }
    let (host, port) = if is_media {
        tcp_media_endpoint(dc)
    } else {
        tcp_endpoint(dc)
    };
    (host.to_string(), port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ip_addresses_map_to_their_dc() {
        assert_eq!(ip_to_dc_entry("149.154.175.52"), Some((1, true)));
        assert_eq!(ip_to_dc_entry("149.154.167.220"), Some((2, false)));
        assert_eq!(ip_to_dc_entry("149.154.164.250"), Some((4, true)));
        assert_eq!(ip_to_dc_entry("91.105.192.100"), Some((203, false)));
        assert_eq!(ip_to_dc_entry("8.8.8.8"), None);
    }

    #[test]
    fn subnets_map_to_dc_by_specificity() {
        assert_eq!(ip_to_dc("149.154.175.53"), 1);
        assert_eq!(ip_to_dc("149.154.167.51"), 2);
        assert_eq!(ip_to_dc("149.154.165.111"), 4);
        assert_eq!(ip_to_dc("91.108.56.134"), 5);
        assert_eq!(ip_to_dc("185.76.151.10"), 2);
        assert_eq!(ip_to_dc("1.2.3.4"), 2);
        assert_eq!(ip_to_dc("not-an-ip"), 2);
        assert_eq!(ip_to_dc("2001:67c:4e8:f002::1"), 2);
        assert_eq!(ip_to_dc("2a0a:f280:203::1"), 203);
    }

    #[test]
    fn telegram_ip_ranges_cover_official_prefixes() {
        assert!(is_telegram_ip("91.108.56.134"));
        assert!(is_telegram_ip("149.154.167.51"));
        assert!(is_telegram_ip("185.76.151.10"));
        assert!(is_telegram_ip("2001:67c:4e8::1"));
        assert!(!is_telegram_ip("8.8.8.8"));
        assert!(!is_telegram_ip("bogus"));
        // python3 -c "from ipaddress import ip_address;
        //              print(str(ip_address('2a0a:f280:203::1')))"
        assert!(is_telegram_ip("2a0a:f280:203::1"));
    }

    #[test]
    fn dc_endpoint_overrides_parse_and_normalize() {
        // python3 -c "
        // import sys; sys.path.insert(0, '/home/kalinov/Документы/zapretgui/src')
        // from telegram_proxy.proxy.dc_map import parse_dc_endpoint_overrides
        // print(parse_dc_endpoint_overrides(
        //     ['2:149.154.167.220', 'bad', '4:999.1.1.1', '4:149.154.167.220',
        //      '203:91.105.192.100']))"
        let items: Vec<String> = [
            "2:149.154.167.220",
            "bad",
            "4:999.1.1.1",
            "4:149.154.167.220",
            "203:91.105.192.100",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            parse_dc_endpoint_overrides(&items),
            vec![
                (2, "149.154.167.220".to_string()),
                (4, "149.154.167.220".to_string()),
                (203, "91.105.192.100".to_string()),
            ]
        );
        assert!(parse_dc_endpoint_overrides(&[]).is_empty());
        assert!(parse_dc_endpoint_overrides(&["7:1.2.3.4".to_string()]).is_empty());
    }

    #[test]
    fn tcp_endpoints_follow_overrides_and_media() {
        let overrides = parse_dc_endpoint_overrides(&["4:149.154.167.220".to_string()]);
        assert_eq!(
            dc_to_tcp_endpoint(4, &overrides, false),
            ("149.154.167.220".to_string(), 443)
        );
        assert_eq!(
            dc_to_tcp_endpoint(2, &[], true),
            ("149.154.167.151".to_string(), 443)
        );
        assert_eq!(
            dc_to_tcp_endpoint(4, &[], true),
            ("149.154.164.250".to_string(), 443)
        );
        assert_eq!(
            dc_to_tcp_endpoint(4, &overrides, true),
            ("149.154.167.220".to_string(), 443)
        );
        assert_eq!(
            dc_to_tcp_endpoint(203, &[], false),
            ("91.105.192.100".to_string(), 443)
        );
    }
}
