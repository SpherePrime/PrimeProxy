//! Порт `src/utils/address_kinds.py` — что за адрес пришёл в ответе DNS.
//!
//! Единственное место, где программа решает, «похож ли адрес на подмену».
//! Проверки (BlockCheck, «Проверка домена», подбор стратегий) берут отсюда вид
//! адреса и сами решают, что сказать пользователю.

use std::net::Ipv4Addr;

/// Значения `AddressKind` — строки отчёта.
pub const AK_PUBLIC: &str = "public";
/// Известная страница-заглушка провайдера или РКН.
pub const AK_BLOCK_STUB: &str = "block_stub";
/// VPN-клиенты в режиме fake-ip (sing-box, Clash, Happ) отдают такие адреса
/// и сами подставляют настоящий сервер. Это не провайдер.
pub const AK_FAKE_IP: &str = "fake_ip";
/// Адрес самого компьютера или «никуда»: 127.0.0.1, 0.0.0.0, ::1.
pub const AK_SELF: &str = "self";
/// Домашняя или рабочая сеть.
pub const AK_LOCAL: &str = "local";
/// Внутренняя сеть провайдера (CGNAT, RFC 6598).
pub const AK_CARRIER: &str = "carrier";
/// Зарезервированные и групповые адреса.
pub const AK_SERVICE: &str = "service";
pub const AK_INVALID: &str = "invalid";

/// `AddressKind` (python Enum со строковым значением).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressKind(&'static str);

impl AddressKind {
    pub const PUBLIC: AddressKind = AddressKind(AK_PUBLIC);
    pub const BLOCK_STUB: AddressKind = AddressKind(AK_BLOCK_STUB);
    pub const FAKE_IP: AddressKind = AddressKind(AK_FAKE_IP);
    pub const SELF: AddressKind = AddressKind(AK_SELF);
    pub const LOCAL: AddressKind = AddressKind(AK_LOCAL);
    pub const CARRIER: AddressKind = AddressKind(AK_CARRIER);
    pub const SERVICE: AddressKind = AddressKind(AK_SERVICE);
    pub const INVALID: AddressKind = AddressKind(AK_INVALID);

    pub fn value(self) -> &'static str {
        self.0
    }
}

/// Чья заглушка — для подписи в отчётах.
pub const BLOCK_STUB_OWNERS: [(&str, &str); 8] = [
    ("195.82.146.214", "Ростелеком"),
    ("81.19.72.32", "МТС"),
    ("213.180.193.250", "Билайн"),
    ("217.169.80.229", "Мегафон"),
    ("62.33.207.196", "РКН"),
    ("62.33.207.197", "РКН"),
    ("62.33.207.198", "РКН"),
    ("10.10.10.10", "внутренняя заглушка"),
];

/// python ip_network("198.18.0.0/15") = 198.18.0.0–198.19.255.255.
fn in_fake_ip_network(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// python ip_network("100.64.0.0/10") = 100.64.0.0–100.127.255.255.
fn in_carrier_network(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && o[1] >= 64 && o[1] <= 127
}

/// python: `address.is_loopback or address.is_unspecified` — и для IPv4, и для IPv6.
fn is_self(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.octets() == [0, 0, 0, 0],
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.octets() == [0u8; 16],
    }
}

/// python: `address.is_reserved or address.is_multicast` — отнесение остальных
/// python: SERVICE = `is_reserved or is_multicast` (упрощение для IPv6 —
/// практические служебные диапазоны, заглушки сайтов так не отвечают).
fn is_service(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || is_reserved_v4(v4),
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_multicast()
                || segments[0] == 0
                || segments[0] == 0x0100
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

/// python `is_reserved` для IPv4: только 240.0.0.0/4 (в 0.0.0.0/8 python
/// относит адреса к частным).
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    v4.octets()[0] >= 240
}

/// python `is_link_local or is_private` для IPv4/IPv6.
fn is_local(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                // 192.0.0.0/29, 192.0.0.170/31 (прочее специальное)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || v4.is_link_local()
                // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (документация)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        std::net::IpAddr::V6(v6) => v6.is_unicast_link_local() || v6.is_unique_local(),
    }
}

/// Адрес из известного словаря заглушек `BLOCK_STUB_OWNERS`.
fn block_stub_by_owner(text: &str) -> bool {
    BLOCK_STUB_OWNERS
        .iter()
        .any(|(owner_ip, _)| *owner_ip == text)
}

/// python `BLOCK_STUB_OWNERS.get(ip, "")`.
pub fn block_stub_owner(ip: &str) -> &str {
    let text = ip.trim();
    BLOCK_STUB_OWNERS
        .iter()
        .find_map(|(owner_ip, owner)| {
            if *owner_ip == text {
                Some(*owner)
            } else {
                None
            }
        })
        .unwrap_or("")
}

/// Адрес у которого вид — из подмены (`STUB_KINDS`): заглушка провайдера, сам
/// компьютер, домашняя сеть, сеть провайдера или служебный адрес.
pub fn is_stub_address(ip: &str) -> bool {
    matches!(
        address_kind(ip),
        AddressKind::BLOCK_STUB
            | AddressKind::SELF
            | AddressKind::LOCAL
            | AddressKind::CARRIER
            | AddressKind::SERVICE
    )
}

/// python `address_kind(ip: str) -> AddressKind`.
pub fn address_kind(ip: &str) -> AddressKind {
    let text = ip.trim();
    if block_stub_by_owner(text) {
        return AddressKind::BLOCK_STUB;
    }
    let parsed: std::net::IpAddr = match text.parse() {
        Ok(value) => value,
        Err(_) => return AddressKind::INVALID,
    };
    match parsed {
        std::net::IpAddr::V4(v4) => {
            if in_fake_ip_network(v4) {
                return AddressKind::FAKE_IP;
            }
            if is_self(parsed) {
                return AddressKind::SELF;
            }
            if in_carrier_network(v4) {
                return AddressKind::CARRIER;
            }
            if v4.is_multicast() || is_reserved_v4(v4) {
                return AddressKind::SERVICE;
            }
            if is_local(parsed) {
                return AddressKind::LOCAL;
            }
            AddressKind::PUBLIC
        }
        std::net::IpAddr::V6(_) => {
            if is_self(parsed) {
                return AddressKind::SELF;
            }
            if is_service(parsed) {
                return AddressKind::SERVICE;
            }
            if is_local(parsed) {
                return AddressKind::LOCAL;
            }
            AddressKind::PUBLIC
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_borrows_for_generic_args)]
mod tests {
    use super::*;

    #[test]
    fn stub_owners() {
        assert_eq!(address_kind("62.33.207.197"), AddressKind::BLOCK_STUB);
        assert_eq!(block_stub_owner("62.33.207.197"), "РКН");
        assert_eq!(block_stub_owner("10.10.10.10"), "внутренняя заглушка");
        assert_eq!(block_stub_owner("1.2.3.4"), "");
    }

    #[test]
    fn fake_ip() {
        assert_eq!(address_kind("198.18.0.1"), AddressKind::FAKE_IP);
        assert_eq!(address_kind("198.19.255.255"), AddressKind::FAKE_IP);
        assert_eq!(address_kind("198.20.0.1"), AddressKind::PUBLIC);
        assert_eq!(address_kind("198.17.255.1"), AddressKind::PUBLIC);
    }

    #[test]
    fn self_and_local() {
        assert_eq!(address_kind("127.0.0.1"), AddressKind::SELF);
        assert_eq!(address_kind("0.0.0.0"), AddressKind::SELF);
        assert_eq!(address_kind("::1"), AddressKind::SELF);
        assert_eq!(address_kind("192.168.1.5"), AddressKind::LOCAL);
        assert_eq!(address_kind("10.1.2.3"), AddressKind::LOCAL);
        assert_eq!(address_kind("100.64.0.1"), AddressKind::CARRIER);
        assert_eq!(address_kind("100.127.0.1"), AddressKind::CARRIER);
        assert_eq!(address_kind("100.128.0.1"), AddressKind::PUBLIC);
    }

    #[test]
    fn service_and_public() {
        assert_eq!(address_kind("240.0.0.1"), AddressKind::SERVICE);
        assert_eq!(address_kind("224.0.0.1"), AddressKind::SERVICE);
        assert_eq!(address_kind("192.0.2.1"), AddressKind::LOCAL);
        assert_eq!(address_kind("77.88.44.242"), AddressKind::PUBLIC);
        assert_eq!(address_kind("2606:4700::1111"), AddressKind::PUBLIC);
    }

    #[test]
    fn invalid() {
        assert_eq!(address_kind(""), AddressKind::INVALID);
        assert_eq!(address_kind("nxdomain"), AddressKind::INVALID);
        assert_eq!(address_kind(" 77.88.44.242 "), AddressKind::PUBLIC);
    }
}
