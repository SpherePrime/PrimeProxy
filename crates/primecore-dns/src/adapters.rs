//! Порт `src/dns/adapters.py` — какие сетевые адаптеры показывать на странице
//! DNS и в каком порядке.
//!
//! Решение принимается по признакам, которые сообщает сама Windows, а не по
//! словам в названии:
//!
//! - показываем настоящие сетевые карты — «аппаратный интерфейс» с «разъёмом»
//!   (Ethernet и Wi-Fi; сетевая карта внутри виртуальной машины тоже такая);
//! - и адаптер Ethernet/Wi-Fi, через который сейчас идёт интернет, даже если
//!   он виртуальный (Hyper-V с внешним коммутатором: IP-настройки хоста живут
//!   на «vEthernet»);
//! - не показываем и не трогаем всё остальное: фильтры (WFP, QoS, Npcap),
//!   внутренние сети Hyper-V/VMware/VirtualBox/WSL, VPN-туннели, Wi-Fi Direct,
//!   отладчик ядра. Смена DNS на них ломает виртуалки и VPN.
//!
//! Типы `RawInterface`/`InternetRoute`/`StaticDns` — данные из `dns/winapi.py`
//! (тонкой обёртки над IP Helper API); сами Windows-вызовы остаются
//! платформенным слоем и портируются следом.

/// python `IF_TYPE_ETHERNET_CSMACD`.
pub const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
/// python `IF_TYPE_IEEE80211`.
pub const IF_TYPE_IEEE80211: u32 = 71;

/// python `DNS_ADAPTER_TYPES`.
pub const DNS_ADAPTER_TYPES: [u32; 2] = [IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211];

/// python `RawInterface` — сетевой интерфейс так, как его описывает Windows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawInterface {
    pub guid: String,
    pub index: u32,
    pub ipv6_index: u32,
    pub name: String,
    pub description: String,
    pub if_type: u32,
    pub connected: bool,
    pub hardware: bool,
    pub filter: bool,
    pub connector: bool,
    pub dns_ipv4: Vec<String>,
    pub dns_ipv6: Vec<String>,
}

/// python `InternetRoute` — индексы интерфейсов, через которые идёт интернет
/// (0 — маршрута нет).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InternetRoute {
    pub ipv4_index: u32,
    pub ipv6_index: u32,
}

impl InternetRoute {
    /// python `has_ipv6` — считает ли Windows, что по IPv6 есть дорога.
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_index != 0
    }
}

/// python `StaticDns` — DNS, прописанные вручную; пусто — адаптер получает
/// DNS автоматически.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticDns {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

/// python `DnsAdapter` — адаптер на странице DNS. Опознаётся по GUID: имя
/// можно переименовать.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsAdapter {
    pub guid: String,
    pub name: String,
    pub description: String,
    /// "ethernet" | "wifi"
    pub kind: String,
    pub connected: bool,
    pub internet: bool,
    pub static_ipv4: Vec<String>,
    pub static_ipv6: Vec<String>,
    pub auto_ipv4: Vec<String>,
    pub auto_ipv6: Vec<String>,
}

impl DnsAdapter {
    /// python `is_automatic` — DNS адаптера выдаётся автоматически.
    #[must_use]
    pub fn is_automatic(&self) -> bool {
        self.static_ipv4.is_empty() && self.static_ipv6.is_empty()
    }
}

/// python `is_internet_interface` — через этот интерфейс идёт интернет.
#[must_use]
pub fn is_internet_interface(interface: &RawInterface, route: &InternetRoute) -> bool {
    let mut indexes: Vec<u32> = Vec::new();
    for index in [route.ipv4_index, route.ipv6_index] {
        if index != 0 && !indexes.contains(&index) {
            indexes.push(index);
        }
    }
    indexes.contains(&interface.index) || indexes.contains(&interface.ipv6_index)
}

/// python `is_dns_adapter` — адаптер показывается на странице и его можно
/// трогать.
#[must_use]
pub fn is_dns_adapter(interface: &RawInterface, route: &InternetRoute) -> bool {
    if interface.filter || !DNS_ADAPTER_TYPES.contains(&interface.if_type) {
        return false;
    }
    if interface.hardware && interface.connector {
        return true;
    }
    is_internet_interface(interface, route)
}

/// python `build_dns_adapters` — адаптеры для страницы: сначала интернет,
/// потом подключённые, потом по имени.
#[must_use]
pub fn build_dns_adapters(
    interfaces: &[RawInterface],
    route: &InternetRoute,
    static_dns: &[(String, StaticDns)],
) -> Vec<DnsAdapter> {
    let mut adapters: Vec<DnsAdapter> = Vec::new();
    for interface in interfaces {
        if !is_dns_adapter(interface, route) {
            continue;
        }
        let static_entry = static_dns
            .iter()
            .find(|(guid, _)| *guid == interface.guid)
            .map(|(_, dns)| dns.clone())
            .unwrap_or_default();
        let kind = if interface.if_type == IF_TYPE_IEEE80211 {
            "wifi"
        } else {
            "ethernet"
        };
        adapters.push(DnsAdapter {
            guid: interface.guid.clone(),
            name: interface.name.clone(),
            description: interface.description.clone(),
            kind: kind.to_string(),
            connected: interface.connected,
            internet: is_internet_interface(interface, route),
            static_ipv4: static_entry.ipv4.clone(),
            static_ipv6: static_entry.ipv6.clone(),
            auto_ipv4: if static_entry.ipv4.is_empty() {
                interface.dns_ipv4.clone()
            } else {
                Vec::new()
            },
            auto_ipv6: if static_entry.ipv6.is_empty() {
                interface.dns_ipv6.clone()
            } else {
                Vec::new()
            },
        });
    }
    // Сортировка: сначала интернет, потом подключённые, потом по имени без
    // учёта регистра (python `casefold`).
    adapters.sort_by(|left, right| {
        let left_key = (!left.internet, !left.connected, left.name.to_lowercase());
        let right_key = (!right.internet, !right.connected, right.name.to_lowercase());
        left_key.cmp(&right_key)
    });
    adapters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(
        guid: &str,
        name: &str,
        if_type: u32,
        hardware: bool,
        connector: bool,
    ) -> RawInterface {
        RawInterface {
            guid: guid.to_string(),
            index: 1,
            ipv6_index: 1,
            name: name.to_string(),
            description: format!("описание {name}"),
            if_type,
            connected: true,
            hardware,
            filter: false,
            connector,
            dns_ipv4: vec!["192.168.1.1".to_string()],
            dns_ipv6: Vec::new(),
        }
    }

    #[test]
    fn selection_by_features_not_names() {
        let route = InternetRoute {
            ipv4_index: 7,
            ipv6_index: 7,
        };
        // Настоящая карта: «аппаратный» с «разъёмом».
        let ethernet = interface("g1", "Ethernet", IF_TYPE_ETHERNET_CSMACD, true, true);
        let wifi = interface("g2", "Wi-Fi", IF_TYPE_IEEE80211, true, true);
        // Виртуальный адаптер с внешним коммутатором: не аппаратный, но через
        // него идёт интернет.
        let mut vethernet = interface("g3", "vEthernet", IF_TYPE_ETHERNET_CSMACD, false, false);
        vethernet.index = 7;
        vethernet.ipv6_index = 7;
        // Фильтр (Npcap): не показывается, даже если признакиhardware.
        let mut npcap = interface("g4", "Npcap", IF_TYPE_ETHERNET_CSMACD, true, true);
        npcap.filter = true;
        // Внутренняя сеть Hyper-V без дороги в интернет: не показывается.
        let internal = interface("g5", "Hyper-V", IF_TYPE_ETHERNET_CSMACD, false, false);
        let adapters = build_dns_adapters(
            &[
                ethernet.clone(),
                wifi.clone(),
                vethernet.clone(),
                npcap,
                internal,
            ],
            &route,
            &[],
        );
        assert_eq!(
            adapters
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["vEthernet", "Ethernet", "Wi-Fi"],
            "интернет первым, дальше по имени"
        );
        assert!(adapters[0].internet);
        assert!(!adapters[1].internet);
        assert_eq!(adapters[0].kind, "ethernet");
        assert_eq!(adapters[1].kind, "ethernet");
        assert_eq!(adapters[2].kind, "wifi");
    }

    #[test]
    fn static_and_auto_dns() {
        let route = InternetRoute {
            ipv4_index: 1,
            ipv6_index: 0,
        };
        let card = interface("g1", "Ethernet", IF_TYPE_ETHERNET_CSMACD, true, true);
        // Ручные DNS на адаптере: авто-адреса не показываются.
        let static_dns = vec![(
            "g1".to_string(),
            StaticDns {
                ipv4: vec!["9.9.9.9".to_string()],
                ipv6: vec!["2620:fe::fe".to_string()],
            },
        )];
        let adapters = build_dns_adapters(&[card], &route, &static_dns);
        assert_eq!(adapters[0].static_ipv4, vec!["9.9.9.9".to_string()]);
        assert_eq!(adapters[0].static_ipv6, vec!["2620:fe::fe".to_string()]);
        assert!(adapters[0].auto_ipv4.is_empty());
        assert!(!adapters[0].is_automatic());
    }

    #[test]
    fn route_index_zero_means_no_route() {
        let interface = interface("g1", "Ethernet", IF_TYPE_ETHERNET_CSMACD, false, false);
        assert!(!is_internet_interface(
            &interface,
            &InternetRoute::default()
        ));
        assert!(!InternetRoute {
            ipv4_index: 0,
            ipv6_index: 0
        }
        .has_ipv6());
        assert!(InternetRoute {
            ipv4_index: 0,
            ipv6_index: 5
        }
        .has_ipv6());
    }
}
