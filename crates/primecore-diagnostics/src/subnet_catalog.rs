//! Порт `src/diagnostics/subnet_catalog.py` — адреса российских и зарубежных сетей
//! для проверки «белого списка» (`diagnostics::subnet_whitelist`).
//!
//! Собран скриптом `scripts/update_subnet_catalog.py`: каждый адрес отвечал на
//! TCP 443 с обычной линии. Подход взят из hyperion-cs/dpi-checkers (Apache-2.0),
//! состав свой.

pub const REGION_RU: &str = "ru";
pub const REGION_FOREIGN: &str = "foreign";

/// (подпись сети, область, адреса из разных /24).
pub const SUBNET_GROUPS: [(&str, &str, &[&str]); 35] = [
    ("Яндекс", REGION_RU, &["77.88.44.242", "5.255.255.242", "77.88.55.242"]),
    ("VK", REGION_RU, &["93.186.225.194", "87.240.129.133", "87.240.132.72"]),
    ("Mail.ru", REGION_RU, &["90.156.232.4", "89.221.239.1", "185.180.201.1"]),
    ("Max", REGION_RU, &["155.212.204.140"]),
    ("Госуслуги", REGION_RU, &["213.59.254.7", "213.59.253.7"]),
    ("Сбер", REGION_RU, &["84.252.149.206"]),
    ("Т-Банк", REGION_RU, &["178.130.128.27"]),
    ("ВТБ", REGION_RU, &["195.242.83.13", "195.242.82.13", "185.179.146.43"]),
    ("Альфа-Банк", REGION_RU, &["217.12.104.100", "217.12.98.153"]),
    ("Ozon", REGION_RU, &["185.73.193.68", "185.73.194.82"]),
    ("Wildberries", REGION_RU, &["185.62.202.2"]),
    ("Авито", REGION_RU, &["176.114.120.24", "176.114.122.24", "176.114.124.24"]),
    ("МТС", REGION_RU, &["178.248.238.27"]),
    ("МегаФон", REGION_RU, &["188.162.60.210", "178.177.13.149"]),
    ("Билайн", REGION_RU, &["217.118.87.98"]),
    ("Т2", REGION_RU, &["37.220.163.23", "78.41.111.223", "37.220.161.64"]),
    ("Ростелеком", REGION_RU, &["87.226.162.216"]),
    ("ФНС", REGION_RU, &["195.208.66.236", "213.24.64.17"]),
    ("Мос.ру", REGION_RU, &["212.11.155.134"]),
    ("Rutube", REGION_RU, &["178.248.233.148", "109.238.90.239"]),
    ("Hetzner", REGION_FOREIGN, &["5.161.7.195", "95.217.255.81"]),
    ("OVH", REGION_FOREIGN, &["141.95.207.211", "198.27.92.14"]),
    ("Vultr", REGION_FOREIGN, &["108.61.198.102", "108.61.210.117", "108.61.209.127"]),
    ("Linode", REGION_FOREIGN, &["139.162.130.8", "176.58.107.39", "50.116.57.237"]),
    ("Leaseweb", REGION_FOREIGN, &["95.211.20.80", "178.162.226.176", "23.105.9.80"]),
    ("Cloudflare", REGION_FOREIGN, &["104.16.132.229", "104.16.133.229", "1.0.0.1"]),
    ("Amazon", REGION_FOREIGN, &["3.78.204.201", "3.78.202.89", "3.5.121.176"]),
    ("Google", REGION_FOREIGN, &["142.251.13.138", "192.178.183.138", "142.251.156.119"]),
    ("GitHub", REGION_FOREIGN, &["140.82.121.3"]),
    ("Microsoft", REGION_FOREIGN, &["40.126.31.130", "20.190.159.2", "40.126.32.133"]),
    ("Fastly", REGION_FOREIGN, &["151.101.193.57", "151.101.129.57", "151.101.65.57"]),
    ("Wikimedia", REGION_FOREIGN, &["185.15.59.224"]),
    ("Apple", REGION_FOREIGN, &["17.248.209.81", "17.179.252.64", "17.23.96.13"]),
    ("Oracle", REGION_FOREIGN, &["138.1.33.162", "23.209.208.114"]),
    ("Stack Overflow", REGION_FOREIGN, &["198.252.206.1"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_shape() {
        assert_eq!(SUBNET_GROUPS.len(), 35);
        assert_eq!(SUBNET_GROUPS[0].0, "Яндекс");
        assert_eq!(SUBNET_GROUPS[0].1, REGION_RU);
        for (title, _region, addresses) in SUBNET_GROUPS {
            assert!(!title.is_empty());
            assert!(!addresses.is_empty(), "{title}");
        }
    }
}
