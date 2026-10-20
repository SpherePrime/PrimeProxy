//! Порт `src/diagnostics` — проверки BlockCheck и DNS-подмены.
//!
//! Модули копируют структуру python-пакета. Сетевые пробы (TLS-стек, QUIC
//! Initial, STUN, DoH/DoT, ping, внешняя служба проекта) разнесены по
//! модулям: каждая держит свои типы, константы и чистый вывод, а сбор
//! сетевых фактов портируется следом, как только появится HTTPS/TLS-клиент.

pub mod address_kinds;
pub mod block_cause;
pub mod block_kind;
pub mod cert_owner;
pub mod chrome_https;
pub mod ip_owner;
pub mod history;
pub mod icmp;
pub mod freeze_check;
pub mod ipv6_check;
pub mod levels;
pub mod limits;
pub mod outside_check;
pub mod probe_result;
pub mod registry;
pub mod my_network;
pub mod name_speed;
pub mod compare;
pub mod crowd_probe;
pub mod dns_place;
pub mod dns_reference;
pub mod problems;
pub mod report_contract;
pub mod report_text;
pub mod report_upgrade;
pub mod protocol_probe;
pub mod quic_probe;
pub mod run_context;
pub mod system_state;
pub mod self_check;
pub mod services;
pub mod speed_check;
pub mod subnet_catalog;
pub mod subnet_whitelist;
pub mod telegram_check;
pub mod udp_burst;
pub mod upload_probe;
pub mod verdict;
pub mod voice_check;
pub mod volume_probe;
pub mod windows_dns_query;
