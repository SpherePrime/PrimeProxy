//! Порт `src/dns/public.py` — фасад-реэкспорт пакета `dns`.
//!
//! Python-модуль перепаковывает публичные команды и типы DNS-слоя под одним
//! именем (`dns`): остальной программе не нужно знать, в каком модуле живёт
//! каждая команда. Rust-версия делает то же: команды из [`crate::dns_commands`]
//! (те, в свою очередь, — из [`crate::runtime`]) и типы из [`crate::state`].
//!
//! Разница с python одна: в Rust команды принимают платформенный ввод
//! (Windows-вызовы, настройки, сеть) замыканиями/трейтами, поэтому фасад
//! экспортирует и вводы — [`crate::runtime::DnsIo`],
//! [`crate::local_proxy::LocalProxySystem`], [`crate::doh_lookup::LookupIo`].

pub use crate::dns_commands::{
    apply_dns, check_answering, consume_warmed_state, delete_custom_server,
    duplicate_custom_server, flush_dns_cache, is_isp_dns_warning_shown, load_page_state,
    mark_isp_dns_warning_shown, measure_dns_latency, migrate_outdated_dns_addresses,
    repair_local_proxy, reset_to_auto, save_custom_server, start_local_proxy,
    stop_local_proxy_if_unused, warm_state,
};

/// python `DNS_PROVIDERS` — весь список серверов программы.
pub use crate::providers::dns_providers;

pub use crate::state::{CustomServerResult, DnsCommandResult, DnsState};
