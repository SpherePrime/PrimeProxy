//! Порт `src/dns` — слой DNS программы: список серверов, свои серверы,
//! проверки линии, встроенный шифрованный посредник.
//!
//! Модули копируют структуру python-пакета `dns`. Сетевые вопросы (UDP/TCP/
//! DoH-запросы) идут через [`primecore_dnswire`], Windows-вызовы (winapi.py)
//! остаются платформенным слоем — здесь только типы и решения по признакам.
//!
//! PyQt6-интерфейс пакета (`dns/ui`) в Rust не переносится: он остаётся
//! в Python-части программы.

pub mod adapters;
pub mod address_migration;
pub mod answering;
pub mod custom_servers;
pub mod dns_check_plans;
pub mod dns_commands;
pub mod doh_lookup;
pub mod domain_lookup;
pub mod domain_lookup_plans;
pub mod domain_lookup_run;
pub mod domain_lookup_steps;
pub mod info_line;
pub mod interception;
pub mod latency;
pub mod line_check;
pub mod local_proxy;
pub mod local_proxy_catalog;
pub mod local_proxy_config;
pub mod page_plans;
pub mod providers;
pub mod public;
pub mod reachability;
pub mod runtime;
pub mod server_check;
pub mod server_check_plans;
pub mod server_check_plans_text;
pub mod server_check_verdict;
pub mod server_check_verdicts;
pub mod state;
