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
pub mod answering;
pub mod custom_servers;
pub mod interception;
pub mod latency;
pub mod local_proxy_catalog;
pub mod providers;
pub mod reachability;
pub mod state;
