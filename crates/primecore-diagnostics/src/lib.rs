//! Порт `src/diagnostics` — проверки BlockCheck и DNS-подмены.
//!
//! Модули копируют структуру python-пакета:
//! `address_kinds` (`utils/address_kinds.py`), `levels`, `limits`,
//! `subnet_catalog`, `block_kind`, `probe_result` (`diagnostics/tls_probe.py`
//! без сетевой части), `services`, `verdict`. Движок, пробы и очереди
//! (`engine`, `run_context`, `registry`, пробы) портируются следом.

pub mod address_kinds;
pub mod block_kind;
pub mod levels;
pub mod limits;
pub mod probe_result;
pub mod services;
pub mod subnet_catalog;
pub mod verdict;
