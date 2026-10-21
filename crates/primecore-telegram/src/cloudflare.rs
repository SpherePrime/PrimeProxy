//! Фасад проверок Cloudflare: `telegram_proxy/proxy/cloudflare.py`.
//!
//! В python-пакете файл один — `proxy/cloudflare.py`, и в крейте он уже
//! перенесён в [`crate::proxy::cloudflare`]. Модуль здесь оставлен, чтобы
//! структура модулей крейта повторяла подпакеты python-пакета и внешние
//! вызовы (`diagnostics`, страницы) могли пользоваться коротким путём.
//!
//! Проверка доступности доменов и воркеров — сетевое действие: она идёт через
//! замыкание `connect`, крейт соединений не открывает.

pub use crate::proxy::cloudflare::{
    auto_cloudflare_domains, build_cfproxy_dns_records_text, build_cfworker_code,
    build_worker_path, check_cloudflare_connectivity, normalize_domain_list, probe_targets,
    CloudflareCheckEntry, CloudflareCheckResult, CloudflareDnsRecord, CloudflareFallbackConfig,
    CLOUDFLARE_DNS_RECORDS,
};
