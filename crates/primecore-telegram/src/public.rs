//! Фасад пакета: реэкспорт публичного API.
//!
//! Порт `telegram_proxy/public.py`: python-модуль только переэкспортирует
//! команды runtime-слоя, чтобы остальной код программы не зависел от
//! внутренней структуры пакета. Здесь то же самое — `pub use` поверх
//! [`crate::runtime`] и [`crate::manager`].
//!
//! python `run_diagnostics` в крейте нет: сама диагностика открывает сеть
//! и остаётся у вызывающего кода; для сборки итогового текста используется
//! [`crate::diagnostics::build_summary`].

/// Действия применения настроек (python `runtime.settings_save_flow`).
pub use crate::config::settings::{merge_restart_request, normalize_restart_request};
/// Менеджер прокси и автозапуск (python `telegram_proxy.manager`).
pub use crate::manager::{
    autostart_params, build_cloudflare_proxy_config_from_settings,
    build_dc_endpoint_overrides_from_settings, build_upstream_proxy_config_from_settings,
    start_proxy_if_enabled_async, ProxyRuntime, ProxyStartParams, TelegramProxyManager,
};
/// Команды runtime-слоя (python `telegram_proxy.runtime.commands`).
pub use crate::runtime::{
    append_log_line, build_diagnostics_finish_plan, build_diagnostics_poll_plan,
    build_diagnostics_start_plan, consume_auto_deeplink_request, copy_text, get_start_config,
    open_external_link, open_log_file, run_telegram_hosts_action, save_settings_action,
    set_enabled, TelegramHostsActionResult, TelegramProxyActionResult,
    TelegramProxyDiagnosticsFinishPlan, TelegramProxyDiagnosticsPollPlan,
    TelegramProxyDiagnosticsStartPlan, TelegramProxyStartConfig, TELEGRAM_HOSTS_ACTIONS,
};

/// Основные типы ядра, доступные через фасад (python берёт их из
/// `telegram_proxy.wss_proxy` и `telegram_proxy.proxy_logger`).
pub use crate::proxy::cloudflare::CloudflareFallbackConfig;
/// Внешний SOCKS5.
pub use crate::proxy::routing::UpstreamProxyConfig;
/// Живая статистика.
pub use crate::proxy::stats::ProxyStats;
/// Снимок состояния внешнего SOCKS5.
pub use crate::proxy::upstream_controller::UpstreamRuntimeSnapshot;
/// Журнал Telegram Proxy.
pub use crate::proxy_logger::ProxyLogger;
