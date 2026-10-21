//! Порт `src/telegram_proxy` — локальный прокси Telegram: SOCKS5/MTProxy на
//! входе, WSS (релеи kwsN, фронты Cloudflare, туннель через воркеры), внешний
//! SOCKS5 и прямой TCP на выходе.
//!
//! Модули повторяют подпакеты python-пакета `telegram_proxy`. Сеть (TCP, TLS,
//! WebSocket-подключение, UDP) в крейте не открывается: сетевые действия идут
//! через замыкания, а здесь остаются решения — план маршрутов, здоровье
//! маршрутов, кластеры ключей медиа-сессии, шифры obfuscated2 и Fake TLS.
//!
//! PyQt6-интерфейс пакета (`telegram_proxy/ui`) в Rust не переносится: он
//! остаётся в Python-части программы. Чистые решения из ui-обёрток
//! (`upstream_workflow`, счётчики журнала) вошли в [`config`] и [`wss_proxy`].

pub mod cloudflare;
pub mod config;
pub mod crypto;
pub mod diagnostics;
pub mod manager;
pub mod proxy;
pub mod proxy_logger;
pub mod public;
pub mod runtime;
pub mod telegram_hosts;
pub mod wss_proxy;
