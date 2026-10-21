//! Подпакет `telegram_proxy/proxy`: ядро прокси Telegram.
//!
//! Шифры и разбор потока — [`obfs`] и [`aes_ctr`], план маршрутов —
//! [`routes`] со здоровьем [`health`] и каталогом адресов [`route_catalog`],
//! ключи медиа-сессии — [`key_clusters`], внешний SOCKS —
//! [`upstream_controller`]. Сеть (WebSocket, TCP, TLS) идёт через замыкания
//! вызывающего кода.

pub mod aes_ctr;
pub mod cloudflare;
pub mod dc_map;
pub mod fake_tls;
pub mod health;
pub mod key_clusters;
pub mod mtproxy;
pub mod obfs;
pub mod pool;
pub mod route_catalog;
pub mod routes;
pub mod routing;
pub mod session;
pub mod socks5;
pub mod stats;
pub mod upstream_controller;
pub mod upstream_runtime;
pub mod ws;
