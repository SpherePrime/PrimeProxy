//! Порт `src/config` (чистая часть) — адреса документации и утилиты
//! Telegram-ссылок.
//!
//! Проверка установленного Telegram (winreg) и открытие ссылок
//! (webbrowser) — платформенные: остаются у вызывающего слоя.

pub mod telegram_links;
pub mod urls;
