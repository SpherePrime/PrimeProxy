//! Порт `src/diagnostics/outside_check.py` — «жив ли сайт снаружи».
//!
//! Проверка спрашивает свой сервер проекта Zapret DNS в Нидерландах
//! (служба `zapret-dns-outside`): он сам открывает сайт по HTTPS и отвечает,
//! жив ли тот. Смотрите только встроенные сайты BlockCheck; адрес сервера
//! узнаётся у эталонного DoH. Сетевая часть (`_post`, `ask`) портируется
//! вместе с HTTPS-клиентом; здесь — константы и типы, на которые опираются
//! вытекающие модули (`run_context`, `report_text`).

pub const SERVER_HOST: &str = "dns.zapret.moe";
pub const PATH: &str = "/api/outside/v1/check";
pub const MAX_HOSTS: usize = 8;
pub const TIMEOUT_S: f64 = 30.0;
pub const MAX_ANSWER: usize = 64 * 1024;

pub const OUTSIDE_UP: &str = "up";
pub const OUTSIDE_DOWN: &str = "down";
