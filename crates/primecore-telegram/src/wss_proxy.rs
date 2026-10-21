//! Локальный прокси Telegram: приём соединений Desktop и выбор маршрута.
//!
//! Порт чистой части `telegram_proxy/wss_proxy.py` (класс `TelegramWSProxy`).
//! Цепочка в python:
//!
//! ```text
//! Telegram Desktop
//!   ├ SOCKS5 (proxy/socks5) → 64 байта заголовка → obfs.parse_plain_client
//!   └ MTProxy (+ Fake TLS)          → obfs.parse_secret_client
//!         ↓
//!   proxy/session.TelegramSession: план маршрутов (proxy/routes),
//!   повтор пакетов на следующий маршрут, пока сервер молчит, пересылка.
//! ```
//!
//! Главный путь — WSS (релей kwsN, фронты Cloudflare, туннель через воркер),
//! запасной — внешний SOCKS5. Не-Telegram трафик и HTTP-транспорт (порт 80)
//! идут обычным TCP: WSS для них не подходит.
//!
//! Сам asyncio-сервер (`start`/`stop`, ретрансляция потоков, UDP-релей) —
//! сетевая часть: в крейте она остаётся у вызывающего кода (диспетчер
//! `manager`), а здесь — решения: какие константы таймаутов, к какой категории
//! отнести соединение, когда повторять bind, что писать в журнал. Запуск
//! соединений оформлен замыканиями/трейтами, где это возможно.

use crate::proxy::cloudflare::CloudflareFallbackConfig;
use crate::proxy::dc_map::{dc_to_tcp_endpoint, ip_to_dc, ip_to_dc_entry};
use crate::proxy::fake_tls::normalize_fake_tls_domain;
use crate::proxy::mtproxy::normalize_secret;
use crate::proxy::routing::{should_route_upstream, UpstreamProxyConfig};
use crate::proxy::upstream_runtime::FULL_CONNECT_TIMEOUT;

/// Таймаут прямого TCP-подключения passthrough (не-Telegram трафик).
pub const CONNECT_TIMEOUT: f64 = 10.0;
/// Таймаут прямого TCP-подключения HTTP-транспорта Telegram (порт 80).
pub const HTTP_DIRECT_CONNECT_TIMEOUT: f64 = 3.0;
/// Таймаут чтения первого пакета (init) после рукопожатия SOCKS5.
pub const INIT_READ_TIMEOUT: f64 = 15.0;
/// Размер куска при ретрансляции «сырого» TCP (128 КБ).
pub const RAW_READ_CHUNK: usize = 128 * 1024;
/// Таймаут подключения к внешнему SOCKS5.
pub const UPSTREAM_CONNECT_TIMEOUT: f64 = FULL_CONNECT_TIMEOUT;

/// Сколько секунд после старта разрешено повторять bind занятого порта.
pub const BIND_RETRY_SECONDS: f64 = 3.0;
/// Пауза между попытками bind занятого порта.
pub const BIND_RETRY_DELAY: f64 = 0.25;

/// DC, для которых план маршрутов считается осмысленным.
pub const KNOWN_DCS: &[i32] = &[1, 2, 3, 4, 5, 203];

/// Позиции журналирования проблем MTProxy: 1, 5, 20, 50 и каждое сотое.
pub const MTPROXY_PROBLEM_LOG_MARKS: &[i64] = &[1, 5, 20, 50];

/// Коды «адрес уже используется» Windows для повторного bind после рестарта.
pub const ADDRESS_IN_USE_WINERRORS: &[i64] = &[10048, 10013];

/// unix-код `EADDRINUSE` (Linux); на Windows коды берутся из `winerror`.
pub const EADDRINUSE: i32 = 98;

/// python `_is_address_in_use_error`: занят ли адрес (после рестарта сокет
/// освобождается с задержкой — bind повторяется).
#[must_use]
pub fn is_address_in_use_error(os_errno: Option<i32>, winerror: Option<i64>) -> bool {
    os_errno == Some(EADDRINUSE)
        || winerror.is_some_and(|code| ADDRESS_IN_USE_WINERRORS.contains(&code))
}

/// Повторять ли bind занятого порта: да, пока не вышло окно [`BIND_RETRY_SECONDS`].
#[must_use]
pub fn should_retry_bind(address_in_use: bool, elapsed_seconds: f64) -> bool {
    address_in_use && elapsed_seconds < BIND_RETRY_SECONDS
}

/// python `_is_domain`: имя хоста (не IP) — трафик уходит passthrough.
#[must_use]
pub fn is_domain(host: &str) -> bool {
    if host.contains(':') {
        return false;
    }
    !host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// python `_error_text`: «Тип: текст» или просто «Тип», если текст пустой.
#[must_use]
pub fn error_text(kind: &str, message: &str) -> String {
    if message.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}: {message}")
    }
}

/// Подпись режима для журнала: MTProxy или SOCKS5.
#[must_use]
pub fn mode_label(mode: &str) -> &'static str {
    if mode == "mtproxy" {
        "MTProxy"
    } else {
        "SOCKS5"
    }
}

/// Строка журнала с деталями маршрута (python `log_route_detail`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn log_route_detail(
    label: &str,
    mode: &str,
    dc: i32,
    is_media: bool,
    target: &str,
    result: &str,
    reason: &str,
    next_step: &str,
    elapsed: Option<f64>,
) -> String {
    let mut text = format!(
        "[{label}] mode={mode} dc={dc} media={}",
        if is_media { "yes" } else { "no" }
    );
    if !target.is_empty() {
        text.push_str(&format!(" target={target}"));
    }
    text.push_str(&format!(" result={result}"));
    if !reason.is_empty() {
        text.push_str(&format!(" reason={reason}"));
    }
    if !next_step.is_empty() {
        text.push_str(&format!(" next={next_step}"));
    }
    if let Some(seconds) = elapsed {
        text.push_str(&format!(" elapsed={seconds:.1}s"));
    }
    text
}

/// python `_should_log_mtproxy_problem`: позиция из набора меток или каждое
/// сотое появление проблемы.
#[must_use]
pub fn should_log_mtproxy_problem(count: i64, marks: &[i64]) -> bool {
    marks.contains(&count) || (count > 0 && count % 100 == 0)
}

/// Причина «init не получен» в статистике (python `mtproxy_last_problem`).
#[must_use]
pub fn mtproxy_invalid_init_problem() -> &'static str {
    "нет MTProxy init packet: проверьте тип прокси, старые записи, \
Fake TLS/secret или авто-проверку Telegram"
}

/// Причина «init не расшифровался» в статистике.
#[must_use]
pub fn mtproxy_bad_handshake_problem() -> &'static str {
    "init есть, но secret или тип secret dd/ee не подошёл"
}

/// Строка журнала о неполученном init (python `_record_mtproxy_invalid_init`).
/// `None`, если на этом счётчике журнал молчит.
#[must_use]
pub fn mtproxy_invalid_init_log_line(label: &str, count: i64) -> Option<String> {
    if !should_log_mtproxy_problem(count, MTPROXY_PROBLEM_LOG_MARKS) {
        return None;
    }
    Some(format!(
        "[{label}] MTProxy init packet не получен; повторов: {count}. \
Что это значит: Telegram подключился к MTProxy-порту, но не прислал \
первый MTProxy-пакет. Что делать: проверьте тип прокси в Telegram, \
удалите старые записи 127.0.0.1, проверьте secret/Fake TLS; \
одиночные проверки клиента могут закрываться сами."
    ))
}

/// Строка журнала о нерасшифровавшемся init (python `_record_mtproxy_bad_handshake`).
/// `None`, если на этом счётчике журнал молчит.
#[must_use]
pub fn mtproxy_bad_handshake_log_line(label: &str, count: i64) -> Option<String> {
    if !should_log_mtproxy_problem(count, MTPROXY_PROBLEM_LOG_MARKS) {
        return None;
    }
    Some(format!(
        "[{label}] MTProxy init получен, но не расшифровался; повторов: {count}. \
Чаще всего это неверный secret, старый прокси в Telegram или mismatch \
типа secret dd/ee."
    ))
}

/// Пределы сервера: размер пула запасных соединений и буфера в байтах.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WssProxyLimits {
    /// Размер пула запасных соединений: 0..=32 (0 — пул выключен).
    pub pool_size: i64,
    /// Размер буфера в байтах: 4..=4096 КБ.
    pub buffer_size: usize,
}

impl WssProxyLimits {
    /// python `TelegramWSProxy.__init__`: зажимает pool_size в 0..=32 и
    /// buffer_kb в 4..=4096 КБ (`0` означает «по умолчанию» — 256 КБ).
    #[must_use]
    pub fn new(pool_size: i64, buffer_kb: i64) -> Self {
        let pool_size = pool_size.clamp(0, 32);
        let kb = if buffer_kb == 0 { 256 } else { buffer_kb };
        Self {
            pool_size,
            buffer_size: kb.clamp(4, 4096) as usize * 1024,
        }
    }

    /// Пул запасных соединений включён?
    #[must_use]
    pub fn pool_enabled(&self) -> bool {
        self.pool_size > 0
    }
}

/// Подготовленные настройки входа `TelegramWSProxy` (python-аргументы
/// `__init__` после нормализации).
#[derive(Debug, Clone, Default)]
pub struct WssProxyOptions {
    pub port: i64,
    pub host: String,
    pub mode: String,
    pub upstream: UpstreamProxyConfig,
    pub cloudflare: CloudflareFallbackConfig,
    pub mtproxy_secret: String,
    pub dc_endpoint_overrides: Vec<(i32, String)>,
    pub limits: WssProxyLimits,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
}

impl WssProxyOptions {
    /// Собирает настройки с нормализацией python `__init__`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        port: i64,
        mode: &str,
        host: &str,
        upstream: Option<UpstreamProxyConfig>,
        cloudflare: Option<CloudflareFallbackConfig>,
        mtproxy_secret: &str,
        dc_endpoint_overrides: Vec<(i32, String)>,
        pool_size: i64,
        buffer_kb: i64,
        fake_tls_domain: &str,
        proxy_protocol: bool,
    ) -> Self {
        Self {
            port,
            host: host.to_string(),
            mode: mode.to_string(),
            upstream: upstream.unwrap_or_default(),
            cloudflare: cloudflare.unwrap_or_default(),
            mtproxy_secret: normalize_secret(mtproxy_secret),
            dc_endpoint_overrides,
            limits: WssProxyLimits::new(pool_size, buffer_kb),
            fake_tls_domain: normalize_fake_tls_domain(fake_tls_domain),
            proxy_protocol,
        }
    }

    /// Подпись режима для журнала.
    #[must_use]
    pub fn mode_label(&self) -> &'static str {
        mode_label(&self.mode)
    }
}

/// Категория SOCKS5-соединения: passthrough или трафик Telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Route {
    /// Домен или не-Telegram IP — обычный TCP (python `_passthrough`).
    Passthrough,
    /// Telegram IP — дальше читается init и выбирается маршрут.
    Telegram,
}

/// python: домен или не-Telegram IP уходят passthrough.
#[must_use]
pub fn socks5_route_kind(target_host: &str) -> Socks5Route {
    if is_domain(target_host) || !crate::proxy::dc_map::is_telegram_ip(target_host) {
        return Socks5Route::Passthrough;
    }
    Socks5Route::Telegram
}

/// Куда вести соединение SOCKS5 по DC (python-блок `_handle_socks5_client`).
///
/// Возвращает `(dc, is_media, host, port)`: неизвестный DC берётся из таблицы
/// IP, IPv6-адрес заменяется IPv4 того же DC.
#[must_use]
pub fn resolve_socks5_target(
    client_dc: i32,
    client_is_media: bool,
    target_host: &str,
    target_port: i64,
    overrides: &[(i32, String)],
) -> (i32, bool, String, i64) {
    let (dc, is_media) = if KNOWN_DCS.contains(&client_dc) {
        (client_dc, client_is_media)
    } else {
        match ip_to_dc_entry(target_host) {
            Some(entry) => entry,
            None => (ip_to_dc(target_host), false),
        }
    };
    if target_host.contains(':') {
        // IPv6 Telegram часто недоступен; маршрутам нужен IPv4 того же DC.
        let (host, port) = dc_to_tcp_endpoint(dc, overrides, is_media);
        return (dc, is_media, host, i64::from(port));
    }
    (dc, is_media, target_host.to_string(), target_port)
}

/// Маршрут «сырого» TCP-потока: HTTP-транспорт Telegram и не-обфусцированный
/// трафик (python `_raw_tcp_session`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTcpRoute {
    /// Режим «весь TCP через SOCKS5» — сразу через внешний прокси.
    UpstreamAlways,
    /// Прямой TCP; при неудаче — запас через внешний прокси, если он включён.
    Direct,
}

/// Решение для сырого потока (python-развилка `_raw_tcp_session`).
#[must_use]
pub fn raw_tcp_route(upstream: &UpstreamProxyConfig) -> RawTcpRoute {
    if should_route_upstream(upstream, "always") {
        return RawTcpRoute::UpstreamAlways;
    }
    RawTcpRoute::Direct
}

/// Есть ли запас через внешний SOCKS5 при неудаче прямого TCP.
#[must_use]
pub fn raw_tcp_fallback(upstream: &UpstreamProxyConfig) -> bool {
    upstream.enabled
}

/// Текст запуска прокси (python `start`).
#[must_use]
pub fn started_log_text(mode: &str, host: &str, port: i64) -> String {
    format!("{} proxy started on {host}:{port}", mode_label(mode))
}

/// Подключение passthrough/HTTP: сеть — замыкание `connect`, отвечающее
/// ошибкой (текст вида python-исключения) при неудаче.
pub type DirectConnectFn<'a> = dyn FnMut(&str, i64, f64) -> Result<(), String> + 'a;

/// Итог попытки прямого TCP для сырого потока (python `_raw_tcp_session`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DirectTcpOutcome {
    /// Куда в итоге пошёл поток: прямой TCP или внешний SOCKS5.
    pub via_upstream: bool,
    /// Строка журнала о решении (python `log_route_detail`).
    pub log_line: String,
}

/// Решение сырого потока без открытия соединений: connect подставляется
/// замыканием, «ретрансляция» остаётся у диспетчера.
#[must_use]
pub fn raw_tcp_plan(
    upstream: &UpstreamProxyConfig,
    target_host: &str,
    target_port: i64,
    label: &str,
    connect: &mut DirectConnectFn<'_>,
    elapsed: f64,
) -> DirectTcpOutcome {
    if raw_tcp_route(upstream) == RawTcpRoute::UpstreamAlways {
        let log_line = log_route_detail(
            label,
            "SOCKS5",
            0,
            false,
            "",
            "upstream",
            "always mode",
            "",
            None,
        );
        return DirectTcpOutcome {
            via_upstream: true,
            log_line,
        };
    }
    match connect(target_host, target_port, HTTP_DIRECT_CONNECT_TIMEOUT) {
        Ok(()) => DirectTcpOutcome {
            via_upstream: false,
            log_line: log_route_detail(
                label,
                "SOCKS5",
                0,
                false,
                &format!("{target_host}:{target_port}"),
                "connected",
                "HTTP transport cannot use WSS",
                "",
                Some(elapsed),
            ),
        },
        Err(reason) => {
            let fallback = raw_tcp_fallback(upstream);
            let next_step = if fallback {
                "upstream SOCKS5 fallback"
            } else {
                "none; HTTP transport cannot use WSS"
            };
            DirectTcpOutcome {
                via_upstream: fallback,
                log_line: log_route_detail(
                    label,
                    "SOCKS5",
                    0,
                    false,
                    &format!("{target_host}:{target_port}"),
                    "error",
                    &reason,
                    next_step,
                    Some(elapsed),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::routing::UpstreamProxyConfig;
    use std::cell::Cell;

    fn upstream(enabled: bool, mode: &str) -> UpstreamProxyConfig {
        UpstreamProxyConfig {
            enabled,
            mode: mode.to_string(),
            ..UpstreamProxyConfig::default()
        }
    }

    #[test]
    fn domain_vs_ip_detection() {
        assert!(is_domain("web.telegram.org"));
        assert!(is_domain("localhost"));
        assert!(!is_domain("149.154.167.51"));
        // IPv6 — не «домен»: это всё равно IP-адрес.
        assert!(!is_domain("2001:db8::1"));
    }

    #[test]
    fn address_in_use_codes() {
        assert!(is_address_in_use_error(Some(EADDRINUSE), None));
        assert!(is_address_in_use_error(None, Some(10048)));
        assert!(is_address_in_use_error(None, Some(10013)));
        assert!(!is_address_in_use_error(None, Some(10049)));
        assert!(!is_address_in_use_error(Some(13), None));
        assert!(!is_address_in_use_error(None, None));
    }

    #[test]
    fn bind_retry_until_deadline() {
        assert!(should_retry_bind(true, 0.0));
        assert!(should_retry_bind(true, 2.9));
        assert!(!should_retry_bind(true, 3.0));
        assert!(!should_retry_bind(true, 5.0));
        // Другие ошибки bind не повторяются.
        assert!(!should_retry_bind(false, 0.0));
        assert!((BIND_RETRY_DELAY - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn error_text_matches_python() {
        assert_eq!(error_text("TimeoutError", ""), "TimeoutError");
        assert_eq!(
            error_text("TimeoutError", "timed out"),
            "TimeoutError: timed out"
        );
    }

    #[test]
    fn mode_label_matches_python() {
        assert_eq!(mode_label("mtproxy"), "MTProxy");
        assert_eq!(mode_label("socks5"), "SOCKS5");
        assert_eq!(mode_label(""), "SOCKS5");
        assert_eq!(
            started_log_text("mtproxy", "127.0.0.1", 1353),
            "MTProxy proxy started on 127.0.0.1:1353"
        );
    }

    #[test]
    fn route_detail_line_matches_python() {
        let line = log_route_detail(
            "127.0.0.1:54321",
            "MTProxy",
            2,
            true,
            "149.154.167.51:443",
            "connected",
            "",
            "открываю WSS",
            Some(1.25),
        );
        assert_eq!(
            line,
            "[127.0.0.1:54321] mode=MTProxy dc=2 media=yes target=149.154.167.51:443 \
result=connected next=открываю WSS elapsed=1.2s"
        );
        // Пустые необязательные части пропускаются.
        let short = log_route_detail("x", "SOCKS5", 0, false, "", "error", "timeout", "", None);
        assert_eq!(
            short,
            "[x] mode=SOCKS5 dc=0 media=no result=error reason=timeout"
        );
    }

    #[test]
    fn mtproxy_problem_marks() {
        for count in [1, 5, 20, 50, 100, 200, 300] {
            assert!(
                should_log_mtproxy_problem(count, MTPROXY_PROBLEM_LOG_MARKS),
                "{count}"
            );
        }
        for count in [0, 2, 3, 4, 6, 19, 49, 51, 99, 101] {
            assert!(
                !should_log_mtproxy_problem(count, MTPROXY_PROBLEM_LOG_MARKS),
                "{count}"
            );
        }
        assert!(mtproxy_invalid_init_log_line("1.2.3.4:5", 1).is_some());
        assert!(mtproxy_invalid_init_log_line("1.2.3.4:5", 2).is_none());
        assert!(mtproxy_bad_handshake_log_line("1.2.3.4:5", 100).is_some());
        assert!(mtproxy_bad_handshake_log_line("1.2.3.4:5", 40).is_none());
        assert_eq!(mtproxy_invalid_init_log_line("x", 1).unwrap(), "[x] MTProxy init packet не получен; повторов: 1. Что это значит: Telegram подключился к MTProxy-порту, но не прислал первый MTProxy-пакет. Что делать: проверьте тип прокси в Telegram, удалите старые записи 127.0.0.1, проверьте secret/Fake TLS; одиночные проверки клиента могут закрываться сами.");
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(
            WssProxyLimits::new(4, 256),
            WssProxyLimits {
                pool_size: 4,
                buffer_size: 256 * 1024
            }
        );
        assert_eq!(WssProxyLimits::new(-5, 256).pool_size, 0);
        assert_eq!(WssProxyLimits::new(100, 256).pool_size, 32);
        assert!(!WssProxyLimits::new(0, 256).pool_enabled());
        // 0 КБ означает «по умолчанию».
        assert_eq!(WssProxyLimits::new(4, 0).buffer_size, 256 * 1024);
        assert_eq!(WssProxyLimits::new(4, 1).buffer_size, 4 * 1024);
        assert_eq!(WssProxyLimits::new(4, 100_000).buffer_size, 4096 * 1024);
    }

    #[test]
    fn options_are_normalized_like_python_init() {
        let options = WssProxyOptions::new(
            1353,
            "mtproxy",
            "127.0.0.1",
            None,
            None,
            "  ABCDEF0123456789ABCDEF0123456789  ",
            vec![(2, "149.154.167.51".to_string())],
            9,
            128,
            " Example.COM ",
            true,
        );
        assert_eq!(options.mtproxy_secret, "abcdef0123456789abcdef0123456789");
        assert_eq!(options.fake_tls_domain, "example.com");
        assert_eq!(options.limits.pool_size, 9);
        assert_eq!(options.limits.buffer_size, 128 * 1024);
        assert!(options.proxy_protocol);
        assert_eq!(options.mode_label(), "MTProxy");
        assert_eq!(options.upstream, UpstreamProxyConfig::default());
        assert_eq!(options.cloudflare, CloudflareFallbackConfig::default());
    }

    #[test]
    fn socks5_targets_are_sorted() {
        // Домен — passthrough.
        assert_eq!(socks5_route_kind("example.com"), Socks5Route::Passthrough);
        // Не-Telegram IP — passthrough.
        assert_eq!(socks5_route_kind("1.2.3.4"), Socks5Route::Passthrough);
        // Telegram IP — трафик Telegram.
        assert_eq!(socks5_route_kind("149.154.167.51"), Socks5Route::Telegram);

        // Известный DC и IPv4 остаются как есть.
        assert_eq!(
            resolve_socks5_target(2, true, "149.154.167.51", 443, &[]),
            (2, true, "149.154.167.51".to_string(), 443)
        );
        // Неизвестный DC восстанавливается по таблице IP (медиа-адрес).
        assert_eq!(
            resolve_socks5_target(9, false, "149.154.167.151", 443, &[]),
            (2, true, "149.154.167.151".to_string(), 443)
        );
        // Совсем неизвестный IP — DC по хешу-заглушке ip_to_dc.
        let (dc, is_media, _, _) = resolve_socks5_target(9, true, "203.0.113.10", 443, &[]);
        assert_eq!(dc, ip_to_dc("203.0.113.10"));
        assert!(!is_media);
        // IPv6 заменяется IPv4 того же DC с учётом переопределений.
        let overrides = vec![(5, "203.0.113.99".to_string())];
        assert_eq!(
            resolve_socks5_target(5, false, "2001:db8::1", 443, &overrides),
            (5, false, "203.0.113.99".to_string(), 443)
        );
    }

    #[test]
    fn raw_tcp_route_decisions() {
        assert_eq!(
            raw_tcp_route(&upstream(true, "always")),
            RawTcpRoute::UpstreamAlways
        );
        assert_eq!(
            raw_tcp_route(&upstream(true, "fallback")),
            RawTcpRoute::Direct
        );
        assert_eq!(
            raw_tcp_route(&upstream(false, "always")),
            RawTcpRoute::Direct
        );
        // При неудаче прямого TCP запас есть только у включённого upstream.
        assert!(raw_tcp_fallback(&upstream(true, "fallback")));
        assert!(!raw_tcp_fallback(&upstream(false, "always")));
    }

    #[test]
    fn raw_tcp_plan_uses_connect_closure() {
        let upstream_on = upstream(true, "fallback");
        // Прямой TCP удался — поток идёт напрямую.
        let mut connected = |_host: &str, _port: i64, _timeout: f64| Ok::<(), String>(());
        let outcome = raw_tcp_plan(
            &upstream_on,
            "149.154.167.51",
            80,
            "label",
            &mut connected,
            0.5,
        );
        assert!(!outcome.via_upstream);
        assert!(outcome.log_line.contains("result=connected"));
        assert!(outcome.log_line.contains("HTTP transport cannot use WSS"));

        // Прямой TCP не удался — запас через внешний SOCKS5.
        let mut refused = |_: &str, _: i64, _: f64| Err("timeout".to_string());
        let outcome = raw_tcp_plan(
            &upstream_on,
            "149.154.167.51",
            80,
            "label",
            &mut refused,
            3.1,
        );
        assert!(outcome.via_upstream);
        assert!(outcome.log_line.contains("result=error"));
        assert!(outcome.log_line.contains("upstream SOCKS5 fallback"));

        // upstream выключен — запаса нет.
        let mut refused = |_: &str, _: i64, _: f64| Err("refused".to_string());
        let outcome = raw_tcp_plan(
            &upstream(false, "fallback"),
            "149.154.167.51",
            80,
            "label",
            &mut refused,
            0.0,
        );
        assert!(!outcome.via_upstream);
        assert!(outcome
            .log_line
            .contains("none; HTTP transport cannot use WSS"));

        // Режим «весь TCP» — всегда через внешний прокси, connect не зовётся.
        let called = Cell::new(false);
        let mut never = |_: &str, _: i64, _: f64| {
            called.set(true);
            Ok::<(), String>(())
        };
        let outcome = raw_tcp_plan(
            &upstream(true, "always"),
            "149.154.167.51",
            80,
            "label",
            &mut never,
            0.0,
        );
        assert!(outcome.via_upstream);
        assert!(!called.get());
    }

    #[test]
    fn timeouts_and_chunk_match_python() {
        assert_eq!(CONNECT_TIMEOUT, 10.0);
        assert_eq!(HTTP_DIRECT_CONNECT_TIMEOUT, 3.0);
        assert_eq!(INIT_READ_TIMEOUT, 15.0);
        assert_eq!(RAW_READ_CHUNK, 128 * 1024);
        assert_eq!(UPSTREAM_CONNECT_TIMEOUT, FULL_CONNECT_TIMEOUT);
        assert_eq!(KNOWN_DCS, &[1, 2, 3, 4, 5, 203]);
    }
}
