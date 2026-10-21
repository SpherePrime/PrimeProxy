//! Внешний SOCKS5-сервер (встроенный сервер страны или ручной) и проверка
//! доступности релея.
//!
//! Порт `telegram_proxy/proxy/routing.py`. Сетевая проверка релея идёт через
//! замыкание: крейт не открывает соединений сам.

/// Конечная точка внешнего SOCKS5.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct UpstreamProxyEndpoint {
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub tls_server_name: String,
    pub tls_verify: bool,
    pub preset_id: String,
    pub preset_name: String,
}

/// Внешний SOCKS5-сервер.
///
/// Режимы (переключатель «Весь TCP через SOCKS5»):
/// - `fallback` — запасной путь после всех маршрутов WSS (по умолчанию);
/// - `always` — весь TCP Telegram только через этот сервер.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub tls_server_name: String,
    pub tls_verify: bool,
    pub mode: String,
    pub udp_enabled: bool,
    pub preset_id: String,
    pub preset_name: String,
    pub fallback_proxies: Vec<UpstreamProxyEndpoint>,
}

impl UpstreamProxyConfig {
    /// Конфиг как endpoint (для `endpoints_from_config`).
    #[must_use]
    pub fn as_endpoint(&self) -> UpstreamProxyEndpoint {
        UpstreamProxyEndpoint {
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
            tls: self.tls,
            tls_server_name: self.tls_server_name.clone(),
            tls_verify: self.tls_verify,
            preset_id: self.preset_id.clone(),
            preset_name: self.preset_name.clone(),
        }
    }
}

/// Итог синхронной проверки TCP+TLS до релея WSS.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RelayReachability {
    pub reachable: bool,
    pub error: String,
    /// Задержка проверки в миллисекундах, округлённая до 0.1.
    pub ms: f64,
}

/// Проверка доступности релея через переданное сетевое замыкание.
///
/// Замыкание подключается по TCP+TLS (SNI `kws2.web.telegram.org`) и
/// возвращает ошибку с текстом вида python-исключения (`"timeout"`,
/// `"Connection refused"`, `"Network error: ..."`).
#[must_use]
pub fn check_relay_reachable(
    relay_ip: &str,
    timeout: f64,
    connect: &dyn Fn(&str, f64) -> Result<(), String>,
) -> RelayReachability {
    let started = std::time::Instant::now();
    match connect(relay_ip, timeout) {
        Ok(()) => RelayReachability {
            reachable: true,
            error: String::new(),
            ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        },
        Err(error) => RelayReachability {
            reachable: false,
            error,
            ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        },
    }
}

/// `true`, когда трафик должен идти через внешний прокси прямо сейчас.
#[must_use]
pub fn should_route_upstream(upstream: &UpstreamProxyConfig, mode: &str) -> bool {
    if !upstream.enabled {
        return false;
    }
    upstream.mode.trim().to_lowercase() == mode.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_mode_decides_routing() {
        let mut upstream = UpstreamProxyConfig {
            mode: "always".into(),
            ..UpstreamProxyConfig::default()
        };
        assert!(!should_route_upstream(&upstream, "always"));
        upstream.enabled = true;
        assert!(should_route_upstream(&upstream, "always"));
        assert!(!should_route_upstream(&upstream, "fallback"));
        upstream.mode = " Always ".into();
        assert!(should_route_upstream(&upstream, "always"));
    }

    #[test]
    fn relay_check_reports_success_and_failure() {
        let ok = check_relay_reachable("149.154.167.220", 5.0, &|_, _| Ok(()));
        assert!(ok.reachable);
        assert_eq!(ok.error, "");
        let fail = check_relay_reachable("149.154.167.220", 5.0, &|_, _| {
            Err("Connection refused".to_string())
        });
        assert!(!fail.reachable);
        assert_eq!(fail.error, "Connection refused");
    }
}
