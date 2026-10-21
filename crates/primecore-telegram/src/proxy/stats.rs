//! Живая статистика прокси и последние решения по маршрутам.
//!
//! Порт `telegram_proxy/proxy/stats.py`.

/// Последнее решение по маршруту для соединения Telegram.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProxyRouteEvent {
    pub dc: i32,
    pub is_media: bool,
    pub route: String,
    pub status: String,
    pub reason: String,
}

/// Живая статистика прокси.
#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub total_connections: i64,
    pub active_connections: i64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub wss_connections: i64,
    pub tcp_fallback_connections: i64,
    pub cloudflare_connections: i64,
    pub cloudflare_worker_connections: i64,
    pub cloudflare_failures: i64,
    pub failed_connections: i64,
    pub pool_hits: i64,
    pub pool_misses: i64,
    pub cloudflare_worker_pool_hits: i64,
    pub cloudflare_worker_pool_misses: i64,
    pub passthrough_connections: i64,
    pub upstream_connections: i64,
    pub recv_zero_count: i64,
    /// Ключ медиа-сессии на другом кластере: -404 скрыт и путь сменён / отдан
    /// Desktop / соединение закрыто молча, пока дом ключа недоступен.
    pub key_cluster_switches: i64,
    pub key_not_found_passed: i64,
    pub key_quiet_closes: i64,
    pub recv_zero_per_dc: std::collections::HashMap<i32, i64>,
    pub http_rejected: i64,
    pub mtproxy_invalid_init_count: i64,
    pub mtproxy_bad_handshake_count: i64,
    pub mtproxy_last_problem: String,
    pub route_events: Vec<ProxyRouteEvent>,
    start_time: std::time::Instant,
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyStats {
    /// Новая статистика с моментом старта «сейчас».
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            wss_connections: 0,
            tcp_fallback_connections: 0,
            cloudflare_connections: 0,
            cloudflare_worker_connections: 0,
            cloudflare_failures: 0,
            failed_connections: 0,
            pool_hits: 0,
            pool_misses: 0,
            cloudflare_worker_pool_hits: 0,
            cloudflare_worker_pool_misses: 0,
            passthrough_connections: 0,
            upstream_connections: 0,
            recv_zero_count: 0,
            key_cluster_switches: 0,
            key_not_found_passed: 0,
            key_quiet_closes: 0,
            recv_zero_per_dc: std::collections::HashMap::new(),
            http_rejected: 0,
            mtproxy_invalid_init_count: 0,
            mtproxy_bad_handshake_count: 0,
            mtproxy_last_problem: String::new(),
            route_events: Vec::new(),
            start_time: std::time::Instant::now(),
        }
    }

    /// Секунды с момента старта.
    #[must_use]
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Запомнить решение по маршруту; хранятся последние 12 событий.
    pub fn record_route_event(
        &mut self,
        dc: i32,
        is_media: bool,
        route: &str,
        status: &str,
        reason: &str,
    ) {
        self.route_events.push(ProxyRouteEvent {
            dc,
            is_media,
            route: route.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
        });
        let extra = self.route_events.len().saturating_sub(12);
        self.route_events.drain(..extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_events_keep_only_last_twelve() {
        let mut stats = ProxyStats::new();
        for index in 0..15 {
            stats.record_route_event(2, false, "WSS", "OK", "");
            let _ = index;
        }
        assert_eq!(stats.route_events.len(), 12);
        assert!(stats.route_events.iter().all(|event| event.route == "WSS"));
    }

    #[test]
    fn event_fields_are_preserved() {
        let mut stats = ProxyStats::new();
        stats.record_route_event(4, true, "TCP", "ошибка", "TimeoutError");
        let event = &stats.route_events[0];
        assert_eq!(event.dc, 4);
        assert!(event.is_media);
        assert_eq!(event.route, "TCP");
        assert_eq!(event.status, "ошибка");
        assert_eq!(event.reason, "TimeoutError");
        assert!(stats.uptime_seconds() >= 0.0);
    }
}
