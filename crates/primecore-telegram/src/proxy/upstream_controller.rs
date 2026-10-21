//! Владелец единственного активного внешнего SOCKS-сервера.
//!
//! Порт `telegram_proxy/proxy/upstream_controller.py`. Контроллер — чистая
//! машина состояний с подменными часами: решения о пробных проверках,
//! переключениях и штрафах те же, что в python-версии.

use std::collections::HashMap;

use crate::proxy::routing::{UpstreamProxyConfig, UpstreamProxyEndpoint};

pub const CONNECT_FAILURE_WINDOW: f64 = 10.0;
/// Telegram открывает соединения параллельно, поэтому оставляем время
/// работающему соединению доказать здоровье сервера до короткой серии сбросов.
pub const CONNECT_FAILURE_LIMIT: usize = 6;
pub const CONNECT_FAILURE_OBSERVATION_WINDOW: f64 = 2.0;
pub const ZERO_RECV_LIMIT: usize = 6;
pub const ZERO_RECV_OBSERVATION_WINDOW: f64 = 2.0;
pub const RETRY_DELAYS: [f64; 3] = [60.0, 180.0, 300.0];

/// Состояние внешнего сервера для страницы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamState {
    Primary,
    Fallback,
    CheckingPrimary,
    Unavailable,
}

/// Ключ конечной точки: всё, что отличает один сервер от другого.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointKey {
    host: String,
    port: i64,
    username: String,
    password: String,
    tls: bool,
    tls_server_name: String,
    tls_verify: bool,
}

/// Ключ конечной точки (как `endpoint_key` в python).
#[must_use]
pub fn endpoint_key(endpoint: &UpstreamProxyEndpoint) -> EndpointKey {
    EndpointKey {
        host: endpoint.host.trim().to_lowercase(),
        port: endpoint.port,
        username: endpoint.username.clone(),
        password: endpoint.password.clone(),
        tls: endpoint.tls,
        tls_server_name: endpoint.tls_server_name.trim().to_lowercase(),
        tls_verify: endpoint.tls_verify,
    }
}

/// Имя сервера для журнала и страницы.
#[must_use]
pub fn endpoint_display_name(endpoint: Option<&UpstreamProxyEndpoint>) -> String {
    let Some(endpoint) = endpoint else {
        return String::new();
    };
    let name = endpoint.preset_name.trim();
    if !name.is_empty() {
        return name.to_string();
    }
    let host = endpoint.host.trim();
    if !host.is_empty() && endpoint.port > 0 {
        return format!("{host}:{}", endpoint.port);
    }
    "внешний прокси".to_string()
}

/// Нормализованная конечная точка; `None` — без хоста или порта.
#[must_use]
fn normalize_endpoint(endpoint: &UpstreamProxyEndpoint) -> Option<UpstreamProxyEndpoint> {
    let host = endpoint.host.trim().to_string();
    let port = endpoint.port;
    if host.is_empty() || port <= 0 {
        return None;
    }
    Some(UpstreamProxyEndpoint {
        host,
        port,
        username: endpoint.username.clone(),
        password: endpoint.password.clone(),
        tls: endpoint.tls,
        tls_server_name: endpoint.tls_server_name.trim().to_string(),
        tls_verify: endpoint.tls_verify,
        preset_id: endpoint.preset_id.trim().to_string(),
        preset_name: endpoint.preset_name.trim().to_string(),
    })
}

/// Конечные точки конфига: основной сервер и уникальные запасные.
#[must_use]
pub fn endpoints_from_config(config: &UpstreamProxyConfig) -> Vec<UpstreamProxyEndpoint> {
    if !config.enabled {
        return Vec::new();
    }
    let primary = config.as_endpoint();
    let mut result: Vec<UpstreamProxyEndpoint> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in std::iter::once(&primary).chain(config.fallback_proxies.iter()) {
        let Some(endpoint) = normalize_endpoint(raw) else {
            continue;
        };
        let key = endpoint_key(&endpoint);
        if !seen.insert(key) {
            continue;
        }
        result.push(endpoint);
    }
    result
}

/// Снимок состояния для страницы.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct UpstreamRuntimeSnapshot {
    #[serde(default)]
    pub selected_preset_id: String,
    #[serde(default)]
    pub selected_name: String,
    #[serde(default)]
    pub active_preset_id: String,
    #[serde(default)]
    pub active_name: String,
    pub state: UpstreamState,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub generation: i64,
    #[serde(default)]
    pub queued_connections: i64,
    #[serde(default)]
    pub rejected_connections: i64,
}

/// Одна попытка подключения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAttempt {
    pub endpoint: UpstreamProxyEndpoint,
    pub generation: i64,
    pub is_probe: bool,
    pub primary_probe: bool,
}

/// Смена активного сервера.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamTransition {
    pub old_endpoint: Option<UpstreamProxyEndpoint>,
    pub new_endpoint: Option<UpstreamProxyEndpoint>,
    pub reason: String,
    pub old_generation: i64,
    pub generation: i64,
    pub retry_after: f64,
}

#[derive(Default)]
struct EndpointHealth {
    connect_failures: std::collections::VecDeque<f64>,
    zero_recv_count: usize,
    zero_recv_started_at: Option<f64>,
    failure_round: usize,
    unavailable_until: f64,
}

/// Колбэк, которому отдаётся каждый новый снимок состояния апстримов.
pub type SnapshotCallback = Box<dyn Fn(&UpstreamRuntimeSnapshot)>;

/// Владелец единственного активного SOCKS-сервера для всего прокси.
pub struct UpstreamStateController {
    clock: Box<dyn Fn() -> f64>,
    on_snapshot: Option<SnapshotCallback>,
    queued_connections: i64,
    rejected_connections: i64,
    last_snapshot: Option<UpstreamRuntimeSnapshot>,
    generation: i64,
    reason: String,
    health: HashMap<EndpointKey, EndpointHealth>,
    probe_key: Option<EndpointKey>,
    probe_is_primary: bool,
    endpoints: Vec<UpstreamProxyEndpoint>,
    active: Option<UpstreamProxyEndpoint>,
}

impl UpstreamStateController {
    /// Новый контроллер с начальной конфигурацией (как в python: replace_config).
    #[must_use]
    pub fn new(
        config: &UpstreamProxyConfig,
        on_snapshot: Option<SnapshotCallback>,
        clock: Box<dyn Fn() -> f64>,
    ) -> Self {
        let mut controller = Self {
            clock,
            on_snapshot,
            queued_connections: 0,
            rejected_connections: 0,
            last_snapshot: None,
            generation: 0,
            reason: String::new(),
            health: HashMap::new(),
            probe_key: None,
            probe_is_primary: false,
            endpoints: Vec::new(),
            active: None,
        };
        controller.replace_config(config, "запуск");
        controller
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Конечные точки в порядке каталога.
    #[must_use]
    pub fn endpoints(&self) -> &[UpstreamProxyEndpoint] {
        &self.endpoints
    }

    /// Выбранный (основной) сервер.
    #[must_use]
    pub fn selected(&self) -> Option<&UpstreamProxyEndpoint> {
        self.endpoints.first()
    }

    /// Активный сервер.
    #[must_use]
    pub fn active(&self) -> Option<&UpstreamProxyEndpoint> {
        self.active.as_ref()
    }

    /// Номер поколения конфигурации.
    #[must_use]
    pub fn generation(&self) -> i64 {
        self.generation
    }

    /// Снимок состояния.
    #[must_use]
    pub fn snapshot(&self) -> UpstreamRuntimeSnapshot {
        let selected = self.selected();
        let active = self.active.as_ref();
        let state = if active.is_none() {
            if self.probe_key.is_some()
                && selected.is_some()
                && self.probe_key.as_ref() == selected.map(endpoint_key).as_ref()
            {
                UpstreamState::CheckingPrimary
            } else {
                UpstreamState::Unavailable
            }
        } else if self.probe_is_primary {
            UpstreamState::CheckingPrimary
        } else {
            match (active, selected.as_ref()) {
                (Some(active), Some(selected))
                    if endpoint_key(active) == endpoint_key(selected) =>
                {
                    UpstreamState::Primary
                }
                _ => UpstreamState::Fallback,
            }
        };
        UpstreamRuntimeSnapshot {
            selected_preset_id: selected
                .map_or(String::new(), |endpoint| endpoint.preset_id.clone()),
            selected_name: endpoint_display_name(selected),
            active_preset_id: active.map_or(String::new(), |endpoint| endpoint.preset_id.clone()),
            active_name: endpoint_display_name(active),
            state,
            reason: self.reason.clone(),
            generation: self.generation,
            queued_connections: self.queued_connections,
            rejected_connections: self.rejected_connections,
        }
    }

    /// Снимок с уведомлением подписчика только при изменении.
    pub fn emit_snapshot(&mut self, force: bool) -> UpstreamRuntimeSnapshot {
        let snapshot = self.snapshot();
        if force || self.last_snapshot.as_ref() != Some(&snapshot) {
            self.last_snapshot = Some(snapshot.clone());
            if let Some(on_snapshot) = &self.on_snapshot {
                on_snapshot(&snapshot);
            }
        }
        snapshot
    }

    /// Счётчики очереди подключения (для страницы).
    pub fn set_queue_state(&mut self, queued: i64, rejected: i64) {
        self.queued_connections = queued.max(0);
        self.rejected_connections = rejected.max(0);
        self.emit_snapshot(false);
    }

    /// Замена конфигурации; возвращает смену сервера, если она видна снаружи.
    pub fn replace_config(
        &mut self,
        config: &UpstreamProxyConfig,
        reason: &str,
    ) -> Option<UpstreamTransition> {
        let old_endpoint = self.active.clone();
        let old_generation = self.generation;
        self.endpoints = endpoints_from_config(config);
        self.health = self
            .endpoints
            .iter()
            .map(|endpoint| (endpoint_key(endpoint), EndpointHealth::default()))
            .collect();
        self.active = self.endpoints.first().cloned();
        self.probe_key = None;
        self.probe_is_primary = false;
        self.reason = if self.active.is_some() {
            reason.to_string()
        } else {
            "сервер не настроен".to_string()
        };
        let old_key = old_endpoint.as_ref().map(endpoint_key);
        let new_key = self.active.as_ref().map(endpoint_key);
        if self.generation == 0 && self.active.is_some() {
            self.generation = 1;
        } else if old_key != new_key {
            self.generation += 1;
        }
        let transition = if old_generation > 0 && old_key != new_key {
            Some(UpstreamTransition {
                old_endpoint,
                new_endpoint: self.active.clone(),
                reason: reason.to_string(),
                old_generation,
                generation: self.generation,
                retry_after: 0.0,
            })
        } else {
            None
        };
        self.emit_snapshot(true);
        transition
    }

    /// Текущий активный сервер.
    #[must_use]
    pub fn current_endpoint(&self) -> Option<&UpstreamProxyEndpoint> {
        self.active.as_ref()
    }

    /// Есть ли сервер, до которого ещё не дотянулась пауза.
    #[must_use]
    pub fn has_available_endpoint(&self) -> bool {
        if self.active.is_some() {
            return true;
        }
        let now = self.now();
        self.endpoints.iter().any(|endpoint| {
            self.health
                .get(&endpoint_key(endpoint))
                .map(|health| health.unavailable_until)
                .unwrap_or(0.0)
                <= now
        })
    }

    /// Выбор попытки: активный сервер или пробная проверка.
    #[must_use]
    pub fn select_attempt(&mut self) -> Option<UpstreamAttempt> {
        if self.endpoints.is_empty() {
            return None;
        }
        let now = self.now();
        let primary = self.selected().cloned();
        if let Some(primary) = &primary {
            if self.active.is_some()
                && endpoint_key(self.active.as_ref().expect("проверено")) != endpoint_key(primary)
                && self.probe_key.is_none()
                && self.health_for(primary).unavailable_until <= now
            {
                self.probe_key = Some(endpoint_key(primary));
                self.probe_is_primary = true;
                self.reason = "проверяем восстановление основного сервера".to_string();
                self.emit_snapshot(false);
                return Some(UpstreamAttempt {
                    endpoint: primary.clone(),
                    generation: self.generation,
                    is_probe: true,
                    primary_probe: true,
                });
            }
        }
        if let Some(active) = self.active.clone() {
            return Some(UpstreamAttempt {
                endpoint: active,
                generation: self.generation,
                is_probe: false,
                primary_probe: false,
            });
        }
        if self.probe_key.is_some() {
            return None;
        }
        let candidate = self.first_available(now, None);
        let Some(candidate) = candidate else {
            self.reason = "все серверы временно недоступны".to_string();
            self.emit_snapshot(false);
            return None;
        };
        let candidate_key = endpoint_key(&candidate);
        self.probe_is_primary = primary
            .as_ref()
            .is_some_and(|primary| endpoint_key(primary) == candidate_key);
        self.probe_key = Some(candidate_key);
        self.reason = format!(
            "пробная проверка: {}",
            endpoint_display_name(Some(&candidate))
        );
        self.emit_snapshot(false);
        Some(UpstreamAttempt {
            endpoint: candidate,
            generation: self.generation,
            is_probe: true,
            primary_probe: self.probe_is_primary,
        })
    }

    /// Неудача подключения активного сервера.
    pub fn record_connect_failure(
        &mut self,
        attempt: &UpstreamAttempt,
        reason: &str,
    ) -> Option<UpstreamTransition> {
        if !self.attempt_is_current(attempt) {
            return None;
        }
        let now = self.now();
        let is_probe = attempt.is_probe;
        let endpoint_key_of_attempt = endpoint_key(&attempt.endpoint);
        if is_probe {
            let retry_after = self.penalize(&attempt.endpoint, now);
            self.clear_probe(&endpoint_key_of_attempt);
            self.reason = format!("пробное подключение не удалось: {reason}");
            self.emit_snapshot(false);
            let _ = retry_after;
            return None;
        }
        let health = self.health_for(&attempt.endpoint);
        health.connect_failures.push_back(now);
        while health
            .connect_failures
            .front()
            .is_some_and(|at| now - at > CONNECT_FAILURE_WINDOW)
        {
            health.connect_failures.pop_front();
        }
        let observation_time = now - health.connect_failures[0];
        if health.connect_failures.len() < CONNECT_FAILURE_LIMIT
            || observation_time < CONNECT_FAILURE_OBSERVATION_WINDOW
        {
            return None;
        }
        let retry_after = self.penalize(&attempt.endpoint, now);
        self.fail_active(
            attempt,
            &format!(
                "{CONNECT_FAILURE_LIMIT} ошибок подключения не менее чем за \
                 {CONNECT_FAILURE_OBSERVATION_WINDOW} с: {reason}"
            ),
            retry_after,
        )
    }

    /// Активное соединение получило ноль данных.
    pub fn record_zero_recv(
        &mut self,
        attempt: &UpstreamAttempt,
        reason: &str,
    ) -> Option<UpstreamTransition> {
        if !self.attempt_is_current(attempt) {
            return None;
        }
        let now = self.now();
        let is_probe = attempt.is_probe;
        let endpoint_key_of_attempt = endpoint_key(&attempt.endpoint);
        if is_probe {
            self.penalize(&attempt.endpoint, now);
            self.clear_probe(&endpoint_key_of_attempt);
            self.reason = format!(
                "пробная проверка не получила данные: {}",
                endpoint_display_name(Some(&attempt.endpoint))
            );
            self.emit_snapshot(false);
            return None;
        }
        let health = self.health_for(&attempt.endpoint);
        if health.zero_recv_started_at.is_none() {
            health.zero_recv_started_at = Some(now);
        }
        health.zero_recv_count += 1;
        let observation_time = now - health.zero_recv_started_at.unwrap_or(now);
        if health.zero_recv_count < ZERO_RECV_LIMIT
            || observation_time < ZERO_RECV_OBSERVATION_WINDOW
        {
            return None;
        }
        let retry_after = self.penalize(&attempt.endpoint, now);
        self.fail_active(
            attempt,
            &format!("шесть соединений без ответных данных: {reason}"),
            retry_after,
        )
    }

    /// Соединение получило настоящие данные.
    pub fn record_recv_ok(&mut self, attempt: &UpstreamAttempt) -> Option<UpstreamTransition> {
        if !self.attempt_is_current(attempt) {
            return None;
        }
        {
            let health = self.health_for(&attempt.endpoint);
            health.connect_failures.clear();
            health.zero_recv_count = 0;
            health.zero_recv_started_at = None;
            health.failure_round = 0;
            health.unavailable_until = 0.0;
        }
        if attempt.is_probe {
            self.clear_probe(&endpoint_key(&attempt.endpoint));
            if self.active.is_none() || attempt.primary_probe {
                return self.switch_active(
                    Some(attempt.endpoint.clone()),
                    "сервер подтвердил работу реальными данными",
                    0.0,
                );
            }
        }
        if let Some(active) = &self.active {
            if endpoint_key(active) == endpoint_key(&attempt.endpoint) {
                self.reason = "сервер передаёт данные".to_string();
                self.emit_snapshot(false);
            }
        }
        None
    }

    /// Проба отменена локально — сервер не виноват.
    pub fn abandon_attempt(&mut self, attempt: &UpstreamAttempt) {
        if attempt.is_probe && self.attempt_is_current(attempt) {
            self.clear_probe(&endpoint_key(&attempt.endpoint));
            self.reason = if self.active.is_some() {
                "основной сервер ждёт следующей пробной проверки".to_string()
            } else {
                "все серверы временно недоступны".to_string()
            };
            self.emit_snapshot(false);
        }
    }

    fn attempt_is_current(&self, attempt: &UpstreamAttempt) -> bool {
        if attempt.generation != self.generation {
            return false;
        }
        let key = endpoint_key(&attempt.endpoint);
        if attempt.is_probe {
            return self.probe_key.as_ref() == Some(&key);
        }
        self.active
            .as_ref()
            .is_some_and(|active| endpoint_key(active) == key)
    }

    fn health_for(&mut self, endpoint: &UpstreamProxyEndpoint) -> &mut EndpointHealth {
        self.health.entry(endpoint_key(endpoint)).or_default()
    }

    fn first_available(
        &self,
        now: f64,
        exclude: Option<EndpointKey>,
    ) -> Option<UpstreamProxyEndpoint> {
        for endpoint in &self.endpoints {
            let key = endpoint_key(endpoint);
            if Some(&key) == exclude.as_ref() {
                continue;
            }
            if self
                .health
                .get(&key)
                .map(|health| health.unavailable_until)
                .unwrap_or(0.0)
                <= now
            {
                return Some(endpoint.clone());
            }
        }
        None
    }

    fn penalize(&mut self, endpoint: &UpstreamProxyEndpoint, now: f64) -> f64 {
        let health = self.health_for(endpoint);
        health.failure_round += 1;
        let retry_after = RETRY_DELAYS[(health.failure_round - 1).min(RETRY_DELAYS.len() - 1)];
        health.unavailable_until = now + retry_after;
        health.connect_failures.clear();
        health.zero_recv_count = 0;
        health.zero_recv_started_at = None;
        retry_after
    }

    fn clear_probe(&mut self, key: &EndpointKey) {
        if self.probe_key.as_ref() == Some(key) {
            self.probe_key = None;
            self.probe_is_primary = false;
        }
    }

    fn fail_active(
        &mut self,
        attempt: &UpstreamAttempt,
        reason: &str,
        retry_after: f64,
    ) -> Option<UpstreamTransition> {
        let Some(active) = &self.active else {
            return None;
        };
        if endpoint_key(active) != endpoint_key(&attempt.endpoint) {
            return None;
        }
        let replacement = self.first_available(self.now(), Some(endpoint_key(&attempt.endpoint)));
        self.switch_active(replacement, reason, retry_after)
    }

    fn switch_active(
        &mut self,
        endpoint: Option<UpstreamProxyEndpoint>,
        reason: &str,
        retry_after: f64,
    ) -> Option<UpstreamTransition> {
        let old_endpoint = self.active.clone();
        let old_key = old_endpoint.as_ref().map(endpoint_key);
        let new_key = endpoint.as_ref().map(endpoint_key);
        if old_key == new_key {
            self.reason = reason.to_string();
            self.emit_snapshot(false);
            return None;
        }
        let old_generation = self.generation;
        self.generation += 1;
        self.active = endpoint;
        self.probe_key = None;
        self.probe_is_primary = false;
        self.reason = if self.active.is_some() {
            reason.to_string()
        } else {
            "все серверы временно недоступны".to_string()
        };
        let transition = UpstreamTransition {
            old_endpoint,
            new_endpoint: self.active.clone(),
            reason: reason.to_string(),
            old_generation,
            generation: self.generation,
            retry_after,
        };
        self.emit_snapshot(true);
        Some(transition)
    }
}

/// Текст смены сервера для журнала (python: `_handle_transition`).
#[must_use]
pub fn switch_log_text(transition: &UpstreamTransition) -> String {
    let old_name = {
        let name = endpoint_display_name(transition.old_endpoint.as_ref());
        if name.is_empty() {
            "нет".to_string()
        } else {
            name
        }
    };
    let new_name = {
        let name = endpoint_display_name(transition.new_endpoint.as_ref());
        if name.is_empty() {
            "временно недоступно".to_string()
        } else {
            name
        }
    };
    let wait_text = if transition.retry_after > 0.0 {
        format!(", повтор через {} с", transition.retry_after as i64)
    } else {
        String::new()
    };
    format!(
        "SOCKS переключён: {old_name} -> {new_name}; причина: {}{wait_text}",
        transition.reason
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type SharedClock = std::sync::Arc<std::sync::Mutex<f64>>;

    struct Fixture {
        controller: UpstreamStateController,
        clock: SharedClock,
    }

    fn endpoint(preset_id: &str, name: &str, host: &str, port: i64) -> UpstreamProxyEndpoint {
        UpstreamProxyEndpoint {
            host: host.into(),
            port,
            username: format!("{preset_id}_user"),
            password: format!("{preset_id}_password"),
            tls: true,
            tls_server_name: "www.google.com".into(),
            tls_verify: false,
            preset_id: preset_id.into(),
            preset_name: name.into(),
        }
    }

    fn config(fallbacks: Vec<UpstreamProxyEndpoint>) -> UpstreamProxyConfig {
        let primary = endpoint("de1", "Германия 1", "95.128.157.251", 9443);
        UpstreamProxyConfig {
            enabled: true,
            mode: "always".into(),
            host: primary.host.clone(),
            port: primary.port,
            username: primary.username.clone(),
            password: primary.password.clone(),
            tls: primary.tls,
            tls_server_name: primary.tls_server_name.clone(),
            preset_id: primary.preset_id.clone(),
            preset_name: primary.preset_name.clone(),
            fallback_proxies: fallbacks,
            ..UpstreamProxyConfig::default()
        }
    }

    impl Fixture {
        fn new() -> Self {
            let clock: SharedClock = std::sync::Arc::new(std::sync::Mutex::new(1000.0));
            let clone = clock.clone();
            Self {
                controller: UpstreamStateController::new(
                    &config(vec![
                        endpoint("uk", "Великобритания", "144.31.213.98", 443),
                        endpoint("no", "Норвегия", "31.76.5.8", 443),
                    ]),
                    None,
                    Box::new(move || *clone.lock().unwrap()),
                ),
                clock,
            }
        }

        fn advance(&self, seconds: f64) {
            *self.clock.lock().unwrap() += seconds;
        }

        fn fail_active(&mut self) -> Option<UpstreamTransition> {
            let attempts: Vec<UpstreamAttempt> = (0..CONNECT_FAILURE_LIMIT)
                .map(|_| self.controller.select_attempt().unwrap())
                .collect();
            for attempt in attempts[..attempts.len() - 1].iter() {
                assert!(self
                    .controller
                    .record_connect_failure(attempt, "timeout")
                    .is_none());
            }
            self.advance(CONNECT_FAILURE_OBSERVATION_WINDOW);
            let last = attempts.last().unwrap().clone();
            self.controller.record_connect_failure(&last, "timeout")
        }
    }

    #[test]
    fn all_connections_use_one_active_server() {
        let mut fixture = Fixture::new();
        let attempts: Vec<UpstreamAttempt> = (0..50)
            .map(|_| fixture.controller.select_attempt().unwrap())
            .collect();
        let hosts: std::collections::HashSet<String> = attempts
            .iter()
            .map(|item| item.endpoint.host.clone())
            .collect();
        assert_eq!(
            hosts,
            std::iter::once("95.128.157.251".to_string()).collect()
        );
        let generations: std::collections::HashSet<i64> =
            attempts.iter().map(|item| item.generation).collect();
        assert_eq!(generations, std::iter::once(1).collect());
    }

    #[test]
    fn two_resets_after_real_data_do_not_drop_working_server() {
        let mut fixture = Fixture::new();
        let attempts: Vec<UpstreamAttempt> = (0..17)
            .map(|_| fixture.controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..15].iter() {
            assert!(fixture.controller.record_recv_ok(attempt).is_none());
        }
        assert!(fixture
            .controller
            .record_connect_failure(&attempts[15], "ConnectionResetError")
            .is_none());
        assert!(fixture
            .controller
            .record_connect_failure(&attempts[16], "ConnectionResetError")
            .is_none());
        assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
        assert_eq!(fixture.controller.snapshot().generation, 1);
    }

    #[test]
    fn parallel_connect_failure_burst_waits_for_inflight_real_data() {
        let mut fixture = Fixture::new();
        let attempts: Vec<UpstreamAttempt> = (0..CONNECT_FAILURE_LIMIT + 1)
            .map(|_| fixture.controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..CONNECT_FAILURE_LIMIT].iter() {
            assert!(fixture
                .controller
                .record_connect_failure(attempt, "timeout")
                .is_none());
        }
        assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
        assert!(fixture
            .controller
            .record_recv_ok(&attempts[CONNECT_FAILURE_LIMIT])
            .is_none());
        assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
        assert_eq!(fixture.controller.snapshot().generation, 1);
    }

    #[test]
    fn repeated_connect_failures_produce_one_global_switch() {
        let mut fixture = Fixture::new();
        let transition = fixture.fail_active();
        assert!(transition.is_some());
        assert_eq!(fixture.controller.snapshot().active_name, "Великобритания");
        assert_eq!(fixture.controller.snapshot().generation, 2);
    }

    #[test]
    fn recv_zero_is_not_success_and_switches_only_after_six() {
        let mut fixture = Fixture::new();
        let attempts: Vec<UpstreamAttempt> = (0..ZERO_RECV_LIMIT)
            .map(|_| fixture.controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..attempts.len() - 1].iter() {
            assert!(fixture
                .controller
                .record_zero_recv(attempt, "соединение не получило ответных данных")
                .is_none());
            assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
        }
        fixture.advance(ZERO_RECV_OBSERVATION_WINDOW);
        let last = attempts.last().unwrap().clone();
        let transition = fixture
            .controller
            .record_zero_recv(&last, "соединение не получило ответных данных");
        assert!(transition.is_some());
        assert_eq!(fixture.controller.snapshot().active_name, "Великобритания");
    }

    #[test]
    fn concurrent_zero_burst_waits_for_inflight_real_data() {
        let mut fixture = Fixture::new();
        let attempts: Vec<UpstreamAttempt> = (0..ZERO_RECV_LIMIT + 1)
            .map(|_| fixture.controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..ZERO_RECV_LIMIT].iter() {
            assert!(fixture.controller.record_zero_recv(attempt, "x").is_none());
        }
        assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
        assert!(fixture
            .controller
            .record_recv_ok(&attempts[ZERO_RECV_LIMIT])
            .is_none());
        assert_eq!(fixture.controller.snapshot().active_name, "Германия 1");
    }

    #[test]
    fn primary_returns_only_after_probe_receives_real_data() {
        let mut fixture = Fixture::new();
        assert!(fixture.fail_active().is_some());
        fixture.advance(RETRY_DELAYS[0]);
        let probe = fixture.controller.select_attempt().unwrap();
        assert!(probe.primary_probe);
        assert_eq!(
            fixture.controller.snapshot().state,
            UpstreamState::CheckingPrimary
        );
        let regular = fixture.controller.select_attempt().unwrap();
        assert_eq!(regular.endpoint.preset_id, "uk");

        fixture.controller.record_zero_recv(&probe, "x");
        assert_eq!(fixture.controller.snapshot().active_preset_id, "uk");
        assert_eq!(fixture.controller.snapshot().state, UpstreamState::Fallback);

        fixture.advance(RETRY_DELAYS[1]);
        let probe = fixture.controller.select_attempt().unwrap();
        let transition = fixture.controller.record_recv_ok(&probe);
        assert!(transition.is_some());
        assert_eq!(fixture.controller.snapshot().active_preset_id, "de1");
        assert_eq!(fixture.controller.snapshot().state, UpstreamState::Primary);
    }

    #[test]
    fn retry_delays_grow_to_five_minutes_without_busy_loop() {
        let clock: SharedClock = std::sync::Arc::new(std::sync::Mutex::new(1000.0));
        let clone = clock.clone();
        let mut controller = UpstreamStateController::new(
            &UpstreamProxyConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 1080,
                ..UpstreamProxyConfig::default()
            },
            None,
            Box::new(move || *clone.lock().unwrap()),
        );
        let attempts: Vec<UpstreamAttempt> = (0..CONNECT_FAILURE_LIMIT)
            .map(|_| controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..attempts.len() - 1].iter() {
            assert!(controller
                .record_connect_failure(attempt, "timeout")
                .is_none());
        }
        *clock.lock().unwrap() += CONNECT_FAILURE_OBSERVATION_WINDOW;
        let last = attempts.last().unwrap().clone();
        assert!(controller
            .record_connect_failure(&last, "timeout")
            .is_some());
        assert!(controller.active().is_none());
        assert!(controller.select_attempt().is_none());

        *clock.lock().unwrap() += RETRY_DELAYS[0];
        let probe = controller.select_attempt();
        assert!(probe.is_some());
        controller.record_connect_failure(&probe.unwrap(), "timeout");
        *clock.lock().unwrap() += RETRY_DELAYS[1] - 1.0;
        assert!(controller.select_attempt().is_none());
        *clock.lock().unwrap() += 1.0;
        let probe = controller.select_attempt();
        assert!(probe.is_some());
        controller.record_connect_failure(&probe.unwrap(), "timeout");
        *clock.lock().unwrap() += RETRY_DELAYS[2] - 1.0;
        assert!(controller.select_attempt().is_none());
        *clock.lock().unwrap() += 1.0;
        assert!(controller.select_attempt().is_some());
    }

    #[test]
    fn manual_server_has_no_hidden_bundled_fallback() {
        let clock: SharedClock = std::sync::Arc::new(std::sync::Mutex::new(1000.0));
        let clone = clock.clone();
        let mut controller = UpstreamStateController::new(
            &UpstreamProxyConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 1080,
                username: "user".into(),
                password: "password".into(),
                ..UpstreamProxyConfig::default()
            },
            None,
            Box::new(move || *clone.lock().unwrap()),
        );
        let attempts: Vec<UpstreamAttempt> = (0..CONNECT_FAILURE_LIMIT)
            .map(|_| controller.select_attempt().unwrap())
            .collect();
        for attempt in attempts[..attempts.len() - 1].iter() {
            assert!(controller
                .record_connect_failure(attempt, "timeout")
                .is_none());
        }
        *clock.lock().unwrap() += CONNECT_FAILURE_OBSERVATION_WINDOW;
        let last = attempts.last().unwrap().clone();
        assert!(controller
            .record_connect_failure(&last, "timeout")
            .is_some());
        assert!(controller.active().is_none());
        assert_eq!(controller.endpoints().len(), 1);
    }

    #[test]
    fn snapshot_keeps_selected_server_separate_from_fallback() {
        let mut fixture = Fixture::new();
        fixture.fail_active();
        let snapshot = fixture.controller.snapshot();
        assert_eq!(snapshot.selected_name, "Германия 1");
        assert_eq!(snapshot.active_name, "Великобритания");
        assert_eq!(snapshot.state, UpstreamState::Fallback);
    }

    #[test]
    fn replace_config_and_hot_swap_follow_python() {
        let clock: SharedClock = std::sync::Arc::new(std::sync::Mutex::new(1000.0));
        let clone = clock.clone();
        let mut controller = UpstreamStateController::new(
            &UpstreamProxyConfig {
                enabled: true,
                host: "old.example".into(),
                port: 1080,
                preset_id: "old".into(),
                preset_name: "OLD".into(),
                ..UpstreamProxyConfig::default()
            },
            None,
            Box::new(move || *clone.lock().unwrap()),
        );
        assert_eq!(controller.current_endpoint().unwrap().host, "old.example");
        let transition = controller.replace_config(
            &UpstreamProxyConfig {
                enabled: true,
                host: "new.example".into(),
                port: 1080,
                preset_id: "uk".into(),
                preset_name: "UK".into(),
                ..UpstreamProxyConfig::default()
            },
            "выбран другой основной сервер",
        );
        assert!(transition.is_some());
        assert_eq!(controller.snapshot().selected_preset_id, "uk");
        assert_eq!(controller.snapshot().active_name, "UK");
        // Отключение: активного сервера нет, состояние unavailable.
        let transition =
            controller.replace_config(&UpstreamProxyConfig::default(), "настройка изменена");
        assert!(transition.is_some());
        assert_eq!(controller.snapshot().state, UpstreamState::Unavailable);
    }

    #[test]
    fn duplicate_fallback_endpoints_are_deduplicated() {
        let tls = UpstreamProxyEndpoint {
            host: "tls".into(),
            port: 443,
            tls: true,
            ..UpstreamProxyEndpoint::default()
        };
        let plain = UpstreamProxyEndpoint {
            host: "plain".into(),
            port: 1080,
            ..UpstreamProxyEndpoint::default()
        };
        let duplicate = plain.clone();
        let endpoints = endpoints_from_config(&UpstreamProxyConfig {
            enabled: true,
            host: tls.host.clone(),
            port: tls.port,
            tls: true,
            fallback_proxies: vec![plain, duplicate],
            ..UpstreamProxyConfig::default()
        });
        assert_eq!(
            endpoints
                .iter()
                .map(|item| item.host.clone())
                .collect::<Vec<_>>(),
            vec!["tls", "plain"]
        );
    }

    #[test]
    fn display_name_and_switch_text_match_python() {
        let named = endpoint("uk", "Великобритания", "144.31.213.98", 443);
        assert_eq!(endpoint_display_name(Some(&named)), "Великобритания");
        let manual = UpstreamProxyEndpoint {
            host: "1.2.3.4".into(),
            port: 1080,
            ..UpstreamProxyEndpoint::default()
        };
        assert_eq!(endpoint_display_name(Some(&manual)), "1.2.3.4:1080");
        assert_eq!(endpoint_display_name(None), "");
        let empty = UpstreamProxyEndpoint::default();
        assert_eq!(endpoint_display_name(Some(&empty)), "внешний прокси");

        let transition = UpstreamTransition {
            old_endpoint: Some(named),
            new_endpoint: None,
            reason: "шесть ошибок".into(),
            old_generation: 1,
            generation: 2,
            retry_after: 60.0,
        };
        assert_eq!(
            switch_log_text(&transition),
            "SOCKS переключён: Великобритания -> временно недоступно; причина: шесть ошибок, повтор через 60 с"
        );
    }
}
