//! Порядок маршрутов для одного соединения Telegram.
//!
//! Порт `telegram_proxy/proxy/routes.py`. Главный путь — WSS, как в ZaStoGram:
//! релей Telegram, свой домен Cloudflare и свой воркер, фронты Cloudflare,
//! туннель через воркеры, внешний SOCKS5, прямой TCP. Если все WSS-ступени
//! подавлены, после внешнего SOCKS или прямого TCP ещё раз пробуются фронты
//! без учёта подавления: DC не должен остаться совсем без маршрута.

use crate::proxy::cloudflare::CloudflareFallbackConfig;
use crate::proxy::dc_map::parse_ipv4;
use crate::proxy::health::{
    address_key, cdn_key, direct_key, RouteHealth, CDN_FAILURES_BEFORE_SUPPRESS,
    FAILURES_BEFORE_SUPPRESS,
};
use crate::proxy::key_clusters::{CLUSTER_MEDIA, CLUSTER_REGULAR};
use crate::proxy::obfs::DcField;
use crate::proxy::route_catalog::{
    relay_addresses, relay_domain, CDN_FRONTS, CDN_FRONT_DCS, TUNNEL_HOSTS, WSS_PATH,
};
use crate::proxy::routing::UpstreamProxyConfig;

pub const KIND_RELAY: &str = "relay";
pub const KIND_USER_DOMAIN: &str = "user_domain";
pub const KIND_USER_WORKER: &str = "user_worker";
pub const KIND_FRONT: &str = "front";
pub const KIND_TUNNEL: &str = "tunnel";
pub const KIND_UPSTREAM: &str = "upstream";
pub const KIND_DIRECT: &str = "direct";

/// Является ли вид маршрута WebSocket-путём.
#[must_use]
pub fn is_ws_kind(kind: &str) -> bool {
    matches!(
        kind,
        KIND_RELAY | KIND_USER_DOMAIN | KIND_USER_WORKER | KIND_FRONT | KIND_TUNNEL
    )
}

/// Основные пути: без суточных лимитов и чужих серверов. Остальные — запасные.
#[must_use]
pub fn is_primary_kind(kind: &str) -> bool {
    matches!(kind, KIND_RELAY | KIND_USER_DOMAIN | KIND_FRONT)
}

/// Пути, которые медиа приводят на обычный кластер: заголовок с +dc.
fn is_regular_cluster_kind(kind: &str) -> bool {
    matches!(kind, KIND_USER_DOMAIN | KIND_FRONT)
}

/// Сколько фронтов пробовать внутри одного соединения Telegram.
pub const FRONTS_PER_CONNECTION: usize = 3;
/// Сколько воркеров-туннелей пробовать внутри одного соединения Telegram.
pub const TUNNELS_PER_CONNECTION: usize = 3;

/// Сколько байт от сервера доказывает, что маршрут действительно возит трафик.
pub const RELAY_PROOF_BYTES: usize = 1;
pub const FRONT_PROOF_BYTES: usize = 32 * 1024;
pub const TUNNEL_PROOF_BYTES: usize = 6 * 1024;
/// Прямой TCP доказывается тем же объёмом, что и фронт: ТСПУ пропускает начало
/// ответа и душит дальше. Сессия, закрытая раньше, — неудача.
pub const DIRECT_PROOF_BYTES: usize = FRONT_PROOF_BYTES;
/// Прямой путь встаёт на паузу после первой же неудачи.
pub const DIRECT_FAILURES_BEFORE_SUPPRESS: usize = 1;

/// Названия маршрутов для route_events: страница Telegram Proxy ищет в них
/// подстроки «cloudflare», «внеш», «tcp».
#[must_use]
pub fn route_label(kind: &str) -> String {
    match kind {
        KIND_RELAY => "WSS".into(),
        KIND_USER_DOMAIN => "Cloudflare".into(),
        KIND_USER_WORKER => "Cloudflare Worker".into(),
        KIND_FRONT => "Cloudflare".into(),
        KIND_TUNNEL => "Cloudflare Worker".into(),
        KIND_UPSTREAM => "внешний SOCKS5".into(),
        KIND_DIRECT => "TCP".into(),
        other => other.to_string(),
    }
}

/// Один маршрут плана.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub kind: String,
    pub connect_host: String,
    pub sni: String,
    pub path: String,
    pub port: i64,
    pub dc_field: DcField,
    pub health_key: String,
    pub health_threshold: usize,
    pub address_health_key: String,
    pub proof_bytes: usize,
    pub pool_key: String,
    pub front_index: i64,
    pub front_family: i64,
    pub target_host: String,
    pub target_port: i64,
    pub cluster: String,
}

impl Route {
    /// Маршрут с полями по умолчанию (как `Route(kind=...)` в python).
    #[must_use]
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            connect_host: String::new(),
            sni: String::new(),
            path: WSS_PATH.to_string(),
            port: 443,
            dc_field: DcField::Signed,
            health_key: String::new(),
            health_threshold: FAILURES_BEFORE_SUPPRESS,
            address_health_key: String::new(),
            proof_bytes: RELAY_PROOF_BYTES,
            pool_key: String::new(),
            front_index: -1,
            front_family: -1,
            target_host: String::new(),
            target_port: 443,
            cluster: CLUSTER_REGULAR.to_string(),
        }
    }

    /// WebSocket-путь (релей, фронты, воркеры).
    #[must_use]
    pub fn is_ws(&self) -> bool {
        is_ws_kind(&self.kind)
    }

    /// Основной путь без суточных лимитов.
    #[must_use]
    pub fn is_primary(&self) -> bool {
        is_primary_kind(&self.kind)
    }

    /// Название для route_events.
    #[must_use]
    pub fn label(&self) -> String {
        route_label(&self.kind)
    }

    /// Короткое описание цели для журнала.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.kind == KIND_UPSTREAM || self.kind == KIND_DIRECT {
            return format!("{}:{}", self.target_host, self.target_port);
        }
        if !self.connect_host.is_empty() && self.connect_host != self.sni {
            return format!("wss://{}{} via {}", self.sni, self.path, self.connect_host);
        }
        format!("wss://{}{}", self.sni, self.path)
    }
}

/// Вход плана: соединение Desktop с известным DC и целями.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanInput {
    pub dc: i32,
    pub is_media: bool,
    pub target_host: String,
    pub target_port: i64,
    pub upstream: UpstreamProxyConfig,
    pub cloudflare: CloudflareFallbackConfig,
    /// Кластер, на котором живёт ключ этого соединения ("" — неизвестен).
    pub key_cluster: String,
}

fn front_domains() -> Vec<&'static str> {
    CDN_FRONTS.iter().map(|front| front.domain).collect()
}

fn relay_route(dc: i32, is_media: bool, health: &RouteHealth) -> Option<Route> {
    let addresses = relay_addresses(dc);
    if addresses.is_empty() {
        return None;
    }
    let domain = relay_domain(dc, is_media);
    if health.is_suppressed(&domain) {
        return None;
    }
    // Один релей в плане: за ним сразу идут фронты, и гонка фронта с
    // недоказанным релеем остаётся в силе. Отказавший адрес уступает место
    // другому адресу DC в следующих соединениях.
    for address in health.relay_address_order(addresses) {
        let addr_key = address_key(&address);
        if health.is_suppressed(&addr_key) {
            continue;
        }
        let mut route = Route::new(KIND_RELAY);
        route.connect_host = address.clone();
        route.sni = domain.clone();
        route.dc_field = DcField::Random;
        route.health_key = domain.clone();
        route.address_health_key = addr_key;
        route.proof_bytes = RELAY_PROOF_BYTES;
        route.pool_key = format!("relay:{domain}@{address}");
        return Some(route);
    }
    let mut route = Route::new(KIND_RELAY);
    route.connect_host = domain.clone();
    route.sni = domain.clone();
    route.dc_field = DcField::Random;
    route.health_key = domain.clone();
    route.proof_bytes = RELAY_PROOF_BYTES;
    route.pool_key = format!("relay:{domain}@dns");
    Some(route)
}

fn user_domain_routes(
    dc: i32,
    config: &CloudflareFallbackConfig,
    health: &RouteHealth,
) -> Vec<Route> {
    if !config.enabled {
        return Vec::new();
    }
    let mut routes = Vec::new();
    for domain in &config.domains {
        if front_domains().contains(&domain.as_str()) {
            continue;
        }
        let host = format!("kws{dc}.{domain}");
        let key = format!("user-cf-{domain}");
        if health.is_suppressed(&key) {
            continue;
        }
        let mut route = Route::new(KIND_USER_DOMAIN);
        route.connect_host = host.clone();
        route.sni = host;
        route.dc_field = DcField::Plus;
        route.health_key = key;
        route.proof_bytes = FRONT_PROOF_BYTES;
        routes.push(route);
    }
    routes
}

fn worker_path(target_ip: &str, dc: i32) -> String {
    format!(
        "{WSS_PATH}?dst={}&dc={}",
        crate::proxy::mtproxy::urlencode(target_ip),
        dc
    )
}

fn user_worker_routes(
    dc: i32,
    target_ip: &str,
    config: &CloudflareFallbackConfig,
    health: &RouteHealth,
) -> Vec<Route> {
    if !config.worker_enabled || target_ip.is_empty() {
        return Vec::new();
    }
    let mut routes = Vec::new();
    for domain in &config.worker_domains {
        let key = format!("user-worker-{domain}");
        if health.is_suppressed(&key) {
            continue;
        }
        let mut route = Route::new(KIND_USER_WORKER);
        route.connect_host = domain.clone();
        route.sni = domain.clone();
        route.path = worker_path(target_ip, dc);
        route.dc_field = DcField::Signed;
        route.health_key = key;
        route.proof_bytes = TUNNEL_PROOF_BYTES;
        routes.push(route);
    }
    routes
}

fn front_routes(dc: i32, health: &RouteHealth, ignore_suppression: bool) -> Vec<Route> {
    if !CDN_FRONT_DCS.contains(&dc) || CDN_FRONTS.is_empty() {
        return Vec::new();
    }
    let key = cdn_key(dc);
    if !ignore_suppression && health.is_suppressed(&key) {
        return Vec::new();
    }
    let mut routes = Vec::new();
    for (index, family) in health.next_front_slots(FRONTS_PER_CONNECTION) {
        let front = &CDN_FRONTS[index];
        let mut route = Route::new(KIND_FRONT);
        route.connect_host = front.addresses[family as usize].to_string();
        route.sni = front.host_for(dc);
        route.dc_field = DcField::Plus;
        route.health_key = key.clone();
        route.health_threshold = CDN_FAILURES_BEFORE_SUPPRESS;
        route.proof_bytes = FRONT_PROOF_BYTES;
        route.pool_key = format!("front:kws{dc}");
        route.front_index = index as i64;
        route.front_family = i64::from(family);
        routes.push(route);
    }
    routes
}

fn tunnel_routes(
    dc: i32,
    target_ip: &str,
    health: &RouteHealth,
    tunnel_hosts: &[&str],
) -> Vec<Route> {
    if target_ip.is_empty() || tunnel_hosts.is_empty() {
        return Vec::new();
    }
    let mut routes = Vec::new();
    for step in 0..tunnel_hosts.len() {
        let host = tunnel_hosts[((health.tunnel_start as usize) + step) % tunnel_hosts.len()];
        if health.is_suppressed(host) {
            continue;
        }
        let mut route = Route::new(KIND_TUNNEL);
        route.connect_host = host.to_string();
        route.sni = host.to_string();
        route.path = worker_path(target_ip, dc);
        route.dc_field = DcField::Signed;
        route.health_key = host.to_string();
        route.proof_bytes = TUNNEL_PROOF_BYTES;
        routes.push(route);
        if routes.len() >= TUNNELS_PER_CONNECTION {
            break;
        }
    }
    routes
}

fn direct_route(dc: i32, target_host: &str, target_port: i64) -> Route {
    let mut route = Route::new(KIND_DIRECT);
    route.target_host = target_host.to_string();
    route.target_port = if target_port == 0 { 443 } else { target_port };
    route.health_key = direct_key(dc);
    route.health_threshold = DIRECT_FAILURES_BEFORE_SUPPRESS;
    route.proof_bytes = DIRECT_PROOF_BYTES;
    route
}

fn cluster(kind: &str, is_media: bool) -> &'static str {
    if is_media && !is_regular_cluster_kind(kind) {
        CLUSTER_MEDIA
    } else {
        CLUSTER_REGULAR
    }
}

/// Основные пути кластера ключа — раньше основных путей другого; запасные на месте.
fn home_cluster_first(plan: Vec<Route>, cluster: &str) -> Vec<Route> {
    let mut primaries: Vec<Route> = plan
        .iter()
        .filter(|route| route.is_primary())
        .cloned()
        .collect();
    primaries.sort_by_key(|route| route.cluster != cluster);
    let mut iterator = primaries.into_iter();
    plan.into_iter()
        .map(|route| {
            if route.is_primary() {
                iterator.next().unwrap_or(route)
            } else {
                route
            }
        })
        .collect()
}

/// План маршрутов с учётом кластера ключа медиа-сессии.
#[must_use]
pub fn build_plan(request: &PlanInput, health: &RouteHealth) -> Vec<Route> {
    build_plan_with_tunnels(request, health, TUNNEL_HOSTS)
}

/// План маршрутов с подменным списком воркеров (тесты перебора туннелей).
#[must_use]
pub fn build_plan_with_tunnels(
    request: &PlanInput,
    health: &RouteHealth,
    tunnel_hosts: &[&str],
) -> Vec<Route> {
    let mut plan = raw_plan(request, health, tunnel_hosts);
    for route in &mut plan {
        route.cluster = cluster(&route.kind, request.is_media).to_string();
    }
    if request.is_media && !request.key_cluster.is_empty() {
        plan = home_cluster_first(plan, &request.key_cluster);
    }
    plan
}

fn raw_plan(request: &PlanInput, health: &RouteHealth, tunnel_hosts: &[&str]) -> Vec<Route> {
    let dc = request.dc;
    let is_media = request.is_media;
    let upstream = &request.upstream;
    let target_ip = if parse_ipv4(&request.target_host).is_some() {
        request.target_host.clone()
    } else {
        String::new()
    };

    let mut upstream_route = Route::new(KIND_UPSTREAM);
    upstream_route.target_host = request.target_host.clone();
    upstream_route.target_port = if request.target_port == 0 {
        443
    } else {
        request.target_port
    };
    if crate::proxy::routing::should_route_upstream(upstream, "always") {
        return vec![upstream_route];
    }

    let mut plan: Vec<Route> = Vec::new();
    if CDN_FRONT_DCS.contains(&dc) {
        if let Some(relay) = relay_route(dc, is_media, health) {
            plan.push(relay);
        }
        plan.extend(user_domain_routes(dc, &request.cloudflare, health));
        plan.extend(user_worker_routes(
            dc,
            &target_ip,
            &request.cloudflare,
            health,
        ));
        plan.extend(front_routes(dc, health, false));
        plan.extend(tunnel_routes(dc, &target_ip, health, tunnel_hosts));
    }

    let all_wss_suppressed = plan.is_empty() && CDN_FRONT_DCS.contains(&dc);
    if upstream.enabled {
        plan.push(upstream_route);
    } else if !CDN_FRONT_DCS.contains(&dc) || !health.is_suppressed(&direct_key(dc)) {
        // DC без WSS-путей идёт напрямую всегда: другого маршрута у него нет.
        plan.push(direct_route(dc, &request.target_host, request.target_port));
    }
    if all_wss_suppressed {
        plan.extend(front_routes(dc, health, true));
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::key_clusters::KeyClusters;

    type SharedClock = std::sync::Arc<std::sync::Mutex<f64>>;

    fn clock_pair(start: f64) -> (SharedClock, Box<dyn Fn() -> f64>) {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(start));
        let clone = shared.clone();
        (shared, Box::new(move || *clone.lock().unwrap()))
    }

    fn preset() -> UpstreamProxyConfig {
        UpstreamProxyConfig {
            enabled: true,
            host: "1.2.3.4".into(),
            port: 1080,
            mode: "fallback".into(),
            preset_id: "ee".into(),
            ..UpstreamProxyConfig::default()
        }
    }

    fn request(dc: i32, is_media: bool, target: &str) -> PlanInput {
        PlanInput {
            dc,
            is_media,
            target_host: target.to_string(),
            target_port: 443,
            upstream: preset(),
            ..PlanInput::default()
        }
    }

    /// Запрос без внешнего SOCKS5 — как PlanInput(...) по умолчанию в python.
    fn plain_request(dc: i32, is_media: bool, target: &str) -> PlanInput {
        PlanInput {
            dc,
            is_media,
            target_host: target.to_string(),
            target_port: 443,
            ..PlanInput::default()
        }
    }

    struct Fixture {
        health: RouteHealth,
        clock: SharedClock,
    }

    impl Fixture {
        fn new() -> Self {
            let (clock, boxed) = clock_pair(1000.0);
            Self {
                health: RouteHealth::new(None, boxed, Box::new(|| 5000.0), CDN_FRONTS.len(), None),
                clock,
            }
        }

        fn advance(&self, seconds: f64) {
            *self.clock.lock().unwrap() += seconds;
        }

        fn suppress(&mut self, key: &str) {
            for _ in 0..6 {
                self.health.note_failure(key, 6, true, "");
                self.advance(3.0);
            }
            assert!(self.health.is_suppressed(key));
        }
    }

    fn kinds(plan: &[Route]) -> Vec<&str> {
        plan.iter().map(|route| route.kind.as_str()).collect()
    }

    fn tunnels() -> Vec<&'static str> {
        let count = TUNNEL_HOSTS.len().min(TUNNELS_PER_CONNECTION);
        vec![KIND_TUNNEL; count]
    }

    #[test]
    fn dc2_goes_relay_fronts_tunnel_then_country_socks() {
        let fixture = Fixture::new();
        let plan = build_plan(&request(2, false, "149.154.167.51"), &fixture.health);
        let mut expected = vec![KIND_RELAY, KIND_FRONT, KIND_FRONT, KIND_FRONT];
        expected.extend(tunnels());
        expected.push(KIND_UPSTREAM);
        assert_eq!(kinds(&plan), expected);
        let relay = &plan[0];
        assert_eq!(relay.connect_host, "149.154.167.220");
        assert_eq!(relay.sni, "kws2.web.telegram.org");
        assert!(plan[1].sni.starts_with("kws2."));
        assert_eq!(plan[4].path, "/apiws?dst=149.154.167.51&dc=2");
    }

    #[test]
    fn media_uses_minus_one_relay_domain() {
        let fixture = Fixture::new();
        let plan = build_plan(&request(4, true, "149.154.164.250"), &fixture.health);
        assert_eq!(plan[0].sni, "kws4-1.web.telegram.org");
    }

    #[test]
    fn media_fronts_land_on_regular_cluster_and_the_rest_on_media() {
        let fixture = Fixture::new();
        let plan = build_plan(&request(2, true, "149.154.167.222"), &fixture.health);
        for route in &plan {
            let expected = if route.kind == KIND_USER_DOMAIN || route.kind == KIND_FRONT {
                CLUSTER_REGULAR
            } else {
                CLUSTER_MEDIA
            };
            assert_eq!(route.cluster, expected, "kind={}", route.kind);
        }
        let plain = build_plan(&request(2, false, "149.154.167.51"), &fixture.health);
        assert!(plain.iter().all(|route| route.cluster == CLUSTER_REGULAR));
    }

    #[test]
    fn key_living_on_regular_cluster_puts_fronts_before_relay() {
        let fixture = Fixture::new();
        let mut media_request = request(2, true, "149.154.167.222");
        media_request.key_cluster = CLUSTER_REGULAR.into();
        let plan = build_plan(&media_request, &fixture.health);
        // Запасные пути (воркеры, SOCKS) ради кластера вперёд не встают.
        let mut expected = vec![KIND_FRONT, KIND_FRONT, KIND_FRONT, KIND_RELAY];
        expected.extend(tunnels());
        expected.push(KIND_UPSTREAM);
        assert_eq!(kinds(&plan), expected);
        let mut home_request = request(2, true, "149.154.167.222");
        home_request.key_cluster = CLUSTER_MEDIA.into();
        let media_home = build_plan(&home_request, &fixture.health);
        assert_eq!(media_home[0].kind, KIND_RELAY);
    }

    #[test]
    fn dc1_dc3_dc5_use_relay_on_their_own_ingress() {
        let fixture = Fixture::new();
        for (dc, address) in [
            (1, "149.154.174.100"),
            (3, "149.154.174.100"),
            (5, "149.154.170.100"),
        ] {
            let plan = build_plan(&plain_request(dc, false, "149.154.175.50"), &fixture.health);
            let mut expected = vec![KIND_RELAY, KIND_FRONT, KIND_FRONT, KIND_FRONT];
            expected.extend(tunnels());
            expected.push(KIND_DIRECT);
            assert_eq!(kinds(&plan), expected, "dc={dc}");
            assert_eq!(
                (plan[0].connect_host.as_str(), plan[0].sni.as_str()),
                (address, format!("kws{dc}.web.telegram.org").as_str())
            );
        }
    }

    #[test]
    fn dc203_goes_through_fronts_then_tunnel_and_direct_before_front_floor() {
        let mut fixture = Fixture::new();
        let plan = build_plan(&request(203, false, "91.105.192.100"), &fixture.health);
        let mut expected = vec![KIND_FRONT, KIND_FRONT, KIND_FRONT];
        expected.extend(tunnels());
        expected.push(KIND_UPSTREAM);
        assert_eq!(kinds(&plan), expected);
        assert!(plan[0].sni.starts_with("kws203.") && plan[0].sni.ends_with(".co.uk"));
        // Без внешнего SOCKS и со всем WSS на паузе — прямой TCP, а за ним снова фронты.
        fixture.suppress(&cdn_key(203));
        for host in TUNNEL_HOSTS {
            fixture.suppress(host);
        }
        let plan = build_plan(
            &PlanInput {
                upstream: UpstreamProxyConfig::default(),
                ..request(203, false, "91.105.192.100")
            },
            &fixture.health,
        );
        assert_eq!(
            kinds(&plan),
            vec![KIND_DIRECT, KIND_FRONT, KIND_FRONT, KIND_FRONT]
        );
    }

    #[test]
    fn tunnels_are_tried_in_a_circle_from_this_install_start() {
        let mut fixture = Fixture::new();
        let hosts = [
            "a.workers.dev",
            "b.workers.dev",
            "c.workers.dev",
            "d.workers.dev",
        ];
        let (clock, boxed) = clock_pair(1000.0);
        let mut health = RouteHealth::new(
            None,
            boxed,
            Box::new(|| 5000.0),
            CDN_FRONTS.len(),
            Some(2 + 4 * 10),
        );
        let _ = clock;
        assert!(health.note_failure(&cdn_key(203), 1, true, ""));
        let http_request = request(203, false, "91.105.192.100");
        let plan = build_plan_with_tunnels(&http_request, &health, &hosts);
        let sni: Vec<String> = plan[..plan.len() - 1]
            .iter()
            .map(|route| route.sni.clone())
            .collect();
        assert_eq!(sni, vec!["c.workers.dev", "d.workers.dev", "a.workers.dev"]);
        assert_eq!(
            plan[..plan.len() - 1]
                .iter()
                .map(|route| route.health_key.clone())
                .collect::<Vec<_>>(),
            sni
        );
        assert_eq!(plan[plan.len() - 1].kind, KIND_UPSTREAM);

        // Воркер с исчерпанным лимитом пропускается, его место занимает следующий.
        assert!(health.note_failure("c.workers.dev", 1, true, ""));
        let plan = build_plan_with_tunnels(&http_request, &health, &hosts);
        let sni: Vec<String> = plan[..plan.len() - 1]
            .iter()
            .map(|route| route.sni.clone())
            .collect();
        assert_eq!(sni, vec!["d.workers.dev", "a.workers.dev", "b.workers.dev"]);
        let _ = &mut fixture;
    }

    #[test]
    fn every_tunnel_suppressed_leaves_dc203_on_fronts() {
        let mut fixture = Fixture::new();
        let hosts = ["a.workers.dev", "b.workers.dev"];
        for host in hosts {
            fixture.suppress(host);
        }
        let plan = build_plan_with_tunnels(
            &request(203, false, "91.105.192.100"),
            &fixture.health,
            &hosts,
        );
        // Воркеры исчерпали суточный лимит — DC203 всё равно идёт через фронты.
        assert_eq!(
            kinds(&plan),
            vec![KIND_FRONT, KIND_FRONT, KIND_FRONT, KIND_UPSTREAM]
        );
    }

    #[test]
    fn manual_always_server_takes_all_traffic() {
        let fixture = Fixture::new();
        let manual = UpstreamProxyConfig {
            enabled: true,
            host: "5.6.7.8".into(),
            port: 1080,
            mode: "always".into(),
            ..UpstreamProxyConfig::default()
        };
        let plan = build_plan(
            &PlanInput {
                upstream: manual,
                ..request(2, false, "149.154.167.51")
            },
            &fixture.health,
        );
        assert_eq!(kinds(&plan), vec![KIND_UPSTREAM]);
    }

    #[test]
    fn country_preset_toggle_all_tcp_through_socks_is_honoured() {
        let fixture = Fixture::new();
        let preset_always = UpstreamProxyConfig {
            enabled: true,
            host: "1.2.3.4".into(),
            port: 1080,
            mode: "always".into(),
            preset_id: "ee".into(),
            ..UpstreamProxyConfig::default()
        };
        let plan = build_plan(
            &PlanInput {
                upstream: preset_always,
                ..request(2, false, "149.154.167.51")
            },
            &fixture.health,
        );
        assert_eq!(kinds(&plan), vec![KIND_UPSTREAM]);
    }

    #[test]
    fn user_domain_and_worker_come_before_builtin_fronts() {
        let mut fixture = Fixture::new();
        let mut domains: Vec<String> = vec!["my.example.com".into()];
        domains.extend(CDN_FRONTS.iter().map(|front| front.domain.to_string()));
        let cloudflare = crate::proxy::cloudflare::CloudflareFallbackConfig {
            enabled: true,
            domains,
            worker_enabled: true,
            worker_domains: vec!["w.example.dev".into()],
        };
        let base = request(1, false, "149.154.175.50");
        let plan = build_plan(
            &PlanInput {
                cloudflare: cloudflare.clone(),
                ..base.clone()
            },
            &fixture.health,
        );
        assert_eq!(
            kinds(&plan)[..4],
            [KIND_RELAY, KIND_USER_DOMAIN, KIND_USER_WORKER, KIND_FRONT]
        );
        assert_eq!(plan[1].sni, "kws1.my.example.com");
        fixture.suppress("kws1.web.telegram.org");
        let plan = build_plan(&PlanInput { cloudflare, ..base }, &fixture.health);
        assert_eq!(
            kinds(&plan)[..3],
            [KIND_USER_DOMAIN, KIND_USER_WORKER, KIND_FRONT]
        );
        assert_eq!(plan[0].sni, "kws1.my.example.com");
    }

    #[test]
    fn suppressed_relay_address_switches_to_the_other_ingress_then_dns() {
        let mut fixture = Fixture::new();
        let http_request = request(2, false, "149.154.167.51");
        fixture.suppress(&address_key("149.154.167.220"));
        let plan = build_plan(&http_request, &fixture.health);
        assert_eq!(plan[0].connect_host, "149.154.167.99");
        assert_eq!(plan[0].address_health_key, address_key("149.154.167.99"));
        assert_eq!(
            plan[0].pool_key,
            "relay:kws2.web.telegram.org@149.154.167.99"
        );
        fixture.suppress(&address_key("149.154.167.99"));
        let plan = build_plan(&http_request, &fixture.health);
        assert_eq!(plan[0].connect_host, "kws2.web.telegram.org");
        assert_eq!(plan[0].address_health_key, "");
        assert_eq!(plan[0].pool_key, "relay:kws2.web.telegram.org@dns");
    }

    #[test]
    fn all_wss_suppressed_goes_socks_then_fronts_anyway() {
        let mut fixture = Fixture::new();
        fixture.suppress("kws1.web.telegram.org");
        fixture.suppress(&cdn_key(1));
        for host in TUNNEL_HOSTS {
            fixture.suppress(host);
        }
        let plan = build_plan(&request(1, false, "149.154.175.50"), &fixture.health);
        assert_eq!(
            kinds(&plan),
            vec![KIND_UPSTREAM, KIND_FRONT, KIND_FRONT, KIND_FRONT]
        );
    }

    #[test]
    fn direct_tcp_is_last_step_and_pauses_after_one_failure() {
        let mut fixture = Fixture::new();
        fixture.suppress("kws1.web.telegram.org");
        fixture.suppress(&cdn_key(1));
        for host in TUNNEL_HOSTS {
            fixture.suppress(host);
        }
        let http_request = plain_request(1, false, "149.154.175.50");
        let plan = build_plan(&http_request, &fixture.health);
        assert_eq!(
            kinds(&plan),
            vec![KIND_DIRECT, KIND_FRONT, KIND_FRONT, KIND_FRONT]
        );
        let direct = &plan[0];
        assert_eq!(
            (direct.target_host.as_str(), direct.health_key.as_str()),
            ("149.154.175.50", direct_key(1).as_str())
        );
        assert_eq!(
            (direct.health_threshold, direct.proof_bytes),
            (1, 32 * 1024)
        );
        // Одной неудачи хватает: следующее соединение идёт только на фронты.
        assert!(fixture
            .health
            .note_failure(&direct.health_key, direct.health_threshold, true, ""));
        assert_eq!(
            kinds(&build_plan(&http_request, &fixture.health)),
            vec![KIND_FRONT, KIND_FRONT, KIND_FRONT]
        );
        // Пауза кончилась — прямой путь снова в плане.
        fixture.advance(121.0);
        assert_eq!(
            kinds(&build_plan(&http_request, &fixture.health))
                .last()
                .copied(),
            Some(KIND_DIRECT)
        );
    }

    #[test]
    fn paused_direct_tcp_drops_out_of_a_working_wss_plan() {
        let mut fixture = Fixture::new();
        let http_request = plain_request(2, false, "149.154.167.51");
        assert_eq!(
            kinds(&build_plan(&http_request, &fixture.health))
                .last()
                .copied(),
            Some(KIND_DIRECT)
        );
        assert!(fixture.health.note_failure(&direct_key(2), 1, true, ""));
        let mut expected = vec![KIND_RELAY, KIND_FRONT, KIND_FRONT, KIND_FRONT];
        expected.extend(tunnels());
        assert_eq!(kinds(&build_plan(&http_request, &fixture.health)), expected);
    }

    #[test]
    fn direct_tcp_waits_for_country_socks_and_media_shares_the_dc_key() {
        let fixture = Fixture::new();
        let plan = build_plan(&plain_request(2, true, "149.154.167.222"), &fixture.health);
        assert_eq!(plan[plan.len() - 1].health_key, direct_key(2));
        let with_socks = build_plan(&request(2, false, "149.154.167.51"), &fixture.health);
        assert!(!kinds(&with_socks).contains(&KIND_DIRECT));
    }

    #[test]
    fn dc_without_wss_keeps_direct_tcp_even_when_paused() {
        let mut fixture = Fixture::new();
        assert!(fixture.health.note_failure(&direct_key(7), 1, true, ""));
        let plan = build_plan(&plain_request(7, false, "149.154.175.50"), &fixture.health);
        assert_eq!(kinds(&plan), vec![KIND_DIRECT]);
    }

    #[test]
    fn key_clusters_in_plan_tests_still_work() {
        let (clock, boxed) = clock_pair(1000.0);
        let mut keys = KeyClusters::new(boxed, 2);
        keys.note_ok(b"k1k1k1k1", CLUSTER_MEDIA);
        let _ = clock;
        assert_eq!(keys.home(b"k1k1k1k1"), CLUSTER_MEDIA);
    }

    #[test]
    fn route_describe_and_labels_match_python() {
        let mut route = Route::new(KIND_RELAY);
        route.sni = "kws2.web.telegram.org".into();
        assert_eq!(route.describe(), "wss://kws2.web.telegram.org/apiws");
        assert_eq!(route.label(), "WSS");
        route.connect_host = "149.154.167.220".into();
        assert_eq!(
            route.describe(),
            "wss://kws2.web.telegram.org/apiws via 149.154.167.220"
        );
        let mut direct = Route::new(KIND_DIRECT);
        direct.target_host = "149.154.167.51".into();
        direct.target_port = 443;
        assert_eq!(direct.describe(), "149.154.167.51:443");
        assert_eq!(direct.label(), "TCP");
        assert_eq!(route_label(KIND_UPSTREAM), "внешний SOCKS5");
    }
}
