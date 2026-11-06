use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tg_mtproto::{generate_secret, parse_secret, proxy_link};
use crate::ws_api::{now_epoch_s, state_dir_path, ws_error};

pub const CONFIG_FILE_NAME: &str = "tg_proxy.json";
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 1443;

#[derive(Clone)]
pub struct TgState {
    state_dir: String,
    tunnel: std::sync::Arc<crate::tg_mtproto::Tunnel>,
}

impl FromRef<crate::App> for TgState {
    fn from_ref(app: &crate::App) -> Self {
        app.tg.clone()
    }
}

impl TgState {
    #[must_use]
    pub fn production() -> Self {
        Self::new(state_dir_path())
    }

    #[must_use]
    pub fn new(state_dir: String) -> Self {
        Self {
            state_dir,
            tunnel: std::sync::Arc::new(crate::tg_mtproto::Tunnel::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TgProxyConfig {
    pub host: String,
    pub port: u16,
    pub secret: String,
    #[serde(default)]
    pub domain: String,
    pub saved_at: i64,
}

impl TgProxyConfig {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        if parse_secret(&self.secret).is_none() {
            if self.domain.is_empty() && self.secret.contains('.') {
                self.domain = self.secret.clone();
            }
            self.secret = generate_secret();
        }
        self
    }
}

#[must_use]
pub fn config_path(state_dir: &str) -> String {
    format!("{state_dir}/{CONFIG_FILE_NAME}")
}

#[must_use]
pub fn load_config(path: &str) -> Option<TgProxyConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_config(path: &str, config: &TgProxyConfig) -> Result<(), String> {
    let text = serde_json::to_string_pretty(config)
        .map_err(|error| format!("конфиг Telegram не сериализовался: {error}"))?;
    write_private(path, &text).map_err(|error| format!("не удалось записать {path}: {error}"))
}

fn write_private(path: &str, text: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)
    }
}

fn ensure_config(state_dir: &str) -> (TgProxyConfig, bool) {
    let path = config_path(state_dir);
    let loaded = load_config(&path);
    let existed = loaded.is_some();
    let config = loaded
        .map(TgProxyConfig::normalized)
        .unwrap_or_else(|| TgProxyConfig {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            secret: generate_secret(),
            domain: String::new(),
            saved_at: now_epoch_s(),
        });
    let _ = save_config(&path, &config);
    (config, existed)
}

pub async fn proxy(State(state): State<TgState>) -> Json<Value> {
    let (config, existed) = ensure_config(&state.state_dir);
    let running = state.tunnel.running().await;
    let stats = state.tunnel.stats();
    let (host, port) = match &running {
        Some((host, port, _, _)) => (host.clone(), *port),
        None => (config.host.clone(), config.port),
    };
    let order = std::sync::atomic::Ordering::Relaxed;
    Json(json!({
        "configured": existed,
        "host": host,
        "port": port,
        "running": running.is_some(),
        "front": if config.domain.is_empty() { running.as_ref().map(|item| item.2.clone()) } else { Some(config.domain.clone()) },
        "started_at": running.as_ref().map(|item| item.3),
        "connections": stats.connections.load(order),
        "active": stats.active.load(order),
        "bytes_up": stats.bytes_up.load(order),
        "bytes_down": stats.bytes_down.load(order),
        "last_front": stats.last_front.lock().await.clone(),
        "last_error": stats.last_error.lock().await.clone(),
        "link": proxy_link(&host, port, &config.secret),
        "saved_at": config.saved_at,
    }))
}

#[derive(Deserialize)]
pub struct TgProxyStartRequest {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub domain: String,
}

pub async fn proxy_start(
    State(state): State<TgState>,
    body: Result<Json<TgProxyStartRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) =
        body.map_err(|rejection| ws_error(StatusCode::BAD_REQUEST, rejection.to_string()))?;
    let host = if request.host.trim().is_empty() {
        DEFAULT_HOST.to_string()
    } else {
        request.host.trim().to_string()
    };
    let domain = request.domain.trim().to_string();
    if !domain.is_empty() && !is_valid_domain(&domain) {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "домен воркера выглядит неверно".to_string(),
        ));
    }
    let (config, _) = ensure_config(&state.state_dir);
    let port = if request.port == 0 { config.port } else { request.port };
    let port = if port == 0 { DEFAULT_PORT } else { port };
    let worker = (!domain.is_empty()).then(|| domain.clone());

    let info = state
        .tunnel
        .start(&host, port, &config.secret, worker)
        .await
        .map_err(|error| {
            let status = if error.contains("уже запущен") {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            ws_error(status, error)
        })?;

    let saved = TgProxyConfig {
        host: info.host.clone(),
        port: info.port,
        secret: config.secret.clone(),
        domain,
        saved_at: now_epoch_s(),
    };
    save_config(&config_path(&state.state_dir), &saved)
        .map_err(|error| ws_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;

    Ok(Json(json!({
        "ok": true,
        "running": true,
        "host": info.host,
        "port": info.port,
        "front": info.front,
        "link": proxy_link(&info.host, info.port, &config.secret),
    })))
}

pub async fn proxy_stop(State(state): State<TgState>) -> Json<Value> {
    let stopped = state.tunnel.stop().await;
    Json(json!({ "ok": true, "running": false, "stopped": stopped }))
}

pub async fn proxy_worker() -> Json<Value> {
    Json(json!({
        "code": primecore_telegram::runtime::get_cloudflare_worker_code(),
        "dns": primecore_telegram::runtime::get_cloudflare_dns_records_text(),
        "path": primecore_telegram::proxy::route_catalog::WSS_PATH,
    }))
}

fn is_valid_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|symbol| symbol.is_ascii_alphanumeric() || symbol == '-')
    }) && labels.last().is_some_and(|tld| tld.len() >= 2)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn tmpdir(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "primecore-server-tg-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("часы идут")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir создан");
        dir.to_string_lossy().into_owned()
    }

    fn router(state_dir: &str) -> axum::Router {
        crate::router(crate::App {
            tg: TgState::new(state_dir.to_string()),
            ..crate::App::test_defaults()
        })
    }

    async fn get(router: axum::Router, uri: &str) -> (StatusCode, Value) {
        let response = router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post_json(router: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[test]
    fn config_roundtrip_through_file() {
        let dir = tmpdir("roundtrip");
        let path = config_path(&dir);
        assert!(load_config(&path).is_none());
        let config = TgProxyConfig {
            host: "127.0.0.1".to_string(),
            port: 1443,
            secret: generate_secret(),
            domain: "example.com".to_string(),
            saved_at: 1739990000,
        };
        save_config(&path, &config).expect("конфиг сохранён");
        assert_eq!(load_config(&path).expect("конфиг прочитан"), config);
    }

    #[test]
    fn legacy_config_moves_domain_out_of_secret() {
        let legacy: TgProxyConfig =
            serde_json::from_str(r#"{"host":"127.0.0.1","port":1353,"secret":"my.example.com","saved_at":1}"#)
                .expect("старый формат читается");
        let config = legacy.normalized();
        assert_eq!(config.domain, "my.example.com");
        assert!(parse_secret(&config.secret).is_some());
    }

    #[test]
    fn domain_check_accepts_real_domains() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("my-worker.example.co.uk"));
        assert!(!is_valid_domain("example"));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("пример.рф"));
    }

    #[tokio::test]
    async fn link_is_stable_mtproto_link_before_start() {
        let dir = tmpdir("empty");
        let (_, first) = get(router(&dir), "/api/tg/proxy").await;
        assert_eq!(first["running"], false);
        let link = first["link"].as_str().unwrap_or_default().to_string();
        assert!(link.starts_with("tg://proxy?server=127.0.0.1&port=1443&secret=dd"), "{link}");
        let (_, second) = get(router(&dir), "/api/tg/proxy").await;
        assert_eq!(second["link"], link.as_str());
    }

    #[tokio::test]
    async fn start_raises_listener_and_stop_closes_it() {
        let dir = tmpdir("start");
        let app = router(&dir);
        let free_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("свободный порт")
            .port();
        let (status, answer) = post_json(
            app.clone(),
            "/api/tg/proxy/start",
            &format!(r#"{{"host":"127.0.0.1","port":{free_port}}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["running"], true);
        let link = answer["link"].as_str().unwrap_or_default();
        assert!(link.starts_with("tg://proxy?"), "{link}");

        let (_, answer) = get(app.clone(), "/api/tg/proxy").await;
        assert_eq!(answer["configured"], true);
        assert_eq!(answer["running"], true);

        let (status, answer) = post_json(app.clone(), "/api/tg/proxy/stop", "{}").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["stopped"], true);
    }

    #[tokio::test]
    async fn start_rejects_bad_domain() {
        let dir = tmpdir("bad-domain");
        let (status, answer) = post_json(
            router(&dir),
            "/api/tg/proxy/start",
            r#"{"host":"127.0.0.1","port":0,"domain":"не-домен"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some_and(|e| !e.is_empty()));
    }

    #[tokio::test]
    async fn worker_endpoint_returns_code_and_dns() {
        let dir = tmpdir("worker");
        let (status, answer) = get(router(&dir), "/api/tg/proxy/worker").await;
        assert_eq!(status, StatusCode::OK);
        let code = answer["code"].as_str().unwrap_or_default();
        assert!(code.contains("cloudflare:sockets"), "{code}");
        assert_eq!(answer["path"], "/apiws");
    }
}
