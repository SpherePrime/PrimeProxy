//! Конфигурация локального прокси Telegram: сохранение и чтение настроек.
//!
//! Python-эталон (`src/telegram_proxy`) поднимает полноценный локальный
//! прокси: SOCKS5/MTProxy на входе, WSS-релеи и внешние SOCKS5 на выходе
//! (`manager.py`, `proxy/socks5.py`, `proxy/mtproxy.py`). Rust-крейт
//! [`primecore-telegram`] переносит чистые решения той логики, но сетевую
//! часть (живые сокеты) держит у вызывающего кода — живой запуск прокси
//! из HTTP-двери пока не подключён.
//!
//! Эти ручки — честная заготовка контракта: `POST /api/tg/proxy/start`
//! сохраняет конфиг в каталог состояния (`tg_proxy.json`, права 0600 —
//! в файле лежит секрет MTProxy) и отвечает `ok`; `GET /api/tg/proxy`
//! показывает, что сохранено. Реальный подъём прокси — следующий шаг,
//! поле `running` пока всегда `false`.

use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::ws_api::{now_epoch_s, state_dir_path, ws_error};

/// Имя файла конфигурации в каталоге состояния.
pub const CONFIG_FILE_NAME: &str = "tg_proxy.json";

// ─────────────────────────── состояние ─────────────────────────────────

/// Состояние вкладки Telegram: каталог состояния (файл конфига лежит там).
#[derive(Clone)]
pub struct TgState {
    state_dir: String,
    tunnel: std::sync::Arc<crate::tg_tunnel::Tunnel>,
}

impl FromRef<crate::App> for TgState {
    fn from_ref(app: &crate::App) -> Self {
        app.tg.clone()
    }
}

impl TgState {
    /// Состояние живого сервера: каталог состояния из окружения.
    #[must_use]
    pub fn production() -> Self {
        Self::new(state_dir_path())
    }

    /// Состояние с явным каталогом (тесты подставляют tmpdir).
    #[must_use]
    pub fn new(state_dir: String) -> Self {
        Self {
            state_dir,
            tunnel: std::sync::Arc::new(crate::tg_tunnel::Tunnel::new()),
        }
    }
}

// ─────────────────────────── конфиг ────────────────────────────────────

/// Сохранённая конфигурация прокси Telegram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TgProxyConfig {
    /// Адрес локального прокси (по умолчанию `127.0.0.1`).
    pub host: String,
    /// Порт локального прокси.
    pub port: u16,
    /// Секрет MTProxy.
    pub secret: String,
    /// Момент сохранения (unix-время, секунды).
    pub saved_at: i64,
}

/// Путь файла конфигурации: `tg_proxy.json` внутри каталога состояния.
#[must_use]
pub fn config_path(state_dir: &str) -> String {
    format!("{state_dir}/{CONFIG_FILE_NAME}")
}

/// Читает конфиг; файла нет или он не разбирается — `None`.
#[must_use]
pub fn load_config(path: &str) -> Option<TgProxyConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Сохраняет конфиг (каталог создаётся; файл с секретом — только для
/// владельца, 0600).
///
/// # Errors
/// Каталог не создался или файл не записался — текст.
pub fn save_config(path: &str, config: &TgProxyConfig) -> Result<(), String> {
    let text = serde_json::to_string_pretty(config)
        .map_err(|error| format!("конфиг Telegram не сериализовался: {error}"))?;
    write_private(path, &text).map_err(|error| format!("не удалось записать {path}: {error}"))
}

/// Запись файла с правами 0600 (Unix); на прочих платформах — обычная запись.
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

// ─────────────────────────── endpoints ─────────────────────────────────

/// Состояние прокси Telegram: `GET /api/tg/proxy`.
///
/// Отдаёт сохранённый конфиг, живое состояние туннеля, счётчики и готовую
/// ссылку `tg://socks` — по ней Telegram Desktop подключается в один клик.
pub async fn proxy(State(state): State<TgState>) -> Json<Value> {
    let config = load_config(&config_path(&state.state_dir));
    let running = state.tunnel.running().await;
    let stats = state.tunnel.stats();
    let (host, port) = match &running {
        Some((host, port, _, _)) => (host.clone(), *port),
        None => match &config {
            Some(config) => (config.host.clone(), config.port),
            None => (DEFAULT_HOST.to_string(), DEFAULT_PORT),
        },
    };
    Json(json!({
        "configured": config.is_some(),
        "host": host,
        "port": port,
        "running": running.is_some(),
        "front": running.as_ref().map(|item| item.2.clone()),
        "started_at": running.as_ref().map(|item| item.3),
        "connections": stats.connections.load(std::sync::atomic::Ordering::Relaxed),
        "active": stats.active.load(std::sync::atomic::Ordering::Relaxed),
        "bytes_up": stats.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
        "bytes_down": stats.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
        "last_front": stats.last_front.lock().await.clone(),
        "last_error": stats.last_error.lock().await.clone(),
        "link": socks_link(&host, port),
        "saved_at": config.as_ref().map(|item| item.saved_at),
    }))
}

/// Адрес и порт локального прокси по умолчанию.
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Порт по умолчанию: свободный и привычный для локального SOCKS5.
pub const DEFAULT_PORT: u16 = 1353;

/// Ссылка для Telegram Desktop: `tg://socks?server=…&port=…`.
#[must_use]
pub fn socks_link(host: &str, port: u16) -> String {
    format!("tg://socks?server={host}&port={port}")
}

/// Тело `POST /api/tg/proxy/start`.
#[derive(Deserialize)]
pub struct TgProxyStartRequest {
    /// Адрес локального прокси (по умолчанию `127.0.0.1`).
    #[serde(default)]
    pub host: String,
    /// Порт локального прокси (по умолчанию 1353).
    #[serde(default)]
    pub port: u16,
    /// Свой домен Cloudflare с воркером; пусто — встроенные фронты.
    #[serde(default)]
    pub domain: String,
}

/// Запуск прокси: `POST /api/tg/proxy/start`.
///
/// ```json
/// {"host":"127.0.0.1","port":1353,"domain":"example.com"}
/// ```
///
/// Ответ: `200 {"ok":true,"running":true,"link":"tg://socks?…"}`.
/// `400` — плохой адрес или порт, `409` — прокси уже запущен,
/// `500` — порт занят или слушатель не поднялся.
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
    let port = if request.port == 0 {
        DEFAULT_PORT
    } else {
        request.port
    };
    let domain = request.domain.trim().to_string();
    if !domain.is_empty() && !is_valid_domain(&domain) {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "домен воркера выглядит неверно".to_string(),
        ));
    }
    let domain = if domain.is_empty() { None } else { Some(domain) };

    let info = state
        .tunnel
        .start(&host, port, domain.clone())
        .await
        .map_err(|error| {
            let status = if error.contains("уже запущен") {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            ws_error(status, error)
        })?;

    // Конфиг сохраняем после успешного старта: он же подсказка для автозапуска.
    let config = TgProxyConfig {
        host: info.host.clone(),
        port: info.port,
        secret: domain.clone().unwrap_or_default(),
        saved_at: now_epoch_s(),
    };
    let path = config_path(&state.state_dir);
    save_config(&path, &config).map_err(|error| ws_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;

    Ok(Json(json!({
        "ok": true,
        "running": true,
        "host": info.host,
        "port": info.port,
        "front": info.front,
        "link": socks_link(&info.host, info.port),
    })))
}

/// Остановка прокси: `POST /api/tg/proxy/stop`.
pub async fn proxy_stop(State(state): State<TgState>) -> Json<Value> {
    let stopped = state.tunnel.stop().await;
    Json(json!({ "ok": true, "running": false, "stopped": stopped }))
}

/// Данные для своего воркера: `GET /api/tg/proxy/worker`.
///
/// Код воркера и DNS-записи — то, что пользователь копирует в Cloudflare,
/// чтобы поднять свой фронт вместо встроенных.
pub async fn proxy_worker() -> Json<Value> {
    Json(json!({
        "code": primecore_telegram::runtime::get_cloudflare_worker_code(),
        "dns": primecore_telegram::runtime::get_cloudflare_dns_records_text(),
        "path": primecore_telegram::proxy::route_catalog::WSS_PATH,
    }))
}

/// Домен годится для фронта: точечные метки, латиница, не односимвольный TLD.
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

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// tmpdir с уникальным именем.
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn config_roundtrip_through_file() {
        let dir = tmpdir("roundtrip");
        let path = config_path(&dir);
        assert!(load_config(&path).is_none(), "конфига ещё нет");
        let config = TgProxyConfig {
            host: "127.0.0.1".to_string(),
            port: 1353,
            secret: "example.com".to_string(),
            saved_at: 1739990000,
        };
        save_config(&path, &config).expect("конфиг сохранён");
        let loaded = load_config(&path).expect("конфиг прочитан");
        assert_eq!(loaded, config);
    }

    #[test]
    fn config_file_is_owner_only() {
        let dir = tmpdir("permissions");
        let path = config_path(&dir);
        let config = TgProxyConfig {
            host: "127.0.0.1".to_string(),
            port: 1353,
            secret: "секрет".to_string(),
            saved_at: 0,
        };
        save_config(&path, &config).expect("конфиг сохранён");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("файл есть")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "секрет читает только владелец");
        }
    }

    #[test]
    fn link_is_ready_for_telegram() {
        assert_eq!(
            socks_link("127.0.0.1", 1353),
            "tg://socks?server=127.0.0.1&port=1353"
        );
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
    async fn proxy_reported_unconfigured_without_file() {
        let dir = tmpdir("empty");
        let (_, answer) = get(router(&dir), "/api/tg/proxy").await;
        assert_eq!(answer["configured"], false);
        assert_eq!(answer["running"], false);
        // Ссылка есть всегда: она нужна интерфейсу ещё до запуска.
        assert_eq!(answer["link"], "tg://socks?server=127.0.0.1&port=1353");
    }

    #[tokio::test]
    async fn start_raises_listener_and_stop_closes_it() {
        let dir = tmpdir("start");
        // Роутер один на весь тест: состояние туннеля живёт в TgState.
        let app = router(&dir);
        // Порт 0 займёт система: тест не зависит от занятости 1353.
        let (status, answer) = post_json(
            app.clone(),
            "/api/tg/proxy/start",
            r#"{"host":"127.0.0.1","port":0}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["running"], true);
        let link = answer["link"].as_str().unwrap_or_default();
        assert!(link.starts_with("tg://socks?"), "{link}");
        // Порт в ссылке — настоящий, а не запрошенный ноль.
        assert!(!link.ends_with("port=0"), "{link}");

        let (_, answer) = get(app.clone(), "/api/tg/proxy").await;
        assert_eq!(answer["configured"], true);
        assert_eq!(answer["running"], true);

        let (status, answer) = post_json(app.clone(), "/api/tg/proxy/stop", "{}").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["running"], false);
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
        assert!(answer["dns"].as_str().is_some_and(|it| !it.is_empty()));
        assert_eq!(answer["path"], "/apiws");
    }
}
