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
        Self { state_dir }
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
/// ```json
/// {"configured":true,"host":"127.0.0.1","port":1353,"running":false}
/// ```
///
/// Конфиг не сохранялся: `{"configured":false,"host":"","port":0,"running":false}`.
/// `running` — заготовка: живой запуск прокси ещё не подключён, поэтому
/// всегда `false`.
pub async fn proxy(State(state): State<TgState>) -> Json<Value> {
    let config = load_config(&config_path(&state.state_dir));
    Json(match config {
        Some(config) => json!({
            "configured": true,
            "host": config.host,
            "port": config.port,
            "running": false,
        }),
        None => json!({
            "configured": false,
            "host": "",
            "port": 0,
            "running": false,
        }),
    })
}

/// Тело `POST /api/tg/proxy/start`.
#[derive(Deserialize)]
pub struct TgProxyStartRequest {
    /// Адрес локального прокси.
    pub host: String,
    /// Порт локального прокси.
    pub port: u16,
    /// Секрет MTProxy.
    pub secret: String,
}

/// Сохранение конфига прокси: `POST /api/tg/proxy/start`.
///
/// ```json
/// {"host":"127.0.0.1","port":1353,"secret":"dd000000…"}
/// ```
///
/// Ответ: `200 {"ok":true,"note":"заготовка","configured":true}` — конфиг
/// сохранён в каталог состояния, реальный запуск прокси пока не подключён;
/// `400 {"error":"…"}` на пустом адресе/секрете.
pub async fn proxy_start(
    State(state): State<TgState>,
    body: Result<Json<TgProxyStartRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) =
        body.map_err(|rejection| ws_error(StatusCode::BAD_REQUEST, rejection.to_string()))?;
    let host = request.host.trim().to_string();
    if host.is_empty() {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "адрес прокси пуст".to_string(),
        ));
    }
    if request.port == 0 {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "порт прокси должен быть от 1 до 65535".to_string(),
        ));
    }
    let secret = request.secret.trim().to_string();
    if secret.is_empty() {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "секрет MTProxy пуст".to_string(),
        ));
    }
    let config = TgProxyConfig {
        host,
        port: request.port,
        secret,
        saved_at: now_epoch_s(),
    };
    let path = config_path(&state.state_dir);
    save_config(&path, &config)
        .map_err(|error| ws_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(json!({
        "ok": true,
        "note": "заготовка",
        "configured": true,
    })))
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
            secret: "dd1a2b3c4d5e6f708192a2b3c4d5e6f708192a2b3c4d5e6f708192a2b3c4d5e6f".to_string(),
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

    #[tokio::test]
    async fn proxy_reported_unconfigured_without_file() {
        let dir = tmpdir("empty");
        let (_, answer) = get(router(&dir), "/api/tg/proxy").await;
        assert_eq!(answer["configured"], false);
        assert_eq!(answer["running"], false);
    }

    #[tokio::test]
    async fn start_saves_config_and_readback() {
        let dir = tmpdir("start");
        let (status, answer) = post_json(
            router(&dir),
            "/api/tg/proxy/start",
            r#"{"host":"127.0.0.1","port":1353,"secret":"ab"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["note"], "заготовка");
        let (_, answer) = get(router(&dir), "/api/tg/proxy").await;
        assert_eq!(answer["configured"], true);
        assert_eq!(answer["host"], "127.0.0.1");
        assert_eq!(answer["port"], 1353);
        assert_eq!(answer["running"], false);
        // Секрет в JSON-ответ не отдаётся.
        assert!(answer.get("secret").is_none());
    }

    #[tokio::test]
    async fn start_rejects_empty_host_and_secret() {
        let dir = tmpdir("reject");
        let (status, answer) = post_json(
            router(&dir),
            "/api/tg/proxy/start",
            r#"{"host":"  ","port":1353,"secret":"ab"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some_and(|e| !e.is_empty()));
        let (status, answer) = post_json(
            router(&dir),
            "/api/tg/proxy/start",
            r#"{"host":"127.0.0.1","port":1353,"secret":" "}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some_and(|e| !e.is_empty()));
        assert!(
            load_config(&config_path(&dir)).is_none(),
            "ничего не сохранилось"
        );
    }
}
