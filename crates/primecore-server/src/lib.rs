//! HTTP-дверь Rust-ядра для Linux/Docker (axum). Чистая логика крейтов
//! primecore-* выставляется наружу без стороннего состояния: сравнение
//! версий, сводка hosts, применение заплатки, проверка списка выпуска.
//! Живой чек выпуска (Forgejo+зеркала) идёт через resolver-гонку — HTTP
//! руки ставит reqwest::blocking внутри tokio::task::spawn_blocking.

use std::sync::Arc;
use std::time::Duration;

mod dns_api;
mod ws_api;

use axum::extract::rejection::JsonRejection;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use primecore_manifest::{self as manifest, Manifest, ManifestError};
use primecore_release as release;
use primecore_versions as versions;

const DEFAULT_PORT: u16 = 7290;

#[derive(Clone)]
struct App {
    ws: ws_api::WsState,
}

// ───────────────────────── запросы/ответы ────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct VersionsRequest {
    a: String,
    b: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct HostsPreviewRequest {
    content: String,
    rows: Vec<Vec<String>>,
    #[serde(default)]
    allow_ipv6: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct PatchRequest {
    old_base64: String,
    patch_base64: String,
    #[serde(default)]
    expected_size: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct ManifestVerifyRequest {
    manifest_base64: String,
    signature_base64: String,
    channel: String,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    installed_version: String,
    #[serde(default)]
    allow_same: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CheckQuery {
    channel: Option<String>,
    #[serde(default)]
    installed: Option<String>,
    #[serde(default)]
    allow_same: bool,
}

// Вспомогательное: одинаковый ответ на плохие входы.
fn bad_request(code: &str, message: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "code": code, "message": message })),
    )
}

fn unprocessable(error: &ManifestError) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "code": error.code, "message": error.message })),
    )
}

fn internal_error(code: &str, message: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "code": code, "message": message })),
    )
}

fn json_reject(rejection: JsonRejection) -> (StatusCode, Json<Value>) {
    bad_request("query", rejection.to_string())
}

// ─────────────────────────── endpoints ─────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "primecore-server",
    }))
}

async fn versions_compare(
    body: Result<Json<VersionsRequest>, JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(query) = body.map_err(json_reject)?;
    let ordering = versions::compare_versions(&query.a, &query.b)
        .map_err(|error| unprocessable(&ManifestError::new("value", error.0)))?;
    Ok(Json(json!({
        "a": query.a,
        "b": query.b,
        "compare": ordering_str(ordering),
    })))
}

fn ordering_str(ordering: std::cmp::Ordering) -> &'static str {
    match ordering {
        std::cmp::Ordering::Less => "less",
        std::cmp::Ordering::Equal => "equal",
        std::cmp::Ordering::Greater => "greater",
    }
}

async fn hosts_preview(
    body: Result<Json<HostsPreviewRequest>, JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) = body.map_err(json_reject)?;
    let rows: primecore_hosts::Rows = request
        .rows
        .iter()
        .filter_map(|pair| {
            let mut cells = pair.iter();
            let domain = cells.next()?.clone();
            let ip = cells.next()?.clone();
            Some((domain, ip))
        })
        .collect();
    let input_lines: primecore_hosts::Lines = request
        .content
        .split_inclusive('\n')
        .map(str::to_string)
        .collect();
    let (without_block, removed) = primecore_hosts::remove_managed_hosts_block(&input_lines);
    let (desired, had_requested) =
        primecore_hosts::filter_desired_hosts_rows(&rows, request.allow_ipv6);
    let (kept, dropped) = primecore_hosts::drop_conflicting_foreign_rows(&without_block, &desired);
    let mut final_lines = kept.clone();
    primecore_hosts::insert_managed_hosts_block(&mut final_lines, &desired, None);
    let block_now = primecore_hosts::iter_managed_hosts_block_rows(&final_lines);
    Ok(Json(json!({
        "had_requested_rows": had_requested,
        "removed_entries": removed,
        "dropped": dropped,
        "desired": desired,
        "content": final_lines.join(""),
        "block_rows": block_now,
    })))
}

async fn patch_apply(
    body: Result<Json<PatchRequest>, JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) = body.map_err(json_reject)?;
    let old = BASE64
        .decode(request.old_base64.trim())
        .map_err(|e| bad_request("patch", format!("old не base64: {e}")))?;
    let patch = BASE64
        .decode(request.patch_base64.trim())
        .map_err(|e| bad_request("patch", format!("patch не base64: {e}")))?;
    let new = primecore_patch::apply(&old, &patch).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"code": error.code, "message": error.message})),
        )
    })?;
    if let Some(expected) = request.expected_size {
        if expected != new.len() {
            return Err(bad_request(
                "expected_size",
                format!(
                    "новый файл вышел {len}, а заявлено {expected}",
                    len = new.len()
                ),
            ));
        }
    }
    let digest = sha256_hex(&new);
    Ok(Json(json!({
        "size": new.len(),
        "sha256": digest,
    })))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let tail = hasher.finalize();
    tail.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn manifest_verify(
    body: Result<Json<ManifestVerifyRequest>, JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) = body.map_err(json_reject)?;
    let raw = BASE64
        .decode(request.manifest_base64.trim())
        .map_err(|e| bad_request("manifest", format!("манифест не base64: {e}")))?;
    let signature = BASE64
        .decode(request.signature_base64.trim())
        .map_err(|e| bad_request("manifest", format!("подпись не base64: {e}")))?;
    let product = request.product.as_deref().unwrap_or(manifest::PRODUCT);
    let manifest_data = manifest::load_signed(
        &raw,
        &signature,
        None,
        product,
        request.channel.trim(),
        request.installed_version.trim(),
        request.allow_same,
    )
    .map_err(|error| unprocessable(&error))?;
    Ok(Json(manifest_summary(&manifest_data)))
}

fn manifest_summary(data: &Manifest) -> Value {
    json!({
        "version": data.version,
        "channel": data.channel,
        "product": data.product,
        "key": data.key,
        "files": data.files.len(),
        "patches": data.patches.len(),
        "installer": data.installer.as_ref().map(|installer| json!({
            "name": installer.name,
            "size": installer.size,
            "sha256": installer.sha256,
        })),
    })
}

async fn check_latest(
    Query(query): Query<CheckQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let channel = query.channel.as_deref().unwrap_or("stable");
    let installed = query.installed.clone().unwrap_or_default();
    let channel = Arc::new(channel.trim().to_string());
    let fetch_forgejo = Arc::new({
        let channel = Arc::clone(&channel);
        move || forgejo_fetch(&channel)
    });
    let fetch_mirrors = Arc::new({
        let channel = Arc::clone(&channel);
        move || mirrors_fetch(&channel)
    });
    // Гонка resolver'а требует блокирующих рук; держим из async их в
    // отдельном потоке, как предписывает tokio.
    let lookup = tokio::task::spawn_blocking(move || {
        release::lookup_latest_release(
            &channel,
            fetch_forgejo,
            fetch_mirrors,
            release::MIRROR_FALLBACK_DELAY_SECONDS,
            release::FORGEJO_DEADLINE_SECONDS,
            release::MIRRORS_DEADLINE_SECONDS,
        )
    })
    .await
    .map_err(|e| bad_request("check", format!("фоновая задача не отработала: {e}")))?;
    let mut answer = json!({
        "ok": lookup.ok(),
        "error": lookup.error,
    });
    if let Some(release) = lookup.release.clone() {
        answer["release"] = release.clone();
    }
    if let (Some(release), false) = (lookup.release.as_ref(), installed.is_empty()) {
        if let Some(check) = check_stale(release, &installed, query.allow_same) {
            answer["stale"] = json!(check);
        }
    }
    Ok(Json(answer))
}

fn check_stale(release: &Value, installed: &str, allow_same: bool) -> Option<&'static str> {
    let latest = release
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string)?;
    let gap = versions::compare_versions(&latest, installed).ok()?;
    Some(match gap {
        std::cmp::Ordering::Less => "old",
        std::cmp::Ordering::Equal if allow_same => "same",
        std::cmp::Ordering::Equal => "same",
        std::cmp::Ordering::Greater => "newer",
    })
}

// ─────────────────────── Forgejo: живая рука ───────────────────────────

fn forgejo_fetch(channel: &str) -> Result<Value, String> {
    let selected = release::normalize_update_channel(channel);
    let client = reqwest::blocking::Client::builder()
        .user_agent("PrimeBypass-Updater/5.0")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("Forgejo клиент: {e}"))?;
    let mut candidates: Vec<Value> = Vec::new();
    let mut last_error = String::new();
    for page in 1..=release::MAX_RELEASE_PAGES {
        let url = forgejo_list_url(selected, page);
        let payload = fetch_json(&client, &url, "application/json", &mut last_error)?;
        if let Some(list) = release::candidates_from_release_list(&payload, selected) {
            candidates.extend(list);
            if !candidates.is_empty()
                || !payload
                    .as_array()
                    .map(|arr| arr.len() >= release::RELEASES_PAGE_LIMIT)
                    .unwrap_or(false)
            {
                break;
            }
        } else {
            return Err("Forgejo вернул неожиданный ответ вместо списка выпусков".to_string());
        }
    }
    if candidates.is_empty() {
        return Err(format!("нет готовых выпусков канала {selected}"));
    }
    let best = select_best(&candidates)
        .ok_or_else(|| "не удалось разобрать версии кандидатов".to_string())?;
    let url = best
        .get("sidecar_url")
        .and_then(Value::as_str)
        .expect("sidecar_url всегда есть у кандидата")
        .to_string();
    let text = fetch_text(&client, &url, "text/plain")?;
    if text.len() > release::MAX_SIDECAR_BYTES {
        return Err("Файл контрольной суммы слишком большой".to_string());
    }
    let sha256 = release::parse_sha256_sidecar(
        &text,
        best.get("file_name").and_then(Value::as_str).unwrap_or(""),
    )?;
    let mut answer = best.clone();
    answer["sha256"] = json!(sha256);
    answer["source"] = json!(release::FORGEJO_SOURCE);
    answer["verify_ssl"] = json!(true);
    let history: Vec<Value> = candidates.iter().map(release::history_entry).collect();
    answer["history"] = json!(history);
    if let Some(object) = answer.as_object_mut() {
        object.remove("sidecar_url");
    }
    Ok(answer)
}

fn forgejo_list_url(_channel: &str, page: usize) -> String {
    let repository = release::FORGEJO_REPOSITORY;
    format!(
        "https://{}/api/v1/repos/{repository}/releases?limit={}&page={page}",
        release::FORGEJO_HOST,
        release::RELEASES_PAGE_LIMIT
    )
}

fn select_best(candidates: &[Value]) -> Option<Value> {
    let mut best: Option<(Vec<u64>, Value)> = None;
    for candidate in candidates {
        let version = candidate.get("version")?.as_str()?;
        let key = primecore_versions::version_key(version).ok()?;
        let better = match &best {
            None => true,
            Some((best_key, _)) => key > *best_key,
        };
        if better {
            best = Some((key, candidate.clone()));
        }
    }
    best.map(|(_, release)| release)
}

fn fetch_json(
    client: &reqwest::blocking::Client,
    url: &str,
    accept: &str,
    error: &mut String,
) -> Result<Value, String> {
    let response = client
        .get(url)
        .header("Accept", accept)
        .send()
        .map_err(|e| {
            *error = format!("список выпусков недоступен — {e}");
            error.clone()
        })?;
    if !response.status().is_success() {
        let status = response.status();
        *error = format!("список выпусков недоступен — HTTP {status}");
        return Err(error.clone());
    }
    response
        .json::<Value>()
        .map_err(|e| format!("список выпусков недоступен — не JSON: {e}"))
}

fn fetch_text(
    client: &reqwest::blocking::Client,
    url: &str,
    accept: &str,
) -> Result<String, String> {
    let response = client
        .get(url)
        .header("Accept", accept)
        .send()
        .map_err(|e| format!("контрольная сумма недоступна — {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(format!("контрольная сумма недоступна — HTTP {status}"));
    }
    response
        .text()
        .map_err(|e| format!("контрольная сумма недоступна — {e}"))
}

// ─────────────────────── зеркала: живая рука ───────────────────────────

/// Зеркала из сборочной конфигурации: PRIMEBYPASS_MIRROR_SERVERS — JSON
/// массив [{name,host,https_port,http_port}].
fn mirror_servers() -> Vec<Value> {
    let raw = std::env::var("PRIMEBYPASS_MIRROR_SERVERS").unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or_default()
}

fn mirrors_fetch(channel: &str) -> Result<Value, String> {
    let servers = mirror_servers();
    if servers.is_empty() {
        return Err("зеркала не настроены".to_string());
    }
    let channel = channel.trim().to_string();
    release::fetch_latest_release_mirrors(
        servers.len(),
        move |index: usize| fetch_mirror(servers.clone(), index, &channel),
        release::MIRRORS_DEADLINE_SECONDS,
        release::MIRRORS_SETTLE_SECONDS,
    )
}

fn fetch_mirror(servers: Vec<Value>, index: usize, channel: &str) -> Result<Value, String> {
    let server = servers
        .get(index)
        .cloned()
        .ok_or_else(|| "зеркало вне списка".to_string())?;
    let name = server
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(
            server
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("зеркало"),
        )
        .to_string();
    let client = reqwest::blocking::Client::builder()
        .user_agent("PrimeBypass-Updater/5.0")
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("{name}: клиент: {e}"))?;
    let mut errors: Vec<String> = Vec::new();
    for (protocol, base_url, verify_ssl) in [
        (
            "HTTPS",
            format!(
                "https://{}:{}",
                server.get("host").and_then(Value::as_str).unwrap_or(""),
                server
                    .get("https_port")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
            ),
            true,
        ),
        (
            "HTTP",
            format!(
                "http://{}:{}",
                server.get("host").and_then(Value::as_str).unwrap_or(""),
                server.get("http_port").and_then(Value::as_i64).unwrap_or(0)
            ),
            false,
        ),
    ] {
        let url = format!("{base_url}/api/all_versions.json");
        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-cache")
            .send();
        let Err(error) = response else {
            let response = response.unwrap();
            if !response.status().is_success() {
                errors.push(format!("{protocol}: HTTP {}", response.status()));
                continue;
            }
            let data = match response.json::<Value>() {
                Ok(value) => value,
                Err(_) => {
                    errors.push(format!("{protocol}: неожиданный ответ"));
                    continue;
                }
            };
            match release::release_from_versions(
                &data,
                channel,
                &base_url,
                verify_ssl,
                &format!("{name} ({protocol})"),
            ) {
                Ok(release_json) => return Ok(release_json),
                Err(message) => errors.push(format!("{protocol}: {message}")),
            }
            continue;
        };
        errors.push(format!("{protocol}: {error}"));
    }
    Err(format!("{name}: {}", errors.join("; ")))
}

// ─────────────────────────── router ───────────────────────────────────

pub fn build_router() -> Router {
    router(App {
        ws: ws_api::WsState::production(),
    })
}

/// Router с готовым состоянием (тесты подставляют свои ресурсы и фейковые
/// привилегированные руки).
pub(crate) fn router(app: App) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/versions/compare", post(versions_compare))
        .route("/api/hosts/preview", post(hosts_preview))
        .route("/api/patch/apply", post(patch_apply))
        .route("/api/manifest/verify", post(manifest_verify))
        .route("/api/check", get(check_latest))
        .route("/api/dns/providers", get(dns_api::providers))
        .route("/api/dns/page_state", get(dns_api::page_state))
        .route("/api/dns/server_check", get(dns_api::server_check))
        .route("/api/dns/domain_lookup", get(dns_api::domain_lookup))
        .route("/api/ws/presets", get(ws_api::presets))
        .route("/api/ws/preset", get(ws_api::preset))
        .route("/api/ws/start", post(ws_api::start))
        .route("/api/ws/stop", post(ws_api::stop))
        .route("/api/ws/status", get(ws_api::status))
        .route("/api/ws/logs", get(ws_api::logs))
        .with_state(app)
}

fn port() -> u16 {
    std::env::var("PRIMECORE_PORT")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

// Точка входа сервера в тестах не запускается: #[tokio::main] возможен
// из бинаря, снаружи полезен только build_router.
pub async fn run() {
    let router = build_router();
    let address = format!("0.0.0.0:{}", port());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("порт свободен");
    axum::serve(listener, router)
        .await
        .expect("сервер вертится");
}
