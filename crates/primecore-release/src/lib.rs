//! Порт чистой логики `src/primebypass_update/release/*` (будущее имя
//! каталога Python-части): каналы обновлений, разбор Telegram-канала,
//! обязательный набор метаданных установщика (release_contract.py),
//! сборка кандидатов Forgejo (forgejo.py) и гонка resolver'а
//! (resolver.py) с зеркалами (mirrors.py).
//!
//! HTTP сюда не входит и в Rust не входит: сетевые руки передаются
//! извне замыканиями — primecore-server ставит на них reqwest. Так же
//! как в Python: без кэшей, «не удалось узнать» никогда не превращается
//! в «обновлений нет».

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use primecore_versions::normalize_version;
use primecore_versions::version_key;

// ───────────────────────── каналы обновлений ─────────────────────────

/// Канонические значения канала обновления (как CHANNEL_* в config).
pub const CHANNEL_STABLE: &str = "stable";
pub const CHANNEL_DEV: &str = "dev";
pub const CANONICAL_UPDATE_CHANNELS: [&str; 2] = [CHANNEL_STABLE, CHANNEL_DEV];

/// Приводит канал обновления к одному каноническому значению.
pub fn normalize_update_channel(channel: &str) -> &'static str {
    if channel.trim().to_lowercase() == CHANNEL_DEV {
        CHANNEL_DEV
    } else {
        CHANNEL_STABLE
    }
}

pub fn is_dev_update_channel(channel: &str) -> bool {
    normalize_update_channel(channel) == CHANNEL_DEV
}

/// Каноническое имя установщика канала — PrimeBypass теперь.
pub fn get_channel_installer_name(channel: &str) -> &'static str {
    if is_dev_update_channel(channel) {
        "PrimeBypassSetup_DEV.exe"
    } else {
        "PrimeBypassSetup.exe"
    }
}

/// Имена Dev-выпускам разрешаются и новые, и прежних выпусков
/// (PrimeProxy, Zapret2Setup) — данные прошлых лет, не бренд.
pub fn is_dev_release_asset_name(file_name: &str) -> bool {
    let upper_name = file_name.trim().to_uppercase();
    upper_name.starts_with("PRIMEBYPASSSETUP_DEV")
        || upper_name.starts_with("PRIMEPROXYSETUP_DEV")
        || upper_name.starts_with("ZAPRET2SETUP_DEV")
        || upper_name.contains("_DEV")
}

// ───────────────────────── Telegram (диагностика) ─────────────────────
//
// Telegram никогда не создаёт предложение обновиться: только строка
// диагностики в таблице серверов. Токенов нет: публичная страница
// t.me/s/<канал>. Имя канала — живой адрес, не переименовывается.

pub const TELEGRAM_CONNECT_SECONDS: u64 = 3;
pub const TELEGRAM_READ_SECONDS: u64 = 5;

pub fn telegram_channel_name(channel: &str) -> &'static str {
    match normalize_update_channel(channel) {
        "dev" => "zapretguidev",
        _ => "zapretnetdiscordyoutube",
    }
}

/// Версия берётся только из имени установщика: произвольные числа из
/// текста поста — даты, IP-адреса — версией не считаются. Принимаются
/// имена и новой программы, и прежних выпусков.
static INSTALLER_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:PrimeBypass|PrimeProxy|Zapret2)Setup(?:_DEV)?_(\d+(?:_\d+){2,})\.exe")
        .expect("регулярка имени установщика компилируется")
});

/// Последняя объявленная в канале версия — по чистому HTML страницы.
pub fn version_from_telegram_html(html: &str) -> Option<String> {
    let mut matches = Vec::new();
    for coordinates in INSTALLER_NAME_RE.captures_iter(html) {
        if let Some(digits) = coordinates.get(1) {
            matches.push(digits.as_str().replace('_', "."));
        }
    }
    matches.pop()
}

pub fn telegram_source_name(channel: &str) -> String {
    format!("Telegram @{}", telegram_channel_name(channel))
}

// ───────────────── release_contract: обязательные поля ────────────────

pub const SHA256_HEX_LENGTH: usize = 64;

pub fn normalize_sha256(value: &str) -> String {
    let normalized = value.trim().to_lowercase();
    if normalized.len() != SHA256_HEX_LENGTH {
        return String::new();
    }
    if !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return String::new();
    }
    normalized
}

/// Как `PurePosixPath(path).name` — крайний кусок пути.
fn posix_path_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

struct UrlParts {
    scheme: String,
    authority: String,
    path: String,
    has_query_or_fragment: bool,
}

fn split_url(url: &str) -> Option<UrlParts> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, tail) = match rest.find('/') {
        Some(index) => (rest[..index].to_string(), rest[index..].to_string()),
        None => (rest.to_string(), String::new()),
    };
    let (path, extras) = match tail.find(['?', '#']) {
        Some(index) => (tail[..index].to_string(), true),
        None => (tail, false),
    };
    Some(UrlParts {
        scheme: scheme.to_lowercase(),
        authority,
        path,
        has_query_or_fragment: extras,
    })
}

fn authority_host(authority: &str) -> String {
    let without_userinfo = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    without_userinfo
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn authority_has_userinfo(authority: &str) -> bool {
    // Полужирный разбор: username/password идут до символа @ в authority.
    authority.rsplit_once('@').is_some()
}

fn authority_has_port(authority: &str) -> bool {
    authority.rsplit_once('@').map_or(authority, |(_, host)| host).contains(':')
}

fn percent_decode(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                Some(byte) => {
                    out.push(byte);
                    index += 3;
                    continue;
                }
                None => {
                    out.push(bytes[index]);
                }
            }
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Проверенные поля одного выпуска из одного источника.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifactMetadata {
    pub version: String,
    pub update_url: String,
    pub file_name: String,
    pub file_size: i64,
    pub sha256: String,
    pub verify_ssl: bool,
}

impl ReleaseArtifactMetadata {
    /// Строгая проверка и сборка из ответа источника.
    pub fn from_mapping(release_info: &Value) -> Result<Self, String> {
        let version = release_info
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if version.is_empty() {
            return Err("В метаданных выпуска нет версии".to_string());
        }
        let update_url = release_info
            .get("update_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let Some(parts) = split_url(&update_url) else {
            return Err("В метаданных выпуска некорректная ссылка".to_string());
        };
        let authority_host = authority_host(&parts.authority);
        let bad_url = (parts.scheme != "http" && parts.scheme != "https")
            || authority_host.is_empty()
            || authority_has_userinfo(&parts.authority)
            || parts.has_query_or_fragment;
        if bad_url {
            return Err("В метаданных выпуска некорректная ссылка".to_string());
        }
        let file_name = release_info
            .get("file_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if file_name.is_empty() {
            return Err("В метаданных выпуска нет имени файла".to_string());
        }
        let remote_name = posix_path_name(&parts.path);
        if remote_name != file_name {
            return Err("Ссылка выпуска не соответствует имени файла".to_string());
        }
        let file_size = release_info.get("file_size").and_then(Value::as_i64).unwrap_or(0);
        if file_size <= 0 {
            return Err("В метаданных выпуска нет размера файла".to_string());
        }
        let sha256 = normalize_sha256(
            release_info.get("sha256").and_then(Value::as_str).unwrap_or(""),
        );
        if sha256.is_empty() {
            return Err("В метаданных выпуска нет SHA-256".to_string());
        }
        Ok(Self {
            version,
            update_url,
            file_name,
            file_size,
            sha256,
            verify_ssl: release_info
                .get("verify_ssl")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }
}

/// Источник описал готовый к скачиванию и проверке установщик.
pub fn is_installable_release(release_info: &Value) -> bool {
    ReleaseArtifactMetadata::from_mapping(release_info).is_ok()
}

// ───────────────────────── Forgejo: кандидаты ─────────────────────────

// Живой домен и текущий репозиторий обновлений — данные сервера, не сменный бренд.
pub const FORGEJO_HOST: &str = "git.zapret.moe";
pub const FORGEJO_REPOSITORY: &str = "zapretdiscordyoutube/zapretgui";
pub const FORGEJO_SOURCE: &str = "Forgejo";
pub const RELEASES_PAGE_LIMIT: usize = 50;
pub const MAX_RELEASE_PAGES: usize = 4;
pub const MAX_SIDECAR_BYTES: usize = 4096;
pub const FORGEJO_RELEASE_DOWNLOAD_PREFIX: &str =
    "/zapretdiscordyoutube/zapretgui/releases/download/";

static SHA256_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\A([0-9a-fA-F]{64})  ([^\r\n]+)\r?\n?\z").expect("регулярка sidecar")
});

fn percent_encode_tag(tag: &str) -> String {
    let mut out = String::with_capacity(tag.len());
    for byte in tag.bytes() {
        // quote(safe='') резервирует только буквы, цифры и _-.
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Страница выпуска на Forgejo — для кнопки «Открыть в браузере».
pub fn release_page_url(tag_name: &str) -> String {
    format!(
        "https://{FORGEJO_HOST}/{FORGEJO_REPOSITORY}/releases/tag/{}",
        percent_encode_tag(tag_name)
    )
}

/// Точная ссылка на собственный домён: https, без порта, логинов,
/// запросов и фрагментов; путь — ровно файл в каталоге выпуска.
pub fn trusted_release_asset_url(url: &str, tag_name: &str, file_name: &str) -> bool {
    let Some(parts) = split_url(url) else {
        return false;
    };
    if parts.scheme != "https"
        || authority_host(&parts.authority) != FORGEJO_HOST
        || authority_has_port(&parts.authority)
        || authority_has_userinfo(&parts.authority)
        || parts.has_query_or_fragment
    {
        return false;
    }
    let expected_prefix = format!("{FORGEJO_RELEASE_DOWNLOAD_PREFIX}{tag_name}/");
    let decoded_path = percent_decode(&parts.path);
    if !decoded_path.starts_with(&expected_prefix) {
        return false;
    }
    let relative = decoded_path[expected_prefix.len()..].to_string();
    relative == file_name && posix_path_name(&relative) == relative
}

/// Файл контрольной суммы: `sha256  имя` одной строкой.
pub fn parse_sha256_sidecar(text: &str, expected_name: &str) -> Result<String, String> {
    let Some(captures) = SHA256_LINE_RE.captures(text.trim_end_matches(['\r', '\n'])) else {
        return Err("Некорректный файл контрольной суммы выпуска".to_string());
    };
    let name = captures.get(2).map(|m| m.as_str()).unwrap_or("");
    if name != expected_name {
        return Err("Некорректный файл контрольной суммы выпуска".to_string());
    }
    Ok(captures.get(1).map(|m| m.as_str()).unwrap_or("").to_lowercase())
}

/// Канал выпуска: dev — если prerelease или dev-имя файла.
pub fn matches_channel(prerelease: bool, exe_name: &str, channel: &str) -> bool {
    let is_dev = prerelease || is_dev_release_asset_name(exe_name);
    if is_dev_update_channel(channel) {
        is_dev
    } else {
        !is_dev
    }
}

fn asset_name(asset: &Value) -> &str {
    asset.get("name").and_then(Value::as_str).unwrap_or("")
}

/// Кандидат из списка выпусков без единого скачивания, либо нет.
pub fn forgejo_candidate(release: &Value, channel: &str) -> Option<Value> {
    if release.get("draft").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    let tag_name = release.get("tag_name").and_then(Value::as_str).unwrap_or("");
    let version = normalize_version(tag_name).ok()?;
    let assets: Vec<&Value> = release
        .get("assets")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();
    let exe_asset = assets
        .iter()
        .copied()
        .find(|asset| asset_name(asset).to_lowercase().ends_with(".exe"))?;
    let exe_name = asset_name(exe_asset);
    let prerelease = release.get("prerelease").and_then(Value::as_bool).unwrap_or(false);
    if !matches_channel(prerelease, exe_name, channel) {
        return None;
    }
    let sidecar_name = format!("{exe_name}.sha256");
    let sidecar = assets.iter().copied().find(|asset| asset_name(asset) == sidecar_name)?;
    let exe_url = exe_asset.get("browser_download_url").and_then(Value::as_str).unwrap_or("");
    let sidecar_url = sidecar.get("browser_download_url").and_then(Value::as_str).unwrap_or("");
    if !trusted_release_asset_url(exe_url, tag_name, exe_name) {
        return None;
    }
    if !trusted_release_asset_url(sidecar_url, tag_name, &sidecar_name) {
        return None;
    }
    let mut candidate = serde_json::json!({
        "version": version,
        "tag_name": tag_name,
        "update_url": exe_url,
        "file_name": exe_name,
        "file_size": exe_asset.get("size").cloned().unwrap_or(Value::Null),
        "sidecar_url": sidecar_url,
        "release_notes": release.get("body").and_then(Value::as_str).unwrap_or(""),
        "prerelease": prerelease,
        "name": release.get("name").and_then(Value::as_str).unwrap_or(""),
        "published_at": release.get("published_at").and_then(Value::as_str).unwrap_or(""),
        "release_url": release_page_url(tag_name),
    });
    // Подписанный список выпуска: по нему проверяется установщик.
    for (key, name) in [
        ("manifest_url", primecore_manifest::MANIFEST_NAME),
        ("signature_url", primecore_manifest::SIGNATURE_NAME),
    ] {
        let url = assets
            .iter()
            .copied()
            .find(|asset| asset_name(asset) == name)
            .and_then(|asset| asset.get("browser_download_url").and_then(Value::as_str))
            .unwrap_or("");
        if trusted_release_asset_url(url, tag_name, name) {
            candidate[key] = Value::String(url.to_string());
        }
    }
    Some(candidate)
}

/// Кандидаты одной страницы списка выпусков (пагинация — у руки с HTTP).
pub fn candidates_from_release_list(payload: &Value, channel: &str) -> Option<Vec<Value>> {
    let items = payload.as_array()?;
    Some(
        items
            .iter()
            .filter_map(|release| forgejo_candidate(release, channel))
            .collect(),
    )
}

/// Запись «Что нового» по кандидату.
pub fn history_entry(candidate: &Value) -> Value {
    serde_json::json!({
        "version": candidate.get("version").cloned().unwrap_or(Value::String(String::new())),
        "notes": candidate.get("release_notes").cloned().unwrap_or(Value::String(String::new())),
        "published_at": candidate.get("published_at").cloned().unwrap_or(Value::String(String::new())),
        "url": candidate.get("release_url").cloned().unwrap_or(Value::String(String::new())),
    })
}

// ───────────────────── зеркала: полный выпуск из all_versions ─────────

/// Выпуск канала из ``all_versions.json`` одного зеркала, строго
/// проверенный. Поля разных источников не смешиваются никогда: ответ
/// либо целиком от Forgejo, либо целиком от одного зеркала.
pub fn release_from_versions(
    data: &Value,
    channel: &str,
    base_url: &str,
    verify_ssl: bool,
    source: &str,
) -> Result<Value, String> {
    let selected = normalize_update_channel(channel);
    let entry = data.get(selected).cloned().unwrap_or(Value::Null);
    if !entry.is_object() || entry.get("version").and_then(Value::as_str).unwrap_or("").is_empty() {
        return Err(format!("в ответе нет канала {selected}"));
    }
    let version = normalize_version(entry.get("version").and_then(Value::as_str).unwrap_or(""))
        .map_err(|error| error.to_string())?;
    let file_name = entry
        .get("file_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut release = serde_json::json!({
        "version": version,
        "tag_name": version,
        "update_url": format!("{base_url}/download/{file_name}"),
        "file_name": file_name,
        "file_size": entry.get("file_size").cloned().unwrap_or(Value::Null),
        "sha256": entry.get("sha256").cloned().unwrap_or(Value::Null),
        "release_notes": entry.get("release_notes").and_then(Value::as_str).unwrap_or(""),
        "prerelease": is_dev_update_channel(selected),
        "name": format!("PrimeBypass {version} ({selected})"),
        "published_at": entry.get("date").and_then(Value::as_str).unwrap_or(""),
        "source": source,
        "verify_ssl": verify_ssl,
    });
    if entry.get("manifest").and_then(Value::as_bool).unwrap_or(false) {
        // Подписанный список выпуска лежит рядом с установщиком.
        release["manifest_url"] = Value::String(format!(
            "{base_url}/download/{file_name}.{}",
            primecore_manifest::MANIFEST_NAME
        ));
        release["signature_url"] = Value::String(format!(
            "{base_url}/download/{file_name}.{}",
            primecore_manifest::SIGNATURE_NAME
        ));
    }
    // Неполный ответ — ошибка этого зеркала, а не повод дополнять.
    ReleaseArtifactMetadata::from_mapping(&release)?;
    Ok(release)
}

/// Адреса одного файла на одном зеркале: основной HTTPS и запасной HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorDownload {
    pub name: String,
    pub host: String,
    pub https_url: String,
    pub http_url: String,
    pub verify_ssl: bool,
}

pub fn mirror_download(server: &Value, file_name: &str, verify_ssl: bool) -> MirrorDownload {
    let host = server.get("host").and_then(Value::as_str).unwrap_or("").to_string();
    let name = server
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(&host)
        .to_string();
    MirrorDownload {
        name,
        host: host.clone(),
        https_url: format!(
            "https://{host}:{}/download/{file_name}",
            server.get("https_port").and_then(Value::as_i64).unwrap_or(0)
        ),
        http_url: format!(
            "http://{host}:{}/download/{file_name}",
            server.get("http_port").and_then(Value::as_i64).unwrap_or(0)
        ),
        verify_ssl,
    }
}

// ───────────────────────── гонка resolver'а ───────────────────────────

pub const MIRROR_FALLBACK_DELAY_SECONDS: f64 = 3.0;
pub const FORGEJO_DEADLINE_SECONDS: f64 = 20.0;
pub const MIRRORS_DEADLINE_SECONDS: f64 = 20.0;
/// Сколько ждать остальные зеркала после первого корректного ответа.
pub const MIRRORS_SETTLE_SECONDS: f64 = 1.5;
pub const NO_ANSWER_IN_TIME: &str = "нет ответа за отведённое время";

/// Итог поиска выпуска: выпуск или текст ошибки для пользователя.
#[derive(Debug, Clone)]
pub struct ReleaseLookup {
    pub release: Option<Value>,
    pub error: String,
}

impl ReleaseLookup {
    pub fn ok(&self) -> bool {
        self.release.is_some()
    }
}

/// Одна сетевая рука: внутри уже короткое сообщение об ошибке.
pub type FetchSource = Arc<dyn Fn() -> Result<Value, String> + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    Forgejo,
    Mirrors,
}

fn truncate_error(error: &str, limit: usize) -> String {
    // Как short_error(limit=…): длинные трейсинги источников не читаем.
    if error.chars().count() <= limit {
        error.to_string()
    } else {
        let mut cut: String = error.chars().take(limit).collect();
        cut.push('…');
        cut
    }
}

fn seconds(value: f64) -> Duration {
    Duration::from_secs_f64(value.max(0.0))
}

/// Единственный путь узнать новейший выпуск канала. Порядок источников:
/// Forgejo — главный (фора MIRROR_FALLBACK_DELAY_SECONDS перед зеркалами);
/// зеркала — запасные, запускаются после ошибки или молчания Forgejo;
/// дальше побеждает первый успешный ответ: готовый ответ зеркала не ждёт
/// тайм-аутов заблокированного Forgejo. Ошибка несёт причины обоих
/// источников, никогда не превращаясь в «обновлений нет».
pub fn lookup_latest_release(
    channel: &str,
    fetch_forgejo: FetchSource,
    fetch_mirrors: FetchSource,
    fallback_delay: f64,
    forgejo_deadline: f64,
    mirrors_deadline: f64,
) -> ReleaseLookup {
    let _selected = normalize_update_channel(channel);
    let started = Instant::now();
    let (sender, receiver) = mpsc::channel::<(Source, Result<Value, String>)>();

    let ask = |source: Source,
               fetch: FetchSource,
               sender: mpsc::Sender<(Source, Result<Value, String>)>| {
        thread::spawn(move || {
            let _ = sender.send((source, fetch()));
        })
    };

    // Источник → момент, после которого его ответ уже не ждём.
    let mut waiting: BTreeMap<Source, Instant> = BTreeMap::new();
    let mut errors: BTreeMap<Source, String> = BTreeMap::new();
    let mut mirrors_start_at: Option<Instant> = Some(started + seconds(fallback_delay));
    waiting.insert(Source::Forgejo, started + seconds(forgejo_deadline));
    ask(Source::Forgejo, fetch_forgejo, sender.clone());

    loop {
        let now = Instant::now();
        for (source, deadline) in waiting.clone() {
            if now >= deadline {
                waiting.remove(&source);
                errors.insert(source, NO_ANSWER_IN_TIME.to_string());
            }
        }
        if let Some(start_at) = mirrors_start_at {
            if errors.contains_key(&Source::Forgejo) || now >= start_at {
                mirrors_start_at = None;
                waiting.insert(Source::Mirrors, Instant::now() + seconds(mirrors_deadline));
                ask(Source::Mirrors, Arc::clone(&fetch_mirrors), sender.clone());
            }
        }
        if waiting.is_empty() {
            break;
        }
        let wake_at = waiting
            .values()
            .copied()
            .chain(mirrors_start_at)
            .min()
            .unwrap_or(now);
        match receiver.recv_timeout(wake_at.saturating_duration_since(now)) {
            Ok((source, outcome)) => {
                if !waiting.remove(&source).is_some() {
                    // Ответ после своего срока: источник уже в ошибках.
                    continue;
                }
                match outcome {
                    Ok(value) => {
                        return ReleaseLookup {
                            release: Some(value),
                            error: String::new(),
                        };
                    }
                    Err(error) => {
                        let limit = if source == Source::Mirrors { 300 } else { 120 };
                        errors.insert(source, truncate_error(&error, limit));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let forgejo_error = errors.get(&Source::Forgejo).cloned().unwrap_or_default();
    let mirrors_error = errors.get(&Source::Mirrors).cloned().unwrap_or_default();
    ReleaseLookup {
        release: None,
        error: format!(
            "Не удалось узнать новейшую версию. Forgejo: {forgejo_error}. Зеркала: {mirrors_error}"
        ),
    }
}

/// Гонка зеркал: первый ответ не победитель — после первого корректного
/// ответа окно ``settle`` остальным зеркалам урезается, и берётся самая
/// новая версия. При равных версиях — зеркало раньше по списку.
pub fn fetch_latest_release_mirrors(
    server_count: usize,
    fetch_one: impl Fn(usize) -> Result<Value, String> + Send + Sync + 'static,
    timeout: f64,
    settle: f64,
) -> Result<Value, String> {
    if server_count == 0 {
        return Err("зеркала не настроены".to_string());
    }
    let fetch_one = Arc::new(fetch_one);
    let (sender, receiver) = mpsc::channel::<(usize, Result<Value, String>)>();
    for index in 0..server_count {
        let fetch_one = Arc::clone(&fetch_one);
        let sender = sender.clone();
        thread::spawn(move || {
            let _ = sender.send((index, fetch_one(index)));
        });
    }
    let mut deadline = Instant::now() + seconds(timeout);
    let mut releases: BTreeMap<usize, Value> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    while releases.len() + errors.len() < server_count {
        let wait = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(wait) {
            Ok((index, Ok(release))) => {
                if releases.is_empty() {
                    deadline = deadline.min(Instant::now() + seconds(settle));
                }
                releases.insert(index, release);
            }
            Ok((_, Err(error))) => errors.push(error),
            Err(_) => break,
        }
    }
    if releases.is_empty() {
        return Err(if errors.is_empty() {
            "нет ответа за отведённое время".to_string()
        } else {
            errors.join("; ")
        });
    }
    let mut chosen: Option<(usize, Vec<u64>, Value)> = None;
    for (index, release) in releases.iter() {
        let current = release
            .get("version")
            .and_then(Value::as_str)
            .and_then(|version| version_key(version).ok())
            .expect("версия ключа распознана");
        let current = (*current).to_vec();
        let better = match &chosen {
            None => true,
            Some((best_index, best_key, _)) => {
                current > *best_key || (current == *best_key && *index < *best_index)
            }
        };
        if better {
            chosen = Some((*index, current, release.clone()));
        }
    }
    Ok(chosen.map(|(_, _, release)| release).expect("выпуск из непустой гонки"))
}
