//! Порт чистой части `presets/preset_url_import.py` — валидация ссылки
//! импорта и имя файла из URL/заголовков.
//!
//! Модуль без сети: скачивание (`download_preset_from_url` с `requests`)
//! остаётся в python-воркере вызывающего слоя; здесь — только разбор URL,
//! заголовков и суффиксов, а также уборка managed-папки скачивания
//! (`cleanup_download`), чтобы временный файл не оставался после импорта.

use once_cell::sync::Lazy;
use primecore_lists::winpath::PureWinPath;
use regex::Regex;

/// Лимит размера скачиваемого пресета (python `MAX_DOWNLOAD_BYTES`).
pub const MAX_DOWNLOAD_BYTES: u64 = 10 * 1024 * 1024;
/// User-Agent скачивания (python `_USER_AGENT`).
pub const USER_AGENT: &str = "PrimeBypass-PresetImport/1.0";
/// Префикс имени managed-папки временных скачиваний.
pub const DOWNLOAD_DIR_PREFIX: &str = "primebypass-preset-url-";
/// Сигнатура ZIP-файла (python `_ZIP_MAGIC`).
pub const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

// Виды ошибок скачивания (python ERROR_KIND_*): строковые метки сохранены,
// чтобы слой верхнего уровня локализовал их так же, как в python.
pub const ERROR_KIND_URL: &str = "url";
pub const ERROR_KIND_SSL: &str = "ssl";
pub const ERROR_KIND_TIMEOUT: &str = "timeout";
pub const ERROR_KIND_NETWORK: &str = "network";
pub const ERROR_KIND_HTTP: &str = "http";
pub const ERROR_KIND_TOO_LARGE: &str = "too_large";
pub const ERROR_KIND_CONTENT: &str = "content";
pub const ERROR_KIND_CANCELLED: &str = "cancelled";

/// Скачанный файл пресета (python `DownloadedPresetFile`); файл лежит в
/// managed-папке — после импорта вызывающая сторона зовёт
/// [`cleanup_download`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedPresetFile {
    pub file_path: String,
    pub source_url: String,
    /// «.txt» или «.zip».
    pub suffix: String,
}

/// python `validate_preset_import_url`: пустая строка — URL пригоден,
/// иначе причина отказа.
#[must_use]
pub fn validate_preset_import_url(url: &str) -> String {
    let text = url.trim();
    if text.is_empty() {
        return "Ссылка пуста".to_string();
    }
    let parts = urlsplit(text);
    if parts.scheme != "http" && parts.scheme != "https" {
        return "Поддерживаются только ссылки http:// и https://".to_string();
    }
    if parts.netloc.is_empty() {
        return "В ссылке не указан адрес сервера".to_string();
    }
    String::new()
}

/// python `is_https_preset_import_url`.
#[must_use]
pub fn is_https_preset_import_url(url: &str) -> bool {
    urlsplit(url.trim()).scheme == "https"
}

/// python `_sanitize_stem`.
#[must_use]
pub fn sanitize_stem(value: &str) -> String {
    static FORBIDDEN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"[\\/:*?"<>|\x00]+"#).expect("regexp"));
    static SPACES: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").expect("regexp"));
    let text = value.trim();
    let sanitized = FORBIDDEN.replace_all(text, "_");
    SPACES
        .replace_all(&sanitized, " ")
        .trim()
        .trim_end_matches('.')
        .chars()
        .take(100)
        .collect()
}

fn filename_star_regex() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)filename\*\s*=\s*[^']*''([^;]+)").expect("regexp"));
    &RE
}

fn filename_regex() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)filename\s*=\s*"?([^";]+)"?"#).expect("regexp"));
    &RE
}

/// python `_stem_from_content_disposition`: имя из заголовка
/// Content-Disposition (расширенная форма `filename*=UTF-8''...` или
/// простая `filename="..."`).
#[must_use]
pub fn stem_from_content_disposition(header_value: Option<&str>) -> String {
    let text = header_value.unwrap_or("");
    if let Some(captures) = filename_star_regex().captures(text) {
        let raw = captures.get(1).map_or(String::new(), |m| {
            m.as_str().trim().trim_matches('"').to_string()
        });
        return PureWinPath::new(&unquote(&raw)).stem();
    }
    if let Some(captures) = filename_regex().captures(text) {
        let raw = captures
            .get(1)
            .map_or(String::new(), |m| m.as_str().trim().to_string());
        return PureWinPath::new(&raw).stem();
    }
    String::new()
}

/// python `preset_file_stem_from_url`: имя пресета — Content-Disposition →
/// последний сегмент URL → "Imported".
#[must_use]
pub fn preset_file_stem_from_url(url: &str, content_disposition: Option<&str>) -> String {
    let mut stem = stem_from_content_disposition(content_disposition);
    if stem.is_empty() {
        let path = urlsplit(url.trim()).path;
        let last_segment = if path.is_empty() {
            String::new()
        } else {
            unquote(path.trim_end_matches('/').rsplit('/').next().unwrap_or(""))
        };
        stem = PureWinPath::new(&last_segment).stem();
    }
    let sanitized = sanitize_stem(&stem);
    if sanitized.is_empty() {
        "Imported".to_string()
    } else {
        sanitized
    }
}

/// python `_resolve_suffix`: суффикс временного файла — по сигнатуре, пути
/// URL или Content-Type.
#[must_use]
pub fn resolve_suffix(url: &str, content_type: Option<&str>, first_chunk: &[u8]) -> String {
    if first_chunk.starts_with(ZIP_MAGIC) {
        return ".zip".to_string();
    }
    let path = urlsplit(url).path;
    let path_suffix = PureWinPath::new(&path)
        .suffixes()
        .last()
        .cloned()
        .unwrap_or_default();
    if path_suffix.to_lowercase() == ".zip" {
        return ".zip".to_string();
    }
    let content_type = content_type.unwrap_or("").to_lowercase();
    if content_type.contains("zip") {
        return ".zip".to_string();
    }
    ".txt".to_string()
}

/// python `is_managed_download_path`: файл лежит в managed-папке скачивания.
#[must_use]
pub fn is_managed_download_path(file_path: &std::path::Path) -> bool {
    file_path
        .parent()
        .and_then(std::path::Path::file_name)
        .map(|name| name.to_string_lossy().starts_with(DOWNLOAD_DIR_PREFIX))
        .unwrap_or(false)
}

/// python `cleanup_download`: удаляет managed-папку скачивания; чужие пути
/// не трогает (ошибки удаления игнорируются, как `rmtree(..., ignore_errors)`).
pub fn cleanup_download(file_path: &std::path::Path) {
    if !is_managed_download_path(file_path) {
        return;
    }
    if let Some(parent) = file_path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

/// python `urlsplit` в объёме, нужном модулю: scheme (в нижнем регистре),
/// netloc, path (без query и fragment).
struct UrlParts {
    scheme: String,
    netloc: String,
    path: String,
}

fn urlsplit(value: &str) -> UrlParts {
    let mut rest = value;
    if let Some(hash) = rest.find('#') {
        rest = &rest[..hash];
    }
    let (scheme, after) = match rest.find(':') {
        Some(colon)
            if colon > 0
                && rest[..colon]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') =>
        {
            (rest[..colon].to_lowercase(), &rest[colon + 1..])
        }
        _ => (String::new(), rest),
    };
    let (netloc, path) = if let Some(tail) = after.strip_prefix("//") {
        let end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
        (tail[..end].to_string(), tail[end..].to_string())
    } else {
        (String::new(), after.to_string())
    };
    UrlParts {
        scheme,
        netloc,
        path,
    }
}

/// python `urllib.parse.unquote` (errors="replace" по умолчанию): некорректные
/// последовательности остаются как есть.
#[must_use]
pub fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_matches_python() {
        for (url, expected) in [
            ("", "Ссылка пуста"),
            (
                "ftp://x/y.txt",
                "Поддерживаются только ссылки http:// и https://",
            ),
            ("http:/x/y.txt", "В ссылке не указан адрес сервера"),
            ("https://", "В ссылке не указан адрес сервера"),
            ("https://ex.com/a/b/preset.zip?x=1", ""),
            ("HTTP://Host/p", ""),
        ] {
            assert_eq!(validate_preset_import_url(url), expected, "{url}");
        }
        assert!(is_https_preset_import_url("HTTPS://x/y"));
        assert!(!is_https_preset_import_url("HTTP://x/y"));
        assert!(!is_https_preset_import_url("ftp://x"));
    }

    #[test]
    fn stems_match_python() {
        assert_eq!(
            preset_file_stem_from_url(
                "https://ex.com/a/b/%D0%9F%D1%80%D0%B5%D1%81%D0%B5%D1%82.txt?d=1",
                None
            ),
            "Пресет"
        );
        assert_eq!(
            stem_from_content_disposition(Some("attachment; filename=\"My Preset.txt\"")),
            "My Preset"
        );
        assert_eq!(
            stem_from_content_disposition(Some("attachment; filename*=UTF-8''%D0%9F%D1%80.txt")),
            "Пр"
        );
        assert_eq!(stem_from_content_disposition(None), "");
        assert_eq!(preset_file_stem_from_url("", None), "Imported");
    }

    #[test]
    fn suffixes_match_python() {
        assert_eq!(
            resolve_suffix("https://x/y.ZIP", Some("text/plain"), b"hello"),
            ".zip"
        );
        assert_eq!(
            resolve_suffix("https://x/y", Some("application/zip"), b"hello"),
            ".zip"
        );
        assert_eq!(
            resolve_suffix("https://x/y", Some("text/plain"), b"hello"),
            ".txt"
        );
        assert_eq!(
            resolve_suffix("https://x/y", Some("text/plain"), ZIP_MAGIC),
            ".zip"
        );
    }
}
