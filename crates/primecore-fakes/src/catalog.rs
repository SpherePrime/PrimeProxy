//! Порт `src/fakes/catalog_repository.py` — читатель реестра фейков
//! winws2 (`system/fakes_catalog.sqlite3`), read-only.
//!
//! База — готовый ресурс: рантайм не создаёт, не мигрирует и не меняет
//! её. Открывается только для чтения, проверяется целостность
//! (quick_check, application_id, user_version, контрольная сумма строк),
//! затем читается срез реестра, отсортированный по `sort_order`.
//! Отсутствие или порча базы — ошибка: пустой запасной вариант молча
//! убрал бы `--blob=`-объявления, и winws2 упал бы позже.
//!
//! Кэш python (`load_fakes_catalog` с подписью файла) — у вызывающего
//! слоя: сигнатура ([`file_content_signature`]) экспортирована.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// python `CATALOG_APPLICATION_ID` — "ZFCT" (Zapret Fakes Catalog).
pub const CATALOG_APPLICATION_ID: i32 = 0x5A46_4354;
/// python `CATALOG_SCHEMA_VERSION`.
pub const CATALOG_SCHEMA_VERSION: i32 = 1;
/// python `CATALOG_FILE_NAME`.
pub const CATALOG_FILE_NAME: &str = "fakes_catalog.sqlite3";

/// python `BIN_REFERENCE_PREFIX`.
pub const BIN_REFERENCE_PREFIX: &str = "@bin/";

/// python `SOURCE_KINDS`.
pub const SOURCE_KINDS: [&str; 2] = ["file", "hex"];

/// python `FAKE_KINDS` — виды содержимого.
pub const FAKE_KINDS: [&str; 10] = [
    "tls",
    "quic",
    "http",
    "stun",
    "dht",
    "discord",
    "wireguard",
    "dtls",
    "zeros",
    "other",
];

/// Ошибка реестра (python `FakesCatalogError`): база отсутствует,
/// повреждена или схема не поддерживается.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakesCatalogError(pub String);

impl core::fmt::Display for FakesCatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for FakesCatalogError {}

/// python `FakeEntry` — одна строка реестра: имя blob-а и точное значение
/// после `--blob=<имя>:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeEntry {
    pub name: String,
    pub source_kind: String,
    pub file_name: Option<String>,
    pub hex_value: Option<String>,
    pub kind: String,
    pub sni: Option<String>,
    pub description: String,
    pub same_bytes_as: Option<String>,
    /// python `sort_order` — порядок показа (в срезе уже отсортирован).
    pub sort_order: i64,
}

impl FakeEntry {
    /// python-проверки `__post_init__` — ошибка значением.
    pub fn validate(&self) -> Result<(), FakesCatalogError> {
        let fail = |message: String| Err(FakesCatalogError(message));
        if !valid_fake_name(&self.name) {
            return fail(format!("недопустимое имя blob-а: {:?}", self.name));
        }
        if !SOURCE_KINDS.contains(&self.source_kind.as_str()) {
            return fail(format!(
                "{}: неизвестный source_kind {:?}",
                self.name, self.source_kind
            ));
        }
        if !FAKE_KINDS.contains(&self.kind.as_str()) {
            return fail(format!("{}: неизвестный kind {:?}", self.name, self.kind));
        }
        if self.source_kind == "file" {
            let Some(file_name) = &self.file_name else {
                return fail(format!(
                    "{}: для source_kind=file нужен только file_name",
                    self.name
                ));
            };
            if self.hex_value.is_some() || file_name.is_empty() {
                return fail(format!(
                    "{}: для source_kind=file нужен только file_name",
                    self.name
                ));
            }
            if file_name.contains('/')
                || file_name.contains('\\')
                || file_name == "."
                || file_name == ".."
            {
                return fail(format!(
                    "{}: file_name — имя внутри bin/, без пути",
                    self.name
                ));
            }
            return Ok(());
        }
        if self.file_name.is_some() || self.hex_value.as_ref().is_none_or(String::is_empty) {
            return fail(format!(
                "{}: для source_kind=hex нужен только hex_value",
                self.name
            ));
        }
        let hex = self.hex_value.as_deref().unwrap_or_default();
        if !valid_hex(hex) {
            return fail(format!(
                "{}: hex_value — чётное число hex-цифр без префикса 0x",
                self.name
            ));
        }
        Ok(())
    }

    /// python `blob_value` — текст после `--blob=<имя>:`.
    #[must_use]
    pub fn blob_value(&self) -> String {
        if self.source_kind == "file" {
            format!(
                "{BIN_REFERENCE_PREFIX}{}",
                self.file_name.as_deref().unwrap_or_default()
            )
        } else {
            format!("0x{}", self.hex_value.as_deref().unwrap_or_default())
        }
    }

    /// python `blob_line` — целая строка пресета.
    #[must_use]
    pub fn blob_line(&self) -> String {
        format!("--blob={}:{}", self.name, self.blob_value())
    }
}

/// python `_NAME_RE` — `[A-Za-z_][A-Za-z0-9_]*`.
#[must_use]
pub fn valid_fake_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// python `_HEX_RE` — чётное число hex-цифр.
#[must_use]
pub fn valid_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// python `FakesCatalog` — неизменяемый срез реестра: записи в порядке
/// `sort_order`, ключи совпадают с именами.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FakesCatalog {
    /// Вставка сохраняет порядок `sort_order` из базы.
    pub entries: Vec<FakeEntry>,
    pub catalog_version: String,
    pub content_sha256: String,
}

impl FakesCatalog {
    /// python `catalog.entries[name]` — поиск по имени blob-а.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FakeEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// python `len(catalog.entries)`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// python: entries never empty after load.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Имена blob-ов в порядке показа.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }
}

/// python `file_content_signature` — подпись содержимого, нечувствительная
/// к изменению только времени файла: (старшие 8 байт sha256, размер).
pub fn file_content_signature(path: &Path) -> Result<(u64, u64), FakesCatalogError> {
    let data = std::fs::read(path).map_err(|error| {
        FakesCatalogError(format!("файл не найден: {}: {error}", path.display()))
    })?;
    let digest = Sha256::digest(&data);
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    Ok((u64::from_be_bytes(head), data.len() as u64))
}

/// python `compute_content_sha256` — хэш всех логических строк реестра,
/// кроме ссылающейся на себя метаданных.
pub fn compute_content_sha256(connection: &Connection) -> Result<String, FakesCatalogError> {
    let mut digest = Sha256::new();
    digest.update(b"fakes\n");
    let mut statement = connection
        .prepare(
            "SELECT name, source_kind, file_name, hex_value, kind, sni, \
             description, same_bytes_as, sort_order FROM fakes ORDER BY name",
        )
        .map_err(|error| {
            FakesCatalogError(format!("структура таблицы fakes повреждена: {error}"))
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok(json_row(
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|error| {
            FakesCatalogError(format!("структура таблицы fakes повреждена: {error}"))
        })?;
    for row in rows {
        let payload = row.map_err(|error| FakesCatalogError(error.to_string()))?;
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload.as_bytes());
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// python `json.dumps(list(row), ensure_ascii=False, separators=(",", ":"))`
/// — представление строки таблицы для хэша.
#[allow(clippy::too_many_arguments)]
fn json_row(
    name: String,
    source_kind: String,
    file_name: Option<String>,
    hex_value: Option<String>,
    kind: String,
    sni: Option<String>,
    description: String,
    same_bytes_as: Option<String>,
    sort_order: i64,
) -> String {
    // python json.dumps(None) → "null"; строки — с json-экранированием.
    let mut parts: Vec<String> = Vec::with_capacity(9);
    parts.push(json_string(&name));
    parts.push(json_string(&source_kind));
    parts.push(match file_name {
        Some(value) => json_string(&value),
        None => "null".to_string(),
    });
    parts.push(match hex_value {
        Some(value) => json_string(&value),
        None => "null".to_string(),
    });
    parts.push(json_string(&kind));
    parts.push(match sni {
        Some(value) => json_string(&value),
        None => "null".to_string(),
    });
    parts.push(json_string(&description));
    parts.push(match same_bytes_as {
        Some(value) => json_string(&value),
        None => "null".to_string(),
    });
    parts.push(sort_order.to_string());
    format!("[{}]", parts.join(","))
}

/// python `json.dumps` для одной строки (ensure_ascii=False,
/// separators=(",", ":")) — экранирование `"` и `\`, управляющих символов.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// python `_validate_database` — quick_check, application_id,
/// user_version, catalog_meta и сверка контрольной суммы.
fn validate_database(
    connection: &Connection,
) -> Result<HashMap<String, String>, FakesCatalogError> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| FakesCatalogError(error.to_string()))?;
    if quick_check.to_lowercase() != "ok" {
        return Err(FakesCatalogError(format!(
            "PRAGMA quick_check: {quick_check}"
        )));
    }

    let application_id: i32 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|error| FakesCatalogError(error.to_string()))?;
    if application_id != CATALOG_APPLICATION_ID {
        return Err(FakesCatalogError(format!(
            "неверный application_id: {application_id}, ожидался {CATALOG_APPLICATION_ID}"
        )));
    }

    let user_version: i32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| FakesCatalogError(error.to_string()))?;
    if user_version != CATALOG_SCHEMA_VERSION {
        return Err(FakesCatalogError(format!(
            "неподдерживаемая схема {user_version}, ожидалась {CATALOG_SCHEMA_VERSION}"
        )));
    }

    let mut meta = HashMap::new();
    let mut statement = connection
        .prepare("SELECT key, value FROM catalog_meta")
        .map_err(|error| {
            FakesCatalogError(format!("не удалось прочитать catalog_meta: {error}"))
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| {
            FakesCatalogError(format!("не удалось прочитать catalog_meta: {error}"))
        })?;
    for row in rows {
        let (key, value) = row.map_err(|error| FakesCatalogError(error.to_string()))?;
        meta.insert(key, value);
    }

    if meta.get("schema_version").map(String::as_str) != Some("1") {
        return Err(FakesCatalogError(
            "catalog_meta.schema_version не соответствует PRAGMA user_version".to_string(),
        ));
    }
    if meta.get("catalog_version").is_none_or(String::is_empty) {
        return Err(FakesCatalogError(
            "catalog_meta.catalog_version отсутствует".to_string(),
        ));
    }
    let expected_hash = meta
        .get("content_sha256")
        .map(String::as_str)
        .unwrap_or_default()
        .to_lowercase();
    if expected_hash.len() != 64 || !expected_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FakesCatalogError(
            "catalog_meta.content_sha256 имеет неверный формат".to_string(),
        ));
    }
    let actual_hash = compute_content_sha256(connection)?;
    if actual_hash != expected_hash {
        return Err(FakesCatalogError(
            "логическая контрольная сумма реестра не совпадает с catalog_meta.content_sha256"
                .to_string(),
        ));
    }
    Ok(meta)
}

/// python `read_fakes_catalog` — открыть, проверить и прочитать реестр
/// без кэширования.
pub fn read_fakes_catalog(path: &Path) -> Result<FakesCatalog, FakesCatalogError> {
    if !path.is_file() {
        return Err(FakesCatalogError(format!(
            "файл не найден: {}",
            path.display()
        )));
    }
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| {
            FakesCatalogError(format!(
                "не удалось открыть базу только для чтения: {error}"
            ))
        })?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|error| FakesCatalogError(error.to_string()))?;

    let meta = validate_database(&connection)?;
    let mut entries = Vec::new();
    let mut statement = connection
        .prepare(
            "SELECT name, source_kind, file_name, hex_value, kind, sni, \
             description, same_bytes_as, sort_order FROM fakes ORDER BY sort_order, name",
        )
        .map_err(|error| FakesCatalogError(format!("ошибка чтения SQLite: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|error| FakesCatalogError(format!("ошибка чтения SQLite: {error}")))?;
    for row in rows {
        let (
            name,
            source_kind,
            file_name,
            hex_value,
            kind,
            sni,
            description,
            same_bytes_as,
            sort_order,
        ) = row.map_err(|error| FakesCatalogError(format!("ошибка чтения SQLite: {error}")))?;
        let entry = FakeEntry {
            name,
            source_kind,
            file_name,
            hex_value,
            kind,
            sni,
            description,
            same_bytes_as,
            sort_order,
        };
        entry
            .validate()
            .map_err(|error| FakesCatalogError(format!("неверная запись реестра: {}", error.0)))?;
        entries.push(entry);
    }
    // python: ключи словаря совпадают с именами записей (гарантировано
    // уникальностью PRIMARY KEY).
    let unique: HashMap<&str, &FakeEntry> = entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry))
        .collect();
    if unique.len() != entries.len() {
        return Err(FakesCatalogError(
            "дубликат имени записи реестра".to_string(),
        ));
    }
    Ok(FakesCatalog {
        entries,
        catalog_version: meta.get("catalog_version").cloned().unwrap_or_default(),
        content_sha256: meta.get("content_sha256").cloned().unwrap_or_default(),
    })
}

/// Кэш python `load_fakes_catalog` — по пути и подписи содержимого.
/// Потокобезопасно; работа с диском остаётся у вызывающего потока.
pub struct FakesCatalogCache {
    cache: std::sync::Mutex<Option<CatalogCacheEntry>>,
}

/// Запись кэша: путь, подпись содержимого, проверенный срез.
struct CatalogCacheEntry {
    path: PathBuf,
    signature: (u64, u64),
    catalog: FakesCatalog,
}

impl Default for FakesCatalogCache {
    fn default() -> Self {
        Self {
            cache: std::sync::Mutex::new(None),
        }
    }
}

impl FakesCatalogCache {
    /// python `load_fakes_catalog(path)` — проверенный срез, закэшированный
    /// по пути и содержимому файла.
    pub fn load(&self, path: &Path) -> Result<FakesCatalog, FakesCatalogError> {
        let resolved = path.canonicalize().map_err(|error| {
            FakesCatalogError(format!("файл не найден: {}: {error}", path.display()))
        })?;
        let signature = file_content_signature(&resolved)?;
        let mut cache = self.cache.lock().expect("замок кэша реестра фейков");
        if let Some(entry) = cache.as_ref() {
            if entry.path == resolved && entry.signature == signature {
                return Ok(entry.catalog.clone());
            }
        }
        let catalog = read_fakes_catalog(&resolved)?;
        *cache = Some(CatalogCacheEntry {
            path: resolved,
            signature,
            catalog: catalog.clone(),
        });
        Ok(catalog)
    }

    /// python `invalidate_fakes_catalog_cache`.
    pub fn invalidate(&self) {
        *self.cache.lock().expect("замок кэша реестра фейков") = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Настоящая база из живой установки Zapret (Faugus/proton prefix).
    const REAL_DATABASE: &str =
        "/home/kalinov/Faugus/default/drive_c/Zapret/Dev/system/fakes_catalog.sqlite3";

    #[test]
    fn reads_real_installed_catalog() {
        // Живой прогон по настоящей базе установки: 81 запись,
        // tls_google → @bin/tls_clienthello_www_google_com.bin.
        let catalog = match read_fakes_catalog(Path::new(REAL_DATABASE)) {
            Ok(catalog) => catalog,
            Err(error) => {
                // База может отсутствовать в другой среде — тогда тест
                // считается пройденным только если причина в отсутствии.
                panic!("база установки не читается: {error}");
            }
        };
        assert_eq!(catalog.entries.len(), 81);
        assert!(!catalog.catalog_version.is_empty());
        assert_eq!(catalog.content_sha256.len(), 64);
        let tls_google = catalog.get("tls_google").unwrap();
        assert_eq!(tls_google.source_kind, "file");
        assert_eq!(
            tls_google.file_name.as_deref(),
            Some("tls_clienthello_www_google_com.bin")
        );
        assert_eq!(
            tls_google.blob_value(),
            "@bin/tls_clienthello_www_google_com.bin"
        );
        assert_eq!(
            tls_google.blob_line(),
            "--blob=tls_google:@bin/tls_clienthello_www_google_com.bin"
        );
        // Порядок показа — по sort_order.
        let orders: Vec<i64> = catalog.entries.iter().map(|e| e.sort_order).collect();
        let mut sorted = orders.clone();
        sorted.sort_unstable();
        assert_eq!(orders, sorted);
    }

    #[test]
    fn missing_file_is_error() {
        let error =
            read_fakes_catalog(Path::new("/nonexistent/fakes_catalog.sqlite3")).unwrap_err();
        assert!(error.0.contains("файл не найден"));
    }

    #[test]
    fn validation_rejects_bad_entries() {
        let mut entry = FakeEntry {
            name: "9bad".to_string(),
            source_kind: "file".to_string(),
            file_name: Some("x.bin".to_string()),
            hex_value: None,
            kind: "tls".to_string(),
            sni: None,
            description: String::new(),
            same_bytes_as: None,
            sort_order: 0,
        };
        // python: имя не может начинаться с цифры.
        assert!(entry.validate().is_err());
        entry.name = "ok_name".to_string();
        entry.source_kind = "unknown".to_string();
        assert!(entry.validate().is_err());
        entry.source_kind = "file".to_string();
        entry.file_name = Some("sub/dir.bin".to_string());
        assert!(entry.validate().is_err());
        entry.file_name = Some("ok.bin".to_string());
        assert!(entry.validate().is_ok());
        entry.source_kind = "hex".to_string();
        entry.file_name = None;
        entry.hex_value = Some("0xAB".to_string());
        assert!(entry.validate().is_err());
        entry.hex_value = Some("ABCD".to_string());
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn hex_entry_blob_value() {
        let entry = FakeEntry {
            name: "hex_fake".to_string(),
            source_kind: "hex".to_string(),
            file_name: None,
            hex_value: Some("0011FF".to_string()),
            kind: "other".to_string(),
            sni: None,
            description: String::new(),
            same_bytes_as: None,
            sort_order: 0,
        };
        assert_eq!(entry.blob_value(), "0x0011FF");
        assert_eq!(entry.blob_line(), "--blob=hex_fake:0x0011FF");
    }

    #[test]
    fn json_row_matches_python_json_dumps() {
        // Эталон от python: json.dumps([...], ensure_ascii=False,
        // separators=(",", ":")).
        let row = json_row(
            "имя".to_string(),
            "file".to_string(),
            Some("a\"b.bin".to_string()),
            None,
            "tls".to_string(),
            None,
            "desc".to_string(),
            None,
            5,
        );
        assert_eq!(
            row,
            "[\"имя\",\"file\",\"a\\\"b.bin\",null,\"tls\",null,\"desc\",null,5]"
        );
    }

    #[test]
    fn cache_respects_file_signature() {
        let cache = FakesCatalogCache::default();
        let path = Path::new(REAL_DATABASE);
        let first = cache.load(path).unwrap();
        let second = cache.load(path).unwrap();
        assert_eq!(first, second);
        cache.invalidate();
        let third = cache.load(path).unwrap();
        assert_eq!(first.catalog_version, third.catalog_version);
    }
}

#[cfg(test)]
mod shipped_tests {
    use super::*;

    /// Ресурсы репозитория относительно крейта.
    const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

    /// Вшитый в репозиторий реестр фейков (копия из живой установки)
    /// проходит полную проверку целостности.
    #[test]
    fn shipped_catalog_is_valid() {
        let path = Path::new(RESOURCES).join("system").join("fakes_catalog.sqlite3");
        let catalog = read_fakes_catalog(&path)
            .unwrap_or_else(|error| panic!("вшитый реестр фейков не читается: {error}"));
        assert_eq!(catalog.entries.len(), 81);
        let tls_google = catalog.get("tls_google").unwrap();
        assert_eq!(
            tls_google.blob_line(),
            "--blob=tls_google:@bin/tls_clienthello_www_google_com.bin"
        );
    }
}
