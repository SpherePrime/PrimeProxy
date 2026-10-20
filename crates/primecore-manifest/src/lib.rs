//! Порт `src/primebypass_update/manifest.py` (+ константы проверки источников из
//! `src/primebypass_update/release/signed.py`): подписанный список выпуска.
//!
//! Список называет всё, из чего состоит версия: файлы программы с размером и
//! SHA-256 и установщик. Рядом лежит подпись Ed25519 над точными байтами
//! списка. Программа верит скачанному файлу, только если он есть в списке с
//! верной подписью, — тогда подменённый файл не пройдёт, даже если его
//! отдаёт взломанное зеркало вместе с подходящей контрольной суммой.
//!
//! Порядок проверки (`load_signed`): сначала подпись над байтами — до
//! разбора JSON, — потом продукт, канал и версия. Версия должна быть новее
//! установленной: старый подписанный выпуск нельзя выдать за обновление.
//!
//! Коды ошибок `ManifestError.code` совпадают с Python («format», «sign»,
//! «key», «product», «stale») — их же смотрят логи и API-потребители.
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use thiserror::Error;

/// Схема списка выпуска. Порт `SCHEMA`.
pub const SCHEMA: i64 = 1;
/// Порт `MANIFEST_NAME`.
pub const MANIFEST_NAME: &str = "update-manifest.json";
/// Порт `SIGNATURE_NAME`.
pub const SIGNATURE_NAME: &str = "update-manifest.json.sig";
/// Список выпуска больше этого — не наш список. Порт `MAX_MANIFEST_BYTES`.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// Подпись больше этого — не наша подпись. Порт `MAX_SIGNATURE_BYTES` из signed.py.
pub const MAX_SIGNATURE_BYTES: usize = 1024;
/// Продукт, чьи списки выпуска принимает программа. Порт `signed.PRODUCT`.
/// Имя хранилища сервера (`public/` слаг) — отдельная вещь и не меняется.
pub const PRODUCT: &str = "primebypass";

/// Продукт, под которым сборка публиковала списки до ребрендинга. Живые
/// выпуски Forgejo до сих пор выходят с этим именем, поэтому в переходный
/// период программы принимают и его: `product=zapret-gui` == наш продукт.
pub const LEGACY_PRODUCT: &str = "zapret-gui";

/// Переходное правило: нынешний продукт принимается всегда, а выпуски,
/// подписанные прежним именем, засчитываются как наши.
#[must_use]
pub fn product_accepted(manifest_product: &str, requested: &str) -> bool {
    manifest_product == requested || (requested == PRODUCT && manifest_product == LEGACY_PRODUCT)
}

/// Виды заплаток: `zstd` лежат в поле `patches`, `bsdiff` — в своём поле.
pub const PATCH_KINDS: [&str; 2] = ["zstd", "bsdiff"];

/// Поле списка, где лежат заплатки вида `kind`. Порт `_PATCH_FIELDS`.
#[must_use]
pub fn patch_field(kind: &str) -> &'static str {
    if kind == "bsdiff" {
        "bsdiff"
    } else {
        "patches"
    }
}

/// Список выпуска не годится; `code` — короткая причина для логов.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ManifestError {
    pub code: &'static str,
    pub message: String,
}

impl ManifestError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type ManifestResult<T> = Result<T, ManifestError>;

/// Файл выпуска со своим размером и суммой. Порт `FileEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Размер `<sha256>.zst` в хранилище; 0 — файла в хранилище нет.
    pub zsize: u64,
}

/// Заплатка: новый файл из прежнего. Порт `PatchEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    pub from_sha256: String,
    pub to_sha256: String,
    pub size: u64,
    pub kind: String,
}

/// Установщик. Порт `InstallerEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Проверенный список выпуска. Порт `Manifest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub product: String,
    pub channel: String,
    pub version: String,
    pub created: u64,
    pub key: String,
    pub files: Vec<FileEntry>,
    pub installer: Option<InstallerEntry>,
    pub patches: Vec<PatchEntry>,
}

impl Manifest {
    /// Самая маленькая заплатка от `from` к `to` из видов `kinds`.
    /// Порт `Manifest.patch_for`.
    #[must_use]
    pub fn patch_for(
        &self,
        from_sha256: &str,
        to_sha256: &str,
        kinds: &[&str],
    ) -> Option<&PatchEntry> {
        self.patches
            .iter()
            .filter(|item| {
                item.from_sha256 == from_sha256
                    && item.to_sha256 == to_sha256
                    && kinds.contains(&item.kind.as_str())
            })
            .min_by_key(|item| item.size)
    }
}

/// `\A[0-9a-f]{64}\Z`. Порт `_SHA256_RE` (без депа на regex).
#[must_use]
pub fn is_lower_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `\A\d{1,6}(?:\.\d{1,6}){1,3}\Z`: 2–4 части по 1–6 цифр. Порт `_VERSION_RE`.
#[must_use]
pub fn is_manifest_version(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    (2..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            (1..=6).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// `\A[a-z][a-z0-9-]{0,31}\Z`. Порт `_NAME_RE`.
#[must_use]
pub fn is_manifest_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Версия списка в числовой ключ из четырёх значений, дополненный нулями до
/// четырёх частей (в отличие от updater-версии — хвост не срезается).
/// Порт `manifest.version_key`.
///
/// # Errors
/// «format»-ошибка, если запись версии неверная.
pub fn version_key(version: &str) -> ManifestResult<[u64; 4]> {
    let text = version.trim();
    if !is_manifest_version(text) {
        return Err(ManifestError::new(
            "format",
            format!("неверный номер версии: {version:?}"),
        ));
    }
    let mut key = [0u64; 4];
    for (index, part) in text.split('.').enumerate() {
        // Число из шести цифр всегда помещается в u64.
        key[index] = part.parse::<u64>().map_err(|_| {
            ManifestError::new("format", format!("неверный номер версии: {version:?}"))
        })?;
    }
    Ok(key)
}

/// Сравнение версий в правиле манифеста. Порт `manifest.compare_versions`.
///
/// # Errors
/// «format»-ошибка, если запись версии неверная.
pub fn compare_versions(left: &str, right: &str) -> ManifestResult<Ordering> {
    Ok(version_key(left)?.cmp(&version_key(right)?))
}

fn json_to_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn is_true_int(value: &Value) -> bool {
    if value.is_boolean() {
        return false;
    }
    matches!(value, Value::Number(number) if number.is_u64() || number.is_i64())
}

fn json_size(value: Option<&Value>) -> ManifestResult<u64> {
    match value {
        None => Err(ManifestError::new(
            "format",
            "в списке выпуска неверный размер файла",
        )),
        Some(raw) => {
            if raw.is_boolean() || !raw.is_number() {
                return Err(ManifestError::new(
                    "format",
                    "в списке выпуска неверный размер файла",
                ));
            }
            raw.as_u64().ok_or_else(|| {
                ManifestError::new("format", "в списке выпуска неверный размер файла")
            })
        }
    }
}

fn json_sha(value: Option<&Value>) -> ManifestResult<String> {
    let text = value.map(json_to_text).unwrap_or_default();
    if !is_lower_sha256(&text) {
        return Err(ManifestError::new(
            "format",
            "в списке выпуска неверная контрольная сумма",
        ));
    }
    Ok(text)
}

/// Путь файла внутри папки программы: без выхода наружу и без дисков.
/// Порт `safe_relative_path`.
///
/// # Errors
/// «format»-ошибка для пути с `..`, `.` и пустыми сегментами, `\\`, `:`,
/// абсолютного POSIX-пути или пустого значения.
pub fn safe_relative_path(text: &str) -> ManifestResult<String> {
    let value = text.to_string();
    let this_bad = || {
        ManifestError::new(
            "format",
            format!("в списке выпуска неверный путь файла: {value:?}"),
        )
    };
    if value.is_empty() || value.contains('\\') || value.contains(':') || value.starts_with('/') {
        return Err(this_bad());
    }
    for part in value.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(this_bad());
        }
    }
    Ok(value)
}

fn file_entry(item: &Value) -> ManifestResult<FileEntry> {
    let map = item
        .as_object()
        .ok_or_else(|| ManifestError::new("format", "в списке выпуска неверная запись файла"))?;
    let path = map.get("path").map(json_to_text).unwrap_or_default();
    let path = safe_relative_path(&path)?;
    let size = json_size(map.get("size"))?;
    let sha256 = json_sha(map.get("sha256"))?;
    let zsize = match map.get("zsize") {
        None | Some(Value::Null) => 0,
        Some(value) => json_size(Some(value))?,
    };
    Ok(FileEntry {
        path,
        size,
        sha256,
        zsize,
    })
}

/// Разбор уже проверенного списка: только поля ожидаемого вида.
/// Порт `parse(payload)`.
///
/// # Errors
/// «format»-ошибка для любого неожиданного поля.
pub fn parse(payload: &Value) -> ManifestResult<Manifest> {
    let map = payload
        .as_object()
        .ok_or_else(|| ManifestError::new("format", "список выпуска неизвестного вида"))?;
    if map.get("schema").and_then(Value::as_i64) != Some(SCHEMA) {
        return Err(ManifestError::new(
            "format",
            "список выпуска неизвестного вида",
        ));
    }

    let product = map.get("product").map(json_to_text).unwrap_or_default();
    let channel = map.get("channel").map(json_to_text).unwrap_or_default();
    let key = map.get("key").map(json_to_text).unwrap_or_default();
    if !is_manifest_name(&product) || !is_manifest_name(&channel) || !is_manifest_name(&key) {
        return Err(ManifestError::new(
            "format",
            "в списке выпуска неверный продукт, канал или ключ",
        ));
    }

    let version = map.get("version").map(json_to_text).unwrap_or_default();
    version_key(&version)?;

    let created = match map.get("created") {
        Some(value) if is_true_int(value) => value
            .as_u64()
            .ok_or_else(|| ManifestError::new("format", "в списке выпуска нет времени сборки"))?,
        _ => {
            return Err(ManifestError::new(
                "format",
                "в списке выпуска нет времени сборки",
            ))
        }
    };

    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for item in map
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let entry = file_entry(item)?;
        // Python casefold: для ASCII-путей совпадает с lowercase.
        if !seen.insert(entry.path.to_lowercase()) {
            return Err(ManifestError::new(
                "format",
                format!("файл назван в списке дважды: {}", entry.path),
            ));
        }
        files.push(entry);
    }

    let installer = match map.get("installer") {
        None | Some(Value::Null) => None,
        Some(raw) => {
            let raw = raw.as_object().ok_or_else(|| {
                ManifestError::new("format", "в списке выпуска неверная запись установщика")
            })?;
            let name = raw.get("name").map(json_to_text).unwrap_or_default();
            if name.is_empty()
                || name.contains('/')
                || name.contains('\\')
                || name == "."
                || name == ".."
            {
                return Err(ManifestError::new(
                    "format",
                    "в списке выпуска неверное имя установщика",
                ));
            }
            let size = json_size(raw.get("size"))?;
            let sha256 = json_sha(raw.get("sha256"))?;
            Some(InstallerEntry { name, size, sha256 })
        }
    };

    let targets: HashSet<String> = files.iter().map(|entry| entry.sha256.clone()).collect();

    let mut patches = Vec::new();
    for kind in PATCH_KINDS {
        let field = patch_field(kind);
        for item in map
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let map = item.as_object().ok_or_else(|| {
                ManifestError::new("format", "в списке выпуска неверная запись заплатки")
            })?;
            let item_kind = match map.get("kind") {
                None => kind.to_string(),
                Some(value) => json_to_text(value),
            };
            if item_kind != kind {
                return Err(ManifestError::new(
                    "format",
                    "в списке выпуска неверная запись заплатки",
                ));
            }
            let from_sha256 = json_sha(map.get("from"))?;
            let to_sha256 = json_sha(map.get("to"))?;
            let size = json_size(map.get("size"))?;
            if !targets.contains(&to_sha256) {
                return Err(ManifestError::new(
                    "format",
                    "заплатка ведёт к файлу, которого нет в выпуске",
                ));
            }
            patches.push(PatchEntry {
                from_sha256,
                to_sha256,
                size,
                kind: kind.to_string(),
            });
        }
    }

    Ok(Manifest {
        product,
        channel,
        version,
        created,
        key,
        files,
        installer,
        patches,
    })
}

/// Подпись лежит в файле base64-текстом; ровно 64 байта. Порт `decode_signature`.
///
/// # Errors
/// «sign»-ошибка, если текст не base64 или результат не 64 байта.
pub fn decode_signature(signature: &[u8]) -> ManifestResult<Signature> {
    let text = String::from_utf8_lossy(signature);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|_| ManifestError::new("sign", "подпись списка выпуска повреждена"))?;
    if decoded.len() != 64 {
        return Err(ManifestError::new(
            "sign",
            "подпись списка выпуска повреждена",
        ));
    }
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&decoded);
    Signature::from_slice(&bytes)
        .map_err(|_| ManifestError::new("sign", "подпись списка выпуска повреждена"))
}

static TRUSTED_KEY_MAP: OnceLock<BTreeMap<&'static str, [u8; 32]>> = OnceLock::new();

/// Открытые ключи, которыми подписаны списки выпуска: рабочий и запасной.
/// Порт `signed.PRODUCT` + `signed.TRUSTED_KEYS`.
#[must_use]
pub fn trusted_keys() -> &'static BTreeMap<&'static str, [u8; 32]> {
    TRUSTED_KEY_MAP.get_or_init(|| {
        const WORKING: &str = "EHFnPsESeiNIq28c+jcvmqeClxDTPheSo/NgR+ea+kI=";
        const RESERVE: &str = "c6fNXZOtY5he05hDoxEx9Y7Zkcej0F0MaeE9tekbn1s=";
        let mut map = BTreeMap::new();
        for (id, encoded) in [("gui-2026a", WORKING), ("gui-reserve-1", RESERVE)] {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("тривиальный base64 вшитого ключа");
            let mut public = [0u8; 32];
            public.copy_from_slice(&raw);
            map.insert(id, public);
        }
        map
    })
}

fn verify_with_key(public_key: &[u8; 32], signature: &Signature, raw: &[u8]) -> bool {
    if raw.len() > MAX_MANIFEST_BYTES {
        return false;
    }
    let key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    key.verify(raw, signature).is_ok()
}

/// Каким из доверенных ключей подписан список; ошибка, если ни одним.
/// Порт `signing_key_id`. Передай `Some(&map)`, чтобы проверить свои ключи.
///
/// # Errors
/// «format», если список слишком велик; «sign», если подпись не сошлась.
pub fn signing_key_id(
    raw: &[u8],
    signature: &[u8],
    trusted: Option<&BTreeMap<&'static str, Vec<u8>>>,
) -> ManifestResult<String> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::new("format", "список выпуска слишком велик"));
    }
    let signed = decode_signature(signature)?;
    let acceptable: &[(&&str, [u8; 32])] = match trusted {
        Some(custom) => &custom
            .iter()
            .filter_map(|(id, bytes)| {
                <[u8; 32]>::try_from(bytes.as_slice())
                    .ok()
                    .map(|key| (id, key))
            })
            .collect::<Vec<_>>(),
        None => &trusted_keys()
            .iter()
            .map(|(id, key)| (id, *key))
            .collect::<Vec<_>>(),
    };
    for (key_id, public_key) in acceptable {
        if verify_with_key(public_key, &signed, raw) {
            return Ok((**key_id).to_string());
        }
    }
    Err(ManifestError::new(
        "sign",
        "подпись списка выпуска не сошлась",
    ))
}

/// Проверенный список выпуска. Порт `load_signed`.
///
/// `newer_than` — установленная версия: список должен быть новее
/// (`allow_same` — ровно та же версия, для починки установки).
///
/// # Errors
/// Порядок кодов повторяет Python: «sign», «format» (JSON), «key»,
/// «product», «stale».
pub fn load_signed(
    raw: &[u8],
    signature: &[u8],
    trusted: Option<&BTreeMap<&'static str, Vec<u8>>>,
    product: &str,
    channel: &str,
    newer_than: &str,
    allow_same: bool,
) -> ManifestResult<Manifest> {
    let key_id = signing_key_id(raw, signature, trusted)?;
    let payload: Value = serde_json::from_slice(raw).map_err(|error| {
        ManifestError::new("format", format!("список выпуска не читается: {error}"))
    })?;
    let manifest = parse(&payload)?;
    if manifest.key != key_id {
        // Подпись верна, но список называет другой ключ: так не бывает у
        // честной сборки — значит, список собран не нашим инструментом.
        return Err(ManifestError::new(
            "key",
            "список выпуска подписан не тем ключом, что в нём назван",
        ));
    }
    if manifest.channel != channel || !product_accepted(&manifest.product, product) {
        return Err(ManifestError::new(
            "product",
            format!(
                "список выпуска для {}/{}, а нужен {}/{}",
                manifest.product, manifest.channel, product, channel
            ),
        ));
    }
    if !newer_than.is_empty() {
        let gap = compare_versions(&manifest.version, newer_than)?;
        if gap == Ordering::Less || (gap == Ordering::Equal && !allow_same) {
            return Err(ManifestError::new(
                "stale",
                format!(
                    "версия {} не новее установленной {}",
                    manifest.version, newer_than
                ),
            ));
        }
    }
    Ok(manifest)
}

/// Байты списка: одинаковые при одинаковом содержании.
///
/// Порт `dumps(payload)`: `json.dumps(payload, ensure_ascii=False,
/// sort_keys=True, indent=1)` + `\n`. Ключи канонической формы сортируются
/// байтом, поэтому явная сортировка вместо порядка карты.
#[must_use]
pub fn canonical_bytes(payload: &Value) -> String {
    let mut out = String::new();
    write_canonical(&mut out, payload, 0);
    out.push('\n');
    out
}

/// Ключи канонической формы в порядке python `sorted`.
fn canonical_object_keys(map: &serde_json::Map<String, Value>) -> Vec<(String, Value)> {
    let mut entries: Vec<(String, Value)> = map
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    entries
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push(' ');
    }
}

fn write_canonical(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => {
            // serde_json выпускает строку с экранированием как в Python:
            // \\, \", \n, \t, \r, \b, \f и остальные <0x20 через \u00XX.
            out.push_str(&serde_json::to_string(text).unwrap_or_default());
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                indent(out, depth + 1);
                write_canonical(out, item, depth + 1);
            }
            out.push('\n');
            indent(out, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (index, (key, item)) in canonical_object_keys(map).iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                indent(out, depth + 1);
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push_str(": ");
                write_canonical(out, item, depth + 1);
            }
            out.push('\n');
            indent(out, depth);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};

    fn repeat64(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn sample_payload() -> Value {
        serde_json::json!({
            "schema": 1,
            "product": "primebypass",
            "channel": "stable",
            "version": "21.1.2.3",
            "created": 1_700_000_000u64,
            "key": "gui-2026a",
            "files": [
                {"path": "cfg.txt", "size": 4, "sha256": repeat64('f')}
            ],
            "installer": {
                "name": "PrimeBypassSetup.exe",
                "size": 9,
                "sha256": repeat64('e')
            }
        })
    }

    fn signed_with(payload: &Value, key: &SigningKey) -> (Vec<u8>, Vec<u8>) {
        let raw = canonical_bytes(payload).into_bytes();
        let signature = key.sign(&raw);
        let signature = B64.encode(signature.to_bytes());
        (raw, signature.into_bytes())
    }

    #[test]
    fn truncates_and_validates_names() {
        assert!(is_manifest_name("gui-2026a"));
        assert!(is_manifest_name("a"));
        assert!(!is_manifest_name(""));
        assert!(!is_manifest_name("1bad"));
        assert!(!is_manifest_name("has space"));
        assert!(&!is_manifest_name(&"a".repeat(33)));
        assert!(is_manifest_name(&"a".repeat(32)));
    }

    #[test]
    fn manifest_version_rules() {
        assert!(is_manifest_version("21.1"));
        assert!(is_manifest_version("21.1.2.3"));
        assert!(!is_manifest_version("21"));
        assert!(!is_manifest_version("21.1.2.3.4"));
        assert!(!is_manifest_version("21.1234567890"));
        assert!(!is_manifest_version("v21.2"));
        assert_eq!(version_key("21.1.2.3").unwrap(), [21, 1, 2, 3]);
        assert_eq!(version_key("21.1").unwrap(), [21, 1, 0, 0]);
        assert_eq!(version_key("1x.2").err().unwrap().code, "format");
    }

    #[test]
    fn canonical_bytes_match_python_dumps() {
        // Ожидание получено из Python:
        // json.dumps({...}, ensure_ascii=False, sort_keys=True, indent=1) + "\n".
        let value = serde_json::json!({
            "b": 1,
            "a": [{"z": true, "y": null}, "текст\"скоб"],
        });
        let expected = "{\n \"a\": [\n  {\n   \"y\": null,\n   \"z\": true\n  },\n  \"текст\\\"скоб\"\n ],\n \"b\": 1\n}\n";
        assert_eq!(canonical_bytes(&value), expected);
    }

    #[test]
    fn parse_ok_and_patch_lookup() {
        let payload = serde_json::json!({
            "schema": 1,
            "product": "primebypass",
            "channel": "stable",
            "version": "21.1.2.3",
            "created": 17u64,
            "key": "gui-2026a",
            "files": [
                {"path": "_internal/settings.yml", "size": 4, "sha256": repeat64('b'), "zsize": 2}
            ],
            "installer": {"name": "PrimeBypassSetup.exe", "size": 7, "sha256": repeat64('c')},
            "patches": [
                {"from": repeat64('a'), "to": repeat64('b'), "size": 5}
            ],
            "bsdiff": [
                {"from": repeat64('a'), "to": repeat64('b'), "size": 1}
            ]
        });
        let manifest = parse(&payload).map_err(|error| format!("{error}")).unwrap();
        assert_eq!(manifest.version, "21.1.2.3");
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(
            manifest.installer.as_ref().unwrap().name,
            "PrimeBypassSetup.exe"
        );
        let kinds = ["zstd", "bsdiff"];
        let patch = manifest
            .patch_for(&repeat64('a'), &repeat64('b'), &kinds)
            .unwrap();
        // Самая маленькая заплатка — bsdiff размером 1.
        assert_eq!(patch.size, 1);
        assert_eq!(
            parse(&serde_json::json!({"schema": 3})).err().unwrap().code,
            "format"
        );
    }

    #[test]
    fn parse_error_codes_match_python() {
        let cases: [(Value, &str); 6] = [
            (serde_json::json!({"schema": 2}), "format"),
            (
                serde_json::json!({"schema": 1, "product": "Bad_Name", "channel": "stable",
                    "key": "k1", "version": "1.2", "created": 1, "files": []}),
                "format",
            ),
            (
                serde_json::json!({"schema": 1, "product": "p", "channel": "dev", "key": "k1",
                    "version": "1.2.3.4.5", "created": 1, "files": []}),
                "format",
            ),
            (
                serde_json::json!({"schema": 1, "product": "p", "channel": "dev", "key": "k1",
                    "version": "1.2", "created": 1,
                    "files": [{"path": "a/b.txt", "size": 1, "sha256": repeat64('a')}],
                    "patches": [{"from": repeat64('b'), "to": repeat64('c'), "size": 3}]}),
                "format",
            ),
            (
                serde_json::json!({"schema": 1, "product": "p", "channel": "dev", "key": "k1",
                    "version": "1.2", "created": 1,
                    "files": [{"path": "../secret.txt", "size": 1, "sha256": repeat64('a')}]}),
                "format",
            ),
            (
                serde_json::json!({"schema": 1, "product": "p", "channel": "dev", "key": "k1",
                    "version": "1.2", "created": -1, "files": []}),
                "format",
            ),
        ];
        for (payload, code) in cases {
            assert_eq!(parse(&payload).err().unwrap().code, code);
        }
        assert_eq!(
            safe_relative_path("C:/WINDOWS/x").err().unwrap().code,
            "format"
        );
        assert_eq!(
            safe_relative_path("a/…/b") /* unicode ok, parts fine */
                .unwrap(),
            "a/…/b"
        );
        assert!(safe_relative_path(props_empty_path()).is_err());
    }

    fn props_empty_path() -> &'static str {
        ""
    }

    #[test]
    fn load_signed_follows_python_order() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (raw, signature) = signed_with(&sample_payload(), &key);

        // Нет доверенных ключей, подпись «не сошлась».
        let result = load_signed(&raw, &signature, None, "primebypass", "stable", "", false);
        assert_eq!(result.err().unwrap().code, "sign");

        let mut custom = BTreeMap::new();
        custom.insert("test-key-a", key.verifying_key().as_bytes().to_vec());

        // Подпись верна, но список называет имя другого ключа → «key»
        // (имя «gui-b-2026a» проходит формат: маленькая буква, буквы и тире).
        let mut renamed = sample_payload();
        renamed["key"] = Value::String("gui-b-2026a".into());
        let (renamed_raw, renamed_signature) = signed_with(&renamed, &key);
        let result = load_signed(
            &renamed_raw,
            &renamed_signature,
            Some(&custom),
            "primebypass",
            "stable",
            "",
            false,
        );
        assert_eq!(result.err().unwrap().code, "key");

        // Ровно та же версия → «stale» (без allow_same), ок с allow_same.
        let mut same = sample_payload();
        same["key"] = Value::String("test-key-a".into());
        same["version"] = Value::String("0.0.1.9".into());
        let (raw9, signature9) = signed_with(&same, &key);
        let result = load_signed(
            &raw9,
            &signature9,
            Some(&custom),
            "primebypass",
            "stable",
            "0.0.1.9",
            false,
        );
        assert_eq!(result.err().unwrap().code, "stale");
        let result = load_signed(
            &raw9,
            &signature9,
            Some(&custom),
            "primebypass",
            "stable",
            "0.0.1.9",
            true,
        );
        assert!(result.is_ok());

        // Продукт/канал чужие.
        let result = load_signed(
            &raw9,
            &signature9,
            Some(&custom),
            "zapret-gui",
            "dev",
            "",
            false,
        );
        assert_eq!(result.err().unwrap().code, "product");

        // Повреждённая подпись перепутана с любым ключом цикла → «sign».
        let mut spoiled = signature9.clone();
        spoiled[0] ^= 0x40;
        let result = load_signed(
            &raw9,
            &spoiled,
            Some(&custom),
            "primebypass",
            "stable",
            "",
            false,
        );
        assert_eq!(result.err().unwrap().code, "sign");
    }

    #[test]
    fn signature_decoding_strict() {
        assert_eq!(decode_signature(b"not base64!").err().unwrap().code, "sign");
        let short = B64.encode([1u8; 31]);
        assert_eq!(
            decode_signature(short.as_bytes()).err().unwrap().code,
            "sign"
        );
        let odd = B64.encode([1u8; 63]);
        assert_eq!(decode_signature(odd.as_bytes()).err().unwrap().code, "sign");
    }

    #[test]
    fn trusted_keys_embedded_once() {
        assert_eq!(trusted_keys().len(), 2);
        assert!(trusted_keys().contains_key("gui-2026a"));
        assert!(trusted_keys().contains_key("gui-reserve-1"));
        assert_eq!(PRODUCT, "primebypass");
        // Переходный период: живые сборки ещё публикуются как zapret-gui.
        assert!(product_accepted("zapret-gui", PRODUCT));
        assert!(product_accepted("primebypass", PRODUCT));
        assert!(!product_accepted("primebypass", "zapret-gui"));
        assert!(!product_accepted("zapret-gui", "dev"));
    }
}
