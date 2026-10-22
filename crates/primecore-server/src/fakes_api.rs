//! Реестр фейков winws2 (страница «Фейки»): перечисление записей каталога
//! `resources/system/fakes_catalog.sqlite3` через крейт [`primecore_fakes`].
//!
//! Страница только читает: фейки — заготовки пакетов для стратегий DESYNC,
//! пресеты подключают их сами через `--blob=`; пользовательский список
//! и редактирование — вне этого среза.

use axum::http::StatusCode;
use axum::Json;
use primecore_fakes::catalog::{FakeEntry, FakesCatalogCache};
use serde_json::{json, Value};

use crate::ws_api::resources_dir;

/// Кэш каталога (как в крейте: пересборка только по смене сигнатуры файла).
static CACHE: std::sync::LazyLock<FakesCatalogCache> =
    std::sync::LazyLock::new(FakesCatalogCache::default);

/// Путь к базе каталога из каталога ресурсов.
fn catalog_path(resources: &str) -> std::path::PathBuf {
    std::path::Path::new(resources)
        .join("system")
        .join("fakes_catalog.sqlite3")
}

/// SHA-256 содержимого фейка (из hex-значения каталога).
fn entry_sha256(entry: &FakeEntry) -> String {
    use sha2::{Digest, Sha256};
    let Some(hex) = entry.hex_value.as_deref() else {
        return String::new();
    };
    let bytes = decode_hex(hex);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hex-строку в байты (не-пары символов пропускаются — каталог валиден).
fn decode_hex(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let digits: Vec<u8> = hex
        .as_bytes()
        .iter()
        .filter_map(|byte| (*byte as char).to_digit(16).map(|digit| digit as u8))
        .collect();
    for pair in digits.chunks(2) {
        let high = pair[0];
        let low = pair.get(1).copied().unwrap_or(0);
        bytes.push((high << 4) | low);
    }
    bytes
}

/// JSON одной записи каталога (поля страницы «Фейки»).
fn entry_json(entry: &FakeEntry) -> Value {
    json!({
        "name": entry.name,
        "kind": entry.kind,
        "sni": entry.sni,
        "description": entry.description,
        "source_kind": entry.source_kind,
        "size": entry.hex_value.as_ref().map_or(0, |hex| hex.len() / 2),
        "same_bytes_as": entry.same_bytes_as,
        "sort_order": entry.sort_order,
        "sha256": entry_sha256(entry),
    })
}

/// Загрузка каталога с ошибкой-ответом.
fn load_catalog(
    resources: &str,
) -> Result<primecore_fakes::catalog::FakesCatalog, (StatusCode, Json<Value>)> {
    CACHE.load(&catalog_path(resources)).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("каталог фейков не читается: {error}")})),
        )
    })
}

/// GET /api/fakes — весь каталог фейков.
pub async fn fakes() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let catalog = load_catalog(&resources_dir())?;
    let fakes: Vec<Value> = catalog.entries.iter().map(entry_json).collect();
    Ok(Json(json!({"fakes": fakes, "total": fakes.len()})))
}

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resources_dir() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../resources")
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn catalog_lists_builtin_entries() {
        let catalog = CACHE
            .load(&catalog_path(&resources_dir()))
            .expect("встроенный каталог читается");
        assert!(catalog.len() >= 80, "в каталоге меньше 80 записей");
        // Разные kind присутствуют (TLS-фейки, QUIC и прочие).
        let kinds: std::collections::BTreeSet<&str> =
            catalog.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.len() >= 2, "ожидались разные kind: {kinds:?}");
    }

    #[test]
    fn entry_json_has_page_fields() {
        let catalog = CACHE
            .load(&catalog_path(&resources_dir()))
            .expect("встроенный каталог читается");
        let entry = &catalog.entries[0];
        let value = entry_json(entry);
        assert_eq!(value["name"], json!(entry.name));
        assert_eq!(value["kind"], json!(entry.kind));
        assert!(value["size"].is_u64());
    }
}
