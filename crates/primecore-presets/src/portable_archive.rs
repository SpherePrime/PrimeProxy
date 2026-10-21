//! Порт `presets/portable_archive.py` — переносимый ZIP-архив пресета и его
//! пользовательских списков.
//!
//! Экспорт: пресет без своих списков уезжает plain TXT; пресет со списками —
//! ZIP (manifest.json + preset.txt + lists/<файл>, с контрольными суммами).
//! Импорт: списки с занятыми именами переименовываются (`lists/<имя>` в
//! пресете переписывается — `preset_contract`, пункт 4), системные
//! (overlay) списки сливаются с user-слоём.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use primecore_lists::layered::{
    delete_profile_user_list_file, layered_list_file, safe_list_file_name,
    validate_profile_list_file_text, write_profile_user_list_text, LayeredListFile,
};
use primecore_lists::winpath::PureWinPath;
use primecore_profile::parser::parse_preset_text;
use regex::Regex;
use serde_json::json;

use crate::errors::{PresetError, PresetResult};
use crate::file_service::PresetBackend;
use crate::preset_text_ops::{rewrite_preset_headers, validate_preset_source_text};
use crate::zipio::{self, ZipEntry};
use crate::PresetManifest;

pub const ARCHIVE_FORMAT: &str = "primebypass-portable-preset";
pub const ARCHIVE_VERSION: u32 = 1;
const MANIFEST_PATH: &str = "manifest.json";
const PRESET_PATH: &str = "preset.txt";
const MAX_ARCHIVE_MEMBER_SIZE: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_SIZE: u64 = 128 * 1024 * 1024;

/// python `_LIST_OPTION_KINDS`: опция пресета → вид файла списка.
pub const LIST_OPTION_KINDS: [(&str, &str); 4] = [
    ("--hostlist", "hostlist"),
    ("--hostlist-exclude", "hostlist"),
    ("--ipset", "ipset"),
    ("--ipset-exclude", "ipset"),
];

// python `_INLINE_OPTION_SPLIT_KEEP_RE` проверяется вручную в
// `line_option_pieces` (см. комментарий там).

fn list_line_regex() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)^(?P<indent>\s*)(?P<option>--(?:hostlist|hostlist-exclude|ipset|ipset-exclude))\s*=\s*(?P<value>.*?)(?P<trailing>\s*)$",
        )
        .expect("regexp")
    });
    &RE
}

/// Список внутри архива: имя, вид, текст и признак «поверх системного».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableListFile {
    pub file_name: String,
    pub kind: String,
    pub text: String,
    pub storage: String,
}

/// Итог экспорта: plain TXT без списков или ZIP-архив.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetExportResult {
    pub path: PathBuf,
    pub archived_list_files: Vec<String>,
}

impl PresetExportResult {
    /// python-свойство `is_archive`.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        !self.archived_list_files.is_empty()
    }
}

/// Итог импорта архива (или TXT-импорта без списков).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetImportResult {
    pub manifest: PresetManifest,
    pub imported_list_files: Vec<String>,
    /// (прежнее имя списка, новое имя) — при коллизии имён.
    pub renamed_list_files: Vec<(String, String)>,
}

impl PresetImportResult {
    /// python-свойство `file_name`.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.manifest.file_name
    }

    /// python-свойство `name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// python-свойство `updated_at`.
    #[must_use]
    pub fn updated_at(&self) -> &str {
        &self.manifest.updated_at
    }

    /// python-свойство `kind`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.manifest.kind
    }

    /// python-свойство `storage_scope`.
    #[must_use]
    pub fn storage_scope(&self) -> &str {
        &self.manifest.storage_scope
    }
}

/// python `export_preset_with_lists`: экспорт пресета и его списков.
pub fn export_preset_with_lists(
    backend: &impl PresetBackend,
    file_name: &str,
    dest_path: &Path,
) -> PresetResult<PresetExportResult> {
    let source_text = backend.read_source_text_by_file_name(file_name)?;
    let lists_root = backend.app_paths().user_root.join("lists");
    let list_files = collect_portable_list_files(&source_text, backend.engine(), &lists_root)?;
    if list_files.is_empty() {
        let destination = dest_path.to_path_buf();
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|error| PresetError(error.to_string()))?;
        }
        std::fs::write(&destination, with_final_newline(&source_text).as_bytes())
            .map_err(|error| PresetError(error.to_string()))?;
        return Ok(PresetExportResult {
            path: destination,
            archived_list_files: Vec::new(),
        });
    }

    let destination = if dest_path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        dest_path.to_path_buf()
    } else {
        with_suffix(dest_path, "zip")
    };
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| PresetError(error.to_string()))?;
    }
    let engine = backend.engine().trim().to_lowercase();
    let manifest = json!({
        "format": ARCHIVE_FORMAT,
        "version": ARCHIVE_VERSION,
        "engine": engine,
        "preset_file_name": file_name.trim(),
        "lists": list_files.iter().map(|item| json!({
            "file_name": item.file_name,
            "kind": item.kind,
            "storage": item.storage,
            "archive_path": format!("lists/{}", item.file_name),
            "sha256": sha256_text(&item.text),
        })).collect::<Vec<_>>(),
    });
    let manifest_text =
        serde_json::to_string_pretty(&manifest).map_err(|error| PresetError(error.to_string()))?;
    let mut entries = vec![
        ZipEntry {
            name: MANIFEST_PATH.to_string(),
            data: manifest_text.into_bytes(),
        },
        ZipEntry {
            name: PRESET_PATH.to_string(),
            data: with_final_newline(&source_text).into_bytes(),
        },
    ];
    for item in &list_files {
        entries.push(ZipEntry {
            name: format!("lists/{}", item.file_name),
            data: with_final_newline(&item.text).into_bytes(),
        });
    }
    zipio::write_archive(&destination, &entries).map_err(|error| PresetError(error.to_string()))?;
    Ok(PresetExportResult {
        archived_list_files: list_files
            .iter()
            .map(|item| item.file_name.clone())
            .collect(),
        path: destination,
    })
}

/// python `import_portable_preset`: импорт архива с пресетом и списками.
pub fn import_portable_preset(
    backend: &impl PresetBackend,
    src_path: &Path,
    name: &str,
) -> PresetResult<PresetImportResult> {
    let (source_text, list_files) = read_portable_archive(src_path, backend.engine())?;
    let referenced_kinds = referenced_list_kinds(&source_text, backend.engine())?;
    for item in &list_files {
        let key = item.file_name.to_lowercase();
        let referenced = referenced_kinds
            .iter()
            .find(|(referenced_key, _)| *referenced_key == key)
            .map(|(_, kind)| kind.as_str());
        if referenced != Some(item.kind.as_str()) {
            return Err(PresetError(format!(
                "ZIP содержит lists/{}, но пресет не ссылается на него как на {}.",
                item.file_name, item.kind
            )));
        }
    }
    let preset_name = {
        // python: str(name or Path(src).stem or "Imported").strip() or "Imported".
        let stem = crate::file_store::stem_of(
            &src_path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default(),
        );
        let candidate = if name.trim().is_empty() && !stem.is_empty() {
            stem
        } else {
            name.trim().to_string()
        };
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            "Imported".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let preset_name = crate::preset_file_ops::unique_preset_name(backend, &preset_name, None)?;
    let lists_root = backend.app_paths().user_root.join("lists");
    let (replacements, writes) = plan_list_imports(&lists_root, &list_files)?;
    let mut rewritten = rewrite_list_file_references(&source_text, &replacements);
    if let Err(error) = validate_preset_source_text(&rewritten, backend.engine()) {
        return Err(PresetError(format!(
            "Архив содержит неверный пресет: {error}"
        )));
    }
    rewritten = rewrite_preset_headers(&rewritten, &preset_name, Some("imported"));

    // Откат: если пресет записать не удалось, user-слои списков
    // возвращаются в прежнее состояние.
    let mut backups: Vec<(String, bool, String)> = Vec::new();
    let imported = (|| -> PresetResult<PresetManifest> {
        for (file_name, text) in &writes {
            let paths = layered_list_file(&lists_root, file_name).map_err(PresetError)?;
            let existed = paths.user_path.is_file();
            let previous = if existed {
                read_lossy(&paths.user_path)
            } else {
                String::new()
            };
            backups.push((file_name.clone(), existed, previous));
            write_profile_user_list_text(&lists_root, file_name, text);
        }

        let rewritten = backend.normalize_source_text(&rewritten);
        backend.preset_file_store().create_preset(
            backend.engine(),
            &preset_name,
            &rewritten,
            "imported",
        )
    })();
    let imported = match imported {
        Ok(imported) => imported,
        Err(error) => {
            restore_user_lists(&lists_root, &backups);
            return Err(error);
        }
    };

    backend.delete_folder_item_meta(
        crate::preset_file_ops::folder_scope_key(backend),
        &imported.file_name,
    );
    backend.notify_presets_changed();
    Ok(PresetImportResult {
        imported_list_files: list_files
            .iter()
            .map(|item| item.file_name.clone())
            .collect(),
        renamed_list_files: replacements
            .iter()
            .filter(|(old_name, new_name)| old_name.to_lowercase() != new_name.to_lowercase())
            .cloned()
            .collect(),
        manifest: imported,
    })
}

/// python `collect_portable_list_files`: файлы списков, на которые ссылается
/// пресет и которые реально есть в слоях lists_root.
pub fn collect_portable_list_files(
    source_text: &str,
    engine: &str,
    lists_root: &Path,
) -> PresetResult<Vec<PortableListFile>> {
    let references = referenced_list_kinds(source_text, engine)?;
    let mut result: Vec<PortableListFile> = Vec::new();
    for (key, kind) in references {
        let own_name = reference_file_name(source_text, &key);
        let file_name = if own_name.is_empty() {
            key.clone()
        } else {
            own_name
        };
        let paths = layered_list_file(lists_root, &file_name).map_err(PresetError)?;
        if paths.user_path.is_file() {
            let text = read_lossy(&paths.user_path);
            if !text.trim().is_empty() {
                validate_exported_list_file(&file_name, &kind, &text)?;
                result.push(PortableListFile {
                    storage: if paths.base_path.is_file() {
                        "overlay".to_string()
                    } else {
                        "standalone".to_string()
                    },
                    file_name,
                    kind,
                    text: with_final_newline(&text),
                });
                continue;
            }
        }
        if paths.base_path.is_file() {
            continue;
        }
        if paths.final_path.is_file() {
            let text = read_lossy(&paths.final_path);
            if !text.trim().is_empty() {
                validate_exported_list_file(&file_name, &kind, &text)?;
                result.push(PortableListFile {
                    storage: "standalone".to_string(),
                    file_name,
                    kind,
                    text: with_final_newline(&text),
                });
                continue;
            }
        }
        return Err(PresetError(
            "Пресет ссылается на lists/{file_name}, но этого файла нет. Исправьте список перед экспортом."
                .replace("{file_name}", &file_name),
        ));
    }
    Ok(result)
}

/// python `_referenced_list_kinds`: ключ — имя файла в нижнем регистре,
/// значение — вид (`hostlist`/`ipset`). Один файл в двух видах — ошибка.
pub fn referenced_list_kinds(
    source_text: &str,
    engine: &str,
) -> PresetResult<Vec<(String, String)>> {
    let preset = parse_preset_text(source_text, engine, "portable_export").map_err(PresetError)?;
    let mut references: Vec<(String, String)> = Vec::new();
    let push =
        |file_name: &str, kind: &str, references: &mut Vec<(String, String)>| -> PresetResult<()> {
            let key = file_name.to_lowercase();
            if let Some((_, previous)) = references.iter().find(|(existing, _)| *existing == key) {
                if previous != kind {
                    return Err(PresetError(format!(
                        "Файл lists/{file_name} одновременно используется как hostlist и ipset."
                    )));
                }
                return Ok(());
            }
            references.push((key, kind.to_string()));
            Ok(())
        };
    for profile in &preset.profiles {
        for segment in &profile.segments {
            let option = segment.name.trim().to_lowercase();
            let Some((_, kind)) = LIST_OPTION_KINDS.iter().find(|(name, _)| *name == option) else {
                continue;
            };
            for file_name in list_file_names_from_value(&segment.value) {
                push(&file_name, kind, &mut references)?;
            }
        }
    }
    Ok(references)
}

/// python-правдивость значения JSON (python `bool(...)`).
fn json_value_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(items) => !items.is_empty(),
    }
}

/// python `_validate_exported_list_file`: первая неверная запись списка —
/// ошибка экспорта/импорта.
fn validate_exported_list_file(file_name: &str, kind: &str, text: &str) -> PresetResult<()> {
    let invalid = validate_profile_list_file_text(kind, text);
    if invalid.is_empty() {
        return Ok(());
    }
    let (line, value) = &invalid[0];
    Err(PresetError(format!(
        "В lists/{file_name}, строка {line}, неверная запись `{value}`."
    )))
}

/// python `_read_portable_archive`: разбор и проверка архива.
fn read_portable_archive(
    path: &Path,
    expected_engine: &str,
) -> PresetResult<(String, Vec<PortableListFile>)> {
    if !zipio::is_zip_archive(path) {
        return Err(PresetError(
            "Файл ZIP повреждён или не является архивом пресета PrimeBypass.".to_string(),
        ));
    }
    let entries = zipio::read_archive(path).map_err(|error| {
        if error.0.contains("Duplicate name") {
            PresetError("В ZIP есть повторяющиеся имена файлов.".to_string())
        } else {
            PresetError(
                "Файл ZIP повреждён или не является архивом пресета PrimeBypass.".to_string(),
            )
        }
    })?;
    let total_size: u64 = entries.iter().map(|entry| entry.data.len() as u64).sum();
    if total_size > MAX_ARCHIVE_TOTAL_SIZE
        || entries
            .iter()
            .any(|entry| entry.data.len() as u64 > MAX_ARCHIVE_MEMBER_SIZE)
    {
        return Err(PresetError("Архив пресета слишком большой.".to_string()));
    }

    let manifest_bytes = zipio::read_entry(&entries, MANIFEST_PATH)
        .ok_or_else(|| PresetError("В ZIP нет manifest.json или preset.txt.".to_string()))?;
    let preset_bytes = zipio::read_entry(&entries, PRESET_PATH)
        .ok_or_else(|| PresetError("В ZIP нет manifest.json или preset.txt.".to_string()))?;
    let source_text = String::from_utf8(preset_bytes.to_vec()).map_err(|_| {
        PresetError("Не удалось прочитать описание ZIP-архива пресета.".to_string())
    })?;
    let manifest_value: serde_json::Value =
        serde_json::from_slice(manifest_bytes).map_err(|_| {
            PresetError("Не удалось прочитать описание ZIP-архива пресета.".to_string())
        })?;
    if !manifest_value.is_object() {
        return Err(PresetError("В ZIP повреждён manifest.json.".to_string()));
    }

    // python: int(manifest.get("version") or 0) с int()-семантикой:
    // числа усекаются, строки-числа разбираются, пустые/false/пустые
    // контейнеры дают 0.
    let archive_version = match manifest_value.get("version") {
        None | Some(serde_json::Value::Null) => 0i64,
        Some(serde_json::Value::Number(number)) => number
            .as_f64()
            .map(|value| value.trunc() as i64)
            .unwrap_or(0),
        Some(serde_json::Value::Bool(value)) => i64::from(*value),
        Some(serde_json::Value::String(text)) if text.is_empty() => 0,
        Some(serde_json::Value::String(text)) => text
            .trim()
            .parse::<i64>()
            .map_err(|_| PresetError("В ZIP неверная версия формата пресета.".to_string()))?,
        Some(serde_json::Value::Array(items)) if items.is_empty() => 0,
        Some(serde_json::Value::Object(items)) if items.is_empty() => 0,
        Some(_) => {
            return Err(PresetError(
                "В ZIP неверная версия формата пресета.".to_string(),
            ));
        }
    };
    let format = manifest_value
        .get("format")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if format != ARCHIVE_FORMAT || archive_version != i64::from(ARCHIVE_VERSION) {
        return Err(PresetError(
            "Этот ZIP имеет неизвестный формат пресета PrimeBypass.".to_string(),
        ));
    }
    let archive_engine = manifest_value
        .get("engine")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if archive_engine != expected_engine.trim().to_lowercase() {
        return Err(PresetError(
            "Архив создан для другого режима Zapret.".to_string(),
        ));
    }

    // python: manifest.get("lists") or [] — пустые/falsy значения дают
    // пустой список, остальные не-массивы — ошибка.
    static EMPTY_LISTS: once_cell::sync::Lazy<Vec<serde_json::Value>> =
        once_cell::sync::Lazy::new(Vec::new);
    let raw_lists = match manifest_value.get("lists") {
        None => &*EMPTY_LISTS,
        Some(serde_json::Value::Array(items)) => items,
        Some(value) if json_value_truthy(value) => {
            return Err(PresetError(
                "В описании ZIP повреждён список файлов.".to_string(),
            ));
        }
        Some(_) => &*EMPTY_LISTS,
    };
    let mut list_files: Vec<PortableListFile> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in raw_lists {
        let Some(raw) = raw.as_object() else {
            return Err(PresetError(
                "В описании ZIP повреждён список файлов.".to_string(),
            ));
        };
        let raw_file_name = raw
            .get("file_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let file_name = match safe_list_file_name(raw_file_name) {
            Some(name) => name,
            None => {
                return Err(PresetError(
                    "В ZIP найдено небезопасное имя файла списка.".to_string(),
                ));
            }
        };
        let kind = raw
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let storage = raw
            .get("storage")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let archive_path = raw
            .get("archive_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .replace('\\', "/")
            .trim()
            .to_string();
        if archive_path != format!("lists/{file_name}") || (kind != "hostlist" && kind != "ipset") {
            return Err(PresetError(
                "В ZIP найдено небезопасное имя файла списка.".to_string(),
            ));
        }
        if (storage != "overlay" && storage != "standalone")
            || seen.contains(&file_name.to_lowercase())
        {
            return Err(PresetError(
                "В ZIP повреждено описание файла списка.".to_string(),
            ));
        }
        seen.insert(file_name.to_lowercase());
        let Some(text_bytes) = zipio::read_entry(&entries, &archive_path) else {
            return Err(PresetError(format!(
                "Не удалось прочитать {archive_path} из ZIP."
            )));
        };
        let text = String::from_utf8(text_bytes.to_vec())
            .map_err(|_| PresetError(format!("Не удалось прочитать {archive_path} из ZIP.")))?;
        if sha256_text(&text)
            != raw
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_lowercase()
        {
            return Err(PresetError(format!(
                "Контрольная сумма {archive_path} не совпадает."
            )));
        }
        let invalid = validate_profile_list_file_text(&kind, &text);
        if let Some((line, value)) = invalid.first() {
            return Err(PresetError(format!(
                "В {archive_path}, строка {line}, неверная запись `{value}`."
            )));
        }
        list_files.push(PortableListFile {
            text: with_final_newline(&text),
            file_name,
            kind,
            storage,
        });
    }
    Ok((source_text, list_files))
}

/// План записи списков: (имя файла в архиве, имя файла в папке списков).
type ListNamePlan = (Vec<(String, String)>, Vec<(String, String)>);

/// python `_plan_list_imports`: куда писать каждый список архива — как есть,
/// под новым именем (коллизия) или слиянием в user-слой системного списка.
fn plan_list_imports(
    lists_root: &Path,
    list_files: &[PortableListFile],
) -> PresetResult<ListNamePlan> {
    let mut replacements: Vec<(String, String)> = Vec::new();
    let mut writes: Vec<(String, String)> = Vec::new();
    let mut reserved: HashSet<String> = HashSet::new();
    for item in list_files {
        let mut target_name = item.file_name.clone();
        let paths = layered_list_file(lists_root, &item.file_name).map_err(PresetError)?;
        if item.storage == "overlay" && paths.base_path.is_file() {
            let existing = if paths.user_path.is_file() {
                read_lossy(&paths.user_path)
            } else {
                String::new()
            };
            let merged = merge_list_text(&existing, &item.text);
            if normalized_text(&existing) != normalized_text(&merged) {
                writes.push((target_name.clone(), merged));
            }
        } else if list_file_exists(&paths) {
            let existing = visible_list_text(&paths);
            if normalized_text(&existing) != normalized_text(&item.text) {
                target_name =
                    unique_imported_list_name(lists_root, &item.file_name, &mut reserved)?;
                writes.push((target_name.clone(), item.text.clone()));
            }
        } else {
            writes.push((target_name.clone(), item.text.clone()));
        }
        reserved.insert(target_name.to_lowercase());
        replacements.push((item.file_name.clone(), target_name));
    }
    Ok((replacements, writes))
}

/// python `_restore_user_lists`: откат записей списков после ошибки.
fn restore_user_lists(lists_root: &Path, backups: &[(String, bool, String)]) {
    for (file_name, existed, previous) in backups.iter().rev() {
        if *existed {
            write_profile_user_list_text(lists_root, file_name, previous);
        } else {
            delete_profile_user_list_file(lists_root, file_name);
        }
    }
}

/// python `_rewrite_list_file_references`: переписывает `lists/<имя>` в
/// опциях списков на новые имена импорта.
#[must_use]
pub fn rewrite_list_file_references(
    source_text: &str,
    replacements: &[(String, String)],
) -> String {
    if replacements.is_empty() {
        return source_text.to_string();
    }
    let mut output: Vec<String> = Vec::new();
    for raw in crate::preset_contract::normalize_line_endings(source_text).split('\n') {
        let mut rewritten: Vec<String> = Vec::new();
        for piece in line_option_pieces(raw) {
            let Some(captures) = list_line_regex().captures(&piece) else {
                rewritten.push(piece);
                continue;
            };
            let indent = captures.name("indent").map_or("", |m| m.as_str());
            let option = captures.name("option").map_or("", |m| m.as_str());
            let value = captures.name("value").map_or("", |m| m.as_str());
            let trailing = captures.name("trailing").map_or("", |m| m.as_str());
            let mut values: Vec<String> = Vec::new();
            let mut changed = false;
            for value_item in split_list_values(value) {
                let file_name = safe_list_file_name(value_item.trim_start_matches('@'));
                let replacement = file_name.as_ref().and_then(|name| {
                    replacements
                        .iter()
                        .find(|(old_name, _)| old_name.to_lowercase() == name.to_lowercase())
                        .map(|(_, new_name)| new_name)
                });
                let unchanged = file_name.as_ref().is_some_and(|name| {
                    replacement.is_some_and(|new| new.to_lowercase() == name.to_lowercase())
                });
                if let Some(new_name) = replacement.filter(|_| !unchanged) {
                    values.push(format!("lists/{new_name}"));
                    changed = true;
                } else {
                    values.push(value_item);
                }
            }
            if changed {
                rewritten.push(format!("{indent}{option}={}{trailing}", values.join(",")));
            } else {
                rewritten.push(piece);
            }
        }
        output.push(rewritten.join(""));
    }
    output.join("\n")
}

/// python `_line_option_pieces`: строка пресета, поделённая на опции тем же
/// правилом, что у парсера и запуска («--a=x --b=y» — две опции), с
/// сохранёнными разделителями: `"".join(pieces) == raw`. Иначе значение
/// `--hostlist=a.txt --filter-tcp=443` целиком принималось за имя файла, и
/// ссылка не переписывалась.
///
/// python делает это регуляркой `((?<=\S)\s+(?=--))` со сбором разделителя;
/// здесь то же правило проверяется вручную: граница — максимальный пробельный
/// пробег после непробельного символа, за которым начинается «--».
#[must_use]
pub fn line_option_pieces(raw: &str) -> Vec<String> {
    if raw.trim_start().starts_with('#') {
        return vec![raw.to_string()];
    }
    let bytes = raw.as_bytes();
    let mut pieces: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace()
            && index > 0
            && !bytes[index - 1].is_ascii_whitespace()
        {
            let mut run_end = index;
            while run_end < bytes.len() && bytes[run_end].is_ascii_whitespace() {
                run_end += 1;
            }
            if run_end + 1 < bytes.len() && bytes[run_end] == b'-' && bytes[run_end + 1] == b'-' {
                pieces.push(raw[start..index].to_string());
                pieces.push(raw[index..run_end].to_string());
                start = run_end;
                index = run_end;
                continue;
            }
        }
        index += 1;
    }
    pieces.push(raw[start..].to_string());
    pieces
}

/// python `_list_file_names_from_value`.
fn list_file_names_from_value(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    for item in split_list_values(value) {
        if let Some(file_name) = safe_list_file_name(item.trim_start_matches('@')) {
            result.push(file_name);
        }
    }
    result
}

/// python `_split_list_values`: значения через запятую, кавычки снимаются.
fn split_list_values(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .split(',')
        .map(|item| item.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// python `_reference_file_name`: как в пресете записан файл с ключом.
fn reference_file_name(source_text: &str, wanted_key: &str) -> String {
    for raw in crate::preset_contract::normalize_line_endings(source_text).split('\n') {
        for piece in line_option_pieces(raw) {
            let Some(captures) = list_line_regex().captures(&piece) else {
                continue;
            };
            let value = captures.name("value").map_or("", |m| m.as_str());
            for value_item in split_list_values(value) {
                let Some(file_name) = safe_list_file_name(value_item.trim_start_matches('@'))
                else {
                    continue;
                };
                if file_name.to_lowercase() == wanted_key {
                    return file_name;
                }
            }
        }
    }
    String::new()
}

/// python `_unique_imported_list_name`: `<stem>-imported-2<suffix>`, …
fn unique_imported_list_name(
    lists_root: &Path,
    file_name: &str,
    reserved: &mut HashSet<String>,
) -> PresetResult<String> {
    let path = PureWinPath::new(file_name);
    let stem = {
        let stem = path.stem();
        if stem.is_empty() {
            "list".to_string()
        } else {
            stem
        }
    };
    let suffix = path
        .suffixes()
        .last()
        .cloned()
        .unwrap_or_else(|| ".txt".to_string());
    let mut counter = 2;
    loop {
        let candidate = format!("{stem}-imported-{counter}{suffix}");
        let free = !reserved.contains(&candidate.to_lowercase())
            && !list_file_exists(&layered_list_file(lists_root, &candidate).map_err(PresetError)?);
        if free {
            return Ok(candidate);
        }
        counter += 1;
    }
}

/// python `_list_file_exists`.
fn list_file_exists(paths: &LayeredListFile) -> bool {
    paths.base_path.is_file() || paths.user_path.is_file() || paths.final_path.is_file()
}

/// python `_visible_list_text`: текст списка в порядке видимости слоёв.
fn visible_list_text(paths: &LayeredListFile) -> String {
    if paths.user_path.is_file() && !paths.base_path.is_file() {
        return read_lossy(&paths.user_path);
    }
    if paths.final_path.is_file() {
        return read_lossy(&paths.final_path);
    }
    if paths.user_path.is_file() {
        return read_lossy(&paths.user_path);
    }
    if paths.base_path.is_file() {
        return read_lossy(&paths.base_path);
    }
    String::new()
}

/// python `_merge_list_text`: слияние системного и импортируемого списка —
/// строки без пустых и повторов (регистр не важен), порядок сохраняется.
fn merge_list_text(current: &str, incoming: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in crate::preset_contract::normalize_line_endings(current)
        .split('\n')
        .chain(crate::preset_contract::normalize_line_endings(incoming).split('\n'))
    {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let key = line.to_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        lines.push(line.to_string());
    }
    let mut merged = lines.join("\n");
    if !lines.is_empty() {
        merged.push('\n');
    }
    merged
}

/// python `_sha256_text`.
#[must_use]
pub fn sha256_text(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(with_final_newline(text).as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// python `_normalized_text`.
fn normalized_text(text: &str) -> String {
    crate::preset_contract::normalize_line_endings(&with_final_newline(text))
}

/// python `_with_final_newline`: LF, без пустого хвоста, ровно один «\n».
#[must_use]
pub fn with_final_newline(text: &str) -> String {
    format!(
        "{}\n",
        crate::preset_contract::normalize_line_endings(text).trim_end_matches('\n')
    )
}

/// Чтение текста списка с заменой некорректных байтов
/// (python `read_text(encoding="utf-8", errors="replace")`).
fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|raw| String::from_utf8_lossy(&raw).to_string())
        .unwrap_or_default()
}

/// python `Path.with_suffix(".zip")` — замена последнего суффикса.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let raw = path.to_string_lossy().to_string();
    let (dir, file) = match raw.rfind(['/', '\\']) {
        Some(index) => (&raw[..=index], &raw[index + 1..]),
        None => ("", raw.as_str()),
    };
    let stem = crate::file_store::stem_of(file);
    PathBuf::from(format!("{dir}{stem}.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_pieces_keep_separators() {
        let pieces = line_option_pieces("--a=x --b=y  --c");
        assert_eq!(pieces.join(""), "--a=x --b=y  --c");
        assert_eq!(pieces, vec!["--a=x", " ", "--b=y", "  ", "--c"]);
        assert_eq!(
            line_option_pieces("# comment --a=1"),
            vec!["# comment --a=1"]
        );
    }

    #[test]
    fn list_values_are_split_like_python() {
        assert_eq!(split_list_values("a.txt, b.txt"), vec!["a.txt", "b.txt"]);
        assert_eq!(split_list_values("\"a.txt\""), vec!["a.txt"]);
        assert_eq!(split_list_values(""), Vec::<String>::new());
        assert_eq!(
            list_file_names_from_value("@lists/a.txt,lists/b.txt"),
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );
    }
}

#[cfg(test)]
mod referenced_list_tests {
    use super::*;

    #[test]
    fn referenced_list_kinds_match_python() {
        // python: _referenced_list_kinds — ключ casefold, вид по опции.
        let text = "# Preset: t\n--new\n--hostlist=lists/a.txt\n--ipset=lists/b.txt\n";
        let references = referenced_list_kinds(text, "winws2").unwrap();
        assert_eq!(
            references,
            vec![
                ("a.txt".to_string(), "hostlist".to_string()),
                ("b.txt".to_string(), "ipset".to_string())
            ]
        );

        // python: один файл и как hostlist, и как ipset — ValueError.
        let conflicting = format!("{text}--ipset=lists/A.txt\n");
        let error = referenced_list_kinds(&conflicting, "winws2")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("lists/A.txt одновременно используется как hostlist и ipset"),
            "{error}"
        );

        // Повтор той же опции — не конфликт.
        let repeated = format!("{text}--hostlist-exclude=lists/A.txt\n");
        assert!(referenced_list_kinds(&repeated, "winws2").is_ok());
    }
}
