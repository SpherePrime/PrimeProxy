//! Порт `presets/file_store.py` — хранилище файлов пресетов.
//!
//! Единственный владелец записи файлов пресетов на диск
//! (`preset_contract.PRESET_FILE_STORE_MODULE`). Сканирует папки
//! пользователя и встроенных пресетов, кэширует манифесты по подписи папок и
//! переживает один заблокированный антивирусом файл (degraded-скан).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use once_cell::sync::Lazy;
use primecore_files::atomic::atomic_write_text;
use primecore_files::decode::{decode_preset_bytes, read_preset_file_text};
use primecore_mode::{AppPaths, EnginePaths};
use regex::Regex;

use crate::builtin_catalog::list_builtin_presets;
use crate::errors::{PresetError, PresetResult};
use crate::timefmt::{file_time_to_iso, now_iso_utc};
use crate::PresetManifest;

const PRESET_HEADER_PATTERN: &str = r"(?im)^\s*#\s*Preset:\s*(.+?)\s*$";
const PRESET_KIND_PATTERN: &str = r"(?im)^\s*#\s*PresetKind:\s*(.+?)\s*$";

fn preset_header_regex() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(PRESET_HEADER_PATTERN).expect("regexp"));
    &RE
}

fn preset_kind_regex() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(PRESET_KIND_PATTERN).expect("regexp"));
    &RE
}

/// Метка BOM — часть кодировки файла, а не текста пресета; старые файлы в
/// cp1251 читаются как cp1251 (см. `primecore-files::decode_preset_bytes`).
fn read_text(path: &Path) -> PresetResult<String> {
    read_preset_file_text(path).map_err(PresetError)
}

/// python `_read_header_text`: шапка файла пресета до первой содержательной
/// строки (байтово, чтобы закодированный файл не читался целиком).
fn read_header_text(path: &Path) -> std::io::Result<String> {
    let raw = std::fs::read(path)?;
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for line in raw.split(|byte| *byte == b'\n') {
        let mut stripped = line.to_vec();
        // python bytes.strip() — пробельные по обе стороны.
        while stripped.first().is_some_and(|b| b.is_ascii_whitespace()) {
            stripped.remove(0);
        }
        while stripped.last().is_some_and(|b| b.is_ascii_whitespace()) {
            stripped.pop();
        }
        let without_bom = stripped
            .strip_prefix(b"\xef\xbb\xbf".as_slice())
            .unwrap_or(&stripped);
        if !without_bom.is_empty() && !without_bom.starts_with(b"#") {
            break;
        }
        // python rstrip(b"\r\n") — все хвостовые \r и \n.
        let mut kept = line.to_vec();
        while kept.last().is_some_and(|b| *b == b'\r' || *b == b'\n') {
            kept.pop();
        }
        lines.push(kept);
    }
    let mut joined: Vec<u8> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            joined.push(b'\n');
        }
        joined.extend_from_slice(line);
    }
    Ok(decode_preset_bytes(&joined))
}

const DEGRADED_SCAN_TTL_SEC: f64 = 2.0;

fn monotonic_seconds() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_secs_f64()
}

/// Кэш манифестов: ключ папок, снятый ДО сканирования.
struct CacheEntry {
    key: CacheKey,
    manifests: Vec<PresetManifest>,
}

#[derive(Clone, PartialEq, Eq)]
struct CacheKey {
    parts: Vec<(bool, u64, u64)>,
    degraded_bucket: Option<u64>,
}

/// Хранилище файлов пресетов (python `PresetFileStore`).
pub struct PresetFileStore {
    app_paths: AppPaths,
    manifest_cache: Mutex<HashMap<String, CacheEntry>>,
}

impl PresetFileStore {
    #[must_use]
    pub fn new(app_paths: AppPaths) -> Self {
        Self {
            app_paths,
            manifest_cache: Mutex::new(HashMap::new()),
        }
    }

    /// python `list_manifests`: манифесты, отсортированные по
    /// (имя, имя файла) без учёта регистра.
    pub fn list_manifests(&self, engine: &str) -> Vec<PresetManifest> {
        let mut manifests = self.load_manifests(engine);
        manifests.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.file_name.to_lowercase().cmp(&b.file_name.to_lowercase()))
        });
        manifests
    }

    /// python `get_manifest`: манифест по имени файла (регистр не важен).
    #[must_use]
    pub fn get_manifest(&self, engine: &str, file_name: &str) -> Option<PresetManifest> {
        let resolved = self.resolve_file_name(engine, file_name).to_lowercase();
        if resolved.is_empty() {
            return None;
        }
        self.load_manifests(engine)
            .into_iter()
            .find(|manifest| manifest.file_name.trim().to_lowercase() == resolved)
    }

    /// python `resolve_file_name`: имя так, как оно записано на диске.
    ///
    /// Сначала — имя из сканирования папки (на Windows `exists()` верен при
    /// любом регистре, и в настройки/мету уходило написание вызывающего, а не
    /// файла), затем прямая проверка обеих папок, затем нормализованный
    /// кандидат.
    #[must_use]
    pub fn resolve_file_name(&self, engine: &str, file_name: &str) -> String {
        let candidate = file_name.trim();
        if candidate.is_empty() {
            return String::new();
        }

        let normalized_candidate = normalize_preset_file_name_candidate(candidate);
        let lowered_names = [
            candidate.to_lowercase(),
            normalized_candidate.to_lowercase(),
        ];

        for manifest in self.load_manifests(engine) {
            let manifest_name = manifest.file_name.trim();
            if !manifest_name.is_empty() && lowered_names.contains(&manifest_name.to_lowercase()) {
                return manifest_name.to_string();
            }
        }

        let Ok(engine_paths) = self.engine_paths(engine) else {
            return normalized_candidate;
        };
        for presets_dir in [
            &engine_paths.user_presets_dir,
            &engine_paths.builtin_presets_dir,
        ] {
            let candidate_path = presets_dir.join(&normalized_candidate);
            if candidate_path.exists() {
                return candidate_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default();
            }
        }

        if normalized_candidate.is_empty() {
            candidate.to_string()
        } else {
            normalized_candidate
        }
    }

    /// Имя, свободное и среди отображаемых имён, и среди имён файлов.
    ///
    /// Раньше файл получал «X (2).txt», а шапка оставалась «# Preset: X» —
    /// в списке стояли два одинаковых «X». Теперь «X (2)» и там и там.
    pub fn unique_preset_name(
        &self,
        engine: &str,
        name: &str,
        exclude_file_name: Option<&str>,
    ) -> PresetResult<String> {
        let base = name.trim();
        if base.is_empty() {
            return Ok(base.to_string());
        }
        let engine_paths = self.engine_paths(engine)?;
        let presets_dirs = [
            &engine_paths.user_presets_dir,
            &engine_paths.builtin_presets_dir,
        ];
        let excluded = exclude_file_name.unwrap_or("").trim().to_lowercase();
        let taken_names: std::collections::HashSet<String> = self
            .load_manifests(engine)
            .into_iter()
            .filter(|manifest| manifest.file_name.trim().to_lowercase() != excluded)
            .map(|manifest| manifest.name.trim().to_lowercase())
            .collect();

        let file_taken = |candidate_name: &str| -> bool {
            let file_name = format!("{}.txt", sanitize_file_stem(candidate_name));
            if file_name.to_lowercase() == excluded {
                return false;
            }
            presets_dirs.iter().any(|dir| dir.join(&file_name).exists())
        };

        let mut candidate = base.to_string();
        let mut counter = 2;
        while taken_names.contains(&candidate.to_lowercase()) || file_taken(&candidate) {
            let suffix = format!(" ({counter})");
            // Имя файла обрезается до 100 символов (sanitize_file_stem): без
            // укорачивания основы длинное «имя (2)» давало тот же файл, что и
            // «имя», и цикл никогда не заканчивался.
            let keep = (100usize.saturating_sub(suffix.chars().count())).max(1);
            candidate = format!(
                "{}{}",
                base.chars().take(keep).collect::<String>().trim_end(),
                suffix
            );
            counter += 1;
            if counter > 10_000 {
                return Err(PresetError(format!(
                    "Не удалось подобрать свободное имя для пресета: {base}"
                )));
            }
        }
        Ok(candidate)
    }

    /// python `read_source_text`.
    pub fn read_source_text(&self, engine: &str, file_name: &str) -> PresetResult<String> {
        let manifest = self
            .get_manifest(engine, file_name)
            .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
        read_text(&self.manifest_path(engine, &manifest)?)
    }

    /// python `get_source_path`.
    pub fn get_source_path(&self, engine: &str, file_name: &str) -> PresetResult<PathBuf> {
        let manifest = self
            .get_manifest(engine, file_name)
            .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
        self.manifest_path(engine, &manifest)
    }

    /// python `create_preset`: новый файл пресета в папке пользователя.
    pub fn create_preset(
        &self,
        engine: &str,
        name: &str,
        source_text: &str,
        kind: &str,
    ) -> PresetResult<PresetManifest> {
        let engine_paths = self.engine_paths(engine)?;
        let normalized_name = name.trim();
        if normalized_name.is_empty() {
            return Err(PresetError("Preset name is required".to_string()));
        }

        let file_name = Self::unique_file_name(
            [
                engine_paths.user_presets_dir.clone(),
                engine_paths.builtin_presets_dir.clone(),
            ],
            normalized_name,
            None,
        );
        let display_name = Self::extract_name(source_text, &stem_of(&file_name));
        let updated_at = now_iso_utc(current_unix_seconds());
        let normalized_kind = Self::infer_kind(None, kind, "user");

        let manifest = PresetManifest {
            file_name: file_name.clone(),
            name: display_name,
            updated_at,
            kind: normalized_kind,
            storage_scope: "user".to_string(),
        };
        self.write_source(&engine_paths.user_presets_dir.join(&file_name), source_text)?;
        self.invalidate_manifest_cache(engine);
        Ok(manifest)
    }

    /// python `update_preset`: перезаписывает файл, только если текст
    /// нормализации изменился; параметр `name` в python игнорируется.
    pub fn update_preset(
        &self,
        engine: &str,
        file_name: &str,
        source_text: &str,
        _name: Option<&str>,
    ) -> PresetResult<PresetManifest> {
        let manifests = self.load_manifests(engine);
        let current = find_manifest(&manifests, file_name)?.clone();
        let destination_path = self
            .engine_paths(engine)?
            .user_presets_dir
            .join(&current.file_name);
        let normalized_source_text = Self::normalize_source_for_write(source_text);
        let current_text = read_text(&self.manifest_path(engine, &current)?).unwrap_or_default();
        if normalized_source_text == Self::normalize_source_for_write(&current_text) {
            return Ok(current);
        }

        let updated = PresetManifest {
            file_name: current.file_name.clone(),
            name: Self::extract_name(source_text, &stem_of(&current.file_name)),
            updated_at: now_iso_utc(current_unix_seconds()),
            kind: Self::infer_kind(Some(&current.kind), "user", "user"),
            storage_scope: "user".to_string(),
        };
        self.write_source(&destination_path, source_text)?;
        self.invalidate_manifest_cache(engine);
        Ok(updated)
    }

    /// python `rename_preset`: переименование файла (только user-пресеты).
    pub fn rename_preset(
        &self,
        engine: &str,
        file_name: &str,
        new_name: &str,
    ) -> PresetResult<PresetManifest> {
        let manifests = self.load_manifests(engine);
        let current = find_manifest(&manifests, file_name)?.clone();
        if current.storage_scope.trim().to_lowercase() != "user" {
            return Err(PresetError(format!(
                "Built-in preset cannot be renamed: {}",
                current.name
            )));
        }
        let normalized_name = new_name.trim();
        if normalized_name.is_empty() {
            return Err(PresetError("Preset name is required".to_string()));
        }

        let engine_paths = self.engine_paths(engine)?;
        let src_path = self.manifest_path(engine, &current)?;
        let destination_file_name = Self::unique_file_name(
            [
                engine_paths.user_presets_dir.clone(),
                engine_paths.builtin_presets_dir.clone(),
            ],
            normalized_name,
            Some(&current.file_name),
        );
        let destination_path = engine_paths.user_presets_dir.join(&destination_file_name);
        if src_path.exists() && src_path != destination_path {
            // Оба пути — своя операция: исчезновение старого файла не должно
            // выглядеть для watcher-а активного пресета как внешняя правка.
            // (Реестр «своих записей» — часть watcher-а и здесь не переносится.)
            std::fs::rename(&src_path, &destination_path)
                .map_err(|error| PresetError(error.to_string()))?;
        }

        let source_text = if destination_path.exists() {
            read_text(&destination_path).unwrap_or_default()
        } else {
            String::new()
        };
        let updated = PresetManifest {
            file_name: destination_file_name.clone(),
            name: Self::extract_name(&source_text, &stem_of(&destination_file_name)),
            updated_at: now_iso_utc(current_unix_seconds()),
            kind: Self::infer_kind(Some(&current.kind), "user", "user"),
            storage_scope: "user".to_string(),
        };
        self.invalidate_manifest_cache(engine);
        Ok(updated)
    }

    /// python `delete_preset`: удаляет user-файл; отсутствие файла — не ошибка.
    pub fn delete_preset(&self, engine: &str, file_name: &str) -> PresetResult<()> {
        let manifests = self.load_manifests(engine);
        let manifest = find_manifest(&manifests, file_name)?.clone();
        if manifest.storage_scope.trim().to_lowercase() != "user" {
            return Err(PresetError(format!(
                "Built-in preset cannot be deleted: {}",
                manifest.name
            )));
        }
        let preset_path = self.manifest_path(engine, &manifest)?;
        match std::fs::remove_file(&preset_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(PresetError(error.to_string())),
        }
        self.invalidate_manifest_cache(engine);
        Ok(())
    }

    /// python `_engine_paths` — папки движка с созданием каталогов.
    pub fn engine_paths(&self, engine: &str) -> PresetResult<EnginePaths> {
        let paths = self.app_paths.engine_paths(Some(engine));
        paths
            .ensure_directories()
            .map_err(|error| PresetError(error.to_string()))?;
        Ok(paths)
    }

    /// python `_load_manifests` — сканирование с кэшем по подписи папок.
    fn load_manifests(&self, engine: &str) -> Vec<PresetManifest> {
        let normalized_engine = engine.trim().to_lowercase();
        let cache_key = self.current_manifest_cache_key(&normalized_engine);

        if let Ok(cache) = self.manifest_cache.lock() {
            if let Some(entry) = cache.get(&normalized_engine) {
                if let Some(key) = &cache_key {
                    let mut degraded_key = key.clone();
                    degraded_key.degraded_bucket =
                        Some((monotonic_seconds() / DEGRADED_SCAN_TTL_SEC) as u64);
                    if entry.key == *key || entry.key == degraded_key {
                        return entry.manifests.clone();
                    }
                }
            }
        }

        let (manifests, degraded) = self.scan_manifests_from_files(engine);
        if let Some(key) = cache_key {
            let mut entry_key = key.clone();
            if degraded {
                // Какой-то файл был заблокирован: его запись неполная (имя из
                // имени файла). Кэшируем ненадолго — чтобы горячие пути не
                // перечитывали папку на каждый вызов, но разблокированный файл
                // скоро получил настоящее имя.
                entry_key.degraded_bucket =
                    Some((monotonic_seconds() / DEGRADED_SCAN_TTL_SEC) as u64);
            }
            if let Ok(mut cache) = self.manifest_cache.lock() {
                cache.insert(
                    normalized_engine,
                    CacheEntry {
                        key: entry_key,
                        manifests: manifests.clone(),
                    },
                );
            }
        }
        manifests
    }

    /// python `_scan_manifests_from_files` — плюс признак degraded-скана.
    /// Возвращаются манифесты в порядке python-словаря: сначала builtin, затем
    /// user, повторы имён файлов (регистр не важен) замещают запись builtin.
    fn scan_manifests_from_files(&self, engine: &str) -> (Vec<PresetManifest>, bool) {
        let engine_paths = match self.engine_paths(engine) {
            Ok(paths) => paths,
            Err(_) => return (Vec::new(), false),
        };
        let mut manifests_by_file_name: Vec<(String, PresetManifest)> = Vec::new();
        let mut degraded = false;
        for (storage_scope, presets_dir) in [
            ("builtin", engine_paths.builtin_presets_dir.clone()),
            ("user", engine_paths.user_presets_dir.clone()),
        ] {
            for preset_path in list_builtin_presets(&presets_dir) {
                let header_text = match read_header_text(&preset_path) {
                    Ok(text) => text,
                    Err(_) => {
                        // Файл заблокирован антивирусом/редактором: один такой
                        // файл не должен ронять весь список пресетов —
                        // показываем его по имени файла.
                        degraded = true;
                        String::new()
                    }
                };
                let file_name = preset_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default();
                let display_name = Self::extract_name(&header_text, &stem_of(&file_name));
                let updated_at = Self::file_time_to_iso(&preset_path)
                    .unwrap_or_else(|| now_iso_utc(current_unix_seconds()));
                let preset_kind = Self::extract_preset_kind(&header_text);
                let kind = Self::infer_kind(preset_kind.as_deref(), storage_scope, storage_scope);
                let manifest = PresetManifest {
                    file_name,
                    name: display_name,
                    updated_at,
                    kind,
                    storage_scope: storage_scope.to_string(),
                };
                let key = preset_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                match manifests_by_file_name
                    .iter_mut()
                    .find(|(existing, _)| *existing == key)
                {
                    Some((_, existing)) => *existing = manifest,
                    None => manifests_by_file_name.push((key, manifest)),
                }
            }
        }
        (
            manifests_by_file_name
                .into_iter()
                .map(|(_, manifest)| manifest)
                .collect(),
            degraded,
        )
    }

    /// python `_extract_name` (staticmethod): имя из шапки `# Preset:`.
    #[must_use]
    pub fn extract_name(source_text: &str, default_name: &str) -> String {
        if let Some(captures) = preset_header_regex().captures(source_text) {
            let value = captures
                .get(1)
                .map_or(String::new(), |m| m.as_str().trim().to_string());
            if !value.is_empty() {
                return value;
            }
        }
        let default = default_name.trim();
        if default.is_empty() {
            "Preset".to_string()
        } else {
            default.to_string()
        }
    }

    /// python `_extract_preset_kind` (staticmethod): вид из шапки
    /// `# PresetKind:` в нижнем регистре.
    #[must_use]
    pub fn extract_preset_kind(source_text: &str) -> Option<String> {
        let captures = preset_kind_regex().captures(source_text)?;
        let value = captures
            .get(1)
            .map_or(String::new(), |m| m.as_str().trim().to_lowercase());
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    /// python `_infer_kind`: builtin-папка даёт builtin, `imported` сохраняется.
    #[must_use]
    pub fn infer_kind(current_kind: Option<&str>, _engine: &str, storage_scope: &str) -> String {
        if storage_scope.trim().to_lowercase() == "builtin" {
            return "builtin".to_string();
        }
        if current_kind.is_some_and(|kind| kind.trim().to_lowercase() == "imported") {
            return "imported".to_string();
        }
        "user".to_string()
    }

    /// python `_current_manifest_cache_key`: подпись обеих папок пресетов.
    fn current_manifest_cache_key(&self, engine: &str) -> Option<CacheKey> {
        let engine_paths = self.engine_paths(engine).ok()?;
        let mut parts = Vec::new();
        for dir in [
            &engine_paths.user_presets_dir,
            &engine_paths.builtin_presets_dir,
        ] {
            match dir.metadata() {
                Ok(metadata) => parts.push((
                    true,
                    metadata
                        .modified()
                        .ok()
                        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|duration| duration.as_nanos() as u64)
                        .unwrap_or(0),
                    metadata.len(),
                )),
                Err(_) => parts.push((false, 0, 0)),
            }
        }
        Some(CacheKey {
            parts,
            degraded_bucket: None,
        })
    }

    /// python `_invalidate_manifest_cache`.
    pub fn invalidate_manifest_cache(&self, engine: &str) {
        if let Ok(mut cache) = self.manifest_cache.lock() {
            cache.remove(engine.trim().to_lowercase().as_str());
        }
    }

    /// python `_file_time_to_iso`: время изменения файла в ISO или пустая строка.
    fn file_time_to_iso(path: &Path) -> Option<String> {
        let metadata = path.metadata().ok()?;
        let seconds = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0);
        if seconds <= 0.0 {
            return None;
        }
        let value = file_time_to_iso(seconds);
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    /// python `_normalize_source_for_write`: перевод строк к LF и перевод
    /// строки в конце — текст так, как он ляжет на диск (пустой текст
    /// становится одним «\n», как в python).
    #[must_use]
    pub fn normalize_source_for_write(source_text: &str) -> String {
        let mut text = source_text.replace("\r\n", "\n").replace('\r', "\n");
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text
    }

    /// python `_write_source`: создание папки и атомарная запись текста.
    fn write_source(&self, path: &Path, source_text: &str) -> PresetResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| PresetError(error.to_string()))?;
        }
        let text = Self::normalize_source_for_write(source_text);
        atomic_write_text(path, &text).map_err(|error| PresetError(error.to_string()))
    }

    /// python `_manifest_path`: файл builtin-пресета живёт в builtin-папке.
    pub fn manifest_path(&self, engine: &str, manifest: &PresetManifest) -> PresetResult<PathBuf> {
        let engine_paths = self.engine_paths(engine)?;
        Ok(
            if manifest.storage_scope.trim().to_lowercase() == "builtin" {
                engine_paths.builtin_presets_dir.join(&manifest.file_name)
            } else {
                engine_paths.user_presets_dir.join(&manifest.file_name)
            },
        )
    }

    /// python `_unique_file_name`: `Имя.txt`, `Имя (2).txt`, …
    #[must_use]
    pub fn unique_file_name(
        presets_dirs: impl AsRef<[PathBuf]>,
        name: &str,
        exclude_file_name: Option<&str>,
    ) -> String {
        let base = sanitize_file_stem(name);
        let mut candidate = format!("{base}.txt");
        let mut counter = 2;
        let excluded = exclude_file_name.unwrap_or("").trim().to_lowercase();
        while presets_dirs
            .as_ref()
            .iter()
            .any(|dir| dir.join(&candidate).exists())
            && candidate.to_lowercase() != excluded
        {
            candidate = format!("{base} ({counter}).txt");
            counter += 1;
        }
        candidate
    }
}

/// python `_find_index`: пресет по имени файла (регистр не важен) или
/// `ValueError("Preset not found: ...")`.
fn find_manifest<'a>(
    manifests: &'a [PresetManifest],
    file_name: &str,
) -> PresetResult<&'a PresetManifest> {
    let candidate = file_name.trim().to_lowercase();
    manifests
        .iter()
        .find(|manifest| manifest.file_name.trim().to_lowercase() == candidate)
        .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))
}

/// Текущее unix-время в секундах (python `time.time()`); точность до
/// секунды достаточна для меток `updated_at` в ISO.
pub fn current_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// python `_sanitize_file_stem`: безопасная основа имени файла пресета.
#[must_use]
pub fn sanitize_file_stem(value: &str) -> String {
    static FORBIDDEN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"[\\/:*?"<>|\x00]+"#).expect("regexp"));
    static SPACES: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").expect("regexp"));
    let text = value.trim();
    if text.is_empty() {
        return "Preset".to_string();
    }
    let sanitized = FORBIDDEN.replace_all(text, "_");
    let sanitized = SPACES.replace_all(&sanitized, " ").trim().to_string();
    let trimmed = sanitized.trim_end_matches('.');
    let truncated: String = trimmed.chars().take(100).collect();
    if truncated.is_empty() {
        "Preset".to_string()
    } else {
        truncated
    }
}

/// python `_normalize_preset_file_name_candidate`: пресеты — только `*.txt`;
/// «v1.5» — это имя «v1.5.txt», а не файл с расширением «.5» (иначе поиск по
/// основе имени находил чужой v1.txt).
#[must_use]
pub fn normalize_preset_file_name_candidate(value: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        return String::new();
    }
    if text.to_lowercase().ends_with(".txt") {
        text.to_string()
    } else {
        format!("{text}.txt")
    }
}

/// python `Path(name).stem` — имя без последнего суффикса.
#[must_use]
pub fn stem_of(file_name: &str) -> String {
    let name = file_name.rsplit(['/', '\\']).next().unwrap_or(file_name);
    match name.rfind('.') {
        Some(index) if !name[..index].trim_start_matches('.').is_empty() => {
            name[..index].to_string()
        }
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_app_paths(name: &str) -> (AppPaths, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("primecore-presets-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        (
            AppPaths {
                user_root: root.clone(),
                local_root: root.clone(),
            },
            root,
        )
    }

    #[test]
    fn sanitize_file_stem_matches_python() {
        // python: _sanitize_file_stem
        assert_eq!(sanitize_file_stem("  Пресет:_test/  "), "Пресет__test_");
        assert_eq!(sanitize_file_stem(""), "Preset");
        assert_eq!(sanitize_file_stem("...."), "Preset");
        assert_eq!(sanitize_file_stem("a b  c"), "a b c");
        assert_eq!(sanitize_file_stem("x?y*"), "x_y_");
        assert_eq!(sanitize_file_stem("имя.с.точками..."), "имя.с.точками");
        assert_eq!(
            sanitize_file_stem(&"а".repeat(120)),
            "а".repeat(100),
            "имя обрезается до 100 символов"
        );
    }

    #[test]
    fn normalize_file_name_candidate_matches_python() {
        // python: _normalize_preset_file_name_candidate
        assert_eq!(normalize_preset_file_name_candidate("v1.5"), "v1.5.txt");
        assert_eq!(normalize_preset_file_name_candidate("name"), "name.txt");
        assert_eq!(
            normalize_preset_file_name_candidate("  Name.TXT  "),
            "Name.TXT"
        );
        assert_eq!(normalize_preset_file_name_candidate("   "), "");
    }

    #[test]
    fn stem_of_matches_python_path_stem() {
        // python: Path(name).stem
        assert_eq!(stem_of("Пресет.txt"), "Пресет");
        assert_eq!(stem_of("v1.5.txt"), "v1.5");
        assert_eq!(stem_of(".hidden"), ".hidden");
        assert_eq!(stem_of("C:\\dir\\a\\b.txt"), "b");
        assert_eq!(stem_of("/usr/local/bin/tool"), "tool");
    }

    #[test]
    fn extract_name_and_kind_match_python() {
        // python: _extract_name / _extract_preset_kind / _infer_kind
        assert_eq!(
            PresetFileStore::extract_name("# Preset:  Мой пресет \n", "file"),
            "Мой пресет"
        );
        assert_eq!(PresetFileStore::extract_name("", ""), "Preset");
        assert_eq!(PresetFileStore::extract_name("", "имя"), "имя");
        assert_eq!(
            PresetFileStore::extract_preset_kind("# PresetKind: HostList\n"),
            Some("hostlist".to_string())
        );
        assert_eq!(PresetFileStore::extract_preset_kind("без шапки"), None);
        assert_eq!(PresetFileStore::infer_kind(None, "winws2", "user"), "user");
        assert_eq!(
            PresetFileStore::infer_kind(Some("Imported"), "winws2", "user"),
            "imported"
        );
        assert_eq!(
            PresetFileStore::infer_kind(Some("builtin"), "winws2", "Builtin "),
            "builtin"
        );
        assert_eq!(
            PresetFileStore::infer_kind(Some("builtin"), "winws2", "user"),
            "user"
        );
    }

    #[test]
    fn normalize_source_for_write_matches_python() {
        // python: _normalize_source_for_write
        assert_eq!(
            PresetFileStore::normalize_source_for_write("a\r\nb\r"),
            "a\nb\n"
        );
        assert_eq!(PresetFileStore::normalize_source_for_write("a"), "a\n");
        assert_eq!(PresetFileStore::normalize_source_for_write("a\n"), "a\n");
        assert_eq!(PresetFileStore::normalize_source_for_write(""), "\n");
    }

    #[test]
    fn unique_file_name_avoids_collisions_in_both_dirs() {
        // python: _unique_file_name — «Имя.txt», «Имя (2).txt», …
        let (app_paths, root) = temp_app_paths("unique-file-name");
        let paths = app_paths.engine_paths(Some("winws2"));
        paths.ensure_directories().unwrap();
        std::fs::write(paths.user_presets_dir.join("Имя.txt"), "x").unwrap();
        std::fs::write(paths.builtin_presets_dir.join("Имя (2).txt"), "x").unwrap();

        assert_eq!(
            PresetFileStore::unique_file_name(
                [
                    paths.user_presets_dir.clone(),
                    paths.builtin_presets_dir.clone()
                ],
                "Имя",
                None,
            ),
            "Имя (3).txt"
        );
        assert_eq!(
            PresetFileStore::unique_file_name(
                [
                    paths.user_presets_dir.clone(),
                    paths.builtin_presets_dir.clone()
                ],
                "Имя",
                Some("Имя (3).TXT"),
            ),
            "Имя (3).txt",
            "исключённое имя не считается занятым (регистр не важен)"
        );
        assert_eq!(
            PresetFileStore::unique_file_name(
                [
                    paths.user_presets_dir.clone(),
                    paths.builtin_presets_dir.clone()
                ],
                "Другое",
                None,
            ),
            "Другое.txt"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unique_preset_name_syncs_header_and_file() {
        // python: unique_preset_name — имя свободно и среди шапок, и среди файлов.
        let (app_paths, root) = temp_app_paths("unique-preset-name");
        let store = PresetFileStore::new(app_paths.clone());
        store
            .create_preset("winws2", "Пресет", "# Preset: Пресет\n", "user")
            .unwrap();
        assert_eq!(
            store.unique_preset_name("winws2", "Пресет", None).unwrap(),
            "Пресет (2)"
        );
        assert_eq!(
            store
                .unique_preset_name("winws2", "Пресет", Some("Пресет.txt"))
                .unwrap(),
            "Пресет"
        );
        assert_eq!(store.unique_preset_name("winws2", "  ", None).unwrap(), "");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_update_delete_roundtrip_matches_python() {
        let (app_paths, root) = temp_app_paths("store-roundtrip");
        let store = PresetFileStore::new(app_paths.clone());

        let created = store
            .create_preset("winws2", "Мой", "# Preset: Мой\nтело\r\n", "user")
            .unwrap();
        assert_eq!(created.file_name, "Мой.txt");
        assert_eq!(created.name, "Мой");
        assert_eq!(created.kind, "user");
        assert_eq!(created.storage_scope, "user");
        assert!(
            created.updated_at.ends_with('Z'),
            "ISO с Z: {}",
            created.updated_at
        );

        // python: update_preset не переписывает файл без изменений нормализации.
        let unchanged = store
            .update_preset("winws2", "Мой.txt", "# Preset: Мой\nтело\n", None)
            .unwrap();
        assert_eq!(unchanged.file_name, created.file_name);
        let renamed = store
            .rename_preset("winws2", "Мой.txt", "Переименованный")
            .unwrap();
        assert_eq!(renamed.file_name, "Переименованный.txt");
        // python: имя в манифесте — из шапки текста, а шапку store-уровень
        // не переписывает (переписывание — в preset_file_ops.rename_by_file_name).
        assert_eq!(renamed.name, "Мой");

        store
            .delete_preset("winws2", "Переименованный.txt")
            .unwrap();
        assert!(store.list_manifests("winws2").is_empty());
        // python: отсутствующий манифест — ValueError, отсутствующий ФАЙЛ — не ошибка.
        assert!(store
            .delete_preset("winws2", "Переименованный.txt")
            .is_err());

        // python: create_preset всегда пишет в user-папку (storage_scope="user"),
        // даже с kind="builtin"; guard переименования — по storage_scope.
        let builtin_kind = store
            .create_preset("winws2", "B", "# PresetKind: builtin\nтекст", "builtin")
            .unwrap();
        assert_eq!(
            builtin_kind.kind, "user",
            "python: create даёт user, kind=builtin не сохраняется"
        );
        assert_eq!(builtin_kind.storage_scope, "user");
        let _ = std::fs::remove_dir_all(&root);
    }
}
