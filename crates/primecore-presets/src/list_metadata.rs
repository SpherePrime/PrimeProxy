//! Порт `presets/list_metadata.py` — лёгкие метаданные пресета для списка.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use primecore_files::decode::read_preset_file_text;
use regex::Regex;

use crate::timefmt::format_file_modified_display;

/// Результат чтения шапки пресета (python-словарь с ключами
/// `description` / `modified_display` / `icon_color`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresetListMetadata {
    pub description: String,
    pub modified_display: String,
    pub icon_color: String,
}

impl PresetListMetadata {
    fn empty() -> Self {
        Self {
            description: String::new(),
            modified_display: String::new(),
            icon_color: String::new(),
        }
    }
}

/// python `_PRESET_LIST_METADATA_CACHE`: результаты чтения шапки по ключу
/// (путь, mtime_ns, размер) — горячие перерисовки списка не перечитывают файл.
type ListMetadataCache = HashMap<(String, u64, u64), PresetListMetadata>;

static CACHE: Lazy<Mutex<ListMetadataCache>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn description_regex() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^#\s*Description:\s*(.*)$").expect("regexp"));
    &RE
}

fn icon_color_regex() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^#\s*IconColor:\s*(.+)$").expect("regexp"));
    &RE
}

/// python `_mtime_ns`.
fn mtime_ns(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// python `_format_file_modified_display`: «ДД.ММ.ГГГГ ЧЧ:ММ» по времени
/// изменения (см. [`crate::timefmt`] про часовой пояс).
#[must_use]
pub fn format_file_modified_display_from(metadata: &std::fs::Metadata) -> String {
    let seconds = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    format_file_modified_display(seconds)
}

/// python `read_preset_list_metadata`: лёгкие метаданные для отрисовки списка.
///
/// Дата изменения берётся из метаданных файла, описание и цвет — из шапки.
/// Файлы пресетов маленькие: читаются целиком по общему правилу кодировки
/// (UTF-8 с BOM, иначе cp1251), шапка разбирается построчно. Любая ошибка
/// чтения даёт пустые поля, но время изменения (если удалось снять stat)
/// остаётся. Результат кэшируется по (путь, mtime_ns, размер).
pub fn read_preset_list_metadata(path: &Path) -> PresetListMetadata {
    let mut result = PresetListMetadata::empty();
    let mut cache_key: Option<(String, u64, u64)> = None;

    if let Ok(metadata) = path.metadata() {
        result.modified_display = format_file_modified_display_from(&metadata);
        cache_key = Some((
            path.to_string_lossy().to_string(),
            mtime_ns(&metadata),
            metadata.len(),
        ));
        if let Some(key) = &cache_key {
            if let Ok(cache) = CACHE.lock() {
                if let Some(cached) = cache.get(key) {
                    return cached.clone();
                }
            }
        }
    }

    // Ошибки чтения/разбора не роняют список: поля просто остаются пустыми.
    if let Ok(text) = read_preset_file_text(path) {
        for raw in text.split('\n') {
            let stripped = raw.trim();
            if stripped.is_empty() {
                continue;
            }
            if !stripped.starts_with('#') {
                break;
            }
            if let Some(captures) = description_regex().captures(stripped) {
                result.description = captures
                    .get(1)
                    .map_or(String::new(), |m| m.as_str().trim().to_string());
                continue;
            }
            if let Some(captures) = icon_color_regex().captures(stripped) {
                result.icon_color = captures
                    .get(1)
                    .map_or(String::new(), |m| m.as_str().trim().to_string());
            }
        }
    }

    if let Some(key) = cache_key {
        if let Ok(mut cache) = CACHE.lock() {
            cache.insert(key, result.clone());
        }
    }
    result
}

/// python `read_preset_stat_metadata`: только время изменения, без чтения файла.
pub fn read_preset_stat_metadata(path: &Path) -> PresetListMetadata {
    match path.metadata() {
        Ok(metadata) => build_preset_stat_metadata(&metadata),
        Err(_) => PresetListMetadata::empty(),
    }
}

/// python `build_preset_stat_metadata` (здесь принимает уже снятый stat).
#[must_use]
pub fn build_preset_stat_metadata(metadata: &std::fs::Metadata) -> PresetListMetadata {
    PresetListMetadata {
        modified_display: format_file_modified_display_from(metadata),
        ..PresetListMetadata::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_preset_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "primecore-presets-list-metadata-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.txt"))
    }

    #[test]
    fn reads_description_and_icon_color_like_python() {
        // python: read_preset_list_metadata — шапка до первой непустой
        // строки без '#', значения обрезаются по краям.
        let path = temp_preset_path("headers");
        std::fs::write(
            &path,
            "# Preset: Тест\n# Description:  Тестовое описание \n# IconColor: #FF00AA\n\n# Description: пропущено\nтело\n",
        )
        .unwrap();
        let metadata = read_preset_list_metadata(&path);
        // python: пустые строки не прерывают шапку, последний заголовок
        // Description побеждает — как в эталоне выше (read_preset_list_metadata).
        assert_eq!(metadata.description, "пропущено");
        assert_eq!(metadata.icon_color, "#FF00AA");
        assert!(!metadata.modified_display.is_empty(), "время из stat");
        assert_eq!(read_preset_stat_metadata(&path).icon_color, "");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unreadable_file_gives_empty_fields() {
        // python: исключение чтения — пустые поля без падения списка.
        let metadata = read_preset_list_metadata(Path::new("/definitely/missing/preset.txt"));
        assert_eq!(metadata, PresetListMetadata::default());
    }

    #[test]
    fn cache_returns_same_result_for_unchanged_file() {
        let path = temp_preset_path("cache");
        std::fs::write(&path, "# Description: закэшировано\nтело\n").unwrap();
        let first = read_preset_list_metadata(&path);
        std::fs::write(&path, "# Description: закэшировано\nтело\n").unwrap();
        let second = read_preset_list_metadata(&path);
        assert_eq!(first, second);
        assert_eq!(first.description, "закэшировано");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
