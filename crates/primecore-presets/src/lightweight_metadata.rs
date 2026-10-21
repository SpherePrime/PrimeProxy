//! Порт `presets/lightweight_metadata.py` — метаданные строки списка пресетов.

use std::path::Path;

use crate::list_metadata::{
    build_preset_stat_metadata, read_preset_list_metadata, read_preset_stat_metadata,
};

/// python-словарь из `build_lightweight_preset_metadata`: метаданные шапки
/// плюс поля строки списка.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LightweightPresetMetadata {
    pub description: String,
    pub modified_display: String,
    pub icon_color: String,
    pub display_name: String,
    pub kind: String,
    pub is_builtin: bool,
    pub can_reset_to_builtin: bool,
}

/// python `build_lightweight_preset_metadata`: метаданные шапки, обогащённые
/// полями строки списка. Ошибка чтения шапки даёт пустые метаданные, но поля
/// строки списка заполняются как обычно.
#[allow(clippy::too_many_arguments)]
pub fn build_lightweight_preset_metadata(
    path: &Path,
    display_name: &str,
    kind: &str,
    is_builtin: bool,
    can_reset_to_builtin: bool,
    read_headers: bool,
    stat_result: Option<&std::fs::Metadata>,
) -> LightweightPresetMetadata {
    // python: str(display_name or path.name).strip() — пустая строка falsy,
    // а пробельная — truthy и после strip() даёт пустое имя.
    let normalized_display_name = if display_name.is_empty() {
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        display_name.trim().to_string()
    };
    let normalized_kind = {
        let value = kind.trim();
        if value.is_empty() {
            "user".to_string()
        } else {
            value.to_string()
        }
    };
    let normalized_is_builtin = is_builtin;
    let normalized_can_reset_to_builtin = can_reset_to_builtin;

    let metadata = if read_headers {
        Some(read_preset_list_metadata(path))
    } else {
        match stat_result {
            Some(stat) => Some(build_preset_stat_metadata(stat)),
            None => Some(read_preset_stat_metadata(path)),
        }
    };

    let (description, modified_display, icon_color) = match metadata {
        Some(metadata) => (
            metadata.description,
            metadata.modified_display,
            metadata.icon_color,
        ),
        None => (String::new(), String::new(), String::new()),
    };

    LightweightPresetMetadata {
        description,
        modified_display,
        icon_color,
        display_name: normalized_display_name,
        kind: normalized_kind,
        is_builtin: normalized_is_builtin,
        can_reset_to_builtin: normalized_can_reset_to_builtin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_preset_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "primecore-presets-lightweight-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("Мой пресет.txt")
    }

    #[test]
    fn reads_headers_and_normalizes_fields() {
        // python: build_lightweight_preset_metadata — имя и вид нормализуются,
        // шапка даёт описание и цвет.
        let path = temp_preset_path("headers");
        std::fs::write(
            &path,
            "# Description: Описание\n# IconColor: #112233\nтело\n",
        )
        .unwrap();
        let metadata = build_lightweight_preset_metadata(
            &path,
            "  Мой пресет  ",
            "  ",
            true,
            true,
            true,
            None,
        );
        assert_eq!(metadata.description, "Описание");
        assert_eq!(metadata.icon_color, "#112233");
        assert_eq!(metadata.display_name, "Мой пресет");
        assert_eq!(metadata.kind, "user", "пустой вид — user");
        assert!(metadata.is_builtin);
        assert!(metadata.can_reset_to_builtin);
        assert!(!metadata.modified_display.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn empty_display_name_falls_back_to_file_name() {
        // python: str(display_name or path.name).strip()
        let path = temp_preset_path("fallback");
        std::fs::write(&path, "тело\n").unwrap();
        let metadata =
            build_lightweight_preset_metadata(&path, "", "hostlist", false, false, false, None);
        assert_eq!(
            metadata.display_name, "Мой пресет.txt",
            "python: display_name or path.name"
        );
        assert_eq!(metadata.kind, "hostlist");
        assert_eq!(metadata.description, "", "шапки не читались");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
