//! Порт `presets/builtin_reset_support.py` — удаление пользовательских
//! копий встроенных пресетов.

use primecore_mode::{AppPaths, ALL_ENGINES};

use crate::builtin_catalog::list_builtin_presets;
use crate::errors::{PresetError, PresetResult};
/// Итог python `reset_all_builtin_overrides`: (удалено, всего builtin,
/// имена (stem) файлов, которые удалить не удалось).
pub struct BuiltinResetResult {
    pub removed: usize,
    pub total_builtin: usize,
    pub failed: Vec<String>,
}

/// python `reset_all_builtin_overrides(engine, app_paths)`: удаляет из папки
/// пользователя каждый файл с именем встроенного пресета.
///
/// Отклонение от python: записи в журнал (`log.log`) не делаются — причины
/// отказов собираются в `failed`, журналирование остаётся за вызывающим слоем.
pub fn reset_all_builtin_overrides(
    engine: &str,
    app_paths: &AppPaths,
) -> PresetResult<BuiltinResetResult> {
    let engine_key = engine.trim().to_lowercase();
    if !ALL_ENGINES.contains(&engine_key.as_str()) {
        return Err(PresetError(format!("Unsupported preset engine: {engine}")));
    }

    let paths = app_paths.engine_paths(Some(&engine_key));
    let engine_paths = paths
        .ensure_directories()
        .map_err(|error| PresetError(error.to_string()))?;
    let builtin_paths = list_builtin_presets(&engine_paths.builtin_presets_dir);
    let mut removed = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for builtin_path in &builtin_paths {
        let Some(file_name) = builtin_path.file_name() else {
            continue;
        };
        let user_path = engine_paths.user_presets_dir.join(file_name);
        if !user_path.exists() {
            continue;
        }
        match std::fs::remove_file(&user_path) {
            Ok(()) => removed += 1,
            Err(_) => failed.push(display_name_for_failed_preset(builtin_path)),
        }
    }

    Ok(BuiltinResetResult {
        removed,
        total_builtin: builtin_paths.len(),
        failed,
    })
}

/// python `_display_name_for_failed_preset` — основа имени файла.
fn display_name_for_failed_preset(path: &std::path::Path) -> String {
    crate::file_store::stem_of(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_app_paths() -> (AppPaths, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "primecore-presets-builtin-reset-{}",
            std::process::id()
        ));
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
    fn removes_user_copies_of_builtin_files() {
        // python: reset_all_builtin_overrides — удалить user-копии с именами
        // builtin-файлов, посчитать удалённые и неудачные.
        let (app_paths, root) = temp_app_paths();
        let engine_paths = app_paths.engine_paths(Some("winws2"));
        engine_paths.ensure_directories().unwrap();
        std::fs::write(
            engine_paths.builtin_presets_dir.join("Standard.txt"),
            "builtin",
        )
        .unwrap();
        std::fs::write(
            engine_paths.builtin_presets_dir.join("Other.txt"),
            "builtin",
        )
        .unwrap();
        std::fs::write(
            engine_paths.user_presets_dir.join("Standard.txt"),
            "override",
        )
        .unwrap();
        std::fs::write(engine_paths.user_presets_dir.join("Custom.txt"), "user own").unwrap();

        let result = reset_all_builtin_overrides("WINWS2", &app_paths).unwrap();
        assert_eq!(result.total_builtin, 2);
        assert_eq!(result.removed, 1);
        assert!(result.failed.is_empty());
        assert!(!engine_paths.user_presets_dir.join("Standard.txt").exists());
        assert!(
            engine_paths.user_presets_dir.join("Custom.txt").exists(),
            "чужой файл остаётся"
        );

        // python: неизвестный движок — ошибка.
        assert!(reset_all_builtin_overrides("unknown", &app_paths).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
