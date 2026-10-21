//! Порт `presets/preset_file_ops.py` — файловые действия над пресетами.
//!
//! Функции принимают backend (python — `PresetFileService` с его утиной
//! типизацией, здесь — [`crate::file_service::PresetBackend`]): сервис
//! предоставляет хранилище, движок, нормализацию текста и крючки в слой
//! уведомлений. Запись файла всегда идёт через хранилище
//! (`preset_contract.PRESET_FILE_WRITE_OWNERS`).

use std::path::{Path, PathBuf};

use primecore_files::decode::read_preset_file_text;
use primecore_mode::default_preset_file_name;

use crate::builtin_catalog::list_builtin_presets;
use crate::builtin_reset_support::{reset_all_builtin_overrides, BuiltinResetResult};
use crate::errors::{PresetError, PresetResult};
use crate::file_service::{PresetBackend, RemoteBindingSnapshot};
use crate::portable_archive::{
    export_preset_with_lists, import_portable_preset, PresetImportResult,
};
use crate::preset_text_ops::{
    header_preset_kind, rewrite_preset_headers, validate_preset_source_text,
};
use crate::PresetManifest;

/// python `_unique_preset_name` — имя, свободное и в списке, и среди файлов
/// (см. `PresetFileStore::unique_preset_name`).
pub fn unique_preset_name(
    backend: &impl PresetBackend,
    name: &str,
    exclude_file_name: Option<&str>,
) -> PresetResult<String> {
    backend
        .preset_file_store()
        .unique_preset_name(backend.engine(), name, exclude_file_name)
}

/// python `_read_standard_builtin_preset` — текст стандартного встроенного
/// пресета движка (источник для «создать с нуля»).
pub fn read_standard_builtin_preset(backend: &impl PresetBackend) -> PresetResult<String> {
    let file_name = default_preset_file_name(backend.engine());
    let paths = backend.app_paths().engine_paths(Some(backend.engine()));
    let engine_paths = paths
        .ensure_directories()
        .map_err(|error| PresetError(error.to_string()))?;
    let source_path = engine_paths.builtin_presets_dir.join(file_name);
    if !source_path.is_file() {
        return Err(PresetError(format!(
            "Default built-in preset not found: {}",
            source_path.display()
        )));
    }
    read_preset_file_text(&source_path).map_err(PresetError)
}

/// python `_remove_active_remote_binding_after_reset`: удаляет активную
/// URL-привязку после удаления user-копии.
///
/// `auto=False` означает не удалённую привязку, а запомненный URL после
/// действия «Отвязать». Её нельзя удалять при сбросе: повторный импорт той же
/// ссылки должен найти прежнюю запись и не создать дубликат. Активная
/// привязка, наоборот, больше не должна относиться к восстановленному
/// builtin-файлу — иначе автосинхронизация снова создаст user-копию.
fn remove_active_remote_binding_after_reset(backend: &impl PresetBackend, file_name: &str) {
    let key = file_name.trim();
    if key.is_empty() {
        return;
    }
    let binding: Option<RemoteBindingSnapshot> =
        backend.get_remote_preset_binding(backend.engine(), key);
    if binding.is_some_and(|binding| binding.auto) {
        backend.delete_remote_binding_meta(backend.engine(), key);
    }
}

/// python `_existing_builtin_override_paths`: user-файлы, которые
/// соответствуют текущим builtin-файлам.
fn existing_builtin_override_paths(backend: &impl PresetBackend) -> Vec<(String, PathBuf)> {
    let paths = backend.app_paths().engine_paths(Some(backend.engine()));
    let engine_paths = match paths.ensure_directories() {
        Ok(paths) => paths,
        Err(_) => return Vec::new(),
    };
    let user_dir = &engine_paths.user_presets_dir;
    list_builtin_presets(&engine_paths.builtin_presets_dir)
        .into_iter()
        .filter_map(|builtin_path| {
            let file_name = builtin_path.file_name()?.to_string_lossy().to_string();
            let user_path = user_dir.join(&file_name);
            user_path.exists().then_some((file_name, user_path))
        })
        .collect()
}

/// python `_user_preset_path`.
fn user_preset_path(backend: &impl PresetBackend, file_name: &str) -> Option<PathBuf> {
    let paths = backend.app_paths().engine_paths(Some(backend.engine()));
    let engine_paths = paths.ensure_directories().ok()?;
    Some(engine_paths.user_presets_dir.join(file_name.trim()))
}

/// python `rename_by_file_name`: переименование с переписыванием шапки
/// `# Preset:`; выбранному пресету обновляется источник.
pub fn rename_by_file_name(
    backend: &impl PresetBackend,
    file_name: &str,
    new_name: &str,
) -> PresetResult<PresetManifest> {
    let manifest = backend
        .get_manifest_by_file_name(file_name)
        .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
    if manifest.kind.trim().to_lowercase() == "builtin" {
        return Err(PresetError(format!(
            "Built-in preset cannot be renamed: {}",
            manifest.name
        )));
    }
    let was_selected = backend.is_selected_file_name(&manifest.file_name);
    let source_text = backend.read_source_text_by_file_name(&manifest.file_name)?;
    let new_name = unique_preset_name(backend, new_name, Some(&manifest.file_name))?;
    let renamed = backend.preset_file_store().rename_preset(
        backend.engine(),
        &manifest.file_name,
        &new_name,
    )?;
    let mut rewritten = rewrite_preset_headers(
        &source_text,
        &new_name,
        header_preset_kind(Some(&manifest.kind)),
    );
    rewritten = backend.normalize_source_text(&rewritten);
    let updated = backend.preset_file_store().update_preset(
        backend.engine(),
        &renamed.file_name,
        &rewritten,
        None,
    )?;
    backend.rename_folder_item_meta(
        folder_scope_key(backend),
        &manifest.file_name,
        &updated.file_name,
    );
    backend.rename_remote_binding_meta(backend.engine(), &manifest.file_name, &updated.file_name);
    if was_selected {
        backend.select_preset(backend.engine(), &updated.file_name, true);
        backend.notify_preset_identity_changed(&updated.file_name);
        backend.refresh_selected_source_preset();
    }
    Ok(updated)
}

/// python `duplicate_by_file_name`: копия пресета с переписанной шапкой.
pub fn duplicate_by_file_name(
    backend: &impl PresetBackend,
    file_name: &str,
    new_name: &str,
) -> PresetResult<PresetManifest> {
    let manifest = backend
        .get_manifest_by_file_name(file_name)
        .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
    let source_text = backend.read_source_text_by_file_name(&manifest.file_name)?;
    let new_name = unique_preset_name(backend, new_name, None)?;
    let mut rewritten = rewrite_preset_headers(
        &source_text,
        &new_name,
        header_preset_kind(Some(&manifest.kind)),
    );
    rewritten = backend.normalize_source_text(&rewritten);
    let duplicated = backend.preset_file_store().create_preset(
        backend.engine(),
        &new_name,
        &rewritten,
        "user",
    )?;
    backend.copy_folder_item_meta(
        folder_scope_key(backend),
        &manifest.file_name,
        &duplicated.file_name,
    );
    backend.notify_presets_changed();
    Ok(duplicated)
}

/// python `create_preset`: новый пресет из текущего текста или из
/// стандартного встроенного.
pub fn create_preset(
    backend: &impl PresetBackend,
    name: &str,
    from_current: bool,
) -> PresetResult<PresetManifest> {
    let source_text = if from_current {
        read_selected_source_text(backend)?
    } else {
        read_standard_builtin_preset(backend)?
    };
    let name = unique_preset_name(backend, name, None)?;
    let mut rewritten = rewrite_preset_headers(&source_text, &name, None);
    rewritten = backend.normalize_source_text(&rewritten);
    let created =
        backend
            .preset_file_store()
            .create_preset(backend.engine(), &name, &rewritten, "user")?;
    backend.notify_presets_changed();
    Ok(created)
}

/// python `read_selected_source_text` через backend: нет выбранного —
/// пустая строка.
fn read_selected_source_text(backend: &impl PresetBackend) -> PresetResult<String> {
    let selected = backend.get_selected_file_name();
    if selected.is_empty() {
        return Ok(String::new());
    }
    backend.read_source_text_by_file_name(&selected)
}

/// python `import_from_file`: TXT-пресет или переносимый ZIP-архив.
pub fn import_from_file(
    backend: &impl PresetBackend,
    src_path: &Path,
    name: Option<&str>,
) -> PresetResult<PresetImportResult> {
    if !src_path.exists() {
        return Err(PresetError(format!(
            "Import source not found: {}",
            src_path.display()
        )));
    }
    let preset_name = {
        // python: str(name or src.stem or "Imported").strip() or "Imported".
        let stem = stem_of_path(src_path).unwrap_or_default();
        let candidate = match name {
            Some(value) if !value.is_empty() => value.to_string(),
            _ => {
                if stem.is_empty() {
                    "Imported".to_string()
                } else {
                    stem
                }
            }
        };
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            "Imported".to_string()
        } else {
            trimmed.to_string()
        }
    };

    let is_zip = src_path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
    if is_zip {
        return import_portable_preset(backend, src_path, &preset_name);
    }
    let source_text = read_preset_file_text(src_path).map_err(PresetError)?;
    if let Err(error) = validate_preset_source_text(&source_text, backend.engine()) {
        return Err(PresetError(format!("Файл не похож на пресет: {error}")));
    }
    let preset_name = unique_preset_name(backend, &preset_name, None)?;
    let mut rewritten = rewrite_preset_headers(&source_text, &preset_name, Some("imported"));
    rewritten = backend.normalize_source_text(&rewritten);
    let imported = backend.preset_file_store().create_preset(
        backend.engine(),
        &preset_name,
        &rewritten,
        "imported",
    )?;
    backend.delete_folder_item_meta(folder_scope_key(backend), &imported.file_name);
    backend.notify_presets_changed();
    Ok(PresetImportResult {
        manifest: imported,
        imported_list_files: Vec::new(),
        renamed_list_files: Vec::new(),
    })
}

/// python `export_plain_text_by_file_name` — экспорт (plain TXT или ZIP).
pub fn export_plain_text_by_file_name(
    backend: &impl PresetBackend,
    file_name: &str,
    dest_path: &Path,
) -> PresetResult<crate::portable_archive::PresetExportResult> {
    export_preset_with_lists(backend, file_name, dest_path)
}

/// python `reset_to_builtin_by_file_name`: user-копия удаляется, на её месте
/// снова живёт встроенный пресет с тем же именем файла.
pub fn reset_to_builtin_by_file_name(
    backend: &impl PresetBackend,
    file_name: &str,
) -> PresetResult<PresetManifest> {
    let manifest = backend
        .get_manifest_by_file_name(file_name)
        .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
    let paths = backend.app_paths().engine_paths(Some(backend.engine()));
    let engine_paths = paths
        .ensure_directories()
        .map_err(|error| PresetError(error.to_string()))?;
    let builtin_path = engine_paths.builtin_presets_dir.join(&manifest.file_name);
    if manifest.kind.trim().to_lowercase() == "builtin" {
        return Ok(manifest);
    }
    if builtin_path.exists() {
        let user_path = user_preset_path(backend, &manifest.file_name);
        let user_existed = user_path.as_ref().is_some_and(|path| path.exists());
        backend
            .preset_file_store()
            .delete_preset(backend.engine(), &manifest.file_name)?;
        let updated = backend
            .get_manifest_by_file_name(&manifest.file_name)
            .ok_or_else(|| PresetError("Built-in preset not found after reset".to_string()))?;
        if user_existed && user_path.as_ref().is_some_and(|path| !path.exists()) {
            remove_active_remote_binding_after_reset(backend, &manifest.file_name);
        }
        if backend.is_selected_file_name(&manifest.file_name) {
            backend.refresh_selected_source_preset();
        }
        backend.notify_preset_content_changed(&updated.file_name, "");
        return Ok(updated);
    }
    Err(PresetError(
        "Сброс невозможен: для этого пользовательского preset-а нет встроенного preset-а с таким же именем файла."
            .to_string(),
    ))
}

/// python `reset_all_to_builtin`: удаляет все user-копии встроенных пресетов.
pub fn reset_all_to_builtin(backend: &impl PresetBackend) -> PresetResult<BuiltinResetResult> {
    let override_paths = existing_builtin_override_paths(backend);
    let result = reset_all_builtin_overrides(backend.engine(), backend.app_paths())?;
    for (file_name, user_path) in override_paths {
        if !user_path.exists() {
            remove_active_remote_binding_after_reset(backend, &file_name);
        }
    }
    backend.notify_presets_changed();
    let selected = backend.get_selected_file_name();
    if !selected.is_empty() && backend.get_manifest_by_file_name(&selected).is_some() {
        backend.refresh_selected_source_preset();
        backend.notify_preset_content_changed(&selected, "");
    }
    Ok(result)
}

/// python `delete_by_file_name`: удаление user-пресета с метой.
pub fn delete_by_file_name(backend: &impl PresetBackend, file_name: &str) -> PresetResult<()> {
    let manifest = backend
        .get_manifest_by_file_name(file_name)
        .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
    if manifest.kind.trim().to_lowercase() == "builtin" {
        return Err(PresetError(format!(
            "Built-in preset cannot be deleted: {}",
            manifest.name
        )));
    }
    backend.ensure_can_delete(backend.engine(), &manifest.file_name)?;
    backend
        .preset_file_store()
        .delete_preset(backend.engine(), &manifest.file_name)?;
    backend.delete_folder_item_meta(folder_scope_key(backend), &manifest.file_name);
    backend.delete_remote_binding_meta(backend.engine(), &manifest.file_name);
    backend.notify_presets_changed();
    Ok(())
}

/// python `_ENGINE_TO_HIERARCHY_SCOPE` + `_folder_scope_key` сервиса: движок
/// → ключ папок пресетов.
pub fn folder_scope_key(backend: &impl PresetBackend) -> &'static str {
    match backend.engine().trim().to_lowercase().as_str() {
        primecore_mode::ENGINE_WINWS2 => primecore_mode::PRESETS_SCOPE_WINWS2,
        _ => primecore_mode::PRESETS_SCOPE_WINWS1,
    }
}

/// python `Path(src).stem`.
fn stem_of_path(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_string_lossy().to_string();
    Some(crate::file_store::stem_of(&file_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_service::PresetModeHooks;
    use primecore_mode::AppPaths;

    /// Минимальный backend для чистых функций (python подставлял сервис).
    struct TestBackend {
        engine: String,
        app_paths: AppPaths,
    }

    impl PresetModeHooks for TestBackend {}

    impl PresetBackend for TestBackend {
        fn engine(&self) -> &str {
            &self.engine
        }
        fn launch_method(&self) -> &str {
            "winws2"
        }
        fn app_paths(&self) -> &AppPaths {
            &self.app_paths
        }
        fn preset_file_store(&self) -> &crate::file_store::PresetFileStore {
            unreachable!("в этих тестах store не нужен")
        }
        fn normalize_source_text(&self, source_text: &str) -> String {
            source_text.to_string()
        }
        fn get_manifest_by_file_name(&self, _file_name: &str) -> Option<PresetManifest> {
            None
        }
        fn read_source_text_by_file_name(&self, _file_name: &str) -> PresetResult<String> {
            Err(PresetError("not found".to_string()))
        }
        fn is_selected_file_name(&self, _file_name: &str) -> bool {
            false
        }
    }

    #[test]
    fn folder_scope_key_follows_engine() {
        // python: _ENGINE_TO_HIERARCHY_SCOPE + _folder_scope_key.
        let root =
            std::env::temp_dir().join(format!("primecore-presets-ops-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let app_paths = AppPaths {
            user_root: root.clone(),
            local_root: root.clone(),
        };
        let winws2 = TestBackend {
            engine: "WinWS2".to_string(),
            app_paths: app_paths.clone(),
        };
        assert_eq!(
            folder_scope_key(&winws2),
            primecore_mode::PRESETS_SCOPE_WINWS2
        );
        let winws1 = TestBackend {
            engine: "winws1".to_string(),
            app_paths: app_paths.clone(),
        };
        assert_eq!(
            folder_scope_key(&winws1),
            primecore_mode::PRESETS_SCOPE_WINWS1
        );
        // python: неизвестный движок попадает в winws1-ветку по умолчанию.
        let unknown = TestBackend {
            engine: "other".to_string(),
            app_paths,
        };
        assert_eq!(
            folder_scope_key(&unknown),
            primecore_mode::PRESETS_SCOPE_WINWS1
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
