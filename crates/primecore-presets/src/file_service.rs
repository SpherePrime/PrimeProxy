//! Порт файловой части `presets/file_service.py` — `PresetFileService`.
//!
//! Сервис работает только с физическими preset-файлами: создать,
//! переименовать, импортировать, сбросить, сохранить текст. Он не строит
//! список profile и не читает содержимое preset-а.
//!
//! Части python-сервиса, завязанные на PyQt (`ui_store`, `selection_service`,
//! `mode_coordinator`), мету папок (`presets/folders.py`) и привязки к
//! удалённым источникам (`remote_sync*`), в крейт не переносятся: ядро
//! вызывает их через крючки [`PresetModeHooks`] (по умолчанию —
//! [`NoHooks`], ничего не делающие), а настоящий слой подключает их сам.

use primecore_mode::{
    engine_for_launch_method_or_none, normalize_launch_method, AppPaths, ENGINE_WINWS1,
    ENGINE_WINWS2, PRESETS_SCOPE_WINWS1, PRESETS_SCOPE_WINWS2,
};

use crate::builtin_catalog::list_builtin_presets;
use crate::errors::{PresetError, PresetResult};
use crate::file_store::PresetFileStore;
use crate::preset_contract::{
    builtin_preset_version, normalize_preset_source_for_save, CONTRACT_MIGRATION_CHANGE_KIND,
};
use crate::preset_file_ops;
use crate::PresetManifest;

/// Привязка пресета к удалённому источнику (python-словарь
/// `remote_bindings`): ядро видит только те поля, которые влияют на файловые
/// действия.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBindingSnapshot {
    /// python `binding.get("auto", True)` — ведёт ли копию автосинк.
    pub auto: bool,
    /// python `binding.get("synced_hash", "")`.
    pub synced_hash: String,
}

/// Крючки в PyQt/сетевой слой приложения (python-поля `preset_ui_store`,
/// `preset_mode_coordinator`, `preset_selection_service`, `remote_bindings`).
///
/// Все методы имеют нейтральные значения по умолчанию: уведомления — ничего,
/// привязки — «привязки нет», сравнение аргументов запуска — «не изменились».
pub trait PresetModeHooks {
    /// python `_ui_store().notify_preset_content_changed`.
    fn notify_preset_content_changed(&self, _file_name: &str, _content_change_kind: &str) {}
    /// python `_ui_store().notify_preset_switched`.
    fn notify_preset_switched(&self, _file_name: &str) {}
    /// python `_ui_store().notify_preset_identity_changed`.
    fn notify_preset_identity_changed(&self, _file_name: &str) {}
    /// python `_ui_store().notify_presets_changed`.
    fn notify_presets_changed(&self) {}
    /// python `preset_mode_coordinator.refresh_selected_launch_preset`.
    fn refresh_selected_launch_preset(&self, _launch_method: &str) {}
    /// python `preset_mode_coordinator.get_selected_source_manifest`.
    fn get_selected_source_manifest(&self, _launch_method: &str) -> Option<PresetManifest> {
        None
    }
    /// python `preset_mode_coordinator.select_preset_file_name`.
    fn select_preset_file_name(
        &self,
        _launch_method: &str,
        _file_name: &str,
    ) -> Option<PresetManifest> {
        None
    }
    /// python `preset_selection_service.select_preset`.
    fn select_preset(&self, _engine: &str, _file_name: &str, _same_preset_renamed: bool) {}
    /// python `preset_selection_service.ensure_can_delete`.
    fn ensure_can_delete(&self, _engine: &str, _file_name: &str) -> PresetResult<()> {
        Ok(())
    }
    /// python `_rename_folder_item_meta` (metа папок/закрепа/оценки).
    fn rename_folder_item_meta(
        &self,
        _scope_key: &str,
        _old_file_name: &str,
        _new_file_name: &str,
    ) {
    }
    /// python `_copy_folder_item_meta`.
    fn copy_folder_item_meta(
        &self,
        _scope_key: &str,
        _source_file_name: &str,
        _new_file_name: &str,
    ) {
    }
    /// python `_delete_folder_item_meta`.
    fn delete_folder_item_meta(&self, _scope_key: &str, _preset_file_name: &str) {}
    /// python `_rename_remote_binding_meta`.
    fn rename_remote_binding_meta(
        &self,
        _engine: &str,
        _old_file_name: &str,
        _new_file_name: &str,
    ) {
    }
    /// python `_delete_remote_binding_meta`.
    fn delete_remote_binding_meta(&self, _engine: &str, _preset_file_name: &str) {}
    /// python `remote_bindings.get_remote_preset_binding`.
    fn get_remote_preset_binding(
        &self,
        _engine: &str,
        _file_name: &str,
    ) -> Option<RemoteBindingSnapshot> {
        None
    }
    /// python `_carry_remote_sync_hash`: перенос запомненного хэша автосинка
    /// на новый текст после разового перевода (действие программы, а не
    /// правка пользователя). Логика хэша живёт в слое `remote_sync`.
    fn carry_remote_sync_hash(&self, _file_name: &str, _old_text: &str, _new_text: &str) {}
    /// python `has_active_remote_binding`: ведёт ли эту копию автосинк
    /// по ссылке (её содержимым владеет источник).
    fn has_active_remote_binding(&self, _engine: &str, _file_name: &str) -> bool {
        false
    }
    /// python-сравнение `launch_args_from_preset_text(new) ==
    /// launch_args_from_preset_text(old)` — принадлежит слою запуска
    /// (`winws_runtime`); ядро спрашивает, изменились ли аргументы запуска.
    fn launch_args_changed(&self, _new_text: &str, _old_text: &str) -> bool {
        false
    }
}

/// python-пустышка: сервис без PyQt-слоя (в тестах, в утилитах CLI).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl PresetModeHooks for NoHooks {}

// python в роли backend-а для файловых операций использовал сам сервис,
// а его hook-методы шли через поля-объекты PyQt-слоя: делегируем в `hooks`.
impl<H: PresetModeHooks> PresetModeHooks for PresetFileService<H> {
    fn rename_remote_binding_meta(&self, engine: &str, old_file_name: &str, new_file_name: &str) {
        self.hooks
            .rename_remote_binding_meta(engine, old_file_name, new_file_name);
    }
    fn delete_remote_binding_meta(&self, engine: &str, preset_file_name: &str) {
        self.hooks
            .delete_remote_binding_meta(engine, preset_file_name);
    }
    fn get_remote_preset_binding(
        &self,
        engine: &str,
        file_name: &str,
    ) -> Option<RemoteBindingSnapshot> {
        self.hooks.get_remote_preset_binding(engine, file_name)
    }
    fn carry_remote_sync_hash(&self, file_name: &str, old_text: &str, new_text: &str) {
        self.hooks
            .carry_remote_sync_hash(file_name, old_text, new_text);
    }
    fn has_active_remote_binding(&self, engine: &str, file_name: &str) -> bool {
        self.hooks.has_active_remote_binding(engine, file_name)
    }
    fn launch_args_changed(&self, new_text: &str, old_text: &str) -> bool {
        self.hooks.launch_args_changed(new_text, old_text)
    }
}

/// Интерфейс «backend» из python `preset_file_ops.py` / `portable_archive.py`:
/// всё, что файловым операциям нужно от сервиса (утиной типизацией в python).
pub trait PresetBackend: PresetModeHooks {
    fn engine(&self) -> &str;
    fn launch_method(&self) -> &str;
    fn app_paths(&self) -> &AppPaths;
    fn preset_file_store(&self) -> &PresetFileStore;
    /// python `normalize_source_text` — нормализация сохранения своего движка.
    fn normalize_source_text(&self, source_text: &str) -> String;
    fn get_manifest_by_file_name(&self, file_name: &str) -> Option<PresetManifest>;
    fn read_source_text_by_file_name(&self, file_name: &str) -> PresetResult<String>;
    fn is_selected_file_name(&self, file_name: &str) -> bool;
    /// python `get_selected_file_name` — имя выбранного source-пресета.
    fn get_selected_file_name(&self) -> String {
        self.get_selected_source_manifest(self.launch_method())
            .map(|manifest| manifest.file_name)
            .unwrap_or_default()
    }
    /// python `_refresh_selected_source_preset`: пересобрать выбранный пресет.
    fn refresh_selected_source_preset(&self) {
        self.refresh_selected_launch_preset(self.launch_method());
    }
}

/// Итог разового перевода пресетов пользователя (preset_contract, пункт 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresetContractMigrationResult {
    /// Имена файлов, текст которых изменился и был записан.
    pub migrated: Vec<String>,
    /// (имя файла, причина) — файл не удалось прочитать или записать.
    pub failed: Vec<(String, String)>,
}

/// Версии для замены устаревшей копии встроенного пресета:
/// (версия user-копии или None, версия встроенного).
type BuiltinOverrideVersions = (Option<Vec<i64>>, Vec<i64>);

/// Итог замены устаревших копий встроенных пресетов (preset_contract, пункт 7).
///
/// `refreshed` — (имя файла, номер версии копии или "", номер версии встроенного).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuiltinOverrideRefreshResult {
    pub refreshed: Vec<(String, String, String)>,
    pub failed: Vec<(String, String)>,
}

/// Файловый сервис пресетного режима (python `PresetFileService`).
pub struct PresetFileService<H: PresetModeHooks = NoHooks> {
    pub engine: String,
    pub launch_method: String,
    pub app_paths: AppPaths,
    pub preset_file_store: PresetFileStore,
    pub hooks: H,
}

/// python `_with_final_newline`: текст так, как его запишет хранилище.
#[must_use]
pub fn with_final_newline(text: &str) -> String {
    if text.ends_with('\n') {
        text.to_string()
    } else {
        format!("{text}\n")
    }
}

/// python `_version_text`: «2.44.1» или пустая строка.
#[must_use]
pub fn version_text(version: Option<&[i64]>) -> String {
    match version {
        Some(parts) if !parts.is_empty() => parts
            .iter()
            .map(|part| part.to_string())
            .collect::<Vec<_>>()
            .join("."),
        _ => String::new(),
    }
}

impl<H: PresetModeHooks> PresetFileService<H> {
    /// python `from_launch_method`: движок строго по методу запуска.
    pub fn from_launch_method(
        launch_method: &str,
        app_paths: AppPaths,
        hooks: H,
    ) -> PresetResult<Self> {
        let method = normalize_launch_method(Some(launch_method), Some(""));
        let engine = engine_for_launch_method_or_none(Some(&method)).ok_or_else(|| {
            PresetError(format!("Unsupported preset launch method: {launch_method}"))
        })?;
        let preset_file_store = PresetFileStore::new(app_paths.clone());
        Ok(Self {
            engine: engine.to_string(),
            launch_method: method,
            app_paths,
            preset_file_store,
            hooks,
        })
    }

    /// python `_folder_scope_key`: движок → ключ папок пресетов.
    pub fn folder_scope_key(&self) -> PresetResult<&'static str> {
        match self.engine.as_str() {
            ENGINE_WINWS2 => Ok(PRESETS_SCOPE_WINWS2),
            ENGINE_WINWS1 => Ok(PRESETS_SCOPE_WINWS1),
            other => Err(PresetError(format!(
                "Unsupported preset mode engine: {other}"
            ))),
        }
    }

    /// python `list_manifests`.
    #[must_use]
    pub fn list_manifests(&self) -> Vec<PresetManifest> {
        self.preset_file_store.list_manifests(&self.engine)
    }

    /// python `get_selected_manifest`: выбранный source-пресет (или None —
    /// «не выбран»; причину пишет вызывающий слой).
    #[must_use]
    pub fn get_selected_manifest(&self) -> Option<PresetManifest> {
        self.hooks.get_selected_source_manifest(&self.launch_method)
    }

    /// python `get_selected_file_name`.
    #[must_use]
    pub fn get_selected_file_name(&self) -> String {
        self.get_selected_manifest()
            .map(|manifest| manifest.file_name)
            .unwrap_or_default()
    }

    /// python `is_selected_file_name`.
    #[must_use]
    pub fn is_selected_file_name(&self, file_name: &str) -> bool {
        let current = self.get_selected_file_name().trim().to_string();
        let candidate = self
            .preset_file_store
            .resolve_file_name(&self.engine, file_name);
        let candidate = if candidate.is_empty() {
            file_name.trim().to_string()
        } else {
            candidate.trim().to_string()
        };
        !current.is_empty()
            && !candidate.is_empty()
            && current.to_lowercase() == candidate.to_lowercase()
    }

    /// python `get_manifest_by_file_name`.
    #[must_use]
    pub fn get_manifest_by_file_name(&self, file_name: &str) -> Option<PresetManifest> {
        self.preset_file_store.get_manifest(&self.engine, file_name)
    }

    /// python `get_source_path_by_file_name`.
    pub fn get_source_path_by_file_name(
        &self,
        file_name: &str,
    ) -> PresetResult<std::path::PathBuf> {
        self.preset_file_store
            .get_source_path(&self.engine, file_name)
    }

    /// python `read_source_text_by_file_name`.
    pub fn read_source_text_by_file_name(&self, file_name: &str) -> PresetResult<String> {
        let manifest = self
            .get_manifest_by_file_name(file_name)
            .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
        self.preset_file_store
            .read_source_text(&self.engine, &manifest.file_name)
    }

    /// python `read_selected_source_text`: нет выбранного — пустая строка.
    pub fn read_selected_source_text(&self) -> PresetResult<String> {
        let selected = self.get_selected_file_name();
        if selected.is_empty() {
            return Ok(String::new());
        }
        self.read_source_text_by_file_name(&selected)
    }

    /// python `normalize_source_text`.
    #[must_use]
    pub fn normalize_source_text(&self, source_text: &str) -> String {
        normalize_preset_source_for_save(source_text, &self.engine)
    }

    /// python `notify_preset_content_changed` и родственные уведомления —
    /// через крючки слоя приложения.
    pub fn notify_preset_content_changed(&self, file_name: &str, content_change_kind: &str) {
        let candidate = file_name.trim();
        if !candidate.is_empty() {
            self.hooks
                .notify_preset_content_changed(candidate, content_change_kind.trim());
        }
    }

    /// python `notify_preset_switched`.
    pub fn notify_preset_switched(&self, file_name: &str) {
        let candidate = file_name.trim();
        if !candidate.is_empty() {
            self.hooks.notify_preset_switched(candidate);
        }
    }

    /// python `notify_preset_identity_changed`.
    pub fn notify_preset_identity_changed(&self, file_name: &str) {
        let candidate = file_name.trim();
        if !candidate.is_empty() {
            self.hooks.notify_preset_identity_changed(candidate);
        }
    }

    /// python `notify_presets_changed`.
    pub fn notify_presets_changed(&self) {
        self.hooks.notify_presets_changed();
    }

    /// python `select_file_name` (без Qt-обвязки): выбор пресета через
    /// координатор и уведомление о смене.
    pub fn select_file_name(&self, file_name: &str) -> Option<PresetManifest> {
        let previous = self.get_selected_file_name().trim().to_string();
        let profile = self
            .hooks
            .select_preset_file_name(&self.launch_method, file_name)?;
        let next = profile.file_name.trim().to_string();
        if !previous.is_empty()
            && !next.is_empty()
            && previous.to_lowercase() == next.to_lowercase()
        {
            return Some(profile);
        }
        self.notify_preset_switched(&profile.file_name);
        Some(profile)
    }

    /// python `activate_preset_file`.
    pub fn activate_preset_file(&self, file_name: &str) -> Option<PresetManifest> {
        self.select_file_name(file_name)
    }

    /// python `publish_preset_content_changed_by_file_name`: файл изменился —
    /// пересобрать выбранный пресет и уведомить UI.
    pub fn publish_preset_content_changed_by_file_name(
        &self,
        file_name: &str,
        content_change_kind: &str,
    ) -> PresetResult<PresetManifest> {
        let manifest = self
            .get_manifest_by_file_name(file_name)
            .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
        if self.is_selected_file_name(&manifest.file_name) {
            self.hooks
                .refresh_selected_launch_preset(&self.launch_method);
        }
        self.notify_preset_content_changed(&manifest.file_name, content_change_kind);
        Ok(manifest)
    }

    /// python `save_source_text_by_file_name`: нормализованный текст
    /// записывается, только если он отличается от нормализованного текущего.
    pub fn save_source_text_by_file_name(
        &self,
        file_name: &str,
        source_text: &str,
        publish_content_changed: bool,
        content_change_kind: &str,
    ) -> PresetResult<PresetManifest> {
        let manifest = self
            .get_manifest_by_file_name(file_name)
            .ok_or_else(|| PresetError(format!("Preset not found: {file_name}")))?;
        let normalized = self.normalize_source_text(source_text);
        let current_text = self.read_source_text_by_file_name(&manifest.file_name)?;
        if normalized == self.normalize_source_text(&current_text) {
            return Ok(manifest);
        }
        let updated = self.preset_file_store.update_preset(
            &self.engine,
            &manifest.file_name,
            &normalized,
            None,
        )?;
        if publish_content_changed {
            self.publish_preset_content_changed_by_file_name(
                &updated.file_name,
                content_change_kind,
            )?;
        }
        Ok(updated)
    }

    /// python `save_selected_source_text`.
    pub fn save_selected_source_text(
        &self,
        source_text: &str,
        content_change_kind: &str,
    ) -> PresetResult<PresetManifest> {
        let selected = self.get_selected_file_name();
        if selected.is_empty() {
            return Err(PresetError("Selected preset is required".to_string()));
        }
        self.save_source_text_by_file_name(&selected, source_text, true, content_change_kind)
    }

    /// Разовый перевод пресетов из папки пользователя в формат сохранения.
    ///
    /// Пункт 6 договора `preset_contract`: каждый пресет пользователя проходит
    /// ту же нормализацию, что и при сохранении (для winws2 — полный блок
    /// `--lua-init`), и записывается, только если текст на диске от этого
    /// изменится. Встроенные пресеты не трогаются: запись в хранилище создала
    /// бы для них скрытую копию в папке пользователя.
    ///
    /// Отклонение от python: сравнение аргументов запуска и уведомление UI
    /// выполняет слой приложения через крючки [`PresetModeHooks::
    /// launch_args_changed`] и обычный `publish_preset_content_changed_...`.
    pub fn migrate_user_presets_to_save_contract(&self) -> PresetContractMigrationResult {
        let mut migrated: Vec<String> = Vec::new();
        let mut failed: Vec<(String, String)> = Vec::new();
        for manifest in self.list_manifests() {
            if manifest.storage_scope.trim().to_lowercase() != "user" {
                continue;
            }
            let file_name = manifest.file_name.clone();
            let (current_text, normalized) = match self
                .preset_file_store
                .read_source_text(&self.engine, &file_name)
                .map(|current| {
                    let normalized = self.normalize_source_text(&current);
                    (current, normalized)
                }) {
                Ok(pair) => pair,
                Err(error) => {
                    failed.push((file_name, error.to_string()));
                    continue;
                }
            };
            if normalized == with_final_newline(&current_text) {
                continue;
            }
            if let Err(error) =
                self.preset_file_store
                    .update_preset(&self.engine, &file_name, &normalized, None)
            {
                failed.push((file_name, error.to_string()));
                continue;
            }
            migrated.push(file_name.clone());
            self.hooks
                .carry_remote_sync_hash(&file_name, &current_text, &normalized);
            if !self.hooks.launch_args_changed(&normalized, &current_text) {
                continue;
            }
            if let Err(error) = self.publish_preset_content_changed_by_file_name(
                &file_name,
                CONTRACT_MIGRATION_CHANGE_KIND,
            ) {
                failed.push((
                    file_name,
                    format!("файл записан, но программа не узнала об изменении: {error}"),
                ));
            }
        }
        PresetContractMigrationResult { migrated, failed }
    }

    pub fn refresh_outdated_builtin_overrides(&self) -> BuiltinOverrideRefreshResult {
        let mut refreshed: Vec<(String, String, String)> = Vec::new();
        let mut failed: Vec<(String, String)> = Vec::new();
        let engine_paths = self.app_paths.engine_paths(Some(&self.engine));
        if let Err(error) = engine_paths.ensure_directories() {
            return BuiltinOverrideRefreshResult {
                refreshed,
                failed: vec![("".to_string(), error.to_string())],
            };
        }
        for builtin_path in list_builtin_presets(&engine_paths.builtin_presets_dir) {
            let Some(file_name) = builtin_path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
            else {
                continue;
            };
            let user_path = engine_paths.user_presets_dir.join(&file_name);
            if !user_path.is_file() {
                continue;
            }
            // Ok(Some(версии)) — замена сделана; Ok(None) — копия актуальна,
            // её нет или ею владеет автосинк (python `continue` внутри try).
            let outcome: PresetResult<Option<BuiltinOverrideVersions>> = (|| {
                let builtin_text = primecore_files::decode::read_preset_file_text(&builtin_path)
                    .map_err(PresetError)?;
                let Some(builtin_version) = builtin_preset_version(&builtin_text) else {
                    return Ok(None);
                };
                let user_text = primecore_files::decode::read_preset_file_text(&user_path)
                    .map_err(PresetError)?;
                let user_version = builtin_preset_version(&user_text);
                if user_version
                    .as_ref()
                    .is_some_and(|version| version.as_slice() >= builtin_version.as_slice())
                {
                    return Ok(None);
                }
                if self
                    .hooks
                    .has_active_remote_binding(&self.engine, &file_name)
                {
                    return Ok(None);
                }
                let backup_dir = engine_paths.replaced_presets_dir();
                std::fs::create_dir_all(&backup_dir)
                    .map_err(|error| PresetError(error.to_string()))?;
                let backup_bytes =
                    std::fs::read(&user_path).map_err(|error| PresetError(error.to_string()))?;
                std::fs::write(backup_dir.join(&file_name), backup_bytes)
                    .map_err(|error| PresetError(error.to_string()))?;
                preset_file_ops::reset_to_builtin_by_file_name(self, &file_name)?;
                Ok(Some((user_version, builtin_version)))
            })();
            match outcome {
                Ok(Some((user_version, builtin_version))) => refreshed.push((
                    file_name,
                    version_text(user_version.as_deref()),
                    version_text(Some(&builtin_version)),
                )),
                Ok(None) => {}
                Err(error) => failed.push((file_name, error.to_string())),
            }
        }
        BuiltinOverrideRefreshResult { refreshed, failed }
    }
}

impl<H: PresetModeHooks> PresetBackend for PresetFileService<H> {
    fn engine(&self) -> &str {
        &self.engine
    }

    fn launch_method(&self) -> &str {
        &self.launch_method
    }

    fn app_paths(&self) -> &AppPaths {
        &self.app_paths
    }

    fn preset_file_store(&self) -> &PresetFileStore {
        &self.preset_file_store
    }

    fn normalize_source_text(&self, source_text: &str) -> String {
        PresetFileService::normalize_source_text(self, source_text)
    }

    fn get_manifest_by_file_name(&self, file_name: &str) -> Option<PresetManifest> {
        PresetFileService::get_manifest_by_file_name(self, file_name)
    }

    fn read_source_text_by_file_name(&self, file_name: &str) -> PresetResult<String> {
        PresetFileService::read_source_text_by_file_name(self, file_name)
    }

    fn is_selected_file_name(&self, file_name: &str) -> bool {
        PresetFileService::is_selected_file_name(self, file_name)
    }
}

// python: методы сервиса делегируют функциям preset_file_ops с backend=self.
impl<H: PresetModeHooks> PresetFileService<H> {
    /// python `rename_by_file_name`.
    pub fn rename_by_file_name(
        &self,
        file_name: &str,
        new_name: &str,
    ) -> PresetResult<PresetManifest> {
        preset_file_ops::rename_by_file_name(self, file_name, new_name)
    }

    /// python `duplicate_by_file_name`.
    pub fn duplicate_by_file_name(
        &self,
        file_name: &str,
        new_name: &str,
    ) -> PresetResult<PresetManifest> {
        preset_file_ops::duplicate_by_file_name(self, file_name, new_name)
    }

    /// python `create`.
    pub fn create(&self, name: &str, from_current: bool) -> PresetResult<PresetManifest> {
        preset_file_ops::create_preset(self, name, from_current)
    }

    /// python `import_from_file`.
    pub fn import_from_file(
        &self,
        src_path: &std::path::Path,
        name: Option<&str>,
    ) -> PresetResult<crate::portable_archive::PresetImportResult> {
        preset_file_ops::import_from_file(self, src_path, name)
    }

    /// python `export_plain_text_by_file_name`.
    pub fn export_plain_text_by_file_name(
        &self,
        file_name: &str,
        dest_path: &std::path::Path,
    ) -> PresetResult<crate::portable_archive::PresetExportResult> {
        preset_file_ops::export_plain_text_by_file_name(self, file_name, dest_path)
    }

    /// python `reset_to_builtin_by_file_name`.
    pub fn reset_to_builtin_by_file_name(&self, file_name: &str) -> PresetResult<PresetManifest> {
        preset_file_ops::reset_to_builtin_by_file_name(self, file_name)
    }

    /// python `reset_all_to_builtin`.
    pub fn reset_all_to_builtin(
        &self,
    ) -> PresetResult<crate::builtin_reset_support::BuiltinResetResult> {
        preset_file_ops::reset_all_to_builtin(self)
    }

    /// python `delete_by_file_name`.
    pub fn delete_by_file_name(&self, file_name: &str) -> PresetResult<()> {
        preset_file_ops::delete_by_file_name(self, file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_final_newline_matches_python() {
        // python: _with_final_newline
        assert_eq!(with_final_newline("a"), "a\n");
        assert_eq!(with_final_newline("a\n"), "a\n");
        assert_eq!(with_final_newline(""), "\n");
    }

    #[test]
    fn version_text_matches_python() {
        // python: _version_text — «2.44.1» или пустая строка.
        assert_eq!(version_text(Some(&[2, 44, 1])), "2.44.1");
        assert_eq!(version_text(Some(&[])), "");
        assert_eq!(version_text(None), "");
    }

    #[test]
    fn from_launch_method_maps_engine() {
        // python: from_launch_method — движок строго по методу запуска.
        let root =
            std::env::temp_dir().join(format!("primecore-presets-service-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let app_paths = AppPaths {
            user_root: root.clone(),
            local_root: root.clone(),
        };
        let method = primecore_mode::ZAPRET2_MODE;
        let service =
            PresetFileService::from_launch_method(method, app_paths.clone(), NoHooks).unwrap();
        assert_eq!(service.engine, "winws2", "zapret2_mode → winws2");
        assert_eq!(service.launch_method, primecore_mode::ZAPRET2_MODE);
        assert_eq!(service.folder_scope_key().unwrap(), PRESETS_SCOPE_WINWS2);
        assert!(
            PresetFileService::from_launch_method("unknown", app_paths.clone(), NoHooks).is_err()
        );
        assert!(service
            .get_remote_preset_binding("winws2", "x.txt")
            .is_none());
        assert!(
            PresetFileService::from_launch_method("orchestra", app_paths.clone(), NoHooks).is_err(),
            "orchestra — не preset-метод запуска"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use primecore_mode::{AppPaths, ZAPRET2_MODE};
    use std::sync::Mutex;

    /// Хуки-регистратор: как python-тест с `_PresetUiStore`, который падает
    /// на лишнем уведомлении.
    struct RecordingHooks {
        notifications: Mutex<Vec<(String, String)>>,
    }

    impl PresetModeHooks for RecordingHooks {
        fn notify_preset_content_changed(&self, file_name: &str, content_change_kind: &str) {
            self.notifications
                .lock()
                .unwrap()
                .push((file_name.to_string(), content_change_kind.to_string()));
        }
    }

    #[test]
    fn save_same_source_text_skips_write_and_content_signal() {
        // python: test_save_same_source_text_skips_file_write_and_content_signal —
        // неизменённый текст не пишет файл и не уведомляет UI.
        let root = std::env::temp_dir().join(format!(
            "primecore-presets-service-guard-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let app_paths = AppPaths {
            user_root: root.clone(),
            local_root: root.clone(),
        };
        let hooks = RecordingHooks {
            notifications: Mutex::new(Vec::new()),
        };
        let service =
            PresetFileService::from_launch_method(ZAPRET2_MODE, app_paths, hooks).unwrap();
        let created = service
            .preset_file_store
            .create_preset(
                "winws2",
                "Default v5",
                "# Preset: Default v5\n--new\n--filter-tcp=443\n",
                "user",
            )
            .unwrap();

        let result = service
            .save_source_text_by_file_name(
                &created.file_name,
                "# Modified: today\r\n# Preset: Default v5\r\n--new\r\n--filter-tcp=443\r\n",
                true,
                "content",
            )
            .unwrap();
        assert_eq!(result.file_name, created.file_name);
        assert!(
            service.hooks.notifications.lock().unwrap().is_empty(),
            "неизменённый пресет не уведомляет UI"
        );

        // Изменённый текст с publish=true — файл записан, UI уведомлён.
        let changed = service
            .save_source_text_by_file_name(
                &created.file_name,
                "# Preset: Default v5\n--new\n--filter-tcp=443\n--wf-tcp-out=443\n",
                true,
                "content",
            )
            .unwrap();
        assert_eq!(changed.file_name, created.file_name);
        let notifications = service.hooks.notifications.lock().unwrap();
        assert_eq!(
            notifications.as_slice(),
            vec![(created.file_name.clone(), "content".to_string())],
            "одно уведомление после реальной записи"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
