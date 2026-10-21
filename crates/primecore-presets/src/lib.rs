//! Крейт `primecore-presets` — перенос чистой логики python-пакета
//! `presets` (zapretgui/src/presets) в Rust.
//!
//! Пресет — точка истины: всё, что запускает winws/winws2, видно в тексте
//! пресета. Состав крейта:
//!
//! - [`preset_contract`] — порт `presets/preset_contract.py`: единственная
//!   нормализация текста перед записью (`normalize_preset_source_for_save`),
//!   номера версий встроенных пресетов и константы договора;
//! - [`preset_text_ops`] — порт `presets/preset_text_ops.py`: переписывание
//!   шапки `# Preset:`/`# PresetKind:`, структурная валидация импортируемого
//!   пресета, переключение `--debug`;
//! - [`file_store`] — порт `presets/file_store.py`: `PresetFileStore`
//!   (сканирование папок пресетов, манифесты, создание/обновление/
//!   переименование/удаление файлов пресетов);
//! - [`file_service`] — порт файловой части `presets/file_service.py`
//!   (`PresetFileService`): сохранение текста, разовый перевод пресетов
//!   пользователя, замена устаревших копий встроенных пресетов;
//! - [`preset_file_ops`] — порт `presets/preset_file_ops.py`: переименование,
//!   дублирование, создание, импорт TXT, сброс к встроенному;
//! - [`portable_archive`] — порт `presets/portable_archive.py`: переносимый
//!   ZIP-архив пресета и его пользовательских списков;
//! - [`zipio`] — минимальный читатель/писатель ZIP для [`portable_archive`]
//!   (Rust-заменитель python `zipfile`);
//! - [`list_metadata`] / [`lightweight_metadata`] — лёгкие метаданные для
//!   отрисовки списка (`# Description:`/`# IconColor:`, время изменения);
//! - [`preset_url_import`] — чистая часть `presets/preset_url_import.py`:
//!   валидация ссылки импорта и имя файла из URL/заголовков (без сети);
//! - [`builtin_catalog`], [`builtin_reset_support`], [`icon_color`],
//!   [`cache_signatures`], [`selection_state`] — маленькие чистые модули
//!   пакета.
//!
//! НЕ переносится (PyQt/сеть/потоки — остаётся в python-приложении или
//! переносится отдельными срезами): `ui_store.py`, `display_state*.py`,
//! `user_presets_*`, `mode_coordinator.py`, `remote_sync*.py`,
//! `remote_bindings.py`, `native_dir_watcher.py`, `selection_service.py`,
//! `raw_preset_loader.py` (целиком состоит из PyQt-воркеров),
//! `folders.py` (мета папок поверх хранилища состояния), `commands.py`
//! (тонкие фабрики над сервисами приложения).
//!
//! Отклонения от python (осознанные):
//! - журналирование (`log.log`) — забота вызывающего слоя: ядро возвращает
//!   значения и причины отказов, а не пишет в журнал;
//! - реестр «своих записей» для подавления watcher-а
//!   (`presets/own_write_registry.py`) не переносится вместе с watcher-ом;
//! - время в метаданных (`modified_display`) считается по UTC: часовой пояс
//!   применяет слой отображения (как в `primecore-diagnostics`);
//! - сравнения имён в python частично используют `casefold()`, в Rust —
//!   `to_lowercase()` (для имён пресетов это эквивалентно).

pub mod builtin_catalog;
pub mod builtin_reset_support;
pub mod cache_signatures;
pub mod errors;
pub mod file_service;
pub mod file_store;
pub mod icon_color;
pub mod lightweight_metadata;
pub mod list_metadata;
pub mod portable_archive;
pub mod preset_contract;
pub mod preset_file_ops;
pub mod preset_text_ops;
pub mod preset_url_import;
pub mod selection_state;
pub mod timefmt;
pub mod zipio;

pub use builtin_catalog::list_builtin_presets;
pub use builtin_reset_support::reset_all_builtin_overrides;
pub use errors::PresetError;
pub use file_service::{
    BuiltinOverrideRefreshResult, PresetContractMigrationResult, PresetFileService, PresetModeHooks,
};
pub use file_store::PresetFileStore;
pub use icon_color::{normalize_preset_icon_color, DEFAULT_PRESET_ICON_COLOR};
pub use lightweight_metadata::build_lightweight_preset_metadata;
pub use list_metadata::{
    build_preset_stat_metadata, read_preset_list_metadata, read_preset_stat_metadata,
    PresetListMetadata,
};
pub use portable_archive::{
    collect_portable_list_files, export_preset_with_lists, import_portable_preset,
    PortableListFile, PresetExportResult, PresetImportResult,
};
pub use preset_contract::{
    builtin_preset_version, normalize_preset_source_for_save, relocate_legacy_debug_log_file,
    strip_utf8_bom,
};
pub use preset_file_ops::{
    create_preset, delete_by_file_name, duplicate_by_file_name, export_plain_text_by_file_name,
    import_from_file, rename_by_file_name, reset_all_to_builtin, reset_to_builtin_by_file_name,
};
pub use preset_text_ops::{rewrite_preset_headers, validate_preset_source_text};
pub use preset_url_import::{
    is_https_preset_import_url, preset_file_stem_from_url, validate_preset_import_url,
    DownloadedPresetFile,
};
pub use selection_state::PresetSelectionState;

/// Пресет-манифест (`presets/__init__.py`, `PresetManifest`): лёгкая запись
/// о файле пресета для списков и настроек.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetManifest {
    pub file_name: String,
    pub name: String,
    pub updated_at: String,
    pub kind: String,
    pub storage_scope: String,
}

impl PresetManifest {
    /// python-конструктор с его значениями по умолчанию
    /// (`kind="user"`, `storage_scope="user"`).
    #[must_use]
    pub fn new(
        file_name: impl Into<String>,
        name: impl Into<String>,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            file_name: file_name.into(),
            name: name.into(),
            updated_at: updated_at.into(),
            kind: "user".to_string(),
            storage_scope: "user".to_string(),
        }
    }
}
