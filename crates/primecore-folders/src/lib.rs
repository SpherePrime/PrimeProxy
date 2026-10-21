//! Крейт `primecore-folders` — перенос чистой логики python-пакета
//! `folders` (zapretgui/src/folders) в Rust.
//!
//! Состав:
//! - [`classify`] — классификаторы папок из `folders/defaults.py`
//!   (`classify_preset_folder`, `classify_profile_folder` и внутренние
//!   правила `_classify_winws1_preset_folder`, `_has_any_token` и т.д.);
//! - [`store`] — порт `folders/store.py`: `normalize_folder_state` и
//!   `FolderLibraryStore` (создание/переименование/удаление/перемещение
//!   папок, метаданные элементов);
//! - [`ordering`] — порт `folders/ordering.py`: `FolderOrderView`,
//!   `resolve_folder_order`, `plan_view_move`, `plan_item_move`,
//!   `build_folder_rows`;
//! - [`pyutil`] — общие хелперы семантики python над `serde_json::Value`
//!   (правдивость `bool(...)`, `int(...)`, `str(...)` для скаляров).
//!
//! Дефолтные наборы папок (`_WINWS2_PRESET_FOLDERS`, `_WINWS1_PRESET_FOLDERS`,
//! `_PROFILE_FOLDERS`, `PROFILE_FOLDER_SPLITS`, `build_default_state`) УЖЕ
//! перенесены в `crates/primecore-settings/src/schema.rs`; здесь они
//! реэкспортируются под исходными именами, чтобы код использовался как в
//! python (`build_default_preset_folders`, `build_default_profile_folders`).
//!
//! `folders/state_lock.py` (`RLock` вокруг операций хранилища) НЕ переносится:
//! это платформенная обвязка потокобезопасности. В Rust-коде синхронизация —
//! забота вызывающей стороны (`Mutex`/`RwLock` вокруг `FolderLibraryStore`).
//!
//! Отклонения от python (осознанные, для значений вне нормализованных
//! состояний): непарсируемые скаляры вместо исключения дают значение по
//! умолчанию (`int("abc")` → default, а не `ValueError`); `str()` от
//! массивов/объектов не поддерживается (в python это repr) — используется
//! значение по умолчанию. На нормализованных состояниях поведение совпадает.

pub mod classify;
pub mod ordering;
pub mod pyutil;
pub mod store;

pub use classify::{classify_preset_folder, classify_profile_folder};
pub use ordering::{
    build_folder_rows, plan_item_move, plan_view_move, resolve_folder_order, FolderOrderView,
};
pub use store::{normalize_folder_state, FolderLibraryStore};

// Константы и дефолтные состояния папок уже перенесены в primecore-settings
// (python folders/defaults.py); реэкспорт под исходными именами.
pub use primecore_settings::schema::{
    default_preset_folders, default_profile_folders, FOLDER_COMMON_KEY as COMMON_FOLDER_KEY,
    FOLDER_PINNED_KEY as PINNED_FOLDER_KEY, FOLDER_VOICE_KEY as VOICE_FOLDER_KEY,
    PROFILE_FOLDER_SPLITS,
};
