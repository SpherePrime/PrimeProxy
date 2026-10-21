//! Порт `folders/store.py`: нормализация состояния библиотеки папок и
//! хранилище `FolderLibraryStore`.
//!
//! Состояние — JSON-значение вида
//! `{"version": 1, "folders": {key: {name, order, collapsed, system}},
//! "items": {item_key: {folder_key, order, rating, pinned?}}}`.
//! Крейт `serde_json` в воркспейсе включён с `preserve_order`, поэтому
//! `serde_json::Map` сохраняет порядок вставки, как dict в python, и
//! порядок правил/слияний совпадает с python-версией.

use std::sync::LazyLock;

use serde_json::{json, Map, Value};

use crate::pyutil::{
    as_int, int_or_zero_field, py_int, state_section_mut, string_or_falsy, truthy,
};
use crate::COMMON_FOLDER_KEY;

static FOLDER_KEY_BASE_RE: LazyLock<Option<fancy_regex::Regex>> =
    LazyLock::new(|| fancy_regex::Regex::new("(?i)[^a-z0-9а-яё]+").ok());
static WHITESPACE_RE: LazyLock<Option<fancy_regex::Regex>> =
    LazyLock::new(|| fancy_regex::Regex::new(r"\s+").ok());

/// Порт `FolderLibraryStore`: изменяемое состояние библиотеки папок с
/// сохранённым дефолтным состоянием. Потоковая обвязка `state_lock.py`
/// (RLock) не переносится — синхронизирует вызывающая сторона.
#[derive(Debug, Clone)]
pub struct FolderLibraryStore {
    default_state: Value,
    state: Value,
}

impl FolderLibraryStore {
    /// python `__init__(state, *, default_state=None)`:
    /// `default_state or state` — при пустом/отсутствующем дефолте
    /// используется само состояние.
    #[must_use]
    pub fn new(state: &Value, default_state: Option<&Value>) -> Self {
        let default_state = match default_state {
            Some(value) if truthy(Some(value)) => value.clone(),
            _ => state.clone(),
        };
        let state = normalize_folder_state(state, &default_state);
        Self {
            default_state,
            state,
        }
    }

    /// python `to_dict`: полная копия состояния.
    #[must_use]
    pub fn to_dict(&self) -> Value {
        self.state.clone()
    }

    /// python `reset_to_default`.
    pub fn reset_to_default(&mut self) -> Value {
        self.state = normalize_folder_state(&self.default_state, &self.default_state);
        self.to_dict()
    }

    /// python `create_folder`: новая папка в конце списка.
    pub fn create_folder(&mut self, name: &str) -> String {
        let clean_name = clean_folder_name(name);
        let folders = folders_mut(&mut self.state);
        let key = unique_folder_key(&clean_name, folders);
        let mut max_order = -1i64;
        for folder in folders.values() {
            if let Some(object) = folder.as_object() {
                max_order = max_order.max(int_or_zero_field(object, "order"));
            }
        }
        folders.insert(
            key.clone(),
            json!({
                "name": clean_name,
                "order": max_order + 1,
                "collapsed": false,
                "system": false,
            }),
        );
        key
    }

    /// python `create_folder_after`: новая папка сразу после указанной
    /// (по отображаемому порядку).
    pub fn create_folder_after(&mut self, name: &str, after_folder_key: &str) -> String {
        let key = self.create_folder(name);
        let after_key = after_folder_key.trim();
        let ordered = self.ordered_folders();
        let after_index = ordered
            .iter()
            .position(|(folder_key, _folder)| folder_key == after_key)
            .map_or(-1i64, |index| index as i64);
        let after_index = if after_index < 0 {
            ordered.len() as i64 - 2
        } else {
            after_index
        };
        let mut folder_keys: Vec<String> = ordered
            .iter()
            .map(|(folder_key, _folder)| folder_key.clone())
            .filter(|folder_key| *folder_key != key)
            .collect();
        let insert_index = (after_index + 1).clamp(0, folder_keys.len() as i64) as usize;
        folder_keys.insert(insert_index, key.clone());
        self.renumber_folders(&folder_keys);
        key
    }

    /// python `rename_folder`: системные папки и неизменённые имена
    /// отклоняются (`false`).
    pub fn rename_folder(&mut self, folder_key: &str, name: &str) -> bool {
        let key = folder_key.trim();
        let folders = folders_mut(&mut self.state);
        let Some(Value::Object(folder)) = folders.get_mut(key) else {
            return false;
        };
        if truthy(folder.get("system")) {
            return false;
        }
        let clean_name = clean_folder_name(name);
        if string_or_falsy(folder.get("name"), "") == clean_name {
            return false;
        }
        folder.insert("name".to_string(), Value::String(clean_name));
        true
    }

    /// python `delete_folder`: системные папки не удаляются, элементы
    /// удалённой папки переезжают в `common`.
    pub fn delete_folder(&mut self, folder_key: &str) -> bool {
        let key = folder_key.trim();
        {
            let folders = folders_mut(&mut self.state);
            let is_system = match folders.get(key) {
                Some(Value::Object(folder)) => truthy(folder.get("system")),
                _ => return false,
            };
            if is_system {
                return false;
            }
            folders.remove(key);
        }
        let items = items_mut(&mut self.state);
        for meta in items.values_mut() {
            if let Value::Object(object) = meta {
                if matches!(object.get("folder_key"), Some(Value::String(value)) if value == key) {
                    object.insert(
                        "folder_key".to_string(),
                        Value::String(COMMON_FOLDER_KEY.to_string()),
                    );
                }
            }
        }
        true
    }

    /// python `move_folder`: установка сохранённого порядка папки.
    pub fn move_folder(&mut self, folder_key: &str, order: i64) -> bool {
        let key = folder_key.trim();
        let next_order = order.max(0);
        let folders = folders_mut(&mut self.state);
        let Some(Value::Object(folder)) = folders.get_mut(key) else {
            return false;
        };
        if int_or_zero_field(folder, "order") == next_order {
            return false;
        }
        folder.insert("order".to_string(), Value::from(next_order));
        true
    }

    /// python `move_folder_by_step`: обмен местами с соседней папкой в
    /// отображаемом порядке.
    pub fn move_folder_by_step(&mut self, folder_key: &str, direction: i64) -> bool {
        let key = folder_key.trim();
        let step = if direction > 0 { 1 } else { -1 };
        let ordered = self.ordered_folders();
        let Some(index) = ordered
            .iter()
            .position(|(folder_key, _folder)| folder_key == key)
        else {
            return false;
        };
        let target_index = index as i64 + step;
        if target_index < 0 || target_index >= ordered.len() as i64 {
            return false;
        }
        let mut folder_keys: Vec<String> = ordered
            .into_iter()
            .map(|(folder_key, _folder)| folder_key)
            .collect();
        folder_keys.swap(index, target_index as usize);
        self.renumber_folders(&folder_keys);
        true
    }

    /// python `set_folder_collapsed`.
    pub fn set_folder_collapsed(&mut self, folder_key: &str, collapsed: bool) -> bool {
        let key = folder_key.trim();
        let folders = folders_mut(&mut self.state);
        let Some(Value::Object(folder)) = folders.get_mut(key) else {
            return false;
        };
        if truthy(folder.get("collapsed")) == collapsed {
            return false;
        }
        folder.insert("collapsed".to_string(), Value::Bool(collapsed));
        true
    }

    /// python `set_item_folder`: папка элемента; несуществующая папка
    /// заменяется на `common`, элемент без изменений не создаётся.
    pub fn set_item_folder(&mut self, item_key: &str, folder_key: &str) -> bool {
        let key = item_key.trim();
        if key.is_empty() {
            return false;
        }
        let mut folder = folder_key.trim().to_string();
        if folder.is_empty() || !self.folder_exists(&folder) {
            folder = COMMON_FOLDER_KEY.to_string();
        }
        let items = items_mut(&mut self.state);
        match items.get_mut(key) {
            Some(Value::Object(meta)) => {
                if string_or_falsy(meta.get("folder_key"), COMMON_FOLDER_KEY) == folder {
                    return false;
                }
                meta.insert("folder_key".to_string(), Value::String(folder));
                true
            }
            _ => {
                if folder == COMMON_FOLDER_KEY {
                    return false;
                }
                items.insert(
                    key.to_string(),
                    json!({"folder_key": folder, "order": Value::Null, "rating": 0}),
                );
                true
            }
        }
    }

    /// python `set_item_order`: `None` сбрасывает ручной порядок.
    pub fn set_item_order(&mut self, item_key: &str, order: Option<i64>) -> bool {
        let key = item_key.trim();
        if key.is_empty() {
            return false;
        }
        let next_order = order.map(|value| value.max(0));
        let items = items_mut(&mut self.state);
        if !matches!(items.get(key), Some(Value::Object(_))) {
            let Some(next_order) = next_order else {
                return false;
            };
            items.insert(
                key.to_string(),
                json!({"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0}),
            );
            let Some(Value::Object(meta)) = items.get_mut(key) else {
                return false;
            };
            meta.insert("order".to_string(), Value::from(next_order));
            return true;
        }
        let Some(Value::Object(meta)) = items.get_mut(key) else {
            return false;
        };
        let current = meta.get("order").and_then(Value::as_i64);
        if current == next_order {
            return false;
        }
        meta.insert(
            "order".to_string(),
            next_order.map(Value::from).unwrap_or(Value::Null),
        );
        true
    }

    /// python `set_item_rating`: 0..10; нулевой рейтинг у отсутствующего
    /// элемента ничего не создаёт.
    pub fn set_item_rating(&mut self, item_key: &str, rating: i64) -> bool {
        let key = item_key.trim();
        if key.is_empty() {
            return false;
        }
        let next_rating = rating.clamp(0, 10);
        let items = items_mut(&mut self.state);
        if !matches!(items.get(key), Some(Value::Object(_))) {
            if next_rating == 0 {
                return false;
            }
            items.insert(
                key.to_string(),
                json!({"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0}),
            );
        }
        let Some(Value::Object(meta)) = items.get_mut(key) else {
            return false;
        };
        if int_or_zero_field(meta, "rating") == next_rating {
            return false;
        }
        meta.insert("rating".to_string(), Value::from(next_rating));
        true
    }

    /// python `set_item_pinned`: закрепление отражается только явным
    /// значением (`pinned` отсутствует у незафиксированных элементов).
    pub fn set_item_pinned(&mut self, item_key: &str, pinned: bool) -> bool {
        let key = item_key.trim();
        if key.is_empty() {
            return false;
        }
        let items = items_mut(&mut self.state);
        if !matches!(items.get(key), Some(Value::Object(_))) {
            if !pinned {
                return false;
            }
            items.insert(
                key.to_string(),
                json!({"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0}),
            );
        }
        let Some(Value::Object(meta)) = items.get_mut(key) else {
            return false;
        };
        if truthy(meta.get("pinned")) == pinned {
            return false;
        }
        if pinned {
            meta.insert("pinned".to_string(), Value::Bool(true));
        } else {
            meta.remove("pinned");
        }
        true
    }

    /// python `_ordered_folders`: сортировка
    /// `(order, name.lower(), ключ папки)`.
    fn ordered_folders(&self) -> Vec<(String, Value)> {
        let Some(folders) = self.state.get("folders").and_then(Value::as_object) else {
            return Vec::new();
        };
        let mut entries: Vec<(String, Value)> = folders
            .iter()
            .map(|(folder_key, folder)| (folder_key.clone(), folder.clone()))
            .collect();
        entries.sort_by(|(key_a, folder_a), (key_b, folder_b)| {
            folder_sort_key(folder_a, key_a).cmp(&folder_sort_key(folder_b, key_b))
        });
        entries
    }

    /// python `_renumber_folders`: перенумерация 0..N.
    fn renumber_folders(&mut self, folder_keys: &[String]) {
        let folders = folders_mut(&mut self.state);
        for (index, folder_key) in folder_keys.iter().enumerate() {
            if let Some(Value::Object(folder)) = folders.get_mut(folder_key) {
                folder.insert("order".to_string(), Value::from(index as i64));
            }
        }
    }

    fn folder_exists(&self, folder_key: &str) -> bool {
        self.state
            .get("folders")
            .and_then(Value::as_object)
            .is_some_and(|folders| folders.contains_key(folder_key))
    }
}

/// Ключ сортировки папки: `(int(order или 0), name.lower() или ключ, ключ)`.
pub(crate) fn folder_sort_key(folder: &Value, key: &str) -> (i64, String, String) {
    let order = folder
        .as_object()
        .map(|object| int_or_zero_field(object, "order"))
        .unwrap_or(0);
    let name = folder
        .as_object()
        .map(|object| string_or_falsy(object.get("name"), key).to_lowercase())
        .unwrap_or_else(|| key.to_lowercase());
    (order, name, key.to_string())
}

/// python `normalize_folder_state(data, default_state)`: приводит
/// сохранённое состояние к каноническому виду, досыпая дефолтные папки.
#[must_use]
pub fn normalize_folder_state(data: &Value, default_state: &Value) -> Value {
    // python: deepcopy(default_state if isinstance(default_state, dict) else {})
    let defaults = default_state.as_object().cloned().unwrap_or_default();
    let default_folders = normalize_folders(defaults.get("folders"), &Map::new());
    let raw = data.as_object().cloned().unwrap_or_default();
    let mut folders = normalize_folders(raw.get("folders"), &default_folders);
    if !default_folders.is_empty() {
        folders = merge_default_folders(&folders, &default_folders);
    }
    if let Some(default_common) = default_folders.get(COMMON_FOLDER_KEY) {
        // python: {**default, **existing, "system": True}
        let mut merged = default_common.clone();
        if let (Some(target), Some(existing)) = (
            merged.as_object_mut(),
            folders.get(COMMON_FOLDER_KEY).and_then(Value::as_object),
        ) {
            for (key, value) in existing {
                target.insert(key.clone(), value.clone());
            }
        }
        if let Some(target) = merged.as_object_mut() {
            target.insert("system".to_string(), Value::Bool(true));
        }
        folders.insert(COMMON_FOLDER_KEY.to_string(), merged);
    }
    if folders.is_empty() {
        folders = default_folders;
    }

    let mut items = Map::new();
    if let Some(raw_items) = raw.get("items").and_then(Value::as_object) {
        for (raw_key, raw_meta) in raw_items {
            // python: key = str(raw_key or "").strip()
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }
            let Some(meta) = raw_meta.as_object() else {
                continue;
            };
            let mut folder_key = string_or_falsy(meta.get("folder_key"), COMMON_FOLDER_KEY)
                .trim()
                .to_string();
            if folder_key.is_empty() {
                folder_key = COMMON_FOLDER_KEY.to_string();
            }
            if !folders.contains_key(&folder_key) {
                folder_key = COMMON_FOLDER_KEY.to_string();
            }
            let order = as_nullable_int(meta.get("order"));
            let rating = as_int(meta.get("rating"), 0, Some(0), Some(10));
            let mut normalized_meta = Map::new();
            normalized_meta.insert("folder_key".to_string(), Value::String(folder_key));
            normalized_meta.insert(
                "order".to_string(),
                order.map(Value::from).unwrap_or(Value::Null),
            );
            normalized_meta.insert("rating".to_string(), Value::from(rating));
            if truthy(meta.get("pinned")) {
                normalized_meta.insert("pinned".to_string(), Value::Bool(true));
            }
            items.insert(key.to_string(), Value::Object(normalized_meta));
        }
    }

    let mut result = Map::new();
    result.insert("version".to_string(), Value::from(1));
    result.insert("folders".to_string(), Value::Object(folders));
    result.insert("items".to_string(), Value::Object(items));
    Value::Object(result)
}

/// python `_normalize_folders(value, *, fallback)`.
fn normalize_folders(value: Option<&Value>, fallback: &Map<String, Value>) -> Map<String, Value> {
    let mut folders = Map::new();
    if let Some(entries) = value.and_then(Value::as_object) {
        for (raw_key, raw_folder) in entries {
            // python: key = str(raw_key or "").strip()
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }
            let Some(folder) = raw_folder.as_object() else {
                continue;
            };
            let name = clean_folder_name(&string_or_falsy(folder.get("name"), key));
            folders.insert(
                key.to_string(),
                json!({
                    "name": name,
                    "order": as_int(folder.get("order"), folders.len() as i64, Some(0), None),
                    "collapsed": truthy(folder.get("collapsed")),
                    "system": truthy(folder.get("system")),
                }),
            );
        }
    }
    if !folders.is_empty() {
        return folders;
    }
    fallback.clone()
}

/// python `_merge_default_folders(folders, default_folders)`: существующие
/// папки остаются, дефолтные досыпаются со сдвигом занятых порядков.
fn merge_default_folders(
    folders: &Map<String, Value>,
    default_folders: &Map<String, Value>,
) -> Map<String, Value> {
    let mut result = folders.clone();
    if result.is_empty() {
        return default_folders.clone();
    }
    for (key, default_folder) in default_folders {
        match result.get(key) {
            Some(existing) => {
                let mut merged = default_folder.clone();
                if let (Some(target), Some(source)) = (merged.as_object_mut(), existing.as_object())
                {
                    for (entry_key, value) in source {
                        target.insert(entry_key.clone(), value.clone());
                    }
                }
                let system = truthy(default_folder.get("system")) || truthy(existing.get("system"));
                if let Some(target) = merged.as_object_mut() {
                    target.insert("system".to_string(), Value::Bool(system));
                }
                result.insert(key.clone(), merged);
            }
            None => {
                let mut folder = default_folder.clone();
                let wanted_order = as_int(folder.get("order"), result.len() as i64, Some(0), None);
                make_order_slot(&mut result, wanted_order);
                if let Some(target) = folder.as_object_mut() {
                    target.insert("order".to_string(), Value::from(wanted_order));
                }
                result.insert(key.clone(), folder);
            }
        }
    }
    result
}

/// python `_make_order_slot`: сдвиг порядков, занятых вставляемым.
fn make_order_slot(folders: &mut Map<String, Value>, order: i64) {
    for folder in folders.values_mut() {
        let Some(object) = folder.as_object_mut() else {
            continue;
        };
        let current = as_int(object.get("order"), 0, Some(0), None);
        if current >= order {
            object.insert("order".to_string(), Value::from(current + 1));
        }
    }
}

/// python `_clean_folder_name(value)`: пробелы схлопываются, длина до 80
/// символов, пустое имя → «Новая папка».
#[must_use]
pub fn clean_folder_name(value: &str) -> String {
    let collapsed = WHITESPACE_RE.as_ref().map_or_else(
        || value.trim().to_string(),
        |pattern| pattern.replace_all(value.trim(), " ").into_owned(),
    );
    let truncated: String = collapsed.chars().take(80).collect();
    if truncated.is_empty() {
        "Новая папка".to_string()
    } else {
        truncated
    }
}

/// python `_unique_folder_key(name, folders)`: `название` → `название-2`,
/// `название-3`, …; база — только строчные латиница/цифры/кириллица.
#[must_use]
pub fn unique_folder_key(name: &str, folders: &Map<String, Value>) -> String {
    // python: name.lower() перед выделением базы.
    let lowered = name.to_lowercase();
    let base = FOLDER_KEY_BASE_RE
        .as_ref()
        .map_or_else(
            || lowered.clone(),
            |pattern| pattern.replace_all(&lowered, "-").into_owned(),
        )
        .trim_matches('-')
        .to_string();
    let base = if base.is_empty() {
        "folder".to_string()
    } else {
        base
    };
    let mut key = base.clone();
    let mut counter = 2;
    while folders.contains_key(&key) {
        key = format!("{base}-{counter}");
        counter += 1;
    }
    key
}

/// python `_as_nullable_int` из store.py: пустая строка и `null` дают
/// `None`, остальные значения приводятся к `int >= 0` либо `None`.
fn as_nullable_int(value: Option<&Value>) -> Option<i64> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        other => py_int(other).map(|result| result.max(0)),
    }
}

fn folders_mut(state: &mut Value) -> &mut Map<String, Value> {
    state_section_mut(state, "folders")
}

fn items_mut(state: &mut Value) -> &mut Map<String, Value> {
    state_section_mut(state, "items")
}
