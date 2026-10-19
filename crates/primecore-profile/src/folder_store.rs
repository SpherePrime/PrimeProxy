//! Порт `src/folders/store.py` — нормализация состояния папок и библиотека
//! операций (FolderLibraryStore).
//!
//! Порядок вставки словарей обеспечивается `preserve_order` у serde_json.

use serde_json::{json, Map, Value};

use super::folders::{COMMON_FOLDER_KEY};

/// Показ состояния: {version:int, folders:map, items:map}.
pub fn get_folders_of(state: &Value) -> &serde_json::Map<String, Value> {
    state.as_object().expect("state object").get("folders").expect("folders").as_object().expect("folders object")
}

pub fn folders_mut(state: &mut Value) -> &mut Map<String, Value> {
    state.as_object_mut().expect("state").get_mut("folders").expect("folders").as_object_mut().expect("folders object")
}

/// python FolderLibraryStore: state-словарь + default_state.
pub struct FolderLibraryStore {
    state: Value,
}

impl FolderLibraryStore {
    pub fn new(state: Value, default_state: &Value) -> Self {
        Self {
            state: normalize_folder_state(&state, default_state),
        }
    }

    pub fn to_dict(&self) -> Value {
        self.state.clone()
    }

    /// python create_folder.
    pub fn create_folder(&mut self, name: &str) -> String {
        let clean_name = clean_folder_name(&Value::String(name.to_string()));
        let folders = get_folders_of(&self.state).clone();
        let key = unique_folder_key(&clean_name, &Value::Object(folders.clone()));
        let mut max_order = -1i64;
        for folder in folders.values() {
            max_order = max_order.max(as_int(&field(folder, "order")));
        }
        folders_mut(&mut self.state).insert(
            key.clone(),
            json!({"name": clean_name, "order": max_order + 1, "collapsed": false, "system": false}),
        );
        key
    }

    /// python create_folder_after.
    pub fn create_folder_after(&mut self, name: &str, after_folder_key: &str) -> String {
        let key = self.create_folder(name);
        let after_key = after_folder_key.trim().to_string();
        let folders = self.ordered_folders();
        let after_index = match folders.iter().position(|(folder_key, _)| folder_key == &after_key) {
            Some(index) if after_key != key => index as i64,
            _ => folders.len() as i64 - 2,
        };
        let mut folder_keys: Vec<String> = folders
            .iter()
            .map(|(folder_key, _)| folder_key.clone())
            .filter(|folder_key| *folder_key != key)
            .collect();
        let insert_index = (after_index + 1).clamp(0, folder_keys.len() as i64) as usize;
        folder_keys.insert(insert_index, key.clone());
        self.renumber_folders(&folder_keys);
        key
    }

    /// python rename_folder.
    pub fn rename_folder(&mut self, folder_key: &str, name: &str) -> bool {
        let key = folder_key.trim().to_string();
        let Some(folder) = folders_mut(&mut self.state).get_mut(&key) else {
            return false;
        };
        if is_true(&field(folder, "system")) {
            return false;
        }
        let clean_name = clean_folder_name(&Value::String(name.to_string()));
        if field(folder, "name").as_str().unwrap_or("") == clean_name {
            return false;
        }
        set_field(folder, "name", json!(clean_name));
        true
    }

    /// python delete_folder.
    pub fn delete_folder(&mut self, folder_key: &str) -> bool {
        let key = folder_key.trim().to_string();
        let removed = {
            let folders = get_folders_of(&self.state);
            match folders.get(&key) {
                Some(folder) if is_true(&field(folder, "system")) => return false,
                Some(_) => folders.contains_key(&key),
                None => return false,
            }
        };
        if !removed {
            return false;
        }
        folders_mut(&mut self.state).remove(&key);
        let items = items_mut(&mut self.state);
        for meta in items.values_mut() {
            if field(meta, "folder_key").as_str().unwrap_or("") == key {
                set_field(meta, "folder_key", json!(COMMON_FOLDER_KEY));
            }
        }
        true
    }

    /// python move_folder.
    pub fn move_folder(&mut self, folder_key: &str, order: i64) -> bool {
        let key = folder_key.trim().to_string();
        if !get_folders_of(&self.state).contains_key(&key) {
            return false;
        }
        let next_order = order.max(0);
        let folder = folders_mut(&mut self.state).get_mut(&key).expect("folder");
        if as_int(&field(folder, "order")) == next_order {
            return false;
        }
        set_field(folder, "order", json!(next_order));
        true
    }

    /// python move_folder_by_step.
    pub fn move_folder_by_step(&mut self, folder_key: &str, direction: i64) -> bool {
        let key = folder_key.trim().to_string();
        let folders = self.ordered_folders();
        let Some(index) = folders
            .iter()
            .position(|(list_key, _)| list_key == &key)
        else {
            return false;
        };
        let step = if direction > 0 { 1 } else { -1 };
        let target_index = index as i64 + step;
        if target_index < 0 || target_index >= folders.len() as i64 {
            return false;
        }
        let mut folder_keys: Vec<String> = folders.iter().map(|(k, _)| k.clone()).collect();
        folder_keys.swap(index, target_index as usize);
        self.renumber_folders(&folder_keys);
        true
    }

    /// python set_folder_collapsed.
    pub fn set_folder_collapsed(&mut self, folder_key: &str, collapsed: bool) -> bool {
        let key = folder_key.trim().to_string();
        if !get_folders_of(&self.state).contains_key(&key) {
            return false;
        }
        let folder = folders_mut(&mut self.state).get_mut(&key).expect("folder");
        if is_true(&field(folder, "collapsed")) == collapsed {
            return false;
        }
        set_field(folder, "collapsed", json!(collapsed));
        true
    }
}

// ---------------------------------------------------------------- доступ

fn field<'a>(value: &'a Value, key: &'a str) -> &'a Value {
    value.as_object().and_then(|map| map.get(key)).unwrap_or(&Value::Null)
}

fn set_field(value: &mut Value, key: &str, new_value: Value) {
    value
        .as_object_mut()
        .expect("dict")
        .insert(key.to_string(), new_value);
}

fn is_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

fn items_mut(state: &mut Value) -> &mut Map<String, Value> {
    state
        .as_object_mut()
        .and_then(|map| map.get_mut("items"))
        .expect("items")
        .as_object_mut()
        .expect("items object")
}

impl FolderLibraryStore {
    /// python _ordered_folders: по (order, name.lower, key).
    fn ordered_folders(&self) -> Vec<(String, Value)> {
        let mut folders: Vec<(String, Value)> = get_folders_of(&self.state)
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        folders.sort_by(|(key_a, folder_a), (key_b, folder_b)| {
            let order_a = as_int(&field(folder_a, "order"));
            let order_b = as_int(&field(folder_b, "order"));
            order_a.cmp(&order_b).then_with(|| {
                let name_a = field(folder_a, "name").as_str().unwrap_or(key_a).to_lowercase();
                let name_b = field(folder_b, "name").as_str().unwrap_or(key_b).to_lowercase();
                name_a.cmp(&name_b).then_with(|| key_a.cmp(key_b))
            })
        });
        folders
    }

    fn renumber_folders(&mut self, folder_keys: &[String]) {
        for (index, key) in folder_keys.iter().enumerate() {
            if let Some(folder) = folders_mut(&mut self.state).get_mut(key) {
                set_field(folder, "order", json!(index));
            }
        }
    }
}

// ---------------------------------------------------------------- нормализация

/// python normalize_folder_state.
pub fn normalize_folder_state(data: &Value, default_state: &Value) -> Value {
    // python: deepcopy(default_state) — здесь просто клон значения.
    let default_folders = normalize_folders(
        &default_state.as_object().and_then(|map| map.get("folders")).cloned().unwrap_or(Value::Null),
        &Map::new(),
    );
    // python: raw = data если dict иначе {}; значения читаются напрямую.
    let raw_map = data.as_object().map(|map| map.clone()).unwrap_or_default();
    let raw = Value::Object(raw_map);
    let empty_map: Map<String, Value> = Map::new();
    let mut folders = normalize_folders(
        raw.get("folders").unwrap_or(&Value::Null),
        default_folders.as_object().unwrap_or(&empty_map),
    );
    let defaults_map = default_folders.as_object().expect("default folders");
    if !defaults_map.is_empty() {
        folders = merge_default_folders(&folders, &default_folders);
    }
    if defaults_map.contains_key(COMMON_FOLDER_KEY) {
        let default_common = defaults_map.get(COMMON_FOLDER_KEY).expect("common").clone();
        let mut merged = match folders
            .as_object()
            .and_then(|map| map.get(COMMON_FOLDER_KEY))
        {
            Some(existing) => {
                let existing = existing.clone();
                merge_existing_common(&default_common, &existing)
            }
            None => default_common,
        };
        set_field(&mut merged, "system", json!(true));
        if let Value::Object(map) = &mut folders {
            map.insert(COMMON_FOLDER_KEY.to_string(), merged);
        }
    }
    if folders.as_object().expect("folders").is_empty() {
        folders = default_folders.clone();
    }

    let mut items = Map::new();
    if let Some(Value::Object(raw_items)) = raw.get("items") {
        for (raw_key, raw_meta) in raw_items.iter() {
            let key = raw_key.trim().to_string();
            let Some(raw_meta_obj) = raw_meta.as_object() else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            let mut folder_key = raw_meta_obj
                .get("folder_key")
                .and_then(Value::as_str)
                .unwrap_or(COMMON_FOLDER_KEY)
                .trim()
                .to_string();
            if folder_key.is_empty() {
                folder_key = COMMON_FOLDER_KEY.to_string();
            }
            if !folders.as_object().expect("folders").contains_key(&folder_key) {
                folder_key = COMMON_FOLDER_KEY.to_string();
            }
            let order = as_nullable_int(raw_meta_obj.get("order").unwrap_or(&Value::Null));
            let rating = as_int_clamped(
                raw_meta_obj.get("rating").unwrap_or(&Value::Null),
                0,
                Some(0),
                Some(10),
            );
            let mut meta = json!({"folder_key": folder_key, "order": order, "rating": rating});
            if is_true(raw_meta_obj.get("pinned").unwrap_or(&Value::Null)) {
                set_field(&mut meta, "pinned", json!(true));
            }
            items.insert(key, meta);
        }
    }

    json!({"version": 1, "folders": folders, "items": items})
}

fn data_null_to_empty(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

/// python _normalize_folders.
fn normalize_folders(value: &Value, fallback: &Map<String, Value>) -> Value {
    let mut folders = Map::new();
    if let Value::Object(raw_map) = value {
        for (raw_key, raw_folder) in raw_map.iter() {
            let key = raw_key.trim().to_string();
            let Some(raw_folder_obj) = raw_folder.as_object() else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            let name_raw = raw_folder_obj.get("name").unwrap_or(&Value::Null);
            let mut name_holder: Option<Value> = None;
            let name_target: Value = if name_raw.is_null() {
                let holder = Value::String(key.clone());
                name_holder = Some(holder);
                name_holder.as_ref().unwrap().clone()
            } else {
                name_raw.clone()
            };
            let name = clean_folder_name(&name_target);
            folders.insert(
                key.clone(),
                json!({
                    "name": name,
                    "order": as_int_clamped(raw_folder_obj.get("order").unwrap_or(&Value::Null), folders.len() as i64, Some(0), None),
                    "collapsed": is_true(raw_folder_obj.get("collapsed").unwrap_or(&Value::Null)),
                    "system": is_true(raw_folder_obj.get("system").unwrap_or(&Value::Null)),
                }),
            );
        }
    }
    if !folders.is_empty() {
        return Value::Object(folders);
    }
    Value::Object(fallback.clone())
}

/// python {**default, **existing} для common-папки.
fn merge_existing_common(default: &Value, existing: &Value) -> Value {
    let mut merged = default.clone();
    if let (Value::Object(merged_map), Value::Object(existing_map)) = (&mut merged, existing) {
        for (key, value) in existing_map.iter() {
            merged_map.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// python _merge_default_folders.
fn merge_default_folders(folders: &Value, default_folders: &Value) -> Value {
    let defaults_map = default_folders.as_object().expect("defaults");
    let result_map = folders.as_object().expect("folders");
    let mut result = result_map.clone();
    if result.is_empty() {
        return default_folders.clone();
    }
    for (key, default_folder) in defaults_map.iter() {
        if let Some(existing) = result.get(key) {
            let mut merged = merge_existing_common(default_folder, existing);
            let system = is_true(&field(default_folder, "system"))
                || is_true(&field(existing, "system"));
            set_field(&mut merged, "system", json!(system));
            result.insert(key.clone(), merged);
            continue;
        }
        let mut folder = default_folder.clone();
        let wanted_order = as_int_clamped(&field(default_folder, "order"), result.len() as i64, Some(0), None);
        make_order_slot(&mut result, wanted_order);
        set_field(&mut folder, "order", json!(wanted_order));
        result.insert(key.clone(), folder);
    }
    Value::Object(result)
}

/// python _make_order_slot.
fn make_order_slot(folders: &mut Map<String, Value>, order: i64) {
    for folder in folders.values_mut() {
        let current_order = as_int_clamped(&field(folder, "order"), 0, Some(0), None);
        if current_order >= order {
            set_field(folder, "order", json!(current_order + 1));
        }
    }
}

/// python _clean_folder_name.
pub fn clean_folder_name(value: &Value) -> String {
    let raw = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => if *flag { "True" } else { "False" }.to_string(),
        _ => String::new(),
    };
    let text = raw.trim();
    let considered: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let truncated: String = considered.chars().take(80).collect();
    if truncated.is_empty() {
        "Новая папка".to_string()
    } else {
        truncated
    }
}

/// python _unique_folder_key.
pub fn unique_folder_key(name: &str, folders: &Value) -> String {
    static NON_WORD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[^a-z0-9а-яё]+").expect("regex")
    });
    let lowered = name.to_lowercase();
    let mut base = NON_WORD.replace_all(&lowered, "-").trim_matches('-').to_string();
    if base.is_empty() {
        base = "folder".to_string();
    }
    let mut key = base.clone();
    let mut counter = 2;
    let folders_map = folders.as_object().expect("folders");
    while folders_map.contains_key(&key) {
        key = format!("{base}-{counter}");
        counter += 1;
    }
    key
}

/// python _as_nullable_int: "" и None → None, иначе max(0, int).
fn as_nullable_int(value: &Value) -> Option<i64> {
    if value.is_null() {
        return None;
    }
    let number = value.as_i64()?;
    Some(number.max(0))
}

/// python _as_int со значениями по умолчанию и границами.
pub fn as_int_clamped(value: &Value, default: i64, minimum: Option<i64>, maximum: Option<i64>) -> i64 {
    let mut result = value
        .as_i64()
        .or_else(|| value.as_f64().map(|float| float as i64))
        .unwrap_or(default);
    if let Some(minimum) = minimum {
        result = result.max(minimum);
    }
    if let Some(maximum) = maximum {
        result = result.min(maximum);
    }
    result
}

/// python int(folder.get("order", 0) or 0).
fn as_int(value: &Value) -> i64 {
    value.as_i64().unwrap_or(0).max(0)
}

pub use as_int_clamped as as_int_clamped_pub;
