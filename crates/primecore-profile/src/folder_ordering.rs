//! Порт `src/folders/ordering.py` + адаптер `src/profile/ordering.py` —
//! канонический порядок элементов папок и планирование перемещений.

use serde_json::{json, Value};

use super::folder_store::{as_int_clamped_pub, normalize_folder_state};
use super::folders::{COMMON_FOLDER_KEY, PINNED_FOLDER_KEY, classify_profile_folder};
use crate::identity::is_profile_uid_text;

/// python FolderOrderView.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FolderOrderView {
    pub folder_keys: Vec<String>,
    pub folder_names: Vec<(String, String)>,
    pub collapsed: Vec<(String, bool)>,
    pub items_by_folder: Vec<(String, Vec<String>)>,
    pub folder_by_item: Vec<(String, String)>,
    pub position_by_item: Vec<(String, usize)>,
}

impl FolderOrderView {
    pub fn name_of(&self, folder_key: &str) -> String {
        self.folder_names
            .iter()
            .find(|(key, _)| key == folder_key)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| folder_key.to_string())
    }

    pub fn is_collapsed(&self, folder_key: &str) -> bool {
        self.collapsed
            .iter()
            .find(|(key, _)| key == folder_key)
            .map(|(_, value)| *value)
            .unwrap_or(false)
    }

    pub fn items_in(&self, folder_key: &str) -> Vec<String> {
        self.items_by_folder
            .iter()
            .find(|(key, _)| key == folder_key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    pub fn folder_of_item(&self, item_key: &str) -> Option<&str> {
        self.folder_by_item
            .iter()
            .find(|(key, _)| key == item_key)
            .map(|(_, folder)| folder.as_str())
    }

    pub fn items_dict(&self) -> Vec<(String, Vec<String>)> {
        self.items_by_folder.clone()
    }
}

/// python live_item (словарь): key/name/folder_key/rating/pinned/manual_tie/auto_rank.
pub type LiveItem = Value;

fn live(item: &LiveItem, key: &str) -> Value {
    item.as_object().and_then(|map| map.get(key)).cloned().unwrap_or(Value::Null)
}

fn live_str(item: &LiveItem, key: &str) -> String {
    match live(item, key) {
        Value::String(text) => text,
        Value::Number(number) => number.to_string(),
        _ => String::new(),
    }
}

fn live_bool(item: &LiveItem, key: &str) -> bool {
    matches!(live(item, key), Value::Bool(true))
}

/// python _entry_sort_key → ключ сравнения (bucket, group, name, key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySortKey {
    bucket: i64,
    group: Vec<i64>,
    name: String,
    key: String,
}

impl EntrySortKey {
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        self.bucket
            .cmp(&other.bucket)
            .then_with(|| compare_slices(&self.group, &other.group))
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.key.cmp(&other.key))
    }
}

fn compare_slices(left: &[i64], right: &[i64]) -> std::cmp::Ordering {
    for (a, b) in left.iter().zip(right.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    left.len().cmp(&right.len())
}

fn item_rating(meta: &Value, live_item: &LiveItem) -> i64 {
    for source in [meta, live_item] {
        if let Some(rating) = rating_value(live(source, "rating")) {
            return rating.clamp(0, 10);
        }
    }
    0
}

/// python int(source.get("rating", 0) or 0).
fn rating_value(value: Value) -> Option<i64> {
    match value {
        Value::Null => Some(0),
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float as i64)),
        _ => None,
    }
}

fn entry_sort_key(order: Option<i64>, meta: &Value, live_item: &LiveItem) -> EntrySortKey {
    let name = {
        let raw = live_str(live_item, "name");
        let raw = if raw.is_empty() { live_str(live_item, "key") } else { raw };
        raw.to_lowercase()
    };
    let key = live_str(live_item, "key");
    if let Some(order) = order {
        let manual_tie = match live(live_item, "manual_tie") {
            Value::Array(items) if !items.is_empty() => {
                items.iter().filter_map(|item| number(item)).collect::<Vec<i64>>()
            }
            _ => vec![-item_rating(meta, live_item)],
        };
        let mut group = vec![order];
        group.extend(manual_tie);
        return EntrySortKey { bucket: 0, group, name, key };
    }
    let auto_rank: Vec<i64> = match live(live_item, "auto_rank") {
        Value::Array(items) if !items.is_empty() => {
            items.iter().filter_map(|item| number(item)).collect::<Vec<i64>>()
        }
        _ => vec![0, -item_rating(meta, live_item)],
    };
    EntrySortKey { bucket: 1, group: auto_rank, name, key }
}

/// python value → int? (None → нет).
fn number(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float as i64)),
        _ => None,
    }
}

/// python resolve_folder_order.
pub fn resolve_folder_order(state: &Value, live_items: &[LiveItem]) -> FolderOrderView {
    let folders = folders_of(state);
    let item_meta = items_of(state);

    // grouped: порядок ключей = порядок вставки папок.
    let folder_keys: Vec<String> = folders.iter().map(|(key, _)| key.clone()).collect();
    let mut grouped: Vec<(String, Vec<(EntrySortKey, String)>)> = folder_keys
        .iter()
        .map(|key| (key.clone(), Vec::new()))
        .collect();
    let mut folder_of: Vec<(String, String)> = Vec::new();

    for live_item in live_items {
        let key = live_str(live_item, "key");
        if key.trim().is_empty() {
            continue;
        }
        let key = key.trim().to_string();
        let meta = item_meta.get(&key).cloned().unwrap_or(json!({}));
        let folder = resolve_item_folder(&meta, live_item, &folders);
        let order = number(&field(&meta, "order"));
        let sort_key = entry_sort_key(order, &meta, live_item);
        if let Some(group) = grouped.iter_mut().find(|(gkey, _)| gkey == &folder) {
            group.1.push((sort_key, key.clone()));
        } else {
            grouped.push((folder.clone(), vec![(sort_key, key.clone())]));
        }
        folder_of.push((key, folder));
    }

    let mut items_by_folder: Vec<(String, Vec<String>)> = Vec::new();
    let mut position_by_item: Vec<(String, usize)> = Vec::new();
    for (folder_key, entries) in &grouped {
        // python sorted() — стабильная сортировка по ключу.
        let mut sorted_entries = entries.clone();
        sorted_entries.sort_by(|pair_a, pair_b| pair_a.0.compare(&pair_b.0));
        let ordered: Vec<String> = sorted_entries.into_iter().map(|(_, key)| key).collect();
        for (position, key) in ordered.iter().enumerate() {
            position_by_item.push((key.clone(), position));
        }
        items_by_folder.push((folder_key.clone(), ordered));
    }

    let sorted_folders = sort_folders(&folders);
    FolderOrderView {
        folder_keys: sorted_folders
            .iter()
            .filter(|(key, _)| key != PINNED_FOLDER_KEY)
            .map(|(key, _)| key.clone())
            .collect(),
        folder_names: folders
            .iter()
            .map(|(key, folder)| (key.clone(), folder_string(folder, "name").unwrap_or_else(|| key.clone())))
            .collect(),
        collapsed: folders
            .iter()
            .map(|(key, folder)| (key.clone(), matches!(field(folder, "collapsed"), Value::Bool(true))))
            .collect(),
        items_by_folder,
        folder_by_item: folder_of,
        position_by_item,
    }
}

fn folders_of(state: &Value) -> Vec<(String, Value)> {
    state
        .as_object()
        .and_then(|map| map.get("folders"))
        .and_then(Value::as_object)
        .map(|map| map.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
        .unwrap_or_default()
}

fn items_of(state: &Value) -> std::collections::HashMap<String, Value> {
    state
        .as_object()
        .and_then(|map| map.get("items"))
        .and_then(Value::as_object)
        .map(|map| map.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
        .unwrap_or_default()
}

fn folder_string(folder: &Value, key: &str) -> Option<String> {
    match field(folder, key) {
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

fn field<'a>(value: &'a Value, key: &'a str) -> &'a Value {
    value.as_object().and_then(|map| map.get(key)).unwrap_or(&Value::Null)
}

/// python _resolve_item_folder.
fn resolve_item_folder(meta: &Value, live_item: &LiveItem, folders: &[(String, Value)]) -> String {
    let mut default_folder = live_str(live_item, "folder_key");
    if default_folder.trim().is_empty() {
        default_folder = COMMON_FOLDER_KEY.to_string();
    }
    let mut folder_key = field(meta, "folder_key")
        .as_str()
        .map(|text| text.trim().to_string())
        .unwrap_or(default_folder);
    if folder_key.trim().is_empty() {
        folder_key = COMMON_FOLDER_KEY.to_string();
    }
    if !folders.iter().any(|(key, _)| key == &folder_key) {
        folder_key = COMMON_FOLDER_KEY.to_string();
    }
    folder_key
}

/// python _sort_folders.
fn sort_folders(folders: &[(String, Value)]) -> Vec<(String, Value)> {
    let mut sorted = folders.to_vec();
    sorted.sort_by(|(key_a, folder_a), (key_b, folder_b)| {
        let order_a = as_int_clamped_pub(&field(folder_a, "order"), 0, None, None);
        let order_b = as_int_clamped_pub(&field(folder_b, "order"), 0, None, None);
        order_a.cmp(&order_b).then_with(|| {
            let name_a = folder_string(folder_a, "name")
                .unwrap_or_else(|| key_a.clone())
                .to_lowercase();
            let name_b = folder_string(folder_b, "name")
                .unwrap_or_else(|| key_b.clone())
                .to_lowercase();
            name_a.cmp(&name_b).then_with(|| key_a.cmp(key_b))
        })
    });
    sorted
}

/// python plan_view_move.
pub fn plan_view_move(
    view: &FolderOrderView,
    action: &str,
    source_key: &str,
    destination_key: &str,
    destination_folder_key: &str,
) -> Option<(String, Vec<String>)> {
    let source = source_key.trim().to_string();
    let destination = destination_key.trim().to_string();
    let kind = action.trim().to_string();
    if source.is_empty() || view.folder_of_item(&source).is_none() {
        return None;
    }

    let target_folder = if kind == "before" || kind == "after" {
        if destination.is_empty() || destination == source || view.folder_of_item(&destination).is_none() {
            return None;
        }
        let explicit = destination_folder_key.trim().to_string();
        if explicit.is_empty() {
            view.folder_of_item(&destination).expect("destination folder").to_string()
        } else {
            explicit
        }
    } else if kind == "end" {
        let explicit = destination_folder_key.trim().to_string();
        if explicit.is_empty() {
            view.folder_of_item(&source).expect("source folder").to_string()
        } else {
            explicit
        }
    } else if kind == "folder" {
        destination_folder_key.trim().to_string()
    } else {
        return None;
    };
    if target_folder.is_empty() {
        return None;
    }

    let mut sequence: Vec<String> = view
        .items_in(&target_folder)
        .into_iter()
        .filter(|key| key != &source)
        .collect();
    if kind == "before" || kind == "after" {
        if !sequence.contains(&destination) {
            // Цель видна в явно указанной папке, а состояние ещё не знает.
            if destination_folder_key.trim().is_empty() {
                return None;
            }
            sequence.push(destination.clone());
        }
        let insert_index = sequence.iter().position(|key| key == &destination).expect("destination")
            + if kind == "after" { 1 } else { 0 };
        sequence.insert(insert_index, source.clone());
    } else {
        sequence.push(source.clone());
    }

    if view.folder_of_item(&source) == Some(target_folder.as_str())
        && sequence == view.items_in(&target_folder)
    {
        return None;
    }
    let _ = destination_folder_key;
    Some((target_folder, sequence))
}

/// python plan_item_move: новое состояние или None (no-op).
pub fn plan_item_move(
    state: &Value,
    live_items: &[LiveItem],
    action: &str,
    source_key: &str,
    destination_key: &str,
    destination_folder_key: &str,
) -> Option<Value> {
    let view = resolve_folder_order(state, live_items);
    let Some((target_folder, sequence)) = plan_view_move(
        &view,
        action,
        source_key,
        destination_key,
        destination_folder_key,
    ) else {
        return None;
    };
    if !folders_of(state).iter().any(|(key, _)| key == &target_folder) {
        return None;
    }
    let source = source_key.trim().to_string();

    let mut next_state = state.clone();
    let items = items_map_mut(&mut next_state);
    let live_by_key: std::collections::HashMap<String, &LiveItem> = live_items
        .iter()
        .map(|item| (live_str(item, "key"), item))
        .collect();

    for (index, key) in sequence.iter().enumerate() {
        if !items.contains_key(key) {
            // Элемент отображался по классификации — материализуем её.
            let meta = new_item_meta(&target_folder, live_by_key.get(key).copied());
            items.insert(key.clone(), meta);
        }
        let meta = items.get_mut(key).expect("meta");
        if view.folder_of_item(key) != Some(target_folder.as_str()) {
            set_field(meta, "folder_key", json!(target_folder));
        }
        set_field(meta, "order", json!(index as i64));
    }
    let _ = source;
    Some(next_state)
}

fn items_map_mut(state: &mut Value) -> &mut serde_json::Map<String, Value> {
    state
        .as_object_mut()
        .and_then(|map| map.get_mut("items"))
        .expect("items")
        .as_object_mut()
        .expect("items object")
}

fn set_field(value: &mut Value, key: &str, new_value: Value) {
    value
        .as_object_mut()
        .expect("dict")
        .insert(key.to_string(), new_value);
}

/// python _new_item_meta.
fn new_item_meta(folder_key: &str, live_item: Option<&LiveItem>) -> Value {
    let mut meta = json!({"folder_key": folder_key, "order": Value::Null, "rating": 0});
    if let Some(live_item) = live_item {
        set_field(&mut meta, "rating", json!(item_rating(&json!({}), live_item)));
        if live_bool(live_item, "pinned") {
            set_field(&mut meta, "pinned", json!(true));
        }
    }
    meta
}

/// python build_folder_rows: строки для отрисовки списка с папками.
pub fn build_folder_rows(
    state: &Value,
    live_items: &[LiveItem],
    include_pinned_folder: bool,
    query: &str,
) -> Vec<Value> {
    let normalized = normalize_folder_state(state, state);
    let folders = get_folders(&normalized);
    let item_meta = items_of(&normalized);
    let normalized_query = query.trim().to_lowercase();

    let folder_keys: Vec<String> = folders.iter().map(|(key, _)| key.clone()).collect();
    let mut grouped: Vec<(String, Vec<Value>)> = folder_keys
        .iter()
        .map(|key| (key.clone(), Vec::new()))
        .collect();
    let mut pinned_rows: Vec<Value> = Vec::new();

    for live_item in live_items {
        let key = live_str(live_item, "key");
        if key.trim().is_empty() {
            continue;
        }
        let key = key.trim().to_string();
        let mut name = live_str(live_item, "name");
        if name.trim().is_empty() {
            name = key.clone();
        }
        let name = name.trim().to_string();
        if !normalized_query.is_empty()
            && !name.to_lowercase().contains(&normalized_query)
            && !key.to_lowercase().contains(&normalized_query)
        {
            continue;
        }
        let meta = item_meta.get(&key).cloned().unwrap_or(json!({}));
        let mut default_folder_key = live_str(live_item, "folder_key");
        if default_folder_key.trim().is_empty() {
            default_folder_key = COMMON_FOLDER_KEY.to_string();
        }
        let mut folder_key = field(&meta, "folder_key")
            .as_str()
            .map(|text| text.trim().to_string())
            .unwrap_or(default_folder_key);
        if folder_key.trim().is_empty() {
            folder_key = COMMON_FOLDER_KEY.to_string();
        }
        if !folders.iter().any(|(key, _)| key == &folder_key) {
            folder_key = COMMON_FOLDER_KEY.to_string();
        }
        let row = json!({
            "kind": "item",
            "key": key,
            "name": name,
            "folder_key": folder_key,
            "order": field(&meta, "order"),
            "rating": item_rating(&meta, live_item),
            "pinned": is_pinned(&meta, live_item),
            "payload": live_item.clone(),
        });
        if include_pinned_folder && is_pinned(&meta, live_item) {
            pinned_rows.push(row);
            continue;
        }
        if let Some(group) = grouped.iter_mut().find(|(gkey, _)| gkey == &folder_key) {
            group.1.push(row);
        } else {
            grouped.push((folder_key.clone(), vec![row]));
        }
    }

    let mut rows: Vec<Value> = Vec::new();
    if !pinned_rows.is_empty() {
        let pinned_meta = folders.iter().find(|(key, _)| key == PINNED_FOLDER_KEY);
        let pinned_collapsed = pinned_meta
            .map(|(_, folder)| matches!(field(folder, "collapsed"), Value::Bool(true)))
            .unwrap_or(false);
        rows.push(json!({
            "kind": "folder",
            "key": PINNED_FOLDER_KEY,
            "name": "Закрепленные",
            "collapsed": pinned_collapsed,
            "system": true,
            "service": true,
            "count": pinned_rows.len(),
        }));
        if !pinned_collapsed || !normalized_query.is_empty() {
            rows.extend(sort_items(&pinned_rows));
        }
    }

    for (folder_key, folder) in sort_folders(&folders) {
        if folder_key == PINNED_FOLDER_KEY {
            continue;
        }
        let items: Vec<Value> = grouped
            .iter()
            .find(|(gkey, _)| gkey == &folder_key)
            .map(|(_, items)| items.clone())
            .unwrap_or_default();
        let items = sort_items(&items);
        if !normalized_query.is_empty() && items.is_empty() {
            continue;
        }
        rows.push(json!({
            "kind": "folder",
            "key": folder_key,
            "name": folder_string(&folder, "name").unwrap_or_else(|| folder_key.clone()),
            "collapsed": matches!(field(&folder, "collapsed"), Value::Bool(true)),
            "system": matches!(field(&folder, "system"), Value::Bool(true)),
            "service": false,
            "count": items.len(),
        }));
        let collapsed = matches!(field(&folder, "collapsed"), Value::Bool(true));
        if !collapsed || !normalized_query.is_empty() {
            rows.extend(items);
        }
    }

    rows
}

fn get_folders(state: &Value) -> Vec<(String, Value)> {
    state
        .as_object()
        .and_then(|map| map.get("folders"))
        .and_then(Value::as_object)
        .map(|map| map.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
        .unwrap_or_default()
}

fn is_pinned(meta: &Value, live_item: &LiveItem) -> bool {
    matches!(field(meta, "pinned"), Value::Bool(true)) || live(live_item, "pinned") == Value::Bool(true)
}

/// python _sort_items.
fn sort_items(items: &[Value]) -> Vec<Value> {
    let mut sorted: Vec<(EntrySortKey, Value)> = items
        .iter()
        .map(|item| {
            (
                entry_sort_key(number(&field(item, "order")), item, item),
                item.clone(),
            )
        })
        .collect();
    sorted.sort_by(|pair_a, pair_b| pair_a.0.compare(&pair_b.0));
    sorted.into_iter().map(|(_, item)| item).collect()
}

// --------------------------------------------------------- адаптер profile/ordering

/// python live_items_from_sources: строки ProfileListSource → live_items.
/// Элементы кортежа: (source_key, order, persistent_key, resolved_display_name,
///                     match_lines, profile.name).
pub fn live_items_from_sources(
    sources: &[(String, i64, String, String, Vec<String>, String)],
) -> Vec<Value> {
    let mut live_items: Vec<Value> = Vec::new();
    for (_source_key, order, persistent_key, resolved_display_name, match_lines, profile_name) in
        sources
    {
        // python: resolved_display_name || profile.display_name || profile.name
        let name = if !resolved_display_name.trim().is_empty() {
            resolved_display_name.trim().to_string()
        } else {
            profile_name.trim().to_string()
        };
        if persistent_key.trim().is_empty() {
            continue;
        }
        live_items.push(live_item_map(
            persistent_key.trim(),
            name.as_str(),
            match_lines.clone(),
            *order,
            profile_name,
        ));
    }
    live_items
}

/// python live_items_from_display_items: элементы UI-слоя
/// (persistent_key, display_name, match_lines, source_order, profile_index,
///  profile_name).
pub fn live_items_from_display_items(
    items: &[(String, String, Vec<String>, i64, i64, String)],
) -> Vec<Value> {
    let mut live_items = Vec::new();
    for (key, display_name, match_lines, source_order, fallback_index, profile_name) in items {
        if key.trim().is_empty() {
            continue;
        }
        let fallback = if *source_order != 0 {
            *source_order
        } else {
            *fallback_index
        };
        live_items.push(live_item_map(
            key.trim(),
            display_name.trim(),
            match_lines.clone(),
            fallback,
            profile_name,
        ));
    }
    live_items
}

/// python profile.ordering.resolve_profile_order_view: view на normalized
/// состоянии папок и live_items из отображаемых item-ов.
pub fn resolve_profile_order_view_from(items: &[(String, String, Vec<String>, i64, i64, String)], folder_state: &Value) -> FolderOrderView {
    let live_items = live_items_from_display_items(items);
    let defaults = super::folders::build_default_profile_folders();
    let state = super::folder_store::normalize_folder_state(folder_state, &defaults);
    resolve_folder_order(&state, &live_items)
}

/// python _live_item.
pub fn live_item_map(
    persistent_key: &str,
    name: &str,
    match_lines: Vec<String>,
    fallback_index: i64,
    classification_extra: &str,
) -> Value {
    // Стабильные uid-ключи не несут классификационного сигнала.
    let key_text = if is_profile_uid_text(persistent_key) {
        String::new()
    } else {
        persistent_key.to_string()
    };
    let mut parts: Vec<String> = Vec::new();
    for part in [
        name.to_string(),
        classification_extra.to_string(),
        key_text,
        match_lines.join(" "),
    ] {
        if !part.is_empty() {
            parts.push(part);
        }
    }
    let classification_text = parts.join(" ");
    let folder_key = classify_profile_folder(&classification_text);
    json!({
        "key": persistent_key,
        "name": name,
        "folder_key": folder_key,
        "manual_tie": [],
        "auto_rank": [
            profile_folder_tail_rank(&folder_key, &classification_text),
            protocol_sort_rank(&match_lines),
            fallback_index,
        ],
    })
}

/// python protocol_sort_rank.
pub fn protocol_sort_rank(match_lines: &[String]) -> i64 {
    let tcp = crate::match_filters::filter_values(match_lines, "--filter-tcp");
    let udp = crate::match_filters::filter_values(match_lines, "--filter-udp");
    let l7 = crate::match_filters::filter_values(match_lines, "--filter-l7");
    if !tcp.is_empty() {
        return 0;
    }
    if !udp.is_empty() && l7.is_empty() {
        return 1;
    }
    if !l7.is_empty() {
        return 2;
    }
    3
}

/// python _profile_folder_tail_rank.
fn profile_folder_tail_rank(folder_key: &str, classification_text: &str) -> i64 {
    if folder_key == "discord" && classification_text.to_lowercase().contains("vencord") {
        return 1;
    }
    0
}

/// normalized state (python _normalized_state).
pub fn normalized_profile_folder_state(folder_state: &Value) -> Value {
    normalize_folder_state(folder_state, &super::folders::build_default_profile_folders())
}
