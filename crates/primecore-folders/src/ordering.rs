//! Порт `folders/ordering.py`: канонический отображаемый порядок папок и
//! элементов, чистые планировщики перемещения и строки для рендеринга.
//!
//! `FolderOrderView` — единственный источник истины: и рендеринг, и
//! планирование перемещений обязаны исходить из одного представления.
//! Сортировки повторяют python-кортежи (`sorted` устойчив; ключи включают
//! имя и ключ, поэтому результат детерминирован).

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::pyutil::{py_int, string_or_falsy, truthy};
use crate::store::{folder_sort_key, normalize_folder_state};
use crate::{COMMON_FOLDER_KEY, PINNED_FOLDER_KEY};

/// Канонический порядок папок и элементов (python-датакласс `FolderOrderView`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderOrderView {
    /// Папки в отображаемом порядке, без сервисной папки `pinned`.
    pub folder_keys: Vec<String>,
    /// Имя папки по ключу (`name` или ключ).
    pub folder_names: BTreeMap<String, String>,
    /// Свёрнутость папки по ключу.
    pub collapsed: BTreeMap<String, bool>,
    /// Элементы папки в отображаемом порядке.
    pub items_by_folder: BTreeMap<String, Vec<String>>,
    /// Папка элемента по ключу элемента.
    pub folder_by_item: BTreeMap<String, String>,
    /// Позиция элемента внутри его папки.
    pub position_by_item: BTreeMap<String, usize>,
}

/// python `_entry_sort_key`: компоненты ранга; в домене это числа
/// (`manual_tie`, `auto_rank` — кортежи чисел). Числа при сравнении идут
/// раньше строк (в python смешение типов дало бы TypeError; такие данные
/// не приходят из домена).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TieComponent {
    Int(i64),
    Text(String),
}

/// Полный ключ сортировки элемента: `(kind, ранг, имя, ключ)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EntrySortKey {
    kind: u8,
    tie: Vec<TieComponent>,
    name: String,
    key: String,
}

/// python `resolve_folder_order(state, live_items)`: строит канонический
/// порядок. Папки — по сохранённому order (имя/ключ как tie-break),
/// элементы — сохранённый order первым, затем доменный `auto_rank`.
///
/// `live_items`: `[{key, name, folder_key?, rating?, manual_tie?,
/// auto_rank?}, ...]`. Ранги задаёт домен; если их нет, используется
/// rating-семантика страницы пресетов (`_entry_sort_key`).
#[must_use]
pub fn resolve_folder_order(state: &Value, live_items: &[Value]) -> FolderOrderView {
    let folders = folders_of(state);
    let item_meta = items_of(state);

    // python: grouped = {key: [] for key in folders}; setdefault для
    // элементов без известной папки (например, common при её отсутствии).
    let mut grouped: BTreeMap<String, Vec<(EntrySortKey, String)>> = BTreeMap::new();
    for folder_key in folders.keys() {
        grouped.insert(folder_key.clone(), Vec::new());
    }
    let mut folder_by_item: BTreeMap<String, String> = BTreeMap::new();
    for live_item in live_items {
        let Some(object) = live_item.as_object() else {
            continue;
        };
        let key = string_or_falsy(object.get("key"), "").trim().to_string();
        if key.is_empty() {
            continue;
        }
        let meta = item_meta.get(&key).and_then(Value::as_object);
        let folder_key = resolve_item_folder(meta, object, &folders);
        let order = as_nullable_int(meta.and_then(|meta| meta.get("order")));
        grouped
            .entry(folder_key.clone())
            .or_default()
            .push((entry_sort_key(order, meta, object), key.clone()));
        folder_by_item.insert(key, folder_key);
    }

    let mut items_by_folder: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut position_by_item: BTreeMap<String, usize> = BTreeMap::new();
    for (folder_key, entries) in &mut grouped {
        entries.sort();
        let ordered: Vec<String> = entries.iter().map(|(_sort_key, key)| key.clone()).collect();
        for (position, key) in ordered.iter().enumerate() {
            position_by_item.insert(key.clone(), position);
        }
        items_by_folder.insert(folder_key.clone(), ordered);
    }

    FolderOrderView {
        folder_keys: sort_folders(&folders)
            .into_iter()
            .map(|(folder_key, _folder)| folder_key)
            .filter(|folder_key| folder_key != PINNED_FOLDER_KEY)
            .collect(),
        folder_names: folders
            .iter()
            .map(|(key, folder)| (key.clone(), folder_display_name(folder, key)))
            .collect(),
        collapsed: folders
            .iter()
            .map(|(key, folder)| {
                (
                    key.clone(),
                    folder
                        .as_object()
                        .map(|object| truthy(object.get("collapsed")))
                        .unwrap_or(false),
                )
            })
            .collect(),
        items_by_folder,
        folder_by_item,
        position_by_item,
    }
}

/// python `plan_view_move`: чистая «математика» перемещения над
/// каноническим представлением. Возвращает `(целевая папка, новая
/// последовательность её элементов)` либо `None`, если перемещение
/// невозможно или не меняет отображаемый порядок.
#[must_use]
pub fn plan_view_move(
    view: &FolderOrderView,
    action: &str,
    source_key: &str,
    destination_key: &str,
    destination_folder_key: &str,
) -> Option<(String, Vec<String>)> {
    let source = source_key.trim();
    let destination = destination_key.trim();
    let kind = action.trim();
    if source.is_empty() || !view.folder_by_item.contains_key(source) {
        return None;
    }

    let target_folder = match kind {
        "before" | "after" => {
            if destination.is_empty()
                || destination == source
                || !view.folder_by_item.contains_key(destination)
            {
                return None;
            }
            let explicit = destination_folder_key.trim();
            if explicit.is_empty() {
                view.folder_by_item
                    .get(destination)
                    .cloned()
                    .unwrap_or_default()
            } else {
                explicit.to_string()
            }
        }
        "end" => {
            let explicit = destination_folder_key.trim();
            if explicit.is_empty() {
                view.folder_by_item.get(source).cloned().unwrap_or_default()
            } else {
                explicit.to_string()
            }
        }
        "folder" => destination_folder_key.trim().to_string(),
        _ => return None,
    };
    if target_folder.is_empty() {
        return None;
    }

    let mut sequence: Vec<String> = view
        .items_by_folder
        .get(&target_folder)
        .map(|items| {
            items
                .iter()
                .filter(|key| key.as_str() != source)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    match kind {
        "before" | "after" => {
            if !sequence.iter().any(|key| key == destination) {
                // UI авторитетен: если цель видна в явно указанной папке, а
                // состояние ещё не знает об этом — цель тоже переезжает туда.
                if destination_folder_key.trim().is_empty() {
                    return None;
                }
                sequence.push(destination.to_string());
            }
            let destination_index = sequence
                .iter()
                .position(|key| key == destination)
                .unwrap_or(0);
            let insert_index = if kind == "after" {
                destination_index + 1
            } else {
                destination_index
            };
            sequence.insert(insert_index, source.to_string());
        }
        _ => sequence.push(source.to_string()),
    }

    if view.folder_by_item.get(source).map(String::as_str) == Some(target_folder.as_str())
        && *sequence
            == view
                .items_by_folder
                .get(&target_folder)
                .cloned()
                .unwrap_or_default()
    {
        return None;
    }
    Some((target_folder, sequence))
}

/// python `plan_item_move`: чистый планировщик перемещения. База —
/// отображаемый порядок (`resolve_folder_order`), поэтому сохранённый
/// результат всегда совпадает с тем, что видит пользователь. Возвращает
/// НОВОЕ состояние или `None` (no-op).
///
/// Гарантии: изменяется только целевая папка (перенумерация 0..N по
/// отображаемой базе) и meta источника; meta других папок и их folder_key
/// не затрагиваются.
#[must_use]
pub fn plan_item_move(
    state: &Value,
    live_items: &[Value],
    action: &str,
    source_key: &str,
    destination_key: &str,
    destination_folder_key: &str,
) -> Option<Value> {
    let view = resolve_folder_order(state, live_items);
    let (target_folder, sequence) = plan_view_move(
        &view,
        action,
        source_key,
        destination_key,
        destination_folder_key,
    )?;
    if !folders_of(state).contains_key(&target_folder) {
        return None;
    }

    let mut next_state = state.clone();
    // python: next_state.setdefault("items", {}) — секция создаётся пустой,
    // если отсутствует.
    let items = crate::pyutil::state_section_mut(&mut next_state, "items");
    let mut live_by_key: BTreeMap<String, Value> = BTreeMap::new();
    for live_item in live_items {
        if let Some(object) = live_item.as_object() {
            let key = string_or_falsy(object.get("key"), "").trim().to_string();
            live_by_key.insert(key, live_item.clone());
        }
    }
    for (index, key) in sequence.iter().enumerate() {
        if !matches!(items.get(key), Some(Value::Object(_))) {
            // Элемент отображался в целевой папке по классификации —
            // материализуем именно её; folder_key элементов других папок
            // не переписывается.
            let meta = new_item_meta(
                &target_folder,
                live_by_key.get(key).and_then(Value::as_object),
            );
            items.insert(key.clone(), meta);
        }
        let Some(Value::Object(meta)) = items.get_mut(key) else {
            continue;
        };
        if view.folder_by_item.get(key).map(String::as_str) != Some(target_folder.as_str()) {
            // Папка меняется только у переезжающих элементов (источник и,
            // при явном destination_folder_key, цель).
            meta.insert(
                "folder_key".to_string(),
                Value::String(target_folder.clone()),
            );
        }
        meta.insert("order".to_string(), Value::from(index as i64));
    }
    Some(next_state)
}

/// python `build_folder_rows`: плоские строки рендеринга (папки + элементы)
/// с сервисной папкой закреплённых и фильтром по подстроке.
#[must_use]
pub fn build_folder_rows(
    state: &Value,
    live_items: &[Value],
    include_pinned_folder: bool,
    query: &str,
) -> Vec<Value> {
    let normalized = normalize_folder_state(state, state);
    let Some(folders) = normalized.get("folders").and_then(Value::as_object) else {
        return Vec::new();
    };
    let Some(item_meta) = normalized.get("items").and_then(Value::as_object) else {
        return Vec::new();
    };
    let normalized_query = query.trim().to_lowercase();

    let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for folder_key in folders.keys() {
        grouped.insert(folder_key.clone(), Vec::new());
    }
    let mut pinned_rows: Vec<Value> = Vec::new();

    for live_item in live_items {
        let Some(object) = live_item.as_object() else {
            continue;
        };
        let key = string_or_falsy(object.get("key"), "").trim().to_string();
        if key.is_empty() {
            continue;
        }
        let name = {
            // python: str(live_item.get("name") or key).strip() or key
            let name = string_or_falsy(object.get("name"), &key).trim().to_string();
            if name.is_empty() {
                key.clone()
            } else {
                name
            }
        };
        if !normalized_query.is_empty()
            && !name.to_lowercase().contains(&normalized_query)
            && !key.to_lowercase().contains(&normalized_query)
        {
            continue;
        }
        let meta = item_meta.get(&key).and_then(Value::as_object);
        let default_folder_key = {
            let folder_key = string_or_falsy(object.get("folder_key"), COMMON_FOLDER_KEY)
                .trim()
                .to_string();
            if folder_key.is_empty() {
                COMMON_FOLDER_KEY.to_string()
            } else {
                folder_key
            }
        };
        let folder_key = {
            let folder_key = match meta.and_then(|meta| meta.get("folder_key")) {
                Some(value) => {
                    let folder_key = string_or_falsy(Some(value), &default_folder_key)
                        .trim()
                        .to_string();
                    if folder_key.is_empty() {
                        default_folder_key.clone()
                    } else {
                        folder_key
                    }
                }
                None => default_folder_key,
            };
            if folders.contains_key(&folder_key) {
                folder_key
            } else {
                COMMON_FOLDER_KEY.to_string()
            }
        };
        let pinned =
            truthy(meta.and_then(|meta| meta.get("pinned"))) || truthy(object.get("pinned"));
        let mut row = Map::new();
        row.insert("kind".to_string(), json!("item"));
        row.insert("key".to_string(), json!(key));
        row.insert("name".to_string(), json!(name));
        row.insert("folder_key".to_string(), json!(folder_key));
        row.insert(
            "order".to_string(),
            meta.and_then(|meta| meta.get("order"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        row.insert("rating".to_string(), json!(item_rating(meta, object)));
        row.insert("pinned".to_string(), Value::Bool(pinned));
        row.insert("payload".to_string(), live_item.clone());
        if include_pinned_folder && pinned {
            pinned_rows.push(Value::Object(row));
            continue;
        }
        grouped
            .entry(folder_key)
            .or_default()
            .push(Value::Object(row));
    }

    let mut rows: Vec<Value> = Vec::new();
    if !pinned_rows.is_empty() {
        let pinned_collapsed = folders
            .get(PINNED_FOLDER_KEY)
            .and_then(Value::as_object)
            .map(|object| truthy(object.get("collapsed")))
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
            rows.extend(sort_items(pinned_rows));
        }
    }

    for (folder_key, folder) in sort_folders(folders) {
        if folder_key == PINNED_FOLDER_KEY {
            continue;
        }
        let folder_object = folder.as_object();
        let items = sort_items(grouped.remove(&folder_key).unwrap_or_default());
        if !normalized_query.is_empty() && items.is_empty() {
            continue;
        }
        let collapsed = folder_object
            .map(|object| truthy(object.get("collapsed")))
            .unwrap_or(false);
        rows.push(json!({
            "kind": "folder",
            "key": folder_key,
            "name": folder_object
                .map(|object| string_or_falsy(object.get("name"), &folder_key))
                .unwrap_or_else(|| folder_key.clone()),
            "collapsed": collapsed,
            "system": folder_object
                .map(|object| truthy(object.get("system")))
                .unwrap_or(false),
            "service": false,
            "count": items.len(),
        }));
        if !collapsed || !normalized_query.is_empty() {
            rows.extend(items);
        }
    }

    rows
}

/// python `_new_item_meta`.
fn new_item_meta(folder_key: &str, live_item: Option<&Map<String, Value>>) -> Value {
    let mut meta = json!({"folder_key": folder_key, "order": Value::Null, "rating": 0});
    if let Some(object) = live_item {
        if let Some(target) = meta.as_object_mut() {
            target.insert("rating".to_string(), json!(item_rating(None, object)));
            if truthy(object.get("pinned")) {
                target.insert("pinned".to_string(), Value::Bool(true));
            }
        }
    }
    meta
}

/// python `_resolve_item_folder`.
fn resolve_item_folder(
    meta: Option<&Map<String, Value>>,
    live_item: &Map<String, Value>,
    folders: &Map<String, Value>,
) -> String {
    // python: default_folder = str(live_item.get("folder_key") or COMMON).strip() or COMMON
    let default_folder = trimmed_or_common(live_item.get("folder_key"));
    // python: folder_key = str(meta.get("folder_key") or default_folder).strip() or COMMON
    let folder_key = string_or_falsy(
        meta.and_then(|meta| meta.get("folder_key")),
        &default_folder,
    );
    let folder_key = {
        let trimmed = folder_key.trim().to_string();
        if trimmed.is_empty() {
            COMMON_FOLDER_KEY.to_string()
        } else {
            trimmed
        }
    };
    if folders.contains_key(&folder_key) {
        folder_key
    } else {
        COMMON_FOLDER_KEY.to_string()
    }
}

/// python-связка `str(value or COMMON).strip() or COMMON`.
fn trimmed_or_common(value: Option<&Value>) -> String {
    let text = string_or_falsy(value, COMMON_FOLDER_KEY).trim().to_string();
    if text.is_empty() {
        COMMON_FOLDER_KEY.to_string()
    } else {
        text
    }
}

/// python `_entry_sort_key(order, meta, live_item)`.
fn entry_sort_key(
    order: Option<i64>,
    meta: Option<&Map<String, Value>>,
    live_item: &Map<String, Value>,
) -> EntrySortKey {
    let name = {
        // python: str(live_item.get("name") or live_item.get("key") or "").lower()
        let source = if truthy(live_item.get("name")) {
            live_item.get("name")
        } else {
            live_item.get("key")
        };
        string_or_falsy(source, "").to_lowercase()
    };
    let key = string_or_falsy(live_item.get("key"), "");
    match order {
        Some(order) => {
            let mut tie = vec![TieComponent::Int(order)];
            tie.extend(tie_components(
                live_item.get("manual_tie"),
                vec![TieComponent::Int(-item_rating(meta, live_item))],
            ));
            EntrySortKey {
                kind: 0,
                tie,
                name,
                key,
            }
        }
        None => EntrySortKey {
            kind: 1,
            tie: tie_components(
                live_item.get("auto_rank"),
                vec![
                    TieComponent::Int(0),
                    TieComponent::Int(-item_rating(meta, live_item)),
                ],
            ),
            name,
            key,
        },
    }
}

/// python `tuple(manual_tie)`: `null`/отсутствие → дефолт (rating-семантика),
/// массив — компоненты, скаляр — единственная компонента (в python скаляр
/// дал бы TypeError — такие данные домен не присылает).
fn tie_components(value: Option<&Value>, default: Vec<TieComponent>) -> Vec<TieComponent> {
    match value {
        None | Some(Value::Null) => default,
        Some(Value::Array(items)) => items.iter().filter_map(tie_component).collect(),
        Some(other) => tie_component(other).into_iter().collect(),
    }
}

fn tie_component(value: &Value) -> Option<TieComponent> {
    match value {
        Value::Null => None,
        Value::Bool(flag) => Some(TieComponent::Int(i64::from(*flag))),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Some(TieComponent::Int(value))
            } else if let Some(value) = number.as_u64() {
                i64::try_from(value).ok().map(TieComponent::Int)
            } else {
                number
                    .as_f64()
                    .map(|value| TieComponent::Int(value.trunc() as i64))
            }
        }
        Value::String(text) => Some(TieComponent::Text(text.clone())),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// python `_folders_of`: объектные папки состояния по ключам.
pub(crate) fn folders_of(state: &Value) -> Map<String, Value> {
    state
        .get("folders")
        .and_then(Value::as_object)
        .map(|folders| {
            folders
                .iter()
                .filter(|(_key, folder)| folder.is_object())
                .map(|(key, folder)| (key.clone(), folder.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// python `_items_of`: объектные meta элементов по ключам.
fn items_of(state: &Value) -> Map<String, Value> {
    state
        .get("items")
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .filter(|(_key, meta)| meta.is_object())
                .map(|(key, meta)| (key.clone(), meta.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// python `_as_nullable_int` из ordering.py: только `null`/отсутствие дают
/// `None`, остальные значения приводятся к `int` либо `None`.
fn as_nullable_int(value: Option<&Value>) -> Option<i64> {
    match value {
        None | Some(Value::Null) => None,
        other => py_int(other),
    }
}

/// python `_sort_folders`: `(int(order или 0), name.lower() или ключ, ключ)`.
pub(crate) fn sort_folders(folders: &Map<String, Value>) -> Vec<(String, Value)> {
    let mut entries: Vec<(String, Value)> = folders
        .iter()
        .map(|(key, folder)| (key.clone(), folder.clone()))
        .collect();
    entries.sort_by(|(key_a, folder_a), (key_b, folder_b)| {
        folder_sort_key(folder_a, key_a).cmp(&folder_sort_key(folder_b, key_b))
    });
    entries
}

/// python `_sort_items`.
fn sort_items(items: Vec<Value>) -> Vec<Value> {
    let mut entries: Vec<(EntrySortKey, Value)> = items
        .into_iter()
        .map(|item| {
            let object = item.as_object().cloned().unwrap_or_default();
            let order = as_nullable_int(object.get("order"));
            (entry_sort_key(order, Some(&object), &object), item)
        })
        .collect();
    entries.sort_by(|(key_a, _), (key_b, _)| key_a.cmp(key_b));
    entries.into_iter().map(|(_key, item)| item).collect()
}

/// python `_item_rating(meta, live_item)`: первый подходящий источник
/// (`meta`, затем `live_item`), 0..10, иначе 0.
fn item_rating(meta: Option<&Map<String, Value>>, live_item: &Map<String, Value>) -> i64 {
    for source in [meta, Some(live_item)].into_iter().flatten() {
        // python: int(source.get("rating", 0) or 0)
        let raw = match source.get("rating") {
            Some(value) if truthy(Some(value)) => value.clone(),
            _ => Value::from(0),
        };
        if let Some(rating) = py_int(Some(&raw)) {
            return rating.clamp(0, 10);
        }
    }
    0
}

fn folder_display_name(folder: &Value, key: &str) -> String {
    folder
        .as_object()
        .map(|object| string_or_falsy(object.get("name"), key))
        .unwrap_or_else(|| key.to_string())
}
