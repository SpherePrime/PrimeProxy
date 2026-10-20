//! Порт `src/profile/key_resolution.py` — стабильные ключи ссылок на профили,
//! карта перестановок ключей и ремап операций.
//!
//! python duck-typing заменён конкретными типами: элементы списков —
//! `Profile`, операции — карты ключ → значение.

use std::collections::{BTreeMap, VecDeque};

use crate::models::{Preset, Profile};

/// python PresetProfileMoveResult: (profile_key, key_map).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresetProfileMoveResult {
    pub profile_key: String,
    pub key_map: BTreeMap<String, String>,
}

impl PresetProfileMoveResult {
    /// python __str__/__eq__-со-строкой.
    pub fn key_display(&self) -> String {
        self.profile_key.trim().to_string()
    }
}

/// Стабильная ссылка на элемент списка профилей.
pub fn profile_reference_key(in_preset: bool, persistent_key: &str, key: &str) -> String {
    if in_preset {
        let persistent = persistent_key.trim();
        if !persistent.is_empty() {
            return persistent.to_string();
        }
    }
    key.trim().to_string()
}

pub fn resolve_preset_profile_row_index(preset: &Preset, profile_key: &str) -> Option<usize> {
    let key = profile_key.trim();
    if key.is_empty() {
        return None;
    }
    preset.profiles.iter().position(|profile| profile.id == key)
}

pub fn resolve_preset_profile_reference_index(preset: &Preset, profile_key: &str) -> Option<usize> {
    if let Some(row_index) = resolve_preset_profile_row_index(preset, profile_key) {
        return Some(row_index);
    }
    let key = profile_key.trim();
    if key.is_empty() {
        return None;
    }
    let matches: Vec<usize> = preset
        .profiles
        .iter()
        .enumerate()
        .filter(|(_, profile)| profile.persistent_key == key)
        .map(|(index, _)| index)
        .collect();
    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

/// Строки списка профилей: (key, in_preset, persistent_key, key источника).
pub type ListSourceKeyRef<'a> = (&'a str, bool, &'a str);

/// python find_profile_list_source: источник по ключу профиля.
pub fn find_profile_list_source_index(
    sources: &[(String, bool, String)],
    profile_key: &str,
) -> Option<usize> {
    // Элементы: (source_key, in_preset, profile.persistent_key).
    let key = profile_key.trim();
    if key.is_empty() {
        return None;
    }
    if let Some(exact) = sources
        .iter()
        .position(|(source_key, _, _)| source_key == key)
    {
        return Some(exact);
    }
    let matches: Vec<usize> = sources
        .iter()
        .enumerate()
        .filter(|(_, (_, _, persistent))| persistent == key)
        .map(|(index, _)| index)
        .collect();
    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

/// Карта перестановок ключей по подписи содержимого профиля.
pub type ProfileKeyMap = BTreeMap<String, String>;

pub fn build_preset_profile_key_map(before: &[Profile], after: &[Profile]) -> ProfileKeyMap {
    // Подпись содержимого → очередь ключей "after".
    let mut candidates: BTreeMap<String, VecDeque<String>> = BTreeMap::new();
    for profile in after {
        candidates
            .entry(profile_content_signature(profile).join("\u{1}"))
            .or_default()
            .push_back(profile.id.clone());
    }

    let mut result: ProfileKeyMap = BTreeMap::new();
    for profile in before {
        let old_key = profile.id.trim().to_string();
        if old_key.is_empty() {
            continue;
        }
        let signature = profile_content_signature(profile).join("\u{1}");
        let Some(queue) = candidates.get_mut(&signature) else {
            continue;
        };
        let Some(new_key) = queue.pop_front() else {
            continue;
        };
        if !new_key.is_empty() {
            result.insert(old_key, new_key);
        }
    }
    result
}

/// python remap_profile_item_keys для пар списка профилей
/// ((key, profile_index, order)) — меняет только такие строки, у которых
/// старый ключ попал в карту.
pub type ProfileItemRow = (String, i64, i64);

pub fn remap_profile_item_rows(
    items: &[ProfileItemRow],
    key_map: &ProfileKeyMap,
) -> Vec<ProfileItemRow> {
    remap_item_keys_by(
        items,
        key_map,
        |(key, _, _)| (*key).clone(),
        |row, new_key, index| {
            let (_, _, order) = row;
            (
                new_key.clone(),
                profile_index_from_key(&new_key, index as i64),
                order,
            )
        },
    )
}

/// Общая форма: элементы с ключом, мапа key_map, конструктор новой строки.
fn remap_item_keys_by<T: Clone>(
    items: &[T],
    key_map: &ProfileKeyMap,
    key_of: impl Fn(&T) -> String,
    with_key: impl Fn(T, String, usize) -> T,
) -> Vec<T> {
    let mut clean_map: ProfileKeyMap = BTreeMap::new();
    for (old_key, new_key) in key_map {
        let old = old_key.trim();
        let new = new_key.trim();
        if !old.is_empty() && !new.is_empty() {
            clean_map.insert(old.to_string(), new.to_string());
        }
    }
    if clean_map.is_empty() {
        return items.to_vec();
    }
    let mut result = Vec::with_capacity(items.len());
    for (row, item) in items.iter().enumerate() {
        let old_key = key_of(item);
        let Some(new_key) = clean_map.get(&old_key) else {
            result.push(item.clone());
            continue;
        };
        let new_key = new_key.clone();
        if new_key == old_key {
            result.push(item.clone());
            continue;
        }
        result.push(with_key(item.clone(), new_key, row));
    }
    result
}

/// python remap_profile_operation_keys.
pub fn remap_profile_operation_keys(
    operation: &BTreeMap<String, String>,
    key_map: &ProfileKeyMap,
) -> BTreeMap<String, String> {
    let mut clean_map: ProfileKeyMap = BTreeMap::new();
    for (old_key, new_key) in key_map {
        let old = old_key.trim();
        let new = new_key.trim();
        if !old.is_empty() && !new.is_empty() {
            clean_map.insert(old.to_string(), new.to_string());
        }
    }
    if clean_map.is_empty() {
        return operation.clone();
    }
    let mut result = operation.clone();
    for field in [
        "profile_key",
        "source_profile_key",
        "destination_profile_key",
    ] {
        let Some(value) = result.get(field).cloned() else {
            continue;
        };
        let value = value.trim();
        if clean_map.contains_key(value) {
            result.insert(field.to_string(), clean_map[value].clone());
        }
    }
    result
}

pub fn profile_order_row_identity(key: &str, persistent_key: &str) -> String {
    if !key.is_empty() {
        return key.to_string();
    }
    if !persistent_key.is_empty() {
        return persistent_key.to_string();
    }
    String::new()
}

pub fn preset_profile_move_result_key(result_key: &str) -> String {
    result_key.trim().to_string()
}

pub fn preset_profile_move_key_map(result: &PresetProfileMoveResult) -> ProfileKeyMap {
    result.key_map.clone()
}

/// python _profile_content_signature: имя + сегменты без name-директивы.
pub fn profile_content_signature(profile: &Profile) -> Vec<String> {
    // `--new=Name` хранится в `profile.new_line`, а при переносе на первое
    // место сериализатор превращает его в `--name=Name` внутри segments.
    let engine = profile.engine.trim().to_lowercase();
    let name_directive = if engine == "winws1" {
        "--comment"
    } else {
        "--name"
    };
    let mut signature = vec![format!("profile-name:{}", profile.name.trim())];
    for segment in &profile.segments {
        let text = segment.text.trim();
        if text.is_empty() {
            continue;
        }
        if segment.kind.trim() == "directive"
            && segment.name.trim().to_lowercase() == name_directive
        {
            continue;
        }
        signature.push(text.to_string());
    }
    signature
}

/// python _profile_index_from_key.
pub fn profile_index_from_key(key: &str, fallback: i64) -> i64 {
    if let Some(value) = key.strip_prefix("profile:") {
        return value.parse::<i64>().unwrap_or(fallback);
    }
    fallback
}
