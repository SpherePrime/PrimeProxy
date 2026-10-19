//! Порт profile/strategy_state.py: оценки, избранное и открытая группа
//! стратегий в общей базе настроек.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use primecore_settings::store::SettingsDatabase;

const VALID_RATINGS: [&str; 3] = ["", "work", "notwork"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStrategyState {
    pub rating: String,
    pub favorite: bool,
}

/// Оценки и избранное у ДРУГИХ профилей: (работает, не работает).
pub type Experience = Vec<(String, (i64, i64))>;

/// Оценки запрошенных стратегий и группа, оставленная открытой.
pub struct StrategyListMarks {
    pub states: Vec<(String, ProfileStrategyState)>,
    pub open_group: Option<String>,
}

impl Default for ProfileStrategyState {
    fn default() -> Self {
        Self {
            rating: String::new(),
            favorite: false,
        }
    }
}

/// python _read: секция уже нормализована хранилищем; version/profiles живы.
fn read_data(database: &mut SettingsDatabase) -> Value {
    let mut raw = database
        .read_raw_sections()
        .ok()
        .and_then(|sections| sections.get("profile_strategy_state").cloned())
        .unwrap_or(Value::Null);
    if !raw.is_object() {
        return Value::Object(Map::new());
    }
    let object = raw.as_object_mut().expect("объект");
    object.insert("version".into(), Value::from(1));
    object
        .entry("profiles")
        .or_insert_with(|| Value::Object(Map::new()));
    raw
}

/// python _write: заменяет секцию, хранилище само нормализует документ.
fn write_section(database: &mut SettingsDatabase, section: Value) -> Result<(), String> {
    database.update_settings(|doc| {
        if !doc.is_object() {
            *doc = Value::Object(Map::new());
        }
        if let Some(doc_object) = doc.as_object_mut() {
            doc_object.insert("profile_strategy_state".into(), section);
        }
    })
    .map(|_normalized| ())
}

fn profiles_map(data: &Value) -> Map<String, Value> {
    data.get("profiles")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn strategies_map(profile_row: &Value) -> Option<Map<String, Value>> {
    profile_row
        .get("strategies")
        .and_then(Value::as_object)
        .cloned()
}

pub fn normalize_profile_key(value: &str) -> String {
    let text = value.trim().to_string();
    if text.starts_with("uid:") || text.starts_with("name:") || text.starts_with("sig:") {
        return text;
    }
    String::new()
}

pub fn normalize_strategy_id(value: &str) -> String {
    let text = value.trim().to_string();
    if text.is_empty() || text == "none" || text == "custom" {
        return String::new();
    }
    text
}

fn normalize_rating(value: &Value) -> String {
    let rating = match value.as_str() {
        Some(raw) => raw.trim().to_lowercase(),
        None => String::new(),
    };
    if VALID_RATINGS.contains(&rating.as_str()) {
        return rating;
    }
    String::new()
}

/// Ключ группы: "" или латиница/цифры с подчёркиванием (^[a-z][a-z0-9_]{0,31}$).
pub fn normalize_open_group(value: &Value) -> Option<String> {
    let Some(text_raw) = value.as_str() else {
        return None;
    };
    let text = text_raw.trim().to_string();
    if text.is_empty() || open_group_key_ok(&text) {
        return Some(text);
    }
    None
}

fn open_group_key_ok(text: &str) -> bool {
    if text.is_empty() || text.len() > 32 {
        return false;
    }
    let mut chars = text.chars();
    let first = chars.next().expect("строка непуста");
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|symbol| symbol.is_ascii_lowercase() || symbol.is_ascii_digit() || symbol == '_')
}

fn state_from_row(row: Option<&Value>) -> ProfileStrategyState {
    let Some(row) = row else {
        return ProfileStrategyState::default();
    };
    ProfileStrategyState {
        rating: normalize_rating(&field(row, "rating")),
        favorite: field(row, "favorite").as_bool().unwrap_or(false),
    }
}

fn field(row: &Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

/// python _open_group_from_row: нет ключа — None; есть — значение или None.
fn open_group_from_row(profile_row: Option<&Value>) -> Option<String> {
    let profile_row = profile_row?;
    let object = profile_row.as_object()?;
    match object.get("open_group") {
        Some(raw) => normalize_open_group(raw),
        None => None,
    }
}

/// Python datetime.now(timezone.utc).replace(microsecond=0).isoformat().
fn now_iso() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0);
    civil_timestamp(seconds)
}

/// Секунды эпохи → гражданское время UTC (алгоритм Говарда Хиннанта).
fn civil_timestamp(seconds: i64) -> String {
    let days = seconds.div_euclid(86400);
    let day_seconds = seconds.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        hour = day_seconds / 3600,
        minute = (day_seconds % 3600) / 60,
        second = day_seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let value = days + 719_468;
    let era = value.div_euclid(146_097);
    let day_of_era = value.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_primary = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_primary + 2) / 5 + 1;
    let month = month_primary + if month_primary < 10 { 3 } else { -9 };
    let year = year_of_era + if month <= 2 { 1 } else { 0 } + era * 400;
    (year, month as u32, day as u32)
}

pub fn strategy_state(
    database: &mut SettingsDatabase,
    profile_key: &str,
    strategy_id: &str,
) -> ProfileStrategyState {
    let data = read_data(database);
    let clean_profile_key = normalize_profile_key(profile_key);
    let clean_strategy_id = normalize_strategy_id(strategy_id);
    let profiles = profiles_map(&data);
    let profile_row = profiles.get(clean_profile_key.as_str());
    let row = strategy_row_of(profile_row, clean_strategy_id.as_str());
    state_from_row(row.as_ref())
}

pub fn strategy_list_marks(
    database: &mut SettingsDatabase,
    profile_key: &str,
    strategy_ids: &[&str],
) -> StrategyListMarks {
    let clean_profile_key = normalize_profile_key(profile_key);
    if clean_profile_key.is_empty() {
        return StrategyListMarks {
            states: Vec::new(),
            open_group: None,
        };
    }
    let clean_ids: Vec<String> = strategy_ids
        .iter()
        .map(|id| normalize_strategy_id(id))
        .filter(|id| !id.is_empty())
        .collect();
    let data = read_data(database);
    let profiles = profiles_map(&data);
    let profile_row = profiles.get(clean_profile_key.as_str());
    let open_group = open_group_from_row(profile_row);
    let states = clean_ids
        .iter()
        .map(|id| (id.clone(), state_from_row(strategy_row_of(profile_row, id).as_ref())))
        .collect();
    StrategyListMarks { states, open_group }
}

/// python _strategy_row: строка стратегии в строке профиля.
fn strategy_row_of(profile_row: Option<&Value>, strategy_id: &str) -> Option<Value> {
    profile_row
        .and_then(|profile| strategies_map(profile))
        .and_then(|strategies| strategies.get(strategy_id).cloned())
}

pub fn strategy_experience(database: &mut SettingsDatabase, profile_key: &str) -> Experience {
    let own_key = normalize_profile_key(profile_key);
    let data = read_data(database);
    let profiles = profiles_map(&data);
    let mut order: Vec<String> = Vec::new();
    let mut counts: HashMap<String, (i64, i64)> = HashMap::new();
    for (other_key, profile_row) in profiles.iter() {
        if other_key == &own_key || !profile_row.is_object() {
            continue;
        }
        let Some(strategies) = strategies_map(profile_row) else {
            continue;
        };
        for (strategy_id, row) in strategies.iter() {
            let rating = normalize_rating(&field(row, "rating"));
            if rating != "work" && rating != "notwork" {
                continue;
            }
            if !counts.contains_key(strategy_id) {
                order.push(strategy_id.clone());
            }
            let entry = counts.entry(strategy_id.clone()).or_insert((0, 0));
            if rating == "work" {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }
    order
        .into_iter()
        .map(|strategy_id| {
            let (works, not_works) = counts.get(&strategy_id).copied().unwrap_or((0, 0));
            (strategy_id, (works, not_works))
        })
        .collect()
}

pub fn set_strategy_state(
    database: &mut SettingsDatabase,
    profile_key: &str,
    strategy_id: &str,
    rating: Option<&str>,
    favorite: Option<bool>,
) -> Result<ProfileStrategyState, String> {
    let clean_profile_key = normalize_profile_key(profile_key);
    let clean_strategy_id = normalize_strategy_id(strategy_id);
    if clean_profile_key.is_empty() {
        return Err("profile key is required".to_string());
    }
    if clean_strategy_id.is_empty() {
        return Err("strategy id is required".to_string());
    }
    let current = strategy_state(database, &clean_profile_key, &clean_strategy_id);
    let next_state = ProfileStrategyState {
        rating: match rating {
            Some(raw) => normalize_rating(&Value::String(raw.to_string())),
            None => current.rating.clone(),
        },
        favorite: favorite.unwrap_or(current.favorite),
    };
    if next_state == current {
        return Ok(current);
    }
    let wanted_rating = match rating {
        Some(raw) => {
            let normalized = normalize_rating(&Value::String(raw.to_string()));
            Some(normalized)
        }
        None => None,
    };
    write_strategy_states(database, |profiles| {
        apply_state_row(profiles, &clean_profile_key, &clean_strategy_id, wanted_rating, favorite)
    })?;
    Ok(strategy_state(database, &clean_profile_key, &clean_strategy_id))
}

/// python: row ищется через setdefault; пустая строка (без оценки и звезды) —
/// запись удаляется, пустая строка профиля тоже.
fn apply_state_row(
    profiles: &mut Map<String, Value>,
    profile_key: &str,
    strategy_id: &str,
    rating: Option<String>,
    favorite: Option<bool>,
) {
    let profile_row = ensure_entry(profiles, profile_key);
    ensure_object(profile_row);
    let row_object = profile_row.as_object_mut().expect("объект");
    let strategies = match row_object.get_mut("strategies") {
        Some(Value::Object(strategies)) => strategies,
        _ => {
            row_object.insert("strategies".into(), Value::Object(Map::new()));
            row_object
                .get_mut("strategies")
                .expect("стратегии")
                .as_object_mut()
                .expect("объект")
        }
    };
    let row = ensure_entry(strategies, strategy_id);
    ensure_object(row);
    let row_object = row.as_object_mut().expect("объект");
    if let Some(rating) = rating {
        row_object.insert("rating".into(), Value::String(rating));
    }
    if let Some(favorite) = favorite {
        row_object.insert("favorite".into(), Value::Bool(favorite));
    }
    row_object.insert("updated_at".into(), Value::String(now_iso()));
    let rating_empty = field(&Value::Object(row_object.clone()), "rating").as_str().unwrap_or("").is_empty();
    let favorite_on = field(&Value::Object(row_object.clone()), "favorite").as_bool().unwrap_or(false);
    if rating_empty && !favorite_on {
        strategies.remove(strategy_id);
    }
    drop_empty_profile_row(profiles, profile_key);
}

/// База: profiles.setdefault(...); записи работают как у python.
fn write_strategy_states(
    database: &mut SettingsDatabase,
    apply: impl FnOnce(&mut Map<String, Value>),
) -> Result<(), String> {
    let data = read_data(database);
    let mut section = section_object(data);
    let profiles_raw = section
        .get_mut("profiles")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut profiles = match profiles_raw {
        Value::Object(profiles) => profiles,
        _ => Map::new(),
    };
    apply(&mut profiles);
    section.insert("profiles".into(), Value::Object(profiles));
    write_section(database, Value::Object(section))
}

/// python _normalize_data ведёт базу прямо здесь, если хранилище не выводило.
fn section_object(data: Value) -> Map<String, Value> {
    match data {
        Value::Object(section) => section,
        _ => Map::new(),
    }
}

fn ensure_entry<'entry>(
    object: &'entry mut Map<String, Value>,
    key: &str,
) -> &'entry mut Value {
    object
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(Map::new()))
}

fn ensure_object(row: &mut Value) {
    if !row.is_object() {
        *row = Value::Object(Map::new());
    }
}

fn drop_empty_profile_row(profiles: &mut Map<String, Value>, profile_key: &str) {
    let Some(profile_row) = profiles.get(profile_key) else {
        return;
    };
    if !profile_row.is_object() {
        profiles.remove(profile_key);
        return;
    }
    let Some(object) = profile_row.as_object() else {
        return;
    };
    let strategies_empty = match object.get("strategies") {
        Some(Value::Object(strategies)) => strategies.is_empty(),
        Some(_) => true,
        None => false,
    };
    if strategies_empty {
        if let Some(object_mut) = profiles.get_mut(profile_key).and_then(Value::as_object_mut) {
            object_mut.remove("strategies");
        }
    }
    let empty = profiles
        .get(profile_key)
        .and_then(Value::as_object)
        .map(|object| object.is_empty())
        .unwrap_or(false);
    if empty {
        profiles.remove(profile_key);
    }
}

pub fn open_group(database: &mut SettingsDatabase, profile_key: &str) -> Option<String> {
    strategy_list_marks(database, profile_key, &[]).open_group
}

pub fn set_open_group(
    database: &mut SettingsDatabase,
    profile_key: &str,
    group_key: &str,
) -> Result<bool, String> {
    let clean_profile_key = normalize_profile_key(profile_key);
    if clean_profile_key.is_empty() {
        return Err("profile key is required".to_string());
    }
    let clean_group_key = normalize_open_group(&Value::String(group_key.to_string()))
        .ok_or_else(|| "unknown strategy group key".to_string())?;
    {
        let data = read_data(database);
        let profile_row = profiles_map(&data).get(clean_profile_key.as_str()).cloned();
        if open_group_from_row(profile_row.as_ref()) == Some(clean_group_key.clone()) {
            return Ok(false);
        }
    }
    write_strategy_states(database, |profiles| {
        let profile_row = ensure_entry(profiles, clean_profile_key.as_str());
        ensure_object(profile_row);
        profile_row
            .as_object_mut()
            .expect("объект строки")
            .insert("open_group".into(), Value::String(clean_group_key.clone()));
    })
    .map(|()| true)
}

pub fn get_grouping(database: &mut SettingsDatabase) -> String {
    let data = read_data(database);
    crate::strategy_plan::normalize_strategy_grouping(field(&data, "grouping").as_str())
}

pub fn set_grouping(database: &mut SettingsDatabase, grouping: &str) -> Result<bool, String> {
    let clean_grouping = crate::strategy_plan::normalize_strategy_grouping(Some(grouping));
    let data = read_data(database);
    let stored = crate::strategy_plan::normalize_strategy_grouping(field(&data, "grouping").as_str());
    if stored == clean_grouping {
        return Ok(false);
    }
    let mut section = match data {
        Value::Object(section) => section,
        _ => Map::new(),
    };
    section.insert("grouping".into(), Value::String(clean_grouping));
    write_section(database, Value::Object(section))?;
    Ok(true)
}

pub fn clear_strategy_state(
    database: &mut SettingsDatabase,
    profile_key: &str,
    strategy_id: &str,
) {
    let clean_profile_key = normalize_profile_key(profile_key);
    let clean_strategy_id = normalize_strategy_id(strategy_id);
    if clean_profile_key.is_empty() || clean_strategy_id.is_empty() {
        return;
    }
    let row_is_present = {
        let data = read_data(database);
        profiles_map(&data)
            .get(clean_profile_key.as_str())
            .and_then(strategies_map)
            .map(|strategies| strategies.contains_key(clean_strategy_id.as_str()))
            .unwrap_or(false)
    };
    if !row_is_present {
        return;
    }
    let _ = write_strategy_states(database, |profiles| {
        if let Some(profile_row) = profiles.get_mut(clean_profile_key.as_str()) {
            if let Some(strategies) = profile_row.get_mut("strategies").and_then(Value::as_object_mut) {
                strategies.remove(clean_strategy_id.as_str());
            }
            drop_empty_profile_row(profiles, clean_profile_key.as_str());
        }
    });
}

/// Переносит записи с legacy-ключей на uid-ключи; uid-запись побеждает.
pub fn migrate_profile_keys(
    database: &mut SettingsDatabase,
    key_mapping: &[(String, String)],
) -> Result<bool, String> {
    let mapping: Vec<(String, String)> = key_mapping
        .iter()
        .map(|(old, new)| (normalize_profile_key(old), normalize_profile_key(new)))
        .filter(|(old, new)| {
            !old.is_empty() && !new.is_empty() && old != new && !old.starts_with("uid:")
        })
        .collect();
    if mapping.is_empty() {
        return Ok(false);
    }
    let mut changed = false;
    let _ = write_strategy_states(database, |profiles| {
        for (old_key, new_key) in mapping.iter() {
            let Some(row) = profiles.remove(old_key) else {
                continue;
            };
            changed = true;
            if !profiles.contains_key(new_key) {
                profiles.insert(new_key.clone(), row);
            }
        }
    });
    Ok(changed)
}
