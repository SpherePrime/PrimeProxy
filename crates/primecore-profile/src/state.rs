//! Порт `src/profile/state.py` — неизменяемые элементы payload-ов списка
//! профилей и setup-страницы, плюс apply-подписи (`setup_apply_signature.py`).


use serde_json::Value;

use crate::strategy_catalog::StrategyEntry;
use crate::strategy_state::{Experience, ProfileStrategyState};
use crate::strategy_usage::{StrategyPlace, StrategyUsage};

/// python {стратегия: (StrategyPlace, ...)}.
pub type StrategyPlaces = Vec<(String, Vec<StrategyPlace>)>;

/// python ProfileListFileEditorState.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileListFileEditorState {
    pub kind: String,
    pub display_path: String,
    pub text: String,
    pub base_text: String,
    pub user_text: String,
    pub base_display_path: String,
    pub user_display_path: String,
    pub editable: bool,
    /// (номер строки, причина) — сравнение tuple-строк.
    pub invalid_lines: Vec<(usize, String)>,
    pub error_text: String,
    pub base_entries_count: i64,
    pub user_entries_count: i64,
}

impl Default for ProfileListFileEditorState {
    fn default() -> Self {
        Self {
            kind: String::new(),
            display_path: String::new(),
            text: String::new(),
            base_text: String::new(),
            user_text: String::new(),
            base_display_path: String::new(),
            user_display_path: String::new(),
            editable: false,
            invalid_lines: Vec::new(),
            error_text: String::new(),
            base_entries_count: 0,
            user_entries_count: 0,
        }
    }
}

/// python ProfileListItem (равенство по всем полям, blob-предупреждения — без).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProfileListItem {
    pub key: String,
    pub persistent_key: String,
    pub profile_index: i64,
    pub display_name: String,
    pub enabled: bool,
    pub in_preset: bool,
    pub strategy_id: String,
    pub strategy_name: String,
    pub match_lines: Vec<String>,
    pub list_type: String,
    pub rating: String,
    pub favorite: bool,
    pub group: String,
    pub group_name: String,
    pub order: i64,
    /// Исходный порядок из файла пресета/шаблонов — вход резолвера порядка.
    pub source_order: i64,
    pub group_rank: i64,
    pub group_collapsed: bool,
    pub user_profile_id: String,
    pub profile_name: String,
    /// Типы пакетов веток составной стратегии («TLS · HTTP»), пусто — обычная.
    pub strategy_payload_scopes: Vec<String>,
}

impl Default for ProfileListItem {
    fn default() -> Self {
        Self {
            key: String::new(),
            persistent_key: String::new(),
            profile_index: -1,
            display_name: String::new(),
            enabled: false,
            in_preset: false,
            strategy_id: String::new(),
            strategy_name: String::new(),
            match_lines: Vec::new(),
            list_type: String::new(),
            rating: String::new(),
            favorite: false,
            group: String::new(),
            group_name: String::new(),
            order: 0,
            source_order: 0,
            group_rank: 10_000,
            group_collapsed: false,
            user_profile_id: String::new(),
            profile_name: String::new(),
            strategy_payload_scopes: Vec::new(),
        }
    }
}

/// python ProfileListPayload.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileListPayload {
    pub items: Vec<ProfileListItem>,
    pub selected_preset_file_name: String,
    pub selected_preset_name: String,
}

/// Стратегии setup-страницы: порядок python dict-обходов.
pub type StrategyEntryMap = Vec<(String, StrategyEntry)>;
pub type StrategyStateMap = Vec<(String, ProfileStrategyState)>;

/// python ProfileSetupPayload.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileSetupPayload {
    pub item: ProfileListItem,
    pub strategy_entries: StrategyEntryMap,
    pub strategy_states: StrategyStateMap,
    pub raw_profile_text: String,
    pub raw_strategy_text: String,
    pub match_summary: String,
    pub editable_filter_kind: String,
    pub editable_filter_value: String,
    pub editable_filter_enabled: bool,
    pub editable_filter_role: String,
    pub editable_filter_kinds: Vec<String>,
    pub in_range: String,
    pub out_range: String,
    pub current_strategy_state: Option<ProfileStrategyState>,
    pub strategy_open_group: Option<String>,
    pub strategy_grouping: String,
    pub strategy_usage: Vec<(String, StrategyUsage)>,
    pub strategy_experience: Experience,
    pub strategy_places: StrategyPlaces,
    pub preset_preamble_text: String,
}

impl Default for ProfileSetupPayload {
    fn default() -> Self {
        Self {
            item: ProfileListItem::default(),
            strategy_entries: Vec::new(),
            strategy_states: Vec::new(),
            raw_profile_text: String::new(),
            raw_strategy_text: String::new(),
            match_summary: String::new(),
            editable_filter_kind: String::new(),
            editable_filter_value: String::new(),
            editable_filter_enabled: true,
            editable_filter_role: "primary".to_string(),
            editable_filter_kinds: Vec::new(),
            in_range: "x".to_string(),
            out_range: "a".to_string(),
            current_strategy_state: None,
            strategy_open_group: None,
            strategy_grouping: "method".to_string(),
            strategy_usage: Vec::new(),
            strategy_experience: Vec::new(),
            strategy_places: Vec::new(),
            preset_preamble_text: String::new(),
        }
    }
}

/// python StrategyApplyResult.
#[derive(Debug, Clone, PartialEq)]
pub struct StrategyApplyResult {
    pub status: String,
    pub profile_key: String,
    pub strategy_id: String,
    pub should_reload: bool,
    pub message: String,
    pub change_kind: String,
    pub list_structure_changed: bool,
    pub profile_payload_changed: bool,
    pub profile_list_item_changed: bool,
    pub summary_changed: bool,
    pub runtime_apply_needed: bool,
    pub blob_warnings: Vec<String>,
}

impl StrategyApplyResult {
    pub fn new(status: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            profile_key: String::new(),
            strategy_id: String::new(),
            should_reload: false,
            message: String::new(),
            change_kind: "unchanged".to_string(),
            list_structure_changed: false,
            profile_payload_changed: false,
            profile_list_item_changed: false,
            summary_changed: false,
            runtime_apply_needed: false,
            blob_warnings: Vec::new(),
        }
    }
}

/// python profile_setup_payload_apply_signature.
pub use profile_setup_apply_signature as profile_setup_payload_apply_signature;

pub fn profile_setup_apply_signature(payload: Option<&ProfileSetupPayload>) -> Value {
    let Some(payload) = payload else {
        return Value::Array(vec![Value::Null]);
    };
    let entries = sorted_entries(&payload.strategy_entries);
    let states = sorted_strategy_states(&payload.strategy_states);
    Value::Array(vec![
        serde_json::to_value(&payload.item).unwrap_or(Value::Null),
        Value::Array(
            entries
                .into_iter()
                .map(|(key, entry)| {
                    Value::Array(vec![
                        Value::String(key),
                        serde_json::to_value(&entry).unwrap_or(Value::Null),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            states
                .into_iter()
                .map(|(key, state)| {
                    Value::Array(vec![
                        Value::String(key),
                        serde_json::to_value(&state).unwrap_or(Value::Null),
                    ])
                })
                .collect(),
        ),
        Value::String(payload.raw_profile_text.clone()),
        Value::String(payload.raw_strategy_text.clone()),
        Value::String(payload.match_summary.clone()),
        Value::String(payload.editable_filter_kind.clone()),
        Value::String(payload.editable_filter_value.clone()),
        Value::Bool(payload.editable_filter_enabled),
        Value::String(payload.editable_filter_role.clone()),
        Value::Array(
            payload
                .editable_filter_kinds
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
        Value::String(if payload.in_range.is_empty() { "x".to_string() } else { payload.in_range.clone() }),
        Value::String(if payload.out_range.is_empty() { "a".to_string() } else { payload.out_range.clone() }),
        payload
            .current_strategy_state
            .as_ref()
            .map(|state| serde_json::to_value(state).unwrap_or(Value::Null))
            .unwrap_or(Value::Null),
    ])
}

fn sorted_entries(entries: &StrategyEntryMap) -> Vec<(String, StrategyEntry)> {
    let mut sorted = entries.clone();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    sorted
}

fn sorted_strategy_states(states: &StrategyStateMap) -> Vec<(String, ProfileStrategyState)> {
    let mut sorted = states.clone();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    sorted
}
