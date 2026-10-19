//! Порт `src/profile/list_apply_signature.py` + `setup_apply_signature.py`
//! — сигнатуры применения (без чего UI-апдейты считаются равными).

use serde_json::Value;

use crate::state::{ProfileListItem, ProfileListPayload, ProfileSetupPayload};

/// python _profile_item_signature: кортеж значимых полей строки.
pub fn profile_item_signature(item: &ProfileListItem) -> Vec<String> {
    vec![
        item.key.clone(),
        item.persistent_key.clone(),
        item.profile_index.to_string(),
        item.display_name.clone(),
        item.enabled.to_string(),
        item.in_preset.to_string(),
        item.strategy_id.clone(),
        item.strategy_name.clone(),
        item.match_lines.join("\u{1}"),
        item.list_type.clone(),
        item.rating.clone(),
        item.favorite.to_string(),
        item.group.clone(),
        item.group_name.clone(),
        item.order.to_string(),
        item.source_order.to_string(),
        item.group_rank.to_string(),
        item.group_collapsed.to_string(),
        item.user_profile_id.clone(),
        item.profile_name.clone(),
        item.strategy_payload_scopes.join("\u{1}"),
    ]
}

/// python profile_payload_apply_signature_base: (tuple по item, имена пресета).
pub fn profile_payload_apply_signature_base(
    payload: &ProfileListPayload,
    view_state: Option<&Value>,
) -> Vec<String> {
    let mut signature: Vec<String> = payload
        .items
        .iter()
        .map(profile_item_signature)
        .map(|parts| parts.join("\u{1f}"))
        .collect();
    signature.push(payload.selected_preset_file_name.clone());
    signature.push(payload.selected_preset_name.clone());
    signature.push(freeze_signature_value(view_state.unwrap_or(&Value::Null)));
    signature
}

/// python profile_payload_apply_signature: base + поиск.
pub fn profile_payload_apply_signature(
    payload: &ProfileListPayload,
    view_state: Option<&Value>,
    search_query: &str,
) -> Vec<String> {
    let mut signature = profile_payload_apply_signature_base(payload, view_state);
    signature.push(search_query.to_string());
    signature
}

/// python _freeze_signature_value: аналог «заморозки» (sorted tuple-сериализация).
pub fn freeze_signature_value(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.to_string(),
        Value::String(text) => serde_json::to_string(text).unwrap_or_default(),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let items: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        freeze_signature_value(&map[key])
                    )
                })
                .collect();
            format!("({})", items.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(freeze_signature_value).collect();
            format!("[{}]", parts.join(","))
        }
    }
}

/// python profile_setup_payload_apply_signature: None помечен префиксом «~».
pub fn profile_setup_payload_apply_signature(payload: Option<&ProfileSetupPayload>) -> Vec<String> {
    let Some(payload) = payload else {
        return vec!["~".to_string()];
    };
    json_setup_signature(&serde_json::to_value(payload).unwrap_or(Value::Null))
}

fn json_setup_signature(payload: &Value) -> Vec<String> {
    let entry = |field: &str| -> String {
        match payload.get(field) {
            Some(value) => freeze_signature_value(value),
            None => "null".to_string(),
        }
    };
    vec![
        entry("item"),
        {
            // python tuple(sorted(strategy_entries.items()))
            let mut parts: Vec<String> = payload
                .get("strategy_entries")
                .and_then(Value::as_array)
                .map(|list| list.iter().map(freeze_signature_value).collect())
                .unwrap_or_default();
            parts.sort();
            format!("({})", parts.join(","))
        },
        {
            let mut parts: Vec<String> = payload
                .get("strategy_states")
                .and_then(Value::as_array)
                .map(|list| list.iter().map(freeze_signature_value).collect())
                .unwrap_or_default();
            parts.sort();
            format!("({})", parts.join(","))
        },
        entry("raw_profile_text"),
        entry("raw_strategy_text"),
        entry("match_summary"),
        entry("editable_filter_kind"),
        entry("editable_filter_value"),
        entry("editable_filter_enabled"),
        entry("editable_filter_role"),
        entry("editable_filter_kinds"),
        entry("in_range"),
        entry("out_range"),
        entry("current_strategy_state"),
    ]
}
