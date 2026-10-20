//! Порт `src/profile/display_items.py` + `order_view_state.py` —
//! строки отображения профиля и состояние окна порядка.

use crate::state::ProfileListItem;
use crate::strategy_shape::payload_badge_text;

/// python ProfileDisplayItem (совместимо с ProfileListItem).
pub type ProfileDisplayItem = ProfileListItem;

/// python profile_display_sort_key: (group_rank, order, display_name.lower, key).
pub fn profile_display_sort_key(item: &ProfileDisplayItem) -> (i64, i64, String, String) {
    (
        item.group_rank,
        item.order,
        item.display_name.trim().to_lowercase(),
        item.key.clone(),
    )
}

/// python build_profile_display_items: стабильно отсортированные строки.
pub fn build_profile_display_items(
    items: impl IntoIterator<Item = ProfileDisplayItem>,
) -> Vec<ProfileDisplayItem> {
    let mut rows: Vec<ProfileDisplayItem> = items.into_iter().collect();
    sort_display_items(&mut rows);
    rows
}

fn sort_display_items(rows: &mut [ProfileDisplayItem]) {
    // python list.sort — стабильная.
    rows.sort_by(|item_a, item_b| {
        profile_display_sort_key(item_a).cmp(&profile_display_sort_key(item_b))
    });
}

/// Значок «TLS · HTTP» по scopes (python payload_badge_text).
pub fn strategy_payload_badge(scopes: &[String]) -> String {
    payload_badge_text(scopes)
}

/// python _display_item_from_profile: значения строк с заполнением.
pub fn display_item_from_list_item(item: &ProfileListItem) -> ProfileDisplayItem {
    ProfileDisplayItem {
        group: item.group.trim().to_string(),
        group_name: {
            let raw = if item.group_name.trim().is_empty() {
                if item.group.trim().is_empty() {
                    "Общие".to_string()
                } else {
                    item.group.trim().to_string()
                }
            } else {
                item.group_name.trim().to_string()
            };
            raw
        },
        display_name: {
            let raw = item.display_name.trim();
            if raw.is_empty() {
                "Профиль".to_string()
            } else {
                raw.to_string()
            }
        },
        strategy_id: {
            let raw = item.strategy_id.trim();
            if raw.is_empty() {
                "none".to_string()
            } else {
                raw.to_string()
            }
        },
        strategy_name: {
            let raw = item.strategy_name.trim();
            if raw.is_empty() {
                "Стратегия не выбрана".to_string()
            } else {
                raw.to_string()
            }
        },
        ..item.clone()
    }
}

// ---------------------------------------------------------------- view_state

/// python ProfileOrderListViewState.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileOrderListViewState {
    pub items: Vec<ProfileListItem>,
    /// Порядок python dict (порядок вставки).
    pub profile_items: Vec<(String, ProfileListItem)>,
}

impl ProfileOrderListViewState {
    /// python item_by_key: get(key).
    pub fn item_by_key(&self, key: &str) -> Option<&ProfileListItem> {
        self.profile_items
            .iter()
            .find(|(item_key, _)| item_key == key)
            .map(|(_, item)| item)
    }
}

/// python build_profile_order_list_view_state.
pub fn build_profile_order_list_view_state(
    items: &[ProfileListItem],
    preserve_order: bool,
) -> ProfileOrderListViewState {
    let mut rows: Vec<ProfileListItem> = items
        .iter()
        .filter(|item| item.in_preset)
        .cloned()
        .collect();
    if !preserve_order {
        // python list.sort — стабильная по profile_index.
        rows.sort_by(|item_a, item_b| item_a.profile_index.cmp(&item_b.profile_index));
    }
    let profile_items: Vec<(String, ProfileListItem)> = rows
        .iter()
        .filter(|item| !item.key.is_empty())
        .map(|item| (item.key.clone(), item.clone()))
        .collect();
    ProfileOrderListViewState {
        items: rows,
        profile_items,
    }
}

/// python move_profile_order_items: новый порядок или None.
pub fn move_profile_order_items(
    items: &[ProfileListItem],
    source_profile_key: &str,
    action: &str,
    destination_profile_key: &str,
) -> Option<Vec<ProfileListItem>> {
    let source_key = source_profile_key.trim();
    let move_action = action.trim();
    let destination_key = destination_profile_key.trim();
    if source_key.is_empty() {
        return None;
    }

    let mut rows: Vec<ProfileListItem> = items
        .iter()
        .filter(|item| item.in_preset)
        .cloned()
        .collect();
    let source_index = rows.iter().position(|item| item.key == source_key)?;
    let source = rows.remove(source_index);

    let insert_index = if move_action == "end" {
        rows.len()
    } else {
        let destination_index = rows.iter().position(|item| item.key == destination_key)?;
        destination_index + if move_action == "after" { 1 } else { 0 }
    };
    rows.insert(insert_index, source);
    Some(rows)
}
