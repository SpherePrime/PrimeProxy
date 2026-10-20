//! Порт `src/profile/list_view_state.py` — состояние списка профилей и строки
//! просмотра (без Qt: строки — данные, рендером занят фасад UI).

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::display_items::{
    build_profile_display_items, profile_display_sort_key, ProfileDisplayItem,
};
use crate::folder_ordering::plan_view_move;
use crate::folders::build_default_profile_folders;
use crate::icons::resolve_profile_icon;
use crate::match_filters::{
    is_voice_match, ports_label_from_match_lines, protocol_label_from_match_lines,
};

/// python PROFILES_NOT_ALL_NEEDED_HINT.
pub const PROFILES_NOT_ALL_NEEDED_HINT: &str = "Включать все профили не нужно: в пресете уже включено то, что обычно требуется. Если сайт не открывается, сначала смените стратегию у включённого профиля.";

/// python PROFILE_METER_MAX_SEGMENTS.
pub const PROFILE_METER_MAX_SEGMENTS: usize = 8;

const PROFILE_NAME_ROLE_SEPARATOR: &str = " · ";

const PROTOCOL_TOOLTIP_NOTES: [(&str, &str); 6] = [
    (
        "TCP",
        "TCP — обычные соединения с сайтами и сервисами (TLS/HTTP).",
    ),
    (
        "TCP/HTTP",
        "TCP/HTTP — незашифрованный HTTP-трафик (порт 80).",
    ),
    (
        "UDP",
        "UDP — трафик без установления соединения: QUIC, голос, игры.",
    ),
    (
        "L7",
        "L7 — фильтр по протоколу приложения: QUIC, STUN, WireGuard и похожие.",
    ),
    ("TCP/UDP", "TCP и UDP — профиль покрывает оба вида трафика."),
    (
        "Voice",
        "Voice — голосовой трафик: Discord Voice, STUN (звонки).",
    ),
];

const LIST_TYPE_TOOLTIP_NOTES: [(&str, &str); 2] = [
    (
        "hostlist",
        "Hostlist — обход действует только для доменов из списка этого профиля.",
    ),
    (
        "ipset",
        "IPset — обход действует по IP-адресам из списка (когда домен определить нельзя, например для QUIC или голоса).",
    ),
];

const SITE_ICON_PREFIXES: [&str; 3] = ["simple:", "own:", "fa5b."];
const INITIALS_ICON_PREFIX: &str = "profile-initials:";

/// python ProfileListViewState (dict-поле — порядок вставки).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileListViewState {
    pub all_items: Vec<ProfileDisplayItem>,
    /// python dict item.key → item (порядок вставки = порядок строк).
    pub profile_items: Vec<(String, ProfileDisplayItem)>,
    /// python dict group → bool.
    pub group_expanded: Vec<(String, bool)>,
    pub active_profile_types: Vec<String>,
    pub search_query: String,
    pub show_only_added: bool,
    pub rows: Vec<Map<String, Value>>,
}

impl ProfileListViewState {
    /// python item_by_key / get(key).
    pub fn item_by_key(&self, key: &str) -> Option<&ProfileDisplayItem> {
        self.profile_items
            .iter()
            .find(|(item_key, _)| item_key == key)
            .map(|(_, item)| item)
    }

    pub fn group_expanded_key(&self, key: &str) -> bool {
        self.group_expanded
            .iter()
            .find(|(group, _)| group == key)
            .map(|(_, value)| *value)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------- helpers

fn item_group_rank(item: &ProfileDisplayItem) -> i64 {
    item.group_rank
}

fn normalized_profile_types(profile_types: Option<&[String]>) -> Vec<String> {
    let mut active: Vec<String> = match profile_types {
        Some(types) => types
            .iter()
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .collect(),
        None => vec!["all".to_string()],
    };
    if active.is_empty() {
        active = vec!["all".to_string()];
    }
    active
}

fn normalized_search_query(query: &str) -> String {
    query
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn grouped_items(items: &[ProfileDisplayItem]) -> Vec<(String, Vec<ProfileDisplayItem>)> {
    let mut grouped: Vec<(String, Vec<ProfileDisplayItem>)> = Vec::new();
    for item in items {
        let group_key = if item.group.is_empty() {
            "common".to_string()
        } else {
            item.group.clone()
        };
        match grouped.iter_mut().find(|(key, _)| *key == group_key) {
            Some((_, group)) => group.push(item.clone()),
            None => grouped.push((group_key, vec![item.clone()])),
        }
    }
    grouped
}

fn initial_group_expanded(items: &[ProfileDisplayItem]) -> Vec<(String, bool)> {
    let mut result: Vec<(String, bool)> = Vec::new();
    for item in items {
        let group_key = if item.group.is_empty() {
            "common".to_string()
        } else {
            item.group.clone()
        };
        if !result.iter().any(|(key, _)| *key == group_key) {
            result.push((group_key, !item.group_collapsed));
        }
    }
    result
}

fn ordered_group_keys(grouped: &[(String, Vec<ProfileDisplayItem>)]) -> Vec<String> {
    // Ранг папки назначает резолвер order-а из состояния папок.
    let rated: Vec<(i64, String)> = grouped
        .iter()
        .map(|(key, group_items)| {
            let rank = group_items
                .iter()
                .map(|item| item_group_rank(item))
                .min()
                .unwrap_or(10_000);
            (rank, key.clone())
        })
        .collect();
    // python sorted(key=(rank, key.lower())), стабильная.
    let mut sorted_keys: Vec<String> = grouped.iter().map(|(key, _)| key.clone()).collect();
    sorted_keys.sort_by(|key_a, key_b| {
        let rank_a = rated
            .iter()
            .find(|(_, key)| *key == *key_a)
            .map(|(rank, _)| *rank)
            .unwrap_or(10_000);
        let rank_b = rated
            .iter()
            .find(|(_, key)| *key == *key_b)
            .map(|(rank, _)| *rank)
            .unwrap_or(10_000);
        let lowered = |items: &str| {
            items
                .chars()
                .map(|c| c.to_uppercase().next().unwrap_or(c))
                .collect::<String>()
                .to_uppercase()
        };
        let _ = lowered;
        let compare = rank_a.cmp(&rank_b).then(key_a.cmp(key_b));
        compare
    });
    let _ = &mut sorted_keys
        .iter()
        .map(|key| key.to_lowercase())
        .collect::<Vec<_>>();
    sorted_keys
}

fn group_name_for_key(group_key: &str, items: &[ProfileDisplayItem]) -> String {
    let key = if group_key.trim().is_empty() {
        "common".to_string()
    } else {
        group_key.trim().to_string()
    };
    for item in items {
        let group = if item.group.is_empty() {
            "common".to_string()
        } else {
            item.group.clone()
        };
        if group == key && !item.group_name.trim().is_empty() {
            return item.group_name.trim().to_string();
        }
    }
    let defaults = build_default_profile_folders();
    let folders = defaults
        .get("folders")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(folder) = folders.get(&key) {
        if let Some(name) = folder.get("name").and_then(Value::as_str) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    title_case(&key)
}

fn title_case(text: &str) -> String {
    // python key.title().
    let mut out = String::with_capacity(text.len());
    let mut upper_next = true;
    for ch in text.chars() {
        if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
        if !out
            .chars()
            .last()
            .is_some_and(|last| last.is_alphanumeric())
        {
            upper_next = true;
        }
        if ch.is_alphanumeric() {
            // после буквы capitalize выключен.
        } else {
            upper_next = true;
        }
    }
    out
}

fn match_summary(item: &ProfileDisplayItem) -> String {
    let protocol = protocol_label_from_match_lines(&item.match_lines);
    let ports = ports_label_from_match_lines(&item.match_lines);
    let mut parts: Vec<String> = Vec::new();
    if !protocol.is_empty() {
        parts.push(protocol);
    }
    if !ports.is_empty() {
        parts.push(ports);
    }
    if !item.list_type.is_empty() {
        parts.push(item.list_type.clone());
    }
    if parts.is_empty() {
        "без явных условий".to_string()
    } else {
        parts.join(" • ")
    }
}

fn profile_search_text(item: &ProfileDisplayItem) -> String {
    let parts = [
        item.display_name.clone(),
        item.group.clone(),
        item.group_name.clone(),
        item.strategy_id.clone(),
        item.strategy_name.clone(),
        item.list_type.clone(),
        match_summary(item),
        item.match_lines.join(" "),
    ];
    parts
        .iter()
        .filter(|part| !part.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn profile_matches_type_filter(item: &ProfileDisplayItem, active_profile_types: &[String]) -> bool {
    if active_profile_types.iter().any(|value| value == "all") {
        return true;
    }
    let match_lines = &item.match_lines;
    let protocol = protocol_label_from_match_lines(match_lines).to_uppercase();
    let summary = match_summary(item);
    let text = format!("{} {} {}", item.display_name, summary, item.group).to_lowercase();
    for active in active_profile_types {
        match active.as_str() {
            "tcp" if protocol.contains("TCP") => return true,
            "udp" if protocol.contains("UDP") || protocol.contains("L7") => return true,
            "discord" if text.contains("discord") => return true,
            "voice" if is_voice_match(match_lines) => return true,
            "games" if text.contains("game") => return true,
            _ => {}
        }
    }
    false
}

fn profile_matches_search_query(item: &ProfileDisplayItem, search_query: &str) -> bool {
    let query = search_query;
    if query.is_empty() {
        return true;
    }
    let search_text = profile_search_text(item);
    query
        .split_whitespace()
        .all(|part| search_text.contains(part))
}

fn profile_matches_filter(
    item: &ProfileDisplayItem,
    active_profile_types: &[String],
    search_query: &str,
    show_only_added: bool,
) -> bool {
    if show_only_added && !item.in_preset {
        return false;
    }
    profile_matches_type_filter(item, active_profile_types)
        && profile_matches_search_query(item, search_query)
}

// ------------------------------------------------------------------ rows

fn display_row(map: &[(&str, Value)]) -> Map<String, Value> {
    map.iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect()
}

fn shared_group_icon(group_items: &[ProfileDisplayItem]) -> Option<(String, String)> {
    // Значок значка группы — значок её главного сайта.
    let mut counts: Vec<(String, usize)> = Vec::new();
    let mut specs: Vec<(String, (String, String))> = Vec::new();
    let mut counted_rows: usize = 0;
    for item in group_items {
        let found = resolve_profile_icon(&item.display_name, &item.match_lines);
        if SITE_ICON_PREFIXES
            .iter()
            .any(|prefix| found.icon_name.starts_with(prefix))
        {
            let existing = counts.iter_mut().find(|(name, _)| *name == found.icon_name);
            match existing {
                Some((_, count)) => {
                    *count += 1;
                }
                None => counts.push((found.icon_name.clone(), 1)),
            }
            if !specs.iter_mut().any(|(name, _)| *name == found.icon_name) {
                specs.push((
                    found.icon_name.clone(),
                    (found.icon_name.clone(), found.color.clone()),
                ));
            }
            counted_rows += 1;
        } else if found.icon_name.starts_with(INITIALS_ICON_PREFIX) {
            counted_rows += 1;
        }
    }
    if counts.is_empty() {
        return None;
    }
    let (icon_name, count) = counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .cloned()
        .unwrap_or_default();
    if count * 2 <= counted_rows {
        return None;
    }
    let (_, (icon_name, icon_color)) = specs
        .into_iter()
        .find(|(name, _)| *name == icon_name)
        .unwrap_or_else(|| (String::new(), (String::new(), String::new())));
    Some((icon_name, icon_color))
}

pub fn profile_group_tooltip(group_name: &str, active_count: usize, count: usize) -> String {
    format!("Группа «{}»: профили одного сайта или сервиса.\nВключено {} из {}. Нажмите на шапку, чтобы свернуть или развернуть группу.", group_name.trim(), active_count, count)
}

pub fn profile_group_counter_tooltip(active_count: usize, count: usize) -> String {
    let meter = if count <= PROFILE_METER_MAX_SEGMENTS {
        "Каждое деление полоски — один профиль, в том же порядке, что строки ниже. Закрашенное деление — профиль включён."
    } else {
        "Полоска показывает, какая часть профилей группы включена."
    };
    format!(
        "Включено {} из {} профилей группы.\n{}\n{}",
        active_count, count, meter, PROFILES_NOT_ALL_NEEDED_HINT
    )
}

pub fn profile_group_chevron_tooltip(expanded: bool) -> &'static str {
    if expanded {
        "Свернуть группу"
    } else {
        "Развернуть группу"
    }
}

pub fn profile_state_tooltip(in_preset: bool, enabled: bool, icon_in_header: bool) -> String {
    let working = in_preset && enabled;
    let marker = if icon_in_header {
        if working {
            "Закрашенная точка"
        } else {
            "Кольцо"
        }
    } else if in_preset {
        "Цветной значок"
    } else {
        "Серый значок"
    };
    if working {
        format!("{marker}: профиль включён, его трафик обрабатывается выбранной стратегией.")
    } else if in_preset {
        format!("{marker}: профиль есть в пресете, но выключен. В файле это записано через --skip.")
    } else {
        format!("{marker}: профиля нет в пресете, он ничего не делает. Это нормально.\n{PROFILES_NOT_ALL_NEEDED_HINT}")
    }
}

pub fn profile_strategy_tooltip(
    in_preset: bool,
    enabled: bool,
    strategy_name: &str,
    rating: &str,
    favorite: bool,
) -> String {
    if !in_preset {
        return format!("Профиль не добавлен в пресет.\nНажмите на него, чтобы включить и выбрать стратегию, — только если этот сайт у вас не открывается.").to_string();
    }
    if !enabled {
        return "Профиль выключен: движок его пропускает.\nВключить его можно в меню по правой кнопке мыши.".to_string();
    }
    let mut lines: Vec<String> = vec![
        format!("Стратегия обхода: {}.", strategy_name.trim()),
        "Если сайт не открывается, нажмите на профиль и попробуйте другую стратегию.".to_string(),
    ];
    if favorite {
        lines.push("Звезда: стратегия у вас в избранном.".to_string());
    }
    if rating == "work" {
        lines.push("Галочка: вы отметили, что эта стратегия работает.".to_string());
    } else if rating == "notwork" {
        lines.push("Крестик: вы отметили, что эта стратегия не работает.".to_string());
    }
    lines.join("\n")
}

pub fn profile_row_tooltip(item: &ProfileDisplayItem) -> String {
    let protocol_label = protocol_label_from_match_lines(&item.match_lines);
    let mut lines: Vec<String> = vec![match_summary(item)];
    if let Some((_, note)) = PROTOCOL_TOOLTIP_NOTES
        .iter()
        .find(|(name, _)| *name == protocol_label.as_str())
    {
        lines.push(note.to_string());
    }
    if let Some((_, note)) = LIST_TYPE_TOOLTIP_NOTES
        .iter()
        .find(|(name, _)| *name == item.list_type.to_lowercase())
    {
        lines.push(note.to_string());
    }
    let strategy_name = item.strategy_name.trim().to_string();
    if !strategy_name.is_empty() && strategy_name != "Стратегия не выбрана" {
        lines.push(format!("Стратегия обхода: {strategy_name}."));
    }
    lines.join("\n")
}

pub fn profile_name_inside_group(name: &str, group_title: &str) -> String {
    let name = name.trim().to_string();
    let prefix = format!(
        "{PROFILE_NAME_ROLE_SEPARATOR_}",
        PROFILE_NAME_ROLE_SEPARATOR_ =
            format!("{}{}", group_title.trim(), PROFILE_NAME_ROLE_SEPARATOR)
    );
    let prefix = format!("{}{}", group_title.trim(), PROFILE_NAME_ROLE_SEPARATOR);
    if prefix.chars().count() <= PROFILE_NAME_ROLE_SEPARATOR.chars().count()
        || !name.to_lowercase().starts_with(&prefix.to_lowercase())
    {
        return name;
    }
    let role = name[prefix.len()..].trim().to_string();
    if role.is_empty() {
        return name;
    }
    format!(
        "{}{}",
        role.chars().next().unwrap_or(' ').to_uppercase(),
        role.chars().skip(1).collect::<String>()
    )
}

pub fn row_for_profile(item: &ProfileDisplayItem, header_icon_name: &str) -> Map<String, Value> {
    let match_lines = item.match_lines.clone();
    let ports = ports_label_from_match_lines(&match_lines);
    let mut description_parts: Vec<String> = Vec::new();
    let protocol_label = protocol_label_from_match_lines(&match_lines);
    description_parts.push(protocol_label.clone());
    if !ports.is_empty() {
        description_parts.push(format!("порты: {ports}"));
    }
    let mut tooltip = profile_row_tooltip(item);
    if !item.in_preset {
        tooltip = format!("{}\nПрофиля ещё нет в пресете. Включать его не обязательно: нажмите на него и выберите готовую стратегию, только если этот сайт у вас не открывается.", tooltip);
    } else if !item.enabled {
        tooltip = format!(
            "{}\nПрофиль есть в пресете, но сейчас выключен. В файле это записано через --skip.",
            tooltip
        );
    }
    let found = resolve_profile_icon(&item.display_name, &match_lines);
    let tile_name = profile_name_inside_group(&item.display_name, &item.group_name);
    if tile_name != item.display_name {
        tooltip = format!("{}\n{}", item.display_name, tooltip);
    }
    let written_name = item.profile_name.trim().to_string();
    if item.in_preset && !written_name.is_empty() && written_name != item.display_name {
        tooltip = format!(
            "{}\nВ тексте пресета профиль записан как «{}».",
            tooltip, written_name
        );
    }
    let description = description_parts
        .iter()
        .filter(|part| !part.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    display_row(&[
        ("kind", json!("profile")),
        ("key", json!(item.key)),
        ("persistent_key", json!(item.persistent_key)),
        ("display_name", json!(item.display_name)),
        ("tile_name", json!(tile_name)),
        ("description", Value::String(description)),
        ("strategy_id", json!(item.strategy_id)),
        ("strategy_name", json!(item.strategy_name)),
        (
            "strategy_payload_badge",
            Value::String(crate::display_items::strategy_payload_badge(
                &item.strategy_payload_scopes,
            )),
        ),
        (
            "match_lines",
            Value::Array(match_lines.iter().map(|line| json!(line)).collect()),
        ),
        ("list_type", json!(item.list_type)),
        ("rating", json!(item.rating)),
        ("favorite", json!(item.favorite)),
        ("in_preset", json!(item.in_preset)),
        ("enabled", json!(item.enabled)),
        ("group", json!(item.group)),
        ("group_name", json!(item.group_name)),
        ("icon_name", Value::String(found.icon_name.clone())),
        (
            "icon_color",
            Value::String(if item.in_preset {
                found.color.clone()
            } else {
                "#888888".to_string()
            }),
        ),
        (
            "icon_in_header",
            json!(!header_icon_name.is_empty() && found.icon_name == header_icon_name),
        ),
        ("tooltip", Value::String(tooltip)),
    ])
}

pub fn build_profile_rows_from(
    items: &[ProfileDisplayItem],
    group_expanded: &[(String, bool)],
    active_profile_types: &[String],
    search_query: &str,
    show_only_added: bool,
) -> Vec<Map<String, Value>> {
    let mut rows: Vec<Map<String, Value>> = Vec::new();
    let grouped = grouped_items(items);
    if grouped.is_empty() {
        return rows;
    }
    for group_key in ordered_group_keys(&grouped) {
        let some_group_items = grouped
            .iter()
            .find(|(key, _)| *key == group_key)
            .map(|(_, group_items)| group_items.clone())
            .unwrap_or_default();
        let filtered: Vec<ProfileDisplayItem> = some_group_items
            .iter()
            .filter(|item| {
                profile_matches_filter(item, active_profile_types, search_query, show_only_added)
            })
            .cloned()
            .collect();
        if filtered.is_empty() {
            continue;
        }
        let mut group_items = filtered;
        sort_display_items(&mut group_items);
        let group_name = group_items
            .first()
            .map(|item| item.group_name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| group_key_title(&group_key));
        let expanded = group_expanded
            .iter()
            .find(|(key, _)| *key == group_key)
            .map(|(_, value)| *value)
            .unwrap_or(true);
        let active_flags: Vec<bool> = group_items
            .iter()
            .map(|item| item.in_preset && item.enabled)
            .collect();
        let active_count = active_flags
            .iter()
            .filter(|flag| **flag)
            .count()
            .to_string();
        let active_count = active_count.parse::<usize>().unwrap_or(0);
        let shared_icon = shared_group_icon(&group_items);
        let row = display_row(&[
            ("kind", json!("folder")),
            ("group", json!(group_key)),
            ("group_name", json!(group_name)),
            ("collapsed", json!(!expanded)),
            ("count", json!(group_items.len())),
            ("active_count", json!(active_count)),
            (
                "active_flags",
                Value::Array(active_flags.iter().map(|flag| json!(flag)).collect()),
            ),
            (
                "tooltip",
                Value::String(profile_group_tooltip(
                    &group_name,
                    active_count,
                    group_items.len(),
                )),
            ),
            (
                "icon_name",
                json!(shared_icon
                    .as_ref()
                    .map(|(name, _)| name.clone())
                    .unwrap_or_default()),
            ),
            (
                "icon_color",
                json!(shared_icon
                    .as_ref()
                    .map(|(name, color)| color.clone())
                    .unwrap_or_default()),
            ),
        ]);
        rows.push(row);
        // python: `(icon_name, color)` значка после сжатия.
        if !expanded && search_query.trim().is_empty() {
            continue;
        }
        let header_icon_name = shared_icon.map(|(name, _)| name).unwrap_or_default();
        for item in &group_items {
            rows.push(row_for_profile(item, &header_icon_name));
        }
    }
    rows
}

fn group_key_title(key: &str) -> String {
    title_case(key)
}

fn sort_display_items(items: &mut [ProfileDisplayItem]) {
    items.sort_by(|a, b| profile_display_sort_key(a).cmp(&profile_display_sort_key(b)));
}

pub fn build_profile_list_view_state(
    items: &[ProfileDisplayItem],
    active_profile_types: Option<&[String]>,
    search_query: &str,
    show_only_added: bool,
    group_expanded: Option<&[(String, bool)]>,
    folder_state: Option<&Value>,
) -> ProfileListViewState {
    let display_items = apply_profile_folder_state_to_items(
        &build_profile_display_items(items.to_vec()),
        folder_state,
    );
    let active = normalized_profile_types(active_profile_types);
    let normalized_search = normalized_search_query(search_query);
    let mut next_group_expanded = match group_expanded {
        Some(value) => value.to_vec(),
        None => initial_group_expanded(&display_items),
    };
    for item in &display_items {
        let group_key = if item.group.is_empty() {
            "common".to_string()
        } else {
            item.group.clone()
        };
        if !next_group_expanded
            .iter()
            .any(|(some, _)| *some == group_key)
        {
            next_group_expanded.push((group_key, true));
        }
    }
    let profile_items: Vec<(String, ProfileDisplayItem)> = display_items
        .iter()
        .map(|item| (item.key.clone(), item.clone()))
        .collect();
    let rows = build_profile_rows_from(
        &display_items,
        &next_group_expanded,
        &active,
        &normalized_search,
        show_only_added,
    );
    ProfileListViewState {
        all_items: display_items,
        profile_items,
        group_expanded: next_group_expanded,
        active_profile_types: active,
        search_query: normalized_search,
        show_only_added: show_only_added.to_string().parse().unwrap_or(false),
        rows,
    }
}

pub fn apply_profile_folder_state_to_items(
    items: &[ProfileDisplayItem],
    folder_state: Option<&Value>,
) -> Vec<ProfileDisplayItem> {
    let Some(folder_state) = folder_state else {
        return items.to_vec();
    };
    if !folder_state.is_object() {
        return items.to_vec();
    }
    let tuples: Vec<(String, String, Vec<String>, i64, i64, String)> = items
        .iter()
        .map(|item| {
            (
                item.persistent_key.clone(),
                item.display_name.clone(),
                item.match_lines.clone(),
                item.source_order,
                if item.source_order != 0 {
                    item.source_order
                } else {
                    item.profile_index
                },
                item.profile_name.clone(),
            )
        })
        .collect();
    let view = crate::folder_ordering::resolve_profile_order_view_from(&tuples, folder_state);
    let rank_of = |key: &str| -> i64 {
        view.folder_keys
            .iter()
            .position(|some| some == key)
            .map(|position| position as i64)
            .unwrap_or(10_000)
    };
    let mut next_items: Vec<ProfileDisplayItem> = Vec::new();
    for item in items {
        let persistent_key = item.persistent_key.clone();
        let folder_key = view
            .folder_by_item
            .iter()
            .find(|(item_key, _)| *item_key == persistent_key)
            .map(|(_, folder)| folder.clone())
            .unwrap_or_else(|| {
                if item.group.is_empty() {
                    "common".to_string()
                } else {
                    item.group.clone()
                }
            });
        let group_name = view
            .folder_names
            .iter()
            .find(|(some, _)| *some == folder_key)
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| {
                if item.group_name.is_empty() {
                    "Общие".to_string()
                } else {
                    item.group_name.clone()
                }
            });
        let order = view
            .position_by_item
            .iter()
            .find(|(some, _)| *some == persistent_key)
            .map(|(_, position)| *position as i64)
            .unwrap_or(item.order);
        let mut next_item = item.clone();
        next_item.group = folder_key.clone();
        next_item.group_name = group_name;
        next_item.order = order;
        next_item.group_rank = rank_of(&folder_key);
        next_item.group_collapsed = view
            .collapsed
            .iter()
            .find(|(some, _)| *some == folder_key)
            .map(|(_, value)| *value)
            .unwrap_or(false);
        next_items.push(next_item);
    }
    sort_display_items(&mut next_items);
    next_items
}

/// python moved_profile_display_items: оптимистичный показ перемещения.
pub fn moved_profile_display_items(
    items: &[ProfileDisplayItem],
    source_profile_key: &str,
    destination_kind: &str,
    destination_profile_key: &str,
    destination_group_key: &str,
    folder_state: Option<&Value>,
) -> Option<Vec<ProfileDisplayItem>> {
    let action = match destination_kind.trim() {
        "profile" => "before",
        "profile_after" => "after",
        "end" => "end",
        "folder" => "folder",
        _ => return None,
    };
    let mut by_key: HashMap<String, ProfileDisplayItem> = HashMap::new();
    let mut grouped: Vec<(String, Vec<&ProfileDisplayItem>)> = Vec::new();
    for item in items {
        let key = item.key.clone();
        if key.is_empty() {
            continue;
        }
        by_key.insert(key, item.clone());
        let group_key = if item.group.is_empty() {
            "common".to_string()
        } else {
            item.group.clone()
        };
        match grouped.iter_mut().find(|(key, _)| *key == group_key) {
            Some((_, group)) => group.push(item),
            None => grouped.push((group_key, vec![item])),
        }
    }
    let mut folder_names: Vec<(String, String)> = Vec::new();
    let mut collapsed: Vec<(String, bool)> = Vec::new();
    let mut rank_by_folder: Vec<(String, i64)> = Vec::new();
    let mut items_by_folder: Vec<(String, Vec<String>)> = Vec::new();
    let mut folder_by_item: Vec<(String, String)> = Vec::new();
    for (group_key, group_items) in &grouped {
        let mut ordered: Vec<String> = group_items.iter().map(|item| item.key.clone()).collect();
        // python sorted(key=profile_display_sort_key) — стабильная.
        let mut sorted_items: Vec<&ProfileDisplayItem> = group_items.clone();
        sorted_items.sort_by(|a, b| profile_display_sort_key(a).cmp(&profile_display_sort_key(b)));
        ordered = sorted_items.iter().map(|item| item.key.clone()).collect();
        items_by_folder.push((group_key.clone(), ordered.clone()));
        for key in &ordered {
            folder_by_item.push((key.clone(), group_key.clone()));
        }
        if let Some(first) = group_items.first() {
            folder_names.push((group_key.clone(), first.group_name.clone()));
            collapsed.push((group_key.clone(), first.group_collapsed));
        }
        let rank = group_items
            .iter()
            .map(|item| item_group_rank(item))
            .min()
            .unwrap_or(10_000);
        rank_by_folder.push((group_key.clone(), rank));
    }
    // python: подмешивание state-папок с сохранением настроек.
    if let Some(folder_state) = folder_state {
        if let Some(state_folders) = folder_state.get("folders").and_then(Value::as_object) {
            let mut keys: Vec<String> = state_folders.keys().cloned().collect();
            let mut state_keys: Vec<String> = keys.clone();
            state_keys.sort_by(|a, b| {
                let order_for = |key: &str| -> i64 {
                    state_folders
                        .get(key)
                        .and_then(|folder| folder.get("order"))
                        .and_then(Value::as_i64)
                        .unwrap_or(10_000)
                };
                let name_for = |key: &str| -> String {
                    state_folders
                        .get(key)
                        .and_then(|folder| folder.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or(key)
                        .to_lowercase()
                };
                order_for(a)
                    .cmp(&order_for(b))
                    .then(name_for(a).cmp(&name_for(b)))
                    .then(a.cmp(b))
            });
            for (rank, some_key) in state_keys.iter().enumerate() {
                let folder = state_folders.get(some_key).cloned().unwrap_or(json!({}));
                let name = folder
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(some_key)
                    .to_string();
                let is_collapsed = folder
                    .get("collapsed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !folder_names.iter().any(|(key, _)| *key == *some_key) {
                    folder_names.push((some_key.clone(), name));
                }
                if !collapsed.iter().any(|(key, _)| *key == *some_key) {
                    collapsed.push((some_key.clone(), is_collapsed));
                }
                if !rank_by_folder.iter().any(|(key, _)| *key == *some_key) {
                    rank_by_folder.push((some_key.clone(), rank as i64));
                }
                if !items_by_folder.iter().any(|(key, _)| *key == *some_key) {
                    items_by_folder.push((some_key.clone(), Vec::new()));
                }
            }
        }
    }

    let mut folder_keys: Vec<String> = items_by_folder.iter().map(|(key, _)| key.clone()).collect();
    folder_keys.sort_by(|a, b| {
        let rank = |key: &str| -> i64 {
            rank_by_folder
                .iter()
                .find(|(some, _)| *some == key)
                .map(|(_, rank)| *rank)
                .unwrap_or(10_000)
        };
        (rank(a), a.to_lowercase()).cmp(&(rank(b), b.to_lowercase()))
    });
    let view = crate::folder_ordering::FolderOrderView {
        folder_keys,
        folder_names,
        collapsed,
        items_by_folder,
        folder_by_item,
        position_by_item: Vec::new(),
    };
    let (target_folder, sequence) = plan_view_move(
        &view,
        action,
        source_profile_key.trim(),
        destination_profile_key.trim(),
        destination_group_key.trim(),
    )?;
    let target_name = view
        .folder_names
        .iter()
        .find(|(key, _)| *key == target_folder)
        .map(|(_, name)| name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| group_name_for_key(&target_folder, items));
    let target_rank = view
        .folder_names
        .iter()
        .find(|(key, _)| *key == target_folder)
        .and_then(|(_, _)| rank_of(&view, &target_folder))
        .unwrap_or(10_000);
    let target_collapsed = view
        .collapsed
        .iter()
        .find(|(some, _)| *some == target_folder)
        .map(|(_, value)| *value)
        .unwrap_or(false);
    let mut position_by_key: HashMap<String, usize> = HashMap::new();
    for (index, key) in sequence.iter().enumerate() {
        position_by_key.insert(key.clone(), index);
    }
    let mut next_items: Vec<ProfileDisplayItem> = Vec::new();
    for item in items {
        let key = item.key.clone();
        if let Some(position) = position_by_key.get(&key) {
            let mut next = item.clone();
            next.group = target_folder.clone();
            next.group_name = target_name.clone();
            next.order = *position as i64;
            next.group_rank = target_rank;
            next.group_collapsed = target_collapsed;
            next_items.push(next);
        } else {
            next_items.push(item.clone());
        }
    }
    Some(next_items)
}

fn rank_of(view: &crate::folder_ordering::FolderOrderView, key: &str) -> Option<i64> {
    view.folder_keys
        .iter()
        .position(|some| some == key)
        .map(|position| position as i64)
}
