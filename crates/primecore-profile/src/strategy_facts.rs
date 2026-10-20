//! Порт profile/strategy_list/facts.py: всё о стратегии каталога в одной строке.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::strategy_catalog::StrategyEntry;
use crate::strategy_families::strategy_family_keys;
use crate::strategy_shape::{payload_badge_accessible_text, payload_badge_text};
use crate::strategy_visuals::{strategy_plain_label, StrategyVisual};

pub const NAME_DETAIL_SEPARATOR: &str = " · ";
const SOURCE_PREFIX: &str = "из ";
/// Описания-заглушки из каталога человеку ничего не говорят.
const PLACEHOLDER_DESCRIPTIONS: [&str; 2] = ["автодобавлено", "потом опишу"];
const BUILTIN_AUTHOR: &str = "builtin";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyFacts {
    pub strategy_id: String,
    pub name: String,
    /// Название без уточнения и уточнение («из Steam»).
    pub title: String,
    pub detail: String,
    /// Первое слово названия («General») и источник уточнения («Steam»).
    pub series: String,
    pub source: String,
    /// Группа по способу обхода (strategy_families).
    pub family_key: String,
    /// Способ простыми словами и именами функций winws2.
    pub plain_label: String,
    pub technical_label: String,
    pub technique_description: String,
    pub args: String,
    pub old_name: String,
    /// Пометка каталога: recommended, stock, experimental, caution, game, stable.
    pub label: String,
    pub author: String,
    pub description: String,
    /// Типы пакетов веток составной стратегии; пусто — обычная.
    pub payload_badge: String,
    pub payload_badge_accessible: String,
    /// Всё, по чему стратегию находит поиск, одной строкой в нижнем регистре.
    pub search_text: String,
}

/// Название стратегии и уточнение после « · ».
pub fn split_strategy_name(name: &str) -> (String, String) {
    let clean = name.trim().to_string();
    match clean.split_once(NAME_DETAIL_SEPARATOR) {
        Some((base, detail)) if !base.trim().is_empty() => {
            (base.trim().to_string(), detail.trim().to_string())
        }
        _ => (clean, String::new()),
    }
}

pub fn strategy_series(name: &str) -> String {
    let (base, _) = split_strategy_name(name);
    match base.split_whitespace().next() {
        Some(word) => word.trim_end_matches([':', ',']).to_string(),
        None => String::new(),
    }
}

/// Откуда взята стратегия: «Steam» из уточнения «из Steam».
pub fn strategy_source(name: &str) -> String {
    let (_, detail) = split_strategy_name(name);
    for part in detail.split(NAME_DETAIL_SEPARATOR) {
        let part = part.trim();
        if part.starts_with(SOURCE_PREFIX) {
            return part[SOURCE_PREFIX.len()..].trim().to_string();
        }
    }
    String::new()
}

fn useful_description(description: &str) -> String {
    let text = description.trim().to_string();
    if PLACEHOLDER_DESCRIPTIONS
        .iter()
        .any(|placeholder| text.to_lowercase().starts_with(placeholder))
    {
        return String::new();
    }
    text
}

/// Сведения о каждой стратегии каталога: {id → StrategyFacts}, порядок каталога.
pub fn build_strategy_facts(
    entries: impl IntoIterator<Item = (String, StrategyEntry)>,
) -> Vec<(String, StrategyFacts)> {
    let entries: Vec<(String, StrategyEntry)> = entries.into_iter().collect();
    let family_of: HashMap<String, String> = strategy_family_keys(entries.iter().cloned())
        .into_iter()
        .collect();
    let mut facts: Vec<(String, StrategyFacts)> = Vec::new();
    for (raw_id, entry) in entries {
        let strategy_id = raw_id.trim().to_string();
        let name = if entry.name.is_empty() {
            strategy_id.clone()
        } else {
            entry.name.clone()
        };
        let args = entry.args.clone();
        let StrategyVisual {
            technique_keys,
            label: technical_label,
            description: technique_description,
            ..
        } = entry.visual.clone();
        let plain_label = strategy_plain_label(&technique_keys, &technical_label);
        let (title, detail) = split_strategy_name(&name);
        let old_name = entry.old_name.trim().to_string();
        let mut author = entry.author.trim().to_string();
        if author.eq_ignore_ascii_case(BUILTIN_AUTHOR) {
            author = String::new();
        }
        let description = useful_description(&entry.description);
        let payload_badge = payload_badge_text(&entry.payload_scopes);
        let label = entry.label.trim().to_lowercase();
        let search_text = [
            name.as_str(),
            old_name.as_str(),
            args.as_str(),
            technical_label.as_str(),
            technique_description.as_str(),
            plain_label.as_str(),
            description.as_str(),
            author.as_str(),
        ]
        .join(" ")
        .to_lowercase();
        facts.push((
            raw_id.clone(),
            StrategyFacts {
                strategy_id,
                name: name.clone(),
                title,
                detail,
                series: strategy_series(&name),
                source: strategy_source(&name),
                family_key: family_of
                    .get(&raw_id)
                    .cloned()
                    .unwrap_or_else(|| "other".to_string()),
                plain_label,
                technical_label,
                technique_description,
                args,
                old_name,
                label,
                author,
                description,
                payload_badge: payload_badge.clone(),
                payload_badge_accessible: payload_badge_accessible_text(&payload_badge),
                search_text,
            },
        ));
    }
    facts
}
