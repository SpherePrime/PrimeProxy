//! Порт profile/strategy_families.py: группы готовых стратегий по способу обхода.

use crate::strategy_visuals::{strategy_technique_keys, StrategyVisual};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyFamily {
    pub key: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub icon_name: &'static str,
    pub color: &'static str,
}

use serde::{Deserialize, Serialize};

/// Порядок кортежа — порядок групп в списке: от простых способов к составным.
pub const STRATEGY_FAMILIES: [StrategyFamily; 9] = [
    family(
        "fake",
        "Подмена пакета",
        "перед настоящими данными уходит поддельный пакет",
        "fa5s.magic",
        "#ff6b6b",
    ),
    family(
        "fake_split",
        "Подмена и разделение",
        "поддельный пакет, затем данные по частям",
        "fa5s.layer-group",
        "#6fb8ff",
    ),
    family(
        "fake_disorder",
        "Подмена и перестановка",
        "поддельный пакет, затем части в другом порядке",
        "fa5s.random",
        "#7fd99a",
    ),
    family(
        "split",
        "Разделение",
        "данные уходят несколькими частями",
        "fa5s.columns",
        "#4cc2ff",
    ),
    family(
        "disorder",
        "Перестановка",
        "части данных уходят в другом порядке",
        "fa5s.random",
        "#58d17a",
    ),
    family(
        "host",
        "По имени сайта",
        "имя сайта режется, между частями ставится поддельное",
        "fa5s.user-secret",
        "#ff8f5a",
    ),
    family(
        "fake_udplen",
        "Подмена и изменение длины",
        "поддельный пакет, а у настоящего меняется длина",
        "fa5s.ruler",
        "#b58cff",
    ),
    family(
        "send",
        "С дополнительной отправкой",
        "перед обходом уходят лишние данные",
        "fa5s.paper-plane",
        "#76d0ff",
    ),
    family(
        "other",
        "Прочие",
        "способ не распознан или встречается редко",
        "fa5s.question",
        "#9aa6b2",
    ),
];

const fn family(
    key: &'static str,
    title: &'static str,
    description: &'static str,
    icon_name: &'static str,
    color: &'static str,
) -> StrategyFamily {
    StrategyFamily {
        key,
        title,
        description,
        icon_name,
        color,
    }
}

fn family_rank_of(key: &str) -> Option<usize> {
    STRATEGY_FAMILIES.iter().position(|known| known.key == key)
}

/// Способ, редко встречающийся в каталоге, своего заголовка не получает.
const MIN_FAMILY_SIZE: usize = 3;

pub fn strategy_family(key: &str) -> StrategyFamily {
    match family_rank_of(key) {
        Some(rank) => STRATEGY_FAMILIES[rank].clone(),
        None => STRATEGY_FAMILIES[STRATEGY_FAMILIES.len() - 1].clone(),
    }
}

pub fn strategy_family_rank(key: &str) -> usize {
    family_rank_of(key).unwrap_or(STRATEGY_FAMILIES.len())
}

/// Группа стратегии по её способам (ключи strategy_visuals) — как в python.
pub fn strategy_family_key(technique_keys: &[String]) -> String {
    const PRELUDE_TECHNIQUES: [&str; 2] = ["send", "syndata"];
    const SPLIT_TECHNIQUES: [&str; 3] = ["split", "multisplit", "tcpseg"];
    const DISORDER_TECHNIQUES: [&str; 2] = ["disorder", "multidisorder"];
    const FAKED_SPLIT_TECHNIQUES: [&str; 2] = ["fakedsplit", "fakemultisplit"];
    const FAKED_DISORDER_TECHNIQUES: [&str; 2] = ["fakeddisorder", "fakemultidisorder"];
    let _ = has_any;

    let has_fake = technique_keys.contains(&"fake".to_string());
    if has_any(&PRELUDE_TECHNIQUES, technique_keys) {
        return "send".to_string();
    }
    if technique_keys.iter().any(|key| key == "hostfakesplit") {
        return "host".to_string();
    }
    for key in technique_keys {
        if PRELUDE_TECHNIQUES.contains(&key.as_str()) || key == "hostfakesplit" {
            continue;
        }
        if PRELUDE_TECHNIQUES.contains(&key.as_str()) {
            return "send".to_string();
        }
        if key == "hostfakesplit" {
            return "host".to_string();
        }
        if FAKED_SPLIT_TECHNIQUES.contains(&key.as_str()) {
            return "fake_split".to_string();
        }
        if FAKED_DISORDER_TECHNIQUES.contains(&key.as_str()) {
            return "fake_disorder".to_string();
        }
        if SPLIT_TECHNIQUES.contains(&key.as_str()) {
            return if has_fake { "fake_split" } else { "split" }.to_string();
        }
        if DISORDER_TECHNIQUES.contains(&key.as_str()) {
            return if has_fake { "fake_disorder" } else { "disorder" }.to_string();
        }
    }
    if has_fake {
        return if technique_keys.iter().any(|key| key == "udplen") {
            "fake_udplen"
        } else {
            "fake"
        }
        .to_string();
    }
    "other".to_string()
}

fn has_any(allowed: &[&str], keys: &[String]) -> bool {
    keys.iter().any(|key| allowed.contains(&key.as_str()))
}

pub fn strategy_family_key_for_entry(entry: &crate::strategy_catalog::StrategyEntry) -> String {
    match &entry.visual {
        StrategyVisual { technique_keys, .. } if !technique_keys.is_empty() => {
            strategy_family_key(technique_keys)
        }
        _ => {
            let keys: Vec<String> = crate::strategy_visuals::strategy_technique_keys(&entry.args);
            strategy_family_key(&keys)
        }
    }
}

/// Группа каждой стратегии каталога: {id → ключ группы}, по всему каталогу.
pub fn strategy_family_keys(
    entries: impl IntoIterator<Item = (String, crate::strategy_catalog::StrategyEntry)>,
) -> Vec<(String, String)> {
    let entries: Vec<(String, crate::strategy_catalog::StrategyEntry)> = entries.into_iter().collect();
    let mut count: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_id, entry) in &entries {
        *count.entry(strategy_family_key_for_entry(entry)).or_insert(0) += 1;
    }
    entries
        .into_iter()
        .map(|(id, entry)| {
            let raw_key = strategy_family_key_for_entry(&entry);
            let size = count.get(&raw_key).copied().unwrap_or(0);
            if size >= MIN_FAMILY_SIZE {
                (id, raw_key)
            } else {
                (id, "other".to_string())
            }
        })
        .collect()
}

pub fn strategy_technique_keys_for_entry(entry: &crate::strategy_catalog::StrategyEntry) -> Vec<String> {
    strategy_technique_keys(&entry.args)
}

pub fn strategy_count_text(count: usize) -> String {
    let count = count as i64;
    let remainder = count % 10;
    let hundred = count % 100;
    if remainder == 1 && hundred != 11 {
        return format!("{count} стратегия");
    }
    if (2..=4).contains(&remainder) && !(12..=14).contains(&hundred) {
        return format!("{count} стратегии");
    }
    format!("{count} стратегий")
}


