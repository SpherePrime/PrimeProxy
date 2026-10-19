//! Порт profile/strategy_visuals.py: способы обхода готовой стратегии.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyTechniqueVisual {
    pub key: String,
    pub label: String,
    pub icon_name: String,
    pub color: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyVisual {
    pub technique_keys: Vec<String>,
    pub icon_name: String,
    pub color: String,
    pub colors: Vec<String>,
    pub label: String,
    pub description: String,
}

fn unknown_technique() -> StrategyTechniqueVisual {
    entry(
        "custom",
        "Своя",
        "fa5s.question",
        "#9aa6b2",
        "готовая стратегия не распознана по --lua-desync",
    )
}

pub const TECHNIQUE_KEYS: &[&str] = &[
    "fake",
    "split",
    "multisplit",
    "disorder",
    "multidisorder",
    "syndata",
    "send",
    "udplen",
    "oob",
    "tcpseg",
    "pass",
    "hostfakesplit",
    "fakedsplit",
    "fakeddisorder",
    "fakemultisplit",
    "fakemultidisorder",
    "drop",
    "wssize",
    "pktmod",
    "tamper",
];

pub fn technique(key: &str) -> StrategyTechniqueVisual {
    match key {
        "fake" => entry("fake", "Fake", "fa5s.magic", "#ff6b6b", "подмена пакета"),
        "split" => entry("split", "Split", "fa5s.cut", "#f59e0b", "разделение данных"),
        "multisplit" => entry(
            "multisplit",
            "MultiSplit",
            "fa5s.columns",
            "#4cc2ff",
            "несколько точек разделения данных",
        ),
        "disorder" => entry(
            "disorder",
            "Disorder",
            "fa5s.random",
            "#58d17a",
            "перестановка частей данных",
        ),
        "multidisorder" => entry(
            "multidisorder",
            "MultiDisorder",
            "fa5s.random",
            "#58d17a",
            "перестановка нескольких частей данных",
        ),
        "syndata" => entry(
            "syndata",
            "Syndata",
            "fa5s.database",
            "#aeb8c5",
            "добавление данных в SYN",
        ),
        "send" => entry(
            "send",
            "Send",
            "fa5s.paper-plane",
            "#76d0ff",
            "дополнительная отправка данных",
        ),
        "udplen" => entry("udplen", "UDPLen", "fa5s.ruler", "#b58cff", "изменение длины UDP-пакета"),
        "oob" => entry(
            "oob",
            "OOB",
            "fa5s.external-link-alt",
            "#ff78b7",
            "отправка out-of-band данных",
        ),
        "tcpseg" => entry("tcpseg", "TCPSeg", "fa5s.code-branch", "#f6c945", "изменение TCP-сегментации"),
        "pass" => entry("pass", "Pass", "fa5s.minus", "#8f9aa6", "строка без активного desync-действия"),
        "hostfakesplit" => entry(
            "hostfakesplit",
            "HostFakeSplit",
            "fa5s.user-secret",
            "#ff8f5a",
            "разделение по имени сайта с поддельным именем между частями",
        ),
        "fakedsplit" => entry(
            "fakedsplit",
            "FakedSplit",
            "fa5s.clone",
            "#ffa94d",
            "разделение данных с поддельными копиями частей",
        ),
        "fakeddisorder" => entry(
            "fakeddisorder",
            "FakedDisorder",
            "fa5s.random",
            "#8bd450",
            "перестановка частей данных с поддельными копиями",
        ),
        "fakemultisplit" => entry(
            "fakemultisplit",
            "FakeMultiSplit",
            "fa5s.layer-group",
            "#6fb8ff",
            "несколько точек разделения с поддельными частями",
        ),
        "fakemultidisorder" => entry(
            "fakemultidisorder",
            "FakeMultiDisorder",
            "fa5s.random",
            "#7fd99a",
            "перестановка нескольких частей с поддельными частями",
        ),
        "drop" => entry("drop", "Drop", "fa5s.ban", "#e5484d", "отбрасывание пакета"),
        "wssize" => entry(
            "wssize",
            "WSSize",
            "fa5s.compress-arrows-alt",
            "#5eead4",
            "уменьшение TCP-окна, чтобы сервер отвечал мелкими частями",
        ),
        "pktmod" => entry("pktmod", "PktMod", "fa5s.sliders-h", "#c4a7ff", "изменение полей текущего пакета"),
        "tamper" => entry(
            "tamper",
            "Tamper",
            "fa5s.pen",
            "#e0b86b",
            "изменение содержимого пакета без разделения",
        ),
        _ => unknown_technique(),
    }
}

fn entry(key: &str, label: &str, icon: &str, color: &str, description: &str) -> StrategyTechniqueVisual {
    StrategyTechniqueVisual {
        key: key.to_string(),
        label: label.to_string(),
        icon_name: icon.to_string(),
        color: color.to_string(),
        description: description.to_string(),
    }
}

/// Точные имена стандартных функций --lua-desync: проверяются раньше поиска
/// по подстроке (иначе hostfakesplit попадал в Split, fakeddisorder — в MultiDisorder).
fn exact_lua_desync(value: &str) -> Option<&'static str> {
    match value {
        "pass" => Some("pass"),
        "send" => Some("send"),
        "syndata" => Some("syndata"),
        "udplen" => Some("udplen"),
        "oob" => Some("oob"),
        "tcpseg" => Some("tcpseg"),
        "fake" => Some("fake"),
        "multisplit" => Some("multisplit"),
        "multidisorder" => Some("multidisorder"),
        "multidisorder_legacy" => Some("multidisorder"),
        "hostfakesplit" => Some("hostfakesplit"),
        "fakedsplit" => Some("fakedsplit"),
        "fakeddisorder" => Some("fakeddisorder"),
        "fakemultisplit" => Some("fakemultisplit"),
        "fakemultidisorder" => Some("fakemultidisorder"),
        "drop" => Some("drop"),
        "wssize" => Some("wssize"),
        "pktmod" => Some("pktmod"),
        "dht_dn" | "http_domcase" | "http_hostcase" | "http_methodeol" | "http_unixeol" => Some("tamper"),
        _ => None,
    }
}

/// Способ обхода одним-двумя словами: плитка стратегии пишет их под названием.
fn plain_word(key: &str) -> Option<&'static str> {
    match key {
        "fake" => Some("подделка"),
        "split" | "multisplit" | "tcpseg" => Some("нарезка"),
        "disorder" | "multidisorder" => Some("перестановка"),
        "syndata" => Some("данные в первом пакете"),
        "send" => Some("повтор пакета"),
        "udplen" => Some("длина пакета"),
        "oob" => Some("лишний байт"),
        "pass" => Some("без обхода"),
        "hostfakesplit" => Some("подмена имени сайта"),
        "fakedsplit" | "fakemultisplit" => Some("нарезка с подделками"),
        "fakeddisorder" | "fakemultidisorder" => Some("перестановка с подделками"),
        "drop" => Some("сброс пакета"),
        "wssize" => Some("мелкое окно"),
        "pktmod" => Some("правка пакета"),
        "tamper" => Some("правка содержимого"),
        _ => None,
    }
}

pub fn strategy_plain_label(technique_keys: &[String], fallback: &str) -> String {
    let mut words: Vec<&str> = Vec::new();
    for key in technique_keys {
        match plain_word(key) {
            None => return fallback.to_string(),
            Some(word) => {
                if !words.contains(&word) {
                    words.push(word);
                }
            }
        }
    }
    if words.is_empty() {
        fallback.to_string()
    } else {
        words.join(" + ")
    }
}

pub fn describe_strategy_visual(args_text: &str) -> StrategyVisual {
    visual_from_techniques(&extract_techniques(args_text))
}

pub fn strategy_technique_keys(args_text: &str) -> Vec<String> {
    extract_techniques(args_text)
}

fn lua_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?:^|\s)--lua-desync=([a-zA-Z0-9_-]+)").expect("постоянный шаблон"))
}

fn extract_techniques(args_text: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for capture in lua_regex().captures_iter(args_text) {
        let key = map_lua_desync_value(&capture[1]);
        if let Some(key) = key {
            if !result.contains(&key.to_string()) {
                result.push(key.to_string());
            }
        }
    }
    result
}

fn map_lua_desync_value(value: &str) -> Option<&'static str> {
    let raw = value.trim().to_lowercase();
    if raw.is_empty() {
        return None;
    }
    if let Some(exact) = exact_lua_desync(&raw) {
        return Some(exact);
    }
    if raw.starts_with("hostfakesplit") {
        return Some("hostfakesplit");
    }
    if raw.contains("syndata") {
        return Some("syndata");
    }
    if raw.contains("udplen") {
        return Some("udplen");
    }
    if raw.contains("oob") {
        return Some("oob");
    }
    if raw.contains("multidisorder") || raw.contains("fakeddisorder") {
        return Some("multidisorder");
    }
    if raw.contains("disorder") {
        return Some("disorder");
    }
    if raw.contains("multisplit") {
        return Some("multisplit");
    }
    if raw.contains("split") {
        return Some("split");
    }
    if raw.contains("tcpseg") {
        return Some("tcpseg");
    }
    if raw.contains("fake") {
        return Some("fake");
    }
    None
}

fn visual_from_techniques(technique_keys: &[String]) -> StrategyVisual {
    let visuals: Vec<StrategyTechniqueVisual> = technique_keys
        .iter()
        .filter(|key| TECHNIQUE_KEYS.contains(&key.as_str()))
        .map(|key| technique(key))
        .collect();
    if visuals.is_empty() {
        let fallback = unknown_technique();
        return StrategyVisual {
            technique_keys: Vec::new(),
            icon_name: fallback.icon_name.clone(),
            color: fallback.color.clone(),
            colors: vec![fallback.color.clone()],
            label: fallback.label.clone(),
            description: fallback.description.clone(),
        };
    }
    let primary = &visuals[0];
    let labels: Vec<&str> = visuals.iter().map(|visual| visual.label.as_str()).collect();
    let descriptions: Vec<String> = visuals
        .iter()
        .map(|visual| format!("{}: {}", visual.label, visual.description))
        .collect();
    StrategyVisual {
        technique_keys: visuals.iter().map(|visual| visual.key.clone()).collect(),
        icon_name: primary.icon_name.clone(),
        color: primary.color.clone(),
        colors: visuals.iter().map(|visual| visual.color.clone()).collect(),
        label: labels.join(" + "),
        description: descriptions.join("; "),
    }
}
