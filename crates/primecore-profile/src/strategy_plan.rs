//! Порт profile/strategy_list/plan.py: раскладка списка готовых стратегий.

use std::collections::HashMap;

use crate::sha1::digest_prefix;
use serde::{Deserialize, Serialize};

pub const GROUPING_METHOD: &str = "method";
pub const GROUPING_SERIES: &str = "series";
pub const GROUPING_SOURCE: &str = "source";

/// Порядок кортежа — порядок пунктов в переключателе над списком.
pub const STRATEGY_GROUPINGS: [(&str, &str); 3] = [
    (GROUPING_METHOD, "По способу обхода"),
    (GROUPING_SERIES, "По серии"),
    (GROUPING_SOURCE, "По источнику"),
];

pub const FILTER_ALL: &str = "all";
pub const FILTER_RECOMMENDED: &str = "recommended";
pub const FILTER_WORKS: &str = "works";
pub const FILTER_FAVORITE: &str = "favorite";

/// Вкладки над списком; порядок кортежа — порядок вкладок.
pub const QUICK_FILTERS: [(&str, &str); 4] = [
    (FILTER_RECOMMENDED, "Советуемые"),
    (FILTER_WORKS, "Работают у меня"),
    (FILTER_FAVORITE, "Избранное"),
    (FILTER_ALL, "Все"),
];

pub const BADGE_NEUTRAL: &str = "neutral";
pub const BADGE_WARNING: &str = "warning";
pub const BADGE_PERSONAL: &str = "personal";

/// Стратегии из готовых пресетов этого же сервиса идут отдельной группой
/// только на вкладке «Советуемые».
pub const RECOMMENDED_GROUP: &str = "recommended";
pub const SERIES_OTHER: &str = "s_other";
pub const SOURCE_NONE: &str = "o_none";
pub const NEUTRAL_COLOR: &str = "#9aa6b2";

pub fn grouping_keys_allowed(value: &str) -> bool {
    STRATEGY_GROUPINGS
        .iter()
        .any(|(key, _title)| key.eq_ignore_ascii_case(value))
}

pub fn normalize_strategy_grouping(value: Option<&str>) -> String {
    let text = value.unwrap_or("").trim().to_lowercase();
    if grouping_keys_allowed(&text) {
        return text;
    }
    GROUPING_METHOD.to_string()
}

pub fn filter_keys_allowed(value: &str) -> bool {
    QUICK_FILTERS
        .iter()
        .any(|(key, _title)| key.eq_ignore_ascii_case(value))
}

pub fn normalize_quick_filter(value: Option<&str>) -> String {
    let text = value.unwrap_or("").trim().to_lowercase();
    if filter_keys_allowed(&text) {
        return text;
    }
    FILTER_ALL.to_string()
}

// ------------------------------------------------------------- usage и входные данные

/// python StrategyUsage (profile.strategy_usage): где стоит стратегия.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyUsage {
    #[serde(default)]
    pub same_service: i64,
    #[serde(default)]
    pub services: i64,
}

impl StrategyUsage {
    pub fn recommended(&self) -> bool {
        self.same_service > 0
    }
}

pub const NO_USAGE: StrategyUsage = StrategyUsage {
    same_service: 0,
    services: 0,
};

impl Default for StrategyUsage {
    fn default() -> Self {
        NO_USAGE
    }
}

/// python PlanRequest: всё, от чего раскладка зависит.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanRequest {
    pub facts: Vec<(String, crate::strategy_facts::StrategyFacts)>,
    #[serde(default)]
    pub states: HashMap<String, crate::strategy_state::ProfileStrategyState>,
    #[serde(default)]
    pub usage: HashMap<String, StrategyUsage>,
    /// Отметки человека у других профилей.
    #[serde(default)]
    pub experience: HashMap<String, (i64, i64)>,
    #[serde(default = "default_current_strategy")]
    pub current_strategy_id: String,
    #[serde(default)]
    pub query: String,
    #[serde(default = "default_filter_all")]
    pub quick_filter: String,
    #[serde(default = "default_grouping_method")]
    pub grouping: String,
}

fn default_current_strategy() -> String {
    "none".to_string()
}

fn default_filter_all() -> String {
    FILTER_ALL.to_string()
}

fn default_grouping_method() -> String {
    GROUPING_METHOD.to_string()
}

impl Default for PlanRequest {
    fn default() -> Self {
        Self {
            facts: Vec::new(),
            states: HashMap::new(),
            usage: HashMap::new(),
            experience: HashMap::new(),
            current_strategy_id: "none".to_string(),
            query: String::new(),
            quick_filter: FILTER_ALL.to_string(),
            grouping: GROUPING_METHOD.to_string(),
        }
    }
}

// ------------------------------------------------------------- плитка и группы

/// python StrategyItem: одна плитка списка.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StrategyItem {
    pub strategy_id: String,
    pub name: String,
    pub title: String,
    pub detail: String,
    pub plain_label: String,
    /// Вторая строка плитки: уточнение, способ словами и где стоит в пресетах.
    pub caption: String,
    pub badge_text: String,
    pub badge_tone: String,
    pub payload_badge: String,
    pub rating: String,
    pub favorite: bool,
    pub is_current: bool,
    pub tooltip: String,
    pub accessible_text: String,
    /// Ключ группы способа и её цвет.
    pub family_key: String,
    pub family_color: String,
    /// Общий ключ для строк с одним названием.
    pub twin_key: String,
}

/// python StrategySection: подзаголовок внутри группы.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategySection {
    pub key: String,
    pub title: String,
    pub items: Vec<StrategyItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyGroup {
    pub key: String,
    pub title: String,
    pub description: String,
    pub icon_name: String,
    pub color: String,
    pub sections: Vec<StrategySection>,
}

impl StrategyGroup {
    pub fn count(&self) -> usize {
        self.sections
            .iter()
            .map(|section| section.items.len())
            .sum()
    }

    pub fn items(&self) -> Vec<&StrategyItem> {
        self.sections
            .iter()
            .flat_map(|section| section.items.iter())
            .collect()
    }

    /// Название выбранной стратегии, если она в этой группе.
    pub fn current_name(&self) -> String {
        self.items()
            .iter()
            .find_map(|item| item.is_current.then(|| item.name.clone()))
            .unwrap_or_default()
    }
}

/// python StrategyListPlan: раскладка целиком.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyListPlan {
    pub groups: Vec<StrategyGroup>,
    pub total_count: usize,
    pub visible_count: usize,
    pub current_strategy_id: String,
    pub grouping: String,
    /// Список сужен поиском или вкладкой.
    pub narrowed: bool,
    pub narrowed_by_query: bool,
    /// Очередь «что пробовать» — весь каталог.
    pub queue: Vec<String>,
    pub recommended_count: usize,
    /// Сколько стратегий каталога на каждой вкладке.
    pub tab_counts: Vec<(String, usize)>,
}

impl Default for StrategyListPlan {
    fn default() -> Self {
        StrategyListPlan {
            groups: Vec::new(),
            total_count: 0,
            visible_count: 0,
            current_strategy_id: "none".to_string(),
            grouping: GROUPING_METHOD.to_string(),
            narrowed: false,
            narrowed_by_query: false,
            queue: Vec::new(),
            recommended_count: 0,
            tab_counts: Vec::new(),
        }
    }
}

impl StrategyListPlan {
    pub fn tab_count(&self, quick_filter: &str) -> usize {
        self.tab_counts
            .iter()
            .find(|(key, _count)| key == quick_filter)
            .map(|(_key, count)| *count)
            .unwrap_or(0)
    }

    pub fn group_of(&self, strategy_id: &str) -> String {
        for group in &self.groups {
            if group
                .items()
                .iter()
                .any(|item| item.strategy_id == strategy_id)
            {
                return group.key.clone();
            }
        }
        String::new()
    }

    pub fn item(&self, strategy_id: &str) -> Option<StrategyItem> {
        for group in &self.groups {
            for item in group.items() {
                if item.strategy_id == strategy_id {
                    return Some(item.clone());
                }
            }
        }
        None
    }
}

pub const NAME_SEPARATOR: &str = " · ";

fn plural(count: i64, one: &str, few: &str, many: &str) -> String {
    let count = count.max(0);
    if count % 10 == 1 && count % 100 != 11 {
        return one.to_string();
    }
    if matches!(count % 10, 2 | 3 | 4) && !matches!(count % 100, 12 | 13 | 14) {
        return few.to_string();
    }
    many.to_string()
}

fn experience_pair(experience: &HashMap<String, (i64, i64)>, strategy_id: &str) -> (i64, i64) {
    let (works, fails) = experience.get(strategy_id).copied().unwrap_or((0, 0));
    (works.max(0), fails.max(0))
}

/// Метка справа на плитке: (текст, тон). Пусто — метки нет.
pub fn strategy_badge(
    usage: &StrategyUsage,
    label: &str,
    personal: (i64, i64),
) -> (String, String) {
    let (works, fails) = personal;
    if works > 0 && works >= fails {
        return (
            format!("у вас работает · {works}"),
            BADGE_PERSONAL.to_string(),
        );
    }
    let same = usage.same_service;
    let services = usage.services;
    if same > 0 {
        return (String::new(), String::new());
    }
    if label == "caution" {
        return ("осторожно".to_string(), BADGE_WARNING.to_string());
    }
    if label == "experimental" && services < 2 {
        return ("опытная".to_string(), BADGE_NEUTRAL.to_string());
    }
    (String::new(), String::new())
}

/// Подпись под названием: где стратегия стоит в готовых пресетах.
pub fn usage_caption(usage: &StrategyUsage) -> String {
    let same = usage.same_service;
    let services = usage.services;
    if same > 0 {
        return format!(
            "на этом сервисе в {same} {}",
            plural(same, "пресете", "пресетах", "пресетах")
        );
    }
    if services >= 2 {
        return format!(
            "на {services} {}",
            plural(services, "сервисе", "сервисах", "сервисах")
        );
    }
    String::new()
}

/// Фраза для подсказки: отметки на других профилях.
pub fn experience_sentence(personal: (i64, i64)) -> String {
    let (works, fails) = personal;
    let mut parts: Vec<String> = Vec::new();
    if works > 0 {
        parts.push(format!(
            "Вы отметили её рабочей на {works} {}.",
            plural(
                works,
                "другом профиле",
                "других профилях",
                "других профилях"
            )
        ));
    }
    if fails > 0 {
        parts.push(format!(
            "Нерабочей — на {fails} {}.",
            plural(fails, "профиле", "профилях", "профилях")
        ));
    }
    parts.join(" ")
}

/// Фраза для подсказки: где стратегия стоит в готовых пресетах.
pub fn usage_sentence(usage: &StrategyUsage) -> String {
    let same = usage.same_service;
    let services = usage.services;
    let mut parts: Vec<String> = Vec::new();
    if same > 0 {
        let word = plural(
            same,
            "готовом пресете",
            "готовых пресетах",
            "готовых пресетах",
        );
        parts.push(format!("Стоит на этом сервисе в {same} {word}."));
    }
    let others = services - if same > 0 { 1 } else { 0 };
    if others > 0 {
        let word = plural(others, "сервисе", "сервисах", "сервисах");
        parts.push(format!(
            "В готовых пресетах встречается ещё на {others} {word}."
        ));
    }
    parts.join(" ")
}

const RATING_RANK_WORK: i64 = 0;
const RATING_RANK_EMPTY: i64 = 1;
const RATING_RANK_NOT_WORK: i64 = 2;

fn rating_rank(rating: &str) -> i64 {
    match rating {
        "work" => RATING_RANK_WORK,
        "" => RATING_RANK_EMPTY,
        "notwork" => RATING_RANK_NOT_WORK,
        _ => RATING_RANK_EMPTY,
    }
}

fn priority(
    facts: &crate::strategy_facts::StrategyFacts,
    state: Option<&crate::strategy_state::ProfileStrategyState>,
    usage: &StrategyUsage,
    personal: (i64, i64),
) -> (i64, bool, i64, i64, i64, String) {
    let (works, fails) = personal;
    (
        rating_rank(state.map(|state| state.rating.as_str()).unwrap_or("")),
        !state.map(|state| state.favorite).unwrap_or(false),
        fails - works,
        -(usage.same_service as i64),
        -(usage.services as i64),
        facts.name.to_lowercase(),
    )
}

/// Лежит ли стратегия на вкладке.
fn on_tab(
    quick_filter: &str,
    state: Option<&crate::strategy_state::ProfileStrategyState>,
    recommended: bool,
) -> bool {
    if quick_filter == FILTER_RECOMMENDED {
        return recommended;
    }
    if quick_filter == FILTER_WORKS {
        return state.map(|state| state.rating.as_str()) == Some("work");
    }
    if quick_filter == FILTER_FAVORITE {
        return state.map(|state| state.favorite).unwrap_or(false);
    }
    true
}

/// python _GroupInfo: заголовок группы и её порядок.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub key: String,
    pub title: String,
    pub description: String,
    pub icon_name: String,
    pub color: String,
    pub rank: Vec<RankPart>,
}

/// Часть кортежа-порядка python: число или строка.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RankPart {
    Number(i64),
    Text(String),
}

/// python: сравнение кортежей разной длины, () меньше любого.
fn compare_parts(left: &[RankPart], right: &[RankPart]) -> std::cmp::Ordering {
    for (left_part, right_part) in left.iter().zip(right.iter()) {
        let order = std::cmp::Ord::cmp(left_part, right_part);
        if order != std::cmp::Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

fn group_info(
    key: &str,
    title: &str,
    description: &str,
    icon_name: &str,
    color: &str,
    rank: Vec<RankPart>,
) -> GroupInfo {
    GroupInfo {
        key: key.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        icon_name: icon_name.to_string(),
        color: color.to_string(),
        rank,
    }
}

/// python _named_groups: группы по значению из названия (серия, источник).
fn named_groups(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    value_of: impl Fn(&crate::strategy_facts::StrategyFacts) -> String,
    prefix: &str,
    min_size: usize,
    other_key: &str,
    other_title: &str,
    other_description: &str,
    icon_name: &str,
) -> (HashMap<String, String>, HashMap<String, GroupInfo>) {
    let values: HashMap<String, String> = order
        .iter()
        .filter_map(|strategy_id| {
            facts
                .get(strategy_id)
                .map(|facts_item| (strategy_id.clone(), value_of(facts_item)))
        })
        .collect();
    let mut sizes: HashMap<String, usize> = HashMap::new();
    for value in values.values() {
        *sizes.entry(value.to_lowercase()).or_insert(0) += 1;
    }
    let mut group_of: HashMap<String, String> = HashMap::new();
    let mut titles: Vec<(String, String)> = Vec::new();
    let mut counts: HashMap<String, i64> = HashMap::new();
    for (strategy_id, value) in &values {
        let key = if value.is_empty() || sizes[value.to_lowercase().as_str()] < min_size {
            let normalized_key = other_key.to_string();
            if !titles.iter().any(|(known, _)| known == &normalized_key) {
                titles.push((normalized_key.clone(), other_title.to_string()));
            }
            normalized_key
        } else {
            let key = digest_prefix(prefix, value);
            if !titles.iter().any(|(known, _)| known == &key) {
                titles.push((key.clone(), value.clone()));
            }
            key
        };
        group_of.insert(strategy_id.clone(), key.clone());
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut infos: HashMap<String, GroupInfo> = HashMap::new();
    for (key, title) in titles {
        let is_other = key == other_key;
        let count = counts.get(&key).copied().unwrap_or(0);
        let rank = vec![
            RankPart::Number(if is_other { 1 } else { 0 }),
            RankPart::Number(-count),
            RankPart::Text(title.to_lowercase()),
        ];
        infos.insert(
            key.clone(),
            group_info(
                &key,
                &title,
                if is_other { other_description } else { "" },
                if is_other {
                    "fa5s.ellipsis-h"
                } else {
                    icon_name
                },
                NEUTRAL_COLOR,
                rank,
            ),
        );
    }
    (group_of, infos)
}

fn series_title(facts: &crate::strategy_facts::StrategyFacts) -> String {
    facts.series.clone()
}

fn source_title(facts: &crate::strategy_facts::StrategyFacts) -> String {
    strip_source_number(&facts.source)
}

fn strip_source_number(source: &str) -> String {
    static SOURCE_NUMBER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SOURCE_NUMBER
        .get_or_init(|| regex::Regex::new(r"\s*№\s*\d+$").expect("regex"))
        .replace(source, "")
        .into_owned()
}

// ------------------------------------------------------------- раскладка

/// python _RECOMMENDED_INFO.
fn recommended_info() -> GroupInfo {
    group_info(
        RECOMMENDED_GROUP,
        "Советуем для этого сервиса",
        "стоят на нём в готовых пресетах: чем чаще, тем выше",
        "fa5s.thumbs-up",
        "#e5b454",
        Vec::new(),
    )
}

/// Под каким подзаголовком стратегия стоит внутри своей группы.
fn section_title(facts: &crate::strategy_facts::StrategyFacts, grouping: &str) -> String {
    if grouping == GROUPING_SERIES {
        return crate::strategy_families::strategy_family(&facts.family_key)
            .title
            .to_string();
    }
    facts.series.clone()
}

fn tooltip(
    facts: &crate::strategy_facts::StrategyFacts,
    usage: &StrategyUsage,
    personal: (i64, i64),
) -> String {
    let mut parts: Vec<String> = vec![
        facts.description.clone(),
        facts.technique_description.clone(),
        experience_sentence(personal),
        usage_sentence(usage),
        if facts.author.is_empty() {
            String::new()
        } else {
            format!("Автор: {}", facts.author)
        },
        if facts.old_name.is_empty() {
            String::new()
        } else {
            format!("Раньше называлась: {}", facts.old_name)
        },
        facts.args.clone(),
    ];
    parts.retain(|part| !part.is_empty());
    parts.join("\n\n")
}

fn status_words(
    state: Option<&crate::strategy_state::ProfileStrategyState>,
    is_current: bool,
) -> Vec<String> {
    let mut words = vec![if is_current {
        "Выбрана".to_string()
    } else {
        "Не выбрана".to_string()
    }];
    if state.map(|state| state.favorite).unwrap_or(false) {
        words.push("В избранном".to_string());
    }
    match state.map(|state| state.rating.as_str()).unwrap_or("") {
        "work" => words.push("Работает".to_string()),
        "notwork" => words.push("Не работает".to_string()),
        _ => {}
    }
    words
}

fn accessible_text(
    facts: &crate::strategy_facts::StrategyFacts,
    state: Option<&crate::strategy_state::ProfileStrategyState>,
    is_current: bool,
    badge_text: &str,
    usage_text: &str,
) -> String {
    let mut parts: Vec<String> = vec![facts.name.clone()];
    parts.extend(
        status_words(state, is_current)
            .into_iter()
            .map(|word| word.to_lowercase()),
    );
    if !facts.plain_label.is_empty() {
        parts.push(format!("способ: {}", facts.plain_label));
    }
    if !usage_text.is_empty() {
        parts.push(usage_text.to_string());
    }
    if !badge_text.is_empty() {
        parts.push(badge_text.to_string());
    }
    if !facts.payload_badge_accessible.is_empty() {
        parts.push(facts.payload_badge_accessible.clone());
    }
    parts.join(", ")
}

#[allow(clippy::too_many_arguments)]
fn make_item(
    facts: &crate::strategy_facts::StrategyFacts,
    state: Option<&crate::strategy_state::ProfileStrategyState>,
    usage: &StrategyUsage,
    is_current: bool,
    detail: &str,
    personal: (i64, i64),
    show_method: bool,
) -> StrategyItem {
    let (badge_text, badge_tone) = strategy_badge(usage, &facts.label, personal);
    let usage_text = usage_caption(usage);
    let caption_parts: Vec<String> = [
        Some(detail.to_string()),
        show_method.then(|| facts.plain_label.clone()),
        (!usage_text.is_empty()).then_some(usage_text.clone()),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect();
    let state_ref = state.map(|state| state.clone());
    StrategyItem {
        strategy_id: facts.strategy_id.clone(),
        name: facts.name.clone(),
        title: facts.title.clone(),
        detail: detail.to_string(),
        plain_label: facts.plain_label.clone(),
        caption: caption_parts.join(NAME_SEPARATOR),
        badge_text,
        badge_tone,
        payload_badge: facts.payload_badge.clone(),
        rating: state_ref
            .as_ref()
            .map(|state| state.rating.clone())
            .unwrap_or_default(),
        favorite: state_ref
            .as_ref()
            .map(|state| state.favorite)
            .unwrap_or(false),
        is_current,
        tooltip: tooltip(facts, usage, personal),
        accessible_text: accessible_text(
            facts,
            state,
            is_current,
            strategy_badge(usage, &facts.label, personal).0.as_str(),
            usage_text.as_str(),
        ),
        family_key: facts.family_key.clone(),
        family_color: crate::strategy_families::strategy_family(&facts.family_key)
            .color
            .to_string(),
        twin_key: String::new(),
    }
}

/// Стратегии с одним названием — один ключ, ставятся рядом.
fn with_twins(group_key: &str, section_key: &str, items: &[StrategyItem]) -> Vec<StrategyItem> {
    let mut by_title: Vec<(String, Vec<&StrategyItem>)> = Vec::new();
    for item in items {
        let title = item.title.to_lowercase();
        match by_title.iter_mut().find(|(known, _)| known == &title) {
            Some((_, list)) => list.push(item),
            None => by_title.push((title, vec![item])),
        }
    }
    let mut ordered: Vec<StrategyItem> = Vec::new();
    let mut placed: Vec<String> = Vec::new();
    for item in items {
        let title = item.title.to_lowercase();
        if placed.contains(&title) {
            continue;
        }
        placed.push(title.clone());
        let twins = by_title
            .iter()
            .find(|(known, _)| known == &title)
            .map(|(_title, list)| list.iter().map(|item| (*item).clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        if twins.len() < 2 {
            ordered.push(item.clone());
            continue;
        }
        let twin_key = format!("{group_key}/{section_key}/{title}");
        for twin in twins {
            let mut twin = twin.clone();
            twin.twin_key = twin_key.clone();
            ordered.push(twin);
        }
    }
    ordered
}

/// Очередь «что пробовать»: советуемые для сервиса, самые частые первыми.
pub fn recommended_queue(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    usage: &HashMap<String, StrategyUsage>,
) -> Vec<String> {
    let mut recommended: Vec<String> = order
        .iter()
        .filter(|strategy_id| facts.contains_key(*strategy_id))
        .filter(|strategy_id| {
            usage
                .get(*strategy_id)
                .map(StrategyUsage::recommended)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    recommended.sort_by(|left, right| {
        let left_usage = usage.get(left).copied().unwrap_or(NO_USAGE);
        let right_usage = usage.get(right).copied().unwrap_or(NO_USAGE);
        (-left_usage.same_service, -left_usage.services)
            .cmp(&(-right_usage.same_service, -right_usage.services))
            .then_with(|| {
                facts[left]
                    .name
                    .to_lowercase()
                    .cmp(&facts[right].name.to_lowercase())
            })
    });
    recommended
}

/// Оценка способов обхода: «работает» минус «не работает».
pub fn family_scores(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    states: &HashMap<String, crate::strategy_state::ProfileStrategyState>,
    experience: &HashMap<String, (i64, i64)>,
) -> HashMap<String, i64> {
    let mut scores: HashMap<String, i64> = HashMap::new();
    for strategy_id in order {
        let Some(item) = facts.get(strategy_id) else {
            continue;
        };
        let (mut works, mut fails) = experience_pair(experience, strategy_id);
        let rating = states
            .get(strategy_id)
            .map(|state| state.rating.as_str())
            .unwrap_or("");
        if rating == "work" {
            works += 1;
        } else if rating == "notwork" {
            fails += 1;
        }
        if works != 0 || fails != 0 {
            *scores.entry(item.family_key.clone()).or_insert(0) += works - fails;
        }
    }
    scores
}

/// python full_queue: очередь перебора по всему каталогу с учётом опыта.
pub fn full_queue(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    usage: &HashMap<String, StrategyUsage>,
    recommended: &[String],
    experience: &HashMap<String, (i64, i64)>,
    states: &HashMap<String, crate::strategy_state::ProfileStrategyState>,
) -> Vec<String> {
    let scores = family_scores(facts, order, states, experience);
    let queue = catalog_queue(facts, order, usage, recommended, &scores);
    let proven: Vec<String> = queue
        .iter()
        .filter(|strategy_id| {
            let (works, fails) = experience_pair(experience, strategy_id);
            works > 0 && works >= fails
        })
        .cloned()
        .collect();
    let mut sorted_proven = proven.clone();
    sorted_proven.sort_by(|left, right| {
        let (left_works, left_fails) = experience_pair(experience, left);
        let (right_works, right_fails) = experience_pair(experience, right);
        (-left_works, left_fails).cmp(&(-right_works, right_fails))
    });
    let doubtful: Vec<String> = queue
        .iter()
        .filter(|strategy_id| {
            let (_works, fails) = experience_pair(experience, strategy_id);
            !sorted_proven.contains(strategy_id) && fails > 0
        })
        .cloned()
        .collect();
    let mut sorted_doubtful = doubtful;
    sorted_doubtful.sort_by(|left, right| {
        let (_left_works, left_fails) = experience_pair(experience, left);
        let (_right_works, right_fails) = experience_pair(experience, right);
        left_fails.cmp(&right_fails)
    });
    let usual: Vec<String> = queue
        .iter()
        .filter(|strategy_id| {
            !sorted_proven.contains(strategy_id) && !sorted_doubtful.contains(strategy_id)
        })
        .cloned()
        .collect();
    [sorted_proven, usual, sorted_doubtful].concat()
}

const NOT_FOR_QUEUE: [&str; 1] = ["pass"];

#[allow(clippy::too_many_arguments)]
fn catalog_queue(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    usage: &HashMap<String, StrategyUsage>,
    recommended: &[String],
    scores: &HashMap<String, i64>,
) -> Vec<String> {
    let rest: Vec<String> = order
        .iter()
        .filter(|strategy_id| facts.contains_key(*strategy_id))
        .filter(|strategy_id| {
            !recommended.contains(strategy_id) && !NOT_FOR_QUEUE.contains(&strategy_id.as_str())
        })
        .cloned()
        .collect();
    let mut used: Vec<String> = rest
        .iter()
        .filter(|strategy_id| {
            usage
                .get(*strategy_id)
                .map(|usage| usage.services > 0)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    used.sort_by(|left, right| {
        let left_services = usage.get(left).map(|usage| usage.services).unwrap_or(0);
        let right_services = usage.get(right).map(|usage| usage.services).unwrap_or(0);
        (-left_services).cmp(&(-right_services)).then_with(|| {
            facts[left]
                .name
                .to_lowercase()
                .cmp(&facts[right].name.to_lowercase())
        })
    });
    let not_used: Vec<String> = rest
        .iter()
        .filter(|strategy_id| !used.contains(strategy_id))
        .cloned()
        .collect();
    let not_used: Vec<String> = {
        let mut ordered = not_used;
        ordered.sort_by(|left, right| {
            facts[left]
                .name
                .to_lowercase()
                .cmp(&facts[right].name.to_lowercase())
        });
        ordered
    };
    let mut by_family: Vec<(String, Vec<String>)> = Vec::new();
    for strategy_id in &not_used {
        let Some(item) = facts.get(strategy_id) else {
            continue;
        };
        match by_family
            .iter_mut()
            .find(|(known, _)| known == &item.family_key)
        {
            Some((_key, list)) => list.push(strategy_id.clone()),
            None => by_family.push((item.family_key.clone(), vec![strategy_id.clone()])),
        }
    }
    let mut ranked: Vec<(String, Vec<String>)> = by_family;
    ranked.sort_by(|(left_key, _), (right_key, _)| {
        let left_score = scores.get(left_key).copied().unwrap_or(0);
        let right_score = scores.get(right_key).copied().unwrap_or(0);
        (-left_score).cmp(&(-right_score)).then_with(|| {
            let left_rank = crate::strategy_families::strategy_family_rank(left_key);
            let right_rank = crate::strategy_families::strategy_family_rank(right_key);
            left_rank.cmp(&right_rank)
        })
    });
    // python: queues — list списков; круг: каждый непустой способ отдаёт верх.
    let mut queues: Vec<Vec<String>> = ranked.into_iter().map(|(_key, list)| list).collect();
    let mut mixed: Vec<String> = Vec::new();
    while queues.iter().any(|queue| !queue.is_empty()) {
        queues = queues
            .iter()
            .filter(|queue| !queue.is_empty())
            .cloned()
            .collect();
        let mut next_round: Vec<Vec<String>> = Vec::new();
        for queue in queues.iter() {
            if let Some(first) = queue.first().cloned() {
                mixed.push(first);
                next_round.push(queue[1..].to_vec());
            }
        }
        queues = next_round;
    }
    [recommended.to_vec(), used, mixed].concat()
}

#[allow(clippy::type_complexity)]
fn groups_for(
    facts: &HashMap<String, crate::strategy_facts::StrategyFacts>,
    order: &[String],
    grouping: &str,
) -> (HashMap<String, String>, HashMap<String, GroupInfo>) {
    if grouping == GROUPING_SERIES {
        return named_groups(
            facts,
            order,
            series_title,
            "s",
            MIN_SERIES_GROUP,
            SERIES_OTHER,
            "Остальные серии",
            "серии из одной-двух стратегий",
            "fa5s.tag",
        );
    }
    if grouping == GROUPING_SOURCE {
        return named_groups(
            facts,
            order,
            source_title,
            "o",
            MIN_SOURCE_GROUP,
            SOURCE_NONE,
            "Без источника",
            "в названии источник не указан",
            "fa5s.share-square",
        );
    }
    let mut infos: HashMap<String, GroupInfo> = HashMap::new();
    for (rank, known) in crate::strategy_families::STRATEGY_FAMILIES
        .iter()
        .enumerate()
    {
        infos.insert(
            known.key.to_string(),
            group_info(
                known.key,
                known.title,
                &format!("способ обхода: {}", known.description),
                known.icon_name,
                known.color,
                vec![RankPart::Number(rank as i64)],
            ),
        );
    }
    let group_of: HashMap<String, String> = order
        .iter()
        .filter_map(|strategy_id| {
            facts
                .get(strategy_id)
                .map(|facts_item| (strategy_id.clone(), facts_item.family_key.clone()))
        })
        .collect();
    (group_of, infos)
}

const MIN_SERIES_GROUP: usize = 3;
const MIN_SOURCE_GROUP: usize = 2;
const MIN_SECTION: usize = 2;
/// В маленькой группе подзаголовки только мешают.
const MIN_GROUP_FOR_SECTIONS: usize = 9;

/// python build_plan: раскладка списка готовых стратегий.
pub fn build_plan(request: &PlanRequest) -> StrategyListPlan {
    let facts: HashMap<String, crate::strategy_facts::StrategyFacts> = request
        .facts
        .iter()
        .map(|(strategy_id, item)| (strategy_id.clone(), item.clone()))
        .collect();
    let order: Vec<String> = request.facts.iter().map(|(key, _)| key.clone()).collect();
    let states: HashMap<String, crate::strategy_state::ProfileStrategyState> =
        request.states.clone();
    let usage: HashMap<String, StrategyUsage> = request.usage.clone();
    let experience: HashMap<String, (i64, i64)> = request.experience.clone();
    let grouping = normalize_strategy_grouping(Some(&request.grouping));
    let quick_filter = normalize_quick_filter(Some(&request.quick_filter));
    let query = request.query.trim().to_lowercase();
    let current_id = {
        let clean = request.current_strategy_id.trim().to_string();
        if clean.is_empty() {
            "none".to_string()
        } else {
            clean
        }
    };
    let narrowed = !query.is_empty() || quick_filter != FILTER_ALL;

    let (mut group_of, mut infos) = groups_for(&facts, &order, &grouping);
    let mut recommended = recommended_queue(&facts, &order, &usage);
    if recommended.is_empty() || recommended.len() >= order.len() {
        recommended = Vec::new();
    }
    if quick_filter == FILTER_RECOMMENDED {
        for strategy_id in &recommended {
            group_of.insert(strategy_id.clone(), RECOMMENDED_GROUP.to_string());
        }
        if !recommended.is_empty() {
            infos.insert(RECOMMENDED_GROUP.to_string(), recommended_info());
        }
    }
    let recommended_set = recommended.clone();
    let tab_counts: Vec<(String, usize)> = QUICK_FILTERS
        .iter()
        .map(|(key, _)| {
            (
                key.to_string(),
                order
                    .iter()
                    .filter(|strategy_id| {
                        on_tab(
                            key,
                            states.get(*strategy_id),
                            recommended_set.contains(*strategy_id),
                        )
                    })
                    .count(),
            )
        })
        .collect();
    let queue = full_queue(
        &facts,
        &order,
        &usage,
        &recommended_set,
        &experience,
        &states,
    );

    let mut members: Vec<(String, Vec<String>)> = Vec::new();
    for strategy_id in &order {
        let Some(group_key) = group_of.get(strategy_id) else {
            continue;
        };
        match members.iter_mut().find(|(known, _)| known == group_key) {
            Some((_, list)) => list.push(strategy_id.clone()),
            None => members.push((group_key.clone(), vec![strategy_id.clone()])),
        }
    }

    let mut groups: Vec<StrategyGroup> = Vec::new();
    let mut visible_count: usize = 0;
    let mut member_keys: Vec<String> = members.iter().map(|(key, _list)| key.clone()).collect();
    member_keys.sort_by(|left_key, right_key| {
        let left_recommended = left_key == RECOMMENDED_GROUP;
        let right_recommended = right_key == RECOMMENDED_GROUP;
        (!left_recommended)
            .cmp(&(!right_recommended))
            .then_with(|| compare_parts(&infos[left_key].rank, &infos[right_key].rank))
    });
    // python sort стабильна: порядок вставки сохраняется для равных ключей.

    for group_key in &member_keys {
        let Some(info) = infos.get(group_key) else {
            continue;
        };
        let Some((_mkey, ids)) = members.iter().find(|(known, _)| known == group_key) else {
            continue;
        };
        let section_names: Vec<(String, String)> = ids
            .iter()
            .filter_map(|strategy_id| facts.get(strategy_id))
            .map(|facts_item| {
                (
                    facts_item.strategy_id.clone(),
                    section_title(facts_item, &grouping),
                )
            })
            .collect();
        let mut titles: HashMap<String, String> = HashMap::new();
        for (strategy_id, title) in &section_names {
            titles.insert(strategy_id.clone(), title.clone());
        }
        let mut sizes: HashMap<String, usize> = HashMap::new();
        for (_, title) in &section_names {
            *sizes.entry(title.to_lowercase()).or_insert(0) += 1;
        }
        let mut section_of: HashMap<String, (String, String)> = HashMap::new();
        let mut section_counts: HashMap<String, usize> = HashMap::new();
        for strategy_id in ids {
            let title = titles[strategy_id].clone();
            let section =
                if !title.is_empty() && sizes[title.to_lowercase().as_str()] >= MIN_SECTION {
                    (
                        format!("{group_key}/{}", title.to_lowercase()),
                        title.clone(),
                    )
                } else {
                    (format!("{group_key}/"), "Остальные".to_string())
                };
            section_of.insert(strategy_id.clone(), section.clone());
            *section_counts.entry(section.0).or_insert(0) += 1;
        }
        let sectioned = !narrowed
            && group_key != RECOMMENDED_GROUP
            && members.len() > 1
            && ids.len() >= MIN_GROUP_FOR_SECTIONS
            && section_counts.len() > 1;

        let shown: Vec<String> = ids
            .iter()
            .filter(|strategy_id| {
                let Some(item) = facts.get(*strategy_id) else {
                    return false;
                };
                (query.is_empty() || item.search_text.contains(query.as_str()))
                    && on_tab(
                        &quick_filter,
                        states.get(*strategy_id),
                        recommended_set.contains(*strategy_id),
                    )
            })
            .cloned()
            .collect();
        if shown.is_empty() {
            continue;
        }
        let mut sorted_shown = shown.clone();
        sorted_shown.sort_by(|left, right| {
            priority(
                &facts[left],
                states.get(left),
                &usage.get(left).copied().unwrap_or(NO_USAGE),
                experience_pair(&experience, left),
            )
            .cmp(&priority(
                &facts[right],
                states.get(right),
                &usage.get(right).copied().unwrap_or(NO_USAGE),
                experience_pair(&experience, right),
            ))
        });
        visible_count += sorted_shown.len();

        let mut by_section: Vec<(String, Vec<StrategyItem>)> = Vec::new();
        let mut section_titles: HashMap<String, String> = HashMap::new();
        for strategy_id in &sorted_shown {
            let item_facts = facts.get(strategy_id).expect("факты показанных");
            let mut detail = item_facts.detail.clone();
            if grouping == GROUPING_SOURCE
                && group_key != SOURCE_NONE
                && group_key != RECOMMENDED_GROUP
            {
                detail = detail
                    .split(NAME_SEPARATOR)
                    .filter(|part| !part.is_empty() && !part.starts_with("из "))
                    .collect::<Vec<&str>>()
                    .join(NAME_SEPARATOR);
            }
            let item_usage = usage.get(strategy_id).copied().unwrap_or(NO_USAGE);
            let item = make_item(
                item_facts,
                states.get(strategy_id),
                &item_usage,
                strategy_id == &current_id,
                &detail,
                experience_pair(&experience, strategy_id),
                !(grouping == GROUPING_METHOD && group_key != RECOMMENDED_GROUP),
            );
            let (key, title) = if sectioned {
                section_of[strategy_id].clone()
            } else {
                (String::new(), String::new())
            };
            match by_section.iter_mut().find(|(known, _)| known == &key) {
                Some((_known, list)) => list.push(item.clone()),
                None => by_section.push((key.clone(), vec![item.clone()])),
            }
            section_titles.insert(key.clone(), title.clone());
        }

        let mut section_order: Vec<String> =
            by_section.iter().map(|(key, _)| key.clone()).collect();
        section_order.sort_by(|left_key, right_key| {
            let left_other = left_key.as_str() == format!("{group_key}/").as_str();
            let right_other = right_key.as_str() == format!("{group_key}/").as_str();
            left_other
                .cmp(&right_other)
                .then_with(|| {
                    let left_count = section_counts.get(left_key).copied().unwrap_or(0);
                    let right_count = section_counts.get(right_key).copied().unwrap_or(0);
                    (-(left_count as i64)).cmp(&(-(right_count as i64)))
                })
                .then_with(|| {
                    section_titles[left_key]
                        .to_lowercase()
                        .cmp(&section_titles[right_key].to_lowercase())
                })
        });

        let sections: Vec<StrategySection> = section_order
            .iter()
            .map(|key| {
                let items = by_section
                    .iter()
                    .find(|(known, _)| known == key)
                    .map(|(_k, list)| list.clone())
                    .unwrap_or_default();
                StrategySection {
                    key: key.clone(),
                    title: section_titles[key].clone(),
                    items: if !query.is_empty() {
                        items
                    } else {
                        with_twins(group_key, key, &items)
                    },
                }
            })
            .collect();
        groups.push(StrategyGroup {
            key: info.key.clone(),
            title: info.title.clone(),
            description: info.description.clone(),
            icon_name: info.icon_name.clone(),
            color: info.color.clone(),
            sections,
        });
    }

    StrategyListPlan {
        groups,
        total_count: order.len(),
        visible_count,
        current_strategy_id: current_id,
        grouping,
        narrowed,
        narrowed_by_query: !query.is_empty(),
        queue,
        recommended_count: recommended_set.len(),
        tab_counts,
    }
}

/// Следующая стратегия очереди, которую человек ещё не оценил.
pub fn next_to_try(
    queue: &[String],
    states: &HashMap<String, crate::strategy_state::ProfileStrategyState>,
    current_strategy_id: &str,
) -> String {
    let current = current_strategy_id.to_string();
    for strategy_id in queue {
        if strategy_id == &current {
            continue;
        }
        let rating = states
            .get(strategy_id)
            .map(|state| state.rating.clone())
            .unwrap_or_default();
        if rating.is_empty() {
            return strategy_id.clone();
        }
    }
    String::new()
}

/// Сколько стратегий очереди человек уже оценил: (оценено, всего).
pub fn try_progress(
    queue: &[String],
    states: &HashMap<String, crate::strategy_state::ProfileStrategyState>,
) -> (usize, usize) {
    let tried = queue
        .iter()
        .filter(|strategy_id| {
            states
                .get(*strategy_id)
                .map(|state| !state.rating.is_empty())
                .unwrap_or(false)
        })
        .count();
    (tried, queue.len())
}

/// Где сейчас перебор: (этап, оценено на этапе, всего на этапе).
pub fn try_stage(
    plan: &StrategyListPlan,
    states: &HashMap<String, crate::strategy_state::ProfileStrategyState>,
) -> (String, usize, usize) {
    let recommended = &plan.queue[..plan.recommended_count.min(plan.queue.len())];
    let (tried, total) = try_progress(recommended, states);
    if total > 0 && tried < total {
        return ("recommended".to_string(), tried, total);
    }
    let (tried, total) = try_progress(&plan.queue, states);
    ("all".to_string(), tried, total)
}

// ------------------------------------------------------------- строки списка (python rows.py)

pub const ROW_GROUP: &str = "group";
pub const ROW_SECTION: &str = "section";
pub const ROW_STRATEGY: &str = "strategy";

/// python VisibleRow: одна строка списка.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VisibleRow {
    pub kind: String,
    /// Постоянное имя строки: по нему список понимает, что строка та же самая.
    pub key: String,
    pub group: Option<StrategyGroup>,
    pub section: Option<StrategySection>,
    pub item: Option<StrategyItem>,
    /// У заголовка группы: раскрыта ли она.
    pub expanded: bool,
    /// У первой стратегии набора: сколько вариантов всего (0 — набора нет).
    pub twin_count: usize,
    pub twin_open: bool,
}

impl VisibleRow {
    pub fn strategy_id(&self) -> String {
        self.item
            .as_ref()
            .map(|item| item.strategy_id.clone())
            .unwrap_or_default()
    }

    pub fn group_key(&self) -> String {
        self.group
            .as_ref()
            .map(|group| group.key.clone())
            .unwrap_or_default()
    }

    /// Всё, что строка показывает на экране: по этому список решает,
    /// перерисовывать ли строку.
    pub fn shown(&self) -> Shown {
        match self.kind.as_str() {
            ROW_STRATEGY => Shown::Strategy(self.item.clone(), self.twin_count, self.twin_open),
            ROW_SECTION => Shown::SectionTitle(
                self.section
                    .as_ref()
                    .map(|section| section.title.clone())
                    .unwrap_or_default(),
                self.section
                    .as_ref()
                    .map(|section| section.items.len())
                    .unwrap_or(0),
            ),
            _ => {
                let group = self.group.as_ref().expect("группа");
                Shown::Group(
                    group.title.clone(),
                    group.description.clone(),
                    group.icon_name.clone(),
                    group.color.clone(),
                    group.count(),
                    group.current_name(),
                    self.expanded,
                )
            }
        }
    }

    /// Клавиатура останавливается на строке (подзаголовок — только подпись).
    pub fn selectable(&self) -> bool {
        self.kind != ROW_SECTION
    }
}

/// python-поле shown строки разной природы.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Shown {
    Strategy(Option<StrategyItem>, usize, bool),
    SectionTitle(String, usize),
    Group(String, String, String, String, usize, String, bool),
}

/// python _strategy_rows: строки одной секции с вариантами одного названия.
fn strategy_rows(
    group: &StrategyGroup,
    section: &StrategySection,
    open_twins: &std::collections::HashSet<String>,
) -> Vec<VisibleRow> {
    let mut rows: Vec<VisibleRow> = Vec::new();
    let mut index = 0usize;
    let items = &section.items;
    while index < items.len() {
        let item = items[index].clone();
        if item.twin_key.is_empty() {
            rows.push(VisibleRow {
                kind: ROW_STRATEGY.to_string(),
                key: format!("i:{}", item.strategy_id),
                group: Some(group.clone()),
                section: Some(section.clone()),
                item: Some(item),
                expanded: true,
                twin_count: 0,
                twin_open: false,
            });
            index += 1;
            continue;
        }
        let mut end = index;
        while end < items.len() && items[end].twin_key == item.twin_key {
            end += 1;
        }
        let twins = &items[index..end];
        let is_open = open_twins.contains(&item.twin_key);
        let shown: Vec<StrategyItem> = if is_open {
            twins.to_vec()
        } else {
            let fallback = twins[0].clone();
            vec![twins
                .iter()
                .find(|twin| twin.is_current)
                .cloned()
                .unwrap_or(fallback)]
        };
        for (position, twin) in shown.iter().enumerate() {
            rows.push(VisibleRow {
                kind: ROW_STRATEGY.to_string(),
                key: format!("i:{}", twin.strategy_id),
                group: Some(group.clone()),
                section: Some(section.clone()),
                item: Some(twin.clone()),
                expanded: true,
                twin_count: if position == 0 { twins.len() } else { 0 },
                twin_open: is_open,
            });
        }
        index = end;
    }
    rows
}

/// python visible_rows: строки списка сверху вниз.
pub fn visible_rows(
    plan: &StrategyListPlan,
    open_groups: Option<&std::collections::HashSet<String>>,
    open_twins: &[String],
) -> Vec<VisibleRow> {
    let open_twins: std::collections::HashSet<String> = open_twins.iter().cloned().collect();
    let groups = &plan.groups;
    let with_headers = groups.len() > 1;
    let mut rows: Vec<VisibleRow> = Vec::new();
    for group in groups {
        let mut expanded = true;
        if with_headers {
            expanded = plan.narrowed
                || match open_groups {
                    None => true,
                    Some(open) => open.contains(&group.key),
                };
            rows.push(VisibleRow {
                kind: ROW_GROUP.to_string(),
                key: format!("g:{}", group.key),
                group: Some(group.clone()),
                section: None,
                item: None,
                expanded,
                twin_count: 0,
                twin_open: false,
            });
        }
        if !expanded {
            continue;
        }
        for section in &group.sections {
            if !section.key.is_empty() {
                rows.push(VisibleRow {
                    kind: ROW_SECTION.to_string(),
                    key: format!("s:{}", section.key),
                    group: Some(group.clone()),
                    section: Some(section.clone()),
                    item: None,
                    expanded: true,
                    twin_count: 0,
                    twin_open: false,
                });
            }
            rows.extend(strategy_rows(group, section, &open_twins));
        }
    }
    rows
}

/// python default_open_group: какая группа раскрыта, пока человек не выбрал сам.
pub fn default_open_group(plan: &StrategyListPlan, remembered: Option<&str>) -> String {
    let keys: Vec<String> = plan.groups.iter().map(|group| group.key.clone()).collect();
    if let Some(remembered) = remembered {
        if remembered.is_empty() || keys.iter().any(|key| key == remembered) {
            return remembered.to_string();
        }
    }
    let current_group = plan.group_of(&plan.current_strategy_id);
    if !current_group.is_empty() {
        return current_group;
    }
    keys.first().cloned().unwrap_or_default()
}
