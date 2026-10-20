//! Порт profile/derived_cache.py: контентно-производные данные профиля
//! (стратегия, вид списка, подпись фильтров) и их LRU-кэш.

use std::path::Path;
use std::time::{Instant, UNIX_EPOCH};

use crate::editable_settings::{read_editable_profile_settings, EditableProfileSettings};
use crate::filter_switch::resolve_filter_kind_switch;
use crate::list_interpreter::{build_profile_list_sources, ProfileListSource};
use crate::match_filters::{
    ports_label_from_match_lines, protocol_label_from_match_lines,
    strategy_catalog_from_match_lines,
};
use crate::models::{Preset, Profile, Strategy, ENGINE_WINWS2};
use crate::strategy_catalog::StrategyEntry;
use crate::strategy_shape::{composite_identity, strategy_shape};

pub const PROFILE_DERIVED_CACHE_LIMIT: usize = 512;
pub const CUSTOM_STRATEGY_NAME: &str = "Своя стратегия";

/// python ProfileDerivedCore: ядро, считанное из текста профиля и каталогов.
#[derive(Debug, Clone)]
pub struct ProfileDerivedCore {
    /// Записи каталога, подходящие профилю (python dict: порядок вставки).
    pub strategy_entries: Vec<StrategyEntry>,
    pub strategy_id: String,
    pub strategy_name: String,
    /// Типы пакетов веток составной стратегии профиля (пусто — обычная).
    pub strategy_payload_scopes: Vec<String>,
    pub list_type: String,
    pub match_summary: String,
    pub raw_profile_text: String,
    pub editable: EditableProfileSettings,
    pub editable_filter_kinds: Vec<String>,
}

/// Каталоги стратегий (python dict[str, dict[str, StrategyEntry]]):
/// пары (имя каталога, записи) в порядке вставки.
pub type CatalogMap = [(String, Vec<StrategyEntry>)];

fn profile_strategy_lines(profile: &Profile) -> Vec<String> {
    match &profile.strategy {
        Some(Strategy::Winws1(inner)) => inner.strategy_lines.clone(),
        Some(Strategy::Winws2(inner)) => inner.strategy_lines.clone(),
        None => Vec::new(),
    }
}

/// python build_profile_derived_core.
pub fn build_profile_derived_core(
    profile: &Profile,
    catalogs: &CatalogMap,
    user_root: &Path,
    raw_profile_text: Option<&str>,
) -> ProfileDerivedCore {
    let raw_text = match raw_profile_text {
        Some(text) => text.to_string(),
        None => profile_raw_text(profile),
    };
    let strategy_entries = basic_strategy_entries(profile, catalogs);
    let (strategy_id, strategy_name) = resolve_strategy(profile, &strategy_entries);
    let editable = read_editable_profile_settings(profile);
    // Проверки файлов hostlist/ipset — единственный диск в ядре; считаем один раз
    // и переиспользуем для list_type и editable_filter_kinds.
    let filter_kinds = available_filter_kinds(&editable, user_root);
    let list_type = visible_list_type_for_kinds(profile, &filter_kinds);
    let match_summary = profile_match_summary(profile, Some(&list_type));
    ProfileDerivedCore {
        strategy_entries,
        strategy_id,
        strategy_name,
        strategy_payload_scopes: profile_strategy_payload_scopes(profile),
        list_type,
        match_summary,
        raw_profile_text: raw_text,
        editable,
        editable_filter_kinds: filter_kinds,
    }
}

/// python ProfileDerivedCache: LRU контентных ядер (не потокобезопасен,
/// вызывающий держит свой лок).
pub struct ProfileDerivedCache {
    entries: std::collections::HashMap<ProfileDerivedKey, ProfileDerivedCore>,
    order: Vec<ProfileDerivedKey>,
    limit: usize,
    lists_signature_value: String,
    lists_signature_at: Option<Instant>,
}

impl Default for ProfileDerivedCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileDerivedCache {
    pub fn new() -> Self {
        Self::with_limit(PROFILE_DERIVED_CACHE_LIMIT)
    }

    pub fn with_limit(limit: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            order: Vec::new(),
            limit: limit.max(1),
            lists_signature_value: String::new(),
            lists_signature_at: None,
        }
    }

    pub fn forget_lists_signature(&mut self) {
        self.lists_signature_at = None;
    }

    /// Отпечаток папки lists и её подпапок: mtime меняется при создании и
    /// удалении файла списка. Запоминается на полсекунды — сборка списка
    /// из сотни профилей не должна опрашивать диск сотню раз.
    fn lists_signature(&mut self, user_root: &Path) -> String {
        if let Some(at) = self.lists_signature_at {
            if at.elapsed() < std::time::Duration::from_millis(500) {
                return self.lists_signature_value.clone();
            }
        }
        let lists_root = user_root.join("lists");
        let mut signature: Vec<String> = Vec::new();
        match dir_mtime_nanos(&lists_root) {
            Some(mtime) => signature.push(format!("root:{mtime}")),
            None => signature.push("root:".to_string()),
        }
        if let Ok(entries) = std::fs::read_dir(&lists_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let mtime = dir_mtime_nanos(&path).unwrap_or_default();
                    signature.push(format!("{name}:{mtime}"));
                }
            }
        }
        signature.sort();
        self.lists_signature_value = signature.join("|");
        self.lists_signature_at = Some(Instant::now());
        self.lists_signature_value.clone()
    }

    pub fn core_for(
        &mut self,
        profile: &Profile,
        catalogs: &CatalogMap,
        catalogs_signature: &str,
        user_root: &Path,
    ) -> ProfileDerivedCore {
        let raw_text = profile_raw_text(profile);
        // Имя профиля не входит в raw_text (оно в «--new=Имя»), а от него
        // зависит роль «исключения»; доступность hostlist/ipset зависит от
        // файлов списков на диске. Без них ядро оставалось бы устаревшим.
        let key = ProfileDerivedKey {
            engine: profile.engine.clone(),
            catalogs_signature: catalogs_signature.to_string(),
            raw_text,
            name: profile.name.clone(),
            display_name: profile.display_name.clone(),
            lists_signature: self.lists_signature(user_root),
        };
        if let Some(cached) = self.entries.get(&key) {
            let cached = cached.clone();
            self.touch(&key);
            return cached;
        }
        let core = build_profile_derived_core(profile, catalogs, user_root, Some(&key.raw_text));
        self.entries.insert(key.clone(), core.clone());
        self.order.push(key);
        while self.order.len() > self.limit {
            let oldest = self.order.remove(0);
            self.entries.remove(&oldest);
        }
        core
    }

    /// python move_to_end: свежее использованное ядро дольше живёт в кэше.
    fn touch(&mut self, key: &ProfileDerivedKey) {
        if let Some(position) = self.order.iter().position(|cached| cached == key) {
            let item = self.order.remove(position);
            self.order.push(item);
        }
    }
}

fn dir_mtime_nanos(path: &Path) -> Option<u128> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    modified
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProfileDerivedKey {
    engine: String,
    catalogs_signature: String,
    raw_text: String,
    name: String,
    display_name: String,
    lists_signature: String,
}

/// python PresetSourcesCache: sources пресета, посчитанные один раз
/// на (ревизию, объект пресета, объект шаблонов).
///
/// Идентичность объектов — как в python (`is`): адрес объекта как `usize`.
/// Риски совпадут: адрес после free может переиспользоваться.
pub struct PresetSourcesCache {
    entry: Option<(PresetSourcesKey, Vec<ProfileListSource>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PresetSourcesKey {
    revision: (usize, usize),
    preset: usize,
    templates: usize,
}

impl Default for PresetSourcesCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PresetSourcesCache {
    pub fn new() -> Self {
        Self { entry: None }
    }

    /// python preset_revision — кортеж (mtime, size); структура caller-а,
    /// здесь приходит уже посчитанной парой.
    pub fn sources_for(
        &mut self,
        preset_revision: (usize, usize),
        preset: &Preset,
        templates: &[(String, Profile)],
    ) -> Vec<ProfileListSource> {
        let key = PresetSourcesKey {
            revision: preset_revision,
            preset: preset as *const Preset as usize,
            templates: templates.as_ptr() as usize,
        };
        if let Some((cached, sources)) = &self.entry {
            if *cached == key {
                return sources.clone();
            }
        }
        let sources = build_profile_list_sources(&preset.profiles, templates);
        self.entry = Some((key, sources.clone()));
        sources
    }

    pub fn clear(&mut self) {
        self.entry = None;
    }
}

/// python basic_strategy_entries.
pub fn basic_strategy_entries(profile: &Profile, catalogs: &CatalogMap) -> Vec<StrategyEntry> {
    if profile_list_type(profile) == "custom" {
        return Vec::new();
    }
    let name = catalog_name_for_profile(profile);
    catalogs
        .iter()
        .find(|(catalog_name, _)| *catalog_name == name)
        .map(|(_name, entries)| entries.clone())
        .unwrap_or_default()
}

/// python resolve_strategy.
pub fn resolve_strategy(profile: &Profile, entries: &[StrategyEntry]) -> (String, String) {
    let lines = profile_strategy_lines(profile);
    resolve_strategy_lines(profile, entries, &lines)
}

/// Identity-строки записи каталога (python _entry_identity_lines).
pub fn entry_identity_lines(engine: &str, args: &str) -> Vec<String> {
    let normalized = normalize_lines(args.lines());
    if engine != ENGINE_WINWS2 {
        return normalized;
    }
    normalized
        .into_iter()
        .filter(|line| line.to_lowercase().starts_with("--lua-desync="))
        .collect()
}

/// Отпечаток составной записи каталога (python _entry_composite_identity).
pub fn entry_composite_identity(args: &str) -> Vec<(String, String)> {
    composite_identity(&strategy_shape(&lines_of(args)).body_lines)
}

/// python resolve_strategy_lines: готовая стратегия, которой равны строки
/// стратегии profile-а.
///
/// winws2: составная стратегия profile-а (несколько веток ``--payload``)
/// сравнивается целиком только с составными записями каталога, обычная — по
/// строкам ``--lua-desync`` только с обычными записями
/// (см. ``profile.strategy_shape``).
pub fn resolve_strategy_lines(
    profile: &Profile,
    entries: &[StrategyEntry],
    lines: &[String],
) -> (String, String) {
    let matches: Vec<&StrategyEntry>;
    if profile.engine != ENGINE_WINWS2 {
        let current = normalize_lines(lines.iter().cloned());
        if current.is_empty() {
            return ("none".to_string(), "Стратегия не выбрана".to_string());
        }
        matches = entries
            .iter()
            .filter(|entry| entry_identity_lines(&profile.engine, &entry.args) == current)
            .collect();
    } else {
        let shape = strategy_shape(lines);
        if shape.lua_lines().is_empty() {
            return ("none".to_string(), "Стратегия не выбрана".to_string());
        }
        if shape.composite {
            let current_composite = composite_identity(&shape.body_lines);
            matches = entries
                .iter()
                .filter(|entry| {
                    entry.is_composite && entry_composite_identity(&entry.args) == current_composite
                })
                .collect();
        } else {
            let current = shape.lua_lines();
            matches = entries
                .iter()
                .filter(|entry| {
                    !entry.is_composite
                        && entry_identity_lines(&profile.engine, &entry.args) == current
                })
                .collect();
        }
    }
    if matches.len() == 1 {
        return (matches[0].strategy_id.clone(), matches[0].name.clone());
    }
    ("custom".to_string(), CUSTOM_STRATEGY_NAME.to_string())
}

/// python profile_strategy_shape: форма стратегии profile-а winws2 по порядку
/// строк в пресете.
pub fn profile_strategy_shape(profile: &Profile) -> crate::strategy_shape::StrategyShape {
    let lines = profile_strategy_lines(profile);
    strategy_shape(&lines)
}

/// python profile_strategy_payload_scopes.
pub fn profile_strategy_payload_scopes(profile: &Profile) -> Vec<String> {
    if profile.engine != ENGINE_WINWS2 {
        return Vec::new();
    }
    let shape = profile_strategy_shape(profile);
    if shape.composite {
        shape.payload_scopes
    } else {
        Vec::new()
    }
}

/// python normalize_lines.
pub fn normalize_lines<L: AsRef<str>>(lines: impl IntoIterator<Item = L>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| line.as_ref().trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn lines_of(args: &str) -> Vec<String> {
    args.lines().map(str::to_string).collect()
}

/// python strategy_identity_lines.
pub fn strategy_identity_lines(profile: &Profile, lines: &[String]) -> Vec<String> {
    let normalized = normalize_lines(lines.iter().cloned());
    if profile.engine != ENGINE_WINWS2 {
        return normalized;
    }
    normalized
        .into_iter()
        .filter(|line| line.to_lowercase().starts_with("--lua-desync="))
        .collect()
}

/// python catalog_name_for_profile.
pub fn catalog_name_for_profile(profile: &Profile) -> String {
    strategy_catalog_from_match_lines(&profile.match_section().all_lines())
}

/// python profile_list_type.
pub fn profile_list_type(profile: &Profile) -> String {
    let catalog_name = catalog_name_for_profile(profile);
    if catalog_name == "voice" {
        return "voice".to_string();
    }
    let match_section = profile.match_section();
    let has_hostlist = !match_section.hostlist_lines.is_empty()
        || !match_section.hostlist_domains_lines.is_empty();
    let has_ipset =
        !match_section.ipset_lines.is_empty() || !match_section.inline_ipset_lines.is_empty();
    let has_excludes = !match_section.hostlist_exclude_lines.is_empty()
        || !match_section.ipset_exclude_lines.is_empty();
    if has_excludes {
        let settings = read_editable_profile_settings(profile);
        if settings.filter_role == "exclude"
            && !has_hostlist
            && !has_ipset
            && (settings.filter_kind == "hostlist" || settings.filter_kind == "ipset")
        {
            return settings.filter_kind.clone();
        }
        return "custom".to_string();
    }
    if has_hostlist && has_ipset {
        return "custom".to_string();
    }
    if has_hostlist {
        return "hostlist".to_string();
    }
    if has_ipset {
        return "ipset".to_string();
    }
    catalog_name
}

/// python visible_list_type.
pub fn visible_list_type(profile: &Profile, user_root: &Path) -> String {
    let settings = read_editable_profile_settings(profile);
    let filter_kinds = available_filter_kinds(&settings, user_root);
    visible_list_type_for_kinds(profile, &filter_kinds)
}

fn visible_list_type_for_kinds(profile: &Profile, filter_kinds: &[String]) -> String {
    let list_type = profile_list_type(profile);
    if list_type != "hostlist" && list_type != "ipset" {
        return String::new();
    }
    let available = filter_kinds
        .iter()
        .filter(|kind| kind.as_str() == "hostlist" || kind.as_str() == "ipset")
        .count();
    if available <= 1 {
        return String::new();
    }
    list_type
}

/// python profile_has_filter_choice.
pub fn profile_has_filter_choice(profile: &Profile, user_root: &Path) -> bool {
    let settings = read_editable_profile_settings(profile);
    if !settings.filter_editable {
        return false;
    }
    available_filter_kinds(&settings, user_root)
        .iter()
        .filter(|kind| kind.as_str() == "hostlist" || kind.as_str() == "ipset")
        .count()
        > 1
}

/// python profile_match_summary.
pub fn profile_match_summary(profile: &Profile, list_type: Option<&str>) -> String {
    let match_lines = profile.match_section().all_lines();
    let visible = match list_type {
        Some(value) => value.to_string(),
        None => profile_list_type(profile),
    };
    let mut parts: Vec<String> = Vec::new();
    for candidate in [
        protocol_label_from_match_lines(&match_lines),
        ports_label_from_match_lines(&match_lines),
        visible,
    ] {
        if !candidate.is_empty() {
            parts.push(candidate);
        }
    }
    if parts.is_empty() {
        return "без явных условий".to_string();
    }
    parts.join(" • ")
}

/// python available_filter_kinds.
pub fn available_filter_kinds(settings: &EditableProfileSettings, user_root: &Path) -> Vec<String> {
    let current_kind = settings.filter_kind.trim().to_lowercase();
    let current_kind = if current_kind.is_empty() {
        "hostlist".to_string()
    } else {
        current_kind
    };
    if !settings.filter_editable || (current_kind != "hostlist" && current_kind != "ipset") {
        return vec![current_kind];
    }

    let mut result: Vec<String> = Vec::new();
    for candidate in ["hostlist", "ipset"] {
        if resolve_filter_kind_switch(settings, candidate, user_root).allowed {
            result.push(candidate.to_string());
        }
    }
    if result.is_empty() {
        vec![current_kind]
    } else {
        result
    }
}

/// python profile_raw_text.
pub fn profile_raw_text(profile: &Profile) -> String {
    let lines: Vec<&str> = profile
        .segments
        .iter()
        .map(|segment| segment.text.as_str())
        .filter(|text| !text.trim().is_empty())
        .collect();
    lines.join("\n").trim().to_string()
}
