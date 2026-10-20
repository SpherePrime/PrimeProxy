//! Порт profile/strategy_usage.py: какие готовые стратегии уже стоят
//! в готовых пресетах и как часто.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use primecore_mode::AppPaths;

use crate::derived_cache::normalize_lines;
use crate::derived_cache::{entry_composite_identity, entry_identity_lines};
use crate::match_filters::strategy_catalog_from_match_lines;
use crate::models::{build_profile_logical_key, Profile, Strategy, ENGINE_WINWS2};
use crate::parser::parse_preset_text;
use crate::strategy_catalog::{StrategyEntry, TreeRow};
use crate::strategy_shape::{composite_identity, strategy_shape};

/// Сервис, на котором стратегия стоит в готовых пресетах.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StrategyPlace {
    pub name: String,
    pub presets: i64,
    /// Профиль этого сервиса в открытом пресете; пусто — в нём такого нет.
    pub profile_key: String,
    pub icon_name: String,
    pub icon_color: String,
}

/// Частота готовой стратегии среди готовых пресетов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct StrategyUsage {
    /// В скольких готовых пресетах стратегия стоит на этом же сервисе.
    pub same_service: i64,
    /// На скольких разных сервисах она встречается в готовых пресетах.
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

/// (каталог стратегии, id стратегии).
pub type StrategyKey = (String, String);

/// Итог обхода готовых пресетов одного движка.
///
/// Поля-списки сохраняют порядок вставки python-словарей:
/// by_service — порядок пресетов, services — первой встречи стратегии.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BuiltinStrategyUsage {
    /// {сервис: {(каталог, id стратегии): число пресетов}}
    pub by_service: Vec<(String, Vec<(StrategyKey, i64)>)>,
    /// {(каталог, id стратегии): число разных сервисов}
    pub services: Vec<(StrategyKey, i64)>,
    /// {сервис: его название в готовых пресетах} — для страницы подробностей.
    pub service_names: Vec<(String, String)>,
    /// {сервис: строки условий его профиля} — по ним подбирается значок сервиса.
    pub service_match_lines: Vec<(String, Vec<String>)>,
}

fn dict_get<'a, T>(rows: &'a [(String, T)], key: &str) -> Option<&'a T> {
    rows.iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

fn dict_set(rows: &mut Vec<(String, String)>, key: &str, value: String) {
    if !rows.iter().any(|(candidate, _)| candidate == key) {
        rows.push((key.to_string(), value));
    }
}

fn dict_set_lines(rows: &mut Vec<(String, Vec<String>)>, key: &str, value: Vec<String>) {
    if !rows.iter().any(|(candidate, _)| candidate == key) {
        rows.push((key.to_string(), value));
    }
}

impl BuiltinStrategyUsage {
    /// Где стратегия стоит в готовых пресетах: (сервис, его название, число пресетов).
    pub fn places(&self, catalog_name: &str, strategy_id: &str) -> Vec<(String, String, i64)> {
        let key: StrategyKey = (catalog_name.to_string(), strategy_id.to_string());
        let mut rows: Vec<(String, String, i64)> = Vec::new();
        for (service, counts) in &self.by_service {
            if let Some((_, count)) = counts.iter().find(|(candidate, _)| *candidate == key) {
                let name = dict_get(&self.service_names, service)
                    .cloned()
                    .unwrap_or_else(|| service.clone());
                rows.push((service.clone(), name, *count));
            }
        }
        rows.sort_by(|left, right| {
            right
                .2
                .cmp(&left.2)
                .then_with(|| left.1.to_lowercase().cmp(&right.1.to_lowercase()))
        });
        rows
    }

    /// Частота стратегий каталога этого профиля: {id стратегии: частота}.
    ///
    /// Порядок совпадает с порядком python-словаря services.
    pub fn for_profile(
        &self,
        profile: &Profile,
        catalog_name: Option<&str>,
    ) -> Vec<(String, StrategyUsage)> {
        let catalog = match catalog_name {
            Some(value) => value.to_string(),
            None => catalog_name_for_profile(profile),
        };
        let service = service_key(profile);
        let same = dict_get(&self.by_service, &service);
        let mut usage: Vec<(String, StrategyUsage)> = Vec::new();
        for (key, services) in &self.services {
            if key.0 != catalog {
                continue;
            }
            let same_service = same
                .and_then(|counts| counts.iter().find(|(candidate, _)| candidate == key))
                .map(|(_, count)| *count)
                .unwrap_or(0);
            let value = StrategyUsage {
                same_service,
                services: *services,
            };
            if let Some(slot) = usage.iter_mut().find(|(id, _)| id == &key.1) {
                slot.1 = value;
            } else {
                usage.push((key.1.clone(), value));
            }
        }
        usage
    }
}

/// Сервис профиля: его условия без различия hostlist/ipset.
pub fn service_key(profile: &Profile) -> String {
    let signature = profile.match_signature.trim().to_string();
    build_profile_logical_key(&signature).trim().to_string()
}

/// python catalog_name_for_profile (тоже в derived_cache).
pub fn catalog_name_for_profile(profile: &Profile) -> String {
    strategy_catalog_from_match_lines(&profile.match_section().all_lines())
}

fn profile_strategy_lines(profile: &Profile) -> Vec<String> {
    match &profile.strategy {
        Some(Strategy::Winws1(inner)) => inner.strategy_lines.clone(),
        Some(Strategy::Winws2(inner)) => inner.strategy_lines.clone(),
        None => Vec::new(),
    }
}

/// Стратегия каталога по строкам стратегии профиля — поиском по словарю.
///
/// Правила те же, что у ``derived_cache.resolve_strategy_lines``, но готовых
/// пресетов сотня с лишним, а профилей в них тысячи: перебирать весь каталог
/// на каждый профиль было самой дорогой частью подсчёта.
pub struct CatalogIndex {
    engine: String,
    plain: HashMap<Vec<String>, Vec<String>>,
    composite: HashMap<Vec<(String, String)>, Vec<String>>,
}

impl CatalogIndex {
    pub fn new(engine: &str, entries: &[StrategyEntry]) -> Self {
        let mut plain: HashMap<Vec<String>, Vec<String>> = HashMap::new();
        let mut composite: HashMap<Vec<(String, String)>, Vec<String>> = HashMap::new();
        for entry in entries {
            let args = entry.args.trim().to_string();
            if engine == ENGINE_WINWS2 && entry.is_composite {
                let key = entry_composite_identity(&args);
                composite
                    .entry(key)
                    .or_default()
                    .push(entry.strategy_id.clone());
            } else {
                let key = entry_identity_lines(engine, &args);
                plain
                    .entry(key)
                    .or_default()
                    .push(entry.strategy_id.clone());
            }
        }
        Self {
            engine: engine.to_string(),
            plain,
            composite,
        }
    }

    /// Id стратегии каталога; пусто, если строки не совпали ровно с одной.
    pub fn strategy_id(&self, lines: &[String]) -> String {
        let matches = if self.engine != ENGINE_WINWS2 {
            self.plain.get(&normalize_lines(lines.iter().cloned()))
        } else {
            let shape = strategy_shape(lines);
            if shape.lua_lines().is_empty() {
                return String::new();
            }
            if shape.composite {
                self.composite.get(&composite_identity(&shape.body_lines))
            } else {
                self.plain.get(&shape.lua_lines())
            }
        };
        match matches {
            Some(ids) if ids.len() == 1 => ids[0].clone(),
            _ => String::new(),
        }
    }
}

/// Считает частоту по текстам готовых пресетов: [(имя файла, текст), ...].
pub fn count_builtin_strategy_usage(
    texts: &[(String, String)],
    engine: &str,
    catalogs: &HashMap<String, Vec<StrategyEntry>>,
) -> BuiltinStrategyUsage {
    let mut by_service: Vec<(String, Vec<(StrategyKey, i64)>)> = Vec::new();
    let mut service_names: Vec<(String, String)> = Vec::new();
    let mut service_match_lines: Vec<(String, Vec<String>)> = Vec::new();
    let mut indexes: HashMap<String, CatalogIndex> = HashMap::new();

    for (source_name, text) in texts {
        let Ok(preset) = parse_preset_text(text, engine, source_name) else {
            continue;
        };
        // Один пресет — один голос за пару «сервис, стратегия».
        let mut seen: Vec<(String, StrategyKey)> = Vec::new();
        for profile in &preset.profiles {
            if !profile.enabled {
                continue;
            }
            let service = service_key(profile);
            let catalog = catalog_name_for_profile(profile);
            if service.is_empty() || catalog.is_empty() {
                continue;
            }
            let index = match indexes.get(&catalog) {
                Some(index) => index,
                None => {
                    let built =
                        CatalogIndex::new(engine, catalogs.get(&catalog).unwrap_or(&Vec::new()));
                    indexes.insert(catalog.clone(), built);
                    indexes.get(&catalog).expect("индекс")
                }
            };
            let lines = profile_strategy_lines(profile);
            let strategy_id = index.strategy_id(&lines);
            if strategy_id.is_empty() {
                continue;
            }
            let vote_key = (catalog.clone(), strategy_id.clone());
            let vote = (service.clone(), vote_key.clone());
            if seen.contains(&vote) {
                continue;
            }
            seen.push(vote);
            let name = if profile.name.is_empty() {
                if profile.display_name.is_empty() {
                    service.clone()
                } else {
                    profile.display_name.clone()
                }
            } else {
                profile.name.clone()
            };
            dict_set(&mut service_names, &service, name);
            dict_set_lines(
                &mut service_match_lines,
                &service,
                profile.match_section().all_lines(),
            );
            let entry = match by_service
                .iter_mut()
                .find(|(candidate, _)| candidate == &service)
            {
                Some((_, counts)) => counts,
                None => {
                    by_service.push((service.clone(), Vec::new()));
                    &mut by_service.last_mut().expect("counts").1
                }
            };
            match entry
                .iter_mut()
                .find(|(candidate, _)| candidate == &vote_key)
            {
                Some(slot) => slot.1 += 1,
                None => entry.push((vote_key, 1)),
            }
        }
    }

    let mut services: Vec<(StrategyKey, i64)> = Vec::new();
    for (_, counts) in &by_service {
        for (strategy, _) in counts {
            match services
                .iter_mut()
                .find(|(candidate, _)| candidate == strategy)
            {
                Some(slot) => slot.1 += 1,
                None => services.push((strategy.clone(), 1)),
            }
        }
    }
    BuiltinStrategyUsage {
        by_service,
        services,
        service_names,
        service_match_lines,
    }
}

type UsageCacheValue = ((Vec<TreeRow>, String), BuiltinStrategyUsage);

fn usage_cache() -> &'static Mutex<HashMap<(String, String), UsageCacheValue>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), UsageCacheValue>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Частота по готовым пресетам движка; пересчитывается, когда меняются файлы.
pub fn load_builtin_strategy_usage(
    app_paths: &AppPaths,
    engine: &str,
    catalogs: &HashMap<String, Vec<StrategyEntry>>,
    catalogs_signature: &str,
) -> BuiltinStrategyUsage {
    use crate::strategy_catalog::tree_signature;

    let engine_key = engine.trim().to_lowercase();
    let directory = app_paths
        .engine_paths(Some(&engine_key))
        .builtin_presets_dir;
    let cache_key = (directory.display().to_string(), engine_key.clone());
    let signature = (tree_signature(&directory), catalogs_signature.to_string());
    let cached = usage_cache()
        .lock()
        .expect("лок кэша готовых пресетов")
        .get(&cache_key)
        .cloned();
    if let Some(((cached_signature, cached_catalogs), usage)) = cached {
        if cached_signature == signature.0 && cached_catalogs == signature.1 {
            return usage;
        }
    }

    let mut texts: Vec<(String, String)> = Vec::new();
    if directory.exists() {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&directory)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        paths.retain(|path| {
            path.is_file()
                && path
                    .extension()
                    .map(|extension| extension == "txt")
                    .unwrap_or(false)
        });
        paths.sort();
        for path in paths {
            let raw = match std::fs::read(&path) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            texts.push((name, String::from_utf8_lossy(&raw).to_string()));
        }
    }
    let usage = count_builtin_strategy_usage(&texts, &engine_key, catalogs);
    usage_cache()
        .lock()
        .expect("лок кэша готовых пресетов")
        .insert(cache_key, (signature, usage.clone()));
    usage
}
