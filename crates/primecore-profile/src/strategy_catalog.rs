//! Порт profile/strategy_catalog.py: каталоги готовых стратегий на диске.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::strategy_shape::{is_filter_line, is_lua_desync_line, is_range_line, strategy_shape};
use crate::strategy_visuals::{describe_strategy_visual, StrategyVisual};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyEntry {
    #[serde(rename = "strategy_id")]
    pub strategy_id: String,
    #[serde(rename = "catalog_name")]
    pub catalog_name: String,
    pub name: String,
    pub args: String,
    pub visual: StrategyVisual,
    #[serde(default)]
    pub is_composite: bool,
    #[serde(default)]
    pub payload_scopes: Vec<String>,
    #[serde(default)]
    pub old_name: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TreeRow {
    pub relative: String,
    pub mtime_ns: u128,
    pub size: u64,
}

pub type Signature = Vec<TreeRow>;

pub type Catalogs = HashMap<String, Vec<StrategyEntry>>;

const META_KEYS: [&str; 3] = ["label", "author", "description"];

fn cache() -> &'static Mutex<HashMap<String, (Signature, Catalogs)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Signature, Catalogs)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn strategy_catalog_root(user_root: &Path) -> PathBuf {
    user_root.join("system").join("strategy_catalogs")
}

#[derive(Debug, Default)]
struct CatalogDraft {
    id: Option<String>,
    catalog_name: String,
    name: String,
    old_name: String,
    meta: HashMap<String, String>,
    args: Vec<String>,
}

pub(crate) fn tree_signature(root: &Path) -> Signature {
    let mut rows: Vec<TreeRow> = Vec::new();
    if !root.exists() {
        return rows;
    }
    let mut walk_queue: Vec<(PathBuf, String)> = Vec::new();
    walk_queue.push((root.to_path_buf(), String::new()));
    // python rglob("*.txt"): обходим дерево целиком, включая вложенные папки.
    while let Some((dir, prefix)) = walk_queue.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let relative = if prefix.is_empty() {
                file_name.to_string_lossy().to_string()
            } else {
                format!("{prefix}/{}", file_name.to_string_lossy())
            };
            match path.is_dir() {
                true => walk_queue.push((path, relative)),
                false => {
                    if !relative.ends_with(".txt") {
                        continue;
                    }
                    if let Ok(metadata) = path.metadata() {
                        let mtime_ns = metadata
                            .modified()
                            .ok()
                            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|duration| duration.as_nanos())
                            .unwrap_or(0);
                        rows.push(TreeRow {
                            relative,
                            mtime_ns,
                            size: metadata.len(),
                        });
                    }
                }
            }
        }
    }
    rows.sort();
    rows
}

const PROFILE_SCOPED_PREFIXES: [&str; 11] = [
    "--name",
    "--template",
    "--import",
    "--skip",
    "--hostlist=",
    "--hostlist-domains=",
    "--hostlist-exclude=",
    "--hostlist-exclude-domains=",
    "--hostlist-auto=",
    "--ipset=",
    "--ipset-exclude=",
];

fn profile_scoped_lines(lines: &[String]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for raw in lines {
        let stripped = raw.trim().to_string();
        let lowered = stripped.to_lowercase();
        if lowered.is_empty() {
            continue;
        }
        if lowered == "--new" || lowered.starts_with("--new=") {
            found.push(stripped.clone());
            continue;
        }
        if lowered.starts_with("--filter-") {
            found.push(stripped.clone());
            continue;
        }
        if PROFILE_SCOPED_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
        {
            found.push(stripped.clone());
            continue;
        }
        if lowered.starts_with("--ipset-exclude-ip=") || lowered.starts_with("--ipset-ip=") {
            found.push(stripped.clone());
        }
    }
    found
}

/// Почему строки --payload/диапазонов недопустимы в записи (None — допустимы).
fn branch_filter_problem(lines: &[String]) -> Option<String> {
    let filters: Vec<&String> = lines.iter().filter(|line| is_filter_line(line)).collect();
    if filters.is_empty() {
        return None;
    }
    let Some(first_lua) = lines.iter().position(|line| is_lua_desync_line(line)) else {
        return Some(format!(
            "фильтры без строк --lua-desync: {}",
            join_lines(&filters)
        ));
    };
    let early_ranges: Vec<&String> = lines[..first_lua]
        .iter()
        .filter(|line| is_range_line(line))
        .collect();
    if !early_ranges.is_empty() {
        return Some(format!(
            "диапазон до первой --lua-desync — это настройка profile-а, а не готовой стратегии: {}",
            join_lines(&early_ranges)
        ));
    }
    if !strategy_shape(lines).composite {
        return Some(format!(
            "--payload в готовой стратегии допустим только как разделитель веток составной стратегии: {}",
            join_lines(&filters)
        ));
    }
    let unknown: Vec<&String> = lines
        .iter()
        .filter(|line| !(is_lua_desync_line(line) || is_filter_line(line)))
        .collect();
    if !unknown.is_empty() {
        return Some(format!(
            "в составной стратегии допустимы только --payload, диапазоны и --lua-desync: {}",
            join_lines(&unknown)
        ));
    }
    None
}

fn join_lines(lines: &[&String]) -> String {
    lines.iter().map(|line| line.as_str()).collect::<Vec<&str>>().join(", ")
}

impl CatalogDraft {
    fn flush_entry(&self) -> Option<StrategyEntry> {
        let Some(current_id) = self.id.clone() else {
            return None;
        };
        let args = self
            .args
            .iter()
            .filter(|line| !line.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        let arg_lines: Vec<String> = args.lines().map(str_to_line).collect();
        if !profile_scoped_lines(&arg_lines).is_empty() {
            // Строки профиля в готовой стратегии — запись отбрасывается.
            return None;
        }
        if branch_filter_problem(arg_lines.as_slice()).is_some() {
            return None;
        }
        let shape = strategy_shape(arg_lines.as_slice());
        let name = if self.name.is_empty() {
            current_id.clone()
        } else {
            self.name.clone()
        };
        Some(StrategyEntry {
            strategy_id: current_id.clone(),
            catalog_name: self.catalog_name.clone(),
            name,
            args: args.clone(),
            visual: describe_strategy_visual(&args),
            is_composite: shape.composite,
            payload_scopes: if shape.composite {
                shape.payload_scopes
            } else {
                Vec::new()
            },
            old_name: self.old_name.clone(),
            label: self
                .meta
                .get("label")
                .map(|value| value.trim().to_lowercase())
                .unwrap_or_default(),
            author: self
                .meta
                .get("author")
                .map(|value| value.trim().to_string())
                .unwrap_or_default(),
            description: self
                .meta
                .get("description")
                .map(|value| value.trim().to_string())
                .unwrap_or_default(),
        })
    }
}

fn str_to_line(line: &str) -> String {
    line.to_string()
}

fn partition_option(value: &str) -> Option<(&str, &str)> {
    let index = value.find('=')?;
    Some((&value[..index], &value[index + 1..]))
}

/// Разбор одного файла каталога: порядок записей — как в python-словаре.
fn parse_catalog_file(payload: &str, catalog_name: &str) -> Vec<StrategyEntry> {
    let mut ordered: Vec<StrategyEntry> = Vec::new();
    let mut seen_ids: Vec<String> = Vec::new();
    let mut draft = CatalogDraft {
        catalog_name: catalog_name.to_string(),
        ..CatalogDraft::default()
    };

    for raw in payload.split('\n') {
        let line = raw.trim_end_matches('\r');
        let stripped = line.trim().to_string();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped.starts_with('[') && stripped.ends_with(']') {
            if let Some(entry) = draft.flush_entry() {
                ordered = push_or_replace(ordered, entry);
            }
            let id = stripped[1..stripped.len() - 1].trim().to_string();
            if seen_ids.contains(&id) {
                // python log: повторяется — будет использована последняя копия.
            }
            seen_ids.push(id.clone());
            draft = CatalogDraft {
                id: Some(id.clone()),
                catalog_name: catalog_name.to_string(),
                name: id.clone(),
                ..CatalogDraft::default()
            };
        } else if draft.id.is_none() {
            continue;
        } else if stripped.starts_with("--") {
            draft.args.push(stripped);
        } else if !draft.args.is_empty() {
            draft.args.push(stripped);
        } else if let Some((key_raw, value_raw)) = partition_option(&stripped) {
            let key = key_raw.trim().to_lowercase();
            let value = value_raw.trim().to_string();
            if key == "name" {
                draft.name = value;
            } else if key == "old_name" {
                draft.old_name = value;
            } else if META_KEYS.contains(&key.as_str()) {
                draft.meta.insert(key, value);
            }
        }
    }
    if let Some(entry) = draft.flush_entry() {
        ordered = push_or_replace(ordered, entry);
    }
    ordered
}

/// python: повторная запись по ключу остаётся на своём месте.
fn push_or_replace(ordered: Vec<StrategyEntry>, entry: StrategyEntry) -> Vec<StrategyEntry> {
    match ordered.iter().position(|known| known.strategy_id == entry.strategy_id) {
        Some(index) => {
            let mut ordered = ordered;
            ordered[index] = entry;
            ordered
        }
        None => {
            let mut ordered = ordered;
            ordered.push(entry);
            ordered
        }
    }
}

fn load_engine_root(root: &Path) -> Catalogs {
    let mut entries: Vec<PathBuf> = Vec::new();
    if let Ok(read) = std::fs::read_dir(root) {
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().map(|extension| extension == "txt").unwrap_or(false) {
                entries.push(path);
            }
        }
    }
    entries.sort();
    let mut catalogs: Catalogs = HashMap::new();
    for path in entries {
        let Ok(payload) = std::fs::read_to_string(&path) else {
            continue;
        };
        let stem = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        catalogs.insert(stem.clone(), parse_catalog_file(&payload, &stem));
    }
    catalogs
}

pub fn parse_catalog_payload(payload: &str, catalog_name: &str) -> Vec<StrategyEntry> {
    parse_catalog_file(payload, catalog_name)
}

pub fn load_strategy_catalogs(user_root: &Path, engine: &str) -> Catalogs {
    load_strategy_catalogs_with_signature(user_root, engine).2
}

/// Возвращает (ключ кэша, подпись дерева файлов, каталоги).
pub fn load_strategy_catalogs_with_signature(user_root: &Path, engine: &str) -> (String, Signature, Catalogs) {
    let engine_key = engine.trim().to_lowercase();
    let engine_root = strategy_catalog_root(user_root).join(&engine_key);
    let cache_key = format!("{}||{}", engine_root.display(), engine_key);
    let signature = tree_signature(&engine_root);
    let mut cache = cache().lock().expect("локальный кэш каталогов");
    if let Some((cached_signature, cached)) = cache.get(&cache_key) {
        if *cached_signature == signature {
            return (cache_key.clone(), cached_signature.clone(), cached.clone());
        }
    }
    let catalogs = load_engine_root(&engine_root);
    cache.insert(cache_key.clone(), (signature.clone(), catalogs.clone()));
    (cache_key, signature, catalogs)
}
