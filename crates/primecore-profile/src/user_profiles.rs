//! Порт `src/profile/user_profiles/service.py` — пользовательские профили:
//! CRUD в секции user_profiles настроек + файлы списков + шаблоны.

use std::path::Path;
use std::path::PathBuf;

use regex::Regex;
use serde_json::{json, Map, Value};

use primecore_lists::layered::{
    create_profile_user_list_file, delete_profile_user_list_file,
    rename_profile_user_list_file, safe_list_file_name, write_profile_user_list_text,
};

use primecore_mode::{ENGINE_WINWS1, ENGINE_WINWS2};

use crate::models::Profile;
use crate::parser::parse_preset_text;
use crate::template_library::{load_profile_templates, profile_template_root};

pub const DEFAULT_HOSTLIST_TEXT: &str = "www.example.com\n";

const TRANSLIT: [(&str, &str); 33] = [
    ("а", "a"), ("б", "b"), ("в", "v"), ("г", "g"), ("д", "d"), ("е", "e"), ("ё", "e"),
    ("ж", "zh"), ("з", "z"), ("и", "i"), ("й", "i"), ("к", "k"), ("л", "l"), ("м", "m"),
    ("н", "n"), ("о", "o"), ("п", "p"), ("р", "r"), ("с", "s"), ("т", "t"), ("у", "u"),
    ("ф", "f"), ("х", "h"), ("ц", "c"), ("ч", "ch"), ("ш", "sh"), ("щ", "sch"), ("ъ", ""),
    ("ы", "y"), ("ь", ""), ("э", "e"), ("ю", "yu"), ("я", "ya"),
];

/// python AppPaths-эквивалент: пользовательский корень.
#[derive(Clone)]
pub struct AppPaths {
    pub user_root: PathBuf,
}

impl AppPaths {
    /// python _system_profile_names / lists_root.
    pub fn lists_root(&self) -> PathBuf {
        self.user_root.join("lists")
    }

    pub fn database_path(&self) -> PathBuf {
        self.user_root.join("user").join("settings.sqlite3")
    }

    fn templates_root(&self) -> PathBuf {
        self.user_root.join("system").join("templates")
    }
}

// ------------------------------------------------------- settings-секция

fn open_database(paths: &AppPaths) -> Result<primecore_settings::store::SettingsDatabase, String> {
    let database_path = paths.database_path();
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    primecore_settings::store::SettingsDatabase::open(&database_path)
}

/// python update_user_profiles_settings(mutator): read-modify-write одним
/// включением. Ошибка mutator-а не записывает секцию (python-откат).
fn update_user_profiles_settings<F>(
    paths: &AppPaths,
    mutator: F,
) -> Result<Value, String>
where
    F: FnOnce(&mut Value) -> Result<(), String>,
{
    let mut failure: Option<String> = None;
    let mut database = open_database(paths)?;
    let result = database.update_settings(|data| {
        let mut section = data
            .get("user_profiles")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match mutator(&mut section) {
            Ok(()) => {
                data["user_profiles"] = section;
            }
            Err(exc) => {
                failure = Some(exc);
            }
        }
    });
    result?;
    if let Some(exc) = failure {
        return Err(exc);
    }
    let sections = database.read_raw_sections()?;
    Ok(sections
        .get("user_profiles")
        .cloned()
        .unwrap_or_else(|| json!({})))
}

fn user_profiles_section(
    paths: &AppPaths,
) -> Result<Map<String, Value>, String> {
    let database = open_database(paths)?;
    let sections = database.read_raw_sections()?;
    let section = sections
        .get("user_profiles")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(as_object(section))
}

fn as_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn row_object_owned(row: Value) -> Option<Map<String, Value>> {
    match row {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

// ------------------------------------------------------------- CRUD

/// python create_user_profile.
pub fn create_user_profile(
    paths: &AppPaths,
    name: &str,
    protocol: &str,
    ports: &str,
) -> Result<String, String> {
    let clean_name = clean_name(name)?;
    let clean_protocol = clean_protocol(protocol)?;
    let clean_ports = clean_ports(ports, &clean_protocol)?;
    let system_names = system_profile_names(paths);
    let lists_root = paths.lists_root();
    let mut created_profile_id = String::new();

    update_user_profiles_settings(paths, |section| {
        let profiles = as_object(section
            .get("profiles")
            .cloned()
            .unwrap_or_else(|| json!({})));
        validate_unique_profile_name(&profiles, &system_names, &clean_name, "")?;
        let profile_id = unique_profile_id(&profiles, &slugify(&clean_name));
        let file_stem = unique_file_stem(&profiles, &slugify(&clean_name), "");
        let hostlist_had_entries =
            user_list_file_has_entries(&lists_root, &format!("{file_stem}.txt"));
        create_profile_user_list_file(&lists_root, &format!("{file_stem}.txt"));
        create_profile_user_list_file(&lists_root, &format!("ipset-{file_stem}.txt"));
        if !hostlist_had_entries {
            write_profile_user_list_text(&lists_root, &format!("{file_stem}.txt"), DEFAULT_HOSTLIST_TEXT);
        }
        let mut profiles = profiles;
        profiles_insert(
            &mut profiles,
            &profile_id,
            json!({
                "name": clean_name,
                "protocol": clean_protocol,
                "ports": clean_ports,
                "hostlist": format!("lists/{file_stem}.txt"),
                "ipset": format!("lists/ipset-{file_stem}.txt"),
            }),
        );
        section["version"] = json!(1);
        section["profiles"] = Value::Object(profiles);
        created_profile_id = profile_id;
        Ok(())
    })?;
    Ok(created_profile_id)
}

fn profiles_insert(profiles: &mut Map<String, Value>, key: &str, value: Value) {
    profiles.insert(key.to_string(), value);
}

/// python update_user_profile: строка до правки + строка после правки.
pub fn update_user_profile(
    paths: &AppPaths,
    profile_id: &str,
    name: &str,
    protocol: &str,
    ports: &str,
) -> Result<(Map<String, Value>, Map<String, Value>), String> {
    let clean_profile_id = profile_id.trim().to_string();
    if clean_profile_id.is_empty() {
        return Err("Profile id не должен быть пустым".to_string());
    }
    let clean_name = clean_name(name)?;
    let clean_protocol = clean_protocol(protocol)?;
    let clean_ports = clean_ports(ports, &clean_protocol)?;
    let system_names = system_profile_names(paths);
    let mut rows: Option<(Map<String, Value>, Map<String, Value>)> = None;

    update_user_profiles_settings(paths, |section| {
        let profiles = as_object(section
            .get("profiles")
            .cloned()
            .unwrap_or_else(|| json!({})));
        let row = row_object_owned(profiles.get(&clean_profile_id).cloned().unwrap_or(Value::Null))
            .ok_or_else(|| "Пользовательский profile не найден".to_string())?;
        validate_unique_profile_name(&profiles, &system_names, &clean_name, &clean_profile_id)?;
        let old_row = row_fields(&row);
        let new_stem =
            unique_file_stem(&profiles, &slugify(&clean_name), &clean_profile_id);
        let updated_row_value = json!({
            "name": clean_name,
            "protocol": clean_protocol,
            "ports": clean_ports,
            "hostlist": format!("lists/{new_stem}.txt"),
            "ipset": format!("lists/ipset-{new_stem}.txt"),
        });
        let updated_row = as_object(updated_row_value.clone());
        rename_user_list_file(paths, &old_row, &updated_row)?;
        let mut profiles = profiles;
        profiles_insert(&mut profiles, &clean_profile_id, updated_row_value);
        section["version"] = json!(1);
        section["profiles"] = Value::Object(profiles);
        rows = Some((old_row, updated_row));
        Ok(())
    })?;
    rows.ok_or_else(|| "Пользовательский profile не найден".to_string())
}

/// python delete_user_profile: удаляет профиль и его файлы, вернёт строку.
pub fn delete_user_profile(
    paths: &AppPaths,
    profile_id: &str,
) -> Result<Map<String, Value>, String> {
    let clean_profile_id = profile_id.trim().to_string();
    if clean_profile_id.is_empty() {
        return Err("Profile id не должен быть пустым".to_string());
    }
    let mut removed: Option<Map<String, Value>> = None;

    update_user_profiles_settings(paths, |section| {
        let profiles = as_object(section
            .get("profiles")
            .cloned()
            .unwrap_or_else(|| json!({})));
        let row_value = profiles.get(&clean_profile_id).cloned().unwrap_or(Value::Null);
        let row = row_object_owned(row_value).ok_or_else(|| "Пользовательский profile не найден".to_string())?;
        let mut profiles = profiles;
        profiles.remove(&clean_profile_id);
        section["version"] = json!(1);
        section["profiles"] = Value::Object(profiles);
        removed = Some(row_fields(&row));
        Ok(())
    })?;
    let row = removed.ok_or_else(|| "Пользовательский profile не найден".to_string())?;
    delete_user_list_file(paths, string_field(&row, "hostlist"));
    delete_user_list_file(paths, string_field(&row, "ipset"));
    Ok(row)
}

// --------------------------------------------------------- вспомогательные

fn string_field(row: &Map<String, Value>, field: &str) -> String {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// python _row_fields: name/protocol/ports/hostlist/ipset строками.
fn row_fields(row: &Map<String, Value>) -> Map<String, Value> {
    let mut fields = Map::new();
    for field in ["name", "protocol", "ports", "hostlist", "ipset"] {
        let value = row
            .get(field)
            .map(|value| match value {
                Value::String(text) => text.trim().to_string(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();
        fields.insert(field.to_string(), Value::String(value));
    }
    fields
}

/// python load_user_profile_templates: id -> профиль, порядок sorted(id).
pub fn load_user_profile_templates(lists_root: &AppPaths, engine: &str) -> Vec<(String, Profile)> {
    let normalized_engine = engine.trim().to_lowercase();
    let Ok(profiles) = user_profiles_section(lists_root) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = profiles.keys().cloned().collect();
    ids.sort();
    let mut result: Vec<(String, Profile)> = Vec::new();
    for profile_id in ids {
        let row = profiles.get(&profile_id).cloned().unwrap_or(Value::Null);
        match profile_text(&row, &normalized_engine) {
            Ok(text) => {
                if text.is_empty() {
                    continue;
                }
                match parse_preset_text(&text, &normalized_engine, "user_profiles") {
                    Ok(preset) => {
                        if let Some(profile) = preset.profiles.into_iter().next() {
                            result.push((format!("user:{profile_id}"), profile));
                        }
                    }
                    Err(_) => {
                        log_skipped_user_profile(&format!("повреждённая запись: parse_preset_text"));
                    }
                }
            }
            Err(exc) => log_skipped_user_profile(&format!("повреждённая запись ({exc})")),
        }
    }
    result
}

fn log_skipped_user_profile(_comment: &str) {
    // python log(..., "WARNING").
}

/// python _profile_text: текст свежего профиля (строки фильтра + pass).
pub fn profile_text(row: &Value, engine: &str) -> Result<String, String> {
    let row = row_object_owned(row.clone()).ok_or_else(|| "не словарь".to_string())?;
    let NameProtocolPorts { name, protocol, ports } = clean_row(&row)?;
    let hostlist = string_field(&row, "hostlist");
    if hostlist.is_empty() {
        return Ok(String::new());
    }
    let name_directive = if engine == ENGINE_WINWS1 { "--comment" } else { "--name" };
    let mut lines = vec![
        format!("{name_directive}={name}"),
        format!("--filter-{protocol}={ports}"),
        format!("--hostlist={hostlist}"),
    ];
    if engine == ENGINE_WINWS2 {
        lines.push("--lua-desync=pass".to_string());
    }
    Ok(format!("{}\n", lines.join("\n")))
}

struct NameProtocolPorts {
    name: String,
    protocol: String,
    ports: String,
}

fn clean_row(row: &Map<String, Value>) -> Result<NameProtocolPorts, String> {
    let name = string_field(row, "name");
    let clean_name = clean_name(&name).map(|value| value).unwrap_or_default();
    let protocol = clean_protocol(&string_field(row, "protocol")).unwrap_or_default();
    let ports = clean_ports(&string_field(row, "ports"), &protocol).unwrap_or_default();
    Ok(NameProtocolPorts {
        name: clean_name,
        protocol,
        ports,
    })
}

fn clean_name(value: &str) -> Result<String, String> {
    let text = value.trim().to_string();
    if text.is_empty() {
        return Err("Название profile не должно быть пустым".to_string());
    }
    Ok(text)
}

fn clean_protocol(value: &str) -> Result<String, String> {
    let protocol = value.trim().to_lowercase();
    if !["tcp", "udp", "l7"].contains(&protocol.as_str()) {
        return Err("Тип profile должен быть TCP, UDP или L7".to_string());
    }
    Ok(protocol)
}

/// python validate_user_profile_filter.
pub fn validate_user_profile_filter(protocol: &str, value: &str) -> Option<String> {
    let clean_protocol = protocol.trim().to_lowercase();
    let text: String = value.trim().replace(' ', "").to_string();
    if text.is_empty() {
        return Some("Значение фильтра profile не должно быть пустым".to_string());
    }
    if clean_protocol == "l7" {
        static L7_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9_,.-]+$").expect("regex"));
        if !L7_RE.is_match(&text) {
            return Some("L7 можно указать словами через запятую, например stun,discord".to_string());
        }
        return None;
    }
    if !["tcp", "udp"].contains(&clean_protocol.as_str()) {
        return Some("Тип profile должен быть TCP, UDP или L7".to_string());
    }
    static PORTS_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^[0-9*,~-]+$").expect("regex"));
    if !PORTS_RE.is_match(&text) {
        return Some("Порты можно указать числами, диапазонами и запятыми".to_string());
    }
    for raw_token in text.split(',') {
        if let Some(error) = validate_port_token(raw_token) {
            return Some(error);
        }
    }
    None
}

const PORT_RANGE_EDGES: &str = "Порт должен быть от 1 до 65535.";

fn ports_message() -> String {
    "Порты можно указать числами, диапазонами и запятыми".to_string()
}

fn validate_port_token(token: &str) -> Option<String> {
    if token.is_empty() {
        return Some(ports_message());
    }
    let mut token = token.to_string();
    if let Some(stripped) = token.strip_prefix('~') {
        let stripped_value = stripped.to_string();
        if stripped_value.is_empty() || stripped_value == "*" {
            return Some(ports_message());
        }
        token = stripped_value;
    }
    if token == "*" {
        return None;
    }
    if token.contains('-') {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Some(ports_message());
        }
        let (Some(start), Some(end)) = (
            parse_port_number(parts[0]),
            parse_port_number(parts[1]),
        ) else {
            return Some(PORT_RANGE_EDGES.to_string());
        };
        if start > end {
            return Some("Начало диапазона портов не должно быть больше конца.".to_string());
        }
        return None;
    }
    if parse_port_number(&token).is_none() {
        return Some(PORT_RANGE_EDGES.to_string());
    }
    None
}

fn parse_port_number(value: &str) -> Option<i64> {
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let port: i64 = value.parse().ok()?;
    if port < 1 || port > 65535 {
        return None;
    }
    Some(port)
}

fn clean_ports(value: &str, protocol: &str) -> Result<String, String> {
    let text = value.trim().replace(' ', "");
    let message = validate_user_profile_filter(protocol, &text);
    if let Some(message) = message {
        return Err(message);
    }
    Ok(text)
}

/// python _slugify: транслит + lowercase + [^a-z0-9а-яё] → '-'; Windows-имена.
pub fn slugify(value: &str) -> String {
    let lowered = value.trim().to_lowercase();
    let mut transliterated = String::with_capacity(lowered.len());
    for ch in lowered.chars() {
        match TRANSLIT.iter().find(|(source, _)| *source == ch.to_string()) {
            Some((_, target)) => transliterated.push_str(target),
            None => transliterated.push(ch),
        }
    }
    // python _SLUG_RE: [^a-z0-9а-яё]+ IGNORECASE — после lower не-буквы → '-'.
    let mut normalized = String::with_capacity(transliterated.len());
    for ch in transliterated.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ('а'..='я').contains(&ch) {
            normalized.push(ch);
        } else {
            normalized.push('-');
        }
    }
    normalized = normalized.trim_matches('-').to_string();
    let mut text = normalized;
    if text.is_empty() {
        text = "profile".to_string();
    }
    if safe_list_file_name(&format!("{text}.txt")).is_none() {
        text = format!("{text}-profile");
    }
    text
}

fn unique_profile_id(profiles: &Map<String, Value>, base: &str) -> String {
    let mut candidate = base.to_string();
    let mut counter = 2;
    while profiles.contains_key(&candidate) {
        candidate = format!("{base}-{counter}");
        counter += 1;
    }
    candidate
}

/// python _unique_file_stem: уникальность среди ФАЙЛОВ всех профилей.
fn unique_file_stem(profiles: &Map<String, Value>, base: &str, exclude_profile_id: &str) -> String {
    let excluded = exclude_profile_id.trim().to_string();
    let mut used: Vec<String> = Vec::new();
    for (profile_id, row_value) in profiles {
        if profile_id.trim() == excluded {
            continue;
        }
        let Some(row) = row_object_owned(row_value.clone()) else {
            continue;
        };
        for field in ["hostlist", "ipset"] {
            let value = row
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .replace('\\', "/");
            let some_name = Path::new(&value)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            if some_name.is_empty() {
                continue;
            }
            let mut stem = some_name.clone();
            if stem.to_lowercase().ends_with(".txt") {
                stem.truncate(stem.len() - 4);
            }
            if let Some(rest) = stem.strip_prefix("ipset-") {
                stem = rest.to_string();
            }
            if !stem.is_empty() {
                used.push(stem.to_lowercase());
            }
        }
    }
    let mut candidate = base.to_string();
    let mut counter = 2;
    while used.contains(&candidate.to_lowercase()) {
        candidate = format!("{base}-{counter}");
        counter += 1;
    }
    candidate
}

fn validate_unique_profile_name(
    profiles: &Map<String, Value>,
    system_names: &std::collections::HashSet<String>,
    name: &str,
    exclude_profile_id: &str,
) -> Result<(), String> {
    let wanted = name.trim().to_lowercase();
    if wanted.is_empty() {
        return Ok(());
    }
    let excluded = exclude_profile_id.trim().to_string();
    for (profile_id, row_value) in profiles {
        if profile_id.trim() == excluded {
            continue;
        }
        if let Some(row) = row_object_owned(row_value.clone()) {
            let name_value = row
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            if name_value == wanted {
                return Err("Пользовательский profile с таким названием уже есть".to_string());
            }
        }
    }
    for system_name in system_names {
        if system_name.trim().to_lowercase() == wanted {
            return Err("Такое название уже занято системным profile-ом".to_string());
        }
    }
    Ok(())
}

/// python _system_profile_names: имена шаблонов обоих движков.
fn system_profile_names(paths: &AppPaths) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for engine in [ENGINE_WINWS2, ENGINE_WINWS1] {
        for (_, profile) in load_profile_templates(&paths.user_root, &engine).into_iter() {
            let name = if profile.name.is_empty() {
                profile.match_signature.clone()
            } else {
                profile.name.clone()
            };
            let name = name.trim().to_string();
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }
    names
}

fn user_list_file_has_entries(lists_root: &Path, file_name: &str) -> bool {
    let path = lists_root.join("user").join(file_name);
    if !path.is_file() {
        return false;
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return true,
    };
    let placeholder = DEFAULT_HOSTLIST_TEXT.trim().to_lowercase();
    text.lines().any(|line| {
        let stripped = line.trim();
        !stripped.is_empty() && !stripped.starts_with('#') && stripped.to_lowercase() != placeholder
    })
}

fn rename_user_list_file(
    paths: &AppPaths,
    old_row: &Map<String, Value>,
    new_row: &Map<String, Value>,
) -> Result<(), String> {
    // python: два независимых переименования (hostlist, ipset).
    let pairs = [
        (string_field(old_row, "hostlist"), string_field(new_row, "hostlist")),
        (string_field(old_row, "ipset"), string_field(new_row, "ipset")),
    ];
    for (old_value, new_value) in &pairs {
        let Some(new_name) = safe_list_file_name(new_value) else {
            continue;
        };
        let old_name = safe_list_file_name(old_value).unwrap_or_else(|| new_name.clone());
        rename_profile_user_list_file(&paths.lists_root(), &old_name, &new_name)?;
    }
    Ok(())
}

fn delete_user_list_file(paths: &AppPaths, value: String) {
    if let Some(name) = safe_list_file_name(&value) {
        delete_profile_user_list_file(&paths.lists_root(), &name);
    }
}
