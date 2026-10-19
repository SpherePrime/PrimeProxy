//! Разбор пресет-текста профилей — порт `src/profile/parser.py`.
//!
//! Структура пресета: # заголовок, общая часть (preamble), профили
//! (`--new`-строка + содержимое) и хвост. Внутри профиля — директивы,
//! match-строки (--filter-/--hostlist=/--ipset=…) и строки стратегии
//! (winws1/winws2 — по движку).

use std::collections::BTreeMap;

use crate::models::{
    build_profile_logical_key, build_profile_persistent_key, Profile, ProfileMatch,
    ProfileSegment, Preset, Strategy, ENGINE_WINWS1, ENGINE_WINWS2,
};
use crate::winws1::parse_winws1_strategy;
use crate::winws2::parse_winws2_strategy;

/// Служебные директивы профиля (python _DIRECTIVE_PREFIXES).
pub const DIRECTIVE_PREFIXES: [&str; 6] =
    ["--name", "--template", "--import", "--skip", "--comment", "--cookie"];

/// Match-префиксы (python _MATCH_PREFIXES).
pub const MATCH_PREFIXES: [&str; 10] = [
    "--filter-",
    "--hostlist=",
    "--hostlist-domains=",
    "--hostlist-exclude=",
    "--hostlist-exclude-domains=",
    "--hostlist-auto=",
    "--ipset=",
    "--ipset-exclude=",
    "--ipset-exclude-ip=",
    "--ipset-ip=",
];

/// Префиксы стратегии WinWS1 (python _WINWS1_STRATEGY_PREFIXES).
pub const WINWS1_STRATEGY_PREFIXES: [&str; 4] = ["--dpi-desync", "--dup", "--wssize", "--ip-id"];

pub fn normalize_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn parse_preset_text(
    text: &str,
    engine: &str,
    source_name: &str,
) -> Result<Preset, String> {
    let normalized_engine = normalize_engine(engine)?;
    let (header_lines, body_lines) = split_header_and_body(text);
    let (preamble_lines, raw_profiles, footer_lines) =
        split_preamble_and_profile_lines(&body_lines);
    let mut profiles: Vec<Profile> = raw_profiles
        .into_iter()
        .enumerate()
        .map(|(index, (new_line, lines))| parse_profile(&lines, &normalized_engine, index, &new_line))
        .collect();
    assign_profile_keys(&mut profiles);
    Ok(Preset {
        engine: normalized_engine,
        header_lines,
        preamble_lines,
        profiles,
        source_name: source_name.to_string(),
        footer_lines,
    })
}

pub fn normalize_engine(engine: &str) -> Result<String, String> {
    let normalized = engine.trim().to_lowercase();
    if normalized != ENGINE_WINWS1 && normalized != ENGINE_WINWS2 {
        return Err(format!("Unsupported profile preset engine: {engine}"));
    }
    Ok(normalized)
}

/// Сколько строк в начале — служебные заголовки (# ...) и пустые.
pub fn header_line_count(lines: &[String]) -> usize {
    for (index, raw) in lines.iter().enumerate() {
        let stripped = raw.trim();
        if !(stripped.starts_with('#') || stripped.is_empty()) {
            return index;
        }
    }
    lines.len()
}

pub fn split_header_and_body(text: &str) -> (Vec<String>, Vec<String>) {
    let lines: Vec<String> = normalize_text(text).split('\n').map(str_to_string).collect();
    let count = header_line_count(&lines);
    (lines[..count].to_vec(), lines[count..].to_vec())
}

fn str_to_string(value: &str) -> String {
    value.to_string()
}

/// Номера строк общей части, профилей (со строкой --new) и хвоста
/// (python _split_preamble_and_profile_indices). Один разбор на всех:
/// по нему делит пресет и сам разборщик, и оглавление.
fn split_preamble_and_profile_indices(
    body_lines: &[String],
) -> (Vec<usize>, Vec<(Option<usize>, Vec<usize>)>, Vec<usize>) {
    let mut preamble: Vec<usize> = Vec::new();
    let mut profiles: Vec<(Option<usize>, Vec<usize>)> = Vec::new();
    let mut footer: Vec<usize> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut current_new_line: Option<usize> = None;
    let mut saw_profile = false;

    for (index, raw) in body_lines.iter().enumerate() {
        let stripped = raw.trim();
        if is_new_profile_line(stripped) {
            if saw_profile {
                if !current.is_empty() {
                    profiles.push((current_new_line, std::mem::take(&mut current)));
                }
            } else if !current.is_empty() {
                preamble.append(&mut current);
            }
            saw_profile = true;
            current_new_line = Some(index);
            continue;
        }
        if !saw_profile && !looks_like_profile_line(stripped) {
            preamble.push(index);
            continue;
        }
        if !saw_profile && looks_like_profile_line(stripped) {
            saw_profile = true;
            current_new_line = None;
        }
        current.push(index);
    }

    if !current.is_empty() {
        if saw_profile {
            let content: Vec<String> =
                current.iter().filter_map(|index| body_lines.get(*index).cloned()).collect();
            if current_new_line.is_some() && !has_profile_content(&content) {
                footer.extend(current);
            } else {
                profiles.push((current_new_line, current));
            }
        } else {
            preamble.extend(current);
        }
    }
    (preamble, profiles, footer)
}

fn split_preamble_and_profile_lines(
    body_lines: &[String],
) -> (Vec<String>, Vec<(String, Vec<String>)>, Vec<String>) {
    let (preamble, profiles, footer) = split_preamble_and_profile_indices(body_lines);
    (
        preamble.iter().map(|index| body_lines[*index].clone()).collect(),
        profiles
            .into_iter()
            .map(|(new_line, indexes)| {
                let name = match new_line {
                    Some(index) => body_lines[index].trim().to_string(),
                    None => String::new(),
                };
                let lines = indexes.into_iter().map(|index| body_lines[index].clone()).collect();
                (name, lines)
            })
            .collect(),
        footer.iter().map(|index| body_lines[*index].clone()).collect(),
    )
}

fn has_profile_content(lines: &[String]) -> bool {
    for line in lines {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        return true;
    }
    false
}

pub fn is_new_profile_line(stripped: &str) -> bool {
    let lowered = stripped.trim().to_lowercase();
    lowered == "--new" || lowered.starts_with("--new=")
}

pub fn looks_like_profile_line(stripped: &str) -> bool {
    MATCH_PREFIXES
        .iter()
        .chain(DIRECTIVE_PREFIXES.iter())
        .chain(["--payload=", "--in-range", "--out-range", "--lua-desync="].iter())
        .chain(WINWS1_STRATEGY_PREFIXES.iter())
        .any(|prefix| stripped.starts_with(prefix))
}

/// Вид строки профиля: blank, comment, directive, match, strategy_filter,
/// strategy, strategy_tail (продолжение стратегии winws1) или other.
pub fn profile_line_kind(stripped: &str, engine: &str, saw_strategy: bool) -> &'static str {
    if stripped.is_empty() {
        return "blank";
    }
    if stripped.starts_with('#') {
        return "comment";
    }
    if is_directive(stripped) {
        return "directive";
    }
    if is_match_line(stripped) {
        return "match";
    }
    if is_strategy_filter_line(stripped, engine) {
        return "strategy_filter";
    }
    if is_strategy_line(stripped, engine) {
        return "strategy";
    }
    if engine == ENGINE_WINWS1 && saw_strategy {
        return "strategy_tail";
    }
    "other"
}

fn is_directive(stripped: &str) -> bool {
    DIRECTIVE_PREFIXES.iter().any(|prefix| stripped.starts_with(prefix))
}

/// Имя — у winws1 это --comment, у winws2 — --name.
fn is_profile_name_directive(engine: &str, directive_name: &str) -> bool {
    let name = directive_name.trim().to_lowercase();
    if engine == ENGINE_WINWS1 {
        return name == "--comment";
    }
    name == "--name"
}

fn is_match_line(stripped: &str) -> bool {
    MATCH_PREFIXES.iter().any(|prefix| stripped.starts_with(prefix))
}

fn is_strategy_filter_line(stripped: &str, engine: &str) -> bool {
    if engine != ENGINE_WINWS2 {
        return false;
    }
    let lowered = stripped.to_lowercase();
    lowered.starts_with("--payload=")
        || lowered.starts_with("--in-range")
        || lowered.starts_with("--out-range")
}

fn is_strategy_line(stripped: &str, engine: &str) -> bool {
    let lowered = stripped.to_lowercase();
    if engine == ENGINE_WINWS2 {
        return lowered.starts_with("--lua-desync=");
    }
    WINWS1_STRATEGY_PREFIXES.iter().any(|prefix| lowered.starts_with(prefix))
}

/// Разрезка на имя и значение по первому «=» (python _split_option).
pub fn split_option(line: &str) -> (String, String) {
    let stripped = line.trim();
    if !stripped.contains('=') {
        return (stripped.to_string(), String::new());
    }
    let (name, value) = stripped.split_once('=').expect("равно было проверено");
    (name.trim().to_string(), value.trim().to_string())
}

/// Разнесение match-строки по корзинам (python _add_match_line).
pub fn add_match_line(match_section: &mut ProfileMatch, line: &str) {
    let lowered = line.to_lowercase();
    if lowered.starts_with("--filter-") {
        match_section.filter_lines.push(line.to_string());
    } else if lowered.starts_with("--hostlist=") {
        match_section.hostlist_lines.push(line.to_string());
    } else if lowered.starts_with("--ipset=") {
        match_section.ipset_lines.push(line.to_string());
    } else if lowered.starts_with("--hostlist-exclude=")
        || lowered.starts_with("--hostlist-exclude-domains=")
    {
        match_section.hostlist_exclude_lines.push(line.to_string());
    } else if lowered.starts_with("--hostlist-auto=") {
        match_section.hostlist_auto_lines.push(line.to_string());
    } else if lowered.starts_with("--ipset-exclude=") || lowered.starts_with("--ipset-exclude-ip=")
    {
        match_section.ipset_exclude_lines.push(line.to_string());
    } else if lowered.starts_with("--hostlist-domains=") {
        match_section.hostlist_domains_lines.push(line.to_string());
    } else if lowered.starts_with("--ipset-ip=") {
        match_section.inline_ipset_lines.push(line.to_string());
    } else {
        match_section.other_lines.push(line.to_string());
    }
}

/// Одна строка профиля → сегмент с «картой» текста (text/name/value).
fn profile_segment(kind: &'static str, text: &str, name: &str, value: &str) -> ProfileSegment {
    ProfileSegment {
        kind: kind.to_string(),
        text: text.to_string(),
        name: name.to_string(),
        value: value.to_string(),
    }
}

/// Разбор одного профиля (python _parse_profile).
pub fn parse_profile(lines: &[String], engine: &str, index: usize, new_line: &str) -> Profile {
    let mut segments: Vec<ProfileSegment> = Vec::new();
    let mut match_section = ProfileMatch::default();
    let mut strategy_lines: Vec<String> = Vec::new();
    let mut name = name_from_new_line(new_line);
    let mut enabled = true;
    let mut saw_strategy = false;

    for raw in lines {
        let stripped = raw.trim();
        let kind = profile_line_kind(stripped, engine, saw_strategy);
        match kind {
            "blank" => segments.push(profile_segment("blank", raw, "", "")),
            "comment" => segments.push(profile_segment("comment", raw, "", "")),
            "directive" => {
                let (option_name, option_value) = split_option(stripped);
                if is_profile_name_directive(engine, &option_name) {
                    if !option_value.is_empty() {
                        name = option_value.clone();
                    }
                }
                if option_name == "--skip" {
                    enabled = false;
                }
                segments.push(profile_segment("directive", stripped, &option_name, &option_value));
            }
            "match" => {
                add_match_line(&mut match_section, stripped);
                let (option_name, option_value) = split_option(stripped);
                segments.push(profile_segment("match", stripped, &option_name, &option_value));
            }
            "strategy_filter" => {
                strategy_lines.push(stripped.to_string());
                saw_strategy = true;
                let (option_name, option_value) = split_option(stripped);
                segments.push(profile_segment("strategy_filter", stripped, &option_name, &option_value));
            }
            "strategy" => {
                strategy_lines.push(stripped.to_string());
                saw_strategy = true;
                let (option_name, option_value) = split_option(stripped);
                segments.push(profile_segment("strategy", stripped, &option_name, &option_value));
            }
            "strategy_tail" => {
                strategy_lines.push(stripped.to_string());
                let (option_name, option_value) = split_option(stripped);
                segments.push(profile_segment("strategy", stripped, &option_name, &option_value));
            }
            _ => {
                add_match_line(&mut match_section, stripped);
                let (option_name, option_value) = split_option(stripped);
                segments.push(profile_segment("match", stripped, &option_name, &option_value));
            }
        }
    }

    let strategy: Strategy = if engine == ENGINE_WINWS2 {
        Strategy::Winws2(parse_winws2_strategy(&strategy_lines))
    } else {
        Strategy::Winws1(parse_winws1_strategy(&strategy_lines))
    };
    let match_signature = build_match_signature(&match_section);
    let display_name = if name.is_empty() {
        infer_profile_display_name(&match_section, index)
    } else {
        name.clone()
    };
    Profile {
        id: format!("profile:{index}"),
        index: index as i64,
        engine: engine.to_string(),
        display_name,
        enabled,
        matched: Some(match_section),
        strategy: Some(strategy),
        segments,
        new_line: new_line.to_string(),
        name,
        match_signature,
        persistent_key: String::new(),
    }
}

/// Имя профиля из строки --new="…"/--new=… (python _name_from_new_line).
pub fn name_from_new_line(new_line: &str) -> String {
    let stripped = new_line.trim();
    if stripped.to_lowercase().starts_with("--new=") {
        let value = stripped.split_once('=').map(|(_, value)| value).unwrap_or("");
        let mut value = value.trim().to_string();
        // python: value.strip().strip('"').strip("'").
        value = value.trim_matches('"').to_string();
        value = value.trim_matches('\'').to_string();
        return value;
    }
    String::new()
}

/// Ключ персистентности обязан быть уникален в пределах пресета — им
/// ключуются мета папок/рейтингов и состояние стратегий в settings.sqlite3.
pub fn assign_profile_keys(profiles: &mut Vec<Profile>) {
    // Группируем основы по базовому ключу (python _assign_profile_keys).
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, profile) in profiles.iter().enumerate() {
        let base = build_profile_persistent_key(&profile.name, &profile.match_signature);
        groups.entry(base).or_default().push(index);
    }
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let groups_vector: Vec<(String, Vec<usize>)> = groups.into_iter().collect();
    for (base, indexes) in &groups_vector {
        let holder = *indexes
            .iter()
            .min_by(|left, right| {
                let left_key = logic_key(&list_at(profiles, **left));
                let right_key = logic_key(&list_at(profiles, **right));
                compare_pair(&left_key, **left, &right_key, **right)
            })
            .expect("группа не пуста");
        profiles[holder].persistent_key = base.clone();
        bump(&mut seen, base);
        for index in indexes {
            if *index == holder {
                continue;
            }
            let candidate = format!("{base}|{}", logic_key(&list_at(profiles, *index)));
            let occurrence = seen.get(&candidate).copied().unwrap_or(0);
            seen.insert(candidate.clone(), occurrence + 1);
            let assigned = if occurrence == 0 {
                candidate.clone()
            } else {
                format!("{candidate}#{}", occurrence + 1)
            };
            profiles[*index].persistent_key = assigned;
        }
    }
}

fn list_at(profiles: &[Profile], index: usize) -> String {
    profiles
        .get(index)
        .map(|profile| profile.match_signature.clone())
        .unwrap_or_default()
}

fn compare_pair(
    left_key: &String,
    left_index: usize,
    right_key: &String,
    right_index: usize,
) -> std::cmp::Ordering {
    left_key.cmp(right_key).then(left_index.cmp(&right_index))
}

fn logic_key(match_signature: &str) -> String {
    build_profile_logical_key(match_signature)
}

fn bump(seen: &mut BTreeMap<String, usize>, key: &str) {
    let value = seen.get(key).copied().unwrap_or(0);
    seen.insert(key.to_string(), value + 1);
}

/// Подпись match-секции: python build_match_signature.
pub fn build_match_signature(match_section: &ProfileMatch) -> String {
    let mut normalized: Vec<String> = Vec::new();
    let mut primary_lines: Vec<String> = Vec::new();
    for batch in [
        &match_section.hostlist_lines,
        &match_section.ipset_lines,
        &match_section.hostlist_domains_lines,
        &match_section.inline_ipset_lines,
    ] {
        primary_lines.extend(batch.iter().cloned());
    }
    let mut identity_lines: Vec<String> = Vec::new();
    identity_lines.extend(match_section.filter_lines.iter().cloned());
    identity_lines.extend(primary_lines.iter().cloned());
    if primary_lines.is_empty() {
        identity_lines.extend(match_section.hostlist_exclude_lines.iter().cloned());
        identity_lines.extend(match_section.ipset_exclude_lines.iter().cloned());
    }
    for line in identity_lines {
        let mut stripped = line.trim().to_lowercase();
        if stripped.is_empty() {
            continue;
        }
        if let Some((name, value)) = stripped.clone().split_once('=') {
            // python: value обрабатывается по спискам опций, а затем слитая
            // пара ПЕРЕсобирается всегда (снятие --/--filter- у имени).
            let mut value_owned: String = value.to_string();
            if let Some(rebuilt) = signature_value(name.trim(), &value_owned) {
                value_owned = rebuilt;
            }
            stripped = format!("{}={}", signature_option_name(name.trim()), value_owned);
        }
        normalized.push(stripped);
    }
    let set: BTreeMap<String, ()> = normalized.into_iter().map(|entry| (entry, ())).collect();
    set.into_keys().collect::<Vec<_>>().join("|")
}

/// Полоска кавычек справа и слева, как'veil python strip('"').strip("'").
fn cleaning_tilde_and_quotes(value: &str) -> String {
    let mut cleaned = value.trim_matches('"').to_string();
    cleaned = cleaned.trim_matches('\'').to_string();
    cleaned
}

/// python: name с обходом --filter- и общего -- префикса.
fn signature_option_name(name: &str) -> String {
    let clean = name.trim().to_lowercase();
    if let Some(rest) = clean.strip_prefix("--filter-") {
        return rest.to_string();
    }
    clean.trim_start_matches("--").to_string()
}

/// Значение пересборки: списки файлов — имя файла;
/// домены/IP — отсортированные токены. None — оставить как есть.
fn signature_value(name: &str, value: &str) -> Option<String> {
    if name == "--hostlist" || name == "--hostlist-exclude" || name == "--hostlist-auto"
        || name == "--ipset" || name == "--ipset-exclude"
    {
        let cleaned = value.trim_start_matches('@');
        let cleaned = cleaning_tilde_and_quotes(cleaned);
        return Some(pure_windows_file_name(&cleaned).to_lowercase());
    }
    if name == "--hostlist-domains"
        || name == "--hostlist-exclude-domains"
        || name == "--ipset-ip"
        || name == "--ipset-exclude-ip"
    {
        let mut tokens: Vec<String> = value
            .split(',')
            .filter(|token| !token.trim().is_empty())
            .map(|token| token.trim().to_lowercase())
            .collect();
        tokens.sort();
        return Some(tokens.join(","));
    }
    None
}

/// Имя пресета если нет --name/--comment (python infer_profile_display_name).
pub fn infer_profile_display_name(match_section: &ProfileMatch, index: usize) -> String {
    let mut base_parts: Vec<String> = Vec::new();
    for (label, option_name) in [
        ("TCP", "--filter-tcp"),
        ("UDP", "--filter-udp"),
        ("L7", "--filter-l7"),
    ] {
        let values = match_values(&match_section.filter_lines, option_name);
        if !values.is_empty() {
            base_parts.push(format!("{label} {}", values.join(",")));
        }
    }
    let base = if base_parts.is_empty() {
        "Без фильтра".to_string()
    } else {
        base_parts.join(" / ")
    };

    let mut suffixes: Vec<String> = Vec::new();
    let simple_hostlist = single_file_name(&match_section.hostlist_lines);
    let simple_ipset = single_file_name(&match_section.ipset_lines);
    let complex_match = is_complex_match(match_section);
    if !simple_hostlist.is_empty() {
        suffixes.push(format!("hostlist {simple_hostlist}"));
    }
    if !simple_ipset.is_empty() {
        suffixes.push(format!("ipset {simple_ipset}"));
    }
    if complex_match {
        suffixes.push("сложный match".to_string());
    }
    if !suffixes.is_empty() {
        return format!("{base} • {}", suffixes.join(" • "));
    }
    if !base.is_empty() {
        base
    } else {
        format!("profile {}", index + 1)
    }
}

/// Значения опции фильтра (python _match_values).
fn match_values(lines: &[String], option_name: &str) -> Vec<String> {
    let prefix = format!("{}=", option_name.to_lowercase());
    let mut values: Vec<String> = Vec::new();
    for line in lines {
        let stripped = line.trim();
        if stripped.to_lowercase().starts_with(&prefix) && stripped.contains('=') {
            let (_, value) = stripped.split_once('=').expect("равно проверено");
            values.push(value.trim().to_string());
        }
    }
    values
}

/// Имя файла из единственной --hostlist=/--ipset= строки (python _single_file_name).
fn single_file_name(lines: &[String]) -> String {
    if lines.len() != 1 {
        return String::new();
    }
    let value = match lines[0].split_once('=') {
        Some((_, value)) => value.trim().to_string(),
        None => String::new(),
    };
    let cleaned = value.trim_start_matches('@').to_string();
    let cleaned = cleaning_tilde_and_quotes(&cleaned);
    pure_windows_file_name(&cleaned)
}

/// Сложный ли match (python _is_complex_match).
fn is_complex_match(match_section: &ProfileMatch) -> bool {
    let list_line_count = match_section.hostlist_lines.len()
        + match_section.ipset_lines.len()
        + match_section.hostlist_domains_lines.len()
        + match_section.inline_ipset_lines.len();
    if list_line_count > 1 {
        return true;
    }
    if !match_section.hostlist_exclude_lines.is_empty() || !match_section.ipset_exclude_lines.is_empty() {
        return true;
    }
    if !match_section.hostlist_auto_lines.is_empty() {
        return true;
    }
    !match_section.other_lines.is_empty()
}

/// PureWindowsPath(value).name в правой упрощённой семантике python.
///
/// Разделитель — оба «\» и «/»; доли «..» и «.» дают пустое имя; хвост
/// слэшей отрезается.
pub fn pure_windows_file_name(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let mut name = value.to_string();
    while name.ends_with('/') || name.ends_with('\\') {
        name.pop();
    }
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_string();
    if name == "." || name == ".." {
        return String::new();
    }
    name
}

// ── Оглавление пресета ───────────────────────── ─ ─ ─ ─ ─

// ── Оглавление пресета ─────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

/// Номера строк одного профиля (с нуля, по всему тексту пресета).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProfileOutline {
    pub new_line: Option<usize>,
    pub lines: Vec<usize>,
    pub name: Vec<usize>,
    pub match_lines: Vec<usize>,
    pub packets: Vec<usize>,
    pub strategy: Vec<usize>,
}

/// Где в тексте пресета какая часть (python PresetOutline).
///
/// Строится теми же правилами, что и parse_preset_text, поэтому обучающий
/// тур показывает пресет ровно так, как его понимает программа.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PresetOutline {
    pub lines: Vec<String>,
    pub header: Vec<usize>,
    pub lua_init: Vec<usize>,
    pub interception: Vec<usize>,
    pub blobs: Vec<usize>,
    pub engine_options: Vec<usize>,
    pub profiles: Vec<ProfileOutline>,
}

pub fn preset_text_outline(text: &str, engine: &str) -> Result<PresetOutline, String> {
    let normalized_engine = normalize_engine(engine)?;
    let lines: Vec<String> = normalize_text(text).split('\n').map(str_to_string).collect();
    let body_start = header_line_count(&lines);
    let header: Vec<usize> =
        (0..body_start).filter(|index| !lines[*index].trim().is_empty()).collect();
    let (preamble, raw_profiles, _footer) =
        split_preamble_and_profile_indices(&lines[body_start..]);

    let mut lua_init: Vec<usize> = Vec::new();
    let mut interception: Vec<usize> = Vec::new();
    let mut blobs: Vec<usize> = Vec::new();
    let mut engine_options: Vec<usize> = Vec::new();
    for body_index in preamble {
        let index = body_start + body_index;
        let stripped = lines[index].trim();
        let lowered = stripped.to_lowercase();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if lowered.starts_with("--lua-init") {
            lua_init.push(index);
        } else if lowered.starts_with("--wf-") {
            interception.push(index);
        } else if lowered.starts_with("--blob=") {
            blobs.push(index);
        } else {
            engine_options.push(index);
        }
    }

    let mut profiles: Vec<ProfileOutline> = Vec::new();
    for (new_line, body_indexes) in raw_profiles {
        let mut name: Vec<usize> = Vec::new();
        let mut match_lines: Vec<usize> = Vec::new();
        let mut packets: Vec<usize> = Vec::new();
        let mut strategy: Vec<usize> = Vec::new();
        let mut content: Vec<usize> = Vec::new();
        let mut saw_strategy = false;
        for body_index in body_indexes {
            let index = body_start + body_index;
            let kind = profile_line_kind(lines[index].trim(), &normalized_engine, saw_strategy);
            if kind == "blank" || kind == "comment" {
                continue;
            }
            content.push(index);
            if kind == "directive" {
                name.push(index);
            } else if kind == "strategy_filter" {
                packets.push(index);
                saw_strategy = true;
            } else if kind == "strategy" || kind == "strategy_tail" {
                strategy.push(index);
                saw_strategy = true;
            } else {
                match_lines.push(index);
            }
        }
        profiles.push(ProfileOutline {
            new_line: match new_line {
                Some(offset) => Some(body_start + offset),
                None => None,
            },
            lines: content,
            name,
            match_lines,
            packets,
            strategy,
        });
    }

    Ok(PresetOutline {
        lines,
        header,
        lua_init,
        interception,
        blobs,
        engine_options,
        profiles,
    })
}
