//! Порт profile/editable_settings.py: читаемые настройки фильтра и диапазонов
//! профиля, их правка и порядок вставки нового профиля.

use serde::{Deserialize, Serialize};

use crate::models::{Preset, Profile, ProfileMatch, ProfileSegment, ENGINE_WINWS1, ENGINE_WINWS2};
use crate::parser::parse_preset_text;
use crate::serializer::serialize_preset;
use crate::winws2_transport::parse_out_range_expression;

const SERVICE_EXCLUDE_LIST_NAMES: [&str; 4] = [
    "ipset-ru.txt",
    "ipset-dns.txt",
    "ipset-exclude.txt",
    "netrogat.txt",
];
const LIST_FILE_EXTENSIONS: [&str; 3] = [".txt", ".lst", ".list"];

const DEFAULT_IN_RANGE: &str = "x";
const DEFAULT_OUT_RANGE: &str = "a";

/// python EditableProfileSettings: настройки профиля, правимость которых
/// видна в интерфейсе.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditableProfileSettings {
    #[serde(default = "default_hostlist")]
    pub filter_kind: String,
    #[serde(default)]
    pub filter_value: String,
    #[serde(default = "default_true")]
    pub filter_editable: bool,
    #[serde(default = "default_primary")]
    pub filter_role: String,
    #[serde(default)]
    pub filter_protocol: String,
    #[serde(default = "default_in_range")]
    pub in_range: String,
    #[serde(default = "default_out_range")]
    pub out_range: String,
}

fn default_hostlist() -> String {
    "hostlist".to_string()
}
fn default_true() -> bool {
    true
}
fn default_primary() -> String {
    "primary".to_string()
}
fn default_in_range() -> String {
    DEFAULT_IN_RANGE.to_string()
}
fn default_out_range() -> String {
    DEFAULT_OUT_RANGE.to_string()
}

impl Default for EditableProfileSettings {
    fn default() -> Self {
        Self {
            filter_kind: default_hostlist(),
            filter_value: String::new(),
            filter_editable: true,
            filter_role: default_primary(),
            filter_protocol: String::new(),
            in_range: default_in_range(),
            out_range: default_out_range(),
        }
    }
}

/// python read_editable_profile_settings.
pub fn read_editable_profile_settings(profile: &Profile) -> EditableProfileSettings {
    let (in_range, out_range) = read_profile_ranges(profile);
    EditableProfileSettings {
        filter_kind: editable_filter_kind(profile),
        filter_value: editable_filter_value(profile),
        filter_editable: editable_filter_is_file_based(profile),
        filter_role: editable_filter_role(profile),
        filter_protocol: editable_filter_protocol(profile),
        in_range,
        out_range,
    }
}

/// python read_profile_ranges: диапазоны профиля до первой --lua-desync.
pub fn read_profile_ranges(profile: &Profile) -> (String, String) {
    if profile.engine != ENGINE_WINWS2 {
        return (DEFAULT_IN_RANGE.to_string(), DEFAULT_OUT_RANGE.to_string());
    }
    let start = first_strategy_line_index(&profile.segments);
    (
        effective_range(&profile.segments, start, "--in-range"),
        effective_range(&profile.segments, start, "--out-range"),
    )
}

/// python with_editable_profile: пресет из одного профиля, правка, разбор назад.
pub fn with_editable_profile(
    profile: &Profile,
    settings: &EditableProfileSettings,
) -> Result<Profile, String> {
    let preset = Preset {
        engine: profile.engine.clone(),
        header_lines: Vec::new(),
        preamble_lines: Vec::new(),
        profiles: vec![profile.clone()],
        source_name: String::new(),
        footer_lines: Vec::new(),
    };
    let updated = with_editable_profile_settings(&preset, 0, settings)?;
    updated
        .profiles
        .into_iter()
        .next()
        .ok_or_else(|| "профиль потерялся при правке".to_string())
}

/// python with_editable_profile_settings: меняет только отличия от текущих настроек.
pub fn with_editable_profile_settings(
    preset: &Preset,
    profile_index: usize,
    settings: &EditableProfileSettings,
) -> Result<Preset, String> {
    if preset.engine != ENGINE_WINWS1 && preset.engine != ENGINE_WINWS2 {
        return Err(format!(
            "Unsupported profile preset engine: {}",
            preset.engine
        ));
    }
    let Some(current_profile) = preset.profiles.get(profile_index) else {
        return Err("list index out of range".to_string());
    };

    let mut updated = preset.clone();
    let profile = &mut updated.profiles[profile_index];
    let current = read_editable_profile_settings(current_profile);

    let filter_kind = settings.filter_kind.trim().to_lowercase();
    if filter_kind != "hostlist" && filter_kind != "ipset" {
        return Err("filter_kind must be hostlist or ipset".to_string());
    }
    let mut filter_role = settings.filter_role.trim().to_lowercase();
    if filter_role != "primary" && filter_role != "exclude" {
        filter_role = current.filter_role.clone();
    }

    if current.filter_editable {
        let filter_value =
            normalize_filter_value(&settings.filter_value, &filter_kind, &filter_role);
        if filter_value.is_empty() {
            return Err("filter_value must not be empty".to_string());
        }
        if !filter_value_is_file_reference(&filter_value) {
            return Err("filter_value must point to a list file".to_string());
        }
        if (filter_kind != current.filter_kind)
            || (filter_value != current.filter_value)
            || (filter_role != current.filter_role)
        {
            let filter_lines: Vec<String> = split_filter_values(&filter_value)
                .into_iter()
                .map(|value| {
                    format!(
                        "--{}={}",
                        filter_option_name(&filter_kind, &filter_role),
                        value
                    )
                })
                .collect();
            profile.segments = replace_match_group(
                profile.segments.clone(),
                match_group_names(&current.filter_kind, &current.filter_role),
                filter_lines,
            );
        }
    }

    if updated.engine == ENGINE_WINWS2 {
        profile.segments =
            with_profile_range(profile.segments.clone(), "--in-range", &settings.in_range)?;
        profile.segments =
            with_profile_range(profile.segments.clone(), "--out-range", &settings.out_range)?;
    }

    reparse(&updated)
}

fn editable_filter_kind(profile: &Profile) -> String {
    let match_section: &ProfileMatch = profile.match_section();
    if !match_section.hostlist_lines.is_empty() {
        return "hostlist".to_string();
    }
    if !match_section.ipset_lines.is_empty() {
        return "ipset".to_string();
    }
    if !match_section.hostlist_exclude_lines.is_empty() {
        return "hostlist".to_string();
    }
    if !match_section.ipset_exclude_lines.is_empty() {
        return "ipset".to_string();
    }
    if !match_section.hostlist_domains_lines.is_empty() {
        return "hostlist-domains".to_string();
    }
    if !match_section.inline_ipset_lines.is_empty() {
        return "ipset-ip".to_string();
    }
    "hostlist".to_string()
}

fn editable_filter_value(profile: &Profile) -> String {
    let match_section = profile.match_section();
    let kind = editable_filter_kind(profile);
    let role = editable_filter_role(profile);
    let group_lines: &[String] = match (kind.as_str(), role.as_str()) {
        ("hostlist", "primary") => &match_section.hostlist_lines,
        ("ipset", "primary") => &match_section.ipset_lines,
        ("hostlist", "exclude") => &match_section.hostlist_exclude_lines,
        ("ipset", "exclude") => &match_section.ipset_exclude_lines,
        ("hostlist-domains", "primary") => &match_section.hostlist_domains_lines,
        ("ipset-ip", "primary") => &match_section.inline_ipset_lines,
        _ => &[],
    };
    let value = joined_group_values(group_lines);
    if !value.is_empty() {
        return value;
    }
    for lines in [
        &match_section.hostlist_lines,
        &match_section.hostlist_domains_lines,
        &match_section.ipset_lines,
        &match_section.inline_ipset_lines,
        &match_section.hostlist_exclude_lines,
        &match_section.ipset_exclude_lines,
    ] {
        let value = joined_group_values(lines);
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn joined_group_values(lines: &[String]) -> String {
    let values: Vec<String> = lines
        .iter()
        .filter(|line| line.contains('='))
        .filter_map(|line| line.split_once('='))
        .map(|(_name, value)| value.trim().to_string())
        .collect();
    values.join(",")
}

fn editable_filter_is_file_based(profile: &Profile) -> bool {
    if editable_filter_role(profile) == "exclude" {
        return true;
    }
    for segment in &profile.segments {
        let name = segment.name.trim().to_lowercase();
        if segment.kind == "match"
            && [
                "--hostlist",
                "--ipset",
                "--hostlist-exclude",
                "--ipset-exclude",
            ]
            .contains(&name.as_str())
        {
            return true;
        }
        if segment.kind == "match"
            && [
                "--hostlist-domains",
                "--ipset-ip",
                "--hostlist-exclude-domains",
                "--ipset-exclude-ip",
            ]
            .contains(&name.as_str())
        {
            return false;
        }
    }
    false
}

fn editable_filter_role(profile: &Profile) -> String {
    if is_service_exclusion_profile(profile) {
        "exclude".to_string()
    } else {
        "primary".to_string()
    }
}

fn editable_filter_protocol(profile: &Profile) -> String {
    let mut has_udp = false;
    let mut has_tcp = false;
    for line in &profile.match_section().filter_lines {
        let lowered = line.trim().to_lowercase();
        if lowered.starts_with("--filter-udp=") {
            has_udp = true;
        } else if lowered.starts_with("--filter-tcp=") {
            has_tcp = true;
        }
    }
    if has_udp && !has_tcp {
        return "udp".to_string();
    }
    if has_tcp && !has_udp {
        return "tcp".to_string();
    }
    String::new()
}

/// python new_profile_insert_index: перед исключением RU или профилем «на всё».
pub fn new_profile_insert_index(preset: &Preset) -> usize {
    for (index, profile) in preset.profiles.iter().enumerate() {
        if is_ru_exclusion_profile(profile) || is_catch_all_profile(profile) {
            return index;
        }
    }
    preset.profiles.len()
}

fn is_ru_exclusion_profile(profile: &Profile) -> bool {
    let match_section = profile.match_section();
    for line in match_section
        .hostlist_lines
        .iter()
        .chain(match_section.ipset_lines.iter())
    {
        let (_option, _separator, value) = partition(line);
        for part in value.split(',') {
            if SERVICE_EXCLUDE_LIST_NAMES.contains(&list_file_name(part).as_str()) {
                return true;
            }
        }
    }
    false
}

fn is_catch_all_profile(profile: &Profile) -> bool {
    let match_section = profile.match_section();
    match_section.hostlist_lines.is_empty()
        && match_section.hostlist_domains_lines.is_empty()
        && match_section.ipset_lines.is_empty()
        && match_section.inline_ipset_lines.is_empty()
}

fn list_file_name(value: &str) -> String {
    let cleaned = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches('@');
    cleaned
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn is_service_exclusion_profile(profile: &Profile) -> bool {
    let match_section = profile.match_section();
    if match_section.hostlist_exclude_lines.is_empty()
        && match_section.ipset_exclude_lines.is_empty()
    {
        return false;
    }
    if !match_section.hostlist_lines.is_empty() || !match_section.ipset_lines.is_empty() {
        return false;
    }
    let node_id = [profile.name.trim(), profile.display_name.trim()].join(" ");
    if node_id.to_lowercase().contains("исключ") {
        return true;
    }
    for line in match_section
        .hostlist_exclude_lines
        .iter()
        .chain(match_section.ipset_exclude_lines.iter())
    {
        let (_option, _separator, value) = partition(line);
        for part in value.split(',') {
            if SERVICE_EXCLUDE_LIST_NAMES.contains(&list_file_name(part).as_str()) {
                return true;
            }
        }
    }
    false
}

fn first_strategy_line_index(segments: &[ProfileSegment]) -> usize {
    segments
        .iter()
        .position(|segment| segment.kind == "strategy")
        .unwrap_or(segments.len())
}

fn effective_range(segments: &[ProfileSegment], before_index: usize, option_name: &str) -> String {
    let default = default_range(option_name);
    let mut value = default.clone();
    for segment in segments.iter().take(before_index) {
        if segment.kind == "strategy_filter" && segment.name.trim().to_lowercase() == option_name {
            let clean = segment.value.trim().to_string();
            value = if clean.is_empty() {
                default.clone()
            } else {
                clean
            };
        }
    }
    value
}

fn default_range(option_name: &str) -> String {
    if option_name == "--out-range" {
        DEFAULT_OUT_RANGE.to_string()
    } else {
        DEFAULT_IN_RANGE.to_string()
    }
}

fn last_range_segment_index(
    segments: &[ProfileSegment],
    first: usize,
    stop: usize,
    option_name: &str,
) -> Option<usize> {
    let end = stop.min(segments.len());
    (first..end).rev().find(|&index| {
        let segment = &segments[index];
        segment.kind == "strategy_filter" && segment.name.trim().to_lowercase() == option_name
    })
}

fn range_segment(option_name: &str, expression: &str) -> ProfileSegment {
    ProfileSegment {
        kind: "strategy_filter".to_string(),
        text: format!("{option_name}={expression}"),
        name: option_name.to_string(),
        value: expression.to_string(),
    }
}

fn with_profile_range(
    segments: Vec<ProfileSegment>,
    option_name: &str,
    value: &str,
) -> Result<Vec<ProfileSegment>, String> {
    let requested = canonical_range_expression(option_name, value)?;
    let start = first_strategy_line_index(&segments);
    let previous = effective_range(&segments, start, option_name);
    if same_range(option_name, &previous, &requested) {
        return Ok(segments);
    }
    let mut result = segments;
    if let Some(own_index) = last_range_segment_index(&result, 0, start, option_name) {
        result[own_index] = range_segment(option_name, &requested);
    } else {
        result.insert(
            range_insert_index(&result, start),
            range_segment(option_name, &requested),
        );
    }
    Ok(result)
}

fn range_insert_index(segments: &[ProfileSegment], first_strategy_index: usize) -> usize {
    if first_strategy_index < segments.len() {
        return first_strategy_index;
    }
    let mut insert_at = segments.len();
    while insert_at > 0 && segments[insert_at - 1].kind == "blank" {
        insert_at -= 1;
    }
    insert_at
}

fn same_range(option_name: &str, left: &str, right: &str) -> bool {
    let canonical = |value: &str| canonical_range_expression(option_name, value).ok();
    match (canonical(left), canonical(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn match_group_names(filter_kind: &str, filter_role: &str) -> Vec<String> {
    let kind = filter_kind.trim().to_lowercase();
    if filter_role.trim().to_lowercase() == "exclude" {
        return if kind == "ipset" {
            vec!["--ipset-exclude", "--ipset-exclude-ip"]
        } else {
            vec!["--hostlist-exclude", "--hostlist-exclude-domains"]
        }
        .into_iter()
        .map(str::to_string)
        .collect();
    }
    vec![format!("--{kind}")]
}

/// python _replace_match_group: замена одной группы match-строк.
fn replace_match_group(
    segments: Vec<ProfileSegment>,
    group_names: Vec<String>,
    filter_lines: Vec<String>,
) -> Vec<ProfileSegment> {
    let replacement: Vec<ProfileSegment> = filter_lines
        .into_iter()
        .map(|line| {
            let (name, value) = split_option(&line);
            ProfileSegment {
                kind: "match".to_string(),
                text: line.clone(),
                name,
                value,
            }
        })
        .collect();
    let mut result: Vec<ProfileSegment> = Vec::new();
    let mut insert_at: Option<usize> = None;
    let mut strategy_insert_at: Option<usize> = None;
    for segment in segments {
        let name = segment.name.trim().to_lowercase();
        if segment.kind == "match" && group_names.iter().any(|known| known == &name) {
            if insert_at.is_none() {
                insert_at = Some(result.len());
            }
            continue;
        }
        if strategy_insert_at.is_none()
            && (segment.kind == "strategy_filter" || segment.kind == "strategy")
        {
            strategy_insert_at = Some(result.len());
        }
        result.push(segment);
    }

    let insert_at = insert_at.or(strategy_insert_at).unwrap_or(result.len());
    result.splice(insert_at..insert_at, replacement);
    result
}

fn canonical_range_expression(option_name: &str, value: &str) -> Result<String, String> {
    let raw_line = format!("{option_name}={value}");
    let parsed = parse_out_range_expression(value, &raw_line);
    match parsed {
        Some(settings) => Ok(settings.expression),
        None => Err(format!(
            "Invalid {ENGINE_WINWS2} packet range value: {value}"
        )),
    }
}

/// python normalize_filter_value: без пустых значений внутри.
pub fn normalize_filter_value(value: &str, filter_kind: &str, filter_role: &str) -> String {
    let _ = filter_role;
    let _ = filter_kind;
    let raw = value.trim().to_string();
    if raw.is_empty() {
        return String::new();
    }
    if raw.contains(',') {
        return raw
            .split(',')
            .filter_map(|item| {
                let item = item.trim().to_string();
                (!item.is_empty()).then_some(item)
            })
            .collect::<Vec<String>>()
            .join(",");
    }
    raw
}

/// python filter_value_is_file_reference: все значения — ссылки на файлы списков.
pub fn filter_value_is_file_reference(value: &str) -> bool {
    let parts = split_filter_values(value);
    !parts.is_empty()
        && parts
            .iter()
            .all(|part| single_filter_value_is_file_reference(part))
}

fn single_filter_value_is_file_reference(value: &str) -> bool {
    let raw = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches('@');
    if raw.is_empty() || raw.contains("://") {
        return false;
    }
    let file_name = raw
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return false;
    }
    LIST_FILE_EXTENSIONS
        .iter()
        .any(|ext| file_name.to_lowercase().ends_with(ext))
}

fn filter_option_name(filter_kind: &str, filter_role: &str) -> String {
    if filter_role == "exclude" {
        return format!("{filter_kind}-exclude");
    }
    filter_kind.to_string()
}

/// python _split_filter_values: разбить значение фильтра на части.
pub fn split_filter_values(filter_value: &str) -> Vec<String> {
    filter_value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

fn split_option(line: &str) -> (String, String) {
    match line.split_once('=') {
        Some((name, value)) => (name.trim().to_string(), value.trim().to_string()),
        None => (line.to_string(), String::new()),
    }
}

fn partition(line: &str) -> (&str, &str, &str) {
    match line.find('=') {
        Some(index) => (&line[..index], &line[index..index + 1], &line[index + 1..]),
        None => (line, "", ""),
    }
}

fn reparse(preset: &Preset) -> Result<Preset, String> {
    parse_preset_text(
        &serialize_preset(preset),
        &preset.engine,
        &preset.source_name,
    )
}
