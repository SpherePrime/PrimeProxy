//! Порт `src/profile/serializer.py` — операции над пресетом: текст →
//! включённость, стратегия, match, добавление/копирование/удаление/сдвиг
//! профилей, сырой текст профиля.

use regex::Regex;

use crate::models::{Preset, Profile, ProfileSegment, Strategy, ENGINE_WINWS1, ENGINE_WINWS2};
use crate::parser::{name_from_new_line, parse_preset_text, split_option};
use crate::strategy_shape::{strategy_shape, union_payload, PAYLOAD_OPTION, RANGE_OPTIONS};

const STRATEGY_KINDS: [&str; 2] = ["strategy", "strategy_filter"];
const LIST_FILE_MATCH_NAMES: [&str; 5] = [
    "--hostlist",
    "--ipset",
    "--hostlist-exclude",
    "--ipset-exclude",
    "--hostlist-auto",
];

/// Текст пресета (python serialize_preset).
pub fn serialize_preset(preset: &Preset) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.extend(preset.header_lines.iter().cloned());
    lines.extend(preset.preamble_lines.iter().cloned());

    for profile in &preset.profiles {
        let segments = profile.segments.iter();
        if !profile.new_line.is_empty() {
            while lines
                .last()
                .map(|last| last.trim().is_empty())
                .unwrap_or(false)
            {
                lines.pop();
            }
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push(profile.new_line.clone());
            lines.push(String::new());
        }
        for segment in segments {
            if segment.kind == "blank" {
                continue;
            }
            lines.push(segment.text.clone());
        }
    }
    lines.extend(preset.footer_lines.iter().cloned());

    while lines
        .last()
        .map(|last| last.trim().is_empty())
        .unwrap_or(false)
    {
        lines.pop();
    }
    format!("{}\n", lines.join("\n"))
}

/// python _reparse: круглый цикл «текст → разбор».
fn reparse(preset: &Preset) -> Result<Preset, String> {
    parse_preset_text(
        &serialize_preset(preset),
        &preset.engine,
        &preset.source_name,
    )
}

fn is_skip(segment: &ProfileSegment) -> bool {
    segment.kind == "directive" && segment.text.trim().to_lowercase() == "--skip"
}

/// Пресет, где профиль включён/выключен (python with_profile_enabled).
pub fn with_profile_enabled(
    preset: &Preset,
    profile_index: usize,
    enabled: bool,
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let profile = &mut updated.profiles[profile_index];
    profile.enabled = enabled;
    let has_skip = profile.segments.iter().any(is_skip);
    if enabled {
        profile.segments.retain(|segment| !is_skip(segment));
        return reparse(&updated);
    }
    if !has_skip {
        let insert_at = directive_insert_index(profile);
        profile.segments.insert(
            insert_at,
            ProfileSegment {
                kind: "directive".to_string(),
                text: "--skip".to_string(),
                name: "--skip".to_string(),
                value: String::new(),
            },
        );
    }
    reparse(&updated)
}

/// Стратегия профиля заменена строками (python with_profile_strategy_lines).
pub fn with_profile_strategy_lines(
    preset: &Preset,
    profile_index: usize,
    strategy_lines: &[String],
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let engine = updated.engine.clone();
    let profile = &mut updated.profiles[profile_index];
    let normalized_lines: Vec<String> = strategy_lines
        .iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    let normalized_lines =
        preserve_missing_winws2_strategy_filters(&engine, profile, normalized_lines);
    let replacement_segments: Vec<ProfileSegment> = normalized_lines
        .iter()
        .map(|line| segment_for_strategy_line(&engine, line))
        .collect();

    let mut first_strategy_index: Option<usize> = None;
    let mut kept: Vec<ProfileSegment> = Vec::new();
    for segment in profile.segments.iter() {
        if STRATEGY_KINDS.contains(&segment.kind.as_str()) {
            if first_strategy_index.is_none() {
                first_strategy_index = Some(kept.len());
            }
            continue;
        }
        kept.push(segment.clone());
    }

    let mut insert_at = first_strategy_index.unwrap_or(kept.len());
    if !replacement_segments.is_empty() {
        while insert_at > 0
            && kept.get(insert_at - 1).map(|segment| segment.kind.as_str()) == Some("blank")
        {
            kept.remove(insert_at - 1);
            insert_at -= 1;
        }
    }
    profile.segments = [
        kept[..insert_at].to_vec(),
        replacement_segments,
        kept[insert_at..].to_vec(),
    ]
    .concat();
    reparse(&updated)
}

/// Пресет, где стратегия профиля (winws2) заменена строками целиком
/// (python with_profile_whole_strategy, пояснения — там).
pub fn with_profile_whole_strategy(
    preset: &Preset,
    profile_index: usize,
    strategy_lines: &[String],
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let engine = updated.engine.clone();
    let profile = &mut updated.profiles[profile_index];
    let replacement: Vec<ProfileSegment> = strategy_lines
        .iter()
        .map(|raw| raw.trim().to_string())
        .filter(|line| !line.is_empty())
        .map(|line| segment_for_strategy_line(&engine, &line))
        .collect();
    let first_lua = profile
        .segments
        .iter()
        .position(|segment| segment.kind == "strategy");
    let segments = &profile.segments;
    let mut kept: Vec<ProfileSegment> = Vec::new();
    let mut first_removed: Option<usize> = None;
    let mut after_last_profile_range: Option<usize> = None;
    for (index, segment) in segments.iter().enumerate() {
        if STRATEGY_KINDS.contains(&segment.kind.as_str()) {
            let is_profile_range = segment.kind == "strategy_filter"
                && RANGE_OPTIONS.contains(&segment.name.trim().to_lowercase().as_str())
                && (first_lua.is_none() || index < first_lua.unwrap());
            if !is_profile_range {
                if first_removed.is_none() {
                    first_removed = Some(kept.len());
                }
                continue;
            }
            kept.push(segment.clone());
            after_last_profile_range = Some(kept.len());
            continue;
        }
        kept.push(segment.clone());
    }

    let insert_at = match first_removed {
        None => {
            let mut insert_at = kept.len();
            while insert_at > 0 && kept[insert_at - 1].kind == "blank" {
                insert_at -= 1;
            }
            insert_at
        }
        Some(first_removed) => first_removed,
    };
    // Диапазоны профиля должны остаться ДО первой --lua-desync новой стратегии.
    let insert_at = match after_last_profile_range {
        Some(range_position) => insert_at.max(range_position),
        None => insert_at,
    };
    profile.segments = [
        kept[..insert_at].to_vec(),
        replacement,
        kept[insert_at..].to_vec(),
    ]
    .concat();
    reparse(&updated)
}

/// Пресет с выбранной готовой стратегией у профиля (python
/// with_profile_ready_strategy) — единое правило для страницы профиля
/// и «PrimeApply» в blockcheck. Второй элемент — строки стратегии,
/// записанные целиком (для проверки после записи), None — если заменены
/// только строки ``--lua-desync``.
pub fn with_profile_ready_strategy(
    preset: &Preset,
    profile_index: usize,
    strategy_lines: &[String],
) -> Result<(Preset, Option<Vec<String>>), String> {
    let lines: Vec<String> = strategy_lines
        .iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if preset.engine == ENGINE_WINWS2 {
        let profile = preset
            .profiles
            .get(profile_index)
            .ok_or_else(|| format!("Profile index out of range: {profile_index}"))?;
        let current_shape = match &profile.strategy {
            Some(Strategy::Winws2(inner)) => strategy_shape(&inner.strategy_lines),
            _ => strategy_shape(&[]),
        };
        let whole: Option<Vec<String>> = if strategy_shape(&lines).composite {
            Some(lines.clone())
        } else if current_shape.composite {
            Some(
                [
                    vec![format!(
                        "{PAYLOAD_OPTION}={}",
                        union_payload(&current_shape.payload_scopes)
                    )],
                    lines.clone(),
                ]
                .concat(),
            )
        } else {
            None
        };
        if let Some(whole_lines) = whole {
            let updated = with_profile_whole_strategy(preset, profile_index, &whole_lines)?;
            return Ok((updated, Some(whole_lines)));
        }
    }
    Ok((
        with_profile_strategy_lines(preset, profile_index, &lines)?,
        None,
    ))
}

fn segment_for_strategy_line(engine: &str, line: &str) -> ProfileSegment {
    let lowered = line.to_lowercase();
    if engine == ENGINE_WINWS2
        && (lowered.starts_with("--payload=")
            || lowered.starts_with("--in-range")
            || lowered.starts_with("--out-range"))
    {
        let (name, value) = split_option(line);
        return ProfileSegment {
            kind: "strategy_filter".to_string(),
            text: line.to_string(),
            name,
            value,
        };
    }
    let (name, value) = split_option(line);
    ProfileSegment {
        kind: "strategy".to_string(),
        text: line.to_string(),
        name,
        value,
    }
}

fn segment_for_match_line(line: &str) -> ProfileSegment {
    let (name, value) = split_option(line);
    ProfileSegment {
        kind: "match".to_string(),
        text: line.to_string(),
        name,
        value,
    }
}

/// Пресет с переписанными match-данными профиля (python with_profile_user_match).
pub fn with_profile_user_match(
    preset: &Preset,
    profile_index: usize,
    name: &str,
    protocol: &str,
    ports: &str,
    hostlist: &str,
    ipset: &str,
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let clean_name = name.trim().to_string();
    let clean_protocol = protocol.trim().to_lowercase();
    let clean_ports = ports.trim().to_string();
    let hostlist = hostlist.trim().to_string();
    let ipset = ipset.trim().to_string();
    if clean_protocol != "tcp" && clean_protocol != "udp" && clean_protocol != "l7" {
        return Err("protocol must be tcp, udp or l7".to_string());
    }
    if clean_name.is_empty() || clean_ports.is_empty() {
        return Err("name and ports are required".to_string());
    }

    let engine = updated.engine.clone();
    let profile = &mut updated.profiles[profile_index];
    let filter_line = format!("--filter-{clean_protocol}={clean_ports}");
    let name_directive = profile_name_directive_name(&engine);
    let mut name_written = false;
    let mut filter_written = false;
    let mut list_written = false;
    let mut insert_at: Option<usize> = None;
    let mut result: Vec<ProfileSegment> = Vec::new();

    for segment in profile.segments.clone() {
        let segment_name = segment.name.trim().to_lowercase();
        if segment.kind == "directive" && segment_name == name_directive {
            result.push(profile_name_segment(&engine, &clean_name));
            name_written = true;
            continue;
        }
        if segment.kind == "match" && segment_name.starts_with("--filter-") {
            if !filter_written {
                result.push(segment_for_match_line(&filter_line));
                filter_written = true;
            }
            continue;
        }
        if segment.kind == "match" && (segment_name == "--hostlist" || segment_name == "--ipset") {
            if segment_name == "--ipset" {
                if !ipset.is_empty() {
                    result.push(segment_for_match_line(&format!("--ipset={ipset}")));
                    list_written = true;
                }
                continue;
            }
            if !hostlist.is_empty() {
                result.push(segment_for_match_line(&format!("--hostlist={hostlist}")));
                list_written = true;
            }
            continue;
        }
        if insert_at.is_none()
            && matches!(
                segment.kind.as_str(),
                "match" | "strategy_filter" | "strategy"
            )
        {
            insert_at = Some(result.len());
        }
        result.push(segment);
    }

    if !name_written {
        result.insert(
            directive_insert_index_for_segments(&result),
            profile_name_segment(&engine, &clean_name),
        );
    }
    if !filter_written {
        let insert = first_strategy_or_end_index(&result);
        result.insert(insert, segment_for_match_line(&filter_line));
    }
    if !list_written && !hostlist.is_empty() {
        let insert = first_strategy_or_end_index(&result);
        result.insert(
            insert,
            segment_for_match_line(&format!("--hostlist={hostlist}")),
        );
    }

    profile.segments = result;
    reparse(&updated)
}

/// Фильтеры начала стратегии сохраняются, если новых способов нет
/// (python _preserve_missing_winws2_strategy_filters).
pub fn preserve_missing_winws2_strategy_filters(
    engine: &str,
    profile: &Profile,
    strategy_lines: Vec<String>,
) -> Vec<String> {
    if engine != ENGINE_WINWS2 {
        return strategy_lines;
    }
    let wanted_names = ["--payload", "--in-range", "--out-range"];
    let provided: Vec<String> = strategy_lines
        .iter()
        .map(|line| split_option(line).0.trim().to_lowercase())
        .collect();
    // Фильтеры, которые стоят ДО первой строки стратегии — они задают, куда
    // применяется начало стратегии. Из подряд идущих действует последний
    // (питонов словарь держит последний по порядку).
    let mut leading: Vec<(String, String)> = Vec::new();
    for segment in &profile.segments {
        if segment.kind == "strategy" {
            break;
        }
        if segment.kind != "strategy_filter" {
            continue;
        }
        let name = segment.name.trim().to_lowercase();
        if !wanted_names.contains(&name.as_str()) || provided.contains(&name) {
            continue;
        }
        let text = segment.text.trim().to_string();
        if text.is_empty() {
            continue;
        }
        leading.retain(|(kind, _)| kind != &name);
        leading.push((name, text));
    }
    leading
        .into_iter()
        .map(|(_, text)| text)
        .chain(strategy_lines)
        .collect()
}

/// Вставка профиля из шаблона: "top", "bottom" или индекс (python
/// append_profile_from_template).
pub fn append_profile_from_template(
    preset: &Preset,
    template: &Profile,
    enabled: bool,
    position: &Position,
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    let insert_at = template_insert_index(position, updated.profiles.len())?;
    let needs_blank = !updated.profiles.is_empty()
        && insert_at == updated.profiles.len()
        && updated
            .profiles
            .last()
            .map(|profile| {
                !profile.segments.is_empty()
                    && profile
                        .segments
                        .last()
                        .map(|segment| !segment.text.trim().is_empty())
                        .unwrap_or(false)
            })
            .unwrap_or(false);
    if needs_blank {
        if let Some(last) = updated.profiles.last_mut() {
            last.segments.push(ProfileSegment {
                kind: "blank".to_string(),
                ..ProfileSegment::default()
            });
        }
    }
    let mut profile = template.clone();
    profile.index = insert_at as i64;
    profile.engine = updated.engine.clone();
    profile.new_line = if insert_at == 0 {
        String::new()
    } else {
        "--new".to_string()
    };
    profile.segments.retain(|segment| !is_skip(segment));
    canonicalize_template_match_paths(&mut profile);
    if !enabled {
        profile.segments.insert(
            directive_insert_index(&profile),
            ProfileSegment {
                kind: "directive".to_string(),
                text: "--skip".to_string(),
                name: "--skip".to_string(),
                value: String::new(),
            },
        );
    }
    ensure_safe_default_strategy(&mut profile);
    insert_profile_position_or_bottom(&mut updated, insert_at, profile);
    ensure_profile_boundaries(&mut updated);
    reparse(&updated)
}

/// Вставка профиля (WELDED индекс может равняться длине).
fn insert_profile_position_or_bottom(preset: &mut Preset, insert_at: usize, profile: Profile) {
    let index = insert_at.min(preset.profiles.len());
    preset.profiles.insert(index, profile);
}

pub enum Position {
    Top,
    Bottom,
    Index(usize),
}

/// Значение границы вставки (python _template_insert_index).
fn template_insert_index(position: &Position, profile_count: usize) -> Result<usize, String> {
    let value = match position {
        Position::Index(index) => (*index).min(profile_count),
        Position::Top => 0,
        Position::Bottom => profile_count,
    };
    Ok(value)
}

/// Пресет без одного профиля (python with_profile_deleted).
pub fn with_profile_deleted(preset: &Preset, profile_index: usize) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    updated.profiles.remove(profile_index);
    ensure_profile_boundaries(&mut updated);
    reparse(&updated)
}

/// Пресет с копией профиля (python with_profile_duplicated).
pub fn with_profile_duplicated(preset: &Preset, profile_index: usize) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let source = updated.profiles[profile_index].clone();
    let mut profile = source.clone();
    profile.index = (profile_index + 1) as i64;
    let unique_name = unique_copy_name(&updated, &source);
    rename_profile_copy(&mut profile, &unique_name);
    insert_profile_position_or_bottom(&mut updated, profile_index + 1, profile);
    ensure_profile_boundaries(&mut updated);
    reparse(&updated)
}

/// Пресет с сдвинутым профилем (python with_profile_moved).
pub fn with_profile_moved(
    preset: &Preset,
    source_index: usize,
    destination_index: usize,
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    let source = source_index;
    let mut destination = destination_index;
    if source >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {source_index}"));
    }
    if destination > updated.profiles.len() {
        destination = updated.profiles.len();
    }
    if source == destination || source + 1 == destination {
        return Ok(updated);
    }
    let profile = updated.profiles.remove(source);
    if source < destination {
        destination -= 1;
    }
    updated.profiles.insert(destination, profile);
    ensure_profile_boundaries(&mut updated);
    reparse(&updated)
}

/// Пресет, в котором профиль заменён сырым текстом (python with_profile_raw_text).
pub fn with_profile_raw_text(
    preset: &Preset,
    profile_index: usize,
    raw_text: &str,
) -> Result<Preset, String> {
    let mut updated = preset.clone();
    if profile_index >= updated.profiles.len() {
        return Err(format!("Profile index out of range: {profile_index}"));
    }
    let text = raw_text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_string();
    if text.is_empty() {
        return Err("profile text must not be empty".to_string());
    }

    // Текст разбирается как профиль после «--new», а не как отдельный
    // пресет: иначе ведущие «# комментарии» улетали бы в шапку пресета.
    let parsed = parse_preset_text(
        &format!("--new\n{text}"),
        &updated.engine,
        &updated.source_name,
    )?;
    if parsed.profiles.len() != 1
        || !parsed.header_lines.is_empty()
        || !parsed.preamble_lines.is_empty()
    {
        return Err("profile text must contain exactly one profile".to_string());
    }

    let mut replacement = parsed.profiles[0].clone();
    replacement.index = profile_index as i64;
    replacement.engine = updated.engine.clone();
    // Граница профиля («--new» / «--new=Имя») не часть его текста —
    // остаётся прежней, вместе с именем, записанным в ней.
    let current_new_line = updated.profiles[profile_index].new_line.clone();
    replacement.new_line = current_new_line.clone();
    if replacement.name.trim().is_empty() {
        replacement.name = name_from_new_line(&current_new_line);
    }
    updated.profiles[profile_index] = replacement;
    ensure_profile_boundaries(&mut updated);
    reparse(&updated)
}

/// Файл-теги match — пути выравниваются в lists/ (python
/// _canonicalize_template_match_paths).
fn canonicalize_template_match_paths(profile: &mut Profile) {
    for segment in profile.segments.iter_mut() {
        let name = segment.name.trim().to_lowercase();
        if segment.kind != "match" || !LIST_FILE_MATCH_NAMES.contains(&name.as_str()) {
            continue;
        }
        let value = lists_relative_value(&segment.value.clone());
        if value == segment.value {
            continue;
        }
        segment.value = value.clone();
        segment.text = format!("{}={}", segment.name.clone(), value);
    }
}

/// python _lists_relative_value.
pub fn lists_relative_value(value: &str) -> String {
    let raw = value.trim().to_string();
    let clean = raw
        .replace('\\', "/")
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    if clean.is_empty() {
        return raw;
    }
    let normalized = clean.replace('\\', "/");
    if normalized.contains('/') || normalized.contains(':') || normalized.starts_with('@') {
        return raw;
    }
    format!("lists/{clean}")
}

fn directive_insert_index_for_segments(segments: &[ProfileSegment]) -> usize {
    for (index, segment) in segments.iter().enumerate() {
        if !["blank", "comment", "directive"].contains(&segment.kind.as_str()) {
            return index;
        }
    }
    segments.len()
}

fn first_strategy_or_end_index(segments: &[ProfileSegment]) -> usize {
    for (index, segment) in segments.iter().enumerate() {
        if segment.kind == "strategy_filter" || segment.kind == "strategy" {
            return index;
        }
    }
    segments.len()
}

/// Индекс первой «дельного» строки (python _directive_insert_index).
fn directive_insert_index(profile: &Profile) -> usize {
    directive_insert_index_for_segments(&profile.segments)
}

/// Уникальное имя копии (python _unique_copy_name).
pub fn unique_copy_name(preset: &Preset, source: &Profile) -> String {
    let base = profile_base_name(source);
    let cleaned = strip_copy_suffix(&base);
    let existing: std::collections::BTreeSet<String> = preset
        .profiles
        .iter()
        .map(|profile| profile_name_or_empty(profile))
        .filter(|name| !name.trim().is_empty())
        .map(|name| name.trim().to_lowercase())
        .collect();
    let mut candidate = format!("{cleaned} копия");
    if !existing.contains(&candidate.to_lowercase()) {
        return candidate;
    }
    let mut counter = 2;
    loop {
        candidate = format!("{cleaned} копия {counter}");
        if !existing.contains(&candidate.to_lowercase()) {
            return candidate;
        }
        counter += 1;
    }
}

fn profile_base_name(source: &Profile) -> String {
    let raw: String = if !source.name.trim().is_empty() {
        source.name.clone()
    } else if !source.display_name.trim().is_empty() {
        source.display_name.clone()
    } else {
        format!("profile {}", source.index + 1)
    };
    if raw.trim().is_empty() {
        "profile".to_string()
    } else {
        raw.trim().to_string()
    }
}

fn profile_name_or_empty(profile: &Profile) -> String {
    if !profile.name.trim().is_empty() {
        profile.name.clone()
    } else {
        profile.display_name.clone()
    }
}

/// python re.sub(r"\s+копия(?:\s+\d+)?$", "", base, flags=re.IGNORECASE).strip() or base
fn strip_copy_suffix(base: &str) -> String {
    let pattern = Regex::new(r"(?i)\s+копия(?:\s+\d+)?\z").expect("постоянный шаблон");
    let without = pattern.replace(base, "");
    let stripped = without.trim().to_string();
    if stripped.is_empty() {
        base.to_string()
    } else {
        stripped
    }
}

/// Итоговые границы профилей (python _ensure_profile_boundaries).
fn ensure_profile_boundaries(preset: &mut Preset) {
    for index in 0..preset.profiles.len() {
        let engine = preset.engine.clone();
        let profile = &mut preset.profiles[index];
        if index == 0 {
            remove_leading_blank_segments(profile);
            ensure_profile_name_directive(profile, &engine);
            profile.new_line = String::new();
            continue;
        }
        if profile_has_name_directive(profile, &engine) {
            profile.new_line = "--new".to_string();
            continue;
        }
        if engine == ENGINE_WINWS1 {
            // winws1 (nfqws1) объявляет --new без аргумента: `--new=имя`
            // не запускается ("option doesn't take an argument -- new").
            profile.new_line = "--new".to_string();
            continue;
        }
        // Только собственное имя профиля (из «--new=Имя»). Отображаемое имя
        // («TCP 443 • hostlist …») вычисляемая подпись интерфейса.
        let name = profile.name.trim().to_string();
        profile.new_line = if name.is_empty() {
            "--new".to_string()
        } else {
            format!("--new={name}")
        };
    }
}

fn ensure_profile_name_directive(profile: &mut Profile, engine: &str) {
    if profile_has_name_directive(profile, engine) {
        return;
    }
    let name = profile.name.trim().to_string();
    if name.is_empty() {
        return;
    }
    let insert_at = directive_insert_index(profile);
    profile
        .segments
        .insert(insert_at, profile_name_segment(engine, &name));
}

fn profile_has_name_directive(profile: &Profile, engine: &str) -> bool {
    let directive_name = profile_name_directive_name(engine);
    profile.segments.iter().any(|segment| {
        segment.kind == "directive" && segment.name.trim().to_lowercase() == directive_name
    })
}

fn profile_name_directive_name(engine: &str) -> String {
    (if engine == ENGINE_WINWS1 {
        "--comment"
    } else {
        "--name"
    })
    .to_string()
}

fn profile_name_segment(engine: &str, name: &str) -> ProfileSegment {
    let directive_name = profile_name_directive_name(engine);
    ProfileSegment {
        kind: "directive".to_string(),
        text: format!("{directive_name}={name}"),
        name: directive_name,
        value: name.to_string(),
    }
}

/// Безопасная стратегия-по-умолчанию для нового профиля · python
/// _ensure_safe_default_strategy.
fn ensure_safe_default_strategy(profile: &mut Profile) {
    if profile.engine != ENGINE_WINWS2 {
        return;
    }
    if profile
        .segments
        .iter()
        .any(|segment| segment.kind == "strategy")
    {
        return;
    }
    let mut insert_at = profile.segments.len();
    while insert_at > 0 && profile.segments[insert_at - 1].kind == "blank" {
        insert_at -= 1;
    }
    profile.segments.insert(
        insert_at,
        ProfileSegment {
            kind: "strategy".to_string(),
            text: "--lua-desync=pass".to_string(),
            name: "--lua-desync".to_string(),
            value: "pass".to_string(),
        },
    );
}

fn remove_leading_blank_segments(profile: &mut Profile) {
    while !profile.segments.is_empty() && profile.segments[0].kind == "blank" {
        profile.segments.remove(0);
    }
}

/// Переименование копии профиля (python _rename_profile_copy).
fn rename_profile_copy(profile: &mut Profile, name: &str) {
    let clean_name = if name.trim().is_empty() {
        "profile копия".to_string()
    } else {
        name.trim().to_string()
    };
    let mut renamed_new_line = false;
    let current_new_line = profile.new_line.trim().to_string();
    if current_new_line.to_lowercase().starts_with("--new=") {
        profile.new_line = format!("--new={clean_name}");
        renamed_new_line = true;
    }

    let directive_name = profile_name_directive_name(&profile.engine);
    for segment in profile.segments.iter_mut() {
        if segment.kind == "directive" && segment.name.trim().to_lowercase() == directive_name {
            segment.value = clean_name.clone();
            segment.text = format!("{}={}", segment.name.clone(), clean_name);
            profile.name = clean_name.clone();
            profile.display_name = clean_name.clone();
            return;
        }
    }

    if renamed_new_line {
        profile.name = clean_name.clone();
        profile.display_name = clean_name.clone();
        return;
    }
    profile.new_line = format!("--new={clean_name}");
    if current_new_line.to_lowercase() != "--new" {
        let insert_at = directive_insert_index(profile);
        profile.segments.insert(
            insert_at,
            profile_name_segment(&profile.engine, &clean_name),
        );
    }
    profile.name = clean_name.clone();
    profile.display_name = clean_name.clone();
}

/// Позиция шаблона из python "top"/"bottom"/int (python str| int).
pub fn position_from(value: &str) -> Result<Position, String> {
    let clean = value.trim().to_lowercase();
    if clean == "top" {
        return Ok(Position::Top);
    }
    if clean == "bottom" {
        return Ok(Position::Bottom);
    }
    if let Ok(index) = value.trim().parse::<usize>() {
        return Ok(Position::Index(index));
    }
    Err(format!("Unsupported template profile position: {value}"))
}
