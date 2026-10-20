//! Порт `src/profile/settings.py` — переключения wssize и debug-лога
//! в выбранном пресете.
//!
//! I/O пресетов отнесён к вызывающей стороне (в python —
//! `profile_services._presets_feature.*`): функции принимают замыкания
//! чтения/записи исходного текста. Проверка метода запуска — на верх.

use regex::Regex;

use crate::models::{Preset, Profile, ProfileSegment, Strategy};

pub const WINWS2_WSSIZE_LINE: &str = "--lua-desync=wssize:wsize=1:scale=6";
pub const WINWS1_WSSIZE_LINES: [&str; 3] = ["--wssize", "1:6", "--wssize-forced-cutoff=0"];

/// python get_wssize_enabled.
pub fn get_wssize_enabled(preset: &Preset) -> bool {
    wssize_targets(preset)
        .iter()
        .any(|profile| profile_has_wssize(profile))
}

fn wssize_targets(preset: &Preset) -> Vec<&Profile> {
    preset
        .profiles
        .iter()
        .filter(|profile| profile.enabled && profile_tcp_includes_443(profile))
        .collect()
}

/// python set_wssize_enabled: true, если файл переписан. Если целевых
/// профилей нет — false при включении и true при выключении (idempotent).
pub fn set_wssize_enabled(preset: &mut Preset, enabled: bool) -> bool {
    let targets = wssize_targets_in_place(preset);
    if targets.is_empty() {
        return !enabled;
    }
    let engine = preset.engine.clone();
    let mut changed = false;
    for index in targets {
        let mut segments = segments_without_wssize(&engine, &preset.profiles[index].segments);
        if enabled {
            segments = segments_with_wssize(&engine, segments);
        }
        if segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            == preset.profiles[index]
                .segments
                .iter()
                .map(|segment| segment.text.as_str())
                .collect::<Vec<_>>()
        {
            continue;
        }
        preset.profiles[index].segments = segments;
        changed = true;
    }
    changed
}

fn wssize_targets_in_place(preset: &Preset) -> Vec<usize> {
    preset
        .profiles
        .iter()
        .enumerate()
        .filter(|(_, profile)| profile.enabled && profile_tcp_includes_443(profile))
        .map(|(index, _)| index)
        .collect()
}

fn wssize_lines_for_engine(engine: &str) -> &'static [&'static str] {
    if engine.trim().to_lowercase() == "winws1" {
        &WINWS1_WSSIZE_LINES
    } else {
        &WINWS2_WSSIZE_LINES_REF
    }
}

static WINWS2_WSSIZE_LINES_REF: [&str; 1] = [WINWS2_WSSIZE_LINE];

/// python _segments_with_wssize: стратегические строки перед первой
/// strategy/strategy_filter (иначе — перед хвостовыми blank).
pub fn segments_with_wssize(engine: &str, segments: Vec<ProfileSegment>) -> Vec<ProfileSegment> {
    let insert_at = segments
        .iter()
        .position(|segment| segment.kind == "strategy" || segment.kind == "strategy_filter")
        .unwrap_or_else(|| {
            let mut at = segments.len();
            while at > 0 && segments[at - 1].kind == "blank" {
                at -= 1;
            }
            at
        });
    let mut wssize_segments: Vec<ProfileSegment> = wssize_lines_for_engine(engine)
        .iter()
        .map(|line| {
            let (name, value) = line.split_once('=').unwrap_or((*line, ""));
            ProfileSegment {
                kind: "strategy".to_string(),
                text: (*line).to_string(),
                name: name.to_string(),
                value: value.to_string(),
            }
        })
        .collect();
    let mut result = Vec::with_capacity(segments.len() + wssize_segments.len());
    result.extend(segments[..insert_at].iter().cloned());
    result.append(&mut wssize_segments);
    result.extend(segments[insert_at..].iter().cloned());
    result
}

/// python _segments_without_wssize: удаляет только строки wssize.
pub fn segments_without_wssize(engine: &str, segments: &[ProfileSegment]) -> Vec<ProfileSegment> {
    let strategy_positions: Vec<usize> = segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.kind == "strategy")
        .map(|(index, _)| index)
        .collect();
    if strategy_positions.is_empty() {
        return segments.to_vec();
    }
    let strategy_texts: Vec<String> = strategy_positions
        .iter()
        .map(|index| segments[*index].text.trim().to_string())
        .collect();
    let kept_texts = remove_wssize_lines_text(engine, &strategy_texts);
    if kept_texts.len() == strategy_texts.len() {
        return segments.to_vec();
    }
    let mut dropped: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut kept_iter = kept_texts.iter();
    let mut next_kept = kept_iter.next();
    for (position, text) in strategy_positions.iter().zip(strategy_texts.iter()) {
        if let Some(kept) = next_kept {
            if text == kept {
                next_kept = kept_iter.next();
                continue;
            }
        }
        dropped.insert(*position);
    }
    segments
        .iter()
        .enumerate()
        .filter(|(index, _)| !dropped.contains(index))
        .map(|(_, segment)| segment.clone())
        .collect()
}

/// python get_debug_log_file по тексту источника.
pub fn extract_debug_log_file(source_text: &str) -> String {
    let text = source_text.replace("\r\n", "\n").replace('\r', "\n");
    for raw in text.split('\n') {
        let stripped = raw.trim();
        if !stripped.to_lowercase().starts_with("--debug=") {
            continue;
        }
        let value = stripped.split_once('=').map_or("", |(_, rest)| rest.trim());
        return value
            .trim_start_matches('@')
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
    }
    String::new()
}

/// python _build_stable_debug_log_file (DEBUG_LOG_DIR от caller-крeйца).
pub fn build_stable_debug_log_file(debug_log_dir: &str, preset_name: &str) -> String {
    static SAFE_NAME: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"[^\w.-]+").expect("regex"));
    let mut safe_name = SAFE_NAME.replace_all(preset_name.trim(), "_").to_string();
    safe_name = safe_name
        .trim_matches(|char| char == '.' || char == '_')
        .to_string();
    if safe_name.is_empty() {
        safe_name = "preset".to_string();
    }
    format!("{debug_log_dir}/{safe_name}_debug.log")
}

/// python _rewrite_debug_log_setting: вставка/уборка `--debug=@файл`.
pub fn rewrite_debug_log_setting(
    source_text: &str,
    debug_log_dir: &str,
    preset_name: &str,
    enabled: bool,
) -> String {
    let text = source_text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = text.split('\n').collect();

    let mut existing_value = String::new();
    let mut existing_insert_at: Option<usize> = None;
    let mut cleaned: Vec<String> = Vec::new();
    for raw in &lines {
        let stripped = raw.trim();
        if stripped.to_lowercase().starts_with("--debug=") {
            if existing_value.is_empty() {
                let value = stripped
                    .split_once('=')
                    .map_or("", |(_, rest)| rest.trim())
                    .trim_start_matches('@')
                    .replace('\\', "/")
                    .trim_start_matches('/')
                    .to_string();
                existing_value = value;
                existing_insert_at = Some(cleaned.len());
            }
            continue;
        }
        cleaned.push((*raw).to_string());
    }

    if enabled {
        let debug_file = if existing_value.is_empty() {
            build_stable_debug_log_file(debug_log_dir, preset_name)
        } else {
            existing_value
        };
        let debug_line = format!("--debug=@{debug_file}");
        let mut insert_at = match existing_insert_at {
            Some(at) => at,
            None => default_debug_insert_index(&cleaned),
        };
        insert_at = insert_at.clamp(0, cleaned.len());
        cleaned.insert(insert_at, debug_line);
    }

    let mut result = cleaned.join("\n");
    while result.ends_with('\n') {
        result.pop();
    }
    result.push('\n');
    result
}

/// python _default_debug_insert_index: после последнего --lua-init, иначе
/// после шапки из комментариев/пустых строк.
fn default_debug_insert_index(lines: &[String]) -> usize {
    let mut insert_at = 0usize;
    for (idx, raw) in lines.iter().enumerate() {
        let stripped = raw.trim();
        if stripped.starts_with("--lua-init=") {
            insert_at = idx + 1;
        }
    }
    if insert_at > 0 {
        return insert_at;
    }
    let mut header_end = 0usize;
    for (idx, raw) in lines.iter().enumerate() {
        let stripped = raw.trim();
        if stripped.starts_with('#') || stripped.is_empty() {
            header_end = idx + 1;
            continue;
        }
        break;
    }
    header_end
}

/// python _profile_has_wssize.
pub fn profile_has_wssize(profile: &Profile) -> bool {
    let engine = profile.engine.trim().to_lowercase();
    let lines: Vec<String> = profile
        .strategy
        .as_ref()
        .map(|strategy| match strategy {
            Strategy::Winws1(w) => &w.strategy_lines,
            Strategy::Winws2(w) => &w.strategy_lines,
        })
        .cloned()
        .unwrap_or_default();
    let lines: Vec<String> = lines
        .iter()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect();
    if engine == "winws1" {
        return lines.iter().any(|line| line.starts_with("--wssize"));
    }
    lines.iter().any(|line| line == WINWS2_WSSIZE_LINE)
}

fn remove_wssize_lines_text(engine: &str, lines: &[String]) -> Vec<String> {
    if engine.trim().to_lowercase() != "winws1" {
        return lines
            .iter()
            .filter(|line| line.to_lowercase() != WINWS2_WSSIZE_LINE)
            .cloned()
            .collect();
    }

    // python re.fullmatch(r"\d+\s*:\s*\d+", lowered) — весь шаблон целиком.
    static VALUE_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"\A\d+\s*:\s*\d+\z").expect("regex"));
    let mut cleaned: Vec<String> = Vec::new();
    let mut skip_next_value = false;
    for line in lines {
        let lowered = line.to_lowercase();
        if skip_next_value && VALUE_RE.is_match(&lowered) {
            skip_next_value = false;
            continue;
        }
        skip_next_value = false;
        if lowered.starts_with("--wssize") {
            if lowered == "--wssize" {
                skip_next_value = true;
            }
            continue;
        }
        cleaned.push(line.clone());
    }
    cleaned
}

/// python _profile_tcp_includes_443.
pub fn profile_tcp_includes_443(profile: &Profile) -> bool {
    let Some(matched) = profile.matched.as_ref() else {
        return false;
    };
    for line in &matched.filter_lines {
        let stripped = line.trim();
        if !stripped.to_lowercase().starts_with("--filter-tcp=") {
            continue;
        }
        let value = stripped.split_once('=').map_or("", |(_, rest)| rest.trim());
        if ports_include_443(value) {
            return true;
        }
    }
    false
}

/// python _ports_include_443.
pub fn ports_include_443(value: &str) -> bool {
    for raw_part in value.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains('-') {
            let Some((start_s, end_s)) = part.split_once('-') else {
                continue;
            };
            let Ok(start) = start_s.trim().parse::<i64>() else {
                continue;
            };
            let Ok(end) = end_s.trim().parse::<i64>() else {
                continue;
            };
            if start <= 443 && 443 <= end {
                return true;
            }
            continue;
        }
        if part.parse::<i64>().map(|port| port == 443).unwrap_or(false) {
            return true;
        }
    }
    false
}
