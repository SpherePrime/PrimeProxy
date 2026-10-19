//! Порт `src/profile/winws2.py` — разбор стратегии WinWS2 из строк:
//! директивы `--payload=`, `--in-range`, `--out-range`, `--lua-desync=`.

use crate::models::{ProfileAction, ProfileActionArg, Winws2Strategy};

/// Разбор строк стратегии WinWS2 (python parse_winws2_strategy).
pub fn parse_winws2_strategy(lines: &[String]) -> Winws2Strategy {
    let mut payload = "all".to_string();
    let mut in_range = "x".to_string();
    let mut out_range = "a".to_string();
    let mut actions: Vec<ProfileAction> = Vec::new();
    let mut other_lines: Vec<String> = Vec::new();

    for raw in lines {
        let line: String = str_of(raw).trim().to_string();
        let lowered = line.to_lowercase();
        if line.is_empty() {
            continue;
        }
        if lowered.starts_with("--payload=") {
            payload = right_side(&line).unwrap_or_default();
            if payload.is_empty() {
                payload = "all".to_string();
            }
            continue;
        }
        if lowered.starts_with("--in-range") {
            in_range = or_default(right_side_maybe(&line), "x");
            continue;
        }
        if lowered.starts_with("--out-range") {
            out_range = or_default(right_side_maybe(&line), "a");
            continue;
        }
        if lowered.starts_with("--lua-desync=") {
            actions.extend(
                split_lua_desync_lines(&line)
                    .into_iter()
                    .map(|action_line| parse_lua_desync(&action_line, &payload, &in_range, &out_range)),
            );
            continue;
        }
        other_lines.push(line);
    }

    let strategy_lines = lines
        .iter()
        .map(|raw| str_of(raw).trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    Winws2Strategy { actions, strategy_lines, other_lines }
}

/// python str(значение or "").
fn str_of(value: &String) -> String {
    value.to_string()
}

/// Правая часть после первого «=», обрезанная (для == и начало строки).
fn right_side(line: &str) -> Option<String> {
    line.split_once('=').map(|(_, value)| value.trim().to_string())
}

/// Правая часть, если «=» есть; иначе None (python: "x"/"a" остаются).
fn right_side_maybe(line: &str) -> Option<String> {
    if !line.contains('=') {
        return None;
    }
    let (value, _) = right_side(line).map(|value| (value, ()))?;
    Some(value)
}

/// Значение или дефолт при пустом (python: `or "x"`), None не превращается
/// в пустую строку — отсутствующее «=» оставляет дефолт тоже.
fn or_default(value: Option<String>, default: &str) -> String {
    match value {
        Some(inner) => if inner.is_empty() { default.to_string() } else { inner },
        None => default.to_string(),
    }
}

/// Хвосты команд между «--lua-desync=» (python _split_lua_desync_lines).
pub fn split_lua_desync_lines(line: &str) -> Vec<String> {
    let stripped = line.trim();
    if stripped.is_empty() {
        return Vec::new();
    }
    const MARKER: &str = "--lua-desync=";
    let lowered = stripped.to_lowercase();
    let mut positions: Vec<usize> = Vec::new();
    let mut search_from = 0;
    loop {
        let index = lowered[search_from..].find(MARKER).map(|offset| offset + search_from);
        match index {
            Some(index) => {
                positions.push(index);
                search_from = index + MARKER.len();
            }
            None => break,
        }
    }
    let mut result: Vec<String> = Vec::new();
    for (idx, &start) in positions.iter().enumerate() {
        let end = next_or_len(&positions, idx + 1, stripped.len());
        let action = stripped[start..end].trim();
        if !action.is_empty() {
            result.push(action.to_string());
        }
    }
    result
}

/// python-структура «крайний элемент = конец строки».
fn next_or_len(positions: &[usize], index: usize, length: usize) -> usize {
    match positions.get(index) {
        Some(value) => *value,
        None => length,
    }
}

/// Разбор одной команды --lua-desync (python _parse_lua_desync).
fn parse_lua_desync(
    line: &str,
    payload: &str,
    in_range: &str,
    out_range: &str,
) -> ProfileAction {
    let value = right_side(line).unwrap_or_default();
    let parts: Vec<String> = split_unescaped(&value, ':')
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect();
    let func_name = parts.first().map(|part| part.trim().to_string()).unwrap_or_default();
    let mut args: Vec<ProfileActionArg> = Vec::new();
    let mut flags: Vec<String> = Vec::new();
    for token in parts.iter().skip(1) {
        let token = unescape_lua_token(token.trim());
        if token.is_empty() {
            continue;
        }
        match token.split_once('=').map(|(key, val)| (key.trim(), val.trim())) {
            Some((key, val)) if !key.is_empty() => args.push(ProfileActionArg {
                raw: token.clone(),
                key: key.to_string(),
                value: val.to_string(),
                is_flag: false,
            }),
            // python: пустой ключ («=значение») и хвосты без «=» — флаги.
            _ => {
                args.push(ProfileActionArg {
                    raw: token.clone(),
                    is_flag: true,
                    ..ProfileActionArg::default()
                });
                flags.push(token);
            }
        }
    }
    ProfileAction {
        raw_line: line.to_string(),
        func_name: unescape_lua_token(&func_name),
        args,
        flags: flags.into_iter().filter(|flag| !flag.is_empty()).collect(),
        payload: payload.to_string(),
        in_range: in_range.to_string(),
        out_range: out_range.to_string(),
    }
}

/// Разрезка по разделителю с соблюдаетом `\:` (python _split_unescaped).
///
/// Эскейп снимается: `\z` → `z`, а `\:` остаётся как `:`.
/// python склеивает `"\\" + char if char != separator else char`.
fn split_unescaped(value: &str, separator: char) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut escaped = false;
    for char in value.to_string().chars() {
        if escaped {
            if char != separator {
                current.push(format!("\\{char}"));
            } else {
                current.push(char.to_string());
            }
            escaped = false;
            continue;
        }
        if char == '\\' {
            escaped = true;
            continue;
        }
        if char == separator {
            parts.push(current.concat());
            current = Vec::new();
            continue;
        }
        current.push(char.to_string());
    }
    if escaped {
        current.push("\\".to_string());
    }
    parts.push(current.concat());
    parts
}

/// Снятие эскейпа разделителя (python _unescape_lua_token).
pub fn unescape_lua_token(value: &str) -> String {
    value.replace("\\:", ":")
}
