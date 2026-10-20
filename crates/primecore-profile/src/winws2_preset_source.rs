//! Порт `src/profile/winws2_preset_source.py` — обязательный блок --lua-init
//! пресета winws2 и признаки circular/strategy-тегов.

use fancy_regex::Regex;

use crate::models::ENGINE_WINWS2;

pub const WINWS2_LUA_INIT_PATHS: [&str; 8] = [
    "lua/zapret-lib.lua",
    "lua/zapret-antidpi.lua",
    "lua/zapret-auto.lua",
    "lua/custom_funcs.lua",
    "lua/custom_diag.lua",
    "lua/zapret-multishake.lua",
    "lua/fakemultisplit.lua",
    "lua/fakemultidisorder.lua",
];

/// python WINWS2_LUA_INIT_LINES.
pub fn winws2_lua_init_lines() -> Vec<String> {
    WINWS2_LUA_INIT_PATHS
        .iter()
        .map(|lua_path| format!("--lua-init=@{lua_path}"))
        .collect()
}

const LUA_INIT_OPTION: &str = "--lua-init=";

/// python is_winws2_circular_preset_source.
pub fn is_winws2_circular_preset_source(source_text: &str) -> bool {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?m)(?<!\S)--lua-desync=(?:circular|shadow_probe)(?::\S*)?(?=\s|$)")
            .expect("regex")
    });
    for raw in source_text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .lines()
    {
        let stripped = raw.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if RE.is_match(stripped).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// python has_winws2_strategy_tags.
pub fn has_winws2_strategy_tags(source_text: &str) -> bool {
    static RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r":strategy=\d+").expect("regex"));
    for raw in source_text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .lines()
    {
        let stripped = raw.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped.to_lowercase().starts_with("--lua-desync=")
            && RE.is_match(stripped).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// python _strip_wrapping_quotes.
fn strip_wrapping_quotes(value: &str) -> String {
    let mut text = value.trim().to_string();
    let mut chars: Vec<char> = text.chars().collect();
    loop {
        if chars.len() >= 2 {
            let first = chars[0];
            let last = chars[chars.len() - 1];
            if first == last && (first == '"' || first == '\'') {
                let inner: String = chars[1..chars.len() - 1].iter().collect();
                text = inner.trim().to_string();
                chars = text.chars().collect();
                continue;
            }
        }
        break;
    }
    text
}

/// python canonical_winws2_lua_init_path.
pub fn canonical_winws2_lua_init_path(option: &str) -> Option<&'static str> {
    let text = option.trim();
    if !text.to_lowercase().starts_with(LUA_INIT_OPTION) {
        return None;
    }
    let value = strip_wrapping_quotes(&text[LUA_INIT_OPTION.len()..]);
    if !value.starts_with('@') {
        return None;
    }
    let path = strip_wrapping_quotes(&value[1..])
        .replace('\\', "/")
        .to_lowercase();
    for lua_path in WINWS2_LUA_INIT_PATHS {
        if path == lua_path || path.ends_with(&format!("/{lua_path}")) {
            return Some(lua_path);
        }
    }
    None
}

/// python _drop_block_options: ((changed, remainder)).
fn drop_block_options(stripped_line: &str) -> (bool, String) {
    static SPLIT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?<=\S)\s+(?=--)").expect("regex"));
    // python: split(...); regex заменяет разделители "" — части без заделов.
    let parts: Vec<String> = split_inline(&SPLIT_RE, stripped_line)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect();
    let kept: Vec<String> = parts
        .iter()
        .filter(|part| canonical_winws2_lua_init_path(part).is_none())
        .cloned()
        .collect();
    if kept.len() == parts.len() {
        return (false, stripped_line.to_string());
    }
    (true, kept.join(" ").trim().to_string())
}

fn split_inline(re: &Regex, text: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut last = 0usize;
    for matched in re.find_iter(text).filter_map(Result::ok) {
        result.push(text[last..matched.start()].to_string());
        last = matched.end();
    }
    result.push(text[last..].to_string());
    result
}

/// python ensure_winws2_lua_init_block.
pub fn ensure_winws2_lua_init_block(source_text: &str) -> String {
    let text = crate::parser::normalize_text(source_text);
    let lines: Vec<&str> = text.split('\n').collect();
    // python parse_preset_text(text, engine=...) — исключения ⇒ header = len(lines).
    let header_end = crate::parser::parse_preset_text(&text, ENGINE_WINWS2, "")
        .map(|preset| preset.header_lines.len())
        .unwrap_or(lines.len());

    let mut body: Vec<String> = Vec::new();
    for raw in &lines[header_end..] {
        let stripped = raw.trim();
        if stripped.starts_with("--") {
            let (changed, remainder) = drop_block_options(stripped);
            if changed {
                if !remainder.is_empty() {
                    body.push(remainder);
                }
                continue;
            }
        }
        body.push((*raw).to_string());
    }

    let mut insert_at = header_end;
    if body.iter().all(|line| line.trim().is_empty()) {
        // В тексте одна шапка: блок сразу после последнего комментария.
        while insert_at > 0 && lines[insert_at - 1].trim().is_empty() {
            insert_at -= 1;
        }
        body = lines[insert_at..header_end]
            .iter()
            .map(|line| (*line).to_string())
            .chain(body)
            .collect();
    }

    let mut result: Vec<String> =
        Vec::with_capacity(header_end + WINWS2_LUA_INIT_PATHS.len() + body.len());
    result.extend(lines[..insert_at].iter().map(|line| (*line).to_string()));
    result.extend(winws2_lua_init_lines());
    result.extend(body);
    result.join("\n")
}
