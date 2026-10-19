//! Порт `src/profile/preset_blob_declarations.py` — объявления фейков
//! (`--blob=`) для выбранной стратегии в преамбуле пресета.

use crate::fakes_names::{BLOB_REFERENCE_ARG_NAMES, NFQWS2_BUILTIN_BLOBS};

/// Глобальные переменные-фейки из обязательного lua/custom_funcs.lua
/// (`--lua-init`) — такие имена объявлять не нужно.
pub const LUA_DEFINED_BLOB_NAMES: [&str; 2] = ["fake_unknown_256", "fake_zero64"];

// Функция, у которой blob= — выходной слот, а не ссылка на фейк.
const BLOB_OUTPUT_SLOT_FUNCTIONS: [&str; 1] = ["tls_client_hello_clone"];

const BLOB_OPTION: &str = "--blob=";
const LUA_DESYNC_OPTION: &str = "--lua-desync=";

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && chars.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
}

/// python BlobDeclarationReport.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlobDeclarationReport {
    pub added: Vec<String>,
    pub unknown: Vec<String>,
    pub conflicts: Vec<String>,
    pub catalog_error: String,
}

impl BlobDeclarationReport {
    /// python user_warnings: короткие сообщения, пусто — всё в порядке.
    pub fn user_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.catalog_error.is_empty() {
            warnings.push(format!(
                "Реестр фейков недоступен ({}); в пресет не добавлены фейки: {}",
                self.catalog_error,
                self.unknown.join(", ")
            ));
        } else if !self.unknown.is_empty() {
            warnings.push(format!(
                "Стратегия ссылается на фейки, которых нет в пресете и в реестре: {}",
                self.unknown.join(", ")
            ));
        }
        warnings
    }
}

/// Притянутый образ строки реестра фейков (`FakeEntryLike`).
#[derive(Clone)]
pub struct FakeEntryBlobLine(pub String);

/// python FakesCatalogLike: name -> entry. Загрузчик: Result вместо исключения.
pub type FakesCatalogLoader<'a> = dyn Fn() -> Result<Vec<(String, String)>, String> + 'a;

fn split_inline_options(line: &str) -> Vec<String> {
    let stripped = line.trim();
    if stripped.is_empty() || stripped.starts_with('#') {
        return Vec::new();
    }
    inline_options_split(stripped)
}

/// python regex re.split(r"(?<=\S)\s+(?=--)") — Rust-regex не умеет lookbehind.
fn inline_options_split(src: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut last = 0;
    let bytes = src.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace()
            && index > 0
            && bytes[index - 1] != b' '
            && !bytes[index - 1].is_ascii_whitespace()
        {
            let mut end = index;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if src[end..].starts_with("--") {
                parts.push(src[last..index].to_string());
                last = end;
                index = end;
                continue;
            }
        }
        index += 1;
    }
    parts.push(src[last..].to_string());
    parts.into_iter().filter(|part| !part.is_empty()).collect()
}

fn is_blob(option: &str) -> bool {
    option.to_lowercase().starts_with(BLOB_OPTION)
}

fn is_lua_init(option: &str) -> bool {
    option.to_lowercase().starts_with("--lua-init=")
}

fn blob_references(lua_desync_value: &str) -> Vec<String> {
    let parts: Vec<&str> = lua_desync_value.split(':').collect();
    let function_name = parts.first().map(|part| part.trim()).unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    for raw_arg in parts.into_iter().skip(1) {
        let (key, separator, value) = match raw_arg.split_once('=') {
            Some((k, v)) => (k.trim(), true, v),
            None => (raw_arg, false, ""),
        };
        if !separator || !BLOB_REFERENCE_ARG_NAMES.contains(&key) {
            continue;
        }
        if key == "blob" && BLOB_OUTPUT_SLOT_FUNCTIONS.contains(&function_name) {
            continue;
        }
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        if value.len() >= 2 && value.to_lowercase().starts_with("0x") {
            continue;
        }
        if !is_identifier(value) {
            continue;
        }
        names.push(value.to_string());
    }
    // python set: только уникальные.
    let mut unique: Vec<String> = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique
}

/// python required_blob_names: имена фейков, на которые смотрит стратегия.
pub fn required_blob_names(strategy_lines: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in strategy_lines {
        for option in split_inline_options(line) {
            let lower = option.to_lowercase();
            if lower.starts_with(LUA_DESYNC_OPTION) {
                let value = &option[LUA_DESYNC_OPTION.len()..];
                for name in blob_references(value) {
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
    }
    // python set: отсортировано в plan — тут порядок не важен; держим уникальность.
    names
}

/// python _blob_declaration: `--blob=NAME:VALUE` -> (NAME, NAME:VALUE).
fn blob_declaration(option: &str) -> Option<(String, String)> {
    if !option.to_lowercase().starts_with(BLOB_OPTION) {
        return None;
    }
    let spec = option[BLOB_OPTION.len()..].trim().to_string();
    let name = spec.split(':').next().unwrap_or_default().trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, spec))
}

/// python declared_blobs: имя -> значение по FIRST вхождению.
pub fn declared_blobs(preset_text: &str) -> Vec<(String, String)> {
    let mut declared: Vec<(String, String)> = Vec::new();
    let text = preset_text.replace("\r\n", "\n").replace('\r', "\n");
    for line in text.split('\n') {
        for option in split_inline_options(line) {
            let parsed = blob_declaration(&option);
            if let Some((name, spec)) = parsed {
                if !declared.iter().any(|(known, _)| *known == name) {
                    declared.push((name, spec));
                }
            }
        }
    }
    declared
}

/// python plan_blob_declaration_lines.
pub fn plan_blob_declaration_lines(
    strategy_lines: &[String],
    declared: &[(String, String)],
    load_catalog: Option<&FakesCatalogLoader<'_>>,
) -> (Vec<String>, BlobDeclarationReport) {
    let mut skipped: Vec<&str> = NFQWS2_BUILTIN_BLOBS.to_vec();
    skipped.extend(LUA_DEFINED_BLOB_NAMES);
    let mut needed: Vec<String> = required_blob_names(strategy_lines)
        .into_iter()
        .filter(|name| !skipped.contains(&name.as_str()))
        .collect();
    needed.sort();
    if needed.is_empty() {
        return (Vec::new(), BlobDeclarationReport::default());
    }
    let missing: Vec<String> = needed
        .iter()
        .filter(|name| !declared.iter().any(|(known, _)| known == *name))
        .cloned()
        .collect();

    let Some(load_catalog) = load_catalog else {
        if missing.is_empty() {
            return (Vec::new(), BlobDeclarationReport::default());
        }
        return (
            Vec::new(),
            BlobDeclarationReport {
                unknown: missing,
                catalog_error: "реестр не подключён".to_string(),
                ..Default::default()
            },
        );
    };
    let entries = match load_catalog() {
        Ok(entries) => entries,
        Err(exc) => {
            if missing.is_empty() {
                return (Vec::new(), BlobDeclarationReport::default());
            }
            return (
                Vec::new(),
                BlobDeclarationReport {
                    unknown: missing,
                    catalog_error: exc,
                    ..Default::default()
                },
            );
        }
    };

    let mut lines: Vec<String> = Vec::new();
    let mut added: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    for name in &needed {
        let parsed = entries
            .iter()
            .find(|(entry_name, _)| entry_name == name)
            .and_then(|(_, blob_line)| blob_declaration(blob_line.trim()))
            .and_then(|(parsed_name, value)| {
                if parsed_name == *name {
                    Some((parsed_name, value))
                } else {
                    None
                }
            });
        if declared.iter().any(|(known, _)| known == name) {
            if let Some((_, value)) = parsed {
                let matches = declared
                    .iter()
                    .filter(|(known, _)| known == name)
                    .any(|(_, known_value)| *known_value == value);
                if !matches {
                    conflicts.push(name.clone());
                }
            }
            continue;
        }
        match parsed {
            Some((_, value)) => {
                lines.push(format!("{BLOB_OPTION}{value}"));
                added.push(name.clone());
            }
            None => unknown.push(name.clone()),
        }
    }
    (
        lines,
        BlobDeclarationReport {
            added,
            unknown,
            conflicts,
            catalog_error: String::new(),
        },
    )
}

fn blob_insert_index(preamble_lines: &[String]) -> usize {
    for index in (0..preamble_lines.len()).rev() {
        if split_inline_options(&preamble_lines[index])
            .iter()
            .any(|option| is_blob(option))
        {
            return index + 1;
        }
    }
    for index in (0..preamble_lines.len()).rev() {
        if split_inline_options(&preamble_lines[index])
            .iter()
            .any(|option| is_lua_init(option))
        {
            return index + 1;
        }
    }
    let mut index = preamble_lines.len();
    while index > 0 && preamble_lines[index - 1].trim().is_empty() {
        index -= 1;
    }
    index
}

/// python with_blob_lines_in_preamble.
pub fn with_blob_lines_in_preamble(preamble_lines: &[String], blob_lines: &[String]) -> Vec<String> {
    if blob_lines.is_empty() {
        return preamble_lines.to_vec();
    }
    let mut lines = preamble_lines.to_vec();
    let mut block = blob_lines.to_vec();
    let index = blob_insert_index(&lines);
    if index > 0
        && !lines[index - 1].trim().is_empty()
        && !split_inline_options(&lines[index - 1])
            .iter()
            .any(|option| is_blob(option))
    {
        block.insert(0, String::new());
    }
    if index < lines.len()
        && !lines[index].trim().is_empty()
        && !split_inline_options(&lines[index])
            .iter()
            .any(|option| is_blob(option))
    {
        block.push(String::new());
    }
    lines.splice(index..index, block);
    lines
}
