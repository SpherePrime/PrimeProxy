//! Порт `src/profile/models.py` — структуры профилей, стратегий, пресетов и
//! логические ключи профилей (build_profile_persistent_key и рядом).
//!
//! Полные типы здесь входят во многие модули (parser, serializer, plan),
//! поэтому живут отдельно от самих функций разбора.

use std::collections::BTreeSet;

use regex::Regex;

/// Движки стратегии (дублируют settings.mode — там константы строк).
pub const ENGINE_WINWS1: &str = "winws1";
pub const ENGINE_WINWS2: &str = "winws2";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProfileSegment {
    pub kind: String,
    pub text: String,
    pub name: String,
    pub value: String,
}

/// Совокупность строк match-секции профиля (python ProfileMatch).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProfileMatch {
    pub filter_lines: Vec<String>,
    pub hostlist_lines: Vec<String>,
    pub ipset_lines: Vec<String>,
    pub hostlist_exclude_lines: Vec<String>,
    pub hostlist_auto_lines: Vec<String>,
    pub ipset_exclude_lines: Vec<String>,
    pub hostlist_domains_lines: Vec<String>,
    pub inline_ipset_lines: Vec<String>,
    pub other_lines: Vec<String>,
}

impl ProfileMatch {
    /// Все строки match-секции в порядке python all_lines().
    pub fn all_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        self.filter_lines
            .iter()
            .chain(&self.hostlist_lines)
            .chain(&self.ipset_lines)
            .chain(&self.hostlist_exclude_lines)
            .chain(&self.hostlist_auto_lines)
            .chain(&self.ipset_exclude_lines)
            .chain(&self.hostlist_domains_lines)
            .chain(&self.inline_ipset_lines)
            .chain(&self.other_lines)
            .for_each(|line| lines.push(line.clone()));
        lines
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProfileActionArg {
    pub raw: String,
    pub key: String,
    pub value: String,
    pub is_flag: bool,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProfileAction {
    pub raw_line: String,
    pub func_name: String,
    pub args: Vec<ProfileActionArg>,
    pub flags: Vec<String>,
    pub payload: String,
    pub in_range: String,
    pub out_range: String,
}

/// Стратегия WinWS2: список --lua-desync-действий и прочие строки.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Winws2Strategy {
    pub actions: Vec<ProfileAction>,
    pub strategy_lines: Vec<String>,
    pub other_lines: Vec<String>,
}

/// Стратегия WinWS1: сырые строки desync/dup/wssize/ip_id.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Winws1Strategy {
    pub dpi_desync_lines: Vec<String>,
    pub dup_lines: Vec<String>,
    pub wssize_lines: Vec<String>,
    pub ip_id_lines: Vec<String>,
    pub strategy_lines: Vec<String>,
    pub other_lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Strategy {
    Winws1(Winws1Strategy),
    Winws2(Winws2Strategy),
}

/// Профиль одного пресета (python Profile).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Profile {
    pub id: String,
    pub index: i64,
    pub engine: String,
    pub display_name: String,
    pub enabled: bool,
    /// Строка match-секции заполнена ровно один раз в Python-модели.
    pub matched: Option<ProfileMatch>,
    pub strategy: Option<Strategy>,
    pub segments: Vec<ProfileSegment>,
    pub new_line: String,
    pub name: String,
    pub match_signature: String,
    pub persistent_key: String,
}

/// Пресет: набор профилей с шапкой и подвалом (python Preset).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Preset {
    pub engine: String,
    pub header_lines: Vec<String>,
    pub preamble_lines: Vec<String>,
    pub profiles: Vec<Profile>,
    pub source_name: String,
    pub footer_lines: Vec<String>,
}

impl Profile {
    pub fn key(&self) -> &str {
        &self.id
    }

    /// match-секция (python-модель гарантирует её наличие).
    pub fn match_section(&self) -> &ProfileMatch {
        self.matched.as_ref().expect("match-секция уже построена")
    }
}

/// Ключ персистентности: по имени, иначе по логической подписи match-секции.
pub fn build_profile_persistent_key(name: &str, match_signature: &str) -> String {
    let clean_name = name.trim();
    if !clean_name.is_empty() {
        return format!("name:{clean_name}");
    }
    format!("sig:{}", build_profile_logical_key(match_signature))
}

/// Логический ключ профиля по подписи match-секции.
pub fn build_profile_logical_key(match_signature: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for raw_part in match_signature.trim().split('|') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(value) = part.strip_prefix("hostlist=").or_else(|| part.strip_prefix("ipset=")) {
            let normalized = logical_list_value(value);
            if !normalized.is_empty() {
                parts.push(format!("list={normalized}"));
                continue;
            }
        }
        parts.push(part.to_string());
    }
    BTreeSet::from_iter(parts)
        .into_iter()
        .collect::<Vec<_>>()
        .join("|")
}

/// Имя списка без папок и метки -ipset-/-hostlist- (python _logical_list_value).
///
/// Файл путь читается как Windows-путь (python PureWindowsPath): и разделитель
/// «\», и «/» подходят.
pub fn logical_list_value(value: &str) -> String {
    let template = value.replace('\\', "/");
    let name = template.split('/').next_back().unwrap_or_default();
    let mut name = name.trim().to_lowercase();
    if name.is_empty() {
        return String::new();
    }
    // python: re.sub(r"\.(txt|lst|list|json)$", "", name, flags=re.IGNORECASE)
    static SUFFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let suffix = SUFFIX.get_or_init(|| Regex::new(r"\.(txt|lst|list|json)$").expect("regex допустим"));
    name = suffix.replace(&name, "").into_owned();
    for prefix in ["ipset-", "hostlist-"] {
        if let Some(stripped) = boxed_strip(&name, prefix) {
            name = stripped;
        }
    }
    name.trim().to_string()
}

/// Хелпер полоски префикса (имена у python-версии только в нижнем регистре).
fn boxed_strip<'text>(name: &'text str, prefix: &str) -> Option<String> {
    name.strip_prefix(prefix).map(|inner| inner.to_string())
}
