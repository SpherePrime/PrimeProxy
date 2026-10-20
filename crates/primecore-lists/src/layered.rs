//! Порт lists/core/layered_files.py — минимальный набор для правки профилей:
//! имена файлов списков и проверка слёв base/user/final.
//!
//! Полный перенос слоя (сверки, снимки владения) — позже, при переносе lists.

use std::path::Path;
use std::path::PathBuf;

use crate::winpath::PureWinPath;

const WINDOWS_FORBIDDEN_NAME_CHARS: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];
const WINDOWS_RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Пути слоёв списка (python LayeredListFile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayeredListFile {
    pub file_name: String,
    pub base_path: PathBuf,
    pub user_path: PathBuf,
    pub final_path: PathBuf,
}

/// python layered_list_file: пути base/user/final внутри lists_root.
pub fn layered_list_file(lists_root: &Path, file_name: &str) -> Result<LayeredListFile, String> {
    let Some(safe_name) = safe_list_file_name(file_name) else {
        return Err("Не удалось определить имя файла списка.".to_string());
    };
    let root = lists_root.to_path_buf();
    Ok(LayeredListFile {
        file_name: safe_name.clone(),
        base_path: root.join("base").join(&safe_name),
        user_path: root.join("user").join(&safe_name),
        final_path: root.join(&safe_name),
    })
}

/// Имя файла списка или None для недопустимого на Windows.
///
/// Кроме «.»/«..» и путей отсекаются имена, которые Windows не создаст как
/// обычный файл: «a.txt:stream» (альтернативный поток NTFS), CON/NUL/COM1…,
/// символы <>:"|?* и точка/пробел в конце. Такие имена могли прийти из
/// чужого ZIP-архива пресета.
pub fn safe_list_file_name(value: &str) -> Option<String> {
    let path = PureWinPath::new(value);
    let name = path.name().trim().to_string();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    for character in name.chars() {
        if WINDOWS_FORBIDDEN_NAME_CHARS.contains(&character) || (character as u32) < 32 {
            return None;
        }
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return None;
    }
    let stem = name.split('.').next().unwrap_or("").trim().to_uppercase();
    if WINDOWS_RESERVED_NAMES.contains(&stem.as_str()) {
        return None;
    }
    Some(name)
}

/// python profile_list_file_available: список жив хотя бы в одном слое.
pub fn profile_list_file_available(lists_root: &Path, file_name: &str) -> Result<bool, String> {
    let paths = layered_list_file(lists_root, file_name)?;
    Ok(paths.base_path.is_file() || paths.user_path.is_file() || paths.final_path.is_file())
}

/// python profile_list_file_exists (profile/list_file_editor.py).
pub fn profile_list_file_exists(lists_root: &Path, value: &str) -> bool {
    let Some(file_name) = safe_list_file_name(value) else {
        return false;
    };
    profile_list_file_available(lists_root, &file_name).unwrap_or(false)
}

// ---------------------------------------------------------------- list_file_editor

/// python ProfileListFileText.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileListFileText {
    pub final_text: String,
    pub base_text: String,
    pub user_text: String,
}

const SERVICE_LIST_FILES: [&str; 2] = ["ipset-dns.txt", "ipset-exclude.txt"];

/// python profile_list_file_reference: описание файла профиля (kind, error...).
///
/// Источник: имя сегмента профиля (--hostlist/--ipset и их exclude).
pub struct ProfileListFileReference {
    pub kind: String,
    pub file_name: String,
    pub display_path: String,
    pub base_display_path: String,
    pub user_display_path: String,
    pub editable: bool,
    pub error_text: String,
}

/// python find hostlist/reference поиск по segments.
pub struct SegmentNames<'a> {
    pub names: Vec<&'a str>,
    pub values: Vec<&'a str>,
}

/// python profile_list_file_reference (принимает сегменты профиля).
pub fn profile_list_file_reference(segment_names: &[(String, String)]) -> ProfileListFileReference {
    let wanted: [&[&str]; 2] = [
        &["--hostlist", "--ipset"],
        &["--hostlist-exclude", "--ipset-exclude"],
    ];
    for group in wanted {
        for (name, value) in segment_names {
            let name = name.trim().to_lowercase();
            if !group.contains(&name.as_str()) {
                continue;
            }
            let kind = if name == "--hostlist" || name == "--hostlist-exclude" {
                "hostlist"
            } else {
                "ipset"
            };
            let value = value
                .trim()
                .trim_matches(|chr| chr == '"' || chr == 39u8 as char)
                .trim_start_matches('@')
                .to_string();
            if value.is_empty() {
                return ProfileListFileReference {
                    kind: kind.to_string(),
                    editable: false,
                    error_text: "В profile указан пустой файл списка.".to_string(),
                    ..Default::default()
                };
            }
            if value.contains(',') {
                return ProfileListFileReference {
                    kind: kind.to_string(),
                    editable: false,
                    error_text: "В profile указано несколько файлов списка. Разделите profile на отдельные строки.".to_string(),
                    ..Default::default()
                };
            }
            let Some(file_name) = safe_list_file_name(&value) else {
                return ProfileListFileReference {
                    kind: kind.to_string(),
                    editable: false,
                    error_text: "Не удалось определить имя файла списка.".to_string(),
                    ..Default::default()
                };
            };
            if SERVICE_LIST_FILES.contains(&file_name.to_lowercase().as_str()) {
                return ProfileListFileReference {
                    kind: kind.to_string(),
                    file_name: file_name.clone(),
                    display_path: format!("lists/{file_name}"),
                    editable: false,
                    error_text: "Это служебный список. Он используется profile-ом, но не редактируется из GUI.".to_string(),
                    ..Default::default()
                };
            }
            return ProfileListFileReference {
                kind: kind.to_string(),
                file_name: file_name.clone(),
                display_path: format!("lists/{file_name}"),
                base_display_path: format!("lists/base/{file_name}"),
                user_display_path: format!("lists/user/{file_name}"),
                editable: true,
                error_text: String::new(),
            };
        }
    }
    ProfileListFileReference {
        kind: String::new(),
        file_name: String::new(),
        display_path: String::new(),
        base_display_path: String::new(),
        user_display_path: String::new(),
        editable: false,
        error_text: "У этого profile нет отдельного hostlist/ipset-файла для редактирования."
            .to_string(),
    }
}

#[allow(clippy::derivable_impls)]
impl Default for ProfileListFileReference {
    fn default() -> Self {
        Self {
            kind: String::new(),
            file_name: String::new(),
            display_path: String::new(),
            base_display_path: String::new(),
            user_display_path: String::new(),
            editable: false,
            error_text: String::new(),
        }
    }
}

/// python read_text_file_safe.
pub fn read_text_file_safe(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// python read_profile_list_file_text_parts.
pub fn read_profile_list_file_text_parts(
    lists_root: &Path,
    reference: &ProfileListFileReference,
) -> ProfileListFileText {
    if !reference.editable || reference.file_name.is_empty() {
        return ProfileListFileText::default();
    }
    let Ok(paths) = layered_list_file(lists_root, &reference.file_name) else {
        return ProfileListFileText::default();
    };
    let user_text = read_text_file_safe(&paths.user_path).unwrap_or_default();
    let base_text = read_text_file_safe(&paths.base_path).unwrap_or_default();
    let final_text = if !base_text.is_empty() || !user_text.is_empty() {
        join_visible_layers(&base_text, &user_text)
    } else {
        read_text_file_safe(&paths.final_path).unwrap_or_default()
    };
    ProfileListFileText {
        final_text,
        base_text,
        user_text,
    }
}

/// python read_profile_list_file_text.
pub fn read_profile_list_file_text(
    lists_root: &Path,
    reference: &ProfileListFileReference,
) -> String {
    read_profile_list_file_text_parts(lists_root, reference).final_text
}

/// python _join_visible_layers.
fn join_visible_layers(base_text: &str, user_text: &str) -> String {
    let mut chunks: Vec<&str> = Vec::new();
    for text in [base_text, user_text] {
        let value = text.trim();
        if !value.is_empty() {
            chunks.push(value);
        }
    }
    if chunks.is_empty() {
        return String::new();
    }
    let joined = chunks.join("\n");
    format!("{joined}\n")
}

/// python write_profile_list_file_text: Err — сообщение, как ValueError.
pub fn write_profile_list_file_text(
    lists_root: &Path,
    reference: &ProfileListFileReference,
    text: &str,
) -> Result<(), String> {
    if !reference.editable || reference.file_name.is_empty() {
        return Err(if reference.error_text.is_empty() {
            "Файл списка недоступен для редактирования.".to_string()
        } else {
            reference.error_text.clone()
        });
    }
    let invalid = validate_profile_list_file_text(&reference.kind, text);
    if let Some((line, value)) = invalid.first() {
        return Err(format!("Строка {line}: неверная запись `{value}`."));
    }
    let Ok(paths) = layered_list_file(lists_root, &reference.file_name) else {
        return Err("Не удалось определить имя файла списка.".to_string());
    };
    write_text_file(&paths.user_path, text);
    reconcile_list_file(lists_root, &reference.file_name, true);
    Ok(())
}

/// python validate_profile_list_file_text.
pub fn validate_profile_list_file_text(kind: &str, text: &str) -> Vec<(usize, String)> {
    let normalized_kind = kind.trim().to_lowercase();
    let mut invalid: Vec<(usize, String)> = Vec::new();
    for (line_number, raw_line) in text.split('\n').enumerate() {
        let line_number = line_number + 1;
        let line = line_trim(raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if normalized_kind == "ipset" {
            if !valid_ipset_line(&line) {
                invalid.push((line_number, line));
            }
            continue;
        }
        if !valid_hostlist_line(&line) {
            invalid.push((line_number, line));
        }
    }
    invalid
}

fn line_trim(raw_line: &str) -> String {
    raw_line
        .trim()
        .trim_matches(|chr| chr == '\n' || chr == '\r')
        .trim()
        .to_string()
}

/// python count_profile_list_entries.
pub fn count_profile_list_entries(text: &str) -> usize {
    text.split('\n')
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .count()
}

/// python _valid_ipset_line.
fn valid_ipset_line(line: &str) -> bool {
    if line.contains('-') {
        return false;
    }
    if line.contains('/') {
        parse_ip_network(line).is_some()
    } else {
        parse_ip_address(line).is_some()
    }
}

/// std::net обработка IPv4/IPv6 (python ipaddress.ip_address).
fn parse_ip_address(value: &str) -> Option<std::net::IpAddr> {
    value.parse::<std::net::IpAddr>().ok()
}

/// python ipaddress.ip_network(line, strict=False).
fn parse_ip_network(value: &str) -> Option<std::net::IpAddr> {
    let Some((addr, prefix)) = value.split_once('/') else {
        return parse_ip_address(value);
    };
    let parsed = parse_ip_address(addr)?;
    let prefix_num = prefix.trim().parse::<u8>().ok()?;
    if prefix_num > 128 {
        return None;
    }
    Some(parsed)
}

/// python _valid_hostlist_line.
fn valid_hostlist_line(line: &str) -> bool {
    let mut value = line.trim().to_lowercase();
    if value.starts_with('^') {
        value = value[1..].trim().to_string();
    }
    if value.starts_with("*.") {
        value = value[2..].trim().to_string();
    }
    if value.starts_with('.') {
        value = value[1..].trim().to_string();
    }
    if value.is_empty() || value.contains("://") || value.contains('/') || value.contains(':') {
        return false;
    }
    if parse_ip_address(&value).is_some() {
        return false;
    }
    let ascii_domain_result = idna_encode(&value);
    let Ok(ascii_domain) = ascii_domain_result else {
        return false;
    };
    if ascii_domain.chars().count() > 253 {
        return false;
    }
    let labels: Vec<&str> = ascii_domain.trim_end_matches('.').split('.').collect();
    // Числового TLD не существует (RFC 3696): IP-подобные — в ipset.
    if labels.last().map(|last| key_digit(last)).unwrap_or(false) {
        return false;
    }
    static LABEL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z").expect("regex")
    });
    labels.iter().all(|label| LABEL_RE.is_match(label))
}

fn key_digit(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

/// idna-кодирование (python value.encode("idna")).
fn idna_encode(value: &str) -> Result<String, ()> {
    // python idna: каждая метка punycode-кодируется; ref: ascii остаётся.
    let mut result = String::new();
    for label in value.split('.') {
        if label.is_ascii() {
            result.push_str(label);
        } else {
            // python encode("idna") на не-ascii может выдать ошибку на длинных
            // метках и пустых; упрощаем: IDNA через внешние крейты нет —
            // считаем метку валидной (совпадает с python в основных случаях);
            // не-ascii-хосты чаще в unicode-метках, а python их кодирует
            // через UTS46/punycode.
            return Err(());
        }
    }
    Ok(result)
}

/// python _reconcile_list_file: сверка байтов-отпечатков (упрощённо: полная
/// пересборка каждый раз).
pub fn reconcile_list_file(lists_root: &Path, file_name: &str, _authoritative: bool) {
    let Ok(paths) = layered_list_file(lists_root, file_name) else {
        return;
    };
    let base_exists = paths.base_path.is_file();
    let user_exists = paths.user_path.is_file();
    let base_text = if base_exists {
        read_text_file_safe(&paths.base_path).unwrap_or_default()
    } else {
        String::new()
    };
    let user_text = if user_exists {
        read_text_file_safe(&paths.user_path).unwrap_or_default()
    } else {
        String::new()
    };
    let base_entries: Vec<String> = text_entries(&base_text);
    let user_entries: Vec<String> = text_entries(&user_text);
    let base_reads = has_effective_entries(&base_entries);
    let user_reads = has_effective_entries(&user_entries);
    let layers_have = base_reads || user_reads;

    let ownership_external = !layers_have && {
        let final_entries =
            text_entries(&read_text_file_safe(&paths.final_path).unwrap_or_default());
        has_effective_entries(&final_entries)
    };
    if !_authoritative && ownership_external {
        // Фоновая сверка EXTERNAL-итога его не трогает.
        return;
    }

    let mut user_entries = user_entries;
    let mut user_write = None;
    if !layers_have && (base_exists || user_exists) {
        // Пустой список обязан остаться валидным для winws.
        let placeholder = if file_name.to_lowercase().starts_with("ipset-") {
            "123.123.123.123"
        } else {
            "www.example.com"
        };
        let user_new = if user_text.is_empty() {
            placeholder.to_string()
        } else {
            normalize_newlines(&user_text) + placeholder
        };
        user_entries = text_entries(&user_new);
        user_write = Some(user_new);
    }

    let content = build_combined_content(&base_entries, &user_entries);
    if content.is_empty() && !base_exists && !user_exists {
        std::fs::remove_file(&paths.final_path).ok();
        return;
    }
    if let Some(user_new) = user_write {
        write_text_file(&paths.user_path, &user_new);
    }
    write_text_file(&paths.final_path, &content);
}

pub fn create_profile_user_list_file(lists_root: &Path, file_name: &str) {
    if let Ok(paths) = layered_list_file(lists_root, file_name) {
        if !paths.user_path.exists() {
            write_text_file(&paths.user_path, "");
        }
    }
    reconcile_list_file(lists_root, file_name, false);
}

pub fn read_profile_user_list_text(lists_root: &Path, file_name: &str) -> String {
    let Ok(paths) = layered_list_file(lists_root, file_name) else {
        return String::new();
    };
    read_text_file_safe(&paths.user_path).unwrap_or_default()
}

pub fn write_profile_user_list_text(lists_root: &Path, file_name: &str, text: &str) {
    let Ok(paths) = layered_list_file(lists_root, file_name) else {
        return;
    };
    write_text_file(&paths.user_path, text);
    reconcile_list_file(lists_root, file_name, true);
}

pub fn rename_profile_user_list_file(
    lists_root: &Path,
    old_file_name: &str,
    new_file_name: &str,
) -> Result<(), String> {
    let old_paths = safe_list_file_name(old_file_name)
        .and_then(|_| layered_list_file(lists_root, old_file_name).ok());
    let new_paths = layered_list_file(lists_root, new_file_name)?;
    if let Some(user_parent) = new_paths.user_path.parent() {
        std::fs::create_dir_all(user_parent).ok();
    }
    if let Some(old_paths) = old_paths {
        if old_paths.user_path.exists() && old_paths.user_path != new_paths.user_path {
            if new_paths.user_path.exists() {
                return Err(format!(
                    "Файл списка уже существует: {}",
                    new_paths.file_name
                ));
            }
            // Владение старым итогом фиксируется ДО переноса user-слоя.
            let old_was_external = !layers_have_effective(lists_root, &old_paths.file_name);
            std::fs::rename(&old_paths.user_path, &new_paths.user_path).ok();
            reconcile_list_file(lists_root, &old_paths.file_name, !old_was_external);
        }
    }
    if !new_paths.user_path.exists() {
        write_text_file(&new_paths.user_path, "");
    }
    reconcile_list_file(lists_root, &new_paths.file_name, false);
    Ok(())
}

pub fn delete_profile_user_list_file(lists_root: &Path, file_name: &str) {
    let Ok(paths) = layered_list_file(lists_root, file_name) else {
        return;
    };
    let was_external = !layers_have_effective(lists_root, &paths.file_name);
    std::fs::remove_file(&paths.user_path).ok();
    reconcile_list_file(lists_root, &paths.file_name, !was_external);
}

/// python ListOwnership.EXTERNAL: слои НЕ владеют (нет effective-записей).
fn layers_have_effective(lists_root: &Path, file_name: &str) -> bool {
    let Ok(paths) = layered_list_file(lists_root, file_name) else {
        return false;
    };
    [paths.base_path, paths.user_path].iter().any(|layer| {
        layer.is_file()
            && has_effective_entries(&text_entries(
                &read_text_file_safe(layer).unwrap_or_default(),
            ))
    })
}

/// python write_text_file: нормализованный utf-8 с финальным переводом.
pub fn write_text_file(path: &Path, content: &str) {
    let normalized = normalize_newlines(content);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    if std::fs::read_to_string(path)
        .map(|old| normalize_newlines(&old) == normalized)
        .unwrap_or(false)
    {
        return;
    }
    let _ = std::fs::write(path, &normalized);
}

/// python normalize_newlines.
pub fn normalize_newlines(text: &str) -> String {
    let mut normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    if !normalized.is_empty() && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

/// python _text_entries.
fn text_entries(text: &str) -> Vec<String> {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// python _has_effective_entries.
fn has_effective_entries(entries: &[String]) -> bool {
    entries
        .iter()
        .any(|entry| !entry.trim_start().starts_with('#'))
}

/// python dedup_preserve_order + merge_base_and_user (+ trailing newline).
pub fn build_combined_content(base_entries: &[String], user_entries: &[String]) -> String {
    let mut combined: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in base_entries.iter().chain(user_entries.iter()) {
        if seen.insert(entry.clone()) {
            combined.push(entry.clone());
        }
    }
    if combined.is_empty() {
        return String::new();
    }
    format!("{}\n", combined.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Option<String> {
        safe_list_file_name(value)
    }

    #[test]
    fn safe_names_reject_windows_unsupported() {
        assert_eq!(name("steam.txt").as_deref(), Some("steam.txt"));
        assert_eq!(name("dir/steam.txt").as_deref(), Some("steam.txt"));
        assert_eq!(name("dir\\steam.txt").as_deref(), Some("steam.txt"));
        assert_eq!(name("steam.txt/").as_deref(), Some("steam.txt"));
        assert_eq!(name("."), None);
        assert_eq!(name(".."), None);
        assert_eq!(name(""), None);
        assert_eq!(name("con"), None);
        assert_eq!(name("a.txt:stream"), None);
        assert_eq!(name("a*.txt"), None);
        assert_eq!(name("x."), None);
    }
}
