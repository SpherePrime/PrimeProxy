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
    Ok(paths.base_path.is_file()
        || paths.user_path.is_file()
        || paths.final_path.is_file())
}

/// python profile_list_file_exists (profile/list_file_editor.py).
pub fn profile_list_file_exists(lists_root: &Path, value: &str) -> bool {
    let Some(file_name) = safe_list_file_name(value) else {
        return false;
    };
    profile_list_file_available(lists_root, &file_name).unwrap_or(false)
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
