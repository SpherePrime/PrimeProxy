//! Порт `presets/builtin_catalog.py` — список встроенных пресетов папки.

use std::path::{Path, PathBuf};

/// python `list_builtin_presets(directory)`: файлы `*.txt` папки, отсортированные
/// по имени без учёта регистра. Пустая/несуществующая папка — пустой список.
#[must_use]
pub fn list_builtin_presets(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
        })
        .collect();
    paths.sort_by_key(|path| file_name_lower(path));
    paths
}

fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("primecore-presets-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lists_txt_files_sorted_case_insensitive() {
        // python: sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".txt", key=lambda p: p.name.lower())
        let dir = temp_dir("builtin-catalog");
        std::fs::write(dir.join("b.txt"), "b").unwrap();
        std::fs::write(dir.join("A.TXT"), "a").unwrap();
        std::fs::write(dir.join("c.dat"), "c").unwrap();
        std::fs::create_dir_all(dir.join("sub.dir")).unwrap();
        let listed = list_builtin_presets(&dir);
        assert_eq!(
            listed,
            vec![dir.join("A.TXT"), dir.join("b.txt")],
            "только *.txt, сортировка без учёта регистра"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_empty_directory_gives_empty_list() {
        assert!(list_builtin_presets(Path::new("/definitely/missing/presets")).is_empty());
        let dir = temp_dir("builtin-catalog-empty");
        assert!(list_builtin_presets(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
