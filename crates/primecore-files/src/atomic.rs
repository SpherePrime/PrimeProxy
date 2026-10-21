//! Порт чистой части `utils/atomic_text.py` — атомарная запись текста.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// python `_REPLACE_RETRY_DELAYS_SEC`: Windows не даёт подменить файл,
/// пока его держит открытым другой читатель (наш фоновый поток,
/// антивирус, индексатор) — `os.replace` падает с PermissionError.
/// Такие блокировки короткие, поэтому несколько повторов с нарастающей
/// паузой (суммарно < 1 с) почти всегда проходят.
const REPLACE_RETRY_DELAYS: [Duration; 6] = [
    Duration::from_millis(20),
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(150),
    Duration::from_millis(250),
    Duration::from_millis(400),
];

/// Ошибка записи — значение (python-исключения).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicWriteError {
    /// python `PermissionError(13, "Файл доступен только для чтения", ...)`.
    ReadOnly(String),
    /// Прочая ошибка ввода-вывода с текстом.
    Io(String),
}

impl core::fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReadOnly(path) => {
                write!(f, "Файл доступен только для чтения: {path}")
            }
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

/// python `_replace_with_retry` — подмена целевого файла с повторами
/// против коротких блокировок.
fn replace_with_retry(source: &Path, destination: &Path) -> Result<(), AtomicWriteError> {
    let mut last_error = None;
    for delay in REPLACE_RETRY_DELAYS {
        match std::fs::rename(source, destination) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                last_error = Some(AtomicWriteError::Io(error.to_string()));
                std::thread::sleep(delay);
            }
            Err(error) => return Err(AtomicWriteError::Io(error.to_string())),
        }
    }
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) => Err(last_error.unwrap_or(AtomicWriteError::Io(error.to_string()))),
    }
}

/// python `atomic_write_text` — пишет текст так, что читатель видит либо
/// старый файл, либо новый целиком.
///
/// Данные сначала уходят во временный файл в той же папке, затем одним
/// `os.replace` подменяют целевой. При любой ошибке целевой файл
/// остаётся нетронутым, а временный удаляется.
///
/// Отличие от python: проверка «только чтение» сделана по флагу
/// «только для чтения» у файла (`permissions.readonly()`), а не
/// `os.access(W_OK)` — проверка доступа к реальному файлу в тестах
/// не подменяется, а атрибут Windows она и отражает.
pub fn atomic_write_text(path: &Path, content: &str) -> Result<(), AtomicWriteError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| AtomicWriteError::Io(error.to_string()))?;
    }
    // Подмена через os.replace обошла бы атрибут «только чтение» (на
    // Linux важны права папки, а не файла): защищённый пользователем
    // файл не трогаем, как не тронула бы его обычная запись.
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.permissions().readonly() {
            return Err(AtomicWriteError::ReadOnly(
                path.to_string_lossy().into_owned(),
            ));
        }
    }

    let data = normalize_text(content);

    let tmp_name = make_temp_file(path)?;
    let write = (|| -> Result<(), AtomicWriteError> {
        let mut handle = std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&tmp_name)
            .map_err(|error| AtomicWriteError::Io(error.to_string()))?;
        handle
            .write_all(data.as_bytes())
            .map_err(|error| AtomicWriteError::Io(error.to_string()))?;
        handle
            .flush()
            .map_err(|error| AtomicWriteError::Io(error.to_string()))?;
        // python: os.fsync — падение диска не оставит пустой файл; если
        // fsync не удался, запись всё равно считается состоявшей.
        let _ = handle.sync_all();
        Ok(())
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&tmp_name);
        return write;
    }

    let replaced = replace_with_retry(&tmp_name, path);
    // python finally: временный файл удаляется, если ещё жив.
    let _ = std::fs::remove_file(&tmp_name);
    replaced
}

/// python-нормализация текста: `"\r\n"` и одиночные `"\r"` → `"\n"`,
/// один завершающий `"\n"` у непустого текста.
#[must_use]
pub fn normalize_text(content: &str) -> String {
    let mut data = content.replace("\r\n", "\n").replace('\r', "\n");
    if !data.is_empty() && !data.ends_with('\n') {
        data.push('\n');
    }
    data
}

/// python `tempfile.mkstemp(prefix="{stem}_", suffix=".tmp", dir=parent)`
/// — уникальное имя в той же папке; файл создаётся эксклюзивно.
fn make_temp_file(target: &Path) -> Result<PathBuf, AtomicWriteError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target.file_stem().map_or_else(
        || "file".to_string(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u64, |since| since.as_nanos() as u64);
    let mut attempt = nanos ^ ((std::process::id() as u64) << 17);
    for _ in 0..1000 {
        let candidate = parent.join(format!("{stem}_{attempt:x}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
            Err(error) => return Err(AtomicWriteError::Io(error.to_string())),
        }
    }
    Err(AtomicWriteError::Io(
        "не удалось создать временный файл".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Список .tmp-файлов, оставшихся в папке (python `_leftover_tmp_files`).
    fn leftover_tmp_files(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("tmp") {
                    Some(path.file_name().unwrap().to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn writes_lf_text_with_single_final_newline() {
        // python: atomic_write_text(target, "--a\r\n--b\r--c") → b"--a\n--b\n--c\n".
        let root = std::env::temp_dir().join(format!("primecore-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("Preset.txt");
        atomic_write_text(&target, "--a\r\n--b\r--c").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"--a\n--b\n--c\n");
        assert!(leftover_tmp_files(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_write_keeps_previous_file_intact() {
        // python ломал запись недокодируемым символом; здесь та же
        // гарантия проверяется ошибкой открытия (целевая папка удалена
        // между созданием временного файла и записью невозможна, поэтому
        // вместо этого — read-only целевой файл).
        let root = std::env::temp_dir().join(format!("primecore-files-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("Preset.txt");
        std::fs::write(&target, "--old\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&target).unwrap().permissions();
            permissions.set_mode(0o444);
            std::fs::set_permissions(&target, permissions).unwrap();
            let error = atomic_write_text(&target, "--new\n").unwrap_err();
            assert!(matches!(error, AtomicWriteError::ReadOnly(_)));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "--old\n");
            assert!(leftover_tmp_files(&root).is_empty());
            let mut permissions = std::fs::metadata(&target).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&target, permissions).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_replaces_whole_file() {
        let root = std::env::temp_dir().join(format!("primecore-files-ov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("nested/Preset.txt");
        atomic_write_text(&target, "first").unwrap();
        atomic_write_text(&target, "second\r\nline").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second\nline\n");
        assert!(leftover_tmp_files(root.parent().unwrap()).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn normalize_matches_python() {
        assert_eq!(normalize_text("--a\r\n--b\r--c"), "--a\n--b\n--c\n");
        assert_eq!(normalize_text("already\n"), "already\n");
        assert_eq!(normalize_text(""), "");
        // python: (content or "") — пустая строка не получает "\n".
        assert_eq!(normalize_text("\r\n\r"), "\n\n");
    }
}
