//! Порт чистых функций `src/log/log.py` — имя журнала сессии, verbose-режим
//! и очистка старых журналов с раздельными лимитами.
//!
//! Асинхронный стор живого журнала (`_AsyncLogStore`) и `Logger` с
//! перенаправлением stdio — платформенные (потоки/файлы): их решение
//! (что записать, в какой файл) остаётся у вызывающего слоя.

use crate::log_kinds::{
    APP_LOG_PATTERNS, BLOCKCHECK_REPORT_PATTERNS, LEGACY_APP_LOG_PATTERNS,
    STRATEGY_SCAN_LOG_PATTERNS, WINWS_DEBUG_LOG_PATTERNS,
};

/// python `config.MAX_LOG_FILES` — основные логи приложения.
pub const MAX_LOG_FILES: usize = 50;
/// python `config.MAX_DEBUG_LOG_FILES` — журналы winws одного вида.
pub const MAX_DEBUG_LOG_FILES: usize = 20;
/// python `log.MAX_BLOCKCHECK_LOG_FILES` — история запусков BlockCheck.
pub const MAX_BLOCKCHECK_LOG_FILES: usize = 200;

/// python `_VERBOSE_LOG_ENV` — переменная окружения verbose-логов.
pub const VERBOSE_LOG_ENV: &str = "ZAPRET_GUI_VERBOSE_LOGS";
/// python `_VERBOSE_LOG_FLAGS` — аргументы командной строки verbose-логов.
pub const VERBOSE_LOG_FLAGS: [&str; 3] = ["--verbose-log", "--debug-log", "--diag-log"];

/// python `_is_truthy` — «включено» в строках окружения.
#[must_use]
pub fn is_truthy(value: &str) -> bool {
    ["1", "true", "yes", "on"].contains(&value.trim().to_lowercase().as_str())
}

/// python `_is_verbose_logging_enabled` — пишутся ли DEBUG/DIAG-логи:
/// переменная окружения сильнее, потом — флаги аргументов. Оба источника
/// (`env`, `args`) передаёт вызывающий код — чистая функция.
#[must_use]
pub fn is_verbose_logging_enabled(env_value: Option<&str>, args: &[String]) -> bool {
    if let Some(value) = env_value {
        if !value.trim().is_empty() {
            return is_truthy(value);
        }
    }
    args.iter()
        .any(|arg| VERBOSE_LOG_FLAGS.contains(&arg.trim().to_lowercase().as_str()))
}

/// python `get_current_log_filename` — имя журнала с датой и временем:
/// `zapret_log_ГГГГ-ММ-ДД_ЧЧ-ММ-СС.txt`. «Сейчас» передаётся частями
/// (год, месяц, день, час, минута, секунда) — чистая функция.
#[must_use]
pub fn current_log_filename(now: (i64, u32, u32, u32, u32, u32)) -> String {
    let (year, month, day, hour, minute, second) = now;
    format!("zapret_log_{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{second:02}.txt")
}

/// python `_cleanup_files_by_pattern` — удаляет старые файлы по шаблону,
/// оставляя последние `max_files` по времени изменения. Имена, времена
/// модификации и удаление — у вызывающего (платформенный слой).
pub fn cleanup_files_by_pattern(
    pattern: &str,
    max_files: usize,
    list_files: &dyn Fn(&str) -> Vec<(String, i64)>,
    remove: &dyn Fn(&str) -> Result<(), String>,
) -> (usize, Vec<String>, usize) {
    let mut files = list_files(pattern);
    let total_found = files.len();
    if total_found <= max_files {
        return (0, Vec::new(), total_found);
    }
    // Сортируем по времени модификации (старые первые; равные времена
    // сохраняют порядок — как стабильная сортировка python).
    files.sort_by_key(|(_, mtime)| *mtime);
    let mut deleted = 0;
    let mut errors = Vec::new();
    for (name, _) in &files[..total_found - max_files] {
        match remove(name) {
            Ok(()) => deleted += 1,
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    (deleted, errors, total_found)
}

/// python `cleanup_old_logs` — очистка папки журналов с раздельными лимитами:
/// - `zapret_log_*.txt` — `max_files`;
/// - журналы winws (оба шаблона) — по [`MAX_DEBUG_LOG_FILES`];
/// - старый формат `zapret_[0-9]*.log` — 10;
/// - история BlockCheck (журнал и отчёт) — [`MAX_BLOCKCHECK_LOG_FILES`].
///
/// Возвращает (сколько удалено, ошибки, сколько найдено) — как python.
pub fn cleanup_old_logs(
    max_files: usize,
    list_files: &dyn Fn(&str) -> Vec<(String, i64)>,
    remove: &dyn Fn(&str) -> Result<(), String>,
) -> (usize, Vec<String>, usize) {
    let mut total_deleted = 0;
    let mut all_errors: Vec<String> = Vec::new();
    let mut total_found = 0;
    let mut step = |pattern: &str, limit: usize| {
        let (deleted, errors, found) = cleanup_files_by_pattern(pattern, limit, list_files, remove);
        total_deleted += deleted;
        all_errors.extend(errors);
        total_found += found;
    };
    step(APP_LOG_PATTERNS[0], max_files);
    for pattern in WINWS_DEBUG_LOG_PATTERNS {
        step(pattern, MAX_DEBUG_LOG_FILES);
    }
    step(LEGACY_APP_LOG_PATTERNS[0], 10);
    step(STRATEGY_SCAN_LOG_PATTERNS[0], MAX_BLOCKCHECK_LOG_FILES);
    step(BLOCKCHECK_REPORT_PATTERNS[0], MAX_BLOCKCHECK_LOG_FILES);
    (total_deleted, all_errors, total_found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Файловая система-подставка: списки по шаблону и удаление из списка.
    /// Подставка файловой системы: список (имя, mtime) + удаление из него.
    type FakeFs = (std::rc::Rc<std::cell::RefCell<Vec<(String, i64)>>>,);

    fn make_fs(
        files: FakeFs,
    ) -> (
        impl Fn(&str) -> Vec<(String, i64)>,
        impl Fn(&str) -> Result<(), String>,
    ) {
        let list_files = std::rc::Rc::clone(&files);
        let list = move |pattern: &str| {
            list_files
                .borrow()
                .iter()
                .filter(|(name, _)| matches(pattern, name))
                .cloned()
                .collect()
        };
        let remove_files = files;
        let remove = move |name: &str| {
            let mut all = remove_files.borrow_mut();
            match all.iter().position(|(item, _)| item == name) {
                Some(index) => {
                    all.remove(index);
                    Ok(())
                }
                None => Err("нет такого файла".to_string()),
            }
        };
        (list, remove)
    }

    #[test]
    fn cleanup_keeps_the_newest_files() {
        // Эталон от python: 5 файлов, лимит 3 → удалены 2 старейших.
        let files = std::rc::Rc::new(std::cell::RefCell::new(vec![
            ("zapret_log_2026-10-20_10-00-00.txt".to_string(), 1000),
            ("zapret_log_2026-10-21_10-00-00.txt".to_string(), 2000),
            ("zapret_log_2026-10-22_10-00-00.txt".to_string(), 3000),
            ("zapret_log_2026-10-23_10-00-00.txt".to_string(), 4000),
            ("zapret_log_2026-10-24_10-00-00.txt".to_string(), 5000),
        ]));
        let (list, remove) = make_fs(std::rc::Rc::clone(&files));
        let (deleted, errors, found) =
            cleanup_files_by_pattern("zapret_log_*.txt", 3, &list, &remove);
        assert_eq!((deleted, errors.is_empty(), found), (2, true, 5));
        let left: Vec<String> = files
            .borrow()
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(
            left,
            vec![
                "zapret_log_2026-10-22_10-00-00.txt",
                "zapret_log_2026-10-23_10-00-00.txt",
                "zapret_log_2026-10-24_10-00-00.txt",
            ]
        );
    }

    #[test]
    fn old_logs_cleanup_respects_separate_limits() {
        // Каждый вид — свой лимит; в пределах лимита удалений нет.
        let files = std::rc::Rc::new(std::cell::RefCell::new(vec![
            ("zapret_log_1.txt".to_string(), 1),
            ("flowseal_debug.log".to_string(), 2),
            ("zapret_winws2_debug_x.log".to_string(), 3),
            ("zapret_123.log".to_string(), 4),
            ("blockcheck_run_a.log".to_string(), 5),
            ("blockcheck_run_a.json".to_string(), 6),
        ]));
        let (list, _remove) = make_fs(files);
        let failing = |_name: &str| Err("занято".to_string());
        let (deleted, errors, found) = cleanup_old_logs(MAX_LOG_FILES, &list, &failing);
        // Каждый файл подходит одному шаблону (python-glob), все в пределах
        // лимитов — удалять нечего.
        assert_eq!((deleted, errors.len(), found), (0, 0, 6));
    }

    #[test]
    fn debug_log_limit_triggers_deletion() {
        // 21 файл *_debug.log при лимите 20: удаляется один старейший,
        // ошибка отказа несёт имя файла (python-формат).
        let files = std::rc::Rc::new(std::cell::RefCell::new(
            (0..21)
                .map(|index| (format!("preset{index}_debug.log"), index as i64))
                .collect(),
        ));
        let (list, _remove) = make_fs(std::rc::Rc::clone(&files));
        let (deleted, errors, found) = cleanup_old_logs(MAX_LOG_FILES, &list, &|name| {
            // Удаление проходит — как в python (os.remove успешен).
            let mut all = files.borrow_mut();
            if let Some(index) = all.iter().position(|(item, _)| item == name) {
                all.remove(index);
            }
            Ok(())
        });
        // Эталон от python: 21 файл при лимите 20 → удалён один старейший.
        assert_eq!((deleted, errors.len(), found), (1, 0, 21));
        let left: Vec<String> = files
            .borrow()
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        assert!(!left.contains(&"preset0_debug.log".to_string()));
        assert!(left.contains(&"preset1_debug.log".to_string()));
    }

    #[test]
    fn verbose_flag_sources() {
        // Переменная окружения сильнее флагов; пустая строка пропускается.
        assert!(is_verbose_logging_enabled(Some("1"), &[]));
        assert!(is_verbose_logging_enabled(Some(" yes "), &[]));
        assert!(!is_verbose_logging_enabled(
            Some("0"),
            &["--verbose-log".to_string()]
        ));
        assert!(!is_verbose_logging_enabled(Some(""), &[]));
        assert!(is_verbose_logging_enabled(
            None,
            &["--debug-log".to_string()]
        ));
        assert!(is_verbose_logging_enabled(
            None,
            &["--DIAG-LOG".to_string()]
        ));
        assert!(!is_verbose_logging_enabled(None, &["--другое".to_string()]));
        assert!(!is_verbose_logging_enabled(None, &[]));
    }

    #[test]
    fn truthy_and_filename() {
        assert!(is_truthy("On"));
        assert!(!is_truthy("включено"));
        // python strftime("%Y-%m-%d_%H-%M-%S").
        assert_eq!(
            current_log_filename((2026, 10, 21, 7, 5, 9)),
            "zapret_log_2026-10-21_07-05-09.txt"
        );
    }
}
