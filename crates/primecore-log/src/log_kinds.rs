//! Порт `src/log/log_kinds.py` — какие файлы в папке журналов какого вида —
//! одно место для всех, кто их ищет.
//!
//! Журнал отладки winws пишется под стабильным именем `<пресет>_debug.log`
//! (`profile.settings._build_stable_debug_log_file`); раньше имя было
//! `zapret_winws2_debug_<время>.log`. Страница журналов, очистка, разбор
//! журнала winws и обращения в поддержку искали каждый свой набор шаблонов,
//! и четверо из пяти знали только старое имя: журнал winws, ради которого
//! собирают обращение, в архив не попадал. Теперь шаблоны берутся только
//! отсюда.

/// Журнал самой программы.
pub const APP_LOG_PATTERNS: [&str; 1] = ["zapret_log_*.txt"];
/// Его старый вид.
pub const LEGACY_APP_LOG_PATTERNS: [&str; 1] = ["zapret_[0-9]*.log"];
/// Вывод winws2/winws: нынешнее имя по пресету и старое имя по времени
/// запуска.
pub const WINWS_DEBUG_LOG_PATTERNS: [&str; 2] = ["*_debug.log", "zapret_winws2_debug_*.log"];
/// Отчёт проверки сайтов BlockCheck.
pub const BLOCKCHECK_REPORT_PATTERNS: [&str; 1] = ["blockcheck_run_*.json"];
/// Журнал подбора стратегий.
pub const STRATEGY_SCAN_LOG_PATTERNS: [&str; 1] = ["blockcheck_run_*.log"];
/// Журнал «Диспетчера» (orchestra).
pub const ORCHESTRA_LOG_PATTERNS: [&str; 1] = ["orchestra_*.log"];

/// python `glob.fnmatch` для шаблонов вида выше: `*` — любые символы,
/// `[0-9]` — один символ из диапазона, прочее — буквально.
#[must_use]
pub fn matches(pattern: &str, name: &str) -> bool {
    fn inner(pattern: &[u8], name: &[u8]) -> bool {
        match (pattern.first(), name.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                // * съедает пусто или один символ и продолжается.
                inner(&pattern[1..], name) || (!name.is_empty() && inner(pattern, &name[1..]))
            }
            (Some(b'['), _) => {
                let Some(close) = pattern.iter().skip(1).position(|byte| *byte == b']') else {
                    // Незакрытый диапазон — квадратная скобка буквальная.
                    return !name.is_empty() && name[0] == b'[' && inner(&pattern[1..], &name[1..]);
                };
                // После диапазона обязана идти закрывающая скобка — её
                // съедаем: rest начинается за ней.
                let range = &pattern[1..close + 1];
                let rest = &pattern[close + 2..];
                let Some(first) = name.first().copied() else {
                    return false;
                };
                let in_range = range
                    .windows(3)
                    .any(|window| window[1] == b'-' && window[0] <= first && first <= window[2])
                    || range.contains(&first);
                in_range && inner(rest, &name[1..])
            }
            (Some(expected), Some(actual)) => {
                expected == actual && inner(&pattern[1..], &name[1..])
            }
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
    inner(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_python_globs() {
        // python-тест log_kinds: журнал winws по пресету и по времени.
        assert!(matches(
            "zapret_log_*.txt",
            "zapret_log_2026-10-21_12-00-00.txt"
        ));
        assert!(matches("*_debug.log", "flowseal-1103-winws1_debug.log"));
        // python-glob: суффикс шаблона обязан совпасть целиком.
        assert!(!matches(
            "zapret_winws2_debug_*.log",
            "zapret_winws2_debug_2026-10-21.txt"
        ));
        assert!(matches(
            "zapret_winws2_debug_*.log",
            "zapret_winws2_debug_2026-10-21.log"
        ));
        // Старый формат — по одной цифре на позицию.
        assert!(matches("zapret_[0-9]*.log", "zapret_123.log"));
        assert!(!matches("zapret_[0-9]*.log", "zapret_abc.log"));
        assert!(matches(
            "blockcheck_run_*.json",
            "blockcheck_run_2026-10-21.json"
        ));
        assert!(matches("orchestra_*.log", "orchestra_beta.log"));
        assert!(!matches("zapret_log_*.txt", "other.txt"));
    }
}
