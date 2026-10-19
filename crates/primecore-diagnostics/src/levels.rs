//! Порт `src/diagnostics/levels.py` — уровни итога проверки как строки отчёта.
//!
//! В отчёте и в истории уровень лежит строкой (`"ok"`, `"warn"`, `"fail"`,
//! `"unknown"`) — значением `diagnostics.verdict::Level`. Что считать «сайт
//! открывается» и в каком порядке показывать уровни, решается только здесь.

pub const OK: &str = "ok";
pub const WARN: &str = "warn";
pub const FAIL: &str = "fail";
pub const UNKNOWN: &str = "unknown";

/// По важности: сначала то, что сломано, потом оговорки, потом неизвестное.
pub const LEVELS: [&str; 4] = [FAIL, WARN, UNKNOWN, OK];

/// Сайт открывается: всё хорошо или открывается с оговорками.
pub const OPEN_LEVELS: [&str; 2] = [OK, WARN];

fn ranked(level: &str) -> Option<usize> {
    LEVELS.iter().position(|candidate| *candidate == level)
}

/// Место уровня в порядке важности; неизвестное значение — в самый конец.
pub fn level_rank(level: &str) -> usize {
    ranked(level).unwrap_or(LEVELS.len())
}

pub fn is_open(level: &str) -> bool {
    OPEN_LEVELS.contains(&level)
}

/// python `worst(levels)` — самый важный из уровней (lowercase строки,
/// гетерогенные значения приводятся к тексту). Пустой список — `ok`.
pub fn worst(levels: &[&str]) -> String {
    levels
        .iter()
        .copied()
        .filter_map(ranked)
        .min()
        .map(|rank| LEVELS[rank].to_string())
        .unwrap_or_else(|| OK.to_string())
}

/// python: `worst` принимает и `Level`-объекты движка, и строки отчёта;
/// в Rust Level даёт `value()` — удобно собрать список строк.
pub fn worst_values(levels: Vec<String>) -> String {
    let borrowed: Vec<&str> = levels.iter().map(String::as_str).collect();
    worst(&borrowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_and_worst() {
        assert_eq!(LEVELS, ["fail", "warn", "unknown", "ok"]);
        assert_eq!(level_rank("fail"), 0);
        assert_eq!(level_rank("warn"), 1);
        assert_eq!(level_rank("unknown"), 2);
        assert_eq!(level_rank("ok"), 3);
        assert_eq!(level_rank("мимо"), 4);
        assert!(is_open("ok"));
        assert!(is_open("warn"));
        assert!(!is_open("fail"));
        assert_eq!(worst(&["ok", "warn"]), "warn");
        assert_eq!(worst(&["unknown", "fail"]), "fail");
        assert_eq!(worst(&[]), "ok");
        assert_eq!(worst(&["мимо"]), "ok");
    }
}
