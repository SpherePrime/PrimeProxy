//! Разбор стартового вывода winws/winws2 — единый источник правды.
//!
//! Порт `winws_runtime/health/winws_output.py`. winws2 при каждом запуске
//! первой строкой печатает служебный баннер вида
//! `github version v1.0.3 (b78b52c4...) lua_compat_ver 6`. Из-за него наивная
//! проверка «вывод пустой» никогда не срабатывает для winws2: процесс, убитый
//! антивирусом до единого сообщения об ошибке, выглядит как процесс с выводом,
//! а пользователю в качестве «причины» показывалась строка версии.
//!
//! Поэтому здесь баннер отделён от диагностики:
//! - [`has_diagnostic_output`] — сказал ли процесс хоть что-то по существу;
//! - [`relevant_error_line`] — какая строка достойна показа пользователю.
//!
//! Оба ответа обязаны быть одинаковыми во всех точках диагностики (раннеры,
//! post-mortem, WinDivert-диагноз), поэтому дублировать эту логику нельзя.

use regex::Regex;
use std::sync::OnceLock;

/// Служебные строки, которые winws/winws2 печатает всегда, независимо от исхода.
fn banner_patterns() -> &'static [Regex; 2] {
    static PATTERNS: OnceLock<[Regex; 2]> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            // winws2: "github version v1.0.3 (b78b52c4...) lua_compat_ver 6"
            Regex::new(r"(?i)^(?:github\s+)?version\s+\S+").expect("корректный regexp"),
            // winws1/nfqws: "winws v70.3", "winws2.exe v1.0.3"
            Regex::new(r"(?i)^(?:winws|nfqws)\d*(?:\.exe)?\s+v?\d").expect("корректный regexp"),
        ]
    })
}

/// Маркеры настоящей диагностики. Строка с ними никогда не считается служебной,
/// даже если формально похожа на баннер.
const WINDIVERT_MARKERS: [&str; 2] = ["windivert:", "error opening filter"];
/// Маркеры ошибки (латиница и кириллица).
const ERROR_MARKERS: [&str; 2] = ["error", "ошибка"];

/// Какую строку вернуть, если содержательных строк с маркерами нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackLine {
    /// Первая диагностическая строка.
    First,
    /// Последняя диагностическая строка.
    Last,
    /// Ничего: вызывающий код сам решит, что показать.
    None,
}

/// True для служебной строки версии, не несущей диагностики.
pub fn is_banner_line(line: &str) -> bool {
    let text = line.trim();
    if text.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    if WINDIVERT_MARKERS.iter().any(|m| lower.contains(m)) {
        return false;
    }
    if ERROR_MARKERS.iter().any(|m| lower.contains(m)) {
        return false;
    }
    banner_patterns()
        .iter()
        .any(|pattern| pattern.is_match(text))
}

/// Непустые строки вывода без служебного баннера версии.
pub fn diagnostic_lines(output: &str) -> Vec<&str> {
    output
        .split('\n')
        .map(|raw_line| raw_line.trim())
        .filter(|line| !line.is_empty() && !is_banner_line(line))
        .collect()
}

/// True, если процесс успел сказать что-то кроме строки версии.
///
/// Ровно этот предикат заменяет «вывод непустой» во всех местах, где важно
/// «процесс умер молча»: у winws2 буквально пустого вывода не бывает.
pub fn has_diagnostic_output(output: &str) -> bool {
    !diagnostic_lines(output).is_empty()
}

/// Самая содержательная строка вывода для показа пользователю.
///
/// Порядок приоритетов повторяет прежние (продублированные) реализации:
/// сначала WinDivert-строка с конца вывода, затем любая строка с признаком
/// ошибки с конца, затем — `fallback`-строка среди диагностических.
/// `FallbackLine::None` отключает последний шаг: вызывающий код сам решит,
/// что показать, когда содержательного текста нет.
pub fn relevant_error_line(output: &str, fallback: FallbackLine) -> String {
    let lines = diagnostic_lines(output);
    if lines.is_empty() {
        return String::new();
    }

    for line in lines.iter().rev() {
        let lower = line.to_lowercase();
        if WINDIVERT_MARKERS.iter().any(|m| lower.contains(m)) {
            return (*line).to_string();
        }
    }
    for line in lines.iter().rev() {
        let lower = line.to_lowercase();
        if ERROR_MARKERS.iter().any(|m| lower.contains(m)) {
            return (*line).to_string();
        }
    }

    match fallback {
        FallbackLine::First => lines[0].to_string(),
        FallbackLine::Last => lines[lines.len() - 1].to_string(),
        FallbackLine::None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BANNER: &str =
        "github version v1.0.3 (b78b52c4cd7f843da3ff0848a3430afbd401bdf2) lua_compat_ver 6";
    const BANNER_SHORT: &str = "github version v1.0.1 lua_compat_ver 6";
    const WINDIVERT_ERROR: &str = "windivert: error opening filter: The service cannot be started";

    #[test]
    fn banner_lines_are_recognized() {
        for line in [
            BANNER,
            BANNER_SHORT,
            "version v1.0.3 lua_compat_ver 6",
            "winws v70.3",
            "winws2.exe v1.0.3",
            "nfqws v2.1",
        ] {
            assert!(is_banner_line(line), "{line}");
        }
    }

    #[test]
    fn meaningful_lines_are_not_banners() {
        for line in [
            "",
            "   ",
            WINDIVERT_ERROR,
            "error: unknown parameter --nope",
            "ошибка загрузки lua",
            "desync function 'fake' does not exist",
        ] {
            assert!(!is_banner_line(line), "{line:?}");
        }
    }

    #[test]
    fn banner_shaped_line_with_error_marker_stays_diagnostic() {
        // Строка версии с признаком ошибки не должна проглатываться.
        assert!(!is_banner_line("github version v1.0.3: version error"));
    }

    #[test]
    fn has_diagnostic_output_ignores_banner_only_output() {
        assert!(!has_diagnostic_output(""));
        assert!(!has_diagnostic_output(BANNER));
        assert!(!has_diagnostic_output(
            format!("{BANNER}\n\n   \n").as_str()
        ));
        assert!(has_diagnostic_output(
            format!("{BANNER}\n{WINDIVERT_ERROR}").as_str()
        ));
        assert!(has_diagnostic_output("usage: winws2 <options>"));
    }

    #[test]
    fn relevant_error_line_prefers_windivert_from_the_tail() {
        let output = format!("{BANNER}\nerror: something earlier\n{WINDIVERT_ERROR}");
        assert_eq!(
            relevant_error_line(&output, FallbackLine::First),
            WINDIVERT_ERROR
        );
    }

    #[test]
    fn relevant_error_line_prefers_last_error_marker() {
        let output = format!("{BANNER}\nerror: first\nerror: last");
        assert_eq!(
            relevant_error_line(&output, FallbackLine::First),
            "error: last"
        );
    }

    #[test]
    fn relevant_error_line_fallbacks_skip_the_banner() {
        let output = format!("{BANNER}\nusage: winws2 <options>\nsee docs");
        assert_eq!(
            relevant_error_line(&output, FallbackLine::First),
            "usage: winws2 <options>"
        );
        assert_eq!(relevant_error_line(&output, FallbackLine::Last), "see docs");
        assert_eq!(relevant_error_line(&output, FallbackLine::None), "");
    }

    #[test]
    fn banner_only_output_has_no_relevant_line() {
        for fallback in [FallbackLine::First, FallbackLine::Last, FallbackLine::None] {
            assert_eq!(relevant_error_line(BANNER, fallback), "", "{fallback:?}");
        }
        assert_eq!(relevant_error_line("", FallbackLine::First), "");
    }
}
