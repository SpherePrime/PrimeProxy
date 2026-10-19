//! Порт `src/primebypass_update/versions.py` — единственное сравнение версий обновлятора.
//!
//! Версии PrimeBypass — только числа через точку (`21.1.5.67`), иногда с
//! префиксом `v`. Сравниваются они как числа, а не как строки: строковое
//! сравнение считало бы `21.1.10` старше `21.1.9`. Неверная запись версии —
//! ошибка, а не повод сравнить «как получится».
//!
//! Отличие от Python намеренное: Python `str.isdigit()` пропускает
//! юникодные цифры (например, арабские), Rust-порт принимает только
//! ASCII-цифры — это ближе к намерению исходного кода.
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use thiserror::Error;

/// Ошибка неверной записи версии; текст совпадает с Python-ошибкой.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("Invalid version format: {0}")]
pub struct VersionError(pub String);

fn strip_v_prefix(value: &str) -> &str {
    value.strip_prefix(['v', 'V']).unwrap_or(value)
}

fn is_all_ascii_digits(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
}

/// Версия без префикса `v`. Ошибка, если это не числа через точку.
///
/// Порт `normalize_version(ver_str)`.
pub fn normalize_version(ver_str: &str) -> Result<String, VersionError> {
    let value = strip_v_prefix(ver_str.trim());
    let mut parts = 0usize;
    for part in value.split('.') {
        if !is_all_ascii_digits(part) || part.len() > u32::MAX as usize {
            return Err(VersionError(value.to_string()));
        }
        parts += 1;
    }
    if parts < 2 {
        return Err(VersionError(value.to_string()));
    }
    Ok(value.to_string())
}

/// Числовой ключ версии без хвостовых нулей: `1.2` равно `1.2.0`.
///
/// Порт `version_key(ver_str)`.
pub fn version_key(ver_str: &str) -> Result<Vec<u64>, VersionError> {
    let normalized = normalize_version(ver_str)?;
    let mut parts: Vec<u64> = normalized
        .split('.')
        .map(|part| part.parse::<u64>())
        .collect::<Result<_, _>>()
        .map_err(|_| VersionError(normalized.clone()))?;
    while parts.len() > 1 && parts.last() == Some(&0) {
        parts.pop();
    }
    Ok(parts)
}

/// `-1`, `0` или `1`. Ошибка, если одна из версий записана неверно.
///
/// Порт `compare_versions(v1, v2)`.
pub fn compare_versions(v1: &str, v2: &str) -> Result<Ordering, VersionError> {
    let first = version_key(v1)?;
    let second = version_key(v2)?;
    Ok(first.cmp(&second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    fn err(text: &str) -> VersionError {
        VersionError(text.to_string())
    }

    #[test]
    fn normalizes_v_prefix_and_whitespace() {
        assert_eq!(normalize_version("v21.1.5").unwrap(), "21.1.5");
        assert_eq!(normalize_version("V21.1.5").unwrap(), "21.1.5");
        assert_eq!(normalize_version("  21.1.5  ").unwrap(), "21.1.5");
        assert_eq!(normalize_version("21.1.5.67").unwrap(), "21.1.5.67");
    }

    #[test]
    fn rejects_invalid_versions() {
        for bad in [
            "", "21", "abc", "1.2.", ".1.2", "1..2", "1.2.3.4.5.6.x", "21,1", "-1.2", "۱.۲",
        ] {
            assert!(normalize_version(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn error_text_matches_python() {
        assert_eq!(normalize_version("abc"), Err(err("abc")));
        assert_eq!(normalize_version("21"), Err(err("21")));
    }

    #[test]
    fn treats_single_part_as_invalid_even_with_digits() {
        assert!(normalize_version("21").is_err());
        assert!(normalize_version("v1").is_err());
    }

    #[test]
    fn numeric_not_lexicographic() {
        assert_eq!(compare_versions("21.1.10", "21.1.9"), Ok(Ordering::Greater));
        assert_eq!(compare_versions("21.1.9", "21.1.10"), Ok(Ordering::Less));
        assert_eq!(compare_versions("21.1.5.67", "21.1.5.7"), Ok(Ordering::Greater));
    }

    #[test]
    fn trailing_zeros_are_equal() {
        assert_eq!(compare_versions("1.2", "1.2.0"), Ok(Ordering::Equal));
        assert_eq!(compare_versions("1.2", "1.2.0.0"), Ok(Ordering::Equal));
        // Одна часть целиком — уже ошибка (Python: len(parts) < 2).
        assert!(normalize_version("0").is_err());
        assert_eq!(version_key("0.0"), Ok(vec![0]));
        assert_eq!(version_key("0.0.0"), Ok(vec![0]));
    }

    #[test]
    fn same_as_python_semantics() {
        // Проверено в Python: compare_versions("21.1", "21.1.0") == 0,
        // version_key("1.2") == (1, 2), "v10.10.10" == "10.10.10".
        assert_eq!(compare_versions("21.1", "21.1.0"), Ok(Ordering::Equal));
        assert_eq!(version_key("1.2"), Ok(vec![1, 2]));
        assert_eq!(compare_versions("v10.10.10", "10.10.10"), Ok(Ordering::Equal));
    }

    #[test]
    fn big_parts_fit_u64() {
        assert_eq!(version_key("18446744073709551615.1"), Ok(vec![u64::MAX, 1]));
        assert!(version_key("99999999999999999999999999").is_err());
    }
}
