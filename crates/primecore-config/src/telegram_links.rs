//! Порт `src/config/telegram_links.py` (чистая часть) — построение пары
//! Telegram-ссылок (tg:// с fallback на https://).
//!
//! `is_telegram_installed` (winreg) и открытие ссылок (webbrowser) —
//! платформенные, остаются у вызывающего слоя.

use regex::Regex;
use std::sync::LazyLock;

/// python `_START_RE` — рекламные метки (параметр start) для ссылок на
/// бота @zapretvpns_bot. Формат метки общий для всех проектов Zapret:
/// «<источник>_<место>», источник PrimeBypass — «gui». По метке бот
/// показывает на панели «Реклама», откуда пришёл человек.
static START_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_-]{1,64}").expect("regex"));

/// python `telegram_urls` — возвращает пару (tg://-ссылка, https://-ссылка).
///
/// `start` — рекламная метка бота (deep-link): только A-Za-z0-9_-, до
/// 64 символов, префикс «ref_» зарезервирован под рефералов. Ошибка
/// метки — значение (python ValueError).
///
/// Приоритет: slug (ссылка на папку с каналами) → post → start.
pub fn telegram_urls(
    domain: &str,
    post: Option<i64>,
    slug: Option<&str>,
    start: Option<&str>,
) -> Result<(String, String), String> {
    if let Some(start) = start {
        // python: _START_RE.fullmatch(start) и не начинается с "ref_".
        let matched = START_RE
            .find(start)
            .is_some_and(|m| m.as_str() == start && m.start() == 0 && m.end() == start.len());
        if !matched || start.starts_with("ref_") {
            return Err(format!("Недопустимая метка start: '{start}'"));
        }
    }
    if let Some(slug) = slug.filter(|s| !s.is_empty()) {
        return Ok((
            format!("tg://addlist?slug={slug}"),
            format!("https://t.me/addlist/{slug}"),
        ));
    }
    if let Some(post) = post.filter(|post| *post != 0) {
        // python: `if post:` — ноль считается отсутствующим.
        return Ok((
            format!("tg://resolve?domain={domain}&post={post}"),
            format!("https://t.me/{domain}/{post}"),
        ));
    }
    if let Some(start) = start {
        return Ok((
            format!("tg://resolve?domain={domain}&start={start}"),
            format!("https://t.me/{domain}?start={start}"),
        ));
    }
    Ok((
        format!("tg://resolve?domain={domain}"),
        format!("https://t.me/{domain}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_match_python_priority() {
        // Эталон от python: telegram_urls("zaprethelp") и варианты.
        assert_eq!(
            telegram_urls("zaprethelp", None, None, None).ok(),
            Some((
                "tg://resolve?domain=zaprethelp".to_string(),
                "https://t.me/zaprethelp".to_string(),
            ))
        );
        assert_eq!(
            telegram_urls("zaprethelp", Some(123), None, None).ok(),
            Some((
                "tg://resolve?domain=zaprethelp&post=123".to_string(),
                "https://t.me/zaprethelp/123".to_string(),
            ))
        );
        assert_eq!(
            telegram_urls("x", None, Some("abc123"), None).ok(),
            Some((
                "tg://addlist?slug=abc123".to_string(),
                "https://t.me/addlist/abc123".to_string(),
            ))
        );
        assert_eq!(
            telegram_urls("zaprethelp", None, None, Some("gui_main")).ok(),
            Some((
                "tg://resolve?domain=zaprethelp&start=gui_main".to_string(),
                "https://t.me/zaprethelp?start=gui_main".to_string(),
            ))
        );
        // slug сильнее post и start (python: if slug → return).
        assert_eq!(
            telegram_urls("x", Some(1), Some("s"), Some("gui")).ok(),
            Some((
                "tg://addlist?slug=s".to_string(),
                "https://t.me/addlist/s".to_string(),
            ))
        );
    }

    #[test]
    fn start_labels_validated() {
        // python: _START_RE.fullmatch, до 64 символов, без ref_-префикса.
        assert!(telegram_urls("x", None, None, Some("gui_main")).is_ok());
        assert!(telegram_urls("x", None, None, Some("A-b_9")).is_ok());
        assert!(telegram_urls("x", None, None, Some("ref_abc")).is_err());
        assert!(telegram_urls("x", None, None, Some("с пробелом")).is_err());
        assert!(telegram_urls("x", None, None, Some("bad.dot")).is_err());
        // 65 символов — длиннее допустимого.
        let long = "a".repeat(65);
        assert!(telegram_urls("x", None, None, Some(&long)).is_err());
        // 64 символа — допустимо.
        let ok = "a".repeat(64);
        assert!(telegram_urls("x", None, None, Some(&ok)).is_ok());
        // Пустая строка не fullmatch (нужно 1..=64).
        assert!(telegram_urls("x", None, None, Some("")).is_err());
    }

    #[test]
    fn zero_post_and_empty_slug_are_falsy_like_python() {
        // python: `if post:` / `if slug:` — 0 и пустая строка пропускаются.
        assert_eq!(
            telegram_urls("x", Some(0), None, None).ok(),
            Some((
                "tg://resolve?domain=x".to_string(),
                "https://t.me/x".to_string(),
            ))
        );
        assert_eq!(
            telegram_urls("x", None, Some(""), None).ok(),
            Some((
                "tg://resolve?domain=x".to_string(),
                "https://t.me/x".to_string(),
            ))
        );
    }

    #[test]
    fn start_error_message_matches_python() {
        // python: f"Недопустимая метка start: {start!r}".
        assert_eq!(
            telegram_urls("x", None, None, Some("ref_1")).unwrap_err(),
            "Недопустимая метка start: 'ref_1'"
        );
    }
}
