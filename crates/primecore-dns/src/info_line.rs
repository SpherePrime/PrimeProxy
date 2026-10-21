//! [`InfoLine`] — строка состояния с тоном (цветом) из python-модуля
//! `dns.domain_lookup_plans`. Она общая для нескольких модулей показа, поэтому
//! живёт отдельно и переиспользуется будущим портом `domain_lookup_plans`.

/// Тон строки: нейтральный, приглушённый.
pub const TONE_MUTED: &str = "muted";
/// Тон строки: акцентный (идёт работа).
pub const TONE_ACCENT: &str = "accent";
/// Тон строки: успешный.
pub const TONE_SUCCESS: &str = "success";
/// Тон строки: предупреждение.
pub const TONE_WARNING: &str = "warning";
/// Тон строки: ошибка.
pub const TONE_ERROR: &str = "error";

/// python `InfoLine(text, tone)` — одна строка состояния и её тон.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoLine {
    pub text: String,
    pub tone: String,
}

impl InfoLine {
    /// python `InfoLine(text, tone)`; тон по умолчанию — [`TONE_MUTED`].
    #[must_use]
    pub fn new(text: impl Into<String>, tone: &str) -> Self {
        Self {
            text: text.into(),
            tone: tone.to_string(),
        }
    }

    /// python `InfoLine(text)` — с тоном по умолчанию.
    #[must_use]
    pub fn muted(text: impl Into<String>) -> Self {
        Self::new(text, TONE_MUTED)
    }
}
