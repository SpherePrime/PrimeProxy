//! Ошибки операций над пресетами (python `ValueError`).
//!
//! Формат сообщений один-в-один с python-кодом пакета `presets`, чтобы
//! строки дошли до пользователя без переводчиков между слоями.

/// Причина отказа операции над пресетом; текст — сообщение python `ValueError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PresetError(pub String);

impl PresetError {
    /// python `ValueError(f"...")`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Результат операций над пресетами: значение или [`PresetError`].
pub type PresetResult<T> = Result<T, PresetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_message_roundtrip() {
        let error = PresetError::new("Preset not found: x.txt");
        assert_eq!(error.to_string(), "Preset not found: x.txt");
        assert_eq!(error, PresetError("Preset not found: x.txt".to_string()));
        let mapped: PresetResult<()> = Err(error);
        assert!(mapped.is_err());
    }
}
