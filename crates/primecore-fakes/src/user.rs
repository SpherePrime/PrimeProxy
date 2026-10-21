//! Порт `fakes/user_fakes.py` (часть о записях секции настроек) — свои
//! фейки пользователя: имена, нормализация строк секции `user_fakes`.
//!
//! Чтение/запись settings.sqlite3 и файловые операции — платформенные.

use serde_json::Value;

/// python `USER_FAKE_NAME_MAX_LENGTH`.
pub const NAME_MAX_LENGTH: usize = 64;

/// python `UserFakeEntry` — свой фейк: имя blob-а и файл в `user/fakes/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFakeEntry {
    pub name: String,
    pub file_name: String,
    pub kind: String,
    pub sni: Option<String>,
    pub description: String,
    pub created_at: String,
}

impl UserFakeEntry {
    /// python `blob_value` — значение после `--blob=<имя>:`.
    #[must_use]
    pub fn blob_value(&self) -> String {
        format!("@user/fakes/{}", self.file_name)
    }

    /// python `blob_line`.
    #[must_use]
    pub fn blob_line(&self) -> String {
        format!("--blob={}:{}", self.name, self.blob_value())
    }
}

/// python `normalize_user_fake_row` — строка секции `user_fakes` или
/// `None`, если она испорчена (python возвращал None и её молча
/// выбрасывали).
#[must_use]
pub fn normalize_user_fake_row(name: &str, raw: &Value) -> Option<UserFakeEntry> {
    let name = name.trim();
    if name.is_empty() || name.len() > NAME_MAX_LENGTH {
        return None;
    }
    if !super::catalog::valid_fake_name(name) {
        return None;
    }
    let object = raw.as_object()?;
    let file_name = object.get("file_name").and_then(Value::as_str)?.trim();
    if file_name.is_empty() || !file_name.ends_with(".bin") {
        return None;
    }
    if file_name.contains('/') || file_name.contains('\\') {
        return None;
    }
    let kind = object.get("kind").and_then(Value::as_str)?;
    if !super::catalog::FAKE_KINDS.contains(&kind) {
        return None;
    }
    Some(UserFakeEntry {
        name: name.to_string(),
        file_name: file_name.to_string(),
        kind: kind.to_string(),
        sni: object
            .get("sni")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: object
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        created_at: object
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// python `user_fakes_from_section` — все записи секции в порядке словаря
/// (serde_json с preserve_order сохраняет порядок вставки).
#[must_use]
pub fn user_fakes_from_section(section: &Value) -> Vec<UserFakeEntry> {
    let Some(map) = section.as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter_map(|(name, raw)| normalize_user_fake_row(name, raw))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_accepts_good_row() {
        let entry = normalize_user_fake_row(
            "my_fake",
            &json!({
                "file_name": "my_fake.bin",
                "kind": "tls",
                "sni": "example.com",
                "description": "свой фейк",
                "created_at": "2026-10-21T10:00:00Z",
            }),
        );
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.blob_value(), "@user/fakes/my_fake.bin");
        assert_eq!(entry.blob_line(), "--blob=my_fake:@user/fakes/my_fake.bin");
    }

    #[test]
    fn normalize_rejects_bad_rows() {
        // Цифра в начале имени.
        assert!(
            normalize_user_fake_row("9fake", &json!({"file_name": "f.bin", "kind": "tls"}))
                .is_none()
        );
        // Пустое имя.
        assert!(
            normalize_user_fake_row(" ", &json!({"file_name": "f.bin", "kind": "tls"})).is_none()
        );
        // Не .bin.
        assert!(
            normalize_user_fake_row("f", &json!({"file_name": "f.txt", "kind": "tls"})).is_none()
        );
        // Путь в file_name.
        assert!(
            normalize_user_fake_row("f", &json!({"file_name": "sub/f.bin", "kind": "tls"}))
                .is_none()
        );
        // Неизвестный kind.
        assert!(
            normalize_user_fake_row("f", &json!({"file_name": "f.bin", "kind": "magic"})).is_none()
        );
        // Не объект.
        assert!(normalize_user_fake_row("f", &json!("строка")).is_none());
        // Слишком длинное имя.
        let long = "a".repeat(NAME_MAX_LENGTH + 1);
        assert!(
            normalize_user_fake_row(&long, &json!({"file_name": "f.bin", "kind": "tls"})).is_none()
        );
    }

    #[test]
    fn section_iteration_skips_bad_rows() {
        let section = json!({
            "good": {"file_name": "good.bin", "kind": "tls", "description": "ок"},
            "bad": {"file_name": "no_kind.bin"},
        });
        let entries = user_fakes_from_section(&section);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good");
        // Мусорная секция — пусто, без ошибки.
        assert!(user_fakes_from_section(&json!("мусор")).is_empty());
    }
}
