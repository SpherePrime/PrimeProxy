//! Модуль привилегий Linux — «sudo один раз при первом запуске».
//!
//! Схема: при первом запуске Electron зовёт `pkexec`/`sudo` → стартует
//! демон `privd`, который держит привилегии; все последующие повышения
//! идут через unix-сокет без пароля. Состояние хранится в
//! `privilege.json`; при истечении сессии (12 часов) или перезагрузке
//! пароль запрашивается снова — ровно один раз.
//!
//! Здесь только чистая логика (состояние, TTL, выбор команды повышения).
//! Платформенный слой (проверка PATH, запуск процессов) — снаружи.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub mod client;
pub mod ops;

/// Время жизни привилегированной сессии: 12 часов.
pub const SESSION_TTL_S: i64 = 12 * 3600;

/// Имя файла состояния внутри каталога состояния.
pub const STATE_FILE_NAME: &str = "privilege.json";

/// Имя демон-помощника (бинарник `privd` из этого же крейта).
pub const HELPER_NAME: &str = "privd";

/// Сохранённое состояние привилегированной сессии.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegeState {
    /// Повышение уже было запрошено и принято пользователем.
    pub granted: bool,
    /// Момент выдачи привилегий (unix-время, секунды).
    pub granted_at_epoch_s: i64,
    /// Путь (или имя) бинарника демон-помощника.
    pub helper_path: String,
}

/// Путь файла состояния: `privilege.json` внутри `dir`.
pub fn path_state(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE_NAME)
}

/// Загрузить состояние из `dir`. Отсутствие файла — не ошибка: возвращается `None`.
pub fn load_state(dir: &Path) -> Result<Option<PrivilegeState>, String> {
    let path = path_state(dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|e| {
            format!(
                "primecore-privilege: не удалось разобрать {}: {e}",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "primecore-privilege: не удалось прочитать {}: {e}",
            path.display()
        )),
    }
}

/// Сохранить состояние в `dir` (каталог создаётся при необходимости).
pub fn save_state(dir: &Path, state: &PrivilegeState) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "primecore-privilege: не удалось создать каталог {}: {e}",
            dir.display()
        )
    })?;
    let text = serde_json::to_string_pretty(state)
        .map_err(|e| format!("primecore-privilege: не удалось сериализовать состояние: {e}"))?;
    std::fs::write(path_state(dir), text).map_err(|e| {
        format!(
            "primecore-privilege: не удалось записать {}: {e}",
            path_state(dir).display()
        )
    })
}

/// Состояние валидно: повышение было и сессия не старше `SESSION_TTL_S`.
/// На границе (ровно 12 часов) сессия ещё валидна — «не старше».
pub fn is_valid(state: &PrivilegeState, now_epoch_s: i64) -> bool {
    state.granted && now_epoch_s - state.granted_at_epoch_s <= SESSION_TTL_S
}

/// Надо ли спрашивать пароль: состояние отсутствует, не валидно
/// или сессия истекла (TTL 12 часов) — то есть повышение не активно.
pub fn needs_prompt(state: Option<&PrivilegeState>, now_epoch_s: i64) -> bool {
    match state {
        Some(state) => !is_valid(state, now_epoch_s),
        None => true,
    }
}

/// Команда первого запуска помощника: `["pkexec", helper]`, если в
/// системе есть `pkexec`, иначе `["sudo", helper]`. Наличие `pkexec`
/// проверяет замыкание (проверка PATH — платформенный слой).
pub fn helper_command<F: FnOnce() -> bool>(has_pkexec: F) -> Vec<String> {
    if has_pkexec() {
        vec!["pkexec".to_string(), HELPER_NAME.to_string()]
    } else {
        vec!["sudo".to_string(), HELPER_NAME.to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(granted_at: i64) -> PrivilegeState {
        PrivilegeState {
            granted: true,
            granted_at_epoch_s: granted_at,
            helper_path: "/usr/local/bin/privd".to_string(),
        }
    }

    #[test]
    fn is_valid_boundaries() {
        let granted_at = 1_000_000;
        let st = state(granted_at);
        assert!(is_valid(&st, granted_at));
        // Ровно на границе 12 часов — ещё валидно («не старше»).
        assert!(is_valid(&st, granted_at + SESSION_TTL_S));
        // Секундой позже — уже нет.
        assert!(!is_valid(&st, granted_at + SESSION_TTL_S + 1));
        // Отрицательная дельта (часы ушли назад) — считаем валидной:
        // секунды совпадают, TTL не истёк.
        assert!(is_valid(&st, granted_at - 60));
        // Не выдано — невалидно в любой момент.
        let not_granted = PrivilegeState {
            granted: false,
            ..st.clone()
        };
        assert!(!is_valid(&not_granted, granted_at));
    }

    #[test]
    fn needs_prompt_boundaries() {
        let granted_at = 5_000_000;
        let st = state(granted_at);
        assert!(needs_prompt(None, granted_at));
        assert!(!needs_prompt(Some(&st), granted_at));
        assert!(!needs_prompt(Some(&st), granted_at + SESSION_TTL_S));
        assert!(needs_prompt(Some(&st), granted_at + SESSION_TTL_S + 1));
        let not_granted = PrivilegeState {
            granted: false,
            ..st
        };
        assert!(needs_prompt(Some(&not_granted), granted_at));
    }

    #[test]
    fn state_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "primecore-privilege-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Файла ещё нет — пусто, без ошибки.
        assert_eq!(load_state(&dir).unwrap(), None);
        let st = state(123456);
        save_state(&dir, &st).unwrap();
        // Путь и round-trip.
        assert_eq!(path_state(&dir), dir.join("privilege.json"));
        assert_eq!(load_state(&dir).unwrap(), Some(st));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn helper_command_chooses_elevator() {
        assert_eq!(
            helper_command(|| true),
            vec!["pkexec".to_string(), "privd".to_string()]
        );
        assert_eq!(
            helper_command(|| false),
            vec!["sudo".to_string(), "privd".to_string()]
        );
    }
}
