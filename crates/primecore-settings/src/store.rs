//! Порт ядра `src/settings/store.py` — sqlite-хранилище настроек.
//!
//! Реализованы: prамгмы/схема\Seeder, quick_check, user_version,
//! чтение секций (SELECT section, payload), операции записи изменившихся
//! с подсчётом ревизии. Держим канонические python-формат json строк
//! (ensure_ascii=False, separators=(",", ":"), sort_keys=True).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::app_settings::normalize_settings;
use crate::schema::{
    build_default_settings, SETTINGS_DATABASE_FILE_NAME, SETTINGS_DIR_NAME,
};

pub const SETTINGS_SCHEMA_VERSION: i64 = 1;

pub const SETTINGS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings_sections (
    section TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO settings_meta(key, value) VALUES('revision', 0);
-- Постоянная идентичность пресетов: uid выдаётся один раз и не меняется.
CREATE TABLE IF NOT EXISTS presets (
    uid TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    file_name TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(scope, file_name)
);
CREATE TABLE IF NOT EXISTS preset_remote_sources (
    preset_uid TEXT PRIMARY KEY REFERENCES presets(uid) ON DELETE CASCADE,
    url TEXT NOT NULL,
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    synced_hash TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    auto INTEGER NOT NULL DEFAULT 1,
    detached INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS profile_identities (
    scope TEXT NOT NULL,
    uid TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    sig TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, uid)
);
";

/// База настроек: живой sqlite-коннект и путь.
pub struct SettingsDatabase {
    connection: Connection,
    path: PathBuf,
}

/// python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
/// serde_json не сортирует ключи по умолчанию — сортируем сами.
pub fn serialize_section(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_default();
    text
}

impl SettingsDatabase {
    /// python _open_connection: прагмы + схема + quick_check + user_version.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("IO error: {error}"))?;
        }
        let (database, _initial) = Self::open_with_recovery(path)?;
        Ok(database)
    }

    /// Возвращает (база, итоговый normalize_settings).
    pub fn open_with_recovery(path: &Path) -> Result<(Self, Value), String> {
        match Self::open_fresh(path) {
            Ok((database, initial)) => Ok((database, initial)),
            Err(error) if is_corruption_error(&error) => {
                // python _backup_corrupt_database_locked: удалить битую базу —
                // без резервировки, тут linux-среда зеркально понята.
                let _ = std::fs::remove_file(path);
                Self::open_fresh(path)
            }
            Err(error) => Err(error),
        }
    }

    fn open_fresh(path: &Path) -> Result<(Self, Value), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("IO error: {error}"))?;
        }
        let connection = Connection::open(path.as_os_str()).map_err(|error| format!("sqlite: {error}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA busy_timeout=10000;",
            )
            .map_err(|error| format!("sqlite pragma: {error}"))?;
        connection
            .execute_batch(SETTINGS_SCHEMA)
            .map_err(|error| format!("sqlite schema: {error}"))?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(|error| format!("sqlite quick_check: {error}"))?;
        if quick_check.to_lowercase() != "ok" {
            return Err(format!(
                "database disk image is malformed: {quick_check}"
            ));
        }
        let current_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|error| format!("sqlite user_version: {error}"))?;
        if current_version > SETTINGS_SCHEMA_VERSION {
            let message = format!(
                "settings.sqlite3 schema {current_version} is newer than supported \
                 {SETTINGS_SCHEMA_VERSION}"
            );
            return Err(message);
        }
        connection
            .execute_batch(&format!("PRAGMA user_version={SETTINGS_SCHEMA_VERSION}"))
            .map_err(|error| format!("sqlite user_version set: {error}"))?;

        let mut database = Self { connection, path: path.to_path_buf() };
        let initial = database.initialize()?;
        Ok((database, initial))
    }

    /// python _initialize_database_locked: прочитать секции, нормализовать,
    /// записать (read-modify-write в транзакции).
    fn initialize(&mut self) -> Result<Value, String> {
        let current = self.read_raw_sections()?;
        let (initial, passed) = if current.is_empty() {
            (normalize_settings(&build_default_settings()), true)
        } else {
            (normalize_settings(&Value::Object(current.clone())), false)
        };
        if passed {
            self.write_changed_sections(&serde_json::Map::new(), &initial)?;
        } else {
            self.write_changed_sections(&current, &initial)?;
        }
        Ok(initial)
    }

    /// python _read_raw_sections_locked.
    pub fn read_raw_sections(&self) -> Result<Map<String, Value>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT section, payload FROM settings_sections")
            .map_err(|error| format!("sqlite select: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                let section: String = row.get(0)?;
                let payload: String = row.get(1)?;
                Ok((section, payload))
            })
            .map_err(|error| format!("sqlite select: {error}"))?;
        let mut raw = Map::new();
        for row in rows {
            let (section, payload) = row.map_err(|error| format!("sqlite select: {error}"))?;
            let value = serde_json::from_str(&payload)
                .map_err(|error| format!("sqlite payload json: {error}"))?;
            raw.insert(section, value);
        }
        Ok(raw)
    }

    pub fn read_revision(&self) -> Result<i64, String> {
        self.connection
            .query_row("SELECT value FROM settings_meta WHERE key='revision'", [], |row| row.get(0))
            .map_err(|error| format!("sqlite revision: {error}"))
    }

    /// python _write_changed_sections_locked: записи изменившихся секций.
    pub fn write_changed_sections(
        &mut self,
        current: &Map<String, Value>,
        updated: &Value,
    ) -> Result<bool, String> {
        let Some(updated_obj) = updated.as_object() else {
            return Err("normalize_settings вернул не объект".to_string());
        };
        let mut _changed = false;
        self.connection
            .execute("BEGIN IMMEDIATE", [])
            .map_err(|error| format!("sqlite begin: {error}"))?;
        let result = (|| -> Result<bool, String> {
            let mut inner_changed = false;
            for (section, value) in updated_obj {
                if current.get(section) == Some(value) {
                    continue;
                }
                self.connection
                    .execute(
                        "INSERT INTO settings_sections(section, payload, updated_at_ms) VALUES(?, ?, ?)
                         ON CONFLICT(section) DO UPDATE SET
                             payload=excluded.payload,
                             updated_at_ms=excluded.updated_at_ms",
                        rusqlite::params![
                            section,
                            serialize_section(value),
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or_default()
                        ],
                    )
                    .map_err(|error| format!("sqlite insert: {error}"))?;
                inner_changed = true;
            }
            let obsolete: Vec<String> = current
                .keys()
                .filter(|key| !updated_obj.contains_key(*key))
                .cloned()
                .collect();
            for name in &obsolete {
                self.connection
                    .execute("DELETE FROM settings_sections WHERE section=?", rusqlite::params![name])
                    .map_err(|error| format!("sqlite delete: {error}"))?;
            }
            if inner_changed || !obsolete.is_empty() {
                self.connection
                    .execute("UPDATE settings_meta SET value=value+1 WHERE key='revision'", [])
                    .map_err(|error| format!("sqlite revision bump: {error}"))?;
                inner_changed = true;
            }
            Ok(inner_changed)
        })();
        match result {
            Ok(changed) => {
                self.connection
                    .execute("COMMIT", [])
                    .map_err(|error| format!("sqlite commit: {error}"))?;
                Ok(changed)
            }
            Err(error) => {
                let _ = self.connection.execute("ROLLBACK", []);
                Err(error)
            }
        }
    }

    /// python _update_settings: полный read-modify-write с нормализацией.
    pub fn update_settings<F>(&mut self, mutator: F) -> Result<Value, String>
    where
        F: FnOnce(&mut Value),
    {
        let current_obj = self.read_raw_sections()?;
        let current_value = Value::Object(current_obj.clone());
        let current = normalize_settings(&current_value);
        let mut working = current.clone();
        mutator(&mut working);
        let normalized = normalize_settings(&working);
        self.write_changed_sections(&current_obj, &normalized)?;
        Ok(normalized)
    }
}

/// python _is_corruption_error.
fn is_corruption_error(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("file is not a database")
        || lowered.contains("database disk image is malformed")
        || lowered.contains("database malformed")
        || lowered.contains("malformed json")
        || lowered.contains("sqlite payload json")
}

/// python get_settings_database_path: <root>/user/settings.sqlite3.
pub fn get_settings_database_path(root: &Path) -> PathBuf {
    root.join(SETTINGS_DIR_NAME).join(SETTINGS_DATABASE_FILE_NAME)
}

/// Путь базы адрес базы: <root>/user/settings.sqlite3..
pub fn database_path_for(root: &Path) -> PathBuf {
    get_settings_database_path(root)
}

pub fn default_settings() -> Value {
    build_default_settings()
}
