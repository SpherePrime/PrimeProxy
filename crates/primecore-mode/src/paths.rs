//! Порт чистой логики `src/core/paths.py` — пути движков относительно
//! корня пользователя. Пути строятся (`Path::join`), а не создаются:
//! `ensure_directories` — отдельный вызов, как в Python.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{BUILTIN_PRESETS_DIR_NAME_WINWS1, BUILTIN_PRESETS_DIR_NAME_WINWS2, ENGINE_WINWS1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePaths {
    pub engine: String,
    pub presets_root_dir: PathBuf,
    pub user_presets_dir: PathBuf,
    pub builtin_presets_dir: PathBuf,
}

impl EnginePaths {
    /// «replaced»: прежние копии встроенных пресетов, заменённые при
    /// обновлении (presets.preset_contract, пункт 7) — в список пресетов
    /// не попадают.
    pub fn replaced_presets_dir(&self) -> PathBuf {
        self.presets_root_dir
            .join("replaced")
            .join(self.user_presets_dir.file_name().unwrap_or_default())
    }

    /// Создаёт все три папки (parents=True, exist_ok), возвращает себя.
    pub fn ensure_directories(&self) -> std::io::Result<&Self> {
        std::fs::create_dir_all(&self.presets_root_dir)?;
        std::fs::create_dir_all(&self.user_presets_dir)?;
        std::fs::create_dir_all(&self.builtin_presets_dir)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub user_root: PathBuf,
    pub local_root: PathBuf,
}

impl AppPaths {
    /// Один-в-один с Python `engine_paths(engine)`: имя движка
    /// чистится (`trim().lower()`), неизвестное — само имя как папка.
    pub fn engine_paths(&self, engine: Option<&str>) -> EnginePaths {
        self.engine_paths_map(engine).1
    }

    /// То же + маркер «дефолт/свой путь» — для золотых сравнений удобнее.
    pub fn engine_paths_map(&self, engine: Option<&str>) -> (bool, EnginePaths) {
        let engine_key = engine.unwrap_or("").trim().to_lowercase();
        let presets_root_dir = self.user_root.join("presets");
        let (known, user_name, builtin_name);
        if engine_key == "winws2" {
            known = true;
            user_name = "winws2".to_string();
            builtin_name = BUILTIN_PRESETS_DIR_NAME_WINWS2.to_string();
        } else if engine_key == ENGINE_WINWS1 {
            known = true;
            user_name = "winws1".to_string();
            builtin_name = BUILTIN_PRESETS_DIR_NAME_WINWS1.to_string();
        } else {
            known = false;
            user_name = engine_key.clone();
            builtin_name = format!("{engine_key}_builtin");
        }
        (
            known,
            EnginePaths {
                engine: engine_key,
                user_presets_dir: join_nonempty(&presets_root_dir, &user_name),
                builtin_presets_dir: join_nonempty(&presets_root_dir, &builtin_name),
                presets_root_dir,
            },
        )
    }
}

/// Python `Path(a) / b` при пустом b возвращает исходную папку,
/// без двойного слэша — повторяем это.
fn join_nonempty(dir: &Path, name: &str) -> PathBuf {
    if name.is_empty() {
        dir.to_path_buf()
    } else {
        dir.join(name)
    }
}

// «replaced» строился по имени папки пользователя; при пустом имени
// замыкается на presets_root (`Path / "replaced" / ""` в Python).
/// Золотая карта «движок → пути» для мгновенных сравнений с Python.
pub fn golden_engine_paths(user_root: &Path) -> HashMap<String, EnginePaths> {
    let app = AppPaths {
        user_root: user_root.to_path_buf(),
        local_root: user_root.to_path_buf(),
    };
    ["winws1", "winws2", "custom"]
        .into_iter()
        .map(|engine| (engine.to_string(), app.engine_paths(Some(engine))))
        .collect()
}
