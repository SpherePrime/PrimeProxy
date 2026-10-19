//! Порт чистой логики `src/settings/mode.py` — режимы запуска
//! (zapret2/zapret1/orchestra) и имена движков/исполняемых файлов.
//!
//! Контракт питоновский один-в-один: строгие функции (`require_*`)
//! возвращают ошибку формата Python `ValueError`, мягкие (`normalize_*`,
//! `*_or_none`) — дефолт/None; булевы «узнавалки» — суффиксы `is_*`.

mod paths;

pub use paths::*;

/// Режим «пресет Zapret 2» (движок winws2).
pub const ZAPRET2_MODE: &str = "zapret2_mode";
/// Режим «пресет Zapret 1» (движок winws1).
pub const ZAPRET1_MODE: &str = "zapret1_mode";
/// Режим orchestrры (live-перебор поверх winws2).
pub const ORCHESTRA_MODE: &str = "orchestra";

pub const DEFAULT_LAUNCH_METHOD: &str = ZAPRET2_MODE;

pub const ALL_LAUNCH_METHODS: [&str; 3] = [ZAPRET2_MODE, ZAPRET1_MODE, ORCHESTRA_MODE];
pub const PRESET_LAUNCH_METHODS: [&str; 2] = [ZAPRET2_MODE, ZAPRET1_MODE];

pub const ENGINE_WINWS1: &str = "winws1";
pub const ENGINE_WINWS2: &str = "winws2";
pub const ALL_ENGINES: [&str; 2] = [ENGINE_WINWS1, ENGINE_WINWS2];

pub const EXE_NAME_WINWS1: &str = "winws.exe";
pub const EXE_NAME_WINWS2: &str = "winws2.exe";
pub const ALL_WINWS_EXE_NAMES: [&str; 2] = [EXE_NAME_WINWS1, EXE_NAME_WINWS2];
pub const WINWS_ENGINE_FAMILY_LABEL: &str = "winws1/winws2";
pub const WINWS_EXE_FAMILY_LABEL: &str = "winws.exe/winws2.exe";

pub const RELATIVE_EXE_PATH_WINWS1: &str = "exe/winws.exe";
pub const RELATIVE_EXE_PATH_WINWS2: &str = "exe/winws2.exe";

pub const SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS1: &str =
    "selected_source_preset_file_name_winws1";
pub const SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS2: &str =
    "selected_source_preset_file_name_winws2";

pub const PRESETS_SCOPE_WINWS1: &str = ENGINE_WINWS1;
pub const PRESETS_SCOPE_WINWS2: &str = ENGINE_WINWS2;
pub const PRESETS_DIR_NAME_WINWS1: &str = PRESETS_SCOPE_WINWS1;
pub const PRESETS_DIR_NAME_WINWS2: &str = PRESETS_SCOPE_WINWS2;
pub const BUILTIN_PRESETS_DIR_NAME_WINWS1: &str = "winws1_builtin";
pub const BUILTIN_PRESETS_DIR_NAME_WINWS2: &str = "winws2_builtin";

pub const DEFAULT_PRESET_FILE_NAME_WINWS1: &str = "Default v1.txt";
pub const DEFAULT_PRESET_FILE_NAME_WINWS2: &str = "Default v1 (game filter).txt";

/// DEFAULT_PRESET_FILE_NAME_BY_ENGINE (по умолчанию winws2 для unknown).
pub fn default_preset_file_name(engine: &str) -> &'static str {
    match engine {
        ENGINE_WINWS1 => DEFAULT_PRESET_FILE_NAME_WINWS1,
        _ => DEFAULT_PRESET_FILE_NAME_WINWS2,
    }
}

fn engine_by_launch_method(method: &str) -> Option<&'static str> {
    match method {
        ZAPRET2_MODE => Some(ENGINE_WINWS2),
        ZAPRET1_MODE => Some(ENGINE_WINWS1),
        _ => None,
    }
}

fn exe_name_by_launch_method(method: &str) -> &'static str {
    match method {
        ZAPRET1_MODE => EXE_NAME_WINWS1,
        _ => EXE_NAME_WINWS2,
    }
}

/// Нормализация режима: пустое/непонятное → дефолт.
pub fn normalize_launch_method(value: Option<&str>, default: Option<&str>) -> String {
    let method = value.unwrap_or("").trim().to_lowercase();
    if ALL_LAUNCH_METHODS.contains(&method.as_str()) {
        return method;
    }
    default.unwrap_or(DEFAULT_LAUNCH_METHOD).to_string()
}

/// Строгая нормализация: непонятное — ошибка формата `ValueError`.
pub fn require_launch_method(value: Option<&str>) -> Result<String, String> {
    let method = value.unwrap_or("").trim().to_lowercase();
    if ALL_LAUNCH_METHODS.contains(&method.as_str()) {
        return Ok(method);
    }
    Err(format!("Unsupported launch method: {value:?}"))
}

pub fn is_known_launch_method(value: Option<&str>) -> bool {
    let method = value.unwrap_or("").trim().to_lowercase();
    ALL_LAUNCH_METHODS.contains(&method.as_str())
}

pub fn is_preset_launch_method(value: Option<&str>) -> bool {
    let method = value.unwrap_or("").trim().to_lowercase();
    PRESET_LAUNCH_METHODS.contains(&method.as_str())
}

pub fn is_orchestra_launch_method(value: Option<&str>) -> bool {
    value.unwrap_or("").trim().to_lowercase() == ORCHESTRA_MODE
}

pub fn is_zapret2_launch_method(value: Option<&str>) -> bool {
    value.unwrap_or("").trim().to_lowercase() == ZAPRET2_MODE
}

pub fn is_zapret1_launch_method(value: Option<&str>) -> bool {
    value.unwrap_or("").trim().to_lowercase() == ZAPRET1_MODE
}

/// Движок режима: для orchestra — ошибка
/// «Launch method has no preset engine: orchestra».
pub fn engine_for_launch_method(value: Option<&str>) -> Result<&'static str, String> {
    let method = require_launch_method(value)?;
    engine_by_launch_method(&method)
        .ok_or_else(|| format!("Launch method has no preset engine: {method}"))
}

pub fn engine_for_launch_method_or_none(value: Option<&str>) -> Option<&'static str> {
    let method = value.unwrap_or("").trim().to_lowercase();
    engine_by_launch_method(&method)
}

pub fn exe_name_for_launch_method(value: Option<&str>) -> Result<&'static str, String> {
    let method = require_launch_method(value)?;
    Ok(exe_name_by_launch_method(&method))
}
