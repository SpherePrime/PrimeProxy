//! Порт `presets/preset_contract.py` — договор «пресет — точка истины».
//!
//! Всё, что запускает winws/winws2, видно в тексте пресета. Программа не
//! держит скрытых добавок: ни при сохранении, ни при запуске она не дописывает
//! в пресет то, чего пользователь не увидит в редакторе. Разрешённые
//! преобразования перечислены в константах ниже (номера пунктов — как в
//! python-доке модуля):
//!
//! 1. сохранение — [`normalize_preset_source_for_save`];
//! 2. запуск — комментарии/пустые строки не передаются, строки делятся на
//!    аргументы, пишутся в @config через экранирование (слой запуска);
//! 3. сгенерированные конфиги вне договора — [`GENERATED_CONFIG_EXEMPTIONS`];
//! 4. импорт ZIP-архива — переименование списка при коллизии имён;
//! 5. явные действия пользователя — объявления `--blob=` для фейков стратегии;
//! 6. разовый перевод пресетов пользователя — нормализация сохранения;
//! 7. обновление встроенного пресета — номер `# BuiltinVersion:`.
//!
//! Списки преобразований читают архитектурные проверки, поэтому новое
//! преобразование сначала добавляется сюда — с понятной причиной, — и только
//! потом в код.

use primecore_profile::winws2_preset_source::ensure_winws2_lua_init_block;

/// python `ENGINE_WINWS1` / `ENGINE_WINWS2` из `preset_contract.py`;
/// значения живут в `primecore-mode`/`primecore-profile`.
pub use primecore_profile::{ENGINE_WINWS1, ENGINE_WINWS2};

// --- 1. Сохранение ---------------------------------------------------------

pub const SAVE_WINWS2_LUA_INIT_BLOCK: &str = "winws2_lua_init_block";
pub const SAVE_LEGACY_DEBUG_LOG_RELOCATION: &str = "legacy_debug_log_relocation";
pub const SAVE_LEGACY_LIST_FILE_RENAME: &str = "legacy_list_file_rename";
pub const SAVE_DROP_SERVICE_HEADER_LINES: &str = "drop_modified_and_active_preset_header_lines";
pub const SAVE_LINE_ENDINGS: &str = "lf_line_endings_and_single_final_newline";
pub const SAVE_PRESET_IDENTITY_HEADERS: &str =
    "preset_identity_headers_on_rename_duplicate_create_import";

/// python `SAVE_TIME_NORMALIZATIONS`: ключ — идентификатор преобразования,
/// значение — человекочитаемая причина.
pub const SAVE_TIME_NORMALIZATIONS: &[(&str, &str)] = &[
    (
        SAVE_WINWS2_LUA_INIT_BLOCK,
        "winws2: полный обязательный блок --lua-init в начале преамбулы",
    ),
    (
        SAVE_LEGACY_DEBUG_LOG_RELOCATION,
        "--debug=@logs/... -> --debug=@user/logs/...",
    ),
    (
        SAVE_LEGACY_LIST_FILE_RENAME,
        "lists/<прежнее имя поставляемого списка> -> lists/<нынешнее> (LEGACY_LIST_FILE_RENAMES)",
    ),
    (
        SAVE_DROP_SERVICE_HEADER_LINES,
        "удаление строк # Modified: и # ActivePreset:",
    ),
    (
        SAVE_LINE_ENDINGS,
        "CRLF/CR -> LF, ровно один перевод строки в конце, без метки BOM в начале",
    ),
    (
        SAVE_PRESET_IDENTITY_HEADERS,
        "# Preset: / # PresetKind: при переименовании, дублировании, создании и импорте",
    ),
];

/// Служебные строки шапки, которые сохранение удаляет (в нижнем регистре).
pub const SERVICE_HEADER_PREFIXES: [&str; 2] = ["# modified:", "# activepreset:"];

pub const LEGACY_DEBUG_LOG_PREFIX: &str = "logs/";
pub const DEBUG_LOG_DIR: &str = "user/logs";

/// Поставляемые списки, сменившие имя: прежнее имя -> нынешнее. Пресеты
/// пользователя, сохранённые до переименования, ссылаются на прежний файл,
/// которого в поставке больше нет.
pub const LEGACY_LIST_FILE_RENAMES: &[(&str, &str)] = &[("git-zapret-moe.txt", "zapret-moe.txt")];

// --- 2. Запуск -------------------------------------------------------------

pub const LAUNCH_DROP_COMMENTS_AND_BLANK_LINES: &str = "drop_comments_and_blank_lines";
pub const LAUNCH_SPLIT_INLINE_OPTIONS: &str = "split_inline_options";
pub const LAUNCH_SHLEX_QUOTE_AT_CONFIG: &str = "shlex_quote_into_at_config";
pub const LAUNCH_WINWS1_PATH_RESOLUTION: &str = "winws1_list_and_bin_path_resolution";
pub const LAUNCH_DRY_RUN_CHECK_FLAGS: &str = "dry_run_check_process_flags";
pub const LAUNCH_FAST_SWITCH_HANDOFF_FLAG: &str = "fast_switch_handoff_flag";

/// python `LAUNCH_TIME_TRANSFORMATIONS`.
pub const LAUNCH_TIME_TRANSFORMATIONS: &[(&str, &str)] = &[
    (LAUNCH_DROP_COMMENTS_AND_BLANK_LINES, "комментарии и пустые строки не передаются"),
    (
        LAUNCH_SPLIT_INLINE_OPTIONS,
        "строка «--a --b» делится на отдельные аргументы",
    ),
    (LAUNCH_SHLEX_QUOTE_AT_CONFIG, "аргументы пишутся в @config через shlex.quote"),
    (
        LAUNCH_WINWS1_PATH_RESOLUTION,
        "winws1: относительные пути к спискам/bin -> абсолютные пути к тем же файлам",
    ),
    (
        LAUNCH_DRY_RUN_CHECK_FLAGS,
        "флаги проверки только в отдельном процессе --dry-run",
    ),
    (
        LAUNCH_FAST_SWITCH_HANDOFF_FLAG,
        "--wf-dup-check=0 при быстрой смене пресета (старый и новый winws2 недолго работают вместе)",
    ),
];

pub const WINWS2_DRY_RUN_EXTRA_ARGS: [&str; 2] = ["--wf-dup-check=0", "--dry-run"];
pub const WINWS1_DRY_RUN_EXTRA_ARGS: [&str; 1] = ["--dry-run"];
pub const FAST_SWITCH_HANDOFF_EXTRA_ARGS: [&str; 1] = ["--wf-dup-check=0"];

/// Функции раннеров, внутри которых процесс проверки запускается со своим
/// @config (имя функции содержит эту метку).
pub const DRY_RUN_FUNCTION_MARKER: &str = "dry_run";

// --- 3. Сгенерированные конфиги --------------------------------------------

/// python `GENERATED_CONFIG_EXEMPTIONS`: файлы, чьи конфиги не пресеты
/// пользователя и не подчиняются пунктам 1–2.
pub const GENERATED_CONFIG_EXEMPTIONS: &[(&str, &str)] = &[
    (
        "src/blockcheck/strategy_search/environment.py",
        "временный @config пробы подбора стратегии",
    ),
    (
        "src/orchestra/orchestra_runner.py",
        "рабочий конфиг circular-оркестратора",
    ),
];

// --- 4. Импорт ZIP-архива --------------------------------------------------

pub const ARCHIVE_IMPORT_LIST_RENAME: &str = "portable_archive_list_rename_on_name_collision";

/// python `ARCHIVE_IMPORT_TRANSFORMATIONS`.
pub const ARCHIVE_IMPORT_TRANSFORMATIONS: &[(&str, &str)] = &[(
    ARCHIVE_IMPORT_LIST_RENAME,
    "список из ZIP с именем, которое уже занято другим файлом, сохраняется под новым именем, и ссылка в пресете меняется на него",
)];

// --- 5. Явные действия пользователя ---------------------------------------

pub const STRATEGY_CHOICE_BLOB_DECLARATIONS: &str = "strategy_choice_blob_declarations";

/// python `EXPLICIT_ACTION_TRANSFORMATIONS`.
pub const EXPLICIT_ACTION_TRANSFORMATIONS: &[(&str, &str)] = &[(
    STRATEGY_CHOICE_BLOB_DECLARATIONS,
    "выбор готовой стратегии или применение найденной в blockcheck дописывает в преамбулу --blob= для фейков стратегии, которых в пресете ещё нет",
)];

// --- 6. Разовый перевод при запуске ---------------------------------------

pub const USER_WINWS2_PRESETS_SAVE_FORMAT_MIGRATION: &str =
    "user_winws2_presets_save_format_migration";

/// python `ONE_TIME_MIGRATIONS`.
pub const ONE_TIME_MIGRATIONS: &[(&str, &str)] = &[(
    USER_WINWS2_PRESETS_SAVE_FORMAT_MIGRATION,
    "после запуска пресеты winws2 из папки пользователя один раз проходят нормализацию сохранения (полный блок --lua-init, новые имена списков) и записываются, только если текст изменился",
)];

pub const OUTDATED_BUILTIN_OVERRIDE_REFRESH: &str = "outdated_builtin_override_refresh";

/// python `BUILTIN_PRESET_UPDATES`.
pub const BUILTIN_PRESET_UPDATES: &[(&str, &str)] = &[(
    OUTDATED_BUILTIN_OVERRIDE_REFRESH,
    "после запуска копия встроенного пресета в папке пользователя заменяется встроенным пресетом, если его номер # BuiltinVersion: стал больше; прежняя копия сохраняется в presets/replaced",
)];

/// Шапка встроенного пресета с номером его версии.
pub const BUILTIN_VERSION_HEADER_PREFIX: &str = "# BuiltinVersion:";

/// Номер версии из шапки пресета («# BuiltinVersion: 2.44» → `[2, 44]`);
/// `None` — номера нет. Шапка кончается на первой непустой строке без «#».
#[must_use]
pub fn builtin_preset_version(text: &str) -> Option<Vec<i64>> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('#') {
            // Шапка кончилась: дальше идут параметры запуска.
            return None;
        }
        if !line.starts_with(BUILTIN_VERSION_HEADER_PREFIX) {
            continue;
        }
        let value = line[BUILTIN_VERSION_HEADER_PREFIX.len()..].trim();
        let mut parts = Vec::new();
        for part in value.split('.') {
            match part.parse::<i64>() {
                Ok(number) => parts.push(number),
                Err(_) => return None,
            }
        }
        return Some(parts);
    }
    None
}

/// Причина изменения пресета, с которой программа узнаёт о разовом переводе.
pub const CONTRACT_MIGRATION_CHANGE_KIND: &str = "contract_migration";

// --- Кто пишет файлы пресетов ----------------------------------------------

/// Единственный модуль, который вызывает запись файла пресета в python
/// (`PresetFileStore.create_preset` / `update_preset`). Все, кроме самого
/// хранилища, обязаны пропустить текст через `normalize_preset_source_for_save`.
pub const PRESET_FILE_STORE_MODULE: &str = "src/presets/file_store.py";

/// python `PRESET_FILE_WRITE_OWNERS`.
pub const PRESET_FILE_WRITE_OWNERS: &[(&str, &str)] = &[
    (
        PRESET_FILE_STORE_MODULE,
        "хранилище: единственная запись файла пресета на диск",
    ),
    (
        "src/presets/file_service.py",
        "сохранение текста пресета и разовый перевод пресетов пользователя",
    ),
    (
        "src/presets/preset_file_ops.py",
        "переименование, дублирование, создание, импорт TXT",
    ),
    (
        "src/presets/portable_archive.py",
        "импорт ZIP-архива со списками",
    ),
];

pub const PRESET_FILE_WRITE_METHODS: [&str; 3] =
    ["create_preset", "update_preset", "_write_source"];
pub const PRESET_SAVE_NORMALIZER_NAMES: [&str; 2] =
    ["normalize_preset_source_for_save", "normalize_source_text"];

/// Где архитектурная проверка ищет запись файлов пресетов и команды запуска winws.
pub const PRESET_CONTRACT_SCOPE: [&str; 6] = [
    "src/winws_runtime/",
    "src/presets/",
    "src/profile/",
    "src/blockcheck/",
    "src/orchestra/",
    "src/core/",
];

/// python `_relocate_legacy_debug_log_lines`: переносит старые
/// `--debug=@logs/...` на актуальный `--debug=@user/logs/...`.
fn relocate_legacy_debug_log_lines(text: &str) -> String {
    if !text.to_lowercase().contains("--debug=") {
        return text.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let stripped = raw.trim();
        // Пресеты, написанные на Windows, пишут путь через «\» — сравниваем
        // уже с прямыми слешами, иначе @logs\x.log остаётся на старом месте.
        let normalized = stripped.replace('\\', "/");
        if normalized.to_lowercase().starts_with("--debug=@logs/") {
            let value = stripped
                .split_once('=')
                .map(|(_, rest)| rest.trim().trim_start_matches('@').replace('\\', "/"))
                .unwrap_or_default();
            out.push(format!(
                "--debug=@{}",
                relocate_legacy_debug_log_file(&value)
            ));
            continue;
        }
        out.push(raw.to_string());
    }
    out.join("\n")
}

/// Переносит старый путь `logs/...` на актуальный `user/logs/...`.
///
/// Пресеты, созданные до переезда логов в user\, содержат
/// `--debug=@logs/...`; winws2 не находит такой каталог и отказывается
/// стартовать («bad file»).
#[must_use]
pub fn relocate_legacy_debug_log_file(value: &str) -> String {
    let path = value.trim();
    if path.is_empty() {
        return String::new();
    }
    if path.to_lowercase().starts_with(LEGACY_DEBUG_LOG_PREFIX) {
        return format!("{DEBUG_LOG_DIR}/{}", &path[LEGACY_DEBUG_LOG_PREFIX.len()..]);
    }
    path.to_string()
}

/// python `_rename_legacy_list_files`: переносит переименованные поставляемые
/// списки на нынешние имена (`LEGACY_LIST_FILE_RENAMES`).
fn rename_legacy_list_files(text: &str) -> String {
    let lowered = text.to_lowercase();
    if !LEGACY_LIST_FILE_RENAMES
        .iter()
        .any(|(old, _)| lowered.contains(old))
    {
        return text.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let stripped = raw.trim();
        let rewritten = stripped.split_once('=').and_then(|(option, value)| {
            if !option.starts_with("--") {
                return None;
            }
            let path = value.trim().replace('\\', "/");
            let (folder, name) = path.rsplit_once('/')?;
            let new_name = LEGACY_LIST_FILE_RENAMES
                .iter()
                .find(|(old, _)| old.eq_ignore_ascii_case(name))
                .map(|(_, new)| *new)?;
            if folder.to_lowercase().trim_start_matches('@') != "lists" {
                return None;
            }
            Some(format!("{option}={folder}/{new_name}"))
        });
        match rewritten {
            Some(line) => out.push(line),
            None => out.push(raw.to_string()),
        }
    }
    out.join("\n")
}

/// python `_drop_service_header_lines`: удаляет строки шапки
/// `# Modified:` и `# ActivePreset:`.
fn drop_service_header_lines(text: &str) -> String {
    text.split('\n')
        .filter(|line| {
            let stripped = line.trim().to_lowercase();
            !SERVICE_HEADER_PREFIXES
                .iter()
                .any(|prefix| stripped.starts_with(prefix))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Метка BOM — часть кодировки файла, а не текста.
pub const UTF8_BOM: char = '\u{feff}';

/// Убирает метку BOM в начале текста: это кодировка файла, а не пресет.
#[must_use]
pub fn strip_utf8_bom(text: &str) -> String {
    text.strip_prefix(UTF8_BOM).unwrap_or(text).to_string()
}

/// python `_normalize_line_endings`: CRLF и CR → LF.
#[must_use]
pub fn normalize_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// python `_single_final_newline`: ровно один перевод строки в конце.
#[must_use]
pub fn single_final_newline(text: &str) -> String {
    format!("{}\n", text.trim_end_matches('\n'))
}

/// Единственная нормализация текста пресета перед записью на диск.
///
/// Делает ровно преобразования из `SAVE_TIME_NORMALIZATIONS` (кроме шапки
/// `# Preset:`, которую переписывают сами операции переименования/создания):
/// перевод строк CRLF/CR → LF, перенос старого `--debug=@logs/...` в
/// `user/logs/...`, переименованные поставляемые списки, удаление служебных
/// строк шапки и (только winws2) полный блок `--lua-init` в начале преамбулы.
#[must_use]
pub fn normalize_preset_source_for_save(source_text: &str, engine: &str) -> String {
    let mut text = normalize_line_endings(&strip_utf8_bom(source_text));
    text = relocate_legacy_debug_log_lines(&text);
    text = rename_legacy_list_files(&text);
    text = drop_service_header_lines(&text);
    if engine.trim().to_lowercase() == ENGINE_WINWS2 {
        text = ensure_winws2_lua_init_block(&text);
    }
    single_final_newline(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_number_from_header() {
        assert_eq!(
            builtin_preset_version("# Preset: x\n# BuiltinVersion: 2.44\n--a\n"),
            Some(vec![2, 44])
        );
        assert_eq!(
            builtin_preset_version("# BuiltinVersion: 2.44.1\n"),
            Some(vec![2, 44, 1])
        );
        assert_eq!(builtin_preset_version("# BuiltinVersion: abc\n"), None);
        assert_eq!(
            builtin_preset_version("# notversion: 1\n# BuiltinVersion: 3.0\n"),
            Some(vec![3, 0])
        );
        assert_eq!(builtin_preset_version(""), None);
    }

    #[test]
    fn normalize_matches_python() {
        assert_eq!(
            normalize_preset_source_for_save(
                "\u{feff}# Modified: t\r\n# Preset: X\r\n--a=1\r\n",
                "winws1"
            ),
            "# Preset: X\n--a=1\n"
        );
        assert_eq!(
            relocate_legacy_debug_log_file("LOGS/x.log"),
            "user/logs/x.log"
        );
        assert_eq!(relocate_legacy_debug_log_file(""), "");
    }

    #[test]
    fn debug_relocation_keeps_absolute_paths() {
        let legacy = "--a=1\n--debug=@logs/Default_v1_game_filter_debug.log\n";
        let normalized = normalize_preset_source_for_save(legacy, "winws1");
        assert!(normalized.contains("--debug=@user/logs/Default_v1_game_filter_debug.log"));
        assert!(!normalized.contains("--debug=@logs/"));

        let backslash = "--a=1\n--debug=@logs\\Default_debug.log\n";
        assert!(normalize_preset_source_for_save(backslash, "winws1")
            .contains("--debug=@user/logs/Default_debug.log"));

        let absolute = "--a=1\n--debug=@C:/Zapret/custom.log\n";
        assert!(normalize_preset_source_for_save(absolute, "winws1")
            .contains("--debug=@C:/Zapret/custom.log"));
    }
}
