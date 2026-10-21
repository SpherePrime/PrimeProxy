//! Runner Zapret 2 (winws2.exe): сборка аргументов из пресета, проверка
//! ссылок на файлы, @config и решения о повторах.
//!
//! Порт чистых частей `winws_runtime/runners/zapret2_runner.py` и
//! `winws_runtime/preset_launch_text.py`. Реальный запуск процесса, чтение
//! его вывода и остановка — платформенные действия (см. [`crate::runner`] и
//! [`crate::engine`]); здесь остаются решения: какие ссылки пресета
//! отсутствуют, как выглядит @config для winws2, когда повторять запуск
//! и какими словами объяснять сбой пользователю.

use primecore_files::decode::read_preset_file_text;
use primecore_mode::ENGINE_WINWS2;
use primecore_profile::parser::parse_preset_text;
use primecore_profile::sha1::sha1_hex;
use primecore_profile::winws2_preset_source::{
    has_winws2_strategy_tags, is_winws2_circular_preset_source,
};
use primecore_profile::winws2_transport::{
    parse_out_range_expression, validate_winws2_payload_filter,
};

use crate::runner::{
    launch_args_from_preset_text, remember_cache_entry, PreparedPresetArtifact, PresetCacheKey,
};
use crate::spawn_failure::{classify_spawn_failure, STATUS_DLL_INIT_FAILED};

/// Сколько раз повторять dry-run winws2 при сбое инициализации процесса
/// (python `_TRANSIENT_DRY_RUN_RETRIES`). Повтор без пауз: немедленный
/// повтор проходит при той же частоте сбоев.
pub const TRANSIENT_DRY_RUN_RETRIES: u32 = 2;

/// Сколько раз повторять запуск при конфликте WinDivert
/// (python `_WINDIVERT_CONFLICT_MAX_RETRIES`).
pub const WINDIVERT_CONFLICT_MAX_RETRIES: u32 = 2;

/// python `_WINDIVERT_SYSTEM_ERROR_NO_RETRY_LOG_MESSAGE`: историческая
/// формулировка zapret2 для системной ошибки без ретрая.
pub const WINDIVERT_SYSTEM_ERROR_NO_RETRY_LOG_MESSAGE: &str =
    "WinDivert system error detected — retry will not help";

/// Стабильное окно восстановления после прямого запроса
/// (python `_DIRECT_NETWORK_RESTORE_STABLE_WINDOW_SEC`).
pub const DIRECT_NETWORK_RESTORE_STABLE_WINDOW_SEC: f64 = 0.3;

// --- preset_launch_text.py: подготовка текста пресета ------------------------

/// Текст пресета, проверенный перед запуском (python `PreparedLaunchPresetText`).
///
/// Подготовка только проверяет текст и никогда его не меняет: `text` — это
/// ровно исходный текст пресета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLaunchPresetText {
    pub text: String,
    pub warnings: Vec<String>,
}

/// python `is_winws2_circular_preset_text` (делегирует profile-модулю).
#[must_use]
pub fn is_winws2_circular_preset_text(source_content: &str) -> bool {
    is_winws2_circular_preset_source(source_content)
}

/// python `prepare_winws2_preset_text_for_launch`: проверяет пресет перед
/// запуском и возвращает его же текст. Ошибка — готовое сообщение.
///
/// - `:strategy=N` разрешён только в circular preset;
/// - у включённых профилей проверяются `--in-range`/`--out-range` и `--payload`.
pub fn prepare_winws2_preset_text_for_launch(
    source_content: &str,
    source_is_circular: bool,
) -> Result<PreparedLaunchPresetText, String> {
    prepare_winws2_preset_text_for_launch_named(source_content, "", source_is_circular)
}

/// То же с именем источника для сообщений разбора (python `source_name`).
pub fn prepare_winws2_preset_text_for_launch_named(
    source_content: &str,
    source_name: &str,
    source_is_circular: bool,
) -> Result<PreparedLaunchPresetText, String> {
    let raw_text = source_content;
    if !source_is_circular && has_winws2_strategy_tags(raw_text) {
        return Err(":strategy=N разрешён только в circular preset".to_string());
    }

    let source = parse_preset_text(raw_text, ENGINE_WINWS2, source_name)?;

    for profile in &source.profiles {
        if !profile.enabled {
            continue;
        }
        for segment in &profile.segments {
            if segment.kind != "strategy_filter" {
                continue;
            }
            let profile_name = if profile.display_name.trim().is_empty() {
                format!("profile {}", profile.index + 1)
            } else {
                profile.display_name.trim().to_string()
            };
            let name = segment.name.trim().to_lowercase();
            let value = segment.value.trim().to_string();
            if (name == "--in-range" || name == "--out-range")
                && parse_out_range_expression(&value, &segment.text).is_none()
            {
                return Err(format!("{profile_name}: неверное значение {name}={value}"));
            }
            if name == "--payload" && !validate_winws2_payload_filter(&value) {
                return Err(format!(
                    "{profile_name}: неверное значение --payload={value}"
                ));
            }
        }
    }

    Ok(PreparedLaunchPresetText {
        text: raw_text.to_string(),
        warnings: Vec::new(),
    })
}

// --- zapret2_runner.py: ссылки пресета на файлы ------------------------------

/// Отсутствующая ссылка пресета (python-кортеж `(ref, expected_abs_path)`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MissingPresetReference {
    /// Как ссылка выглядит в пресете: `--hostlist=lists/x.txt`.
    pub reference: String,
    /// Ожидаемый абсолютный путь к файлу.
    pub expected_path: String,
}

/// python `_strip_outer_quotes`: снимает внешние кавычки значения.
#[must_use]
pub fn strip_outer_quotes(value: &str) -> String {
    let v = value.trim();
    let v = if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
        || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
    {
        &v[1..v.len() - 1]
    } else {
        v
    };
    v.trim().to_string()
}

fn norm_slashes(s: &str) -> String {
    s.replace('\\', "/")
}

/// python `_resolve_candidates`: варианты абсолютного пути для значения опции.
fn resolve_reference_candidates(raw_value: &str, work_dir: &str) -> Vec<String> {
    let mut v = raw_value.trim().to_string();
    if v.is_empty() {
        return Vec::new();
    }

    // Некоторые опции допускают значения @файл.
    if let Some(rest) = v.strip_prefix('@') {
        v = rest.trim().to_string();
    }

    v = strip_outer_quotes(&v);
    if v.is_empty() {
        return Vec::new();
    }

    // Windows-абсолютный путь распознаётся даже на не-Windows системах.
    if crate::engine::path_is_abs(&v) {
        return vec![crate::engine::normpath(&v)];
    }

    // Относительный путь — winws2 открывает его от work_dir, как и любой
    // другой относительный (отдельной папки по умолчанию у опций нет).
    vec![crate::engine::normpath(&crate::engine::join_paths(
        work_dir, &v,
    ))]
}

fn candidates_exist(candidates: &[String], exists: &dyn Fn(&str) -> bool) -> bool {
    candidates.iter().any(|p| !p.is_empty() && exists(p))
}

fn push_missing(
    missing: &mut Vec<MissingPresetReference>,
    seen: &mut std::collections::HashSet<String>,
    key: &str,
    value: &str,
    candidates: &[String],
    exists: &dyn Fn(&str) -> bool,
) {
    if candidates.is_empty() || candidates_exist(candidates, exists) {
        return;
    }
    let reference = format!(
        "{key}={}",
        norm_slashes(strip_outer_quotes(value).trim_start_matches('@'))
    );
    let dedup = reference.to_lowercase();
    if seen.insert(dedup) {
        missing.push(MissingPresetReference {
            reference,
            expected_path: candidates.first().cloned().unwrap_or_default(),
        });
    }
}

/// Ключи `lists/*.txt` (python-набор в `_collect_missing_...`).
const LIST_KEYS: [&str; 4] = [
    "--hostlist",
    "--ipset",
    "--hostlist-exclude",
    "--ipset-exclude",
];

/// Ключи bin-файлов фиктивных полезных нагрузок (winws/winws2).
const FAKE_BIN_KEYS: [&str; 12] = [
    "--dpi-desync-fake-syndata",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-unknown-udp",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-dht",
    "--dpi-desync-fake-wireguard",
];

/// Собирает отсутствующие ссылки на файлы из текста пресета
/// (python `_collect_missing_preset_references_from_text`).
///
/// `exists` — проверка существования пути (python `os.path.exists`); она
/// остаётся за вызывающим, чтобы тесты могли подменять файловую систему.
#[must_use]
pub fn collect_missing_preset_references(
    content: &str,
    work_dir: &str,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<MissingPresetReference> {
    let mut missing: Vec<MissingPresetReference> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for raw in content.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key_l = key.trim().to_lowercase();
        let value_s = value.trim().to_string();

        // lists/*.txt
        if LIST_KEYS.contains(&key_l.as_str()) {
            let candidates = resolve_reference_candidates(&value_s, work_dir);
            push_missing(
                &mut missing,
                &mut seen,
                key.trim(),
                &value_s,
                &candidates,
                exists,
            );
            continue;
        }

        // lua/*.lua: nfqws2 принимает здесь не только @файл, но и исходный
        // Lua-код — встроенный код не является файловой ссылкой.
        if key_l == "--lua-init" {
            let unquoted = strip_outer_quotes(&value_s);
            let looks_like_lua_source =
                !unquoted.starts_with('@') && !unquoted.to_lowercase().ends_with(".lua");
            if looks_like_lua_source {
                continue;
            }
            let candidates = resolve_reference_candidates(&value_s, work_dir);
            push_missing(
                &mut missing,
                &mut seen,
                key.trim(),
                &value_s,
                &candidates,
                exists,
            );
            continue;
        }

        // windivert.filter/*
        if key_l == "--wf-raw-part" {
            let candidates = resolve_reference_candidates(&value_s, work_dir);
            push_missing(
                &mut missing,
                &mut seen,
                key.trim(),
                &value_s,
                &candidates,
                exists,
            );
            continue;
        }

        // Bin-файлы фиктивных полезных нагрузок.
        if FAKE_BIN_KEYS.contains(&key_l.as_str()) {
            let mut special = strip_outer_quotes(value_s.trim());
            if let Some(rest) = special.strip_prefix('@') {
                special = rest.trim().to_string();
            }
            let special_lower = special.to_lowercase();
            if special_lower.starts_with("0x")
                || special_lower.starts_with('!')
                || special_lower.starts_with('^')
            {
                continue;
            }
            // Файловой ссылкой считается только *.bin.
            if !special_lower.ends_with(".bin") {
                continue;
            }
            let candidates = resolve_reference_candidates(&value_s, work_dir);
            push_missing(
                &mut missing,
                &mut seen,
                key.trim(),
                &value_s,
                &candidates,
                exists,
            );
            continue;
        }

        // --blob=name:@path или --blob=name:+offset@path
        if key_l == "--blob" {
            let blob_value = strip_outer_quotes(&value_s);
            let Some((_name, tail)) = blob_value.split_once(':') else {
                continue;
            };
            let tail = tail.trim();
            if tail.is_empty() {
                continue;
            }
            // Hex-блобы и встроенные значения — не файлы.
            if tail.to_lowercase().starts_with("0x") {
                continue;
            }
            let file_part = if let Some(rest) = tail.strip_prefix('@') {
                rest.trim().to_string()
            } else if tail.starts_with('+') {
                match tail.find('@') {
                    Some(at_idx) if at_idx > 0 && at_idx < tail.len() - 1 => {
                        tail[at_idx + 1..].trim().to_string()
                    }
                    _ => String::new(),
                }
            } else {
                String::new()
            };
            if file_part.is_empty() {
                continue;
            }
            let candidates = resolve_reference_candidates(&file_part, work_dir);
            if !candidates.is_empty() && !candidates_exist(&candidates, exists) {
                let reference = format!("{}={}", key.trim(), norm_slashes(&blob_value));
                let dedup = reference.to_lowercase();
                if seen.insert(dedup) {
                    missing.push(MissingPresetReference {
                        reference,
                        expected_path: candidates[0].clone(),
                    });
                }
            }
            continue;
        }
    }

    missing
}

/// Текст отчёта о проверке пресета (python `_build_validation_report`).
#[must_use]
pub fn build_validation_report(missing: &[MissingPresetReference]) -> String {
    if missing.is_empty() {
        return String::new();
    }

    let max_show = 15usize;
    let shown = &missing[..missing.len().min(max_show)];
    let hidden = missing.len() - shown.len();

    let header = if let Some(first) = shown.first() {
        format!(
            "Preset содержит ссылки на отсутствующие файлы ({}), например: {}",
            missing.len(),
            first.reference
        )
    } else {
        format!(
            "Preset содержит ссылки на отсутствующие файлы ({}):",
            missing.len()
        )
    };

    let mut lines = vec![header];
    for item in shown {
        if item.expected_path.is_empty() {
            lines.push(format!("- {}", item.reference));
        } else {
            lines.push(format!(
                "- {}  (ожидается: {})",
                item.reference, item.expected_path
            ));
        }
    }
    if hidden > 0 {
        lines.push(format!("... и еще {hidden} файл(ов)"));
    }
    lines.join("\n")
}

// --- zapret2_runner.py: @config и пути вспомогательных файлов ----------------

/// python `shlex.quote` — экранирование одного аргумента @config.
#[must_use]
pub fn shlex_quote(argument: &str) -> String {
    if argument.is_empty() {
        return "''".to_string();
    }
    // python: r'[^\w@%+=:,./-]' — «опасный» символ требует кавычек; \w
    // включает юникодные буквы и цифры, как python str.isalnum().
    let unsafe_char = argument
        .chars()
        .any(|c| !(c.is_alphanumeric() || c == '_' || "@%+=:,./-".contains(c)));
    if !unsafe_char {
        return argument.to_string();
    }
    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

/// Текст @config winws2 из подготовленного текста пресета
/// (python `_build_winws2_at_config_text`).
///
/// Аргументы разделяются переводами строк, каждый экранирован
/// [`shlex_quote`]; пустой текст пресета даёт пустой @config.
#[must_use]
pub fn build_winws2_at_config_text(prepared_text: &str) -> String {
    let args = launch_args_from_preset_text(prepared_text);
    if args.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    for arg in &args {
        result.push_str(&shlex_quote(arg));
        result.push('\n');
    }
    result
}

/// python `_winws2_at_config_dir`: `work_dir/user/tmp/winws2_at_config`.
#[must_use]
pub fn winws2_at_config_dir(work_dir: &str) -> String {
    let user = crate::engine::join_paths(work_dir, "user");
    let tmp = crate::engine::join_paths(&user, "tmp");
    crate::engine::join_paths(&tmp, "winws2_at_config")
}

/// python `_winws2_startup_output_dir`: `work_dir/user/tmp/winws2_startup_output`.
#[must_use]
pub fn winws2_startup_output_dir(work_dir: &str) -> String {
    let user = crate::engine::join_paths(work_dir, "user");
    let tmp = crate::engine::join_paths(&user, "tmp");
    crate::engine::join_paths(&tmp, "winws2_startup_output")
}

/// Имя @config с sha1-дайджестом источника (python `_write_winws2_at_config`,
/// шаг без записи). Путь определяется содержимым: совпадение аргументов
/// запуска означает идентичную конфигурацию.
#[must_use]
pub fn winws2_at_config_path(work_dir: &str, preset_path: &str, config_text: &str) -> String {
    let digest_source = format!(
        "{}\u{0}{}",
        crate::engine::absolute_path(preset_path),
        config_text
    );
    let digest = &sha1_hex(digest_source.as_bytes())[..20];
    crate::engine::join_paths(
        &winws2_at_config_dir(work_dir),
        &format!("winws2_at_{digest}.txt"),
    )
}

/// Путь к файлу стартового вывода winws2 для артефакта
/// (python `_startup_output_path_for_artifact`).
#[must_use]
pub fn winws2_startup_output_path(
    work_dir: &str,
    preset_path: &str,
    launch_args: &[String],
) -> String {
    let joined_args = launch_args
        .iter()
        .map(|arg| arg.trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let digest_source = format!(
        "{}\u{0}{}",
        crate::engine::absolute_path(preset_path),
        joined_args
    );
    let digest = &sha1_hex(digest_source.as_bytes())[..20];
    crate::engine::join_paths(
        &winws2_startup_output_dir(work_dir),
        &format!("winws2_startup_{digest}.log"),
    )
}

/// python `_launch_args_files_exist`: все @файлы аргументов существуют.
///
/// Пустой набор аргументов — отсутствие файлов.
#[must_use]
pub fn launch_args_files_exist(launch_args: &[String], exists: &dyn Fn(&str) -> bool) -> bool {
    if launch_args.is_empty() {
        return false;
    }
    for arg in launch_args {
        if let Some(path) = arg.strip_prefix('@') {
            if !path.is_empty() && !exists(path) {
                return false;
            }
        }
    }
    true
}

/// python `AT_CONFIG_MAX_FILES`: сколько @config-файлов остаётся в каталоге.
pub const AT_CONFIG_MAX_FILES: usize = 64;

/// python `prune_at_config_cache` (из `preset_runner_support.py`): в каталоге
/// @config остаётся не больше [`AT_CONFIG_MAX_FILES`] файлов с префиксом;
/// текущий файл сохраняется всегда.
pub fn prune_at_config_cache(config_dir: &str, keep_path: &str, filename_prefix: &str) {
    let limit = AT_CONFIG_MAX_FILES;

    let keep_norm = crate::engine::normcase(&crate::engine::absolute_path(keep_path));
    let mut entries: Vec<(bool, i128, String, String)> = Vec::new();
    let Ok(scan) = std::fs::read_dir(config_dir) else {
        return;
    };
    for entry in scan.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(filename_prefix) || !name.ends_with(".txt") {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let absolute = crate::engine::absolute_path(&path.to_string_lossy());
        entries.push((
            crate::engine::normcase(&absolute) == keep_norm,
            file_mtime_ns(&metadata),
            name,
            absolute,
        ));
    }
    if entries.len() <= limit {
        return;
    }

    let has_keep = entries.iter().any(|(is_keep, _, _, _)| *is_keep);
    let keep_count = if has_keep { limit - 1 } else { limit };
    let mut not_keep: Vec<&(bool, i128, String, String)> = entries
        .iter()
        .filter(|(is_keep, _, _, _)| !*is_keep)
        .collect();
    // python: сортировка по (mtime, name), новейшие сверху.
    not_keep.sort_by(|a, b| (b.1, &b.2).cmp(&(a.1, &a.2)));
    let mut allowed: std::collections::HashSet<String> = not_keep
        .into_iter()
        .take(keep_count)
        .map(|(_, _, _, path)| crate::engine::normcase(path))
        .collect();
    if has_keep {
        allowed.insert(keep_norm);
    }

    for (_, _, _, path) in &entries {
        if allowed.contains(&crate::engine::normcase(path)) {
            continue;
        }
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(unix)]
fn file_mtime_ns(metadata: &std::fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    metadata.mtime_nsec() as i128
}

#[cfg(not(unix))]
fn file_mtime_ns(metadata: &std::fs::Metadata) -> i128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

// --- zapret2_runner.py: решения о повторах и тексты ошибок -------------------

/// python `_should_retry_dry_run_exit_code`: повтор dry-run при DLL-init сбое.
#[must_use]
pub fn should_retry_dry_run_exit_code(exit_code: i64) -> bool {
    classify_spawn_failure(exit_code, "", &crate::health::AssumedHealthyProbes)
        .is_transient_dll_init
}

/// python `_should_retry_fast_switch_spawn_exit_code`.
#[must_use]
pub fn should_retry_fast_switch_spawn_exit_code(exit_code: i64) -> bool {
    classify_spawn_failure(exit_code, "", &crate::health::AssumedHealthyProbes)
        .is_transient_dll_init
}

/// python `_format_exit_code`: код выхода в виде для сообщения.
///
/// `None` — код неизвестен («unknown»); DLL-init код дублируется в hex.
#[must_use]
pub fn format_exit_code(exit_code: Option<i64>) -> String {
    let Some(code) = exit_code else {
        return "unknown".to_string();
    };
    if code == STATUS_DLL_INIT_FAILED {
        return format!("{code} / 0x{code:08X}");
    }
    code.to_string()
}

/// python `_format_windows_process_init_failure`: сообщение о DLL-init сбое
/// Windows при запуске winws2.
#[must_use]
pub fn format_windows_process_init_failure(exit_code: Option<i64>) -> String {
    format!(
        "{ENGINE_WINWS2} не запустился: Windows не смогла инициализировать DLL (код {})",
        format_exit_code(exit_code)
    )
}

/// python `_log_fast_switch_retry_reason`: текст лога перед повтором
/// быстрого переключения. winws2 различает DLL-init провал и
/// WinDivert-конфликт.
#[must_use]
pub fn fast_switch_retry_log_message(exit_code: i64) -> String {
    if should_retry_fast_switch_spawn_exit_code(exit_code) {
        format!(
            "{}. Повторяем запуск после восстановления WinDivert",
            format_windows_process_init_failure(Some(exit_code))
        )
    } else {
        "Fast preset switch hit WinDivert conflict, retrying inside switch after cleanup"
            .to_string()
    }
}

/// python `_artifact_for_handoff_locked`: временный @config, который может
/// недолго сосуществовать со старым winws2.
///
/// `Some` — готовый текст handoff-конфига; `None` — текст пуст, артефакт не
/// меняется.
#[must_use]
pub fn handoff_preset_text(normalized_text: &str) -> Option<String> {
    let text = normalized_text.trim_end();
    if text.is_empty() {
        return None;
    }
    Some(format!("{text}\n--wf-dup-check=0\n"))
}

/// python `_artifact_for_dry_run_locked`: текст @config для dry-run проверки
/// пресета перед настоящим запуском.
///
/// `Some` — готовый текст dry-run-конфига; `None` — текст пуст.
#[must_use]
pub fn dry_run_preset_text(normalized_text: &str) -> Option<String> {
    let text = normalized_text.trim_end();
    if text.is_empty() {
        return None;
    }
    Some(format!("{text}\n--wf-dup-check=0\n--dry-run\n"))
}

/// Решение об очистке перед запуском
/// (python `_resolve_cleanup_required_before_spawn`).
///
/// `has_own_winws_process` — платформенная проверка процессов (остаётся за
/// вызывающим); результат: нужно ли останавливать свои процессы перед spawn.
#[must_use]
pub fn resolve_cleanup_required_before_spawn(
    force_cleanup: bool,
    running_process_alive: bool,
    has_own_winws_process: bool,
) -> bool {
    let mut cleanup_required = force_cleanup;
    if running_process_alive {
        cleanup_required = true;
    }
    // Свои winws, которых раннер не держит (остались от прошлого запуска
    // программы). Чужие winws из других папок не трогаются.
    if has_own_winws_process {
        cleanup_required = true;
    }
    cleanup_required
}

/// python `_artifact_for_handoff_locked` полностью: строит артефакт с новым
/// @config-файлом. Файловая система здесь используется напрямую (это не
/// запуск процесса).
pub fn artifact_for_handoff(
    artifact: &PreparedPresetArtifact,
    work_dir: &str,
) -> PreparedPresetArtifact {
    let Some(handoff_text) = handoff_preset_text(&artifact.normalized_text) else {
        return artifact.clone();
    };
    let at_config_path = write_winws2_at_config(work_dir, &artifact.preset_path, &handoff_text);
    PreparedPresetArtifact {
        preset_path: artifact.preset_path.clone(),
        cache_key: None,
        normalized_text: handoff_text,
        launch_args: vec![format!("@{at_config_path}")],
        validation_ok: artifact.validation_ok,
        validation_report: artifact.validation_report.clone(),
    }
}

/// python `_artifact_for_dry_run_locked` полностью: артефакт с dry-run @config.
pub fn artifact_for_dry_run(
    artifact: &PreparedPresetArtifact,
    work_dir: &str,
) -> PreparedPresetArtifact {
    let Some(dry_run_text) = dry_run_preset_text(&artifact.normalized_text) else {
        return artifact.clone();
    };
    let at_config_path = write_winws2_at_config(work_dir, &artifact.preset_path, &dry_run_text);
    PreparedPresetArtifact {
        preset_path: artifact.preset_path.clone(),
        cache_key: None,
        normalized_text: dry_run_text,
        launch_args: vec![format!("@{at_config_path}")],
        validation_ok: artifact.validation_ok,
        validation_report: artifact.validation_report.clone(),
    }
}

/// python `_write_winws2_at_config`: пишет @config с дайджестом в имени.
///
/// Если файл уже существует с тем же содержимым — он остаётся; кеш
/// подрезается через [`prune_at_config_cache`].
pub fn write_winws2_at_config(work_dir: &str, preset_path: &str, prepared_text: &str) -> String {
    let config_text = build_winws2_at_config_text(prepared_text);
    let config_dir = winws2_at_config_dir(work_dir);
    let config_path = winws2_at_config_path(work_dir, preset_path, &config_text);
    let _ = std::fs::create_dir_all(&config_dir);

    if let Ok(existing) = std::fs::read_to_string(&config_path) {
        if existing == config_text {
            prune_at_config_cache(&config_dir, &config_path, "winws2_at_");
            return config_path;
        }
    }

    let _ = std::fs::write(&config_path, config_text);
    prune_at_config_cache(&config_dir, &config_path, "winws2_at_");
    config_path
}

/// python `_compile_preset_artifact`: готовый артефакт запуска из preset-файла.
///
/// Кеш `PreparedPresetArtifact` с ключами [`PresetCacheKey`] здесь не
/// используется (состояние кеша — за вызывающим), сборка выполняется заново.
/// Валидация не прерывает сборку: артефакт несёт отчёт, а решение — за
/// операцией запуска.
pub fn compile_winws2_preset_artifact(preset_path: &str, work_dir: &str) -> PreparedPresetArtifact {
    let p = preset_path.trim();
    if p.is_empty() {
        return PreparedPresetArtifact {
            preset_path: String::new(),
            cache_key: None,
            normalized_text: String::new(),
            launch_args: Vec::new(),
            validation_ok: false,
            validation_report: "Не указан путь к preset файлу".to_string(),
        };
    }
    if !std::path::Path::new(p).exists() {
        return PreparedPresetArtifact {
            preset_path: p.to_string(),
            cache_key: None,
            normalized_text: String::new(),
            launch_args: Vec::new(),
            validation_ok: false,
            validation_report: format!("Preset файл не найден: {p}"),
        };
    }

    let cache_key = crate::runner::preset_cache_key(p);

    let source_content = match read_preset_file_text(std::path::Path::new(p)) {
        Ok(text) => text,
        Err(_) => {
            return PreparedPresetArtifact {
                preset_path: p.to_string(),
                cache_key,
                normalized_text: String::new(),
                launch_args: Vec::new(),
                validation_ok: false,
                validation_report: format!("Preset файл не найден: {p}"),
            };
        }
    };

    let prepared = match prepare_winws2_preset_text_for_launch_named(
        &source_content,
        "",
        is_winws2_circular_preset_text(&source_content),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return PreparedPresetArtifact {
                preset_path: p.to_string(),
                cache_key,
                normalized_text: String::new(),
                launch_args: Vec::new(),
                validation_ok: false,
                validation_report: format!("Не удалось подготовить preset файл: {error}"),
            };
        }
    };
    let normalized_text = prepared.text;

    let missing = collect_missing_preset_references(&normalized_text, work_dir, &fs_exists);
    let validation_ok = missing.is_empty();
    let validation_report = if validation_ok {
        String::new()
    } else {
        build_validation_report(&missing)
    };
    let at_config_path = write_winws2_at_config(work_dir, p, &normalized_text);

    PreparedPresetArtifact {
        preset_path: p.to_string(),
        cache_key,
        normalized_text,
        launch_args: vec![format!("@{at_config_path}")],
        validation_ok,
        validation_report,
    }
}

/// python `os.path.exists` как замыкание для [`collect_missing_preset_references`].
#[must_use]
pub fn fs_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// python `validate_preset_file`: `(ok, report)` по компиляции пресета.
#[must_use]
pub fn validate_preset_file(preset_path: &str, work_dir: &str) -> (bool, String) {
    let artifact = compile_winws2_preset_artifact(preset_path, work_dir);
    (artifact.validation_ok, artifact.validation_report)
}

/// python `remember_cache_entry` для `PreparedPresetArtifact`.
pub fn remember_preset_artifact(
    cache: &mut std::collections::VecDeque<(PresetCacheKey, PreparedPresetArtifact)>,
    key: Option<PresetCacheKey>,
    artifact: PreparedPresetArtifact,
) {
    remember_cache_entry(cache, key, artifact, AT_CONFIG_MAX_FILES);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none_exists(_path: &str) -> bool {
        false
    }

    fn tmpdir(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("primecore_ws_z2_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог");
        dir.to_string_lossy().to_string()
    }

    // --- подготовка текста пресета (preset_launch_text.py) --------------------

    #[test]
    fn launch_preparation_keeps_valid_preset_text_unchanged() {
        let source = [
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=lists/youtube.txt",
            "--payload=tls_client_hello",
            "--lua-desync=fake:blob=tls_google",
            "",
        ]
        .join("\n");

        let prepared = prepare_winws2_preset_text_for_launch(&source, false).expect("валидный");

        assert_eq!(prepared.text, source);
        assert!(!prepared.text.contains("--out-range=-d8"));
    }

    #[test]
    fn launch_preparation_allows_unknown_filename_when_syntax_is_valid() {
        let source = [
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=unknown.txt",
            "--lua-desync=fake:blob=tls_google",
            "",
        ]
        .join("\n");

        let prepared =
            prepare_winws2_preset_text_for_launch_named(&source, "placeholder.txt", false)
                .expect("валидный");

        assert_eq!(prepared.text, source);
    }

    #[test]
    fn launch_preparation_rejects_strategy_tags_in_non_circular_preset() {
        let source = [
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=lists/youtube.txt",
            "--lua-desync=fake:blob=tls_google:strategy=1",
            "",
        ]
        .join("\n");

        let error =
            prepare_winws2_preset_text_for_launch(&source, false).expect_err("должен отклонить");

        assert!(error.contains("strategy"), "{error}");
        assert_eq!(error, ":strategy=N разрешён только в circular preset");
    }

    #[test]
    fn launch_preparation_allows_strategy_tags_in_circular_preset() {
        let source = [
            "--wf-tcp-out=443",
            "--lua-desync=circular",
            "--lua-desync=fake:blob=tls_google:strategy=1",
            "",
        ]
        .join("\n");

        let prepared = prepare_winws2_preset_text_for_launch(&source, true).expect("circular");

        assert_eq!(prepared.text, source);
    }

    #[test]
    fn launch_preparation_ignores_strategy_tags_in_comments() {
        let source = [
            "# example: --lua-desync=fake:strategy=1",
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=lists/youtube.txt",
            "--lua-desync=fake:blob=tls_google",
            "",
        ]
        .join("\n");

        let prepared = prepare_winws2_preset_text_for_launch(&source, false).expect("валидный");

        assert_eq!(prepared.text, source);
    }

    #[test]
    fn circular_detection_uses_official_lua_desync_line_not_name() {
        // Сверено с python is_winws2_circular_preset_text.
        assert!(is_winws2_circular_preset_text(
            &[
                "# Preset: anything",
                "--in-range=-s5556 --lua-desync=circular:fails=4:retrans=2:maxseq=16384",
                "--lua-desync=fake:strategy=1",
                "",
            ]
            .join("\n")
        ));
        // shadow_probe — такой же оркестратор над метками :strategy=N.
        assert!(is_winws2_circular_preset_text(
            &[
                "# Preset: anything",
                "--in-range=-s1",
                "--lua-desync=shadow_probe:probes=4",
                "--lua-desync=fake:strategy=1",
                "",
            ]
            .join("\n")
        ));
        assert!(!is_winws2_circular_preset_text(
            &[
                "# Preset: Default (circular)",
                "--wf-tcp-out=443",
                "--lua-desync=fake:blob=tls_google:strategy=1",
                "",
            ]
            .join("\n")
        ));
        assert!(!is_winws2_circular_preset_text(
            &[
                "--wf-tcp-out=443",
                "--lua-desync=circular_quality:fails=4",
                "--lua-desync=fake:strategy=1",
                "",
            ]
            .join("\n")
        ));
    }

    // --- сбор отсутствующих ссылок ---------------------------------------------

    #[test]
    fn runner_checks_unknown_filename_by_file_existence() {
        // python test_runner_checks_unknown_filename_by_file_existence.
        let root = tmpdir("unknown");
        let lists_dir = format!("{root}/lists");
        std::fs::create_dir_all(&lists_dir).expect("lists");

        let source = [
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=unknown.txt",
            "--lua-desync=fake:blob=tls_google",
            "",
        ]
        .join("\n");

        let missing = collect_missing_preset_references(&source, &root, &fs_exists);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].reference.contains("--hostlist=unknown.txt"));

        std::fs::write(format!("{lists_dir}/unknown.txt"), "example.com\n").expect("файл");
        assert_eq!(
            collect_missing_preset_references(&source, &root, &fs_exists).len(),
            1
        );

        std::fs::write(format!("{root}/unknown.txt"), "example.com\n").expect("файл");
        assert!(collect_missing_preset_references(&source, &root, &fs_exists).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn winws2_validation_treats_bare_list_file_as_workdir_relative() {
        let root = tmpdir("bare");
        let lists_dir = format!("{root}/lists");
        std::fs::create_dir_all(&lists_dir).expect("lists");
        std::fs::write(format!("{lists_dir}/tankix.txt"), "example.com\n").expect("файл");

        let source = [
            "--wf-tcp-out=443",
            "--filter-tcp=443",
            "--hostlist=tankix.txt",
            "--lua-desync=fake:blob=tls_google",
            "",
        ]
        .join("\n");

        let missing = collect_missing_preset_references(&source, &root, &fs_exists);

        assert_eq!(missing.len(), 1);
        // Ожидаемый путь — work_dir/tankix.txt (posix normpath в тестах).
        assert!(
            missing[0].expected_path.ends_with("/tankix.txt"),
            "{}",
            missing[0].expected_path
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn winws2_validation_accepts_inline_lua_init_source() {
        let root = tmpdir("lua");

        let source = "--lua-init=fake_unknown_256=string.rep(string.char(0),256);fake_zero64=string.rep(string.char(0),64)\n";

        assert!(collect_missing_preset_references(source, &root, &fs_exists).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_references_skip_hex_and_modifier_values() {
        // Сверено с python: hex-блобы и модификаторы не считаются файлами.
        let root = tmpdir("hex");
        let source = [
            "--dpi-desync-fake-tls=0x1603030021",
            "--dpi-desync-fake-http=!custom",
            "--dpi-desync-fake-quic=^pattern",
            "--dpi-desync-fake-unknown=d0a0d0b0",
            "",
        ]
        .join("\n");
        assert!(collect_missing_preset_references(&source, &root, &none_exists).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_blob_reference_is_reported_with_offset() {
        // python --blob=name:+offset@path.
        let root = tmpdir("blob");
        let source = "--blob=marker:+8@lists/absent.bin\n";
        let missing = collect_missing_preset_references(source, &root, &none_exists);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].reference, "--blob=marker:+8@lists/absent.bin");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validation_report_limits_listed_files() {
        // Сверено с python _build_validation_report: 15 позиций и хвост.
        let missing: Vec<MissingPresetReference> = (0..17)
            .map(|n| MissingPresetReference {
                reference: format!("--hostlist=list{n}.txt"),
                expected_path: format!("/p/list{n}.txt"),
            })
            .collect();

        let report = build_validation_report(&missing);

        assert!(report.starts_with(
            "Preset содержит ссылки на отсутствующие файлы (17), например: --hostlist=list0.txt"
        ));
        assert!(report.contains("(ожидается: /p/list0.txt)"));
        assert!(report.contains("... и еще 2 файл(ов)"));
        assert!(!report.contains("list15.txt"));
    }

    #[test]
    fn empty_missing_gives_empty_report() {
        assert_eq!(build_validation_report(&[]), "");
    }

    // --- @config ---------------------------------------------------------------

    #[test]
    fn winws2_compile_accepts_explicit_lists_paths_for_at_launch() {
        let root = tmpdir("compile");
        let lists_dir = format!("{root}/lists");
        std::fs::create_dir_all(&lists_dir).expect("lists");
        std::fs::write(format!("{lists_dir}/tankix.txt"), "example.com\n").expect("файл");
        std::fs::write(format!("{lists_dir}/ipset-tankix.txt"), "1.2.3.4\n").expect("файл");
        let preset_path = format!("{root}/selected.txt");
        std::fs::write(
            &preset_path,
            [
                "--wf-tcp-out=443",
                "--filter-tcp=443",
                "--hostlist=lists/tankix.txt",
                "--ipset=lists/ipset-tankix.txt",
                "--lua-desync=fake:blob=tls_google",
                "",
            ]
            .join("\n"),
        )
        .expect("пресет");

        let artifact = compile_winws2_preset_artifact(&preset_path, &root);

        assert!(artifact.validation_ok, "{}", artifact.validation_report);
        assert_eq!(artifact.launch_args.len(), 1);
        assert!(artifact.launch_args[0].starts_with('@'));
        let at_config_path = artifact.launch_args[0][1..].to_string();
        let text = std::fs::read_to_string(&at_config_path).expect("@config");
        assert!(text.contains("--hostlist=lists/tankix.txt"), "{text}");
        // Каталог — user/tmp/winws2_at_config внутри work_dir.
        assert!(at_config_path.starts_with(&format!("{root}/user/tmp/winws2_at_config/")));
        assert!(at_config_path.ends_with(".txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn winws2_compile_launches_safe_at_config_file() {
        let root = tmpdir("safe");
        let lists_dir = format!("{root}/lists");
        std::fs::create_dir_all(&lists_dir).expect("lists");
        std::fs::write(format!("{lists_dir}/tankix.txt"), "example.com\n").expect("файл");
        let preset_path = format!("{root}/selected with spaces.txt");
        std::fs::write(
            &preset_path,
            [
                "# Preset: selected with spaces",
                "--wf-tcp-out=443",
                "--new",
                "--name=youtube.com (QUIC)",
                "--filter-tcp=443",
                "--hostlist=lists/tankix.txt",
                "--lua-desync=fake:blob=tls_google",
                "",
            ]
            .join("\n"),
        )
        .expect("пресет");

        let artifact = compile_winws2_preset_artifact(&preset_path, &root);

        assert!(artifact.validation_ok, "{}", artifact.validation_report);
        let at_config_path = artifact.launch_args[0][1..].to_string();
        let at_config_text = std::fs::read_to_string(&at_config_path).expect("@config");
        // Комментарий пресета не попадает в @config, а значение с пробелами
        // экранируется одинарными кавычками (python shlex.quote).
        assert!(!at_config_text.contains("# Preset:"), "{at_config_text}");
        assert!(
            at_config_text.contains("'--name=youtube.com (QUIC)'"),
            "{at_config_text}"
        );
        assert!(
            at_config_text.contains("--hostlist=lists/tankix.txt"),
            "{at_config_text}"
        );

        // Пересборка после удаления файла снова создаёт @config.
        std::fs::remove_file(&at_config_path).expect("удаление");
        let rebuilt = compile_winws2_preset_artifact(&preset_path, &root);
        assert!(std::path::Path::new(&rebuilt.launch_args[0][1..]).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dry_run_artifact_stays_inside_at_config() {
        // python test_winws2_dry_run_artifact_stays_inside_at_config.
        let root = tmpdir("dryrun");
        let preset_path = format!("{root}/selected.txt");
        std::fs::write(&preset_path, "--wf-tcp-out=443\n").expect("пресет");

        let artifact = compile_winws2_preset_artifact(&preset_path, &root);
        let dry_run_artifact = artifact_for_dry_run(&artifact, &root);

        let dry_run_config = &dry_run_artifact.launch_args[0][1..];
        assert!(dry_run_config.starts_with(&format!("{root}/user/tmp/winws2_at_config/")));
        let text = std::fs::read_to_string(dry_run_config).expect("@config");
        assert!(text.contains("--dry-run"), "{text}");
        assert!(text.contains("--wf-dup-check=0"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn handoff_artifact_appends_dup_check_only() {
        let artifact = PreparedPresetArtifact {
            preset_path: "/p".to_string(),
            cache_key: None,
            normalized_text: "--wf-tcp-out=443\n".to_string(),
            launch_args: vec!["@old".to_string()],
            validation_ok: true,
            validation_report: String::new(),
        };
        let root = tmpdir("handoff");
        let handoff = artifact_for_handoff(&artifact, &root);
        let text = std::fs::read_to_string(&handoff.launch_args[0][1..]).expect("@config");
        assert!(text.contains("--wf-dup-check=0"));
        assert!(!text.contains("--dry-run"));
        // Кеш-ключ у временного артефакта пуст.
        assert!(handoff.cache_key.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_normalized_text_leaves_artifact_unchanged() {
        let artifact = PreparedPresetArtifact {
            preset_path: "/p".to_string(),
            cache_key: None,
            normalized_text: String::new(),
            launch_args: vec![],
            validation_ok: false,
            validation_report: "report".to_string(),
        };
        let root = tmpdir("empty");
        assert_eq!(artifact_for_handoff(&artifact, &root), artifact);
        assert_eq!(artifact_for_dry_run(&artifact, &root), artifact);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn at_config_digest_depends_on_preset_path_and_text() {
        let root = tmpdir("digest");
        let path_a = format!("{root}/a.txt");
        let path_b = format!("{root}/b.txt");
        let first = winws2_at_config_path(&root, &path_a, "--wf-tcp-out=443\n");
        let same = winws2_at_config_path(&root, &path_a, "--wf-tcp-out=443\n");
        let other_text = winws2_at_config_path(&root, &path_a, "--wf-tcp-out=80\n");
        let other_path = winws2_at_config_path(&root, &path_b, "--wf-tcp-out=443\n");

        assert_eq!(first, same);
        assert_ne!(first, other_text);
        assert_ne!(first, other_path);
        assert!(first
            .rsplit('/')
            .next()
            .unwrap_or("")
            .starts_with("winws2_at_"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_output_path_uses_args_digest() {
        let root = tmpdir("output");
        let path = winws2_startup_output_path(&root, "/p", &["@config.txt".to_string()]);
        assert!(path.contains("/user/tmp/winws2_startup_output/winws2_startup_"));
        let other = winws2_startup_output_path(&root, "/p", &["@other.txt".to_string()]);
        assert_ne!(path, other);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn launch_args_files_exist_requires_all_at_files() {
        assert!(!launch_args_files_exist(&[], &fs_exists));
        assert!(launch_args_files_exist(
            &["--flag".to_string()],
            &none_exists
        ));
        assert!(launch_args_files_exist(&["@existing".to_string()], &|p| p == "existing"));
        assert!(!launch_args_files_exist(
            &["@absent".to_string()],
            &none_exists
        ));
        // Пустое значение "@" не проверяется — как в python (len > 1).
        assert!(launch_args_files_exist(&["@".to_string()], &none_exists));
    }

    // --- решения о повторах и тексты ------------------------------------------

    #[test]
    fn dll_init_exit_code_is_transient_and_retried() {
        // Сверено с python: 0xC0000142 — transient DLL init.
        assert!(should_retry_dry_run_exit_code(STATUS_DLL_INIT_FAILED));
        assert!(should_retry_fast_switch_spawn_exit_code(
            STATUS_DLL_INIT_FAILED
        ));
        assert!(!should_retry_dry_run_exit_code(1));
        assert!(!should_retry_fast_switch_spawn_exit_code(87));
    }

    #[test]
    fn exit_code_formatting_matches_python() {
        assert_eq!(format_exit_code(None), "unknown");
        assert_eq!(format_exit_code(Some(1)), "1");
        assert_eq!(
            format_exit_code(Some(STATUS_DLL_INIT_FAILED)),
            format!(
                "{} / 0x{:08X}",
                STATUS_DLL_INIT_FAILED, STATUS_DLL_INIT_FAILED as u32
            )
        );
    }

    #[test]
    fn windows_process_init_failure_message_matches_python() {
        assert_eq!(
            format_windows_process_init_failure(Some(STATUS_DLL_INIT_FAILED)),
            format!(
                "winws2 не запустился: Windows не смогла инициализировать DLL (код {} / 0x{:08X})",
                STATUS_DLL_INIT_FAILED, STATUS_DLL_INIT_FAILED as u32
            )
        );
        assert_eq!(
            format_windows_process_init_failure(None),
            "winws2 не запустился: Windows не смогла инициализировать DLL (код unknown)"
        );
    }

    #[test]
    fn fast_switch_retry_message_distinguishes_dll_init_and_conflict() {
        assert_eq!(
            fast_switch_retry_log_message(STATUS_DLL_INIT_FAILED),
            format!(
                "{}. Повторяем запуск после восстановления WinDivert",
                format_windows_process_init_failure(Some(STATUS_DLL_INIT_FAILED))
            )
        );
        assert_eq!(
            fast_switch_retry_log_message(1),
            "Fast preset switch hit WinDivert conflict, retrying inside switch after cleanup"
        );
    }

    #[test]
    fn cleanup_required_resolves_from_forces_and_processes() {
        // python _resolve_cleanup_required_before_spawn.
        assert!(!resolve_cleanup_required_before_spawn(false, false, false));
        assert!(resolve_cleanup_required_before_spawn(true, false, false));
        assert!(resolve_cleanup_required_before_spawn(false, true, false));
        assert!(resolve_cleanup_required_before_spawn(false, false, true));
    }

    #[test]
    fn shlex_quote_matches_python() {
        // Сверено с python shlex.quote.
        assert_eq!(shlex_quote("safe"), "safe");
        assert_eq!(
            shlex_quote("--hostlist=lists/x.txt"),
            "--hostlist=lists/x.txt"
        );
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(
            shlex_quote("--name=youtube.com (QUIC)"),
            "'--name=youtube.com (QUIC)'"
        );
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shlex_quote("кириллица"), "кириллица");
    }

    #[test]
    fn at_config_text_quotes_each_argument() {
        // Сверено с python _build_winws2_at_config_text.
        let text = build_winws2_at_config_text("--wf-tcp-out=443\n--name=тест (QUIC)\n");
        assert_eq!(text, "--wf-tcp-out=443\n'--name=тест (QUIC)'\n");
        assert_eq!(build_winws2_at_config_text(""), "");
        // Комментарии и пустые строки не попадают в @config.
        assert_eq!(
            build_winws2_at_config_text("# комментарий\n\n--wf-udp-out=53\n"),
            "--wf-udp-out=53\n"
        );
    }

    #[test]
    fn dry_run_text_appends_flags() {
        assert_eq!(
            dry_run_preset_text("--wf-tcp-out=443\n").as_deref(),
            Some("--wf-tcp-out=443\n--wf-dup-check=0\n--dry-run\n")
        );
        assert!(dry_run_preset_text("  \n").is_none());
    }

    #[test]
    fn handoff_text_appends_dup_check() {
        assert_eq!(
            handoff_preset_text("--wf-tcp-out=443\n").as_deref(),
            Some("--wf-tcp-out=443\n--wf-dup-check=0\n")
        );
        assert!(handoff_preset_text("").is_none());
    }

    #[test]
    fn retry_constants_match_python() {
        assert_eq!(TRANSIENT_DRY_RUN_RETRIES, 2);
        assert_eq!(WINDIVERT_CONFLICT_MAX_RETRIES, 2);
        assert_eq!(
            WINDIVERT_SYSTEM_ERROR_NO_RETRY_LOG_MESSAGE,
            "WinDivert system error detected — retry will not help"
        );
        assert!((DIRECT_NETWORK_RESTORE_STABLE_WINDOW_SEC - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn strip_outer_quotes_removes_outer_pair_only() {
        // Сверено с python _strip_outer_quotes.
        assert_eq!(strip_outer_quotes("\"a b\""), "a b");
        assert_eq!(strip_outer_quotes("'a'"), "a");
        assert_eq!(strip_outer_quotes("\"a\"b\""), "a\"b");
        assert_eq!(strip_outer_quotes("  x  "), "x");
        assert_eq!(strip_outer_quotes(""), "");
    }

    #[test]
    fn is_winws2_circular_preset_text_delegates() {
        assert!(!is_winws2_circular_preset_text("--wf-tcp-out=443\n"));
    }
}
