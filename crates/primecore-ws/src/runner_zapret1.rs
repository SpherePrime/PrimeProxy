//! Runner Zapret 1 (winws.exe): сборка @config из пресета, dry-run проверка
//! и правила повторов.
//!
//! Порт чистых частей `winws_runtime/runners/zapret1_runner.py`,
//! `utils/args_resolver.py` (используется раннерами) и
//! `health/windows_system_dependencies.py` (сообщение о недостающих DLL).
//! Реальный запуск процесса и события Windows — платформенные действия
//! (см. [`crate::runner`] и [`crate::engine`]); здесь остаются решения: как
//! разрешаются относительные пути аргументов, когда повторять запуск и какими
//! словами объяснять сбой пользователю.

use primecore_files::decode::read_preset_file_text;
use primecore_mode::EXE_NAME_WINWS1;
use primecore_profile::sha1::sha1_hex;

use crate::runner::{launch_args_from_preset_text, PreparedPresetArtifact, PresetCacheKey};
use crate::spawn_failure::is_silent_exit;

/// python `health/windows_system_dependencies.py::WINDOWS_SERVER_WLANAPI_MARKER`.
pub const WINDOWS_SERVER_WLANAPI_MARKER: &str = "[WINDOWS_SERVER_WLANAPI]";

// --- args_resolver.py: разрешение путей в аргументах -------------------------

/// Префиксы для файлов из папки lists/ (python `LISTS_PREFIXES`).
pub const LISTS_PREFIXES: [&str; 4] = [
    "--hostlist=",
    "--ipset=",
    "--hostlist-exclude=",
    "--ipset-exclude=",
];

/// Префиксы для файлов из папки bin/ (python `BIN_PREFIXES`).
pub const BIN_PREFIXES: [&str; 12] = [
    "--dpi-desync-fake-tls=",
    "--dpi-desync-fake-syndata=",
    "--dpi-desync-fake-quic=",
    "--dpi-desync-fake-unknown-udp=",
    "--dpi-desync-split-seqovl-pattern=",
    "--dpi-desync-fake-http=",
    "--dpi-desync-fake-unknown=",
    "--dpi-desync-fakedsplit-pattern=",
    "--dpi-desync-fake-discord=",
    "--dpi-desync-fake-stun=",
    "--dpi-desync-fake-dht=",
    "--dpi-desync-fake-wireguard=",
];

/// Разрешает относительные пути к файлам в аргументах командной строки
/// (python `resolve_args_paths`).
///
/// `--hostlist`/`--ipset`-файлы достраиваются до `lists_dir`, bin-файлы — до
/// `bin_dir`, `--wf-raw-part` — до `filter_dir` (если задан). Абсолютные пути
/// и специальные значения (hex, модификаторы) остаются как есть.
#[must_use]
pub fn resolve_args_paths(
    args: &[String],
    lists_dir: &str,
    bin_dir: &str,
    filter_dir: Option<&str>,
) -> Vec<String> {
    args.iter()
        .map(|arg| resolve_single_arg(arg, lists_dir, bin_dir, filter_dir))
        .collect()
}

/// python `_resolve_single_arg`: разрешение пути в одном аргументе.
#[must_use]
fn resolve_single_arg(
    arg: &str,
    lists_dir: &str,
    bin_dir: &str,
    filter_dir: Option<&str>,
) -> String {
    // --wf-raw-part (для winws2).
    if arg.starts_with("--wf-raw-part=") {
        if let (Some(filter_dir), Some(value)) = (filter_dir, arg.split('=').nth(1)) {
            if let Some(filename_raw) = value.strip_prefix('@') {
                let filename = filename_raw.trim_matches('"');
                if !crate::engine::path_is_abs(filename) {
                    let mut rel = filename.replace('\\', "/").trim().to_string();
                    if let Some(stripped) = rel.strip_prefix("./") {
                        rel = stripped.to_string();
                    }
                    if rel.to_lowercase().starts_with("windivert.filter/") {
                        rel = rel["windivert.filter/".len()..].to_string();
                    }
                    let full_path = crate::engine::join_paths(filter_dir, &rel);
                    return format!("--wf-raw-part=@{full_path}");
                }
                return format!("--wf-raw-part=@{filename}");
            }
        }
        return arg.to_string();
    }

    // Файлы из lists/ (без @ — просто путь).
    for prefix in LISTS_PREFIXES {
        if arg.starts_with(prefix) {
            let Some((_key, filename)) = arg.split_once('=') else {
                return arg.to_string();
            };
            let filename = filename.trim_matches('"');
            if !crate::engine::path_is_abs(filename) {
                let mut rel = filename.replace('\\', "/").trim().to_string();
                if let Some(stripped) = rel.strip_prefix("./") {
                    rel = stripped.to_string();
                }
                if rel.to_lowercase().starts_with("lists/") {
                    rel = rel["lists/".len()..].to_string();
                }
                let full_path = crate::engine::join_paths(lists_dir, &rel);
                return format!("{prefix}{full_path}");
            }
            return arg.to_string();
        }
    }

    // Файлы из bin/.
    for prefix in BIN_PREFIXES {
        if arg.starts_with(prefix) {
            let Some((_key, raw_value)) = arg.split_once('=') else {
                return arg.to_string();
            };
            let value = raw_value.trim().trim_matches('"').trim_matches('\'');
            if value.is_empty() {
                return arg.to_string();
            }
            let at_prefix = if value.starts_with('@') { "@" } else { "" };
            let filename = value
                .strip_prefix('@')
                .unwrap_or(value)
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if filename.is_empty() {
                return arg.to_string();
            }
            let lowered = filename.to_lowercase();
            // Специальные значения (hex и модификаторы) НЕ являются файлами.
            if lowered.starts_with("0x") || lowered.starts_with('!') || lowered.starts_with('^') {
                return arg.to_string();
            }
            let is_abs = crate::engine::path_is_abs(filename);
            let has_path_sep = filename.contains('/') || filename.contains('\\');
            let is_bin_name = lowered.ends_with(".bin");
            // В bin/ автодобавляются только bare *.bin имена (foo.bin).
            if is_abs || has_path_sep {
                return arg.to_string();
            }
            if !is_bin_name {
                return arg.to_string();
            }
            let full_path = crate::engine::join_paths(bin_dir, filename);
            return format!("{prefix}{at_prefix}{full_path}");
        }
    }

    arg.to_string()
}

// --- zapret1_runner.py: @config ----------------------------------------------

/// python `_build_winws1_at_config_text`: @config winws1 из текста пресета.
///
/// В отличие от winws2, здесь сначала разрешаются относительные пути
/// аргументов (`lists/`, `bin/`, `windivert.filter/`).
#[must_use]
pub fn build_winws1_at_config_text(
    source_text: &str,
    lists_dir: &str,
    bin_dir: &str,
    filter_dir: Option<&str>,
) -> String {
    let args = resolve_args_paths(
        &launch_args_from_preset_text(source_text),
        lists_dir,
        bin_dir,
        filter_dir,
    );
    if args.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    for arg in &args {
        result.push_str(&crate::runner_zapret2::shlex_quote(arg));
        result.push('\n');
    }
    result
}

/// python `_winws1_at_config_dir`: `work_dir/user/tmp/winws1_at_config`.
#[must_use]
pub fn winws1_at_config_dir(work_dir: &str) -> String {
    let user = crate::engine::join_paths(work_dir, "user");
    let tmp = crate::engine::join_paths(&user, "tmp");
    crate::engine::join_paths(&tmp, "winws1_at_config")
}

/// python `_winws1_startup_output_dir`: `work_dir/user/tmp/winws1_startup_output`.
#[must_use]
pub fn winws1_startup_output_dir(work_dir: &str) -> String {
    let user = crate::engine::join_paths(work_dir, "user");
    let tmp = crate::engine::join_paths(&user, "tmp");
    crate::engine::join_paths(&tmp, "winws1_startup_output")
}

/// Имя @config с sha1-дайджестом источника
/// (python `_write_winws1_at_config`, шаг без записи).
#[must_use]
pub fn winws1_at_config_path(work_dir: &str, preset_path: &str, config_text: &str) -> String {
    let digest_source = format!(
        "{}\u{0}{}",
        crate::engine::absolute_path(preset_path),
        config_text
    );
    let digest = &sha1_hex(digest_source.as_bytes())[..20];
    crate::engine::join_paths(
        &winws1_at_config_dir(work_dir),
        &format!("winws1_at_{digest}.txt"),
    )
}

/// Путь к файлу стартового вывода winws для артефакта
/// (python `_startup_output_path_for_artifact`).
#[must_use]
pub fn winws1_startup_output_path(
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
        &winws1_startup_output_dir(work_dir),
        &format!("winws1_startup_{digest}.log"),
    )
}

/// python `_write_winws1_at_config`: пишет @config с дайджестом в имени.
///
/// Если файл уже существует с тем же содержимым — он остаётся; кеш подрезается
/// через [`crate::runner_zapret2::prune_at_config_cache`].
pub fn write_winws1_at_config(
    work_dir: &str,
    preset_path: &str,
    source_text: &str,
    lists_dir: &str,
    bin_dir: &str,
    filter_dir: Option<&str>,
) -> String {
    let config_text = build_winws1_at_config_text(source_text, lists_dir, bin_dir, filter_dir);
    let config_dir = winws1_at_config_dir(work_dir);
    let config_path = winws1_at_config_path(work_dir, preset_path, &config_text);
    let _ = std::fs::create_dir_all(&config_dir);

    if let Ok(existing) = std::fs::read_to_string(&config_path) {
        if existing == config_text {
            crate::runner_zapret2::prune_at_config_cache(&config_dir, &config_path, "winws1_");
            return config_path;
        }
    }

    let _ = std::fs::write(&config_path, config_text);
    crate::runner_zapret2::prune_at_config_cache(&config_dir, &config_path, "winws1_");
    config_path
}

/// python `_write_winws1_dry_run_at_config`: текст dry-run @config.
///
/// Если `--dry-run` уже есть среди строк — текст не меняется; иначе он
/// добавляется отдельной строкой.
#[must_use]
pub fn winws1_dry_run_config_text(config_text: &str) -> String {
    let has_dry_run = config_text.lines().any(|line| line.trim() == "--dry-run");
    if has_dry_run {
        return config_text.to_string();
    }
    format!(
        "{}\n--dry-run\n",
        config_text.trim_end_matches(['\r', '\n'])
    )
}

/// Путь dry-run @config
/// (python `_write_winws1_dry_run_at_config`, шаг без записи).
#[must_use]
pub fn winws1_dry_run_config_path(
    work_dir: &str,
    source_config_path: &str,
    config_text: &str,
) -> String {
    let digest_source = format!(
        "{}\u{0}{}",
        crate::engine::absolute_path(source_config_path),
        config_text
    );
    let digest = &sha1_hex(digest_source.as_bytes())[..20];
    crate::engine::join_paths(
        &winws1_at_config_dir(work_dir),
        &format!("winws1_dry_run_{digest}.txt"),
    )
}

/// python `_write_winws1_dry_run_at_config` полностью: читает @config
/// артефакта, добавляет `--dry-run` и пишет отдельный файл. Ошибка —
/// готовый текст (python-`ValueError`/`OSError` как сообщение).
pub fn write_winws1_dry_run_at_config(work_dir: &str, launch_arg: &str) -> Result<String, String> {
    if !launch_arg.starts_with('@') || launch_arg.len() <= 1 {
        return Err("Zapret 1 dry-run requires an @config launch artifact".to_string());
    }

    let source_config_path = &launch_arg[1..];
    let raw = std::fs::read(source_config_path).map_err(|error| format!("{error}"))?;
    let config_text = winws1_dry_run_config_text(&String::from_utf8_lossy(&raw));
    let config_dir = winws1_at_config_dir(work_dir);
    let config_path = winws1_dry_run_config_path(work_dir, source_config_path, &config_text);
    let _ = std::fs::create_dir_all(&config_dir);

    if let Ok(existing) = std::fs::read_to_string(&config_path) {
        if existing == config_text {
            crate::runner_zapret2::prune_at_config_cache(&config_dir, &config_path, "winws1_");
            return Ok(config_path);
        }
    }

    let _ = std::fs::write(&config_path, config_text);
    crate::runner_zapret2::prune_at_config_cache(&config_dir, &config_path, "winws1_");
    Ok(config_path)
}

// --- zapret1_runner.py: dry-run вывод и решения о повторах -------------------

/// python `_decode_dry_run_output`: конкатенация stdout+stderr с заменой
/// ошибок декодирования, без внешних пробелов.
#[must_use]
pub fn decode_dry_run_output(stdout_data: &[u8], stderr_data: &[u8]) -> String {
    let mut data = Vec::with_capacity(stdout_data.len() + stderr_data.len());
    data.extend_from_slice(stdout_data);
    data.extend_from_slice(stderr_data);
    String::from_utf8_lossy(&data).trim().to_string()
}

/// python `_launch_args_files_exist` (та же проверка, что у winws2).
#[must_use]
pub fn launch_args_files_exist(launch_args: &[String], exists: &dyn Fn(&str) -> bool) -> bool {
    crate::runner_zapret2::launch_args_files_exist(launch_args, exists)
}

/// python `_should_retry_unclassified_code_one`: неклассифицированный код 1
/// без диагностического вывода повторяется один раз.
#[must_use]
pub fn should_retry_unclassified_code_one(
    exit_code: i64,
    stderr_output: &str,
    retry_count: u32,
) -> bool {
    if retry_count >= 1 {
        return false;
    }
    is_silent_exit(exit_code, stderr_output)
}

/// python `_build_silent_exit_message`: диагноз молчаливого отказа winws1 по
/// проверяемым фактам. Опрос системы идёт через [`crate::health::SilentExitProbes`].
#[must_use]
pub fn build_silent_exit_message(
    probes: &dyn crate::health::SilentExitProbes,
    exit_code: i64,
) -> String {
    let report = crate::health::run_silent_exit_probes(probes, "", EXE_NAME_WINWS1);
    crate::health::format_silent_exit_message(&report, EXE_NAME_WINWS1, exit_code, None)
}

/// Сообщение dry-run winws1 при неудачном коде выхода
/// (ветка python `_run_preset_dry_run_locked`).
///
/// Порядок совпадает с python: сначала осмысленная строка вывода, иначе —
/// короткое сообщение с кодом.
#[must_use]
pub fn dry_run_failure_message(exit_code: i64, output: &str) -> String {
    let summary = crate::output::relevant_error_line(output, crate::output::FallbackLine::First);
    if !summary.is_empty() {
        return format!(
            "Проверка preset для winws не прошла (код {exit_code}): {:.200}",
            summary
        );
    }
    format!("Проверка preset для winws не прошла (код {exit_code})")
}

/// Сообщение о недостающих системных DLL
/// (python `_format_missing_windows_system_dependency_error`).
///
/// `is_windows_server` — платформенная проверка редакции Windows (реестр и
/// `platform.win32_edition` остаются за вызывающим); при успехе сообщение
/// помечается маркером [`WINDOWS_SERVER_WLANAPI_MARKER`].
#[must_use]
pub fn format_missing_windows_system_dependency_error(
    missing_dlls: &[&str],
    exe_name: &str,
    is_windows_server: bool,
) -> String {
    let dll_text = missing_dlls
        .iter()
        .filter(|name| !name.trim().is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let dll_text = if dll_text.is_empty() {
        "системная DLL".to_string()
    } else {
        dll_text
    };
    let exe = exe_name.rsplit(['/', '\\']).next().unwrap_or("winws");
    let exe = if exe.is_empty() { "winws" } else { exe };
    let message = format!(
        "Windows урезана: не найден системный файл {dll_text}. Из-за этого {exe} не может запуститься. Нужна обычная Windows или сборка, где есть компонент автонастройки WLAN (беспроводная сеть)."
    );
    // python should_offer_windows_server_wlanapi_install: wlanapi.dll и Server.
    if has_wlanapi_missing(missing_dlls) && is_windows_server {
        return mark_windows_server_wlanapi_message(&message);
    }
    message
}

/// python `mark_windows_server_wlanapi_message`.
#[must_use]
pub fn mark_windows_server_wlanapi_message(message: &str) -> String {
    let text = message.trim();
    if text.starts_with(WINDOWS_SERVER_WLANAPI_MARKER) {
        return text.to_string();
    }
    format!("{WINDOWS_SERVER_WLANAPI_MARKER} {text}")
        .trim()
        .to_string()
}

/// python `has_wlanapi_missing`.
#[must_use]
pub fn has_wlanapi_missing(missing_dlls: &[&str]) -> bool {
    missing_dlls
        .iter()
        .any(|name| name.trim().to_lowercase() == "wlanapi.dll")
}

// --- zapret1_runner.py: сборка артефакта -------------------------------------

/// python `_compile_preset_artifact` у winws1: артефакт запуска из пресета.
///
/// Валидация ссылок у winws1 не выполняется (пресет отдаётся как есть через
/// @config); ошибки подготовки — текст отчёта.
pub fn compile_winws1_preset_artifact(
    preset_path: &str,
    work_dir: &str,
    lists_dir: &str,
    bin_dir: &str,
) -> PreparedPresetArtifact {
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

    let cache_key: Option<PresetCacheKey> = crate::runner::preset_cache_key(p);

    let source_text = match read_preset_file_text(std::path::Path::new(p)) {
        Ok(text) => text,
        Err(error) => {
            return PreparedPresetArtifact {
                preset_path: p.to_string(),
                cache_key: None,
                normalized_text: String::new(),
                launch_args: Vec::new(),
                validation_ok: false,
                validation_report: format!("Не удалось прочитать preset файл: {error}"),
            };
        }
    };

    let at_config_path =
        write_winws1_at_config(work_dir, p, &source_text, lists_dir, bin_dir, None);

    PreparedPresetArtifact {
        preset_path: p.to_string(),
        cache_key,
        normalized_text: source_text,
        launch_args: vec![format!("@{at_config_path}")],
        validation_ok: true,
        validation_report: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("primecore_ws_z1_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог");
        dir.to_string_lossy().to_string()
    }

    // --- args_resolver.py -------------------------------------------------------

    #[test]
    fn resolve_args_paths_resolves_lists_and_bin() {
        // Сверено с python resolve_args_paths.
        let args: Vec<String> = [
            "--hostlist=lists/x.txt",
            "--ipset=y.txt",
            "--hostlist=C:\\abs\\h.txt",
            "--dpi-desync-fake-tls=fake.bin",
            "--dpi-desync-fake-tls=@payload.bin",
            "--dpi-desync-fake-tls=@0x1603",
            "--dpi-desync-fake-tls=lists/nested.bin",
            "--wf-tcp-out=443",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let resolved = resolve_args_paths(&args, "/root/lists", "/root/bin", None);

        assert_eq!(resolved[0], "--hostlist=/root/lists/x.txt");
        assert_eq!(resolved[1], "--ipset=/root/lists/y.txt");
        assert_eq!(resolved[2], "--hostlist=C:\\abs\\h.txt");
        assert_eq!(resolved[3], "--dpi-desync-fake-tls=/root/bin/fake.bin");
        assert_eq!(resolved[4], "--dpi-desync-fake-tls=@/root/bin/payload.bin");
        assert_eq!(resolved[5], "--dpi-desync-fake-tls=@0x1603");
        // Путь с разделителем в bin/ не автодобавляется.
        assert_eq!(resolved[6], "--dpi-desync-fake-tls=lists/nested.bin");
        assert_eq!(resolved[7], "--wf-tcp-out=443");
    }

    #[test]
    fn resolve_args_paths_resolves_windivert_filter() {
        // Сверено с python: --wf-raw-part ищется в папке windivert.filter.
        let args: Vec<String> = [
            "--wf-raw-part=@windivert.filter/custom.txt",
            "--wf-raw-part=@C:\\abs\\f.txt",
            "--wf-raw-part=@C:/abs/f.txt",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let resolved = resolve_args_paths(
            &args,
            "/root/lists",
            "/root/bin",
            Some("/root/windivert.filter"),
        );

        assert_eq!(
            resolved[0],
            "--wf-raw-part=@/root/windivert.filter/custom.txt"
        );
        // Windows-абсолютный путь распознаётся и не меняется.
        assert_eq!(resolved[1], "--wf-raw-part=@C:\\abs\\f.txt");
        assert_eq!(resolved[2], "--wf-raw-part=@C:/abs/f.txt");
    }

    #[test]
    fn resolve_args_paths_without_filter_dir_keeps_raw_part() {
        let args: Vec<String> = vec!["--wf-raw-part=@custom.txt".to_string()];
        let resolved = resolve_args_paths(&args, "/lists", "/bin", None);
        assert_eq!(resolved[0], "--wf-raw-part=@custom.txt");
    }

    // --- @config ----------------------------------------------------------------

    #[test]
    fn winws1_at_config_has_no_bom_and_no_comments() {
        // python test_winws1_at_config_has_no_bom.
        let root = tmpdir("bom1");
        let preset_path = format!("{root}/selected.txt");
        std::fs::write(&preset_path, "--wf-tcp=443\n").expect("пресет");

        let at_config_path = write_winws1_at_config(
            &root,
            &preset_path,
            "--wf-tcp=443\n",
            "/lists",
            "/bin",
            None,
        );

        let text = std::fs::read_to_string(&at_config_path).expect("@config");
        assert!(!text.starts_with('\u{FEFF}'), "{text}");
        assert_eq!(text, "--wf-tcp=443\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn winws1_at_config_resolves_relative_paths() {
        // Сверено с python _build_winws1_at_config_text: пути разрешаются до
        // записи в @config.
        let text = build_winws1_at_config_text(
            "--hostlist=lists/x.txt\n--dpi-desync-fake-tls=f.bin\n",
            "/root/lists",
            "/root/bin",
            None,
        );
        assert_eq!(
            text,
            "--hostlist=/root/lists/x.txt\n--dpi-desync-fake-tls=/root/bin/f.bin\n"
        );
    }

    #[test]
    fn at_config_digest_depends_on_preset_path_and_text() {
        let root = tmpdir("digest1");
        let path_a = format!("{root}/a.txt");
        let path_b = format!("{root}/b.txt");
        let first = winws1_at_config_path(&root, &path_a, "--wf-tcp=443\n");
        let same = winws1_at_config_path(&root, &path_a, "--wf-tcp=443\n");
        let other_text = winws1_at_config_path(&root, &path_a, "--wf-tcp=80\n");
        let other_path = winws1_at_config_path(&root, &path_b, "--wf-tcp=443\n");

        assert_eq!(first, same);
        assert_ne!(first, other_text);
        assert_ne!(first, other_path);
        assert!(first
            .rsplit('/')
            .next()
            .unwrap_or("")
            .starts_with("winws1_at_"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn startup_output_path_uses_args_digest() {
        let root = tmpdir("out1");
        let path = winws1_startup_output_path(&root, "/p", &["@config.txt".to_string()]);
        assert!(path.contains("/user/tmp/winws1_startup_output/winws1_startup_"));
        let other = winws1_startup_output_path(&root, "/p", &["@other.txt".to_string()]);
        assert_ne!(path, other);
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- dry-run ----------------------------------------------------------------

    #[test]
    fn dry_run_config_text_appends_dry_run_once() {
        // Сверено с python _write_winws1_dry_run_at_config.
        assert_eq!(
            winws1_dry_run_config_text("--wf-tcp=443\n"),
            "--wf-tcp=443\n--dry-run\n"
        );
        // Уже есть --dry-run — текст не меняется.
        assert_eq!(
            winws1_dry_run_config_text("--wf-tcp=443\n--dry-run\n"),
            "--wf-tcp=443\n--dry-run\n"
        );
        // CRLF-хвост обрезается.
        assert_eq!(
            winws1_dry_run_config_text("--wf-tcp=443\r\n"),
            "--wf-tcp=443\n--dry-run\n"
        );
    }

    #[test]
    fn dry_run_at_config_is_written_to_tmp_dir() {
        let root = tmpdir("dryrun1");
        let config_path = format!("{root}/at.txt");
        std::fs::write(&config_path, "--wf-tcp=443\n").expect("@config");

        let dry_run_path =
            write_winws1_dry_run_at_config(&root, &format!("@{config_path}")).expect("файл");

        assert!(dry_run_path.starts_with(&format!("{root}/user/tmp/winws1_at_config/")));
        assert!(dry_run_path.contains("winws1_dry_run_"));
        let text = std::fs::read_to_string(&dry_run_path).expect("текст");
        assert_eq!(text, "--wf-tcp=443\n--dry-run\n");

        // Повторная запись возвращает тот же путь (дайджест по содержимому).
        let again =
            write_winws1_dry_run_at_config(&root, &format!("@{config_path}")).expect("файл");
        assert_eq!(dry_run_path, again);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dry_run_requires_at_config_artifact() {
        let root = tmpdir("dryrun_err");
        let error =
            write_winws1_dry_run_at_config(&root, "--wf-tcp=443").expect_err("требуется @config");
        assert_eq!(
            error,
            "Zapret 1 dry-run requires an @config launch artifact"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn decode_dry_run_output_merges_streams_and_trims() {
        // Сверено с python _decode_dry_run_output.
        assert_eq!(decode_dry_run_output(b"out\n", b"err\n"), "out\nerr");
        assert_eq!(decode_dry_run_output(b"", b""), "");
        assert_eq!(decode_dry_run_output(b"\n", b"  err  \n"), "err");
        // Некорректные байты заменяются (python errors="replace").
        assert_eq!(decode_dry_run_output(b"\xff\xfe", b""), "\u{FFFD}\u{FFFD}");
    }

    // --- решения о повторах и тексты ------------------------------------------

    #[test]
    fn unclassified_code_one_retried_once_without_output() {
        // Сверено с python _should_retry_unclassified_code_one.
        assert!(should_retry_unclassified_code_one(1, "", 0));
        assert!(!should_retry_unclassified_code_one(1, "", 1));
        assert!(!should_retry_unclassified_code_one(1, "some error", 0));
        assert!(!should_retry_unclassified_code_one(87, "", 0));
    }

    #[test]
    fn dry_run_failure_message_prefers_diagnostic_line() {
        // Сверено с python-веткой сообщения dry-run.
        assert_eq!(
            dry_run_failure_message(87, "github version v1\nwindivert: error opening filter\n"),
            "Проверка preset для winws не прошла (код 87): windivert: error opening filter"
        );
        assert_eq!(
            dry_run_failure_message(1, ""),
            "Проверка preset для winws не прошла (код 1)"
        );
    }

    #[test]
    fn silent_exit_message_uses_probes() {
        // Сверено с python _build_silent_exit_message: диагноз строится по
        // проверяемым фактам из опроса системы.
        let message = build_silent_exit_message(&crate::health::SilentExitProbesUnavailable, 1);
        assert!(message.contains("winws"), "{message}");
        assert!(message.contains("1"), "{message}");
    }

    #[test]
    fn missing_dll_message_matches_python() {
        // Сверено с python _format_missing_windows_system_dependency_error.
        assert_eq!(
            format_missing_windows_system_dependency_error(&["wlanapi.dll"], "winws.exe", false),
            "Windows урезана: не найден системный файл wlanapi.dll. Из-за этого winws.exe не может запуститься. Нужна обычная Windows или сборка, где есть компонент автонастройки WLAN (беспроводная сеть)."
        );
        // На Windows Server сообщение помечается маркером.
        assert!(format_missing_windows_system_dependency_error(
            &["wlanapi.dll"],
            "winws.exe",
            true
        )
        .starts_with("[WINDOWS_SERVER_WLANAPI] "));
        assert!(
            format_missing_windows_system_dependency_error(&[], "winws.exe", true)
                .contains("системная DLL")
        );
    }

    #[test]
    fn wlanapi_marker_added_once() {
        // Сверено с python mark_windows_server_wlanapi_message.
        assert_eq!(
            mark_windows_server_wlanapi_message("[WINDOWS_SERVER_WLANAPI] текст"),
            "[WINDOWS_SERVER_WLANAPI] текст"
        );
        assert_eq!(
            mark_windows_server_wlanapi_message("текст"),
            "[WINDOWS_SERVER_WLANAPI] текст"
        );
    }

    #[test]
    fn has_wlanapi_missing_checks_name_case_insensitive() {
        assert!(has_wlanapi_missing(&["WLANAPI.dll"]));
        assert!(!has_wlanapi_missing(&["other.dll"]));
        assert!(!has_wlanapi_missing(&[]));
    }

    #[test]
    fn compile_winws1_preset_artifact_reports_missing_file() {
        // Сверено с python _compile_preset_artifact.
        let artifact = compile_winws1_preset_artifact("", "/work", "/lists", "/bin");
        assert!(!artifact.validation_ok);
        assert_eq!(artifact.validation_report, "Не указан путь к preset файлу");

        let artifact =
            compile_winws1_preset_artifact("/absent/preset.txt", "/work", "/lists", "/bin");
        assert!(!artifact.validation_ok);
        assert_eq!(
            artifact.validation_report,
            "Preset файл не найден: /absent/preset.txt"
        );
    }

    #[test]
    fn compile_winws1_preset_artifact_builds_at_config() {
        let root = tmpdir("compile1");
        std::fs::create_dir_all(format!("{root}/lists")).expect("lists");
        std::fs::create_dir_all(format!("{root}/bin")).expect("bin");
        let preset_path = format!("{root}/selected.txt");
        std::fs::write(&preset_path, "--wf-tcp=443\n--hostlist=lists/x.txt\n").expect("пресет");
        std::fs::write(format!("{root}/lists/x.txt"), "example.com\n").expect("файл");

        let artifact = compile_winws1_preset_artifact(
            &preset_path,
            &root,
            &format!("{root}/lists"),
            &format!("{root}/bin"),
        );

        assert!(artifact.validation_ok, "{}", artifact.validation_report);
        assert_eq!(artifact.launch_args.len(), 1);
        assert!(artifact.launch_args[0].starts_with('@'));
        let text = std::fs::read_to_string(&artifact.launch_args[0][1..]).expect("@config");
        assert!(text.contains("--wf-tcp=443"), "{text}");
        assert!(text.contains("--hostlist="), "{text}");
        // lists/x.txt разрешён в реальный путь.
        assert!(text.contains("/lists/x.txt"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
