//! База стратегий-раннеров winws: сборка командной строки и каркас состояния.
//!
//! Порт чистых частей `winws_runtime/runners/runner_base.py`,
//! `runners/preset_runner_support.py` и `runners/constants.py`. Реальный запуск
//! процесса, чтение его вывода и остановка — платформенные действия; они
//! описаны трейтом [`ProcessSpawner`], а здесь остаются решения: порядок
//! аргументов из preset-файла, машина состояний запуска, текст запуска для
//! журнала и план запуска.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- runners/constants.py ---------------------------------------------------

/// Метки для стратегий.
pub const LABEL_RECOMMENDED: &str = "recommended";
/// Метка «осторожно».
pub const LABEL_CAUTION: &str = "caution";
/// Метка «эксперимент».
pub const LABEL_EXPERIMENTAL: &str = "experimental";
/// Метка «стабильная».
pub const LABEL_STABLE: &str = "stable";
/// Метка «для игр».
pub const LABEL_GAME: &str = "game";
/// Метка WARP.
pub const LABEL_WARP: &str = "warp";

/// Константы скрытого запуска Windows: `wShowWindow = SW_HIDE`.
pub const SW_HIDE: u32 = 0;
/// Константы скрытого запуска Windows: `CREATE_NO_WINDOW`.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Константы скрытого запуска Windows: `STARTF_USESHOWWINDOW`.
pub const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;

/// Настройки отображения меток: цвета по меткам.
pub fn label_colors() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (LABEL_RECOMMENDED, "#00B900"),
        (LABEL_CAUTION, "#FF6600"),
        (LABEL_EXPERIMENTAL, "#CC0000"),
        (LABEL_STABLE, "#006DDA"),
        (LABEL_GAME, "#FFC862"),
        (LABEL_WARP, "#EE850C"),
    ])
}

/// Настройки отображения меток: подписи по меткам.
pub fn label_texts() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (LABEL_RECOMMENDED, "Рекомендуется"),
        (LABEL_CAUTION, "Осторожно"),
        (LABEL_EXPERIMENTAL, "Эксперимент"),
        (LABEL_STABLE, "Стабильная"),
        (LABEL_GAME, "Для игр"),
        (LABEL_WARP, "WARP"),
    ])
}

// --- preset_runner_support: argv из текста пресета ---------------------------

/// Разбивает строку пресета на один или несколько аргументов командной строки.
///
/// Circular/source presets may store several `--...` arguments on one line to
/// keep a single logical strategy together. Запуск всё равно требует каждый
/// CLI-аргумент отдельным элементом, поэтому делим только по пробелу, который
/// вводит следующий `--`-аргумент.
fn split_launch_line(raw_line: &str) -> Vec<String> {
    let stripped = raw_line.trim();
    if stripped.is_empty() {
        return Vec::new();
    }
    if !stripped.starts_with("--") {
        return vec![stripped.to_string()];
    }
    let mut parts = Vec::new();
    let bytes = stripped.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            // Граница: перед ней непробельный символ, сразу после — "--".
            let preceding_non_space = i > 0 && !bytes[i - 1].is_ascii_whitespace();
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let next_starts_arg = stripped[j..].starts_with("--");
            if preceding_non_space && next_starts_arg && i > start {
                parts.push(stripped[start..i].trim().to_string());
                start = j;
                i = j;
                continue;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    parts.push(stripped[start..].trim().to_string());
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

/// Собирает argv из текста выбранного preset-файла.
///
/// Ведущий BOM (U+FEFF от «UTF-8 с BOM» в Блокноте) — это часть кодировки
/// файла, а не текста пресета: `str.trim()` его не убирает, и без явного
/// снятия он прилипал бы к первой опции. Проверка пресета снимает его так же.
pub fn launch_args_from_preset_text(content: &str) -> Vec<String> {
    let text = content.strip_prefix('\u{FEFF}').unwrap_or(content);
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut args: Vec<String> = Vec::new();
    // Только «\n», как у парсера: splitlines() делил бы ещё по \x0b/\x85/\u2028.
    for raw in text.split('\n') {
        let stripped = raw.trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with('#') {
            continue;
        }
        args.extend(split_launch_line(stripped));
    }
    args
}

/// Готовый к запуску артефакт preset-файла.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPresetArtifact {
    pub preset_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_key: Option<PresetCacheKey>,
    pub normalized_text: String,
    pub launch_args: Vec<String>,
    pub validation_ok: bool,
    pub validation_report: String,
}

// --- preset_runner_support: машина состояний ---------------------------------

/// Состояние preset-раннера; значения строк — python-имена `PresetRunnerState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresetRunnerState {
    Idle,
    Stopping,
    Starting,
    Running,
    Failed,
}

impl PresetRunnerState {
    pub fn as_str(self) -> &'static str {
        match self {
            PresetRunnerState::Idle => "idle",
            PresetRunnerState::Stopping => "stopping",
            PresetRunnerState::Starting => "starting",
            PresetRunnerState::Running => "running",
            PresetRunnerState::Failed => "failed",
        }
    }
}

/// Снимок состояния preset-раннера для интерфейса и рантайма.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetRunnerStateSnapshot {
    pub state: PresetRunnerState,
    pub generation: u64,
    pub preset_path: String,
    pub strategy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub error: String,
    pub reason: String,
}

/// Параметры перехода машины состояний (python-именованные аргументы
/// `transition()`).
#[derive(Debug, Clone, Default)]
pub struct TransitionParams<'a> {
    pub preset_path: &'a str,
    pub strategy_name: &'a str,
    pub pid: Option<u32>,
    pub error: &'a str,
    pub reason: &'a str,
    pub allow_same: bool,
}

/// Машина состояний preset-раннера: какие переходы разрешены.
///
/// python-версия бросала `RuntimeError` на запрещённом переходе; здесь это
/// значение-ошибка с тем же текстом.
pub struct PresetRunnerStateMachine {
    generation: u64,
    snapshot: PresetRunnerStateSnapshot,
}

impl Default for PresetRunnerStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl PresetRunnerStateMachine {
    /// Разрешённые переходы; соответствуют `_ALLOWED` python-класса.
    fn allowed(from: PresetRunnerState) -> &'static [PresetRunnerState] {
        match from {
            PresetRunnerState::Idle => &[PresetRunnerState::Starting, PresetRunnerState::Failed],
            PresetRunnerState::Stopping => &[
                PresetRunnerState::Idle,
                PresetRunnerState::Starting,
                PresetRunnerState::Failed,
            ],
            PresetRunnerState::Starting => &[
                PresetRunnerState::Running,
                PresetRunnerState::Failed,
                PresetRunnerState::Idle,
            ],
            PresetRunnerState::Running => &[
                PresetRunnerState::Starting,
                PresetRunnerState::Stopping,
                PresetRunnerState::Failed,
                PresetRunnerState::Idle,
            ],
            PresetRunnerState::Failed => &[PresetRunnerState::Idle, PresetRunnerState::Starting],
        }
    }

    pub fn new() -> Self {
        Self {
            generation: 0,
            snapshot: PresetRunnerStateSnapshot {
                state: PresetRunnerState::Idle,
                generation: 0,
                preset_path: String::new(),
                strategy_name: String::new(),
                pid: None,
                error: String::new(),
                reason: "initialized".to_string(),
            },
        }
    }

    pub fn snapshot(&self) -> &PresetRunnerStateSnapshot {
        &self.snapshot
    }

    /// Переход в новое состояние. Запрещённый переход — ошибка с текстом
    /// «Invalid preset runner state transition: {from} -> {to}».
    pub fn transition(
        &mut self,
        target: PresetRunnerState,
        params: TransitionParams<'_>,
    ) -> Result<PresetRunnerStateSnapshot, String> {
        let current = self.snapshot.state;
        if target == current && !params.allow_same {
            return Ok(self.snapshot.clone());
        }

        if target != current && !Self::allowed(current).contains(&target) {
            return Err(format!(
                "Invalid preset runner state transition: {} -> {}",
                current.as_str(),
                target.as_str()
            ));
        }

        self.generation += 1;
        self.snapshot = PresetRunnerStateSnapshot {
            state: target,
            generation: self.generation,
            preset_path: params.preset_path.to_string(),
            strategy_name: params.strategy_name.to_string(),
            pid: params.pid,
            error: params.error.to_string(),
            reason: params.reason.to_string(),
        };
        Ok(self.snapshot.clone())
    }
}

// --- preset_runner_support: ключ кеша пресета --------------------------------

/// Ключ кеша скомпилированного пресета: (путь, mtime_ns, размер, digest).
///
/// python-версия хранила кортеж; здесь — структура с теми же полями.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PresetCacheKey {
    pub path: String,
    pub mtime_ns: i128,
    pub size: u64,
    pub digest: String,
}

/// Ключ кеша для файла пресета или `None`, если файла нет/путь пуст.
pub fn preset_cache_key(path: &str) -> Option<PresetCacheKey> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let metadata = std::fs::metadata(trimmed).ok()?;

    let digest = std::fs::read(trimmed)
        .ok()
        .map(|data| blake2b_digest_16(&data))
        .unwrap_or_default();

    Some(PresetCacheKey {
        path: normcase(trimmed),
        mtime_ns: file_mtime_ns(&metadata),
        size: metadata.len(),
        digest,
    })
}

/// `os.path.normcase`: на Windows — нижний регистр и «\», на остальных — как есть.
fn normcase(path: &str) -> String {
    if cfg!(windows) {
        path.to_lowercase().replace('/', "\\")
    } else {
        path.to_string()
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

/// blake2b-дайджест длиной 16 байт в hex — как `hashlib.blake2b(digest_size=16)`.
fn blake2b_digest_16(data: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(16)
        .to_state()
        .update(data)
        .finalize()
        .to_hex()
        .to_string()
}

/// Ограниченный кеш «ключ → значение» (python `remember_cache_entry`):
/// при переполнении вытесняет самую старую запись.
pub fn remember_cache_entry<V: Clone>(
    cache: &mut std::collections::VecDeque<(PresetCacheKey, V)>,
    key: Option<PresetCacheKey>,
    value: V,
    max_entries: usize,
) {
    let Some(key) = key else { return };
    cache.push_back((key, value));
    while cache.len() > max_entries {
        cache.pop_front();
    }
}

// --- runner_base: план запуска и текст ---------------------------------------

/// Сколько символов стартового вывода winws2 попадает в общий лог при отказе.
pub const STARTUP_OUTPUT_LOG_LIMIT: usize = 2000;

/// Сколько ждать подтверждения выхода процесса после команды на завершение.
/// Это верхняя граница, а не пауза: обычно Windows подтверждает выход за
/// миллисекунды, и ожидание заканчивается сразу.
pub const PROCESS_STOP_TIMEOUT_SECONDS: f64 = 5.0;

/// Безопасные авто-действия WinDivert после неудачного запуска.
pub const SAFE_WINDIVERT_AUTOFIX_ACTIONS: [&str; 3] =
    ["cleanup_driver", "enable_bfe", "enable_adapters"];

/// Системные DLL, требуемые winws (python `_WINDOWS_SYSTEM_DLLS_REQUIRED_BY_WINWS`).
pub const WINDOWS_SYSTEM_DLLS_REQUIRED_BY_WINWS: [&str; 1] = ["wlanapi.dll"];

/// План запуска: командная строка winws и рабочий каталог.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
    /// Полный путь к winws.exe / winws2.exe.
    pub exe: String,
    /// Аргументы стратегии в порядке пресета.
    pub args: Vec<String>,
    /// Рабочий каталог запуска.
    pub cwd: String,
}

/// Один запущенный процесс: дескриптор определяется реализацией [`ProcessSpawner`].
pub trait SpawnedProcess {
    /// PID процесса, если он известен.
    fn pid(&self) -> Option<u32>;
    /// `None` — процесс жив, `Some(code)` — завершился с кодом.
    fn poll(&self) -> Option<i32>;
    /// Принудительно завершает процесс.
    fn kill(&mut self);
}

/// Платформенный запуск процессов winws. Реализация живёт вне крейта:
/// на Windows это `CreateProcess` со скрытым окном, в тестах — фейки.
pub trait ProcessSpawner {
    type Process: SpawnedProcess;

    /// Запускает процесс по плану. Ошибка — человеко-читаемый текст.
    fn spawn(&mut self, plan: &LaunchPlan) -> Result<Self::Process, String>;
}

/// Командная строка запуска в виде, пригодном для журнала и запуска
/// (python `subprocess.list2cmdline`).
pub fn format_launch_command_line(cmd: &[String]) -> String {
    let mut result = String::new();
    for (index, arg) in cmd.iter().enumerate() {
        if index > 0 {
            result.push(' ');
        }
        result.push_str(&list2cmdline_single(arg));
    }
    result
}

/// Кавычки и обратные слэши по правилам MS C runtime для одного аргумента.
fn list2cmdline_single(arg: &str) -> String {
    let chars: Vec<char> = arg.chars().collect();
    let need_quote = arg.contains(' ') || arg.contains('\t') || arg.is_empty();

    let mut result = String::new();
    if need_quote {
        result.push('"');
    }
    let mut bs_buf: Vec<char> = Vec::new();
    for &c in &chars {
        if c == '\\' {
            bs_buf.push(c);
        } else if c == '"' {
            let bs = bs_buf.iter().collect::<String>();
            result.push_str(&bs);
            result.push_str(&bs);
            bs_buf.clear();
            result.push('\\');
            result.push('"');
        } else {
            if !bs_buf.is_empty() {
                let bs = bs_buf.iter().collect::<String>();
                result.push_str(&bs);
                bs_buf.clear();
            }
            result.push(c);
        }
    }
    let bs = bs_buf.iter().collect::<String>();
    if need_quote {
        // двойные обратные слэши перед закрывающей кавычкой
        result.push_str(&bs);
        result.push_str(&bs);
        result.push('"');
    } else {
        result.push_str(&bs);
    }
    result
}

/// Строка вывода winws2, годная для показа пользователю.
///
/// Пустая строка означает «winws2 не сказал ничего по существу»: служебный
/// баннер версии он печатает всегда, и выдавать его за причину отказа нельзя
/// (см. [`crate::output`] — единый разбор вывода).
pub fn summarize_startup_output(output: &str) -> String {
    crate::output::relevant_error_line(output, crate::output::FallbackLine::First)
}

/// Текст записи общего лога при неудачном старте (python `_log_full_startup_output`):
/// `None` — писать нечего (пустой вывод), иначе готовая строка WARNING.
pub fn format_full_startup_log(engine_name: &str, output: &str) -> Option<String> {
    let text = output.trim();
    if text.is_empty() {
        return Some(format!("{engine_name} не оставил стартового вывода"));
    }
    let truncated: String = text.chars().take(STARTUP_OUTPUT_LOG_LIMIT).collect();
    let suffix = if text.chars().count() > STARTUP_OUTPUT_LOG_LIMIT {
        " […]"
    } else {
        ""
    };
    Some(format!(
        "{engine_name} startup output ({} B): {}{suffix}",
        text.chars().count(),
        truncated.replace('\n', " | ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_is_stripped_and_crlf_normalized() {
        let args = launch_args_from_preset_text("\u{FEFF}--wf-tcp-out=443\r\n--wf-udp-out=53\r\n");
        assert_eq!(args, vec!["--wf-tcp-out=443", "--wf-udp-out=53"]);
    }

    #[test]
    fn comments_and_empty_lines_are_skipped() {
        let args = launch_args_from_preset_text("# комментарий\n\n  \n--wf-tcp-out=443");
        assert_eq!(args, vec!["--wf-tcp-out=443"]);
    }

    #[test]
    fn inline_arguments_are_split_only_before_next_option() {
        // Сверено с python: одна строка — несколько --аргументов.
        let args = launch_args_from_preset_text("--wf-tcp-out=443 --wf-udp-out=53");
        assert_eq!(args, vec!["--wf-tcp-out=443", "--wf-udp-out=53"]);
        // Значение с пробелами внутри не делится.
        let args = launch_args_from_preset_text("--hostlist=файл со пробелом.txt");
        assert_eq!(args, vec!["--hostlist=файл со пробелом.txt"]);
        // Несколько пробелов перед следующим --аргументом.
        let args = launch_args_from_preset_text("--a=1   --b=2");
        assert_eq!(args, vec!["--a=1", "--b=2"]);
        // Не-опционная строка не делится вовсе.
        let args = launch_args_from_preset_text("просто текст --не опция");
        assert_eq!(args, vec!["просто текст --не опция"]);
    }

    #[test]
    fn empty_text_gives_no_args() {
        assert!(launch_args_from_preset_text("").is_empty());
        assert!(launch_args_from_preset_text("\n\n").is_empty());
    }

    #[test]
    fn state_machine_starts_idle() {
        let machine = PresetRunnerStateMachine::new();
        assert_eq!(machine.snapshot().state, PresetRunnerState::Idle);
        assert_eq!(machine.snapshot().generation, 0);
        assert_eq!(machine.snapshot().reason, "initialized");
    }

    #[test]
    fn state_machine_allows_documented_transitions() {
        let mut machine = PresetRunnerStateMachine::new();
        let snapshot = machine
            .transition(
                PresetRunnerState::Starting,
                TransitionParams {
                    preset_path: "/p",
                    strategy_name: "Стратегия",
                    reason: "start",
                    ..Default::default()
                },
            )
            .expect("idle → starting");
        assert_eq!(snapshot.state, PresetRunnerState::Starting);
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.preset_path, "/p");

        machine
            .transition(
                PresetRunnerState::Running,
                TransitionParams {
                    preset_path: "/p",
                    strategy_name: "Стратегия",
                    pid: Some(42),
                    reason: "running",
                    ..Default::default()
                },
            )
            .expect("starting → running");
        let snapshot = machine
            .transition(
                PresetRunnerState::Stopping,
                TransitionParams {
                    reason: "stop",
                    ..Default::default()
                },
            )
            .expect("running → stopping");
        assert_eq!(snapshot.pid, None);
        machine
            .transition(
                PresetRunnerState::Idle,
                TransitionParams {
                    reason: "done",
                    ..Default::default()
                },
            )
            .expect("stopping → idle");
        assert_eq!(machine.snapshot().generation, 4);
    }

    #[test]
    fn state_machine_rejects_invalid_transition() {
        let mut machine = PresetRunnerStateMachine::new();
        let error = machine
            .transition(PresetRunnerState::Running, TransitionParams::default())
            .expect_err("idle → running запрещён");
        assert_eq!(
            error,
            "Invalid preset runner state transition: idle -> running"
        );
        // Состояние не изменилось.
        assert_eq!(machine.snapshot().state, PresetRunnerState::Idle);
    }

    #[test]
    fn state_machine_same_state_is_noop_unless_allowed() {
        let mut machine = PresetRunnerStateMachine::new();
        machine
            .transition(PresetRunnerState::Idle, TransitionParams::default())
            .expect("same state без allow_same — no-op");
        assert_eq!(machine.snapshot().generation, 0);
        machine
            .transition(
                PresetRunnerState::Idle,
                TransitionParams {
                    reason: "retry",
                    allow_same: true,
                    ..Default::default()
                },
            )
            .expect("same state с allow_same");
        assert_eq!(machine.snapshot().generation, 1);
        assert_eq!(machine.snapshot().reason, "retry");
    }

    #[test]
    fn list2cmdline_quotes_only_when_needed() {
        // Сверено с python subprocess.list2cmdline.
        assert_eq!(
            format_launch_command_line(&["winws2.exe".to_string(), "--wf-tcp-out=443".to_string()]),
            "winws2.exe --wf-tcp-out=443"
        );
        assert_eq!(format_launch_command_line(&["a b".to_string()]), "\"a b\"");
        assert_eq!(format_launch_command_line(&["".to_string()]), "\"\"");
        assert_eq!(
            format_launch_command_line(&["he said \"hi\"".to_string()]),
            "\"he said \\\"hi\\\"\""
        );
        assert_eq!(
            format_launch_command_line(&["trailing \\".to_string()]),
            "\"trailing \\\\\""
        );
    }

    #[test]
    fn startup_output_summary_hides_banner() {
        const BANNER: &str = "github version v1.0.3 (b78b52c4) lua_compat_ver 6";
        const WINDIVERT_ERROR: &str =
            "windivert: error opening filter: The service cannot be started";
        assert_eq!(summarize_startup_output(BANNER), "");
        assert_eq!(
            summarize_startup_output(&format!("{BANNER}\n{WINDIVERT_ERROR}")),
            WINDIVERT_ERROR
        );
    }

    #[test]
    fn full_startup_log_handles_empty_and_long_output() {
        assert_eq!(
            format_full_startup_log("winws2", ""),
            Some("winws2 не оставил стартового вывода".to_string())
        );
        let text = format_full_startup_log("winws2", "строка 1\nстрока 2").expect("текст");
        assert!(
            text.contains("winws2 startup output (17 B): строка 1 | строка 2"),
            "{text}"
        );

        let long = "x".repeat(STARTUP_OUTPUT_LOG_LIMIT + 100);
        let text = format_full_startup_log("winws2", &long).expect("текст");
        assert!(text.contains("[…]"));
        assert!(text.len() < STARTUP_OUTPUT_LOG_LIMIT + 200);
    }

    #[test]
    fn cache_remember_evicts_oldest_entries() {
        let mut cache = std::collections::VecDeque::new();
        let key = |n: u64| PresetCacheKey {
            path: format!("/p{n}"),
            mtime_ns: 0,
            size: 0,
            digest: String::new(),
        };
        for n in 0..5u64 {
            remember_cache_entry(&mut cache, Some(key(n)), n, 3);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.front().unwrap().1, 2);
    }
}
