//! Оркестрация движка: подтверждение запуска по его выводу и правила
//! обращения со службой драйвера WinDivert.
//!
//! Порт чистых частей `winws_runtime/engine/startup.py`,
//! `winws_runtime/engine/driver.py` и `winws_runtime/engine/process_control.py`.
//! Реальные обращения к WinAPI (хэндлы процессов и служб) идут через трейты
//! [`EngineWait`] и [`DriverServiceApi`], а здесь остаются решения: когда
//! запуск считается подтверждённым, когда служба драйвера мешает запуску и
//! что именно мешает, по каким путям отличают свой драйвер от чужого.
//!
//! Принципы python-модулей сохранены: подтверждение запуска — строка
//! `windivert initialized` из вывода самого движка (а не «процесс прожил
//! секунду»), слой драйвера никогда не правит реестр и не снимает пометку
//! удаления, а только спрашивает состояние и честно сообщает, что мешает.

use std::collections::HashMap;
use std::sync::OnceLock;

// --- process_control: имена сигналов и константы остановки -------------------

/// Код завершения при жёсткой остановке (python `ENGINE_KILL_EXIT_CODE`).
///
/// Отличен от кода 1 молчаливого падения winws: принудительная остановка не
/// должна быть неотличима от сбоя.
pub const ENGINE_KILL_EXIT_CODE: i64 = 0x5A50;

/// Префикс управляющих событий движка: `Global\<префикс>_<pid>_<вид>`.
///
/// Префикс один и тот же у winws.exe и winws2.exe.
pub const ENGINE_SIGNAL_PREFIX: &str = "winws2_sig";
/// Сигнал «завершись сам».
pub const ENGINE_SIGNAL_TERM: &str = "term";
/// Сигнал «перечитай файлы списков».
pub const ENGINE_SIGNAL_HUP: &str = "hup";

/// Сколько ждём выхода движка после сигнала «term» (python
/// `ENGINE_GRACEFUL_STOP_SECONDS`).
pub const ENGINE_GRACEFUL_STOP_SECONDS: f64 = 2.0;

/// Имя управляющего события движка с данным номером процесса.
#[must_use]
pub fn engine_signal_name(pid: u32, kind: &str) -> String {
    format!("Global\\{ENGINE_SIGNAL_PREFIX}_{pid}_{kind}")
}

// --- общие помощники путей (поведение os.path с учётом платформы) ------------

/// `os.path.normcase`: на Windows — нижний регистр и «\», на остальных — как есть.
#[must_use]
pub fn normcase(path: &str) -> String {
    if cfg!(windows) {
        path.to_lowercase().replace('/', "\\")
    } else {
        path.to_string()
    }
}

/// `os.path.isabs` с учётом платформы; windows-пути распознаются всегда
/// (как `_is_windows_abs` из zapret2_runner.py).
#[must_use]
pub fn path_is_abs(path: &str) -> bool {
    if cfg!(windows) {
        // ntpath.isabs: UNC-путь или диск с корнем.
        let bytes = path.as_bytes();
        if bytes.starts_with(b"\\\\") {
            return true;
        }
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            return true;
        }
    } else if path.starts_with('/') {
        return true;
    }
    is_windows_abs(path)
}

/// `zapret2_runner._WINDOWS_ABS_RE`: распознаёт windows-абсолютные пути
/// даже на не-Windows системах разработки.
#[must_use]
pub fn is_windows_abs(path: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // ^(?:[A-Za-z]:[\\/]|\\\\)
        regex::Regex::new("^(?:[A-Za-z]:[/\\\\]|\\\\\\\\)").expect("статический regex")
    });
    re.is_match(path)
}

/// `os.path.join` для двух частей с учётом платформы.
#[must_use]
pub fn join_paths(base: &str, tail: &str) -> String {
    let sep = if cfg!(windows) { '\\' } else { '/' };
    if path_is_abs(tail) {
        return tail.to_string();
    }
    if base.is_empty() {
        return tail.to_string();
    }
    if base.ends_with(sep) || (cfg!(windows) && base.ends_with(':')) {
        format!("{base}{tail}")
    } else {
        format!("{base}{sep}{tail}")
    }
}

/// `os.path.normpath` с учётом платформы.
///
/// На не-Windows (среда тестов) повторяет posix-алгоритм: `\` остаётся
/// обычным символом, как в python на Linux. На Windows повторяет ntpath:
/// разделители приводятся к «\», повторные сворачиваются, «.» и «..»
/// разрешаются с учётом диска и UNC.
#[must_use]
pub fn normpath(path: &str) -> String {
    if cfg!(windows) {
        normpath_windows(path)
    } else {
        normpath_posix(path)
    }
}

fn normpath_posix(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let leading = path.chars().take_while(|&c| c == '/').count();
    let initial_slashes = if leading >= 2 { 2 } else { leading.min(1) };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp == ".." {
            if let Some(last) = comps.last() {
                if *last != ".." {
                    comps.pop();
                    continue;
                }
            }
            if initial_slashes == 0 {
                comps.push("..");
            }
        } else if !comp.is_empty() && comp != "." {
            comps.push(comp);
        }
    }
    if comps.is_empty() {
        if initial_slashes > 0 {
            return "/".repeat(initial_slashes);
        }
        return ".".to_string();
    }
    let mut result = "/".repeat(initial_slashes);
    result.push_str(&comps.join("/"));
    result
}

fn normpath_windows(path: &str) -> String {
    let text = path.replace('/', "\\");
    if text.is_empty() {
        return ".".to_string();
    }
    // Префиксы device-путей сохраняются дословно (ntpath их не разбирает).
    for prefix in ["\\\\?\\", "\\??\\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return format!("{prefix}{rest}");
        }
    }

    // Префикс: UNC \\server\share либо диск «C:\».
    let mut prefix = String::new();
    let mut body = text.as_str();
    if body.starts_with("\\\\") {
        let trimmed = &body[2..];
        let mut parts = trimmed.splitn(2, '\\');
        let server = parts.next().unwrap_or("");
        let remainder = parts.next().unwrap_or("");
        if remainder.is_empty() {
            return format!("\\\\{server}");
        }
        let mut share_parts = remainder.splitn(2, '\\');
        let share = share_parts.next().unwrap_or("");
        prefix = format!("\\\\{server}\\{share}");
        body = share_parts.next().unwrap_or("");
    } else {
        let bytes = body.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            prefix = body[..2].to_string();
            body = &body[2..];
            if let Some(rest) = body.strip_prefix('\\') {
                prefix.push('\\');
                body = rest;
            }
        }
    }
    let absolute = !prefix.is_empty() || body.starts_with('\\');

    let mut comps: Vec<&str> = Vec::new();
    for comp in body.split('\\') {
        if comp == ".." {
            if let Some(last) = comps.last() {
                if *last != ".." {
                    comps.pop();
                    continue;
                }
            }
            if !absolute {
                comps.push("..");
            }
        } else if !comp.is_empty() && comp != "." {
            comps.push(comp);
        }
    }

    let prefix_empty = prefix.is_empty();
    let mut result = prefix;
    if prefix_empty && absolute {
        result.push('\\');
    }
    if !comps.is_empty() {
        if !result.is_empty() && !result.ends_with('\\') && !result.ends_with(':') {
            result.push('\\');
        }
        result.push_str(&comps.join("\\"));
    }
    if result.is_empty() {
        return ".".to_string();
    }
    result
}

/// `os.path.abspath`: относительный путь достраивается до текущего каталога.
#[must_use]
pub fn absolute_path(path: &str) -> String {
    if path_is_abs(path) {
        return path.to_string();
    }
    match std::env::current_dir() {
        Ok(cwd) => join_paths(&cwd.to_string_lossy(), path),
        Err(_) => path.to_string(),
    }
}

/// Путь к exe в виде, пригодном для сравнения (python `normalize_image_path`).
#[must_use]
pub fn normalize_image_path(path: &str) -> String {
    let mut text = path.trim().to_string();
    if text.is_empty() {
        return String::new();
    }
    if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
        text = format!("\\\\{rest}");
    } else if let Some(rest) = text.strip_prefix("\\\\?\\") {
        text = rest.to_string();
    } else if let Some(rest) = text.strip_prefix("\\??\\UNC\\") {
        text = format!("\\\\{rest}");
    } else if let Some(rest) = text.strip_prefix("\\??\\") {
        text = rest.to_string();
    }
    text = absolute_path(&text);
    normcase(&text)
}

// --- startup.py: подтверждение запуска по выводу движка ----------------------

/// Строка готовности, которую печатают winws и winws2 (python `READY_MARKER`).
pub const READY_MARKER: &[u8] = b"windivert initialized";

/// Окно после строки готовности, в котором проявляются ошибки Lua-скриптов.
pub const DEFAULT_SETTLE_SECONDS: f64 = 0.35;
/// Сколько ждать строку готовности (большие списки грузятся до драйвера).
pub const DEFAULT_READY_TIMEOUT_SECONDS: f64 = 15.0;
/// Окно для запуска без файла вывода: подтвердить готовность нечем.
pub const DEFAULT_ALIVE_WINDOW_SECONDS: f64 = 1.0;
/// Тик ожидания файла вывода между ожиданиями на хэндле процесса.
const TAIL_TICK_SECONDS: f64 = 0.01;

/// python `REASON_READY`.
pub const REASON_READY: &str = "ready";
/// python `REASON_ALIVE_WITHOUT_MARKER`.
pub const REASON_ALIVE_WITHOUT_MARKER: &str = "alive_without_marker";
/// python `REASON_EXITED`.
pub const REASON_EXITED: &str = "exited";
/// python `REASON_EXITED_AFTER_READY`.
pub const REASON_EXITED_AFTER_READY: &str = "exited_after_ready";

/// Итог ожидания готовности движка (python `EngineStartOutcome`).
#[derive(Debug, Clone, PartialEq)]
pub struct EngineStartOutcome {
    pub started: bool,
    pub reason: &'static str,
    pub marker_seen: bool,
    pub elapsed: f64,
}

/// Ожидание выхода процесса с таймаутом (python `wait_process_exit`).
///
/// На Windows это ожидание на хэндле процесса: смерть процесса будит поток
/// сразу, без опроса. Реализация живёт вне крейта; в тестах — фейки.
pub trait EngineWait {
    /// `true` — выход подтверждён за отведённое время.
    fn wait_exit(&mut self, timeout_seconds: f64) -> bool;
}

/// Дочитывает новые байты файла вывода и ищет в них строку готовности
/// (python `_OutputTail`).
pub struct OutputTail {
    path: String,
    marker: Vec<u8>,
    offset: u64,
    carry: Vec<u8>,
}

impl OutputTail {
    #[must_use]
    pub fn new(path: &str, marker: &[u8]) -> Self {
        Self {
            path: path.to_string(),
            marker: marker.to_vec(),
            offset: 0,
            carry: Vec::new(),
        }
    }

    /// `true`, если строка готовности появилась в новых байтах файла.
    pub fn marker_appeared(&mut self) -> bool {
        if self.path.is_empty() {
            return false;
        }
        use std::io::{Read, Seek, SeekFrom};
        let mut chunk = Vec::new();
        match std::fs::File::open(&self.path) {
            Ok(mut file) => {
                if file.seek(SeekFrom::Start(self.offset)).is_err() {
                    return false;
                }
                if file.read_to_end(&mut chunk).is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
        if chunk.is_empty() {
            return false;
        }
        self.offset += chunk.len() as u64;
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(&chunk);
        if contains_subslice(&window, &self.marker) {
            return true;
        }
        // Строка может лечь на границу двух чтений — держим хвост.
        let keep = self.marker.len().saturating_sub(1);
        let start = window.len().saturating_sub(keep);
        self.carry = window[start..].to_vec();
        false
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Ждёт подтверждения, что движок запустился и не умер при инициализации
/// (python `wait_engine_ready`).
///
/// Логика python сохранена: без файла вывода остаётся только проверка, что
/// процесс не умер сразу; с файлом — строка готовности, затем окно `settle`
/// на ошибки Lua-скриптов. Ожидания идут через [`EngineWait`] — на Windows
/// это ожидание на хэндле процесса, смерть будит поток сразу.
#[must_use]
pub fn wait_engine_ready(
    process: &mut dyn EngineWait,
    output_path: &str,
    settle: f64,
    ready_timeout: f64,
    alive_window: f64,
    clock: &mut dyn FnMut() -> f64,
) -> EngineStartOutcome {
    let started_at = clock();
    let elapsed = |clock: &mut dyn FnMut() -> f64| (clock() - started_at).max(0.0);

    if output_path.is_empty() {
        if process.wait_exit(alive_window.max(0.0)) {
            return EngineStartOutcome {
                started: false,
                reason: REASON_EXITED,
                marker_seen: false,
                elapsed: elapsed(clock),
            };
        }
        return EngineStartOutcome {
            started: true,
            reason: REASON_ALIVE_WITHOUT_MARKER,
            marker_seen: false,
            elapsed: elapsed(clock),
        };
    }

    let mut tail = OutputTail::new(output_path, READY_MARKER);
    let deadline = started_at + ready_timeout.max(0.0);
    let mut marker_seen = false;
    loop {
        if tail.marker_appeared() {
            marker_seen = true;
            break;
        }
        if process.wait_exit(TAIL_TICK_SECONDS) {
            // Процесс мог напечатать строку и умереть между двумя чтениями.
            marker_seen = tail.marker_appeared();
            let reason = if marker_seen {
                REASON_EXITED_AFTER_READY
            } else {
                REASON_EXITED
            };
            return EngineStartOutcome {
                started: false,
                reason,
                marker_seen,
                elapsed: elapsed(clock),
            };
        }
        if clock() >= deadline {
            break;
        }
    }

    if !marker_seen {
        // Процесс жив, но строки нет: сборка без этой строки или очень долгая
        // загрузка списков. Не хуже прежнего правила «жив — значит запустился».
        return EngineStartOutcome {
            started: true,
            reason: REASON_ALIVE_WITHOUT_MARKER,
            marker_seen: false,
            elapsed: elapsed(clock),
        };
    }

    if process.wait_exit(settle.max(0.0)) {
        return EngineStartOutcome {
            started: false,
            reason: REASON_EXITED_AFTER_READY,
            marker_seen: true,
            elapsed: elapsed(clock),
        };
    }
    EngineStartOutcome {
        started: true,
        reason: REASON_READY,
        marker_seen: true,
        elapsed: elapsed(clock),
    }
}

// --- driver.py: служба драйвера WinDivert ------------------------------------

/// Имя службы драйвера нашей сборки.
pub const OWN_DRIVER_SERVICE_NAME: &str = "Monkey";
/// Имена службы драйвера: наша сборка и оригинальный WinDivert, которые могут
/// остаться от других программ.
pub const DRIVER_SERVICE_NAMES: [&str; 4] = ["Monkey", "WinDivert", "WinDivert14", "WinDivert64"];

/// Шаг переспрашивания состояния службы (python `_POLL_INTERVAL_SECONDS`).
pub const POLL_INTERVAL_SECONDS: f64 = 0.05;
/// Общий срок ожидания службы по умолчанию.
pub const DEFAULT_WAIT_SECONDS: f64 = 3.0;

/// python `BLOCKER_NONE` — запуску ничего не мешает.
pub const BLOCKER_NONE: &str = "";
/// python `BLOCKER_STOP_PENDING`.
pub const BLOCKER_STOP_PENDING: &str = "stop_pending";
/// python `BLOCKER_STUCK_ENTRY`.
pub const BLOCKER_STUCK_ENTRY: &str = "stuck_entry";

/// python `RELEASE_ABSENT`.
pub const RELEASE_ABSENT: &str = "absent";
/// python `RELEASE_RELEASED`.
pub const RELEASE_RELEASED: &str = "released";
/// python `RELEASE_SKIPPED_IN_USE`.
pub const RELEASE_SKIPPED_IN_USE: &str = "skipped_in_use";
/// python `RELEASE_SKIPPED_ANTIVIRUS`.
pub const RELEASE_SKIPPED_ANTIVIRUS: &str = "skipped_antivirus";
/// python `RELEASE_STUCK_STOP_PENDING`.
pub const RELEASE_STUCK_STOP_PENDING: &str = "stuck_stop_pending";
/// python `RELEASE_STUCK_ENTRY`.
pub const RELEASE_STUCK_ENTRY: &str = "stuck_entry";
/// python `RELEASE_ERROR`.
pub const RELEASE_ERROR: &str = "error";

/// python `MESSAGE_STOP_PENDING` (шаблон с `{name}`).
pub const MESSAGE_STOP_PENDING: &str = "Драйвер WinDivert ({name}) выгружается, но его ещё держит другая программа. Закройте другие программы обхода блокировок и повторите запуск; если не поможет — перезагрузите компьютер";
/// python `MESSAGE_STUCK_ENTRY` (шаблон с `{name}`).
pub const MESSAGE_STUCK_ENTRY: &str = "Запись службы драйвера WinDivert ({name}) осталась после остановки: её держит открытой другая программа (окно «Службы», Process Hacker, Process Explorer или антивирус). Закройте её и повторите запуск; если не поможет — перезагрузите компьютер";

/// Состояния службы Windows (python `winapi.SERVICE_*`).
pub mod service_state {
    pub const SERVICE_STOPPED: u32 = 0x0000_0001;
    pub const SERVICE_START_PENDING: u32 = 0x0000_0002;
    pub const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
    pub const SERVICE_RUNNING: u32 = 0x0000_0004;
}

/// Типы запуска службы Windows (python `winapi.SERVICE_*_START`).
pub mod service_start_type {
    pub const SERVICE_BOOT_START: u32 = 0x0000_0000;
    pub const SERVICE_SYSTEM_START: u32 = 0x0000_0001;
    pub const SERVICE_AUTO_START: u32 = 0x0000_0002;
    pub const SERVICE_DEMAND_START: u32 = 0x0000_0003;
    pub const SERVICE_DISABLED: u32 = 0x0000_0004;
}

/// Запись службы диспетчера служб Windows (python `winapi.ServiceInfo`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub state: u32,
    pub start_type: u32,
    pub image_path: String,
}

impl ServiceInfo {
    #[must_use]
    pub fn new(name: &str, state: u32, start_type: u32, image_path: &str) -> Self {
        Self {
            name: name.to_string(),
            state,
            start_type,
            image_path: image_path.to_string(),
        }
    }
}

/// Доступ к диспетчеру служб Windows (те `winapi`-функции, которые использует
/// driver.py). Реализация живёт вне крейта; в тестах — фейки.
pub trait DriverServiceApi {
    /// python `winapi.query_service`: `Ok(None)` — записи нет.
    fn query_service(&self, name: &str) -> Result<Option<ServiceInfo>, String>;
    /// python `winapi.send_service_stop`: возвращает следующее состояние.
    fn send_service_stop(&self, name: &str) -> Result<Option<u32>, String>;
    /// python `winapi.delete_service`.
    fn delete_service(&self, name: &str) -> Result<bool, String>;
}

/// Можно ли сейчас запускать движок с точки зрения службы драйвера
/// (python `DriverPreflight`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DriverPreflight {
    pub ok: bool,
    pub blocker: String,
    pub service: String,
    pub message: String,
}

impl DriverPreflight {
    /// Успешная проверка (python `DriverPreflight(ok=True)`).
    #[must_use]
    pub fn ok_now() -> Self {
        Self {
            ok: true,
            blocker: BLOCKER_NONE.to_string(),
            service: String::new(),
            message: String::new(),
        }
    }
}

/// Итог выгрузки драйвера (python `DriverReleaseResult`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DriverReleaseResult {
    pub outcome: String,
    pub service: String,
    pub message: String,
}

impl DriverReleaseResult {
    #[must_use]
    pub fn new(outcome: &str) -> Self {
        Self {
            outcome: outcome.to_string(),
            service: String::new(),
            message: String::new(),
        }
    }

    #[must_use]
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = service.to_string();
        self
    }

    #[must_use]
    pub fn with_message(mut self, message: &str) -> Self {
        self.message = message.to_string();
        self
    }

    /// Зависла ли остановка службы (python-свойство `stuck`).
    #[must_use]
    pub fn stuck(&self) -> bool {
        self.outcome == RELEASE_STUCK_STOP_PENDING || self.outcome == RELEASE_STUCK_ENTRY
    }
}

/// Путь к файлу драйвера из записи службы в обычном виде
/// (python `normalize_driver_image_path`).
///
/// Пути из диспетчера служб всегда с «\»; на тестовых POSIX-системах они
/// приводятся к «/» явно — как в python через `os.sep`.
#[must_use]
pub fn normalize_driver_image_path(image_path: &str) -> String {
    let mut text = image_path.trim().trim_matches('"').to_string();
    for prefix in ["\\??\\", "\\\\?\\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.to_string();
            break;
        }
    }
    if text.is_empty() {
        return String::new();
    }
    if cfg!(windows) {
        normpath(&text).to_lowercase()
    } else {
        normpath(&text.replace('\\', "/")).to_lowercase()
    }
}

/// Лежит ли файл драйвера в одной из папок нашей установки
/// (python `is_own_driver`).
#[must_use]
pub fn is_own_driver(image_path: &str, own_roots: &[&str]) -> bool {
    let driver_path = normalize_driver_image_path(image_path);
    if driver_path.is_empty() {
        return false;
    }
    let sep = if cfg!(windows) { '\\' } else { '/' };
    for root in own_roots {
        let normalized_root = normalize_root(root);
        if normalized_root.is_empty() {
            continue;
        }
        if driver_path == normalized_root
            || driver_path.starts_with(&format!("{normalized_root}{sep}"))
        {
            return true;
        }
    }
    false
}

fn normalize_root(root: &str) -> String {
    let text = root.trim();
    if text.is_empty() {
        return String::new();
    }
    if cfg!(windows) {
        normpath(text).to_lowercase()
    } else {
        normpath(&text.replace('\\', "/")).to_lowercase()
    }
}

/// Относится ли запись к драйверу, которым пользуется наш движок
/// (python `_is_relevant`).
///
/// Наша сборка WinDivert называет службу Monkey: запись с этим именем наша
/// при любом пути к файлу. Записи оригинального WinDivert принадлежат другим
/// программам, пока их файл не лежит в нашей папке.
#[must_use]
pub fn driver_service_is_relevant(info: &ServiceInfo, own_roots: &[String]) -> bool {
    let roots: Vec<&str> = own_roots.iter().map(String::as_str).collect();
    info.name == OWN_DRIVER_SERVICE_NAME || is_own_driver(&info.image_path, &roots)
}

/// Записи службы драйвера, относящиеся к нашему движку
/// (python `list_driver_services`).
pub fn list_driver_services(
    api: &dyn DriverServiceApi,
    own_roots: &[String],
) -> Result<Vec<ServiceInfo>, String> {
    let roots: Vec<String> = own_roots
        .iter()
        .map(String::as_str)
        .filter(|root| !root.trim().is_empty())
        .map(str::to_string)
        .collect();
    let mut services = Vec::new();
    for name in DRIVER_SERVICE_NAMES {
        let info = api.query_service(name)?;
        if let Some(info) = info {
            if driver_service_is_relevant(&info, &roots) {
                services.push(info);
            }
        }
    }
    Ok(services)
}

/// Остановленная запись, помеченная на удаление: ждёт закрытия хэндлов
/// (python `_is_marked_leftover`).
#[must_use]
pub fn service_is_marked_leftover(info: &ServiceInfo) -> bool {
    info.state == service_state::SERVICE_STOPPED
        && info.start_type == service_start_type::SERVICE_DISABLED
}

/// Запись не мешает запуску: winws либо откроет драйвер, либо запустит его
/// (python `_is_startable_as_is`).
#[must_use]
pub fn service_is_startable_as_is(info: &ServiceInfo) -> bool {
    if info.state == service_state::SERVICE_RUNNING
        || info.state == service_state::SERVICE_START_PENDING
    {
        return true;
    }
    if info.state == service_state::SERVICE_STOPPED {
        // Остановленная запись с обычным типом запуска — winws запустит её сам.
        // Остановленная и отключённая — та самая застрявшая запись.
        return !service_is_marked_leftover(info);
    }
    false
}

/// Ждёт, пока состояние службы не станет нужным (python `_wait_until`).
///
/// Состояние переспрашивается короткими шагами до общего срока: каждый запрос
/// открывает и сразу закрывает хэндл службы, и этого достаточно, чтобы Windows
/// убрала запись, которую больше никто не держит.
fn wait_until(
    mut predicate: impl FnMut() -> bool,
    wait_seconds: f64,
    clock: &mut dyn FnMut() -> f64,
    sleep: &mut dyn FnMut(f64),
) -> bool {
    let deadline = clock() + wait_seconds.max(0.0);
    loop {
        if predicate() {
            return true;
        }
        if clock() >= deadline {
            return false;
        }
        sleep(POLL_INTERVAL_SECONDS);
    }
}

/// Срок вышел, а служба всё ещё мешает: имя службы, блокер и готовое сообщение.
fn blocked_preflight(info: &ServiceInfo) -> DriverPreflight {
    let (blocker, template) = if info.state == service_state::SERVICE_STOP_PENDING {
        (BLOCKER_STOP_PENDING, MESSAGE_STOP_PENDING)
    } else {
        (BLOCKER_STUCK_ENTRY, MESSAGE_STUCK_ENTRY)
    };
    DriverPreflight {
        ok: false,
        blocker: blocker.to_string(),
        service: info.name.clone(),
        message: template.replace("{name}", &info.name),
    }
}

/// Проверяет перед запуском, что служба драйвера не застряла
/// (python `ensure_driver_startable`).
///
/// Только чтение: ничего не останавливает и не правит. Если драйвер как раз
/// выгружается, даёт ему до `wait_seconds` закончить. Сбой запроса не мешает
/// запуску: причину отказа, если она есть, назовёт сам winws в своём выводе.
#[must_use]
pub fn ensure_driver_startable(
    api: &dyn DriverServiceApi,
    own_roots: &[String],
    wait_seconds: f64,
    clock: &mut dyn FnMut() -> f64,
    sleep: &mut dyn FnMut(f64),
) -> DriverPreflight {
    let roots: Vec<String> = own_roots
        .iter()
        .map(String::as_str)
        .filter(|root| !root.trim().is_empty())
        .map(str::to_string)
        .collect();

    // Ошибка запроса службы трактуется как «не мешает»: см. rustdoc выше.
    let mut blocked: Vec<ServiceInfo> = Vec::new();
    let settled = wait_until(
        || {
            blocked.clear();
            let services = match list_driver_services(api, &roots) {
                Ok(services) => services,
                Err(_) => return true,
            };
            for info in &services {
                if !service_is_startable_as_is(info) {
                    blocked.push(info.clone());
                }
            }
            blocked.is_empty()
        },
        wait_seconds,
        clock,
        sleep,
    );
    if settled {
        return DriverPreflight::ok_now();
    }

    match blocked.into_iter().next() {
        Some(info) => blocked_preflight(&info),
        None => DriverPreflight::ok_now(),
    }
}

/// Выгружает драйвер и убирает его службу, если им никто не пользуется
/// (python `release_driver_if_unused`).
///
/// Драйвер не трогается, пока жив хотя бы один winws (свой или чужой) или
/// пока антивирус с фильтрами делает выгрузку опасной. Записи оригинального
/// WinDivert, чей файл лежит не в нашей папке, сюда не попадают вовсе.
pub fn release_driver_if_unused(
    api: &dyn DriverServiceApi,
    own_roots: &[String],
    engine_in_use: &mut dyn FnMut() -> Result<bool, String>,
    antivirus_blocks_unload: Option<&mut dyn FnMut() -> Result<bool, String>>,
    wait_seconds: f64,
    clock: &mut dyn FnMut() -> f64,
    sleep: &mut dyn FnMut(f64),
) -> DriverReleaseResult {
    let roots: Vec<String> = own_roots
        .iter()
        .map(String::as_str)
        .filter(|root| !root.trim().is_empty())
        .map(str::to_string)
        .collect();

    let services = match list_driver_services(api, &roots) {
        Ok(services) => services,
        Err(error) => return DriverReleaseResult::new(RELEASE_ERROR).with_message(&error),
    };
    if services.is_empty() {
        return DriverReleaseResult::new(RELEASE_ABSENT);
    }

    // Не знаем, пользуются ли драйвером, — значит, не трогаем.
    let in_use = engine_in_use().unwrap_or(true);
    if in_use {
        return DriverReleaseResult::new(RELEASE_SKIPPED_IN_USE).with_service(&services[0].name);
    }

    if let Some(antivirus) = antivirus_blocks_unload {
        // Сбой определения антивируса трактуем в безопасную сторону.
        let blocked = antivirus().unwrap_or(true);
        if blocked {
            return DriverReleaseResult::new(RELEASE_SKIPPED_ANTIVIRUS)
                .with_service(&services[0].name);
        }
    }

    let mut result = DriverReleaseResult::new(RELEASE_ABSENT);
    for info in &services {
        let outcome = release_one_service(api, info, wait_seconds, clock, sleep);
        if outcome.stuck() || outcome.outcome == RELEASE_ERROR {
            return outcome;
        }
        if outcome.outcome == RELEASE_RELEASED || result.outcome == RELEASE_ABSENT {
            result = outcome;
        }
    }
    result
}

/// python `_release_one`: выгрузка одной записи службы с ожиданием её
/// исчезновения. Сбой запроса — [`RELEASE_ERROR`], а не «службы нет».
fn release_one_service(
    api: &dyn DriverServiceApi,
    info: &ServiceInfo,
    wait_seconds: f64,
    clock: &mut dyn FnMut() -> f64,
    sleep: &mut dyn FnMut(f64),
) -> DriverReleaseResult {
    let name = info.name.clone();

    if info.state == service_state::SERVICE_RUNNING {
        // Библиотека WinDivert уже пометила запись на удаление при запуске
        // драйвера: после остановки диспетчер служб уберёт её сам.
        if let Err(error) = api.send_service_stop(&name) {
            return DriverReleaseResult::new(RELEASE_ERROR)
                .with_service(&name)
                .with_message(&error);
        }
    } else if info.state == service_state::SERVICE_STOPPED && !service_is_marked_leftover(info) {
        // Остановленная запись без пометки — остаток от прошлых версий
        // программы или от перезагрузки. Убираем штатным вызовом.
        if let Err(error) = api.delete_service(&name) {
            return DriverReleaseResult::new(RELEASE_ERROR)
                .with_service(&name)
                .with_message(&error);
        }
    }
    // Иначе запись уже останавливается или ждёт удаления: остаётся дождаться,
    // пока Windows уберёт её сама.

    let mut last_info: Option<ServiceInfo>;
    let mut gone = false;
    let deadline = clock() + wait_seconds.max(0.0);
    loop {
        match api.query_service(&name) {
            Ok(query) => last_info = query,
            Err(error) => {
                return DriverReleaseResult::new(RELEASE_ERROR)
                    .with_service(&name)
                    .with_message(&error);
            }
        }
        if last_info.is_none() {
            gone = true;
            break;
        }
        if clock() >= deadline {
            break;
        }
        sleep(POLL_INTERVAL_SECONDS);
    }

    if gone {
        return DriverReleaseResult::new(RELEASE_RELEASED).with_service(&name);
    }

    let state = last_info.map(|info| info.state);
    if state == Some(service_state::SERVICE_STOP_PENDING) {
        return DriverReleaseResult::new(RELEASE_STUCK_STOP_PENDING)
            .with_service(&name)
            .with_message(&MESSAGE_STOP_PENDING.replace("{name}", &name));
    }
    DriverReleaseResult::new(RELEASE_STUCK_ENTRY)
        .with_service(&name)
        .with_message(&MESSAGE_STUCK_ENTRY.replace("{name}", &name))
}

// --- process_control: итог остановки своих процессов движка ------------------

/// Процесс движка из снимка системы (python `EngineProcessRecord`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EngineProcessRecord {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Итог остановки своих процессов движка (python `EngineStopResult`).
///
/// `stopped` — выход подтверждён; `failed` — процесс наш, но не вышел за
/// отведённое время или не дал себя завершить; `foreign` — winws из другой
/// папки, мы его не трогали. Сборка снимка процессов и хэндлы WinAPI остаются
/// вне крейта.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EngineStopResult {
    pub stopped: Vec<u32>,
    pub failed: Vec<u32>,
    pub foreign: Vec<EngineProcessRecord>,
    pub snapshot_failed: bool,
}

impl EngineStopResult {
    /// `true`, если никто не остался жить (python-свойство `ok`).
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed.is_empty() && !self.snapshot_failed
    }
}

/// Сопоставление «имя exe → нормализованный путь» для своих процессов
/// (python `_expected_by_name`).
///
/// Разделитель разбираем сами: путь Windows должен читаться одинаково и на
/// Windows, и в тестах на другой системе.
#[must_use]
pub fn expected_by_name(expected_paths: &[&str]) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for path in expected_paths {
        let normalized = normalize_image_path(path);
        if normalized.is_empty() {
            continue;
        }
        let name = normalized
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if !name.is_empty() {
            result.insert(name, normalized);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    // --- нормализация путей ---------------------------------------------------

    #[test]
    fn windows_abs_paths_recognized_everywhere() {
        // Сверено с python: _WINDOWS_ABS_RE ловит диск и UNC на любой системе.
        assert!(is_windows_abs("C:\\x"));
        assert!(is_windows_abs("c:/x"));
        assert!(is_windows_abs("\\\\server\\share"));
        assert!(!is_windows_abs("relative/x"));
        assert!(!is_windows_abs(""));
    }

    #[test]
    fn normpath_collapses_separators_and_dots() {
        // Сверено с python os.path.normpath (posix, среда тестов).
        assert_eq!(normpath("C:/Zapret/Dev"), "C:/Zapret/Dev");
        assert_eq!(normpath("a//b///c"), "a/b/c");
        assert_eq!(normpath("a/./b"), "a/b");
        assert_eq!(normpath("../a/./b/../c"), "../a/c");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath("/"), "/");
        assert_eq!(normpath("//"), "//");
    }

    #[test]
    fn join_paths_appends_relative_tail() {
        assert_eq!(join_paths("/root", "lists/x.txt"), "/root/lists/x.txt");
        assert_eq!(join_paths("/root", "/abs"), "/abs");
        assert_eq!(join_paths("", "x"), "x");
    }

    #[test]
    fn signal_names_use_the_same_prefix_for_both_engines() {
        assert_eq!(
            engine_signal_name(4321, "term"),
            r"Global\winws2_sig_4321_term"
        );
        assert_eq!(engine_signal_name(7, "hup"), r"Global\winws2_sig_7_hup");
    }

    #[test]
    fn expected_by_name_matches_lowercase_basenames() {
        let map = expected_by_name(&[r"C:\Zapret\exe\Winws2.EXE", ""]);
        assert_eq!(
            map.get("winws2.exe").map(String::as_str),
            Some(r"C:\Zapret\exe\Winws2.EXE")
        );
        assert_eq!(map.len(), 1);
    }

    // --- startup.py: ожидание готовности ---------------------------------------

    struct FakeProcess {
        wait_timeouts: Vec<f64>,
        exits_after_waits: usize,
        on_wait: Option<Box<dyn FnMut()>>,
        waited: usize,
    }

    impl FakeProcess {
        fn new() -> Self {
            Self {
                wait_timeouts: Vec::new(),
                exits_after_waits: 0,
                on_wait: None,
                waited: 0,
            }
        }
    }

    impl EngineWait for FakeProcess {
        fn wait_exit(&mut self, timeout_seconds: f64) -> bool {
            self.wait_timeouts.push(timeout_seconds);
            self.waited += 1;
            if let Some(on_wait) = self.on_wait.as_mut() {
                on_wait();
            }
            if self.exits_after_waits > 0 && self.waited >= self.exits_after_waits {
                return true;
            }
            false
        }
    }

    fn write_file(path: &str, text: &str) {
        std::fs::write(path, text).expect("запись файла вывода");
    }

    fn tmpdir(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("primecore_ws_engine_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог");
        dir.to_string_lossy().to_string()
    }

    #[test]
    fn ready_line_confirms_start() {
        let dir = tmpdir("ready");
        let output_path = format!("{dir}/startup.log");
        write_file(
            &output_path,
            "github version v1\nwindivert initialized. capture is started.\n",
        );
        let mut process = FakeProcess::new();

        let outcome = wait_engine_ready(&mut process, &output_path, 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(outcome.started);
        assert_eq!(outcome.reason, REASON_READY);
        assert!(outcome.marker_seen);
        // После строки готовности — одно окно на ошибки Lua-скриптов.
        assert_eq!(process.wait_timeouts, vec![0.35]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn death_before_ready_line_is_a_failed_start() {
        let dir = tmpdir("death_before");
        let output_path = format!("{dir}/startup.log");
        write_file(
            &output_path,
            "github version v1\nwindivert: error opening filter: access denied\n",
        );
        let mut process = FakeProcess::new();
        process.exits_after_waits = 1;

        let outcome = wait_engine_ready(&mut process, &output_path, 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(!outcome.started);
        assert_eq!(outcome.reason, REASON_EXITED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn death_right_after_ready_line_is_a_failed_start() {
        // Строка печатается до загрузки Lua: ошибка скрипта убивает процесс
        // уже после неё.
        let dir = tmpdir("death_after");
        let output_path = format!("{dir}/startup.log");
        write_file(
            &output_path,
            "windivert initialized. capture is started.\nLUA ERROR: boom\n",
        );
        let mut process = FakeProcess::new();
        process.exits_after_waits = 1;

        let outcome = wait_engine_ready(&mut process, &output_path, 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(!outcome.started);
        assert_eq!(outcome.reason, REASON_EXITED_AFTER_READY);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ready_line_split_across_reads_is_found() {
        let dir = tmpdir("split");
        let output_path = format!("{dir}/startup.log");
        write_file(&output_path, "github version v1\nwindivert initi");
        let path_for_hook = output_path.clone();
        let mut process = FakeProcess::new();
        process.on_wait = Some(Box::new(move || {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path_for_hook)
                .expect("файл");
            file.write_all(b"alized. capture is started.\n")
                .expect("дополнение");
        }));

        let outcome = wait_engine_ready(&mut process, &output_path, 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(outcome.started);
        assert_eq!(outcome.reason, REASON_READY);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alive_engine_without_ready_line_is_accepted_after_timeout() {
        // Не хуже прежнего правила «жив — значит запустился», но с пометкой.
        let dir = tmpdir("alive");
        let output_path = format!("{dir}/startup.log");
        write_file(&output_path, "github version v1\n");
        let mut process = FakeProcess::new();
        let ticks = RefCell::new(0.0f64);

        let outcome = wait_engine_ready(&mut process, &output_path, 0.35, 5.0, 1.0, &mut || {
            *ticks.borrow_mut() += 1.0;
            *ticks.borrow()
        });

        assert!(outcome.started);
        assert_eq!(outcome.reason, REASON_ALIVE_WITHOUT_MARKER);
        assert!(!outcome.marker_seen);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_output_file_only_survival_is_checked() {
        let mut process = FakeProcess::new();

        let outcome = wait_engine_ready(&mut process, "", 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(outcome.started);
        assert_eq!(outcome.reason, REASON_ALIVE_WITHOUT_MARKER);
        assert_eq!(process.wait_timeouts, vec![1.0]);
    }

    #[test]
    fn without_output_file_death_is_a_failed_start() {
        let mut process = FakeProcess::new();
        process.exits_after_waits = 1;

        let outcome = wait_engine_ready(&mut process, "", 0.35, 15.0, 1.0, &mut || 0.0);

        assert!(!outcome.started);
        assert_eq!(outcome.reason, REASON_EXITED);
    }

    // --- driver.py: служба драйвера --------------------------------------------

    const OWN_ROOT: &str = r"C:\Zapret\Dev";
    const OWN_DRIVER: &str = r"\??\C:\Zapret\Dev\exe\Monkey64.sys";
    const FOREIGN_DRIVER: &str = r"\??\C:\Other\zapret\exe\Monkey64.sys";

    /// python FakeClock: копит паузы и двигает время.
    #[derive(Clone)]
    struct SharedClock {
        now: Rc<Cell<f64>>,
        sleeps: Rc<RefCell<Vec<f64>>>,
    }

    impl SharedClock {
        fn new() -> Self {
            Self {
                now: Rc::new(Cell::new(0.0)),
                sleeps: Rc::new(RefCell::new(Vec::new())),
            }
        }
        fn clock(&self) -> f64 {
            self.now.get()
        }
        fn advance(&self, seconds: f64) {
            self.sleeps.borrow_mut().push(seconds);
            self.now.set(self.now.get() + seconds);
        }
        fn advance_fn(&self) -> impl FnMut(f64) {
            let this = self.clone();
            move |seconds| this.advance(seconds)
        }
        fn clock_fn(&self) -> impl FnMut() -> f64 {
            let this = self.clone();
            move || this.clock()
        }
    }

    /// Подделка диспетчера служб с поведением настоящего (python FakeScm).
    struct FakeScm {
        services: RefCell<BTreeMap<String, ServiceInfo>>,
        device_holder_alive: Cell<bool>,
        foreign_service_handle: Cell<bool>,
        stop_requests: RefCell<Vec<String>>,
        delete_requests: RefCell<Vec<String>>,
        query_error: Option<String>,
    }

    impl FakeScm {
        fn new() -> Self {
            Self {
                services: RefCell::new(BTreeMap::new()),
                device_holder_alive: Cell::new(false),
                foreign_service_handle: Cell::new(false),
                stop_requests: RefCell::new(Vec::new()),
                delete_requests: RefCell::new(Vec::new()),
                query_error: None,
            }
        }

        fn add(&self, name: &str, state: u32, start_type: u32, image_path: &str) {
            self.services.borrow_mut().insert(
                name.to_string(),
                ServiceInfo::new(name, state, start_type, image_path),
            );
        }

        /// Штатный вид работающего драйвера: отключён и помечен на удаление.
        fn add_running_driver(&self, name: &str, image_path: &str) {
            self.add(
                name,
                service_state::SERVICE_RUNNING,
                service_start_type::SERVICE_DISABLED,
                image_path,
            );
        }

        fn settle(&self, name: &str) {
            let mut services = self.services.borrow_mut();
            let Some(info) = services.get(name).cloned() else {
                return;
            };
            let mut info = info;
            if info.state == service_state::SERVICE_STOP_PENDING && !self.device_holder_alive.get()
            {
                info.state = service_state::SERVICE_STOPPED;
                services.insert(name.to_string(), info.clone());
            }
            let marked = info.start_type == service_start_type::SERVICE_DISABLED;
            if info.state == service_state::SERVICE_STOPPED
                && marked
                && !self.foreign_service_handle.get()
            {
                services.remove(name);
            }
        }
    }

    impl DriverServiceApi for FakeScm {
        fn query_service(&self, name: &str) -> Result<Option<ServiceInfo>, String> {
            if let Some(error) = &self.query_error {
                return Err(error.clone());
            }
            self.settle(name);
            Ok(self.services.borrow().get(name).cloned())
        }

        fn send_service_stop(&self, name: &str) -> Result<Option<u32>, String> {
            self.stop_requests.borrow_mut().push(name.to_string());
            let mut services = self.services.borrow_mut();
            let Some(info) = services.get(name).cloned() else {
                return Ok(None);
            };
            let next_state = if self.device_holder_alive.get() {
                service_state::SERVICE_STOP_PENDING
            } else {
                service_state::SERVICE_STOPPED
            };
            services.insert(
                name.to_string(),
                ServiceInfo::new(name, next_state, info.start_type, &info.image_path),
            );
            Ok(Some(next_state))
        }

        fn delete_service(&self, name: &str) -> Result<bool, String> {
            self.delete_requests.borrow_mut().push(name.to_string());
            let mut services = self.services.borrow_mut();
            let Some(info) = services.get(name).cloned() else {
                return Ok(false);
            };
            services.insert(
                name.to_string(),
                ServiceInfo::new(
                    name,
                    info.state,
                    service_start_type::SERVICE_DISABLED,
                    &info.image_path,
                ),
            );
            Ok(true)
        }
    }

    fn release_with(
        scm: &FakeScm,
        clock: &SharedClock,
        in_use: bool,
        antivirus: Option<&mut dyn FnMut() -> Result<bool, String>>,
        wait_seconds: f64,
        sleep: &mut dyn FnMut(f64),
    ) -> DriverReleaseResult {
        let mut clock_fn = clock.clock_fn();
        release_driver_if_unused(
            scm,
            &[OWN_ROOT.to_string()],
            &mut move || Ok(in_use),
            antivirus,
            wait_seconds,
            &mut clock_fn,
            sleep,
        )
    }

    fn preflight_with(
        scm: &FakeScm,
        clock: &SharedClock,
        wait_seconds: f64,
        sleep: &mut dyn FnMut(f64),
    ) -> DriverPreflight {
        let mut clock_fn = clock.clock_fn();
        ensure_driver_startable(
            scm,
            &[OWN_ROOT.to_string()],
            wait_seconds,
            &mut clock_fn,
            sleep,
        )
    }

    fn no_sleep(_seconds: f64) {}

    #[test]
    fn absent_service_is_normal() {
        let scm = FakeScm::new();
        let clock = SharedClock::new();
        let mut sleep = no_sleep;
        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);
        assert_eq!(result.outcome, RELEASE_ABSENT);
        assert!(scm.stop_requests.borrow().is_empty());
    }

    #[test]
    fn unused_driver_is_stopped_and_its_entry_disappears() {
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_RELEASED);
        assert_eq!(*scm.stop_requests.borrow(), vec!["Monkey".to_string()]);
        assert!(scm.services.borrow().get("Monkey").is_none());
        // Запись помечена на удаление самим WinDivert: удалять её не нужно.
        assert!(scm.delete_requests.borrow().is_empty());
        // Запись исчезла сразу — ждать было нечего.
        assert!(clock.sleeps.borrow().is_empty());
    }

    #[test]
    fn driver_in_use_is_never_stopped() {
        // Остановка при живом winws и создаёт зависшую службу.
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, true, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_SKIPPED_IN_USE);
        assert!(scm.stop_requests.borrow().is_empty());
        assert_eq!(
            scm.services.borrow()["Monkey"].state,
            service_state::SERVICE_RUNNING
        );
    }

    #[test]
    fn failed_in_use_check_counts_as_in_use() {
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_driver_if_unused(
            &scm,
            &[OWN_ROOT.to_string()],
            &mut || Err("snapshot failed".to_string()),
            None,
            3.0,
            &mut clock.clock_fn(),
            &mut sleep,
        );

        assert_eq!(result.outcome, RELEASE_SKIPPED_IN_USE);
        assert!(scm.stop_requests.borrow().is_empty());
    }

    #[test]
    fn antivirus_blocks_unload() {
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, Some(&mut || Ok(true)), 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_SKIPPED_ANTIVIRUS);
        assert!(scm.stop_requests.borrow().is_empty());
    }

    #[test]
    fn failed_antivirus_detection_blocks_unload() {
        // Сбой детекта трактуется в безопасную сторону: драйвер не выгружаем.
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(
            &scm,
            &clock,
            false,
            Some(&mut || Err("probe failed".to_string())),
            3.0,
            &mut sleep,
        );

        assert_eq!(result.outcome, RELEASE_SKIPPED_ANTIVIRUS);
        assert!(scm.stop_requests.borrow().is_empty());
    }

    #[test]
    fn stop_pending_is_reported_as_stuck_with_reason() {
        // Кто-то, кого мы не видим, держит устройство драйвера.
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        scm.device_holder_alive.set(true);
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();

        let result = release_with(&scm, &clock, false, None, 0.2, &mut sleep);

        assert_eq!(result.outcome, RELEASE_STUCK_STOP_PENDING);
        assert!(result.stuck());
        assert!(result.message.contains("Monkey"));
        assert_eq!(
            scm.services.borrow()["Monkey"].state,
            service_state::SERVICE_STOP_PENDING
        );
        // Ожидание ограничено сроком, а не длится вечно.
        let total: f64 = clock.sleeps.borrow().iter().sum();
        assert!(
            total <= 0.2 + POLL_INTERVAL_SECONDS + f64::EPSILON,
            "{total}"
        );
    }

    #[test]
    fn foreign_service_handle_is_reported_as_stuck_entry() {
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        scm.foreign_service_handle.set(true);
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();

        let result = release_with(&scm, &clock, false, None, 0.2, &mut sleep);

        assert_eq!(result.outcome, RELEASE_STUCK_ENTRY);
        assert!(result.stuck());
        assert!(result.message.contains("держит"));
        // Запись не «добивается» повторным удалением и правкой реестра.
        assert!(scm.delete_requests.borrow().is_empty());
    }

    #[test]
    fn plain_stopped_leftover_is_deleted_through_scm() {
        // Остановленная запись без пометки — остаток прошлых версий программы.
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOPPED,
            service_start_type::SERVICE_DEMAND_START,
            OWN_DRIVER,
        );
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_RELEASED);
        assert_eq!(*scm.delete_requests.borrow(), vec!["Monkey".to_string()]);
        assert!(scm.stop_requests.borrow().is_empty());
        assert!(scm.services.borrow().get("Monkey").is_none());
    }

    #[test]
    fn unused_monkey_driver_from_another_folder_is_released() {
        // Под именем Monkey работает и наш winws; неиспользуемый драйвер из
        // чужой папки выгружаем, чтобы следующий запуск поставил свой.
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", FOREIGN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_RELEASED);
    }

    #[test]
    fn original_windivert_of_another_program_is_never_touched() {
        let scm = FakeScm::new();
        scm.add(
            "WinDivert",
            service_state::SERVICE_RUNNING,
            service_start_type::SERVICE_DEMAND_START,
            r"\??\C:\GoodbyeDPI\x86_64\WinDivert64.sys",
        );
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_ABSENT);
        assert!(scm.stop_requests.borrow().is_empty());
        assert!(scm.delete_requests.borrow().is_empty());
        assert!(scm.services.borrow().get("WinDivert").is_some());
    }

    #[test]
    fn original_windivert_from_own_folder_is_ours() {
        let scm = FakeScm::new();
        scm.add(
            "WinDivert",
            service_state::SERVICE_RUNNING,
            service_start_type::SERVICE_DISABLED,
            r"\??\C:\Zapret\Dev\exe\WinDivert64.sys",
        );
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_RELEASED);
        assert_eq!(*scm.stop_requests.borrow(), vec!["WinDivert".to_string()]);
    }

    #[test]
    fn scm_failure_is_an_error_not_absence() {
        // «Не удалось узнать» нельзя принимать за «службы нет».
        let mut scm = FakeScm::new();
        scm.query_error = Some("OpenSCManagerW: 5".to_string());
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = release_with(&scm, &clock, false, None, 3.0, &mut sleep);

        assert_eq!(result.outcome, RELEASE_ERROR);
        assert!(!result.stuck());
    }

    #[test]
    fn absent_service_is_startable() {
        let scm = FakeScm::new();
        let clock = SharedClock::new();
        let mut sleep = no_sleep;
        assert!(preflight_with(&scm, &clock, 3.0, &mut sleep).ok);
    }

    #[test]
    fn running_disabled_marked_driver_is_the_normal_state() {
        // Именно это состояние прежний код принимал за поломку.
        let scm = FakeScm::new();
        scm.add_running_driver("Monkey", OWN_DRIVER);
        let clock = SharedClock::new();
        let mut sleep = no_sleep;

        let result = preflight_with(&scm, &clock, 3.0, &mut sleep);

        assert!(result.ok);
        assert!(clock.sleeps.borrow().is_empty());
        assert!(scm.stop_requests.borrow().is_empty());
    }

    #[test]
    fn plain_stopped_entry_is_startable() {
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOPPED,
            service_start_type::SERVICE_DEMAND_START,
            OWN_DRIVER,
        );
        let clock = SharedClock::new();
        let mut sleep = no_sleep;
        assert!(preflight_with(&scm, &clock, 3.0, &mut sleep).ok);
    }

    #[test]
    fn stop_pending_blocks_start_and_names_the_service() {
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOP_PENDING,
            service_start_type::SERVICE_DISABLED,
            OWN_DRIVER,
        );
        scm.device_holder_alive.set(true);
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();

        let result = preflight_with(&scm, &clock, 0.2, &mut sleep);

        assert!(!result.ok);
        assert_eq!(result.blocker, BLOCKER_STOP_PENDING);
        assert_eq!(result.service, "Monkey");
        assert!(result.message.contains("Monkey"));
    }

    #[test]
    fn stuck_entry_blocks_start() {
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOPPED,
            service_start_type::SERVICE_DISABLED,
            OWN_DRIVER,
        );
        scm.foreign_service_handle.set(true);
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();

        let result = preflight_with(&scm, &clock, 0.2, &mut sleep);

        assert!(!result.ok);
        assert_eq!(result.blocker, BLOCKER_STUCK_ENTRY);
    }

    #[test]
    fn unloading_driver_gets_time_to_finish() {
        // Драйвер как раз выгружается: первой проверки недостаточно, но после
        // одной паузы состояние устаканивается.
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOP_PENDING,
            service_start_type::SERVICE_DISABLED,
            OWN_DRIVER,
        );
        scm.device_holder_alive.set(true);
        let clock = SharedClock::new();
        let clock_for_sleep = clock.clone();
        let mut sleep = |seconds: f64| {
            clock_for_sleep.advance(seconds);
            scm.device_holder_alive.set(false);
        };

        let result = preflight_with(&scm, &clock, 3.0, &mut sleep);

        assert!(result.ok);
        assert_eq!(clock.sleeps.borrow().len(), 1);
    }

    #[test]
    fn preflight_never_changes_the_service() {
        let scm = FakeScm::new();
        scm.add(
            "Monkey",
            service_state::SERVICE_STOPPED,
            service_start_type::SERVICE_DISABLED,
            OWN_DRIVER,
        );
        scm.foreign_service_handle.set(true);
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();

        let _ = preflight_with(&scm, &clock, 0.2, &mut sleep);

        assert!(scm.stop_requests.borrow().is_empty());
        assert!(scm.delete_requests.borrow().is_empty());
    }

    #[test]
    fn foreign_windivert_entry_does_not_block_our_start() {
        let scm = FakeScm::new();
        scm.add(
            "WinDivert",
            service_state::SERVICE_STOP_PENDING,
            service_start_type::SERVICE_DEMAND_START,
            r"\??\C:\GoodbyeDPI\x86_64\WinDivert64.sys",
        );
        let clock = SharedClock::new();
        let mut sleep = clock.advance_fn();
        assert!(preflight_with(&scm, &clock, 0.2, &mut sleep).ok);
    }

    #[test]
    fn scm_failure_does_not_block_start() {
        // Причину отказа, если она есть, назовёт сам winws в своём выводе.
        let mut scm = FakeScm::new();
        scm.query_error = Some("OpenSCManagerW: 5".to_string());
        let clock = SharedClock::new();
        let mut sleep = no_sleep;
        assert!(preflight_with(&scm, &clock, 3.0, &mut sleep).ok);
    }

    #[test]
    fn image_path_prefix_and_case_are_normalised() {
        assert!(is_own_driver(
            r"\??\c:\zapret\dev\EXE\Monkey64.sys",
            &[OWN_ROOT]
        ));
        assert!(is_own_driver(
            r#""C:\Zapret\Dev\exe\Monkey64.sys""#,
            &[OWN_ROOT]
        ));
    }

    #[test]
    fn sibling_folder_is_not_own() {
        // C:\Zapret\Dev2 не должна считаться частью C:\Zapret\Dev.
        assert!(!is_own_driver(
            r"\??\C:\Zapret\Dev2\exe\Monkey64.sys",
            &[OWN_ROOT]
        ));
    }

    #[test]
    fn empty_path_is_not_own() {
        assert!(!is_own_driver("", &[OWN_ROOT]));
    }

    #[test]
    fn release_result_stuck_matches_python_property() {
        assert!(!DriverReleaseResult::new(RELEASE_ABSENT).stuck());
        assert!(DriverReleaseResult::new(RELEASE_STUCK_ENTRY).stuck());
        assert!(DriverReleaseResult::new(RELEASE_STUCK_STOP_PENDING).stuck());
    }

    #[test]
    fn kill_exit_code_differs_from_silent_crash_code() {
        // Мягко остановленный движок выходит с кодом 0; TerminateProcess
        // получает отдельный код, отличный от кода 1 молчаливого сбоя.
        assert_eq!(ENGINE_KILL_EXIT_CODE, 0x5A50);
        assert_ne!(ENGINE_KILL_EXIT_CODE, 1);
    }

    #[test]
    fn message_templates_contain_name_placeholder() {
        assert!(MESSAGE_STOP_PENDING.contains("{name}"));
        assert!(MESSAGE_STUCK_ENTRY.contains("{name}"));
        assert!(MESSAGE_STOP_PENDING
            .replace("{name}", "Monkey")
            .contains("Monkey"));
    }
}
