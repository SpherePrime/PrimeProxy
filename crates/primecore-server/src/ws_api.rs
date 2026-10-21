//! HTTP-ручки управления обходом nfqws2 (zapret2) для вкладки интерфейса:
//! каталог пресетов, запуск и остановка обхода, статус и общий журнал.
//!
//! Логика запуска уже собрана в [`primecore_ws::runner_nfqws2`] (стрип
//! Windows-only строк, подстановка маркеров листов, план запуска, текст
//! правил nftables); этот модуль только склеивает её с HTTP: хранит
//! состояние запущенного демона, применяет правила и порождает процесс
//! через [`PrivilegedExecutor`], а stdout/stderr демона складывает в
//! кольцевой буфер журнала.
//!
//! Привилегированные команды (nftables, запуск демона) — главная тонкость:
//! под root они идут напрямую, без root — через `pkexec`. Оба пути спрятаны
//! за трейтом [`PrivilegedExecutor`], в тестах подставляется фейк.

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::{FromRef, Query, State};
use axum::http::StatusCode;
use axum::Json;
use primecore_ws::runner_nfqws2::{
    nfqws2_launch_plan, nft_rules_text, strip_windows_only, substitute_hostlist_markers,
    HostlistFilterMode, HostlistSubstitution, Nfqws2LaunchPlan, Nfqws2NftFilters,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::App;

/// Ёмкость кольцевого буфера журнала.
const LOG_CAPACITY: usize = 2000;
/// Метка пакета nfqws2 (`NFQWS2_DESYNC_MARK`, та же в правилах nft).
const FWMARK: &str = "0x40000000";
/// Имя nft-таблицы обхода.
const NFT_TABLE: &str = "zapret2";
/// Очередь по умолчанию, если в запросе старта нет `qnum`.
const DEFAULT_QNUM: u32 = 300;
/// Порты TCP — эталонные `NFQWS2_PORTS_TCP` из `config.default`.
const TCP_PORTS: &str = "80,443";
/// Порты UDP — эталонные `NFQWS2_PORTS_UDP`.
const UDP_PORTS: &str = "443";
/// «Первые пакеты» — эталонные `NFQWS2_*_PKT_OUT/IN`.
const TCP_PKT_OUT: u32 = 20;
const TCP_PKT_IN: u32 = 10;
const UDP_PKT_OUT: u32 = 5;
const UDP_PKT_IN: u32 = 3;
/// Служебные подсети-исключения (как в example `nfqws2_plan`): локальный
/// трафик не должен попадать в очередь nfqws2.
const NOZAPRET4: [&str; 6] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];
const NOZAPRET6: [&str; 3] = ["::1/128", "fe80::/10", "fc00::/7"];

// ───────────────────────── состояние обхода ───────────────────────────

/// Кольцевой буфер журнала со сквозной нумерацией строк: номер растёт
/// навсегда, старые строки вытесняются по capacity.
pub struct RingBuffer {
    capacity: usize,
    /// Номер следующей строки (нумерация с 1).
    next_number: u64,
    lines: VecDeque<(u64, String)>,
}

impl RingBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_number: 1,
            lines: VecDeque::new(),
        }
    }

    /// Кладёт строку в буфер, выдавая ей очередной сквозной номер.
    pub fn push(&mut self, line: String) {
        let number = self.next_number;
        self.next_number += 1;
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back((number, line));
    }

    /// Строки с номером больше `after`, по возрастанию номеров.
    #[must_use]
    pub fn since(&self, after: u64) -> Vec<String> {
        self.lines
            .iter()
            .filter(|(number, _)| *number > after)
            .map(|(_, line)| line.clone())
            .collect()
    }

    /// Всего строк записано за всё время.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.next_number - 1
    }

    /// Строк, вытесненных из буфера из-за capacity.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.total() - self.lines.len() as u64
    }
}

/// Общий журнал stdout/stderr демона и сообщений управления.
pub type LogSink = Arc<Mutex<RingBuffer>>;

/// Один запущенный демон: ручка определяется реализацией [`PrivilegedExecutor`].
pub trait DaemonProcess: Send {
    /// PID процесса, если он известен.
    fn pid(&self) -> Option<u32>;
    /// Принудительно завершает процесс. Ошибка — человеко-читаемый текст.
    fn kill(&mut self) -> Result<(), String>;
}

/// Привилегированные руки обхода: применение правил nftables и запуск
/// демона. Реализации — [`DirectExecutor`] (под root) и [`PkexecExecutor`]
/// (через `pkexec`); в тестах — фейк.
pub trait PrivilegedExecutor: Send + Sync {
    /// Применяет полный текст правил (`nft -f -`). Ошибка — человеко-читаемый
    /// текст.
    fn run_nft_script(&self, text: &str) -> Result<(), String>;
    /// Удаляет таблицу `inet zapret2`. Отсутствие таблицы — не ошибка
    /// (эквивалент `2>/dev/null`).
    fn delete_nft_table(&self) -> Result<(), String>;
    /// Запускает демона по плану, читая stdout/stderr в `log`.
    fn run_daemon(
        &self,
        plan: &Nfqws2LaunchPlan,
        log: &LogSink,
    ) -> Result<Box<dyn DaemonProcess>, String>;
}

/// Запущенный обход: процесс и то, что нужно для показа и остановки.
struct Running {
    preset: String,
    qnum: u32,
    pid: Option<u32>,
    process: Box<dyn DaemonProcess>,
}

/// Состояние вкладки обхода: контроллер запуска, журнал, руки исполнения.
struct WsInner {
    resources_dir: String,
    executor: Arc<dyn PrivilegedExecutor>,
    controller: Mutex<Option<Running>>,
    logs: LogSink,
}

/// Клоняемая ручка состояния для ручек axum.
#[derive(Clone)]
pub struct WsState {
    inner: Arc<WsInner>,
}

impl FromRef<App> for WsState {
    fn from_ref(app: &App) -> Self {
        app.ws.clone()
    }
}

impl WsState {
    /// Состояние для живого сервера: ресурсы из окружения, руки по euid.
    #[must_use]
    pub fn production() -> Self {
        Self::new(resources_dir(), select_executor())
    }

    /// Состояние с явными ресурсами и руками (тесты).
    #[must_use]
    pub fn new(resources_dir: String, executor: Arc<dyn PrivilegedExecutor>) -> Self {
        Self {
            inner: Arc::new(WsInner {
                resources_dir,
                executor,
                controller: Mutex::new(None),
                logs: Arc::new(Mutex::new(RingBuffer::new(LOG_CAPACITY))),
            }),
        }
    }

    fn logs(&self) -> LogSink {
        Arc::clone(&self.inner.logs)
    }
}

/// Каталог ресурсов: `PRIMECORE_RESOURCES`, иначе `resources` относительно
/// каталога запуска сервера (корень репозитория).
#[must_use]
pub fn resources_dir() -> String {
    std::env::var("PRIMECORE_RESOURCES")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "resources".to_string())
}

// ─────────────────────── привилегированные руки ───────────────────────

/// Способ исполнения привилегированных команд.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorKind {
    /// Прямой запуск (euid == 0).
    Direct,
    /// Через `pkexec` (иначе).
    Pkexec,
}

/// Выбор способа по признаку root: под root — напрямую, иначе — `pkexec`.
#[must_use]
pub fn select_executor_kind(is_root: bool) -> ExecutorKind {
    if is_root {
        ExecutorKind::Direct
    } else {
        ExecutorKind::Pkexec
    }
}

/// `true`, если процесс работает под root (euid == 0).
#[must_use]
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map(|metadata| metadata.uid() == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Руки живого сервера: выбор по euid.
#[must_use]
pub fn select_executor() -> Arc<dyn PrivilegedExecutor> {
    match select_executor_kind(is_root()) {
        ExecutorKind::Direct => Arc::new(DirectExecutor),
        ExecutorKind::Pkexec => Arc::new(PkexecExecutor),
    }
}

/// Прямые руки: работают только под root.
pub struct DirectExecutor;

impl PrivilegedExecutor for DirectExecutor {
    fn run_nft_script(&self, text: &str) -> Result<(), String> {
        let mut child = std::process::Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| format!("не удалось запустить nft: {error}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "stdin nft недоступен".to_string())?;
        stdin
            .write_all(text.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("не удалось передать правила в nft: {error}"))?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|error| format!("nft не дождался ответа: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "nft отверг правила: {}",
                stderr_text(&output.stderr)
            ))
        }
    }

    fn delete_nft_table(&self) -> Result<(), String> {
        let output = std::process::Command::new("nft")
            .arg("delete")
            .arg("table")
            .arg("inet")
            .arg(NFT_TABLE)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|error| format!("не удалось запустить nft: {error}"))?;
        // Отсутствие таблицы — норма для idempotent-остановки.
        if output.status.success() || table_missing(&output.stderr) {
            Ok(())
        } else {
            Err(format!(
                "nft не удалил таблицу: {}",
                stderr_text(&output.stderr)
            ))
        }
    }

    fn run_daemon(
        &self,
        plan: &Nfqws2LaunchPlan,
        log: &LogSink,
    ) -> Result<Box<dyn DaemonProcess>, String> {
        let mut command = std::process::Command::new(&plan.exe);
        command
            .args(&plan.args)
            .current_dir(&plan.cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, value) in &plan.env {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("не удалось запустить {}: {error}", plan.exe))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        spawn_log_readers(log, stdout, stderr);
        Ok(Box::new(DirectProcess { child: Some(child) }))
    }
}

/// Процесс, запущенный напрямую: `std::process::Child`.
struct DirectProcess {
    child: Option<std::process::Child>,
}

impl DaemonProcess for DirectProcess {
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(std::process::Child::id)
    }

    fn kill(&mut self) -> Result<(), String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child
            .kill()
            .map_err(|error| format!("не удалось завершить процесс: {error}"))?;
        child
            .wait()
            .map(|_status| ())
            .map_err(|error| format!("не дождались завершения процесса: {error}"))
    }
}

/// Руки через `pkexec`: правила идут временным файлом, демон — временным
/// shell-скриптом, который после `exec` становится самим nfqws2 (тот же
/// PID, kill ручки убивает nfqws2).
pub struct PkexecExecutor;

impl PrivilegedExecutor for PkexecExecutor {
    fn run_nft_script(&self, text: &str) -> Result<(), String> {
        let path = write_temp_file("primecore-nft-", ".nft", text)?;
        let result = run_pkexec(&["nft", "-f", &path.to_string_lossy()]);
        let _ = std::fs::remove_file(&path);
        result
    }

    fn delete_nft_table(&self) -> Result<(), String> {
        // Отсутствие таблицы pkexec-путь тоже молчит: `pkexec nft` не отличить
        // без stderr, поэтому текст удаления даём через скрипт с перенаправлением.
        let script = format!("nft delete table inet {NFT_TABLE} 2>/dev/null\nexit 0\n");
        let path = write_temp_file("primecore-nft-del-", ".sh", &script)?;
        let result = run_pkexec(&["sh", &path.to_string_lossy()]);
        let _ = std::fs::remove_file(&path);
        result
    }

    fn run_daemon(
        &self,
        plan: &Nfqws2LaunchPlan,
        log: &LogSink,
    ) -> Result<Box<dyn DaemonProcess>, String> {
        let script = daemon_script_text(plan);
        let path = write_temp_file("primecore-nfqws2-", ".sh", &script)?;
        set_executable(&path)?;
        let mut command = std::process::Command::new("pkexec");
        command
            .arg("sh")
            .arg(&path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("не удалось запустить pkexec: {error}"))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        spawn_log_readers(log, stdout, stderr);
        // Скрипт нужен, пока его читает sh: уберём его, когда поток вывода
        // увидит конец (процесс завершился).
        let cleanup = path.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = std::fs::remove_file(cleanup);
        });
        Ok(Box::new(DirectProcess { child: Some(child) }))
    }
}

/// Один вызов `pkexec <argv>`; ошибка — текст stderr.
fn run_pkexec(argv: &[&str]) -> Result<(), String> {
    let mut command = std::process::Command::new("pkexec");
    command.args(argv).stdin(std::process::Stdio::null());
    let output = command
        .output()
        .map_err(|error| format!("не удалось запустить pkexec: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pkexec {}: {}",
            argv.join(" "),
            stderr_text(&output.stderr)
        ))
    }
}

/// Текст временного скрипта запуска демона: `cd <cwd> && exec <exe> <args>`,
/// переменные окружения экспортируются. После `exec` процесс sh становится
/// nfqws2 с тем же PID.
#[must_use]
pub fn daemon_script_text(plan: &Nfqws2LaunchPlan) -> String {
    let mut script = String::from("#!/bin/sh\n");
    for (key, value) in &plan.env {
        script.push_str(&format!("export {}={}\n", key, shell_quote(value)));
    }
    script.push_str(&format!("cd {} || exit 1\n", shell_quote(&plan.cwd)));
    script.push_str("exec ");
    script.push_str(&shell_quote(&plan.exe));
    for arg in &plan.args {
        script.push(' ');
        script.push_str(&shell_quote(arg));
    }
    script.push('\n');
    script
}

/// Одинарные кавычки POSIX: `'` внутри значения превращается в `'\''`.
#[must_use]
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Временный файл с уникальным именем (PID + наносекунды).
fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &str,
) -> Result<std::path::PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.subsec_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("{prefix}{}-{nanos}{suffix}", std::process::id()));
    std::fs::write(&path, content)
        .map_err(|error| format!("временный файл {}: {error}", path.display()))?;
    Ok(path)
}

/// Права 0755 на временный скрипт.
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| format!("нет скрипта {}: {error}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| format!("chmod {}: {error}", path.display()))
}

/// stderr процесса одной строкой (для сообщений об ошибках).
fn stderr_text(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "нет пояснений".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `true`, если nft сообщил об отсутствии таблицы (idempotent-удаление).
fn table_missing(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    text.contains("no such file") || text.contains("not found") || text.contains("no such table")
}

/// Читает stdout и stderr процесса в общий журнал, каждый поток — свой.
fn spawn_log_readers(
    log: &LogSink,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
) {
    let streams: Vec<Box<dyn std::io::Read + Send>> = [
        stdout.map(|stream| -> Box<dyn std::io::Read + Send> { Box::new(stream) }),
        stderr.map(|stream| -> Box<dyn std::io::Read + Send> { Box::new(stream) }),
    ]
    .into_iter()
    .flatten()
    .collect();
    for stream in streams {
        let log = Arc::clone(log);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut reader = std::io::BufReader::new(stream);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        for part in line.lines() {
                            log.lock()
                                .expect("журнал не отравлен")
                                .push(part.to_string());
                        }
                    }
                }
            }
        });
    }
}

/// Ответ ошибки ws-API в формате контракта: `{"error":"…"}`.
fn ws_error(status: StatusCode, message: String) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

// ─────────────────────────── endpoints ─────────────────────────────────

/// Каталог пресетов: `GET /api/ws/presets`.
///
/// ```json
/// {"presets":[{"name":"Universal V5","description":"Основной пресет. …"}]}
/// ```
pub async fn presets(State(state): State<WsState>) -> Json<Value> {
    let dir = presets_dir(&state.inner.resources_dir);
    let presets = list_presets(&dir)
        .into_iter()
        .map(|(name, description)| json!({ "name": name, "description": description }))
        .collect::<Vec<_>>();
    Json(json!({ "presets": presets }))
}

#[derive(Deserialize)]
pub struct PresetQuery {
    name: String,
}

/// Один пресет: `GET /api/ws/preset?name=<имя>`.
///
/// ```json
/// {"text":"…","stripped":"…","plan":{"exe":"…","args":[…],"cwd":"…","pidfile":"…"}}
/// ```
///
/// План строится на stripped-тексте: подстановка листов на этом этапе не
/// применяется, режим передаётся на старт. Пресеты с остаточными маркерами
/// плана не получают — фронтенд в этом случае видит 400 с пояснением.
pub async fn preset(
    State(state): State<WsState>,
    Query(query): Query<PresetQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let path = preset_path(&state.inner.resources_dir, &query.name)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
    let text =
        std::fs::read_to_string(&path).map_err(|error| preset_not_found(&query.name, error))?;
    let stripped = strip_windows_only(&text).map_err(|error| {
        ws_error(
            StatusCode::BAD_REQUEST,
            format!("пресет {} не годится: {error}", query.name),
        )
    })?;
    let exe = nfqws2_exe_path(&state.inner.resources_dir)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
    let plan = nfqws2_launch_plan(
        &exe,
        &state.inner.resources_dir,
        &stripped,
        DEFAULT_QNUM,
        FWMARK,
    )
    .map_err(|error| ws_error(StatusCode::BAD_REQUEST, format!("план запуска: {error}")))?;
    Ok(Json(json!({
        "text": text,
        "stripped": stripped,
        "plan": plan_json(&plan),
    })))
}

/// Тело `POST /api/ws/start`.
#[derive(Deserialize)]
pub struct StartRequest {
    /// Имя пресета (имя файла без `.txt`).
    pub name: String,
    /// Номер очереди netfilter.
    #[serde(default = "default_qnum")]
    pub qnum: u32,
    /// Режим листов: `none`, `hostlist`, `autohostlist`.
    #[serde(default = "default_hostlist_mode")]
    pub hostlist_mode: String,
}

fn default_qnum() -> u32 {
    DEFAULT_QNUM
}

fn default_hostlist_mode() -> String {
    "none".to_string()
}

/// Запуск обхода: `POST /api/ws/start`.
///
/// ```json
/// {"name":"Universal V5","qnum":300,"hostlist_mode":"none"}
/// ```
///
/// Ответ: `200 {"ok":true,"pid":1234}`, `409 {"error":"уже запущено"}` или
/// `400 {"error":"…"}`. Порядок: сначала правила nftables, затем spawn
/// демона по плану; при неудаче spawn таблица убирается обратно.
pub async fn start(
    State(state): State<WsState>,
    body: Result<Json<StartRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) =
        body.map_err(|rejection| ws_error(StatusCode::BAD_REQUEST, rejection.to_string()))?;
    // Применение правил и spawn — блокирующие вызовы: из async выносим в
    // отдельный поток, как предписывает tokio.
    let answer = tokio::task::spawn_blocking(move || start_sync(&state, &request))
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("фоновая задача не отработала: {error}") })),
            )
        })??;
    Ok(Json(answer))
}
/// Синхронная начинка старта: вся работа под мьютексом контроллера, чтобы
/// два параллельных старта не породили два демона.
fn start_sync(state: &WsState, request: &StartRequest) -> Result<Value, (StatusCode, Json<Value>)> {
    let mode = hostlist_mode(&request.hostlist_mode).ok_or_else(|| {
        ws_error(
            StatusCode::BAD_REQUEST,
            format!(
                "неизвестный режим листов: {} (none|hostlist|autohostlist)",
                request.hostlist_mode
            ),
        )
    })?;
    let preset_path = preset_path(&state.inner.resources_dir, &request.name)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
    let text = std::fs::read_to_string(&preset_path)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, preset_error(&request.name, error)))?;

    // Мьютекс держим до конца: проверка «уже запущено» и spawn — атомарно.
    let mut controller = state
        .inner
        .controller
        .lock()
        .expect("контроллер не отравлен");
    if controller.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({ "error": "уже запущено" })),
        ));
    }

    let stripped = strip_windows_only(&text).map_err(|error| {
        ws_error(
            StatusCode::BAD_REQUEST,
            format!("пресет {} не годится: {error}", request.name),
        )
    })?;
    // Подстановка листов: строки путей живут в этом блоке, структура
    // `HostlistSubstitution` заимствует их — поэтому конструируется здесь,
    // а не в отдельной функции.
    let lists_dir = format!("{}/lists", state.inner.resources_dir);
    let autohostlist = mode == HostlistFilterMode::Autohostlist;
    let user = existing_list(&lists_dir, "zapret-hosts-user.txt");
    let main = existing_list(&lists_dir, "zapret-hosts.txt");
    let exclude = existing_list(&lists_dir, "zapret-hosts-user-exclude.txt");
    let auto = autohostlist
        .then(|| existing_list(&lists_dir, "zapret-hosts-auto.txt"))
        .flatten();
    let auto_debug = autohostlist
        .then(|| existing_list(&lists_dir, "zapret-hosts-auto-debug.log"))
        .flatten();
    let substitution = HostlistSubstitution {
        mode,
        hostlist_user: user.as_deref(),
        hostlist: main.as_deref(),
        hostlist_exclude: exclude.as_deref(),
        hostlist_auto: auto.as_deref(),
        hostlist_auto_debug: auto_debug.as_deref(),
        autohostlist_extra_params: Vec::new(),
    };
    let prepared = substitute_hostlist_markers(&stripped, &substitution).map_err(|error| {
        ws_error(
            StatusCode::BAD_REQUEST,
            format!("подстановка листов: {error}"),
        )
    })?;
    let exe = nfqws2_exe_path(&state.inner.resources_dir)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
    if !Path::new(&exe).exists() {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            format!("бинарь nfqws2 не найден: {exe}"),
        ));
    }
    let plan = nfqws2_launch_plan(
        &exe,
        &state.inner.resources_dir,
        &prepared,
        request.qnum,
        FWMARK,
    )
    .map_err(|error| ws_error(StatusCode::BAD_REQUEST, format!("план запуска: {error}")))?;

    let filters = default_filters();
    let nft = nft_rules_text(request.qnum, &[], &[], &NOZAPRET4, &NOZAPRET6, &filters);
    state.inner.executor.run_nft_script(&nft).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("правила nftables: {error}") })),
        )
    })?;
    let process = match state.inner.executor.run_daemon(&plan, &state.logs()) {
        Ok(process) => process,
        // Таблица без демона не нужна: убираем обратно, ошибку spawn показываем.
        Err(error) => {
            if let Err(remove_error) = state.inner.executor.delete_nft_table() {
                state
                    .logs()
                    .lock()
                    .expect("журнал не отравлен")
                    .push(format!(
                        "nfqws2: не убрали таблицу после неудачного старта: {remove_error}"
                    ));
            }
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("запуск nfqws2: {error}") })),
            ));
        }
    };
    let pid = process.pid();
    state
        .logs()
        .lock()
        .expect("журнал не отравлен")
        .push(format!(
            "nfqws2: запущен пресет «{}» (qnum {}, режим листов {}, pid {})",
            request.name,
            request.qnum,
            request.hostlist_mode,
            pid.map_or_else(|| "неизвестен".to_string(), |pid| pid.to_string())
        ));
    *controller = Some(Running {
        preset: request.name.clone(),
        qnum: request.qnum,
        pid,
        process,
    });
    Ok(json!({ "ok": true, "pid": pid }))
}

/// Остановка обхода: `POST /api/ws/stop` → `200 {"ok":true}`.
///
/// Идемпотентна: если демон не запущен, всё равно убирается nft-таблица.
pub async fn stop(State(state): State<WsState>) -> Json<Value> {
    let log = state.logs();
    if let Ok(mut controller) = state.inner.controller.lock() {
        if let Some(mut running) = controller.take() {
            let result = running.process.kill();
            log.lock()
                .expect("журнал не отравлен")
                .push(match (&result, running.pid) {
                    (Ok(()), Some(pid)) => format!("nfqws2: остановлен (pid {pid})"),
                    (Ok(()), None) => "nfqws2: остановлен".to_string(),
                    (Err(error), _) => format!("nfqws2: остановка с ошибкой: {error}"),
                });
        }
    }
    let delete = tokio::task::spawn_blocking({
        let executor = Arc::clone(&state.inner.executor);
        move || executor.delete_nft_table()
    })
    .await;
    match delete {
        Ok(Ok(())) => {}
        Ok(Err(error)) => log
            .lock()
            .expect("журнал не отравлен")
            .push(format!("nfqws2: не убрали таблицу {NFT_TABLE}: {error}")),
        Err(error) => log
            .lock()
            .expect("журнал не отравлен")
            .push(format!("nfqws2: фоновая задача удаления таблицы: {error}")),
    }
    Json(json!({ "ok": true }))
}

/// Статус обхода: `GET /api/ws/status`.
///
/// ```json
/// {"running":true,"pid":1234,"preset":"Universal V5","qnum":300,"root":false}
/// ```
pub async fn status(State(state): State<WsState>) -> Json<Value> {
    let controller = state
        .inner
        .controller
        .lock()
        .expect("контроллер не отравлен");
    let running = controller.as_ref();
    Json(json!({
        "running": running.is_some(),
        "pid": running.and_then(|running| running.pid),
        "preset": running.map(|running| running.preset.clone()),
        "qnum": running.map(|running| running.qnum),
        "root": is_root(),
    }))
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    since: Option<u64>,
}

/// Журнал: `GET /api/ws/logs?since=<N>` — строки с номером больше `N`.
///
/// ```json
/// {"lines":["…"],"total":42,"dropped":0}
/// ```
pub async fn logs(State(state): State<WsState>, Query(query): Query<LogsQuery>) -> Json<Value> {
    let after = query.since.unwrap_or(0);
    let buffer = state.inner.logs.lock().expect("журнал не отравлен");
    Json(json!({
        "lines": buffer.since(after),
        "total": buffer.total(),
        "dropped": buffer.dropped(),
    }))
}

// ─────────────────────────── пресеты и пути ────────────────────────────

/// Каталог встроенных пресетов nfqws2.
fn presets_dir(resources_dir: &str) -> String {
    format!("{resources_dir}/presets/winws2_builtin")
}

/// Путь к пресету по имени с проверкой имени (без путей и `..`).
fn preset_path(resources_dir: &str, name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("имя пресета пустое".to_string());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!("недопустимое имя пресета: {name}"));
    }
    Ok(format!("{}/{}.txt", presets_dir(resources_dir), name))
}

fn preset_not_found(name: &str, error: std::io::Error) -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": format!("пресет {name} не найден: {error}") })),
    )
}

fn preset_error(name: &str, error: std::io::Error) -> String {
    format!("пресет {name} не читается: {error}")
}

/// Каталог пресетов: пары (имя без `.txt`, описание из шапки).
#[must_use]
pub fn list_presets(dir: &str) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut presets: Vec<(String, String)> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("txt"))
        .filter_map(|path| {
            let name = path.file_stem()?.to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).ok()?;
            Some((name, preset_description(&text)))
        })
        .collect();
    presets.sort_by(|a, b| a.0.cmp(&b.0));
    presets
}

/// Описание из шапки пресета: первая строка `# Description: …`,
/// без описания — пустая строка.
#[must_use]
pub fn preset_description(preset_text: &str) -> String {
    for line in preset_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#") {
            let rest = rest.trim();
            if let Some(description) = rest.strip_prefix("Description:") {
                return description.trim().to_string();
            }
        }
    }
    String::new()
}

/// Путь к бинарю nfqws2 по архитектуре хоста (`std::env::consts::ARCH`).
fn nfqws2_exe_path(resources_dir: &str) -> Result<String, String> {
    let dir = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64",
        "x86" => "linux-x86",
        "aarch64" => "linux-arm64",
        "arm" => "linux-arm",
        "riscv64" => "linux-riscv64",
        other => return Err(format!("нет сборки nfqws2 для архитектуры {other}")),
    };
    Ok(format!("{resources_dir}/bin-linux/{dir}/nfqws2"))
}

/// Режим листов из строки запроса.
fn hostlist_mode(value: &str) -> Option<HostlistFilterMode> {
    match value.trim().to_lowercase().as_str() {
        "none" => Some(HostlistFilterMode::None),
        "hostlist" => Some(HostlistFilterMode::Hostlist),
        "autohostlist" => Some(HostlistFilterMode::Autohostlist),
        _ => None,
    }
}

/// Существующий файл стандартного имени в каталоге листов (полный путь).
fn existing_list(lists_dir: &str, file_name: &str) -> Option<String> {
    let path = format!("{lists_dir}/{file_name}");
    Path::new(&path).is_file().then_some(path)
}

/// Фильтры очереди: эталонные значения по умолчанию.
#[must_use]
pub fn default_filters() -> Nfqws2NftFilters {
    Nfqws2NftFilters {
        disable_ipv4: false,
        disable_ipv6: false,
        postnat: false,
        filter_ttl_expired_icmp: false,
        tcp_ports: Some(TCP_PORTS.to_string()),
        udp_ports: Some(UDP_PORTS.to_string()),
        tcp_first_packets_out: TCP_PKT_OUT,
        tcp_first_packets_in: TCP_PKT_IN,
        udp_first_packets_out: UDP_PKT_OUT,
        udp_first_packets_in: UDP_PKT_IN,
    }
}

/// План запуска в JSON ответа.
fn plan_json(plan: &Nfqws2LaunchPlan) -> Value {
    json!({
        "exe": plan.exe,
        "args": plan.args,
        "cwd": plan.cwd,
        "pidfile": plan.pidfile,
    })
}

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// Каталог ресурсов репозитория из каталога крейта (cwd тестов).
    fn repo_resources() -> String {
        "../../resources".to_string()
    }

    /// Фейковые привилегированные руки: ничего не исполняет, только пишет.
    struct FakeExecutor {
        nft_scripts: Mutex<Vec<String>>,
        delete_calls: Mutex<u32>,
        daemon_calls: Mutex<Vec<String>>,
        fail_nft: bool,
        fail_spawn: bool,
    }

    impl FakeExecutor {
        fn new() -> Arc<Self> {
            Self::failing(false, false)
        }

        fn failing(fail_nft: bool, fail_spawn: bool) -> Arc<Self> {
            Arc::new(Self {
                nft_scripts: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(0),
                daemon_calls: Mutex::new(Vec::new()),
                fail_nft,
                fail_spawn,
            })
        }
    }

    impl PrivilegedExecutor for FakeExecutor {
        fn run_nft_script(&self, text: &str) -> Result<(), String> {
            self.nft_scripts.lock().unwrap().push(text.to_string());
            if self.fail_nft {
                Err("nft отверг правила".to_string())
            } else {
                Ok(())
            }
        }

        fn delete_nft_table(&self) -> Result<(), String> {
            *self.delete_calls.lock().unwrap() += 1;
            Ok(())
        }

        fn run_daemon(
            &self,
            plan: &Nfqws2LaunchPlan,
            _log: &LogSink,
        ) -> Result<Box<dyn DaemonProcess>, String> {
            self.daemon_calls.lock().unwrap().push(plan.exe.clone());
            if self.fail_spawn {
                return Err("spawn сорвался".to_string());
            }
            Ok(Box::new(FakeDaemon {
                pid: Some(4242),
                killed: Arc::new(AtomicBool::new(false)),
            }))
        }
    }

    struct FakeDaemon {
        pid: Option<u32>,
        killed: Arc<AtomicBool>,
    }

    impl DaemonProcess for FakeDaemon {
        fn pid(&self) -> Option<u32> {
            self.pid
        }

        fn kill(&mut self) -> Result<(), String> {
            self.killed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn app_with(executor: &Arc<FakeExecutor>, resources: &str) -> crate::App {
        let executor: Arc<dyn PrivilegedExecutor> = executor.clone();
        crate::App {
            ws: WsState::new(resources.to_string(), executor),
        }
    }

    async fn get(router: axum::Router, uri: &str) -> (StatusCode, Value) {
        let response = router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn post_json(router: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn ring_buffer_keeps_through_numbering_and_reports_dropped() {
        let mut buffer = RingBuffer::new(3);
        for value in 1..=5 {
            buffer.push(format!("строка {value}"));
        }
        assert_eq!(buffer.total(), 5);
        assert_eq!(buffer.dropped(), 2);
        assert_eq!(buffer.since(0), vec!["строка 3", "строка 4", "строка 5"]);
        assert_eq!(buffer.since(3), vec!["строка 4", "строка 5"]);
        assert!(buffer.since(5).is_empty());
    }

    #[test]
    fn executor_kind_follows_root_flag() {
        assert_eq!(select_executor_kind(true), ExecutorKind::Direct);
        assert_eq!(select_executor_kind(false), ExecutorKind::Pkexec);
    }

    #[test]
    fn daemon_script_quotes_paths_and_exports_env() {
        let plan = Nfqws2LaunchPlan {
            exe: "/opt/resources/bin-linux/linux-x86_64/nfqws2".to_string(),
            args: vec![
                "--qnum=300".to_string(),
                "--hostlist=zapret 'hosts'.txt".to_string(),
            ],
            env: [("MARK".to_string(), "0x40000000".to_string())]
                .into_iter()
                .collect(),
            cwd: "/opt/resources".to_string(),
            pidfile: "/run/nfqws2_1.pid".to_string(),
        };
        let script = daemon_script_text(&plan);
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("export MARK='0x40000000'"));
        assert!(script.contains("cd '/opt/resources' || exit 1"));
        assert!(script.contains("exec '/opt/resources/bin-linux/linux-x86_64/nfqws2' '--qnum=300'"));
        // Кавычка внутри значения уходит как '\'' — sh не съест остальное.
        assert!(script.contains("'--hostlist=zapret '\\''hosts'\\''.txt'"));
    }

    #[tokio::test]
    async fn presets_list_reads_real_catalog() {
        let app = app_with(&FakeExecutor::new(), &repo_resources());
        let (status, answer) = get(crate::router(app), "/api/ws/presets").await;
        assert_eq!(status, StatusCode::OK);
        let presets = answer["presets"].as_array().expect("список пресетов");
        assert!(!presets.is_empty(), "встроенных пресетов 136");
        let names: Vec<&str> = presets
            .iter()
            .filter_map(|preset| preset["name"].as_str())
            .collect();
        assert!(names.iter().all(|name| !name.contains(".txt")));
        assert!(names.iter().all(|name| !name.is_empty()));
        // Имена без расширения и с пробелами сохраняются как есть.
        assert!(
            names.iter().any(|name| name.contains(' ')),
            "имена пресетов содержат пробелы: {names:?}"
        );
        // Описание берётся из шапки; часть пресетов без описания — пустая строка.
        let described = presets.iter().any(|preset| {
            preset["description"]
                .as_str()
                .is_some_and(|d| !d.is_empty())
        });
        assert!(described, "есть пресеты с непустым Description");
    }

    #[tokio::test]
    async fn preset_endpoint_builds_plan_on_stripped_text() {
        let app = app_with(&FakeExecutor::new(), &repo_resources());
        let (status, answer) = get(crate::router(app), "/api/ws/preset?name=Preset.X1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(answer["text"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(answer["stripped"]
            .as_str()
            .is_some_and(|text| !text.is_empty()));
        let plan = &answer["plan"];
        assert!(plan["exe"]
            .as_str()
            .is_some_and(|exe| exe.ends_with("/nfqws2")));
        assert_eq!(plan["args"][0], "--qnum=300");
        assert_eq!(plan["args"][1], "--fwmark=0x40000000");
        assert!(plan["pidfile"]
            .as_str()
            .is_some_and(|p| p.ends_with(".pid")));
        assert!(plan["cwd"]
            .as_str()
            .is_some_and(|cwd| cwd.ends_with("resources")));
    }

    #[tokio::test]
    async fn preset_endpoint_404_on_unknown_name() {
        let app = app_with(&FakeExecutor::new(), &repo_resources());
        let (status, answer) = get(
            crate::router(app),
            "/api/ws/preset?name=%D0%BD%D0%B5%D1%82-%D1%82%D0%B0%D0%BA%D0%BE%D0%B3%D0%BE",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(answer["error"]
            .as_str()
            .is_some_and(|e| e.contains("нет-такого")));
    }

    #[tokio::test]
    async fn start_stop_lifecycle_with_fake_executor() {
        let executor = FakeExecutor::new();
        let app = app_with(&executor, &repo_resources());

        // Неизвестный режим — 400.
        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"ipset"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some());

        // Неизвестный пресет — 400.
        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"нет-такого","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some());

        // Успешный старт.
        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["pid"], 4242);

        // Правила nft применены до демона, демон запущен ровно один раз.
        assert_eq!(executor.nft_scripts.lock().unwrap().len(), 1);
        assert!(executor.nft_scripts.lock().unwrap()[0].contains("queue num 300"));
        assert_eq!(executor.daemon_calls.lock().unwrap().len(), 1);
        assert_eq!(*executor.delete_calls.lock().unwrap(), 0);

        // Повторный старт — 409.
        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["error"], "уже запущено");

        // Статус показывает запущенный обход.
        let (status, answer) = get(crate::router(app.clone()), "/api/ws/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["running"], true);
        assert_eq!(answer["pid"], 4242);
        assert_eq!(answer["preset"], "Preset.X1");
        assert_eq!(answer["qnum"], 300);
        assert!(answer["root"].is_boolean());

        // Остановка: kill и удаление таблицы.
        let (status, answer) = post_json(crate::router(app.clone()), "/api/ws/stop", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(*executor.delete_calls.lock().unwrap(), 1);

        let (status, answer) = get(crate::router(app.clone()), "/api/ws/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["running"], false);
        assert!(answer["pid"].is_null());

        // Повторная остановка idempotent: всё ещё 200, таблица удаляется снова.
        let (status, answer) = post_json(crate::router(app.clone()), "/api/ws/stop", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(*executor.delete_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn start_failure_leaves_nothing_running() {
        let executor = FakeExecutor::failing(false, true);
        let app = app_with(&executor, &repo_resources());

        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(answer["error"].as_str().is_some());

        // Демон не числится запущенным, таблица убрана обратно.
        let (status, answer) = get(crate::router(app.clone()), "/api/ws/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["running"], false);
        assert_eq!(*executor.delete_calls.lock().unwrap(), 1);

        // Неудача применения правил тоже не оставляет демона.
        let executor2 = FakeExecutor::failing(true, false);
        let app2 = app_with(&executor2, &repo_resources());
        let (status, _answer) = post_json(
            crate::router(app2.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(executor2.daemon_calls.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn logs_endpoint_returns_ring_buffer_state() {
        let executor = FakeExecutor::new();
        let app = app_with(&executor, &repo_resources());

        let (status, _answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, answer) = get(crate::router(app.clone()), "/api/ws/logs").await;
        assert_eq!(status, StatusCode::OK);
        let lines = answer["lines"].as_array().expect("список строк");
        assert!(!lines.is_empty());
        assert!(lines.iter().any(|line| {
            line.as_str()
                .is_some_and(|line| line.contains("запущен пресет"))
        }));
        let total = answer["total"].as_u64().expect("total");
        assert!(total > 0);

        // since=total — новых строк нет.
        let (status, answer) = get(
            crate::router(app.clone()),
            &format!("/api/ws/logs?since={total}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(answer["lines"].as_array().is_some_and(Vec::is_empty));
        assert_eq!(answer["total"], total);

        // После остановки в журнале есть запись об остановке.
        let (_, _) = post_json(crate::router(app.clone()), "/api/ws/stop", "").await;
        let (status, answer) = get(
            crate::router(app.clone()),
            &format!("/api/ws/logs?since={total}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(answer["lines"]
            .as_array()
            .is_some_and(|lines| !lines.is_empty()));
    }

    #[test]
    fn preset_description_parses_header_and_defaults_to_empty() {
        assert_eq!(
            preset_description("# Preset: X\n# Description: Тестовый пресет\n--qnum=1\n"),
            "Тестовый пресет"
        );
        assert_eq!(preset_description("--qnum=1\n"), "");
        assert_eq!(preset_description("# Description:\n"), "");
        assert_eq!(
            preset_description("#   Description:   с пробелами  \n"),
            "с пробелами"
        );
    }

    #[test]
    fn preset_path_rejects_traversal() {
        assert!(preset_path("resources", "Preset.X1").is_ok());
        assert!(preset_path("resources", "").is_err());
        assert!(preset_path("resources", "a/b").is_err());
        assert!(preset_path("resources", "..").is_err());
        assert!(preset_path("resources", "a..b").is_err());
    }

    #[test]
    fn nfqws2_exe_path_maps_known_architectures() {
        // На хосте тестов архитектура известна; путь обязан указывать на её каталог.
        let path = nfqws2_exe_path("resources").unwrap();
        assert!(path.starts_with("resources/bin-linux/"));
        assert!(path.ends_with("/nfqws2"));
    }
}
