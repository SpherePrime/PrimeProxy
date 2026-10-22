//! HTTP-ручки управления обходом nfqws2 (zapret2) для вкладки интерфейса:
//! каталог пресетов, запуск и остановка обхода, статус, журнал и
//! привилегии (состояние повышения, запуск демон-помощника `privd`).
//!
//! Логика запуска собрана в [`primecore_ws::runner_nfqws2`] (стрип
//! Windows-only строк, подстановка маркеров листов, план запуска, текст
//! правил nftables); этот модуль только склеивает её с HTTP: хранит
//! состояние запущенного обхода и исполняет привилегированные операции
//! через демон `privd` по unix-сокету ([`PrivdExecutor`]).
//!
//! Привилегии: сервер сам не повышает права — все привилегированные
//! операции (`nft -f -`, удаление таблицы, spawn nfqws2) уходят JSON-
//! запросом демону `privd`, который один раз запускается через
//! `pkexec`/`sudo` (ручка `POST /api/ws/privilege/grant`). Если демон не
//! поднят, start/stop отвечают 409 с приглашением нажать «Разрешить».
//! В тестах руки подменяются фейком, сокет не трогается.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, Query, State};
use axum::http::StatusCode;
use axum::Json;
use primecore_privilege::{
    client, helper_command, is_valid, load_state, needs_prompt, save_state, PrivilegeState,
};
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

/// Сокет демона `privd` по умолчанию.
const DEFAULT_PRIV_SOCK: &str = "/tmp/primecore-privd.sock";
/// Сообщение о не поднятых правах (демон `privd` не отвечает).
pub(crate) const NO_PRIVILEGE_ERROR: &str = "нет прав: нажмите «Разрешить» — запустится privd";
/// Сколько пресетов можно объединить в один запуск.
const MAX_NAMES: usize = 8;
/// Таймаут проверки пресета `--dry-run`.
const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(15);
/// Сколько последних строк stderr показывать при неудаче `--dry-run`.
const DRY_RUN_TAIL_LINES: usize = 15;
/// Сколько ждать появления сокета `privd` после запуска помощника.
const GRANT_WAIT: Duration = Duration::from_secs(60);
/// Шаг опроса сокета `privd`.
const GRANT_INTERVAL: Duration = Duration::from_millis(500);

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

/// Общий журнал сообщений управления (статус-события и ошибки сервера).
///
/// Вывод самого nfqws2 уходит в stdout/stderr демона `privd` (он живёт
/// дольше соединения и не отдаёт трубы клиенту); реальный stdout можно
/// потом читать через journal — здесь буфер наполняют только события
/// запуска/остановки и ошибки сервера.
pub type LogSink = Arc<Mutex<RingBuffer>>;

/// Ошибка проверки пресета `--dry-run`: текст для пользователя и хвост
/// stderr (последние строки) для диагностики.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunFailure {
    /// Короткое человеко-читаемое сообщение.
    pub error: String,
    /// Последние строки вывода nfqws2.
    pub tail: String,
}

/// Привилегированные руки обхода: проверка живости демона, правила
/// nftables, запуск/убийство демона — всё через демон `privd`. Реализация
/// по умолчанию — [`PrivdExecutor`]; в тестах подставляется фейк.
pub trait PrivilegedExecutor: Send + Sync {
    /// Демон `privd` отвечает? Ошибка — человеко-читаемый текст.
    fn ping(&self) -> Result<(), String>;
    /// Применяет полный текст правил (`nft -f -`). Ошибка — текст.
    fn run_nft_script(&self, text: &str) -> Result<(), String>;
    /// Удаляет таблицу `inet zapret2`. Отсутствие таблицы — не ошибка
    /// (эквивалент `2>/dev/null`).
    fn delete_nft_table(&self) -> Result<(), String>;
    /// Запускает демона по плану, возвращает ручку процесса.
    fn run_daemon(&self, plan: &Nfqws2LaunchPlan) -> Result<DaemonProcess, String>;
    /// Завершает процесс по pid.
    fn kill(&self, pid: u32) -> Result<(), String>;
    /// Жив ли процесс по pid.
    fn is_running(&self, pid: u32) -> Result<bool, String>;
    /// Проверка пресета без применения правил: запуск nfqws2 с
    /// `--dry-run` вместо `--pidfile`/`--daemon` (это НЕ привилегированная
    /// операция — процесс порождается напрямую из сервера).
    fn dry_run(&self, exe: &str, args: &[String]) -> Result<(), DryRunFailure>;
}

/// Ручка запущенного через `privd` демона: только pid — процесс принадлежит
/// демону, поэтому kill/статус тоже идут операциями протокола.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonProcess {
    pid: u32,
    sock: String,
}

impl DaemonProcess {
    #[must_use]
    pub fn new(pid: u32, sock: String) -> Self {
        Self { pid, sock }
    }

    /// PID демона.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Завершить процесс (`op kill`).
    ///
    /// # Errors
    /// Сокет не отвечает или демон вернул ошибку — текст.
    pub fn kill(&self) -> Result<(), String> {
        let reply = request_privd(&self.sock, json!({ "op": "kill", "pid": self.pid }))?;
        if reply["ok"] == json!(true) {
            Ok(())
        } else {
            Err(error_text(&reply, "демон не завершил процесс"))
        }
    }

    /// Жив ли процесс (`op status`).
    ///
    /// # Errors
    /// Сокет не отвечает или демон вернул ошибку — текст.
    pub fn is_running(&self) -> Result<bool, String> {
        let reply = request_privd(&self.sock, json!({ "op": "status", "pid": self.pid }))?;
        if reply["ok"] == json!(true) {
            Ok(reply["running"].as_bool().unwrap_or(false))
        } else {
            Err(error_text(&reply, "демон не ответил на status"))
        }
    }
}

/// Руки через демон `privd`: каждый вызов — один запрос по unix-сокету.
pub struct PrivdExecutor {
    sock: String,
}

impl PrivdExecutor {
    #[must_use]
    pub fn new(sock: String) -> Self {
        Self { sock }
    }
}

impl PrivilegedExecutor for PrivdExecutor {
    fn ping(&self) -> Result<(), String> {
        client::connect_and_ping(&self.sock)
    }

    fn run_nft_script(&self, text: &str) -> Result<(), String> {
        let reply = request_privd(&self.sock, json!({ "op": "nft", "script": text }))?;
        if reply["ok"] == json!(true) {
            Ok(())
        } else {
            Err(error_text(&reply, "nft отверг правила"))
        }
    }

    fn delete_nft_table(&self) -> Result<(), String> {
        let reply = request_privd(
            &self.sock,
            json!({ "op": "nft_delete", "table": NFT_TABLE }),
        )?;
        if reply["ok"] == json!(true) {
            Ok(())
        } else {
            Err(error_text(&reply, "nft не удалил таблицу"))
        }
    }

    fn run_daemon(&self, plan: &Nfqws2LaunchPlan) -> Result<DaemonProcess, String> {
        let reply = request_privd(
            &self.sock,
            json!({
                "op": "daemon",
                "exe": plan.exe,
                "args": plan.args,
                "cwd": plan.cwd,
                "env": plan.env,
                "pidfile": plan.pidfile,
            }),
        )?;
        if reply["ok"] != json!(true) {
            return Err(error_text(&reply, "демон не запустил nfqws2"));
        }
        let pid = reply["pid"]
            .as_u64()
            .ok_or_else(|| format!("демон не вернул pid: {reply}"))?;
        let pid = u32::try_from(pid).map_err(|error| format!("странный pid {pid}: {error}"))?;
        Ok(DaemonProcess::new(pid, self.sock.clone()))
    }

    fn kill(&self, pid: u32) -> Result<(), String> {
        DaemonProcess::new(pid, self.sock.clone()).kill()
    }

    fn is_running(&self, pid: u32) -> Result<bool, String> {
        DaemonProcess::new(pid, self.sock.clone()).is_running()
    }

    fn dry_run(&self, exe: &str, args: &[String]) -> Result<(), DryRunFailure> {
        dry_run_process(exe, args)
    }
}

/// Один запрос к демону `privd`: строка-запрос → разобранный JSON-ответ.
///
/// # Errors
/// Сокет не отвечает или ответ не JSON — текст.
pub(crate) fn request_privd(sock: &str, request: Value) -> Result<Value, String> {
    let reply = client::request(sock, &request.to_string())?;
    serde_json::from_str(&reply).map_err(|error| format!("ответ демона не JSON: {error} ({reply})"))
}

/// Поле `error` ответа или запасной текст.
fn error_text(reply: &Value, fallback: &str) -> String {
    reply["error"]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map_or_else(|| fallback.to_string(), str::to_string)
}

/// Проверка пресета `--dry-run`: прямой запуск nfqws2 (права не нужны)
/// с аргументами плана, где `--pidfile…`/`--daemon` заменены на
/// `--dry-run`. Успех — код возврата 0; иначе хвост stderr в ошибке.
fn dry_run_process(exe: &str, args: &[String]) -> Result<(), DryRunFailure> {
    let run_args = dry_run_args(args);
    let mut child = match std::process::Command::new(exe)
        .args(&run_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return Err(DryRunFailure {
                error: format!("не удалось запустить {exe}: {error}"),
                tail: String::new(),
            })
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || read_all_to_string(stdout));
    let stderr_reader = std::thread::spawn(move || read_all_to_string(stderr));

    let deadline = Instant::now() + DRY_RUN_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(DryRunFailure {
                    error: format!("не дождались проверки пресета: {error}"),
                    tail: String::new(),
                })
            }
        }
    };
    let output = format!(
        "{}{}",
        stdout_reader.join().unwrap_or_default(),
        stderr_reader.join().unwrap_or_default()
    );
    match status {
        None => Err(DryRunFailure {
            error: format!(
                "проверка пресета (--dry-run) не завершилась за {} с",
                DRY_RUN_TIMEOUT.as_secs()
            ),
            tail: dry_run_tail(&output, DRY_RUN_TAIL_LINES),
        }),
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(DryRunFailure {
            error: format!("проверка пресета (--dry-run) не прошла: код {status}"),
            tail: dry_run_tail(&output, DRY_RUN_TAIL_LINES),
        }),
    }
}

/// Аргументы проверки `--dry-run`: из аргументов плана убираются
/// `--pidfile…`/`--daemon`, в конец добавляется `--dry-run`.
#[must_use]
pub fn dry_run_args(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| !arg.starts_with("--pidfile") && arg.as_str() != "--daemon")
        .cloned()
        .chain(["--dry-run".to_string()])
        .collect()
}

/// Читает поток целиком в строку (поток-читатель для фонового вывода).
fn read_all_to_string(stream: Option<impl std::io::Read + Send>) -> String {
    let Some(mut stream) = stream else {
        return String::new();
    };
    let mut text = String::new();
    let _ = std::io::Read::read_to_string(&mut stream, &mut text);
    text
}

/// Последние `max_lines` строк вывода одной строкой через `\n`.
#[must_use]
pub fn dry_run_tail(output: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

// ─────────────────────── состояние и ручки axum ───────────────────────

/// Запущенный обход: имена пресетов, очередь, pid и pid-файл демона
/// (процесс принадлежит `privd`, поэтому хранится не `Child`, а pid).
struct Running {
    names: Vec<String>,
    qnum: u32,
    pid: Option<u32>,
    pidfile: String,
}

/// Состояние вкладки обхода: контроллер запуска, журнал, руки исполнения,
/// пути сокета `privd` и каталога состояния привилегий.
struct WsInner {
    resources_dir: String,
    executor: Arc<dyn PrivilegedExecutor>,
    controller: Mutex<Option<Running>>,
    logs: LogSink,
    sock_path: String,
    state_dir: String,
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
    /// Состояние для живого сервера: ресурсы и пути из окружения, руки —
    /// демон `privd`.
    #[must_use]
    pub fn production() -> Self {
        Self::new(
            resources_dir(),
            Arc::new(PrivdExecutor::new(privd_sock_path())),
        )
    }

    /// Состояние с явными ресурсами и руками; пути сокета и каталога
    /// состояния — из окружения (тесты, которым эти пути безразличны).
    #[must_use]
    pub fn new(resources_dir: String, executor: Arc<dyn PrivilegedExecutor>) -> Self {
        Self::new_with_paths(resources_dir, executor, privd_sock_path(), state_dir_path())
    }

    /// Состояние с явными путями (тесты ручек привилегий).
    #[must_use]
    pub fn new_with_paths(
        resources_dir: String,
        executor: Arc<dyn PrivilegedExecutor>,
        sock_path: String,
        state_dir: String,
    ) -> Self {
        Self {
            inner: Arc::new(WsInner {
                resources_dir,
                executor,
                controller: Mutex::new(None),
                logs: Arc::new(Mutex::new(RingBuffer::new(LOG_CAPACITY))),
                sock_path,
                state_dir,
            }),
        }
    }

    fn logs(&self) -> LogSink {
        Arc::clone(&self.inner.logs)
    }

    /// Сокет демона `privd` (для прямых операций смежных модулей).
    #[must_use]
    pub fn sock_path(&self) -> &str {
        &self.inner.sock_path
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

/// Сокет демона `privd`: `PRIMECORE_PRIV_SOCK`, иначе
/// `/tmp/primecore-privd.sock`.
#[must_use]
pub fn privd_sock_path() -> String {
    std::env::var("PRIMECORE_PRIV_SOCK")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PRIV_SOCK.to_string())
}

/// Каталог состояния привилегий: `PRIMECORE_STATE_DIR`, иначе
/// `$HOME/.local/state/primebypass`, иначе временный каталог.
#[must_use]
pub fn state_dir_path() -> String {
    if let Ok(dir) = std::env::var("PRIMECORE_STATE_DIR") {
        if !dir.trim().is_empty() {
            return dir;
        }
    }
    match std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
    {
        Some(home) => format!("{home}/.local/state/primebypass"),
        None => std::env::temp_dir()
            .join("primebypass-state")
            .to_string_lossy()
            .into_owned(),
    }
}

/// Текущее unix-время в секундах (сбой часов — 0).
#[must_use]
pub fn now_epoch_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs() as i64)
        .unwrap_or(0)
}

/// Есть ли `pkexec` в PATH.
#[must_use]
pub fn has_pkexec() -> bool {
    let path = std::env::var("PATH").unwrap_or_default();
    find_in_path("pkexec", &path)
}

/// Поиск исполняемого файла по каталогам `PATH`-строки.
#[must_use]
pub fn find_in_path(name: &str, path_variable: &str) -> bool {
    path_variable
        .split(':')
        .filter(|dir| !dir.is_empty())
        .any(|dir| Path::new(dir).join(name).is_file())
}

// ─────────────────────────── endpoints ─────────────────────────────────

/// Каталог пресетов: `GET /api/ws/presets`.
///
/// ```json
/// {"presets":[{"name":"Universal V5","description":"Основной пресет. …",
///              "targets":["Discord","YouTube"]}]}
/// ```
pub async fn presets(State(state): State<WsState>) -> Json<Value> {
    let dir = presets_dir(&state.inner.resources_dir);
    let presets = list_presets(&dir)
        .into_iter()
        .map(|(name, description, targets)| {
            json!({ "name": name, "description": description, "targets": targets })
        })
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
///
/// Новый формат — массив пресетов `names` (1..=8), объединяемых через
/// маркер `--new`; старый одиночный `name` тоже принимается.
#[derive(Deserialize)]
pub struct StartRequest {
    /// Имя пресета (имя файла без `.txt`) — старый одиночный формат.
    #[serde(default)]
    pub name: Option<String>,
    /// Имена пресетов — новый формат (1..=8).
    #[serde(default)]
    pub names: Option<Vec<String>>,
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

/// Имена пресетов из запроса: `names` (если задан и непуст), иначе старый
/// одиночный `name`. От 1 до [`MAX_NAMES`], без пустых имён.
fn resolve_names(request: &StartRequest) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let names = match (&request.names, &request.name) {
        (Some(names), _) if !names.is_empty() => names.clone(),
        (Some(_), _) => {
            return Err(ws_error(
                StatusCode::BAD_REQUEST,
                "список пресетов пуст".to_string(),
            ))
        }
        (_, Some(name)) => vec![name.clone()],
        (None, None) => {
            return Err(ws_error(
                StatusCode::BAD_REQUEST,
                "не указан пресет: ждётся name или names".to_string(),
            ))
        }
    };
    let names: Vec<String> = names.iter().map(|name| name.trim().to_string()).collect();
    if names.iter().any(|name| name.is_empty()) {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            "имя пресета пустое".to_string(),
        ));
    }
    if names.len() > MAX_NAMES {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            format!(
                "пресетов должно быть от 1 до {MAX_NAMES}, а не {}",
                names.len()
            ),
        ));
    }
    Ok(names)
}

/// Объединение текстов пресетов: маркер `--new` между ними (одиночный
/// пресет остаётся без изменений).
#[must_use]
pub fn merge_preset_texts(texts: &[String]) -> String {
    texts.join("\n--new\n")
}

/// Убирает точные дубли стандартных аргументов, которые при объединении
/// пресетов повторяются (`--lua-init=@…`, `--blob=…`): первый экземпляр
/// остаётся, повторные выбрасываются.
fn dedupe_repeated_args(args: &[String]) -> Vec<String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut result = Vec::with_capacity(args.len());
    for arg in args {
        let repeatable = arg.starts_with("--lua-init=@") || arg.starts_with("--blob=");
        if repeatable {
            if seen.contains(&arg.as_str()) {
                continue;
            }
            seen.push(arg);
        }
        result.push(arg.clone());
    }
    result
}

/// Запуск обхода: `POST /api/ws/start`.
///
/// ```json
/// {"names":["Preset.X1","ALL TCP & UDP v2"],"qnum":300,"hostlist_mode":"none"}
/// ```
/// (старый формат `{"name":"Preset.X1",…}` тоже принимается)
///
/// Ответ: `200 {"ok":true,"pid":1234,"names":["Preset.X1",…]}`,
/// `409 {"error":"уже запущено"}`, `409 {"error":"нет прав: нажмите
/// «Разрешить» — запустится privd"}` или `400 {"error":"…","tail":"…"}`.
///
/// Порядок: проверка живости `privd` (409), проверка пресетов `--dry-run`
/// напрямую (400 с хвостом stderr), затем правила nftables через `privd`,
/// затем spawn демона через `privd`; при неудаче spawn таблица убирается
/// обратно.
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
    let names = resolve_names(request)?;

    // Демон `privd` должен отвечать: без него привилегированные операции
    // невозможны, приглашаем нажать «Разрешить».
    state.inner.executor.ping().map_err(|_error| {
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": NO_PRIVILEGE_ERROR })),
        )
    })?;

    // Пресеты: чтение, стрип, подстановка листов.
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
    let mut prepared = Vec::with_capacity(names.len());
    for name in &names {
        let path = preset_path(&state.inner.resources_dir, name)
            .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|error| ws_error(StatusCode::BAD_REQUEST, preset_error(name, error)))?;
        let stripped = strip_windows_only(&text).map_err(|error| {
            ws_error(
                StatusCode::BAD_REQUEST,
                format!("пресет {name} не годится: {error}"),
            )
        })?;
        let substituted =
            substitute_hostlist_markers(&stripped, &substitution).map_err(|error| {
                ws_error(
                    StatusCode::BAD_REQUEST,
                    format!("подстановка листов: {error}"),
                )
            })?;
        prepared.push(substituted);
    }

    let exe = nfqws2_exe_path(&state.inner.resources_dir)
        .map_err(|error| ws_error(StatusCode::BAD_REQUEST, error))?;
    if !Path::new(&exe).exists() {
        return Err(ws_error(
            StatusCode::BAD_REQUEST,
            format!("бинарь nfqws2 не найден: {exe}"),
        ));
    }

    // Объединённый текст: text1 + "\n--new\n" + text2 (если пресетов >1).
    let merged = merge_preset_texts(&prepared);
    let mut plan = nfqws2_launch_plan(
        &exe,
        &state.inner.resources_dir,
        &merged,
        request.qnum,
        FWMARK,
    )
    .map_err(|error| ws_error(StatusCode::BAD_REQUEST, format!("план запуска: {error}")))?;
    plan.args = dedupe_repeated_args(&plan.args);

    // Валидация merged-конфигурации: dry-run напрямую, без привилегий.
    state
        .inner
        .executor
        .dry_run(&plan.exe, &plan.args)
        .map_err(|failure| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": failure.error, "tail": failure.tail })),
            )
        })?;

    // Мьютекс держим до конца: проверка «уже запущено» и spawn — атомарно.
    let mut controller = state
        .inner
        .controller
        .lock()
        .expect("контроллер не отравлен");
    if controller.is_some() {
        // Мёртвый процесс (демон подтвердил) не считается запущенным —
        // поверх его записи можно стартовать заново.
        let alive = controller
            .as_ref()
            .and_then(|previous| previous.pid)
            .map(|pid| state.inner.executor.is_running(pid).unwrap_or(true))
            .unwrap_or(true);
        if alive {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({ "error": "уже запущено" })),
            ));
        }
        *controller = None;
    }

    let filters = default_filters();
    let nft = nft_rules_text(request.qnum, &[], &[], &NOZAPRET4, &NOZAPRET6, &filters);
    state.inner.executor.run_nft_script(&nft).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("правила nftables: {error}") })),
        )
    })?;
    let process = match state.inner.executor.run_daemon(&plan) {
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
    let preset_label = names.join(" + ");
    state
        .logs()
        .lock()
        .expect("журнал не отравлен")
        .push(format!(
            "запуск: пресет «{preset_label}» (PID {pid}, qnum {}, режим листов {})",
            request.qnum, request.hostlist_mode
        ));
    *controller = Some(Running {
        names: names.clone(),
        qnum: request.qnum,
        pid: Some(pid),
        pidfile: plan.pidfile,
    });
    Ok(json!({ "ok": true, "pid": pid, "names": names }))
}

/// Остановка обхода: `POST /api/ws/stop` → `200 {"ok":true}`.
///
/// Идемпотентна: если демон не запущен, всё равно убирается nft-таблица.
/// Без живого `privd` — 409 (убить процесс и снять правила нечем).
pub async fn stop(State(state): State<WsState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let answer = tokio::task::spawn_blocking(move || stop_sync(&state))
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("фоновая задача не отработала: {error}") })),
            )
        })??;
    Ok(Json(answer))
}

/// Синхронная начинка остановки.
fn stop_sync(state: &WsState) -> Result<Value, (StatusCode, Json<Value>)> {
    state.inner.executor.ping().map_err(|_error| {
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": NO_PRIVILEGE_ERROR })),
        )
    })?;
    let log = state.logs();
    let mut controller = state
        .inner
        .controller
        .lock()
        .expect("контроллер не отравлен");
    if let Some(running) = controller.take() {
        if let Some(pid) = running.pid {
            let result = state.inner.executor.kill(pid);
            let label = running.names.join(" + ");
            log.lock().expect("журнал не отравлен").push(match &result {
                Ok(()) => format!(
                    "останов: пресет «{label}» (PID {pid}, pidfile {})",
                    running.pidfile
                ),
                Err(error) => format!("остановка с ошибкой: {error}"),
            });
        }
    }
    drop(controller);
    if let Err(error) = state.inner.executor.delete_nft_table() {
        log.lock()
            .expect("журнал не отравлен")
            .push(format!("nfqws2: не убрали таблицу {NFT_TABLE}: {error}"));
    }
    Ok(json!({ "ok": true }))
}

/// Статус обхода: `GET /api/ws/status`.
///
/// ```json
/// {"running":true,"pid":1234,"preset":"A + B","names":["A","B"],"qnum":300,"root":false}
/// ```
pub async fn status(State(state): State<WsState>) -> Json<Value> {
    let record = {
        let controller = state
            .inner
            .controller
            .lock()
            .expect("контроллер не отравлен");
        controller
            .as_ref()
            .map(|running| (running.names.clone(), running.pid, running.qnum))
    };
    let pid = record.as_ref().and_then(|(_, pid, _)| *pid);
    // Запись есть, но процесс мог умереть: живость подтверждает демон
    // `privd` (op status). Ошибка опроса трактуется как «не жив».
    let alive = match pid {
        Some(pid) => {
            let executor = Arc::clone(&state.inner.executor);
            tokio::task::spawn_blocking(move || executor.is_running(pid))
                .await
                .ok()
                .and_then(|result| result.ok())
                .unwrap_or(false)
        }
        None => false,
    };
    let running = record.is_some() && alive;
    Json(json!({
        "running": running,
        "pid": pid.filter(|_| running),
        "preset": running.then(|| record.as_ref().expect("запись есть").0.join(" + ")),
        "names": running.then(|| record.as_ref().expect("запись есть").0.clone()),
        "qnum": running.then(|| record.as_ref().expect("запись есть").2),
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

// ─────────────────────────── привилегии ───────────────────────────────

/// Состояние привилегий: `GET /api/ws/privilege`.
///
/// ```json
/// {"granted":true,"needs_prompt":false,"helper":["pkexec","privd"],
///  "sock":"/tmp/primecore-privd.sock"}
/// ```
///
/// `granted` — состояние валидно (не старше 12 часов) И демон `privd`
/// отвечает на сокете; `needs_prompt` — по сохранённому состоянию
/// (`needs_prompt(state, now)`, TTL 12 часов).
pub async fn privilege(State(state): State<WsState>) -> Json<Value> {
    let sock = state.inner.sock_path.clone();
    let state_dir = state.inner.state_dir.clone();
    // Соединение с сокетом — блокирующий вызов: выносим из async.
    let answer = tokio::task::spawn_blocking(move || privilege_info(&sock, &state_dir))
        .await
        .unwrap_or_else(|error| {
            json!({
                "granted": false,
                "needs_prompt": true,
                "error": format!("фоновая задача не отработала: {error}"),
            })
        });
    Json(answer)
}

/// Сборка статуса привилегий (блокирующая часть ручки).
fn privilege_info(sock: &str, state_dir: &str) -> Value {
    let saved = load_state(Path::new(state_dir)).ok().flatten();
    let now = now_epoch_s();
    let state_valid = saved
        .as_ref()
        .map(|state| is_valid(state, now))
        .unwrap_or(false);
    let daemon_alive = client::connect_and_ping(sock).is_ok();
    json!({
        "granted": state_valid && daemon_alive,
        "needs_prompt": needs_prompt(saved.as_ref(), now),
        "helper": helper_command(has_pkexec),
        "sock": sock,
    })
}

/// Запуск повышения: `POST /api/ws/privilege/grant`.
///
/// Запускает помощника (`pkexec privd` или `sudo privd` — pkexec сам
/// показывает диалог) и ждёт появления живого сокета до 60 секунд; при
/// успехе сохраняет состояние привилегий. Ответ:
/// `200 {"ok":true,"helper":["pkexec","privd"]}` или
/// `500 {"error":"…"}`.
pub async fn privilege_grant(
    State(state): State<WsState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sock = state.inner.sock_path.clone();
    let state_dir = state.inner.state_dir.clone();
    let granted = tokio::task::spawn_blocking(move || grant_sync(&sock, &state_dir))
        .await
        .map_err(|error| {
            ws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("фоновая задача не отработала: {error}"),
            )
        })?
        .map_err(|error| ws_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(json!({ "ok": true, "helper": granted })))
}

/// Синхронная начинка повышения: запуск помощника, ожидание сокета,
/// сохранение состояния. Возвращает использованную команду помощника.
fn grant_sync(sock: &str, state_dir: &str) -> Result<Vec<String>, String> {
    grant_sync_with(sock, state_dir, GRANT_WAIT, GRANT_INTERVAL, run_helper)
}

/// То же с подменяемым запуском помощника и таймаутами (тесты).
fn grant_sync_with<F>(
    sock: &str,
    state_dir: &str,
    wait: Duration,
    interval: Duration,
    spawn_helper: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(&[String]) -> Result<std::process::Child, String>,
{
    let helper = helper_command(has_pkexec);
    let mut child = spawn_helper(&helper).map_err(|error| format!("запуск помощника: {error}"))?;
    let deadline = Instant::now() + wait;
    loop {
        if client::connect_and_ping(sock).is_ok() {
            save_state(
                Path::new(state_dir),
                &PrivilegeState {
                    granted: true,
                    granted_at_epoch_s: now_epoch_s(),
                    helper_path: helper_path(&helper),
                },
            )?;
            return Ok(helper);
        }
        // Помощник завершился, не подняв демон (например, диалог
        // отменён) — ждать до таймаута бессмысленно.
        if child
            .try_wait()
            .map_err(|error| format!("помощник: {error}"))?
            .is_some()
        {
            return Err("помощник завершился, не подняв демон privd".to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "демон privd не отвечает на {sock} за {} с",
                wait.as_secs()
            ));
        }
        std::thread::sleep(interval);
    }
}

/// Путь помощника для состояния: второй элемент команды (`privd`).
fn helper_path(helper: &[String]) -> String {
    helper.get(1).cloned().unwrap_or_default()
}

/// Запуск помощника без ожидания: stdout/stderr наследуются — pkexec сам
/// показывает диалог пользователю.
fn run_helper(helper: &[String]) -> Result<std::process::Child, String> {
    let Some(program) = helper.first() else {
        return Err("команда повышения пуста".to_string());
    };
    std::process::Command::new(program)
        .args(helper.iter().skip(1))
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))
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

/// Каталог пресетов: тройки (имя без `.txt`, описание из шапки, цели).
#[must_use]
pub fn list_presets(dir: &str) -> Vec<(String, String, Vec<String>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut presets: Vec<(String, String, Vec<String>)> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("txt"))
        .filter_map(|path| {
            let name = path.file_stem()?.to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).ok()?;
            let targets = preset_targets(&text);
            Some((name, preset_description(&text), targets))
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

/// Цели пресета по ссылкам на списки: `--hostlist=lists/<имя>.txt`
/// (только hostlist-ссылки; `--ipset` не рассматривается). Порядок — по
/// каталогу целей; без совпадений — `["Общий"]`.
#[must_use]
pub fn preset_targets(preset_text: &str) -> Vec<String> {
    let mut matched: Vec<&'static str> = Vec::new();
    for raw in preset_text.split('\n') {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        for token in line.split_whitespace() {
            let Some(value) = token.strip_prefix("--hostlist=") else {
                continue;
            };
            let Some(name) = value.strip_prefix("lists/") else {
                continue;
            };
            let name = name.strip_suffix(".txt").unwrap_or(name);
            for target in list_targets(name) {
                if !matched.contains(&target) {
                    matched.push(target);
                }
            }
        }
    }
    // Порядок по каталогу целей.
    let mut targets = Vec::with_capacity(matched.len());
    for label in TARGET_CATALOG_LABELS {
        if matched.contains(&label) {
            targets.push((*label).to_string());
        }
    }
    if targets.is_empty() {
        targets.push("Общий".to_string());
    }
    targets
}

/// Метки целей в каталоговом порядке.
const TARGET_CATALOG_LABELS: [&str; 8] = [
    "Discord",
    "YouTube",
    "Google",
    "ChatGPT",
    "Соцсети Meta",
    "Twitch",
    "Игры",
    "Все сайты",
];

/// Цели одного списка (в каталоговом порядке; несколько — допустимо).
fn list_targets(list_name: &str) -> Vec<&'static str> {
    let name = list_name.to_lowercase();
    let mut targets = Vec::new();
    if name.contains("discord") {
        targets.push("Discord");
    }
    if name.contains("youtube")
        || name.contains("googlevideo")
        || name.contains("ipset-russia-youtube")
    {
        targets.push("YouTube");
    }
    if name.starts_with("google") {
        targets.push("Google");
    }
    if name.contains("chatgpt") || name.contains("openai") {
        targets.push("ChatGPT");
    }
    if name.contains("instagram") || name.contains("facebook") {
        targets.push("Соцсети Meta");
    }
    if name.contains("twitch") {
        targets.push("Twitch");
    }
    if name.contains("steam") || name.contains("roblox") {
        targets.push("Игры");
    }
    if name.contains("russia-blacklist")
        || name.contains("zapret-moe")
        || name.contains("netrogat")
        || name.contains("allzone")
    {
        targets.push("Все сайты");
    }
    targets
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

/// Ответ ошибки ws-API в формате контракта: `{"error":"…"}`.
pub(crate) fn ws_error(status: StatusCode, message: String) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

/// `true`, если процесс работает под root (euid == 0) — поле `root` статуса.
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

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use primecore_privilege::ops::PrivilegedOps;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// Каталог ресурсов репозитория из каталога крейта (cwd тестов).
    fn repo_resources() -> String {
        "../../resources".to_string()
    }

    /// tmpdir с уникальным именем.
    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "primecore-server-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("часы идут")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir создан");
        dir
    }

    /// Фейковые привилегированные руки: ничего не исполняет, только пишет.
    struct FakeExecutor {
        nft_scripts: Mutex<Vec<String>>,
        delete_calls: Mutex<u32>,
        daemon_calls: Mutex<Vec<Vec<String>>>,
        dry_runs: Mutex<Vec<Vec<String>>>,
        killed: Mutex<Vec<u32>>,
        running: Mutex<HashMap<u32, bool>>,
        fail_nft: bool,
        fail_spawn: bool,
        fail_dry_run: Option<DryRunFailure>,
        ping_ok: bool,
    }

    impl FakeExecutor {
        fn new() -> Arc<Self> {
            Self::failing(false, false)
        }

        fn failing(fail_nft: bool, fail_spawn: bool) -> Arc<Self> {
            Arc::new(Self::raw(fail_nft, fail_spawn))
        }

        fn raw(fail_nft: bool, fail_spawn: bool) -> Self {
            Self {
                nft_scripts: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(0),
                daemon_calls: Mutex::new(Vec::new()),
                dry_runs: Mutex::new(Vec::new()),
                killed: Mutex::new(Vec::new()),
                running: Mutex::new(HashMap::new()),
                fail_nft,
                fail_spawn,
                fail_dry_run: None,
                ping_ok: true,
            }
        }

        fn failing_dry_run(tail: &str) -> Arc<Self> {
            let mut fake = Self::raw(false, false);
            fake.fail_dry_run = Some(DryRunFailure {
                error: "проверка пресета (--dry-run) не прошла: код 1".to_string(),
                tail: tail.to_string(),
            });
            Arc::new(fake)
        }

        fn without_privd() -> Arc<Self> {
            let mut fake = Self::raw(false, false);
            fake.ping_ok = false;
            Arc::new(fake)
        }
    }

    impl PrivilegedExecutor for FakeExecutor {
        fn ping(&self) -> Result<(), String> {
            if self.ping_ok {
                Ok(())
            } else {
                Err("демон не отвечает".to_string())
            }
        }

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

        fn run_daemon(&self, plan: &Nfqws2LaunchPlan) -> Result<DaemonProcess, String> {
            self.daemon_calls.lock().unwrap().push(plan.args.clone());
            if self.fail_spawn {
                return Err("spawn сорвался".to_string());
            }
            let pid = 4242;
            self.running.lock().unwrap().insert(pid, true);
            Ok(DaemonProcess::new(pid, "fake.sock".to_string()))
        }

        fn kill(&self, pid: u32) -> Result<(), String> {
            self.killed.lock().unwrap().push(pid);
            self.running.lock().unwrap().insert(pid, false);
            Ok(())
        }

        fn is_running(&self, pid: u32) -> Result<bool, String> {
            Ok(self
                .running
                .lock()
                .unwrap()
                .get(&pid)
                .copied()
                .unwrap_or(false))
        }

        fn dry_run(&self, _exe: &str, args: &[String]) -> Result<(), DryRunFailure> {
            self.dry_runs.lock().unwrap().push(args.to_vec());
            match &self.fail_dry_run {
                Some(failure) => Err(failure.clone()),
                None => Ok(()),
            }
        }
    }

    fn app_with(executor: &Arc<FakeExecutor>, resources: &str) -> crate::App {
        let executor: Arc<dyn PrivilegedExecutor> = executor.clone();
        crate::App {
            ws: WsState::new(resources.to_string(), executor),
            ..crate::App::test_defaults()
        }
    }

    fn app_with_paths(executor: &Arc<FakeExecutor>, sock: &str, state_dir: &str) -> crate::App {
        let executor: Arc<dyn PrivilegedExecutor> = executor.clone();
        crate::App {
            ws: WsState::new_with_paths(
                repo_resources(),
                executor,
                sock.to_string(),
                state_dir.to_string(),
            ),
            ..crate::App::test_defaults()
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
        // У каждого пресета есть массив целей.
        assert!(presets
            .iter()
            .all(|preset| preset["targets"].as_array().is_some_and(|t| !t.is_empty())));
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

        // Успешный старт (старый одиночный формат).
        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["pid"], 4242);
        assert_eq!(answer["names"], json!(["Preset.X1"]));

        // Проверка dry-run прошла до nft, правила применены до демона,
        // демон запущен ровно один раз.
        assert_eq!(executor.dry_runs.lock().unwrap().len(), 1);
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
        assert_eq!(answer["names"], json!(["Preset.X1"]));
        assert_eq!(answer["qnum"], 300);
        assert!(answer["root"].is_boolean());

        // Остановка: kill по pid и удаление таблицы.
        let (status, answer) = post_json(crate::router(app.clone()), "/api/ws/stop", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(*executor.killed.lock().unwrap(), vec![4242]);
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
    async fn start_accepts_names_array_and_merges_presets() {
        let executor = FakeExecutor::new();
        let app = app_with(&executor, &repo_resources());

        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"names":["Preset.X1","ALL TCP & UDP v2"],"qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["pid"], 4242);
        assert_eq!(answer["names"], json!(["Preset.X1", "ALL TCP & UDP v2"]));

        // Объединённый конфиг: маркер --new между пресетами попал в args,
        // дублей стандартных lua-init нет.
        let (call_count, has_new, no_lua_dups) = {
            let daemon_calls = executor.daemon_calls.lock().unwrap();
            let has_new =
                daemon_calls.len() == 1 && daemon_calls[0].iter().any(|arg| arg == "--new");
            let lua_inits: Vec<&String> = daemon_calls
                .first()
                .map(|args| {
                    args.iter()
                        .filter(|arg| arg.starts_with("--lua-init=@"))
                        .collect()
                })
                .unwrap_or_default();
            let mut unique = lua_inits.clone();
            unique.sort_unstable();
            unique.dedup();
            let no_lua_dups = lua_inits.len() == unique.len();
            (daemon_calls.len(), has_new, no_lua_dups)
        };
        assert_eq!(call_count, 1);
        assert!(has_new, "маркер --new есть в args демона");
        assert!(no_lua_dups, "нет дублей lua-init");

        // Статус: пресеты через « + », names отдельным полем.
        let (_, answer) = get(crate::router(app.clone()), "/api/ws/status").await;
        assert_eq!(answer["preset"], "Preset.X1 + ALL TCP & UDP v2");
        assert_eq!(answer["names"], json!(["Preset.X1", "ALL TCP & UDP v2"]));
    }

    #[tokio::test]
    async fn start_validates_names_bounds() {
        let app = app_with(&FakeExecutor::new(), &repo_resources());
        // Пустой список — 400.
        let (status, _answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"names":[],"qnum":300}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Ни name, ни names — 400.
        let (status, _answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"qnum":300}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Девять пресетов — 400.
        let names = (1..=9)
            .map(|index| format!("Preset.X{index}"))
            .collect::<Vec<_>>();
        let body =
            serde_json::to_string(&serde_json::json!({"names": names, "qnum": 300})).expect("JSON");
        let (status, answer) = post_json(crate::router(app.clone()), "/api/ws/start", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"].as_str().is_some_and(|e| e.contains("8")));
    }

    #[tokio::test]
    async fn start_dry_run_failure_answers_400_before_nft() {
        let executor = FakeExecutor::failing_dry_run("строка 1\nстрока 2\nошибка тут");
        let app = app_with(&executor, &repo_resources());

        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(answer["error"]
            .as_str()
            .is_some_and(|e| e.contains("dry-run")));
        assert!(answer["tail"]
            .as_str()
            .is_some_and(|t| t.contains("ошибка тут")));
        // Привилегированные операции не начались.
        assert!(executor.nft_scripts.lock().unwrap().is_empty());
        assert!(executor.daemon_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn start_and_stop_without_privd_answer_409() {
        let executor = FakeExecutor::without_privd();
        let app = app_with(&executor, &repo_resources());

        let (status, answer) = post_json(
            crate::router(app.clone()),
            "/api/ws/start",
            r#"{"name":"Preset.X1","qnum":300,"hostlist_mode":"none"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["error"], NO_PRIVILEGE_ERROR);
        // Привилегированные шаги не начались.
        assert!(executor.nft_scripts.lock().unwrap().is_empty());

        let (status, answer) = post_json(crate::router(app.clone()), "/api/ws/stop", "").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["error"], NO_PRIVILEGE_ERROR);
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
                .is_some_and(|line| line.contains("запуск") && line.contains("PID 4242"))
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
        assert!(answer["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().is_some_and(|line| line.contains("останов"))));
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

    #[test]
    fn merge_preset_texts_joins_with_new_marker() {
        assert_eq!(
            merge_preset_texts(&["--qnum=1".to_string()]),
            "--qnum=1",
            "одиночный пресет без изменений"
        );
        assert_eq!(
            merge_preset_texts(&["a".to_string(), "b".to_string(), "c".to_string()]),
            "a\n--new\nb\n--new\nc"
        );
    }

    #[test]
    fn dedupe_repeated_args_keeps_first_occurrence() {
        let args = vec![
            "--qnum=300".to_string(),
            "--lua-init=@lua/zapret-lib.lua".to_string(),
            "--filter-tcp=443".to_string(),
            "--lua-init=@lua/zapret-lib.lua".to_string(),
            "--blob=tls_google:@bin/x.bin".to_string(),
            "--blob=tls_google:@bin/x.bin".to_string(),
            "--lua-init=@lua/другой.lua".to_string(),
        ];
        assert_eq!(
            dedupe_repeated_args(&args),
            vec![
                "--qnum=300".to_string(),
                "--lua-init=@lua/zapret-lib.lua".to_string(),
                "--filter-tcp=443".to_string(),
                "--blob=tls_google:@bin/x.bin".to_string(),
                "--lua-init=@lua/другой.lua".to_string(),
            ]
        );
        // Не повторяемые аргументы не трогаются.
        let args = vec![
            "--filter-tcp=443".to_string(),
            "--filter-tcp=443".to_string(),
        ];
        assert_eq!(dedupe_repeated_args(&args), args);
    }

    #[test]
    fn dry_run_tail_takes_last_lines() {
        let text = "1\n2\n3\n4\n5";
        assert_eq!(dry_run_tail(text, 2), "4\n5");
        assert_eq!(dry_run_tail(text, 10), text);
        assert_eq!(dry_run_tail("", 5), "");
    }

    #[test]
    fn resolve_names_accepts_new_and_legacy_bodies() {
        let legacy = StartRequest {
            name: Some(" Solo ".to_string()),
            names: None,
            qnum: 300,
            hostlist_mode: "none".to_string(),
        };
        assert_eq!(resolve_names(&legacy).unwrap(), vec!["Solo"]);

        let multiple = StartRequest {
            name: None,
            names: Some(vec!["A".to_string(), "B".to_string()]),
            qnum: 300,
            hostlist_mode: "none".to_string(),
        };
        assert_eq!(resolve_names(&multiple).unwrap(), vec!["A", "B"]);

        // names имеет приоритет над name.
        let both = StartRequest {
            name: Some("ignored".to_string()),
            names: Some(vec!["A".to_string()]),
            qnum: 300,
            hostlist_mode: "none".to_string(),
        };
        assert_eq!(resolve_names(&both).unwrap(), vec!["A"]);

        let empty = StartRequest {
            name: None,
            names: Some(Vec::new()),
            qnum: 300,
            hostlist_mode: "none".to_string(),
        };
        assert!(resolve_names(&empty).is_err());

        let too_many = StartRequest {
            name: None,
            names: Some((1..=9).map(|i| format!("p{i}")).collect()),
            qnum: 300,
            hostlist_mode: "none".to_string(),
        };
        assert!(resolve_names(&too_many).is_err());
    }

    #[test]
    fn find_in_path_scans_directories() {
        assert!(find_in_path("sh", "/bin:/usr/bin"));
        assert!(!find_in_path("нет-такого", "/bin"));
        assert!(!find_in_path("sh", "/нет/такого"));
        assert!(!find_in_path("sh", ""));
    }

    #[test]
    fn state_dir_path_prefers_env_then_home() {
        // Функция консервативна: путь всегда оканчивается на primebypass,
        // когда задан HOME, и на каталог состояния из окружения.
        let saved = std::env::var("PRIMECORE_STATE_DIR").ok();
        std::env::remove_var("PRIMECORE_STATE_DIR");
        let dir = state_dir_path();
        if std::env::var("HOME").is_ok_and(|home| !home.trim().is_empty()) {
            assert!(dir.ends_with(".local/state/primebypass"), "{dir}");
        }
        std::env::set_var("PRIMECORE_STATE_DIR", "/tmp/явный-каталог");
        assert_eq!(state_dir_path(), "/tmp/явный-каталог");
        match saved {
            Some(value) => std::env::set_var("PRIMECORE_STATE_DIR", value),
            None => std::env::remove_var("PRIMECORE_STATE_DIR"),
        }
    }

    #[test]
    fn dry_run_args_replaces_pidfile_and_daemon() {
        let args = vec![
            "--qnum=300".to_string(),
            "--pidfile=/run/x.pid".to_string(),
            "--daemon".to_string(),
        ];
        assert_eq!(
            dry_run_args(&args),
            vec!["--qnum=300".to_string(), "--dry-run".to_string()]
        );
        // Без pidfile/daemon просто добавляется флаг.
        assert_eq!(
            dry_run_args(&["--qnum=1".to_string()]),
            vec!["--qnum=1".to_string(), "--dry-run".to_string()]
        );
    }

    // ── цели пресетов ────────────────────────────────────────────────

    #[test]
    fn preset_targets_maps_catalog_and_orders() {
        let text = "--hostlist=lists/netrogat.txt\n--hostlist=lists/discord.txt --hostlist=lists/googlevideo.txt\n";
        assert_eq!(
            preset_targets(text),
            vec![
                "Discord".to_string(),
                "YouTube".to_string(),
                "Google".to_string(),
                "Все сайты".to_string()
            ]
        );
        // Дедуп: один и тот же список дважды — одна цель.
        let text = "--hostlist=lists/discord.txt\n--hostlist=lists/discord-images.txt\n";
        assert_eq!(preset_targets(text), vec!["Discord".to_string()]);
        // Без совпадений — «Общий».
        assert_eq!(
            preset_targets("--hostlist=lists/rutor.txt\n"),
            vec!["Общий"]
        );
        // Только hostlist-ссылки: ipset не рассматривается.
        assert_eq!(
            preset_targets("--ipset=lists/ipset-discord.txt\n"),
            vec!["Общий"]
        );
        // Игры: steam и roblox.
        assert_eq!(
            preset_targets("--hostlist=lists/steam.txt --hostlist=lists/roblox.txt"),
            vec!["Игры"]
        );
        // Соцсети Meta.
        assert_eq!(
            preset_targets("--hostlist=lists/instagram.txt\n--hostlist=lists/facebook.txt"),
            vec!["Соцсети Meta"]
        );
    }

    #[tokio::test]
    async fn preset_targets_on_real_corpus() {
        let dir = presets_dir(&repo_resources());
        let presets = list_presets(&dir);
        assert!(!presets.is_empty(), "пресеты читаются из репозитория");
        let all_targets: Vec<String> = presets
            .iter()
            .flat_map(|(_, _, targets)| targets.clone())
            .collect();
        assert!(
            all_targets.iter().any(|t| t == "Discord"),
            "{all_targets:?}"
        );
        assert!(all_targets.iter().any(|t| t == "YouTube"));
        assert!(all_targets.iter().any(|t| t == "Все сайты"));
        // У каждого пресета каталога есть непустой список целей (встроенный
        // каталог подобран под сервисы); fallback «Общий» покрыт
        // синтетическим тестом выше.
    }

    // ── привилегии ───────────────────────────────────────────────────

    /// Поднимает фейковый privd на tmp-сокете (обслуживает соединения,
    /// пока жив слушатель).
    fn spawn_fake_privd(sock: std::path::PathBuf) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(&sock).expect("сокет привязан");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("клон"));
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if writeln!(stream, r#"{{"ok":true}}"#).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    #[tokio::test]
    async fn privilege_endpoint_reports_state_socket_and_helper() {
        let dir = tmpdir("privilege");
        let sock = dir.join("privd.sock");
        let state_dir = dir.join("state");
        let sock_str = sock.to_string_lossy().into_owned();
        let state_str = state_dir.to_string_lossy().into_owned();
        let app = app_with_paths(&FakeExecutor::new(), &sock_str, &state_str);

        // Нет состояния и нет демона: granted=false, needs_prompt=true.
        let (status, answer) = get(crate::router(app.clone()), "/api/ws/privilege").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["granted"], false);
        assert_eq!(answer["needs_prompt"], true);
        assert_eq!(answer["sock"], json!(sock_str));
        let helper = answer["helper"].as_array().expect("helper");
        assert_eq!(helper.len(), 2);
        assert_eq!(helper[1], "privd");
        assert!(helper[0] == "pkexec" || helper[0] == "sudo");

        // Валидное состояние, но демон молчит: granted всё ещё false,
        // needs_prompt уже false.
        save_state(
            &state_dir,
            &PrivilegeState {
                granted: true,
                granted_at_epoch_s: now_epoch_s(),
                helper_path: "privd".to_string(),
            },
        )
        .expect("состояние сохранено");
        let (_, answer) = get(crate::router(app.clone()), "/api/ws/privilege").await;
        assert_eq!(answer["granted"], false);
        assert_eq!(answer["needs_prompt"], false);

        // Живой демон на tmp-сокете: granted=true.
        spawn_fake_privd(sock.clone());
        let (_, answer) = get(crate::router(app.clone()), "/api/ws/privilege").await;
        assert_eq!(answer["granted"], true);
        assert_eq!(answer["needs_prompt"], false);

        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn grant_sync_times_out_without_socket() {
        let dir = tmpdir("grant-timeout");
        let sock = dir.join("never.sock");
        let state_dir = dir.join("state");
        let sock_str = sock.to_string_lossy().into_owned();
        let state_str = state_dir.to_string_lossy().into_owned();
        let error = grant_sync_with(
            &sock_str,
            &state_str,
            Duration::from_millis(500),
            Duration::from_millis(100),
            |_helper| {
                // Помощник жив, но демон так и не поднялся.
                std::process::Command::new("sleep")
                    .arg("5")
                    .spawn()
                    .map_err(|error| error.to_string())
            },
        )
        .expect_err("сокет не появился");
        assert!(error.contains("не отвечает"), "{error}");
        assert!(load_state(&state_dir).expect("читается").is_none());
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn grant_sync_saves_state_when_socket_appears() {
        let dir = tmpdir("grant-ok");
        let sock = dir.join("grant.sock");
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).expect("каталог состояния");
        let sock_for_thread = sock.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            spawn_fake_privd(sock_for_thread);
        });
        let sock_str = sock.to_string_lossy().into_owned();
        let state_str = state_dir.to_string_lossy().into_owned();
        let helper = grant_sync_with(
            &sock_str,
            &state_str,
            Duration::from_secs(3),
            Duration::from_millis(100),
            |_helper| {
                // Фейковый помощник: живёт, пока сокет не поднимется.
                std::process::Command::new("sleep")
                    .arg("5")
                    .spawn()
                    .map_err(|error| error.to_string())
            },
        )
        .expect("повышение прошло");
        assert_eq!(helper[1], "privd");
        let saved = load_state(&state_dir)
            .expect("состояние читается")
            .expect("сохранено");
        assert!(saved.granted);
        assert_eq!(saved.helper_path, "privd");
        assert!(is_valid(&saved, now_epoch_s()));
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn grant_sync_fails_fast_when_helper_exits() {
        let dir = tmpdir("grant-fail");
        let sock = dir.join("grant.sock");
        let state_dir = dir.join("state");
        let sock_str = sock.to_string_lossy().into_owned();
        let state_str = state_dir.to_string_lossy().into_owned();
        let error = grant_sync_with(
            &sock_str,
            &state_str,
            Duration::from_secs(3),
            Duration::from_millis(100),
            |_helper| {
                // Помощник сразу выходит, не подняв демон.
                std::process::Command::new("true")
                    .spawn()
                    .map_err(|error| error.to_string())
            },
        )
        .expect_err("сокет не появился");
        assert!(error.contains("помощник завершился"), "{error}");
        assert!(load_state(&state_dir).expect("читается").is_none());
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn daemon_process_talks_over_ops_protocol() {
        // Ручка DaemonProcess поверх реального протокола: проверяем на
        // fake-исполнителе, что kill/status уходят операциями kill/status.

        struct RecordingOps {
            kill_pids: Mutex<Vec<u32>>,
            status_pids: Mutex<Vec<u32>>,
        }
        impl PrivilegedOps for RecordingOps {
            fn handle(&mut self, request: &str) -> String {
                let value: Value = serde_json::from_str(request.trim()).unwrap();
                match value["op"].as_str() {
                    Some("kill") => {
                        self.kill_pids
                            .lock()
                            .unwrap()
                            .push(value["pid"].as_u64().unwrap() as u32);
                        r#"{"ok":true}"#.to_string()
                    }
                    Some("status") => {
                        self.status_pids
                            .lock()
                            .unwrap()
                            .push(value["pid"].as_u64().unwrap() as u32);
                        r#"{"ok":true,"running":true}"#.to_string()
                    }
                    _ => r#"{"ok":true}"#.to_string(),
                }
            }
        }

        let dir = tmpdir("daemon-handle");
        let sock = dir.join("handle.sock");
        let ops = Arc::new(Mutex::new(RecordingOps {
            kill_pids: Mutex::new(Vec::new()),
            status_pids: Mutex::new(Vec::new()),
        }));
        // Сервер-нитка на 2 соединения, ручки идут через общий ops.
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("сокет");
        let ops_for_server = Arc::clone(&ops);
        use std::io::BufRead;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = std::io::BufReader::new(stream.try_clone().expect("клон"));
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let reply = ops_for_server.lock().unwrap().handle(&line);
                            use std::io::Write;
                            if writeln!(stream, "{reply}").is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let sock_str = sock.to_string_lossy().into_owned();
        let process = DaemonProcess::new(777, sock_str.clone());
        assert_eq!(process.pid(), 777);
        assert!(process.is_running().expect("status"));
        process.kill().expect("kill");

        let recorder = ops.lock().unwrap();
        assert_eq!(*recorder.status_pids.lock().unwrap(), vec![777]);
        assert_eq!(*recorder.kill_pids.lock().unwrap(), vec![777]);
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }
}
