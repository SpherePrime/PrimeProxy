//! Порт `src/diagnostics/run_context.py` — данные одного адреса сайта.
//!
//! - `Probe` — всё, что собрано про один адрес сайта: ответы DNS, попытки
//!   соединения, уточняющие пробы. Выводы из этого (`kind`,
//!   `address_confirmed`, `fingerprint`) считаются здесь же, чистыми свойствами.
//!
//! Тот же файл в python держит и общие для прогона вещи (`Run`: пул потоков,
//! общий срок, «Стоп», учёт эталонных DNS-серверов; `Lane` — очередь с
//! пределом; `Live` и `Steps` — растущий отчёт и ход шагов). Движок и его
//! сетевые пробы портируются следом вместе с ними.
use crate::block_cause::Cause;
use crate::block_kind;
use crate::cert_owner::CertVerdict;
use crate::outside_check::OUTSIDE_DOWN;
use crate::probe_result::{ProbeResult, KIND_CONNECT};
use crate::protocol_probe::ProtocolLine;
use crate::quic_probe::{QuicVerdict, QUIC_OK};
use crate::services::Target;
use crate::verdict::{DnsJudgement, ReachState};
use crate::volume_probe::VolumeVerdict;
use crate::windows_dns_query::DnsAnswer;

/// python `RECHECK_OPENED`.
pub const RECHECK_OPENED: &str = "opened";
/// python `RECHECK_SAME`.
pub const RECHECK_SAME: &str = "same";
/// Сбой, успех и снова сбой: сайт открывается через раз.
pub const RECHECK_UNSTABLE: &str = "unstable";

/// python `Probe` — всё про один адрес сайта.
///
/// По python: числовые поля и строки пустые по умолчанию, ссылки (`dns`,
/// `judgement`…) — «не проверяли».
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub target: Target,
    pub service: String,
    pub host: String,
    pub discovery_note: String,
    pub dns: DnsAnswer,
    /// Сколько из DNS_ATTEMPTS запросов получили «такого сайта нет».
    pub dns_nxdomain: u32,
    pub hosts_ips: Vec<String>,
    pub reference_ips: Vec<String>,
    pub reference_ok: bool,
    pub reference_ipv6: Vec<String>,
    /// HTTPS-запрос к адресу из hosts или DNS системы (проверка сертификата).
    pub local_check: Option<ProbeResult>,
    /// DNS ответил и адресом из эталона, и другим: запрос к этому другому
    /// адресу решает, CDN это или подмена «через раз».
    pub suspect_check: Option<ProbeResult>,
    /// Итоговый запрос «открывается ли» и откуда взят его адрес.
    pub reach: Option<ProbeResult>,
    pub reach_source: String,
    pub attempts: u32,
    /// Была ли запасная попытка по IPv6 и чем она кончилась.
    pub ipv6_result: Option<ProbeResult>,
    pub judgement: Option<DnsJudgement>,
    pub reach_state: ReachState,
    /// Как именно блокируют (по имени сайта, по адресу, страницей провайдера),
    /// если удалось выяснить.
    pub cause: Option<Cause>,
    /// Сайт открылся, но не каждый раз или не по каждому адресу: что именно
    /// шатается. Пусто — стабилен.
    pub unstable: String,
    /// Кто ответил вместо сайта, когда сертификат не прошёл проверку.
    pub cert: Option<CertVerdict>,
    /// Проходит ли QUIC (UDP 443) к этому сайту. None — не проверяли
    /// или проверку сняли.
    pub quic: Option<QuicVerdict>,
    /// Проходит ли по одному соединению больше 16 КБ. None — не проверяли:
    /// сайт не открылся или главная страница и так больше.
    pub volume: Option<VolumeVerdict>,
    /// Тот же адрес по TLS 1.2, TLS 1.3 и HTTP отдельно.
    // Пусто — не проверяли.
    pub protocols: Vec<ProtocolLine>,
    /// Все попытки основного запроса по порядку: (адрес, исход).
    pub tried: Vec<(String, String)>,
    /// Все попытки кончились одинаково: ответа на соединение не было вовсе.
    pub tried_silent: bool,
    /// Адрес из файла hosts не ответил, а настоящий адрес сайта открылся.
    pub hosts_stale: bool,
    /// Чем кончилась повторная проверка поодиночке: `RECHECK_OPENED` — сайт
    /// открылся (первый сбой дала нагрузка самой проверки),
    /// `RECHECK_SAME` — не открылся снова.
    pub rechecked: String,
    /// Что ответил сервер за рубежом («up» / «down», `outside_check`).
    /// Пусто — не спрашивали.
    pub outside: String,
    /// Сколько секунд заняла проверка этого адреса.
    pub seconds: f64,
    /// То же по частям проверки (`protocol_probe::STAGE_TITLES`).
    pub stages: std::collections::BTreeMap<String, f64>,
    /// Эталонные серверы для экрана: подпись, адрес, ok, сколько ответил/не ответил, причина.
    ///
    /// (python держит отчёт эталонных серверов в `Run.reference_report` — здесь
    /// он нужен `problems.rs`, и запись та же; сам учёт по ходу прогона — в engine.)
    pub reference: Vec<ReferenceReport>,
}

/// python `Run.reference_report` — запись о состоянии эталонного DNS-сервера.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceReport {
    pub label: String,
    pub address: String,
    /// Сервер считается недоступным, только если не ответил ни разу.
    pub ok: bool,
    pub answered: u32,
    pub failed: u32,
    pub reason: String,
}

impl ReferenceReport {
    pub fn from(
        label: impl Into<String>,
        address: impl Into<String>,
        ok: bool,
        answered: u32,
        failed: u32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            address: address.into(),
            ok,
            answered,
            failed,
            reason: reason.into(),
        }
    }
}

impl Probe {
    /// python `Probe.mark(stage)` — закончилась часть проверки.
    pub fn mark(&mut self, stage: &str, since_start: f64) {
        *self.stages.entry(stage.to_string()).or_default() =
            (self.stages.get(stage).copied().unwrap_or_default() + since_start * 10.0).round()
                / 10.0;
    }

    /// python `Probe.fingerprint` — Chrome режут, а простое приветствие к тому же адресу проходит.
    pub fn fingerprint(&self) -> bool {
        self.protocols
            .iter()
            .any(|line| line.code == crate::protocol_probe::CODE_FINGERPRINT)
    }

    /// python `Probe.settle_protocols(lines)` — принимает строки дорог.
    pub fn settle_protocols(&mut self, lines: Vec<ProtocolLine>) {
        self.protocols = lines;
    }

    /// python `Probe.address_confirmed` — несоединение перепроверено: молчат все
    /// адреса сайта, и другим путём он не открылся.
    ///
    /// Только тогда оно называется «баном по адресу». Одно неудачное соединение
    /// бывает из-за устаревшей записи в hosts, потерянного пакета или антивируса.
    pub fn address_confirmed(&self) -> bool {
        if self.tried.is_empty() || self.tried.iter().any(|(_ip, kind)| kind != KIND_CONNECT) {
            return false;
        }
        // Отказ адреса и ошибка системы (нет сети, запрет сетевого экрана) — не молчание:
        // так фильтр провайдера адреса не закрывает.
        if !self.tried_silent {
            return false;
        }
        // Нужна перепроверка: второй адрес или повтор на том же после паузы.
        if self.tried.len() < 2 {
            return false;
        }
        // Адреса только из hosts — это проверка записи в hosts, а не сайта.
        if !self.hosts_ips.is_empty()
            && self.tried.iter().all(|(ip, _)| self.hosts_ips.contains(ip))
        {
            return false;
        }
        // QUIC к тому же адресу отвечает — дорога до адреса открыта, браузер сайт откроет.
        if self
            .quic
            .as_ref()
            .is_some_and(|verdict| verdict.code == QUIC_OK)
        {
            return false;
        }
        true
    }

    /// python `Probe.kind` — вид блокировки: по адресу, по имени сайта,
    /// обрыв после 16 КБ… Пусто — сайт открывается.
    pub fn kind(&self) -> String {
        let mut kind = block_kind::site_kind(
            self.reach_state.value(),
            self.cause
                .as_ref()
                .map(|cause| cause.code.as_str())
                .unwrap_or(""),
            self.address_confirmed(),
        );
        // Не открылся и из-за рубежа — не блокировка: сайт не работает сам.
        if !kind.is_empty()
            && self.outside == OUTSIDE_DOWN
            && matches!(self.reach_state, ReachState::IpBlock | ReachState::Dpi)
        {
            kind = block_kind::KIND_DOWN.to_string();
        }
        // Причину пробы не назвали, но простое приветствие проходит, а Chrome — нет.
        if kind == block_kind::KIND_UNCLEAR && self.fingerprint() {
            return block_kind::KIND_FINGERPRINT.to_string();
        }
        kind
    }
}

// ---------------------------------------------------------------------------
// Общие для прогона вещи (python `run_context.py`, нижняя половина)
// ---------------------------------------------------------------------------

use std::any::Any;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use primecore_dnswire::FAILURE_CANCELLED;
use primecore_socketcancel::SocketCancel;

use crate::dns_reference::REFERENCE_RESOLVERS;
use crate::limits::{
    NET_AT_ONCE, NET_AT_ONCE_WEAK, REFERENCE_AT_ONCE, RUN_DEADLINE, SITE_START_GAP_S,
};

/// Ошибка задачи: python-исключение, которое вернул `Future.result`.
///
/// `Stopped` проходит мимо ловушек (`except _Stopped: raise`), `Cancelled` —
/// задачу сняли (строка пустая, как у python), `Failed` — прочий сбой.
#[derive(Debug)]
pub enum TaskError {
    Stopped,
    Cancelled,
    Failed(String),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // str(Stopped()) и str(CancelledError()) в python пустые.
            TaskError::Stopped | TaskError::Cancelled => Ok(()),
            TaskError::Failed(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for TaskError {}

/// Канал итога задачи: python `Future` хранит результат один раз.
pub type TaskSender = mpsc::Sender<Result<Box<dyn Any + Send>, TaskError>>;

/// Замыкание хода проверки: python `progress(шаг, готово, всего)`.
pub type ProgressFn = dyn Fn(&str, u32, u32) + Send + Sync;

/// Замыкание отметки шага: python `note(шаг, закончен)`.
pub type StageNote = dyn Fn(&str, bool) + Send + Sync;

/// Замыкание публикации отчёта: python `partial(отчёт)`.
pub type PublishFn = dyn Fn(&serde_json::Value) + Send + Sync;

/// Замыкание пересчёта «свежих» полей отчёта: python `fresh`.
pub type FreshFn = dyn Fn() -> Vec<(String, serde_json::Value)> + Send + Sync;

/// python `Future` — задание, которое можно ждать и снять.
///
/// Итог кладётся в канал однажды (python `Future` тоже отдаёт результат один
/// раз — повторный `result()` ждёт тот же итог, здесь второй `poll` уже не
/// увидит значения).
pub struct Handle<T> {
    core: Arc<HandleCore>,
    rx: Mutex<mpsc::Receiver<Result<Box<dyn Any + Send>, TaskError>>>,
    _value: std::marker::PhantomData<T>,
}

struct HandleCore {
    cancelled: AtomicBool,
}

impl<T: Send + 'static> Handle<T> {
    fn channel() -> (Arc<HandleCore>, TaskSender, Handle<T>) {
        let core = Arc::new(HandleCore {
            cancelled: AtomicBool::new(false),
        });
        let (tx, rx) = mpsc::channel();
        let handle = Handle {
            core: Arc::clone(&core),
            rx: Mutex::new(rx),
            _value: std::marker::PhantomData,
        };
        (core, tx, handle)
    }

    /// python `future.result(timeout=…)` без поднятия: `None` — ещё не готово.
    pub fn poll(&self, timeout: Duration) -> Option<Result<T, TaskError>> {
        let rx = self.rx.lock().ok()?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(value)) => Some(Ok(*value.downcast::<T>().expect("тип задания"))),
            Ok(Err(error)) => Some(Err(error)),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
        }
    }

    /// python `future.cancel()` — снять задачу, если она ещё не началась.
    pub fn cancel(&self) {
        self.core.cancelled.store(true, Ordering::SeqCst);
    }

    /// python `future.cancelled()`.
    pub fn is_cancelled(&self) -> bool {
        self.core.cancelled.load(Ordering::SeqCst)
    }
}

/// python `ThreadPoolExecutor` — пул потоков с очередью заданий.
struct Pool {
    state: Mutex<PoolState>,
    signal: Condvar,
}

struct PoolState {
    queue: VecDeque<QueuedJob>,
    open: bool,
}

struct QueuedJob {
    /// Снятая до запуска задача получает `Cancelled` вместо молчания.
    fail: Box<dyn FnOnce() + Send>,
    run: Option<Box<dyn FnOnce() + Send>>,
}

impl Pool {
    fn new(workers: usize) -> Arc<Self> {
        let pool = Arc::new(Pool {
            state: Mutex::new(PoolState {
                queue: VecDeque::new(),
                open: true,
            }),
            signal: Condvar::new(),
        });
        for index in 0..workers.max(1) {
            let pool = Arc::clone(&pool);
            let _thread = std::thread::Builder::new()
                .name(format!("diag-{index}"))
                .spawn(move || pool.work())
                .expect("поток пула");
        }
        pool
    }

    fn work(&self) {
        loop {
            let job = {
                let mut state = self.state.lock().expect("замок пула");
                while state.queue.is_empty() && state.open {
                    state = self.signal.wait(state).expect("замок пула");
                }
                match state.queue.pop_front() {
                    Some(job) => job,
                    None => return, // очередь пуста и пул закрыт
                }
            };
            if let Some(run) = job.run {
                run();
            }
        }
    }

    fn push(
        &self,
        core: Arc<HandleCore>,
        fail: Box<dyn FnOnce() + Send>,
        run: Box<dyn FnOnce() + Send>,
    ) {
        let mut state = self.state.lock().expect("замок пула");
        if !state.open {
            drop(state);
            // Пул закрыт («Стоп» или конец прогона): задача не состоится.
            core.cancelled.store(true, Ordering::SeqCst);
            fail();
            return;
        }
        state.queue.push_back(QueuedJob {
            fail,
            run: Some(run),
        });
        drop(state);
        self.signal.notify_one();
    }

    /// python `shutdown(cancel_futures=True)`: ждущие задачи снимаются.
    fn close(&self) {
        let mut state = self.state.lock().expect("замок пула");
        state.open = false;
        let queued: Vec<QueuedJob> = state.queue.drain(..).collect();
        drop(state);
        self.signal.notify_all();
        for job in queued {
            (job.fail)();
        }
    }
}

/// Развернуть панику задачи в python-подобное исключение.
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "task panicked".to_string())
}

/// Запуск задачи с ловлей паники: python кладёт исключение в `Future`.
fn run_task<T: Send + 'static>(
    core: &Arc<HandleCore>,
    tx: TaskSender,
    job: impl FnOnce() -> Result<T, TaskError>,
) {
    if core.cancelled.load(Ordering::SeqCst) {
        let _ = tx.send(Err(TaskError::Cancelled));
        return;
    }
    let result = match catch_unwind(AssertUnwindSafe(job)) {
        Ok(result) => result,
        Err(payload) => Err(TaskError::Failed(panic_message(payload))),
    };
    let _ = tx.send(result.map(|value| Box::new(value) as Box<dyn Any + Send>));
}

/// То же для отложенных задач, чей итог уже упакован в `Any`.
fn run_task_boxed(core: &Arc<HandleCore>, tx: TaskSender, job: StagedJob) {
    if core.cancelled.load(Ordering::SeqCst) {
        let _ = tx.send(Err(TaskError::Cancelled));
        return;
    }
    let result = match catch_unwind(AssertUnwindSafe(job)) {
        Ok(result) => result,
        Err(payload) => Err(TaskError::Failed(panic_message(payload))),
    };
    let _ = tx.send(result);
}

/// python `fn(*args, **kwargs)` отложенной задачи: итог уже упакован.
type StagedJob = Box<dyn FnOnce() -> Result<Box<dyn Any + Send>, TaskError> + Send>;

/// python `Lane` — очередь задач с пределом «не больше `limit` одновременно».
///
/// Задача, которой ещё не пришла очередь, просто лежит в списке и потока не
/// занимает.
pub struct Lane {
    pool: Arc<Pool>,
    limit: usize,
    state: Mutex<LaneState>,
}

struct LaneState {
    waiting: VecDeque<StagedWaiting>,
    running: usize,
    closed: bool,
}

struct StagedWaiting {
    core: Arc<HandleCore>,
    tx: TaskSender,
    job: StagedJob,
}

impl Lane {
    fn new(pool: Arc<Pool>, limit: usize) -> Arc<Self> {
        Arc::new(Lane {
            pool,
            limit: limit.max(1),
            state: Mutex::new(LaneState {
                waiting: VecDeque::new(),
                running: 0,
                closed: false,
            }),
        })
    }

    /// python `lane.submit(fn, *args, **kwargs)`.
    pub fn submit<T, F>(self: &Arc<Self>, job: F) -> Handle<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, TaskError> + Send + 'static,
    {
        let (core, tx, handle) = Handle::channel();
        let mut state = self.state.lock().expect("замок очереди");
        if state.closed {
            drop(state);
            core.cancelled.store(true, Ordering::SeqCst);
            let _ = tx.send(Err(TaskError::Cancelled));
            return handle;
        }
        state.waiting.push_back(StagedWaiting {
            core,
            tx,
            job: Box::new(move || job().map(|value| Box::new(value) as Box<dyn Any + Send>)),
        });
        drop(state);
        self.pump();
        handle
    }

    fn pump(self: &Arc<Self>) {
        loop {
            let item = {
                let mut state = self.state.lock().expect("замок очереди");
                if state.closed || state.running >= self.limit {
                    return;
                }
                let Some(item) = state.waiting.pop_front() else {
                    return;
                };
                state.running += 1;
                item
            };
            let StagedWaiting { core, tx, job } = item;
            // Задача держит очередь через слабую ссылку: когда прогон снят,
            // досчитывать некому — и взаимной блокировки на закрытии нет.
            let lane = Arc::downgrade(self);
            let runner = move || {
                if let Some(lane) = lane.upgrade() {
                    run_task_boxed(&core, tx, job);
                    if let Ok(mut state) = lane.state.lock() {
                        state.running -= 1;
                    }
                    lane.pump();
                }
            };
            self.pool.push(
                Arc::new(HandleCore {
                    cancelled: AtomicBool::new(false),
                }),
                Box::new(|| {}),
                Box::new(runner),
            );
        }
    }

    /// python `lane.close()`: ждущие задачи снимаются.
    fn close(&self) {
        let mut state = self.state.lock().expect("замок очереди");
        state.closed = true;
        let waiting: Vec<_> = state.waiting.drain(..).collect();
        drop(state);
        for StagedWaiting { core, tx, job: _ } in waiting {
            core.cancelled.store(true, Ordering::SeqCst);
            let _ = tx.send(Err(TaskError::Cancelled));
        }
    }
}

/// python `Steps` — ход проверки по шагам: сообщает экрану и запоминает,
/// сколько шёл каждый шаг.
pub struct Steps {
    progress: Option<Arc<ProgressFn>>,
    times: Mutex<BTreeMap<String, (f64, f64)>>,
}

impl Steps {
    pub fn new(progress: Option<Arc<ProgressFn>>) -> Self {
        Steps {
            progress,
            times: Mutex::new(BTreeMap::new()),
        }
    }

    /// python `step(шаг, готово, всего)`; сбой обработки на экране не роняет проверку.
    pub fn step(&self, name: &str, done: u32, total: u32) {
        let now = clock_now();
        if let Ok(mut times) = self.times.lock() {
            times
                .entry(name.to_string())
                .and_modify(|pair| pair.1 = now)
                .or_insert((now, now));
        }
        if let Some(progress) = &self.progress {
            progress(name, done, total);
        }
    }

    /// python `seconds()` — сколько шёл каждый шаг.
    pub fn seconds(&self) -> BTreeMap<String, f64> {
        self.times
            .lock()
            .map(|times| {
                times
                    .iter()
                    .map(|(name, (first, last))| {
                        (name.clone(), crate::report_text::py_round1(last - first))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// python `line(titles)` — строка «⏱ По шагам: …» для конца отчёта.
    pub fn line(&self) -> String {
        let seconds = self.seconds();
        let parts: Vec<String> = seconds
            .iter()
            .map(|(name, value)| {
                format!(
                    "{} {} с",
                    crate::report_text::step_title(name),
                    crate::report_text::py_round0(*value)
                )
            })
            .collect();
        if parts.is_empty() {
            String::new()
        } else {
            format!("⏱ По шагам: {}", parts.join(" · "))
        }
    }
}

/// python `time.monotonic()` — секунды от произвольной точки.
pub fn clock_now() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// python `Live` — отчёт, который растёт по ходу проверки: единственное место,
/// где лежит её итог.
///
/// Каждый раздел кладётся сюда, как только готов (`put`), и тут же уходит
/// наружу — экран рисует его сразу, не дожидаясь конца проверки. Итоговый
/// отчёт — это тот же словарь, а не отдельная сборка.
pub struct Live {
    publish: Option<Arc<PublishFn>>,
    fresh: Option<Arc<FreshFn>>,
    data: Mutex<serde_json::Map<String, serde_json::Value>>,
}

impl Live {
    pub fn new(
        publish: Option<Arc<PublishFn>>,
        fresh: Option<Arc<FreshFn>>,
        start: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Live {
            publish,
            fresh,
            data: Mutex::new(start),
        }
    }

    /// python `put(**parts)` — разделы кладут и рабочие потоки, поэтому под замком.
    ///
    /// Возвращает снимок отчёта: получатель не должен видеть, как словарь
    /// дополняется дальше.
    pub fn put(
        &self,
        parts: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> serde_json::Value {
        let snapshot = {
            let Ok(mut data) = self.data.lock() else {
                return serde_json::Value::Null;
            };
            for (key, value) in parts {
                data.insert(key, value);
            }
            if let Some(fresh) = &self.fresh {
                for (key, value) in fresh() {
                    data.insert(key, value);
                }
            }
            serde_json::Value::Object(data.clone())
        };
        if let Some(publish) = &self.publish {
            publish(&snapshot);
        }
        snapshot
    }
}

struct ReferenceEntry {
    answered: u32,
    failed: u32,
    reason: String,
}

struct RunState {
    user_stopped: bool,
    timed_out: bool,
}

/// python `Run` — общие для одного прогона пул потоков, дедлайн и отмена.
///
/// «Стоп» пользователя и истёкший общий лимит — разные вещи: после «Стопа»
/// отчёт не печатается, а по лимиту незавершённые запросы снимаются, и отчёт
/// выводится с пометкой, что часть проверок не успела.
pub struct Run {
    should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    state: Mutex<RunState>,
    /// python `run.probe_cancel` — общий «Стоп» сетевых проб.
    pub probe_cancel: Arc<SocketCancel>,
    pool: Arc<Pool>,
    lanes: Mutex<Vec<Arc<Lane>>>,
    /// Шаг → отложенные задачи: (канал итога, функция, признак запуска).
    staged: Mutex<HashMap<String, Vec<StagedTask>>>,
    /// Эталонный сервер → [сколько раз ответил, сколько раз нет, последняя причина].
    reference: Mutex<HashMap<usize, ReferenceEntry>>,
    /// python `run.deadline_seconds`.
    pub deadline_seconds: f64,
    deadline: Instant,
    closed: AtomicBool,
    start_lock: Mutex<f64>,
    /// Вопросы к эталонным DNS-серверам: каждый — отдельное шифрованное соединение.
    pub reference_lane: Arc<Lane>,
    /// Мелкие пробы сайтов — общий предел на прогон. Сюда идут только «листья»:
    /// задача из этой очереди не ждёт другую задачу из неё же, иначе взаимная блокировка.
    pub net_lane: Arc<Lane>,
}

struct StagedTask {
    core: Arc<HandleCore>,
    tx: TaskSender,
    job: StagedJob,
}

impl Run {
    pub fn new(
        should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
        workers: usize,
        deadline: Option<f64>,
    ) -> Arc<Self> {
        let pool = Pool::new(workers);
        let probe_cancel = Arc::new(SocketCancel::new());
        let reference_lane = Lane::new(Arc::clone(&pool), REFERENCE_AT_ONCE as usize);
        let net_lane_limit =
            if std::thread::available_parallelism().map_or(true, |count| count.get() <= 2) {
                NET_AT_ONCE_WEAK
            } else {
                NET_AT_ONCE
            } as usize;
        let net_lane = Lane::new(Arc::clone(&pool), net_lane_limit);
        let deadline_seconds = deadline.unwrap_or(RUN_DEADLINE);
        Arc::new_cyclic(|weak: &std::sync::Weak<Run>| {
            let watch = weak.clone();
            let _thread = std::thread::Builder::new()
                .name("diag-watch".to_string())
                .spawn(move || {
                    // «Стоп» и срок закрывают сокеты сразу, чем бы ни был занят
                    // главный поток: раньше их замечал только тот, кто сам спросил.
                    while !watch
                        .upgrade()
                        .is_some_and(|run| run.closed.load(Ordering::SeqCst))
                    {
                        std::thread::sleep(Duration::from_secs_f64(0.1));
                        let Some(run) = watch.upgrade() else { return };
                        if run.stopped() || run.expired() {
                            return;
                        }
                    }
                })
                .expect("поток-наблюдатель");
            Run {
                should_stop,
                state: Mutex::new(RunState {
                    user_stopped: false,
                    timed_out: false,
                }),
                probe_cancel,
                pool,
                lanes: Mutex::new(Vec::new()),
                staged: Mutex::new(HashMap::new()),
                reference: Mutex::new(HashMap::new()),
                deadline_seconds,
                deadline: Instant::now() + Duration::from_secs_f64(deadline_seconds),
                closed: AtomicBool::new(false),
                start_lock: Mutex::new(0.0),
                reference_lane,
                net_lane,
            }
        })
    }

    /// python `submit(fn, *args, **kwargs)`.
    pub fn submit<T, F>(&self, job: F) -> Handle<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, TaskError> + Send + 'static,
    {
        let (core, tx, handle) = Handle::channel();
        let fail_tx = tx.clone();
        let fail: Box<dyn FnOnce() + Send> = Box::new(move || {
            let _ = fail_tx.send(Err(TaskError::Cancelled));
        });
        self.pool.push(
            Arc::clone(&core),
            fail,
            Box::new(move || run_task(&core, tx, job)),
        );
        handle
    }

    /// python `lane(limit)` — очередь для однотипных задач.
    pub fn lane(&self, limit: usize) -> Arc<Lane> {
        let lane = Lane::new(Arc::clone(&self.pool), limit);
        if let Ok(mut lanes) = self.lanes.lock() {
            lanes.push(Arc::clone(&lane));
        }
        lane
    }

    /// python `later(stage, fn, *args, **kwargs)` — откладывает задачу до своего
    /// шага (`start_stages`). Итог придёт в возвращённый `Handle`.
    pub fn later<T, F>(&self, stage: &str, job: F) -> Handle<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, TaskError> + Send + 'static,
    {
        let (core, tx, handle) = Handle::channel();
        if let Ok(mut staged) = self.staged.lock() {
            staged
                .entry(stage.to_string())
                .or_default()
                .push(StagedTask {
                    core,
                    tx,
                    job: Box::new(move || {
                        job().map(|value| Box::new(value) as Box<dyn Any + Send>)
                    }),
                });
        }
        handle
    }

    /// python `start_stages(order, note)` — запускает отложенные задачи шаг за
    /// шагом: следующий шаг ждёт конца предыдущего.
    ///
    /// Внутри шага его задачи идут вместе. `note(шаг, закончен)` зовётся в начале
    /// и в конце шага — так экран показывает «идёт» и «готово» в тот момент,
    /// когда это происходит, а шаги не мешают друг другу и не грузят компьютер
    /// все разом.
    pub fn start_stages(&self, order: &[&str], note: Arc<StageNote>) {
        let tasks: Vec<(String, Vec<StagedTask>)> = {
            let Ok(mut staged) = self.staged.lock() else {
                return;
            };
            order
                .iter()
                .filter_map(|stage| {
                    staged
                        .remove(*stage)
                        .map(|tasks| ((*stage).to_string(), tasks))
                })
                .collect()
        };
        let pool = Arc::clone(&self.pool);
        let _ = self.submit(move || -> Result<(), TaskError> {
            for (stage, stage_tasks) in tasks {
                note(&stage, false);
                let left = Arc::new((Mutex::new(stage_tasks.len()), Condvar::new()));
                for StagedTask { core, tx, job } in stage_tasks {
                    let counter = Arc::clone(&left);
                    let fail_tx = tx.clone();
                    let fail: Box<dyn FnOnce() + Send> = Box::new(move || {
                        let _ = fail_tx.send(Err(TaskError::Cancelled));
                    });
                    let push_core = Arc::clone(&core);
                    let done = move || {
                        run_task_boxed(&core, tx, job);
                        if let Ok(mut count) = counter.0.lock() {
                            *count -= 1;
                            counter.1.notify_all();
                        }
                    };
                    pool.push(push_core, fail, Box::new(done));
                }
                // Шаги идут по очереди: следующий ждёт конца предыдущего.
                let (lock_count, signal) = &*left;
                let mut count = lock_count.lock().expect("замок шага");
                while *count > 0 {
                    let (waited, _) = signal
                        .wait_timeout(count, Duration::from_secs_f64(0.1))
                        .expect("замок шага");
                    count = waited;
                }
                note(&stage, true);
            }
            Ok(())
        });
    }

    /// python `stopped()` — «Стоп» пользователя (запоминается и отменяет пробы).
    pub fn stopped(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.user_stopped {
            return true;
        }
        if let Some(should_stop) = &self.should_stop {
            if should_stop() {
                state.user_stopped = true;
                self.probe_cancel.cancel();
                return true;
            }
        }
        false
    }

    /// python `expired()` — истёк общий лимит: незавершённые запросы снимаются.
    pub fn expired(&self) -> bool {
        if Instant::now() < self.deadline {
            return false;
        }
        if let Ok(mut state) = self.state.lock() {
            if !state.timed_out {
                state.timed_out = true;
                // Всё, что ещё висит, снимаем: запросы и DNS вернутся сразу.
                self.probe_cancel.cancel();
            }
        }
        true
    }

    /// python `dns_cancelled()` — «Стоп» или общий лимит.
    pub fn dns_cancelled(&self) -> bool {
        self.stopped() || self.expired()
    }

    /// python `pause(seconds)` — пауза, которую снимают «Стоп» и общий лимит
    /// времени. `false` — проверку сняли.
    pub fn pause(&self, seconds: f64) -> bool {
        let deadline = Instant::now() + Duration::from_secs_f64(seconds.max(0.0));
        while !self.dns_cancelled() {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64();
            if remaining <= 0.0 {
                return true;
            }
            self.probe_cancel.sleep(0.1_f64.min(remaining));
        }
        false
    }

    /// python `wait_start_turn()` — сайт ждёт своей очереди на старт: между
    /// стартами — случайная пауза `SITE_START_GAP_S`. `false` — проверку сняли.
    ///
    /// Без неё все сайты начинались в одну и ту же долю секунды, каждый раз
    /// одинаково, а такой узор сам выдаёт проверяльщика.
    pub fn wait_start_turn(&self) -> bool {
        let now = clock_now();
        let start = {
            let Ok(mut next_start) = self.start_lock.lock() else {
                return false;
            };
            let start = now.max(*next_start);
            let (low, high) = SITE_START_GAP_S;
            *next_start = start + low + fastrand::f64() * (high - low);
            start
        };
        self.probe_cancel.sleep(start - now)
    }

    /// python `note_reference(resolver, result)` — учёт ответов эталонных
    /// DNS-серверов. Снятый запрос ничего о сервере не говорит.
    pub fn note_reference(&self, resolver: usize, result: &primecore_dnswire::DnsQueryResult) {
        if result.failure == FAILURE_CANCELLED {
            return;
        }
        if let Ok(mut reference) = self.reference.lock() {
            let entry = reference.entry(resolver).or_insert(ReferenceEntry {
                answered: 0,
                failed: 0,
                reason: String::new(),
            });
            if result.answered() {
                entry.answered += 1;
            } else {
                entry.failed += 1;
                entry.reason = result.failure_text();
            }
        }
    }

    /// python `reference_report()` — состояние эталонных серверов за прогон,
    /// в постоянном порядке.
    pub fn reference_report(&self) -> Vec<ReferenceReport> {
        let seen = self
            .reference
            .lock()
            .map(|reference| {
                reference
                    .iter()
                    .map(|(index, entry)| {
                        (*index, (entry.answered, entry.failed, entry.reason.clone()))
                    })
                    .collect::<HashMap<usize, (u32, u32, String)>>()
            })
            .unwrap_or_default();
        let mut report = Vec::new();
        for (index, resolver) in REFERENCE_RESOLVERS.iter().enumerate() {
            let Some((answered, failed, reason)) = seen.get(&index).cloned() else {
                continue;
            };
            report.push(ReferenceReport::from(
                resolver.label,
                resolver.address,
                answered > 0,
                answered,
                failed,
                if answered == 0 { reason } else { String::new() },
            ));
        }
        report
    }

    /// python `wait(future)` — ждёт результат, не пропуская «Стоп» и общий дедлайн.
    pub fn wait<T: Send + 'static>(&self, handle: &Handle<T>) -> Result<T, TaskError> {
        loop {
            if self.stopped() {
                return Err(TaskError::Stopped);
            }
            self.expired();
            if let Some(result) = handle.poll(Duration::from_secs_f64(0.1)) {
                return result;
            }
        }
    }

    /// python `close()` — конец прогона: «Стоп» всем задачам, очереди закрыты.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.probe_cancel.cancel();
        if let Ok(lanes) = self.lanes.lock() {
            for lane in lanes.iter() {
                lane.close();
            }
        }
        self.reference_lane.close();
        self.net_lane.close();
        self.pool.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with(tried: Vec<(&'static str, &str)>) -> Probe {
        Probe {
            tried: tried
                .iter()
                .map(|(ip, kind)| (ip.to_string(), kind.to_string()))
                .collect(),
            tried_silent: true,
            ..Default::default()
        }
    }

    #[test]
    fn address_confirmed_rules() {
        let empty = Probe::default();
        assert!(!empty.address_confirmed());
        // Одно соединение: перепроверки не было.
        let single = probe_with(vec![("1.2.3.4", KIND_CONNECT)]);
        assert!(!single.address_confirmed());
        let double = probe_with(vec![("1.2.3.4", KIND_CONNECT), ("3.3.3.3", KIND_CONNECT)]);
        assert!(double.address_confirmed());
        // Не молчали вовсе (отказ или ошибка) — не считаем.
        assert!(!Probe {
            tried_silent: false,
            ..double.clone()
        }
        .address_confirmed());
        // QUIC к тому же адресу прошёл: дорога открыта.
        let with_quic = Probe {
            quic: Some(QuicVerdict {
                code: QUIC_OK.to_string(),
                text: "отвечает".to_string(),
            }),
            ..double.clone()
        };
        assert!(!with_quic.address_confirmed());
    }

    #[test]
    fn hosts_only_tried_not_confirmed() {
        // Адреса только из hosts — проверка записи, а не сайта.
        let only_hosts = Probe {
            hosts_ips: vec!["1.2.3.4".to_string(), "3.3.3.3".to_string()],
            tried: probe_with(vec![("1.2.3.4", KIND_CONNECT), ("3.3.3.3", KIND_CONNECT)]).tried,
            tried_silent: true,
            ..Default::default()
        };
        assert!(!only_hosts.address_confirmed());
        // Настоящий адрес сайта среди проб — считается.
        let real = Probe {
            hosts_ips: vec!["1.2.3.4".to_string()],
            ..only_hosts.clone()
        };
        assert!(real.address_confirmed());
    }

    #[test]
    fn kind_fingerprint_and_down() {
        // DPI без причины → «unclear», а с пройденным простым приветствием (fingerprint) — особый вид.
        let mut value = Probe {
            reach_state: ReachState::Dpi,
            ..Default::default()
        };
        assert_eq!(value.kind(), block_kind::KIND_UNCLEAR);
        value.protocols = vec![crate::protocol_probe::ProtocolLine {
            code: crate::protocol_probe::CODE_FINGERPRINT.to_string(),
            ..Default::default()
        }];
        assert_eq!(value.kind(), block_kind::KIND_FINGERPRINT);
        // Не открылся и из-за рубежа — сайт не работает сам.
        let mut down = Probe {
            reach_state: ReachState::IpBlock,
            outside: OUTSIDE_DOWN.to_string(),
            ..Default::default()
        };
        down.settle_protocols(Vec::new());
        assert_eq!(down.tried.len(), 0);
        down.tried = vec![
            ("1.2.3.4".to_string(), KIND_CONNECT.to_string()),
            ("1.1.1.1".to_string(), KIND_CONNECT.to_string()),
        ];
        down.tried_silent = true;
        assert_eq!(down.kind(), block_kind::KIND_DOWN);
        let abroad = Probe {
            reach_state: ReachState::IpBlock,
            outside: crate::outside_check::OUTSIDE_UP.to_string(),
            ..down.clone()
        };
        assert_eq!(abroad.kind(), block_kind::KIND_IP);
    }

    #[test]
    fn fingerprint_property() {
        assert!(!Probe::default().fingerprint());
        let mut value = Probe::default();
        let mut line = crate::protocol_probe::tls_line(
            crate::protocol_probe::PROTO_BROWSER,
            Some(&crate::block_cause::HelloResult::new(
                crate::block_cause::HELLO_OK,
            )),
        )
        .unwrap();
        line.code = crate::protocol_probe::CODE_FINGERPRINT.to_string();
        value.settle_protocols(vec![line.clone()]);
        assert!(value.fingerprint());
    }

    // Тесты машины прогона — в общем модуле тестов ниже.

    #[cfg(test)]
    mod run_tests {
        use super::*;
        use std::sync::atomic::AtomicUsize;

        fn run_simple() -> Arc<Run> {
            Run::new(None, 4, None)
        }

        #[test]
        fn submit_and_wait() {
            let run = run_simple();
            let handle = run.submit(|| Ok::<_, TaskError>(41));
            assert_eq!(run.wait(&handle).expect("итог"), 41);
            // Сбой задачи превращается в ошибку, а не в панику ждущего.
            let failed = run.submit(|| Err::<u32, _>(TaskError::Failed("сломалось".to_string())));
            match run.wait(&failed) {
                Err(TaskError::Failed(message)) => assert_eq!(message, "сломалось"),
                other => panic!("ожидался сбой: {other:?}"),
            }
            run.close();
        }

        #[test]
        fn stopped_run_raises_stopped() {
            let stopped_flag = Arc::new(AtomicBool::new(true));
            let flag = Arc::clone(&stopped_flag);
            let run = Run::new(Some(Arc::new(move || flag.load(Ordering::SeqCst))), 2, None);
            let handle = run.submit(|| Ok::<u32, TaskError>(1));
            match run.wait(&handle) {
                Err(TaskError::Stopped) => {}
                other => panic!("ожидался Stopped: {other:?}"),
            }
            run.close();
        }

        #[test]
        fn lane_limits_concurrency() {
            let run = run_simple();
            let lane = run.lane(2);
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..6 {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                handles.push(lane.submit(move || {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(30));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<(), TaskError>(())
                }));
            }
            for handle in &handles {
                let _ = run.wait(handle);
            }
            assert!(peak.load(Ordering::SeqCst) <= 2, "пик {peak:?}");
            run.close();
        }

        #[test]
        fn lane_close_cancels_waiting() {
            let run = run_simple();
            // Занимаем единственное место в очереди долгой задачей.
            let lane = run.lane(1);
            let busy = lane.submit(|| {
                std::thread::sleep(Duration::from_millis(150));
                Ok::<(), TaskError>(())
            });
            let queued = lane.submit(|| Ok::<(), TaskError>(()));
            lane.close();
            let _ = run.wait(&busy);
            match run.wait(&queued) {
                Err(TaskError::Cancelled) => {}
                other => panic!("ожидался Cancelled: {other:?}"),
            }
            run.close();
        }

        #[test]
        fn later_and_start_stages_run_in_order() {
            let run = run_simple();
            let order = Arc::new(Mutex::new(Vec::<String>::new()));
            let first = {
                let order = Arc::clone(&order);
                run.later::<u32, _>("a", move || {
                    order.lock().unwrap().push("a".to_string());
                    Ok(1)
                })
            };
            let second = {
                let order = Arc::clone(&order);
                run.later::<u32, _>("b", move || {
                    order.lock().unwrap().push("b".to_string());
                    Ok(2)
                })
            };
            let notes = Arc::new(Mutex::new(Vec::<(String, bool)>::new()));
            let note = {
                let notes = Arc::clone(&notes);
                Arc::new(move |stage: &str, finished: bool| {
                    notes.lock().unwrap().push((stage.to_string(), finished));
                })
            };
            run.start_stages(&["a", "b"], note);
            assert_eq!(run.wait(&first).expect("a"), 1);
            assert_eq!(run.wait(&second).expect("b"), 2);
            // Итог шага «b» отмечается после отсылки результата задачи — как и в python.
            let seen = loop {
                let seen = notes.lock().unwrap().clone();
                if seen.len() >= 4 {
                    break seen;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(
                seen,
                vec![
                    ("a".to_string(), false),
                    ("a".to_string(), true),
                    ("b".to_string(), false),
                    ("b".to_string(), true)
                ]
            );
            run.close();
        }

        #[test]
        fn steps_track_seconds() {
            let steps = Steps::new(None);
            steps.step("sites", 0, 2);
            std::thread::sleep(Duration::from_millis(30));
            steps.step("sites", 1, 2);
            steps.step("ipv6", 1, 1);
            let seconds = steps.seconds();
            assert!(seconds["sites"] >= 0.0);
            assert!(seconds.contains_key("ipv6"));
            let line = steps.line();
            assert!(line.starts_with("⏱ По шагам: "));
            assert!(line.contains("сайты"), "{line}");
            assert!(line.contains("IPv6"), "{line}");
        }

        #[test]
        fn live_publishes_snapshot() {
            let published: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&published);
            let live = Live::new(
                Some(Arc::new(move |value: &serde_json::Value| {
                    sink.lock().unwrap().push(value.clone());
                })),
                None,
                serde_json::Map::new(),
            );
            live.put([("services".to_string(), serde_json::json!([]))]);
            let snapshot = live.put([
                ("voice".to_string(), serde_json::json!({"level": "ok"})),
                ("partial".to_string(), serde_json::Value::Bool(true)),
            ]);
            assert_eq!(snapshot["voice"]["level"], "ok");
            let seen = published.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[1]["partial"], serde_json::Value::Bool(true));
        }

        #[test]
        fn reference_accounting() {
            use primecore_dnswire::{DnsQueryResult, RCODE_OK};
            let run = run_simple();
            let answered = DnsQueryResult {
                status: RCODE_OK.to_string(),
                rcode: Some(RCODE_OK),
                ..Default::default()
            };
            run.note_reference(0, &answered);
            let failed = DnsQueryResult {
                failure: "timeout".to_string(),
                ..Default::default()
            };
            run.note_reference(1, &failed);
            run.note_reference(1, &failed);
            // Снятый запрос ничего не говорит о сервере.
            let cancelled = DnsQueryResult {
                failure: primecore_dnswire::FAILURE_CANCELLED.to_string(),
                ..Default::default()
            };
            run.note_reference(1, &cancelled);
            let report = run.reference_report();
            assert_eq!(report.len(), 2, "только тронутые серверы");
            assert_eq!(report[0].label, REFERENCE_RESOLVERS[0].label);
            assert!(report[0].ok);
            assert_eq!(report[0].answered, 1);
            assert!(!report[1].ok);
            assert_eq!(report[1].failed, 2);
            assert_eq!(report[1].reason, "сервер молчит");
            run.close();
        }

        #[test]
        fn pause_survives_without_stop() {
            let run = run_simple();
            assert!(run.pause(0.01), "короткая пауза проходит");
            run.close();
        }

        #[test]
        fn expired_cancels_and_marks() {
            let run = Run::new(None, 2, Some(0.01));
            std::thread::sleep(Duration::from_millis(30));
            assert!(run.expired());
            assert!(run.dns_cancelled());
            run.close();
        }
    }
}
