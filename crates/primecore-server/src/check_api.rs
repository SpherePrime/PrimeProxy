//! Проверка обхода (blockcheck): доступность сайтов по HTTPS.
//!
//! Порт идеи python-эталона `blockcheck` (`data_lists.HTTPS_TARGETS`,
//! `models.TestStatus`, фоновый воркер с частичными результатами): список
//! целей спрашивается HTTPS-запросами «как браузер», по каждой цели
//! собирается статус (`ok` / `slow` / `blocked`), время ответа и пояснение.
//!
//! Отличия от эталона (осознанные): python-проверка ходит через `curl_cffi`
//! с отпечатком ClientHello Chrome — Rust-крейт TLS-отпечатков не умеет,
//! поэтому запрос идёт обычным `reqwest` (blocking). Для blocked-статуса
//! этого достаточно: отказ соединения, сброс и таймаут видны и без
//! отпечатка; тонкие различия «пропустил пакет с другим ClientHello»
//! остаются за настоящим браузером.
//!
//! Прогон фоновый: `POST /api/check/sites` запускает задачу и сразу
//! отвечает; результаты по мере готовности отдаёт `GET
//! /api/check/sites/status` (как «частичный отчёт» воркера эталона).
//! Сетевые руки спрятаны за трейтом [`SiteProber`]: живой сервер ставит
//! [`RealProber`], тесты — фейк, сеть в тестах не трогается.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ws_api::now_epoch_s;

/// Таймаут одной попытки HTTPS-запроса.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Считать «медленно» ответы дольше этого срока (мс).
const SLOW_MS: u64 = 2000;
/// Сколько попыток на домен: блокировка иногда включается не с первой.
const ATTEMPTS: usize = 2;
/// Пауза между попытками.
const RETRY_PAUSE: Duration = Duration::from_millis(300);
/// Предел списка доменов в одном прогоне.
const MAX_DOMAINS: usize = 32;

/// Дефолтный набор целей: основные проверяемые сайты (как в python-эталоне
/// `blockcheck/data_lists.py::HTTPS_TARGETS`) плюс домены из листов
/// `resources/lists` (`rutracker.txt`, `twitter.txt`, `linkedin.txt`).
pub const DEFAULT_DOMAINS: [&str; 11] = [
    "www.youtube.com",
    "discord.com",
    "gateway.discord.gg",
    "chatgpt.com",
    "www.google.com",
    "www.twitch.tv",
    "instagram.com",
    "store.steampowered.com",
    "rutracker.org",
    "x.com",
    "www.linkedin.com",
];

// ─────────────────────────── модель пробы ──────────────────────────────

/// Итог пробы одного домена: статус, время ответа, пояснение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// Итоговый статус: `ok`, `slow` или `blocked`.
    pub status: String,
    /// Время лучшего удачного ответа, мс (у blocked — нет).
    pub ms: Option<u64>,
    /// Код ответа или текст последней ошибки.
    pub detail: String,
}

/// Вид сетевой ошибки одной попытки (python `net_failure.classify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// Ответ не пришёл за таймаут.
    Timeout,
    /// Соединение не установилось (отказ, недоступность, DNS).
    Connect,
    /// Соединение оборвано (reset) или прочий сбой.
    Other,
}

/// Исход одной попытки (python `TestStatus` в терминах пробы сайта).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    /// Ответ пришёл быстро.
    Ok,
    /// Ответ пришёл, но медленно (дольше [`SLOW_MS`]).
    Slow,
    /// Ответа нет: ошибка сети или код вне 2xx/3xx.
    Failed,
}

/// Классификация одной попытки по коду ответа, времени и ошибке.
///
/// Любой код HTTP означает, что транспорт до сайта работает (2xx/3xx —
/// `ok`; 4xx/5xx — тоже ответ сервера, а не блокировка канала: у части
/// сайтов обычное состояние — 403/429). Блокировка — это отказ соединения,
/// сброс или таймаут, и она решается на уровне попыток ([`combine_attempts`]).
#[must_use]
pub fn attempt_status(code: Option<u16>, ms: u64, error: Option<ProbeError>) -> AttemptStatus {
    match (error, code) {
        (Some(_), _) | (None, None) => AttemptStatus::Failed,
        (None, Some(_)) if ms > SLOW_MS => AttemptStatus::Slow,
        (None, Some(_)) => AttemptStatus::Ok,
    }
}

/// Итог по всем попыткам домена: все неудачные — `blocked`, иначе статус
/// лучшей удачной попытки.
#[must_use]
pub fn combine_attempts(attempts: &[AttemptStatus]) -> String {
    if attempts.is_empty()
        || attempts
            .iter()
            .all(|attempt| *attempt == AttemptStatus::Failed)
    {
        return "blocked".to_string();
    }
    if attempts.contains(&AttemptStatus::Ok) {
        "ok".to_string()
    } else {
        "slow".to_string()
    }
}

/// Сетевые руки проверки: проба одного домена. Сеть в тестах не трогается —
/// фейк подставляет заготовленные [`ProbeResult`].
pub trait SiteProber: Send + Sync {
    /// Проба одного домена: HTTPS-запрос с таймаутом, замер времени.
    fn probe(&self, domain: &str) -> ProbeResult;
}

/// Живые руки: `reqwest` (blocking), HEAD `https://<домен>`, таймаут 5 с,
/// [`ATTEMPTS`] попытки с паузой.
pub struct RealProber;

impl SiteProber for RealProber {
    fn probe(&self, domain: &str) -> ProbeResult {
        let client = match reqwest::blocking::Client::builder()
            .user_agent("PrimeBypass-BlockCheck/1.0")
            .connect_timeout(PROBE_TIMEOUT)
            .timeout(PROBE_TIMEOUT)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                return ProbeResult {
                    status: "blocked".to_string(),
                    ms: None,
                    detail: format!("клиент HTTPS не собрался: {error}"),
                }
            }
        };
        let mut attempts = Vec::with_capacity(ATTEMPTS);
        let mut last_error = String::new();
        let mut best_ms: Option<u64> = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(RETRY_PAUSE);
            }
            let started = std::time::Instant::now();
            match client.head(format!("https://{domain}/")).send() {
                Ok(response) => {
                    let ms = started.elapsed().as_millis() as u64;
                    let code = response.status().as_u16();
                    attempts.push(attempt_status(Some(code), ms, None));
                    if best_ms.is_none_or(|best| ms < best) {
                        best_ms = Some(ms);
                    }
                    last_error = format!("HTTP {code}");
                }
                Err(error) => {
                    let kind = if error.is_timeout() {
                        ProbeError::Timeout
                    } else if error.is_connect() {
                        ProbeError::Connect
                    } else {
                        ProbeError::Other
                    };
                    attempts.push(attempt_status(None, 0, Some(kind)));
                    last_error = error.to_string();
                }
            }
        }
        ProbeResult {
            status: combine_attempts(&attempts),
            ms: best_ms,
            detail: last_error,
        }
    }
}

// ─────────────────────────── состояние и job ───────────────────────────

/// Запись результата по одному домену.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteOutcome {
    pub domain: String,
    pub status: String,
    pub ms: Option<u64>,
    pub detail: String,
}

/// Прогон проверки: момент старта, признак завершения, накопленные записи.
#[derive(Debug, Default)]
struct JobInner {
    started_at: i64,
    done: bool,
    results: Vec<SiteOutcome>,
}

/// Состояние вкладки проверки: сетевые руки и текущий (или прошлый) прогон.
struct CheckInner {
    prober: Arc<dyn SiteProber>,
    job: Mutex<Option<Arc<Mutex<JobInner>>>>,
}

/// Клоняемая ручка состояния для ручек axum.
#[derive(Clone)]
pub struct CheckState {
    inner: Arc<CheckInner>,
}

impl FromRef<crate::App> for CheckState {
    fn from_ref(app: &crate::App) -> Self {
        app.check.clone()
    }
}

impl CheckState {
    /// Состояние живого сервера: реальные HTTPS-пробы.
    #[must_use]
    pub fn production() -> Self {
        Self::new(Arc::new(RealProber))
    }

    /// Состояние с явными руками (тесты подставляют фейк).
    #[must_use]
    pub fn new(prober: Arc<dyn SiteProber>) -> Self {
        Self {
            inner: Arc::new(CheckInner {
                prober,
                job: Mutex::new(None),
            }),
        }
    }

    /// Зарегистрировать новый прогон. Идущий (`done == false`) прогон
    /// занимает слот — `Err` с записью; иначе старый заменяется.
    fn begin_job(&self) -> Result<Arc<Mutex<JobInner>>, Arc<Mutex<JobInner>>> {
        let mut slot = self.inner.job.lock().expect("реестр прогонов не отравлен");
        if let Some(job) = slot.as_ref() {
            if !job.lock().expect("прогон не отравлен").done {
                return Err(Arc::clone(job));
            }
        }
        let job = Arc::new(Mutex::new(JobInner {
            started_at: now_epoch_s(),
            ..JobInner::default()
        }));
        *slot = Some(Arc::clone(&job));
        Ok(job)
    }

    /// Сам прогон: каждая проба — блокирующий вызов, из async живёт в
    /// `spawn_blocking` (как живой server_check в [`crate::dns_api`]).
    async fn run_job(&self, job: Arc<Mutex<JobInner>>, domains: Vec<String>) {
        let handles: Vec<_> = domains
            .into_iter()
            .map(|domain| {
                let prober = Arc::clone(&self.inner.prober);
                let job = Arc::clone(&job);
                tokio::task::spawn_blocking(move || {
                    let result = prober.probe(&domain);
                    let mut inner = job.lock().expect("прогон не отравлен");
                    inner.results.push(SiteOutcome {
                        domain,
                        status: result.status,
                        ms: result.ms,
                        detail: result.detail,
                    });
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.await;
        }
        job.lock().expect("прогон не отравлен").done = true;
    }
}

// ─────────────────────────── endpoints ─────────────────────────────────

/// Тело `POST /api/check/sites`. Пустое тело или пустой список — дефолтный
/// набор целей.
#[derive(Deserialize)]
pub struct SitesRequest {
    #[serde(default)]
    pub domains: Option<Vec<String>>,
}

/// Нормализация списка доменов: трим, пустые — прочь, дубли — прочь,
/// предел [`MAX_DOMAINS`].
#[must_use]
pub fn normalize_domains(domains: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() || seen.contains(&domain) {
            continue;
        }
        if seen.len() == MAX_DOMAINS {
            break;
        }
        seen.push(domain);
    }
    seen
}

/// Запуск проверки: `POST /api/check/sites`.
///
/// ```json
/// {"domains":["www.youtube.com","discord.com"]}
/// ```
/// (тело можно не передавать — берётся дефолтный набор из
/// [`DEFAULT_DOMAINS`]; сломанный JSON отвечает встроенной ошибкой axum).
///
/// Ответ: `200 {"ok":true,"count":11,"started_at":1739990000}` — проверка
/// ушла в фон; `409 {"error":"проверка уже идёт"}`, если прошлый прогон
/// ещё не закончился.
pub async fn sites(
    State(state): State<CheckState>,
    body: Option<Json<SitesRequest>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let domains = match body {
        Some(Json(request)) => request.domains.unwrap_or_default(),
        None => Vec::new(),
    };
    let domains = if domains.is_empty() {
        DEFAULT_DOMAINS
            .iter()
            .map(|domain| (*domain).to_string())
            .collect()
    } else {
        normalize_domains(&domains)
    };
    if domains.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "список доменов пуст" })),
        ));
    }
    let count = domains.len();
    let started_at = {
        let job = match state.begin_job() {
            Ok(job) => job,
            Err(_running) => {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "проверка уже идёт" })),
                ))
            }
        };
        let started_at = job.lock().expect("прогон не отравлен").started_at;
        let run_state = state.clone();
        tokio::task::spawn(async move { run_state.run_job(job, domains).await });
        started_at
    };
    Ok(Json(
        json!({ "ok": true, "count": count, "started_at": started_at }),
    ))
}

/// Состояние проверки: `GET /api/check/sites/status`.
///
/// ```json
/// {"done":true,"started_at":1739990000,
///  "results":[{"domain":"discord.com","status":"ok","ms":123,"detail":"HTTP 200"}]}
/// ```
///
/// Пока прогон не запускался ни разу: `{"done":false,"started_at":null,
/// "results":[]}`.
pub async fn status(State(state): State<CheckState>) -> Json<Value> {
    let job = state.inner.job.lock().expect("реестр прогонов не отравлен");
    let Some(job) = job.as_ref() else {
        return Json(json!({ "done": false, "started_at": null, "results": [] }));
    };
    let inner = job.lock().expect("прогон не отравлен");
    let results: Vec<Value> = inner
        .results
        .iter()
        .map(|outcome| {
            json!({
                "domain": outcome.domain,
                "status": outcome.status,
                "ms": outcome.ms,
                "detail": outcome.detail,
            })
        })
        .collect();
    Json(json!({
        "done": inner.done,
        "started_at": inner.started_at,
        "results": results,
    }))
}

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// Фейковые руки: заготовленные результаты по доменам, домены
    /// запоминаются.
    struct FakeProber {
        answers: HashMap<String, ProbeResult>,
        asked: Mutex<Vec<String>>,
    }

    impl FakeProber {
        fn new(answers: HashMap<String, ProbeResult>) -> Arc<Self> {
            Arc::new(Self {
                answers,
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    impl SiteProber for FakeProber {
        fn probe(&self, domain: &str) -> ProbeResult {
            self.asked.lock().unwrap().push(domain.to_string());
            self.answers.get(domain).cloned().unwrap_or(ProbeResult {
                status: "blocked".to_string(),
                ms: None,
                detail: "нет заготовки".to_string(),
            })
        }
    }

    fn ok(ms: u64) -> ProbeResult {
        ProbeResult {
            status: "ok".to_string(),
            ms: Some(ms),
            detail: "HTTP 200".to_string(),
        }
    }

    fn blocked(detail: &str) -> ProbeResult {
        ProbeResult {
            status: "blocked".to_string(),
            ms: None,
            detail: detail.to_string(),
        }
    }

    fn state_with(answers: HashMap<String, ProbeResult>) -> (CheckState, Arc<FakeProber>) {
        let prober = FakeProber::new(answers);
        let state = CheckState::new(Arc::clone(&prober) as Arc<dyn SiteProber>);
        (state, prober)
    }

    async fn post_json(router: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
        post_with(router, uri, body, true).await
    }

    /// POST без заголовка content-type: для axum это «тела нет» — ручка
    /// обязана взять дефолтный набор.
    async fn post_bodyless(router: axum::Router, uri: &str) -> (StatusCode, Value) {
        post_with(router, uri, "", false).await
    }

    async fn post_with(
        router: axum::Router,
        uri: &str,
        body: &str,
        with_content_type: bool,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method("POST").uri(uri);
        if with_content_type {
            request = request.header("content-type", "application/json");
        }
        let request = request.body(Body::from(body.to_string())).unwrap();
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

    fn router(state: CheckState) -> axum::Router {
        crate::router(crate::App {
            check: state,
            ..crate::App::test_defaults()
        })
    }

    #[test]
    fn attempt_status_classifies_codes_and_errors() {
        assert_eq!(attempt_status(Some(200), 100, None), AttemptStatus::Ok);
        assert_eq!(attempt_status(Some(301), 100, None), AttemptStatus::Ok);
        // Любой код HTTP — транспорт жив; медленный ответ — slow.
        assert_eq!(attempt_status(Some(403), 100, None), AttemptStatus::Ok);
        assert_eq!(attempt_status(Some(503), 100, None), AttemptStatus::Ok);
        assert_eq!(
            attempt_status(Some(200), SLOW_MS + 1, None),
            AttemptStatus::Slow
        );
        // Граница: ровно 2000 мс — ещё не slow.
        assert_eq!(attempt_status(Some(200), SLOW_MS, None), AttemptStatus::Ok);
        // Ошибки сети и отсутствие кода — провал попытки.
        for error in [ProbeError::Timeout, ProbeError::Connect, ProbeError::Other] {
            assert_eq!(attempt_status(None, 0, Some(error)), AttemptStatus::Failed);
        }
        assert_eq!(attempt_status(None, 0, None), AttemptStatus::Failed);
    }

    #[test]
    fn combine_attempts_blocks_only_when_all_failed() {
        assert_eq!(combine_attempts(&[]), "blocked");
        assert_eq!(
            combine_attempts(&[AttemptStatus::Failed, AttemptStatus::Failed]),
            "blocked"
        );
        assert_eq!(
            combine_attempts(&[AttemptStatus::Failed, AttemptStatus::Ok]),
            "ok"
        );
        assert_eq!(
            combine_attempts(&[AttemptStatus::Slow, AttemptStatus::Failed]),
            "slow"
        );
    }

    #[test]
    fn normalize_domains_trims_dedupes_and_caps() {
        let domains = normalize_domains(&[
            " YouTube.COM ".to_string(),
            "youtube.com".to_string(),
            String::new(),
            "discord.com".to_string(),
        ]);
        assert_eq!(domains, vec!["youtube.com", "discord.com"]);
        let many: Vec<String> = (0..MAX_DOMAINS + 5)
            .map(|i| format!("d{i}.example"))
            .collect();
        assert_eq!(normalize_domains(&many).len(), MAX_DOMAINS);
    }

    #[tokio::test]
    async fn sites_start_and_status_roundtrip() {
        let mut answers = HashMap::new();
        answers.insert("www.youtube.com".to_string(), ok(120));
        answers.insert("discord.com".to_string(), blocked("connect: отказ"));
        let (state, prober) = state_with(answers);
        let app = router(state.clone());

        let (status, answer) = post_json(
            app,
            "/api/check/sites",
            r#"{"domains":["www.youtube.com","discord.com"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["count"], 2);
        assert!(answer["started_at"].as_i64().is_some());

        // Прогон фоновый: статус мог быть и до конца, дожидаемся done.
        for _ in 0..100 {
            let (_, snapshot) = get(router(state.clone()), "/api/check/sites/status").await;
            if snapshot["done"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (_, snapshot) = get(router(state.clone()), "/api/check/sites/status").await;
        assert_eq!(snapshot["done"], true);
        let results = snapshot["results"].as_array().expect("результаты");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["domain"], "www.youtube.com");
        assert_eq!(results[0]["status"], "ok");
        assert_eq!(results[0]["ms"], 120);
        assert_eq!(results[1]["domain"], "discord.com");
        assert_eq!(results[1]["status"], "blocked");
        assert!(results[1]["ms"].is_null());
        let asked = prober.asked.lock().unwrap();
        assert_eq!(
            *asked,
            vec!["www.youtube.com".to_string(), "discord.com".to_string()]
        );
    }

    #[tokio::test]
    async fn sites_start_accepts_empty_body_and_uses_defaults() {
        let (state, prober) = state_with(HashMap::new());
        let app = router(state.clone());
        let (status, answer) = post_bodyless(app, "/api/check/sites").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["count"], DEFAULT_DOMAINS.len());
        // Прогон фоновый: дожидаемся, пока все дефолтные цели спросятся.
        for _ in 0..100 {
            if prober.asked.lock().unwrap().len() == DEFAULT_DOMAINS.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(prober.asked.lock().unwrap().len(), DEFAULT_DOMAINS.len());
    }

    #[tokio::test]
    async fn sites_start_rejects_running_job() {
        let (state, _prober) = state_with(HashMap::new());
        // Заняли слот незавершённым прогоном.
        state.begin_job().expect("слот занят");
        let (status, answer) = post_json(
            router(state),
            "/api/check/sites",
            r#"{"domains":["b.example"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["error"], "проверка уже идёт");
    }

    #[tokio::test]
    async fn sites_status_without_job_is_empty() {
        let (state, _prober) = state_with(HashMap::new());
        let (_, answer) = get(router(state), "/api/check/sites/status").await;
        assert_eq!(answer["done"], false);
        assert!(answer["started_at"].is_null());
        assert_eq!(answer["results"].as_array().expect("пусто").len(), 0);
    }

    #[tokio::test]
    async fn rerun_after_done_replaces_job() {
        let (state, _prober) = state_with(HashMap::new());
        let job = state.begin_job().expect("слот занят");
        job.lock().unwrap().done = true;
        let (status, answer) = post_json(
            router(state),
            "/api/check/sites",
            r#"{"domains":["b.example"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["count"], 1);
    }
}
