//! Порт `src/diagnostics/engine.py` — движок BlockCheck и проверки DNS подмены.
//!
//! BlockCheck отвечает на вопрос «какие сайты открываются и что с остальными».
//! Сайты собраны в сервисы (Discord — это сайт, чат и CDN картинок; YouTube —
//! сайт, превью и видеосервер). Режим «Discord и YouTube» проверяет только их,
//! «Все сайты» — ещё мессенджеры, соцсети, контрольные сайты и домены
//! пользователя. Голосовые серверы (UDP) и обрыв загрузки на 16–20 КБ
//! проверяются всегда.
//!
//! Как проверяется один адрес:
//!
//! 1. Параллельно спрашиваются DNS системы (без кэша и hosts), эталон по
//!    DNS-over-HTTPS к 1.1.1.1 и 8.8.8.8 (по IP, чтобы эталон не зависел от
//!    проверяемого DNS) и файл hosts.
//! 2. **Открывается ли сайт.** HTTPS-запрос идёт через `tls_probe` к адресу,
//!    которым воспользовался бы браузер: из hosts, из DNS системы, если он
//!    подлинный, иначе из эталона. При неудаче — ещё одна попытка на другом
//!    адресе и одна по IPv6.
//! 3. **Честен ли DNS.** Если адрес из DNS не совпал с эталоном, решает
//!    сертификат по этому адресу (`verdict`).
//! 4. **Чем именно мешают.** Если сайт не открылся, дополнительные пробы
//!    (`block_cause`) выясняют, режут по имени сайта или закрыт сам адрес.
//!    Если открылся — по одному соединению набирается объём (`volume_probe`).
//!    Итог — вид блокировки (`block_kind`).
//! 5. Результаты печатаются в постоянном порядке, в конце — итог с советами.
//!
//! Транспорт (пулы, TLS-стек, DNS-запросы) приходит замыканиями, как и в
//! остальных модулях крейта; машина прогона — `run_context::{Run, Lane, Live,
//! Steps}`.

use std::collections::BTreeMap;

use primecore_dnswire::TYPE_A;
use serde_json::{json, Value};

use crate::problems::{self, Problem};
use crate::run_context::Probe;
use crate::sections::CollectedProbes;
use crate::services::Service;
use crate::udp_burst::BurstVerdict;
use crate::verdict::{summarize_service, DnsState, ServiceVerdict, TargetOutcome};
use crate::windows_dns_query::{DnsAnswer, DNS_STATUS_NAME_ERROR};

/// Сколько тела ответа читать, чтобы заметить обрыв после ~16 КБ (ТСПУ режет
/// соединение с зарубежными CDN ровно на этом объёме).
pub const BODY_PROBE_BYTES: usize = 64 * 1024;

/// python `DNS_TYPE_A`.
pub const DNS_TYPE_A: u16 = TYPE_A;

/// Один сайт проверяется быстрее целого набора: дольше ждать незачем.
pub const SITE_CHECK_DEADLINE: f64 = 35.0;

/// Разделы отчёта, которые заполняются по ходу проверки.
const REPORT_SECTIONS: [&str; 11] = [
    "services",
    "voice",
    "freeze",
    "telegram",
    "network",
    "speed",
    "ipv6",
    "dns_servers",
    "filter",
    "habits",
    "crowd",
];

/// python `_WORKERS_PER_TARGET` — сколько потоков нужно одной цели в худшем
/// случае: сама цель, три запроса к DNS системы, два эталона (A и AAAA) по
/// запросу на каждый эталонный сервер и несколько HTTPS-запросов, четыре пробы
/// уточнения причины, три пакета QUIC и пять потоков на TLS 1.2 / TLS 1.3 /
/// «как Chrome» / HTTP. Задачи ждут друг друга внутри одного пула, поэтому
/// нехватка потоков — это не «медленнее», а взаимная блокировка.
pub fn workers_per_target() -> usize {
    28 + 2 * crate::dns_reference::REFERENCE_RESOLVERS.len()
}

/// python `_merge_dns_answers` — сводит несколько одинаковых DNS-запросов.
///
/// Адреса — все, что пришли хоть раз; если адресов не было ни разу, берётся
/// первый ответ с его кодом ошибки. Второе значение — сколько раз «сайта нет».
#[must_use]
pub fn merge_dns_answers(answers: &[DnsAnswer]) -> (DnsAnswer, u32) {
    let nxdomain = answers
        .iter()
        .filter(|answer| answer.ips.is_empty() && answer.status == DNS_STATUS_NAME_ERROR)
        .count() as u32;
    let mut ips: Vec<String> = Vec::new();
    for answer in answers {
        for ip in &answer.ips {
            if !ips.contains(ip) {
                ips.push(ip.clone());
            }
        }
    }
    if ips.is_empty() {
        let first = answers.first().cloned().unwrap_or_default();
        return (first, nxdomain);
    }
    let first = answers
        .iter()
        .find(|answer| !answer.ips.is_empty())
        .cloned()
        .unwrap_or_default();
    (
        DnsAnswer {
            ips,
            cnames: first.cnames,
            status: first.status,
            detail: first.detail,
            elapsed_ms: first.elapsed_ms,
        },
        nxdomain,
    )
}

/// python `_service_verdict` — итог по сервису из проб его адресов.
#[must_use]
pub fn service_verdict(
    service: &Service,
    probes: &[Probe],
    zapret_running: Option<bool>,
) -> ServiceVerdict {
    let outcomes = probes
        .iter()
        .map(|probe| TargetOutcome {
            host: probe.host.clone(),
            purpose: probe.target.purpose.to_string(),
            reach: probe.reach_state.value().to_string(),
            dns: probe
                .judgement
                .as_ref()
                .map_or(DnsState::Unknown, |item| item.state),
            main: probe.target.main,
            kind: probe.kind(),
            hosts_stale: probe.hosts_stale,
            unstable: !probe.unstable.is_empty(),
            dns_blind: probe.judgement.as_ref().is_some_and(|item| {
                item.state == DnsState::Spoofed
                    && probe.dns.ips.is_empty()
                    && probe.hosts_ips.is_empty()
            }),
        })
        .collect::<Vec<_>>();
    summarize_service(&service.label, &outcomes, zapret_running)
}

/// python `_with_section_problems` — строки итога из отдельных разделов вдобавок
/// к строкам по сайтам, все по важности.
#[must_use]
pub fn with_section_problems(
    mut problems: Vec<Problem>,
    burst: Option<&BurstVerdict>,
    dns_servers: Option<&Value>,
    speed: Option<&Value>,
    crowd: Option<&Value>,
    zapret_running: Option<bool>,
) -> Vec<Problem> {
    problems.extend(problems::burst_problems(burst));
    problems.extend(crate::sections::dns_problems(dns_servers));
    problems.extend(crate::sections::speed_problems(speed, zapret_running));
    problems.extend(crate::sections::crowd_problems(crowd, zapret_running));
    // python `sort` устойчив: при равном уровне порядок вставки сохраняется.
    problems.sort_by_key(|item| crate::levels::level_rank(item.level.value()));
    problems
}

/// python `_has_spoofing(collected)` — нашлась ли хоть одна явная подмена DNS.
#[must_use]
pub fn has_spoofing(collected: &CollectedProbes) -> bool {
    collected.values().flatten().any(|probe| {
        probe
            .judgement
            .as_ref()
            .is_some_and(|item| item.state == DnsState::Spoofed)
    })
}

/// python `_add_name_speed(site, names)` — дописывает к записи сайта замер
/// потока по имени; замедление или обрыв меняют итог.
pub fn add_name_speed(site: &mut Value, names: &Value, zapret_running: Option<bool>) {
    site["names"] = names.clone();
    if names["level"].as_str() != Some("warn") {
        return;
    }
    let hurt: Vec<String> = names["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item["state"].as_str() == Some("warn"))
                .map(|item| item["host"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    if site["level"].as_str() == Some("ok") {
        // Иначе итогом осталось бы «открывается», хотя пользоваться сайтом нельзя.
        site["level"] = json!("warn");
        site["status"] = json!("Поток режут");
        site["headline"] = json!(format!(
            "{} открывается, но поток данных режут по имени: {}",
            site["label"].as_str().unwrap_or(""),
            hurt.join(", ")
        ));
    }
    let speed_section = json!({"names": names});
    for problem in crate::sections::speed_problems(Some(&speed_section), zapret_running) {
        for item in &problem.advice {
            if item.is_empty() {
                continue;
            }
            let advice = site
                .as_object_mut()
                .expect("запись сайта")
                .entry("advice")
                .or_insert_with(|| json!([]));
            if let Some(list) = advice.as_array_mut() {
                if !list.iter().any(|known| known == item) {
                    list.push(json!(item));
                }
            }
        }
    }
}

/// python `_REPORT_SECTIONS` + стартовые поля отчёта — стартовый словарь `Live`.
#[must_use]
pub fn fresh_live_data(
    scope: &str,
    environment: &[String],
    zapret_running: Option<bool>,
    zapret_line: &str,
    other_tools: &[String],
    in_path: &[String],
) -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert("scope".to_string(), json!(scope));
    data.insert("environment".to_string(), json!(environment.to_vec()));
    data.insert(
        "report_version".to_string(),
        json!(crate::report_upgrade::REPORT_VERSION),
    );
    data.insert("zapret_running".to_string(), json!(zapret_running));
    data.insert("zapret_line".to_string(), json!(zapret_line));
    for section in REPORT_SECTIONS {
        data.insert(section.to_string(), Value::Null);
    }
    data.insert(
        "other_bypass_tools".to_string(),
        json!(other_tools.to_vec()),
    );
    data.insert("tools_in_path".to_string(), json!(in_path.to_vec()));
    data.insert("partial".to_string(), json!(true));
    data
}

// ---------------------------------------------------------------------------
// Транспорт движка (всё, что ходит в сеть или в систему, — замыканиями)
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use primecore_dnswire::DnsQueryResult;
use primecore_socketcancel::SocketCancel;

use crate::block_cause::{self, CauseFacts};
use crate::cert_owner::{self, CertNames};
use crate::dns_reference::{ReferenceResolver, REFERENCE_RESOLVERS};
use crate::ipv6_check::Ipv6Verdict;
use crate::limits::{
    DISCOVERY_READ_BUDGET_S, DISCOVERY_TIMEOUT, DNS_ATTEMPTS, FREEZE_MAX_BYTES, READ_TIMEOUT,
    RECHECK_AT_ONCE, RECHECK_LIGHT_AT_ONCE, RECHECK_NEEDS_S, RECHECK_SITES, REGISTRY_WAIT_S,
    RUN_DEADLINE, RUN_DEADLINE_ALL, RUN_DEADLINE_FULL, SITES_AT_ONCE, VIDEO_SERVERS,
};
use crate::net_access;
use crate::probe_result::{ProbeResult, KIND_CANCELLED, KIND_CERT};
use crate::problems::CollectOutput;
use crate::protocol_probe::{self, ProtocolFacts};
use crate::quic_probe::{self, QuicFacts};
use crate::reach;
use crate::registry;
use crate::run_context::{
    clock_now, Handle, Live, ProgressFn, PublishFn, Run, Steps, TaskError, RECHECK_OPENED,
    RECHECK_SAME, RECHECK_UNSTABLE,
};
use crate::sections::{self, LiveServices};
use crate::services::{
    build_services, site_service, Target, GOOGLEVIDEO_FALLBACK_HOST, SCOPE_ALL, SCOPE_FULL,
    SCOPE_MAIN, SCOPE_TITLES, STEP_DNS_SERVERS, STEP_FILTER, STEP_HOSTINGS, STEP_IPV6, STEP_SITES,
    STEP_SYSTEM, STEP_VOICE, YOUTUBE_HOST,
};
use crate::subnet_whitelist::SubnetVerdict;
use crate::system_state::SystemItem;
use crate::telegram_check::DcResult;
use crate::verdict::{judge_dns, judge_reach, JudgeDnsArgs, ReachState};
use crate::voice_check::VoiceServer;
use crate::volume_probe::{self, VolumeFacts, VOLUME_CUT, VOLUME_OK};

/// python-замыкание `chrome_get` — HTTPS-запрос «как браузер»; общий на прогон.
pub type ChromeGetMut = dyn FnMut(&str, &str, &str, f64, usize, f64, Option<&dyn Fn(&[u8]) -> bool>, bool) -> ProbeResult
    + Send;

/// Замыкания шапки окружения.
pub type LinesFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;
pub type ZapretStatusFn = Arc<dyn Fn() -> (Option<bool>, String) + Send + Sync>;
pub type ToolsListFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;
pub type RoutedAdaptersFn = Arc<dyn Fn() -> Option<Vec<String>> + Send + Sync>;
pub type ToolsInPathFn = Arc<dyn Fn(&[String], Option<&[String]>) -> Vec<String> + Send + Sync>;
pub type ToolsLineFn = Arc<dyn Fn(&[String], &[String]) -> String + Send + Sync>;
pub type ClockLabelFn = Arc<dyn Fn() -> String + Send + Sync>;

/// Сетевые замыкания движка.
pub type SystemDnsFn = Arc<dyn Fn(&str) -> DnsAnswer + Send + Sync>;
pub type HostsFn = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;
pub type DohQueryFn = Arc<Mutex<dyn FnMut(&ReferenceResolver) -> DnsQueryResult + Send>>;
pub type DohAskQueryFn =
    Arc<Mutex<dyn FnMut(&ReferenceResolver, &str, u16) -> DnsQueryResult + Send>>;
pub type DohAaaaFn = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;
pub type PingFn = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;
pub type GooglevideoExtractFn = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;
pub type FreezeTargetsFn = Arc<dyn Fn() -> Vec<Value> + Send + Sync>;
pub type OutsideAnswersFn = Arc<dyn Fn(&[String]) -> BTreeMap<String, String> + Send + Sync>;
pub type HabitSendFn = Arc<dyn Fn(&str, &[Vec<u8>], f64) -> String + Send + Sync>;
pub type HabitRestsFn = Arc<dyn Fn(f64) + Send + Sync>;
pub type TraceRouteFn = Arc<dyn Fn(&str) -> Option<crate::path_trace::RouteTrace> + Send + Sync>;
pub type PathPairFn = Arc<dyn Fn(&str, &str, &str, &str, u32) -> Option<bool> + Send + Sync>;
pub type PathConnectsFn = Arc<dyn Fn(&str, u32) -> bool + Send + Sync>;
pub type DnsPlaceAskFn = Arc<dyn Fn(u32) -> Option<bool> + Send + Sync>;
pub type SpeedDownloadFn =
    Arc<dyn Fn(&crate::speed_check::SpeedServer) -> Option<(u64, f64)> + Send + Sync>;
pub type NameSpeedDownloadFn =
    Arc<dyn Fn(&str, &str, &SocketCancel) -> crate::name_speed::NameRun + Send + Sync>;
pub type CrowdHelloFn = Arc<dyn Fn(&str, &str) -> String + Send + Sync>;
pub type CrowdTogetherFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// python `on_probe(key, probe)` — сайт проверен.
pub type OnProbeFn = dyn Fn(&str, &Probe) + Send + Sync;
/// python `on_done(готово, всего)` — цель проверена.
pub type OnDoneFn = dyn Fn(u32, u32) + Send + Sync;

/// python `quic_probe.collect(host, ip, submit, cancel)` — три пакета QUIC.
pub type QuicCollect =
    Arc<dyn Fn(&str, &str, &SocketCancel) -> Result<QuicFacts, TaskError> + Send + Sync>;
/// python `protocol_probe.collect(host, ip, submit, cancel)` — дороги по адресу.
pub type ProtocolsCollect =
    Arc<dyn Fn(&str, &str, &SocketCancel) -> Result<ProtocolFacts, TaskError> + Send + Sync>;
/// python `block_cause.collect(host, result, submit, cancel, ping)` — причины.
pub type CauseCollect =
    Arc<dyn Fn(&str, &ProbeResult, &SocketCancel) -> Result<CauseFacts, TaskError> + Send + Sync>;
/// python `volume_probe.collect(host, ip, path, cancel)` — объём по соединению.
pub type VolumeCollect =
    Arc<dyn Fn(&str, &str, &str, &SocketCancel) -> Result<VolumeFacts, TaskError> + Send + Sync>;
/// python `cert_owner.collect(host, ip, cancel)` — кто ответил вместо сайта.
pub type CertCollect =
    Arc<dyn Fn(&str, &str, &SocketCancel) -> Result<CertNames, TaskError> + Send + Sync>;

/// python `check_voice(submit, wait, cancel)` — STUN-серверы.
pub type VoiceCollect = Arc<dyn Fn(&Run) -> Result<Vec<VoiceServer>, TaskError> + Send + Sync>;
/// python `sections.check_udp_burst(run)` — серии UDP-пакетов.
pub type BurstCollect = Arc<dyn Fn(&Run) -> Result<BurstVerdict, TaskError> + Send + Sync>;
/// python `check_freeze(submit, wait, download, upload, every, on_server)` —
/// замер обрыва по хостингам; `targets` и загрузка — внутри замыкания.
pub type FreezeCheck = Arc<
    dyn Fn(
            &Run,
            bool,
            &dyn Fn(&crate::freeze_check::FreezeServer, u32, u32),
        ) -> Result<Vec<crate::freeze_check::FreezeServer>, TaskError>
        + Send
        + Sync,
>;
/// python `telegram_check.check_telegram(submit, wait, connect, pause)`.
pub type TelegramCollect = Arc<dyn Fn(&Run) -> Result<Vec<DcResult>, TaskError> + Send + Sync>;
/// python `sections.check_ipv6(run)`.
pub type Ipv6Check = Arc<dyn Fn(&Run) -> Result<Ipv6Verdict, TaskError> + Send + Sync>;
/// python `sections.check_system(run, services, zapret_running, intercept)`.
pub type SystemCheck = Arc<
    dyn Fn(&Run, &[(String, Service)], Option<bool>, bool) -> Result<Vec<SystemItem>, TaskError>
        + Send
        + Sync,
>;
/// python `sections.check_subnets(run, emit)` — подтверждение «белых списков».
pub type SubnetsCheck = Arc<dyn Fn(&Run) -> Result<Option<SubnetVerdict>, TaskError> + Send + Sync>;
/// python `sections.check_network(run, other_tools)` — готовый словарь «Ваша сеть».
pub type NetworkCheck = Arc<dyn Fn(&Run, &[String]) -> Value + Send + Sync>;
/// python `sections.start_registry()` — начал качать список, вернул «ждалку».
pub type RegistryStart =
    Arc<dyn Fn() -> Arc<dyn Fn(f64, &SocketCancel) -> registry::Index + Send + Sync> + Send + Sync>;
/// python `check_dns_servers` вкладки DNS-серверов: получает `should_stop`.
pub type DnsServersCheck =
    Arc<dyn Fn(Box<dyn Fn() -> bool + Send + Sync>) -> Result<Value, TaskError> + Send + Sync>;
/// python `geo_service_for` — поиск «адрес → сервис» по гео-сайтам каталога hosts.
pub type GeoServiceFor = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Шапка окружения и программы обхода: всё, что знает только слой запуска.
pub struct SystemIo {
    /// python `sections.environment_lines()` — включая строку Windows.
    pub environment_lines: LinesFn,
    /// python `sections.zapret_status()` — (запущен ли, строка отчёта).
    pub zapret_status: ZapretStatusFn,
    /// python `utils.bypass_tools.running_bypass_tools()`.
    pub running_bypass_tools: ToolsListFn,
    /// python `sections.routed_adapters()` — VPN-адаптеры на дороге.
    pub routed_adapters: RoutedAdaptersFn,
    /// python `utils.bypass_tools.tools_in_path(other_tools, routed)`.
    pub tools_in_path: ToolsInPathFn,
    /// python `sections.tools_line(other_tools, in_path)`.
    pub tools_line: ToolsLineFn,
    /// python `datetime.now().strftime('%d.%m.%Y %H:%M:%S')` — метка шапки.
    pub clock_label: ClockLabelFn,
}

/// Транспорт движка: сеть, система и списки целей приходят замыканиями.
///
/// Проверки, чей сбор ещё не перенесён (голосовые, Telegram, обрыв, подсети,
/// состояние системы), приходят готовыми замыканиями: слой запуска связывает
/// их с сетевым стеком так же, как python-версия связывает их с `Run`.
pub struct EngineIo {
    pub system: SystemIo,
    /// python `net_access.system_ipv4` — ответ DNS системы (без кэша и hosts).
    pub system_dns: SystemDnsFn,
    /// python `net_access.hosts_ipv4`.
    pub hosts: HostsFn,
    /// Вопрос одному эталонному серверу про A-запись (python `doher`).
    pub doh_query: DohQueryFn,
    /// Эталон по произвольному имени и типу (python `net_access.doh_ask`).
    pub doh_ask_query: DohAskQueryFn,
    /// Эталон по IPv6 (python `lookup` в `reach` и `check_ipv6`).
    pub doh_aaaa: DohAaaaFn,
    /// python `chrome_get` — весь HTTPS.
    pub chrome_get: Arc<Mutex<ChromeGetMut>>,
    /// python `net_access.ping_ok`.
    pub ping: PingFn,
    pub quic_collect: QuicCollect,
    pub protocols_collect: ProtocolsCollect,
    pub cause_collect: CauseCollect,
    pub volume_collect: VolumeCollect,
    pub cert_collect: CertCollect,
    /// python `blockcheck.googlevideo_discovery.extract_googlevideo_hosts`.
    pub googlevideo_extract: GooglevideoExtractFn,
    /// Список целей проверки обрыва (python `blockcheck.data_lists.TCP_16_20_TARGETS`).
    pub freeze_targets: FreezeTargetsFn,
    pub voice_collect: VoiceCollect,
    pub burst_collect: BurstCollect,
    pub freeze_check: FreezeCheck,
    pub telegram_collect: TelegramCollect,
    pub ipv6_check: Ipv6Check,
    pub system_check: SystemCheck,
    pub subnets_check: SubnetsCheck,
    pub network_check: NetworkCheck,
    pub registry_start: RegistryStart,
    /// python `sections.ask_outside` — ответы сервера за рубежом по списку имён.
    pub outside_answers: OutsideAnswersFn,
    /// python `filter_habits`-пробы: `(адрес, куски, пауза)` → исход.
    pub habit_send: HabitSendFn,
    /// python `filter_habits`-паузы между пробами (python `run.pause`).
    pub habit_rests: HabitRestsFn,
    /// python `path_trace.trace_route` — трассировка до адреса.
    pub trace_route: TraceRouteFn,
    /// python-замыкание `pair` у `locate_filter`: способ, адрес, имя сайта,
    /// имя пробника, срок жизни.
    pub path_pair: PathPairFn,
    /// python-замыкание `connects`: отвечает ли узел на сроке жизни.
    pub path_connects: PathConnectsFn,
    /// python `dns_place.ask_with_ttl` — вопрос с заданным сроком жизни.
    pub dns_place_ask: DnsPlaceAskFn,
    /// Замер скорости: python-замыкание `download` в `check_speed`.
    pub speed_download: SpeedDownloadFn,
    /// Замер по имени: python `name_speed.download(ip, name, cancel)`.
    pub name_speed_download: NameSpeedDownloadFn,
    /// python `crowd_probe` — приветствие с одного адреса.
    pub crowd_hello: CrowdHelloFn,
    /// python `crowd_probe` — соединения разом.
    pub crowd_together: CrowdTogetherFn,
}

impl Clone for EngineIo {
    fn clone(&self) -> Self {
        EngineIo {
            system: SystemIo {
                environment_lines: Arc::clone(&self.system.environment_lines),
                zapret_status: Arc::clone(&self.system.zapret_status),
                running_bypass_tools: Arc::clone(&self.system.running_bypass_tools),
                routed_adapters: Arc::clone(&self.system.routed_adapters),
                tools_in_path: Arc::clone(&self.system.tools_in_path),
                tools_line: Arc::clone(&self.system.tools_line),
                clock_label: Arc::clone(&self.system.clock_label),
            },
            system_dns: Arc::clone(&self.system_dns),
            hosts: Arc::clone(&self.hosts),
            doh_query: Arc::clone(&self.doh_query),
            doh_ask_query: Arc::clone(&self.doh_ask_query),
            doh_aaaa: Arc::clone(&self.doh_aaaa),
            chrome_get: Arc::clone(&self.chrome_get),
            ping: Arc::clone(&self.ping),
            quic_collect: Arc::clone(&self.quic_collect),
            protocols_collect: Arc::clone(&self.protocols_collect),
            cause_collect: Arc::clone(&self.cause_collect),
            volume_collect: Arc::clone(&self.volume_collect),
            cert_collect: Arc::clone(&self.cert_collect),
            googlevideo_extract: Arc::clone(&self.googlevideo_extract),
            freeze_targets: Arc::clone(&self.freeze_targets),
            voice_collect: Arc::clone(&self.voice_collect),
            burst_collect: Arc::clone(&self.burst_collect),
            freeze_check: Arc::clone(&self.freeze_check),
            telegram_collect: Arc::clone(&self.telegram_collect),
            ipv6_check: Arc::clone(&self.ipv6_check),
            system_check: Arc::clone(&self.system_check),
            subnets_check: Arc::clone(&self.subnets_check),
            network_check: Arc::clone(&self.network_check),
            registry_start: Arc::clone(&self.registry_start),
            outside_answers: Arc::clone(&self.outside_answers),
            habit_send: Arc::clone(&self.habit_send),
            habit_rests: Arc::clone(&self.habit_rests),
            trace_route: Arc::clone(&self.trace_route),
            path_pair: Arc::clone(&self.path_pair),
            path_connects: Arc::clone(&self.path_connects),
            dns_place_ask: Arc::clone(&self.dns_place_ask),
            speed_download: Arc::clone(&self.speed_download),
            name_speed_download: Arc::clone(&self.name_speed_download),
            crowd_hello: Arc::clone(&self.crowd_hello),
            crowd_together: Arc::clone(&self.crowd_together),
        }
    }
}

// ---------------------------------------------------------------------------
// Отдельные проверки
// ---------------------------------------------------------------------------

/// Общий кэш «адрес → куда ходили» на прогон (python `net_access` хранит его
/// в своём `Run`).
pub type KnownAddresses = Arc<Mutex<BTreeMap<String, String>>>;

#[must_use]
pub fn known_addresses() -> KnownAddresses {
    Arc::new(Mutex::new(BTreeMap::new()))
}

/// python `net_access.known_address(run, host)` — адрес сервера с кэшем на прогон.
#[must_use]
pub fn known_address(io: &EngineIo, cache: &KnownAddresses, host: &str) -> String {
    let known = cache.lock().expect("замок адресов").get(host).cloned();
    let address = net_access::known_address(known, &mut |name| browser_ips(io, name), host);
    if !address.is_empty() {
        cache
            .lock()
            .expect("замок адресов")
            .insert(host.to_string(), address.clone());
    }
    address
}

/// python `net_access.browser_ipv4` — адреса, которыми воспользовался бы браузер.
#[must_use]
pub fn browser_ips(io: &EngineIo, host: &str) -> Vec<String> {
    net_access::browser_ipv4(
        io.hosts.as_ref(),
        &|name| Some((io.system_dns)(name)),
        &mut |name| (io.doh_aaaa)(name),
        host,
    )
}

/// python `net_access.get(run, host, ip, path, read_limit=…)` через общий `chrome_get`.
#[must_use]
pub fn get_via(io: &EngineIo, host: &str, ip: &str, path: &str, read_limit: usize) -> ProbeResult {
    let mut chrome_get = io.chrome_get.lock().expect("замок chrome_get");
    net_access::get(host, ip, path, read_limit, &mut *chrome_get)
}

/// Задание «обычный запрос к адресу» для пула прогона.
fn get_task(
    run: &Run,
    io: &EngineIo,
    host: &str,
    ip: &str,
    path: &str,
    read_limit: usize,
) -> Handle<ProbeResult> {
    let chrome_get = Arc::clone(&io.chrome_get);
    let host = host.to_string();
    let ip = ip.to_string();
    let path = path.to_string();
    run.submit(move || {
        let mut chrome_get = chrome_get.lock().expect("замок chrome_get");
        Ok(net_access::get(
            &host,
            &ip,
            &path,
            read_limit,
            &mut *chrome_get,
        ))
    })
}

/// python `_discover_googlevideo` — видеосерверы, которые YouTube выдаёт этой
/// сети. (хосты, пояснение).
fn discover_googlevideo(_run: &Run, io: &EngineIo) -> Result<(Vec<String>, String), TaskError> {
    let found: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Когда начали читать страницу и вышел ли срок чтения.
    let reading: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let late: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    let done_found = Arc::clone(&found);
    let done_reading = Arc::clone(&reading);
    let done_late = Arc::clone(&late);
    let extract = Arc::clone(&io.googlevideo_extract);
    let done = move |body: &[u8]| -> bool {
        if body
            .windows(b"googlevideo".len())
            .any(|part| part == b"googlevideo")
        {
            let text = String::from_utf8_lossy(body);
            let hosts = extract(&text);
            if !hosts.is_empty() {
                let mut found = done_found.lock().expect("замок находок");
                for host in hosts.into_iter().take(VIDEO_SERVERS as usize) {
                    if !found.contains(&host) {
                        found.push(host);
                    }
                }
                return true;
            }
        }
        let mut started = done_reading.lock().expect("замок чтения");
        if started.is_none() {
            *started = Some(clock_now());
        }
        if clock_now() - started.expect("начало чтения") >= DISCOVERY_READ_BUDGET_S {
            drop(started);
            *done_late.lock().expect("замок срока") = true;
            return true;
        }
        false
    };

    // Адрес YouTube — тот, которым воспользовался бы браузер.
    let candidates = browser_ips(io, YOUTUBE_HOST);
    for ip in candidates.iter().take(1) {
        // Имя видеосервера ищется в самой странице: её нужно распаковать.
        let chrome_get = Arc::clone(&io.chrome_get);
        let result = {
            let mut chrome_get = chrome_get.lock().expect("замок chrome_get");
            net_access::fetch(
                YOUTUBE_HOST,
                ip,
                WATCH_PAGE,
                DISCOVERY_TIMEOUT,
                WATCH_PAGE_MAX_BYTES,
                READ_TIMEOUT,
                Some(&done),
                true,
                &mut *chrome_get,
            )
        };
        let hosts = found.lock().expect("замок находок").clone();
        if !hosts.is_empty() {
            return Ok((hosts, "адрес видеосервера получен от YouTube".to_string()));
        }
        if *late.lock().expect("замок срока") {
            return Ok((
                vec![GOOGLEVIDEO_FALLBACK_HOST.to_string()],
                "страница YouTube грузилась слишком медленно, поэтому проверяем общий адрес"
                    .to_string(),
            ));
        }
        if result.ok() {
            return Ok((
                vec![GOOGLEVIDEO_FALLBACK_HOST.to_string()],
                "YouTube не назвал видеосервер, поэтому проверяем общий адрес".to_string(),
            ));
        }
        if result.kind == KIND_CANCELLED {
            break;
        }
    }
    Ok((
        vec![GOOGLEVIDEO_FALLBACK_HOST.to_string()],
        "страница YouTube не открылась, поэтому проверяем общий адрес видеосерверов".to_string(),
    ))
}

const WATCH_PAGE: &str = "/watch?v=jNQXAC9IVRw&hl=en";
const WATCH_PAGE_MAX_BYTES: usize = 2_000_000;

/// python `_probe_target` — проба цели: у видеосервера сначала узнаётся адрес.
fn probe_target(
    run: &Arc<Run>,
    io: &EngineIo,
    target: &Target,
    service: &str,
    full: bool,
    volume: bool,
) -> Result<Probe, TaskError> {
    if !target.discover_googlevideo {
        return probe_host(run, io, target, service, &target.host, "", full, volume);
    }
    let (hosts, note) = discover_googlevideo(run, io)?;
    let first = probe_host(run, io, target, service, &hosts[0], &note, full, volume)?;
    // Один видеосервер не ответил — плеер взял бы следующий. Проверяем так же.
    let mut probe = first.clone();
    for host in hosts.iter().skip(1) {
        if probe.reach_state == ReachState::Ok || run.dns_cancelled() {
            break;
        }
        probe = probe_host(
            run,
            io,
            target,
            service,
            host,
            &format!("{note}; первый видеосервер не ответил, проверен запасной"),
            full,
            volume,
        )?;
    }
    if probe.reach_state == ReachState::Ok {
        Ok(probe)
    } else {
        Ok(first)
    }
}

/// python `_probe_host` — вся проверка одного адреса.
#[allow(clippy::too_many_arguments)]
fn probe_host(
    run: &Arc<Run>,
    io: &EngineIo,
    target: &Target,
    service: &str,
    host: &str,
    discovery_note: &str,
    full: bool,
    volume: bool,
) -> Result<Probe, TaskError> {
    let mut probe = Probe {
        target: target.clone(),
        service: service.to_string(),
        host: host.to_string(),
        discovery_note: discovery_note.to_string(),
        ..Default::default()
    };
    let read_limit = if full && target.read_body {
        BODY_PROBE_BYTES
    } else {
        0
    };
    let mut marked = clock_now();

    // 1. Параллельно: DNS системы (несколько попыток), эталон по DoH, файл hosts.
    let mut dns_futures = Vec::new();
    for _attempt in 0..DNS_ATTEMPTS {
        let system_dns = Arc::clone(&io.system_dns);
        let asked = host.to_string();
        dns_futures.push(run.submit(move || Ok(system_dns(&asked))));
    }
    let doh_query = Arc::clone(&io.doh_query);
    let noting = Arc::downgrade(run);
    let doh_future: Handle<(bool, Vec<String>)> = run.submit(move || {
        let mut query = doh_query.lock().expect("замок эталона");
        let mut note = |resolver: &ReferenceResolver, result: &DnsQueryResult| {
            if let Some(run) = noting.upgrade() {
                let index = REFERENCE_RESOLVERS
                    .iter()
                    .position(|item| {
                        item.label == resolver.label && item.address == resolver.address
                    })
                    .unwrap_or(0);
                run.note_reference(index, result);
            }
        };
        Ok(net_access::doh_lookup(&mut *query, &mut note))
    });
    probe.hosts_ips = (io.hosts)(host);
    let mut answers = Vec::new();
    for future in &dns_futures {
        answers.push(run.wait(future)?);
    }
    let (dns_answer, nxdomain) = merge_dns_answers(&answers);
    probe.dns = dns_answer;
    probe.dns_nxdomain = nxdomain;

    let local_ips: Vec<String> = if probe.hosts_ips.is_empty() {
        probe.dns.ips.clone()
    } else {
        probe.hosts_ips.clone()
    };
    // В полной проверке запрос к адресу из DNS нужен всегда — не ждём эталон.
    let mut local_future: Option<Handle<ProbeResult>> = None;
    if full && !local_ips.is_empty() {
        local_future = Some(get_task(
            run,
            io,
            host,
            &local_ips[0],
            target.path,
            read_limit,
        ));
    }

    let (reference_ok, reference_ips) = run.wait(&doh_future)?;
    probe.reference_ok = reference_ok;
    probe.reference_ips = reference_ips;
    let reference: HashSet<&String> = probe.reference_ips.iter().collect();
    let matches = probe.dns.ips.iter().any(|ip| reference.contains(ip));
    if local_future.is_none() && !local_ips.is_empty() && (!probe.hosts_ips.is_empty() || !matches)
    {
        local_future = Some(get_task(run, io, host, &local_ips[0], target.path, 0));
    }
    // DNS дал и адрес из эталона, и другой. У CDN так бывает, но так же
    // выглядит подмена «через раз»: сертификат по другому адресу решает.
    let suspects: Vec<String> = if matches && probe.hosts_ips.is_empty() {
        probe
            .dns
            .ips
            .iter()
            .filter(|ip| !reference.contains(*ip))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let mut suspect_future: Option<Handle<ProbeResult>> = None;
    if !suspects.is_empty() && local_ips.first().is_none_or(|first| first != &suspects[0]) {
        suspect_future = Some(get_task(run, io, host, &suspects[0], target.path, 0));
    }
    if let Some(future) = &local_future {
        probe.local_check = Some(run.wait(future)?);
    }
    if let Some(future) = &suspect_future {
        probe.suspect_check = Some(run.wait(future)?);
    } else if !suspects.is_empty() {
        probe.suspect_check = probe.local_check.clone();
    }

    // При совпадении с эталоном о DNS говорит только проверка «лишнего»
    // адреса: сбой на подтверждённом адресе — дело не DNS.
    let dns_check = if matches && probe.hosts_ips.is_empty() {
        probe.suspect_check.clone()
    } else {
        probe.local_check.clone()
    };
    // Чужой сертификат по адресу из DNS — контроль тем же запросом на
    // эталонный адрес: если и там чужой, подменяют HTTPS (антивирус, прокси),
    // а не адрес.
    let mut control: Option<ProbeResult> = None;
    if dns_check
        .as_ref()
        .is_some_and(|item| item.kind == KIND_CERT)
        && probe.hosts_ips.is_empty()
        && !probe.reference_ips.is_empty()
        && probe.reference_ips[0] != dns_check.as_ref().expect("сертификат проверен").ip
        && !run.dns_cancelled()
    {
        control = Some(get_via(io, host, &probe.reference_ips[0], target.path, 0));
    }
    probe.judgement = Some(judge_dns(JudgeDnsArgs {
        system_ips: probe.dns.ips.clone(),
        system_status: probe.dns.status,
        reference_ips: probe.reference_ips.clone(),
        hosts_ips: probe.hosts_ips.clone(),
        check_kind: dns_check
            .as_ref()
            .map_or(String::new(), |item| item.kind.clone()),
        check_cert_problem: dns_check
            .as_ref()
            .map_or(String::new(), |item| item.cert_problem.clone()),
        nxdomain_count: probe.dns_nxdomain,
        attempts: DNS_ATTEMPTS,
        control_kind: control
            .as_ref()
            .map_or(String::new(), |item| item.kind.clone()),
    }));
    let now = clock_now();
    probe.mark("dns", now - marked);
    marked = now;
    if full {
        // 2. Открывается ли сайт — попытки, как у браузера.
        let mut reach_run = ProbeReachRun {
            run: Arc::clone(run),
            host: host.to_string(),
            path: target.path,
            read_limit,
            chrome_get: Arc::clone(&io.chrome_get),
        };
        let doh_aaaa = Arc::clone(&io.doh_aaaa);
        let asked = host.to_string();
        let mut aaaa_lookup = move || doh_aaaa(&asked);
        reach::check_reach(
            &mut probe,
            &mut reach_run,
            &mut |ip| get_via(io, host, ip, target.path, read_limit),
            &mut aaaa_lookup,
        );
        probe.reach_state = judge_reach(probe.reach.as_ref());
        // Чужой сертификат — у самого сайта или у адреса из hosts, который не
        // подошёл: читаем, чей он.
        let local = if probe.hosts_stale {
            probe.local_check.clone()
        } else {
            None
        };
        let wrong = if probe.reach_state == ReachState::Cert {
            probe.reach.clone()
        } else {
            local.filter(|item| item.kind == KIND_CERT)
        };
        if let Some(wrong) = wrong.filter(|_| !run.dns_cancelled()) {
            let names = (io.cert_collect)(host, &wrong.ip, &run.probe_cancel)?;
            let from_hosts = probe.hosts_ips.contains(&wrong.ip);
            probe.cert = Some(cert_owner::judge(
                Some(&names),
                host,
                &wrong.cert_problem,
                from_hosts,
            ));
        }
        let now = clock_now();
        probe.mark("reach", now - marked);
        marked = now;
        // Пакеты QUIC уходят сразу, а ждём их после уточнения причины: обе
        // проверки идут одновременно.
        let quic_future = start_quic(run, io, &probe)?;
        let protocols_future = start_protocols(run, io, &probe)?;
        refine_cause(run, io, &mut probe)?;
        let now = clock_now();
        probe.mark("cause", now - marked);
        marked = now;
        if volume {
            check_volume(run, io, &mut probe)?;
            let now = clock_now();
            probe.mark("volume", now - marked);
            marked = now;
        }
        if let Some(future) = &quic_future {
            let facts = run.wait(future)?;
            probe.quic = quic_probe::judge(&facts);
        }
        let facts = match &protocols_future {
            Some(future) => Some(run.wait(future)?),
            None => None,
        };
        let chrome = protocol_probe::chrome_line(probe.reach.as_ref());
        probe.settle_protocols(protocol_probe::judge(facts.as_ref(), chrome.as_ref()));
        let now = clock_now();
        probe.mark("roads", now - marked);
    }
    Ok(probe)
}

/// python `_start_protocols` — TLS 1.2, TLS 1.3 и HTTP по тому же адресу, к
/// которому шёл основной запрос.
///
/// Только если сайт не открылся: открывшемуся хватает строки «Как Chrome» из
/// основной проверки.
fn start_protocols(
    run: &Arc<Run>,
    io: &EngineIo,
    probe: &Probe,
) -> Result<Option<Handle<ProtocolFacts>>, TaskError> {
    let Some(result) = probe.reach.as_ref() else {
        return Ok(None);
    };
    if result.ip.is_empty() || probe.reach_state == ReachState::Ok || run.dns_cancelled() {
        return Ok(None);
    }
    let collect = Arc::clone(&io.protocols_collect);
    let host = probe.host.clone();
    let ip = result.ip.clone();
    let cancel = Arc::clone(&run.probe_cancel);
    Ok(Some(run.submit(move || collect(&host, &ip, &cancel))))
}

/// python `_start_quic` — QUIC по тому же адресу, к которому шёл основной запрос.
fn start_quic(
    run: &Arc<Run>,
    io: &EngineIo,
    probe: &Probe,
) -> Result<Option<Handle<QuicFacts>>, TaskError> {
    let Some(result) = probe.reach.as_ref() else {
        return Ok(None);
    };
    if result.ip.is_empty() || run.dns_cancelled() {
        return Ok(None);
    }
    let collect = Arc::clone(&io.quic_collect);
    let host = probe.host.clone();
    let ip = result.ip.clone();
    let cancel = Arc::clone(&run.probe_cancel);
    Ok(Some(run.submit(move || collect(&host, &ip, &cancel))))
}

/// python `_refine_cause` — сайт не открылся: выясняем, режут по имени или по адресу.
fn refine_cause(run: &Arc<Run>, io: &EngineIo, probe: &mut Probe) -> Result<(), TaskError> {
    let result = probe.reach.clone();
    if !block_cause::needs_refining(result.as_ref()) || run.dns_cancelled() {
        return Ok(());
    }
    let result = result.expect("причина уточняется при известном исходе");
    let facts = (io.cause_collect)(&probe.host, &result, &run.probe_cancel)?;
    // Проверку могли снять, пока шли пробы: по обрывкам вывод не делаем.
    if !run.dns_cancelled() {
        probe.cause = block_cause::judge(&facts);
    }
    Ok(())
}

/// python `_check_volume` — сайт открылся: проверяем, проходит ли по одному
/// соединению больше 16 КБ.
fn check_volume(run: &Arc<Run>, io: &EngineIo, probe: &mut Probe) -> Result<(), TaskError> {
    if probe.reach_state != ReachState::Ok {
        return Ok(());
    }
    let Some(result) = probe.reach.as_ref().filter(|item| !item.ip.is_empty()) else {
        return Ok(());
    };
    if run.dns_cancelled() {
        return Ok(());
    }
    if result.body_size >= FREEZE_MAX_BYTES && !result.body_cut {
        // Главная страница сама больше окна обрыва и пришла целиком.
        return Ok(());
    }
    let facts = (io.volume_collect)(
        &probe.host,
        &result.ip,
        probe.target.path,
        &run.probe_cancel,
    )?;
    if run.dns_cancelled() {
        return Ok(());
    }
    probe.volume = Some(volume_probe::judge(&facts));
    if probe
        .volume
        .as_ref()
        .is_some_and(|item| item.code == VOLUME_CUT)
    {
        probe.reach_state = ReachState::Freeze;
        return Ok(());
    }
    // Обрыв бывает на одном адресе сайта из нескольких: проверяем ещё адрес
    // из другой сети.
    let other = probe
        .dns
        .ips
        .iter()
        .chain(probe.reference_ips.iter())
        .find(|ip| !ip.contains(':') && !reach::same_network(ip, &result.ip))
        .cloned()
        .unwrap_or_default();
    if !probe
        .volume
        .as_ref()
        .is_some_and(|item| item.code == VOLUME_OK)
        || other.is_empty()
        || run.dns_cancelled()
    {
        return Ok(());
    }
    let facts = (io.volume_collect)(&probe.host, &other, probe.target.path, &run.probe_cancel)?;
    let second = volume_probe::judge(&facts);
    if second.code == VOLUME_CUT && !run.dns_cancelled() {
        probe.unstable = format!(
            "по адресу {} загрузка идёт, а по адресу {} обрывается: {}. \
             Браузер попадает то на один адрес, то на другой",
            result.ip, other, second.text
        );
    }
    Ok(())
}

/// python-замыкание `_one` внутри `check_reach` и его `run` — мост планирования
/// для попыток основного запроса.
struct ProbeReachRun {
    run: Arc<Run>,
    host: String,
    path: &'static str,
    read_limit: usize,
    chrome_get: Arc<Mutex<ChromeGetMut>>,
}

impl reach::ReachRun for ProbeReachRun {
    fn dns_cancelled(&self) -> bool {
        self.run.dns_cancelled()
    }

    fn pause(&mut self, seconds: f64) {
        self.run.pause(seconds);
    }

    fn submit(&mut self, ip: &str) -> Box<dyn reach::ReachTask> {
        let chrome_get = Arc::clone(&self.chrome_get);
        let host = self.host.clone();
        let path = self.path;
        let read_limit = self.read_limit;
        let ip = ip.to_string();
        let handle = self.run.submit(move || {
            let mut chrome_get = chrome_get.lock().expect("замок chrome_get");
            Ok(net_access::get(
                &host,
                &ip,
                path,
                read_limit,
                &mut *chrome_get,
            ))
        });
        Box::new(ReachProbeTask { handle })
    }
}

struct ReachProbeTask {
    handle: Handle<ProbeResult>,
}

impl reach::ReachTask for ReachProbeTask {
    fn result(&mut self, timeout: Option<f64>) -> Option<ProbeResult> {
        let timeout = timeout
            .map(|seconds| Duration::from_secs_f64(seconds.max(0.0)))
            .unwrap_or(Duration::from_secs(86_400));
        self.handle.poll(timeout).and_then(|outcome| outcome.ok())
    }
}

// ---------------------------------------------------------------------------
// Прогоны
// ---------------------------------------------------------------------------

type DoneProbe = (String, Target, Option<Probe>, String);

/// python `_run_probes` — запускает все цели сразу и печатает их блоки по порядку.
///
/// `on_done(готово, всего)` зовётся после каждой проверенной цели.
/// `ask_outside` — галочка человека: без неё проверка «вне зоны» не зовётся.
#[allow(clippy::too_many_arguments)]
pub fn run_probes(
    run: &Arc<Run>,
    io: &EngineIo,
    services: &[(String, Service)],
    full: bool,
    emit: &mut dyn FnMut(&str),
    on_done: Option<Arc<OnDoneFn>>,
    on_probe: Option<Arc<OnProbeFn>>,
    ask_outside_flag: bool,
) -> Result<CollectedProbes, TaskError> {
    let total: u32 = services
        .iter()
        .map(|(_key, service)| service.targets.len() as u32)
        .sum();
    // Десятки сайтов разом — это сотни запросов к эталонным DNS-серверам в одну
    // секунду: они начинают отказывать, и это выглядело бы как блокировка.
    let lane = run.lane(SITES_AT_ONCE as usize);
    let done_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));

    let mut jobs: Vec<(String, Target, bool)> = Vec::new();
    for (key, service) in services {
        for target in &service.targets {
            let mut target = target.clone();
            if !full && target.discover_googlevideo {
                target = Target {
                    host: target.host.clone(),
                    purpose: target.purpose,
                    path: target.path,
                    read_body: false,
                    main: target.main,
                    discover_googlevideo: false,
                };
            }
            // Объём по одному соединению — это десятки запросов подряд:
            // контрольные сайты ими не нагружаем, их всё равно не блокируют.
            jobs.push((key.clone(), target, full && !service.control));
        }
    }
    // Сайты стартуют каждый раз в новом порядке (отчёт печатается в прежнем):
    // одинаковый порядок от проверки к проверке — тоже узор.
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    shuffle(&mut order);

    let mut futures: Vec<Option<Handle<Probe>>> = (0..jobs.len()).map(|_| None).collect();
    for index in order {
        let (key, target, volume) = jobs[index].clone();
        let run_task = Arc::clone(run);
        let io_task = io.clone();
        let on_probe_task = on_probe.clone();
        let on_done_task = on_done.clone();
        let done_count_task = Arc::clone(&done_count);
        futures[index] = Some(lane.submit(move || -> Result<Probe, TaskError> {
            let outcome = (|| -> Result<Probe, TaskError> {
                run_task.wait_start_turn();
                let started = clock_now();
                let mut probe = probe_target(&run_task, &io_task, &target, &key, full, volume)?;
                probe.seconds = clock_now() - started;
                if let Some(on_probe) = &on_probe_task {
                    on_probe(&key, &probe);
                }
                Ok(probe)
            })();
            if let Some(on_done) = &on_done_task {
                let ready = {
                    let mut count = done_count_task.lock().expect("замок готовности");
                    *count += 1;
                    *count
                };
                on_done(ready, total);
            }
            outcome
        }));
    }

    // Сначала дожидаемся всех, затем перепроверяем упавшие, и только потом
    // печатаем: перепроверка может изменить результат.
    let mut done_probes: Vec<DoneProbe> = Vec::new();
    for (index, (key, target, _volume)) in jobs.iter().enumerate() {
        let handle = futures[index].take().expect("задание создано");
        match run.wait(&handle) {
            Ok(probe) => {
                done_probes.push((key.clone(), target.clone(), Some(probe), String::new()))
            }
            Err(TaskError::Stopped) => return Err(TaskError::Stopped),
            Err(error) => done_probes.push((key.clone(), target.clone(), None, error.to_string())),
        }
    }
    if full {
        done_probes = recheck_failed(run, io, services, done_probes)?;
        if ask_outside_flag {
            apply_outside(run, io, services, &mut done_probes);
        }
    }

    let mut collected: CollectedProbes = BTreeMap::new();
    let mut current_service = String::new();
    for (key, target, probe, error) in &done_probes {
        if key != &current_service {
            current_service = key.clone();
            emit("");
            let label = services
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_name, service)| service.label.as_str())
                .unwrap_or("");
            emit(&format!("━━━━━━━━ {label} ━━━━━━━━"));
        }
        let Some(probe) = probe else {
            emit(&format!(
                "❔ {} — {}: проверка не выполнилась ({error})",
                target.host, target.purpose
            ));
            continue;
        };
        collected
            .entry(key.clone())
            .or_default()
            .push(probe.clone());
        for line in crate::report_text::probe_lines(probe, full) {
            emit(&line);
        }
    }
    emit("");
    Ok(collected)
}

/// python `random.sample(range(len(jobs)), len(jobs))` — случайный порядок без
/// повторов.
fn shuffle(order: &mut [usize]) {
    for index in (1..order.len()).rev() {
        let pick = fastrand::usize(..=index);
        order.swap(index, pick);
    }
}

/// Отложенная перепроверка: лёгкий шаг возвращает тяжёлое задание.
type RecheckPlan = Vec<(usize, Handle<Option<Handle<Option<Probe>>>>)>;

/// python `sections.ask_outside` — правка `probe.outside` по ответам сервера.
fn apply_outside(
    run: &Arc<Run>,
    io: &EngineIo,
    services: &[(String, Service)],
    done_probes: &mut [DoneProbe],
) {
    let map: BTreeMap<String, Service> = services.iter().cloned().collect();
    let probes: Vec<&Probe> = done_probes
        .iter()
        .filter_map(|(_key, _target, probe, _error)| probe.as_ref())
        .collect();
    let answers = Arc::clone(&io.outside_answers);
    let cancelled_run = Arc::clone(run);
    let left_run = Arc::clone(run);
    let results = sections::ask_outside(
        &map,
        &probes,
        &move |hosts: &[String]| answers(hosts),
        &move || cancelled_run.dns_cancelled(),
        &move || left_run.seconds_left(),
    );
    for (service, host, answer) in results {
        for (key, _target, probe, _error) in done_probes.iter_mut() {
            if key == &service && probe.as_ref().is_some_and(|item| item.host == host) {
                if let Some(item) = probe {
                    item.outside = answer;
                }
                break;
            }
        }
    }
}

/// python `_recheck_failed` — сайты, которые не открылись, проверяются ещё раз —
/// поодиночке, когда залп закончился.
///
/// Первая проверка идёт по десяткам сайтов разом. Если сбой дала сама эта
/// нагрузка (роутер или провайдер не успели), при спокойной повторной проверке
/// сайт откроется. Не открылся снова — сбой настоящий.
fn recheck_failed(
    run: &Arc<Run>,
    io: &EngineIo,
    services: &[(String, Service)],
    done_probes: Vec<DoneProbe>,
) -> Result<Vec<DoneProbe>, TaskError> {
    let failed: Vec<usize> = done_probes
        .iter()
        .enumerate()
        .filter(|(_index, (_key, _target, probe, _error))| {
            probe.as_ref().is_some_and(|item| {
                matches!(item.reach_state, ReachState::IpBlock | ReachState::Dpi)
            })
        })
        .map(|(index, _)| index)
        .take(RECHECK_SITES as usize)
        .collect();
    if failed.is_empty() || run.dns_cancelled() || run.seconds_left() < RECHECK_NEEDS_S {
        return Ok(done_probes);
    }
    let light = run.lane(RECHECK_LIGHT_AT_ONCE as usize);
    let heavy = run.lane(RECHECK_AT_ONCE as usize);
    let shared: Arc<Mutex<Vec<DoneProbe>>> = Arc::new(Mutex::new(done_probes));
    let service_map: Arc<BTreeMap<String, Service>> = Arc::new(services.iter().cloned().collect());

    let mut futures: RecheckPlan = Vec::new();
    for &index in &failed {
        let shared_light = Arc::clone(&shared);
        let run_light = Arc::clone(run);
        let io_light = io.clone();
        let heavy_light = Arc::clone(&heavy);
        let service_map_loop = Arc::clone(&service_map);
        futures.push((
            index,
            light.submit(move || -> Result<Option<Handle<Option<Probe>>>, TaskError> {
                let service_map = Arc::clone(&service_map_loop);
                let (_key, target, first, _error) = {
                    let guard = shared_light.lock().expect("замок перепроверки");
                    guard[index].clone()
                };
                if run_light.dns_cancelled() {
                    return Ok(None);
                }
                let Some(first) = &first else {
                    return Ok(None);
                };
                // Сначала один лёгкий запрос к тому же адресу. Полная проверка
                // сайта заново — это десяток запросов с ожиданием; на линии,
                // где закрыта половина сайтов, она одна съедала больше минуты.
                // Она нужна, только если сайт на этот раз открылся.
                if let Some(reach) = first.reach.as_ref().filter(|item| !item.ip.is_empty()) {
                    if !get_via(&io_light, &first.host, &reach.ip, target.path, 0).ok() {
                        let cancelled = run_light.dns_cancelled();
                        if let Ok(mut guard) = shared_light.lock() {
                            if let Some(probe) = guard[index].2.as_mut() {
                                probe.rechecked = if cancelled {
                                    String::new()
                                } else {
                                    RECHECK_SAME.to_string()
                                };
                            }
                        }
                        return Ok(None);
                    }
                }
                let shared_again = Arc::clone(&shared_light);
                let run_again = Arc::clone(&run_light);
                let io_again = io_light.clone();
                let service_map_again = service_map;
                Ok(Some(heavy_light.submit(move || -> Result<Option<Probe>, TaskError> {
                    let (key, target, first, _error) = {
                        let guard = shared_again.lock().expect("замок перепроверки");
                        guard[index].clone()
                    };
                    if run_again.dns_cancelled() {
                        return Ok(None);
                    }
                    let Some(first) = first else {
                        return Ok(None);
                    };
                    let volume = service_map_again
                        .get(&key)
                        .map(|service| !service.control)
                        .unwrap_or(false);
                    let mut again = probe_target(&run_again, &io_again, &target, &key, true, volume)?;
                    // Повтор не успел — остаётся первый результат, без пометки.
                    if again.reach.as_ref().is_none_or(|item| item.kind == KIND_CANCELLED) {
                        return Ok(None);
                    }
                    again.rechecked = if again.reach_state == ReachState::Ok {
                        RECHECK_OPENED
                    } else {
                        RECHECK_SAME
                    }
                    .to_string();
                    if again.rechecked == RECHECK_OPENED && !run_again.dns_cancelled() {
                        // Сбой и успех — счёт равный. Третья попытка решает:
                        // случайный это сбой или сайт открывается через раз.
                        let ip = again
                            .reach
                            .as_ref()
                            .map(|item| item.ip.clone())
                            .unwrap_or_default();
                        let third = get_via(&io_again, &again.host, &ip, target.path, 0);
                        if !third.ok() && third.kind != KIND_CANCELLED {
                            again.rechecked = RECHECK_UNSTABLE.to_string();
                            again.unstable =
                                "из трёх попыток подряд прошла одна: сбой, успех и снова сбой".to_string();
                        }
                    }
                    if first.reach_state != again.reach_state && again.reach_state != ReachState::Ok {
                        // Сбой другого вида: берём свежий, но «подтверждённым»
                        // его не считаем.
                        again.rechecked = String::new();
                    }
                    Ok(Some(again))
                })))
            }),
        ));
    }

    let mut result: Vec<DoneProbe> = shared.lock().expect("замок перепроверки").clone();
    for (index, future) in futures {
        let full_check = match run.wait(&future) {
            Ok(handle) => handle,
            Err(TaskError::Stopped) => return Err(TaskError::Stopped),
            Err(_) => continue,
        };
        let Some(heavy_handle) = full_check else {
            continue;
        };
        let again = match run.wait(&heavy_handle) {
            Ok(value) => value,
            Err(TaskError::Stopped) => return Err(TaskError::Stopped),
            Err(_) => continue,
        };
        if let Some(again) = again {
            result[index].2 = Some(again);
        }
    }
    Ok(result)
}

/// python `_Setting` — в каких условиях идёт проверка: это печатается первым
/// и лежит в отчёте.
pub struct Setting {
    pub environment: Vec<String>,
    pub zapret_running: Option<bool>,
    pub zapret_line: String,
    pub other_tools: Vec<String>,
    pub in_path: Vec<String>,
}

/// python `_announce` — шапка отчёта: режим, система, Zapret и программы
/// обхода, которые могут мешать проверке.
fn announce(scope: &str, io: &EngineIo, emit: &mut dyn FnMut(&str)) -> Setting {
    let title = SCOPE_TITLES
        .iter()
        .find(|(name, _)| *name == scope)
        .map(|(_name, title)| *title)
        .unwrap_or("");
    emit(&format!(
        "🔍 BlockCheck: {title} — {}",
        (io.system.clock_label)()
    ));
    let environment = (io.system.environment_lines)();
    for line in &environment {
        emit(line);
    }
    let (zapret_running, zapret_line) = (io.system.zapret_status)();
    emit(&zapret_line);
    let other_tools = (io.system.running_bypass_tools)();
    // VPN мешает проверке, только если интернет идёт через его адаптер;
    // прокси — не мешает вовсе.
    let routed = (io.system.routed_adapters)();
    let in_path = (io.system.tools_in_path)(&other_tools, routed.as_deref());
    if !other_tools.is_empty() || !in_path.is_empty() {
        emit(&(io.system.tools_line)(&other_tools, &in_path));
    }
    emit("⏳ Проверяем так же, как браузер: TLS 1.3, правильные адреса сайтов…");
    Setting {
        environment,
        zapret_running,
        zapret_line,
        other_tools,
        in_path,
    }
}

/// python `_attempt` — раздел, который идёт прямо сейчас. Его сбой оставляет
/// строку в отчёте и не роняет проверку; «Стоп» уходит наверх.
fn attempt<T>(
    emit: &mut dyn FnMut(&str),
    title: &str,
    call: impl FnOnce(&mut dyn FnMut(&str)) -> Result<T, TaskError>,
) -> Result<Option<T>, TaskError> {
    let outcome = {
        let mut forward: &mut dyn FnMut(&str) = emit;
        call(&mut forward)
    };
    match outcome {
        Ok(value) => Ok(Some(value)),
        Err(TaskError::Stopped) => Err(TaskError::Stopped),
        Err(error) => {
            emit(&format!("❔ {title}: проверка не выполнилась ({error})"));
            Ok(None)
        }
    }
}

/// python `_settle` — итог раздела, который шёл в фоне. `None` — раздел не
/// запускали или он сломался.
///
/// Сбой одного раздела не должен ронять всю проверку: о нём остаётся строка
/// в отчёте, остальные разделы показываются как обычно.
fn settle<T: Send + 'static>(
    run: &Run,
    future: &Handle<T>,
    emit: &mut dyn FnMut(&str),
    title: &str,
) -> Result<Option<T>, TaskError> {
    match run.wait(future) {
        Ok(value) => Ok(Some(value)),
        Err(TaskError::Stopped) => Err(TaskError::Stopped),
        Err(error) => {
            emit(&format!("❔ {title}: проверка не выполнилась ({error})"));
            Ok(None)
        }
    }
}

/// Мост для проверок из `sections`, которым нужен прогон: соединяет чистую
/// логику крейта с транспортом.
struct Wired<'a> {
    run: &'a Arc<Run>,
    io: &'a EngineIo,
}

impl Wired<'_> {
    fn cancelled(&self) -> bool {
        self.run.dns_cancelled()
    }

    /// python `lookup_ip_owner(ip, doh_ask)` — владелец адреса.
    fn owner_of(&self, ip: &str) -> Option<(String, String)> {
        let doh_ask_query = Arc::clone(&self.io.doh_ask_query);
        let owner = crate::ip_owner::lookup_ip_owner(ip, move |name: &str, rtype: u16| {
            let mut query = doh_ask_query.lock().expect("замок эталона");
            net_access::doh_ask(name, rtype, &mut |resolver, asked, asked_type| {
                query(resolver, asked, asked_type)
            })
        });
        owner.and_then(|item| {
            (!item.asn.is_empty() || !item.owner.is_empty())
                .then(|| (item.asn.clone(), item.owner.clone()))
        })
    }
}

/// python `sections.find_filter_place(run, …)` — где стоит фильтр.
#[allow(clippy::too_many_arguments)]
fn filter_place_section(
    wired: &Wired<'_>,
    collected: &CollectedProbes,
    emit: &mut dyn FnMut(&str),
    zapret_running: Option<bool>,
    other_tools: &[String],
    own_asn: &str,
) -> Option<Value> {
    let dns_ask: &crate::dns_place::TtlAsk<'_> = &move |ttl: u32| (wired.io.dns_place_ask)(ttl);
    let traced = |ip: &str| (wired.io.trace_route)(ip);
    let connects = |ip: &str, ttl: u32| (wired.io.path_connects)(ip, ttl);
    let pair_of = |method: &str, ip: &str, host: &str, name: &str, ttl: u32| {
        (wired.io.path_pair)(method, ip, host, name, ttl)
    };
    sections::find_filter_place(
        collected,
        emit,
        &|| wired.cancelled(),
        zapret_running,
        other_tools,
        own_asn,
        &pair_of,
        &connects,
        &|ip| wired.owner_of(ip),
        &traced,
        dns_ask,
    )
}

/// python `run_blockcheck` — проверка BlockCheck. Печатает отчёт через `emit`
/// и возвращает итог для экрана.
///
/// `progress(шаг, готово, всего)` — ход проверки для экрана; шаги перечислены
/// в `PROGRESS_STEPS`. Зовётся из рабочих потоков. `partial(отчёт)` — тот же
/// отчёт, что вернётся в конце, но пока неполный: зовётся после каждого раздела.
///
/// `geo_service_for` — поиск «адрес → сервис» по гео-сайтам каталога hosts:
/// таким сайтам советуется hosts или DNS, а не подбор стратегии.
/// `check_dns_servers` — проверка DNS-серверов для полной проверки: получает
/// `should_stop` и возвращает `{"level", "findings": [{"level", "text"}], "text"}`.
/// `ask_outside` — галочка «Сверить с сервером в Нидерландах».
#[allow(clippy::too_many_arguments)]
pub fn run_blockcheck(
    scope_arg: &str,
    user_domains: &[String],
    should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    emit: &mut dyn FnMut(&str),
    progress: Option<Arc<ProgressFn>>,
    partial: Option<Arc<PublishFn>>,
    geo_service_for: Option<GeoServiceFor>,
    check_dns_servers: Option<DnsServersCheck>,
    ask_outside_flag: bool,
    io: &EngineIo,
) -> Value {
    let mut scope = scope_arg.trim().to_lowercase();
    if !SCOPE_TITLES.iter().any(|(name, _)| *name == scope) {
        scope = SCOPE_MAIN.to_string();
    }
    let full = scope == SCOPE_FULL;
    let user_refs: Vec<&str> = user_domains.iter().map(String::as_str).collect();
    let services_list = build_services(&scope, &user_refs);
    let services: BTreeMap<String, Service> = services_list.iter().cloned().collect();

    let step = Arc::new(Steps::new(progress));
    let targets_count: u32 = services_list
        .iter()
        .map(|(_key, service)| service.targets.len() as u32)
        .sum();
    // Полная проверка держит по потоку на каждый хостинг из списка.
    let run = Run::new(
        should_stop,
        targets_count as usize * workers_per_target() + if full { 120 } else { 40 },
        Some(match scope.as_str() {
            SCOPE_ALL => RUN_DEADLINE_ALL,
            SCOPE_FULL => RUN_DEADLINE_FULL,
            _ => RUN_DEADLINE,
        }),
    );
    let known = known_addresses();
    let started = clock_now();
    let outcome: Result<Value, TaskError> = (|| {
        let setting = announce(&scope, io, emit);
        let environment = setting.environment;
        let zapret_running = setting.zapret_running;
        let other_tools = setting.other_tools;
        let in_path = setting.in_path;
        let wired = Wired { run: &run, io };
        // Разделы, которых в этом режиме нет или которые не удались, в отчёте
        // остаются пустыми.
        let start: serde_json::Map<String, Value> = fresh_live_data(
            &scope,
            &environment,
            zapret_running,
            &setting.zapret_line,
            &other_tools,
            &in_path,
        )
        .into_iter()
        .collect();
        let step_seconds = Arc::clone(&step);
        let live = Arc::new(Live::new(
            partial,
            Some(Arc::new(move || {
                let seconds = step_seconds.seconds();
                vec![(
                    "step_seconds".to_string(),
                    serde_json::to_value(seconds).unwrap_or(Value::Null),
                )]
            })),
            start,
        ));

        // Звонки и обрыв на 16 КБ проверяются всегда: режим меняет только
        // список сайтов.
        let voice_collect = Arc::clone(&io.voice_collect);
        let voice_run = Arc::clone(&run);
        let voice_future = run.later(STEP_VOICE, move || voice_collect(&voice_run));
        // Серия UDP и отправка данных — пробы, которых браузер не делает:
        // только в глубокой диагностике.
        let burst_future = if full {
            let burst_collect = Arc::clone(&io.burst_collect);
            let burst_run = Arc::clone(&run);
            Some(run.later(STEP_VOICE, move || burst_collect(&burst_run)))
        } else {
            None
        };
        let freeze_check = Arc::clone(&io.freeze_check);
        let freeze_run = Arc::clone(&run);
        let freeze_step = Arc::clone(&step);
        let freeze_future = run.later(STEP_HOSTINGS, move || {
            let on_server =
                move |_server: &crate::freeze_check::FreezeServer, done: u32, total: u32| {
                    freeze_step.step(STEP_HOSTINGS, done, total)
                };
            freeze_check(&freeze_run, full, &on_server)
        });

        let network_check = Arc::clone(&io.network_check);
        let network_run = Arc::clone(&run);
        let network_tools = other_tools.clone();
        let network_future = run.later(STEP_SYSTEM, move || {
            Ok(network_check(&network_run, &network_tools))
        });
        // Дата-центры Telegram — часть списка «все сайты»: в коротком режиме
        // их не трогаем.
        let telegram_future = if scope != SCOPE_MAIN {
            let telegram_collect = Arc::clone(&io.telegram_collect);
            let telegram_run = Arc::clone(&run);
            Some(run.later(STEP_SYSTEM, move || telegram_collect(&telegram_run)))
        } else {
            None
        };
        let ipv6_check_fn = Arc::clone(&io.ipv6_check);
        let ipv6_run = Arc::clone(&run);
        let ipv6_future = run.later(STEP_IPV6, move || ipv6_check_fn(&ipv6_run));
        let system_check = Arc::clone(&io.system_check);
        let system_run = Arc::clone(&run);
        let system_services = services_list.clone();
        let system_future = run.later(STEP_SYSTEM, move || {
            system_check(&system_run, &system_services, zapret_running, full)
        });

        step.step(STEP_SITES, 0, targets_count);
        let verdict_running = zapret_running;
        let verdict_of: crate::sections::VerdictOf =
            Arc::new(move |service: &Service, probes: &[Probe]| {
                service_verdict(service, probes, verdict_running)
            });
        // Сервис уходит на экран, как только проверены все его адреса, а не
        // когда кончатся все сайты.
        let live_services = LiveServices::new(&services, Arc::clone(&verdict_of), {
            let live = Arc::clone(&live);
            Arc::new(move |ready: Vec<Value>| {
                live.put([("services".to_string(), Value::Array(ready))]);
            })
        });
        let on_done: Arc<dyn Fn(u32, u32) + Send + Sync> = {
            let step = Arc::clone(&step);
            Arc::new(move |ready: u32, total: u32| step.step(STEP_SITES, ready, total))
        };
        let collected = run_probes(
            &run,
            io,
            &services_list,
            true,
            emit,
            Some(on_done),
            Some(Arc::new(move |key: &str, probe: &Probe| {
                live_services.on_probe(key, probe)
            })),
            ask_outside_flag,
        )?;
        let verdicts: BTreeMap<String, ServiceVerdict> = services
            .keys()
            .map(|key| {
                let empty: Vec<Probe> = Vec::new();
                let probes = collected.get(key).unwrap_or(&empty);
                (key.clone(), verdict_of(&services[key], probes))
            })
            .collect();
        let services_report =
            crate::report_text::services_report(&services_list, &verdicts, &collected);
        live.put([(
            "services".to_string(),
            Value::Array(services_report.clone()),
        )]);
        // Шаги идут по очереди, как строки на экране, а не все разом: вместе
        // они забирали процессор у окна программы, и оно замирало.
        let dns = full && check_dns_servers.is_some();
        let dns_future = if dns {
            let check = Arc::clone(check_dns_servers.as_ref().expect("проверка есть"));
            let run_dns = Arc::clone(&run);
            Some(run.later(STEP_DNS_SERVERS, move || {
                let should_stop: Box<dyn Fn() -> bool + Send + Sync> = {
                    let run_dns = Arc::clone(&run_dns);
                    Box::new(move || run_dns.dns_cancelled())
                };
                check(should_stop)
            }))
        } else {
            None
        };
        // У хостингов свой счётчик «готово из всего» — им отметка шага не нужна.
        // Шаги после сайтов, которые идут в фоне по очереди (место фильтра —
        // отдельно, в конце).
        let staged = [
            STEP_HOSTINGS,
            STEP_VOICE,
            STEP_IPV6,
            STEP_SYSTEM,
            STEP_DNS_SERVERS,
        ];
        let step_stages = Arc::clone(&step);
        run.start_stages(
            &staged,
            Arc::new(move |name: &str, finished: bool| {
                if name != STEP_HOSTINGS {
                    step_stages.step(name, u32::from(finished), 1);
                }
            }),
        );
        let registry_wait = (io.registry_start)();

        let freeze_facts = settle(&run, &freeze_future, emit, "Обрыв на 16–20 КБ")?;
        let freeze = freeze_facts
            .as_ref()
            .map(|servers| crate::freeze_check::summarize_freeze(servers, zapret_running));
        sections::emit_freeze(freeze.as_ref(), emit);
        live.put([(
            "freeze".to_string(),
            crate::report_text::freeze_report(freeze.as_ref()).unwrap_or(Value::Null),
        )]);

        let voice_facts = settle(&run, &voice_future, emit, "Голосовые серверы")?;
        let voice = voice_facts
            .as_ref()
            .map(|servers| crate::voice_check::summarize_voice(servers));
        sections::emit_voice(voice.as_ref(), emit);

        let burst = match &burst_future {
            Some(future) => settle(&run, future, emit, "Серия пакетов UDP")?,
            None => None,
        };
        for line in crate::udp_burst::lines(burst.as_ref()) {
            emit(&line);
        }
        live.put([(
            "voice".to_string(),
            crate::report_text::voice_report(voice.as_ref(), burst.as_ref()).unwrap_or(Value::Null),
        )]);

        let ipv6 = settle(&run, &ipv6_future, emit, "IPv6")?;
        if let Some(verdict) = &ipv6 {
            emit("━━━━━━━━ IPv6 ━━━━━━━━");
            emit(&format!(
                "{} IPv6 {}",
                sections::ipv6_icon(&verdict.code),
                verdict.text
            ));
            live.put([(
                "ipv6".to_string(),
                serde_json::json!({"state": verdict.code, "text": verdict.text}),
            )]);
        }

        let system = settle(&run, &system_future, emit, "Состояние системы")?.unwrap_or_default();
        sections::emit_system(&system, emit);
        live.put([(
            "system".to_string(),
            Value::Array(crate::report_text::system_report(&system)),
        )]);

        let telegram_facts = match &telegram_future {
            Some(future) => settle(&run, future, emit, "Дата-центры Telegram")?,
            None => None,
        };
        let telegram = telegram_facts
            .as_ref()
            .map(|servers| crate::telegram_check::summarize_telegram(servers));
        sections::emit_telegram(telegram.as_ref(), emit);

        let network = settle(&run, &network_future, emit, "Ваша сеть")?;
        sections::emit_network(network.as_ref(), emit);
        live.put([
            (
                "telegram".to_string(),
                crate::report_text::telegram_report(telegram.as_ref()).unwrap_or(Value::Null),
            ),
            (
                "network".to_string(),
                network.clone().unwrap_or(Value::Null),
            ),
        ]);

        let dns_servers = match &dns_future {
            Some(future) => {
                let waited = match run.wait(future) {
                    Ok(value) => Ok(value),
                    Err(TaskError::Stopped) => return Err(TaskError::Stopped),
                    Err(error) => Err(error.to_string()),
                };
                sections::finish_dns_servers(waited, emit)
            }
            None => None,
        };
        live.put([(
            "dns_servers".to_string(),
            dns_servers.clone().unwrap_or(Value::Null),
        )]);
        if full {
            step.step(STEP_FILTER, 0, 1);
        }
        let filter_place = if full {
            let own_asn = network
                .as_ref()
                .and_then(|item| item.get("asn"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            filter_place_section(&wired, &collected, emit, zapret_running, &in_path, &own_asn)
        } else {
            None
        };
        let extra = full && !run.dns_cancelled();
        let mut local: Vec<String> = Vec::new();
        if zapret_running == Some(true) {
            local.push("Zapret".to_string());
        }
        local.extend(in_path.iter().cloned());
        let habit_send = Arc::clone(&io.habit_send);
        let habit_rests = Arc::clone(&io.habit_rests);
        let habits_run = Arc::clone(&run);
        let habits_collected = collected.clone();
        let habits_tools = local.clone();
        let habits = if extra {
            attempt(emit, "Как работает фильтр", |forward| {
                let send =
                    move |ip: &str, parts: &[Vec<u8>], pause: f64| (habit_send)(ip, parts, pause);
                let rests = move |seconds: f64| habit_rests(seconds);
                Ok(sections::check_filter_habits(
                    &habits_collected,
                    forward,
                    &|| habits_run.dns_cancelled(),
                    &send,
                    &rests,
                    &habits_tools,
                ))
            })?
            .flatten()
        } else {
            None
        };
        if full {
            step.step(STEP_FILTER, 1, 1);
        }
        let speed = if full && !run.dns_cancelled() {
            let speed_download = Arc::clone(&io.speed_download);
            let speed_fetches = Arc::clone(&io.name_speed_download);
            let speed_run = Arc::clone(&run);
            let speed_known = Arc::clone(&known);
            let speed_io = io.clone();
            let speed_collected = collected.clone();
            let speed_services = services.clone();
            attempt(emit, "Скорость", |forward| {
                let known_lookup = move |host: &str| -> Option<String> {
                    let address = known_address(&speed_io, &speed_known, host);
                    (!address.is_empty()).then_some(address)
                };
                let speed_cancel = Arc::clone(&speed_run);
                let mut fetches = move |ip: &str, name: &str| {
                    (speed_fetches)(ip, name, &speed_cancel.probe_cancel)
                };
                let mut download =
                    move |server: &crate::speed_check::SpeedServer| (speed_download)(server);
                Ok(sections::check_speed(
                    Some(&speed_collected),
                    Some(&speed_services),
                    forward,
                    &move || speed_run.dns_cancelled(),
                    &mut download,
                    &known_lookup,
                    &mut fetches,
                ))
            })?
            .flatten()
        } else {
            None
        };
        // Последней — проба, которая сама может остановить сайт на пару минут.
        let crowd = if full && !run.dns_cancelled() {
            let crowd_hello = Arc::clone(&io.crowd_hello);
            let crowd_together = Arc::clone(&io.crowd_together);
            let crowd_run = Arc::clone(&run);
            let crowd_collected = collected.clone();
            let crowd_services = services.clone();
            let crowd_tools = local.clone();
            attempt(
                emit,
                "Несколько соединений сразу",
                |forward| {
                    let crowd_pause = Arc::clone(&crowd_run);
                    let hello = move |host: &str, ip: &str| (crowd_hello)(host, ip);
                    let together = move || (crowd_together)();
                    Ok(sections::check_crowd(
                        &crowd_collected,
                        &crowd_services,
                        forward,
                        &{
                            let crowd_cancel = Arc::clone(&crowd_run);
                            move || crowd_cancel.dns_cancelled()
                        },
                        &crowd_tools,
                        &hello,
                        &together,
                        &clock_now,
                        &mut move |seconds| crowd_pause.pause(seconds),
                        &move || crowd_run.seconds_left(),
                    ))
                },
            )?
            .flatten()
        } else {
            None
        };
        live.put([
            ("filter".to_string(), filter_place.unwrap_or(Value::Null)),
            ("habits".to_string(), habits.unwrap_or(Value::Null)),
            ("speed".to_string(), speed.clone().unwrap_or(Value::Null)),
            ("crowd".to_string(), crowd.clone().unwrap_or(Value::Null)),
        ]);

        let reference = run.reference_report();
        // Признак «белых списков» по контрольным сайтам проверяется по десяткам
        // сетей: без признака эти сорок соединений не нужны.
        let suspected = {
            let services_entries = crate::problems::Entries::new(services_list.clone());
            let verdict_entries = crate::problems::Entries::new(
                verdicts
                    .iter()
                    .map(|(key, item)| (key.clone(), item.clone()))
                    .collect(),
            );
            let collected_entries = crate::problems::Entries::new(
                collected
                    .iter()
                    .map(|(key, probes)| (key.clone(), probes.clone()))
                    .collect(),
            );
            crate::problems::whitelist_suspected(
                &services_entries,
                &verdict_entries,
                &collected_entries,
                &reference,
            )
        };
        let subnets = if suspected && !run.dns_cancelled() {
            let subnets_check = Arc::clone(&io.subnets_check);
            let subnets_run = Arc::clone(&run);
            attempt(emit, "Подсети", |_forward| {
                subnets_check(&subnets_run)
            })?
            .flatten()
        } else {
            None
        };
        let CollectOutput {
            mut problems,
            working,
            spoofed,
        } = {
            let services_entries = crate::problems::Entries::new(services_list.clone());
            let verdict_entries = crate::problems::Entries::new(
                verdicts
                    .iter()
                    .map(|(key, item)| (key.clone(), item.clone()))
                    .collect(),
            );
            let collected_entries = crate::problems::Entries::new(
                collected
                    .iter()
                    .map(|(key, probes)| (key.clone(), probes.clone()))
                    .collect(),
            );
            let voice_says = voice.as_ref().map(|item| crate::problems::VerdictSays {
                level: item.level,
                headline: item.headline.clone(),
                advice: item.advice.clone(),
            });
            let freeze_says = freeze.as_ref().map(|item| crate::problems::VerdictSays {
                level: item.level,
                headline: item.headline.clone(),
                advice: item.advice.clone(),
            });
            crate::problems::collect_problems(
                &services_entries,
                &verdict_entries,
                &collected_entries,
                voice_says.as_ref(),
                freeze_says.as_ref(),
                zapret_running,
                geo_service_for
                    .as_deref()
                    .map(|item| item as &dyn Fn(&str) -> String),
                &reference,
                ipv6.as_ref(),
                &system,
                telegram.as_ref(),
                subnets.as_ref(),
            )
        };
        problems = with_section_problems(
            problems,
            burst.as_ref(),
            dns_servers.as_ref(),
            speed.as_ref(),
            crowd.as_ref(),
            zapret_running,
        );

        let registry_index = registry_wait(REGISTRY_WAIT_S, &run.probe_cancel);
        if run.stopped() {
            return Err(TaskError::Stopped);
        }
        let services_report = registry::annotate(&services_report, &registry_index);
        for line in registry::lines(&services_report, &registry_index, None) {
            emit(&line);
        }
        emit(&step.line());
        let elapsed = clock_now() - started;
        for line in crate::report_text::summary_lines(
            &problems,
            &working,
            run.timed_out(),
            run.deadline_seconds,
            elapsed,
        ) {
            emit(&line);
        }

        Ok(live.put([
            ("services".to_string(), Value::Array(services_report)),
            (
                "registry".to_string(),
                registry::summary(&registry_index, None),
            ),
            (
                "problems".to_string(),
                Value::Array(
                    problems
                        .iter()
                        .map(crate::problems::problem_value)
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "working".to_string(),
                Value::Array(working.iter().map(|item| json!(item)).collect()),
            ),
            (
                "spoofed_hosts".to_string(),
                Value::Array(spoofed.iter().map(|item| json!(item)).collect()),
            ),
            (
                "reference".to_string(),
                Value::Array(
                    reference
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "label": item.label,
                                "address": item.address,
                                "ok": item.ok,
                                "answered": item.answered,
                                "failed": item.failed,
                                "reason": item.reason,
                            })
                        })
                        .collect::<Vec<_>>(),
                ),
            ),
            ("timed_out".to_string(), json!(run.timed_out())),
            ("elapsed".to_string(), json!(elapsed)),
            ("partial".to_string(), json!(false)),
        ]))
    })();
    run.close();
    match outcome {
        Ok(report) => report,
        Err(TaskError::Stopped) => serde_json::json!({"stopped": true}),
        Err(error) => serde_json::json!({"stopped": true, "error": error.to_string()}),
    }
}

/// python `check_site` — один сайт теми же пробами, что в BlockCheck: TLS 1.2
/// и 1.3, «как Chrome», HTTP, QUIC, способ блокировки.
///
/// Возвращает запись сервиса — такую же, как в `report["services"]` полной
/// проверки (с отметкой реестра РКН), поэтому экран показывает её той же
/// карточкой сайта. `None` — проверку остановили. Нужна «Проверке домена»:
/// там сайт один, а остальные разделы BlockCheck не запускаются.
pub fn check_site(
    host: &str,
    should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    emit: &mut dyn FnMut(&str),
    io: &EngineIo,
) -> Option<Value> {
    let service = site_service(host);
    let services_list = vec![(service.key.clone(), service.clone())];
    let services: BTreeMap<String, Service> = services_list.iter().cloned().collect();
    let run = Run::new(
        should_stop,
        service.targets.len() * workers_per_target() + 12,
        Some(SITE_CHECK_DEADLINE),
    );
    let known = known_addresses();
    let outcome: Result<Option<Value>, TaskError> = (|| {
        let (zapret_running, _line) = (io.system.zapret_status)();
        let registry_wait = (io.registry_start)();
        let collected = run_probes(&run, io, &services_list, true, emit, None, None, false)?;
        let verdicts: BTreeMap<String, ServiceVerdict> = services
            .keys()
            .map(|key| {
                let empty: Vec<Probe> = Vec::new();
                let probes = collected.get(key).unwrap_or(&empty);
                (
                    key.clone(),
                    service_verdict(&services[key], probes, zapret_running),
                )
            })
            .collect();
        let report = crate::report_text::services_report(&services_list, &verdicts, &collected);
        // Сайт может открываться, а поток к нему — придерживаться или
        // обрываться по имени (так «крутит загрузку» видео). Соединение этого
        // не покажет: нужен замер потока с именем сайта и видеосервера.
        let speed_fetches = Arc::clone(&io.name_speed_download);
        let speed_run = Arc::clone(&run);
        let speed_known = Arc::clone(&known);
        let speed_io = io.clone();
        let names = sections::check_name_speed_report(
            &collected,
            &services,
            emit,
            &|| run.dns_cancelled(),
            &move |name: &str| {
                let address = known_address(&speed_io, &speed_known, name);
                (!address.is_empty()).then_some(address)
            },
            &mut move |ip: &str, name: &str| (speed_fetches)(ip, name, &speed_run.probe_cancel),
        );
        let registry_index = registry_wait(REGISTRY_WAIT_S, &run.probe_cancel);
        if run.stopped() {
            return Err(TaskError::Stopped);
        }
        let report = registry::annotate(&report, &registry_index);
        let mut site = report.first().cloned().unwrap_or(Value::Null);
        if !site.is_null() {
            if let Some(names) = names {
                add_name_speed(&mut site, &names, zapret_running);
            }
        }
        Ok((!site.is_null()).then_some(site))
    })();
    run.close();
    outcome.ok().flatten()
}

/// python `run_dns_check` — проверка DNS подмены для вкладки «Проверка DNS подмены».
pub fn run_dns_check(
    should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    emit: &mut dyn FnMut(&str),
    io: &EngineIo,
) -> Value {
    let services_list = build_services(SCOPE_MAIN, &[]);
    let targets_count: u32 = services_list
        .iter()
        .map(|(_key, service)| service.targets.len() as u32)
        .sum();
    let run = Run::new(
        should_stop,
        targets_count as usize * workers_per_target(),
        Some(RUN_DEADLINE),
    );
    let started = clock_now();
    let outcome: Result<Value, TaskError> = (|| {
        emit("🔍 ПРОВЕРКА DNS ПОДМЕНЫ");
        for line in (io.system.environment_lines)() {
            emit(&line);
        }
        emit(
            "Как проверяем: адрес от DNS системы сравниваем с эталоном по DNS-over-HTTPS. \
             Если адреса разные, решает сертификат сервера: подлинный — подмены нет.",
        );

        let collected = run_probes(&run, io, &services_list, false, emit, None, None, false)?;

        let spoofed = has_spoofing(&collected);
        emit("━━━━━━━━ 📊 Итог ━━━━━━━━");
        if run.timed_out() {
            emit(&crate::report_text::timed_out_line(run.deadline_seconds));
        }
        if spoofed {
            emit("❌ Обнаружена DNS подмена:");
            for probes in collected.values() {
                for probe in probes {
                    if probe
                        .judgement
                        .as_ref()
                        .is_some_and(|item| item.state == DnsState::Spoofed)
                    {
                        let reason = probe
                            .judgement
                            .as_ref()
                            .map(|item| item.reason.as_str())
                            .unwrap_or("");
                        emit(&format!("   • {} — {reason}", probe.host));
                    }
                }
            }
            emit(
                "Браузер с защищённым DNS этого не замечает, а программы, которые спрашивают адрес \
                 у Windows, получат неверный ответ.",
            );
            emit("👉 Откройте «Настройка DNS» и включите DNS с шифрованием (DoH) — его провайдер перехватить не сможет.");
        } else if collected.values().flatten().any(|probe| {
            probe
                .judgement
                .as_ref()
                .is_some_and(|item| item.state == DnsState::Unknown)
        }) {
            emit("✅ Явной подмены не найдено. Часть адресов (❔) отличается от эталона, а проверить их не удалось — для CDN это обычно нормально.");
        } else {
            emit("✅ DNS работает честно. Если сайты не открываются — дело не в DNS, а в блокировке соединения.");
        }
        let reference = run.reference_report();
        for item in crate::problems::blocked_references(&reference) {
            emit(&format!("⚠️ {}", crate::problems::reference_text(&item)));
            emit(&format!(
                "   👉 {}",
                crate::problems::ADVICE_BLOCKED_REFERENCE
            ));
        }
        emit(&format!("Проверка заняла {:.1} с.", clock_now() - started));
        let mut domains = serde_json::Map::new();
        for probes in collected.values() {
            for probe in probes {
                let (state, reason) = probe
                    .judgement
                    .as_ref()
                    .map_or((String::new(), String::new()), |item| {
                        (item.state.value().to_string(), item.reason.clone())
                    });
                domains.insert(
                    probe.host.clone(),
                    serde_json::json!({
                        "state": state,
                        "reason": reason,
                        "system_ips": probe.dns.ips.clone(),
                        "reference_ips": probe.reference_ips.clone(),
                        "hosts_ips": probe.hosts_ips.clone(),
                    }),
                );
            }
        }
        Ok(serde_json::json!({
            "summary": {"dns_poisoning_detected": spoofed},
            "reference": reference
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "label": item.label,
                        "address": item.address,
                        "ok": item.ok,
                        "answered": item.answered,
                        "failed": item.failed,
                        "reason": item.reason,
                    })
                })
                .collect::<Vec<_>>(),
            "domains": Value::Object(domains),
        }))
    })();
    run.close();
    match outcome {
        Ok(report) => report,
        Err(TaskError::Stopped) => {
            serde_json::json!({"summary": {"dns_poisoning_detected": false}, "stopped": true})
        }
        Err(error) => serde_json::json!({
            "summary": {"dns_poisoning_detected": false},
            "stopped": true,
            "error": error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe_result::ProbeResult;
    use crate::services::Target;
    use crate::services::SCOPE_MAIN;
    use crate::verdict::Level;
    use crate::verdict::ReachState;

    fn simple_problem(level: Level, text: &str) -> Problem {
        Problem::new(level, text, Vec::new(), "", "", "", "", Vec::new(), "", "")
    }

    fn answer(ips: &[&str], status: i64) -> DnsAnswer {
        DnsAnswer {
            ips: ips.iter().map(|ip| (*ip).to_string()).collect(),
            cnames: Vec::new(),
            status,
            detail: String::new(),
            elapsed_ms: 0.0,
        }
    }

    #[test]
    fn merge_dns_answers_orders_and_counts() {
        let good = answer(&["1.1.1.1", "2.2.2.2"], 0);
        let again = answer(&["2.2.2.2", "3.3.3.3"], 0);
        let (merged, nxdomain) = merge_dns_answers(&[good, again]);
        assert_eq!(merged.ips, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
        assert_eq!(merged.status, 0);
        assert_eq!(nxdomain, 0);

        let denial = answer(&[], DNS_STATUS_NAME_ERROR);
        let empty = DnsAnswer::default();
        let (merged, nxdomain) = merge_dns_answers(&[empty, denial]);
        assert!(merged.ips.is_empty());
        assert_eq!(merged.status, 0, "первый ответ с его кодом");
        assert_eq!(nxdomain, 1);

        let (merged, _) = merge_dns_answers(&[]);
        assert!(merged.ips.is_empty());
    }

    fn probe(host: &str, state: ReachState, spoofed: bool) -> Probe {
        Probe {
            target: Target {
                host: host.to_string(),
                purpose: "сайт",
                path: "/",
                read_body: false,
                main: true,
                discover_googlevideo: false,
            },
            host: host.to_string(),
            reach_state: state,
            judgement: Some(crate::verdict::DnsJudgement {
                state: if spoofed {
                    DnsState::Spoofed
                } else {
                    DnsState::Ok
                },
                reason: String::new(),
            }),
            dns: DnsAnswer {
                ips: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn has_spoofing_scans_all_services() {
        let mut collected: CollectedProbes = BTreeMap::new();
        collected.insert(
            "a".to_string(),
            vec![probe("a.example", ReachState::Ok, false)],
        );
        assert!(!has_spoofing(&collected));
        collected.insert(
            "b".to_string(),
            vec![probe("b.example", ReachState::Dpi, true)],
        );
        assert!(has_spoofing(&collected));
    }

    #[test]
    fn service_verdict_builds_outcomes() {
        let service = Service {
            key: "k".to_string(),
            label: "Сервис".to_string(),
            targets: vec![Target {
                host: "h.example".to_string(),
                purpose: "сайт",
                path: "/",
                read_body: false,
                main: true,
                discover_googlevideo: false,
            }],
            control: false,
            domestic: false,
        };
        let mut spoofed_probe = probe("h.example", ReachState::Dpi, true);
        spoofed_probe.dns.ips.clear();
        let verdict = service_verdict(&service, &[spoofed_probe], Some(false));
        assert_eq!(verdict.level, Level::Fail);
        assert!(
            !verdict.dns_note.is_empty(),
            "подмена DNS — отдельная строка"
        );
    }

    #[test]
    fn section_problems_sorted_by_rank() {
        let mut base = vec![
            simple_problem(Level::Ok, "ok строка"),
            simple_problem(Level::Fail, "fail строка"),
            simple_problem(Level::Warn, "warn строка"),
        ];
        let burst = BurstVerdict {
            code: crate::udp_burst::BURST_FREEZE.to_string(),
            text: "серия замерла".to_string(),
            servers: Vec::new(),
        };
        let merged = with_section_problems(base.split_off(0), Some(&burst), None, None, None, None);
        let ranks: Vec<usize> = merged
            .iter()
            .map(|item| crate::levels::level_rank(item.level.value()))
            .collect();
        assert!(ranks.windows(2).all(|pair| pair[0] <= pair[1]), "{ranks:?}");
        assert!(
            merged.iter().any(|item| item.text.contains("UDP замирает")),
            "{merged:?}"
        );
    }

    #[test]
    fn add_name_speed_downgrades_and_appends_advice() {
        let mut site = json!({
            "label": "YouTube",
            "level": "ok",
            "advice": ["уже есть"],
        });
        let names = json!({
            "level": "warn",
            "items": [
                {"host": "www.youtube.com", "state": "warn"},
                {"host": "cdn.example", "state": "ok"},
            ],
        });
        add_name_speed(&mut site, &names, None);
        assert_eq!(site["level"], "warn");
        assert_eq!(site["status"], "Поток режут");
        assert_eq!(
            site["headline"],
            "YouTube открывается, но поток данных режут по имени: www.youtube.com"
        );
        let advice = site["advice"].as_array().unwrap();
        assert!(advice.contains(&json!("уже есть")));
        assert!(advice
            .iter()
            .any(|item| item.as_str().unwrap_or("").contains("Zapret")));

        // Не warn — запись не меняется.
        let mut calm = json!({"label": "X", "level": "ok"});
        add_name_speed(&mut calm, &json!({"level": "ok", "items": []}), None);
        assert_eq!(calm["level"], "ok");
        assert_eq!(calm["names"]["level"], "ok", "замер дописывается всегда");
    }

    #[test]
    fn fresh_live_data_fields() {
        let data = fresh_live_data(
            SCOPE_MAIN,
            &["система: Windows".to_string()],
            Some(false),
            "Zapret не запущен",
            &["outline".to_string()],
            &[],
        );
        for section in REPORT_SECTIONS {
            assert!(data.contains_key(section), "{section}");
        }
        assert_eq!(data["partial"], json!(true));
        assert_eq!(data["zapret_running"], json!(false));
        assert_eq!(data["other_bypass_tools"], json!(["outline"]));
    }

    // заглушка, чтобы ProbeResult не был «неиспользуемым» импортом при росте модуля
    #[allow(unused)]
    fn _touch(result: &ProbeResult) -> &str {
        &result.kind
    }
}
