//! Золотой тест для `problems.rs`: сверка с python `collect_problems`.
//!
//! Вход и готовый выход построены программой `/tmp/opencode/problems_golden.py`
//! и лежатся рядом (`problems_golden.json`). Каждый сценарий: сервисы,
//! вердикты, пробы, параметры; ожидаемый список проблем, работающих сайтов и
//! подменённых DNS.
use primecore_diagnostics::block_cause;
use primecore_diagnostics::cert_owner::CertVerdict;
use primecore_diagnostics::ipv6_check::Ipv6Verdict;
use primecore_diagnostics::probe_result::{ProbeResult, KIND_OK};
use primecore_diagnostics::problems::{self, Entries, Problem, VerdictSays};
use primecore_diagnostics::quic_probe::QuicVerdict;
use primecore_diagnostics::run_context::{Probe, ReferenceReport};
use primecore_diagnostics::services::{Service, Target};
use primecore_diagnostics::subnet_whitelist::SubnetVerdict;
use primecore_diagnostics::system_state::SystemItem;
use primecore_diagnostics::telegram_check::TelegramReport;
use primecore_diagnostics::verdict::{DnsJudgement, DnsState, Level, ReachState, ServiceVerdict};
use primecore_diagnostics::volume_probe::VolumeVerdict;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct Fixture {
    name: String,
    services: Vec<ServiceEntry>,
    verdicts: std::collections::BTreeMap<String, VerdictEntry>,
    probes: std::collections::BTreeMap<String, Vec<ProbeEntry>>,
    params: Params,
    expected: Expected,
    #[allow(dead_code)]
    #[serde(default)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ServiceEntry {
    key: String,
    label: String,
    #[serde(default)]
    control: bool,
    #[serde(default)]
    domestic: bool,
}

#[derive(Deserialize)]
struct VerdictEntry {
    level: String,
    #[serde(default)]
    headline: String,
    #[serde(default)]
    advice: Vec<String>,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    dns_note: String,
}

#[derive(Deserialize)]
struct ProbeEntry {
    host: String,
    #[serde(default)]
    discovery_note: String,
    #[serde(default)]
    dns_nxdomain: u32,
    #[serde(default)]
    hosts_ips: Vec<String>,
    #[serde(default)]
    reference_ips: Vec<String>,
    #[serde(default)]
    reference_ok: bool,
    #[serde(default)]
    reach: Option<ReachEntry>,
    #[serde(default)]
    reach_source: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    judgement_state: String,
    #[serde(default)]
    judgement_reason: String,
    reach_state: String,
    #[serde(default)]
    cause_code: String,
    #[serde(default)]
    cause_text: String,
    #[serde(default)]
    unstable: String,
    #[serde(default)]
    cert_code: String,
    #[serde(default)]
    cert_text: String,
    #[serde(default)]
    cert_advice: String,
    #[serde(default)]
    quic_code: String,
    #[serde(default)]
    quic_text: String,
    #[serde(default)]
    volume_code: String,
    #[serde(default)]
    volume_text: String,
    #[serde(default)]
    volume_cut_kb: u64,
    #[serde(default, deserialize_with = "empty_string_array_as_none")]
    tried: Vec<(String, String)>,
    #[serde(default)]
    tried_silent: bool,
    #[serde(default)]
    hosts_stale: bool,
    #[serde(default)]
    rechecked: String,
    #[serde(default)]
    outside: String,
    #[serde(default)]
    protocols: Vec<ProtocolEntry>,
}

/// python описывает массивом `[["ip", "kind"], ...]`, а пустое — `[]`.
fn empty_string_array_as_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<(String, String)>, D::Error> {
    let value: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

#[derive(Deserialize)]
struct ProtocolEntry {
    #[serde(default)]
    key: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    word: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct ReachEntry {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    tls_version: String,
    #[serde(default)]
    elapsed_ms: f64,
}

#[derive(Deserialize)]
struct Params {
    #[serde(default)]
    zapret_running: Option<bool>,
    #[serde(default)]
    reference: Vec<RefEntry>,
    #[serde(default)]
    ipv6: Option<Ipv6Entry>,
    #[serde(default)]
    subnets: Option<SubnetsEntry>,
    #[serde(default)]
    voice: Option<SaysEntry>,
    #[serde(default)]
    freeze: Option<SaysEntry>,
    #[serde(default)]
    system: Vec<SystemEntry>,
    #[serde(default)]
    telegram: Option<TelegramEntry>,
    #[serde(default)]
    geo: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    burst: Option<BurstEntry>,
}

#[derive(Deserialize)]
struct RefEntry {
    #[serde(default)]
    label: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    answered: u32,
    #[serde(default)]
    failed: u32,
    #[serde(default)]
    reason: String,
}

impl From<&RefEntry> for ReferenceReport {
    fn from(entry: &RefEntry) -> Self {
        ReferenceReport::from(
            &entry.label,
            &entry.address,
            entry.ok,
            entry.answered,
            entry.failed,
            &entry.reason,
        )
    }
}

#[derive(Deserialize)]
struct Ipv6Entry {
    code: String,
    text: String,
}

#[derive(Deserialize)]
struct SubnetsEntry {
    code: String,
    #[serde(default)]
    ru_open: usize,
    #[serde(default)]
    ru_total: usize,
    #[serde(default)]
    foreign_open: usize,
    #[serde(default)]
    foreign_total: usize,
}

#[derive(Deserialize)]
struct SaysEntry {
    level: String,
    #[serde(default)]
    headline: String,
    #[serde(default)]
    advice: Vec<String>,
}

#[derive(Deserialize)]
struct SystemEntry {
    #[serde(default)]
    key: String,
    title: String,
    level: String,
    text: String,
    #[serde(default)]
    advice: String,
}

#[derive(Deserialize)]
struct TelegramEntry {
    level: String,
    #[serde(default)]
    headline: String,
    #[serde(default)]
    advice: Vec<String>,
}

#[derive(Deserialize)]
struct BurstEntry {
    code: String,
    #[serde(default)]
    text: String,
    #[allow(dead_code)]
    #[serde(default)]
    servers: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Expected {
    problems: Vec<ProblemEntry>,
    working: Vec<String>,
    spoofed: Vec<String>,
}

#[derive(Deserialize)]
struct ProblemEntry {
    level: String,
    text: String,
    #[serde(default)]
    advice: Vec<String>,
    #[serde(default)]
    action: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    site: String,
    #[serde(default)]
    section: String,
}

impl ProblemEntry {
    fn matches(&self, problem: &Problem) -> bool {
        self.level == problem.level.value()
            && self.text == problem.text
            && self.advice == problem.advice
            && self.kind == problem.kind
            && self.action == problem.action
            && self.target == problem.target
            && self.title == problem.title
            && self.evidence == problem.evidence
            && self.site == problem.site
            && self.section == problem.section
    }
}

fn verdict(value: &VerdictEntry) -> ServiceVerdict {
    ServiceVerdict {
        level: Level::from_ascii(&value.level),
        headline: value.headline.clone(),
        advice: value.advice.clone(),
        dns_note: value.dns_note.clone(),
        kind: value.kind.clone(),
    }
}

fn probe(value: &ProbeEntry) -> Probe {
    with_defaults(
        Probe {
            target: Target {
                host: value.host.clone(),
                purpose: "сайт",
                ..Default::default()
            },
            host: value.host.clone(),
            discovery_note: value.discovery_note.clone(),
            ..Default::default()
        },
        value,
    )
}

/// Поля, которые python ставит по входу сценария.
fn with_defaults(mut self_data: Probe, value: &ProbeEntry) -> Probe {
    self_data.dns_nxdomain = value.dns_nxdomain;
    self_data.hosts_ips = value.hosts_ips.clone();
    self_data.reference_ips = value.reference_ips.clone();
    self_data.reference_ok = value.reference_ok;
    if let Some(reach) = value.reach.as_ref() {
        self_data.reach = Some(ProbeResult {
            kind: if reach.kind.is_empty() {
                KIND_OK.to_string()
            } else {
                reach.kind.clone()
            },
            ip: reach.ip.clone(),
            tls_version: reach.tls_version.clone(),
            elapsed_ms: reach.elapsed_ms,
            ..Default::default()
        });
    }
    self_data.reach_source = value.reach_source.clone();
    self_data.attempts = value.attempts;
    if !value.judgement_state.is_empty() {
        self_data.judgement = Some(DnsJudgement {
            state: DnsState::from_ascii(&value.judgement_state),
            reason: value.judgement_reason.clone(),
        });
    }
    self_data.reach_state = ReachState::from_ascii(&value.reach_state);
    if !value.cause_code.is_empty() {
        self_data.cause = Some(block_cause::Cause::new(
            &value.cause_code,
            &value.cause_text,
            true,
        ));
    }
    self_data.unstable = value.unstable.clone();
    if !value.cert_code.is_empty() {
        self_data.cert = Some(CertVerdict {
            code: value.cert_code.clone(),
            text: value.cert_text.clone(),
            advice: value.cert_advice.clone(),
            ..Default::default()
        });
    }
    if !value.quic_code.is_empty() {
        self_data.quic = Some(QuicVerdict {
            code: value.quic_code.clone(),
            text: value.quic_text.clone(),
        });
    }
    if !value.volume_code.is_empty() {
        self_data.volume = Some(VolumeVerdict {
            code: value.volume_code.clone(),
            text: value.volume_text.clone(),
            cut_kb: value.volume_cut_kb,
        });
    }
    self_data.protocols = value
        .protocols
        .iter()
        .map(|line| primecore_diagnostics::protocol_probe::ProtocolLine {
            key: line.key.clone(),
            title: line.title.clone(),
            state: line.state.clone(),
            word: line.word.clone(),
            text: line.text.clone(),
            ..Default::default()
        })
        .collect();
    self_data.tried = value.tried.clone();
    self_data.tried_silent = value.tried_silent;
    self_data.hosts_stale = value.hosts_stale;
    self_data.rechecked = value.rechecked.clone();
    self_data.outside = value.outside.clone();
    self_data
}

fn says(value: &SaysEntry) -> VerdictSays {
    VerdictSays {
        level: Level::from_ascii(&value.level),
        headline: value.headline.clone(),
        advice: value.advice.clone(),
    }
}

/// Сценарии, где без полного списка сервисов не собрать.
fn build_services(lines: &[ServiceEntry]) -> Entries<Service> {
    Entries::new(
        lines
            .iter()
            .map(|entry| {
                (
                    entry.key.clone(),
                    Service {
                        key: entry.key.clone(),
                        label: entry.label.clone(),
                        targets: vec![Target {
                            host: entry.key.clone(),
                            purpose: "сайт",
                            ..Default::default()
                        }],
                        control: entry.control,
                        domestic: entry.domestic,
                    },
                )
            })
            .collect(),
    )
}

fn run_case(case: &Fixture) {
    let services = build_services(&case.services);
    let verdicts = Entries::new(
        case.services
            .iter()
            .map(|entry| {
                (
                    entry.key.clone(),
                    verdict(case.verdicts.get(&entry.key).unwrap_or(&VerdictEntry {
                        level: "ok".to_string(),
                        headline: String::new(),
                        advice: Vec::new(),
                        kind: String::new(),
                        dns_note: String::new(),
                    })),
                )
            })
            .collect(),
    );
    let collected = Entries::new(
        case.services
            .iter()
            .map(|service| {
                (
                    service.key.clone(),
                    case.probes
                        .get(&service.key)
                        .map(|probes| probes.iter().map(probe).collect())
                        .unwrap_or_default(),
                )
            })
            .collect(),
    );
    let reference: Vec<ReferenceReport> = case
        .params
        .reference
        .iter()
        .map(|entry| {
            ReferenceReport::from(
                &entry.label,
                &entry.address,
                entry.ok,
                entry.answered,
                entry.failed,
                &entry.reason,
            )
        })
        .collect();
    let ipv6 = case.params.ipv6.as_ref().map(|entry| Ipv6Verdict {
        code: entry.code.clone(),
        text: entry.text.clone(),
    });
    let subnets = case.params.subnets.as_ref().map(|entry| SubnetVerdict {
        code: entry.code.clone(),
        ru_open: entry.ru_open,
        ru_total: entry.ru_total,
        foreign_open: entry.foreign_open,
        foreign_total: entry.foreign_total,
    });
    let voice = case.params.voice.as_ref().map(says);
    let freeze = case.params.freeze.as_ref().map(says);
    let system: Vec<SystemItem> = case
        .params
        .system
        .iter()
        .map(|entry| SystemItem {
            key: entry.key.clone(),
            title: entry.title.clone(),
            level: entry.level.clone(),
            text: entry.text.clone(),
            advice: entry.advice.clone(),
        })
        .collect();
    let telegram = case.params.telegram.as_ref().map(|entry| TelegramReport {
        level: Level::from_ascii(&entry.level),
        headline: entry.headline.clone(),
        advice: entry.advice.clone(),
        servers: Vec::new(),
    });
    let geo = case.params.geo.clone();
    let geo_for = |host: &str| -> String { geo.get(host).cloned().unwrap_or_default() };
    let result = problems::collect_problems(
        &services,
        &verdicts,
        &collected,
        voice.as_ref(),
        freeze.as_ref(),
        case.params.zapret_running,
        Some(&geo_for),
        &reference,
        ipv6.as_ref(),
        &system,
        telegram.as_ref(),
        subnets.as_ref(),
    );
    assert_eq!(
        case.expected.problems.len(),
        result.problems.len(),
        "{}: число проблем",
        case.name
    );
    for (index, (line, actual)) in case
        .expected
        .problems
        .iter()
        .zip(result.problems.iter())
        .enumerate()
    {
        assert!(
            line.matches(actual),
            "{}[{}]: ожидалось «{}» / {}",
            case.name,
            index,
            line.text,
            actual.text
        );
    }
    assert_eq!(
        case.expected.working, result.working,
        "{}: работающие",
        case.name
    );
    assert_eq!(
        case.expected.spoofed, result.spoofed,
        "{}: подменённые",
        case.name
    );
}

const JSON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/problems_golden.json");

fn fixtures() -> Vec<Fixture> {
    let text = std::fs::read_to_string(JSON_PATH).expect("problems_golden.json рядом с тестом");
    serde_json::from_str(&text).expect("JSON читается")
}

#[test]
fn golden_collect_problems() {
    for case in fixtures() {
        if matches!(case.name.as_str(), "burst_freeze" | "reference_helpers") {
            continue;
        }
        run_case(&case);
    }
}

#[test]
fn golden_burst_problems() {
    for case in fixtures() {
        if case.name != "burst_freeze" {
            continue;
        }
        let burst = case.params.burst.as_ref().expect("burst в сценарии");
        let verdict = primecore_diagnostics::udp_burst::BurstVerdict {
            code: burst.code.clone(),
            text: burst.text.clone(),
            servers: Vec::new(),
        };
        let got = problems::burst_problems(Some(&verdict));
        assert_eq!(
            got.len(),
            case.expected.problems.len(),
            "{}: число проблем burst",
            case.name
        );
        for line in case.expected.problems.iter() {
            assert!(
                line.matches(got.first().unwrap()),
                "{}: burst mismatch",
                case.name
            );
        }
        assert!(problems::burst_problems(None).is_empty());
    }
}

#[test]
fn golden_reference_helpers() {
    for case in fixtures() {
        if case.name != "reference_helpers" {
            continue;
        }
        let reference: Vec<ReferenceReport> = case
            .params
            .reference
            .iter()
            .map(|entry| {
                ReferenceReport::from(
                    &entry.label,
                    &entry.address,
                    entry.ok,
                    entry.answered,
                    entry.failed,
                    &entry.reason,
                )
            })
            .collect();
        let blocked = problems::blocked_references(&reference);
        assert_eq!(
            blocked.len(),
            case.expected.problems.len(),
            "{}: число недоступных",
            case.name
        );
        for line in case.expected.problems.iter() {
            assert_eq!(
                line.text,
                problems::reference_text(&blocked[0]),
                "{}: reference_text",
                case.name
            );
        }
        // Если молчат все — это «нет интернета»: списка нет.
        let all_down: Vec<ReferenceReport> = reference
            .iter()
            .map(|item| ReferenceReport {
                ok: false,
                ..item.clone()
            })
            .collect();
        assert!(problems::blocked_references(&all_down).is_empty());
    }
}
