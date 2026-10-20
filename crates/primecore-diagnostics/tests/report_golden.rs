//! Золотой тест для сборщиков отчёта `report_text.rs`: сверка с python
//! `report_text` (`target_report`, `services_report`, `voice_report`,
//! `freeze_report`, `telegram_report`, `system_report`).
//!
//! Вход и готовый выход построены программой `/tmp/opencode/report_golden.py`
//! и лежатся рядом (`report_golden.json`). Каждый сценарий: вход цели/сервисов
//! или разделов; ожидаемый словарь отчёта — тот, что вернул python.
use primecore_diagnostics::block_cause::Cause;
use primecore_diagnostics::cert_owner::CertVerdict;
use primecore_diagnostics::freeze_check::{FreezeReport, FreezeServer, FreezeState};
use primecore_diagnostics::probe_result::ProbeResult;
use primecore_diagnostics::protocol_probe::ProtocolLine;
use primecore_diagnostics::quic_probe::QuicVerdict;
use primecore_diagnostics::report_text;
use primecore_diagnostics::run_context::Probe;
use primecore_diagnostics::services::{Service, Target};
use primecore_diagnostics::system_state::SystemItem;
use primecore_diagnostics::telegram_check::{DcResult, TelegramReport};
use primecore_diagnostics::udp_burst::BurstVerdict;
use primecore_diagnostics::verdict::{DnsJudgement, DnsState, Level, ReachState, ServiceVerdict};
use primecore_diagnostics::voice_check::{VoiceReport, VoiceServer};
use primecore_diagnostics::volume_probe::VolumeVerdict;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Fixture {
    name: String,
    kind: String,
    input: Value,
    expected: Value,
}

fn leak(value: &str) -> &'static str {
    Box::leak(value.to_string().into_boxed_str())
}

/// Поле записи, которого может не быть: `Value::Null` вместо паники индексации.
fn fld<'a>(entry: &'a Value, key: &str) -> &'a Value {
    entry.get(key).unwrap_or(&Value::Null)
}

/// python возвращает `None` — в JSON это `null`.
fn opt(value: &Value) -> Option<Value> {
    if value.is_null() {
        None
    } else {
        Some(value.clone())
    }
}

fn level(word: &str) -> Level {
    match word {
        "ok" => Level::Ok,
        "warn" => Level::Warn,
        "fail" => Level::Fail,
        _ => Level::Unknown,
    }
}

fn dns_state(word: &str) -> DnsState {
    match word {
        "ok" => DnsState::Ok,
        "spoofed" => DnsState::Spoofed,
        "local" => DnsState::Local,
        _ => DnsState::Unknown,
    }
}

fn reach_state(word: &str) -> ReachState {
    match word {
        "ok" => ReachState::Ok,
        "dpi" => ReachState::Dpi,
        "freeze" => ReachState::Freeze,
        "ip_block" => ReachState::IpBlock,
        "cert" => ReachState::Cert,
        "no_address" => ReachState::NoAddress,
        _ => ReachState::Unknown,
    }
}

fn string_or_empty(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn make_probe(entry: &Value) -> Probe {
    let reach_ip = fld(entry, "reach_ip").as_str().unwrap_or_default();
    Probe {
        target: Target {
            host: string_or_empty(entry, "host"),
            purpose: leak(fld(entry, "purpose").as_str().unwrap_or_default()),
            path: leak("/"),
            read_body: false,
            main: fld(entry, "main").as_bool().unwrap_or_default(),
            discover_googlevideo: false,
        },
        service: string_or_empty(entry, "service"),
        host: string_or_empty(entry, "host"),
        discovery_note: string_or_empty(entry, "discovery_note"),
        dns_nxdomain: fld(entry, "dns_nxdomain").as_u64().unwrap_or_default() as u32,
        hosts_ips: strings(entry, "hosts_ips"),
        reference_ips: strings(entry, "reference_ips"),
        reach: if reach_ip.is_empty() {
            None
        } else {
            Some(ProbeResult {
                ip: reach_ip.to_string(),
                kind: primecore_diagnostics::probe_result::KIND_OK.to_string(),
                ..Default::default()
            })
        },
        reach_state: reach_state(fld(entry, "reach_state").as_str().unwrap_or_default()),
        judgement: fld(entry, "judgement")
            .as_object()
            .map(|item| DnsJudgement {
                state: dns_state(item["state"].as_str().unwrap_or_default()),
                reason: item["reason"].as_str().unwrap_or_default().to_string(),
            }),
        cause: fld(entry, "cause").as_object().map(|item| Cause {
            code: item["code"].as_str().unwrap_or_default().to_string(),
            text: item["text"].as_str().unwrap_or_default().to_string(),
            confident: item
                .get("confident")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }),
        unstable: string_or_empty(entry, "unstable"),
        cert: fld(entry, "cert").as_object().map(|item| CertVerdict {
            code: item["code"].as_str().unwrap_or_default().to_string(),
            text: item["text"].as_str().unwrap_or_default().to_string(),
            advice: item["advice"].as_str().unwrap_or_default().to_string(),
            subject: item["subject"].as_str().unwrap_or_default().to_string(),
            issuer: item["issuer"].as_str().unwrap_or_default().to_string(),
            names: item["names"]
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .map(|name| name.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default(),
        }),
        quic: fld(entry, "quic").as_object().map(|item| QuicVerdict {
            code: item["code"].as_str().unwrap_or_default().to_string(),
            text: item["text"].as_str().unwrap_or_default().to_string(),
        }),
        volume: fld(entry, "volume").as_object().map(|item| VolumeVerdict {
            code: item["code"].as_str().unwrap_or_default().to_string(),
            text: item["text"].as_str().unwrap_or_default().to_string(),
            cut_kb: item
                .get("cut_kb")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        }),
        protocols: fld(entry, "protocols")
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .map(|line| ProtocolLine {
                        key: string_or_empty(line, "key"),
                        title: string_or_empty(line, "title"),
                        state: string_or_empty(line, "state"),
                        word: string_or_empty(line, "word"),
                        text: string_or_empty(line, "text"),
                        ms: line.get("ms").and_then(Value::as_f64),
                        code: string_or_empty(line, "code"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        tried: fld(entry, "tried")
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|pair| {
                        (
                            pair[0].as_str().unwrap_or_default().to_string(),
                            pair[1].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        tried_silent: fld(entry, "tried_silent").as_bool().unwrap_or_default(),
        hosts_stale: fld(entry, "hosts_stale").as_bool().unwrap_or_default(),
        rechecked: string_or_empty(entry, "rechecked"),
        outside: string_or_empty(entry, "outside"),
        seconds: fld(entry, "seconds").as_f64().unwrap_or_default(),
        stages: fld(entry, "stages")
            .as_object()
            .map(|items| {
                items
                    .iter()
                    .map(|(key, value)| (key.clone(), value.as_f64().unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn make_service(entry: &Value) -> (String, Service) {
    let service = Service {
        key: string_or_empty(entry, "key"),
        label: string_or_empty(entry, "label"),
        targets: vec![Target {
            host: "h".to_string(),
            purpose: "сайт",
            path: "/",
            read_body: false,
            main: false,
            discover_googlevideo: false,
        }],
        control: entry["control"].as_bool().unwrap_or_default(),
        domestic: entry["domestic"].as_bool().unwrap_or_default(),
    };
    (service.key.clone(), service)
}

fn make_verdict(entry: &Value) -> ServiceVerdict {
    ServiceVerdict {
        level: level(entry["level"].as_str().unwrap_or_default()),
        headline: string_or_empty(entry, "headline"),
        advice: strings(entry, "advice"),
        dns_note: string_or_empty(entry, "dns_note"),
        kind: string_or_empty(entry, "kind"),
    }
}

fn make_voice(entry: &Value) -> VoiceReport {
    VoiceReport {
        level: level(entry["level"].as_str().unwrap_or_default()),
        headline: string_or_empty(entry, "headline"),
        servers: entry["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .map(|item| VoiceServer {
                name: string_or_empty(item, "name"),
                host: string_or_empty(item, "host"),
                answered: item["answered"].as_bool().unwrap_or_default(),
                text: string_or_empty(item, "text"),
                decided: item["decided"].as_bool().unwrap_or(true),
                group: "general".to_string(),
            })
            .collect(),
        advice: strings(entry, "advice"),
    }
}

fn make_burst(entry: &Value) -> BurstVerdict {
    BurstVerdict {
        code: string_or_empty(entry, "code"),
        text: string_or_empty(entry, "text"),
        servers: entry["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap_or_default().to_string(),
                    pair[1]
                        .as_array()
                        .expect("series")
                        .iter()
                        .map(|item| item.as_str().unwrap_or_default().to_string())
                        .collect::<Vec<_>>(),
                )
            })
            .collect(),
    }
}

fn make_freeze(entry: &Value) -> FreezeReport {
    FreezeReport {
        level: level(entry["level"].as_str().unwrap_or_default()),
        headline: string_or_empty(entry, "headline"),
        servers: entry["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .map(|item| FreezeServer {
                name: string_or_empty(item, "name"),
                state: match item["state"].as_str().unwrap_or_default() {
                    "ok" => FreezeState::Ok,
                    "freeze" => FreezeState::Freeze,
                    _ => FreezeState::Unknown,
                },
                text: string_or_empty(item, "text"),
                direction: string_or_empty(item, "direction"),
                provider: string_or_empty(item, "provider"),
                host: string_or_empty(item, "host"),
                ident: string_or_empty(item, "ident"),
                seconds: item["seconds"].as_f64().unwrap_or_default(),
            })
            .collect(),
        advice: strings(entry, "advice"),
    }
}

fn make_telegram(entry: &Value) -> TelegramReport {
    TelegramReport {
        level: level(entry["level"].as_str().unwrap_or_default()),
        headline: string_or_empty(entry, "headline"),
        servers: entry["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .map(|item| DcResult {
                name: string_or_empty(item, "name"),
                address: string_or_empty(item, "address"),
                connected: item["connected"].as_bool(),
                ms: item["ms"].as_f64(),
                attempts: item["attempts"].as_u64().unwrap_or(1) as u32,
            })
            .collect(),
        advice: strings(entry, "advice"),
    }
}

fn make_system(entry: &Value) -> SystemItem {
    SystemItem {
        key: string_or_empty(entry, "key"),
        title: string_or_empty(entry, "title"),
        level: string_or_empty(entry, "level"),
        text: string_or_empty(entry, "text"),
        advice: string_or_empty(entry, "advice"),
    }
}

#[test]
fn golden_report_builders() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/report_golden.json"),
    )
    .expect("fixture");
    let fixtures: Vec<Fixture> = serde_json::from_str(&text).expect("fixture json");
    assert!(fixtures.len() >= 5, "нужны все сценарии");
    for fixture in fixtures {
        match fixture.kind.as_str() {
            "target_report" => {
                let probe = make_probe(&fixture.input);
                assert_eq!(
                    report_text::target_report(&probe),
                    fixture.expected,
                    "сценарий {}",
                    fixture.name
                );
            }
            "services_report" => {
                let services: Vec<(String, Service)> = fixture.input["services"]
                    .as_array()
                    .expect("services")
                    .iter()
                    .map(make_service)
                    .collect();
                let verdicts: BTreeMap<String, ServiceVerdict> = fixture.input["verdicts"]
                    .as_object()
                    .expect("verdicts")
                    .iter()
                    .map(|(key, entry)| (key.clone(), make_verdict(entry)))
                    .collect();
                let mut collected: BTreeMap<String, Vec<Probe>> = BTreeMap::new();
                for entry in fixture.input["probes"].as_array().expect("probes") {
                    collected
                        .entry(string_or_empty(entry, "service"))
                        .or_default()
                        .push(make_probe(entry));
                }
                assert_eq!(
                    serde_json::to_value(report_text::services_report(
                        &services, &verdicts, &collected
                    ))
                    .unwrap(),
                    fixture.expected,
                    "сценарий {}",
                    fixture.name
                );
            }
            "sections" => {
                let voice = if fixture.input["voice"].is_null() {
                    None
                } else {
                    Some(make_voice(&fixture.input["voice"]))
                };
                let burst = if fixture.input["burst"].is_null() {
                    None
                } else {
                    Some(make_burst(&fixture.input["burst"]))
                };
                let freeze = if fixture.input["freeze"].is_null() {
                    None
                } else {
                    Some(make_freeze(&fixture.input["freeze"]))
                };
                let telegram = if fixture.input["telegram"].is_null() {
                    None
                } else {
                    Some(make_telegram(&fixture.input["telegram"]))
                };
                let system: Vec<SystemItem> = fixture.input["system"]
                    .as_array()
                    .map(|items| items.iter().map(make_system).collect())
                    .unwrap_or_default();
                let expected = &fixture.expected;
                assert_eq!(
                    report_text::voice_report(voice.as_ref(), burst.as_ref()),
                    opt(&expected["voice"]),
                    "сценарий {}: voice",
                    fixture.name
                );
                assert_eq!(
                    report_text::freeze_report(freeze.as_ref()),
                    opt(&expected["freeze"]),
                    "сценарий {}: freeze",
                    fixture.name
                );
                assert_eq!(
                    report_text::telegram_report(telegram.as_ref()),
                    opt(&expected["telegram"]),
                    "сценарий {}: telegram",
                    fixture.name
                );
                assert_eq!(
                    serde_json::to_value(report_text::system_report(&system)).unwrap(),
                    expected["system"],
                    "сценарий {}: system",
                    fixture.name
                );
            }
            other => panic!("неизвестный вид сценария: {other}"),
        }
    }
}
