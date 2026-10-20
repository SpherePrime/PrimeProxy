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
