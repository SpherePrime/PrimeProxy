//! Порт `src/diagnostics/sections.py` — проверки отдельных разделов BlockCheck.
//!
//! Каждая функция отвечает за один раздел отчёта: собирает факты снаружи
//! (транспорт — замыканиями, как в python передаются `pair`/`probe`/`emit`),
//! отдаёт их чистому судье своего модуля и возвращает готовый итог.
//!
//! Порядок разделов и общий отчёт — дело движка (python `diagnostics.engine`);
//! здесь нет ничего про сайты и сервисы. Python-потоки через `run.submit` в
//! порте собираются подряд: набор проб и порядок те же, а параллель решает
//! движок — он передаёт замыкания, которые сами бегут на потоках.
//!
//! Python-функции, которые целиком держатся на потоках `Run` (обновление
//! реестра, состояние системы с DNS-поиском, замер обрыва и загрузки,
//! самопроверка перехвата, IPv6, приёмник «сайт проверен», строки окружения) —
//! забота движка: см. `docs_porting-notes.md`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::block_cause::CAUSE_BY_NAME;
use crate::block_kind::{KIND_DNS, KIND_SNI};
use crate::crowd_probe::{CrowdFacts, CrowdVerdict};
use crate::crowd_probe::{CROWD_FREEZE, CROWD_NONE, CROWD_STUCK};
use crate::dns_place::{DnsPlaceVerdict, TtlAsk, DNS_SERVER, MAX_TTL as DNS_MAX_TTL};
use crate::filter_place;
use crate::freeze_check::{FreezeReport, FreezeState};
use crate::limits::FILTER_MAX_TTL;
use crate::limits::OUTSIDE_NEEDS_S;
use crate::name_speed::{self as name_speed_mod, NameRun};
use crate::path_trace::{
    locate_filter, tcp_distance, DistanceOf, FilterFacts, PathPair, RouteTrace, MAX_HOPS,
};
use crate::probe_result::KIND_RESET;
use crate::problems::{Problem, SECTION_CROWD, SECTION_DNS_SERVERS, SECTION_SPEED};
use crate::quic_probe::QUIC_BLOCKED_BY_NAME;
use crate::run_context::Probe;
use crate::telegram_check::TelegramReport;
use crate::verdict::{Level, ReachState as ReachStateKind};

/// python `IPV6_ICON`.
#[must_use]
pub fn ipv6_icon(code: &str) -> &'static str {
    match code {
        crate::ipv6_check::IPV6_OK => "✅",
        crate::ipv6_check::IPV6_ABSENT => "ℹ️",
        crate::ipv6_check::IPV6_BROKEN => "⚠️",
        _ => "❔",
    }
}

/// python `SYSTEM_ICON`.
#[must_use]
pub fn system_icon(level: &str) -> &'static str {
    match level {
        crate::system_state::LEVEL_OK => "✅",
        crate::system_state::LEVEL_INFO => "ℹ️",
        crate::system_state::LEVEL_WARN => "⚠️",
        crate::system_state::LEVEL_FAIL => "❌",
        _ => "❔",
    }
}

/// python `_DNS_FINDING_ICON`.
#[must_use]
pub fn dns_finding_icon(level: &str) -> &'static str {
    match level {
        "ok" => "✅",
        "warn" => "⚠️",
        "fail" => "❌",
        _ => "ℹ️",
    }
}

pub const HABIT_SITES: usize = 3;
/// Срок одной пробы дробления: их десятки подряд к одному адресу. Сервер
/// отвечает на приветствие за доли секунды; на линии, где фильтр молча глотает
/// пакеты, три секунды на пробу давали полторы минуты на шаг.
pub const HABIT_TIMEOUT_S: f64 = 2.0;
pub const ECH_HOST: &str = "www.cloudflare.com";

/// Сколько секунд общего срока проверки оставить после ожидания замороженного
/// сайта — на итог и запись отчёта.
pub const CROWD_RESERVE_S: f64 = 10.0;

/// Готовые части находки про DNS: заголовок, все серверы парами «сервис, адрес»
/// и пояснение. Пусто (`Null`), если проверка их не дала: тогда экран делит фразу сам.
#[must_use]
pub fn dns_finding_parts(finding: &Value) -> Value {
    let title = finding["title"].as_str().unwrap_or("");
    if title.is_empty() {
        return Value::Null;
    }
    let servers: Vec<Value> = finding["servers"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|pair| {
            let items = pair.as_array()?;
            (items.len() == 2).then(|| {
                json!([
                    items[0].as_str().unwrap_or(""),
                    items[1].as_str().unwrap_or("")
                ])
            })
        })
        .collect();
    json!({
        "title": title,
        "servers": servers,
        "note": finding["note"].as_str().unwrap_or(""),
    })
}

fn level_of_word(word: &str) -> Option<Level> {
    match word {
        "ok" => Some(Level::Ok),
        "warn" => Some(Level::Warn),
        "fail" => Some(Level::Fail),
        _ => None,
    }
}

/// Итог проверки DNS-серверов для полной проверки: печатает раздел и возвращает словарь.
///
/// `waited` — уже ожидаемый итог `run.wait(future)`: `Err(exc)` — проверка не выполнилась.
pub fn finish_dns_servers(
    waited: Result<Value, String>,
    emit: &mut dyn FnMut(&str),
) -> Option<Value> {
    let result = match waited {
        Ok(item) if item.is_object() => item,
        Err(exc) => {
            emit(&format!("❔ DNS-серверы: проверка не выполнилась ({exc})"));
            return None;
        }
        Ok(_) => return None,
    };
    let mut findings: Vec<Value> = Vec::new();
    for item in result["findings"].as_array().unwrap_or(&Vec::new()) {
        let text = item["text"].as_str().unwrap_or("");
        if text.is_empty() {
            continue;
        }
        let mut record = Map::new();
        record.insert(
            "level".into(),
            json!(item["level"].as_str().unwrap_or("info")),
        );
        record.insert("text".into(), json!(text));
        let parts = dns_finding_parts(item);
        if let Value::Object(extra) = parts {
            for (key, value) in extra {
                record.insert(key, value);
            }
        }
        findings.push(Value::Object(record));
    }
    emit("");
    emit("━━━━━━━━ DNS-серверы ━━━━━━━━");
    for finding in &findings {
        emit(&format!(
            "{} {}",
            dns_finding_icon(finding["level"].as_str().unwrap_or("info")),
            finding["text"].as_str().unwrap_or("")
        ));
    }
    let text = result["text"].as_str().unwrap_or("").to_string();
    for line in text.lines() {
        emit(&format!("   {line}"));
    }
    Some(json!({
        "level": result["level"].as_str().unwrap_or("unknown"),
        "findings": findings,
        "text": text,
    }))
}

/// Основное соединение с сайтом оборвалось сбросом (а не тишиной).
#[must_use]
pub fn tcp_reset_seen(probe: &Probe) -> bool {
    probe
        .reach
        .as_ref()
        .is_some_and(|item| item.kind == KIND_RESET)
}

/// Находки проверки DNS-серверов строками итога.
#[must_use]
pub fn dns_problems(dns_servers: Option<&Value>) -> Vec<Problem> {
    let mut found: Vec<Problem> = Vec::new();
    for finding in dns_servers
        .and_then(|item| item["findings"].as_array().cloned())
        .unwrap_or_default()
    {
        let Some(level) = level_of_word(finding["level"].as_str().unwrap_or("info")) else {
            continue;
        };
        let mut record = Problem::new(
            level,
            finding["text"].as_str().unwrap_or(""),
            Vec::new(),
            "dns",
            "",
            KIND_DNS,
            "",
            Vec::new(),
            "",
            SECTION_DNS_SERVERS,
        );
        record.parts = parts_of(&finding);
        found.push(record);
    }
    found
}

/// python `Problem.parts` у находок про DNS — словарь с заголовком, списком
/// серверов и пояснением; в Rust он готовым JSON.
fn parts_of(finding: &Value) -> Option<Value> {
    let item = dns_finding_parts(finding);
    (!item.is_null()).then_some(item)
}

/// Раздел «Обрыв на 16–20 КБ» текстового отчёта.
pub fn emit_freeze(freeze: Option<&FreezeReport>, emit: &mut dyn FnMut(&str)) {
    let Some(item) = freeze else {
        return;
    };
    let rows: Vec<(String, String, String)> = item
        .servers
        .iter()
        .map(|server| {
            let mark = match server.state {
                FreezeState::Ok => "✅",
                FreezeState::Freeze => "❌",
                FreezeState::Unknown => "❔",
            };
            (mark.to_string(), server.name.clone(), server.text.clone())
        })
        .collect();
    for line in crate::report_text::section_level_lines(
        "Обрыв на 16–20 КБ",
        item.level,
        &item.headline,
        &rows,
    ) {
        emit(&line);
    }
}

/// Раздел «Telegram: дата-центры» текстового отчёта.
pub fn emit_telegram(telegram: Option<&TelegramReport>, emit: &mut dyn FnMut(&str)) {
    let Some(item) = telegram else {
        return;
    };
    let rows: Vec<(String, String, String)> = item
        .servers
        .iter()
        .map(|server| {
            let mark = match crate::report_text::telegram_state(server).as_str() {
                "ok" => "✅",
                "fail" => "❌",
                _ => "❔",
            };
            (
                mark.to_string(),
                format!("{} ({})", server.name, server.address),
                crate::report_text::telegram_text(server),
            )
        })
        .collect();
    for line in crate::report_text::section_level_lines(
        "Telegram: дата-центры",
        item.level,
        &item.headline,
        &rows,
    ) {
        emit(&line);
    }
}

/// Раздел «Состояние системы» текстового отчёта.
pub fn emit_system(system: &[crate::system_state::SystemItem], emit: &mut dyn FnMut(&str)) {
    if system.is_empty() {
        return;
    }
    emit("");
    emit("━━━━━━━━ Состояние системы ━━━━━━━━");
    for item in system {
        let icon = match item.level.as_str() {
            crate::system_state::LEVEL_OK => "✅",
            crate::system_state::LEVEL_INFO => "ℹ️",
            crate::system_state::LEVEL_WARN => "⚠️",
            crate::system_state::LEVEL_FAIL => "❌",
            _ => "❔",
        };
        emit(&format!("{icon} {}: {}", item.title, item.text));
    }
}

/// Раздел «Ваша сеть» текстового отчёта.
pub fn emit_network(network: Option<&Value>, emit: &mut dyn FnMut(&str)) {
    let Some(item) = network else {
        return;
    };
    emit("");
    emit("━━━━━━━━ Ваша сеть ━━━━━━━━");
    for line in item["lines"].as_array().unwrap_or(&Vec::new()) {
        emit(&format!(
            "{} {}: {}",
            if line["state"].as_str() == Some("warn") {
                "⚠️"
            } else {
                "ℹ️"
            },
            line["name"].as_str().unwrap_or(""),
            line["text"].as_str().unwrap_or("")
        ));
    }
}

/// Раздел «Голосовые звонки» текстового отчёта.
pub fn emit_voice(voice: Option<&crate::voice_check::VoiceReport>, emit: &mut dyn FnMut(&str)) {
    let Some(item) = voice else {
        return;
    };
    let rows: Vec<(String, String, String)> = item
        .servers
        .iter()
        .map(|server| {
            let mark = if server.answered {
                "✅"
            } else if server.decided {
                "❌"
            } else {
                "❔"
            };
            (mark.to_string(), server.name.clone(), server.text.clone())
        })
        .collect();
    for line in crate::report_text::section_level_lines(
        "Голосовые звонки (UDP)",
        item.level,
        &item.headline,
        &rows,
    ) {
        emit(&line);
    }
}

/// Где перехватывают обычные DNS-запросы (см. [`crate::dns_place`]).
///
/// python `_dns_place(run, trace)`: `traced` — дорога к DNS-серверу, `ask` —
/// UDP-запрос со сроком жизни. None — проверку сняли.
#[must_use]
pub fn dns_place_verdict(ask: &TtlAsk<'_>, traced: Option<&RouteTrace>) -> Option<DnsPlaceVerdict> {
    let reached = traced.is_some_and(|item| item.supported && item.reached);
    let distance = match traced {
        Some(item) if reached => item.hops.len() as u32,
        _ => 0,
    };
    crate::dns_place::judge(Some(&crate::dns_place::collect(
        ask,
        distance,
        DNS_MAX_TTL,
        DNS_SERVER,
    )))
}

/// Проблемы «сайт открывается, но его замедляют по имени». Пусто — замедления нет.
#[must_use]
pub fn speed_problems(speed: Option<&Value>, zapret_running: Option<bool>) -> Vec<Problem> {
    let mut found: Vec<Problem> = Vec::new();
    for item in speed
        .and_then(|item| {
            item["names"]
                .get("items")
                .and_then(|items| items.as_array().cloned())
        })
        .unwrap_or_default()
    {
        if item["state"].as_str() != Some("warn") {
            continue;
        }
        let advice = format!(
            "Замедление по имени обходится так же, как блокировка по имени: фильтр не должен увидеть имя сайта. {}",
            if zapret_running == Some(true) {
                "Сейчас Zapret запущен, но для этого сайта выбранный пресет замедление не снимает — \
                 попробуйте другой пресет или «Подбор стратегии»."
            } else {
                "Запустите Zapret; если не поможет — подберите стратегию для этого сайта."
            }
        );
        found.push(Problem::new(
            Level::Warn,
            format!(
                "{} открывается, но медленно: {}",
                item["name"].as_str().unwrap_or(""),
                item["text"].as_str().unwrap_or("")
            ),
            vec![advice],
            if zapret_running == Some(false) {
                "start_zapret"
            } else {
                "strategy"
            },
            item["host"].as_str().unwrap_or(""),
            KIND_SNI,
            item["name"].as_str().unwrap_or(""),
            Vec::new(),
            "",
            SECTION_SPEED,
        ));
    }
    found
}

/// Проблема «сайт замирает от нескольких соединений сразу». Пусто — такого нет.
#[must_use]
pub fn crowd_problems(crowd: Option<&Value>, zapret_running: Option<bool>) -> Vec<Problem> {
    let item = match crowd {
        Some(item) if item["level"].as_str() == Some("warn") => item,
        _ => return Vec::new(),
    };
    vec![Problem::new(
        Level::Warn,
        item["text"].as_str().unwrap_or(""),
        vec![item["advice"].as_str().unwrap_or("").to_string()],
        if zapret_running == Some(false) {
            "start_zapret"
        } else {
            "strategy"
        },
        item["host"].as_str().unwrap_or(""),
        KIND_SNI,
        item["label"].as_str().unwrap_or(""),
        Vec::new(),
        "",
        SECTION_CROWD,
    )]
}

/// python `Probe`, собранный движком для каждого сайта.
pub type CollectedProbes = BTreeMap<String, Vec<Probe>>;

/// Где стоит фильтр — по нескольким сайтам, которые режут по имени
/// (см. [`crate::filter_place`]).
///
/// Здесь уже нет `Run`/`submit`: путь ищется на сайтах по порядку кандидатов —
/// тот же порядок, что дал бы `run.submit`. Транспорт даёт движок:
///
/// * `pair_of(способ, адрес, имя сайта, имя пробника, срок жизни)` — пробы
///   перехватывающего и нейтрального пакета на том же сокете (QUIC/TLS);
/// * `connects(ip, ttl)` — соединение со сроком жизни (расстояние до сервера);
/// * `owner_of(ip)` — (номер сети AS, название) владельца;
/// * `traced(ip)` — узлы дороги (раздел «Где стоит фильтр» и перехват DNS);
/// * `dns_ask(ttl)` — UDP-запрос DNS со сроком жизни (механизм «dns»).
#[allow(clippy::too_many_arguments)]
pub fn find_filter_place(
    collected: &CollectedProbes,
    emit: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
    zapret_running: Option<bool>,
    other_tools: &[String],
    own_asn: &str,
    pair_of: &PairOf<'_>,
    connects: &dyn Fn(&str, u32) -> bool,
    owner_of: &OwnerOf<'_>,
    traced: &dyn Fn(&str) -> Option<RouteTrace>,
    dns_ask: &TtlAsk<'_>,
) -> Option<Value> {
    let mut sites: Vec<(String, String, bool, bool)> = Vec::new();
    for items in collected.values() {
        for probe in items {
            let ip = probe
                .reach
                .as_ref()
                .map_or(String::new(), |item| item.ip.clone());
            let quic_blocked = probe
                .quic
                .as_ref()
                .is_some_and(|item| item.code == QUIC_BLOCKED_BY_NAME);
            // По TCP ищется только фильтр, который рвёт соединение сбросом,
            // и только доказанная блокировка по имени.
            let tcp_reset = probe
                .cause
                .as_ref()
                .is_some_and(|item| item.code == CAUSE_BY_NAME)
                && tcp_reset_seen(probe);
            sites.push((probe.host.clone(), ip, quic_blocked, tcp_reset));
        }
    }
    let candidates = filter_place::pick_candidates(&sites, filter_place::MAX_SITES);
    if cancelled() {
        return None;
    }
    // Блокировок по имени нет — дорогу всё равно показываем: по первому открывшемуся сайту.
    let plain = collected
        .values()
        .flat_map(|items| items.iter())
        .find(|probe| {
            probe
                .reach
                .as_ref()
                .is_some_and(|item| item.ok() && !item.ip.is_empty() && !item.ip.contains(':'))
        })
        .cloned();

    // Расстояние у сайта одно на оба способа: второй раз не меряем.
    let mut distances: BTreeMap<String, Option<u32>> = BTreeMap::new();
    let mut locate_site =
        |method: &str, ip: &str, host: &str, item_traced: Option<&RouteTrace>| -> FilterFacts {
            let value: Option<u32> = if let Some(item) = distances.get(ip) {
                *item
            } else {
                let around = item_traced
                    .filter(|item| item.supported && item.reached)
                    .map_or(0, |item| item.hops.len() as u32);
                let computed = tcp_distance(MAX_HOPS, cancelled, &|ttl| connects(ip, ttl), around);
                distances.insert(ip.to_string(), computed);
                computed
            };
            let distance_of: &DistanceOf<'_> = &move || value;
            // python: pair(ip, blocked_name, ttl) — адрес и имя сайта знает движок.
            let pair: &PathPair<'_> =
                &move |name: &str, ttl: u32| pair_of(method, ip, host, name, ttl);
            locate_filter(FILTER_MAX_TTL, cancelled, distance_of, pair)
        };

    let facts: Vec<filter_place::SiteFacts> = candidates
        .iter()
        .map(|candidate| {
            let item_traced = traced(&candidate.ip);
            let found = candidate
                .methods
                .iter()
                .map(|method| {
                    (
                        *method,
                        locate_site(method, &candidate.ip, &candidate.host, item_traced.as_ref()),
                    )
                })
                .collect();
            filter_place::SiteFacts {
                host: candidate.host.clone(),
                ip: candidate.ip.clone(),
                trace: item_traced,
                found,
            }
        })
        .collect();
    if cancelled() {
        return None;
    }
    let judged: Vec<(&filter_place::SiteFacts, Option<filter_place::SiteVerdict>)> = facts
        .iter()
        .map(|item| (item, filter_place::judge_site(item)))
        .collect();
    let verdicts: Vec<filter_place::SiteVerdict> = judged
        .iter()
        .filter_map(|(_, verdict)| verdict.clone())
        .collect();
    // Узлы показываем по сайту, где место найдено; если нигде — по первому.
    let with_hop = judged
        .iter()
        .find(|(_, verdict)| verdict.as_ref().is_some_and(|item| item.hop.is_some()));
    let shown = match with_hop {
        Some((item, verdict)) => (Some(*item), verdict.clone()),
        None => {
            let first = judged.iter().find(|(_, verdict)| verdict.is_some());
            first.map_or((None, None), |(item, verdict)| {
                (Some(*item), verdict.clone())
            })
        }
    };

    let mut route = shown.0.and_then(|item| item.trace.clone());
    if route.is_none() && candidates.is_empty() {
        route = plain
            .as_ref()
            .and_then(|item| item.reach.as_ref())
            .and_then(|item| traced(&item.ip));
    }
    let listed = filter_place::describe_hops(route.as_ref(), own_asn, owner_of);
    let placement = filter_place::aggregate(&verdicts, &listed, zapret_running, other_tools);
    let mut place = filter_place::report(&placement, &verdicts, &listed, shown.1.as_ref());
    let dns = dns_place_verdict(dns_ask, traced(DNS_SERVER).as_ref());
    if let Value::Object(object) = &mut place {
        let extra = filter_place::mechanisms(&verdicts, dns.as_ref());
        if let Value::Object(part) = extra {
            for (key, value) in part {
                object.insert(key, value);
            }
        }
    }
    if shown.0.is_none() && plain.is_some() && !listed.is_empty() {
        if let (Value::Object(object), Some(item)) = (&mut place, plain.as_ref()) {
            object.insert("host".into(), json!(item.host));
            object.insert("address".into(), json!(item.reach.as_ref().unwrap().ip));
        }
    }
    for line in filter_place::lines(&place) {
        emit(&line);
    }
    Some(place)
}

/// python `owner_of(адрес)` → (номер сети AS, название) или None — держит движок.
pub type OwnerOf<'a> = dyn Fn(&str) -> Option<(String, String)> + 'a;

/// Отправка разрезанного приветствия: `(адрес, куски, пауза)` → исход.
/// None — проверку сняли; движок учитывает «Стоп» внутри.
pub type HabitSend<'a> = dyn Fn(&str, &[Vec<u8>], f64) -> String + 'a;

/// Как работает фильтр: какое дробление приветствия проходит и режется ли ECH.
///
/// `tools` — запущенные Zapret, VPN и другие программы обхода: пробы идут через
/// них, поэтому вывод помечается как «сеть вместе с обходом». `sent` — замыкание
/// отправки приветствий (проверка дробления), `rests` — передышка между
/// соединениями к одному адресу.
#[allow(clippy::too_many_arguments)]
pub fn check_filter_habits(
    collected: &CollectedProbes,
    emit: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
    sent: &HabitSend<'_>,
    rests: &dyn Fn(f64),
    tools: &[String],
) -> Option<Value> {
    use crate::filter_habits::{check_ech, check_split, judge_ech, judge_split, lines, summarize};
    let probes: Vec<&Probe> = collected.values().flat_map(|items| items.iter()).collect();
    // Дробление сравнивается только там, где блокировка по имени уже доказана.
    // С каждого сервиса — один адрес, и сначала из разных сетей: три адреса
    // одного Discord показали бы одно и то же трижды.
    let mut blocked: Vec<(String, &Probe)> = Vec::new();
    let mut spare: Vec<(String, &Probe)> = Vec::new();
    let mut networks: Vec<String> = Vec::new();
    for items in collected.values() {
        for probe in items {
            let ip = probe
                .reach
                .as_ref()
                .map_or(String::new(), |item| item.ip.clone());
            if ip.is_empty()
                || ip.contains(':')
                || probe.cause.is_none()
                || probe
                    .cause
                    .as_ref()
                    .is_some_and(|item| item.code != CAUSE_BY_NAME)
            {
                continue;
            }
            let network = ip.split('.').take(2).collect::<Vec<_>>().join(".");
            if networks.contains(&network) {
                if !spare.iter().any(|(known, _)| *known == ip) {
                    spare.push((ip, probe));
                }
            } else {
                blocked.push((ip, probe));
                networks.push(network);
            }
            break;
        }
    }
    for (ip, probe) in &spare {
        if !blocked.iter().any(|(known, _)| known == ip.as_str()) {
            blocked.push((ip.clone(), probe));
        }
    }
    let cloudflare: Option<&Probe> = probes.iter().copied().find(|probe| {
        probe.host == ECH_HOST
            && probe
                .reach
                .as_ref()
                .is_some_and(|item| item.ok() && !item.ip.contains(':'))
    });
    if cancelled() || (blocked.is_empty() && cloudflare.is_none()) {
        return None;
    }
    let ech_ip: Option<String> = cloudflare
        .and_then(|item| item.reach.as_ref())
        .map(|item| item.ip.clone());
    let ech_facts = ech_ip
        .as_deref()
        .map(|ip| check_ech(ip, &mut send_of(sent)));
    let mut splits: Vec<crate::filter_habits::SplitVerdict> = Vec::new();
    for (ip, probe) in blocked.iter().take(HABIT_SITES) {
        let pausing = move |seconds: f64| rests(seconds);
        let facts = check_split(&probe.host, ip, &mut send_of(sent), &pausing);
        if let Some(verdict) = judge_split(&facts) {
            splits.push(verdict);
        }
    }
    let echo = judge_ech(ech_facts.as_ref());
    // python: `summarize(splits, ech, tools=tools)`; `splits` — ссылки.
    let links: Vec<&crate::filter_habits::SplitVerdict> = splits.iter().collect();
    let report = summarize(&links, (echo.0, echo.1.as_str()), tools)?;
    for line in lines(&report) {
        emit(&line);
    }
    Some(report)
}

/// python `path_trace.send_pair`/`tcp_pair` — способ, адрес, имя сайта, имя пробника, срок жизни.
pub type PairOf<'a> = dyn Fn(&str, &str, &str, &str, u32) -> Option<bool> + 'a;

/// python `filter_habits.Send` — `(адрес, куски, пауза)` → исход строки.
fn send_of<'s>(sent: &'s HabitSend<'_>) -> impl FnMut(&str, &[Vec<u8>], f64) -> String + 's {
    move |ip: &str, parts: &[Vec<u8>], pause: f64| sent(ip, parts, pause)
}

/// python `name_speed.collect(list(labels), ...)` — записи имён в порядке их
/// первого появления (setdefault не перезаписывает).
pub type NameLabels = Vec<(String, String)>;

/// Замедление по имени сайта — у сайтов, которые открылись.
///
/// None — проверять нечего или контроль не вышел. `known` — адрес сервера
/// замера по имени, `fetches(ip, name)` — одна загрузка с именем в приветствии.
#[allow(clippy::too_many_arguments)]
pub fn name_speed_report(
    collected: &CollectedProbes,
    services: &BTreeMap<String, crate::services::Service>,
    emit: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
    known: &dyn Fn(&str) -> Option<String>,
    fetches: &mut dyn FnMut(&str, &str) -> NameRun,
) -> Option<Value> {
    let mut labels: NameLabels = Vec::new();
    let label_by_host = |labels: &NameLabels, host: &str| {
        labels
            .iter()
            .find(|(known, _)| known == host)
            .map(|(_, label)| label.clone())
    };
    // Имён проверяется немного: сначала главный адрес каждого сервиса, затем
    // вторые адреса (у YouTube это видеосервер — замедляли именно его).
    for place in 0..2 {
        for (key, probes) in collected {
            let Some(service) = services.get(key) else {
                continue;
            };
            if service.control {
                continue;
            }
            let mut opened: Vec<&Probe> = probes
                .iter()
                .filter(|probe| probe.reach_state == ReachStateKind::Ok)
                .collect();
            // Вторым идёт именно видеосервер, а не просто следующий адрес.
            opened.sort_by_key(|probe| (!probe.target.main, !probe.target.discover_googlevideo));
            if let Some(probe) = opened.get(place) {
                if labels.iter().all(|(host, _)| *host != probe.host) {
                    labels.push((probe.host.clone(), service.label.clone()));
                }
            }
        }
    }
    if labels.is_empty() {
        return None;
    }
    // Адрес сервера замера нужен заранее — если не разрешился, проверять нечего.
    let site = known(name_speed_mod::SERVER_HOST)?;
    if site.is_empty() || cancelled() {
        return None;
    }
    let names: Vec<String> = labels.iter().map(|(host, _)| host.clone()).collect();
    let mut download = |name: &str| fetches(site.as_str(), name);
    let facts = name_speed_mod::collect(&names, &mut download, Some(cancelled));
    let (control, listing) = name_speed_mod::judge(&facts);
    let (Some(control), listing) = (control, listing) else {
        return None;
    };
    if listing.is_empty() {
        return None;
    }
    let slow_names: Vec<String> = listing
        .iter()
        .filter(|item| item.code == name_speed_mod::SLOW)
        .filter_map(|item| label_by_host(&labels, &item.name))
        .collect();
    let cut_names: Vec<String> = listing
        .iter()
        .filter(|item| item.code == name_speed_mod::CUT)
        .filter_map(|item| label_by_host(&labels, &item.name))
        .collect();
    let headline = if !cut_names.is_empty() {
        let mut value = format!(
            "Обрывают поток по имени сайта: {}",
            dedup(&cut_names).join(", ")
        );
        if !slow_names.is_empty() {
            value.push_str(&format!("; замедляют: {}", dedup(&slow_names).join(", ")));
        }
        value
    } else if !slow_names.is_empty() {
        format!("Замедляют по имени сайта: {}", slow_names.join(", "))
    } else {
        "Замедления по имени сайта не видно: с именами сайтов скорость та же, что с обычным"
            .to_string()
    };
    let slow = [slow_names, cut_names].concat();
    emit(&format!(
        "ℹ️ Замедление по имени: контроль {} — {}",
        name_speed_mod::SERVER_HOST,
        name_speed_mod::speed_text(Some(control))
    ));
    for item in &listing {
        let icon = if item.code == name_speed_mod::SLOW || item.code == name_speed_mod::CUT {
            "⚠️"
        } else if item.code == name_speed_mod::FINE {
            "✅"
        } else {
            "❔"
        };
        let label = label_by_host(&labels, &item.name).unwrap_or_default();
        emit(&format!("{icon} {} ({}): {}", label, item.name, item.text));
    }
    emit(&format!(
        "{} {headline}",
        if slow.is_empty() { "✅" } else { "⚠️" }
    ));
    let states = |code: &str| -> &'static str {
        if code == name_speed_mod::SLOW || code == name_speed_mod::CUT {
            "warn"
        } else if code == name_speed_mod::FINE {
            "ok"
        } else {
            "unknown"
        }
    };
    Some(json!({
        "level": if slow.is_empty() { "ok" } else { "warn" },
        "headline": headline,
        "server": name_speed_mod::SERVER_HOST,
        "control": name_speed_mod::speed_text(Some(control)),
        "items": listing.iter().map(|item| {
            let label = label_by_host(&labels, &item.name).unwrap_or_default();
            json!({
                "name": label,
                "host": item.name,
                "kbps": item.kbps.map(|kbps| round_fps(kbps, 1)),
                "state": states(item.code.as_str()),
                "text": item.text,
            })
        }).collect::<Vec<_>>(),
    }))
}

/// python `dedup_by_first`: dict.fromkeys — первое появление.
fn dedup(values: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for value in values {
        if !seen.contains(value) {
            seen.push(value.clone());
        }
    }
    seen
}

fn round_fps(value: f64, digits: u32) -> f64 {
    let factor = 10f64.powi(digits as i32);
    crate::report_text::py_round0(value * factor) as f64 / factor
}

/// python `name_speed.collect` и `judge` — для этого же замера, но со своими
/// замыканиями. python `check_name_speed(run, ...)` — то же самое.
pub fn check_name_speed_report(
    run_collected: &CollectedProbes,
    run_services: &BTreeMap<String, crate::services::Service>,
    run_emit: &mut dyn FnMut(&str),
    run_cancelled: &dyn Fn() -> bool,
    run_known: &dyn Fn(&str) -> Option<String>,
    run_fetches: &mut dyn FnMut(&str, &str) -> NameRun,
) -> Option<Value> {
    name_speed_report(
        run_collected,
        run_services,
        run_emit,
        run_cancelled,
        run_known,
        run_fetches,
    )
}

/// Замирает ли сайт от нескольких соединений сразу (см. [`crate::crowd_probe`]).
///
/// Идёт самой последней: проба сама может остановить сайт на пару минут. При
/// работающем обходе (`tools`) не делается — мерили бы обход, а не линию.
/// `clock` — секунды (python `time.monotonic`), `left` — сколько секунд осталось
/// до конца прогона.
#[allow(clippy::too_many_arguments)]
pub fn check_crowd(
    collected: &CollectedProbes,
    services: &BTreeMap<String, crate::services::Service>,
    emit: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
    tools: &[String],
    hello_of: &dyn Fn(&str, &str) -> String,
    together: &dyn Fn() -> Vec<String>,
    clock: &dyn Fn() -> f64,
    wait: &mut dyn FnMut(f64) -> bool,
    left: &dyn Fn() -> f64,
) -> Option<Value> {
    if !tools.is_empty() {
        return None;
    }
    // Сайт, который открылся: основная проверка открывает его как Chrome, иначе
    // сравнивать не с чем.
    let site = collected
        .iter()
        .filter(|(key, _)| services.get(*key).is_some_and(|service| !service.control))
        .flat_map(|(_, items)| items.iter())
        .find(|probe| {
            probe.target.main
                && probe.reach_state == ReachStateKind::Ok
                && probe
                    .reach
                    .as_ref()
                    .is_some_and(|item| !item.ip.contains(':'))
                && probe.unstable.is_empty()
        })?;
    let control = collected
        .iter()
        .filter(|(key, _)| services.get(*key).is_some_and(|service| service.control))
        .flat_map(|(_, items)| items.iter())
        .find(|probe| {
            probe.reach_state == ReachStateKind::Ok
                && probe
                    .reach
                    .as_ref()
                    .is_some_and(|item| !item.ip.contains(':'))
        })?;
    if cancelled() {
        return None;
    }
    let site_ip = site.reach.as_ref().map_or("", |item| item.ip.as_str());
    let control_ip = control.reach.as_ref().map_or("", |item| item.ip.as_str());
    let facts: CrowdFacts = crate::crowd_probe::collect(
        &site.host,
        site_ip,
        hello_of,
        together,
        || hello_of(control_ip, control.host.as_str()),
        wait,
        clock,
        // python: max(0.0, deadline - now - CROWD_RESERVE_S).
        (left() - CROWD_RESERVE_S).max(0.0),
    );
    let verdict: CrowdVerdict = crate::crowd_probe::judge(Some(&facts))?;
    emit("");
    emit("━━━━━━━━ Несколько соединений сразу ━━━━━━━━");
    let icon = match verdict.code {
        CROWD_NONE => "✅",
        CROWD_FREEZE | CROWD_STUCK => "⚠️",
        _ => "❔",
    };
    emit(&format!(
        "{} {}",
        icon,
        crate::report_text::sentence(&verdict.text)
    ));
    if !verdict.advice.is_empty() {
        emit(&format!("   👉 {}", verdict.advice));
    }
    let level = match verdict.code {
        CROWD_NONE => "ok",
        CROWD_FREEZE | CROWD_STUCK => "warn",
        _ => "unknown",
    };
    // python: label сервиса — перед собранной пачкой.
    let label = collected
        .iter()
        .find(|(_, probes)| probes.iter().any(|probe| std::ptr::eq(probe, site)))
        .and_then(|(key, _)| services.get(key))
        .map_or(String::new(), |service| service.label.clone());
    Some(json!({
        "state": verdict.code,
        "level": level,
        "host": facts.host,
        "address": facts.ip,
        "label": label,
        // Слово итога и исходы по строкам — готовыми словами: экран их только показывает.
        "status": crate::crowd_probe::status(verdict.code),
        "rows": crate::crowd_probe::rows(&facts)
            .iter()
            .map(|row| json!({"title": row.title, "text": row.text, "state": row.state}))
            .collect::<Vec<_>>(),
        "text": crate::report_text::sentence(&verdict.text),
        "advice": verdict.advice,
        // Факты как есть: исход одиночного соединения до пачки, каждого из пачки
        // и одиночного после.
        "before": facts.before,
        "crowd": facts.crowd,
        "after": facts.after,
        "control": facts.control,
        "recovered_s": facts.recovered_s.map(|value| round_fps(value, 1)),
        "waited_s": round_fps(facts.waited_s, 1),
    }))
}

/// Скорость зарубежных серверов против российских и замедление по имени сайта.
///
/// Идёт последней, когда остальная нагрузка спала. `collected` и `services` —
/// проверенные сайты: у открывшихся ищется замедление по имени. `download` —
/// одна загрузка с сервера (движок даёт замыкание вместе с известным адресом).
#[allow(clippy::too_many_arguments)]
pub fn check_speed(
    collected: Option<&CollectedProbes>,
    services: Option<&BTreeMap<String, crate::services::Service>>,
    emit: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
    download: &mut dyn FnMut(&crate::speed_check::SpeedServer) -> Option<(u64, f64)>,
    known: &dyn Fn(&str) -> Option<String>,
    fetches: &mut dyn FnMut(&str, &str) -> NameRun,
) -> Option<Value> {
    use crate::speed_check::{check_speed as check_runs, speed_text, summarize_speed, SpeedReport};
    let samples = check_runs(download, Some(cancelled));
    if samples.is_empty() {
        return None;
    }
    let report: SpeedReport = summarize_speed(&samples);
    emit("");
    emit("━━━━━━━━ Скорость ━━━━━━━━");
    for item in &samples {
        let place = if item.server.domestic {
            "Россия"
        } else {
            "за границей"
        };
        emit(&format!(
            "{} {} ({}): {}",
            if item.kbps.is_some() { "ℹ️" } else { "❔" },
            item.server.name,
            place,
            speed_text(item.kbps)
        ));
    }
    emit(&format!(
        "{} {}",
        crate::report_text::level_icon(report.level),
        report.headline
    ));
    let slow = report.level == Level::Warn;
    let both = collected.is_some() && services.is_some();
    let names = if both {
        name_speed_report(
            collected.unwrap(),
            services.unwrap(),
            emit,
            cancelled,
            known,
            fetches,
        )
    } else {
        None
    };
    Some(json!({
        "level": report.level.value(),
        "headline": report.headline,
        "names": names,
        "items": samples.iter().map(|item| json!({
            "name": item.server.name,
            "host": item.server.host,
            "domestic": item.server.domestic,
            "kbps": item.kbps.map(|value| round_fps(value, 1)),
            "state": if item.kbps.is_none() {
                "unknown"
            } else if slow && !item.server.domestic {
                "warn"
            } else {
                "ok"
            },
            "text": speed_text(item.kbps),
        })).collect::<Vec<_>>(),
    }))
}

/// «Ваша сеть»: внешний адрес, провайдер и адрес компьютера — готовым словарём
/// для отчёта. `fetches` — тело `/cdn-cgi/trace`; `asks` — владельца сети
/// шифрованным путём (иначе за него ответил бы перехватчик DNS); `locates` —
/// адрес адаптера; `hops` — пинги узлов.
pub fn check_network(
    fetches: &dyn Fn(&str) -> Option<Vec<u8>>,
    asks: &dyn Fn(&str) -> Option<crate::ip_owner::IpOwner>,
    locates: &dyn Fn() -> String,
    hops: Option<&crate::my_network::Prober>,
    bypass_tools: &[String],
) -> Value {
    let facts = crate::my_network::collect(fetches, asks, locates, hops);
    let lines = crate::my_network::judge(&facts, bypass_tools);
    let owner = facts.owner.as_ref();
    let mut parts: Vec<String> = Vec::new();
    if let Some(item) = owner {
        if !item.owner.is_empty() {
            parts.push(item.owner.clone());
        }
        if !item.asn.is_empty() {
            parts.push(format!("AS{}", item.asn));
        }
    }
    let provider = parts.join(" · ");
    let lines_list: Vec<Value> = lines
        .iter()
        .map(|line| json!({"state": line.state, "name": line.name, "text": line.text}))
        .collect();
    json!({
        "external_ip": facts.external_ip,
        "country": facts.country,
        "provider": provider,
        "asn": owner.map_or("", |item| item.asn.as_str()),
        "prefix": owner.map_or("", |item| item.prefix.as_str()),
        "local_ip": facts.local_ip,
        "lines": lines_list,
    })
}

/// Сайты без дороги и после перепроверки: живы ли они снаружи (сервер Zapret DNS).
///
/// Только по галочке: само соединение с сервером проекта выдаёт программу.
/// Только встроенные сайты: свои домены пользователя (`user:`) на сервер
/// не уходят. Контрольные не спрашиваются: по ним судят о сети целиком.
/// `answers` — по списку имён даёт `{сайт: up | down}`; `left` — сколько секунд
/// осталось у прогона.
pub fn ask_outside(
    services: &BTreeMap<String, crate::services::Service>,
    probes_list: &[&Probe],
    answers: &dyn Fn(&[String]) -> BTreeMap<String, String>,
    cancelled: &dyn Fn() -> bool,
    left: &dyn Fn() -> f64,
) -> Vec<(String, String, String)> {
    let mut failed: Vec<&Probe> = Vec::new();
    for probe in probes_list {
        if probe.reach_state != ReachStateKind::IpBlock && probe.reach_state != ReachStateKind::Dpi
        {
            continue;
        }
        if probe.service.starts_with("user:") {
            continue;
        }
        if services
            .get(&probe.service)
            .is_some_and(|service| service.control)
        {
            continue;
        }
        failed.push(probe);
    }
    if failed.is_empty() || cancelled() || left() < OUTSIDE_NEEDS_S {
        return Vec::new();
    }
    let listing: Vec<String> = failed.iter().map(|probe| probe.host.clone()).collect();
    let got = answers(&listing);
    // python: probe.outside = answers.get(probe.host, "") — пустой ответ тоже виден.
    failed
        .iter()
        .map(|probe| {
            let answer = got.get(&probe.host).cloned().unwrap_or_default();
            (probe.service.clone(), probe.host.clone(), answer)
        })
        .collect()
}

/// python-замыкание `verdict_of(сервис, пробы)`.
pub type VerdictOf = Arc<
    dyn Fn(&crate::services::Service, &[Probe]) -> crate::verdict::ServiceVerdict + Send + Sync,
>;

/// python `live_services` — приёмник «сайт проверен»: сервис уходит на экран,
/// как только готовы все его адреса.
///
/// `verdict_of(сервис, пробы)` даёт итог сервиса, `publish(список)` получает
/// готовые сервисы в том же виде, что и в итоговом отчёте. После перепроверки
/// движок кладёт окончательный список — он заменяет этот предварительный.
pub struct LiveServices {
    services: BTreeMap<String, crate::services::Service>,
    verdict_of: VerdictOf,
    publish: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
    state: Mutex<LiveServicesState>,
}

struct LiveServicesState {
    done: BTreeMap<String, Vec<Probe>>,
    /// Готовые записи сервисов: пересчитывается только тот, что сейчас
    /// завершился, а не все готовые на каждом сайте (было O(N²) сборок за прогон).
    entries: BTreeMap<String, Value>,
}

impl LiveServices {
    pub fn new(
        services: &BTreeMap<String, crate::services::Service>,
        verdict_of: VerdictOf,
        publish: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(LiveServices {
            services: services.clone(),
            verdict_of,
            publish,
            state: Mutex::new(LiveServicesState {
                done: BTreeMap::new(),
                entries: BTreeMap::new(),
            }),
        })
    }

    /// python `on_probe(key, probe)`.
    pub fn on_probe(&self, key: &str, probe: &Probe) {
        let ready = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let probes = state.done.entry(key.to_string()).or_default();
            probes.push(probe.clone());
            let Some(service) = self.services.get(key) else {
                return;
            };
            if probes.len() < service.targets.len() {
                return;
            }
            (key.to_string(), probes.clone())
        };
        let (key, probes) = ready;
        let Some(service) = self.services.get(&key) else {
            return;
        };
        let verdict = (self.verdict_of)(service, &probes);
        let mut verdicts = BTreeMap::new();
        verdicts.insert(key.clone(), verdict);
        let mut collected: CollectedProbes = BTreeMap::new();
        collected.insert(key.clone(), probes);
        let entry = crate::report_text::services_report(
            &[(key.clone(), service.clone())],
            &verdicts,
            &collected,
        )
        .into_iter()
        .next();
        let Some(entry) = entry else { return };
        let snapshot = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            // Под замком: снимок, собранный раньше, не перебьёт более полный.
            state.entries.insert(key, entry);
            self.services
                .keys()
                .filter_map(|name| state.entries.get(name).cloned())
                .collect::<Vec<_>>()
        };
        (self.publish)(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_reach(host: &str, ip: &str) -> Probe {
        Probe {
            target: crate::services::Target {
                host: host.to_string(),
                purpose: "сайт",
                ..crate::services::Target::default()
            },
            service: format!("main.{host}"),
            host: host.to_string(),
            reach: Some(crate::probe_result::ProbeResult::new(
                ip,
                crate::probe_result::KIND_OK,
            )),
            reach_state: ReachStateKind::Ok,
            ..Probe::default()
        }
    }

    #[test]
    fn dns_finding_parts_are_picked_up_and_leave_when_there_is_no_title() {
        let spoofed = serde_json::json!({
            "title": "Обычные ответы подменяются у серверов",
            "servers": [["Cloudflare", "1.1.1.1"], ["Cloudflare", "1.0.0.1"], ["один", "два", "три"]],
            "note": "",
        });
        let parts = dns_finding_parts(&spoofed);
        assert_eq!(
            parts,
            serde_json::json!({
                "title": "Обычные ответы подменяются у серверов",
                "servers": [["Cloudflare", "1.1.1.1"], ["Cloudflare", "1.0.0.1"]],
                "note": "",
            })
        );
        let plain = serde_json::json!({"level": "warn", "text": "DNS без частей"});
        assert_eq!(dns_finding_parts(&plain), Value::Null);
    }

    #[test]
    fn finish_dns_servers_prints_the_section_and_merges_the_parts() {
        let waited = Ok(serde_json::json!({
            "level": "fail",
            "findings": [
                {
                    "level": "fail",
                    "text": "Обычные ответы подменяются у серверов: Cloudflare (1.1.1.1) и ещё 1.",
                    "title": "Обычные ответы подменяются у серверов",
                    "servers": [["Cloudflare", "1.1.1.1"]],
                    "note": "",
                },
                {"level": "warn", "text": ""},
            ],
            "text": "первая строка\nвторая строка",
        }));
        let mut lines: Vec<String> = Vec::new();
        let result = finish_dns_servers(waited, &mut |line| lines.push(line.to_string())).unwrap();

        assert_eq!(result["level"], "fail");
        let findings = result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0]["title"],
            "Обычные ответы подменяются у серверов"
        );
        assert!(lines.contains(&"━━━━━━━━ DNS-серверы ━━━━━━━━".to_string()));
        assert!(
            lines.iter().any(|line| {
                line == "❌ Обычные ответы подменяются у серверов: Cloudflare (1.1.1.1) и ещё 1."
            }),
            "{lines:?}"
        );
        assert!(lines.contains(&"   первая строка".to_string()));
        assert!(lines.contains(&"   вторая строка".to_string()));

        let mut lost: Vec<String> = Vec::new();
        assert!(
            finish_dns_servers(Err("нет сети".to_string()), &mut |line| lost
                .push(line.to_string()))
            .is_none()
        );
        assert_eq!(
            lost,
            vec!["❔ DNS-серверы: проверка не выполнилась (нет сети)"]
        );
        let mut quiet: Vec<String> = Vec::new();
        assert!(
            finish_dns_servers(Ok(Value::Null), &mut |line| quiet.push(line.to_string())).is_none()
        );
    }

    #[test]
    fn dns_problems_keep_only_known_levels_and_mirror_the_parts() {
        let dns_servers = serde_json::json!({
            "findings": [
                {
                    "level": "fail",
                    "text": "Обычные ответы подменяются у серверов.",
                    "title": "Обычные ответы подменяются у серверов",
                    "servers": [["Cloudflare", "1.1.1.1"]],
                    "note": "",
                },
                {"level": "info", "text": "запись без уровня"},
                {"level": "warn", "text": "DNS без частей."},
            ]
        });
        let problems = dns_problems(Some(&dns_servers));
        assert_eq!(problems.len(), 2);
        assert_eq!(problems[0].section, SECTION_DNS_SERVERS);
        assert_eq!(problems[0].kind, KIND_DNS);
        assert_eq!(problems[0].action, "dns");
        assert_eq!(problems[0].title, "");
        assert!(problems[0].parts.is_some());
        assert!(problems[1].parts.is_none());

        let problems = dns_problems(None);
        assert!(problems.is_empty());
    }

    #[test]
    fn speed_problems_advise_to_start_zapret_only_when_it_is_not_running() {
        let speed = serde_json::json!({
            "names": {"items": [
                {"state": "warn", "name": "YouTube", "host": "media.example", "text": "поток медленный"},
                {"state": "ok", "name": "Discord", "host": "discord.com", "text": "всё нормально"},
            ]}
        });

        for (running, advice_text, action) in [
            (
                Some(true),
                "Замедление по имени обходится так же, как блокировка по имени: фильтр не должен увидеть имя сайта. Сейчас Zapret запущен, но для этого сайта выбранный пресет замедление не снимает — попробуйте другой пресет или «Подбор стратегии».",
                "strategy",
            ),
            (
                Some(false),
                "Замедление по имени обходится так же, как блокировка по имени: фильтр не должен увидеть имя сайта. Запустите Zapret; если не поможет — подберите стратегию для этого сайта.",
                "start_zapret",
            ),
            (
                None,
                "Замедление по имени обходится так же, как блокировка по имени: фильтр не должен увидеть имя сайта. Запустите Zapret; если не поможет — подберите стратегию для этого сайта.",
                "strategy",
            ),
        ] {
            let problems = speed_problems(Some(&speed), running);
            assert_eq!(problems.len(), 1, "running: {running:?}");
            assert_eq!(problems[0].level, Level::Warn, "running: {running:?}");
            assert_eq!(
                problems[0].text,
                "YouTube открывается, но медленно: поток медленный"
            );
            assert_eq!(problems[0].advice.first().map(String::as_str), Some(advice_text));
            assert_eq!(problems[0].action, action);
            assert_eq!(problems[0].target, "media.example");
            assert_eq!(problems[0].title, "YouTube");
            assert_eq!(problems[0].kind, crate::block_kind::KIND_SNI);
            assert_eq!(problems[0].section, SECTION_SPEED);
        }

        assert!(speed_problems(None, Some(false)).is_empty());
        let empty = serde_json::json!({"names": {"items": []}});
        assert!(speed_problems(Some(&empty), Some(false)).is_empty());
    }

    #[test]
    fn crowd_problems_name_the_site_and_the_zapret_action() {
        let crowd = serde_json::json!({
            "level": "warn",
            "text": "YouTube замирает, когда соединений несколько.",
            "advice": "Сократите число соединений.",
            "host": "media.example",
            "label": "YouTube",
        });
        let problems = crowd_problems(Some(&crowd), Some(false));
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].level, Level::Warn);
        assert_eq!(
            problems[0].text,
            "YouTube замирает, когда соединений несколько."
        );
        assert_eq!(
            problems[0].advice.first().map(String::as_str),
            Some("Сократите число соединений.")
        );
        assert_eq!(problems[0].action, "start_zapret");
        assert_eq!(problems[0].target, "media.example");
        assert_eq!(problems[0].title, "YouTube");
        assert_eq!(problems[0].section, SECTION_CROWD);

        let open = serde_json::json!({"level": "ok"});
        assert!(crowd_problems(Some(&open), Some(false)).is_empty());
        assert!(crowd_problems(None, Some(false)).is_empty());
    }

    #[test]
    fn facts_helper_duplicates_are_removed_and_rounding_is_banks_style() {
        assert_eq!(
            dedup(&[
                "a".to_string(),
                "b".to_string(),
                "a".to_string(),
                "c".to_string()
            ]),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        // python round(x, 1) — банковское округление: 12.5 → 12, а не 13.
        assert_eq!(round_fps(1.25, 1), 1.2);
        assert_eq!(round_fps(1.35, 1), 1.4);
    }

    #[test]
    fn tcp_reset_seen_requires_the_reset_kind() {
        let mut value = probe_reach("discord.com", "155.133.248.21");
        value.reach.as_mut().unwrap().kind = crate::probe_result::KIND_RESET.to_string();
        assert!(tcp_reset_seen(&value));
        value.reach_state = ReachStateKind::IpBlock;
        assert!(tcp_reset_seen(&value));
        let opened = probe_reach("discord.com", "155.133.248.21");
        assert!(!tcp_reset_seen(&opened));
        let mut silent = probe_reach("discord.com", "155.133.248.21");
        silent.reach.as_mut().unwrap().kind = crate::probe_result::KIND_TIMEOUT.to_string();
        assert!(!tcp_reset_seen(&silent));
    }

    #[test]
    fn filter_habits_collect_one_address_per_service_and_spare_only_new_networks() {
        // тот же IP первым из первой сети — оба остаются кандидатами, как в python.
        let mut first = probe_reach("discord.com", "155.133.0.1");
        first.cause = Some(crate::block_cause::Cause::new(
            CAUSE_BY_NAME,
            "по имени",
            true,
        ));
        let mut second = probe_reach("www.youtube.com", "155.133.1.1");
        second.cause = Some(crate::block_cause::Cause::new(
            CAUSE_BY_NAME,
            "по имени",
            true,
        ));
        let open = probe_reach("open.example", "8.8.4.4");

        let mut collected: CollectedProbes = BTreeMap::new();
        collected.insert("main.discord".to_string(), vec![first]);
        collected.insert("main.youtube".to_string(), vec![second, open.clone()]);

        // Какие адреса посылались на пробы: раскроет «один адрес на сервис» и
        // «запасной только из новой сети».
        let probed: std::rc::Rc<std::cell::RefCell<Vec<String>>> = Default::default();
        let capture = probed.clone();
        let listener = move |ip: &str, _parts: &[Vec<u8>], _pause: f64| -> String {
            capture.borrow_mut().push(ip.to_string());
            crate::block_cause::HELLO_OK.to_string()
        };
        let sent: &HabitSend<'_> = &listener;
        let mut lines: Vec<String> = Vec::new();
        let report = check_filter_habits(
            &collected,
            &mut |line| lines.push(line.to_string()),
            &|| false,
            sent,
            &|_seconds| {},
            &[],
        )
        .unwrap();

        // Из двух сетей — два адреса (155.133.0.1 и 155.133.1.1): сети разные.
        let sites = report["sites"].as_array().unwrap();
        assert_eq!(sites.len(), 2, "{report:?}");
        assert_eq!(sites[0]["host"], "discord.com");
        assert_eq!(sites[1]["host"], "www.youtube.com");
        let touched = probed.borrow();
        assert!(touched.contains(&"155.133.0.1".to_string()), "{touched:?}");
        assert!(touched.contains(&"155.133.1.1".to_string()), "{touched:?}");
        assert!(!touched.contains(&"8.8.4.4".to_string()), "{touched:?}");
    }

    #[test]
    fn without_blocks_by_name_the_road_is_still_shown() {
        let mut plain = probe_reach("cloudflare.com", "1.1.1.1");
        plain.target.main = true;
        let mut collected: CollectedProbes = BTreeMap::new();
        collected.insert("main.cloudflare".to_string(), vec![plain]);

        let trace = |ip: &str| -> Option<RouteTrace> {
            (ip == "1.1.1.1").then(|| RouteTrace {
                target: ip.to_string(),
                hops: (1..=3)
                    .map(|ttl| crate::path_trace::Hop {
                        ttl,
                        kind: crate::icmp::HOP_ROUTER,
                        address: format!("10.0.0.{ttl}"),
                        rtt_ms: Some(ttl as f64),
                    })
                    .collect(),
                reached: false,
                supported: true,
            })
        };

        let mut lines: Vec<String> = Vec::new();
        let place = find_filter_place(
            &collected,
            &mut |line| lines.push(line.to_string()),
            &|| false,
            None,
            &[],
            "",
            &move |_method, _ip, _host, _name, _ttl| Some(true),
            &|_ip, _ttl| false,
            &move |owner| match owner {
                "10.0.0.1" | "10.0.0.2" => Some(("".to_string(), "".to_string())),
                _ => None,
            },
            &trace,
            &|_ttl| None,
        )
        .unwrap();

        assert_eq!(place["state"], "none");
        assert_eq!(place["found"], false);
        assert_eq!(place["hops"].as_array().unwrap().len(), 3);
        assert_eq!(place["host"], "cloudflare.com");
        assert_eq!(place["address"], "1.1.1.1");
        assert!(
            place["text"]
                .as_str()
                .unwrap()
                .contains("искать место фильтра не по чему"),
            "{:?}",
            place["text"]
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("━━━━━━━━ Где стоит фильтр ━━━━━━━━")),
            "{lines:?}"
        );
    }

    #[test]
    fn speed_rows_name_places_and_keeps_names_absent_without_sites() {
        let mut lines: Vec<String> = Vec::new();
        let report = check_speed(
            None,
            None,
            &mut |line| lines.push(line.to_string()),
            &|| false,
            &mut |_server| {
                // 335 КБ за 2 с — одна из машин (чуть больше 1 Мбит/с).
                Some((335 * 1024 * 2, 2.0))
            },
            &|_name| None,
            &mut |_ip, _name| panic!("имён проверять не должны"),
        )
        .unwrap();

        assert_eq!(report["names"], Value::Null);
        let items = report["items"].as_array().unwrap();
        assert!(!items.is_empty());
        for item in items {
            assert!(
                ["ok", "warn", "unknown"].contains(&item["state"].as_str().unwrap_or("")),
                "{item:?}"
            );
        }
        assert!(lines.contains(&"━━━━━━━━ Скорость ━━━━━━━━".to_string()));
        // В строках пробы указано место сервера: «... (Россия): ...» и «... (за границей): ...».
        assert!(
            lines.iter().any(|line| line.contains("(Россия):")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("(за границей):")),
            "{lines:?}"
        );
    }
}
