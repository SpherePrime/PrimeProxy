//! Порт `src/diagnostics/history.py` — история проверок сети: что запомнить о
//! прогоне и что изменилось с прошлого раза.
//!
//! Одна проверка отвечает на вопрос «что сейчас». История отвечает на вопрос
//! «что изменилось»: сайт, который вчера открывался, а сегодня нет, — самый
//! верный признак новой блокировки.
//!
//! Здесь только чистые функции. Хранит историю `settings.store` (общая база
//! настроек программы): запись короткая — итог и состояние каждого сервиса.
//! Полный текст прогона лежит в журнале проверки, запись на него ссылается.

use regex::Regex;
use serde_json::{json, Value};

use crate::levels::{is_open, level_rank, worst, FAIL, UNKNOWN, WARN};
use crate::report_upgrade::{text_scalar, truthy};
use crate::services::SCOPE_TITLES;

pub const KIND_BLOCKCHECK: &str = "blockcheck";
/// Название и номер формата выгрузки: по ним чужая программа поймёт, что перед ней.
pub const REPORT_FORMAT: &str = "primebypass.blockcheck/1";

pub const KIND_DOMAIN: &str = "domain";
pub const KIND_DNS: &str = "dns";
pub const KIND_SERVERS: &str = "servers";

/// python `datetime.now()` без внешних крейтов — время в формате ISO
/// (`timespec="seconds"`). Часовой пояс машины берёт движок.
#[must_use]
pub fn now_iso(unix_s: i64) -> String {
    let (year, month, day, hour, minute, second) = civil_parts(unix_s);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
}

// ---------------------------------------------------------------------------
// Чистое время: разбор ISO и «07.10 20:15»
// ---------------------------------------------------------------------------

/// Разбор «2026-10-16T20:15:07» (python `datetime.fromisoformat`)
/// в «наивное» unix-время; сдвиг часового пояса вычитается.
#[must_use]
pub fn parse_iso(value: &str) -> Option<i64> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$").expect("regexp"));
    let captures = re.captures(value)?;
    let year: i64 = captures.get(1)?.as_str().parse().ok()?;
    let month: u32 = captures.get(2)?.as_str().parse().ok()?;
    let day: u32 = captures.get(3)?.as_str().parse().ok()?;
    let hour: i64 = captures.get(4)?.as_str().parse().ok()?;
    let minute: i64 = captures.get(5)?.as_str().parse().ok()?;
    let second: i64 = captures
        .get(6)
        .map(|m| m.as_str().parse())
        .transpose()
        .ok()?
        .unwrap_or(0);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    if let Some(zone) = captures.get(8) {
        let zone = zone.as_str();
        if zone != "Z" {
            let sign = if zone.starts_with('-') { 1 } else { -1 };
            let digits: String = zone.chars().filter(|c| c.is_ascii_digit()).collect();
            let hours: i64 = digits.get(..2)?.parse().ok()?;
            let minutes: i64 = digits.get(2..4)?.parse().ok()?;
            seconds += sign * (hours * 3_600 + minutes * 60);
        }
    }
    Some(seconds)
}

/// «07.10 20:15» из времени записи; при неразборчивом времени — как есть.
#[must_use]
pub fn format_time(value: &str) -> String {
    match parse_iso(value) {
        Some(seconds) => {
            let (_year, month, day, hour, minute, _second) = civil_parts(seconds);
            format!("{day:02}.{month:02} {hour:02}:{minute:02}")
        }
        None => value.to_string(),
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_parts(unix_s: i64) -> (i64, u32, u32, u32, u32, u32) {
    let day_number = unix_s.div_euclid(86_400);
    let seconds_of_day = unix_s.rem_euclid(86_400);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    let z = day_number + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = y + i64::from(month <= 2);
    (year, month, day, hour, minute, second)
}

// ---------------------------------------------------------------------------
// Записи о прогонах
// ---------------------------------------------------------------------------

fn overall_level(report: &Value) -> String {
    let levels: Vec<String> = report
        .get("problems")
        .and_then(Value::as_array)
        .map(|problems| {
            problems
                .iter()
                .map(|problem| text_scalar(problem.get("level")))
                .collect()
        })
        .unwrap_or_default();
    let levels: Vec<&str> = levels.iter().map(String::as_str).collect();
    worst(&levels)
}

/// python `blockcheck_entry`. `when` — «unix, секунды»
/// (python передаёт `datetime.now()`); `None` — не указано, запись без времени.
#[must_use]
pub fn blockcheck_entry(
    report: &Value,
    log_file: &str,
    when: Option<i64>,
    preset: &str,
    zapret_mark: impl Fn(Option<bool>) -> String,
) -> Value {
    let problems: Vec<String> = report
        .get("problems")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| text_scalar(item.get("text")))
                .collect()
        })
        .unwrap_or_default();
    let mut states = Vec::new();
    if let Some(services) = report.get("services").and_then(Value::as_array) {
        for service in services {
            if truthy(service.get("control")) {
                continue;
            }
            let label = text_scalar(service.get("label"));
            let name = if !label.is_empty() {
                label
            } else {
                text_scalar(service.get("key"))
            };
            let state = {
                let level = text_scalar(service.get("level"));
                if level.is_empty() {
                    "unknown".to_string()
                } else {
                    level
                }
            };
            if !name.is_empty() {
                states.push((name, state));
            }
        }
    }
    let level = overall_level(report);
    let headline = if level == "ok" {
        "Всё открывается".to_string()
    } else {
        problems
            .first()
            .cloned()
            .unwrap_or_else(|| "Проверка не дала ответа".to_string())
    };
    let time = match when {
        Some(seconds) => now_iso(seconds),
        None => String::new(),
    };
    let scope = text_scalar(report.get("scope"));
    let title = SCOPE_TITLES
        .iter()
        .find(|(key, _)| *key == scope)
        .map(|(_, title)| (*title).to_string())
        .unwrap_or(scope);
    json!({
        "kind": KIND_BLOCKCHECK,
        "time": time,
        "title": title,
        "level": level,
        "headline": headline,
        "problems": problems,
        "states": states.into_iter().map(|(name, state)| (name, json!(state))).collect::<serde_json::Map<String, Value>>(),
        "log_file": log_file,
        // При каких условиях шла проверка — для сравнения «с Zapret и без».
        "zapret": zapret_mark(match report.get("zapret_running") {
            Some(Value::Bool(flag)) => Some(*flag),
            _ => None,
        }),
        "preset": preset,
        // Только программы, которые стояли на дороге проверки: запущенный, но не включённый VPN не в счёт.
        "tools": truthy(report.get("tools_in_path")),
        // Как ведёт себя фильтр (код из filter_habits) — подсказка подбору стратегий.
        "habit": text_scalar(report.get("habits").filter(|habits| habits.is_object()).and_then(|habits| habits.get("code"))),
    })
}

/// python `dns_check_entry`. `None` — проверку остановили или она не дала данных.
#[must_use]
pub fn dns_check_entry(results: &Value, when: Option<i64>) -> Option<Value> {
    if truthy(results.get("stopped")) {
        return None;
    }
    let domains = results.get("domains")?.as_object()?.clone();
    if domains.is_empty() {
        return None;
    }
    let mut states = Vec::new();
    for (host, item) in &domains {
        let mapped = match text_scalar(item.get("state")).as_str() {
            "ok" | "local" => "ok",
            "spoofed" => "fail",
            _ => "unknown",
        };
        states.push((host.clone(), json!(mapped)));
    }
    let spoofed: Vec<String> = states
        .iter()
        .filter(|(_, level)| level == "fail")
        .map(|(host, _)| host.clone())
        .collect();
    let unknown: Vec<String> = states
        .iter()
        .filter(|(_, level)| level == "unknown")
        .map(|(host, _)| host.clone())
        .collect();
    let (level, headline) = if !spoofed.is_empty() {
        (FAIL, format!("Подменяются адреса: {}", spoofed.join(", ")))
    } else if !unknown.is_empty() && unknown.len() == states.len() {
        // Ни один адрес проверить не удалось — это «не узнали», а не предупреждение.
        (UNKNOWN, "Проверить DNS не удалось".to_string())
    } else if !unknown.is_empty() {
        (
            WARN,
            format!(
                "Подмены не видно, но не удалось проверить: {}",
                unknown.join(", ")
            ),
        )
    } else {
        ("ok", "DNS отвечает честно".to_string())
    };
    let problems: Vec<Value> = spoofed
        .iter()
        .map(|host| {
            let reason = domains
                .get(host)
                .and_then(|item| item.get("reason"))
                .filter(|value| truthy(Some(value)));
            let reason = match reason {
                Some(reason) => text_scalar(Some(reason)),
                None => "адрес подменён".to_string(),
            };
            json!(format!("{host}: {reason}"))
        })
        .collect();
    Some(json!({
        "kind": KIND_DNS,
        "time": when.map(now_iso).unwrap_or_default(),
        "title": "DNS подмена",
        "level": level,
        "headline": headline,
        "problems": problems,
        "states": states.into_iter().collect::<serde_json::Map<String, Value>>(),
        "log_file": "",
    }))
}

/// python-«уточнение» серверной проверки (`dns.server_check.Finding`): здесь
/// достаточно полей, которые читает история.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerFinding {
    pub level: String,
    pub title: String,
    pub text: String,
}

/// Отчёт проверки DNS-серверов (python передаёт объект с атрибутами).
#[derive(Debug, Clone, Default)]
pub struct ServerRun {
    pub finished: bool,
    pub stopped: bool,
    pub timed_out: bool,
    pub rows: usize,
    pub findings: Vec<ServerFinding>,
}

/// python `server_check_entry`. `None` — проверку остановили или она не закончилась.
#[must_use]
pub fn server_check_entry(report: &ServerRun, when: Option<i64>) -> Option<Value> {
    if !report.finished || report.stopped || report.rows == 0 {
        return None;
    }
    // Сведения («info») в итог прогона не идут: в истории — только то, что мешает.
    let serious: Vec<&ServerFinding> = report
        .findings
        .iter()
        .filter(|item| item.level == FAIL || item.level == WARN)
        .collect();
    let level = worst(
        &serious
            .iter()
            .map(|item| item.level.as_str())
            .collect::<Vec<_>>(),
    );
    let headline = match serious.iter().min_by_key(|item| level_rank(&item.level)) {
        Some(first) => {
            if first.title.is_empty() {
                first.text.clone()
            } else {
                first.title.clone()
            }
        }
        None => "Замечаний нет".to_string(),
    };
    let (level, headline) = if report.timed_out {
        // Часть адресов не проверена: «замечаний нет» по половине списка было бы неправдой.
        (
            UNKNOWN.to_string(),
            "Проверка не успела закончиться".to_string(),
        )
    } else {
        (level, headline)
    };
    let problems: Vec<String> = serious
        .iter()
        .map(|item| {
            if item.title.is_empty() {
                item.text.clone()
            } else {
                item.title.clone()
            }
        })
        .collect();
    Some(json!({
        "kind": KIND_SERVERS,
        "time": when.map(now_iso).unwrap_or_default(),
        "title": format!("Адресов проверено: {}", report.rows),
        "level": level,
        "headline": headline,
        "problems": problems,
        "states": serde_json::Map::<String, Value>::new(),
        "log_file": "",
    }))
}

/// python `domain_entry`: запись о проверке одного домена.
#[must_use]
pub fn domain_entry(
    target: &str,
    level: &str,
    headline: &str,
    problems: &[&str],
    when: Option<i64>,
) -> Value {
    let level = if ["ok", "warn", "fail"].contains(&level) {
        level.to_string()
    } else {
        UNKNOWN.to_string()
    };
    json!({
        "kind": KIND_DOMAIN,
        "time": when.map(now_iso).unwrap_or_default(),
        "title": target,
        "level": level,
        "headline": headline,
        "problems": problems,
        "states": serde_json::Map::<String, Value>::new(),
        "log_file": "",
    })
}

/// Прежние названия режимов: прошлые проверки хранят название того дня, а
/// сравнивать их надо с тем же режимом под новым именем
/// (2026-10-16: «Полная проверка» стала «Глубокой диагностикой»).
const RENAMED_TITLES: [(&str, &str); 1] = [("Полная проверка", "Глубокая диагностика")];

/// python `same_run_kind`: прогоны одного вида и одного набора сайтов.
#[must_use]
pub fn same_run_kind(run: &Value, entry: &Value) -> bool {
    let renamed = |text: &str| -> String {
        match RENAMED_TITLES.iter().find(|(old, _)| *old == text) {
            Some((_, renamed)) => (*renamed).to_string(),
            None => text.to_string(),
        }
    };
    let run_title = renamed(&text_scalar(run.get("title")));
    let entry_title = renamed(&text_scalar(entry.get("title")));
    text_scalar(run.get("kind")) == text_scalar(entry.get("kind")) && run_title == entry_title
}

/// Последний прошлый прогон того же вида и с тем же набором сайтов.
#[must_use]
pub fn previous_run<'a>(history: &'a [Value], entry: &Value) -> Option<&'a Value> {
    history.iter().rev().find(|run| same_run_kind(run, entry))
}

/// Прошлые проверки для экрана, свежие сверху: (уровень, «что · когда», итог).
#[must_use]
pub fn history_rows(runs: &[Value]) -> Vec<(String, String, String)> {
    runs.iter()
        .rev()
        .map(|run| {
            let title = text_scalar(run.get("title"));
            let when = format_time(&text_scalar(run.get("time")));
            let level = {
                let level = text_scalar(run.get("level"));
                if level.is_empty() {
                    UNKNOWN.to_string()
                } else {
                    level
                }
            };
            let parts: Vec<&str> = [title.as_str(), when.as_str()]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect();
            (level, parts.join(" · "), text_scalar(run.get("headline")))
        })
        .collect()
}

/// Что изменилось с прошлой проверки, по одному предложению на сервис.
///
/// Сравнивается только «открывается / не открывается». Сервис, которого в
/// одной из проверок не было или про который ответа не получили, не
/// сравнивается: неизвестное — не перемена.
#[must_use]
pub fn describe_changes(previous: Option<&Value>, current: &Value) -> Vec<String> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let before = previous.get("states").and_then(Value::as_object);
    let after: Vec<(String, String)> = current
        .get("states")
        .and_then(Value::as_object)
        .map(|states| {
            states
                .iter()
                .map(|(name, state)| (name.clone(), text_scalar(Some(state))))
                .collect()
        })
        .unwrap_or_default();
    let mut stopped: Vec<String> = Vec::new();
    let mut recovered: Vec<String> = Vec::new();
    for (name, state) in after {
        let old = before
            .and_then(|states| states.get(name.as_str()))
            .map(|value| text_scalar(Some(value)));
        let open_old = old.as_ref().map(|old| is_open(old)).unwrap_or(false);
        if open_old && state == FAIL {
            stopped.push(name);
        } else if old.as_deref() == Some(FAIL) && is_open(&state) {
            recovered.push(name);
        }
    }
    let mut changes: Vec<String> = Vec::new();
    if !stopped.is_empty() {
        changes.push(format!("перестали открываться: {}", stopped.join(", ")));
    }
    if !recovered.is_empty() {
        changes.push(format!("снова открываются: {}", recovered.join(", ")));
    }
    changes
}

/// Полный отчёт в строгом виде — для разбора другой программой и для отправки.
#[must_use]
pub fn report_json(report: &Value, entry: &Value, app_version: &str) -> String {
    let document = json!({
        "format": REPORT_FORMAT,
        "app_version": app_version,
        "time": entry.get("time"),
        "title": entry.get("title"),
        "level": entry.get("level"),
        "report": report,
    });
    serde_json::to_string_pretty(&document).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn time_roundtrip_and_fallback() {
        assert_eq!(parse_iso("2026-10-16T20:15:07"), Some(1_792_181_707));
        assert_eq!(
            parse_iso("2026-10-16T20:15"),
            parse_iso("2026-10-16 20:15:00")
        );
        assert!(parse_iso("2026-13-01T00:00:00").is_none());
        assert_eq!(format_time("2026-10-16T20:15:07"), "16.10 20:15");
        assert_eq!(format_time("какой-то текст"), "какой-то текст");
        assert_eq!(format_time(""), "");
    }

    #[test]
    fn blockcheck_entry_python_shape() {
        let report = json!({
            "scope": "main",
            "zapret_running": true,
            "tools_in_path": ["vpn"],
            "habits": {"code": "cut"},
            "problems": [{"level": "warn", "text": "Первая фраза"}, {"level": "fail", "text": "Вторая"}],
            "services": [
                {"key": "youtube", "label": "YouTube", "level": "fail"},
                {"key": "control", "label": "Пробный контроль", "level": "ok", "control": true},
                {"key": "", "label": "", "level": "ok"},
            ],
        });
        let entry = blockcheck_entry(
            &report,
            "",
            Some(1_792_181_707),
            "Оттский",
            crate::compare::zapret_mark,
        );
        assert_eq!(
            entry.get("kind").and_then(Value::as_str),
            Some("blockcheck")
        );
        assert_eq!(
            entry.get("time").and_then(Value::as_str),
            Some("2026-10-16T20:15:07")
        );
        assert_eq!(
            entry.get("title").and_then(Value::as_str),
            Some("Discord и YouTube")
        );
        assert_eq!(entry.get("level").and_then(Value::as_str), Some("fail"));
        assert_eq!(
            entry.get("headline").and_then(Value::as_str),
            Some("Первая фраза")
        );
        assert_eq!(entry.get("zapret").and_then(Value::as_str), Some("on"));
        assert_eq!(entry.get("tools").and_then(Value::as_bool), Some(true));
        assert_eq!(entry.get("habit").and_then(Value::as_str), Some("cut"));
        let states = entry.get("states").and_then(Value::as_object).unwrap();
        assert_eq!(states.get("YouTube").and_then(Value::as_str), Some("fail"));
        assert_eq!(states.len(), 1);
        let level_ok = json!({"scope": "all", "problems": [], "services": []});
        let entry = blockcheck_entry(&level_ok, "", None, "", crate::compare::zapret_mark);
        assert_eq!(entry.get("level").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            entry.get("headline").and_then(Value::as_str),
            Some("Всё открывается")
        );
    }

    #[test]
    fn dns_entry_python_text() {
        let results = json!({
            "domains": {
                "one.example": {"state": "spoofed", "reason": ""},
                "two.example": {"state": "local"},
                "three.example": {"state": "strange"},
            }
        });
        let entry = dns_check_entry(&results, Some(1_792_181_707)).unwrap();
        assert_eq!(entry.get("level").and_then(Value::as_str), Some("fail"));
        assert_eq!(
            entry.get("headline").and_then(Value::as_str),
            Some("Подменяются адреса: one.example")
        );
        let problems = entry.get("problems").and_then(Value::as_array).unwrap();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].as_str(), Some("one.example: адрес подменён"));
        let stopped = dns_check_entry(
            &json!({"stopped": true, "domains": {"a": {"state": "ok"}}}),
            None,
        );
        assert!(stopped.is_none());
        let unknown = dns_check_entry(&json!({"domains": {"a": {"state": ""}}}), None).unwrap();
        assert_eq!(
            unknown.get("level").and_then(Value::as_str),
            Some("unknown")
        );
        let mixed = dns_check_entry(
            &json!({"domains": {"a": {"state": "ok"}, "b": {"state": ""}}}),
            None,
        )
        .unwrap();
        assert_eq!(mixed.get("level").and_then(Value::as_str), Some("warn"));
        let clean = dns_check_entry(&json!({"domains": {"a": {"state": "ok"}}}), None).unwrap();
        assert_eq!(clean.get("level").and_then(Value::as_str), Some("ok"));
    }

    #[test]
    fn server_entry_muted_when_unfinished() {
        let run = ServerRun {
            finished: true,
            findings: vec![
                ServerFinding {
                    level: WARN.to_string(),
                    title: "Тайтл".into(),
                    text: "Весь текст".into(),
                },
                ServerFinding {
                    level: WARN.to_string(),
                    title: String::new(),
                    text: "Только текст".into(),
                },
            ],
            rows: 4,
            ..Default::default()
        };
        let entry = server_check_entry(&run, None).unwrap();
        assert_eq!(entry.get("level").and_then(Value::as_str), Some("warn"));
        assert_eq!(entry.get("headline").and_then(Value::as_str), Some("Тайтл"));
        assert_eq!(
            entry.get("title").and_then(Value::as_str),
            Some("Адресов проверено: 4")
        );
        let run_timed = ServerRun {
            finished: true,
            findings: run.findings.clone(),
            rows: 1,
            timed_out: true,
            ..Default::default()
        };
        assert_eq!(
            server_check_entry(&run_timed, None)
                .unwrap()
                .get("level")
                .and_then(Value::as_str),
            Some("unknown")
        );
        assert!(server_check_entry(
            &ServerRun {
                findings: run.findings.clone(),
                ..Default::default()
            },
            None
        )
        .is_none());
        assert!(server_check_entry(
            &ServerRun {
                finished: true,
                ..Default::default()
            },
            None
        )
        .is_none());
    }

    #[test]
    fn same_kind_and_previous() {
        let entry = json!({"kind": "blockcheck", "title": "Глубокая диагностика"});
        let new_named = json!({"kind": "blockcheck", "title": "Глубокая диагностика"});
        let old_named = json!({"kind": "blockcheck", "title": "Полная проверка"});
        let other_kind = json!({"kind": "dns", "title": "Глубокая диагностика"});
        assert!(same_run_kind(&new_named, &entry));
        assert!(same_run_kind(&old_named, &entry));
        assert!(!same_run_kind(&other_kind, &entry));
        let history = vec![json!({"kind": "blockcheck", "title": "Полная проверка", "time": "t1"})];
        assert!(previous_run(&history, &entry).is_some());
        assert!(previous_run(&[], &entry).is_none());
    }

    #[test]
    fn history_rows_reversed_python_text() {
        let runs = vec![
            json!({"title": "Старая", "time": "2026-10-16T20:15:07", "level": "ok", "headline": "Всё открывается"}),
            json!({"title": "Свежая", "time": "", "level": "fail", "headline": "Нет"}),
        ];
        let rows = history_rows(&runs);
        assert_eq!(
            rows[0],
            ("fail".to_string(), "Свежая".to_string(), "Нет".to_string())
        );
        assert_eq!(
            rows[1],
            (
                "ok".to_string(),
                "Старая · 16.10 20:15".to_string(),
                "Всё открывается".to_string()
            )
        );
    }

    #[test]
    fn describe_changes_pairs() {
        let previous = json!({"states": {"YouTube": "ok", "Discord": "fail", "Twitch": "fail"}});
        let current = json!({"states": {"YouTube": "fail", "Discord": "warn", "Twitch": "fail"}});
        let changes = describe_changes(Some(&previous), &current);
        assert_eq!(
            changes,
            vec![
                "перестали открываться: YouTube",
                "снова открываются: Discord"
            ]
        );
        assert_eq!(describe_changes(None, &current).len(), 0);
        // Новые сервисы не сравниваются.
        let grown = json!({"states": {"YouTube": "fail", "Новый": "ok"}});
        assert_eq!(describe_changes(Some(&previous), &grown).len(), 1);
    }

    #[test]
    fn report_json_fields() {
        let text = report_json(
            &json!({"x": 1}),
            &json!({"time": "t", "title": "Т", "level": "ok"}),
            "1.2",
        );
        assert!(text.contains("\"format\": \"") && text.contains(REPORT_FORMAT));
        assert!(text.contains("\"app_version\": \"1.2\""));
    }
}
