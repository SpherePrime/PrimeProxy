//! Порт `src/diagnostics/report_upgrade.py` — версия формата отчёта BlockCheck
//! и перевод старых отчётов в новый вид.
//!
//! Отчёт хранится в файле и в истории, а открывается и через месяц — новой
//! версией программы. Всё, что знает о старых видах отчёта, живёт только здесь:
//! экран и карточки работают с отчётом текущей версии и ничего не угадывают.
//!
//! Версии:
//!
//! 1. Отчёты до появления версии. Строка итога не говорила, о каком она сайте и
//!    из какого раздела: экран угадывал это по тексту фразы.
//! 2. Строка итога несёт `site` (ключ сайта из `services`) и `section` (раздел
//!    отчёта, из которого она выведена); кнопку «Telegram Proxy» ставит движок.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

pub const REPORT_VERSION: i64 = 2;

/// Вид проблемы → раздел отчёта, когда сайта у неё нет.
const KIND_SECTIONS: [(&str, &str); 4] =
    [("voice", "voice"), ("system", "system"), ("cut16", "freeze"), ("quic", "quic")];
/// Виды, при которых закрытому Telegram советовали встроенный прокси.
const TELEGRAM_PROXY_KINDS: [&str; 3] = ["ip", "other", "noconnect"];

fn for_sites_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(.*?) для: (.+)$").expect("regexp"))
}

/// Python-правдивость JSON-значения (`if value:`).
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().map(|n| n != 0.0).unwrap_or(false),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(entries)) => !entries.is_empty(),
    }
}

/// python `str(value or "")` для скаляров отчёта.
pub fn text_scalar(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items.iter().map(Value::to_string).collect::<Vec<_>>().join(", "),
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(key, value)| format!("{key}: {}", text_scalar(Some(value))))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// `int(report.get("report_version") or 1)`: не число — версия 1.
fn version_of(value: Option<&Value>) -> i64 {
    let parsed = match value {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(|n| n as i64)),
        Some(Value::String(text)) => text.trim().parse::<i64>().ok(),
        Some(Value::Bool(flag)) => Some(i64::from(*flag)),
        _ => None,
    };
    parsed.unwrap_or(1)
}

/// Отчёт текущей версии. Отчёт уже нужной версии возвращается как есть.
#[must_use]
pub fn upgrade(report: &Value) -> Value {
    if !report.is_object() {
        return report.clone();
    }
    if version_of(report.get("report_version")) >= REPORT_VERSION {
        return report.clone();
    }
    let services: Vec<Value> = report
        .get("services")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|item| item.is_object()).cloned().collect())
        .unwrap_or_default();
    let problems: Vec<Value> = report
        .get("problems")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|item| item.is_object()).map(|item| problem_v2(item, &services, report)).collect())
        .unwrap_or_default();
    let mut upgraded = report.as_object().cloned().unwrap_or_default();
    upgraded.insert("problems".to_string(), json!(problems));
    upgraded.insert("report_version".to_string(), json!(REPORT_VERSION));
    Value::Object(upgraded)
}

/// Строка итога версии 1 → 2: сайт и раздел по старым правилам экрана.
#[must_use]
pub fn problem_v2(problem: &Value, services: &[Value], report: &Value) -> Value {
    let mut upgraded = problem.as_object().cloned().unwrap_or_default();
    let kind = text_scalar(problem.get("kind"));
    let kind = if kind.is_empty() { "other".to_string() } else { kind };
    let text = text_scalar(problem.get("text"));
    let site = if truthy(problem.get("site")) { String::new() } else { guess_site(problem, services) };
    if !site.is_empty() {
        upgraded.insert("site".to_string(), json!(site));
    }
    if !truthy(problem.get("section")) {
        let section = if !site.is_empty() {
            Some("services")
        } else if kind == "dns" {
            Some(if truthy(report.get("dns_servers")) { "dns_servers" } else { "dns" })
        } else if kind == "network" {
            Some(if text.starts_with("IPv6") { "ipv6" } else { "network" })
        } else {
            KIND_SECTIONS.iter().find(|(name, _)| *name == kind).map(|(_, section)| *section)
        };
        if let Some(section) = section {
            upgraded.insert("section".to_string(), json!(section));
        }
    }
    if !truthy(problem.get("action")) && TELEGRAM_PROXY_KINDS.contains(&kind.as_str()) {
        let title = text_scalar(problem.get("title"));
        if format!("{title} {text}").to_lowercase().contains("telegram") {
            upgraded.insert("action".to_string(), json!("telegram_proxy"));
        }
    }
    Value::Object(upgraded)
}

/// Сайт строки старого отчёта: по названию, по адресу или по первому слову фразы.
#[must_use]
pub fn guess_site(problem: &Value, services: &[Value]) -> String {
    let kind = text_scalar(problem.get("kind"));
    let kind = if kind.is_empty() { "other".to_string() } else { kind };
    let text = text_scalar(problem.get("text"));
    let target = text_scalar(problem.get("target"));
    let mut names = vec![
        text_scalar(problem.get("title")),
        text
            .split(' ')
            .next()
            .unwrap_or("")
            .trim_end_matches([',', ':'])
            .to_string(),
    ];
    if kind == "quic" {
        // «QUIC … для: YouTube, X. …» — подробности на карточке первого названного сайта.
        let head = match text.find(". ") {
            Some(index) => &text[..index],
            None => text.as_str(),
        };
        if let Some(captures) = for_sites_re().captures(head) {
            if let Some(first) = captures.get(2) {
                let first = first.as_str().split(',').next().unwrap_or("").trim();
                names.push(first.to_string());
            }
        }
    }
    names.retain(|name| !name.is_empty());
    for service in services {
        let hosts: Vec<String> = service
            .get("targets")
            .and_then(Value::as_array)
            .map(|targets| targets.iter().map(|item| text_scalar(item.get("host"))).collect())
            .unwrap_or_default();
        let label = text_scalar(service.get("label"));
        if (names.contains(&label) || (!target.is_empty() && hosts.contains(&target)))
            && truthy(service.get("key"))
        {
            return text_scalar(service.get("key"));
        }
    }
    String::new()
}

/// Заготовка отчёта версии 1 без Problems — для тестов движков.
#[must_use]
pub fn blank_v1() -> Value {
    Value::Object(Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn already_current_returns_same() {
        let current = json!({"report_version": 2, "problems": []});
        assert_eq!(upgrade(&current), current);
        let newer = json!({"report_version": 3});
        assert_eq!(upgrade(&newer), newer);
        let not_dict = json!([1, 2]);
        assert_eq!(upgrade(&not_dict), not_dict);
        // report_version не число — считается 1.
        let broken = json!({"report_version": "abc", "problems": []});
        assert_eq!(upgrade(&broken).get("report_version").and_then(Value::as_i64), Some(2));
    }

    #[test]
    fn v1_problems_receive_site_and_section() {
        let report = json!({
            "report_version": 1,
            "dns_servers": [{"name": "X"}],
            "services": [
                {"key": "youtube", "label": "YouTube", "targets": [{"host": "yt.example"}]},
            ],
            "problems": [
                {"kind": "dns", "text": "DNS серверы молчат"},
                {"kind": "network", "text": "IPv6 недоступен"},
                {"kind": "voice", "text": "Голос не работает"},
                {"kind": "quic", "text": "QUIC для: YouTube, Google. подробности"},
                {"kind": "ip", "text": "прошло", "site": "youtube", "section": "services", "action": ""},
                {"kind": "noconnect", "text": "нет ответа", "title": "Telegram сайт", "target": "yt.example"},
            ]
        });
        let got = upgrade(&report);
        let problems = got.get("problems").and_then(Value::as_array).unwrap();
        assert_eq!(problems[0].get("section").and_then(Value::as_str), Some("dns_servers"));
        assert_eq!(problems[1].get("section").and_then(Value::as_str), Some("ipv6"));
        assert_eq!(problems[2].get("section").and_then(Value::as_str), Some("voice"));
        assert_eq!(problems[3].get("section").and_then(Value::as_str), Some("services"));
        assert_eq!(problems[3].get("site").and_then(Value::as_str), Some("youtube"));
        assert_eq!(problems[4].get("action").and_then(Value::as_str), Some(""));
        // kind=noconnect и «Telegram» в тексте → телеграм-прокси.
        assert_eq!(problems[5].get("section").and_then(Value::as_str), Some("services"));
        assert_eq!(problems[5].get("action").and_then(Value::as_str), Some("telegram_proxy"));
        assert_eq!(got.get("report_version").and_then(Value::as_i64), Some(2));
    }

    #[test]
    fn quic_for_sites_first_named() {
        let problem = json!({"kind": "quic", "text": "QUIC stripped для: YouTube, X. Хром молчит"});
        let services = json!([{"key": "yt", "label": "YouTube"}]);
        assert_eq!(guess_site(&problem, services.as_array().unwrap()), "yt");
        let other = json!({"kind": "quic", "text": "QUIC потерян: нет ответа"});
        assert_eq!(guess_site(&other, services.as_array().unwrap()), "");
    }
}
