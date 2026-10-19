//! Порт profile/conditions_text.py: условия профиля словами — сводка в шапке
//! и пояснения к диапазонам пакетов. Текст пресета не меняется: это только
//! показ того, что в нём уже записано.

use std::sync::OnceLock;

use crate::match_filters::{ports_label_from_match_lines, protocol_label_from_match_lines};

const PLAIN_PROTOCOLS: [&str; 3] = ["TCP", "UDP", "TCP/UDP"];

fn first_packets_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::RegexBuilder::new(r"^-(?P<mode>[nd])(?P<count>\d+)$")
            .case_insensitive(true)
            .build()
            .expect("regex диапазона пакетов")
    })
}

/// python _first_packets_phrase.
fn first_packets_phrase(count: i64, with_data: bool) -> String {
    let tail = if with_data { " с данными" } else { "" };
    let last_two = count % 100;
    let last = count % 10;
    if last == 1 && last_two != 11 {
        if count != 1 {
            return format!("первый {count} пакет{tail}");
        }
        return format!("первый пакет{tail}");
    }
    if (2..=4).contains(&last) && !matches!(last_two, 12..=14) {
        return format!("первые {count} пакета{tail}");
    }
    format!("первые {count} пакетов{tail}")
}

/// Диапазон winws2 словами: `-d8` → «первые 8 пакетов с данными».
pub fn range_phrase(expression: &str) -> String {
    let expr = expression.trim().to_lowercase();
    if expr.is_empty() {
        return String::new();
    }
    if expr == "a" {
        return "все пакеты".to_string();
    }
    if expr == "x" {
        return "не обрабатываются".to_string();
    }
    if let Some(captures) = first_packets_re().captures(&expr) {
        let count: i64 = captures["count"].parse().expect("число пакетов");
        let with_data = captures["mode"].to_lowercase() == "d";
        return first_packets_phrase(count, with_data);
    }
    expr
}

/// Пояснение под полем диапазона в панели условий.
pub fn range_hint(mode: &str, value: &str) -> String {
    let mode = mode.trim().to_lowercase();
    let value = value.trim().to_string();
    if mode == "a" {
        return "Стратегия работает на всех пакетах соединения.".to_string();
    }
    if mode == "x" {
        return "Пакеты в эту сторону стратегия не трогает.".to_string();
    }
    if mode == "n" || mode == "d" {
        if !is_all_digits(&value) {
            return "Укажите число: сколько первых пакетов соединения обрабатывать.".to_string();
        }
        let count: i64 = value.parse().unwrap_or(0);
        let phrase = first_packets_phrase(count, mode == "d");
        if mode == "d" {
            return format!("Только {phrase}. Служебные пакеты без данных не считаются.");
        }
        return format!("Только {phrase} соединения по счёту.");
    }
    if mode == "custom" {
        return "Выражение winws2 записывается как есть, например s1<d1 или -d8.".to_string();
    }
    String::new()
}

/// python str.isdigit(): цифры и не пусто.
fn is_all_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|symbol| char::is_ascii_digit(&symbol))
}

fn match_label(match_lines: &[String]) -> String {
    let protocol = protocol_label_from_match_lines(match_lines);
    let ports = ports_label_from_match_lines(match_lines);
    // «TCP • TCP 80,443» — одно и то же дважды: порты уже называют протокол.
    if !ports.is_empty() && PLAIN_PROTOCOLS.contains(&protocol.as_str()) {
        return ports;
    }
    [protocol, ports]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Одна строка в шапке профиля: что он ловит и на каких пакетах работает.
pub fn conditions_summary(
    match_lines: &[String],
    match_summary: &str,
    filter_value: &str,
    in_range: &str,
    out_range: &str,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if match_lines.is_empty() {
        parts.push(match_summary.trim().to_string());
    } else {
        parts.push(match_label(match_lines));
    }
    parts.push(filter_value.trim().to_string());

    let out_value = range_phrase(out_range);
    if !out_value.is_empty() {
        if out_value == "не обрабатываются" {
            parts.push("исходящие не обрабатываются".to_string());
        } else {
            parts.push(out_value);
        }
    }
    let in_expr = in_range.trim().to_lowercase();
    if !in_expr.is_empty() && in_expr != "x" {
        parts.push(format!("входящие: {}", range_phrase(&in_expr)));
    }
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}
