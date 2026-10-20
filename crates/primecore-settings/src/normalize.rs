//! Порт чистой логики `src/settings/normalize.py` — interpretation
//! произвольных значений в строгие типы. Один-в-один с Python,
//! включая странности (as_bool clinical "maybe" → default,
//! as_int("12.5") → default из-за исключения int()).

use crate::schema::{orchestra_askey_is_known, ORCHESTRA_ASK_EXAMPLE_DEFAULT};
use std::net::{IpAddr, Ipv4Addr};

pub trait JsonValue {
    /// В Python эти функции принимают object (JSON-значение из базы).
    /// В Rust — serde_json::Value.
    type Output;
}

// ---- модель значения: Value из serde_json ----

use serde_json::Value;

fn is_list_tuple_set(value: &Value) -> bool {
    matches!(value, Value::Array(_))
}

pub fn as_dict(value: &Value) -> serde_json::Map<String, Value> {
    match value {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    }
}

/// as_bool(value, default): None/нечитаемое → default («"maybe"» — это
/// тоже default: только наборы слов для true/false признаются).
pub fn as_bool(value: &Value, default: bool) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Number(nr) => {
            // Python: isinstance(value, int) → bool(value); float НЕ int,
            // но в JSON-данных float приходит редко — пусть float тоже
            // даёт false, если это не целое-выглядящее число.
            nr.as_i64().is_some_and(|n| n != 0)
        }
        Value::String(text) => {
            let normalized = text.trim().to_lowercase();
            if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
                return true;
            }
            if matches!(normalized.as_str(), "0" | "false" | "no" | "off") {
                return false;
            }
            default
        }
        _ => default,
    }
}

/// int(value) с фоллбэком default, обрезанием min/max.
pub fn as_int(value: &Value, default: i64, minimum: Option<i64>, maximum: Option<i64>) -> i64 {
    let mut result = python_int(value).unwrap_or(default);
    if let Some(minimum) = minimum {
        result = result.max(minimum);
    }
    if let Some(maximum) = maximum {
        result = result.min(maximum);
    }
    result
}

/// Поведение Python int(value): строки и bool ведут себя как Python
/// (`"12.5"` → None, `True` → 1, float с остатком → None? В Python
/// int(2.5)=2 — ординарно, значит int(Float) ломится вниз).
fn python_int(value: &Value) -> Option<i64> {
    match value {
        Value::Null => None,
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(nr) => {
            if let Some(i) = nr.as_i64() {
                Some(i)
            } else {
                nr.as_f64().map(
                    |f| f.trunc() as i64, /* int(float) → floor по модулю */
                )
            }
        }
        Value::String(text) => {
            let trimmed = text.trim();
            parse_python_int_str(trimmed)
        }
        _ => None,
    }
}

/// Python int(str): допускает `±[0-9]+` и пробелы вокруг; float-строку
/// не допускает; подчёркивания в числах допускает (`1_0` = 10).
pub fn parse_python_int_str(text: &str) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let cleaned = text.replace('_', "");
    if cleaned.contains('.') {
        return None;
    }
    cleaned.parse::<i64>().ok()
}

pub fn as_nullable_int(value: &Value) -> Option<i64> {
    python_int(value)
}

pub fn as_str(value: &Value, default: &str) -> String {
    match value {
        Value::Null => default.to_string(),
        Value::String(text) => text.clone(),
        // Python str(True) = "True" (заглавная), не serde-представление.
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Number(nr) => nr.to_string(),
        _ => python_repr(value),
    }
}

/// str(объект) для непечатаемых JSON-типов: Python дал бы «<...repr».
/// Для массива/словаря Python печатает repr: [1, 2] → "[1, 2]".
fn python_repr(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_repr_inner).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(_) => "{...}".to_string(), // pydict-строку сверять не приходится
        other => python_repr_inner(other),
    }
}

fn python_repr_inner(value: &Value) -> String {
    match value {
        Value::String(text) => format!("'{text}'"), // по умолчанию '...'
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

pub fn as_clean_str(value: &Value, default: &str) -> String {
    as_str(value, default).trim().to_string()
}

pub fn as_nullable_str(value: &Value) -> Option<String> {
    let text = as_clean_str(value, "");
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// as_str_in: значение чистится, радикалится, и должно быть в allowed.
pub fn as_str_in(value: &Value, allowed: &[&str], default: &str) -> String {
    let text = as_clean_str(value, "").to_lowercase();
    if allowed.contains(&text.as_str()) {
        text
    } else {
        default.to_string()
    }
}

pub fn normalize_hex_secret(value: &Value) -> String {
    let text = as_clean_str(value, "").to_lowercase();
    if text.len() != 32 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return String::new();
    }
    text
}

/// Имя домена: leading/trailing точки снимаются, только a-z0-9-, метки
/// ≤63, всего ≤253, пустые метки запрещены. IDN/русские → "".
pub fn normalize_domain(value: &Value) -> String {
    let cleaned = as_clean_str(value, "").trim_matches('.').to_lowercase();
    if cleaned.is_empty() || cleaned.len() > 253 {
        return String::new();
    }
    for label in cleaned.split('.') {
        if label.is_empty() || label.len() > 63 {
            return String::new();
        }
        if label.starts_with('-') || label.ends_with('-') {
            return String::new();
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return String::new();
        }
    }
    cleaned
}

fn raw_items(value: &Value) -> Vec<String> {
    match value {
        Value::String(text) =>
        {
            #[allow(clippy::collapsible_str_replace)]
            text.replace(',', " ")
                .replace(';', " ")
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        }
        Value::Array(items) => {
            let mut collected = Vec::new();
            for item in items {
                if let Value::String(text) = item {
                    #[allow(clippy::collapsible_str_replace)]
                    collected.extend(
                        text.replace(',', " ")
                            .replace(';', " ")
                            .split_whitespace()
                            .map(|s| s.to_string()),
                    );
                } else {
                    collected.push(python_repr(item));
                }
            }
            collected
        }
        _ => Vec::new(),
    }
}

pub fn unique_str_list(value: &Value) -> Vec<String> {
    if !is_list_tuple_set(value) {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Value::Array(items) = value {
        for item in items {
            let text = as_clean_str(item, "");
            if text.is_empty() {
                continue;
            }
            let normalized = text.to_lowercase();
            if !seen.insert(normalized) {
                continue;
            }
            result.push(text);
        }
    }
    result
}

/// `_is_valid_domain`: строгий домен окончания breadth ≥2 и буква в TLD.
fn is_valid_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tail = labels[labels.len() - 1];
    tail.len() >= 2 && tail.chars().any(|c| c.is_ascii_alphabetic())
}

pub fn unique_domain_list(value: &Value) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in raw_items(value) {
        let domain = item.trim().to_lowercase();
        if seen.contains(&domain) || !is_valid_domain(&domain) {
            continue;
        }
        seen.insert(domain.clone());
        result.push(domain);
    }
    result
}

/// Целевые IP Telegram DC: только номера 1,2,3,4,5,203.
pub fn unique_dc_ip_list(value: &Value) -> Vec<String> {
    const DC_NUMBERS: [i64; 6] = [1, 2, 3, 4, 5, 203];
    let mut by_dc: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    let mut order: Vec<i64> = Vec::new();
    for item in raw_items(value) {
        let text = item.trim();
        let (dc_part, ip_part) = match text.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        let dc = match parse_python_int_str(dc_part.trim()) {
            Some(number) => number,
            None => continue,
        };
        let ip = match ip_part.trim().parse::<Ipv4Addr>() {
            Ok(addr) => addr.to_string(),
            Err(_) => continue,
        };
        if !DC_NUMBERS.contains(&dc) {
            continue;
        }
        if !by_dc.contains_key(&dc) {
            order.push(dc);
        }
        by_dc.insert(dc, ip);
    }
    order
        .into_iter()
        .map(|dc| format!("{dc}:{}", by_dc[&dc]))
        .collect()
}

pub fn unique_int_list(value: &Value) -> Vec<i64> {
    if !is_list_tuple_set(value) {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Value::Array(items) = value {
        for item in items {
            if let Some(number) = python_int(item) {
                if seen.insert(number) {
                    result.push(number);
                }
            }
        }
    }
    result
}

pub fn unique_ip_list(value: &Value) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in raw_items(value) {
        let parsed: Option<IpAddr> = item.trim().parse().ok();
        let normalized = match parsed {
            Some(addr) => addr.to_string(),
            None => continue,
        };
        if seen.contains(&normalized) {
            continue;
        }
        seen.insert(normalized.clone());
        result.push(normalized);
    }
    result
}

/// normalize_custom_dns_servers: дедуп по (id-кейсу, имени-кейсу),
/// DoH только https без пробелов.
pub fn normalize_custom_dns_servers(value: &Value) -> Vec<serde_json::Map<String, Value>> {
    let items = match value {
        Value::Array(items) => items.clone(),
        _ => return Vec::new(),
    };
    let mut result: Vec<serde_json::Map<String, Value>> = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_names = std::collections::HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let raw = as_dict(item);
        let server_id = {
            let id = as_clean_str(raw.get("id").unwrap_or(&Value::Null), "");
            if id.is_empty() {
                format!("custom-{}", index + 1)
            } else {
                id
            }
        };
        let name = {
            let got = as_clean_str(raw.get("name").unwrap_or(&Value::Null), "");
            if got.is_empty() {
                "Свой DNS".to_string()
            } else {
                got
            }
        };
        let mut ipv4 = unique_ip_list(raw.get("ipv4").unwrap_or(&Value::Null));
        ipv4.retain(|ip| ip.contains('.'));
        let mut ipv6 = unique_ip_list(raw.get("ipv6").unwrap_or(&Value::Null));
        ipv6.retain(|ip| ip.contains(':'));
        if ipv4.is_empty() && ipv6.is_empty() {
            continue;
        }
        let mut doh = as_clean_str(raw.get("doh").unwrap_or(&Value::Null), "");
        if !doh.to_lowercase().starts_with("https://") || doh.chars().any(|c| c.is_whitespace()) {
            doh = String::new();
        }
        let id_key = server_id.to_lowercase();
        let name_key = name.to_lowercase();
        if seen_ids.contains(&id_key) || seen_names.contains(&name_key) {
            continue;
        }
        seen_ids.insert(id_key);
        seen_names.insert(name_key);
        let mut row = serde_json::Map::new();
        row.insert("id".to_string(), Value::String(server_id));
        row.insert("name".to_string(), Value::String(name));
        row.insert("ipv4".to_string(), json_vec(&ipv4));
        row.insert("ipv6".to_string(), json_vec(&ipv6));
        row.insert("doh".to_string(), Value::String(doh));
        result.push(row);
    }
    result
}

fn json_vec(parts: &[String]) -> Value {
    Value::Array(parts.iter().map(|s| Value::String(s.clone())).collect())
}

pub fn normalize_lookup_key(value: &Value) -> String {
    as_clean_str(value, "").to_lowercase()
}

/// askey оркестра только из ORCHESTRA_ASKEYS, иначе «tls».
pub fn normalize_askey(value: &Value) -> String {
    let normalized = as_clean_str(value, "").to_lowercase();
    if orchestra_askey_is_known(&normalized) {
        normalized
    } else {
        ORCHESTRA_ASK_EXAMPLE_DEFAULT.to_string()
    }
}

/// Утилиты тестам: списки строк/чисел как JSON-значения.
pub fn vec_json(parts: &[String]) -> Value {
    json_vec(parts)
}

pub fn vec_i_json(parts: &[i64]) -> Value {
    Value::Array(parts.iter().map(|n| Value::from(*n)).collect())
}
