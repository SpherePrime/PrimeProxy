//! Хелперы семантики python над значениями JSON.
//!
//! Python-код работает с «сырыми» значениями (`dict.get(...) or ...`,
//! `int(value)` с try/except, `bool(value)`). Здесь собраны эквиваленты для
//! `serde_json::Value`, чтобы порты модулей оставались дословными.
//!
//! Осознанные упрощения (не встречаются на нормализованных состояниях):
//! - `int()` от непарсируемой строки / массива / объекта → `None`
//!   (в python это исключение, перехватываемое `try/except`);
//! - `str()` от массива/объекта → `None` (в python это repr).

use serde_json::Value;

/// python `bool(value)` для значения JSON (отсутствие ключа = `False`):
/// ложны `null`, `false`, `0`, `""`, `[]`, `{}`.
#[must_use]
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(value @ Value::Number(_)) => {
            value.as_f64().map(|number| number != 0.0).unwrap_or(true)
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// python `int(value)`; `None` — как исключение в python.
#[must_use]
pub fn py_int(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Null => None,
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => number_as_int(number),
        Value::String(text) => int_from_str(text),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn number_as_int(number: &serde_json::Number) -> Option<i64> {
    if let Some(value) = number.as_i64() {
        return Some(value);
    }
    if let Some(value) = number.as_u64() {
        return i64::try_from(value).ok();
    }
    // python int(float) отсекает дробную часть к нулю.
    number.as_f64().map(|value| value.trunc() as i64)
}

/// python `int(str)`: необязательный знак, десятичные цифры, пробелы по
/// краям, подчёркивания между цифрами игнорируются (упрощённо, как в python
/// `int("1_0") == 10`).
fn int_from_str(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    let (sign, digits) = match trimmed.as_bytes().first() {
        Some(b'+') => (1, &trimmed[1..]),
        Some(b'-') => (-1, &trimmed[1..]),
        _ => (1, trimmed),
    };
    if digits.is_empty() {
        return None;
    }
    let cleaned: String = digits
        .chars()
        .filter(|character| *character != '_')
        .collect();
    if !cleaned.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    cleaned.parse::<i64>().ok().map(|value| sign * value)
}

/// python `str(value)` для скалярных значений JSON; для массивов/объектов
/// `None` (в python это repr, здесь такие значения не ожидаются).
#[must_use]
pub fn py_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Bool(true) => Some("True".to_string()),
        Value::Bool(false) => Some("False".to_string()),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Some(value.to_string())
            } else if let Some(value) = number.as_u64() {
                Some(value.to_string())
            } else {
                number.as_f64().map(python_float_string)
            }
        }
        Value::Array(_) | Value::Object(_) | Value::Null => None,
    }
}

fn python_float_string(value: f64) -> String {
    // python repr всегда показывает дробную точку: 5.0, 0.1.
    if value.fract() == 0.0 && value.is_finite() {
        format!("{value:.1}")
    } else {
        format!("{value}")
    }
}

/// python-связка `str(value or default)`: при «ложном» значении (см.
/// [`truthy`]) возвращается `default`, иначе строковое представление.
/// Для массивов/объектов (repr в python) возвращается `default`.
#[must_use]
pub fn string_or_falsy(value: Option<&Value>, default: &str) -> String {
    if truthy(value) {
        py_scalar_string(value.unwrap_or(&Value::Null)).unwrap_or_else(|| default.to_string())
    } else {
        default.to_string()
    }
}

/// python `int(obj.get(key, 0) or 0)`: ложное значение считается нулём,
/// непарсируемое — тоже нулём (в python было бы исключение).
#[must_use]
pub fn int_or_zero_field(object: &serde_json::Map<String, Value>, key: &str) -> i64 {
    let raw = object.get(key);
    let effective = if truthy(raw) {
        raw.unwrap_or(&Value::Null)
    } else {
        &Value::from(0)
    };
    py_int(Some(effective)).unwrap_or(0)
}

/// python `_as_int(value, default, minimum=..., maximum=...)` из
/// folders/store.py: `int(value)` с откатом на default и ограничениями.
#[must_use]
pub fn as_int(
    value: Option<&Value>,
    default: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> i64 {
    let mut result = py_int(value).unwrap_or(default);
    if let Some(minimum) = minimum {
        result = result.max(minimum);
    }
    if let Some(maximum) = maximum {
        result = result.min(maximum);
    }
    result
}

/// python `settings["section"]` как мутабельный объект с автосозданием:
/// гарантированно возвращает `&mut serde_json::Map` для секции состояния
/// (в python отсутствующая секция означала бы `KeyError`, здесь она
/// создаётся пустой — состояния всегда приходят нормализованными).
pub fn state_section_mut<'a>(
    state: &'a mut Value,
    key: &str,
) -> &'a mut serde_json::Map<String, Value> {
    loop {
        if let Value::Object(map) = state {
            let entry = map
                .entry(key.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            loop {
                match entry {
                    Value::Object(inner) => return inner,
                    _ => *entry = Value::Object(serde_json::Map::new()),
                }
            }
        }
        *state = Value::Object(serde_json::Map::new());
    }
}
