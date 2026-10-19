//! Золото winws2_transport.py: диапазоны пакетов.

use once_cell::sync::Lazy;
use serde_json::Value;

use primecore_profile::winws2_transport::{
    normalize_out_range_expression, parse_out_range_expression, validate_winws2_payload_filter,
};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_winws2_transport.json"
    ))
    .expect("golden_winws2_transport.json");
    serde_json::from_str(&source).expect("json")
});

#[test]
fn parse_matches_python() {
    for row in GOLDEN["ops"]["parse"].as_array().expect("строки") {
        let pair = row.as_array().expect("пара");
        let value = pair[0].as_str().expect("значение");
        let raw_line = format!("--out-range={value}");
        let computed = parse_out_range_expression(value, &raw_line);
        if pair[1].is_null() {
            assert!(
                computed.is_none(),
                "{value}: питон вернул None, расчёт — {computed:?}"
            );
            continue;
        }
        let settings = computed.unwrap_or_else(|| panic!("{value}: расчёт None"));
        assert_eq!(
            serde_json::to_value(&settings).expect("json"),
            pair[1],
            "разбор {value}"
        );
    }
}

#[test]
fn normalize_matches_python() {
    for row in GOLDEN["ops"]["normalize"].as_array().expect("строки") {
        let pair = row.as_array().expect("пара");
        let value = pair[0].as_str().expect("значение");
        assert_eq!(pair[1].as_str().expect("нормализованное"), normalize_out_range_expression(value), "нормализация {value}");
    }
}

#[test]
fn payload_filter_matches_python() {
    for row in GOLDEN["ops"]["payload"].as_array().expect("строки") {
        let pair = row.as_array().expect("пара");
        let value = pair[0].as_str().expect("значение");
        assert_eq!(
            pair[1].as_bool().expect("булево"),
            validate_winws2_payload_filter(value),
            "payload {value}"
        );
    }
}
