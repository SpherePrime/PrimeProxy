//! Золотые тесты собраны с живого Python (normalize_settings) на данных:
//! - `default` / `canonical` — schema.build_default_settings и его результат;
//! - `noisy_in` / `noisy_out` — мусорные значения во всех секциях;
//! - `garbage_in` / `garbage_out` — совсем испорченные секции;
//! - `empty_out` — {} (все секции по умолчанию).

use std::sync::OnceLock;

use serde_json::Value;

use primecore_settings::app_settings::normalize_settings;
use primecore_settings::schema::{build_default_settings, SETTINGS_VERSION};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        serde_json::from_slice(include_bytes!("golden_settings.json")).expect("золотой json")
    })
}

fn expect_section(out: &Value, expected: &Value, context: &str) {
    let walk = |path: &str| (out.pointer(path), expected.pointer(path));
    assert!(
        out == expected,
        "{context}: результат не совпал; пересечение начинается со списка ниже"
    );
    let _ = walk("");
}

#[test]
fn canonical_defaults_match_python() {
    let built = build_default_settings();
    assert_eq!(golden()["canonical"], normalize_settings(&built), "canonical");
    // Дефолты сами должны совпасть — питоновская build_default_settings.
    assert_eq!(&golden()["default"], &built, "schema default");
    assert_eq!(SETTINGS_VERSION, golden()["schema_version"].as_i64().unwrap());
}

#[test]
fn noisy_sections_match_python() {
    let out = normalize_settings(&golden()["noisy_in"]);
    let expected = &golden()["noisy_out"];
    expect_section(&out, expected, "noisy");
}

#[test]
fn garbage_matches_python() {
    let out = normalize_settings(&golden()["garbage_in"]);
    expect_section(&out, &golden()["garbage_out"], "garbage");
}

#[test]
fn empty_matches_python() {
    let out = normalize_settings(&Value::Object(serde_json::Map::new()));
    expect_section(&out, &golden()["empty_out"], "empty");
}
