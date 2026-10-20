//! Золото conditions_text.py: условия профиля словами.

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use primecore_profile::conditions_text::{conditions_summary, range_hint, range_phrase};
use primecore_profile::derived_cache::profile_match_summary;
use primecore_profile::editable_settings::read_editable_profile_settings;
use primecore_profile::parser::parse_preset_text;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_conditions_text.json"
    ))
    .expect("golden_conditions_text.json");
    serde_json::from_str(&source).expect("json")
});

const PRESET_TEXT: &str = concat!(
    "--new=Сводка\n",
    "--filter-tcp=443\n",
    "--hostlist=gov.ru.txt\n",
    "--lua-desync=multisplit\n",
);
const UDP_PRESET_TEXT: &str = concat!(
    "--new=Голос UDP\n",
    "--filter-udp=50000\n",
    "--lua-desync=fake:blob=fake_default_quic\n",
);
const PLAIN_PRESET_TEXT: &str = "--new=Без условий\n--lua-desync=multisplit\n";
const HTTP_PRESET_TEXT: &str = concat!(
    "--new=HTTP\n",
    "--filter-tcp=80\n",
    "--hostlist-domains=mayak.su\n",
    "--in-range=a\n",
    "--out-range=x\n",
    "--lua-desync=multidisorder\n",
);

#[test]
fn conditions_match_python() {
    let range_phrases = [
        "",
        "  ",
        "a",
        "A",
        "x",
        "-d8",
        "-D1",
        "-n3",
        "-n21",
        "-d11",
        "-d12",
        "-n22",
        "-nxx",
        "s1<d1",
        "-d",
        "-n",
        "-d0",
        "-n1000000",
    ];
    let mut rp = serde_json::Map::new();
    for value in range_phrases {
        rp.insert(value.to_string(), json!(range_phrase(value)));
    }
    let mut computed = json!({ "range_phrase": Value::Object(rp) });

    let hints = [
        ("", ""),
        ("a", ""),
        ("n", "8"),
        ("d", "8"),
        ("n", ""),
        ("d", ""),
        ("n", "abc"),
        ("d", "-3"),
        ("custom", ""),
        ("unknown", "5"),
        ("  D  ", " 12 "),
    ];
    let mut hint_map = serde_json::Map::new();
    for (mode, value) in hints {
        hint_map.insert(format!("{mode}|{value}"), json!(range_hint(mode, value)));
    }
    computed["range_hint"] = Value::Object(hint_map);

    // Сводка из параметров, как её передаёт сервис.
    let mut scenarios: Vec<Value> = Vec::new();
    for (name, text) in [
        ("tcp", PRESET_TEXT),
        ("udp", UDP_PRESET_TEXT),
        ("plain", PLAIN_PRESET_TEXT),
        ("http", HTTP_PRESET_TEXT),
    ] {
        let profile = &parse_preset_text(text, "winws2", name)
            .expect("профиль")
            .profiles[0];
        let settings = read_editable_profile_settings(profile);
        let match_lines = profile.match_section().all_lines();
        scenarios.push(json!({
            "match_lines": match_lines,
            "match_summary": profile_match_summary(profile, None),
            "filter_value": settings.filter_value,
            "in_range": settings.in_range,
            "out_range": settings.out_range,
        }));
    }
    computed["scenarios"] = json!(scenarios.clone());

    let mut summaries = Vec::new();
    for scenario in scenarios {
        let match_lines: Vec<String> = scenario["match_lines"]
            .as_array()
            .expect("строки")
            .iter()
            .map(|line| line.as_str().expect("строка").to_string())
            .collect();
        let summary = conditions_summary(
            &match_lines,
            scenario["match_summary"].as_str().unwrap_or(""),
            scenario["filter_value"].as_str().unwrap_or(""),
            scenario["in_range"].as_str().unwrap_or(""),
            scenario["out_range"].as_str().unwrap_or(""),
        );
        summaries.push(json!(summary));
    }
    computed["conditions_summary"] = json!(summaries);

    assert_eq!(computed, GOLDEN.clone(), "условия профиля словами");
}
