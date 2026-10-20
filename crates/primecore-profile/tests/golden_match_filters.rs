//! Золото match_filters.py: протоколы и порты.

use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::Value;

use primecore_profile::match_filters::{
    filter_values, is_http80_match, is_voice_match, l7_transport, ports_label_from_match_lines,
    protocol_label_from_match_lines, strategy_catalog_from_match_lines,
};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_match_filters.json"
    ))
    .expect("golden_match_filters.json");
    serde_json::from_str(&source).expect("json")
});

static CASES: Lazy<std::collections::HashMap<&'static str, Vec<String>>> = Lazy::new(|| {
    let mut cases: std::collections::HashMap<&'static str, Vec<String>> =
        std::collections::HashMap::new();
    for (name, lines) in [
        ("tcp_only", vec!["--filter-tcp=443"]),
        ("tcp_udp", vec!["--filter-tcp=443", "--filter-udp=123"]),
        ("l7_tcp", vec!["--filter-l7=http,tls"]),
        ("l7_udp_quic", vec!["--filter-l7=quic"]),
        ("l7_mixed", vec!["--filter-l7=http,quic"]),
        ("l7_empty", vec!["--filter-l7="]),
        ("voice_stun", vec!["--filter-l7=stun"]),
        (
            "voice_ports",
            vec!["--filter-l7=", "--filter-udp=50000-59000", "voice"],
        ),
        ("voice_no_ports", vec!["--filter-udp=100", "голос"]),
        ("http80", vec!["--filter-tcp=80"]),
        ("http80_plus", vec!["--filter-tcp=80,443"]),
        ("http80_range", vec!["--filter-tcp=80-81"]),
        ("http80_range_big", vec!["--filter-tcp=80-10000"]),
        ("http80_udp", vec!["--filter-tcp=80", "--filter-udp=443"]),
        ("http80_quic", vec!["--filter-tcp=80", "--filter-l7=quic"]),
        (
            "ports_mixed",
            vec!["--filter-tcp=443,80-81,x", "--filter-udp=50000-59001"],
        ),
        ("ports_bad", vec!["--filter-tcp=-,  ", "--filter-udp=..-3"]),
        ("tcp_range_swap", vec!["--filter-tcp=81-80"]),
        ("voice_discord_udp", vec!["--filter-udp=51000", "Discord"]),
        ("voice_only_ports", vec!["--filter-udp=51000"]),
        ("empty", vec![]),
        ("neg_number", vec!["--filter-tcp=-1"]),
    ] {
        cases.insert(
            name,
            lines.into_iter().map(|line| line.to_string()).collect(),
        );
    }
    cases
});

fn as_value(value: &impl Serialize) -> Value {
    serde_json::to_value(value).expect("сериализация")
}

#[test]
fn labels_and_catalog_match_python() {
    for (name, expected) in GOLDEN["ops"]["catalog"].as_object().expect("каталог") {
        let lines = &CASES[name.as_str()];
        assert_eq!(
            expected,
            &as_value(&strategy_catalog_from_match_lines(lines)),
            "каталог {name}"
        );
    }
    for (name, expected) in GOLDEN["ops"]["protocol_label"].as_object().expect("метки") {
        let lines = &CASES[name.as_str()];
        assert_eq!(
            expected,
            &as_value(&protocol_label_from_match_lines(lines)),
            "протокол {name}"
        );
    }
    for (name, expected) in GOLDEN["ops"]["ports_label"].as_object().expect("порты") {
        let lines = &CASES[name.as_str()];
        assert_eq!(
            expected,
            &as_value(&ports_label_from_match_lines(lines)),
            "порты {name}"
        );
    }
}

#[test]
fn filter_values_and_matches_match_python() {
    for (name, expected) in GOLDEN["ops"]["filter_values"]
        .as_object()
        .expect("значения")
    {
        let lines = &CASES[name.as_str()];
        assert_eq!(
            as_value(&filter_values(lines, "--filter-tcp")),
            expected["tcp"],
            "tcp значения {name}"
        );
        assert_eq!(
            as_value(&filter_values(lines, "--filter-udp")),
            expected["udp"],
            "udp значения {name}"
        );
        assert_eq!(
            as_value(&filter_values(lines, "--filter-l7")),
            expected["l7"],
            "l7 значения {name}"
        );
    }
    for (name, expected) in GOLDEN["ops"]["is_voice"].as_object().expect("voice") {
        let lines = &CASES[name.as_str()];
        assert_eq!(expected, &as_value(&is_voice_match(lines)), "voice {name}");
    }
    for (name, expected) in GOLDEN["ops"]["is_http80"].as_object().expect("http80") {
        let lines = &CASES[name.as_str()];
        assert_eq!(
            expected,
            &as_value(&is_http80_match(lines)),
            "http80 {name}"
        );
    }
}

#[test]
fn l7_transport_matches_python() {
    let expected = GOLDEN["ops"]["l7_transport"].as_array().expect("список");
    for entry in expected {
        let pair = entry.as_array().expect("пара");
        let values: Vec<String> = pair[0]
            .as_array()
            .expect("массив значений")
            .iter()
            .map(|value| value.as_str().expect("строка").to_string())
            .collect();
        assert_eq!(
            pair[1]
                .as_str()
                .map(|value| value.to_string())
                .unwrap_or_default(),
            l7_transport(&values).unwrap_or(""),
            "транспорт {values:?}"
        );
        // None и пустая строка в золоте различаются.
        assert_eq!(
            pair[1].is_null(),
            l7_transport(&values).is_none(),
            "None_transport"
        );
    }
}
