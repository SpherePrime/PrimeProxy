//! Золотые тесты против живого Python (src/settings/normalize.py):
//! численные пары «вход → выход» сняты моментом из эталонной среды,
//! XLbounds-спека повторяется константами в тесте.

use std::sync::OnceLock;

use primecore_settings as s;
use serde_json::Value;

fn golden() -> &'static serde_json::Value {
    static GOLDEN: OnceLock<serde_json::Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        serde_json::from_slice(include_bytes!("golden.json")).expect("золотой json")
    })
}

fn pairs(key: &str) -> &Vec<Value> {
    golden()[key].as_array().unwrap()
}

#[test]
fn as_bool_matches_python() {
    for pair in pairs("as_bool") {
        let actual = s::as_bool(&pair[0], true);
        assert_eq!(actual, pair[1].as_bool().unwrap(), "as_bool({pair})");
    }
}

#[test]
fn as_int_matches_python() {
    for pair in pairs("as_int") {
        let actual = s::as_int(&pair[0], pair[1].as_i64().unwrap(), None, None);
        assert_eq!(actual, pair[2].as_i64().unwrap(), "as_int(x, default)");
    }
}

#[test]
fn as_int_bounded_matches_python() {
    for quint in pairs("as_int_bounded") {
        let actual = s::as_int(
            &quint[0],
            quint[1].as_i64().unwrap(),
            Some(quint[2].as_i64().unwrap()),
            Some(quint[3].as_i64().unwrap()),
        );
        assert_eq!(actual, quint[4].as_i64().unwrap(), "as_int_bounded");
    }
}

#[test]
fn as_nullable_int_matches_python() {
    for pair in pairs("as_nullable_int") {
        let actual = match s::as_nullable_int(&pair[0]) {
            Some(number) => number.to_string(),
            None => "null".to_string(),
        };
        assert_eq!(actual, pair[1].to_string(), "as_nullable_int({pair})");
    }
}

#[test]
fn as_str_and_clean_match_python() {
    for pair in pairs("as_str") {
        assert_eq!(
            s::as_str(&pair[0], "zzz"),
            pair[1].as_str().unwrap(),
            "as_str"
        );
    }
    for pair in pairs("as_clean_str") {
        assert_eq!(
            s::as_clean_str(&pair[0], "d"),
            pair[1].as_str().unwrap(),
            "as_clean_str"
        );
    }
}

#[test]
fn as_str_in_matches_python() {
    // Спека дефолтов как в генераторе золотой пары: d1..d4 по порядку.
    let defaults = ["d1", "d2", "d3", "d4"];
    for (index, triple) in pairs("as_str_in").iter().enumerate() {
        let allowed: Vec<&str> = triple[1]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            s::as_str_in(&triple[0], &allowed, defaults[index]),
            triple[2].as_str().unwrap(),
            "as_str_in({triple})"
        );
    }
}

#[test]
fn hex_and_domain_match_python() {
    for pair in pairs("normalize_hex_secret") {
        assert_eq!(s::normalize_hex_secret(&pair[0]), pair[1].as_str().unwrap());
    }
    for pair in pairs("normalize_domain") {
        assert_eq!(s::normalize_domain(&pair[0]), pair[1].as_str().unwrap());
    }
}

#[test]
fn lists_match_python() {
    let sections = [
        "unique_str_list",
        "unique_domain_list",
        "unique_dc_ip_list",
        "unique_int_list",
        "unique_ip_list",
    ];
    for section in sections {
        for pair in pairs(section) {
            let actual = match section {
                "unique_str_list" => s::vec_json(&s::unique_str_list(&pair[0])),
                "unique_domain_list" => s::vec_json(&s::unique_domain_list(&pair[0])),
                "unique_dc_ip_list" => s::vec_json(&s::unique_dc_ip_list(&pair[0])),
                "unique_int_list" => s::vec_i_json(&s::unique_int_list(&pair[0])),
                "unique_ip_list" => s::vec_json(&s::unique_ip_list(&pair[0])),
                _ => unreachable!(),
            };
            assert_eq!(actual, pair[1], "{section}");
        }
    }
}

#[test]
fn custom_dns_servers_match_python() {
    for pair in pairs("normalize_custom_dns_servers") {
        let actual = s::normalize_custom_dns_servers(&pair[0]);
        let actual_json = Value::Array(actual.into_iter().map(Value::Object).collect());
        assert_eq!(actual_json, pair[1], "custom dns");
    }
}

#[test]
fn lookup_and_askey_match_python() {
    let askeys = s::schema::ORCHESTRA_ASKEYS;
    assert!(askeys.contains(&"quic"));
    for triple in pairs("lookup_askey") {
        assert_eq!(
            s::normalize_lookup_key(&triple[0]),
            triple[1].as_str().unwrap()
        );
        assert_eq!(s::normalize_askey(&triple[0]), triple[2].as_str().unwrap());
    }
}
