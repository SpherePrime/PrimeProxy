//! Золотые тесты DNS-кодека против живого Python (utils/dns_wire.py).

use std::sync::OnceLock;

use serde_json::{json, Value};

use primecore_dnswire::{
    answered_result, build_query, encode_name, parse_response, reverse_name, DnsMessage,
    DnsQueryResult,
};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden.json")).unwrap())
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn encode_err(call: impl FnOnce() -> Result<Vec<u8>, String>) -> Value {
    match call() {
        Ok(bytes) => json!({"ok": true, "value": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

#[test]
fn encode_name_matches_python() {
    for entry in golden()["encode_name"].as_array().unwrap() {
        let actual = encode_err(|| encode_name(entry[0].as_str().unwrap()));
        assert_eq!(actual, entry[1], "encode_name({:?})", entry[0]);
    }
}

#[test]
fn build_query_matches_python() {
    for entry in golden()["build_query"].as_array().unwrap() {
        let expect_id = entry[0].as_u64().unwrap() as u16;
        let actual =
            encode_err(|| build_query(expect_id, entry[1].as_str().unwrap(), entry[2].as_u64().unwrap() as u16));
        assert_eq!(actual, entry[3], "build_query({expect_id}, {:?})", entry[1]);
    }
}

#[test]
fn reverse_name_matches_python() {
    for entry in golden()["reverse_name"].as_array().unwrap() {
        let actual = match reverse_name(entry[0].as_str().unwrap()) {
            Ok(value) => json!({"ok": true, "value": value}),
            Err(error) => json!({"ok": false, "error": error}),
        };
        assert_eq!(actual, entry[1], "reverse_name({})", entry[0]);
    }
}

#[test]
fn parse_response_matches_python() {
    for entry in golden()["parse_response"].as_array().unwrap() {
        let packet = hex_to_bytes(entry["packet"].as_str().unwrap());
        let parsed = parse_response(&packet);
        match entry.get("error") {
            Some(expected_error) => {
                let error = parsed.err().expect("python выдал DnsWireError");
                assert_eq!(error, expected_error.as_str().unwrap(), "{}", entry["name"]);
            }
            None => {
                let expected = entry.get("message").expect("python разобрал пакет");
                let message = parsed.expect("разбор должен пройти");
                assert_eq!(message.query_id, expected["query_id"].as_u64().unwrap() as u16, "{}", entry["name"]);
                assert_eq!(message.is_response, expected["is_response"].as_bool().unwrap());
                assert_eq!(message.truncated, expected["truncated"].as_bool().unwrap());
                assert_eq!(message.rcode, expected["rcode"].as_u64().unwrap() as u16);
                assert_eq!(message.question, expected["question"].as_str().unwrap());
                assert_eq!(message.authoritative, expected["authoritative"].as_bool().unwrap());
                assert_eq!(message.authority_count, expected["authority_count"].as_u64().unwrap() as u16);
                let answers = &message.answers;
                assert_eq!(answers.len(), expected["answers"].as_array().unwrap().len());
                for (record, expected_record) in answers.iter().zip(expected["answers"].as_array().unwrap()) {
                    assert_eq!(record.name, expected_record["name"].as_str().unwrap());
                    assert_eq!(record.rtype, expected_record["rtype"].as_u64().unwrap() as u16);
                    assert_eq!(record.ttl, expected_record["ttl"].as_u64().unwrap() as u32);
                    assert_eq!(record.value, expected_record["value"].as_str().unwrap());
                }
            }
        }
    }
}

/// Спека «cases» из генератора золота: ключ набора → поля DnsQueryResult.
fn case_by_key(key: &str) -> DnsQueryResult {
    let mut result = DnsQueryResult::default();
    match key {
        "ok" => {
            result.status = "ok".into();
            result.rcode = Some(0);
            result.transport = "udp".into();
        }
        "empty" => {
            result.status = "empty".into();
            result.rcode = Some(0);
            result.transport = "udp".into();
        }
        "nxdomain_forged" => {
            result.status = "nxdomain".into();
            result.rcode = Some(3);
            result.transport = "udp".into();
            result.authoritative = true;
        }
        "nxdomain_honest" => {
            result.status = "nxdomain".into();
            result.rcode = Some(3);
            result.transport = "udp".into();
            result.authoritative = true;
            result.authority_count = 1;
        }
        "nxdomain_notauthoritative" => {
            result.status = "nxdomain".into();
            result.rcode = Some(3);
            result.transport = "udp".into();
        }
        "timeout" => {
            result.status = "timeout".into();
            result.transport = "udp".into();
            result.failure = "timeout".into();
        }
        "refused_port" => {
            result.status = "error".into();
            result.transport = "udp".into();
            result.failure = "refused".into();
            result.detail = "time out".into();
        }
        "reset" => {
            result.status = "error".into();
            result.transport = "tcp".into();
            result.failure = "reset".into();
        }
        "closed" => {
            result.status = "error".into();
            result.transport = "dot".into();
            result.failure = "closed".into();
        }
        "unreachable" => {
            result.status = "error".into();
            result.transport = "udp".into();
            result.failure = "unreachable".into();
        }
        "tls" => {
            result.status = "error".into();
            result.transport = "dot".into();
            result.failure = "tls".into();
        }
        "cert" => {
            result.status = "error".into();
            result.transport = "dot".into();
            result.failure = "cert".into();
        }
        "cancelled" => {
            result.status = "error".into();
            result.transport = "udp".into();
            result.failure = "cancelled".into();
        }
        "malformed" => {
            result.status = "error".into();
            result.transport = "doh".into();
            result.failure = "malformed".into();
        }
        "http_451" => {
            result.status = "error".into();
            result.transport = "doh".into();
            result.failure = "http".into();
            result.detail = "HTTP 451".into();
        }
        "http_empty" => {
            result.status = "error".into();
            result.transport = "doh".into();
            result.failure = "http".into();
        }
        "other" => {
            result.status = "error".into();
            result.transport = "udp".into();
            result.failure = "other".into();
            result.detail = "bad server".into();
        }
        unknown => panic!("неизвестный ключ случая: {unknown}"),
    }
    result
}

#[test]
fn failure_text_matches_python() {
    for entry in golden()["failure_text"].as_array().unwrap() {
        let key = entry[0].as_str().unwrap();
        let actual = case_by_key(key).failure_text();
        assert_eq!(actual, entry[1].as_str().unwrap(), "failure_text({key})");
    }
}

#[test]
fn forged_denial_matches_python() {
    for entry in golden()["forged_denial"].as_array().unwrap() {
        let key = entry[0].as_str().unwrap();
        assert_eq!(case_by_key(key).forged_denial(), entry[1].as_bool().unwrap(), "forged_denial({key})");
    }
}

#[test]
fn answered_matches_python() {
    for entry in golden()["answered"].as_array().unwrap() {
        let key = entry[0].as_str().unwrap();
        assert_eq!(case_by_key(key).answered(), entry[1].as_bool().unwrap(), "answered({key})");
    }
}

#[test]
fn values_matches_python() {
    use primecore_dnswire::{TYPE_A, TYPE_AAAA, TYPE_TXT};
    let records = vec![
        primecore_dnswire::DnsRecord {
            name: "example.com".into(),
            rtype: TYPE_A,
            ttl: 1,
            value: "1.2.3.4".into(),
        },
        primecore_dnswire::DnsRecord {
            name: "example.com".into(),
            rtype: TYPE_A,
            ttl: 2,
            value: "1.2.3.4".into(),
        },
        primecore_dnswire::DnsRecord {
            name: "example.com".into(),
            rtype: TYPE_AAAA,
            ttl: 3,
            value: "::1".into(),
        },
        primecore_dnswire::DnsRecord {
            name: "example.com".into(),
            rtype: TYPE_TXT,
            ttl: 4,
            value: "x".into(),
        },
    ];
    let result = DnsQueryResult {
        status: "ok".into(),
        rcode: Some(0),
        records,
        ..DnsQueryResult::default()
    };
    assert_eq!(result.values(TYPE_A), vec!["1.2.3.4".to_string()]);
    assert_eq!(result.values(TYPE_AAAA), vec!["::1".to_string()]);
    assert!(result.values(5).is_empty());
}

#[test]
fn answered_result_status_logic() {
    let find_packet = |name: &str| -> String {
        golden()["parse_response"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"].as_str().unwrap() == name)
            .unwrap()["packet"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // простой ответ: статус ok, нет подмены
    let message = parse_response(&hex_to_bytes(&find_packet("simple_a"))).unwrap();
    let result = answered_result("udp", message, 3.5);
    assert_eq!(result.status, "ok");
    assert!(result.answered());
    assert!(!result.forged_denial());
    assert_eq!(result.detail, "");
    // честный NXDOMAIN с SOA: не подмена
    let message = parse_response(&hex_to_bytes(&find_packet("honest_nosuch"))).unwrap();
    let result = answered_result("udp", message, 1.0);
    assert_eq!(result.status, "nxdomain");
    assert!(!result.forged_denial());
    // подставной NXDOMAIN: AA есть, SOA нет
    let message = parse_response(&hex_to_bytes(&find_packet("forged_nosuch"))).unwrap();
    let result = answered_result("udp", message, 1.0);
    assert_eq!(result.status, "nxdomain");
    assert!(result.forged_denial());
    // SERVFAIL → refused-статус (python _status_for)
    let message = parse_response(&hex_to_bytes(&find_packet("servfail"))).unwrap();
    let result = answered_result("udp", message, 1.0);
    assert_eq!(result.status, "refused");
    assert_eq!(result.detail, "rcode 2");
    // TC-флаг доходит до truncated
    let message = parse_response(&hex_to_bytes(&find_packet("truncated"))).unwrap();
    let result = answered_result("udp", message, 1.0);
    assert!(result.truncated);
}
