//! Золотые тесты против живого Python (utils/net_failure.py).
//!
//! §/errno-значения сняты на Linux-рантайме, как в tests/golden.json
//! (errno_values). Файлы: classify_code по кодам, winerror-таблица.

use std::sync::OnceLock;

use serde_json::Value;

use primecore_netfailure::{classify_code, classify_os_error, FAILURE_REFUSED, FAILURE_RESET, FAILURE_TIMEOUT, FAILURE_UNREACHABLE};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden.json")).unwrap())
}

#[test]
fn linux_errno_values_match_python_runtime() {
    let expected = golden()["errno_values"].as_object().unwrap();
    assert_eq!(expected["ETIMEDOUT"].as_i64().unwrap(), 110);
    assert_eq!(expected["ECONNREFUSED"].as_i64().unwrap(), 111);
    assert_eq!(expected["ECONNRESET"].as_i64().unwrap(), 104);
    assert_eq!(expected["ECONNABORTED"].as_i64().unwrap(), 103);
    assert_eq!(expected["EPIPE"].as_i64().unwrap(), 32);
    assert_eq!(expected["ENETDOWN"].as_i64().unwrap(), 100);
    assert_eq!(expected["ENETUNREACH"].as_i64().unwrap(), 101);
    assert_eq!(expected["EHOSTUNREACH"].as_i64().unwrap(), 113);
}

#[test]
fn winerror_table_matches_python() {
    let expected = golden()["winerror"].as_object().unwrap();
    let table = [
        (10060, "timeout"),
        (10061, "refused"),
        (10054, "reset"),
        (10053, "reset"),
        (10050, "unreachable"),
        (10051, "unreachable"),
        (10065, "unreachable"),
    ];
    for (code, failure) in table {
        assert_eq!(
            expected
                .get(&code.to_string())
                .and_then(Value::as_str),
            Some(failure),
            "winerror {code}"
        );
    }
}

#[test]
fn classify_code_matches_python() {
    for entry in golden()["classify_code"].as_array().unwrap() {
        let code = entry[0].as_i64().unwrap();
        let expected = entry[1].as_str().unwrap();
        assert_eq!(classify_code(code), expected, "classify_code({code})");
    }
}

#[test]
fn classify_os_error_matches_python_classes() {
    use std::io::Error;
    // python ConnectionRefusedError → refused
    assert_eq!(classify_os_error(&Error::from_raw_os_error(111)), FAILURE_REFUSED);
    // python ConnectionResetError → reset
    assert_eq!(classify_os_error(&Error::from_raw_os_error(104)), FAILURE_RESET);
    // python BrokenPipeError → reset
    assert_eq!(classify_os_error(&Error::from_raw_os_error(32)), FAILURE_RESET);
    // python TimeoutError (errno ETIMEDOUT) → timeout
    assert_eq!(classify_os_error(&Error::from_raw_os_error(110)), FAILURE_TIMEOUT);
    // unreachable
    assert_eq!(classify_os_error(&Error::from_raw_os_error(113)), FAILURE_UNREACHABLE);
    // Winsock-код без errno-эквивалента (linux): classify_code по таблице
    assert_eq!(classify_code(10060), FAILURE_TIMEOUT);
    assert_eq!(classify_code(10061), FAILURE_REFUSED);
    assert_eq!(classify_code(10054), FAILURE_RESET);
    // неизвестный код: python-функция отдаёт ""
    assert_eq!(classify_code(9999), "");
    assert_eq!(classify_code(0), "");
}
