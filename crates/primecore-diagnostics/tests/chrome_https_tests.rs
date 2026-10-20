//! Золотой тест классификации исхода HTTPS-запроса против python
//! (`chrome_https._classify`, `chrome_https._cert_problem`): каждый случай —
//! точные коды libcurl, вид сбоя системы и то, что успело прийти.

use std::collections::BTreeMap;
use std::time::Instant;

use primecore_diagnostics::chrome_https::{
    cert_problem, classify, Exchange, Progress, E_COULDNT_CONNECT, E_GOT_NOTHING, E_HTTP2,
    E_HTTP2_STREAM, E_PARTIAL_FILE, E_PEER_VERIFY, E_RECV, E_SEND, E_SSL_CERTPROBLEM,
    E_SSL_CONNECT, E_TIMEOUT, E_WRITE_ERROR,
};
use primecore_netfailure::{FAILURE_OTHER, FAILURE_RESET, FAILURE_TIMEOUT};
use primecore_socketcancel::SocketCancel;
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    classify: Vec<Case>,
    cert_problem: Vec<CertCase>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input: Input,
    expected: Expected,
}

#[derive(Deserialize)]
struct Input {
    error_code: i32,
    os_failure: String,
    message: String,
    progress: ProgressInput,
    stage: String,
}

#[derive(Deserialize)]
struct ProgressInput {
    status: Option<i64>,
    body_len: usize,
    cancelled: bool,
    stopped_by_us: bool,
    tls_started: bool,
    secured: bool,
}

#[derive(Deserialize)]
struct Expected {
    kind: String,
    detail: String,
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct CertCase {
    message: String,
    expected: String,
}

/// Вид сбоя системы из golden — в статические строки общего словаря.
fn os_failure_static(value: &str) -> &'static str {
    match value {
        "timeout" => FAILURE_TIMEOUT,
        "reset" => FAILURE_RESET,
        "refused" => primecore_netfailure::FAILURE_REFUSED,
        "other" => FAILURE_OTHER,
        "" => "",
        other => panic!("неизвестный вид сбоя в golden: {other}"),
    }
}

#[test]
fn classify_matches_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("chrome_https_golden.json")).expect("golden читается");
    for case in &golden.classify {
        let progress = Progress {
            status: case.input.progress.status,
            body: vec![0u8; case.input.progress.body_len],
            stopped_by_us: case.input.progress.stopped_by_us,
            cancelled: case.input.progress.cancelled,
            tls_started: case.input.progress.tls_started,
            secured: case.input.progress.secured,
            ..Progress::default()
        };
        let exchange = Exchange {
            progress,
            error_code: case.input.error_code,
            message: case.input.message.clone(),
            os_failure: os_failure_static(&case.input.os_failure),
            reconnected: false,
        };
        // Этап в golden выведен из тех же флагов, что и в Exchange::stage.
        assert_eq!(exchange.stage(), case.input.stage, "этап: {}", case.name);
        let result = classify(&exchange, &SocketCancel::new(), Instant::now(), "10.0.0.1");
        assert_eq!(result.kind, case.expected.kind, "вид исхода: {}", case.name);
        assert_eq!(result.detail, case.expected.detail, "деталь: {}", case.name);
        for (key, value) in &case.expected.extra {
            match key.as_str() {
                "body_cut" => assert_eq!(
                    result.body_cut,
                    value.as_bool().expect("body_cut — булево"),
                    "body_cut: {}",
                    case.name
                ),
                "cert_problem" => assert_eq!(
                    result.cert_problem,
                    value.as_str().expect("cert_problem — строка"),
                    "cert_problem: {}",
                    case.name
                ),
                "connect_fail" => assert_eq!(
                    result.connect_fail,
                    value.as_str().expect("connect_fail — строка"),
                    "connect_fail: {}",
                    case.name
                ),
                other => panic!("неизвестное поле extra в golden: {other}"),
            }
        }
        assert_eq!(
            result.status, case.input.progress.status,
            "статус: {}",
            case.name
        );
        assert_eq!(
            result.body_size, case.input.progress.body_len as u64,
            "размер тела: {}",
            case.name
        );
    }
    // Коды ошибок, на которых стоят случаи, — те же константы, что в python.
    assert_eq!(E_TIMEOUT, 28);
    assert_eq!(E_PEER_VERIFY, 60);
    assert_eq!(E_SSL_CERTPROBLEM, 58);
    assert_eq!(E_SSL_CONNECT, 35);
    assert_eq!(E_COULDNT_CONNECT, 7);
    assert_eq!(E_GOT_NOTHING, 52);
    assert_eq!(E_RECV, 56);
    assert_eq!(E_SEND, 55);
    assert_eq!(E_WRITE_ERROR, 23);
    assert_eq!(E_HTTP2, 16);
    assert_eq!(E_HTTP2_STREAM, 92);
    assert_eq!(E_PARTIAL_FILE, 18);
}

#[test]
fn cert_problem_matches_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("chrome_https_golden.json")).expect("golden читается");
    for case in &golden.cert_problem {
        assert_eq!(
            cert_problem(&case.message),
            case.expected,
            "причина: {}",
            case.message
        );
    }
}
