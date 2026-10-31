//! Золотые тесты против живого Python (utils/net_failure.py).
//!
//! §/errno-значения сняты на Linux-рантайме, как в tests/golden.json
//! (errno_values). Файлы: classify_code по кодам, winerror-таблица.

use std::sync::OnceLock;

use serde_json::Value;

use primecore_netfailure::{
    classify_code, classify_os_error, FAILURE_REFUSED, FAILURE_RESET, FAILURE_TIMEOUT,
    FAILURE_UNREACHABLE,
};

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
            expected.get(&code.to_string()).and_then(Value::as_str),
            Some(failure),
            "winerror {code}"
        );
    }
}

/// Коды из golden-списка, снятые на Linux-рантайме (`errno_values`): на
/// Windows сетевые виды приходят кодами Winsock, и эти числа там ничего не
/// значат.
fn is_linux_errno_code(code: i64) -> bool {
    matches!(code, 110 | 111 | 104 | 103 | 32 | 100 | 101 | 113)
}

#[test]
fn classify_code_matches_python() {
    for entry in golden()["classify_code"].as_array().unwrap() {
        let code = entry[0].as_i64().unwrap();
        let expected = entry[1].as_str().unwrap();
        // Список снят на Linux-рантайме и смешивает коды Winsock (одинаковые
        // на всех системах) с errno-значениями Linux. На Windows errno-таблица
        // пуста — сетевые виды там приходят кодами Winsock, — поэтому
        // errno-часть списка проверяется только на Linux (см. тест
        // `linux_errno_codes_are_unknown_on_windows`).
        if !cfg!(target_os = "linux") && is_linux_errno_code(code) {
            continue;
        }
        assert_eq!(classify_code(code), expected, "classify_code({code})");
    }
}

/// На Windows сетевые виды приходят кодами Winsock (таблица `winerror`),
/// а linux-errno в этой системе ничего не значит: «код ни о чём».
#[cfg(target_family = "windows")]
#[test]
fn linux_errno_codes_are_unknown_on_windows() {
    for code in [110, 111, 104, 103, 32, 100, 101, 113] {
        assert_eq!(classify_code(code), "", "classify_code({code})");
    }
}

#[test]
fn classify_os_error_matches_python_classes() {
    use std::io::{Error, ErrorKind};
    // Классы исключений python → те же виды сбоя. Ошибка без кода системы
    // (`Error::new`) разбирается по классу одинаково на всех платформах.
    assert_eq!(
        classify_os_error(&Error::new(ErrorKind::ConnectionRefused, "проба")),
        FAILURE_REFUSED
    );
    assert_eq!(
        classify_os_error(&Error::new(ErrorKind::ConnectionReset, "проба")),
        FAILURE_RESET
    );
    assert_eq!(
        classify_os_error(&Error::new(ErrorKind::BrokenPipe, "проба")),
        FAILURE_RESET
    );
    assert_eq!(
        classify_os_error(&Error::new(ErrorKind::TimedOut, "проба")),
        FAILURE_TIMEOUT
    );

    // Коды системы: на Linux это errno (значения сняты с Linux-рантайма).
    #[cfg(target_os = "linux")]
    {
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(111)),
            FAILURE_REFUSED
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(104)),
            FAILURE_RESET
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(32)),
            FAILURE_RESET
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(110)),
            FAILURE_TIMEOUT
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(113)),
            FAILURE_UNREACHABLE
        );
    }

    // На macOS те же виды, но свои номера errno (таблица крейта).
    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(61)),
            FAILURE_REFUSED
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(54)),
            FAILURE_RESET
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(60)),
            FAILURE_TIMEOUT
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(65)),
            FAILURE_UNREACHABLE
        );
    }

    // На Windows коды системы — это коды Winsock.
    #[cfg(target_family = "windows")]
    {
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(10061)),
            FAILURE_REFUSED
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(10054)),
            FAILURE_RESET
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(10053)),
            FAILURE_RESET
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(10060)),
            FAILURE_TIMEOUT
        );
        assert_eq!(
            classify_os_error(&Error::from_raw_os_error(10065)),
            FAILURE_UNREACHABLE
        );
    }

    // Winsock-коды разбираются одинаково на всех системах: таблица WINERROR
    // от платформы не зависит.
    assert_eq!(classify_code(10060), FAILURE_TIMEOUT);
    assert_eq!(classify_code(10061), FAILURE_REFUSED);
    assert_eq!(classify_code(10054), FAILURE_RESET);
    // неизвестный код: python-функция отдаёт ""
    assert_eq!(classify_code(9999), "");
    assert_eq!(classify_code(0), "");
}
