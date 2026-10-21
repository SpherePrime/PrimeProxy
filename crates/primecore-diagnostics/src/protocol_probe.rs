//! Порт `src/diagnostics/protocol_probe.py` — сайт по четырём дорогам отдельно:
//! «как Chrome», TLS 1.2, TLS 1.3 и обычный HTTP.
//!
//! Основная проверка сама открывает сайт как Chrome — это строка **«Как
//! Chrome»** (`chrome_line`), она берётся из её итога, отдельной пробы для неё
//! нет. Остальные дороги пробуются, только если сайт не открылся:
//! TLS 1.2, TLS 1.3 простым приветствием и HTTP порт 80.
//! Сбор (`collect`, `_timed_http`) — сетевая часть, портируется с TLS-пробами.
//! Здесь — чистая часть: строки и вывод `judge`.

use crate::block_cause::{
    stub_reason, HelloResult, HttpFacts, HELLO_ALERT, HELLO_CANCELLED, HELLO_CONNECT, HELLO_ERROR,
    HELLO_OK, HELLO_RESET, HELLO_TIMEOUT,
};
use crate::probe_result::{
    ProbeResult, KIND_CANCELLED, KIND_CERT, KIND_CONNECT, KIND_OK, KIND_RESET, KIND_TIMEOUT,
    KIND_TLS,
};

pub const PROTO_TLS12: &str = "tls12";
pub const PROTO_TLS13: &str = "tls13";
pub const PROTO_BROWSER: &str = "browser";
pub const PROTO_HTTP: &str = "http";

/// Простое приветствие проходит, а браузерное — нет: режут по «почерку» браузера.
pub const CODE_FINGERPRINT: &str = "fingerprint";
/// Слово строки «Как Chrome», когда соединение оборвали или заглушили.
pub const WORD_CUT: &str = "режется";

pub const STATE_OK: &str = "ok";
pub const STATE_FAIL: &str = "fail";
/// Не блокировка и не успех: сервер сам так устроен.
pub const STATE_INFO: &str = "info";
pub const STATE_UNKNOWN: &str = "unknown";

fn title_for(key: &str) -> &'static str {
    match key {
        PROTO_TLS12 => "TLS 1.2",
        PROTO_TLS13 => "TLS 1.3",
        PROTO_BROWSER => "Как Chrome",
        PROTO_HTTP => "HTTP",
        _ => "",
    }
}

/// python `ProtocolFacts`.
#[derive(Debug, Clone, Default)]
pub struct ProtocolFacts {
    pub host: String,
    pub ip: String,
    pub tls12: Option<HelloResult>,
    pub tls13: Option<HelloResult>,
    pub http: Option<HttpFacts>,
    /// За сколько ответил порт 80. None — не ответил.
    pub http_ms: Option<f64>,
    pub cancelled: bool,
}

/// python `ProtocolLine`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProtocolLine {
    pub key: String,
    pub title: String,
    pub state: String,
    /// Одно-два слова для метки на карточке: «работает», «сброс», «заглушка».
    pub word: String,
    /// Полная фраза для подробностей.
    pub text: String,
    pub ms: Option<f64>,
    /// Особый вывод строки (`CODE_FINGERPRINT`). Пусто — обычная строка.
    pub code: String,
}

fn ms(value: Option<f64>) -> String {
    match value {
        None => String::new(),
        Some(value) if value < 1.0 => "меньше 1 мс".to_string(),
        Some(value) => format!("{} мс", value.round() as i64),
    }
}

/// python `_tls_line(key, result)`.
pub fn tls_line(key: &str, result: Option<&HelloResult>) -> Option<ProtocolLine> {
    let title = title_for(key);
    let result = result?;
    if result.kind == HELLO_CANCELLED {
        return None;
    }
    let line = move |word: &str, text: &str, state: &str| ProtocolLine {
        key: key.to_string(),
        title: title.to_string(),
        state: state.to_string(),
        word: word.to_string(),
        text: text.to_string(),
        ms: result.ms,
        code: String::new(),
    };
    Some(match result.kind.as_str() {
        HELLO_OK => {
            ProtocolLine { text: format!("шифрование установилось за {}", ms(result.ms)), ..line("работает", "", STATE_OK) }
        }
        HELLO_ALERT => line(
            "нет у сервера",
            "сервер ответил отказом: этой версией он не работает — это не блокировка",
            STATE_INFO,
        ),
        HELLO_RESET => line(
            "сброс",
            "соединение оборвано сразу после приветствия — так фильтр рвёт соединения с этим сайтом",
            STATE_FAIL,
        ),
        HELLO_TIMEOUT => line(
            "молчит",
            "на приветствие никто не ответил — так фильтр молча глушит соединения с этим сайтом",
            STATE_FAIL,
        ),
        HELLO_CONNECT => line("нет соединения", "не удалось соединиться с адресом", STATE_UNKNOWN),
        HELLO_ERROR => line(
            "не проверено",
            "шифрование не установилось, причину определить не удалось",
            STATE_UNKNOWN,
        ),
        _ => line(
            "чужой ответ",
            "вместо шифрования пришло что-то другое: ответил не сервер",
            STATE_FAIL,
        ),
    })
}

/// python `chrome_line(result)` — строка «Как Chrome», итог основной проверки.
pub fn chrome_line(result: Option<&ProbeResult>) -> Option<ProtocolLine> {
    let title = title_for(PROTO_BROWSER);
    let result = result?;
    if result.kind == KIND_CANCELLED {
        return None;
    }
    if result.kind == KIND_CERT {
        return Some(ProtocolLine {
            key: PROTO_BROWSER.to_string(),
            title: title.to_string(),
            state: STATE_FAIL.to_string(),
            word: "чужой сертификат".to_string(),
            text: format!("сервер предъявил чужой сертификат: {}", result.cert_problem),
            ms: None,
            code: String::new(),
        });
    }
    if result.kind == KIND_OK || result.status.is_some() {
        return Some(ProtocolLine {
            key: PROTO_BROWSER.to_string(),
            title: title.to_string(),
            state: STATE_OK.to_string(),
            word: "проходит".to_string(),
            text: format!(
                "сайт отвечает так, как ответил бы Chrome, за {}",
                ms(Some(result.elapsed_ms))
            ),
            ms: Some(result.elapsed_ms),
            code: String::new(),
        });
    }
    if result.kind == KIND_CONNECT {
        return Some(ProtocolLine {
            key: PROTO_BROWSER.to_string(),
            title: title.to_string(),
            state: STATE_UNKNOWN.to_string(),
            word: "нет соединения".to_string(),
            text: "не удалось соединиться с адресом".to_string(),
            ms: None,
            code: String::new(),
        });
    }
    if result.kind == KIND_RESET || result.kind == KIND_TIMEOUT || result.kind == KIND_TLS {
        let how = match result.kind.as_str() {
            KIND_RESET => "соединение сбрасывают",
            KIND_TIMEOUT => "ответа нет",
            _ => "шифрование не устанавливается",
        };
        return Some(ProtocolLine {
            key: PROTO_BROWSER.to_string(),
            title: title.to_string(),
            state: STATE_FAIL.to_string(),
            word: WORD_CUT.to_string(),
            text: format!("на соединение, какое открывает Chrome, {how}"),
            ms: None,
            code: String::new(),
        });
    }
    Some(ProtocolLine {
        key: PROTO_BROWSER.to_string(),
        title: title.to_string(),
        state: STATE_UNKNOWN.to_string(),
        word: "не проверено".to_string(),
        text: "соединение не удалось, причину определить не удалось".to_string(),
        ms: None,
        code: String::new(),
    })
}

/// python `_fingerprint(chrome, facts)` — Chrome режут, а простое приветствие
/// к тому же адресу с тем же именем проходит — режут по «почерку».
fn fingerprint_line(chrome: &ProtocolLine, facts: &ProtocolFacts) -> ProtocolLine {
    let plain: Vec<&HelloResult> = facts.tls12.iter().chain(facts.tls13.iter()).collect();
    let plain_ok = plain.iter().any(|item| item.kind == HELLO_OK);
    if chrome.word != WORD_CUT || !plain_ok {
        return chrome.clone();
    }
    ProtocolLine {
        code: CODE_FINGERPRINT.to_string(),
        text: format!(
            "{}, а простое приветствие к тому же адресу с тем же именем проходит. Похоже на блокировку \
             по «почерку» браузера: фильтр узнаёт Chrome по первому пакету соединения, другие программы \
             к сайту пускает",
            chrome.text
        ),
        ..chrome.clone()
    }
}

/// python `_http_line(facts)`.
fn http_line(facts: &ProtocolFacts) -> Option<ProtocolLine> {
    let title = title_for(PROTO_HTTP);
    let http = facts.http.as_ref()?;
    if http.status.is_none() {
        // Порт 80 у многих сайтов закрыт самим сайтом.
        return Some(ProtocolLine {
            key: PROTO_HTTP.to_string(),
            title: title.to_string(),
            state: STATE_UNKNOWN.to_string(),
            word: "не ответил".to_string(),
            text: "порт 80 не ответил — у сайта он может быть закрыт".to_string(),
            ms: facts.http_ms,
            code: String::new(),
        });
    }
    let stub = stub_reason(&facts.host, facts.http.as_ref());
    if !stub.is_empty() {
        return Some(ProtocolLine {
            key: PROTO_HTTP.to_string(),
            title: title.to_string(),
            state: STATE_FAIL.to_string(),
            word: "заглушка".to_string(),
            text: format!("страница провайдера о блокировке: {stub}"),
            ms: facts.http_ms,
            code: String::new(),
        });
    }
    let status = http.status.unwrap();
    let took = ms(facts.http_ms);
    if (300..400).contains(&status) {
        return Some(ProtocolLine {
            key: PROTO_HTTP.to_string(),
            title: title.to_string(),
            state: STATE_OK.to_string(),
            word: "переход".to_string(),
            text: format!("сайт отвечает переходом (код {status}) за {took}"),
            ms: facts.http_ms,
            code: String::new(),
        });
    }
    Some(ProtocolLine {
        key: PROTO_HTTP.to_string(),
        title: title.to_string(),
        state: STATE_OK.to_string(),
        word: format!("код {status}"),
        text: format!("сайт отвечает, код {status}, за {took}"),
        ms: facts.http_ms,
        code: String::new(),
    })
}

/// python `_old_hello_only(line)` — TLS 1.2 режут, а TLS 1.3 к тому же сайту
/// проходит: объяснить, кому это мешает и что делать.
fn old_hello_only(line: &ProtocolLine) -> ProtocolLine {
    let how = if line.word == "молчит" {
        "молча глушит (ответа нет)"
    } else {
        "обрывает"
    };
    ProtocolLine {
        text: format!(
            "приветствие этой версии фильтр {how}, а TLS 1.3 к тому же сайту проходит. Браузеру это не мешает: он берёт \
             TLS 1.3. Мешает старым программам и телевизорам — им поможет другой пресет или «Подбор стратегии»",
        ),
        ..line.clone()
    }
}

/// python `judge(facts, chrome=None)` — строки по каждой дороге.
/// Без проб (сайт открылся или их сняли) остаётся одна строка «Как Chrome».
pub fn judge(facts: Option<&ProtocolFacts>, chrome: Option<&ProtocolLine>) -> Vec<ProtocolLine> {
    let Some(facts) = facts else {
        return chrome
            .map(|chrome| vec![chrome.clone()])
            .unwrap_or_default();
    };
    if facts.cancelled {
        return chrome
            .map(|chrome| vec![chrome.clone()])
            .unwrap_or_default();
    }
    let mut found: Vec<ProtocolLine> = [
        tls_line(PROTO_TLS12, facts.tls12.as_ref()),
        tls_line(PROTO_TLS13, facts.tls13.as_ref()),
        chrome.map(|chrome| fingerprint_line(chrome, facts)),
        http_line(facts),
    ]
    .into_iter()
    .flatten()
    .collect();
    let state_of = |key: &str| {
        found
            .iter()
            .find(|line| line.key == key)
            .map(|line| line.state.clone())
    };
    if state_of(PROTO_TLS12).as_deref() == Some(STATE_FAIL)
        && state_of(PROTO_TLS13).as_deref() == Some(STATE_OK)
    {
        for line in found.iter_mut() {
            if line.key == PROTO_TLS12 {
                *line = old_hello_only(line);
            }
        }
    }
    found
}

/// Что это за дорога — одной фразой для человека, который видит слово впервые.
pub fn hint(key: &str) -> &'static str {
    match key {
        PROTO_TLS12 => {
            "TLS 1.2 — прежняя версия шифрования. Так подключаются старые программы и устройства; браузеры почти всегда берут TLS 1.3."
        }
        PROTO_TLS13 => {
            "TLS 1.3 — нынешняя версия шифрования. Здесь её проверяют простым соединением, каким ходят программы, а не браузер."
        }
        PROTO_BROWSER => {
            "Основная проверка: сайт открывается так, как его открыл бы Chrome, — с тем же началом соединения. Эта строка ближе всего к тому, что вы увидите в браузере."
        }
        PROTO_HTTP => {
            "Обычное соединение без шифрования (порт 80). Сайты отвечают на него переходом на защищённый адрес — это норма."
        }
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Сбор проб по дорогам
// ---------------------------------------------------------------------------

use primecore_socketcancel::SocketCancel;
use std::sync::Arc;

use crate::run_context::{Run, TaskError};

/// python `_timed_http` — проба порта 80 с замером времени ответа.
pub fn timed_http(host: &str, ip: &str, cancel: &SocketCancel) -> (HttpFacts, Option<f64>) {
    let started = std::time::Instant::now();
    let facts =
        crate::block_cause::http_probe(host, ip, 80, crate::block_cause::HTTP_TIMEOUT_S, cancel);
    let ms = if facts.status.is_some() {
        Some(started.elapsed().as_secs_f64() * 1000.0)
    } else {
        None
    };
    (facts, ms)
}

/// python `protocol_probe.collect(host, ip, submit, cancel)` — три пробы к
/// адресу сайта, который не открылся: TLS 1.2, TLS 1.3 и HTTP. Два
/// шифрованных соединения с одним именем уходят не разом, а с шагом: пачка
/// одновременных соединений к одному сайту сама бывает поводом для фильтра
/// придержать их все.
pub fn collect(host: &str, ip: &str, run: &Arc<Run>) -> Result<ProtocolFacts, TaskError> {
    collect_with_port(host, ip, 443, run)
}

/// То же с заданным портом шифрованных проб (в тестах — локальный сервер).
pub fn collect_with_port(
    host: &str,
    ip: &str,
    port: u16,
    run: &Arc<Run>,
) -> Result<ProtocolFacts, TaskError> {
    let cancel = Arc::clone(&run.probe_cancel);
    let tls12 = run.submit({
        let ip = ip.to_string();
        let host = host.to_string();
        let cancel = Arc::clone(&cancel);
        move || {
            Ok(crate::block_cause::tls_hello(
                &ip,
                Some(&host),
                port,
                crate::block_cause::HELLO_TIMEOUT_S,
                &cancel,
                crate::block_cause::TLS_1_2,
            ))
        }
    });
    let tls13 = run.submit({
        let ip = ip.to_string();
        let host = host.to_string();
        let cancel = Arc::clone(&cancel);
        move || {
            cancel.sleep(crate::block_cause::STAGGER_S);
            Ok(crate::block_cause::tls_hello(
                &ip,
                Some(&host),
                port,
                crate::block_cause::HELLO_TIMEOUT_S,
                &cancel,
                crate::block_cause::TLS_1_3,
            ))
        }
    });
    let http = run.submit({
        let ip = ip.to_string();
        let host = host.to_string();
        let cancel = Arc::clone(&cancel);
        move || Ok(timed_http(&host, &ip, &cancel))
    });
    let tls12 = run.wait(&tls12)?;
    let tls13 = run.wait(&tls13)?;
    let (http_facts, http_ms) = run.wait(&http)?;
    Ok(ProtocolFacts {
        host: host.to_string(),
        ip: ip.to_string(),
        tls12: Some(tls12),
        tls13: Some(tls13),
        http: Some(http_facts),
        http_ms,
        cancelled: cancel.cancelled(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(kind: &str) -> Option<HelloResult> {
        Some(HelloResult::new(kind))
    }

    #[test]
    fn chrome_line_cases() {
        let mut ok = ProbeResult {
            kind: KIND_OK.to_string(),
            elapsed_ms: 42.7,
            ..Default::default()
        };
        ok.status = Some(200);
        assert_eq!(chrome_line(Some(&ok)).unwrap().word, "проходит");
        assert!(chrome_line(Some(&ok)).unwrap().text.contains("за 43 мс"));
        assert_eq!(
            chrome_line(Some(&probe_kind(KIND_CERT))).unwrap().word,
            "чужой сертификат"
        );
        assert_eq!(
            chrome_line(Some(&probe_kind(KIND_RESET))).unwrap().word,
            WORD_CUT
        );
        assert_eq!(
            chrome_line(Some(&probe_kind(KIND_CONNECT))).unwrap().state,
            STATE_UNKNOWN
        );
        assert_eq!(chrome_line(None), None);
    }

    fn probe_kind(kind: &str) -> ProbeResult {
        ProbeResult {
            kind: kind.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn fingerprint_and_old_tls12() {
        let mut facts = ProtocolFacts {
            host: "site.example".to_string(),
            ..Default::default()
        };
        facts.tls12 = hello(HELLO_OK);
        let chrome = chrome_line(Some(&probe_kind(KIND_RESET))).unwrap();
        let lines = judge(Some(&facts), Some(&chrome));
        let browser = lines.iter().find(|line| line.key == PROTO_BROWSER).unwrap();
        assert_eq!(browser.key, PROTO_BROWSER);
        assert_eq!(browser.word, WORD_CUT);
        assert_eq!(browser.code, CODE_FINGERPRINT);
        // TLS 1.2 режут, TLS 1.3 проходит: строка TLS 1.2 получает пояснение.
        facts.tls13 = hello(HELLO_OK);
        facts.tls12 = hello(HELLO_TIMEOUT);
        let lines = judge(Some(&facts), None);
        assert!(lines.iter().any(|line| line.key == PROTO_TLS12
            && line.text.contains("TLS 1.3 к тому же сайту проходит")));
    }

    #[test]
    fn http_line_variants() {
        let mut facts = ProtocolFacts {
            host: "site.example".to_string(),
            http_ms: Some(5.0),
            ..Default::default()
        };
        facts.http = Some(HttpFacts {
            status: None,
            ..Default::default()
        });
        assert_eq!(judge(Some(&facts), None)[0].word, "не ответил");
        facts.http = Some(HttpFacts {
            status: Some(302),
            location: "https://site.example/".to_string(),
            body: Vec::new(),
        });
        assert!(judge(Some(&facts), None)[0].word.starts_with("переход"));
        facts.http = Some(HttpFacts {
            status: Some(200),
            location: String::new(),
            body: Vec::new(),
        });
        assert_eq!(judge(Some(&facts), None)[0].word, "код 200");
    }

    #[test]
    fn hints_shape() {
        assert!(!hint(PROTO_BROWSER).is_empty());
        assert_eq!(hint("мимо"), "");
    }
}
