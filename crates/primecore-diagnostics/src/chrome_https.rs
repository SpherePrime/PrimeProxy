//! Порт `src/utils/chrome_https.py` — запрос «как Chrome»: настоящее
//! рукопожатие и HTTP/2 браузера, те же заголовки, та же классификация исхода.
//!
//! Зачем: фильтр провайдера различает программы по первому пакету шифрованного
//! соединения (ClientHello): его размеру, набору и порядку расширений, ключам.
//! Обычный TLS-клиент шлёт приветствие «втрое короче браузерного, в один пакет
//! вместо двух». По такому почерку проверку легко отличить от человека; хуже
//! того, стратегия обхода режет и подделывает именно этот пакет: проверенная
//! на приветствии не-браузера, она может не сработать в браузере, и наоборот.
//!
//! В python запрос идёт через `curl_cffi` — libcurl с BoringSSL и отпечатком
//! Chrome (`CHROME_TARGET`). В Rust отпечаток Chrome недостижим без той же
//! основы; здесь те же заголовки [`WINDOWS_HEADERS`], дословный порт
//! классификации [`classify`] и suche же итоги ([`ProbeResult`]), как у python,
//! а транспорт подменяется сообщнику [`ChromeConnection`] — как в python тестах
//! подменяли `_curl_api`.
//!
//! Адрес задаётся явно: диагностика сама решает, к какому IP идти, а имя сайта
//! уходит в SNI и в заголовок `:authority`, как у браузера. Сжатый ответ по
//! умолчанию не распаковывается: размер тела — это байты на проводе, а по ним
//! судят об обрыве по объёму.
//!
//! Отмена: отмена замечается на каждом куске ответа; подключение и рукопожатие
//! ограничены сроком `timeout`.

use std::time::Instant;

use primecore_netfailure::{FAILURE_OTHER, FAILURE_RESET, FAILURE_TIMEOUT};
use primecore_socketcancel::SocketCancel;

use crate::probe_result::{
    KIND_CANCELLED, KIND_CERT, KIND_CONNECT, KIND_ERROR, KIND_OK, KIND_RESET, KIND_TLS, KIND_TIMEOUT, ProbeResult,
    STAGE_CONNECT, STAGE_READ, STAGE_TLS,
};

/// Какой браузер изображать: самая новая версия Chrome из профиля curl_cffi 0.16.
pub const CHROME_TARGET: &str = "chrome150";

/// Заголовки запроса — как у Chrome 150 на Windows с русским языком, в его
/// порядке. Профиль curl_cffi снят с Chrome на macOS; запрос «с Mac» с
/// компьютера, который по пакетам Windows, сам бы выделялся. Свои заголовки
/// curl_cffi поэтому выключены, а не подменяются поштучно: смесь его заголовков
/// со своими роняла libcurl на повторных запросах по одному соединению.
pub static WINDOWS_HEADERS: [&str; 13] = [
    "sec-ch-ua: \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
    "sec-ch-ua-mobile: ?0",
    "sec-ch-ua-platform: \"Windows\"",
    "Upgrade-Insecure-Requests: 1",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site: none",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-User: ?1",
    "Sec-Fetch-Dest: document",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Priority: u=0, i",
];

// Коды ошибок libcurl (CURLcode), по которым судим об исходе.
pub const E_COULDNT_CONNECT: i32 = 7;
pub const E_WRITE_ERROR: i32 = 23; // мы сами прервали чтение: набрали сколько нужно или «Стоп»
pub const E_TIMEOUT: i32 = 28;
pub const E_SSL_CONNECT: i32 = 35;
pub const E_GOT_NOTHING: i32 = 52;
pub const E_SEND: i32 = 55;
pub const E_RECV: i32 = 56;
pub const E_PEER_VERIFY: i32 = 60;
pub const E_HTTP2: i32 = 16;
pub const E_HTTP2_STREAM: i32 = 92;
pub const E_SSL_CERTPROBLEM: i32 = 58;
pub const E_PARTIAL_FILE: i32 = 18;

// Виды отладочных событий libcurl (curl_infotype), по которым виден этап соединения.
pub const DEBUG_TEXT: i32 = 0;
pub const DEBUG_HEADER_OUT: i32 = 2;
pub const DEBUG_SSL_DATA_OUT: i32 = 6;

// Соединение оборвали: пустой ответ, ошибка приёма или отправки, обрыв потока HTTP/2.
pub static RESET_CODES: [i32; 6] = [E_RECV, E_SEND, E_GOT_NOTHING, E_HTTP2, E_HTTP2_STREAM, E_PARTIAL_FILE];

/// Что успело произойти: от этого зависит, чем считать сбой.
///
/// Замеры времени libcurl при сбое обнуляются, поэтому этап берётся из его
/// отладочных событий: ушёл первый пакет шифрования — соединение есть и идёт
/// рукопожатие; ушёл заголовок запроса — шифрование установлено.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Progress {
    pub status: Option<i64>,
    pub body: Vec<u8>,
    /// Сколько байт заголовков ответа пришло: у HEAD, кроме них, ничего нет.
    pub header_size: u32,
    /// Чтение прервали мы сами: набрали сколько нужно (`stopped_by_us`) или нажали «Стоп».
    pub stopped_by_us: bool,
    pub cancelled: bool,
    pub tls_started: bool,
    pub secured: bool,
    pub tls_version: String,
}

impl Progress {
    #[must_use]
    pub fn new() -> Self {
        Progress::default()
    }
}

/// Почему сертификат не прошёл проверку — человеческими словами (python `_cert_problem`).
#[must_use]
pub fn cert_problem(message: &str) -> String {
    let text = message.to_lowercase();
    // python: "hostname" in text or "subject" in text or "name" in text and "match" in text
    let hostname = text.contains("hostname");
    let subject = text.contains("subject");
    let name_match = text.contains("name") && text.contains("match");
    if hostname || subject || name_match {
        return "сертификат выдан другому сайту".to_string();
    }
    if text.contains("expired") || text.contains("not yet valid") {
        return "сертификат просрочен или ещё не действует (проверьте часы Windows)".to_string();
    }
    if text.contains("self signed") || text.contains("self-signed") {
        return "самодельный сертификат".to_string();
    }
    if text.contains("issuer") || text.contains("unable to get local") {
        return "сертификат выдан неизвестным центром".to_string();
    }
    "сертификат не прошёл проверку".to_string()
}

/// Один запрос по соединению.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSpec {
    pub path: String,
    pub method: &'static str,
}

impl RequestSpec {
    #[must_use]
    pub fn get(path: &str) -> Self {
        RequestSpec { path: path.to_string(), method: "GET" }
    }

    #[must_use]
    pub fn head(path: &str) -> Self {
        RequestSpec { path: path.to_string(), method: "HEAD" }
    }
}

/// Чем кончился один запрос по соединению (python `Exchange`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Exchange {
    pub progress: Progress,
    /// Код libcurl (0 — без ошибки), его текст и вид сбоя по коду ошибки системы.
    pub error_code: i32,
    pub message: String,
    pub os_failure: &'static str,
    /// Для этого запроса libcurl открыл новое соединение: прежнее закрыли.
    pub reconnected: bool,
}

impl Exchange {
    /// Байты ответа: заголовки и тело.
    #[must_use]
    pub fn received(&self) -> usize {
        self.progress.header_size as usize + self.progress.body.len()
    }

    /// Данные перестали идти (или не пошли) дольше срока.
    #[must_use]
    pub fn stalled(&self) -> bool {
        self.error_code == E_TIMEOUT || (self.error_code != 0 && self.os_failure == FAILURE_TIMEOUT)
    }

    /// Соединение оборвали.
    #[must_use]
    pub fn reset(&self) -> bool {
        self.error_code != 0 && (self.os_failure == FAILURE_RESET || RESET_CODES.contains(&self.error_code))
    }

    /// Какой этап дошёл: чтение, рукопожатие или подключение.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        if self.progress.secured {
            STAGE_READ
        } else if self.progress.tls_started {
            STAGE_TLS
        } else {
            STAGE_CONNECT
        }
    }
}

/// Отладочные события libcurl — та же нумерация (python `_Progress.on_debug`).
pub fn on_debug(progress: &mut Progress, kind: i32, data: &[u8]) {
    match kind {
        DEBUG_SSL_DATA_OUT => progress.tls_started = true,
        DEBUG_HEADER_OUT => progress.secured = true,
        DEBUG_TEXT if data.starts_with(b"SSL connection using ") => {
            progress.secured = true;
            let rest = &data[b"SSL connection using ".len()..];
            let word = rest.split(|byte| *byte == b' ').next().unwrap_or(rest);
            progress.tls_version = String::from_utf8_lossy(word).to_string();
        }
        _ => {}
    }
}

/// Заголовочная строка ответа: статус из первого «настоящего» HTTP-заголовка
/// (python `_on_header`). Перед окончательным ответом бывают промежуточные
/// (100, 103): ждём настоящий.
pub fn on_header(progress: &mut Progress, line: &[u8]) {
    progress.header_size += line.len() as u32;
    if line.starts_with(b"HTTP/") {
        // python: line.split() игнорирует разделители и хвостовые пробелы.
        let mut parts = std::str::from_utf8(line).unwrap_or("").split_ascii_whitespace();
        let _first = parts.next();
        if let Some(second) = parts.next() {
            let digits = second.to_string();
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) && !digits.starts_with('1') {
                progress.status = digits.parse::<i64>().ok();
            }
        }
    }
}

/// Кусок тела: учесть и по нему решить, продолжать ли чтение (python `_on_body`).
///
/// `enough` — «читать дальше незачем» (чтение прерывается без сбоя).
#[must_use]
pub fn on_body(progress: &mut Progress, token: &SocketCancel, chunk: &[u8], enough: &mut dyn FnMut(&[u8]) -> bool) -> BodyDecision {
    progress.body.extend_from_slice(chunk);
    if token.cancelled() {
        progress.cancelled = true;
        return BodyDecision::WriteError;
    }
    if enough(&progress.body) {
        progress.stopped_by_us = true;
        return BodyDecision::WriteError;
    }
    BodyDecision::Continue
}

/// Что решил обработчик тела: читать дальше или прервать запись со своей стороны
/// (python возвращает код ошибки записи `CURL_WRITEFUNC_ERROR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyDecision {
    /// Читать дальше.
    Continue,
    /// Прервать чтение — это не сбой сети.
    WriteError,
}

/// Дополнительный вывод исхода: то, что python передавал как `**extra`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeResultExtra {
    pub body_cut: bool,
    pub cert_problem: String,
    pub connect_fail: &'static str,
}

/// Исход по коду libcurl, коду ошибки системы и тому, что успело прийти
/// (python `_classify`). Точные тексты и ветки — как в python.
#[must_use]
pub fn classify(exchange: &Exchange, cancel: &SocketCancel, started: Instant, ip: &str) -> ProbeResult {
    let build = |kind: &'static str, detail: &str, extra: &ProbeResultExtra| -> ProbeResult {
        let mut extra = extra.clone();
        if cancel.cancelled() && (kind != KIND_OK || extra.body_cut) {
            extra.body_cut = false;
            return ProbeResult {
                ip: ip.to_string(),
                kind: KIND_CANCELLED.to_string(),
                stage: exchange.stage(),
                status: exchange.progress.status,
                body_size: exchange.progress.body.len() as u64,
                tls_version: exchange.progress.tls_version.clone(),
                elapsed_ms: finished_ms(started),
                detail: String::new(),
                body: exchange.progress.body.clone(),
                ..ProbeResult::default()
            };
        }
        ProbeResult {
            ip: ip.to_string(),
            kind: kind.to_string(),
            stage: exchange.stage(),
            status: exchange.progress.status,
            body_size: exchange.progress.body.len() as u64,
            body_cut: extra.body_cut,
            cert_problem: extra.cert_problem.clone(),
            tls_version: exchange.progress.tls_version.clone(),
            elapsed_ms: finished_ms(started),
            detail: detail.to_string(),
            body: exchange.progress.body.clone(),
            connect_fail: extra.connect_fail,
        }
    };
    let progress = &exchange.progress;
    let stage = exchange.stage();
    let got_answer = progress.status.is_some();
    if progress.cancelled {
        return build(KIND_CANCELLED, "", &ProbeResultExtra::default());
    }
    if exchange.error_code == 0 || (exchange.error_code == E_WRITE_ERROR && progress.stopped_by_us) {
        if !got_answer {
            return build(KIND_RESET, "сервер закрыл соединение без ответа", &ProbeResultExtra::default());
        }
        return build(KIND_OK, "", &ProbeResultExtra::default());
    }
    if exchange.error_code == E_PEER_VERIFY || exchange.error_code == E_SSL_CERTPROBLEM {
        let extra = ProbeResultExtra { cert_problem: cert_problem(&exchange.message), ..Default::default() };
        return build(KIND_CERT, &exchange.message, &extra);
    }
    if got_answer {
        // Заголовок пришёл, а тело оборвалось: сброс, замирание или обрыв HTTP/2.
        let extra = ProbeResultExtra { body_cut: true, ..Default::default() };
        return build(KIND_OK, &exchange.message, &extra);
    }
    if stage == STAGE_CONNECT {
        if exchange.error_code == E_TIMEOUT {
            let extra = ProbeResultExtra { connect_fail: FAILURE_TIMEOUT, ..Default::default() };
            return build(KIND_CONNECT, "сервер не отвечает на подключение", &extra);
        }
        let extra = ProbeResultExtra {
            connect_fail: if exchange.os_failure.is_empty() { FAILURE_OTHER } else { exchange.os_failure },
            ..Default::default()
        };
        return build(KIND_CONNECT, &exchange.message, &extra);
    }
    if exchange.error_code == E_TIMEOUT || exchange.os_failure == FAILURE_TIMEOUT {
        return build(KIND_TIMEOUT, &exchange.message, &ProbeResultExtra::default());
    }
    if exchange.os_failure == FAILURE_RESET || RESET_CODES.contains(&exchange.error_code) {
        return build(KIND_RESET, &exchange.message, &ProbeResultExtra::default());
    }
    if exchange.error_code == E_SSL_CONNECT {
        return build(KIND_TLS, &exchange.message, &ProbeResultExtra::default());
    }
    build(KIND_ERROR, &exchange.message, &ProbeResultExtra::default())
}

fn finished_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_like_python() {
        assert_eq!(CHROME_TARGET, "chrome150");
        assert!(WINDOWS_HEADERS[0].starts_with("sec-ch-ua: \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\""));
        assert_eq!(WINDOWS_HEADERS[3], "Upgrade-Insecure-Requests: 1");
        assert!(WINDOWS_HEADERS[4].contains("Chrome/150.0.0.0 Safari/537.36"));
        assert!(WINDOWS_HEADERS[10].contains("zstd"));
        assert_eq!(WINDOWS_HEADERS.len(), 13);
    }

    #[test]
    fn cert_problems_by_word() {
        assert_eq!(cert_problem("README: hostname mismatch"), "сертификат выдан другому сайту");
        assert_eq!(cert_problem("certificate subject does not match"), "сертификат выдан другому сайту");
        assert_eq!(cert_problem("x name match of z"), "сертификат выдан другому сайту");
        assert_eq!(cert_problem("cert has expired"), "сертификат просрочен или ещё не действует (проверьте часы Windows)");
        assert_eq!(cert_problem("self signed certificate"), "самодельный сертификат");
        assert_eq!(cert_problem("issuer certificate not found"), "сертификат выдан неизвестным центром");
        assert_eq!(cert_problem("unable to get local issuer"), "сертификат выдан неизвестным центром");
        assert_eq!(cert_problem("что-то постороннее"), "сертификат не прошёл проверку");
    }

    #[test]
    fn debug_seen_stages() {
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_TEXT, b"Try connect to 1.1.1.1...");
        assert!(!progress.tls_started && !progress.secured);
        on_debug(&mut progress, DEBUG_TEXT, b"SSL connection using TLSv1.3 / TLS_AES");
        assert_eq!(progress.tls_version, "TLSv1.3");
        // Замеченный python-порядок: строка «SSL connection using …» уже означает защищённое.
        assert_eq!(Exchange { progress, error_code: 0, message: String::new(), os_failure: "", reconnected: false }.stage(), STAGE_READ);
        let mut raw = Progress::new();
        on_debug(&mut raw, DEBUG_SSL_DATA_OUT, &[0u8, 1, 2]);
        assert!(raw.tls_started);
        assert_eq!(Exchange { progress: raw, error_code: 0, message: String::new(), os_failure: "", reconnected: false }.stage(), STAGE_TLS);
    }

    #[test]
    fn header_status_skips_informational() {
        let mut progress = Progress::new();
        on_header(&mut progress, b"HTTP/2 100\r\n");
        assert_eq!(progress.status, None);
        assert_eq!(progress.header_size, 12);
        on_header(&mut progress, b"HTTP/2 200\r\n");
        assert_eq!(progress.status, Some(200));
        assert_eq!(progress.header_size, 24);
    }

    #[test]
    fn body_runs_until_enough() {
        let token = SocketCancel::new();
        let mut progress = Progress::new();
        let mut hit = 0usize;
        assert_eq!(
            on_body(&mut progress, &token, b"re", &mut |_body| { hit += 1; false }),
            BodyDecision::Continue
        );
        assert_eq!(hit, 1);
        assert_eq!(progress.body, b"re".to_vec());
        assert_eq!(on_body(&mut progress, &token, b"st", &mut |_| true), BodyDecision::WriteError);
        assert!(progress.stopped_by_us);
        assert!(!progress.cancelled);
        token.cancel();
        assert_eq!(on_body(&mut progress, &token, b"x", &mut |_| false), BodyDecision::WriteError);
        assert!(progress.cancelled);
    }

    #[test]
    fn exchange_stages_and_stalls() {
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_SSL_DATA_OUT, &[0u8]);
        let mut exchange = Exchange {
            progress: progress.clone(),
            error_code: 0,
            message: String::new(),
            os_failure: "",
            reconnected: false,
        };
        assert_eq!(exchange.stage(), STAGE_TLS);
        on_debug(&mut progress, DEBUG_HEADER_OUT, &[0u8]);
        exchange.progress = progress.clone();
        assert_eq!(exchange.stage(), STAGE_READ);
        assert!(!exchange.stalled());
        assert!(!exchange.reset());
        exchange.error_code = E_TIMEOUT;
        assert!(exchange.stalled());
        let mut cut = Progress::new();
        on_debug(&mut cut, DEBUG_SSL_DATA_OUT, &[0u8]);
        on_debug(&mut cut, DEBUG_HEADER_OUT, &[0u8]);
        on_header(&mut cut, b"HTTP/2 200\r\n");
        exchange = Exchange { progress: cut, error_code: E_RECV, message: "reset".to_string(), os_failure: "", reconnected: false };
        assert_eq!(exchange.stage(), STAGE_READ);
        assert!(exchange.reset());
        assert_eq!(exchange.received(), 12);
    }

    #[test]
    fn classify_paths_match_python_branches() {
        let started = Instant::now();
        let token = SocketCancel::new();
        // На этапе подключения — таймаут: connect_fail = "timeout".
        let mut exchange = Exchange {
            progress: Progress::new(),
            error_code: E_TIMEOUT,
            message: "timed out".to_string(),
            os_failure: "",
            reconnected: false,
        };
        let result = classify(&exchange, &token, started, "10.0.0.1", );
        assert_eq!(result.kind, KIND_CONNECT);
        assert_eq!(result.detail, "сервер не отвечает на подключение");
        assert_eq!(result.connect_fail, "timeout");
        // Другой сбой на этапе подключения: «other».
        exchange.error_code = E_COULDNT_CONNECT;
        let result = classify(&exchange, &token, started, "10.0.0.1", );
        assert_eq!(result.connect_fail, "other");

        // Проверка сертификата: kind cert + человеческая причина.
        exchange.error_code = E_PEER_VERIFY;
        exchange.message = "secure connection: certificate has expired".to_string();
        let result = classify(&exchange, &token, started, "10.0.0.1", );
        assert_eq!(result.kind, KIND_CERT);
        assert_eq!(result.cert_problem, "сертификат просрочен или ещё не действует (проверьте часы Windows)");

        // Заголовок пришёл, а тело оборвалось: ok + body_cut.
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_HEADER_OUT, &[0u8]);
        on_header(&mut progress, b"HTTP/2 200\r\n");
        exchange = Exchange { progress, error_code: E_RECV, message: "reset".to_string(), os_failure: "", reconnected: false };
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_OK);

        // Тихий рукопожатийный сброс.
        let mut progress_clear = Progress::new();
        on_debug(&mut progress_clear, DEBUG_SSL_DATA_OUT, &[0u8]);
        exchange.progress = progress_clear;
        exchange.error_code = E_SSL_CONNECT;
        let result = classify(&exchange, &token, started, "10.0.0.1", );
        assert_eq!(result.kind, KIND_TLS);
        exchange.error_code = E_RECV;
        assert_eq!(classify(&exchange, &token, started, "10.0.0.1", ).kind, KIND_RESET);
        exchange.error_code = E_HTTP2_STREAM;
        assert_eq!(classify(&exchange, &token, started, "10.0.0.1", ).kind, KIND_RESET);
        exchange.error_code = 77;
        assert_eq!(classify(&exchange, &token, started, "10.0.0.1", ).kind, KIND_ERROR);

        // «Стоп» mid-запроса — cancelled.
        let stop = SocketCancel::new();
        stop.cancel();
        let mut progress = Progress::new();
        progress.cancelled = true;
        exchange.progress = progress;
        exchange.error_code = 0;
        assert_eq!(classify(&exchange, &stop, started, "10.0.0.1", ).kind, KIND_CANCELLED);

        // Отмена<Node Отмена после успешного ответа — всё равно вид KIND_OK.
        let cancelled = SocketCancel::new();
        cancelled.cancel();
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_HEADER_OUT, &[0u8]);
        on_header(&mut progress, b"HTTP/2 200\r\n");
        exchange.progress = progress;
        let result = classify(&exchange, &cancelled, started, "10.0.0.1", );
        assert_eq!(result.kind, KIND_OK);
        exchange.progress.body = b"partial".to_vec();
        // «Стоп» посреди тела останавливает запись со своей стороны (E_WRITE_ERROR), а не сеть.
        exchange.error_code = E_WRITE_ERROR;
        let result = classify(&exchange, &cancelled, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_CANCELLED);
    }
}
