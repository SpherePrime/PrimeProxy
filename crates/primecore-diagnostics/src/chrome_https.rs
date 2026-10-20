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
//! основы (rustls шлёт своё приветствие): здесь те же заголовки
//! [`WINDOWS_HEADERS`], дословный порт классификации [`classify`], те же
//! итоги ([`ProbeResult`]) и свой транспорт [`ChromeConnection`] на rustls —
//! рукопожатие честное, HTTP/1.1 (HTTP/2 rustls не говорит). Выводы
//! диагностики опираются только на виды исхода, этапы и `body_cut` — их
//! решение перенесено золотым тестом против python. Сам отпечаток приветствия
//! rustls браузерный не повторяет — это отмечено в docs_migration-map.
//!
//! Адрес задаётся явно: диагностика сама решает, к какому IP идти, а имя сайта
//! уходит в SNI и в заголовок `:authority`, как у браузера. Сжатый ответ по
//! умолчанию не распаковывается: размер тела — это байты на проводе, а по ним
//! судят об обрыве по объёму.
//!
//! Отмена: отмена замечается на каждом куске ответа; подключение и рукопожатие
//! ограничены сроком `timeout`.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use primecore_netfailure::{classify_os_error, FAILURE_OTHER, FAILURE_RESET, FAILURE_TIMEOUT};
use primecore_socketcancel::SocketCancel;
use rustls::pki_types::ServerName;

use crate::probe_result::{
    ProbeResult, KIND_CANCELLED, KIND_CERT, KIND_CONNECT, KIND_ERROR, KIND_OK, KIND_RESET,
    KIND_TIMEOUT, KIND_TLS, STAGE_CONNECT, STAGE_READ, STAGE_TLS,
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
pub static RESET_CODES: [i32; 6] = [
    E_RECV,
    E_SEND,
    E_GOT_NOTHING,
    E_HTTP2,
    E_HTTP2_STREAM,
    E_PARTIAL_FILE,
];

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
        RequestSpec {
            path: path.to_string(),
            method: "GET",
        }
    }

    #[must_use]
    pub fn head(path: &str) -> Self {
        RequestSpec {
            path: path.to_string(),
            method: "HEAD",
        }
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
        self.error_code != 0
            && (self.os_failure == FAILURE_RESET || RESET_CODES.contains(&self.error_code))
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
        let mut parts = std::str::from_utf8(line)
            .unwrap_or("")
            .split_ascii_whitespace();
        let _first = parts.next();
        if let Some(second) = parts.next() {
            let digits = second.to_string();
            if !digits.is_empty()
                && digits.chars().all(|c| c.is_ascii_digit())
                && !digits.starts_with('1')
            {
                progress.status = digits.parse::<i64>().ok();
            }
        }
    }
}

/// Кусок тела: учесть и по нему решить, продолжать ли чтение (python `_on_body`).
///
/// `enough` — «читать дальше незачем» (чтение прерывается без сбоя).
#[must_use]
pub fn on_body(
    progress: &mut Progress,
    token: &SocketCancel,
    chunk: &[u8],
    enough: &mut dyn FnMut(&[u8]) -> bool,
) -> BodyDecision {
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
pub fn classify(
    exchange: &Exchange,
    cancel: &SocketCancel,
    started: Instant,
    ip: &str,
) -> ProbeResult {
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
    if exchange.error_code == 0 || (exchange.error_code == E_WRITE_ERROR && progress.stopped_by_us)
    {
        if !got_answer {
            return build(
                KIND_RESET,
                "сервер закрыл соединение без ответа",
                &ProbeResultExtra::default(),
            );
        }
        return build(KIND_OK, "", &ProbeResultExtra::default());
    }
    if exchange.error_code == E_PEER_VERIFY || exchange.error_code == E_SSL_CERTPROBLEM {
        let extra = ProbeResultExtra {
            cert_problem: cert_problem(&exchange.message),
            ..Default::default()
        };
        return build(KIND_CERT, &exchange.message, &extra);
    }
    if got_answer {
        // Заголовок пришёл, а тело оборвалось: сброс, замирание или обрыв HTTP/2.
        let extra = ProbeResultExtra {
            body_cut: true,
            ..Default::default()
        };
        return build(KIND_OK, &exchange.message, &extra);
    }
    if stage == STAGE_CONNECT {
        if exchange.error_code == E_TIMEOUT {
            let extra = ProbeResultExtra {
                connect_fail: FAILURE_TIMEOUT,
                ..Default::default()
            };
            return build(KIND_CONNECT, "сервер не отвечает на подключение", &extra);
        }
        let extra = ProbeResultExtra {
            connect_fail: if exchange.os_failure.is_empty() {
                FAILURE_OTHER
            } else {
                exchange.os_failure
            },
            ..Default::default()
        };
        return build(KIND_CONNECT, &exchange.message, &extra);
    }
    if exchange.error_code == E_TIMEOUT || exchange.os_failure == FAILURE_TIMEOUT {
        return build(
            KIND_TIMEOUT,
            &exchange.message,
            &ProbeResultExtra::default(),
        );
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

// ---------------------------------------------------------------------------
// Транспорт: то, что в python делает libcurl.
// ---------------------------------------------------------------------------

/// Как часто при чтении между отрезками проверяется «Стоп».
const POLL_SLICE_S: f64 = 0.2;

/// Корневые сертификаты: как `certifi` у python — свой комплект, а не
/// хранилище системы (python: «BoringSSL не читает хранилище Windows»; rustls
/// его тоже не читает, на Windows системное хранилище порой неполно).
fn root_store() -> Arc<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(roots)
}

/// Куда писать и читать: зашифрованный поток или открытый (только в тестах —
/// живой путь всегда через рукопожатие).
enum TlsStream {
    /// Открытый поток — строится только в тестах этого модуля.
    #[cfg_attr(not(test), allow(dead_code))]
    Plain(TcpStream),
    Secured(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl TlsStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) {
        let _ = match self {
            TlsStream::Plain(stream) => stream.set_read_timeout(timeout),
            TlsStream::Secured(secured) => secured.sock.set_read_timeout(timeout),
        };
    }

    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Plain(stream) => stream.read(buffer),
            TlsStream::Secured(secured) => secured.read(buffer),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            TlsStream::Plain(stream) => stream.write_all(data),
            TlsStream::Secured(secured) => secured.write_all(data),
        }
    }
}

/// Человекочитаемая версия согласованного шифрования — как libcurl писал её в
/// отладке («SSL connection using TLSv1.3»), откуда её брал python.
fn tls_version(common: &rustls::CommonState) -> String {
    match common.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "",
    }
    .to_string()
}

/// Текст ошибки проверки сертификата словами libcurl — от них [`cert_problem`]
/// узнаёт причину (сообщения rustls других слов).
fn verify_message(error: &rustls::CertificateError) -> String {
    use rustls::CertificateError::*;
    match error {
        Expired | ExpiredContext { .. } => "certificate has expired".to_string(),
        NotValidYet | NotValidYetContext { .. } => "certificate is not yet valid".to_string(),
        NotValidForName | NotValidForNameContext { .. } => {
            "certificate subject name mismatch".to_string()
        }
        UnknownIssuer => "unable to get local issuer certificate".to_string(),
        BadSignature => "self signed certificate in certificate chain".to_string(),
        other => other.to_string(),
    }
}

/// Сбой чтения в код libcurl: внутри `io::Error` может сидеть ошибка TLS —
/// вытащим её; иначе это сбой системы (обрыв, тишина).
fn read_failure(error: &std::io::Error) -> (i32, String, &'static str) {
    if let Some(inner) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        let code = match inner {
            rustls::Error::InvalidCertificate(reason) => {
                return (E_PEER_VERIFY, verify_message(reason), "");
            }
            _ => E_SSL_CONNECT,
        };
        return (code, inner.to_string(), "");
    }
    let failure = classify_os_error(error);
    if failure == FAILURE_TIMEOUT {
        return (E_TIMEOUT, error.to_string(), "");
    }
    (E_RECV, error.to_string(), failure)
}

/// Сбой запроса, кроме кода и текста, — вид сбоя системы; пусто, если код сам
/// всё говорит. Собирает `Exchange` из частей.
fn failure_exchange(
    progress: Progress,
    error_code: i32,
    message: String,
    os_failure: &'static str,
    reconnected: bool,
) -> Exchange {
    Exchange {
        progress,
        error_code,
        message,
        os_failure,
        reconnected,
    }
}

/// Сроки чтения: общий предел запроса и предел замирания данных.
struct ReadBudget {
    deadline: Instant,
    stall: Duration,
    last: Instant,
}

impl ReadBudget {
    fn new(total: Duration, stall: Duration) -> Self {
        ReadBudget {
            deadline: Instant::now() + total,
            stall,
            last: Instant::now(),
        }
    }

    fn mark(&mut self) {
        self.last = Instant::now();
    }

    /// Отрезок ожидания до общего предела — не длиннее проверочного куска.
    fn slice(&self) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs_f64(POLL_SLICE_S))
    }

    /// Закончился общий срок запроса или данные замерли дольше срока.
    fn exceeded(&self) -> Option<(i32, String)> {
        if Instant::now() >= self.deadline {
            return Some((E_TIMEOUT, "запрос не уложился в срок".to_string()));
        }
        if self.last.elapsed() >= self.stall {
            return Some((E_TIMEOUT, "данные перестали идти дольше срока".to_string()));
        }
        None
    }
}

/// Конфиг клиента: провайдер шифрования выбирается явно — в графе бывают
/// включены сразу ring и aws-lc-rs, и rustls в этом случае не выбирает сам;
/// ring же не требует cmake/NASM при сборке под Windows.
fn client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("версии TLS доступны")
        .with_root_certificates(root_store())
        .with_no_client_auth();
    // Проба говорит только по HTTP/1.1: приветствие и объявляем это.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// python `ChromeConnection` — соединение «как Chrome» с сайтом по заданному
/// адресу: запросы подряд идут по нему же (браузер грузит страницу несколькими
/// запросами по одному соединению). Фильтр считает данные по соединению,
/// поэтому обрыв по объёму видно только так.
pub struct ChromeConnection {
    host: String,
    ip: String,
    port: u16,
    timeout: f64,
    read_timeout: f64,
    decode_body: bool,
    cancel: Arc<SocketCancel>,
    stream: Option<TlsStream>,
    requests: usize,
    /// Только в тестах этого модуля: открытый HTTP вместо TLS.
    #[cfg(test)]
    insecure: bool,
}

impl ChromeConnection {
    /// python `ChromeConnection(host, ip, timeout=…, port=…, read_timeout=…,
    /// decode_body=…, cancel=…)`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        ip: &str,
        timeout: f64,
        port: u16,
        read_timeout: f64,
        decode_body: bool,
        cancel: Arc<SocketCancel>,
    ) -> Self {
        ChromeConnection {
            host: host.to_string(),
            ip: ip.to_string(),
            port,
            timeout,
            read_timeout,
            decode_body,
            cancel,
            stream: None,
            requests: 0,
            #[cfg(test)]
            insecure: false,
        }
    }

    /// Только для тестов этого модуля: соединение без шифрования, рукопожатие
    /// считается состоявшимся — весь путь запроса остаётся как у живого.
    #[cfg(test)]
    fn insecure_http_for_tests(
        host: &str,
        ip: &str,
        timeout: f64,
        port: u16,
        read_timeout: f64,
        cancel: Arc<SocketCancel>,
    ) -> Self {
        ChromeConnection {
            host: host.to_string(),
            ip: ip.to_string(),
            port,
            timeout,
            read_timeout,
            decode_body: false,
            cancel,
            stream: None,
            requests: 0,
            insecure: true,
        }
    }

    /// python `close()` — соединение закрыто, следующий запрос пойдёт по новому.
    pub fn close(&mut self) {
        self.stream = None;
    }

    /// Соединение и рукопожатие, если ещё не установлены (python делает это
    /// libcurl при первом запросе). Двигает `progress` так же, как отладочные
    /// события libcurl: ушёл первый пакет шифрования — `tls_started`,
    /// рукопожатие сошлось — `secured`.
    fn ensure_secured(
        &mut self,
        progress: &mut Progress,
    ) -> Result<(), (i32, String, &'static str)> {
        #[cfg(test)]
        if self.insecure {
            if self.stream.is_none() {
                self.stream = Some(TlsStream::Plain(self.open_socket()?));
            }
            progress.tls_started = true;
            progress.secured = true;
            return Ok(());
        }
        if matches!(self.stream, Some(TlsStream::Secured(_))) {
            return Ok(());
        }
        let plain = match self.stream.take() {
            Some(TlsStream::Plain(stream)) => stream,
            Some(secured @ TlsStream::Secured(_)) => {
                self.stream = Some(secured);
                return Ok(());
            }
            None => self.open_socket()?,
        };
        // Первый пакет шифрования уходит сразу за подключением (DEBUG_SSL_DATA_OUT).
        progress.tls_started = true;
        let config = client_config();
        let server_name = match ServerName::try_from(self.host.clone()) {
            Ok(name) => name,
            Err(error) => return Err((E_SSL_CONNECT, error.to_string(), "")),
        };
        let connection = match rustls::ClientConnection::new(Arc::new(config), server_name) {
            Ok(connection) => connection,
            Err(error) => return Err((E_SSL_CONNECT, error.to_string(), "")),
        };
        let mut secured = rustls::StreamOwned::new(connection, plain);
        // Рукопожатие ограничено сроком подключения (python CONNECTTIMEOUT).
        let deadline = Instant::now() + Duration::from_secs_f64(self.timeout.max(0.2));
        loop {
            if self.cancel.cancelled() {
                progress.cancelled = true;
                return Err((E_WRITE_ERROR, String::new(), ""));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err((E_TIMEOUT, "рукопожатие не уложилось в срок".to_string(), ""));
            }
            let slice = remaining.min(Duration::from_secs_f64(POLL_SLICE_S));
            let _ = secured.sock.set_read_timeout(Some(slice));
            let _ = secured.sock.set_write_timeout(Some(slice));
            match secured.conn.complete_io(&mut secured.sock) {
                Ok(_) => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    let failure = read_failure(&error);
                    return Err(failure);
                }
            }
        }
        progress.secured = true;
        progress.tls_version = tls_version(&secured.conn);
        self.stream = Some(TlsStream::Secured(Box::new(secured)));
        Ok(())
    }

    /// Подключение по заданному адресу (python `CURLOPT_RESOLVE`): диагностика
    /// сама решает, к какому IP идти, поэтому DNS здесь не нужен.
    fn open_socket(&self) -> Result<TcpStream, (i32, String, &'static str)> {
        let address = if self.ip.contains(':') {
            format!("[{}]:{}", self.ip, self.port)
        } else {
            format!("{}:{}", self.ip, self.port)
        };
        let target = match address.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(target) => target,
                None => {
                    return Err((
                        E_COULDNT_CONNECT,
                        "адрес не разобран".to_string(),
                        FAILURE_OTHER,
                    ));
                }
            },
            Err(error) => {
                return Err((
                    E_COULDNT_CONNECT,
                    error.to_string(),
                    classify_os_error(&error),
                ));
            }
        };
        TcpStream::connect_timeout(&target, Duration::from_secs_f64(self.timeout.max(0.2))).map_err(
            |error| {
                (
                    E_COULDNT_CONNECT,
                    error.to_string(),
                    classify_os_error(&error),
                )
            },
        )
    }

    /// Заголовок запроса: стартовая строка, `Host` и браузерные заголовки
    /// (`WINDOWS_HEADERS`) — весь набор, как у python.
    fn request_head(&self, path: &str, method: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {}", self.host);
        if self.port != 443 {
            head.push(':');
            head.push_str(&self.port.to_string());
        }
        head.push_str("\r\n");
        for header in WINDOWS_HEADERS {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        head
    }

    /// Один запрос по соединению (python `request`).
    ///
    /// `enough(тело)` — читать дальше незачем (чтение прерывается без сбоя,
    /// `E_WRITE_ERROR`, как в python запись со своей стороны).
    pub fn request(
        &mut self,
        path: &str,
        method: &str,
        enough: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Exchange {
        let mut progress = Progress::default();
        if self.cancel.cancelled() {
            progress.cancelled = true;
            return failure_exchange(progress, 0, String::new(), "", false);
        }
        let opened = self.stream.is_none();
        if let Err((code, message, os_failure)) = self.ensure_secured(&mut progress) {
            return failure_exchange(progress, code, message, os_failure, false);
        }
        let head = self.request_head(path, method);
        if let Err(error) = self
            .stream
            .as_mut()
            .expect("соединение открыто перед записью")
            .write_all(head.as_bytes())
        {
            return failure_exchange(progress, E_SEND, error.to_string(), "", false);
        }
        // Ушёл заголовок запроса — шифрование установлено (DEBUG_HEADER_OUT).
        progress.secured = true;

        let mut budget = ReadBudget::new(
            Duration::from_secs_f64(self.timeout.max(0.2) + 60.0),
            Duration::from_secs_f64(self.read_timeout.max(1.0)),
        );
        // Заголовки — построчно, как их видел python в `HEADERFUNCTION`.
        let mut line: Vec<u8> = Vec::new();
        let mut header_lines: Vec<Vec<u8>> = Vec::new();
        let headers = loop {
            if let Some((code, message)) = budget.exceeded() {
                return failure_exchange(progress, code, message, "", false);
            }
            match self.read_byte(&mut progress, &mut budget) {
                Ok(Some(byte)) => {
                    line.push(byte);
                    if !line.ends_with(b"\r\n") {
                        continue;
                    }
                    on_header(&mut progress, &line);
                    if line.len() == 2 {
                        break Ok(());
                    }
                    header_lines.push(std::mem::take(&mut line));
                }
                Ok(None) => {
                    // Соединение закрылось, не договорившись заголовками.
                    break Err((E_GOT_NOTHING, String::new(), ""));
                }
                Err(failure) => break Err(failure),
            }
        };
        if let Err((code, message, os_failure)) = headers {
            return failure_exchange(
                progress,
                code,
                message,
                os_failure,
                self.reconnected(opened),
            );
        }

        // Длина тела и кодировка — из заголовков ответа.
        let (content_length, chunked, content_encoding) = body_framing(&header_lines);
        let mut decoder = WireDecoder::new(self.decode_body, &content_encoding);

        if method.eq_ignore_ascii_case("HEAD") {
            // python `NOBODY`: у HEAD тела нет вовсе.
            return failure_exchange(progress, 0, String::new(), "", self.reconnected(opened));
        }

        let body = if chunked {
            self.read_chunked_body(&mut progress, &mut budget, &mut decoder, enough)
        } else {
            self.read_plain_body(
                &mut progress,
                &mut budget,
                &mut decoder,
                content_length,
                enough,
            )
        };
        if let Err((code, message, os_failure)) = body {
            return failure_exchange(
                progress,
                code,
                message,
                os_failure,
                self.reconnected(opened),
            );
        }
        failure_exchange(progress, 0, String::new(), "", self.reconnected(opened))
    }

    /// python: `reconnected = self._requests > 1 and NUM_CONNECTS > 0` —
    /// прежнее соединение закрыли, этот запрос открыл новое.
    fn reconnected(&mut self, opened: bool) -> bool {
        self.requests += 1;
        self.requests > 1 && opened
    }

    /// Одна попытка чтения одного байта с отменой и сроками. `Ok(None)` —
    /// соединение закрылось; тишина и «Стоп» возвращаются ошибкой, как их видел
    /// libcurl.
    fn read_byte(
        &mut self,
        progress: &mut Progress,
        budget: &mut ReadBudget,
    ) -> Result<Option<u8>, (i32, String, &'static str)> {
        let mut one = [0u8; 1];
        let got = self.read_sized(progress, budget, &mut one)?;
        Ok(if got == 0 { None } else { Some(one[0]) })
    }

    /// Чтение тела по длине на проводе или до закрытия соединения (python
    /// читает libcurl): тело распаковывается по ходу, но полнота ответа судится
    /// по байтам на проводе — так же, как libcurl по `Content-Length`.
    fn read_plain_body(
        &mut self,
        progress: &mut Progress,
        budget: &mut ReadBudget,
        decoder: &mut WireDecoder,
        content_length: Option<usize>,
        enough: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), (i32, String, &'static str)> {
        let target = content_length.unwrap_or(usize::MAX);
        let mut wire = 0usize;
        loop {
            let mut chunk = [0u8; 16 * 1024];
            let got = self.read_sized(progress, budget, &mut chunk)?;
            if got == 0 {
                // Соединение закрылось: без объявленной длины это конец
                // ответа, с объявленной — ответ оборвался (E_PARTIAL_FILE).
                if content_length.is_some() && wire < target {
                    return Err((E_PARTIAL_FILE, String::new(), ""));
                }
                return Ok(());
            }
            wire += got;
            self.deliver(progress, decoder, &chunk[..got], enough)?;
            if wire >= target {
                return Ok(());
            }
        }
    }

    /// Чтение тела по чанкам (`Transfer-Encoding: chunked`): чанки собираются,
    /// как их собирал libcurl.
    fn read_chunked_body(
        &mut self,
        progress: &mut Progress,
        budget: &mut ReadBudget,
        decoder: &mut WireDecoder,
        enough: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), (i32, String, &'static str)> {
        loop {
            let size_line = match self.read_line(progress, budget)? {
                Some(line) => line,
                None => return Err((E_PARTIAL_FILE, String::new(), "")),
            };
            let text = String::from_utf8_lossy(&size_line);
            let digits = text.trim().split(';').next().unwrap_or("").trim();
            let size = match usize::from_str_radix(digits, 16) {
                Ok(size) => size,
                Err(_) => return Err((E_RECV, "чанк не разобран".to_string(), "")),
            };
            if size == 0 {
                // Хвостовые заголовки — до пустой строки; соединение при этом
                // остаётся открытым (keep-alive).
                loop {
                    match self.read_line(progress, budget)? {
                        Some(line) if line.len() > 2 => continue,
                        _ => return Ok(()),
                    }
                }
            }
            let mut left = size;
            let mut chunk = vec![0u8; size.min(16 * 1024)];
            while left > 0 {
                let want = chunk.len().min(left);
                match self.read_sized(progress, budget, &mut chunk[..want]) {
                    Ok(0) => return Err((E_PARTIAL_FILE, String::new(), "")),
                    Ok(got) => {
                        left -= got;
                        self.deliver(progress, decoder, &chunk[..got], enough)?;
                    }
                    Err(failure) => return Err(failure),
                }
            }
            // Пустая строка после чанка.
            match self.read_line(progress, budget)? {
                Some(line) if line.len() <= 2 => {}
                Some(_) => {
                    return Err((
                        E_RECV,
                        "чанк не закончился переводом строки".to_string(),
                        "",
                    ));
                }
                None => return Err((E_PARTIAL_FILE, String::new(), "")),
            }
        }
    }

    /// Строка до перевода строки включительно (для размеров чанков и хвостов).
    fn read_line(
        &mut self,
        progress: &mut Progress,
        budget: &mut ReadBudget,
    ) -> Result<Option<Vec<u8>>, (i32, String, &'static str)> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            match self.read_byte(progress, budget)? {
                Some(byte) => {
                    line.push(byte);
                    if line.ends_with(b"\r\n") {
                        return Ok(Some(line));
                    }
                }
                None => {
                    if line.is_empty() {
                        return Ok(None);
                    }
                    return Err((E_PARTIAL_FILE, String::new(), ""));
                }
            }
        }
    }

    /// Чтение точного количества байт с отменой и сроками.
    fn read_sized(
        &mut self,
        progress: &mut Progress,
        budget: &mut ReadBudget,
        out: &mut [u8],
    ) -> Result<usize, (i32, String, &'static str)> {
        loop {
            if let Some((code, message)) = budget.exceeded() {
                return Err((code, message, ""));
            }
            if self.cancel.cancelled() {
                progress.cancelled = true;
                return Err((E_WRITE_ERROR, String::new(), ""));
            }
            let slice = budget.slice();
            let stream = self
                .stream
                .as_mut()
                .expect("соединение открыто перед чтением");
            stream.set_read_timeout(Some(slice));
            match stream.read(out) {
                Ok(0) => return Ok(0),
                Ok(size) => {
                    budget.mark();
                    return Ok(size);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(read_failure(&error)),
            }
        }
    }

    /// Кусок провода: распаковать и отдать обработчику тела (python `on_body`).
    fn deliver(
        &mut self,
        progress: &mut Progress,
        decoder: &mut WireDecoder,
        chunk: &[u8],
        enough: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), (i32, String, &'static str)> {
        let mut decoded = Vec::new();
        if let Err(message) = decoder.feed(chunk, &mut decoded) {
            return Err((E_RECV, message, ""));
        }
        if decoded.is_empty() {
            return Ok(());
        }
        if on_body(progress, self.cancel.as_ref(), &decoded, enough) == BodyDecision::WriteError {
            return Err((E_WRITE_ERROR, String::new(), ""));
        }
        Ok(())
    }
}

/// Длина тела и кодировка из заголовков ответа.
fn body_framing(header_lines: &[Vec<u8>]) -> (Option<usize>, bool, String) {
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut content_encoding = String::new();
    for line in header_lines {
        let text = String::from_utf8_lossy(line);
        let Some((name, value)) = text.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                if content_length.is_none() {
                    content_length = value.trim().parse::<usize>().ok();
                }
            }
            "transfer-encoding" => {
                chunked = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
            }
            "content-encoding" => content_encoding = value.trim().to_ascii_lowercase(),
            _ => {}
        }
    }
    (content_length, chunked, content_encoding)
}

/// Распаковка сжатого тела (в python это делает libcurl при `decode_body`).
///
/// Рекламируется то же браузерное `Accept-Encoding`; gzip и deflate
/// распаковываются, br и zstd в Rust остаются сжатыми (тело тогда уже не
/// содержимое страницы — различие с python отмечено в docs_migration-map).
struct WireDecoder {
    inflate: Option<flate2::Decompress>,
}

impl WireDecoder {
    fn new(decode_body: bool, content_encoding: &str) -> Self {
        if !decode_body {
            return WireDecoder { inflate: None };
        }
        let inflate = match content_encoding {
            "gzip" => Some(flate2::Decompress::new(true)),
            "deflate" => Some(flate2::Decompress::new(false)),
            _ => None,
        };
        WireDecoder { inflate }
    }

    /// Распаковать кусок в `out`; без распаковки — скопировать как есть.
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        let Some(decompress) = &mut self.inflate else {
            out.extend_from_slice(chunk);
            return Ok(());
        };
        out.reserve(chunk.len() + 64);
        let mut input = chunk;
        while !input.is_empty() {
            let before_in = decompress.total_in();
            let before_out = out.len();
            decompress
                .decompress_vec(input, out, flate2::FlushDecompress::None)
                .map_err(|error| format!("тело не распаковалось: {error}"))?;
            let consumed = (decompress.total_in() - before_in) as usize;
            let produced = out.len() - before_out;
            if consumed == 0 && produced == 0 {
                break;
            }
            input = &input[consumed..];
        }
        Ok(())
    }
}

/// Обратный вызов «читать дальше незачем» (python `body_done`).
type BodyDone<'d> = Option<&'d dyn Fn(&[u8]) -> bool>;

/// python `chrome_get` — GET `https://host/path` по адресу `ip` с
/// рукопожатием и заголовками Chrome.
///
/// `read_limit` — сколько байт тела читать (0 — только заголовок);
/// `read_timeout` — сколько ждать следующих данных, замершее на середине тело
/// видно как `body_cut`; `body_done` получает тело (без заголовков) и говорит,
/// что читать дальше незачем; конец ответа транспорт видит сам.
/// `decode_body` — распаковать сжатое тело (нужно содержимое страницы);
/// размер тогда уже не байты на проводе и для суждения об обрыве по объёму
/// не годится.
#[allow(clippy::too_many_arguments)]
pub fn chrome_get(
    host: &str,
    ip: &str,
    path: &str,
    timeout: f64,
    port: u16,
    read_limit: usize,
    read_timeout: f64,
    body_done: BodyDone<'_>,
    decode_body: bool,
    cancel: Arc<SocketCancel>,
) -> ProbeResult {
    let started = Instant::now();
    if cancel.cancelled() {
        return ProbeResult {
            ip: ip.to_string(),
            kind: KIND_CANCELLED.to_string(),
            stage: STAGE_CONNECT,
            ..ProbeResult::default()
        };
    }
    let mut enough =
        |body: &[u8]| body.len() >= read_limit.max(1) || body_done.is_some_and(|done| done(body));
    let mut connection =
        ChromeConnection::new(host, ip, timeout, port, read_timeout, decode_body, cancel);
    let exchange = connection.request(path, "GET", &mut enough);
    classify(&exchange, connection.cancel.as_ref(), started, ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_like_python() {
        assert_eq!(CHROME_TARGET, "chrome150");
        assert!(WINDOWS_HEADERS[0]
            .starts_with("sec-ch-ua: \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\""));
        assert_eq!(WINDOWS_HEADERS[3], "Upgrade-Insecure-Requests: 1");
        assert!(WINDOWS_HEADERS[4].contains("Chrome/150.0.0.0 Safari/537.36"));
        assert!(WINDOWS_HEADERS[10].contains("zstd"));
        assert_eq!(WINDOWS_HEADERS.len(), 13);
    }

    #[test]
    fn cert_problems_by_word() {
        assert_eq!(
            cert_problem("README: hostname mismatch"),
            "сертификат выдан другому сайту"
        );
        assert_eq!(
            cert_problem("certificate subject does not match"),
            "сертификат выдан другому сайту"
        );
        assert_eq!(
            cert_problem("x name match of z"),
            "сертификат выдан другому сайту"
        );
        assert_eq!(
            cert_problem("cert has expired"),
            "сертификат просрочен или ещё не действует (проверьте часы Windows)"
        );
        assert_eq!(
            cert_problem("self signed certificate"),
            "самодельный сертификат"
        );
        assert_eq!(
            cert_problem("issuer certificate not found"),
            "сертификат выдан неизвестным центром"
        );
        assert_eq!(
            cert_problem("unable to get local issuer"),
            "сертификат выдан неизвестным центром"
        );
        assert_eq!(
            cert_problem("что-то постороннее"),
            "сертификат не прошёл проверку"
        );
    }

    #[test]
    fn debug_seen_stages() {
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_TEXT, b"Try connect to 1.1.1.1...");
        assert!(!progress.tls_started && !progress.secured);
        on_debug(
            &mut progress,
            DEBUG_TEXT,
            b"SSL connection using TLSv1.3 / TLS_AES",
        );
        assert_eq!(progress.tls_version, "TLSv1.3");
        // Замеченный python-порядок: строка «SSL connection using …» уже означает защищённое.
        assert_eq!(
            Exchange {
                progress,
                error_code: 0,
                message: String::new(),
                os_failure: "",
                reconnected: false
            }
            .stage(),
            STAGE_READ
        );
        let mut raw = Progress::new();
        on_debug(&mut raw, DEBUG_SSL_DATA_OUT, &[0u8, 1, 2]);
        assert!(raw.tls_started);
        assert_eq!(
            Exchange {
                progress: raw,
                error_code: 0,
                message: String::new(),
                os_failure: "",
                reconnected: false
            }
            .stage(),
            STAGE_TLS
        );
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
            on_body(&mut progress, &token, b"re", &mut |_body| {
                hit += 1;
                false
            }),
            BodyDecision::Continue
        );
        assert_eq!(hit, 1);
        assert_eq!(progress.body, b"re".to_vec());
        assert_eq!(
            on_body(&mut progress, &token, b"st", &mut |_| true),
            BodyDecision::WriteError
        );
        assert!(progress.stopped_by_us);
        assert!(!progress.cancelled);
        token.cancel();
        assert_eq!(
            on_body(&mut progress, &token, b"x", &mut |_| false),
            BodyDecision::WriteError
        );
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
        exchange = Exchange {
            progress: cut,
            error_code: E_RECV,
            message: "reset".to_string(),
            os_failure: "",
            reconnected: false,
        };
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
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_CONNECT);
        assert_eq!(result.detail, "сервер не отвечает на подключение");
        assert_eq!(result.connect_fail, "timeout");
        // Другой сбой на этапе подключения: «other».
        exchange.error_code = E_COULDNT_CONNECT;
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.connect_fail, "other");

        // Проверка сертификата: kind cert + человеческая причина.
        exchange.error_code = E_PEER_VERIFY;
        exchange.message = "secure connection: certificate has expired".to_string();
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_CERT);
        assert_eq!(
            result.cert_problem,
            "сертификат просрочен или ещё не действует (проверьте часы Windows)"
        );

        // Заголовок пришёл, а тело оборвалось: ok + body_cut.
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_HEADER_OUT, &[0u8]);
        on_header(&mut progress, b"HTTP/2 200\r\n");
        exchange = Exchange {
            progress,
            error_code: E_RECV,
            message: "reset".to_string(),
            os_failure: "",
            reconnected: false,
        };
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_OK);

        // Тихий рукопожатийный сброс.
        let mut progress_clear = Progress::new();
        on_debug(&mut progress_clear, DEBUG_SSL_DATA_OUT, &[0u8]);
        exchange.progress = progress_clear;
        exchange.error_code = E_SSL_CONNECT;
        let result = classify(&exchange, &token, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_TLS);
        exchange.error_code = E_RECV;
        assert_eq!(
            classify(&exchange, &token, started, "10.0.0.1",).kind,
            KIND_RESET
        );
        exchange.error_code = E_HTTP2_STREAM;
        assert_eq!(
            classify(&exchange, &token, started, "10.0.0.1",).kind,
            KIND_RESET
        );
        exchange.error_code = 77;
        assert_eq!(
            classify(&exchange, &token, started, "10.0.0.1",).kind,
            KIND_ERROR
        );

        // «Стоп» mid-запроса — cancelled.
        let stop = SocketCancel::new();
        stop.cancel();
        let mut progress = Progress::new();
        progress.cancelled = true;
        exchange.progress = progress;
        exchange.error_code = 0;
        assert_eq!(
            classify(&exchange, &stop, started, "10.0.0.1",).kind,
            KIND_CANCELLED
        );

        // Отмена после успешного ответа — всё равно вид KIND_OK.
        let cancelled = SocketCancel::new();
        cancelled.cancel();
        let mut progress = Progress::new();
        on_debug(&mut progress, DEBUG_HEADER_OUT, &[0u8]);
        on_header(&mut progress, b"HTTP/2 200\r\n");
        exchange.progress = progress;
        let result = classify(&exchange, &cancelled, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_OK);
        exchange.progress.body = b"partial".to_vec();
        // «Стоп» посреди тела останавливает запись со своей стороны (E_WRITE_ERROR), а не сеть.
        exchange.error_code = E_WRITE_ERROR;
        let result = classify(&exchange, &cancelled, started, "10.0.0.1");
        assert_eq!(result.kind, KIND_CANCELLED);
    }

    // --- Живые проверки на локальных серверах (внешней сети нет) ---

    /// Локальный сервер: принимает одно соединение и действует по сценарию.
    /// Поток с замолкшим сервером оставляем жить — процесс теста его переживёт.
    fn spawn_server(script: impl FnOnce(TcpStream) + Send + 'static) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
        let port = listener.local_addr().expect("адрес").port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                script(stream);
            }
        });
        port
    }

    /// Сценарий «заголовки, потом тело по кускам».
    fn respond(stream: &mut TcpStream, head: &[u8], chunks: &[&[u8]]) {
        let _ = stream.write_all(head);
        for chunk in chunks {
            let _ = stream.write_all(chunk);
            let _ = stream.flush();
        }
    }

    /// Вычитать запрос клиента: без этого закрытие сокета с непрочитанными
    /// данными шлёт RST вместо вежливого конца соединения.
    fn drain(stream: &mut TcpStream) {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer);
    }

    #[test]
    fn plain_http_full_body() {
        let port = spawn_server(|mut stream| {
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
                &[b"hello"],
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let exchange = connection.request("/probe", "GET", &mut enough);
        assert_eq!(exchange.error_code, 0, "{}", exchange.message);
        assert_eq!(exchange.progress.status, Some(200));
        assert_eq!(exchange.progress.body, b"hello".to_vec());
        assert!(exchange.progress.secured);
        assert_eq!(exchange.stage(), STAGE_READ);
        assert!(!exchange.reconnected);
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        assert_eq!(result.kind, KIND_OK);
        assert!(!result.body_cut);
        assert_eq!(result.body_size, 5);
    }

    #[test]
    fn plain_http_enough_stops_mid_body() {
        let port = spawn_server(|mut stream| {
            drain(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nab");
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = stream.write_all(b"cd");
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |body: &[u8]| body.len() >= 3;
        let exchange = connection.request("/probe", "GET", &mut enough);
        // Чтение прервали мы сами — это не сбой (E_WRITE_ERROR при stopped_by_us).
        assert_eq!(exchange.error_code, E_WRITE_ERROR);
        assert!(exchange.progress.stopped_by_us);
        // Тело приходит кусками по мере прихода; чтение остановилось,
        // когда набралось больше трёх байт.
        assert_eq!(exchange.progress.body, b"abcd".to_vec());
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        assert_eq!(result.kind, KIND_OK);
        assert!(!result.body_cut);
    }

    #[test]
    fn plain_http_chunked_and_keepalive() {
        let port = spawn_server(move |mut stream| {
            drain(&mut stream);
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                &[],
            );
            // Второй запрос по тому же соединению (keep-alive).
            drain(&mut stream);
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nagain",
                &[],
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let first = connection.request("/probe", "GET", &mut enough);
        assert_eq!(first.error_code, 0, "{}", first.message);
        assert_eq!(first.progress.body, b"hello world".to_vec());
        assert!(!first.reconnected);
        let second = connection.request("/probe", "GET", &mut enough);
        assert_eq!(second.error_code, 0, "{}", second.message);
        assert_eq!(second.progress.status, Some(200));
        assert_eq!(second.progress.body, b"again".to_vec());
        // Соединение не переоткрывалось: запросы идут по одному потоку.
        assert!(!second.reconnected);
    }

    #[test]
    fn plain_http_stall_mid_body_is_body_cut() {
        let port = spawn_server(|mut stream| {
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nabc",
                &[],
            );
            // Тело замерло: дальше сервер молчит.
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            0.3,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let exchange = connection.request("/probe", "GET", &mut enough);
        assert_eq!(exchange.error_code, E_TIMEOUT, "{}", exchange.message);
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        // Заголовок пришёл — исход «ответ есть», но оборвался посреди тела.
        assert_eq!(result.kind, KIND_OK);
        assert!(result.body_cut);
        assert_eq!(result.body_size, 3);
    }

    #[test]
    fn plain_http_reset_mid_body_is_body_cut() {
        let port = spawn_server(|mut stream| {
            drain(&mut stream);
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab",
                &[],
            );
            // Соединение оборвали посреди тела: вежливый конец (FIN), а не RST —
            // нечитанных данных на сервере уже нет.
            drop(stream);
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let exchange = connection.request("/probe", "GET", &mut enough);
        assert_eq!(exchange.error_code, E_PARTIAL_FILE, "{}", exchange.message);
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        assert_eq!(result.kind, KIND_OK);
        assert!(result.body_cut);
    }

    #[test]
    fn plain_http_close_without_answer() {
        let port = spawn_server(|mut stream| {
            // Вычитать запрос, иначе закрытие уйдёт RST-ом вместо тихого конца.
            drain(&mut stream);
            // Ответа нет вовсе: сервер сразу закрыл соединение.
            drop(stream);
        });
        let cancel = Arc::new(SocketCancel::new());
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let exchange = connection.request("/probe", "GET", &mut enough);
        assert_eq!(exchange.error_code, E_GOT_NOTHING, "{}", exchange.message);
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        assert_eq!(result.kind, KIND_RESET);
        // Деталь «сервер закрыл соединение без ответа» в python звучит при коде 0;
        // libcurl в этом случае даёт код 52 с текстом — вид исхода тот же.
    }

    #[test]
    fn plain_http_cancel_mid_body() {
        let port = spawn_server(|mut stream| {
            respond(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nabc",
                &[],
            );
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        let cancel = Arc::new(SocketCancel::new());
        let stopped = Arc::clone(&cancel);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            stopped.cancel();
        });
        let mut connection = ChromeConnection::insecure_http_for_tests(
            "example.test",
            "127.0.0.1",
            5.0,
            port,
            3.0,
            Arc::clone(&cancel),
        );
        let mut enough = |_body: &[u8]| false;
        let exchange = connection.request("/probe", "GET", &mut enough);
        assert!(exchange.progress.cancelled);
        let result = classify(&exchange, cancel.as_ref(), Instant::now(), "127.0.0.1");
        assert_eq!(result.kind, KIND_CANCELLED);
        assert!(!result.body_cut);
    }

    #[test]
    fn chrome_get_connect_refused() {
        // Сокет ещё не открыт: адрес сам отказал.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
        let port = listener.local_addr().expect("адрес").port();
        drop(listener);
        let result = chrome_get(
            "example.test",
            "127.0.0.1",
            "/probe",
            2.0,
            port,
            0,
            1.0,
            None,
            false,
            Arc::new(SocketCancel::new()),
        );
        assert_eq!(result.kind, KIND_CONNECT, "{}", result.detail);
        assert_eq!(result.connect_fail, "refused");
        assert_eq!(result.stage, STAGE_CONNECT);
    }

    #[test]
    fn chrome_get_cancelled_before_start() {
        let cancel = Arc::new(SocketCancel::new());
        cancel.cancel();
        let result = chrome_get(
            "example.test",
            "127.0.0.1",
            "/probe",
            2.0,
            443,
            0,
            1.0,
            None,
            false,
            cancel,
        );
        assert_eq!(result.kind, KIND_CANCELLED);
        assert_eq!(result.stage, STAGE_CONNECT);
    }

    #[test]
    fn tls_handshake_silence_is_timeout() {
        // Сервер принимает TCP, но не отвечает на рукопожатие: шифрование
        // не установилось, исход — тишина на этапе рукопожатия.
        let port = spawn_server(|stream| {
            // Молчим, держа соединение открытым.
            let _ = stream;
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        let result = chrome_get(
            "example.test",
            "127.0.0.1",
            "/probe",
            0.6,
            port,
            0,
            1.0,
            None,
            false,
            Arc::new(SocketCancel::new()),
        );
        assert_eq!(result.kind, KIND_TIMEOUT, "{}", result.detail);
        assert_eq!(result.stage, STAGE_TLS);
    }

    #[test]
    fn tls_unknown_certificate_is_cert_kind() {
        // Самоподписанный сертификат: рукопожатие состояться не должно,
        // исход — «cert» с человеческой причиной.
        use rustls::ServerConfig;

        let certified = rcgen::generate_simple_self_signed(vec!["example.test".to_string()])
            .expect("сертификат сгенерирован");
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("версии TLS доступны")
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        certified.key_pair.serialize_der().into(),
                    ),
                )
                .expect("конфиг сервера собран"),
        );
        let port = spawn_server(move |mut stream| {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
            let mut server = match rustls::ServerConnection::new(Arc::clone(&server_config)) {
                Ok(server) => server,
                Err(_) => return,
            };
            // Рукопожатие по локальному сокету; клиент откажет от сертификата.
            for _ in 0..10 {
                match server.complete_io(&mut stream) {
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
        });
        let result = chrome_get(
            "example.test",
            "127.0.0.1",
            "/probe",
            5.0,
            port,
            0,
            1.0,
            None,
            false,
            Arc::new(SocketCancel::new()),
        );
        assert_eq!(result.kind, KIND_CERT, "{}", result.detail);
        assert_eq!(result.cert_problem, "сертификат выдан неизвестным центром");
        assert_eq!(result.stage, STAGE_TLS);
    }

    #[test]
    fn request_head_is_browser_shaped() {
        let cancel = Arc::new(SocketCancel::new());
        let connection = ChromeConnection::new(
            "example.test",
            "127.0.0.1",
            5.0,
            8443,
            3.0,
            false,
            Arc::clone(&cancel),
        );
        let head = connection.request_head("/probe", "GET");
        assert!(head.starts_with("GET /probe HTTP/1.1\r\n"));
        assert!(head.contains("Host: example.test:8443\r\n"));
        for header in WINDOWS_HEADERS {
            assert!(head.contains(header), "нет заголовка: {header}");
        }
        assert!(head.ends_with("\r\n\r\n"));
        // Порт по умолчанию в Host не пишется — как у браузера.
        let connection_443 =
            ChromeConnection::new("example.test", "127.0.0.1", 5.0, 443, 3.0, false, cancel);
        assert!(connection_443
            .request_head("/", "GET")
            .contains("Host: example.test\r\n"));
    }
}
