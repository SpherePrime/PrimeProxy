//! Порт `src/diagnostics/block_cause.py` — почему сайт не открылся: уточнение
//! причины дополнительными пробами.
//!
//! Основная проверка (`probe_result`) говорит, на какой ступени оборвалось
//! соединение. Этого мало, чтобы понять, **как** блокируют: по имени сайта или
//! по адресу. В python делаются три дешёвые пробы к тому же адресу: SNI с
//! посторонним именем, HTTP порт 80, пинг. Здесь — чистая часть (состав проб,
//! сравнение фактов, вывод `judge`) и сбор: `tls_hello` — шифрованное
//! соединение без проверки сертификата (важно одно — ответил ли сервер
//! вообще), `http_probe` — обычный порт 80, `collect` — пробы разом.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;
use rustls::pki_types::ServerName;

use crate::probe_result::{
    ProbeResult, KIND_CONNECT, KIND_RESET, KIND_TIMEOUT, KIND_TLS, STAGE_CONNECT, STAGE_TLS,
};
use crate::run_context::{Run, TaskError};

pub const CAUSE_STUB_PAGE: &str = "stub_page";
pub const CAUSE_BY_NAME: &str = "by_name";
/// К адресу пускают только имена из разрешённого списка.
pub const CAUSE_NAME_WHITELIST: &str = "name_whitelist";
pub const CAUSE_BY_ADDRESS: &str = "by_address";
/// Ни одно имя не прошло, но часть проб сброшена: адрес это или сам сервер — не ясно.
pub const CAUSE_NO_NAME_WORKS: &str = "no_name_works";
pub const CAUSE_ADDRESS_CLOSED: &str = "address_closed";
pub const CAUSE_ADDRESS_SILENT: &str = "address_silent";

pub const NEUTRAL_NAME: &str = "example.com";
pub const ALLOWED_NAME: &str = "vk.com";
pub const ALLOWED_NAMES: [&str; 3] = ["max.ru", "ya.ru", ALLOWED_NAME];

pub const HELLO_TIMEOUT_S: f64 = 4.0;
pub const HTTP_TIMEOUT_S: f64 = 4.0;
pub const STAGGER_S: f64 = 0.25;
/// Шаг между пробами одного сайта, чтобы не ставить фильтр в известность пачкой.
pub const HTTP_READ_LIMIT: usize = 4096;
const STATUS_UNAVAILABLE_FOR_LEGAL_REASONS: i64 = 451;

/// Страницы-заглушки операторов: куда уводит перенаправление.
const STUB_HOSTS: [&str; 5] = [
    "warning.rt.ru",
    "block.mts.ru",
    "blocked.beeline.ru",
    "block.megafon.ru",
    "rkn.gov.ru",
];

/// Признаки в тексте страницы. Только такие, которых на обычном сайте не бывает:
/// слова вроде «заблокирован» встречаются и на обычных страницах.
const STUB_MARKERS: [&str; 3] = ["eais.rkn.gov.ru", "blocklist.rkn.gov.ru", "nap.rkn.gov.ru"];

/// Номер закона встречается и на обычных страницах (новости, справки), поэтому
/// сам по себе признаком не считается — только вместе со словами об ограничении доступа.
const LAW_MARKERS: [&str; 2] = ["149-фз", "149-fz"];
const RESTRICTED_MARKERS: [&str; 4] = [
    "доступ ограничен",
    "доступ к ресурсу ограничен",
    "доступ к информационному ресурсу ограничен",
    "доступ закрыт",
];

/// Версии шифрования простых приветствий (python `TLS_1_2` / `TLS_1_3`).
pub const TLS_1_2: &str = "1.2";
pub const TLS_1_3: &str = "1.3";
/// Любая версия, на какую сервер согласится (для cert_owner и тестов).
pub const TLS_ANY: &str = "any";

/// Результат простого приветствия (`HELLO_*`): вид исхода, подпись, время.
pub const HELLO_OK: &str = "ok"; // шифрование установилось
pub const HELLO_ALERT: &str = "alert"; // сервер отказал сам — но ответил
pub const HELLO_RESET: &str = "reset";
pub const HELLO_TIMEOUT: &str = "timeout";
pub const HELLO_CONNECT: &str = "connect"; // не удалось даже соединиться
pub const HELLO_GARBAGE: &str = "garbage"; // пришло не шифрование: ответил не сервер
pub const HELLO_CANCELLED: &str = "cancelled";
pub const HELLO_ERROR: &str = "error"; // ошибка, которую не удалось истолковать

/// python `HelloResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct HelloResult {
    pub kind: String,
    pub detail: String,
    /// За сколько установилось шифрование. None — не установилось.
    pub ms: Option<f64>,
}

impl HelloResult {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            detail: String::new(),
            ms: None,
        }
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
    pub fn with_ms(mut self, ms: f64) -> Self {
        self.ms = Some(ms);
        self
    }
    /// Сервер по этому адресу ответил — значит, дорога до него открыта.
    pub fn answered(&self) -> bool {
        self.kind == HELLO_OK || self.kind == HELLO_ALERT
    }
}

/// python `HttpFacts` — что ответил порт 80. `status` None — ответа не было.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpFacts {
    pub status: Option<i64>,
    pub location: String,
    pub body: Vec<u8>,
}

/// python `CauseFacts` — всё, что удалось узнать дополнительно. Выводов здесь нет.
#[derive(Debug, Clone, Default)]
pub struct CauseFacts {
    pub host: String,
    pub result: Option<ProbeResult>,
    pub neutral: Option<HelloResult>,
    pub nameless: Option<HelloResult>,
    /// То же, но с именем, которое провайдеры заведомо пропускают (`ALLOWED_NAME`).
    pub allowed: Option<HelloResult>,
    /// С каким из разрешённых имён получен `allowed`.
    pub allowed_name: String,
    /// Настоящее имя ещё раз, на том же адресе. None — не проверяли.
    pub real_again: Option<HelloResult>,
    pub http: Option<HttpFacts>,
    /// None — пинг не делали или он недоступен в системе.
    pub ping_ok: Option<bool>,
}

/// python `Cause`. Уверенный вывод опирается на прямое противоречие, а не на отсутствие ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cause {
    pub code: String,
    pub text: String,
    pub confident: bool,
}

impl Cause {
    pub fn new(code: impl Into<String>, text: impl Into<String>, confident: bool) -> Self {
        Self {
            code: code.into(),
            text: text.into(),
            confident,
        }
    }
}

/// python `_same_site(host, other)` — связаны ли имена одним доменом.
pub fn same_site(host: &str, other: &str) -> bool {
    let clean = |value: &str| value.to_lowercase().trim_end_matches('.').to_string();
    let host = clean(host);
    let other = clean(other);
    other == host || other.ends_with(&format!(".{host}")) || host.ends_with(&format!(".{other}"))
}

/// python `urlsplit(location).hostname` — имя узла из Location: `_scheme://host[:port]/path`.
pub fn location_host(location: &str) -> Option<String> {
    let rest = location
        .split_once("://")
        .map_or(location, |(_scheme, rest)| rest);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = rest
        .split_once('@')
        .map_or(rest, |(_credentials, authority)| authority);
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(inside, _)| inside)
            .unwrap_or(authority)
    } else {
        authority
    };
    // IPv4-хост с портом: `host:port` → `host`. Для IPv6 в скобках порт отсечён выше.
    if let Some((bare, port)) = host.rsplit_once(':') {
        if !bare.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some(bare.to_lowercase());
        }
    }
    if host.trim().is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// python `stub_reason(host, facts)` — почему ответ порта 80 — страница о блокировке.
/// Пусто, если это обычный ответ.
pub fn stub_reason(host: &str, facts: Option<&HttpFacts>) -> String {
    let Some(facts) = facts else {
        return String::new();
    };
    let Some(status) = facts.status else {
        return String::new();
    };
    if status == STATUS_UNAVAILABLE_FOR_LEGAL_REASONS {
        return "код 451 «недоступно по юридическим причинам»".to_string();
    }
    let target = if facts.location.is_empty() {
        String::new()
    } else {
        location_host(&facts.location)
            .map(|host| host.to_lowercase())
            .unwrap_or_default()
    };
    if !target.is_empty() && !same_site(host, &target) {
        for stub in STUB_HOSTS {
            if target == stub || target.ends_with(&format!(".{stub}")) {
                return format!("перенаправление на страницу о блокировке {target}");
            }
        }
    }
    // Страницы провайдеров бывают в обеих кодировках, а регистр букв — любой.
    // python декодирует тело в utf-8 и cp1251; для кириллических признаков это
    // важно и делается в TLS-порте, здесь пробуем только utf-8 (lossy).
    let lower = String::from_utf8_lossy(&facts.body).to_lowercase();
    for marker in STUB_MARKERS {
        if lower.contains(marker) {
            return "страница со ссылкой на реестр блокировок".to_string();
        }
    }
    for law in LAW_MARKERS {
        if lower.contains(law) {
            for restricted in RESTRICTED_MARKERS {
                if lower.contains(restricted) {
                    return "страница об ограничении доступа по закону 149-ФЗ".to_string();
                }
            }
        }
    }
    String::new()
}

/// python `needs_refining(result)` — есть ли что уточнять: соединение не
/// состоялось или оборвалось на шифровании.
pub fn needs_refining(result: Option<&ProbeResult>) -> bool {
    let Some(result) = result else { return false };
    if result.ip.is_empty() {
        return false;
    }
    if result.kind == KIND_CONNECT {
        return true;
    }
    // reset/timeout/tls на этапе tls — рукопожатие началось, но оборвалось:
    // соединение-то было. Python проверяет `result.kind in (…) and stage == STAGE_TLS`;
    // приоритет в python: сначала CONNECT, потом-triple с этапом tls.
    (result.kind == KIND_RESET || result.kind == KIND_TIMEOUT) && result.stage == STAGE_TLS
        || (result.kind == KIND_TLS && result.stage == STAGE_TLS)
}

fn how(result: &ProbeResult) -> &'static str {
    if result.kind == KIND_TIMEOUT {
        "молча пропадает"
    } else {
        "обрывается"
    }
}

/// python `judge(facts)` — вывод о способе блокировки или None, если фактов для него не хватает.
pub fn judge(facts: &CauseFacts) -> Option<Cause> {
    let stub = stub_reason(&facts.host, facts.http.as_ref());
    if !stub.is_empty() {
        return Some(Cause::new(
            CAUSE_STUB_PAGE,
            format!("провайдер показывает страницу о блокировке: {stub}"),
            true,
        ));
    }

    let result = facts.result.as_ref()?;
    if result.kind == KIND_CONNECT && result.stage == STAGE_CONNECT {
        if let Some(http) = facts.http.as_ref() {
            if http.status.is_some() {
                // Тот же адрес ответил по обычному порту: сервер жив, дорога до него есть.
                // Наблюдение, а не вывод: так выглядит и закрытый порт, и чужой адрес из hosts.
                return Some(Cause::new(
                    CAUSE_ADDRESS_CLOSED,
                    "тот же адрес отвечает по обычному порту 80, а соединение с портом 443 не устанавливается",
                    false,
                ));
            }
        }
        if facts.ping_ok == Some(true) {
            return Some(Cause::new(
                CAUSE_ADDRESS_CLOSED,
                "адрес отвечает на пинг, но соединение с портом 443 не устанавливается",
                false,
            ));
        }
        if facts.ping_ok == Some(false) {
            return Some(Cause::new(
                CAUSE_ADDRESS_SILENT,
                "адрес не отвечает совсем — ни на соединение, ни на пинг",
                false,
            ));
        }
        return None;
    }

    let hellos: Vec<HelloResult> = facts
        .neutral
        .iter()
        .chain(facts.nameless.iter())
        .filter(|item| item.kind != HELLO_CANCELLED)
        .cloned()
        .collect();
    if hellos.is_empty() {
        return None;
    }
    // Сервер сам отказал на настоящее имя — тогда его отказ на постороннее ничего не
    // доказывает: он просто так отвечает. Сравнение честно, только когда с
    // настоящим именем соединение рвётся или молчит, а с другим — есть ответ.
    let refused_by_server = result.kind == KIND_TLS;
    let passed: Vec<HelloResult> = hellos
        .iter()
        .filter(|item| item.kind == HELLO_OK || (item.answered() && !refused_by_server))
        .cloned()
        .collect();
    if !passed.is_empty() {
        let again = facts.real_again.as_ref();
        if again.is_some_and(|item| item.kind == HELLO_OK) {
            // Со второго раза настоящее имя прошло: первый обрыв был сбоем, сравнивать нечего.
            return None;
        }
        let neutral_passed = facts
            .neutral
            .as_ref()
            .map(|item| passed.contains(item))
            .unwrap_or(false);
        let other = if neutral_passed {
            "с посторонним именем"
        } else {
            "без имени"
        };
        let repeated =
            again.is_some_and(|item| item.kind == HELLO_RESET || item.kind == HELLO_TIMEOUT);
        return Some(Cause::new(
            CAUSE_BY_NAME,
            format!(
                "блокировка по имени сайта: с именем {host} соединение {how}{tail}, а {other} тот же сервер отвечает",
                host = facts.host,
                how = how(result),
                tail = if repeated { " (дважды подряд)" } else { "" },
            ),
            // Не проверяли повторно (старые данные) — верим первому сравнению; повтор не дал ясного ответа — нет.
            facts.real_again.is_none() || repeated,
        ));
    }
    if facts
        .real_again
        .as_ref()
        .is_some_and(|item| item.kind == HELLO_OK)
    {
        // Простое приветствие с настоящим именем проходит: ни имя, ни адрес не закрыты. Рвут само
        // соединение основной проверки — например, по почерку браузера (строка «Как Chrome»).
        return None;
    }
    if let Some(allowed) = facts.allowed.as_ref() {
        if allowed.answered() {
            // Постороннее имя не прошло, а разрешённое прошло: к этому адресу пускают только
            // имена из списка. Это тоже блокировка по имени, а не закрытый адрес.
            return Some(Cause::new(
                CAUSE_NAME_WHITELIST,
                format!(
                    "к этому адресу проходят только разрешённые имена: с именем {} сервер отвечает, \
                     а с именем {} и с посторонним — нет",
                    if facts.allowed_name.is_empty() { ALLOWED_NAME } else { &facts.allowed_name },
                    facts.host
                ),
                true,
            ));
        }
    }
    let mut probes: Vec<HelloResult> = hellos.clone();
    if let Some(allowed) = facts.allowed.as_ref() {
        if allowed.kind != HELLO_CANCELLED {
            probes.push(allowed.clone());
        }
    }
    let checked = if facts.allowed.as_ref().is_some_and(|item| !item.answered()) {
        "ни с каким именем, даже с разрешённым"
    } else {
        "ни с каким именем"
    };
    if probes.iter().all(|item| item.kind == HELLO_TIMEOUT) {
        // Тишина на любое имя — так молчит фильтр. Сервер, который сам не принимает
        // чужие имена, отвечает отказом или сбросом, а не молчанием.
        return Some(Cause::new(
            CAUSE_BY_ADDRESS,
            format!(
                "соединение с адресом устанавливается, а шифрование — {checked}: ответа нет вовсе. Похоже, закрыт сам \
                 адрес или вся его сеть (так выглядит и режим «белых списков» адресов), а не имя сайта",
            ),
            false,
        ));
    }
    if probes
        .iter()
        .all(|item| item.kind == HELLO_RESET || item.kind == HELLO_TIMEOUT)
    {
        return Some(Cause::new(
            CAUSE_NO_NAME_WORKS,
            format!(
                "шифрование не устанавливается {checked}: закрыт адрес или сервер сам сбрасывает \
                 соединения с чужими именами — по этим пробам не отличить",
            ),
            false,
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Транспорт: tls_hello, http_probe и сбор проб
// ---------------------------------------------------------------------------

/// Как часто при чтении между отрезками проверяется «Стоп».
const POLL_SLICE_S: f64 = 0.2;

/// Проверки сертификата здесь нет: с посторонним именем сервер и должен
/// предъявить «не тот», важно одно — ответил ли он вообще (python
/// `check_hostname = False, verify_mode = CERT_NONE`).
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<rustls::SignatureScheme>,
}

impl NoVerify {
    fn new(provider: &Arc<rustls::crypto::CryptoProvider>) -> Self {
        NoVerify {
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// python `_hello_context` — клиент приветствия: без проверки сертификата,
/// ALPN `http/1.1`; `version` — только эта версия шифрования. Клиенты живут
/// один раз на процесс (создание небыстрое).
fn hello_config(version: &str) -> Arc<rustls::ClientConfig> {
    static ANY: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static TLS12: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static TLS13: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let build = |versions: &[&'static rustls::SupportedProtocolVersion]| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .expect("версии TLS доступны")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify::new(&provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    };
    match version {
        TLS_1_2 => TLS12.get_or_init(|| build(&[&rustls::version::TLS12])),
        TLS_1_3 => TLS13.get_or_init(|| build(&[&rustls::version::TLS13])),
        _ => ANY.get_or_init(|| build(rustls::DEFAULT_VERSIONS)),
    }
    .clone()
}

/// python `_hello_failure` — сбой на приветствии: ответивший сервер или мусор.
fn hello_failure(error: &rustls::Error) -> HelloResult {
    let text = error.to_string().to_uppercase();
    if text.contains("ALERT")
        || text.contains("UNRECOGNIZED_NAME")
        || text.contains("HANDSHAKE_FAILURE")
    {
        return HelloResult::new(HELLO_ALERT).with_detail(error.to_string());
    }
    if text.contains("WRONG_VERSION_NUMBER")
        || text.contains("UNKNOWN_PROTOCOL")
        || text.contains("RECORD_LAYER")
        || text.contains("CORRUPT MESSAGE")
        || text.contains("INVALID_MESSAGE")
    {
        return HelloResult::new(HELLO_GARBAGE).with_detail(error.to_string());
    }
    // Незнакомая ошибка шифрования — это «не поняли», а не «ответил чужой сервер».
    HelloResult::new(HELLO_ERROR).with_detail(error.to_string())
}

/// python `tls_hello` — начинает шифрованное соединение с `ip`, называя имя
/// `name` (None — без имени). `version` — только этой версией шифрования.
pub fn tls_hello(
    ip: &str,
    name: Option<&str>,
    port: u16,
    timeout: f64,
    cancel: &SocketCancel,
    version: &str,
) -> HelloResult {
    let started = Instant::now();
    match tls_stream(ip, name, port, timeout, cancel, version) {
        Ok(_) => HelloResult::new(HELLO_OK).with_ms(started.elapsed().as_secs_f64() * 1000.0),
        Err(result) => result,
    }
}

/// Установленное шифрованное соединение — для тех, кому нужен сам канал
/// (`cert_owner::collect` читает из него сертификат сервера). Ошибка —
/// `HelloResult` с причиной сбоя.
pub fn tls_stream(
    ip: &str,
    name: Option<&str>,
    port: u16,
    timeout: f64,
    cancel: &SocketCancel,
    version: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, HelloResult> {
    if cancel.cancelled() {
        return Err(HelloResult::new(HELLO_CANCELLED));
    }
    let config = hello_config(version);
    // python: AF_INET6, если адрес с двоеточием.
    let address = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };
    let target = match address.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(target) => target,
            None => return Err(HelloResult::new(HELLO_CONNECT)),
        },
        Err(_) => return Err(HelloResult::new(HELLO_CONNECT)),
    };
    let stream = match TcpStream::connect_timeout(&target, Duration::from_secs_f64(timeout)) {
        Ok(stream) => stream,
        Err(error) => {
            if cancel.cancelled() {
                return Err(HelloResult::new(HELLO_CANCELLED));
            }
            // До соединения дело не дошло — это не сбой дороги.
            return Err(HelloResult::new(HELLO_CONNECT).with_detail(error.to_string()));
        }
    };
    let server_name = match ServerName::try_from(name.unwrap_or(ip).to_string()) {
        Ok(name) => name,
        Err(_) => return Err(HelloResult::new(HELLO_CONNECT)),
    };
    // Клиент готовится до отсчёта времени: его создание бывает небыстрым.
    let connection = match rustls::ClientConnection::new(config, server_name) {
        Ok(connection) => connection,
        Err(error) => return Err(hello_failure(&error)),
    };
    let mut secured = rustls::StreamOwned::new(connection, stream);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.2));
    loop {
        if cancel.cancelled() {
            return Err(HelloResult::new(HELLO_CANCELLED));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HelloResult::new(HELLO_TIMEOUT));
        }
        let slice = remaining.min(Duration::from_secs_f64(POLL_SLICE_S));
        let _ = secured.sock.set_read_timeout(Some(slice));
        let _ = secured.sock.set_write_timeout(Some(slice));
        match secured.conn.complete_io(&mut secured.sock) {
            Ok(_) => return Ok(secured),
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
                if cancel.cancelled() {
                    return Err(HelloResult::new(HELLO_CANCELLED));
                }
                return Err(
                    match error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                    {
                        Some(tls_error) => hello_failure(tls_error),
                        None => match error.kind() {
                            std::io::ErrorKind::UnexpectedEof => HelloResult::new(HELLO_RESET)
                                .with_detail("соединение закрыто на приветствии"),
                            std::io::ErrorKind::TimedOut => HelloResult::new(HELLO_TIMEOUT),
                            _ => HelloResult::new(HELLO_RESET).with_detail(error.to_string()),
                        },
                    },
                );
            }
        }
    }
}

/// python `http_probe` — `GET http://host/` по адресу `ip`: код ответа, куда
/// перенаправили и начало страницы.
pub fn http_probe(
    host: &str,
    ip: &str,
    port: u16,
    timeout: f64,
    cancel: &SocketCancel,
) -> HttpFacts {
    if cancel.cancelled() {
        return HttpFacts::default();
    }
    let address = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };
    let target = match address.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(target) => target,
            None => return HttpFacts::default(),
        },
        Err(_) => return HttpFacts::default(),
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&target, Duration::from_secs_f64(timeout))
    else {
        return HttpFacts::default();
    };
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return HttpFacts::default();
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.2));
    let mut data = Vec::with_capacity(HTTP_READ_LIMIT);
    while data.len() < HTTP_READ_LIMIT {
        if cancel.cancelled() {
            return HttpFacts::default();
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining.min(Duration::from_secs_f64(POLL_SLICE_S))));
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => {
                let left = HTTP_READ_LIMIT - data.len();
                data.extend_from_slice(&chunk[..size.min(left)]);
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
            Err(_) => break,
        }
    }
    if cancel.cancelled() {
        return HttpFacts::default();
    }
    parse_http_facts(&data)
}

/// Разбор ответа порта 80 (python: разрез по пустой строке, статус из первой
/// строки, `Location` из заголовков, тело — что после заголовков).
fn parse_http_facts(data: &[u8]) -> HttpFacts {
    let (head, body) = match data.windows(4).position(|part| part == b"\r\n\r\n") {
        Some(split) => (&data[..split], &data[split + 4..]),
        None => (data, &b""[..]),
    };
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split_ascii_whitespace();
    let Some(first) = parts.next() else {
        return HttpFacts::default();
    };
    let Some(second) = parts.next() else {
        return HttpFacts::default();
    };
    if !first.starts_with("HTTP/")
        || second.is_empty()
        || !second.chars().all(|c| c.is_ascii_digit())
    {
        return HttpFacts::default();
    }
    let status = second.parse::<i64>().ok();
    let mut location = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                location = value.trim().to_string();
            }
        }
    }
    HttpFacts {
        status,
        location,
        body: body.to_vec(),
    }
}

/// python `later` — вызов через `delay` секунд; «Стоп» ждать не заставляет.
fn later_hello(
    delay: f64,
    ip: String,
    name: Option<String>,
    port: u16,
    timeout: f64,
    cancel: Arc<SocketCancel>,
    version: &'static str,
) -> impl FnOnce() -> Result<HelloResult, TaskError> + Send + 'static {
    move || {
        cancel.sleep(delay);
        Ok(tls_hello(
            &ip,
            name.as_deref(),
            port,
            timeout,
            &cancel,
            version,
        ))
    }
}

/// python `block_cause.collect(host, result, submit, cancel, ping)` —
/// дополнительные пробы к адресу, на котором сайт не открылся; идут
/// одновременно (через машину прогона), приветствия — с шагом.
#[allow(clippy::type_complexity)]
pub fn collect(
    host: &str,
    result: &ProbeResult,
    run: &Arc<Run>,
    ping: Option<&Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>>,
) -> Result<CauseFacts, TaskError> {
    let cancel = Arc::clone(&run.probe_cancel);
    let ip = result.ip.clone();
    let http_job = {
        let host = host.to_string();
        let ip = ip.clone();
        let cancel = Arc::clone(&cancel);
        run.submit(move || Ok(http_probe(&host, &ip, 80, HTTP_TIMEOUT_S, &cancel)))
    };
    if result.kind == KIND_CONNECT {
        let ping_job = ping.map(|ping| {
            let ip = ip.clone();
            let ping = Arc::clone(ping);
            run.submit(move || Ok(ping(&ip)))
        });
        let http = run.wait(&http_job)?;
        let ping_ok = match &ping_job {
            Some(job) => run.wait(job)?,
            None => None,
        };
        return Ok(CauseFacts {
            host: host.to_string(),
            result: Some(result.clone()),
            http: Some(http),
            ping_ok,
            ..CauseFacts::default()
        });
    }
    let neutral = run.submit({
        let ip = ip.clone();
        let cancel = Arc::clone(&cancel);
        move || {
            Ok(tls_hello(
                &ip,
                Some(NEUTRAL_NAME),
                443,
                HELLO_TIMEOUT_S,
                &cancel,
                "",
            ))
        }
    });
    let nameless = run.submit(later_hello(
        STAGGER_S,
        ip.clone(),
        None,
        443,
        HELLO_TIMEOUT_S,
        Arc::clone(&cancel),
        "",
    ));
    let mut allowed_jobs = Vec::with_capacity(ALLOWED_NAMES.len());
    for (index, name) in ALLOWED_NAMES.iter().enumerate() {
        allowed_jobs.push((
            (*name).to_string(),
            run.submit(later_hello(
                (2 + index) as f64 * STAGGER_S,
                ip.clone(),
                Some((*name).to_string()),
                443,
                HELLO_TIMEOUT_S,
                Arc::clone(&cancel),
                "",
            )),
        ));
    }
    // Настоящее имя ещё раз: один сбой — не сравнение. Вывод «по имени»
    // уверенный, только если оно оборвалось и теперь, пока постороннее имя
    // проходит.
    let real_again = run.submit(later_hello(
        (2 + ALLOWED_NAMES.len()) as f64 * STAGGER_S,
        ip.clone(),
        Some(host.to_string()),
        443,
        HELLO_TIMEOUT_S,
        Arc::clone(&cancel),
        "",
    ));
    let neutral = run.wait(&neutral)?;
    let nameless = run.wait(&nameless)?;
    let mut answers = Vec::with_capacity(allowed_jobs.len());
    for (name, job) in allowed_jobs {
        answers.push((name, run.wait(&job)?));
    }
    let (allowed_name, allowed) = answers
        .iter()
        .find(|(_name, result)| result.answered())
        .map(|(name, result)| (name.clone(), Some(result.clone())))
        .unwrap_or_else(|| {
            let (name, result) = answers.last().expect("разрешённые имена есть");
            (name.clone(), Some(result.clone()))
        });
    let real_again = run.wait(&real_again)?;
    let http = run.wait(&http_job)?;
    Ok(CauseFacts {
        host: host.to_string(),
        result: Some(result.clone()),
        neutral: Some(neutral),
        nameless: Some(nameless),
        allowed,
        allowed_name,
        real_again: Some(real_again),
        http: Some(http),
        ping_ok: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(ip: &str, kind: &str, stage: &'static str) -> ProbeResult {
        ProbeResult {
            ip: ip.to_string(),
            kind: kind.to_string(),
            stage,
            ..Default::default()
        }
    }

    fn facts(base: ProbeResult, mut setup: impl FnMut(&mut CauseFacts)) -> Option<Cause> {
        let mut value = CauseFacts {
            host: "site.example".to_string(),
            result: Some(base.clone()),
            ..Default::default()
        };
        setup(&mut value);
        judge(&value)
    }

    #[test]
    fn same_site_and_hosts() {
        assert!(same_site("Ya.Ru.", "ya.ru"));
        assert!(same_site("a.ya.ru", "ya.ru"));
        assert!(!same_site("maya.ru", "ya.ru"));
        assert_eq!(
            location_host("http://warning.rt.ru/x?y"),
            Some("warning.rt.ru".to_string())
        );
        assert_eq!(
            location_host("https://user:pw@block.mts.ru:443/"),
            Some("block.mts.ru".to_string())
        );
        assert_eq!(location_host("/relative"), None);
    }

    #[test]
    fn stub_page_marks() {
        let http = HttpFacts {
            status: Some(451),
            location: String::new(),
            body: b"<?xml?>".to_vec(),
        };
        assert_eq!(
            stub_reason("site.example", Some(&http)),
            "код 451 «недоступно по юридическим причинам»"
        );
        let redirect = HttpFacts {
            status: Some(302),
            location: "http://warning.rt.ru/".to_string(),
            body: Vec::new(),
        };
        assert_eq!(
            stub_reason("site.example", Some(&redirect)),
            "перенаправление на страницу о блокировке warning.rt.ru"
        );
        let registry = HttpFacts {
            status: Some(200),
            location: String::new(),
            body: "EAIS.RKN.GOV.RU реестр".as_bytes().to_vec(),
        };
        assert_eq!(
            stub_reason("site.example", Some(&registry)),
            "страница со ссылкой на реестр блокировок"
        );
        assert_eq!(stub_reason("site.example", None), "");
    }

    #[test]
    fn needs_refining_cases() {
        assert!(!needs_refining(None));
        assert!(!needs_refining(Some(&probe("", "connect", "connect"))));
        assert!(needs_refining(Some(&probe(
            "1.2.3.4", "connect", "connect"
        ))));
        assert!(needs_refining(Some(&probe("1.2.3.4", "reset", "tls"))));
        assert!(!needs_refining(Some(&probe("1.2.3.4", "reset", "read"))));
        assert!(needs_refining(Some(&probe("1.2.3.4", "tls", "tls"))));
    }

    #[test]
    fn judge_by_name_and_by_address() {
        // Базовая проверка обрывается.
        let base = probe("1.2.3.4", "reset", "tls");
        // Настоящее имя рвётся, с посторонним — шифрование установилось: блокировка по имени.
        assert_eq!(
            facts(base.clone(), |facts| {
                facts.neutral = Some(HelloResult::new(HELLO_OK));
            })
            .unwrap()
            .code,
            CAUSE_BY_NAME
        );
        // Повтор показал, что настоящее имя проходит: сравнивать нечего.
        assert!(facts(base.clone(), |facts| {
            facts.neutral = Some(HelloResult::new(HELLO_OK));
            facts.real_again = Some(HelloResult::new(HELLO_OK));
        })
        .is_none());
        // Молчание на все имена, включая разрешённое: закрыт сам адрес.
        assert_eq!(
            facts(base.clone(), |facts| {
                facts.allowed = Some(HelloResult::new(HELLO_TIMEOUT));
                facts.neutral = Some(HelloResult::new(HELLO_TIMEOUT));
            })
            .unwrap()
            .code,
            CAUSE_BY_ADDRESS
        );
        // Разрешённое имя прошло, своё и постороннее — нет: белый список имён.
        assert_eq!(
            facts(base.clone(), |facts| {
                facts.neutral = Some(HelloResult::new(HELLO_RESET));
                facts.allowed = Some(HelloResult::new(HELLO_OK));
            })
            .unwrap()
            .code,
            CAUSE_NAME_WHITELIST
        );
        // Соединение само не установилось, пинг ответил: наблюдение о закрытом 443.
        assert_eq!(
            facts(probe("1.2.3.4", "connect", "connect"), |facts| facts.http =
                Some(HttpFacts {
                    status: Some(200),
                    ..Default::default()
                }))
            .unwrap()
            .code,
            CAUSE_ADDRESS_CLOSED
        );
    }
}
