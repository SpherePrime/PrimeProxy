//! Порт `src/diagnostics/block_cause.py` — почему сайт не открылся: уточнение
//! причины дополнительными пробами.
//!
//! Основная проверка (`probe_result`) говорит, на какой ступени оборвалось
//! соединение. Этого мало, чтобы понять, **как** блокируют: по имени сайта или
//! по адресу. В python делаются три дешёвые пробы к тому же адресу: SNI с
//! посторонним именем, HTTP порт 80, пинг. Сбор (`collect`, `tls_hello`,
//! `http_probe`) — сетевая часть (TLS-клиент), портируется следом; здесь —
//! чистая часть: состав проб, сравнение фактов и вывод (`judge`).

use crate::probe_result::{
    ProbeResult, KIND_CONNECT, KIND_RESET, KIND_TIMEOUT, KIND_TLS, STAGE_CONNECT, STAGE_TLS,
};

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
