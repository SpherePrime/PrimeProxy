//! Порт `src/dns/doh_lookup.py` — поиск IP-адресов сервера по его адресу DoH.
//!
//! Windows не умеет «просто строку» `https://имя/dns-query`: в настройках
//! адаптера всегда стоят IP-адреса, а шифрование включается для пары
//! «адрес + шаблон DoH». Поэтому, когда пользователь задал только адрес DoH,
//! программа сама узнаёт IP сервера и проверяет каждый.
//!
//! Шаги:
//! 1. кандидаты — адреса имени сервера: шифрованный вопрос эталонным серверам
//!    (`crate::reference_ask`-транспорт) и DNS системы; берётся первый ответ
//!    и те, что пришли сразу за ним;
//! 2. проверка — каждому кандидату отправляется настоящий запрос DoH с именем
//!    сервера и проверкой сертификата. Адрес, подменённый провайдером,
//!    сертификат не предъявит и проверку не пройдёт;
//! 3. если Windows сама DoH не умеет (Windows 10), адрес должен отвечать ещё
//!    и на обычный DNS — иначе с ним не откроется ни один сайт.
//!
//! В запись сервера попадает не больше [`MAX_PER_FAMILY`] проверенных
//! адресов каждой версии: основной и запасной.

use primecore_dnswire::doh::query_doh;
use primecore_dnswire::net::query_udp;
use primecore_dnswire::{DnsQueryResult, ENCRYPTED_TIMEOUT_S, TYPE_A, TYPE_AAAA};
use primecore_socketcancel::SocketCancel;

use crate::custom_servers::DohTemplate;

pub const PROBE_DOMAIN: &str = "example.com";
pub const MAX_PER_FAMILY: usize = 2;
pub const MAX_CANDIDATES: usize = 8;
pub const PLAIN_TIMEOUT_S: f64 = 1.5;
/// Сколько ещё ждать остальных ответов после первого удачного: успевают AAAA
/// и DNS системы.
pub const ANSWER_GRACE_S: f64 = 0.4;

/// python `DohLookup` — что нашлось: проверенные адреса или причина, почему
/// их нет.
///
/// `notice` — оговорка к удачному поиску (например, что шифрования на этой
/// Windows не будет).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DohLookup {
    pub host: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub error: String,
    pub notice: String,
}

impl DohLookup {
    #[must_use]
    pub fn found(&self) -> bool {
        (!self.ipv4.is_empty() || !self.ipv6.is_empty()) && self.error.is_empty()
    }
}

/// Тип [`LookupIo::resolve`] — поиск адресов имени.
pub type ResolveFn<'a> = Box<dyn Fn(&str, bool) -> Vec<String> + 'a>;
/// Тип [`LookupIo::probe`] — настоящий запрос DoH по адресу.
pub type ProbeFn<'a> = Box<dyn Fn(&str, &DohTemplate) -> DnsQueryResult + 'a>;
/// Тип [`LookupIo::plain`] — обычный DNS-запрос по адресу.
pub type PlainFn<'a> = Box<dyn Fn(&str) -> DnsQueryResult + 'a>;

/// Транспорт поиска (python `resolve`/`probe`/`plain`-замыкания).
pub struct LookupIo<'a> {
    /// Адреса имени: (host, нужен ли IPv6) → список кандидатов.
    pub resolve: ResolveFn<'a>,
    /// Настоящий запрос DoH по адресу: сертификат проверяется для имени сервера.
    pub probe: ProbeFn<'a>,
    /// Обычный DNS-запрос по адресу (UDP, порт 53).
    pub plain: PlainFn<'a>,
}

impl LookupIo<'_> {
    /// Живой ввод: эталонные серверы по DoH, DNS системы и настоящие запросы.
    #[must_use]
    pub fn live(cancel: std::sync::Arc<SocketCancel>) -> Self {
        Self::with_cancel(cancel)
    }

    /// Тот же ввод с общим (Arc) отменой — для движка.
    #[must_use]
    pub fn with_cancel(cancel: std::sync::Arc<SocketCancel>) -> Self {
        let resolve_cancel = std::sync::Arc::clone(&cancel);
        let probe_cancel = std::sync::Arc::clone(&cancel);
        let plain_cancel = std::sync::Arc::clone(&cancel);
        Self {
            resolve: Box::new(move |host, ipv6| {
                resolve_candidates(host, ipv6, Some(&resolve_cancel))
            }),
            probe: Box::new(move |address, template| {
                probe_doh(address, template, Some(&probe_cancel))
            }),
            plain: Box::new(move |address| probe_plain(address, Some(&plain_cancel))),
        }
    }
}

/// python `_is_ipv6` — адрес IPv6, если есть двоеточие.
#[must_use]
pub fn is_ipv6_address(address: &str) -> bool {
    address.contains(':')
}

/// python `resolve_candidates` — адреса имени сервера: сначала от эталонных
/// серверов по DoH, затем от DNS системы.
///
/// Закрытый на линии эталонный сервер молчит до тайм-аута. Ждать всех незачем:
/// хватит первого, кто назвал адреса, — каждый кандидат всё равно проверяется.
/// Параллельный залп — слой запуска; здесь вопросы складываются по порядку
/// (движок даёт машину прогона).
pub fn resolve_candidates(host: &str, ipv6: bool, cancel: Option<&SocketCancel>) -> Vec<String> {
    use primecore_diagnostics::dns_reference::{doh_query, REFERENCE_RESOLVERS};

    let rtypes: &[u16] = if ipv6 {
        &[TYPE_A, TYPE_AAAA]
    } else {
        &[TYPE_A]
    };
    let mut result: Vec<String> = Vec::new();
    for resolver in REFERENCE_RESOLVERS.iter() {
        for rtype in rtypes {
            let values = doh_query(resolver.address, host, *rtype, ENCRYPTED_TIMEOUT_S, cancel)
                .values(*rtype);
            for value in values {
                if !result.contains(&value) && (ipv6 || !is_ipv6_address(&value)) {
                    result.push(value);
                }
            }
        }
        if !result.is_empty() {
            // Первый ответивший назвал адреса — остальных ждать незачем.
            break;
        }
    }
    // DNS системы — запасной источник (python socket.getaddrinfo; здесь
    // системный резолвер через std).
    if result.is_empty() {
        if let Ok(addrs) =
            std::net::ToSocketAddrs::to_socket_addrs(format!("{host}:443").as_str() as &str)
        {
            for address in addrs {
                let text = address.ip().to_string();
                if !result.contains(&text) && (ipv6 || !is_ipv6_address(&text)) {
                    result.push(text);
                }
            }
        }
    }
    result
}

/// python `probe_doh` — настоящий запрос DoH по адресу: сертификат
/// проверяется для имени сервера.
#[must_use]
pub fn probe_doh(
    address: &str,
    template: &DohTemplate,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    query_doh(
        address,
        PROBE_DOMAIN,
        TYPE_A,
        if template.host_is_address() {
            ""
        } else {
            &template.host
        },
        template.port,
        &template.path,
        ENCRYPTED_TIMEOUT_S,
        cancel,
    )
}

/// python `probe_plain` — обычный DNS-запрос по адресу (UDP, порт 53).
#[must_use]
pub fn probe_plain(address: &str, cancel: Option<&SocketCancel>) -> DnsQueryResult {
    query_udp(address, PROBE_DOMAIN, TYPE_A, PLAIN_TIMEOUT_S, 53, cancel)
}

/// python `_reason` — причина сбоя словами: текст сбоя, деталь или «нет ответа».
fn reason(result: &DnsQueryResult) -> String {
    let text = result.failure_text();
    if !text.is_empty() {
        return text;
    }
    if !result.detail.is_empty() {
        return result.detail.clone();
    }
    "нет ответа".to_string()
}

/// python `find_doh_addresses` — проверенные IP-адреса сервера DoH или
/// понятная причина, почему их нет.
///
/// `ipv6` — есть ли у компьютера дорога по IPv6: без неё адреса IPv6 не
/// проверить, и в запись они не попадают. `doh_supported` — умеет ли эта
/// Windows шифровать DNS сама.
#[must_use]
pub fn find_doh_addresses(
    template: &DohTemplate,
    ipv6: bool,
    doh_supported: bool,
    io: &LookupIo<'_>,
) -> DohLookup {
    let host = template.host.clone();
    let mut candidates: Vec<String> = if template.host_is_address() {
        if ipv6 || !is_ipv6_address(&host) {
            vec![host.clone()]
        } else {
            Vec::new()
        }
    } else {
        (io.resolve)(&host, ipv6)
    };
    candidates.truncate(MAX_CANDIDATES);
    if candidates.is_empty() {
        return DohLookup {
            error: format!(
                "Не удалось узнать IP-адреса сервера {host}: имя не находится. \
                 Проверьте адрес DoH или впишите IP-адреса сервера сами."
            ),
            host,
            ..Default::default()
        };
    }

    let answers: Vec<DnsQueryResult> = candidates
        .iter()
        .map(|address| (io.probe)(address, template))
        .collect();
    let working: Vec<String> = candidates
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| answer.answered())
        .map(|(address, _)| address.clone())
        .collect();
    if working.is_empty() {
        return DohLookup {
            error: format!(
                "Сервер {host} найден ({}), но на запрос DoH не ответил: {}. \
                 Проверьте адрес DoH; возможно, сервер закрыт на вашей линии.",
                candidates
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                reason(&answers[0])
            ),
            host,
            ..Default::default()
        };
    }

    let mut working = working;
    let mut notice = String::new();
    if !doh_supported {
        let plain_answers: Vec<DnsQueryResult> =
            working.iter().map(|address| (io.plain)(address)).collect();
        working = working
            .into_iter()
            .zip(&plain_answers)
            .filter(|(_, answer)| answer.answered())
            .map(|(address, _)| address)
            .collect();
        if working.is_empty() {
            return DohLookup {
                error: format!(
                    "Сервер {host} отвечает только по DoH, а эта Windows сама шифровать DNS не умеет \
                     (нужна Windows 11). Работать он здесь не будет — выберите плитку из группы «Шифрованные»."
                ),
                host,
            ..Default::default()
            };
        }
        notice = "Эта Windows сама шифровать DNS не умеет (нужна Windows 11): запросы к серверу \
                  пойдут обычным DNS."
            .to_string();
    }

    DohLookup {
        error: String::new(),
        host,
        ipv4: working
            .iter()
            .filter(|address| !is_ipv6_address(address))
            .take(MAX_PER_FAMILY)
            .cloned()
            .collect(),
        ipv6: working
            .iter()
            .filter(|address| is_ipv6_address(address))
            .take(MAX_PER_FAMILY)
            .cloned()
            .collect(),
        notice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primecore_dnswire::DnsRecord;

    fn template(doh: &str) -> DohTemplate {
        crate::custom_servers::parse_doh_template(doh).expect("шаблон разобран")
    }

    fn answered(ips: &[&str], rtype: u16) -> DnsQueryResult {
        primecore_dnswire::answered_result(
            "doh",
            primecore_dnswire::DnsMessage {
                answers: ips
                    .iter()
                    .map(|ip| DnsRecord {
                        name: "x".to_string(),
                        rtype,
                        ttl: 60,
                        value: (*ip).to_string(),
                    })
                    .collect(),
                ..Default::default()
            },
            10.0,
        )
    }

    fn silent() -> DnsQueryResult {
        DnsQueryResult {
            transport: "doh".to_string(),
            failure: primecore_dnswire::FAILURE_TIMEOUT.to_string(),
            ..Default::default()
        }
    }

    fn io_with(candidates: &[&str], probe_ok: &[&str], plain_ok: bool) -> LookupIo<'static> {
        let candidates: Vec<String> = candidates.iter().map(|item| (*item).to_string()).collect();
        let probe_ok: Vec<String> = probe_ok.iter().map(|item| (*item).to_string()).collect();
        LookupIo {
            resolve: Box::new(move |_host, _ipv6| candidates.clone()),
            probe: Box::new(move |address: &str, _template: &DohTemplate| {
                if probe_ok.contains(&address.to_string()) {
                    answered(&["93.184.216.14"], TYPE_A)
                } else {
                    silent()
                }
            }),
            plain: Box::new(move |_address: &str| {
                if plain_ok {
                    answered(&["93.184.216.14"], TYPE_A)
                } else {
                    silent()
                }
            }),
        }
    }

    #[test]
    fn addresses_found_and_verified() {
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            true,
            &io_with(&["9.9.9.9", "149.112.112.112"], &["9.9.9.9"], true),
        );
        assert!(lookup.found());
        assert_eq!(lookup.ipv4, vec!["9.9.9.9".to_string()]);
        assert!(lookup.ipv6.is_empty());
        assert!(lookup.notice.is_empty());
    }

    #[test]
    fn families_capped() {
        // Три работающих адреса IPv4 — берутся первые два (MAX_PER_FAMILY).
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            true,
            &io_with(
                &["9.9.9.9", "149.112.112.112", "9.9.9.10"],
                &["9.9.9.9", "149.112.112.112", "9.9.9.10"],
                true,
            ),
        );
        assert_eq!(lookup.ipv4.len(), MAX_PER_FAMILY);
    }

    #[test]
    fn no_candidates_is_an_error() {
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            true,
            &LookupIo {
                resolve: Box::new(|_host, _ipv6| Vec::new()),
                probe: Box::new(|_address, _template| silent()),
                plain: Box::new(|_address| silent()),
            },
        );
        assert!(!lookup.found());
        assert!(lookup.error.contains("имя не находится"));
    }

    #[test]
    fn all_candidates_silent_is_an_error() {
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            true,
            &io_with(&["9.9.9.9"], &[], true),
        );
        assert!(!lookup.found());
        assert!(lookup.error.contains("на запрос DoH не ответил"));
    }

    #[test]
    fn without_doh_support_plain_is_checked() {
        // Windows 10: работает только тот, кто отвечает и обычным DNS.
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            false,
            &io_with(
                &["9.9.9.9", "149.112.112.112"],
                &["9.9.9.9", "149.112.112.112"],
                false,
            ),
        );
        assert!(!lookup.found());
        assert!(lookup.error.contains("сама шифровать DNS не умеет"));
        let lookup = find_doh_addresses(
            &template("https://dns.quad9.net/dns-query"),
            false,
            false,
            &io_with(&["9.9.9.9"], &["9.9.9.9"], true),
        );
        assert!(lookup.found());
        assert!(!lookup.notice.is_empty(), "оговорка про Windows 10");
    }

    #[test]
    fn host_as_address_skips_lookup() {
        // Адрес в шаблоне: имя не спрашивается, проверяется сам адрес.
        let template = template("[2606:4700:4700::1111]");
        assert!(template.host_is_address());
        // IPv6-адрес проверяется только с дорогой IPv6 (python: ipv6 or not _is_ipv6).
        let lookup = find_doh_addresses(
            &template,
            true,
            true,
            &io_with(&[], &["2606:4700:4700::1111"], true),
        );
        assert!(lookup.ipv6.contains(&"2606:4700:4700::1111".to_string()));
        // Без дороги IPv6 проверять нечего.
        let lookup = find_doh_addresses(&template, false, true, &io_with(&[], &[], true));
        assert!(lookup.error.contains("имя не находится"));
    }
}
