//! Порт `src/dns/reachability.py` — отвечает ли DNS-сервер из сети
//! пользователя: проверка перед применением.
//!
//! Блокировка у каждого провайдера своя: один и тот же сервер может быть
//! закрыт у одного и открыт у другого. Поэтому «заблокирован» нельзя записать
//! в список серверов — это узнаётся только на месте, в момент, когда
//! пользователь выбрал сервер. Если сервер не отвечает ни одним способом,
//! программа его не ставит: иначе компьютер остался бы без DNS и без
//! интернета.
//!
//! Сервер считается живым, если ответил хотя бы один способ: обычный запрос
//! (UDP), запрос по TCP или шифрованный (DoH, когда у сервера есть шаблон).
//! Так программа не отказывает там, где провайдер режет только открытый DNS.
//!
//! Обратный случай тоже отмечается: шаблон DoH есть, а шифрованный путь
//! молчит, хотя обычный отвечает. Windows записывается с откатом на обычный
//! DNS, поэтому DNS заработает, но без шифрования — об этом человеку надо
//! сказать, иначе он считает свои запросы закрытыми.

use primecore_dnswire::doh::query_doh;
use primecore_dnswire::net::{query_tcp, query_udp};
use primecore_dnswire::TYPE_A;

/// Безобидное имя для самой проверки связи.
pub const PROBE_NAME: &str = "example.com";
pub const UDP_TIMEOUT_S: f64 = 2.0;
pub const TCP_TIMEOUT_S: f64 = 3.0;
pub const DOH_TIMEOUT_S: f64 = 4.0;

/// python `ServerReach`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerReach {
    /// Почему сервер не ставится; пустая строка — ставить можно.
    pub blocked: String,
    /// Шифрованный путь закрыт, а обычный отвечает: Windows будет спрашивать
    /// без шифрования.
    pub doh_closed: bool,
}

/// python `_is_local` — свой компьютер или домашняя сеть: такие адреса
/// снаружи не блокируют.
#[must_use]
pub fn is_local(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(ip) => match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || ((v6.segments()[0] & 0xfe00) == 0xfc00) // fc00::/7 — unique local
                    || ((v6.segments()[0] & 0xffc0) == 0xfe80) // fe80::/10 — link local
            }
        },
        Err(_) => true,
    }
}

/// python `_Answers` — ответы способов по одному адресу.
#[derive(Debug, Clone, Copy)]
struct Answers {
    plain: bool,
    /// None — шаблона DoH у адреса нет, спрашивать нечем.
    doh: Option<bool>,
}

/// Транспорт проверок (python `query_*` из utils.dns_wire); разнесён для
/// живых тестов на подставных серверах.
pub type UdpQuery<'a> = dyn Fn(&str, &str, f64) -> primecore_dnswire::DnsQueryResult + 'a;
pub type TcpQuery<'a> = dyn Fn(&str, &str, f64) -> primecore_dnswire::DnsQueryResult + 'a;
pub type DohQuery<'a> =
    dyn Fn(&str, &str, &str, u16, &str, f64) -> primecore_dnswire::DnsQueryResult + 'a;

fn answers(
    address: &str,
    template: &str,
    udp: &UdpQuery<'_>,
    tcp: &TcpQuery<'_>,
    doh: Option<&DohQuery<'_>>,
) -> Answers {
    let plain_udp = udp(address, PROBE_NAME, UDP_TIMEOUT_S).answered();
    let plain_tcp = tcp(address, PROBE_NAME, TCP_TIMEOUT_S).answered();
    let doh_answered = template_parts(template).map(|(tls_host, port, path)| {
        doh.expect("шаблон есть — транспорт DoH передан")(
            address,
            PROBE_NAME,
            &tls_host,
            port,
            &path,
            DOH_TIMEOUT_S,
        )
        .answered()
    });
    Answers {
        plain: plain_udp || plain_tcp,
        doh: doh_answered,
    }
}

/// (имя для сертификата, порт, путь) из шаблона DoH; None — шаблон не адрес
/// HTTPS (python `urlsplit(template).hostname`).
fn template_parts(template: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = template.split_once("://")?;
    if scheme != "https" {
        return None;
    }
    let authority_end = rest.find(['/']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = rest.get(authority_end..).unwrap_or("").to_string();
    let (host, port) = split_host_port(authority);
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port, path))
}

/// `имя[:порт]` из authority-части; порт по умолчанию 443.
fn split_host_port(authority: &str) -> (&str, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(443);
            return (host, port);
        }
        return (authority, 443);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => {
            (host, port.parse().expect("проверено"))
        }
        _ => (authority, 443),
    }
}

/// Живые запросы (python `query_udp`/`query_tcp`/`query_doh` на порту 53/853).
pub fn live_queries() -> (
    Box<UdpQuery<'static>>,
    Box<TcpQuery<'static>>,
    Box<DohQuery<'static>>,
) {
    let udp: Box<UdpQuery<'static>> =
        Box::new(|server, name, timeout| query_udp(server, name, TYPE_A, timeout, 53, None));
    let tcp: Box<TcpQuery<'static>> =
        Box::new(|server, name, timeout| query_tcp(server, name, TYPE_A, timeout, 53, None));
    let doh: Box<DohQuery<'static>> = Box::new(|server, name, tls_host, port, path, timeout| {
        query_doh(server, name, TYPE_A, tls_host, port, path, timeout, None)
    });
    (udp, tcp, doh)
}

/// python `check_servers(ipv4, ipv6, templates)` — можно ли ставить сервер и
/// дойдёт ли до него шифрование.
///
/// Проверяются адреса IPv4; IPv6 — только когда других нет: у многих
/// провайдеров IPv6 не работает вовсе, и это не блокировка сервера.
#[must_use]
pub fn check_servers(
    ipv4: &[String],
    ipv6: &[String],
    templates: &[(String, String)],
) -> ServerReach {
    check_servers_with(ipv4, ipv6, templates, &live_queries())
}

/// То же с подставными запросами — для живых тестов.
#[must_use]
pub fn check_servers_with(
    ipv4: &[String],
    ipv6: &[String],
    templates: &[(String, String)],
    (udp, tcp, doh): &(Box<UdpQuery<'_>>, Box<TcpQuery<'_>>, Box<DohQuery<'_>>),
) -> ServerReach {
    let clean = |items: &[String]| -> Vec<String> {
        items
            .iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty() && !is_local(item))
            .collect()
    };
    let mut addresses = clean(ipv4);
    if addresses.is_empty() {
        addresses = clean(ipv6);
    }
    if addresses.is_empty() {
        return ServerReach::default();
    }
    let answers: Vec<Answers> = addresses
        .iter()
        .map(|address| {
            let template = templates
                .iter()
                .find(|(known, _)| known == address)
                .map(|(_, template)| template.as_str())
                .unwrap_or("");
            let with_doh = template_parts(template).is_some();
            if with_doh {
                answers(address, template, udp, tcp, Some(doh.as_ref()))
            } else {
                answers(address, template, udp, tcp, None)
            }
        })
        .collect();
    if !answers
        .iter()
        .any(|item| item.plain || item.doh == Some(true))
    {
        return ServerReach {
            blocked: format!(
                "Сервер {} не отвечает из вашей сети ни обычным, ни шифрованным запросом — \
                 похоже, его блокирует провайдер. DNS не изменён: с этим сервером интернет \
                 перестал бы работать. Выберите другой сервер.",
                addresses.join(", ")
            ),
            doh_closed: false,
        };
    }
    let with_doh: Vec<&Answers> = answers.iter().filter(|item| item.doh.is_some()).collect();
    // Хоть один адрес ответил по DoH — Windows шифрует через него.
    ServerReach {
        blocked: String::new(),
        doh_closed: !with_doh.is_empty() && !with_doh.iter().any(|item| item.doh == Some(true)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn silent(_server: &str, _name: &str, _timeout: f64) -> primecore_dnswire::DnsQueryResult {
        primecore_dnswire::DnsQueryResult {
            transport: "udp".to_string(),
            failure: primecore_dnswire::FAILURE_TIMEOUT.to_string(),
            ..Default::default()
        }
    }

    fn answering(_server: &str, _name: &str, _timeout: f64) -> primecore_dnswire::DnsQueryResult {
        primecore_dnswire::answered_result(
            "udp",
            primecore_dnswire::parse_response(&[0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
                .expect("разобран"),
            12.0,
        )
    }

    #[test]
    fn local_and_bad_addresses_are_skipped() {
        assert!(is_local("127.0.0.1"));
        assert!(is_local("192.168.1.5"));
        assert!(is_local("169.254.1.2"));
        assert!(is_local("::1"));
        assert!(is_local("fe80::1"));
        assert!(is_local("fd00::1"));
        assert!(!is_local("9.9.9.9"));
        assert!(!is_local("2620:fe::fe"));
        // Не адрес — «локальный»: снаружи не блокирует, а проверять нечего.
        assert!(is_local("не адрес"));
    }

    fn silent_doh(
        _server: &str,
        _name: &str,
        _tls_host: &str,
        _port: u16,
        _path: &str,
        _timeout: f64,
    ) -> primecore_dnswire::DnsQueryResult {
        silent("", "", 0.0)
    }

    fn answering_doh(
        _server: &str,
        _name: &str,
        _tls_host: &str,
        _port: u16,
        _path: &str,
        _timeout: f64,
    ) -> primecore_dnswire::DnsQueryResult {
        answering("", "", 0.0)
    }

    #[test]
    fn blocked_when_all_silent() {
        let server = "9.9.9.9".to_string();
        let reach = check_servers_with(
            std::slice::from_ref(&server),
            &[],
            &[],
            &(
                Box::new(silent) as Box<UdpQuery<'_>>,
                Box::new(silent) as Box<TcpQuery<'_>>,
                Box::new(silent_doh) as Box<DohQuery<'_>>,
            ),
        );
        assert!(reach.blocked.contains("не отвечает из вашей сети"));
        assert!(!reach.doh_closed);
        // Пустой список — и решения нет: сервер можно ставить (не было проверок).
        let empty = check_servers(&[], &[], &[]);
        assert!(empty.blocked.is_empty());
    }

    #[test]
    fn plain_answer_is_enough() {
        let server = "9.9.9.9".to_string();
        let reach = check_servers_with(
            &[server],
            &[],
            &[],
            &(
                Box::new(answering) as Box<UdpQuery<'_>>,
                Box::new(silent) as Box<TcpQuery<'_>>,
                Box::new(silent_doh) as Box<DohQuery<'_>>,
            ),
        );
        assert!(reach.blocked.is_empty());
    }

    #[test]
    fn doh_closed_when_template_silent() {
        let server = "9.9.9.9".to_string();
        let template = (
            "9.9.9.9".to_string(),
            "https://dns.quad9.net/dns-query".to_string(),
        );
        // Обычный отвечает, шифрованный молчит: ставить можно, но без шифрования.
        let reach = check_servers_with(
            std::slice::from_ref(&server),
            &[],
            std::slice::from_ref(&template),
            &(
                Box::new(answering) as Box<UdpQuery<'_>>,
                Box::new(silent) as Box<TcpQuery<'_>>,
                Box::new(silent_doh) as Box<DohQuery<'_>>,
            ),
        );
        assert!(reach.blocked.is_empty());
        assert!(reach.doh_closed);
        // А если и обычный молчит, и шифрованный — блокировка.
        let blocked = check_servers_with(
            &["9.9.9.9".to_string()],
            &[],
            std::slice::from_ref(&template),
            &(
                Box::new(silent) as Box<UdpQuery<'_>>,
                Box::new(silent) as Box<TcpQuery<'_>>,
                Box::new(silent_doh) as Box<DohQuery<'_>>,
            ),
        );
        assert!(!blocked.blocked.is_empty());
        // Шифрованный путь ответил — doh_closed нет, хотя обычные молчали.
        let reach = check_servers_with(
            std::slice::from_ref(&server),
            &[],
            std::slice::from_ref(&template),
            &(
                Box::new(silent) as Box<UdpQuery<'_>>,
                Box::new(silent) as Box<TcpQuery<'_>>,
                Box::new(answering_doh) as Box<DohQuery<'_>>,
            ),
        );
        assert!(reach.blocked.is_empty());
        assert!(!reach.doh_closed);
    }

    #[test]
    fn template_parts_parsed() {
        assert_eq!(
            template_parts("https://dns.quad9.net/dns-query"),
            Some(("dns.quad9.net".to_string(), 443, "/dns-query".to_string()))
        );
        assert_eq!(
            template_parts("https://dns.quad9.net:8443/q"),
            Some(("dns.quad9.net".to_string(), 8443, "/q".to_string()))
        );
        assert_eq!(template_parts("http://dns.quad9.net"), None);
        assert_eq!(template_parts("https://"), None);
        assert_eq!(template_parts(""), None);
    }
}
