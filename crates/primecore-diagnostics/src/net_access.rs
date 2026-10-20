//! Порт `src/diagnostics/net_access.py` — единственный выход BlockCheck в сеть.
//!
//! Все обращения прогона наружу идут через функции этого файла: запрос
//! страницы, вопрос к DNS системы, эталон по DNS-over-HTTPS, файл hosts.
//! Движок и проверки разделов сами сеть не трогают — поэтому у каждого
//! запроса один и тот же срок, одна и та же отмена по «Стоп», и подменить
//! сеть в тестах можно в одном месте.
//!
//! Здесь только факты («что ответили»). Выводы из них делают другие модули.
//!
//! Сетевые вызовы (HTTP, ICMP, системный DNS, параллельный залп эталона)
//! приходят замыканиями — как в остальных чистых модулях: сам транспорт ещё
//! переносится.
use crate::dns_reference::{ReferenceResolver, REFERENCE_RESOLVERS};
use crate::limits::{DNS_TIMEOUT, HTTPS_TIMEOUT, READ_TIMEOUT};
use crate::probe_result::ProbeResult;
use primecore_dnswire::{DnsQueryResult, TYPE_A};

/// Скачивание служебных списков (реестр): общий срок и предел размера.
pub const FILE_TIMEOUT_S: f64 = 40.0;
pub const FILE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// python-ответ скачивания: `(содержимое, метка версии)`; `(None, etag)` при
/// 304 «не менялся»; `None` — не вышло.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Downloaded {
    pub body: Option<Vec<u8>>,
    pub etag: String,
    /// python `HTTPError 304` — на сервере та же метка.
    pub not_modified: bool,
}

/// python `doh_lookup` — эталонные адреса: (ответил ли хоть один, адреса).
///
/// Спрашиваются все эталонные серверы сразу, ответы складываются. Кто из них
/// не ответил и почему — запоминается в прогоне и попадает в отчёт
/// (`note`). Молчащего сервера сайт не ждёт: после первого ответа остальным
/// даётся [`crate::limits::REFERENCE_GRACE_S`].
///
/// Параллельный залп — слой запуска; здесь чистая версия складывает ответы
/// по порядку Resolver-ов (`first_answer` семантика в виде сортированных
/// сроков готовит слой запуска, точные расписания см. engine).
pub type DoHQuery<'q> = dyn FnMut(&ReferenceResolver) -> DnsQueryResult + 'q;

pub fn doh_lookup(
    query: &mut DoHQuery<'_>,
    note: &mut dyn FnMut(&ReferenceResolver, &DnsQueryResult),
) -> (bool, Vec<String>) {
    let mut answered = false;
    let mut ips: Vec<String> = Vec::new();
    for resolver in REFERENCE_RESOLVERS.iter() {
        let result = query(resolver);
        note(resolver, &result);
        // Ответ опоздавшего сервера тоже учитывается в отчёте, хотя сайт его уже не ждёт.
        if result.answered() {
            answered = true;
            for ip in result.values(TYPE_A) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    (answered, ips)
}

/// python-замыкание `doher` — вопрос отдельного эталонного сервера.
pub type DoHAsk<'q> = dyn FnMut(&ReferenceResolver, &str, u16) -> DnsQueryResult + 'q;

/// python `doh_ask` — произвольный вопрос к эталону: первый ответивший
/// сервер. None — не ответил никто.
pub fn doh_ask(
    name: &str,
    record_type: u16,
    query: &mut DoHAsk<'_>,
) -> Option<DnsQueryResult> {
    for resolver in REFERENCE_RESOLVERS.iter() {
        let result = query(resolver, name, record_type);
        if result.answered() {
            return Some(result);
        }
    }
    None
}

/// python-замыкание `chrome_get` — сетевой запрос «как браузер».
pub type ChromeGet<'g> = dyn FnMut(
    &str,
    &str,
    &str,
    f64,
    usize,
    f64,
    Option<&dyn Fn(&[u8]) -> bool>,
    bool,
) -> ProbeResult
    + 'g;

/// python `fetch` — HTTPS-запрос к сайту `host` по адресу `ip` — так, как его
/// открыл бы Chrome. Снимается кнопкой «Стоп».
#[must_use]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn fetch(
    host: &str,
    ip: &str,
    path: &str,
    timeout: f64,
    read_limit: usize,
    read_timeout: f64,
    body_done: Option<&dyn Fn(&[u8]) -> bool>,
    decode_body: bool,
    chrome_get: &mut ChromeGet<'_>,
) -> ProbeResult {
    chrome_get(host, ip, path, timeout, read_limit, read_timeout, body_done, decode_body)
}

/// python `get` — обычный запрос «открывается ли сайт» с общими сроками.
#[must_use]
pub fn get(
    host: &str,
    ip: &str,
    path: &str,
    read_limit: usize,
    chrome_get: &mut ChromeGet<'_>,
) -> ProbeResult {
    fetch(host, ip, path, HTTPS_TIMEOUT, read_limit, READ_TIMEOUT, None, false, chrome_get)
}

/// python `download_file` — скачивает файл целиком: (содержимое, метка
/// версии) или None — не вышло.
///
/// `etag` — метка версии, которая уже есть: если на сервере та же, файл не
/// качается и содержимое возвращается как `not_modified`. Сжатие включено:
/// список реестра по сети идёт вчетверо меньше.
#[must_use]
pub fn download_file(
    url: &str,
    etag: &str,
    timeout: f64,
    limit: usize,
    open: &mut dyn FnMut(&str, &str, f64, usize) -> Downloaded,
) -> Downloaded {
    open(url, etag, timeout, limit)
}

/// python `system_ipv4` — ответ DNS системы (без кэша и hosts).
#[must_use]
pub fn system_ipv4(
    host: &str,
    query: &mut dyn FnMut(&str, f64) -> crate::windows_dns_query::DnsAnswer,
) -> crate::windows_dns_query::DnsAnswer {
    query(host, DNS_TIMEOUT)
}

/// python `hosts_ipv4` — адреса сайта из файла hosts.
#[must_use]
pub fn hosts_ipv4(host: &str, hosts: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    hosts(host)
}

/// python `system_servers` — DNS-серверы, заданные в системе.
#[must_use]
pub fn system_servers(servers: &dyn Fn() -> Vec<String>) -> Vec<String> {
    servers()
}

/// python `browser_ipv4` — адреса, которыми воспользовался бы браузер: hosts,
/// DNS системы, а если DNS не дал — эталон.
#[must_use]
pub fn browser_ipv4(
    hosts: &dyn Fn(&str) -> Vec<String>,
    system: &dyn Fn(&str) -> Option<crate::windows_dns_query::DnsAnswer>,
    doh: &mut dyn FnMut(&str) -> Vec<String>,
    host: &str,
) -> Vec<String> {
    let from_hosts = hosts(host);
    if !from_hosts.is_empty() {
        return from_hosts;
    }
    if let Some(answer) = system(host) {
        if !answer.ips.is_empty() {
            return answer.ips;
        }
    }
    doh(host)
}

/// python `known_address` — адрес сервера: из hosts/DNS системы, иначе
/// эталон. Пусто — не нашли.
///
/// Адрес запоминается на прогон: отправка проверяется на том же адресе, что
/// и загрузка.
#[must_use]
pub fn known_address(
    known: Option<String>,
    browser: &mut dyn FnMut(&str) -> Vec<String>,
    host: &str,
) -> String {
    if let Some(stored) = known {
        return stored;
    }
    browser(host).first().cloned().unwrap_or_default()
}

/// python `ping_hop` — один пинг со сроком жизни `ttl`:
/// (адрес ответившего узла, время) или None — ответа нет.
///
/// `Err(())` — пинг в этой системе недоступен (python `NotImplementedError`).
/// Из IP-адреса брошен сам вопрос к ICMP-слою (rust `icmp::classify_hop`).
#[allow(clippy::result_unit_err)]
pub fn ping_hop(
    ip: &str,
    ttl: u8,
    trace: &dyn Fn(&str, u8) -> Option<crate::icmp::TraceHopResult>,
) -> Result<Option<(String, Option<f64>)>, ()> {
    let Some(result) = trace(ip, ttl) else { return Err(()) };
    if result.kind == crate::icmp::HOP_UNSUPPORTED {
        return Err(());
    }
    if result.kind == crate::icmp::HOP_SILENT {
        return Ok(None);
    }
    Ok(Some((
        if result.address.is_empty() {
            String::new()
        } else {
            result.address.clone()
        },
        result.rtt_ms,
    )))
}

/// python `ping_ok` — отвечает ли адрес на пинг. None — пинг в этой системе
/// недоступен (заглушка вместо адреса берётся снаружи).
#[must_use]
pub fn ping_ok(ping: &dyn Fn(&str) -> Option<bool>) -> Option<bool> {
    // Замыкание само решает, какой адрес доносится (в сети нужна «система»).
    ping("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_reference::ReferenceResolver;
    use primecore_dnswire::{DnsRecord, RCODE_OK};

    fn result_ok(ips: &[&str]) -> DnsQueryResult {
        DnsQueryResult {
            status: RCODE_OK.to_string(),
            rcode: Some(RCODE_OK),
            records: ips
                .iter()
                .map(|ip| DnsRecord {
                    name: String::new(),
                    rtype: TYPE_A,
                    ttl: 0,
                    value: ip.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// python `doh_lookup` — сложение ответов эталонных серверов.
    #[test]
    fn doh_lookup_python() {
        let mut noted: Vec<String> = Vec::new();
        let (answered, ips) = doh_lookup(
            &mut |resolver| {
                if resolver.label == "Cloudflare" {
                    result_ok(&["1.1.1.1", "8.8.4.4"])
                } else if resolver.label == "Google" {
                    result_ok(&["1.1.1.1", "9.9.9.9"])
                } else {
                    // Молчание остальных серверов не мешает первой паре.
                    DnsQueryResult::default()
                }
            },
            &mut |resolver, result| {
                noted.push(format!("{}:{}", resolver.label, result.answered()));
            },
        );
        assert!(answered);
        assert_eq!(ips, vec!["1.1.1.1", "8.8.4.4", "9.9.9.9"]);
        assert!(noted.len() == REFERENCE_RESOLVERS.len());
        assert!(noted.iter().all(|row| row.contains(":true") || row.contains(":false")));
    }

    /// python `doh_ask` — ответившего выбирает первый.
    #[test]
    fn doh_ask_python() {
        let found = doh_ask("site.org", TYPE_A, &mut |_resolver, name, _rtype| {
            if name == "site.org" {
                result_ok(&["2.2.2.2"])
            } else {
                DnsQueryResult::default()
            }
        });
        assert!(found.is_some());
        // Ни один не ответил — None.
        let none = doh_ask("site.org", TYPE_A, &mut |_resolver, _name, _rtype| DnsQueryResult::default());
        assert!(none.is_none());
    }

    /// python `browser_ipv4` — hosts, потом система, потом эталон.
    #[test]
    fn browser_ipv4_python() {
        fn hosts(name: &str) -> Vec<String> {
            if name == "host-site" {
                vec!["5.5.5.5".to_string()]
            } else {
                Vec::new()
            }
        }
        fn system_ok(_name: &str) -> Option<crate::windows_dns_query::DnsAnswer> {
            Some(crate::windows_dns_query::DnsAnswer {
                ips: vec!["3.3.3.3".to_string()],
                ..Default::default()
            })
        }
        fn system_empty(_name: &str) -> Option<crate::windows_dns_query::DnsAnswer> {
            Some(crate::windows_dns_query::DnsAnswer::default())
        }
        fn no_system(_name: &str) -> Option<crate::windows_dns_query::DnsAnswer> {
            None
        }
        fn doh_list(_name: &str) -> Vec<String> {
            vec!["2.2.2.2".to_string()]
        }
        let mut doh_a = doh_list;
        assert_eq!(&browser_ipv4(&hosts, &system_ok, &mut doh_a, "host-site"), &["5.5.5.5"]);
        let mut doh_b = doh_list;
        assert_eq!(&browser_ipv4(&hosts, &system_ok, &mut doh_b, "site.org"), &["3.3.3.3"]);
        let mut doh_c = doh_list;
        assert_eq!(&browser_ipv4(&hosts, &system_empty, &mut doh_c, "site.org"), &["2.2.2.2"]);
        let mut doh_d = doh_list;
        assert_eq!(&browser_ipv4(&hosts, &no_system, &mut doh_d, "site.org"), &["2.2.2.2"]);
    }

    /// python `known_address`.
    #[test]
    fn known_address_python() {
        fn take_first(name: &str) -> Vec<String> {
            assert_eq!(name, "site.org");
            vec!["9.8.7.6".to_string(), "8.8.8.8".to_string()]
        }
        fn none_at_all(_name: &str) -> Vec<String> {
            Vec::new()
        }
        assert_eq!(known_address(Some("1.2.3.4".into()), &mut none_at_all, "site.org"), "1.2.3.4");
        let mut reactive = take_first;
        assert_eq!(known_address(None, &mut reactive, "site.org"), "9.8.7.6");
        let mut empty = none_at_all;
        assert_eq!(known_address(None, &mut empty, "site.org"), "");
    }

    /// python `download_file` — сквозная передача до открытого потока.
    #[test]
    fn download_file_python() {
        let mut opened: Vec<(String, String)> = Vec::new();
        let answer = download_file(
            "https://a/reestr.txt",
            "e11",
            FILE_TIMEOUT_S,
            FILE_LIMIT_BYTES,
            &mut |url, etag, _timeout, _limit| {
                opened.push((url.to_string(), etag.to_string()));
                Downloaded {
                    body: Some(b"path".to_vec()),
                    etag: etag.to_string(),
                    not_modified: false,
                }
            },
        );
        assert_eq!(answer.body.as_deref(), Some(b"path".as_slice()));
        assert_eq!(
            opened,
            vec![("https://a/reestr.txt".to_string(), "e11".to_string())]
        );
    }

    /// python `system_ipv4` — общий срок DNS_TIMEOUT.
    #[test]
    fn system_ipv4_python() {
        let mut timeouts: Vec<f64> = Vec::new();
        let mut query = |name: &str, timeout: f64| -> crate::windows_dns_query::DnsAnswer {
            timeouts.push(timeout);
            assert_eq!(name, "site.org");
            crate::windows_dns_query::DnsAnswer::default()
        };
        let _ = system_ipv4("site.org", &mut query);
        assert_eq!(timeouts, vec![DNS_TIMEOUT]);
    }

    /// python `system_servers`/`hosts_ipv4` — тонкая обёртка.
    #[test]
    fn wrappers_python() {
        assert_eq!(system_servers(&|| vec!["1.1.1.1".into()]), vec!["1.1.1.1"]);
        assert_eq!(hosts_ipv4("x", &|_h| vec!["2.2.2.2".into()]), vec!["2.2.2.2"]);
    }

    /// python `ping_hop` — классификация ответа узла.
    #[test]
    fn ping_hop_python() {
        let silent = |_ip: &str, _ttl: u8| Some(crate::icmp::TraceHopResult::new(crate::icmp::HOP_SILENT));
        let unsupported = |_ip: &str, _ttl: u8| Some(crate::icmp::TraceHopResult::new(crate::icmp::HOP_UNSUPPORTED));
        let router = |_ip: &str, _ttl: u8| {
            Some(crate::icmp::TraceHopResult {
                kind: crate::icmp::HOP_ROUTER,
                address: "10.0.0.1".to_string(),
                rtt_ms: Some(2.0),
            })
        };
        assert!(ping_hop("site.org", 2, &silent) == Ok(None));
        assert!(ping_hop("site.org", 2, &unsupported) == Err(()));
        assert_eq!(
            ping_hop("site.org", 2, &router),
            Ok(Some(("10.0.0.1".to_string(), Some(2.0))))
        );
    }

    /// python `ping_ok` — замыкание без сети.
    #[test]
    fn ping_ok_python() {
        assert_eq!(ping_ok(&|_ip| Some(true)), Some(true));
        assert_eq!(ping_ok(&|_ip| None), None);
        let _ = REFERENCE_RESOLVERS.len();
    }

    /// Заглушка: реальный ReferenceResolver из dns_reference.
    #[test]
    fn resolver_label_types() {
        let _resolver = ReferenceResolver::new("google", "https://dns.google/dns-query");
    }
}
