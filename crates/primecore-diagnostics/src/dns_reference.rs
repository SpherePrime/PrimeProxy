//! Порт `src/utils/dns_reference.py` — эталонные DNS-серверы: кому программа
//! верит, когда сравнивает ответы.
//!
//! Запрос к ним идёт шифрованным (DNS поверх HTTPS) и прямо по адресу, без
//! имени: системный DNS в этом не участвует, а сертификат сервера проверяется
//! по его адресу. Такой ответ провайдер не может незаметно подменить по пути.
//!
//! Серверов несколько и у разных владельцев: провайдер может закрыть любой из
//! них (так уже бывало с 8.8.8.8), и эталон не должен пропадать вместе с ним.
//! Проверки сообщают, какой именно сервер недоступен.

use primecore_dnswire::doh::query_doh;
use primecore_dnswire::{DnsQueryResult, FAILURE_CANCELLED};
use primecore_socketcancel::SocketCancel;

/// Один эталонный сервер: подпись для отчёта и адрес без DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceResolver {
    pub label: &'static str,
    pub address: &'static str,
}

impl ReferenceResolver {
    pub const fn new(label: &'static str, address: &'static str) -> Self {
        ReferenceResolver { label, address }
    }
}

/// Эталонные DNS-over-HTTPS серверы, в том порядке, как их пробуют.
pub static REFERENCE_RESOLVERS: [ReferenceResolver; 4] = [
    ReferenceResolver::new("Cloudflare", "1.1.1.1"),
    ReferenceResolver::new("Google", "8.8.8.8"),
    ReferenceResolver::new("AdGuard", "94.140.14.140"),
    ReferenceResolver::new("OpenDNS", "208.67.222.222"),
];

/// Поручить вопрос эталонам: как в python — срок один и тот же, отмена общая.
pub fn doh_query(
    server: &str,
    name: &str,
    rtype: u16,
    timeout_s: f64,
    cancel: Option<&SocketCancel>,
) -> DnsQueryResult {
    query_doh(server, name, rtype, "", 443, "/dns-query", timeout_s, cancel)
}

/// Владелец сети: о нём не должен отвечать перехватчик DNS, поэтому вопрос
/// спрашивается «через голову» сети — эталонам по очереди до первого ответа.
pub type ReferenceAsk<'a> = dyn Fn(&str, u16) -> Option<DnsQueryResult> + 'a;

/// Замыкание `ask(name, rtype)`: первый ответивший сервер или None.
/// Нужен для [`crate::ip_owner::lookup_ip_owner`] и прочих служебных вопросов.
pub struct ReferenceAsker;

pub fn reference_ask(cancel: SocketCancel) -> impl Fn(&str, u16) -> Option<DnsQueryResult> {
    move |name: &str, rtype: u16| -> Option<DnsQueryResult> {
        let mut last: Option<DnsQueryResult> = None;
        for resolver in REFERENCE_RESOLVERS.iter() {
            let result = doh_query(resolver.address, name, rtype, 4.0, Some(&cancel));
            let reached = result.answered() || result.failure == FAILURE_CANCELLED;
            last = Some(result);
            if reached {
                return last;
            }
        }
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolvers_table_python_order() {
        let labels: Vec<&str> = REFERENCE_RESOLVERS.iter().map(|resolver| resolver.label).collect();
        assert_eq!(labels, vec!["Cloudflare", "Google", "AdGuard", "OpenDNS"]);
        assert_eq!(REFERENCE_RESOLVERS[2].address, "94.140.14.140");
    }
}
