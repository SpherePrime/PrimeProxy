//! Порт `src/utils/ip_owner.py` — владелец сети по DNS-службе Team Cymru.
//!
//! Служба отвечает обычными DNS-записями: без сайтов, ключей и ограничений по
//! числу запросов. Первый запрос даёт номер сети (автономной системы), диапазон
//! и страну, второй — название владельца этой сети.
//!
//! Каким способом спрашивать, решает вызывающий: проверка перехвата DNS обязана
//! идти шифрованным путём, иначе о владельце ответит сам перехватчик.

use primecore_dnswire::{DnsQueryResult, TYPE_TXT};
#[cfg(test)]
use primecore_dnswire::DnsRecord;


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpOwner {
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub owner: String,
}

fn texts(result: Option<&DnsQueryResult>) -> Vec<String> {
    match result {
        Some(found) => found.values(TYPE_TXT),
        None => Vec::new(),
    }
}

/// Владелец сети адреса или None, если служба не ответила.
pub fn lookup_ip_owner<F>(ip: &str, ask: F) -> Option<IpOwner>
where
    F: Fn(&str, u16) -> Option<DnsQueryResult>,
{
    let pointer = primecore_dnswire::reverse_name(ip).ok()?;
    let name = if pointer.ends_with(".in-addr.arpa") {
        format!("{}.origin.asn.cymru.com", &pointer[..pointer.len() - ".in-addr.arpa".len()])
    } else {
        format!("{}.origin6.asn.cymru.com", &pointer[..pointer.len() - ".ip6.arpa".len()])
    };
    let all = texts(ask(&name, TYPE_TXT).as_ref());
    if all.is_empty() {
        return None;
    }
    let parts: Vec<String> = all[0].split('|').map(|part| part.trim().to_string()).collect();
    let asn = if !parts.is_empty() && !parts[0].is_empty() {
        parts[0].split_whitespace().next().unwrap_or("").to_string()
    } else {
        String::new()
    };
    let info = IpOwner {
        asn: asn.clone(),
        prefix: if parts.len() > 1 { parts[1].clone() } else { String::new() },
        country: if parts.len() > 2 { parts[2].clone() } else { String::new() },
        ..IpOwner::default()
    };
    if asn.is_empty() {
        return Some(info);
    }
    let owners = texts(ask(&format!("AS{asn}.asn.cymru.com"), TYPE_TXT).as_ref());
    if owners.is_empty() {
        return Some(info);
    }
    Some(IpOwner {
        asn: info.asn,
        prefix: info.prefix,
        country: info.country,
        owner: owners[0].split('|').next_back().unwrap_or("").trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, _rtype: u16) -> Option<DnsQueryResult> {
        let mut result = DnsQueryResult::default();
        let answer = if name.ends_with(".origin.asn.cymru.com") {
            "15169 | 74.125.0.0/16 | US | arin | 2000-03-30"
        } else {
            "15169 | GOOGLE, US"
        };
        result.records.push(DnsRecord { name: String::new(), rtype: TYPE_TXT, ttl: 0, value: answer.to_string() });
        Some(result)
    }

    #[test]
    fn parses_owner_chain() {
        let owner = lookup_ip_owner("74.125.205.100", query).unwrap();
        assert_eq!(owner.asn, "15169");
        assert_eq!(owner.prefix, "74.125.0.0/16");
        assert_eq!(owner.country, "US");
        assert_eq!(owner.owner, "GOOGLE, US");
    }

    #[test]
    fn silent_service_is_none() {
        let none = lookup_ip_owner("74.125.205.100", |_name, _rtype| None);
        assert!(none.is_none());
    }
}
