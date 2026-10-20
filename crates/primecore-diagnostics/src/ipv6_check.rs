//! Порт `src/diagnostics/ipv6_check.py` — работает ли IPv6 в этой сети сам по себе.
//!
//! Браузер пробует IPv6 первым. Если IPv6 в системе настроен, но не работает
//! (адрес выдан, а пакеты не ходят), каждый сайт открывается с задержкой.
//! Проверка: к двум заведомо доступным сайтам идёт обычный HTTPS-запрос по их
//! IPv6-адресам. Здесь — данные и чистый вывод (`judge`); сбор (`collect`)
//! — сетевая часть (HTTPS-клиент), портируется следом.

use crate::probe_result::{ProbeResult, KIND_CANCELLED, KIND_CONNECT};

/// У обоих есть IPv6, и их почти никогда не блокируют.
pub const PROBE_HOSTS: [&str; 2] = ["www.google.com", "www.cloudflare.com"];

pub const IPV6_OK: &str = "ok";
pub const IPV6_ABSENT: &str = "absent";
pub const IPV6_BROKEN: &str = "broken";
pub const IPV6_UNKNOWN: &str = "unknown";

/// python `Ipv6Facts` — (сайт, его IPv6-адрес или "", результат или None).
#[derive(Debug, Clone, Default)]
pub struct Ipv6Facts {
    /// Считает ли система, что по IPv6 есть дорога в интернет. None — узнать не удалось.
    pub has_route: Option<bool>,
    pub probes: Vec<(String, String, Option<ProbeResult>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Verdict {
    pub code: String,
    pub text: String,
}

/// python `judge(facts)`
pub fn judge(facts: &Ipv6Facts) -> Ipv6Verdict {
    let results: Vec<&ProbeResult> = facts
        .probes
        .iter()
        .filter_map(|(_host, _ip, result)| result.as_ref())
        .collect();
    let working: Vec<f64> = results
        .iter()
        .filter(|result| result.ok())
        .map(|result| result.elapsed_ms)
        .collect();
    if !working.is_empty() {
        let fastest = working.iter().copied().fold(f64::INFINITY, f64::min);
        return Ipv6Verdict {
            code: IPV6_OK.to_string(),
            text: format!("работает (ответ за {} мс)", (fastest.round() as i64).max(1)),
        };
    }
    if results.iter().any(|result| result.kind == KIND_CANCELLED) {
        return Ipv6Verdict {
            code: IPV6_UNKNOWN.to_string(),
            text: "проверить не успели".to_string(),
        };
    }
    if facts.has_route == Some(false) {
        return Ipv6Verdict {
            code: IPV6_ABSENT.to_string(),
            text: "в этой сети его нет — сайты открываются по IPv4, это нормально".to_string(),
        };
    }
    if results.iter().any(|result| result.kind != KIND_CONNECT) {
        // Сервер по IPv6 ответил, пусть и с ошибкой (сертификат, сброс): дорога есть.
        return Ipv6Verdict {
            code: IPV6_UNKNOWN.to_string(),
            text: "проверочные сайты по IPv6 отвечают, но с ошибкой — сам IPv6, похоже, работает"
                .to_string(),
        };
    }
    if results.is_empty() {
        // Эталонные серверы не дали адресов: судить о самом IPv6 не по чему.
        return Ipv6Verdict {
            code: IPV6_UNKNOWN.to_string(),
            text: "проверить не удалось: не получили адреса проверочных сайтов".to_string(),
        };
    }
    if facts.has_route.is_none() {
        return Ipv6Verdict {
            code: IPV6_UNKNOWN.to_string(),
            text:
                "проверочные сайты по IPv6 не ответили, а есть ли он в системе — узнать не удалось"
                    .to_string(),
        };
    }
    Ipv6Verdict {
        code: IPV6_BROKEN.to_string(),
        text: "настроен, но не работает: Windows считает, что дорога по IPv6 есть, а проверочные сайты по нему не отвечают"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(kind: &str, ok: bool) -> ProbeResult {
        let mut value = ProbeResult {
            kind: kind.to_string(),
            ..Default::default()
        };
        if ok {
            value.kind = KIND_OK.to_string();
        }
        value
    }

    use crate::probe_result::KIND_OK;

    fn facts_mtls(items: Vec<(&str, Option<ProbeResult>)>, route: Option<bool>) -> Ipv6Facts {
        Ipv6Facts {
            has_route: route,
            probes: items
                .into_iter()
                .map(|(host, result)| (host.to_string(), "2606::1".to_string(), result))
                .collect(),
        }
    }

    #[test]
    fn verdicts() {
        let mut working = probe("tls", true);
        working.elapsed_ms = 12.0;
        assert_eq!(
            judge(&facts_mtls(vec![("g", Some(working))], None)).text,
            "работает (ответ за 12 мс)"
        );
        assert_eq!(
            judge(&facts_mtls(
                vec![("g", Some(probe(KIND_CANCELLED, false)))],
                None
            ))
            .text,
            "проверить не успели"
        );
        assert_eq!(
            judge(&facts_mtls(
                vec![("g", Some(probe("connect", false)))],
                Some(false)
            ))
            .code,
            IPV6_ABSENT
        );
        assert_eq!(
            judge(&facts_mtls(
                vec![("g", Some(probe("reset", false)))],
                Some(true)
            ))
            .code,
            IPV6_UNKNOWN
        );
        assert_eq!(judge(&facts_mtls(vec![], None)).code, IPV6_UNKNOWN);
        assert_eq!(
            judge(&facts_mtls(
                vec![("g", Some(probe("connect", false)))],
                None
            ))
            .code,
            IPV6_UNKNOWN
        );
        assert_eq!(
            judge(&facts_mtls(
                vec![("g", Some(probe("connect", false)))],
                Some(true)
            ))
            .code,
            IPV6_BROKEN
        );
    }
}
