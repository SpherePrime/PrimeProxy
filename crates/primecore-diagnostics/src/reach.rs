//! Порт `src/diagnostics/reach.py` — открывается ли сайт: какие его адреса
//! пробовать, в каком порядке и когда верить сбою.
//!
//! Часть проверки одного сайта (`crate::engine`): сюда приходит проба с уже
//! известными адресами (hosts, DNS системы, эталон), отсюда уходит итог
//! основного запроса `probe.reach` и список всех попыток.
//!
//! Одному сбою здесь не верят: молчащий адрес перепроверяется другими
//! адресами сайта, повтором после паузы и попыткой по IPv6 — как это сделал
//! бы браузер.

use crate::limits::{
    HEAD_START_S, REACH_ADDRESSES, RETRY_PAUSE_S, SOURCE_HOSTS, SOURCE_REFERENCE, SOURCE_SYSTEM,
};
use crate::probe_result::{ProbeResult, KIND_CANCELLED, KIND_CERT, KIND_CONNECT};
use crate::run_context::Probe;
use primecore_netfailure::FAILURE_TIMEOUT;

/// Задание отдельной попытки (python `Future`): `None` — таймаут ожидания.
pub trait ReachTask {
    /// python `future.result(timeout=...)`; `None` в аргументе — ждать до конца.
    fn result(&mut self, timeout: Option<f64>) -> Option<ProbeResult>;
}

/// python `Run` — минимальный мост планирования для проверки адресов.
pub trait ReachRun {
    /// python `run.dns_cancelled` — проверку DNS прервали («Стоп», лимит времени).
    fn dns_cancelled(&self) -> bool;
    /// python `run.pause` — пауза между попытками.
    fn pause(&mut self, seconds: f64);
    /// python `run.submit` — попытка в общий залп проверки.
    fn submit(&mut self, ip: &str) -> Box<dyn ReachTask>;
}

/// python `_network_of` — сеть адреса для грубого сравнения: первые два числа IPv4.
#[must_use]
pub fn network_of(ip: &str) -> String {
    if ip.contains('.') {
        let mut parts = ip.splitn(3, '.');
        let first = parts.next().unwrap_or("");
        let second = parts.next().unwrap_or("");
        format!("{first}.{second}")
    } else {
        ip.split(':').next().unwrap_or("").to_string()
    }
}

/// python `same_network` — адреса из одной сети (грубо: совпадают первые два числа).
#[must_use]
pub fn same_network(first: &str, second: &str) -> bool {
    network_of(first) == network_of(second)
}

/// python `_reach_order` — адреса для проверки «открывается ли» и откуда они взяты.
#[must_use]
pub fn reach_order(probe: &Probe, local_ok: bool) -> (Vec<String>, &'static str) {
    if !probe.hosts_ips.is_empty() {
        return (probe.hosts_ips.clone(), SOURCE_HOSTS);
    }
    // Сначала адреса, которые подтвердил эталон: если DNS «через раз»
    // подсовывает чужой адрес, открываемость сайта проверяется по настоящему.
    let mut system = probe.dns.ips.clone();
    system.sort_by_key(|ip| !probe.reference_ips.contains(ip));
    let matches = system.iter().any(|ip| probe.reference_ips.contains(ip));
    if !system.is_empty() && (local_ok || matches || probe.reference_ips.is_empty()) {
        return (system, SOURCE_SYSTEM);
    }
    (probe.reference_ips.clone(), SOURCE_REFERENCE)
}

/// python `_reach_candidates` — все известные адреса сайта: сначала те, что
/// выбрал [`reach_order`], затем остальные.
///
/// Запись в hosts или ответ DNS могут вести на неотвечающий адрес — тогда
/// сайт перепроверяется по остальным, как это сделал бы браузер.
#[must_use]
pub fn reach_candidates(probe: &Probe, order: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for ip in order
        .iter()
        .chain(probe.dns.ips.iter())
        .chain(probe.reference_ips.iter())
    {
        if !ip.is_empty() && !seen.contains(ip) {
            seen.push(ip.clone());
        }
    }
    if seen.is_empty() {
        return seen;
    }
    // После первого адреса — сначала адреса из других сетей: соседние адреса
    // одной сети обычно закрыты или открыты все разом, и четыре попытки в
    // одну сеть ничего не перепроверили бы.
    let first = seen[0].clone();
    let first_network = network_of(&first);
    let mut by_network: Vec<(String, Vec<String>)> = Vec::new();
    for ip in &seen[1..] {
        let network = network_of(ip);
        if let Some(slot) = by_network.iter_mut().find(|(key, _items)| key == &network) {
            slot.1.push(ip.clone());
        } else {
            by_network.push((network, vec![ip.clone()]));
        }
    }
    // python `sorted(...)` — стабильная: сети первого адреса уходят последними.
    by_network.sort_by_key(|(network, _items)| network == &first_network);
    let mut spread: Vec<String> = Vec::new();
    while by_network.iter().any(|(_network, items)| !items.is_empty()) {
        for (_network, items) in by_network.iter_mut() {
            if let Some(item) = (!items.is_empty()).then(|| items.remove(0)) {
                spread.push(item);
            }
        }
    }
    let mut result = vec![first];
    result.extend(spread);
    result
}

/// python `_settled` — хоть одна попытка открыла сайт или проверку прервали.
fn settled(items: &[ProbeResult]) -> bool {
    items
        .iter()
        .any(|item| item.ok() || item.kind == KIND_CANCELLED)
}

/// python `check_reach` — основной запрос «открывается ли» со всеми попытками.
pub fn check_reach(
    probe: &mut Probe,
    run: &mut dyn ReachRun,
    get: &mut dyn FnMut(&str) -> ProbeResult,
    aaaa_lookup: &mut dyn FnMut() -> Vec<String>,
) {
    let local = probe.local_check.clone();
    let (order, source) = reach_order(probe, local.as_ref().is_some_and(|item| item.ok()));
    probe.reach_source = source.to_string();
    if order.is_empty() {
        // Адреса нет потому, что проверку прервали (лимит времени или «Стоп»),
        // — это «не успели», а не «не удалось узнать адрес».
        if run.dns_cancelled() || probe.dns.status == crate::windows_dns_query::ERROR_CANCELLED {
            probe.reach = Some(ProbeResult::new("", KIND_CANCELLED));
        }
        return;
    }
    let all_candidates = reach_candidates(probe, &order);
    let others: Vec<String> = all_candidates
        .into_iter()
        .filter(|ip| ip != &order[0])
        .take(usize::try_from(REACH_ADDRESSES).unwrap_or(4) - 1)
        .collect();

    let mut attempts: Vec<ProbeResult> = Vec::new();
    let mut early: Vec<Box<dyn ReachTask>> = Vec::new();
    if let Some(local) = local {
        if local.ip == order[0] {
            attempts.push(local);
        } else if run.dns_cancelled() {
            // Проверку прервали до первого запроса: это «не успели», а не «не открывается».
            probe.reach = Some(ProbeResult::new("", KIND_CANCELLED));
            return;
        } else {
            let mut first = run.submit(&order[0]);
            match first.result(Some(HEAD_START_S)) {
                Some(item) => attempts.push(item),
                None => {
                    // Живой сайт отвечает за доли секунды. Раз первый адрес
                    // молчит, остальные пробуются сразу, не дожидаясь его
                    // полного срока: так же поступает браузер.
                    early = others.iter().map(|ip| run.submit(ip)).collect();
                    if let Some(item) = first.result(None) {
                        attempts.push(item);
                    }
                }
            }
        }
    } else if run.dns_cancelled() {
        probe.reach = Some(ProbeResult::new("", KIND_CANCELLED));
        return;
    } else {
        let mut first = run.submit(&order[0]);
        match first.result(Some(HEAD_START_S)) {
            Some(item) => attempts.push(item),
            None => {
                early = others.iter().map(|ip| run.submit(ip)).collect();
                if let Some(item) = first.result(None) {
                    attempts.push(item);
                }
            }
        }
    }

    // Чужой сертификат на адресе — повод попробовать другой адрес, но не тот же ещё раз.
    if !settled(&attempts) && !run.dns_cancelled() {
        if !others.is_empty() {
            // Остальные адреса пробуются разом: ждать их по очереди — это десятки секунд.
            let mut futures = early;
            if futures.is_empty() {
                futures = others.iter().map(|ip| run.submit(ip)).collect();
            }
            for mut future in futures {
                if let Some(item) = future.result(None) {
                    attempts.push(item);
                }
            }
            if attempts.iter().all(|item| item.kind == KIND_CONNECT) && !run.dns_cancelled() {
                // Все адреса пробовались в одну секунду: короткий сбой сети
                // задел бы их разом. Ещё одна попытка после паузы отделяет
                // сбой от блокировки.
                run.pause(RETRY_PAUSE_S);
                if !run.dns_cancelled() {
                    attempts.push(get(&order[0]));
                }
            }
        } else if attempts[0].kind != KIND_CERT {
            run.pause(RETRY_PAUSE_S);
            if !run.dns_cancelled() {
                attempts.push(get(&order[0]));
            }
        }
    }

    probe.attempts = attempts.len() as u32;
    probe.tried = attempts
        .iter()
        .filter(|item| item.kind != KIND_CANCELLED)
        .map(|item| (item.ip.clone(), item.kind.clone()))
        .collect();
    probe.tried_silent = !probe.tried.is_empty()
        && attempts
            .iter()
            .filter(|item| item.kind != KIND_CANCELLED)
            .all(|item| item.kind == KIND_CONNECT && item.connect_fail == FAILURE_TIMEOUT);
    let opened = attempts.iter().find(|item| item.ok()).cloned();
    probe.reach = Some(opened.clone().unwrap_or_else(|| attempts[0].clone()));
    if opened.is_none() && run.dns_cancelled() && probe.tried.len() < 2 {
        // Время вышло раньше перепроверки: один сбой — это «не успели», а не «не открывается».
        probe.reach = Some(ProbeResult::new(attempts[0].ip.clone(), KIND_CANCELLED));
        return;
    }
    if let Some(opened) = &opened {
        if !order.contains(&opened.ip) {
            // Открылся адрес не из того источника, с которого начинали.
            probe.reach_source = if probe.dns.ips.contains(&opened.ip) {
                SOURCE_SYSTEM.to_string()
            } else {
                SOURCE_REFERENCE.to_string()
            };
            probe.hosts_stale = source == SOURCE_HOSTS;
        }
    }

    // Браузер сам уходит на IPv6, если IPv4 не отвечает: без этой попытки
    // проверка показала бы ❌ там, где сайт у пользователя открывается.
    // Адреса IPv6 спрашиваются у эталона только здесь: раньше их узнавали для
    // каждого сайта заранее — по четыре лишних шифрованных соединения на сайт.
    let last = probe.reach.clone();
    let Some(last) = last else { return };
    if last.ok() || last.kind == KIND_CANCELLED || last.kind == KIND_CERT || run.dns_cancelled() {
        return;
    }
    let reference_ipv6 = aaaa_lookup();
    probe.reference_ipv6 = reference_ipv6.clone();
    if !reference_ipv6.is_empty() && !run.dns_cancelled() {
        let result = get(&reference_ipv6[0]);
        if result.ok() {
            probe.reach = Some(result);
            probe.hosts_stale = source == SOURCE_HOSTS;
        } else {
            probe.ipv6_result = Some(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::Target;

    fn probe(hosts: &[&str], dns: &[&str], reference: &[&str]) -> Probe {
        Probe {
            target: Target::default(),
            host: "site.org".to_string(),
            hosts_ips: hosts.iter().map(|ip| ip.to_string()).collect(),
            dns: crate::windows_dns_query::DnsAnswer {
                ips: dns.iter().map(|ip| ip.to_string()).collect(),
                ..Default::default()
            },
            reference_ips: reference.iter().map(|ip| ip.to_string()).collect(),
            ..Default::default()
        }
    }

    /// python `_reach_order` — приоритет источников адресов.
    #[test]
    fn order_python() {
        // hosts всегда первые.
        let (order, source) = reach_order(&probe(&["9.9.9.9"], &["1.1.1.1"], &["2.2.2.2"]), false);
        assert_eq!(order, vec!["9.9.9.9"]);
        assert_eq!(source, SOURCE_HOSTS);
        // Система и эталон совпадают — система.
        let (order, source) =
            reach_order(&probe(&[], &["1.1.1.1", "2.2.2.2"], &["2.2.2.2"]), false);
        assert_eq!(order, vec!["2.2.2.2", "1.1.1.1"]);
        assert_eq!(source, SOURCE_SYSTEM);
        // RHS системы с эталоном не совпадает, local_ok=false — эталон.
        let (order, source) = reach_order(&probe(&[], &["3.3.3.3"], &["2.2.2.2"]), false);
        assert_eq!(order, vec!["2.2.2.2"]);
        assert_eq!(source, SOURCE_REFERENCE);
        // Совпадений нет, но local_ok — всё равно система.
        let (order, source) = reach_order(&probe(&[], &["3.3.3.3"], &["2.2.2.2"]), true);
        assert_eq!(order, vec!["3.3.3.3"]);
        assert_eq!(source, SOURCE_SYSTEM);
        // Эталона нет — система даже без совпадений.
        let (order, source) = reach_order(&probe(&[], &["3.3.3.3"], &[]), false);
        assert_eq!(order, vec!["3.3.3.3"]);
        assert_eq!(source, SOURCE_SYSTEM);
    }

    /// python `_reach_candidates` — все адреса, расставленные по сетям.
    #[test]
    fn candidates_python() {
        let sample = probe(&[], &["1.1.1.1", "9.9.9.9", "1.1.1.2"], &["9.9.9.8"]);
        let order = vec!["1.1.1.1".to_string()];
        // Первая сеть — первой, остальные — по широкому разбросу.
        assert_eq!(
            reach_candidates(&sample, &order),
            vec![
                "1.1.1.1",
                // Разные сети до той же, где уже был первый адрес.
                "9.9.9.9", "1.1.1.2", "9.9.9.8",
            ]
        );
    }

    /// python `same_network`.
    #[test]
    fn same_network_python() {
        assert!(same_network("1.2.3.4", "1.2.9.9"));
        assert!(!same_network("1.2.3.4", "1.3.3.4"));
        assert!(same_network("2607:fc00::1", "2607:fca0::9"));
        assert!(!same_network("2607:fc00::1", "1.2.3.4"));
    }
}
