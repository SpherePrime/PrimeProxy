//! Порт `src/dns/latency.py` — замер скорости DNS-серверов.
//!
//! Каждому серверу отправляется настоящий DNS-запрос (UDP, порт 53) и
//! засекается время до ответа. Популярный домен почти наверняка уже лежит в
//! кэше сервера, поэтому замер показывает именно дорогу до сервера, а не
//! скорость его поиска. Из нескольких попыток берётся лучшая: первая часто
//! медленнее из-за прогрева сети.
//!
//! Заодно проверяется перехват (`crate::interception`): если запросы
//! заворачиваются по пути, цифры показывают перехватчик, а не выбранные
//! серверы.

use crate::interception::canary_answered_for;
use primecore_dnswire::net::query_udp;
use primecore_dnswire::{FAILURE_OTHER, TYPE_A};

pub const QUERY_DOMAIN: &str = "google.com";
pub const ATTEMPTS: usize = 3;
pub const TIMEOUT_S: f64 = 1.0;
pub const MAX_PARALLEL: usize = 16;

/// python `DnsLatencyReport` — итог замера: {адрес: мс или None} и признак
/// перехвата DNS по пути.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsLatencyReport {
    /// Порядок как у python dict(zip(...)): серверы без повторов в исходном порядке.
    pub results: Vec<(String, Option<f64>)>,
    pub intercepted: bool,
}

impl DnsLatencyReport {
    /// python `report.results[server]`.
    #[must_use]
    pub fn ms(&self, server: &str) -> Option<Option<f64>> {
        self.results
            .iter()
            .find(|(known, _)| known == server)
            .map(|(_, value)| *value)
    }
}

/// Транспорт одного запроса (python `query_udp`).
pub type ServerQuery<'a> = dyn Fn(&str, &str, f64) -> primecore_dnswire::DnsQueryResult + 'a;

/// python `measure_server_ms` — лучшее время ответа сервера в миллисекундах
/// или None, если он молчит.
#[must_use]
pub fn measure_server_ms_with(
    server: &str,
    query: &ServerQuery<'_>,
    attempts: usize,
    domain: &str,
) -> Option<f64> {
    let mut best: Option<f64> = None;
    for _attempt in 0..attempts.max(1) {
        let result = query(server, domain, TIMEOUT_S);
        if result.failure == FAILURE_OTHER {
            // Не адрес или не имя: повторять бессмысленно.
            return None;
        }
        if let (true, Some(elapsed)) = (result.answered(), result.elapsed_ms) {
            best = match best {
                None => Some(elapsed),
                Some(current) => Some(current.min(elapsed)),
            };
        }
    }
    best
}

/// python `measure_dns_latency(servers)` — замеряет все серверы и заодно
/// проверяет перехват. В python замер идёт параллельно (ThreadPoolExecutor);
/// здесь замыкание `query` само решает, как гонять серверы (движок даёт
/// машину прогона с пулом).
#[must_use]
pub fn measure_dns_latency_with(
    servers: &[String],
    intercepted: bool,
    query: &ServerQuery<'_>,
) -> DnsLatencyReport {
    let mut unique: Vec<String> = Vec::new();
    for server in servers {
        let server = server.trim().to_string();
        if !server.is_empty() && !unique.contains(&server) {
            unique.push(server);
        }
    }
    let results = unique
        .iter()
        .map(|server| {
            (
                server.clone(),
                measure_server_ms_with(server, query, ATTEMPTS, QUERY_DOMAIN),
            )
        })
        .collect();
    DnsLatencyReport {
        results,
        intercepted,
    }
}

/// Живой замер: настоящие UDP-запросы по очереди и настоящая проверка перехвата.
#[must_use]
pub fn measure_dns_latency(servers: &[String]) -> DnsLatencyReport {
    let query =
        |server: &str, name: &str, timeout: f64| query_udp(server, name, TYPE_A, timeout, 53, None);
    let intercepted = canary_answered_for(QUERY_DOMAIN, TIMEOUT_S, None);
    measure_dns_latency_with(servers, intercepted, &query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answering(elapsed_ms: f64) -> primecore_dnswire::DnsQueryResult {
        primecore_dnswire::answered_result(
            "udp",
            primecore_dnswire::parse_response(&[0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0])
                .expect("разобран"),
            elapsed_ms,
        )
    }

    #[test]
    fn best_of_attempts_wins() {
        let times = [40.0, 12.0, 25.0];
        let index = std::sync::atomic::AtomicUsize::new(0);
        let query = |_server: &str, _name: &str, _timeout: f64| {
            let step = index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            answering(times[step % times.len()])
        };
        assert_eq!(
            measure_server_ms_with("9.9.9.9", &query, ATTEMPTS, QUERY_DOMAIN),
            Some(12.0)
        );
    }

    #[test]
    fn silence_is_none_and_bad_input_stops() {
        let query = |_server: &str, _name: &str, _timeout: f64| primecore_dnswire::DnsQueryResult {
            transport: "udp".to_string(),
            failure: primecore_dnswire::FAILURE_TIMEOUT.to_string(),
            ..Default::default()
        };
        assert_eq!(
            measure_server_ms_with("9.9.9.9", &query, 2, QUERY_DOMAIN),
            None
        );
        // Не адрес: повторять бессмысленно.
        let query_bad =
            |_server: &str, _name: &str, _timeout: f64| primecore_dnswire::DnsQueryResult {
                transport: "udp".to_string(),
                failure: FAILURE_OTHER.to_string(),
                ..Default::default()
            };
        assert_eq!(
            measure_server_ms_with("записки", &query_bad, 3, QUERY_DOMAIN),
            None
        );
    }

    #[test]
    fn duplicates_removed_order_kept() {
        let servers = vec![
            "9.9.9.9".to_string(),
            "9.9.9.9".to_string(),
            " ".to_string(),
            "8.8.8.8".to_string(),
        ];
        let query = |_server: &str, _name: &str, _timeout: f64| answering(20.0);
        let report = measure_dns_latency_with(&servers, false, &query);
        assert_eq!(
            report
                .results
                .iter()
                .map(|(server, _)| server.clone())
                .collect::<Vec<_>>(),
            vec!["9.9.9.9".to_string(), "8.8.8.8".to_string()]
        );
        assert_eq!(report.ms("8.8.8.8"), Some(Some(20.0)));
        assert_eq!(report.ms("1.1.1.1"), None);
        assert!(!report.intercepted);
    }
}
