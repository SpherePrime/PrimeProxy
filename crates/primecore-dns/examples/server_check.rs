//! Живая проверка DNS-серверов на любой системе — Windows, Linux, macOS.
//!
//! Это тот же прогон, что вкладка «DNS-серверы» в программе: каждый сервер
//! спрашивается всеми способами (UDP 53, TCP 53, DoT 853, DoH 443), ответы
//! судятся (judge_report), собирается вердикт и текстовый отчёт с таблицей.
//!
//! Пинг не делается: на Linux он требует прав root (raw-socket), а на вывод
//! проверки не влияет — молчание пинга обычное дело.
//!
//! Запуск: `cargo run -p primecore-dns --example server_check -- [домен]`
//! Домен по умолчанию — example.com; для горячей пробы подмены возьми
//! заблокированный у себя.

use primecore_diagnostics::dns_reference::REFERENCE_RESOLVERS;
use primecore_dns::interception::canary_answered;
use primecore_dns::server_check::{
    ask_udp, build_targets, once_doh, once_dot, once_tcp, series, Observation, ServerCheckReport,
};
use primecore_dns::server_check_plans::build_cards;
use primecore_dns::server_check_plans_text::build_text_report;
use primecore_dns::server_check_verdict::build_verdict;
use primecore_dns::server_check_verdicts::judge_report;
use primecore_dnswire::{TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_TCP, TRANSPORT_UDP};
use primecore_socketcancel::SocketCancel;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    let cancel = Arc::new(SocketCancel::new());
    let started = Instant::now();

    // Цели — из встроенного каталога программы, IPv6 выключен.
    let providers = primecore_dns::providers::dns_providers();
    let targets = build_targets(providers, false);
    println!("Серверов в списке: {} — опрашиваю всех\n", targets.len());

    // Каждый адрес — в своём потоке: как в программе, опрос идёт залпом.
    let rows: Vec<Observation> = std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                let cancel = Arc::clone(&cancel);
                let domain = domain.clone();
                let address = target.address.clone();
                scope.spawn(move || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        check_target(target, &domain, &cancel)
                    }))
                    .map_err(|panic| {
                        let message = panic
                            .downcast_ref::<&str>()
                            .map(|text| text.to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| format!("{panic:?}"));
                        format!("{address}: {message}")
                    })
                })
            })
            .collect();
        let mut rows = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok(row)) => rows.push(row),
                Ok(Err(message)) => eprintln!("  ! опрос сорвался: {message}"),
                Err(_) => eprintln!("  ! поток опроса паниковал"),
            }
        }
        rows
    });

    // Контрольный адрес без DNS-сервера: кто-то ответил — запросы перехватываются.
    let canary = canary_answered(Some(&cancel));
    if canary {
        println!(
            "\n⚠ Контрольный адрес {} ответил: DNS перехватывается по дороге.\n",
            primecore_dns::interception::CANARY_SERVER
        );
    }

    let report = ServerCheckReport {
        rows,
        total: targets.len(),
        canary: Some(canary),
        finished: true,
        elapsed_s: started.elapsed().as_secs_f64(),
        ..Default::default()
    };
    let report = ServerCheckReport {
        findings: judge_report(&report.rows, report.canary, &|_| None, &[], &|_| false),
        ..report
    };

    println!("{}", build_text_report(&report));
    let verdict = build_verdict(&report);
    println!("\nВЕРДИКТ: {} — {}", verdict.kind, verdict.detail);

    let cards = build_cards(&report);
    for card in &cards {
        println!("  [{}] {} — {}", card.status, card.server, card.note);
    }

    // Эталоны для сравнения: как программа сверяет обычный путь с шифрованным.
    println!(
        "\nЭталоны: {}",
        REFERENCE_RESOLVERS
            .iter()
            .map(|r| r.address)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Полный опрос одного адреса: UDP, TCP, DoT, DoH — по ячейке на способ.
/// Порядок ячеек — как в TRANSPORTS (icmp не спрашиваем — см. шапку файла).
fn check_target(
    target: &primecore_dns::server_check::CheckTarget,
    domain: &str,
    cancel: &SocketCancel,
) -> Observation {
    let udp = series(|| ask_udp(&target.address, domain, cancel), false, None);
    let tcp = series(|| once_tcp(target, domain, cancel), false, None);
    let dot = if target.dot_host.is_empty() {
        primecore_dns::server_check::Cell::default()
    } else {
        series(|| once_dot(target, domain, cancel), false, None)
    };
    let doh = if target.doh_host.is_empty() {
        primecore_dns::server_check::Cell::default()
    } else {
        series(|| once_doh(target, domain, cancel, true), false, None)
    };
    Observation {
        target: target.clone(),
        cells: vec![
            (
                "icmp".to_string(),
                primecore_dns::server_check::Cell::default(),
            ),
            (TRANSPORT_UDP.to_string(), udp),
            (TRANSPORT_TCP.to_string(), tcp),
            (TRANSPORT_DOT.to_string(), dot),
            (TRANSPORT_DOH.to_string(), doh),
        ],
        ..Default::default()
    }
}
