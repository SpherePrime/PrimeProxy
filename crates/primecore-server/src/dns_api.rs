//! DNS-ручки HTTP-двери: каталог серверов, заготовка состояния страницы и
//! живая проверка DNS-серверов (`crates/primecore-dns/examples/server_check.rs`
//! — тот же прогон, что вкладка «DNS-серверы» в программе).
//!
//! Живой прогон блокирующий: опрос всех адресов идёт в `std::thread::scope`,
//! поэтому из async он вынесен в [`tokio::task::spawn_blocking`], как и
//! resolver-гонка в [`crate::check_latest`].

use std::sync::Arc;
use std::time::Instant;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::Json;
use primecore_dns::interception::canary_answered;
use primecore_dns::server_check::{
    ask_udp, build_targets, once_doh, once_dot, once_tcp, series, Observation, ServerCheckReport,
};
use primecore_dns::server_check_plans::build_cards;
use primecore_dns::server_check_plans_text::build_text_report;
use primecore_dns::server_check_verdict::{build_verdict, Verdict};
use primecore_dns::server_check_verdicts::judge_report;
use primecore_dnswire::{TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_TCP, TRANSPORT_UDP};
use primecore_socketcancel::SocketCancel;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{bad_request, internal_error};

#[derive(Deserialize)]
pub struct ServerCheckQuery {
    #[serde(default)]
    domain: Option<String>,
}

// ─────────────────────────── endpoints ─────────────────────────────────

/// Каталог DNS-серверов программы целиком: группы и их плитки.
pub async fn providers() -> Json<Value> {
    Json(json!({
        "providers": primecore_dns::providers::dns_providers(),
    }))
}

/// Состояние страницы «Настройка DNS»: каталог серверов и заготовки полей,
/// которые заполнят адаптеры программы, когда появятся.
pub async fn page_state() -> Json<Value> {
    Json(json!({
        "providers": primecore_dns::providers::dns_providers(),
        "local_proxy_mode": "",
        "local_proxy_server": "",
        "line_check": null,
    }))
}

/// Живой прогон проверки серверов: каждый адрес спрашивается UDP, TCP, DoT и
/// DoH, ответы судятся, собирается вердикт, карточки и текстовый отчёт.
pub async fn server_check(
    Query(query): Query<ServerCheckQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let domain = query
        .domain
        .unwrap_or_else(|| "example.com".to_string())
        .trim()
        .to_string();
    if domain.is_empty() {
        return Err(bad_request(
            "domain",
            "домен пуст — проверять нечего".to_string(),
        ));
    }
    // Опрос всех серверов с таймаутами может занять десятки секунд: держим
    // блокирующий прогон из async в отдельном потоке, как предписывает tokio.
    let answer = tokio::task::spawn_blocking(move || run_server_check(&domain))
        .await
        .map_err(|e| {
            internal_error("server_check", format!("фоновая задача не отработала: {e}"))
        })?;
    Ok(Json(answer))
}

/// Проверка одного домена двумя волнами, как вкладка «Проверка домена».
///
/// Живого конструктора [`primecore_dns::domain_lookup_run::LookupIo`] в
/// primecore-dns нет: прогону нужен полный набор сетевых замыканий (DNS-запросы,
/// пинг, TCP, QUIC, сертификаты, внешние сервисы, дорога программ), а живую
/// сборку собирает слой запуска движка. Компактной интеграции не выйдет, поэтому
/// ручка честно отвечает 501 вместо сломанного кода.
pub async fn domain_lookup() -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "domain_lookup: живой прогон ещё не подключён",
        })),
    )
}

// ───────────────────── живой прогон server_check ───────────────────────

/// Полный опрос одного адреса: UDP, TCP, DoT, DoH — по ячейке на способ.
/// Порядок ячеек — как в TRANSPORTS (icmp не спрашиваем — на Linux пинг требует
/// прав root, а на вывод проверки не влияет).
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

fn run_server_check(domain: &str) -> Value {
    let cancel = Arc::new(SocketCancel::new());
    let started = Instant::now();
    let targets = build_targets(primecore_dns::providers::dns_providers(), false);

    // Каждый адрес — в своём потоке: как в программе, опрос идёт залпом.
    let rows: Vec<Observation> = std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                let cancel = Arc::clone(&cancel);
                let domain = domain.to_string();
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

    let verdict = build_verdict(&report);
    let text = build_text_report(&report);
    let cards = build_cards(&report);
    json!({
        "report": report,
        "text": text,
        "verdict": verdict_json(&verdict),
        "cards": cards
            .iter()
            .map(|card| {
                json!({
                    "server": card.server,
                    "status": card.status,
                    "note": card.note,
                    "best": card.best,
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// [`Verdict`] без `Serialize`: собираем JSON вручную по полям.
fn verdict_json(verdict: &Verdict) -> Value {
    json!({
        "kind": verdict.kind,
        "title": verdict.title,
        "detail": verdict.detail,
        "items": verdict
            .items
            .iter()
            .map(|item| json!({
                "level": item.level,
                "title": item.title,
                "detail": item.detail,
            }))
            .collect::<Vec<_>>(),
        "suggests_encrypted_dns": verdict.suggests_encrypted_dns,
    })
}
