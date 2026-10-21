//! Порт выводов `src/dns/server_check.py` (`judge_row`, `judge_report`,
//! `rejudge_report`) — продолжение [`crate::server_check`]: только по
//! собранным фактам, без сети.
//!
//! Выводы опираются на противоречия, а не на догадки:
//!
//! - сервер по UDP говорит «сайта нет», а по шифрованному пути тот же сервер
//!   даёт адрес — честный сервер себе не противоречит, ответ подменён;
//! - обычные запросы к серверам разных владельцев выполняет одна и та же
//!   чужая сеть — их перехватывают и уводят на общий сервер, а обратный адрес
//!   подставляют, будто ответил выбранный;
//! - ответил адрес, где DNS-сервера нет ([`crate::interception`]).

use crate::server_check::{
    Cell, Finding, IpOwner, Observation, ServerCheckReport, CODE_ALL_FINE, CODE_BEST,
    CODE_BYPASS_RUNNING, CODE_DEAD, CODE_DOH_BLOCKED, CODE_DOH_NAME_BLOCKED, CODE_DOT_BLOCKED,
    CODE_FOREIGN_ANSWERS, CODE_INTERCEPTED, CODE_SELF_FILTER, CODE_SPOOFED, CODE_TCP_BLOCKED,
    CODE_UDP_BLOCKED, CODE_UNSTABLE, LEVEL_FAIL, LEVEL_INFO, LEVEL_OK, LEVEL_WARN, STATE_FAIL,
    STATE_OK, TRANSPORT_ICMP,
};
use primecore_dnswire::{
    FAILURE_TIMEOUT, STATUS_NXDOMAIN, TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_TCP, TRANSPORT_UDP,
};

/// Пути сравнения, которые по дороге не подменить. Обычный TCP:53 сюда не
/// входит: перехватчик подменяет его так же, как UDP, — по нему видно лишь,
/// что UDP режут отдельно.
fn encrypted_path(via: &str) -> bool {
    via == TRANSPORT_DOH || via == TRANSPORT_DOT
}

/// python `_path_words` — как назвать путь сравнения: («по шифрованному
/// пути», «шифрованные») или то же про TCP.
fn path_words(row: &Observation) -> (&'static str, &'static str) {
    if encrypted_path(&row.secure_via) {
        ("по шифрованному пути", "шифрованные")
    } else {
        ("по TCP", "запросы по TCP")
    }
}

/// python `_owner_name` — название владельца: имя или номер сети.
#[must_use]
pub fn owner_name(owner: Option<&IpOwner>) -> String {
    let Some(owner) = owner else {
        return String::new();
    };
    if !owner.owner.is_empty() {
        owner.owner.clone()
    } else if !owner.asn.is_empty() {
        format!("AS{}", owner.asn)
    } else {
        String::new()
    }
}

/// python `_foreign_network` — сеть, которая отвечает на обычные запросы
/// вместо сервера (или None).
fn foreign_network(
    row: &Observation,
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
) -> Option<IpOwner> {
    let udp_owner = owner_of(&row.udp_egress)?;
    let secure_owner = owner_of(&row.secure_egress)?;
    if udp_owner.asn.is_empty() || secure_owner.asn.is_empty() {
        return None;
    }
    (udp_owner.asn != secure_owner.asn).then(|| udp_owner.clone())
}

/// python `_spoofed_domains` — сайты, про которые сервер обычным путём
/// ответил не то, что шифрованным.
///
/// Молчание на обычный запрос подменой не считается: сервер мог просто долго
/// искать ответ. Считается только явное «сайта нет» или адрес-заглушка.
/// Заглушки распознаёт `diagnostics::address_kinds` — он приходит замыканием,
/// чтобы не тянуть зависимости.
fn spoofed_domains(row: &Observation, is_stub: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut spoofed = Vec::new();
    for fact in &row.domains {
        let genuine = fact.secure_ips.iter().any(|ip| !is_stub(ip));
        if !genuine {
            // Шифрованным путём сервер адреса не дал: сравнивать не с чем.
            continue;
        }
        if fact.udp_status == STATUS_NXDOMAIN || fact.udp_ips.iter().any(|ip| is_stub(ip)) {
            spoofed.push(fact.domain.clone());
        }
    }
    spoofed
}

/// python `resolvable_domains` — контрольные сайты, настоящий адрес которых
/// шифрованным путём дал хоть один сервер.
#[must_use]
pub fn resolvable_domains(rows: &[Observation], is_stub: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for row in rows {
        for fact in &row.domains {
            if fact.secure_ips.iter().any(|ip| !is_stub(ip)) && !found.contains(&fact.domain) {
                found.push(fact.domain.clone());
            }
        }
    }
    found
}

/// python `_self_filtered_domains` — сайты, которые сервер не отдаёт сам:
/// «сайта нет» или заглушка даже по шифрованному пути.
///
/// Шифрованный ответ по дороге не подменить, значит так решил сам сервер.
/// Чтобы не записать в фильтрацию сайт, которого и правда нет, берём только
/// сайты, настоящий адрес которых в этой же проверке дал другой сервер. Если
/// сравнивали по обычному TCP, вывода нет: такой ответ мог подменить и
/// перехватчик.
fn self_filtered_domains(
    row: &Observation,
    resolvable: &[String],
    is_stub: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    if !encrypted_path(&row.secure_via) {
        return Vec::new();
    }
    let mut filtered = Vec::new();
    for fact in &row.domains {
        if !resolvable.contains(&fact.domain) {
            continue;
        }
        let stub = !fact.secure_ips.is_empty() && fact.secure_ips.iter().all(|ip| is_stub(ip));
        if fact.secure_status == STATUS_NXDOMAIN || stub {
            filtered.push(fact.domain.clone());
        }
    }
    filtered
}

const SERIES_TITLES: [&str; 4] = ["обычный DNS (UDP)", "DNS по TCP", "DoT", "DoH"];

/// python `_unstable_level` — один запрос без ответа — случайная потеря.
/// Обрыв или два срыва из трёх — уже не случайность.
fn unstable_level(shaky: &[(&str, &Cell)]) -> &'static str {
    for (_title, cell) in shaky {
        if cell.attempts() - cell.answered() >= 2 || cell.failure != FAILURE_TIMEOUT {
            return LEVEL_WARN;
        }
    }
    LEVEL_INFO
}

/// python `judge_row` — выводы об одном адресе. Только по собранным фактам.
///
/// `resolvable` — контрольные сайты, которые точно существуют (см.
/// [`resolvable_domains`]): по ним видно, что сервер фильтрует ответы сам.
#[must_use]
pub fn judge_row(
    row: &Observation,
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
    resolvable: &[String],
    is_stub: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let udp = row.cell(TRANSPORT_UDP);
    let tcp = row.cell(TRANSPORT_TCP);
    let dot = row.cell(TRANSPORT_DOT);
    let doh = row.cell(TRANSPORT_DOH);
    let dns_cells: Vec<&Cell> = [&udp, &tcp, &dot, &doh]
        .into_iter()
        .filter(|cell| cell.state == STATE_OK || cell.state == STATE_FAIL)
        .collect();

    if !dns_cells.is_empty() && dns_cells.iter().all(|cell| cell.failed()) {
        let alive = if row.cell(TRANSPORT_ICMP).ok() {
            " (на пинг при этом отвечает)"
        } else {
            ""
        };
        return vec![Finding {
            level: LEVEL_FAIL.to_string(),
            code: CODE_DEAD.to_string(),
            text: format!("не отвечает ни одним способом{alive}"),
            ..Finding::default()
        }];
    }

    let (path, path_requests) = path_words(row);
    let spoofed = spoofed_domains(row, is_stub);
    if !spoofed.is_empty() {
        findings.push(Finding {
            level: LEVEL_FAIL.to_string(),
            code: CODE_SPOOFED.to_string(),
            text: format!(
                "обычные ответы подменяются: про {} приходит «сайта нет» или заглушка, \
                 хотя {} тот же сервер даёт настоящий адрес",
                spoofed.join(", "),
                path
            ),
            ..Finding::default()
        });
    }
    let filtered = self_filtered_domains(row, resolvable, is_stub);
    if !filtered.is_empty() {
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_SELF_FILTER.to_string(),
            text: format!(
                "сам не отдаёт адреса сайтов: {} — так он отвечает и по шифрованному пути, \
                 который по дороге не подменить; это решение самого сервера, а не провайдера",
                filtered.join(", ")
            ),
            ..Finding::default()
        });
    }
    let foreign = foreign_network(row, owner_of);
    if let Some(foreign) = foreign {
        // Само по себе это не тревога: так устроены и некоторые серверы.
        // Перехват признаётся в общем итоге, когда одна сеть отвечает за
        // разных владельцев.
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_FOREIGN_ANSWERS.to_string(),
            text: format!(
                "обычные запросы выполняет сеть {}, а {} — {}",
                owner_name(Some(&foreign)),
                path_requests,
                owner_name(owner_of(&row.secure_egress).as_ref())
            ),
            ..Finding::default()
        });
    }
    if udp.failed() {
        findings.push(Finding {
            level: LEVEL_FAIL.to_string(),
            code: CODE_UDP_BLOCKED.to_string(),
            text: format!("обычный DNS (UDP) закрыт: {}", udp.reason),
            ..Finding::default()
        });
    }
    if tcp.failed() && !udp.failed() {
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_TCP_BLOCKED.to_string(),
            text: format!("DNS по TCP не проходит: {}", tcp.reason),
            ..Finding::default()
        });
    }
    if dot.failed() {
        findings.push(Finding {
            level: LEVEL_WARN.to_string(),
            code: CODE_DOT_BLOCKED.to_string(),
            text: format!("шифрованный DNS по DoT закрыт: {}", dot.reason),
            ..Finding::default()
        });
    }
    if doh.failed() {
        if row.doh_by_address.as_ref().is_some_and(Cell::ok) {
            findings.push(Finding {
                level: LEVEL_WARN.to_string(),
                code: CODE_DOH_NAME_BLOCKED.to_string(),
                text: format!(
                    "шифрованный DNS по DoH закрыт по имени {}: без имени тот же адрес отвечает — \
                     так блокируют по имени сервера",
                    row.target.doh_host
                ),
                ..Finding::default()
            });
        } else {
            findings.push(Finding {
                level: LEVEL_WARN.to_string(),
                code: CODE_DOH_BLOCKED.to_string(),
                text: format!("шифрованный DNS по DoH закрыт: {}", doh.reason),
                ..Finding::default()
            });
        }
    }
    let shaky: Vec<(&str, &Cell)> = SERIES_TITLES
        .iter()
        .copied()
        .zip([&udp, &tcp, &dot, &doh])
        .filter(|(_title, cell)| cell.unstable())
        .collect();
    if !shaky.is_empty() {
        let parts: Vec<String> = shaky
            .iter()
            .map(|(title, cell)| {
                format!(
                    "{title} — {} из {} запросов ({})",
                    cell.answered(),
                    cell.attempts(),
                    cell.reason
                )
            })
            .collect();
        let fades = if shaky.iter().any(|(_title, cell)| cell.fades()) {
            " Первые запросы проходят, а следующие уже нет."
        } else {
            ""
        };
        findings.push(Finding {
            level: unstable_level(&shaky).to_string(),
            code: CODE_UNSTABLE.to_string(),
            text: format!("отвечает через раз: {}.{fades}", parts.join("; ")),
            ..Finding::default()
        });
    }
    findings
}

/// python `_label` — «провайдер (адрес)».
fn label(row: &Observation) -> String {
    format!("{} ({})", row.target.provider, row.target.address)
}

fn pair(row: &Observation) -> (String, String) {
    (row.target.provider.clone(), row.target.address.clone())
}

fn labels(servers: &[(String, String)]) -> Vec<String> {
    servers
        .iter()
        .map(|(provider, address)| format!("{provider} ({address})"))
        .collect()
}

/// python `_short_list` — до четырёх пунктов, дальше «и ещё N».
fn short_list(items: &[String], limit: usize) -> String {
    let shown = items
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > limit {
        format!("{shown} и ещё {}", items.len() - limit)
    } else {
        shown
    }
}

/// python `_shared_foreign_network` — чужая сеть, которая отвечает на обычные
/// запросы серверам разных владельцев.
///
/// Владельца сервера выдаёт сеть, через которую он выполняет шифрованные
/// запросы: её по дороге не подменить. Два названия одного владельца (у них
/// эта сеть общая) перехватом не считаются — так сервер может быть устроен
/// сам.
fn shared_foreign_network(
    rows: &[Observation],
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
) -> (Option<IpOwner>, Vec<String>) {
    let mut providers_by_asn: Vec<(String, Vec<String>)> = Vec::new();
    let mut operators_by_asn: Vec<(String, Vec<String>)> = Vec::new();
    let mut owners: Vec<(String, IpOwner)> = Vec::new();
    for row in rows {
        let Some(foreign) = foreign_network(row, owner_of) else {
            continue;
        };
        let secure_asn = owner_of(&row.secure_egress)
            .map(|owner| owner.asn.clone())
            .unwrap_or_default();
        if let Some(entry) = owners.iter_mut().find(|(asn, _)| *asn == foreign.asn) {
            entry.1 = foreign.clone();
        } else {
            owners.push((foreign.asn.clone(), foreign.clone()));
        }
        if let Some((_, operators)) = operators_by_asn
            .iter_mut()
            .find(|(asn, _)| *asn == foreign.asn)
        {
            if !operators.contains(&secure_asn) {
                operators.push(secure_asn);
            }
        } else {
            operators_by_asn.push((foreign.asn.clone(), vec![secure_asn]));
        }
        let names = match providers_by_asn
            .iter_mut()
            .find(|(asn, _)| *asn == foreign.asn)
        {
            Some((_, names)) => names,
            None => {
                providers_by_asn.push((foreign.asn.clone(), Vec::new()));
                &mut providers_by_asn.last_mut().expect("только вставили").1
            }
        };
        if !names.contains(&row.target.provider) {
            names.push(row.target.provider.clone());
        }
    }
    for (asn, operators) in &operators_by_asn {
        if operators.len() >= 2 {
            let owner = owners
                .iter()
                .find(|(known, _)| known == asn)
                .map(|(_, owner)| owner.clone());
            let providers = providers_by_asn
                .iter()
                .find(|(known, _)| known == asn)
                .map(|(_, names)| names.clone())
                .unwrap_or_default();
            return (owner, providers);
        }
    }
    (None, Vec::new())
}

fn has(row: &Observation, code: &str, level: &str) -> bool {
    row.findings
        .iter()
        .any(|finding| finding.code == code && (level.is_empty() || finding.level == level))
}

fn without_remarks(row: &Observation) -> bool {
    !row.findings
        .iter()
        .any(|finding| finding.level == LEVEL_WARN || finding.level == LEVEL_FAIL)
}

/// Меньше адресов — не «закрыт весь способ», а совпадение.
const WHOLESALE_MIN: usize = 3;

/// python `_transport_summary` — одна находка о закрытом способе связи:
/// «закрыт целиком» или у каких серверов.
fn transport_summary(
    rows: &[Observation],
    transport: &str,
    title: &str,
    codes: &[&str],
    code: &str,
) -> Option<Finding> {
    let tried: Vec<&Observation> = rows
        .iter()
        .filter(|row| {
            let cell = row.cell(transport);
            cell.state == STATE_OK || cell.state == STATE_FAIL
        })
        .collect();
    let closed: Vec<&Observation> = tried
        .iter()
        .copied()
        .filter(|row| {
            row.findings
                .iter()
                .any(|finding| codes.contains(&finding.code.as_str()))
        })
        .collect();
    if closed.is_empty() {
        return None;
    }
    if closed.len() == tried.len() && tried.len() >= WHOLESALE_MIN {
        let note = format!("не ответил ни один из {} адресов.", tried.len());
        return Some(Finding {
            level: LEVEL_WARN.to_string(),
            code: code.to_string(),
            text: format!("{title} закрыт целиком: {note}"),
            title: format!("{title} закрыт целиком"),
            note: capital(&note),
            ..Finding::default()
        });
    }
    let servers: Vec<(String, String)> = closed.iter().map(|row| pair(row)).collect();
    let head = format!("{title} закрыт у части серверов");
    Some(Finding {
        level: LEVEL_WARN.to_string(),
        code: code.to_string(),
        text: format!("{head}: {}.", short_list(&labels(&servers), 4)),
        title: head,
        servers,
        ..Finding::default()
    })
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// python `judge_report` — общий итог по всем адресам: сначала самое важное.
#[must_use]
pub fn judge_report(
    rows: &[Observation],
    canary: Option<bool>,
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
    bypass: &[String],
    _is_stub: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    if !bypass.is_empty() {
        // Первой строкой: от этого зависит, как читать всё остальное.
        let note = format!(
            "{}. Такие программы меняют соединения и DNS, поэтому результат показывает сеть \
             вместе с ними, а не «чистую» сеть провайдера.",
            bypass.join(", ")
        );
        let head = "Во время проверки работали";
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_BYPASS_RUNNING.to_string(),
            text: format!("{head}: {note}"),
            title: head.to_string(),
            note,
            ..Finding::default()
        });
    }
    let (network, providers) = shared_foreign_network(rows, owner_of);
    if canary == Some(true) || network.is_some() {
        let mut evidence: Vec<String> = Vec::new();
        if canary == Some(true) {
            evidence.push("ответил адрес, где DNS-сервера нет".to_string());
        }
        if let Some(network) = network.as_ref() {
            evidence.push(format!(
                "обычные запросы к {} на самом деле выполняет одна сеть — {}",
                short_list(&providers, 4),
                owner_name(Some(network))
            ));
        }
        let head = "Обычные DNS-запросы перехватываются по дороге (провайдером или роутером)";
        let note = format!(
            "{}. Какой бы сервер вы ни выбрали, без шифрования отвечает перехватчик.",
            evidence.join("; ")
        );
        findings.push(Finding {
            level: LEVEL_FAIL.to_string(),
            code: CODE_INTERCEPTED.to_string(),
            text: format!("{head}: {note}"),
            title: head.to_string(),
            note: capital(&note),
            ..Finding::default()
        });
    }

    let spoofed: Vec<(String, String)> = rows
        .iter()
        .filter(|row| has(row, CODE_SPOOFED, ""))
        .map(pair)
        .collect();
    if !spoofed.is_empty() {
        let head = "Обычные ответы подменяются у серверов";
        findings.push(Finding {
            level: LEVEL_FAIL.to_string(),
            code: CODE_SPOOFED.to_string(),
            text: format!("{head}: {}.", short_list(&labels(&spoofed), 4)),
            title: head.to_string(),
            servers: spoofed,
            ..Finding::default()
        });
    }

    let closed = [
        transport_summary(
            rows,
            TRANSPORT_DOT,
            "Шифрованный DNS по DoT (порт 853)",
            &[CODE_DOT_BLOCKED],
            CODE_DOT_BLOCKED,
        ),
        transport_summary(
            rows,
            TRANSPORT_DOH,
            "Шифрованный DNS по DoH (порт 443)",
            &[CODE_DOH_BLOCKED, CODE_DOH_NAME_BLOCKED],
            CODE_DOH_BLOCKED,
        ),
        transport_summary(
            rows,
            TRANSPORT_UDP,
            "Обычный DNS (UDP, порт 53)",
            &[CODE_UDP_BLOCKED],
            CODE_UDP_BLOCKED,
        ),
    ];
    findings.extend(closed.into_iter().flatten());
    // Случайные потери и настоящие срывы — разные вещи: первые только считаем,
    // вторые называем.
    let shaky: Vec<(String, String)> = rows
        .iter()
        .filter(|row| has(row, CODE_UNSTABLE, LEVEL_WARN))
        .map(pair)
        .collect();
    if !shaky.is_empty() {
        let head = "Отвечают через раз";
        let note = "Так бывает, когда блокировка включается не с первого запроса.";
        findings.push(Finding {
            level: LEVEL_WARN.to_string(),
            code: CODE_UNSTABLE.to_string(),
            text: format!("{head}: {}. {note}", short_list(&labels(&shaky), 4)),
            title: head.to_string(),
            servers: shaky,
            note: note.to_string(),
        });
    }
    let lossy = rows
        .iter()
        .filter(|row| has(row, CODE_UNSTABLE, LEVEL_INFO))
        .count();
    if lossy > 0 {
        let head = "Потеряли по одному запросу";
        let note = format!(
            "{} из {} адресов. Похоже на обычные потери в сети.",
            lossy,
            rows.len()
        );
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_UNSTABLE.to_string(),
            text: format!("{head}: {note}"),
            title: head.to_string(),
            note,
            ..Finding::default()
        });
    }
    let filtering: Vec<(String, String)> = rows
        .iter()
        .filter(|row| has(row, CODE_SELF_FILTER, ""))
        .map(pair)
        .collect();
    if !filtering.is_empty() {
        // Фильтрует сервис целиком, поэтому во фразе — названия без повторов;
        // адреса — в перечне.
        let mut names: Vec<String> = Vec::new();
        for (provider, _address) in &filtering {
            if !names.contains(provider) {
                names.push(provider.clone());
            }
        }
        let head = "Сами не отдают часть сайтов";
        let note = "Это решение самих серверов: так они отвечают и по шифрованному пути.";
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_SELF_FILTER.to_string(),
            text: format!("{head}: {}. {note}", short_list(&names, 4)),
            title: head.to_string(),
            servers: filtering,
            note: note.to_string(),
        });
    }
    let dead: Vec<(String, String)> = rows
        .iter()
        .filter(|row| has(row, CODE_DEAD, ""))
        .map(pair)
        .collect();
    if !dead.is_empty() {
        let head = "Не отвечают совсем";
        findings.push(Finding {
            level: LEVEL_INFO.to_string(),
            code: CODE_DEAD.to_string(),
            text: format!("{head}: {}.", short_list(&labels(&dead), 4)),
            title: head.to_string(),
            servers: dead,
            ..Finding::default()
        });
    }

    // Windows шифрует запросы по DoH и по имени сервера: годится только тот,
    // кто так отвечает.
    let usable: Vec<&Observation> =
        rows.iter()
            .filter(|row| {
                let cell = row.cell(TRANSPORT_DOH);
                cell.ok()
                    && !cell.unstable()
                    && !row.findings.iter().any(|finding| {
                        finding.code == CODE_SPOOFED || finding.code == CODE_SELF_FILTER
                    })
            })
            .collect();
    if !usable.is_empty() {
        let best = usable
            .iter()
            .copied()
            .min_by(|left, right| {
                let left = left.cell(TRANSPORT_DOH).elapsed_ms.unwrap_or(f64::INFINITY);
                let right = right
                    .cell(TRANSPORT_DOH)
                    .elapsed_ms
                    .unwrap_or(f64::INFINITY);
                left.partial_cmp(&right).expect("без NaN")
            })
            .expect("список не пуст");
        let clean = rows.iter().filter(|row| without_remarks(row)).count();
        let elapsed = best.cell(TRANSPORT_DOH).elapsed_ms.unwrap_or(0.0);
        let note = format!(
            "шифрованный запрос проходит за {} мс. Без замечаний: {} из {} адресов.",
            elapsed.round().max(1.0) as u64,
            clean,
            rows.len()
        );
        findings.push(Finding {
            level: LEVEL_OK.to_string(),
            code: CODE_BEST.to_string(),
            text: format!(
                "Для защищённого DNS сейчас лучше всего подходит {}: {note}",
                label(best)
            ),
            title: "Для защищённого DNS сейчас лучше всего подходит".to_string(),
            servers: vec![pair(best)],
            note: capital(&note),
        });
    } else if !rows.is_empty()
        && !findings.iter().any(|finding| {
            finding.level == LEVEL_WARN || finding.level == LEVEL_FAIL || finding.level == LEVEL_OK
        })
        && !findings.iter().any(|finding| finding.code == CODE_DEAD)
    {
        findings.push(Finding {
            level: LEVEL_OK.to_string(),
            code: CODE_ALL_FINE.to_string(),
            text: "Замечаний нет.".to_string(),
            title: "Замечаний нет".to_string(),
            ..Finding::default()
        });
    }
    findings
}

/// python `rejudge_report` — выводы законченной проверки заново, по нынешним
/// правилам и тем же сырым фактам.
///
/// Нужен прошлым проверкам из файла: в нём лежат и факты, и выводы того дня.
/// Остановленная проверка выводов не имеет и остаётся как есть.
#[must_use]
pub fn rejudge_report(
    report: &ServerCheckReport,
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
    is_stub: &dyn Fn(&str) -> bool,
) -> ServerCheckReport {
    if !report.finished || report.stopped {
        return report.clone();
    }
    let resolvable = resolvable_domains(&report.rows, is_stub);
    let rows: Vec<Observation> = report
        .rows
        .iter()
        .map(|row| Observation {
            findings: judge_row(row, owner_of, &resolvable, is_stub),
            ..row.clone()
        })
        .collect();
    let findings = judge_report(&rows, report.canary, owner_of, &report.bypass, is_stub);
    ServerCheckReport {
        rows,
        findings,
        ..report.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_check::TRANSPORTS;
    use crate::server_check::{CheckTarget, DomainFact};
    use primecore_dnswire::TYPE_A;

    fn owner(asn: &str, name: &str) -> IpOwner {
        IpOwner {
            asn: asn.to_string(),
            owner: name.to_string(),
            ..Default::default()
        }
    }

    fn target(provider: &str, address: &str) -> CheckTarget {
        CheckTarget {
            provider: provider.to_string(),
            address: address.to_string(),
            ..Default::default()
        }
    }

    fn ok_cell(trail: &[bool]) -> Cell {
        Cell {
            state: STATE_OK.to_string(),
            elapsed_ms: Some(12.0),
            trail: trail.to_vec(),
            ..Cell::default()
        }
    }

    fn fail_cell(failure: &str, reason: &str) -> Cell {
        Cell {
            state: STATE_FAIL.to_string(),
            failure: failure.to_string(),
            reason: reason.to_string(),
            ..Cell::default()
        }
    }

    #[test]
    fn dead_when_all_dns_ways_fail() {
        let row = Observation {
            target: target("X", "1.1.1.1"),
            cells: vec![
                (TRANSPORT_ICMP.to_string(), ok_cell(&[])),
                (
                    TRANSPORT_UDP.to_string(),
                    fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                ),
                (
                    TRANSPORT_TCP.to_string(),
                    fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                ),
                (
                    TRANSPORT_DOT.to_string(),
                    fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                ),
                (
                    TRANSPORT_DOH.to_string(),
                    fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                ),
            ],
            ..Default::default()
        };
        let findings = judge_row(&row, &|_ip| None, &[], &|_ip| false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CODE_DEAD);
        assert!(findings[0].text.contains("на пинг при этом отвечает"));
        // Пинг молчит — без оговорки.
        let mut row = row;
        row.cells[0].1 = fail_cell(FAILURE_TIMEOUT, "не отвечает на пинг");
        let findings = judge_row(&row, &|_ip| None, &[], &|_ip| false);
        assert!(!findings[0].text.contains("на пинг"));
    }

    #[test]
    fn spoofed_when_nxdomain_but_secure_answered() {
        let row = Observation {
            target: target("X", "1.1.1.1"),
            cells: vec![
                (TRANSPORT_UDP.to_string(), ok_cell(&[true])),
                (TRANSPORT_DOH.to_string(), ok_cell(&[true])),
            ],
            secure_via: TRANSPORT_DOH.to_string(),
            domains: vec![
                DomainFact {
                    domain: "rutor.info".to_string(),
                    udp_status: STATUS_NXDOMAIN.to_string(),
                    secure_status: "ok".to_string(),
                    secure_ips: vec!["1.2.3.4".to_string()],
                    ..Default::default()
                },
                DomainFact {
                    domain: "example.org".to_string(),
                    udp_status: "ok".to_string(),
                    udp_ips: vec!["5.6.7.8".to_string()],
                    secure_status: "ok".to_string(),
                    secure_ips: vec!["5.6.7.8".to_string()],
                },
            ],
            ..Default::default()
        };
        let findings = judge_row(&row, &|_ip| None, &[], &|_ip| false);
        assert!(findings.iter().any(|finding| finding.code == CODE_SPOOFED));
        assert!(findings[0].text.contains("rutor.info"));
        assert!(!findings[0].text.contains("example.org"));
    }

    #[test]
    fn spoofed_by_stub_address() {
        let row = Observation {
            target: target("X", "1.1.1.1"),
            cells: vec![
                (TRANSPORT_UDP.to_string(), ok_cell(&[true])),
                (TRANSPORT_DOH.to_string(), ok_cell(&[true])),
            ],
            secure_via: TRANSPORT_DOH.to_string(),
            domains: vec![DomainFact {
                domain: "flibusta.is".to_string(),
                udp_status: "ok".to_string(),
                udp_ips: vec!["5.61.33.9".to_string()],
                secure_status: "ok".to_string(),
                secure_ips: vec!["1.2.3.4".to_string()],
            }],
            ..Default::default()
        };
        let findings = judge_row(&row, &|_ip| None, &[], &|ip| ip == "5.61.33.9");
        assert!(findings.iter().any(|finding| finding.code == CODE_SPOOFED));
    }

    #[test]
    fn self_filter_needs_resolvable_and_encrypted_path() {
        let fact = DomainFact {
            domain: "rezka.ag".to_string(),
            secure_status: STATUS_NXDOMAIN.to_string(),
            ..Default::default()
        };
        let mut row = Observation {
            target: target("X", "1.1.1.1"),
            secure_via: TRANSPORT_TCP.to_string(),
            domains: vec![fact.clone()],
            ..Default::default()
        };
        // Сравнивали по TCP — вывода нет: подменить мог и перехватчик.
        let findings = judge_row(&row, &|_ip| None, &["rezka.ag".to_string()], &|_ip| false);
        assert!(!findings
            .iter()
            .any(|finding| finding.code == CODE_SELF_FILTER));
        // Шифрованный путь + сайт резолвится другим сервером → вывод.
        row.secure_via = TRANSPORT_DOH.to_string();
        let findings = judge_row(&row, &|_ip| None, &["rezka.ag".to_string()], &|_ip| false);
        assert!(findings
            .iter()
            .any(|finding| finding.code == CODE_SELF_FILTER));
    }

    #[test]
    fn foreign_network_and_shared_one() {
        let row = Observation {
            target: target("Cloudflare", "1.1.1.1"),
            cells: vec![(TRANSPORT_DOH.to_string(), ok_cell(&[true]))],
            secure_via: TRANSPORT_DOH.to_string(),
            udp_egress: "203.0.113.5".to_string(),
            secure_egress: "198.51.100.5".to_string(),
            ..Default::default()
        };
        let owners = |ip: &str| match ip {
            "203.0.113.5" => Some(owner("12345", "Chaos")),
            "198.51.100.5" => Some(owner("13335", "Cloudflare")),
            _ => None,
        };
        let findings = judge_row(&row, &owners, &[], &|_ip| false);
        let foreign = findings
            .iter()
            .find(|finding| finding.code == CODE_FOREIGN_ANSWERS)
            .expect("чужая сеть замечена");
        assert!(foreign.text.contains("Chaos"));
        assert!(foreign.text.contains("Cloudflare"));
        // Одна и та же сеть — не находка.
        let owners_same = |_ip: &str| Some(owner("13335", "Cloudflare"));
        let findings = judge_row(&row, &owners_same, &[], &|_ip| false);
        assert!(!findings
            .iter()
            .any(|finding| finding.code == CODE_FOREIGN_ANSWERS));
        // Общий перехват: одна сеть за двумя владельцами (у второго сервера
        // обычные запросы выполняет та же чужая сеть Chaos, а шифрованные —
        // другой владелец).
        let mut second = row.clone();
        second.target = target("Quad9", "9.9.9.9");
        let owners_two = |ip: &str| match ip {
            "203.0.113.5" => Some(owner("12345", "Chaos")),
            "198.51.100.5" => Some(owner("13335", "Cloudflare")),
            "203.0.113.6" => Some(owner("12345", "Chaos")),
            "198.51.100.9" => Some(owner("21681", "Quad9")),
            _ => None,
        };
        second.udp_egress = "203.0.113.6".to_string();
        second.secure_egress = "198.51.100.9".to_string();
        let (network, providers) = shared_foreign_network(&[row, second], &owners_two);
        assert!(network.is_some());
        assert_eq!(network.expect("сеть").owner, "Chaos");
        assert!(providers.contains(&"Cloudflare".to_string()));
        assert!(providers.contains(&"Quad9".to_string()));
    }

    #[test]
    fn unstable_findings_and_levels() {
        // Два срыва из трёх — warn; один — info.
        let shaky = [(
            "DoH",
            Cell {
                state: STATE_OK.to_string(),
                failure: FAILURE_TIMEOUT.to_string(),
                trail: vec![true, false, false],
                ..Cell::default()
            },
        )];
        assert_eq!(
            unstable_level(&shaky.iter().map(|(t, c)| (*t, c)).collect::<Vec<_>>()),
            LEVEL_WARN
        );
        let mild = [(
            "DoH",
            Cell {
                state: STATE_OK.to_string(),
                failure: FAILURE_TIMEOUT.to_string(),
                trail: vec![true, false, true],
                ..Cell::default()
            },
        )];
        assert_eq!(
            unstable_level(&mild.iter().map(|(t, c)| (*t, c)).collect::<Vec<_>>()),
            LEVEL_INFO
        );
        // Обрыв — уже не случайность.
        let torn = [(
            "UDP",
            Cell {
                state: STATE_OK.to_string(),
                failure: primecore_dnswire::FAILURE_RESET.to_string(),
                trail: vec![true, false, true],
                ..Cell::default()
            },
        )];
        assert_eq!(
            unstable_level(&torn.iter().map(|(t, c)| (*t, c)).collect::<Vec<_>>()),
            LEVEL_WARN
        );
    }

    #[test]
    fn report_level_order() {
        // Ничего не сломано: находки идут в правильном порядке —
        // перехват первым.
        let rows = vec![Observation {
            target: target("A", "1.1.1.1"),
            cells: vec![(TRANSPORT_DOH.to_string(), ok_cell(&[true]))],
            ..Default::default()
        }];
        let findings = judge_report(&rows, Some(true), &|_ip| None, &[], &|_ip| false);
        assert_eq!(findings[0].code, CODE_INTERCEPTED);
        assert_eq!(findings[0].level, LEVEL_FAIL);
        // Самый быстрый DoH-сервер назван лучшим.
        assert!(findings.iter().any(|finding| finding.code == CODE_BEST));
    }

    #[test]
    fn wholesale_closure_reported() {
        let rows: Vec<Observation> = (0..3)
            .map(|index| Observation {
                target: target(&format!("S{index}"), &format!("10.0.0.{index}")),
                cells: vec![
                    (
                        TRANSPORT_UDP.to_string(),
                        fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                    ),
                    (TRANSPORT_DOH.to_string(), ok_cell(&[true])),
                ],
                ..Default::default()
            })
            .collect();
        let rows: Vec<Observation> = rows
            .into_iter()
            .map(|row| Observation {
                findings: judge_row(&row, &|_ip| None, &[], &|_ip| false),
                ..row
            })
            .collect();
        let findings = judge_report(&rows, None, &|_ip| None, &[], &|_ip| false);
        let wholesale = findings
            .iter()
            .find(|finding| finding.code == CODE_UDP_BLOCKED)
            .expect("способ закрыт целиком");
        assert!(wholesale.text.contains("закрыт целиком"));
        assert!(wholesale.text.contains("ни один из 3"));
    }

    #[test]
    fn best_and_all_fine() {
        let rows = vec![Observation {
            target: target("A", "1.1.1.1"),
            cells: vec![
                (TRANSPORT_UDP.to_string(), ok_cell(&[true])),
                (TRANSPORT_TCP.to_string(), ok_cell(&[true])),
                (TRANSPORT_DOH.to_string(), ok_cell(&[true])),
            ],
            ..Default::default()
        }];
        let findings = judge_report(&rows, Some(false), &|_ip| None, &[], &|_ip| false);
        assert!(findings.iter().any(|finding| finding.code == CODE_BEST));
        // Без пригодных для Windows серверов и без замечаний — «Замечаний нет».
        let plain = vec![Observation {
            target: target("A", "1.1.1.1"),
            cells: vec![(TRANSPORT_UDP.to_string(), ok_cell(&[true]))],
            ..Default::default()
        }];
        let findings = judge_report(&plain, None, &|_ip| None, &[], &|_ip| false);
        assert!(findings.iter().any(|finding| finding.code == CODE_ALL_FINE));
    }

    #[test]
    fn bypass_listed_first() {
        let rows = vec![Observation {
            target: target("A", "1.1.1.1"),
            cells: vec![(TRANSPORT_DOH.to_string(), ok_cell(&[true]))],
            ..Default::default()
        }];
        let findings = judge_report(&rows, None, &|_ip| None, &["Zapret".to_string()], &|_ip| {
            false
        });
        assert_eq!(findings[0].code, CODE_BYPASS_RUNNING);
        assert_eq!(findings[0].title, "Во время проверки работали");
    }

    #[test]
    fn resolvable_deduped() {
        let rows = vec![
            Observation {
                domains: vec![DomainFact {
                    domain: "rezka.ag".to_string(),
                    secure_ips: vec!["1.2.3.4".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            Observation {
                domains: vec![DomainFact {
                    domain: "rezka.ag".to_string(),
                    secure_ips: vec!["1.2.3.4".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ];
        assert_eq!(
            resolvable_domains(&rows, &|_ip| false),
            vec!["rezka.ag".to_string()]
        );
    }

    #[test]
    fn owner_name_prefers_title() {
        assert_eq!(
            owner_name(Some(&owner("13335", "Cloudflare"))),
            "Cloudflare"
        );
        assert_eq!(owner_name(Some(&owner("13335", ""))), "AS13335");
        assert_eq!(owner_name(None), "");
    }

    #[test]
    fn values_typed() {
        assert_eq!(TYPE_A, 1);
        assert_eq!(TRANSPORTS.len(), 5);
    }
}
