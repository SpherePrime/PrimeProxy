//! Порт `src/dns/server_check_plans.py` (часть 2) — подробности по адресам,
//! сводка способов связи, строка состояния, итог и полный текстовый отчёт.
//!
//! Константы, строки таблицы и карточки — в [`crate::server_check_plans`].

use crate::info_line::{InfoLine, TONE_ACCENT, TONE_MUTED, TONE_WARNING};
use crate::server_check::{
    Observation, ServerCheckReport, STATE_FAIL, STATE_OK, STATE_SKIP, TRANSPORTS, TRANSPORT_ICMP,
};
use crate::server_check_plans::{
    address_status, build_cards, build_rows, card_hint, card_title, cell_level, cell_text,
    level_mark, level_tone, owner_text, sentence, transport_about, transport_title, AddressDetails,
    ServerDetails, TransportSummary, CELL_FAIL, CELL_OK, CELL_WARN,
};
use primecore_dnswire::{STATUS_EMPTY, STATUS_ERROR, STATUS_NXDOMAIN, STATUS_TIMEOUT};

/// python `_ANSWER_WORDS` — что сервер ответил про сайт, когда адресов в
/// ответе нет: словами вместо служебных названий.
#[must_use]
fn answer_word(status: &str) -> String {
    match status {
        STATUS_NXDOMAIN => "сайта нет".to_string(),
        STATUS_TIMEOUT => "нет ответа".to_string(),
        STATUS_EMPTY => "пустой ответ".to_string(),
        STATUS_ERROR => "ошибка".to_string(),
        "" => "—".to_string(),
        other => other.to_string(),
    }
}

/// python `_answer_text` — адреса через запятую или словами.
#[must_use]
fn answer_text(status: &str, ips: &[String]) -> String {
    if ips.is_empty() {
        answer_word(status)
    } else {
        ips.join(", ")
    }
}

/// python `build_details` — подробности по одному серверу: каждый адрес,
/// каждый способ связи, все выводы целиком.
#[must_use]
pub fn build_details(report: &ServerCheckReport, server: &str) -> Option<ServerDetails> {
    let card = build_cards(report)
        .into_iter()
        .find(|card| card.server == server)?;
    let intercepted = report
        .findings
        .iter()
        .any(|finding| finding.code == crate::server_check::CODE_INTERCEPTED);
    let mut addresses: Vec<AddressDetails> = Vec::new();
    for row in &report.rows {
        if row.target.provider != server {
            continue;
        }
        let mut cells = Vec::new();
        for transport in TRANSPORTS {
            let cell = row.cell(transport);
            let reason = if cell.state == STATE_FAIL || cell.state == STATE_SKIP || cell.unstable()
            {
                cell.reason.clone()
            } else {
                String::new()
            };
            cells.push((
                transport_title(transport).to_string(),
                cell_text(transport, &cell),
                cell_level(transport, &cell).to_string(),
                reason,
            ));
        }
        let mut who = Vec::new();
        if !row.udp_egress.is_empty() || !row.secure_egress.is_empty() {
            let udp = owner_text(report, &row.udp_egress);
            let secure = owner_text(report, &row.secure_egress);
            who.push(format!(
                "Обычные запросы выполняет: {}",
                if udp.is_empty() {
                    "не узнали".to_string()
                } else {
                    udp
                }
            ));
            who.push(format!(
                "Шифрованные запросы выполняет: {}",
                if secure.is_empty() {
                    "не узнали".to_string()
                } else {
                    secure
                }
            ));
        }
        addresses.push(AddressDetails {
            address: row.target.address.clone(),
            status: address_status(row, intercepted).to_string(),
            cells,
            findings: row
                .findings
                .iter()
                .map(|finding| (finding.level.clone(), sentence(&finding.text)))
                .collect(),
            who,
            domains: row
                .domains
                .iter()
                .map(|fact| {
                    (
                        fact.domain.clone(),
                        answer_text(&fact.udp_status, &fact.udp_ips),
                        answer_text(&fact.secure_status, &fact.secure_ips),
                        fact.udp_status != fact.secure_status || fact.udp_ips != fact.secure_ips,
                    )
                })
                .collect(),
            times_ms: TRANSPORTS
                .iter()
                .map(|transport| {
                    let cell = row.cell(transport);
                    if cell.state == STATE_OK {
                        cell.elapsed_ms
                    } else {
                        None
                    }
                })
                .collect(),
        });
    }
    let mut lines = vec![
        format!("{server} — {}", card_title(&card.status)),
        card_hint(&card.status).to_string(),
    ];
    for row in &card.addresses {
        lines.push(String::new());
        lines.push(row.tooltip.clone());
    }
    Some(ServerDetails {
        card,
        addresses,
        text: lines.join("\n"),
    })
}

/// python `build_transport_summary` — сводка по способам связи: у скольких
/// адресов сервера каждый из них отвечает.
#[must_use]
pub fn build_transport_summary(details: &ServerDetails) -> Vec<TransportSummary> {
    let mut result = Vec::new();
    for (index, transport) in TRANSPORTS.iter().enumerate() {
        let dots: Vec<String> = details
            .addresses
            .iter()
            .map(|address| address.cells[index].2.clone())
            .collect();
        let failed = dots.iter().filter(|dot| *dot == CELL_FAIL).count();
        let unstable = dots.iter().filter(|dot| *dot == CELL_WARN).count();
        let answered = dots.iter().filter(|dot| *dot == CELL_OK).count() + unstable;
        let checked = answered + failed;
        let ping = *transport == TRANSPORT_ICMP;
        let (level, note) = if checked == 0 {
            (
                crate::server_check_plans::CELL_MUTED,
                // Молчание на пинг ошибкой не считается, поэтому провалов у
                // него не бывает.
                if ping {
                    "молчит — для пинга это обычное дело"
                } else {
                    "не объявлен у сервера"
                }
                .to_string(),
            )
        } else if failed == checked {
            (CELL_FAIL, "закрыт на всех адресах".to_string())
        } else if failed > 0 {
            (CELL_FAIL, format!("закрыт на адресах: {failed}"))
        } else if unstable > 0 {
            (
                CELL_WARN,
                format!("отвечает через раз на адресах: {unstable}"),
            )
        } else if ping && answered < dots.len() {
            (
                CELL_OK,
                "часть адресов молчит — для пинга это обычное дело".to_string(),
            )
        } else {
            (CELL_OK, "отвечает без сбоев".to_string())
        };
        result.push(TransportSummary {
            title: transport_title(transport).to_string(),
            about: transport_about(transport).to_string(),
            answered,
            total: if ping || checked == 0 {
                dots.len()
            } else {
                checked
            },
            level: level.to_string(),
            note,
            dots,
        });
    }
    result
}

/// python `build_status` — строка состояния проверки.
#[must_use]
pub fn build_status(report: &ServerCheckReport) -> InfoLine {
    let done = report.rows.len();
    let total = report.total;
    if !report.finished {
        return InfoLine::new(
            format!("Проверяем серверы: готово {done} из {total} адресов…"),
            TONE_ACCENT,
        );
    }
    if report.stopped {
        return InfoLine::new(
            format!("Проверка остановлена. Успели проверить {done} из {total} адресов."),
            TONE_WARNING,
        );
    }
    if total == 0 {
        return InfoLine::new("В списке нет ни одного сервера для проверки.", TONE_WARNING);
    }
    let text = format!(
        "Проверено {done} из {total} адресов за {:.0} с.",
        report.elapsed_s
    );
    if report.timed_out {
        return InfoLine::new(
            format!("{text} Часть проверок не уложилась во время и была прервана."),
            TONE_WARNING,
        );
    }
    InfoLine::new(text, TONE_MUTED)
}

/// python `build_summary` — итоговые выводы проверки строками состояния.
#[must_use]
pub fn build_summary(report: &ServerCheckReport) -> Vec<InfoLine> {
    report
        .findings
        .iter()
        .map(|finding| InfoLine::new(finding.text.clone(), level_tone(&finding.level)))
        .collect()
}

/// python `pad` из f-строк `{value:<{width}}` — выравнивание по левому краю.
#[must_use]
fn pad_left(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - len))
    }
}

/// python `build_text_report` — полный текст для окна отчёта и для отправки:
/// таблица, итог и подробности по адресам.
#[must_use]
pub fn build_text_report(report: &ServerCheckReport) -> String {
    let mut lines = vec![
        "ПРОВЕРКА DNS-СЕРВЕРОВ".to_string(),
        build_status(report).text,
        String::new(),
    ];
    if !report.findings.is_empty() {
        lines.push("Итог:".to_string());
        lines.extend(
            report
                .findings
                .iter()
                .map(|finding| format!("  {} {}", level_mark(&finding.level), finding.text)),
        );
        lines.push(String::new());
    }
    if !report.bypass.is_empty() {
        lines.push(format!(
            "Работали во время проверки: {}",
            report.bypass.join(", ")
        ));
    }
    if let Some(canary) = report.canary {
        let answered = if canary {
            "ОТВЕТИЛ — запросы перехватываются"
        } else {
            "молчит, как и должен"
        };
        lines.push(format!("Контрольный адрес без DNS-сервера: {answered}"));
        lines.push(String::new());
    }

    let rows = build_rows(report);
    let titles: Vec<&str> = TRANSPORTS
        .iter()
        .map(|transport| transport_title(transport))
        .collect();
    let server_width = rows
        .iter()
        .map(|row| row.server.chars().count())
        .chain(["Сервер".chars().count()])
        .max()
        .unwrap_or(0);
    let address_width = rows
        .iter()
        .map(|row| row.address.chars().count())
        .chain(["Адрес".chars().count()])
        .max()
        .unwrap_or(0);
    let widths: Vec<usize> = titles
        .iter()
        .enumerate()
        .map(|(index, title)| {
            rows.iter()
                .map(|row| row.cells[index].chars().count())
                .chain([title.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let header = format!(
        "{}  {}  {}",
        pad_left("Сервер", server_width),
        pad_left("Адрес", address_width),
        titles
            .iter()
            .zip(&widths)
            .map(|(title, width)| pad_left(title, *width))
            .collect::<Vec<_>>()
            .join("  ")
    );
    lines.push(header.trim_end().to_string());
    for row in &rows {
        let cells = row
            .cells
            .iter()
            .zip(&widths)
            .map(|(text, width)| pad_left(text, *width))
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(
            format!(
                "{}  {}  {}",
                pad_left(&row.server, server_width),
                pad_left(&row.address, address_width),
                cells
            )
            .trim_end()
            .to_string(),
        );
    }

    let details: Vec<&Observation> = report
        .rows
        .iter()
        .filter(|row| {
            !row.findings.is_empty() || !row.udp_egress.is_empty() || !row.secure_egress.is_empty()
        })
        .collect();
    if !details.is_empty() {
        lines.push(String::new());
        lines.push("Подробности:".to_string());
    }
    for row in details {
        lines.push(format!("{} ({})", row.target.provider, row.target.address));
        if !row.udp_egress.is_empty() || !row.secure_egress.is_empty() {
            let udp = owner_text(report, &row.udp_egress);
            let secure = owner_text(report, &row.secure_egress);
            lines.push(format!(
                "  обычные запросы выполняет: {}",
                if udp.is_empty() {
                    "не узнали".to_string()
                } else {
                    udp
                }
            ));
            lines.push(format!(
                "  шифрованные выполняет: {}",
                if secure.is_empty() {
                    "не узнали".to_string()
                } else {
                    secure
                }
            ));
        }
        for fact in &row.domains {
            if fact.udp_status != fact.secure_status || fact.udp_ips != fact.secure_ips {
                lines.push(format!(
                    "  {}: обычным путём {} {}; шифрованным {} {}",
                    fact.domain,
                    fact.udp_status,
                    if fact.udp_ips.is_empty() {
                        "—".to_string()
                    } else {
                        fact.udp_ips.join(", ")
                    },
                    fact.secure_status,
                    if fact.secure_ips.is_empty() {
                        "—".to_string()
                    } else {
                        fact.secure_ips.join(", ")
                    }
                ));
            }
        }
        for finding in &row.findings {
            lines.push(format!(
                "  {} {}",
                level_mark(&finding.level),
                sentence(&finding.text)
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use crate::server_check::{Cell, Observation, STATE_OK};
    use crate::server_check_plans::{
        build_cards, build_rows,
        support::{
            base_report, blocked, fail_cell, google, make_row, mixed_report, ok_cell, server_rows,
            silent_cell,
        },
        CARD_NETWORK, CARD_OK, CARD_PARTIAL, CARD_SELF, CARD_SILENT, CARD_UNKNOWN, CELL_FAIL,
        CELL_MUTED, CELL_OK,
    };
    use crate::server_check_plans_text::{build_details, build_status, build_text_report};
    use primecore_dnswire::{FAILURE_REFUSED, FAILURE_TIMEOUT};

    #[test]
    fn cells_show_time_or_short_reason() {
        let report = base_report(vec![
            blocked(),
            crate::server_check_plans::support::healthy(),
        ]);
        let rows = build_rows(&report);
        assert_eq!(
            rows[0].cells,
            vec!["нет ответа", "12 мс", "30 мс", "молчит", "порт закрыт"]
        );
        assert_eq!(
            rows[1].cells,
            vec!["< 1 мс", "9 мс", "20 мс", "60 мс", "55 мс"]
        );
    }

    #[test]
    fn silent_ping_is_not_painted_as_failure() {
        let report = base_report(vec![
            blocked(),
            crate::server_check_plans::support::healthy(),
        ]);
        let rows = build_rows(&report);
        assert_eq!(
            rows[0].cell_levels,
            vec![
                crate::server_check_plans::CELL_MUTED,
                CELL_OK,
                CELL_OK,
                CELL_FAIL,
                CELL_FAIL,
            ]
        );
        assert!(rows[1].cell_levels.iter().all(|level| level == CELL_OK));
    }

    #[test]
    fn note_does_not_repeat_what_cells_already_show() {
        let report = base_report(vec![
            blocked(),
            crate::server_check_plans::support::healthy(),
        ]);
        let rows = build_rows(&report);
        // Закрытые DoT и DoH видны в ячейках; в замечаниях остаётся то, чего
        // там нет. Коротко, чтобы помещалось в столбец; полная фраза — в
        // подсказке строки.
        assert_eq!(rows[0].note, "Отвечает чужая сеть");
        assert!(rows[0]
            .tooltip
            .contains("Обычные запросы выполняет сеть NSDI, а шифрованные — GOOGLE"));
        assert_eq!(
            (rows[0].note_level.as_str(), rows[0].level.as_str()),
            ("info", "warn")
        );
        assert_eq!(
            (rows[1].level.as_str(), rows[1].note.as_str()),
            ("ok", "Без замечаний")
        );
    }

    #[test]
    fn transport_answering_every_other_time_shows_how_many_of_how_many() {
        let shaky = Cell {
            state: STATE_OK.to_string(),
            elapsed_ms: Some(40.0),
            failure: FAILURE_TIMEOUT.to_string(),
            reason: "сервер молчит".to_string(),
            trail: vec![true, false, false],
        };
        let row = make_row(
            crate::server_check_plans::support::backup(),
            [
                ok_cell(1.0),
                ok_cell(9.0),
                ok_cell(20.0),
                ok_cell(60.0),
                shaky,
            ],
        );
        let report = base_report(vec![row]);
        let shown = &build_rows(&report)[0];
        assert_eq!(
            (shown.cells[4].as_str(), shown.cell_levels[4].as_str()),
            ("40 мс · 1 из 3", "warn")
        );
        assert!(shown
            .tooltip
            .contains("DoH 443: 40 мс, ответил на 1 из 3 запросов (остальные: сервер молчит)"));
    }

    #[test]
    fn row_with_only_closed_transports_has_empty_note_not_all_clear() {
        let only_closed = Observation {
            target: google(),
            cells: blocked().cells,
            findings: vec![crate::server_check::Finding {
                level: "warn".to_string(),
                code: crate::server_check::CODE_DOT_BLOCKED.to_string(),
                text: "шифрованный DNS по DoT закрыт: сервер молчит".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let report = base_report(vec![only_closed]);
        let shown = &build_rows(&report)[0];
        assert_eq!((shown.note.as_str(), shown.level.as_str()), ("", "warn"));
        assert!(shown.tooltip.contains("! Шифрованный DNS по DoT закрыт"));
    }

    #[test]
    fn most_important_remark_goes_first() {
        let spoofed = Observation {
            target: google(),
            cells: crate::server_check_plans::support::healthy().cells,
            findings: vec![
                crate::server_check::Finding {
                    level: "info".to_string(),
                    code: crate::server_check::CODE_FOREIGN_ANSWERS.to_string(),
                    text: "обычные запросы выполняет сеть NSDI".to_string(),
                    ..Default::default()
                },
                crate::server_check::Finding {
                    level: "fail".to_string(),
                    code: crate::server_check::CODE_SPOOFED.to_string(),
                    text: "обычные ответы подменяются".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let report = base_report(vec![spoofed]);
        let shown = &build_rows(&report)[0];
        assert_eq!(shown.note, "Ответы подменяются · Отвечает чужая сеть");
        assert_eq!(shown.note_level, "fail");
    }

    #[test]
    fn tooltip_keeps_full_reasons_and_who_answers() {
        let report = base_report(vec![
            blocked(),
            crate::server_check_plans::support::healthy(),
        ]);
        let tooltip = &build_rows(&report)[0].tooltip;
        assert!(tooltip.contains("DoT 853: сервер молчит"));
        assert!(tooltip.contains("Кто выполняет обычные запросы: 4.4.4.4 (NSDI)"));
        assert!(tooltip.contains("Кто выполняет шифрованные: 2.2.2.2 (GOOGLE)"));
    }

    #[test]
    fn server_without_encrypted_transport_shows_dash() {
        let skip = Cell {
            state: crate::server_check::STATE_SKIP.to_string(),
            reason: "сервер не объявлял этот способ".to_string(),
            ..Default::default()
        };
        let row = make_row(
            crate::server_check::CheckTarget {
                provider: "Свой".to_string(),
                address: "10.0.0.53".to_string(),
                ..Default::default()
            },
            [ok_cell(1.0), ok_cell(2.0), ok_cell(3.0), skip.clone(), skip],
        );
        let report = base_report(vec![row]);
        let shown = &build_rows(&report)[0];
        assert_eq!(
            (&shown.cells[3], &shown.cells[4]),
            (&"—".to_string(), &"—".to_string())
        );
        assert!(shown.cell_levels[3..]
            .iter()
            .all(|level| level == CELL_MUTED));
    }

    #[test]
    fn status_follows_run_state() {
        let mut report = base_report(vec![blocked()]);
        report.total = 2;
        report.finished = false;
        assert!(build_status(&report).text.contains("готово 1 из 2"));

        report.stopped = true;
        report.finished = true;
        assert!(build_status(&report).text.contains("остановлена"));

        report.stopped = false;
        report.total = 2;
        report.rows = vec![blocked(), crate::server_check_plans::support::healthy()];
        assert!(build_status(&report)
            .text
            .contains("Проверено 2 из 2 адресов за 12 с"));

        report.timed_out = true;
        assert!(build_status(&report).text.contains("не уложилась"));

        report.rows = vec![];
        report.total = 0;
        assert!(build_status(&report).text.contains("нет ни одного сервера"));
    }

    #[test]
    fn unfinished_row_has_no_all_clear_yet() {
        let mut report = base_report(vec![crate::server_check_plans::support::healthy()]);
        report.finished = false;
        assert_eq!(build_rows(&report)[0].note, "");
    }

    #[test]
    fn text_report_has_summary_table_and_details() {
        let text = build_text_report(&base_report(vec![
            blocked(),
            crate::server_check_plans::support::healthy(),
        ]));
        assert!(text.contains("ПРОВЕРКА DNS-СЕРВЕРОВ"));
        assert!(text.contains("✗ Обычные DNS-запросы перехватываются по дороге."));
        assert!(text.contains("Контрольный адрес без DNS-сервера: ОТВЕТИЛ"));
        let header = text
            .lines()
            .find(|line| line.starts_with("Сервер"))
            .expect("заголовок таблицы");
        for title in ["Пинг", "UDP 53", "TCP 53", "DoT 853", "DoH 443"] {
            assert!(header.contains(title), "{title} нет в заголовке");
        }
        assert!(text.contains("обычные запросы выполняет: 4.4.4.4 (NSDI)"));
        assert!(text.contains("! Шифрованный DNS по DoH закрыт: порт закрыт"));
    }

    #[test]
    fn one_card_per_server_with_who_is_to_blame() {
        let report = mixed_report();
        let statuses: Vec<(String, String)> = build_cards(&report)
            .into_iter()
            .map(|card| (card.server, card.status))
            .collect();
        let by_name = |name: &str| {
            statuses
                .iter()
                .find(|(server, _)| server == name)
                .map(|(_, status)| status.clone())
                .expect("карточка сервера")
        };
        assert_eq!(by_name("Быстрый"), CARD_OK);
        assert_eq!(by_name("Медленный"), CARD_OK);
        assert_eq!(by_name("Молчун"), CARD_SILENT);
        assert_eq!(by_name("Фильтр"), CARD_SELF);
        assert_eq!(by_name("Закрытый"), CARD_NETWORK);
        assert_eq!(by_name("Шаткий"), CARD_PARTIAL);
        assert_eq!(by_name("Без DoH"), CARD_PARTIAL);

        let cards = build_cards(&report);
        let slow = cards
            .iter()
            .find(|card| card.server == "Медленный")
            .expect("карточка");
        // Два адреса одного сервера — одна карточка, по точке на адрес у
        // каждого способа связи.
        assert_eq!(slow.addresses.len(), 2);
        assert_eq!(
            slow.dots,
            vec![
                vec!["ok", "ok"],
                vec!["ok", "ok"],
                vec!["ok", "ok"],
                vec!["ok", "ok"]
            ]
        );
        let closed = cards
            .iter()
            .find(|card| card.server == "Закрытый")
            .expect("карточка");
        assert_eq!(closed.dots[3], vec!["fail"]);
        // На карточке ячеек не видно, поэтому закрытый способ назван словами;
        // важное идёт первым.
        assert_eq!(closed.note, "Ответы подменяются · DoH закрыт");
        let filter = cards
            .iter()
            .find(|card| card.server == "Фильтр")
            .expect("карточка");
        assert_eq!(filter.note, "Сам не отдаёт часть сайтов");
        let fast = cards
            .iter()
            .find(|card| card.server == "Быстрый")
            .expect("карточка");
        assert_eq!((fast.note.as_str(), fast.best.as_str()), ("", "DoH 20 мс"));
        assert!(filter.tooltip.contains("решил сам сервер"));
        assert!(closed.tooltip.contains("Это доказано"));
        // Закрытый способ связи сам по себе вину провайдера не доказывает: так
        // мог сделать и сервер.
        let without_doh = cards
            .iter()
            .find(|card| card.server == "Без DoH")
            .expect("карточка");
        assert_eq!(without_doh.note, "DoH закрыт");
        assert!(without_doh.tooltip.contains("и провайдер, и сам сервер"));
    }

    #[test]
    fn cards_go_from_blocked_to_silent_and_faster_first() {
        let order: Vec<String> = build_cards(&mixed_report())
            .into_iter()
            .map(|card| card.server)
            .collect();
        assert_eq!(
            order,
            vec![
                "Закрытый",
                "Шаткий",
                "Без DoH",
                "Фильтр",
                "Быстрый",
                "Медленный",
                "Молчун"
            ]
        );
    }

    #[test]
    fn server_with_one_silent_address_is_alive() {
        let mut rows = server_rows(
            "Двойной",
            &["10.0.0.1"],
            vec![],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(50.0),
            ],
        );
        rows.extend(server_rows(
            "Двойной",
            &["10.0.0.2"],
            vec![crate::server_check_plans::support::dead_finding()],
            [
                ok_cell(1.0),
                silent_cell(),
                silent_cell(),
                silent_cell(),
                silent_cell(),
            ],
        ));
        let card = &build_cards(&base_report(rows))[0];
        assert_eq!(
            (card.status.as_str(), card.note.as_str()),
            ("ok", "Молчит адресов: 1 из 2")
        );
    }

    #[test]
    fn foreign_network_blames_the_road_only_when_interception_is_proven() {
        let foreign = crate::server_check::Finding {
            level: "info".to_string(),
            code: crate::server_check::CODE_FOREIGN_ANSWERS.to_string(),
            text: "обычные запросы выполняет сеть NSDI".to_string(),
            ..Default::default()
        };
        let rows = server_rows(
            "Чужой",
            &["10.0.0.1"],
            vec![foreign],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(50.0),
            ],
        );
        let mut plain_report = base_report(rows.clone());
        plain_report.findings = vec![];
        let plain = build_cards(&plain_report);
        let mut proven_report = base_report(rows);
        proven_report.findings = vec![crate::server_check::Finding {
            level: "fail".to_string(),
            code: crate::server_check::CODE_INTERCEPTED.to_string(),
            text: "Перехват.".to_string(),
            ..Default::default()
        }];
        let proven = build_cards(&proven_report);
        assert_eq!(
            (plain[0].status.as_str(), proven[0].status.as_str()),
            ("ok", "network")
        );
    }

    #[test]
    fn unfinished_check_shows_only_answering_and_silent() {
        let mut rows = server_rows(
            "Живой",
            &["10.0.0.1"],
            vec![],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(50.0),
            ],
        );
        rows.extend(server_rows(
            "Молчун",
            &["10.0.2.1"],
            vec![],
            [
                ok_cell(1.0),
                silent_cell(),
                silent_cell(),
                silent_cell(),
                silent_cell(),
            ],
        ));
        let mut report = base_report(rows);
        report.total = 5;
        report.finished = false;
        let statuses: Vec<String> = build_cards(&report)
            .into_iter()
            .map(|card| card.status)
            .collect();
        assert_eq!(statuses, vec![CARD_OK, CARD_SILENT]);
    }

    #[test]
    fn unprobed_address_is_not_shown_as_working() {
        // «Не узнали» — отдельный исход: недопроверенное не выдаётся за
        // «всё в порядке».
        let unprobed = Observation {
            target: google(),
            cells: crate::server_check::TRANSPORTS
                .iter()
                .map(|transport| (transport.to_string(), Cell::default()))
                .collect(),
            ..Default::default()
        };
        let report = base_report(vec![unprobed]);
        let card = &build_cards(&report)[0];
        assert_eq!(card.status, CARD_UNKNOWN);
        let row = &build_rows(&report)[0];
        assert_ne!(row.note, "Без замечаний");
    }

    #[test]
    fn details_tell_everything_about_every_address() {
        let fact = crate::server_check::DomainFact {
            domain: "rutor.info".to_string(),
            udp_status: "nxdomain".to_string(),
            secure_status: "ok".to_string(),
            secure_ips: vec!["6.6.6.6".to_string()],
            ..Default::default()
        };
        let mut blocked_row = blocked();
        blocked_row.domains = vec![fact];
        let report = base_report(vec![
            blocked_row,
            crate::server_check_plans::support::healthy(),
        ]);
        let details = build_details(&report, "Google DNS").expect("подробности");

        let addresses: Vec<String> = details
            .addresses
            .iter()
            .map(|address| address.address.clone())
            .collect();
        assert_eq!(addresses, vec!["8.8.8.8", "8.8.4.4"]);
        let first = &details.addresses[0];
        assert_eq!(first.status, CARD_NETWORK);
        // Причина отказа — словами, а не одним коротким словом из карточки.
        assert!(first.cells.contains(&(
            "DoT 853".to_string(),
            "молчит".to_string(),
            CELL_FAIL.to_string(),
            "сервер молчит".to_string()
        )));
        assert!(first.findings.contains(&(
            "warn".to_string(),
            "Шифрованный DNS по DoH закрыт: порт закрыт".to_string()
        )));
        assert_eq!(first.who[0], "Обычные запросы выполняет: 4.4.4.4 (NSDI)");
    }

    #[test]
    fn details_of_unknown_server_are_none() {
        assert!(build_details(&base_report(vec![blocked()]), "Нет такого").is_none());
    }

    #[test]
    fn failed_queries_are_words_not_status_names() {
        // python `_answer_text` словами вместо служебных названий.
        let mut report = base_report(vec![blocked()]);
        report.rows[0].domains = vec![crate::server_check::DomainFact {
            domain: "example.com".to_string(),
            udp_status: primecore_dnswire::STATUS_NXDOMAIN.to_string(),
            secure_status: primecore_dnswire::STATUS_TIMEOUT.to_string(),
            ..Default::default()
        }];
        let details = build_details(&report, "Google DNS").expect("подробности");
        let first = &details.addresses[0];
        assert_eq!(
            first.domains[0],
            (
                "example.com".to_string(),
                "сайта нет".to_string(),
                "нет ответа".to_string(),
                true
            )
        );
    }

    #[test]
    fn failed_refused_cell_in_report_uses_short_words() {
        // Ячейка с «порт закрыт» — из failure, а не из reason.
        let cell = fail_cell(FAILURE_REFUSED, "полная причина");
        assert_eq!(
            crate::server_check_plans::cell_text(primecore_dnswire::TRANSPORT_UDP, &cell),
            "порт закрыт"
        );
        let _ = FAILURE_TIMEOUT;
    }
}
