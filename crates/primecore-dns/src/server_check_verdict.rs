//! Порт `src/dns/server_check_verdict.py` — итог проверки DNS-серверов для
//! человека: одна фраза, пояснение и находки.
//!
//! Выводы делает [`crate::server_check_verdicts::judge_report`]; здесь они
//! только раскладываются для показа: короткий заголовок отдельно,
//! подробности отдельно. Чистые функции над [`ServerCheckReport`]: ни сети,
//! ни Qt.

use crate::server_check::{
    Finding, Observation, ServerCheckReport, CODE_BYPASS_RUNNING, CODE_DEAD, CODE_INTERCEPTED,
    CODE_SPOOFED, CODE_UNSTABLE, LEVEL_FAIL, LEVEL_WARN, STATE_FAIL, STATE_OK, TRANSPORT_ICMP,
};

pub const KIND_OK: &str = "ok";
pub const KIND_NOTES: &str = "notes";
pub const KIND_WARN: &str = "warn";
pub const KIND_FAIL: &str = "fail";
pub const KIND_STOPPED: &str = "stopped";
pub const KIND_EMPTY: &str = "empty";

/// Заголовки находок, у которых начало текста для заголовка не годится.
fn title_of(code: &str) -> &str {
    match code {
        CODE_BYPASS_RUNNING => "Проверка шла вместе с программами обхода",
        CODE_INTERCEPTED => "Обычные DNS-запросы перехватываются по дороге",
        _ => "",
    }
}

/// Текст таких находок остаётся в подробностях целиком.
fn keep_whole(code: &str) -> bool {
    code == CODE_BYPASS_RUNNING
}

/// python `VerdictItem` — находка готовой карточкой.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerdictItem {
    pub level: String,
    pub title: String,
    pub detail: String,
}

/// python `Tally` — сколько адресов отвечает и сколько молчит: для счётчиков
/// хода проверки.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub good: usize,
    pub silent: usize,
}

/// python `Verdict`.
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub items: Vec<VerdictItem>,
    /// Поможет ли шифрованный DNS: тогда уместна кнопка в «Настройку DNS».
    pub suggests_encrypted_dns: bool,
}

/// python `_sentence` — «первая буква — заглавная».
fn sentence(text: &str) -> String {
    let text = text.trim();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// python `split_finding` — находка пишется как «что случилось: подробности»
/// — делим её по первому двоеточию.
#[must_use]
pub fn split_finding(finding: &Finding) -> VerdictItem {
    if keep_whole(&finding.code) {
        return VerdictItem {
            level: finding.level.clone(),
            title: title_of(&finding.code).to_string(),
            detail: finding.text.clone(),
        };
    }
    let (head, tail) = match finding.text.split_once(": ") {
        Some((head, tail)) => (head, Some(tail)),
        None => (finding.text.as_str(), None),
    };
    let title = if title_of(&finding.code).is_empty() {
        head.trim_end_matches('.').to_string()
    } else {
        title_of(&finding.code).to_string()
    };
    VerdictItem {
        level: finding.level.clone(),
        title,
        detail: tail.map(sentence).unwrap_or_default(),
    }
}

/// python `_answers` — адрес отвечает хоть одним способом (пинг не считается:
/// живой адрес без DNS для страницы всё равно мёртв).
fn answers(row: &Observation) -> bool {
    row.cells
        .iter()
        .any(|(transport, cell)| transport != TRANSPORT_ICMP && cell.state == STATE_OK)
}

/// python `_is_silent` — молчит: часть способов проверена, ответов нет.
fn is_silent(row: &Observation) -> bool {
    let cells: Vec<&crate::server_check::Cell> = row
        .cells
        .iter()
        .filter(|(transport, _)| transport != TRANSPORT_ICMP)
        .map(|(_, cell)| cell)
        .collect();
    cells.iter().any(|cell| cell.state == STATE_FAIL) && !answers(row)
}

/// python `tally` — сколько адресов уже ответило и сколько молчит: для
/// счётчиков, пока проверка идёт.
#[must_use]
pub fn tally(report: &ServerCheckReport) -> Tally {
    Tally {
        good: report.rows.iter().filter(|row| answers(row)).count(),
        silent: report.rows.iter().filter(|row| is_silent(row)).count(),
    }
}

/// python `build_verdict` — главная фраза итога. Вызывать для законченной
/// проверки.
#[must_use]
pub fn build_verdict(report: &ServerCheckReport) -> Verdict {
    let done = report.rows.len();
    let total = report.total;
    if report.stopped {
        return Verdict {
            kind: KIND_STOPPED.to_string(),
            title: "Проверка остановлена".to_string(),
            detail: format!(
                "В карточках ниже — то, что успели узнать: {done} из {total} адресов. \
                 Выводы делаются только по полной проверке."
            ),
            ..Verdict::default()
        };
    }
    if report.rows.is_empty() {
        return Verdict {
            kind: KIND_EMPTY.to_string(),
            title: "Проверять нечего".to_string(),
            detail: "В списке нет ни одного DNS-сервера.".to_string(),
            ..Verdict::default()
        };
    }
    if report.timed_out {
        // Часть адресов не проверена: «всё в порядке» по половине списка было
        // бы неправдой.
        return Verdict {
            kind: KIND_STOPPED.to_string(),
            title: "Проверка не успела закончиться".to_string(),
            detail: format!(
                "Вышло отведённое время. В карточках ниже — то, что успели узнать: {done} из {total} адресов. \
                 Выводы делаются только по полной проверке — запустите её ещё раз."
            ),
            ..Verdict::default()
        };
    }

    let items: Vec<VerdictItem> = report.findings.iter().map(split_finding).collect();
    let codes: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    let has = |code: &str| codes.contains(&code);
    let levels: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.level.as_str())
        .collect();
    if has(CODE_INTERCEPTED) {
        return Verdict {
            kind: KIND_FAIL.to_string(),
            title: "Обычный DNS перехватывают — нужен шифрованный".to_string(),
            detail: "На запросы без шифрования отвечает не выбранный вами сервер, а посредник: \
                     провайдер или роутер. Шифрованный DNS он не может ни прочитать, ни подменить."
                .to_string(),
            items,
            suggests_encrypted_dns: true,
        };
    }
    if has(CODE_SPOOFED) {
        return Verdict {
            kind: KIND_FAIL.to_string(),
            title: "Ответы обычного DNS подменяют".to_string(),
            detail: "Про часть сайтов без шифрования приходит неправда: «сайта нет» или адрес \
                     заглушки. Шифрованный DNS отдаёт настоящие адреса."
                .to_string(),
            items,
            suggests_encrypted_dns: true,
        };
    }
    if levels.contains(&LEVEL_WARN) || levels.contains(&LEVEL_FAIL) {
        let only_shaky = report
            .findings
            .iter()
            .filter(|finding| finding.level == LEVEL_WARN || finding.level == LEVEL_FAIL)
            .all(|finding| finding.code == CODE_UNSTABLE);
        return Verdict {
            kind: KIND_WARN.to_string(),
            title: if only_shaky {
                "Часть серверов отвечает через раз".to_string()
            } else {
                "Часть способов связи закрыта".to_string()
            },
            detail: "Подмены не видно, но не всякий сервер и не всяким способом доступен. \
                     Выбирайте серверы с пометкой «Работает»."
                .to_string(),
            items,
            ..Verdict::default()
        };
    }
    if has(CODE_DEAD) || has(CODE_UNSTABLE) {
        return Verdict {
            kind: KIND_NOTES.to_string(),
            title: "Серьёзных проблем нет".to_string(),
            detail:
                "Ответы никто не перехватывает и не подменяет. Несколько серверов недоступны — \
                     их просто не выбирайте."
                    .to_string(),
            items,
            ..Verdict::default()
        };
    }
    Verdict {
        kind: KIND_OK.to_string(),
        title: "С DNS всё в порядке 👍".to_string(),
        detail: "Ответы никто не перехватывает и не подменяет, шифрованный DNS доступен."
            .to_string(),
        items,
        ..Verdict::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_check::{Cell, CheckTarget, LEVEL_INFO};

    fn target(provider: &str, address: &str) -> CheckTarget {
        CheckTarget {
            provider: provider.to_string(),
            address: address.to_string(),
            ..Default::default()
        }
    }

    fn finding(level: &str, code: &str, text: &str) -> Finding {
        Finding {
            level: level.to_string(),
            code: code.to_string(),
            text: text.to_string(),
            ..Finding::default()
        }
    }

    #[test]
    fn finding_split_by_colon() {
        let item = split_finding(&finding(
            LEVEL_FAIL,
            CODE_SPOOFED,
            "Обычные ответы подменяются у серверов: Cloudflare (1.1.1.1).",
        ));
        assert_eq!(item.title, "Обычные ответы подменяются у серверов");
        assert_eq!(item.detail, "Cloudflare (1.1.1.1).");
        // Целый текст: заголовок из таблицы.
        let item = split_finding(&finding(
            LEVEL_INFO,
            CODE_BYPASS_RUNNING,
            "Во время проверки работали: Zapret.",
        ));
        assert_eq!(item.title, "Проверка шла вместе с программами обхода");
        assert_eq!(item.detail, "Во время проверки работали: Zapret.");
    }

    #[test]
    fn tally_counts_answers() {
        let report = ServerCheckReport {
            rows: vec![
                Observation {
                    target: target("A", "1.1.1.1"),
                    cells: vec![(
                        "udp".to_string(),
                        Cell {
                            state: STATE_OK.to_string(),
                            ..Cell::default()
                        },
                    )],
                    ..Default::default()
                },
                Observation {
                    target: target("B", "9.9.9.9"),
                    cells: vec![(
                        "udp".to_string(),
                        Cell {
                            state: STATE_FAIL.to_string(),
                            ..Cell::default()
                        },
                    )],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let tally = tally(&report);
        assert_eq!(tally.good, 1);
        assert_eq!(tally.silent, 1);
    }

    #[test]
    fn verdict_kinds() {
        let ok = ServerCheckReport {
            total: 1,
            rows: vec![Observation {
                target: target("A", "1.1.1.1"),
                cells: vec![(
                    "udp".to_string(),
                    Cell {
                        state: STATE_OK.to_string(),
                        ..Cell::default()
                    },
                )],
                ..Default::default()
            }],
            findings: vec![finding(LEVEL_INFO, "all_fine", "Замечаний нет.")],
            finished: true,
            ..Default::default()
        };
        assert_eq!(build_verdict(&ok).kind, KIND_OK);
        // Перехват → fail с советом про шифрованный DNS.
        let mut intercepted = ok.clone();
        intercepted.findings = vec![finding(LEVEL_FAIL, CODE_INTERCEPTED, "перехват: доказан")];
        let verdict = build_verdict(&intercepted);
        assert_eq!(verdict.kind, KIND_FAIL);
        assert!(verdict.suggests_encrypted_dns);
        assert_eq!(
            verdict.title,
            "Обычный DNS перехватывают — нужен шифрованный"
        );
        // Остановленная проверка — вывода нет.
        let mut stopped = ok.clone();
        stopped.stopped = true;
        assert_eq!(build_verdict(&stopped).kind, KIND_STOPPED);
        // Пустой список.
        assert_eq!(
            build_verdict(&ServerCheckReport::default()).kind,
            KIND_EMPTY
        );
        // Срок вышел.
        let mut timed = ok.clone();
        timed.timed_out = true;
        assert_eq!(build_verdict(&timed).kind, KIND_STOPPED);
        // Мёртвые серверы — замечания, не беда.
        let mut notes = ok.clone();
        notes.findings = vec![finding(LEVEL_INFO, CODE_DEAD, "Не отвечают совсем: X.")];
        let verdict = build_verdict(&notes);
        assert_eq!(verdict.kind, KIND_NOTES);
        assert!(!verdict.suggests_encrypted_dns);
    }

    #[test]
    fn only_shaky_warn_has_its_title() {
        let shaky = ServerCheckReport {
            total: 1,
            rows: vec![Observation {
                target: target("A", "1.1.1.1"),
                ..Default::default()
            }],
            findings: vec![finding(LEVEL_WARN, CODE_UNSTABLE, "отвечает через раз: …")],
            finished: true,
            ..Default::default()
        };
        assert_eq!(
            build_verdict(&shaky).title,
            "Часть серверов отвечает через раз"
        );
        let closed = ServerCheckReport {
            total: 1,
            rows: shaky.rows,
            findings: vec![finding(LEVEL_WARN, "udp_blocked", "закрыт: …")],
            finished: true,
            ..Default::default()
        };
        assert_eq!(build_verdict(&closed).title, "Часть способов связи закрыта");
    }
}
