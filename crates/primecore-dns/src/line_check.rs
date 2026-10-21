//! Порт `src/dns/line_check.py` — что прошлая проверка «DNS-серверов» нашла на
//! линии пользователя, для плиток «Настройки DNS».
//!
//! Отметка «блокируется» в каталоге серверов общая для всей России, а
//! блокировки у каждого провайдера свои. Если человек недавно проверял
//! серверы в BlockCheck, его собственный результат точнее каталога: плитка
//! берёт отметку из него и называет дату проверки. Старая проверка (дольше
//! [`MAX_AGE_DAYS`]) не показывается — за это время провайдер мог поменять
//! правила.
//!
//! Чтение настроек и файла отчёта — платформенный слой, поэтому сюда они
//! приходят готовыми: список записей истории и замыкание, читающее отчёт.

use crate::server_check::ServerCheckReport;
use crate::server_check_plans::{build_cards, CARD_UNKNOWN};
use crate::state::LineCheck;
use serde_json::Value;

/// python `MAX_AGE = timedelta(days=14)` — старше этого проверка не
/// показывается.
pub const MAX_AGE_DAYS: i64 = 14;
/// [`MAX_AGE_DAYS`] в секундах.
pub const MAX_AGE_S: i64 = MAX_AGE_DAYS * 24 * 60 * 60;

/// python `_last_run` — последняя запись истории, у которой есть файл отчёта.
#[must_use]
pub fn last_run(runs: &[Value]) -> Option<&Value> {
    runs.iter().rev().find(|run| {
        run.as_object()
            .and_then(|run| run.get("log_file"))
            .and_then(Value::as_str)
            .is_some_and(|log_file| !log_file.is_empty())
    })
}

/// Время ISO-записи истории: `ГГГГ-ММ-ДДТЧЧ:ММ:СС`, разобранное на части.
/// python `datetime.fromisoformat`; смещение часового пояса разбирающий код
/// не принимает — с ним сравнение с «сейчас» падает (python TypeError, тоже
/// «не читается»).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Stamp {
    /// Секунды от начала эпохи — чтобы сравнивать возраст (наивное время
    /// считается UTC, сравнивать с «сейчас» так же).
    #[must_use]
    pub fn epoch_s(self) -> i64 {
        days_from_civil(self.year, i64::from(self.month), i64::from(self.day)) * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    /// python `isoformat(timespec="seconds")`.
    #[must_use]
    pub fn iso(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// python `datetime.fromisoformat` для наивных времён истории.
#[must_use]
pub fn parse_iso(text: &str) -> Option<Stamp> {
    let text = text.trim();
    let (date, time) = match text.split_once(['T', ' ']) {
        Some((date, time)) => (date, Some(time)),
        None => (text, None),
    };
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let (mut hour, mut minute, mut second) = (0u32, 0u32, 0u32);
    if let Some(time) = time {
        // Смещение часового пояса не принимается: с ним сравнение с «сейчас»
        // в python падает TypeError, то есть «не читается».
        let (time, offset) = match time.find(['+', '-']) {
            Some(index) => (&time[..index], true),
            None => (time, false),
        };
        if offset || time.ends_with('Z') {
            return None;
        }
        // Доли секунды обрезаются: в показ идут целые секунды.
        let time = time.split(['.', ',']).next().unwrap_or(time);
        let mut parts = time.split(':');
        hour = parts.next()?.parse::<u32>().ok()?;
        minute = parts.next()?.parse::<u32>().ok()?;
        if let Some(seconds) = parts.next() {
            second = seconds.parse::<u32>().ok()?;
        }
        if parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(Stamp {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Алгоритм days_from_civil (Г. Хиннант) — дни от 1970-01-01.
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let year_of_era = year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// python `load_line_check` — итог последней сохранённой проверки серверов или
/// None: её нет, она стара или не читается.
///
/// `runs` — записи истории проверки (settings «blockcheck.servers_history»),
/// `now_epoch_s` — «сейчас» в секундах от начала эпохи, `load_report` —
/// чтение сохранённого отчёта по пути (платформенный слой; None — файл не
/// читается).
#[must_use]
pub fn load_line_check(
    runs: &[Value],
    now_epoch_s: i64,
    load_report: &mut dyn FnMut(&str) -> Option<ServerCheckReport>,
) -> Option<LineCheck> {
    let run = last_run(runs)?;
    let when = parse_iso(run.get("time").and_then(Value::as_str).unwrap_or(""))?;
    if now_epoch_s - when.epoch_s() > MAX_AGE_S {
        return None;
    }
    let log_file = run.get("log_file").and_then(Value::as_str)?;
    let report = load_report(log_file)?;
    let cards: Vec<(String, String, String)> = build_cards(&report)
        .into_iter()
        .filter(|card| card.status != CARD_UNKNOWN)
        .map(|card| (card.server, card.status, card.note))
        .collect();
    if cards.is_empty() {
        return None;
    }
    Some(LineCheck {
        time: when.iso(),
        cards,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_check::{Cell, CheckTarget, Finding, Observation, STATE_FAIL, STATE_OK};
    use crate::server_check_plans::support::{ok_cell, silent_cell};
    use primecore_dnswire::FAILURE_TIMEOUT;

    fn stamp_epoch(text: &str) -> i64 {
        parse_iso(text).expect("разобранное время").epoch_s()
    }

    fn run(time: &str, log_file: &str) -> Value {
        serde_json::json!({ "time": time, "log_file": log_file })
    }

    fn observation(
        name: &str,
        address: &str,
        cells: [Cell; 5],
        findings: Vec<Finding>,
    ) -> Observation {
        Observation {
            target: CheckTarget {
                provider: name.to_string(),
                address: address.to_string(),
                ..Default::default()
            },
            cells: crate::server_check::TRANSPORTS
                .iter()
                .map(|transport| transport.to_string())
                .zip(cells)
                .collect(),
            findings,
            ..Default::default()
        }
    }

    fn sample_report() -> ServerCheckReport {
        // «Quad9» — блокируется, «Google DNS» — работает, «AdGuard» — не
        // проверен (до него проверка не дошла).
        let blocked = observation(
            "Quad9",
            "9.9.9.9",
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(4.0),
                silent_cell(),
            ],
            vec![Finding {
                level: crate::server_check::LEVEL_FAIL.to_string(),
                code: crate::server_check::CODE_SPOOFED.to_string(),
                text: "обычные ответы подменяются: про rutor.info".to_string(),
                ..Default::default()
            }],
        );
        let healthy = observation(
            "Google DNS",
            "8.8.8.8",
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(4.0),
                ok_cell(5.0),
            ],
            vec![],
        );
        let unprobed = observation(
            "AdGuard",
            "94.140.14.14",
            std::array::from_fn(|_| Cell::default()),
            vec![],
        );
        ServerCheckReport {
            rows: vec![blocked, healthy, unprobed],
            total: 3,
            finished: true,
            ..Default::default()
        }
    }

    #[test]
    fn last_saved_check_gives_card_per_known_server() {
        let runs = vec![
            run("2026-10-10T10:00:00", "old.json"),
            run("2026-10-12T21:05:00", "last.json"),
        ];
        let mut loaded = Vec::new();
        let check = load_line_check(&runs, stamp_epoch("2026-10-13T12:00:00"), &mut |log_file| {
            loaded.push(log_file.to_string());
            Some(sample_report())
        })
        .expect("проверка читается");
        // Читается только последний запуск.
        assert_eq!(loaded, vec!["last.json".to_string()]);
        assert_eq!(check.time, "2026-10-12T21:05:00");
        assert_eq!(
            check.cards,
            vec![
                (
                    "Quad9".to_string(),
                    crate::server_check_plans::CARD_NETWORK.to_string(),
                    "Ответы подменяются".to_string(),
                ),
                (
                    "Google DNS".to_string(),
                    crate::server_check_plans::CARD_OK.to_string(),
                    String::new()
                ),
            ]
        );
    }

    #[test]
    fn old_check_is_not_shown() {
        let runs = vec![run("2026-09-20T10:00:00", "x.json")];
        let mut loaded = Vec::new();
        let check = load_line_check(&runs, stamp_epoch("2026-10-13T12:00:00"), &mut |log_file| {
            loaded.push(log_file.to_string());
            Some(sample_report())
        });
        assert!(check.is_none());
        assert!(loaded.is_empty(), "старую проверку не читают");
    }

    #[test]
    fn no_history_unreadable_time_or_lost_file_give_nothing() {
        // Нет истории; нет файла отчёта в записи; время не разбирается; файл
        // отчёта не читается.
        let cases: Vec<(Vec<Value>, bool)> = vec![
            (vec![], true),
            (
                vec![serde_json::json!({ "time": "2026-10-12T21:05:00" })],
                true,
            ),
            (vec![run("вчера", "x.json")], true),
            (vec![run("2026-10-12T21:05:00", "x.json")], false),
        ];
        for (runs, report_exists) in cases {
            let check =
                load_line_check(&runs, stamp_epoch("2026-10-13T12:00:00"), &mut move |_| {
                    report_exists.then(sample_report)
                });
            assert!(check.is_none(), "должно быть None: {runs:?}");
        }
    }

    #[test]
    fn time_without_seconds_is_normalized() {
        // python fromisoformat принимает время без секунд, а в показе они есть.
        let runs = vec![run("2026-10-12T21:05", "x.json")];
        let check = load_line_check(&runs, stamp_epoch("2026-10-13T12:00:00"), &mut |_| {
            Some(sample_report())
        })
        .expect("проверка читается");
        assert_eq!(check.time, "2026-10-12T21:05:00");
    }

    #[test]
    fn max_age_is_fourteen_days() {
        // Ровно 14 дней — ещё показывается, секунда позже — уже нет.
        let when = "2026-09-29T12:00:00";
        let runs = vec![run(when, "x.json")];
        let now = stamp_epoch(when) + MAX_AGE_S;
        assert!(load_line_check(&runs, now, &mut |_| Some(sample_report())).is_some());
        assert!(load_line_check(&runs, now + 1, &mut |_| Some(sample_report())).is_none());
    }

    #[test]
    fn silent_everywhere_is_not_unknown_but_still_shown() {
        // Молчащий адрес — CARD_SILENT, он показывается; не проверенный — нет.
        let report = sample_report();
        let cards: Vec<String> = build_cards(&report)
            .into_iter()
            .map(|card| card.status)
            .collect();
        assert_eq!(
            cards,
            vec![
                crate::server_check_plans::CARD_NETWORK.to_string(),
                crate::server_check_plans::CARD_OK.to_string(),
                CARD_UNKNOWN.to_string(),
            ]
        );
        let _ = (STATE_FAIL, STATE_OK, FAILURE_TIMEOUT);
    }
}
