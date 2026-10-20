//! Порт `src/diagnostics/report_contract.py` — договор об отчёте BlockCheck:
//! какие поля в нём есть и где каждое показано.
//!
//! Отчёт — единственный источник истины: его собирает движок, по нему рисуется
//! экран, он же целиком пишется в файл. Экран не может показать то, чего в
//! отчёте нет. Обратное само не получается: новое поле можно положить в отчёт и
//! забыть вывести. Этот список закрывает такую дыру — у каждого поля отчёта
//! здесь должно быть одно из трёх мест:
//!
//! - [`CARD_FIELDS`] — поле видно на карточках результатов;
//! - [`SUMMARY_FIELDS`] — поле читает панель итога или сама страница;
//! - [`SERVICE_FIELDS`] — поле служебное, с объяснением, почему его не показывают.

use std::collections::BTreeSet;

/// Разделы, из которых строятся карточки результатов.
pub const CARD_FIELDS: [&str; 22] = [
    "services",
    "freeze",
    "voice",
    "telegram",
    "network",
    "speed",
    "ipv6",
    "dns_servers",
    "filter",
    "habits",
    // Карточка «Несколько соединений сразу».
    "crowd",
    "system",
    "registry",
    "reference",
    "spoofed_hosts",
    // Карточка «Ход проверки»: время шагов и условия, при которых шла проверка.
    "step_seconds",
    "environment",
    "zapret_line",
    "other_bypass_tools",
    // Какие из них стояли на дороге проверки (VPN с проложенной дорогой, программы, меняющие пакеты).
    "tools_in_path",
    "preset",
    // Карточка «С Zapret и без»: сравнение с прошлой проверкой в противоположном состоянии обхода.
    "compare",
];

/// Поля, которые читает панель итога и страница.
pub const SUMMARY_FIELDS: [&str; 7] =
    ["scope", "problems", "zapret_running", "elapsed", "timed_out", "history", "text"];

/// Служебные поля: на экран не выводятся, и вот почему.
pub fn service_fields() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "working",
            "открывающиеся сайты — строка текстового отчёта; на экране их показывают плитка и полоса видов блокировки",
        ),
        (
            "partial",
            "признак «отчёт ещё пополняется»: по нему экран отличает ход проверки от итога",
        ),
        (
            "report_version",
            "версия формата отчёта: по ней старые отчёты переводятся в новый вид (diagnostics.report_upgrade)",
        ),
        (
            "changes",
            "что изменилось с прошлой проверки — сохраняется в файле отчёта, поэтому видно и в «Прошлых проверках»",
        ),
        (
            "previous_time",
            "время прошлой такой же проверки — нужно только для строки об изменениях",
        ),
        (
            "json_file",
            "путь к файлу отчёта — по нему собирается обращение в поддержку",
        ),
        (
            "stopped",
            "пометка прерванной проверки в сохранённом файле",
        ),
        (
            "failed",
            "пометка упавшей проверки в сохранённом файле",
        ),
        (
            "error",
            "текст ошибки упавшей проверки",
        ),
    ]
}

/// Все поля, которым в отчёте есть место (python `declared_fields`).
#[must_use]
pub fn declared_fields() -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    all.extend(CARD_FIELDS.iter().map(|name| (*name).to_string()));
    all.extend(SUMMARY_FIELDS.iter().map(|name| (*name).to_string()));
    all.extend(service_fields().into_iter().map(|(name, _)| name.to_string()));
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_matches_python_shape() {
        let fields = declared_fields();
        assert_eq!(CARD_FIELDS.len(), 22);
        assert_eq!(SUMMARY_FIELDS.len(), 7);
        assert_eq!(service_fields().len(), 9);
        assert_eq!(fields.len(), CARD_FIELDS.len() + SUMMARY_FIELDS.len() + 9);
        for name in ["services", "crowd", "preset", "compare", "scope", "problems", "working", "error"] {
            assert!(fields.contains(name), "{name}");
        }
    }
}
