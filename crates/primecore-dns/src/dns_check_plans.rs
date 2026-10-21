//! Порт `src/dns/dns_check_plans.py` — итог вкладки «DNS подмена»: из него
//! и панель, и строка состояния, и история.
//!
//! Чистые функции без сети и интерфейса: планы состояния вкладки до и после
//! проверки, сводка результатов и имя файла для сохранения отчёта. Запись
//! в историю — в [`primecore_diagnostics::history::dns_check_entry`].
//! Результаты проверки приходят готовыми — тот же словарь, что в python
//! (`serde_json::Value`).

use primecore_diagnostics::report_upgrade::{text_scalar, truthy};
use serde_json::{Map, Value};

use crate::info_line::{TONE_ACCENT, TONE_ERROR, TONE_MUTED, TONE_SUCCESS, TONE_WARNING};

/// python `DNSCheckStartPlan` — как выглядит вкладка, пока проверка идёт.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCheckStartPlan {
    pub status_text: String,
    pub status_tone: String,
    pub check_enabled: bool,
    pub save_enabled: bool,
    pub progress_visible: bool,
}

/// python `DNSCheckFinishPlan` — как выглядит вкладка, когда проверка кончилась.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCheckFinishPlan {
    pub status_text: String,
    pub status_tone: String,
    pub check_enabled: bool,
    pub save_enabled: bool,
    pub progress_visible: bool,
}

/// python `DNSSaveResultPlan` — что показать после сохранения отчёта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSaveResultPlan {
    pub success: bool,
    pub title: String,
    pub content: String,
}

/// python-словарь из `summarize_dns_results`: вид итога (`kind`), заголовок,
/// объяснение и число подмен. `count` заполнен только при `kind == "spoofed"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub count: Option<usize>,
}

pub const KIND_SPOOFED: &str = "spoofed";
pub const KIND_OK: &str = "ok";
pub const KIND_PARTIAL: &str = "partial";
pub const KIND_STOPPED: &str = "stopped";
pub const KIND_ERROR: &str = "error";

/// python `UNVERIFIED_TITLE` — заголовок, когда «честный DNS» доказать нечем.
pub const UNVERIFIED_TITLE: &str = "Проверить DNS не удалось";

/// python `build_start_plan` — вкладка на время проверки: кнопки выключены,
/// полоса прогресса видна.
#[must_use]
pub fn build_start_plan() -> DnsCheckStartPlan {
    DnsCheckStartPlan {
        status_text: "🔄 Выполняется проверка DNS...".to_string(),
        status_tone: TONE_ACCENT.to_string(),
        check_enabled: false,
        save_enabled: false,
        progress_visible: true,
    }
}

/// python `_FINISH_STATUS` — итог → строка состояния под кнопками. Та же
/// сводка, что у панели итога: зелёного «завершена» при сбое или остановке
/// больше нет.
#[must_use]
fn finish_status(kind: &str) -> (&'static str, &'static str) {
    match kind {
        KIND_SPOOFED => ("⚠️ Обнаружена DNS подмена!", TONE_ERROR),
        KIND_OK => ("✅ Проверка завершена", TONE_SUCCESS),
        KIND_PARTIAL => (
            "⚠️ Проверка завершена, но не всё удалось проверить",
            TONE_WARNING,
        ),
        KIND_STOPPED => ("⏹️ Проверка остановлена", TONE_MUTED),
        _ => ("❌ Проверка не удалась", TONE_ERROR),
    }
}

/// python `build_finish_plan` — вкладка после проверки. `results` — итог
/// проверки (в python мог быть и `None`, тогда это пустой словарь).
#[must_use]
pub fn build_finish_plan(results: Option<&Value>) -> DnsCheckFinishPlan {
    let summary = summarize_dns_results(results);
    let (status_text, status_tone) = finish_status(&summary.kind);
    DnsCheckFinishPlan {
        status_text: status_text.to_string(),
        status_tone: status_tone.to_string(),
        check_enabled: true,
        // Сохранять есть что, только если проверка дала строки по доменам.
        save_enabled: truthy(results.and_then(|results| results.get("domains"))),
        progress_visible: false,
    }
}

/// python `build_save_default_filename` — имя файла отчёта с отметкой времени:
/// `dns_check_ГГГГММДД_ЧЧММСС.txt`.
///
/// В python время бралось из `datetime.now()` (локальное); здесь «сейчас»
/// передаёт вызывающая сторона — секунды от начала эпохи по локальным часам.
#[must_use]
pub fn build_save_default_filename(now_epoch_s: i64) -> String {
    let (year, month, day, hour, minute, second) = civil_parts(now_epoch_s);
    format!("dns_check_{year:04}{month:02}{day:02}_{hour:02}{minute:02}{second:02}.txt")
}

/// python `_reference_note` — что с эталонными серверами, с которыми
/// сравнивались ответы. Пусто — все ответили.
#[must_use]
fn reference_note(results: &Value) -> String {
    let reference: Vec<&Value> = results
        .get("reference")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|item| item.is_object()).collect())
        .unwrap_or_default();
    let down: Vec<&&Value> = reference
        .iter()
        .filter(|item| !truthy(item.get("ok")))
        .collect();
    if reference.is_empty() || down.is_empty() {
        return String::new();
    }
    if down.len() == reference.len() {
        return "Ни один эталонный сервер не ответил — сравнивать ответы было не с чем."
            .to_string();
    }
    let names = down
        .iter()
        .map(|item| {
            let label = text_scalar(item.get("label"));
            let address = text_scalar(item.get("address"));
            let mut name = format!("{label} ({address})");
            if truthy(item.get("reason")) {
                name.push_str(&format!(" — {}", text_scalar(item.get("reason"))));
            }
            name
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("Не ответили эталонные серверы: {names}. Сравнение сделано по остальным.")
}

/// python `summarize_dns_results` — итог проверки для панели: вид, заголовок,
/// объяснение и число подмен.
#[must_use]
pub fn summarize_dns_results(results: Option<&Value>) -> DnsSummary {
    let results = results.unwrap_or(&Value::Null);
    let mut summary = summarize(results);
    let note = reference_note(results);
    if !note.is_empty() && summary.kind != KIND_STOPPED && summary.kind != KIND_ERROR {
        let reference = results.get("reference").and_then(Value::as_array);
        let all_reference_down =
            reference.is_some_and(|items| items.iter().all(|item| !truthy(item.get("ok"))));
        if summary.kind == KIND_OK && all_reference_down {
            // Без эталона «честный DNS» утверждать нельзя.
            summary = DnsSummary {
                kind: KIND_PARTIAL.to_string(),
                title: UNVERIFIED_TITLE.to_string(),
                detail: String::new(),
                count: None,
            };
        }
        summary.detail = format!("{} {}", summary.detail, note).trim().to_string();
    }
    summary
}

/// python `_summarize` — сводка по самому словарю результатов, без примечаний
/// про эталонные серверы.
#[must_use]
fn summarize(results: &Value) -> DnsSummary {
    if truthy(results.get("stopped")) {
        return DnsSummary {
            kind: KIND_STOPPED.to_string(),
            title: "Проверка остановлена".to_string(),
            detail: String::new(),
            count: None,
        };
    }
    let domains: &Map<String, Value> = match results.get("domains").and_then(Value::as_object) {
        Some(domains) if !domains.is_empty() => domains,
        _ => {
            return DnsSummary {
                kind: KIND_ERROR.to_string(),
                title: "Проверка не удалась".to_string(),
                detail: "Подробности — в подробном логе ниже. Проверьте подключение и попробуйте ещё раз."
                    .to_string(),
                count: None,
            };
        }
    };
    let mut spoofed: Vec<&str> = Vec::new();
    let mut unknown: Vec<&str> = Vec::new();
    for (host, item) in domains {
        match item.get("state").and_then(Value::as_str) {
            Some("spoofed") => spoofed.push(host),
            Some("unknown") => unknown.push(host),
            _ => {}
        }
    }
    if !spoofed.is_empty() {
        let noun = if spoofed.len() == 1 {
            "сайта"
        } else {
            "сайтов"
        };
        return DnsSummary {
            kind: KIND_SPOOFED.to_string(),
            title: format!("Поймали провайдера за руку: подменяет адреса {} {noun}", spoofed.len()),
            detail: (
                "Программы, которые спрашивают адрес у Windows, получают неверный ответ. Включите DNS \
                 с шифрованием (DoH) на странице «Настройка DNS» — его провайдер перехватить не сможет."
            )
                .to_string(),
            count: Some(spoofed.len()),
        };
    }
    if !unknown.is_empty() {
        return DnsSummary {
            kind: KIND_PARTIAL.to_string(),
            title: "Явной подмены нет".to_string(),
            detail:
                ("Часть адресов отличается от эталона, но проверить их не удалось — для CDN это \
                 обычно нормально.")
                    .to_string(),
            count: None,
        };
    }
    if domains
        .values()
        .all(|item| item.get("state").and_then(Value::as_str) == Some("local"))
    {
        // Ни один адрес не пришёл от провайдера: сравнивать было нечего,
        // «честный DNS» не доказан.
        return DnsSummary {
            kind: KIND_PARTIAL.to_string(),
            title: "Адреса берутся не у провайдера".to_string(),
            detail:
                ("Все проверенные адреса заданы на этом компьютере или в вашей сети — файл hosts, \
                 VPN, домашний фильтр, — поэтому подмену у провайдера по ним не проверить.")
                    .to_string(),
            count: None,
        };
    }
    DnsSummary {
        kind: KIND_OK.to_string(),
        title: "Ваш DNS честный 👍".to_string(),
        detail: ("Адреса совпадают с эталоном. Если сайты не открываются — дело не в DNS, а в \
             блокировке соединения.")
            .to_string(),
        count: None,
    }
}

/// Секунды эпохи → (год, месяц, день, час, минута, секунда). Копия
/// `civil_parts` из `primecore_diagnostics::history` (там функция закрыта);
/// в python это делает `datetime`. Время «наивное»: часовой пояс выбирает
/// вызывающая сторона, передающая `now_epoch_s`.
fn civil_parts(unix_s: i64) -> (i64, u32, u32, u32, u32, u32) {
    let day_number = unix_s.div_euclid(86_400);
    let seconds_of_day = unix_s.rem_euclid(86_400);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    let z = day_number + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = y + i64::from(month <= 2);
    (year, month, day, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primecore_diagnostics::history::dns_check_entry;
    use serde_json::json;

    // python: FinishPlanTests.test_failed_or_stopped_check_is_not_green
    #[test]
    fn failed_or_stopped_check_is_not_green() {
        let failed = build_finish_plan(None);
        let stopped = build_finish_plan(Some(&json!({"stopped": true})));
        assert_eq!(
            (failed.status_tone.as_str(), failed.save_enabled),
            (TONE_ERROR, false)
        );
        assert_eq!(stopped.status_tone, TONE_MUTED);
        assert!(!failed.status_text.contains('✅'));
        assert!(!stopped.status_text.contains('✅'));
    }

    // python: FinishPlanTests.test_spoofing_and_partial_and_ok
    #[test]
    fn spoofing_and_partial_and_ok() {
        let spoofed = build_finish_plan(Some(&json!({"domains": {"a": {"state": "spoofed"}}})));
        assert_eq!(spoofed.status_tone, TONE_ERROR);
        assert_eq!(spoofed.status_text, "⚠️ Обнаружена DNS подмена!");
        let unknown = build_finish_plan(Some(&json!({"domains": {"a": {"state": "unknown"}}})));
        assert_eq!(unknown.status_tone, TONE_WARNING);
        let ok = build_finish_plan(Some(&json!({"domains": {"a": {"state": "ok"}}})));
        assert_eq!(ok.status_tone, TONE_SUCCESS);
        assert_eq!(ok.status_text, "✅ Проверка завершена");
    }

    // python: FinishPlanTests.test_addresses_all_set_locally_prove_nothing_about_the_provider
    #[test]
    fn addresses_all_set_locally_prove_nothing_about_the_provider() {
        let summary = summarize_dns_results(Some(
            &json!({"domains": {"a": {"state": "local"}, "b": {"state": "local"}}}),
        ));
        assert_eq!(summary.kind, KIND_PARTIAL);
        assert!(!summary.title.contains("честный"));
        assert_eq!(summary.title, "Адреса берутся не у провайдера");
    }

    // python: FinishPlanTests.test_history_of_a_check_that_learned_nothing_is_unknown
    // (dns_check_entry портирована в primecore-diagnostics::history)
    #[test]
    fn history_of_a_check_that_learned_nothing_is_unknown() {
        let entry = dns_check_entry(
            &json!({"domains": {"a": {"state": "unknown"}, "b": {"state": "unknown"}}}),
            None,
        )
        .expect("запись должна быть");
        assert_eq!(entry.get("level").and_then(Value::as_str), Some("unknown"));
        let partly = dns_check_entry(
            &json!({"domains": {"a": {"state": "unknown"}, "b": {"state": "ok"}}}),
            None,
        )
        .expect("запись должна быть");
        assert_eq!(partly.get("level").and_then(Value::as_str), Some("warn"));
    }

    // python: build_start_plan — сверено с эталоном.
    #[test]
    fn start_plan_matches_python() {
        let plan = build_start_plan();
        assert_eq!(plan.status_text, "🔄 Выполняется проверка DNS...");
        assert_eq!(plan.status_tone, TONE_ACCENT);
        assert!(!plan.check_enabled);
        assert!(!plan.save_enabled);
        assert!(plan.progress_visible);
    }

    // python: summarize_dns_results(None) и пустой словарь — «Проверка не удалась».
    #[test]
    fn empty_results_summarize_to_error() {
        let none = summarize_dns_results(None);
        assert_eq!(none.kind, KIND_ERROR);
        assert_eq!(none.title, "Проверка не удалась");
        assert_eq!(
            none.detail,
            "Подробности — в подробном логе ниже. Проверьте подключение и попробуйте ещё раз."
        );
        let empty = summarize_dns_results(Some(&json!({})));
        assert_eq!(empty, none);
    }

    // python: слова «сайта»/«сайтов» и число подмен в сводке.
    #[test]
    fn spoofed_count_and_wording() {
        let one = summarize_dns_results(Some(&json!({"domains": {"a": {"state": "spoofed"}}})));
        assert_eq!(one.kind, KIND_SPOOFED);
        assert_eq!(one.count, Some(1));
        assert_eq!(
            one.title,
            "Поймали провайдера за руку: подменяет адреса 1 сайта"
        );
        let many = summarize_dns_results(Some(&json!({
            "domains": {"a": {"state": "spoofed"}, "b": {"state": "spoofed"}, "c": {"state": "ok"}},
        })));
        assert_eq!(many.count, Some(2));
        assert_eq!(
            many.title,
            "Поймали провайдера за руку: подменяет адреса 2 сайтов"
        );
    }

    // python: все эталонные серверы молчат — «честный DNS» становится «partial».
    #[test]
    fn reference_all_down_downgrades_ok_to_partial() {
        let results = json!({
            "domains": {"a": {"state": "ok"}},
            "reference": [
                {"label": "Google", "address": "8.8.8.8", "ok": false, "reason": "тайм-аут"},
                {"label": "Cloudflare", "address": "1.1.1.1", "ok": false},
            ],
        });
        let summary = summarize_dns_results(Some(&results));
        assert_eq!(summary.kind, KIND_PARTIAL);
        assert_eq!(summary.title, UNVERIFIED_TITLE);
        assert_eq!(
            summary.detail,
            "Ни один эталонный сервер не ответил — сравнивать ответы было не с чем."
        );
    }

    // python: примечание про молчащие эталоны дописывается к «ok»-сводке.
    #[test]
    fn reference_note_appends_names_to_ok() {
        let results = json!({
            "domains": {"a": {"state": "ok"}},
            "reference": [
                {"label": "Google", "address": "8.8.8.8", "ok": true},
                {"label": "Яндекс", "address": "77.88.8.8", "ok": false, "reason": "тайм-аут"},
            ],
        });
        let summary = summarize_dns_results(Some(&results));
        assert_eq!(summary.kind, KIND_OK);
        assert_eq!(
            summary.detail,
            "Адреса совпадают с эталоном. Если сайты не открываются — дело не в DNS, \
             а в блокировке соединения. Не ответили эталонные серверы: Яндекс (77.88.8.8) — \
             тайм-аут. Сравнение сделано по остальным."
        );
    }

    // python: «stopped» и «error» не получают примечание про эталоны.
    #[test]
    fn stopped_and_error_keep_their_detail_even_with_reference_note() {
        let stopped = summarize_dns_results(Some(
            &json!({"stopped": true, "reference": [{"ok": false}]}),
        ));
        assert_eq!(stopped.kind, KIND_STOPPED);
        assert_eq!(stopped.detail, "");
        let error = summarize_dns_results(Some(&json!({"reference": [{"ok": false}]})));
        assert_eq!(error.kind, KIND_ERROR);
        assert_eq!(
            error.detail,
            "Подробности — в подробном логе ниже. Проверьте подключение и попробуйте ещё раз."
        );
    }

    // python: примечание дописывается и к «partial» по неизвестным адресам;
    // единственный молчащий эталон — «ни один не ответил».
    #[test]
    fn reference_note_appends_to_partial_unknown() {
        let results = json!({
            "domains": {"a": {"state": "unknown"}},
            "reference": [{"label": "X", "address": "1.2.3.4", "ok": false}],
        });
        let summary = summarize_dns_results(Some(&results));
        assert_eq!(summary.kind, KIND_PARTIAL);
        assert_eq!(summary.title, "Явной подмены нет");
        assert_eq!(
            summary.detail,
            "Часть адресов отличается от эталона, но проверить их не удалось — для CDN это \
             обычно нормально. Ни один эталонный сервер не ответил — сравнивать ответы было \
             не с чем."
        );
    }

    // python: build_save_default_filename — формат strftime("%Y%m%d_%H%M%S");
    // 1760000000 с — это 2025-10-09 08:53:20 UTC.
    #[test]
    fn save_default_filename_matches_strftime() {
        assert_eq!(
            build_save_default_filename(1_760_000_000),
            "dns_check_20251009_085320.txt"
        );
        assert_eq!(
            build_save_default_filename(0),
            "dns_check_19700101_000000.txt"
        );
    }

    // python: build_finish_plan — кнопки и полоса прогресса после проверки.
    #[test]
    fn finish_plan_enables_save_only_with_domains() {
        let plan = build_finish_plan(Some(&json!({"domains": {"a": {"state": "ok"}}})));
        assert!(plan.check_enabled);
        assert!(plan.save_enabled);
        assert!(!plan.progress_visible);
        let empty = build_finish_plan(Some(&json!({})));
        assert!(!empty.save_enabled);
    }

    // python: DNSSaveResultPlan — поля отчёта сохранения.
    #[test]
    fn save_result_plan_holds_report_fields() {
        let plan = DnsSaveResultPlan {
            success: true,
            title: "Сохранено".to_string(),
            content: "dns_check_20251009_085320.txt".to_string(),
        };
        assert!(plan.success);
        assert_eq!(plan.title, "Сохранено");
    }
}
