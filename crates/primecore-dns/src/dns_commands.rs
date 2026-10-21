//! Порт `src/dns/commands.py` — публичные команды DNS-слоя для фасада
//! программы.
//!
//! Это последний слой цепочки: `dns.winapi` (вызовы Windows) →
//! `dns.adapters` → `dns.runtime` (что сделать) → этот модуль (команды,
//! которые зовёт фасад). Команды только собирают уже портированные решения
//! (`dns.runtime`, `dns.custom_servers`, `dns.doh_lookup`,
//! `dns.server_check`, `dns.diagnostics`) и передают им платформенный ввод —
//! настройки программы, файлы журналов, сеть — замыканиями.
//!
//! Не перенесено (остаётся платформенным или ждёт своих модулей):
//! - `_save_past_check`/`save_domain_lookup_text` — запись отчётов проверок в
//!   папку журналов (файловая система, имена с датой); оставлен чистый
//!   помощник отсечения старых файлов [`past_check_files_to_prune`];
//! - `run_server_check` и `_running_bypass` — сама проверка серверов и список
//!   запущенных программ обхода (список процессов Windows);
//! - `build_domain_lookup_servers`, `run_domain_lookup` и
//!   `load_past_domain_lookup_report` — ждут порта `dns.domain_lookup`.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::custom_servers as custom;
use crate::dns_check_plans::DnsSaveResultPlan;
use crate::doh_lookup::{self, LookupIo};
use crate::providers;
use crate::server_check::ServerCheckReport;
use crate::server_check_verdicts::rejudge_report;
use crate::state::CustomServerResult;

// Форматы файлов прошлых проверок (python-константы commands.py).
pub const DOMAIN_LOOKUP_FORMAT: &str = "primebypass.domain_lookup/1";
pub const DNS_CHECK_FORMAT: &str = "primebypass.dns_check/1";
pub const SERVER_CHECK_FORMAT: &str = "primebypass.server_check/1";
/// Столько файлов прошлых проверок каждой вкладки хранится; история вкладки
/// короче.
pub const PAST_CHECK_FILES_KEPT: usize = 40;

// Публичные команды состояния и действий — те же функции слоя `dns.runtime`;
// Windows-ввод они принимают параметрами (см. `crate::runtime::DnsIo`).
pub use crate::answering::check_answering;
pub use crate::latency::measure_dns_latency;
pub use crate::runtime::{
    adapters_with_static_dns, apply_dns, consume_warmed_state, flush_dns_cache,
    load_custom_servers, load_page_state, load_state, migrate_outdated_dns_addresses,
    repair_local_proxy, reset_to_auto, start_local_proxy, stop_local_proxy_if_unused, warm_state,
    write_doh_templates,
};

// ── предупреждение про DNS провайдера ─────────────────────────────────────

/// python `is_isp_dns_warning_shown` — видел ли пользователь уже
/// предупреждение про DNS провайдера (`read` — чтение настройки).
#[must_use]
pub fn is_isp_dns_warning_shown(read: &dyn Fn() -> bool) -> bool {
    read()
}

/// python `mark_isp_dns_warning_shown` — запомнить, что предупреждение
/// показано (`write` — запись настройки); вернула ли она успех.
pub fn mark_isp_dns_warning_shown(write: &mut dyn FnMut(bool) -> bool) -> bool {
    write(true)
}

// ── свои DNS-серверы ──────────────────────────────────────────────────────

/// python `_reserved_names` — названия серверов программы: свой сервер не
/// может называться так же.
#[must_use]
pub fn reserved_names() -> Vec<String> {
    providers::iter_providers()
        .into_iter()
        .map(|(_group, name, _data)| name)
        .collect()
}

/// python-сигнатура `change(список)` → (новый список, ошибка): `Err` —
/// изменение отвергнуто, настройки остаются прежними.
pub type CustomChange<'a> = dyn Fn(&[Value]) -> Result<Vec<Value>, String> + 'a;

/// python `update_custom_dns_servers(mutate)` — транзакция настроек: получает
/// функцию `mutate(текущий список) → новый список или ошибка` и возвращает
/// итоговый список (или отказ — тогда список не менялся).
/// python `mutate(текущий список) → новый список или ошибка` — правка
/// списка внутри транзакции.
pub type MutateCustom<'a> = dyn FnMut(&[Value]) -> Result<Vec<Value>, String> + 'a;

/// python `update_custom_dns_servers(mutate)` — транзакция настроек: получает
/// функцию `mutate(текущий список) → новый список или ошибка` и возвращает
/// итоговый список (или отказ — тогда список не менялся).
pub type CommitCustom<'a> = dyn FnMut(&mut MutateCustom<'_>) -> Result<Vec<Value>, String> + 'a;

/// python `_change_custom_servers` — меняет список своих DNS одной
/// транзакцией; `change(список) → (новый список, ошибка)`.
pub fn change_custom_servers(
    load: &dyn Fn() -> Vec<Value>,
    change: &CustomChange<'_>,
    commit: &mut CommitCustom<'_>,
) -> CustomServerResult {
    match change(&load()) {
        Ok(_servers) => {
            // Внутри транзакции изменение применяется к текущему списку
            // настроек: если между проверкой и записью список менялся,
            // изменение отвергается так же.
            let mut mutate = |current: &[Value]| change(current);
            match commit(&mut mutate) {
                Ok(servers) => CustomServerResult {
                    success: true,
                    servers,
                    ..CustomServerResult::default()
                },
                Err(error) => CustomServerResult {
                    success: false,
                    servers: load(),
                    message: error,
                    ..CustomServerResult::default()
                },
            }
        }
        Err(error) => CustomServerResult {
            success: false,
            servers: load(),
            message: error,
            ..CustomServerResult::default()
        },
    }
}

/// python `save_custom_server` — добавляет или заменяет (по id) свой
/// DNS-сервер.
///
/// Если задан только адрес DoH, сначала находятся и проверяются IP-адреса
/// сервера (dns.doh_lookup): без них Windows сервер не примет. `ipv6` —
/// живёт ли IPv6 на компьютере (python `winapi.internet_route().has_ipv6`),
/// `doh_supported` — умеет ли Windows DoH, `lookup` — ввод поиска адресов.
pub fn save_custom_server(
    server: &Value,
    ipv6: bool,
    doh_supported: bool,
    lookup: &LookupIo<'_>,
    load: &dyn Fn() -> Vec<Value>,
    commit: &mut CommitCustom<'_>,
) -> CustomServerResult {
    let mut record = custom::copy_server(Some(server));
    let mut notice = String::new();
    let doh = record.get("doh").and_then(Value::as_str).unwrap_or("");
    let ipv4 = text_array(&record, "ipv4");
    let ipv6_addresses = text_array(&record, "ipv6");
    if !doh.is_empty() && ipv4.is_empty() && ipv6_addresses.is_empty() {
        let Some(template) = custom::parse_doh_template(doh) else {
            return CustomServerResult {
                success: false,
                message: "Адрес DoH записан неверно.".to_string(),
                field: custom::FIELD_DOH.to_string(),
                ..CustomServerResult::default()
            };
        };
        let found = doh_lookup::find_doh_addresses(&template, ipv6, doh_supported, lookup);
        if !found.found() {
            return CustomServerResult {
                success: false,
                message: found.error.clone(),
                field: custom::FIELD_DOH.to_string(),
                ..CustomServerResult::default()
            };
        }
        record["ipv4"] = json!(found.ipv4);
        record["ipv6"] = json!(found.ipv6);
        notice = found.notice.clone();
    }

    let server_id = record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reserved = reserved_names();
    let reserved: Vec<&str> = reserved.iter().map(String::as_str).collect();
    let change = |current: &[Value]| -> Result<Vec<Value>, String> {
        let (servers, error) = custom::upsert_server(current, &record, &reserved);
        if error.is_empty() {
            Ok(servers)
        } else {
            Err(error)
        }
    };
    let result = change_custom_servers(load, &change, commit);
    if !result.success {
        // Ошибка названия — к полю названия (см. python-команду).
        return CustomServerResult {
            success: false,
            servers: result.servers,
            message: result.message,
            field: custom::FIELD_NAME.to_string(),
            ..CustomServerResult::default()
        };
    }
    let saved = result
        .servers
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str).unwrap_or("") == server_id)
        .cloned()
        .unwrap_or_else(|| record.clone());
    CustomServerResult {
        success: true,
        servers: result.servers,
        server: Some(saved),
        notice,
        ..CustomServerResult::default()
    }
}

/// python `delete_custom_server` — убирает свой сервер по id.
pub fn delete_custom_server(
    server_id: &str,
    load: &dyn Fn() -> Vec<Value>,
    commit: &mut CommitCustom<'_>,
) -> CustomServerResult {
    let change = move |current: &[Value]| -> Result<Vec<Value>, String> {
        Ok(custom::remove_server(current, server_id))
    };
    change_custom_servers(load, &change, commit)
}

/// python `duplicate_custom_server` — копия своего сервера с новым
/// названием и id.
pub fn duplicate_custom_server(
    server_id: &str,
    load: &dyn Fn() -> Vec<Value>,
    commit: &mut CommitCustom<'_>,
) -> CustomServerResult {
    let reserved = reserved_names();
    let reserved: Vec<&str> = reserved.iter().map(String::as_str).collect();
    let change = move |current: &[Value]| -> Result<Vec<Value>, String> {
        Ok(custom::duplicate_server(current, server_id, &reserved))
    };
    change_custom_servers(load, &change, commit)
}

fn text_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ── цели проверки DNS-серверов ────────────────────────────────────────────

/// python `build_server_check_targets` — адреса для вкладки «DNS-серверы»:
/// все серверы программы и свои, IPv6 — если он есть.
///
/// `ipv6` — есть ли дорога по IPv6 (python `winapi.internet_route`), `custom`
/// — свои DNS из настроек.
#[must_use]
pub fn build_server_check_targets(
    ipv6: bool,
    custom: &[Value],
) -> Vec<crate::server_check::CheckTarget> {
    let providers_map =
        custom::build_dns_providers_with_custom(&providers::network_providers(), custom);
    crate::server_check::build_targets(&providers_map, ipv6)
}

// ── проверка DNS подмены ──────────────────────────────────────────────────

/// python `run_dns_poisoning_check` — проверка DNS подмены для вкладки
/// «Проверка DNS подмены».
///
/// Строки отчёта копятся, чтобы лечь в тот же файл: у прошлой проверки по ним
/// работает кнопка «Отчёт». `save_past` — сохранение документа проверки в
/// папку журналов (python `_save_past_check`), `remember` — запись итога в
/// историю вкладки (python `settings.store.add_tab_history_run`).
pub fn run_dns_poisoning_check(
    should_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    io: &primecore_diagnostics::engine::EngineIo,
    save_past: &mut dyn FnMut(&Value) -> String,
    remember: &dyn Fn(Option<&Value>),
) -> Value {
    use primecore_diagnostics::history::dns_check_entry;

    let mut lines: Vec<String> = Vec::new();
    let mut emit = |line: &str| lines.push(line.to_string());
    let mut results = primecore_diagnostics::engine::run_dns_check(should_stop, &mut emit, io);
    let entry = dns_check_entry(&results, None);
    match entry {
        Some(mut entry) => {
            // Итог целиком — в файл: прошлая проверка открывается теми же
            // карточками.
            let document = json!({
                "format": DNS_CHECK_FORMAT,
                "report": results.clone(),
                "text": lines,
            });
            entry["log_file"] = Value::String(save_past(&document));
            // Экран показывает ту самую запись, что сохранена в настройки.
            results["history_entry"] = entry.clone();
            remember(Some(&entry));
        }
        None => remember(None),
    }
    results
}

// ── сохранение отчёта проверки DNS подмены ────────────────────────────────

/// python `save_dns_check_results` — сохранить отчёт проверки в файл и
/// показать, что вышло.
///
/// `now_text` — «сейчас» строкой вида `2026-10-12 21:05:00`, `write` — запись
/// файла, `reveal` — открыть папку в проводнике (python `os.startfile`;
/// сбой открытия на итог не влияет).
#[must_use]
pub fn save_dns_check_results(
    file_path: &str,
    plain_text: &str,
    now_text: &str,
    write: &mut dyn FnMut(&str, &str) -> Result<(), String>,
    reveal: &dyn Fn(&str),
) -> DnsSaveResultPlan {
    let target_path = file_path.trim();
    if target_path.is_empty() {
        return DnsSaveResultPlan {
            success: false,
            title: "Ошибка".to_string(),
            content: "Не указан путь для сохранения файла.".to_string(),
        };
    }
    let text = format!(
        "DNS CHECK RESULTS\nDate: {now_text}\n{}\n\n{}",
        "=".repeat(60),
        plain_text
    );
    if let Err(error) = write(target_path, &text) {
        return DnsSaveResultPlan {
            success: false,
            title: "Ошибка".to_string(),
            content: format!("Не удалось сохранить файл:\n{error}"),
        };
    }
    let folder = Path::new(target_path)
        .parent()
        .map(|folder| folder.to_string_lossy().to_string())
        .unwrap_or_default();
    if !folder.is_empty() {
        reveal(&folder);
    }
    DnsSaveResultPlan {
        success: true,
        title: "Сохранено".to_string(),
        content: format!("Результаты сохранены в:\n{target_path}"),
    }
}

// ── файлы прошлых проверок ────────────────────────────────────────────────

/// python `_format_version` — номер версии файла той же вкладки
/// (`primebypass.<вкладка>/<номер>`). `None` — чужой файл.
#[must_use]
pub fn format_version(value: &str, expected_format: &str) -> Option<i64> {
    let family = expected_format
        .rsplit_once('/')
        .map_or("", |(family, _)| family);
    let (name, slash, number) = python_rpartition(value);
    if slash.is_empty() || name != family {
        return None;
    }
    number.parse::<i64>().ok()
}

/// python `str.rpartition` — (до, разделитель, после) по последнему
/// вхождению; без разделителя — ("", "", вся строка).
fn python_rpartition(value: &str) -> (&str, &str, &str) {
    match value.rfind('/') {
        Some(index) => (
            &value[..index],
            &value[index..index + 1],
            &value[index + 1..],
        ),
        None => ("", "", value),
    }
}

/// python `_read_past_check` — документ прошлой проверки вкладки. `None` —
/// файла нет, он чужой или из более новой программы.
///
/// Файл любой версии формата этой вкладки не новее текущей читается: смена
/// номера версии не должна делать нечитаемыми все сохранённые проверки.
/// `read_json` — чтение файла настроек как JSON (платформенный слой).
#[must_use]
pub fn read_past_check(
    log_file: Option<&str>,
    expected_format: &str,
    read_json: &dyn Fn(&str) -> Option<Value>,
) -> Option<Value> {
    let log_file = log_file?;
    let document = read_json(log_file)?;
    if !document.is_object() {
        return None;
    }
    let version = format_version(
        document.get("format").and_then(Value::as_str).unwrap_or(""),
        expected_format,
    );
    let current = format_version(expected_format, expected_format);
    match (version, current) {
        (Some(version), Some(current)) if version <= current => Some(document),
        _ => None,
    }
}

/// python `load_past_domain_lookup` — текст прошлой проверки домена. Пусто —
/// файла нет или он не читается.
#[must_use]
pub fn load_past_domain_lookup(
    log_file: Option<&str>,
    read_json: &dyn Fn(&str) -> Option<Value>,
) -> String {
    lines_text(
        read_past_check(log_file, DOMAIN_LOOKUP_FORMAT, read_json)
            .as_ref()
            .and_then(|document| document.get("text")),
    )
}

/// python `load_past_dns_check_text` — текст прошлой проверки DNS подмены.
/// Пусто — файла нет или текст в него не клали.
#[must_use]
pub fn load_past_dns_check_text(
    log_file: Option<&str>,
    read_json: &dyn Fn(&str) -> Option<Value>,
) -> String {
    lines_text(
        read_past_check(log_file, DNS_CHECK_FORMAT, read_json)
            .as_ref()
            .and_then(|document| document.get("text")),
    )
}

/// python `load_past_dns_check_report` — итог прошлой проверки DNS подмены —
/// тем же словарём, что уходил на экран вкладки. `None` — файла нет.
#[must_use]
pub fn load_past_dns_check_report(
    log_file: Option<&str>,
    read_json: &dyn Fn(&str) -> Option<Value>,
) -> Option<Value> {
    read_past_check(log_file, DNS_CHECK_FORMAT, read_json)?
        .get("report")
        .filter(|report| report.is_object())
        .cloned()
}

/// python `load_past_server_check_report` — отчёт прошлой проверки
/// DNS-серверов — тем же объектом, из которого строятся карточки. `None` —
/// файла нет, он не читается или сохранён до того, как отчёт стали класть в
/// файл.
///
/// Выводы пересчитываются по нынешним правилам (`rejudge_report`): сырые
/// факты в файле есть, а правила с тех пор могли уточниться. `owner_of` и
/// `is_stub` — ввод выводов (см. `dns.server_check_verdict`).
#[must_use]
pub fn load_past_server_check_report(
    log_file: Option<&str>,
    read_json: &dyn Fn(&str) -> Option<Value>,
    owner_of: &dyn Fn(&str) -> Option<crate::server_check::IpOwner>,
    is_stub: &dyn Fn(&str) -> bool,
) -> Option<ServerCheckReport> {
    let report = read_past_check(log_file, SERVER_CHECK_FORMAT, read_json)?
        .get("report")?
        .clone();
    let report: ServerCheckReport = serde_json::from_value(report).ok()?;
    Some(rejudge_report(&report, owner_of, is_stub))
}

/// python `"\\n".join(...)` по списку строк документа.
fn lines_text(value: Option<&Value>) -> String {
    let Some(lines) = value.and_then(Value::as_array) else {
        return String::new();
    };
    lines
        .iter()
        .map(|line| match line {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Чистое правило чистки папки журналов (python `_save_past_check`): из
/// отсортированных по имени файлов префикса остаются `kept` самых новых,
/// остальные удаляются.
#[must_use]
pub fn past_check_files_to_prune(mut names: Vec<String>, kept: usize) -> Vec<String> {
    names.sort();
    let cut = names.len().saturating_sub(kept);
    names.truncate(cut);
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(id: &str, name: &str, ipv4: &[&str], doh: &str) -> Value {
        json!({"id": id, "name": name, "ipv4": ipv4, "ipv6": [], "doh": doh})
    }

    fn noop_commit() -> impl FnMut(&mut MutateCustom<'_>) -> Result<Vec<Value>, String> {
        |_mutate: &mut MutateCustom<'_>| Ok(Vec::new())
    }

    #[test]
    fn rejected_change_keeps_current_servers_and_reports_the_reason() {
        let current = vec![server("a", "Мой", &["203.0.113.5"], "")];
        let load = || current.clone();
        let change = |_current: &[Value]| -> Result<Vec<Value>, String> {
            Err("Сервер с названием «Мой» уже есть. Впишите другое название.".to_string())
        };
        let mut commit = |_mutate: &mut MutateCustom<'_>| Err("не должно вызываться".to_string());

        let result = change_custom_servers(&load, &change, &mut commit);

        assert!(!result.success);
        assert_eq!(result.servers, current);
        assert!(result.message.contains("уже есть"));
    }

    #[test]
    fn accepted_change_commits_the_new_list() {
        let current = vec![server("a", "Мой", &["203.0.113.5"], "")];
        let load = || current.clone();
        let change = |current: &[Value]| -> Result<Vec<Value>, String> {
            let mut servers = current.to_vec();
            servers.push(server("b", "Второй", &["203.0.113.9"], ""));
            Ok(servers)
        };
        let mut commit = |mutate: &mut MutateCustom<'_>| mutate(&load());

        let result = change_custom_servers(&load, &change, &mut commit);

        assert!(result.success);
        assert_eq!(result.servers.len(), 2);
        assert_eq!(result.message, "");
    }

    /// Ввод поиска адресов DoH (python `dns.doh_lookup`): имя даёт адрес
    /// `answer`, все запросы отвечают им же; `None` — не отвечают.
    fn lookup_io(answer: Option<&str>) -> LookupIo<'static> {
        let resolved = answer.unwrap_or("").to_string();
        let probe_record = answer.map(|value| primecore_dnswire::DnsRecord {
            name: String::new(),
            rtype: primecore_dnswire::TYPE_A,
            ttl: 0,
            value: value.to_string(),
        });
        let plain_record = probe_record.clone();
        LookupIo {
            resolve: Box::new(move |_host, _ipv6| {
                if resolved.is_empty() {
                    Vec::new()
                } else {
                    vec![resolved.clone()]
                }
            }),
            probe: Box::new(move |_address, _template| match &probe_record {
                Some(record) => primecore_dnswire::DnsQueryResult {
                    transport: "doh".to_string(),
                    rcode: Some(0),
                    records: vec![record.clone()],
                    ..Default::default()
                },
                None => primecore_dnswire::DnsQueryResult::default(),
            }),
            plain: Box::new(move |_address| match &plain_record {
                Some(record) => primecore_dnswire::DnsQueryResult {
                    transport: "udp".to_string(),
                    rcode: Some(0),
                    records: vec![record.clone()],
                    ..Default::default()
                },
                None => primecore_dnswire::DnsQueryResult::default(),
            }),
        }
    }

    #[test]
    fn doh_only_server_gets_its_addresses_from_the_lookup() {
        // Сервер с одним адресом DoH: адреса находит dns.doh_lookup.
        let lookup = lookup_io(Some("203.0.113.5"));
        let current: Vec<Value> = Vec::new();
        let load = || current.clone();
        let mut commit = |mutate: &mut MutateCustom<'_>| mutate(&load());

        let result = save_custom_server(
            &json!({"id": "a", "name": "Мой", "doh": "https://dns.example.com/dns-query"}),
            false,
            true,
            &lookup,
            &load,
            &mut commit,
        );

        assert!(result.success, "{}", result.message);
        let saved = result.server.expect("сервер сохранён");
        assert_eq!(
            saved.get("ipv4"),
            Some(&json!(["203.0.113.5"])),
            "адреса найдены"
        );
    }

    #[test]
    fn bad_doh_address_is_rejected_at_its_field() {
        let lookup = lookup_io(None);
        let current: Vec<Value> = Vec::new();
        let load = || current.clone();
        let mut commit = noop_commit();

        let result = save_custom_server(
            &json!({"id": "a", "name": "Мой", "doh": "не адрес"}),
            false,
            true,
            &lookup,
            &load,
            &mut commit,
        );

        assert!(!result.success);
        assert_eq!(result.field, custom::FIELD_DOH);
        assert!(result.message.contains("записан неверно"));
    }

    #[test]
    fn duplicate_name_is_rejected_at_the_name_field() {
        let lookup = lookup_io(None);
        let current = vec![server("a", "Quad9", &["203.0.113.5"], "")];
        let load = || current.clone();
        let mut commit = noop_commit();

        let result = save_custom_server(
            &json!({"id": "a", "name": "Quad9", "ipv4": ["203.0.113.9"]}),
            false,
            true,
            &lookup,
            &load,
            &mut commit,
        );

        assert!(!result.success);
        assert_eq!(result.field, custom::FIELD_NAME);
        assert!(result.message.contains("уже есть"));
        assert_eq!(result.servers, current);
    }

    #[test]
    fn delete_and_duplicate_change_the_list() {
        let current = vec![server("a", "Мой", &["203.0.113.5"], "")];
        let load = || current.clone();
        let mut commit = |mutate: &mut MutateCustom<'_>| mutate(&load());

        let deleted = delete_custom_server("a", &load, &mut commit);
        assert!(deleted.success);
        assert!(deleted.servers.is_empty());

        let duplicated = duplicate_custom_server("a", &load, &mut commit);
        assert!(duplicated.success);
        assert_eq!(duplicated.servers.len(), 2);
        let copy = duplicated.servers.last().expect("копия добавлена");
        assert_eq!(copy.get("name").and_then(Value::as_str), Some("Мой копия"));
    }

    #[test]
    fn reserved_names_come_from_the_program_catalog() {
        let names = reserved_names();
        assert!(names.contains(&"Quad9".to_string()));
        assert!(names.contains(&"DNSCrypt".to_string()));
    }

    #[test]
    fn server_check_targets_cover_program_and_custom_servers() {
        let custom = vec![server("a", "Мой", &["203.0.113.5"], "")];

        let targets = build_server_check_targets(true, &custom);

        assert!(targets.iter().any(|target| target.address == "9.9.9.9"));
        assert!(targets.iter().any(|target| target.address == "203.0.113.5"));
        // С IPv6 цели содержат и IPv6-адреса серверов программы.
        let without_ipv6 = build_server_check_targets(false, &custom);
        assert!(targets.len() > without_ipv6.len());
    }

    #[test]
    fn format_version_only_accepts_the_same_family() {
        assert_eq!(
            format_version("primebypass.domain_lookup/1", DOMAIN_LOOKUP_FORMAT),
            Some(1)
        );
        assert_eq!(
            format_version("primebypass.domain_lookup/12", DOMAIN_LOOKUP_FORMAT),
            Some(12)
        );
        assert_eq!(
            format_version("primebypass.dns_check/1", DOMAIN_LOOKUP_FORMAT),
            None
        );
        assert_eq!(format_version("без версии", DOMAIN_LOOKUP_FORMAT), None);
        assert_eq!(
            format_version("primebypass.domain_lookup/х", DOMAIN_LOOKUP_FORMAT),
            None
        );
    }

    fn past_document(format_value: &str, text: &[&str]) -> Value {
        json!({"format": format_value, "target": "example.com", "text": text})
    }

    #[test]
    fn past_check_of_the_same_or_older_version_is_read_back() {
        let documents = [(
            "old.json".to_string(),
            past_document(DOMAIN_LOOKUP_FORMAT, &["строка 1", "строка 2"]),
        )];
        let read_json = move |path: &str| -> Option<Value> {
            documents
                .iter()
                .find(|(name, _)| name == path)
                .map(|(_, document)| document.clone())
        };

        let document = read_past_check(Some("old.json"), DOMAIN_LOOKUP_FORMAT, &read_json)
            .expect("документ прочитан");
        assert_eq!(
            document.get("target").and_then(Value::as_str),
            Some("example.com")
        );

        assert_eq!(
            load_past_domain_lookup(Some("old.json"), &read_json),
            "строка 1\nстрока 2"
        );
    }

    #[test]
    fn missing_foreign_or_newer_past_check_is_ignored() {
        let documents = [
            (
                "foreign.json".to_string(),
                past_document(DNS_CHECK_FORMAT, &["чужая вкладка"]),
            ),
            (
                "newer.json".to_string(),
                past_document("primebypass.domain_lookup/2", &["новее программы"]),
            ),
        ];
        let read_json = move |path: &str| -> Option<Value> {
            documents
                .iter()
                .find(|(name, _)| name == path)
                .map(|(_, document)| document.clone())
        };

        // Чужой формат и версия новее программы не читаются.
        assert!(read_past_check(Some("foreign.json"), DOMAIN_LOOKUP_FORMAT, &read_json).is_none());
        assert!(read_past_check(Some("newer.json"), DOMAIN_LOOKUP_FORMAT, &read_json).is_none());
        // Файла нет — пусто.
        assert!(read_past_check(None, DOMAIN_LOOKUP_FORMAT, &read_json).is_none());
        assert!(read_past_check(Some("нет.json"), DOMAIN_LOOKUP_FORMAT, &read_json).is_none());
        assert_eq!(
            load_past_domain_lookup(Some("foreign.json"), &read_json),
            ""
        );
    }

    #[test]
    fn dns_check_text_is_read_back() {
        let document = json!({
            "format": DNS_CHECK_FORMAT,
            "report": {"domains": {"example.com": {"state": "ok"}}},
            "text": ["строка 1", "строка 2"],
        });
        let documents = [("check.json".to_string(), document)];
        let read_json = move |path: &str| -> Option<Value> {
            documents
                .iter()
                .find(|(name, _)| name == path)
                .map(|(_, document)| document.clone())
        };

        assert_eq!(
            load_past_dns_check_text(Some("check.json"), &read_json),
            "строка 1\nстрока 2"
        );
        let report = load_past_dns_check_report(Some("check.json"), &read_json).expect("итог есть");
        assert!(report.get("domains").is_some());
    }

    #[test]
    fn save_dns_check_results_reports_success_and_failures() {
        let mut saved: Vec<(String, String)> = Vec::new();
        let revealed = std::cell::RefCell::new(Vec::new());
        let plan = save_dns_check_results(
            "C:/tmp/report.txt",
            "текст отчёта",
            "2026-10-12 21:05:00",
            &mut |path, text| {
                saved.push((path.to_string(), text.to_string()));
                Ok(())
            },
            &|folder| revealed.borrow_mut().push(folder.to_string()),
        );
        assert!(plan.success);
        assert_eq!(plan.title, "Сохранено");
        assert_eq!(plan.content, "Результаты сохранены в:\nC:/tmp/report.txt");
        let (path, text) = &saved[0];
        assert_eq!(path, "C:/tmp/report.txt");
        assert_eq!(
            text,
            "DNS CHECK RESULTS\nDate: 2026-10-12 21:05:00\n\
             ============================================================\n\nтекст отчёта"
        );
        assert_eq!(*revealed.borrow(), vec!["C:/tmp".to_string()]);

        let plan = save_dns_check_results("   ", "", "", &mut |_path, _text| Ok(()), &|_folder| ());
        assert!(!plan.success);
        assert_eq!(plan.title, "Ошибка");
        assert_eq!(plan.content, "Не указан путь для сохранения файла.");

        let plan = save_dns_check_results(
            "C:/tmp/report.txt",
            "",
            "",
            &mut |_path, _text| Err("диск занят".to_string()),
            &|_folder| (),
        );
        assert!(!plan.success);
        assert_eq!(plan.content, "Не удалось сохранить файл:\nдиск занят");
    }

    #[test]
    fn old_past_check_files_are_pruned_beyond_the_limit() {
        let names: Vec<String> = (0..45)
            .map(|index| format!("dns_check_2026_{index:02}.json"))
            .collect();
        assert_eq!(
            past_check_files_to_prune(names, PAST_CHECK_FILES_KEPT).len(),
            5
        );
        // Незачем чистить: файлов ещё нет и лимита.
        assert!(past_check_files_to_prune(vec![], PAST_CHECK_FILES_KEPT).is_empty());
        let few: Vec<String> = vec!["a.json".to_string(), "b.json".to_string()];
        assert!(past_check_files_to_prune(few, PAST_CHECK_FILES_KEPT).is_empty());
    }
}
