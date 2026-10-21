//! Порт `src/dns/page_plans.py` — чистые решения страницы DNS: без Qt и без
//! вызовов Windows.
//!
//! Переводы строк python берёт из `app/ui_texts.py`
//! (`from app.ui_texts import tr as tr_catalog`). Модуля переводов в крейте
//! нет, поэтому функции принимают замыкание [`TrFn`] — `(ключ, язык) ->
//! текст` — и передают ему те же ключи, что и python в
//! `tr_catalog(key, language=language, default=...)`. [`catalog_tr`] —
//! встроенный справочник русских текстов каталога для этой страницы: тесты
//! сверяются с python 1:1 по русским фразам, а платформенный слой позже
//! подставит свой переводчик.
//!
//! Адаптеры — [`crate::adapters::DnsAdapter`], список серверов —
//! [`serde_json::Map`] из [`crate::providers`] (дословный python-словарь,
//! порядок групп сохранён). python-функции принимают ключевые аргументы —
//! в Rust порядок позиционный, он совпадает с порядком в python-сигнатурах.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::adapters::DnsAdapter;

/// python `from app.ui_texts import tr as tr_catalog` — перевод по ключу и
/// языку: `tr(key, language)`.
pub type TrFn<'a> = &'a dyn Fn(&str, &str) -> String;

/// Встроенный справочник русских текстов каталога `app/ui_texts.py` для
/// ключей страницы «Настройка DNS» — замена `tr_catalog` там, где интерфейса
/// нет (тесты, платформенный слой). Неизвестный ключ возвращается самим
/// собой, как в python без найденного значения и без `default`.
///
/// Значения — из каталога `ui_texts.py`, не из python-дефолтов `page_plans`:
/// у существующих ключей побеждает каталог (например, кнопка совета —
/// «Применить Quad9», а не дефолт «Установить рекомендуемый DNS»).
#[must_use]
pub fn catalog_tr(key: &str, _language: &str) -> String {
    match key {
        "page.network.error.title" => "Ошибка",
        "page.network.error.flush_cache_failed" => "Не удалось очистить кэш: {error}",
        "page.network.isp_dns.infobar.title" => "DNS от провайдера",
        "page.network.isp_dns.infobar.content" => {
            "У вас установлен DNS от провайдера (получен автоматически через DHCP). \
             Провайдерский DNS может подменять ответы и мешать обходу блокировок.\n\n\
             Можно вручную применить публичный DNS Quad9 или выбрать другой DNS из списка ниже."
        }
        "page.network.isp_dns.infobar.action" => "Применить Quad9",
        "page.network.isp_dns.infobar.dismiss" => "Нет, спасибо",
        _ => key,
    }
    .to_string()
}

/// python `NetworkProviderDnsPlan` — какие адреса сервера прописать.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProviderDnsPlan {
    pub valid: bool,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub log_level: Option<String>,
    pub log_message: String,
}

/// python `NetworkDnsApplyResultPlan` — итог применения DNS к адаптерам.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkDnsApplyResultPlan {
    pub log_level: Option<String>,
    pub log_message: String,
    pub adapter_count: usize,
    pub success_count: usize,
    pub error: String,
    /// DNS встал, но шифрование до сервера не доходит
    /// (DnsCommandResult.doh_closed).
    pub doh_closed: bool,
}

/// python `NetworkFlushDnsCacheResultPlan` — итог очистки кэша DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkFlushDnsCacheResultPlan {
    pub success: bool,
    pub title: String,
    pub content: String,
}

/// python `NetworkIspDnsWarningPlan` — совет про DNS провайдера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIspDnsWarningPlan {
    pub should_show: bool,
    pub title: String,
    pub content: String,
    pub action_text: String,
    pub dismiss_text: String,
}

/// python `normalize_dns_list` — строки адресов из значения "ipv4"/"ipv6":
/// python принимает строку с любыми разделителями или список, здесь значение
/// приходит из JSON-данных сервера. Повторы убираются, порядок сохраняется.
#[must_use]
pub fn normalize_dns_list(value: &Value) -> Vec<String> {
    let items: Vec<String> = match value {
        Value::String(text) => text
            .replace(',', " ")
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        Value::Array(items) => items.iter().map(item_to_string).collect(),
        _ => Vec::new(),
    };
    let mut result: Vec<String> = Vec::new();
    for item in items {
        let trimmed = item.trim().to_string();
        if trimmed.is_empty() || result.contains(&trimmed) {
            continue;
        }
        result.push(trimmed);
    }
    result
}

/// python `str(item)` для элемента списка адресов.
fn item_to_string(item: &Value) -> String {
    match item {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

// ── применение ────────────────────────────────────────────────────────────

/// python `build_provider_dns_plan` — какие адреса сервера прописать.
/// IPv6-адреса пишутся всегда: без IPv6 они не мешают.
#[must_use]
pub fn build_provider_dns_plan(
    name: &str,
    data: &Value,
    ipv6_available: bool,
) -> NetworkProviderDnsPlan {
    let empty = Value::Array(Vec::new());
    let ipv4 = normalize_dns_list(data.get("ipv4").unwrap_or(&empty));
    let ipv6 = normalize_dns_list(data.get("ipv6").unwrap_or(&empty));
    if ipv4.is_empty() && (ipv6.is_empty() || !ipv6_available) {
        return NetworkProviderDnsPlan {
            valid: false,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            log_level: Some("WARNING".to_string()),
            log_message: format!("DNS: у провайдера {name} нет DNS адресов для текущей системы"),
        };
    }
    NetworkProviderDnsPlan {
        valid: true,
        ipv4,
        ipv6,
        log_level: None,
        log_message: String::new(),
    }
}

/// python `_apply_result` — общий итог применения: успех только когда
/// отмечены адаптеры и на всех всё записалось.
#[must_use]
fn apply_result(
    what: &str,
    adapter_count: usize,
    success_count: usize,
    error: &str,
) -> NetworkDnsApplyResultPlan {
    let done = adapter_count > 0 && success_count == adapter_count;
    NetworkDnsApplyResultPlan {
        log_level: if done { Some("INFO".to_string()) } else { None },
        log_message: if done {
            format!("DNS: {what} применён к адаптерам: {success_count}")
        } else {
            String::new()
        },
        adapter_count,
        success_count,
        error: error.to_string(),
        doh_closed: false,
    }
}

/// python `build_auto_dns_apply_result_plan` — итог возврата «Автоматически».
#[must_use]
pub fn build_auto_dns_apply_result_plan(
    adapter_count: usize,
    success_count: usize,
    error: &str,
) -> NetworkDnsApplyResultPlan {
    apply_result("автоматический DNS", adapter_count, success_count, error)
}

/// python `build_provider_dns_apply_result_plan` — итог применения сервера.
#[must_use]
pub fn build_provider_dns_apply_result_plan(
    name: &str,
    adapter_count: usize,
    success_count: usize,
    ipv6: &[String],
    error: &str,
    doh_closed: bool,
) -> NetworkDnsApplyResultPlan {
    let what = if ipv6.is_empty() {
        name.to_string()
    } else {
        format!("{name} (IPv4+IPv6)")
    };
    let mut plan = apply_result(&what, adapter_count, success_count, error);
    plan.doh_closed = doh_closed;
    plan
}

/// python `build_flush_dns_cache_result_plan` — итог очистки кэша DNS.
/// Успех молчит, провал называет причину. Язык учтён замыканием [`TrFn`],
/// как python-параметр `language` у `tr_catalog`.
#[must_use]
pub fn build_flush_dns_cache_result_plan(
    tr: TrFn<'_>,
    success: bool,
    message: &str,
    language: &str,
) -> NetworkFlushDnsCacheResultPlan {
    if success {
        return NetworkFlushDnsCacheResultPlan {
            success: true,
            title: String::new(),
            content: String::new(),
        };
    }
    NetworkFlushDnsCacheResultPlan {
        success: false,
        title: tr("page.network.error.title", language),
        content: tr("page.network.error.flush_cache_failed", language).replace("{error}", message),
    }
}

// ── совет про DNS провайдера ──────────────────────────────────────────────

/// python `should_show_isp_dns_warning` — показываем один раз, если на всех
/// подключённых адаптерах DNS автоматический.
#[must_use]
pub fn should_show_isp_dns_warning(adapters: &[DnsAdapter], warning_already_shown: bool) -> bool {
    if warning_already_shown {
        return false;
    }
    let connected: Vec<&DnsAdapter> = adapters
        .iter()
        .filter(|adapter| adapter.connected)
        .collect();
    !connected.is_empty() && connected.iter().all(|adapter| adapter.is_automatic())
}

/// python `build_isp_dns_warning_plan` — тексты совета про DNS провайдера.
#[must_use]
pub fn build_isp_dns_warning_plan(
    tr: TrFn<'_>,
    adapters: &[DnsAdapter],
    warning_already_shown: bool,
    language: &str,
) -> NetworkIspDnsWarningPlan {
    NetworkIspDnsWarningPlan {
        should_show: should_show_isp_dns_warning(adapters, warning_already_shown),
        title: tr("page.network.isp_dns.infobar.title", language),
        content: tr("page.network.isp_dns.infobar.content", language),
        action_text: tr("page.network.isp_dns.infobar.action", language),
        dismiss_text: tr("page.network.isp_dns.infobar.dismiss", language),
    }
}

// ── текущий DNS отмеченных адаптеров ──────────────────────────────────────

/// python `"none"` — адаптеры не отмечены.
pub const KIND_NONE: &str = "none";
/// python `"auto"` — DNS получается автоматически.
pub const KIND_AUTO: &str = "auto";
/// python `"provider"` — один из известных серверов.
pub const KIND_PROVIDER: &str = "provider";
/// python `"custom"` — адреса, которых нет в списке.
pub const KIND_CUSTOM: &str = "custom";
/// python `"mixed"` — на отмеченных адаптерах стоят разные DNS.
pub const KIND_MIXED: &str = "mixed";

/// python `CurrentDnsPlan` — что сейчас стоит на отмеченных адаптерах.
///
/// `kind`: [`KIND_NONE`] — адаптеры не отмечены; [`KIND_AUTO`] — DNS
/// получается автоматически (ipv4/ipv6 — адреса, выданные роутером);
/// [`KIND_PROVIDER`] — один из известных серверов (provider — его имя);
/// [`KIND_CUSTOM`] — адреса, которых нет в списке; [`KIND_MIXED`] — на
/// отмеченных адаптерах стоят разные DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurrentDnsPlan {
    pub kind: String,
    pub provider: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

/// python `LOCAL_PROXY_ADDRESSES` — адрес встроенного шифрованного DNS.
pub const LOCAL_PROXY_ADDRESSES: [&str; 2] = ["127.0.0.1", "::1"];

/// python `find_provider_for_dns` — имя сервера из списка, чей основной адрес
/// стоит первым на адаптере.
///
/// Адрес 127.0.0.1 — встроенный шифрованный DNS: у всех его режимов адрес
/// один, поэтому плитку называет режим работающего движка
/// (`local_proxy_mode`). В режиме DoH движок работает на сервер обычной
/// плитки — её называет `local_proxy_server`. Движок не работает — это
/// чей-то чужой локальный DNS.
#[must_use]
pub fn find_provider_for_dns(
    providers: &Map<String, Value>,
    ipv4: &[String],
    ipv6: &[String],
    local_proxy_mode: &str,
    local_proxy_server: &str,
) -> Option<String> {
    let first: &str = if !ipv4.is_empty() {
        &ipv4[0]
    } else if !ipv6.is_empty() {
        &ipv6[0]
    } else {
        ""
    };
    if LOCAL_PROXY_ADDRESSES.contains(&first) {
        if !local_proxy_server.is_empty() {
            for group in providers.values() {
                for name in group.as_object().expect("группа — словарь").keys() {
                    if name.as_str() == local_proxy_server {
                        return Some(name.clone());
                    }
                }
            }
            return None;
        }
        for group in providers.values() {
            for (name, data) in group.as_object().expect("группа — словарь") {
                if !local_proxy_mode.is_empty()
                    && data.get("local_proxy").and_then(Value::as_str) == Some(local_proxy_mode)
                {
                    return Some(name.clone());
                }
            }
        }
        return None;
    }
    for group in providers.values() {
        for (name, data) in group.as_object().expect("группа — словарь") {
            let proxy = data
                .get("local_proxy")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !proxy.is_empty() {
                continue;
            }
            let empty = Value::Array(Vec::new());
            let provider_v4 = normalize_dns_list(data.get("ipv4").unwrap_or(&empty));
            let provider_v6 = normalize_dns_list(data.get("ipv6").unwrap_or(&empty));
            if !ipv4.is_empty() && !provider_v4.is_empty() && provider_v4[0] == ipv4[0] {
                return Some(name.clone());
            }
            if ipv4.is_empty()
                && !ipv6.is_empty()
                && !provider_v6.is_empty()
                && provider_v6[0] == ipv6[0]
            {
                return Some(name.clone());
            }
        }
    }
    None
}

/// python `describe_adapter_dns` — что стоит на одном адаптере.
#[must_use]
pub fn describe_adapter_dns(
    adapter: &DnsAdapter,
    providers: &Map<String, Value>,
    local_proxy_mode: &str,
    local_proxy_server: &str,
) -> CurrentDnsPlan {
    if adapter.is_automatic() {
        return CurrentDnsPlan {
            kind: KIND_AUTO.to_string(),
            provider: None,
            ipv4: adapter.auto_ipv4.clone(),
            ipv6: adapter.auto_ipv6.clone(),
        };
    }
    let provider = find_provider_for_dns(
        providers,
        &adapter.static_ipv4,
        &adapter.static_ipv6,
        local_proxy_mode,
        local_proxy_server,
    );
    CurrentDnsPlan {
        kind: if provider.is_some() {
            KIND_PROVIDER
        } else {
            KIND_CUSTOM
        }
        .to_string(),
        provider,
        ipv4: adapter.static_ipv4.clone(),
        ipv6: adapter.static_ipv6.clone(),
    }
}

/// python `LEFTOVER_IPV6` — утечка по IPv6 с адаптера с выбранным сервером.
pub const LEFTOVER_IPV6: &str = "ipv6";
/// python `LEFTOVER_ADAPTER` — свой DNS на подключённом, но не отмеченном
/// адаптере.
pub const LEFTOVER_ADAPTER: &str = "adapter";

/// python `DnsLeftover` — дорога, по которой DNS-запросы идут мимо выбранного
/// сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLeftover {
    /// [`LEFTOVER_IPV6`] | [`LEFTOVER_ADAPTER`].
    pub kind: String,
    pub adapter: String,
    pub addresses: Vec<String>,
}

/// python `_real_dns` — адреса DNS без заглушек Windows: fec0:0:0:ffff::1…3
/// она показывает там, где IPv6-DNS нет вовсе.
#[must_use]
fn real_dns(addresses: &[String]) -> Vec<String> {
    addresses
        .iter()
        .filter(|item| !item.to_lowercase().starts_with("fec0:"))
        .cloned()
        .collect()
}

/// python `find_dns_leftovers` — что осталось мимо выбранного сервера после
/// его установки. Пусто — выбранный сервер один на всех дорогах.
///
/// Windows спрашивает все DNS-серверы, которые у неё есть, и берёт первый
/// ответ:
///
/// - у адаптера с выбранным сервером по IPv4 может остаться автоматический
///   DNS по IPv6 (от роутера или провайдера) — так бывает, когда у выбранного
///   сервера адресов IPv6 нет; Windows спрашивает его наравне с выбранным;
/// - на подключённом, но не отмеченном адаптере остаётся его собственный DNS.
///
/// Пока сервер не выбран («Автоматически»), утечки нет: выбирать не из чего.
#[must_use]
pub fn find_dns_leftovers(adapters: &[DnsAdapter], selected_guids: &[String]) -> Vec<DnsLeftover> {
    let selected: HashSet<&str> = selected_guids.iter().map(String::as_str).collect();
    let chosen: Vec<&DnsAdapter> = adapters
        .iter()
        .filter(|item| {
            selected.contains(item.guid.as_str())
                && item.connected
                && (!item.static_ipv4.is_empty() || !item.static_ipv6.is_empty())
        })
        .collect();
    if chosen.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<DnsLeftover> = Vec::new();
    for adapter in &chosen {
        let automatic_v6 = real_dns(&adapter.auto_ipv6);
        if !adapter.static_ipv4.is_empty()
            && adapter.static_ipv6.is_empty()
            && !automatic_v6.is_empty()
        {
            found.push(DnsLeftover {
                kind: LEFTOVER_IPV6.to_string(),
                adapter: adapter.name.clone(),
                addresses: automatic_v6,
            });
        }
    }
    let primary: HashSet<&str> = chosen
        .iter()
        .map(|adapter| {
            if !adapter.static_ipv4.is_empty() {
                adapter.static_ipv4[0].as_str()
            } else {
                adapter.static_ipv6[0].as_str()
            }
        })
        .collect();
    for adapter in adapters {
        if selected.contains(adapter.guid.as_str()) || !adapter.connected {
            continue;
        }
        let mut static_both: Vec<String> = adapter.static_ipv4.clone();
        static_both.extend(adapter.static_ipv6.iter().cloned());
        let mut own = real_dns(&static_both);
        if own.is_empty() {
            let mut auto_both: Vec<String> = adapter.auto_ipv4.clone();
            auto_both.extend(adapter.auto_ipv6.iter().cloned());
            own = real_dns(&auto_both);
        }
        if !own.is_empty() && !primary.contains(own[0].as_str()) {
            found.push(DnsLeftover {
                kind: LEFTOVER_ADAPTER.to_string(),
                adapter: adapter.name.clone(),
                addresses: own,
            });
        }
    }
    found
}

/// python `build_current_dns_plan` — сводка по всем отмеченным адаптерам:
/// один DNS на всех или «разные».
#[must_use]
pub fn build_current_dns_plan(
    adapters: &[DnsAdapter],
    providers: &Map<String, Value>,
    local_proxy_mode: &str,
    local_proxy_server: &str,
) -> CurrentDnsPlan {
    let plans: Vec<CurrentDnsPlan> = adapters
        .iter()
        .map(|adapter| {
            describe_adapter_dns(adapter, providers, local_proxy_mode, local_proxy_server)
        })
        .collect();
    let Some(first) = plans.first() else {
        return CurrentDnsPlan {
            kind: KIND_NONE.to_string(),
            ..CurrentDnsPlan::default()
        };
    };
    let same = |plan: &CurrentDnsPlan| -> bool {
        if plan.kind != first.kind {
            return false;
        }
        if plan.kind == KIND_AUTO {
            return true;
        }
        plan.provider == first.provider
            && plan.ipv4.first() == first.ipv4.first()
            && plan.ipv6.first() == first.ipv6.first()
    };
    if plans[1..].iter().all(same) {
        first.clone()
    } else {
        CurrentDnsPlan {
            kind: KIND_MIXED.to_string(),
            ..CurrentDnsPlan::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ETH: &str = "{00000000-0000-0000-0000-000000000009}";
    const WIFI: &str = "{00000000-0000-0000-0000-000000000012}";
    const SPARE: &str = "{00000000-0000-0000-0000-000000000020}";

    /// python-тест `test_dns_page.py`: адаптеры страницы по умолчанию.
    fn adapter(guid: &str, name: &str, kind: &str, connected: bool, internet: bool) -> DnsAdapter {
        DnsAdapter {
            guid: guid.to_string(),
            name: name.to_string(),
            description: String::new(),
            kind: kind.to_string(),
            connected,
            internet,
            ..DnsAdapter::default()
        }
    }

    fn ethernet() -> DnsAdapter {
        let mut item = adapter(ETH, "Ethernet", "ethernet", true, true);
        item.static_ipv4 = vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()];
        item.static_ipv6 = vec!["2606:4700:4700::1111".to_string()];
        item
    }

    fn wifi() -> DnsAdapter {
        let mut item = adapter(WIFI, "Wi-Fi", "wifi", true, false);
        item.auto_ipv4 = vec!["192.168.1.1".to_string()];
        item
    }

    /// Отключённый адаптер виден, но не отмечен.
    fn spare() -> DnsAdapter {
        adapter(SPARE, "Ethernet 2", "ethernet", false, false)
    }

    /// python `data.get(key)` со списком адресов — как есть, без нормализации.
    fn string_list(value: Option<&Value>) -> Vec<String> {
        value
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

    /// Полный каталог серверов — встроенный JSON из `providers`.
    fn catalog_map() -> Map<String, Value> {
        serde_json::from_str::<Value>(crate::providers::CATALOG_JSON)
            .expect("встроенный список разобран")
            .as_object()
            .expect("каталог — словарь")
            .clone()
    }

    fn with_static(base: &DnsAdapter, v4: &[&str], v6: &[&str]) -> DnsAdapter {
        let mut item = base.clone();
        item.static_ipv4 = v4.iter().map(|text| (*text).to_string()).collect();
        item.static_ipv6 = v6.iter().map(|text| (*text).to_string()).collect();
        item
    }

    #[test]
    fn normalize_dns_list_cleans_and_deduplicates() {
        // python: строка с запятыми и пробелами, список, прочее — пусто.
        assert_eq!(
            normalize_dns_list(&json!("8.8.8.8,  1.1.1.1 8.8.8.8,")),
            vec!["8.8.8.8", "1.1.1.1"]
        );
        assert_eq!(
            normalize_dns_list(&json!(["9.9.9.9", " 9.9.9.9 ", "2620:fe::fe"])),
            vec!["9.9.9.9", "2620:fe::fe"]
        );
        assert!(normalize_dns_list(&Value::Null).is_empty());
        assert!(normalize_dns_list(&json!({"ipv4": []})).is_empty());
    }

    // python-тест `test_dns_ipv6_provider_apply.py`.

    #[test]
    fn provider_dns_plan_accepts_ipv6_only_when_ipv6_is_available() {
        let plan = build_provider_dns_plan(
            "Мой IPv6 DNS",
            &json!({"ipv4": [], "ipv6": ["2001:4860:4860::8888"]}),
            true,
        );
        assert!(plan.valid);
        assert!(plan.ipv4.is_empty());
        assert_eq!(plan.ipv6, vec!["2001:4860:4860::8888"]);
    }

    #[test]
    fn provider_dns_plan_rejects_ipv6_only_when_ipv6_is_unavailable() {
        let plan = build_provider_dns_plan(
            "Мой IPv6 DNS",
            &json!({"ipv4": [], "ipv6": ["2001:4860:4860::8888"]}),
            false,
        );
        assert!(!plan.valid);
        assert!(plan.log_message.contains("нет DNS"));
    }

    #[test]
    fn ipv6_addresses_are_kept_even_without_ipv6_route() {
        let plan = build_provider_dns_plan(
            "Cloudflare",
            &json!({"ipv4": ["1.1.1.1"], "ipv6": ["2606:4700:4700::1111"]}),
            false,
        );
        assert!(plan.valid);
        assert_eq!(plan.ipv6, vec!["2606:4700:4700::1111"]);
    }

    // python-тест `test_dns_page.py::test_partial_apply_and_errors_are_reported`
    // (построение плана; показ инфобара — Qt, не переносится).

    #[test]
    fn provider_plan_warns_without_addresses_for_current_system() {
        let invalid =
            build_provider_dns_plan("X", &json!({"ipv4": [], "ipv6": ["2a00::1"]}), false);
        assert!(!invalid.valid);
        assert!(invalid.ipv4.is_empty() && invalid.ipv6.is_empty());
        assert_eq!(invalid.log_level.as_deref(), Some("WARNING"));
        assert_eq!(
            invalid.log_message,
            "DNS: у провайдера X нет DNS адресов для текущей системы"
        );
    }

    #[test]
    fn apply_result_plans_report_done_partial_and_doh_closed() {
        let partial = build_auto_dns_apply_result_plan(2, 1, "«Wi-Fi»: ошибка Windows 5");
        assert_eq!(partial.log_level, None);
        assert_eq!(partial.log_message, "");
        assert_eq!(partial.adapter_count, 2);
        assert_eq!(partial.success_count, 1);
        assert_eq!(partial.error, "«Wi-Fi»: ошибка Windows 5");
        assert!(!partial.doh_closed);

        let idle = build_auto_dns_apply_result_plan(0, 0, "");
        assert_eq!(idle.log_level, None);
        assert_eq!(idle.log_message, "");

        let done = build_provider_dns_apply_result_plan("Quad9", 1, 1, &[], "", false);
        assert_eq!(done.log_level.as_deref(), Some("INFO"));
        assert_eq!(done.log_message, "DNS: Quad9 применён к адаптерам: 1");
        assert!(!done.doh_closed);

        let refused = build_provider_dns_apply_result_plan("Google DNS", 2, 0, &[], "", false);
        assert_eq!(refused.log_level, None);
        assert_eq!(refused.log_message, "");

        let with_ipv6 = build_provider_dns_apply_result_plan(
            "Quad9",
            1,
            1,
            &["2620:fe::fe".to_string()],
            "",
            false,
        );
        assert_eq!(
            with_ipv6.log_message,
            "DNS: Quad9 (IPv4+IPv6) применён к адаптерам: 1"
        );

        let plain = build_provider_dns_apply_result_plan("AdGuard", 1, 1, &[], "", true);
        assert!(plain.doh_closed);
        assert_eq!(plain.log_message, "DNS: AdGuard применён к адаптерам: 1");
    }

    #[test]
    fn flush_cache_reports_result() {
        let ok = build_flush_dns_cache_result_plan(&catalog_tr, true, "", "ru");
        assert!(ok.success);
        assert!(ok.title.is_empty());
        assert!(ok.content.is_empty());

        let failed =
            build_flush_dns_cache_result_plan(&catalog_tr, false, "нет прав администратора", "ru");
        assert!(!failed.success);
        assert_eq!(failed.title, "Ошибка");
        assert_eq!(
            failed.content,
            "Не удалось очистить кэш: нет прав администратора"
        );
    }

    // python-тест `test_dns_page.py::test_isp_warning_looks_only_at_connected_adapters`.

    #[test]
    fn isp_warning_looks_only_at_connected_adapters() {
        assert!(should_show_isp_dns_warning(&[wifi(), spare()], false));
        assert!(!should_show_isp_dns_warning(&[wifi()], true));
        assert!(!should_show_isp_dns_warning(&[ethernet(), wifi()], false));
        assert!(!should_show_isp_dns_warning(&[spare()], false));
    }

    #[test]
    fn isp_warning_plan_uses_catalog_texts() {
        let plan = build_isp_dns_warning_plan(&catalog_tr, &[wifi()], false, "ru");
        assert!(plan.should_show);
        assert_eq!(plan.title, "DNS от провайдера");
        assert_eq!(
            plan.content,
            "У вас установлен DNS от провайдера (получен автоматически через DHCP). \
             Провайдерский DNS может подменять ответы и мешать обходу блокировок.\n\n\
             Можно вручную применить публичный DNS Quad9 или выбрать другой DNS из списка ниже."
        );
        assert_eq!(plan.action_text, "Применить Quad9");
        assert_eq!(plan.dismiss_text, "Нет, спасибо");
    }

    // python-тест `test_dns_page.py::test_current_dns_plan_matches_providers`.

    #[test]
    fn current_dns_plan_matches_providers() {
        let providers = json!({"G": {"Only6": {"ipv4": [], "ipv6": ["2a00::1"]}, "Q": {"ipv4": ["9.9.9.9"], "ipv6": []}}});
        let providers = providers.as_object().expect("словарь");
        let base = adapter("{A}", "A", "ethernet", true, false);
        let plan = |first: (&[&str], &[&str]), second: (&[&str], &[&str])| -> CurrentDnsPlan {
            build_current_dns_plan(
                &[
                    with_static(&base, first.0, first.1),
                    with_static(&base, second.0, second.1),
                ],
                providers,
                "",
                "",
            )
        };

        let only6 = plan((&[], &["2a00::1"]), (&[], &["2a00::1"]));
        assert_eq!(only6.provider.as_deref(), Some("Only6"));

        let quad9 = plan((&["9.9.9.9", "1.2.3.4"], &[]), (&["9.9.9.9"], &[]));
        assert_eq!(quad9.provider.as_deref(), Some("Q"));

        assert_eq!(
            plan((&["10.0.0.1"], &[]), (&["10.0.0.1"], &[])).kind,
            KIND_CUSTOM
        );
        assert_eq!(plan((&["10.0.0.1"], &[]), (&[], &[])).kind, KIND_MIXED);
        assert_eq!(plan((&[], &[]), (&[], &[])).kind, KIND_AUTO);
        assert_eq!(
            build_current_dns_plan(&[], providers, "", "").kind,
            KIND_NONE
        );
    }

    // python-тест
    // `test_dns_page.py::test_dns_that_stays_beside_the_chosen_server_is_named`.

    #[test]
    fn dns_that_stays_beside_the_chosen_server_is_named() {
        // У выбранного сервера нет IPv6, а роутер раздаёт свой IPv6-DNS:
        // Windows спрашивает и его.
        let mut leaky = ethernet();
        leaky.static_ipv4 = vec!["83.220.169.155".to_string()];
        leaky.static_ipv6 = Vec::new();
        leaky.auto_ipv6 = vec!["fe80::1".to_string(), "fec0:0:0:ffff::1".to_string()];
        let other = wifi();

        let found =
            find_dns_leftovers(&[leaky.clone(), other.clone(), spare()], &[ETH.to_string()]);
        assert_eq!(
            found,
            vec![
                DnsLeftover {
                    kind: LEFTOVER_IPV6.to_string(),
                    adapter: "Ethernet".to_string(),
                    addresses: vec!["fe80::1".to_string()],
                },
                DnsLeftover {
                    kind: LEFTOVER_ADAPTER.to_string(),
                    adapter: "Wi-Fi".to_string(),
                    addresses: vec!["192.168.1.1".to_string()],
                },
            ]
        );

        // Заглушки Windows fec0:… — не DNS; отключённый адаптер не в счёт;
        // пока сервер не выбран, утечки нет.
        let mut only_stub = leaky.clone();
        only_stub.auto_ipv6 = vec![
            "fec0:0:0:ffff::1".to_string(),
            "fec0:0:0:ffff::2".to_string(),
        ];
        assert!(find_dns_leftovers(&[only_stub, spare()], &[ETH.to_string()]).is_empty());
        assert!(find_dns_leftovers(&[wifi()], &[WIFI.to_string()]).is_empty());

        // Шифрованный DNS с адресом ::1 закрывает IPv6; тот же сервер на
        // втором адаптере — не утечка.
        let mut closed = leaky;
        closed.static_ipv4 = vec!["127.0.0.1".to_string()];
        closed.static_ipv6 = vec!["::1".to_string()];
        let mut twin = wifi();
        twin.static_ipv4 = vec!["127.0.0.1".to_string()];
        twin.auto_ipv4 = Vec::new();
        assert!(find_dns_leftovers(&[closed, twin], &[ETH.to_string()]).is_empty());
    }

    // python-тест
    // `test_dns_providers_catalog.py::test_every_server_is_recognized_by_its_primary_address`.

    #[test]
    fn every_server_is_recognized_by_its_primary_address() {
        let providers = catalog_map();
        for (_group, name, data) in crate::providers::iter_providers() {
            let mode = data
                .get("local_proxy")
                .and_then(Value::as_str)
                .unwrap_or("");
            let ipv4 = string_list(data.get("ipv4"));
            let ipv6 = string_list(data.get("ipv6"));
            assert_eq!(
                find_provider_for_dns(&providers, &ipv4, &ipv6, mode, "").as_deref(),
                Some(name.as_str()),
                "сервер {name} не опознаётся по основному адресу"
            );
        }
    }

    // python-тест
    // `test_dns_providers_catalog.py::test_encrypted_modes_share_one_local_address…`
    // (часть про `find_provider_for_dns`).

    #[test]
    fn encrypted_modes_share_one_local_address() {
        let providers = catalog_map();
        // Без работающего движка 127.0.0.1 — не наш режим.
        assert_eq!(
            find_provider_for_dns(
                &providers,
                &["127.0.0.1".to_string()],
                &["::1".to_string()],
                "",
                ""
            ),
            None
        );
        assert_eq!(
            find_provider_for_dns(&providers, &[], &["::1".to_string()], "odoh", "").as_deref(),
            Some("ODoH")
        );
    }
}
