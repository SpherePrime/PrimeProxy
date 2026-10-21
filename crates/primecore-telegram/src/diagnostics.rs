//! Диагностика Telegram Proxy: адреса проверки и итоговая сводка.
//!
//! Порт чистой части `telegram_proxy/diagnostics/runner.py`. Сами проверки
//! (TCP, TLS, WSS-рукопожатие, SOCKS5-рукопожатие, процесс winws2) — сетевые
//! и платформенные действия: они идут замыканиями и трейтами
//! ([`ProbesIo`]), крейт соединений не открывает. Здесь — таблицы целей,
//! разбор ответов и сборка текста сводки (`_build_summary`).

use std::collections::BTreeMap;

use crate::proxy::route_catalog::relay_addresses;

/// Имя движка zapret, который может обходить блокировку TLS к IP Telegram.
pub const ENGINE_WINWS2: &str = "winws2";

/// Цель прямой проверки: (IP, подпись DC, имя WSS-релея или «—»).
pub const DC_TARGETS: &[(&str, &str, &str)] = &[
    ("149.154.167.220", "WSS relay", "—"),
    ("149.154.167.99", "WSS relay", "—"),
    ("149.154.167.50", "DC2", "kws2"),
    ("149.154.167.41", "DC2", "kws2"),
    ("149.154.167.91", "DC4", "kws4"),
    ("149.154.175.53", "DC1", "—"),
    ("149.154.175.55", "DC1", "—"),
    ("149.154.175.100", "DC3 (→DC1)", "—"),
    ("91.108.56.134", "DC5", "—"),
    ("91.108.56.149", "DC5", "—"),
    ("91.105.192.100", "DC203 CDN", "—"),
    ("149.154.167.151", "DC2 media", "—"),
    ("149.154.167.222", "DC2 media", "—"),
    ("149.154.175.52", "DC1 media", "—"),
    ("91.108.56.102", "DC5 media", "—"),
    ("149.154.175.102", "DC3 media", "—"),
    ("149.154.164.250", "DC4 media", "—"),
];

/// Цель проверки WSS-релея: (IP, домен kwsN, DC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WssProbeTarget {
    pub ip: &'static str,
    pub domain: &'static str,
    pub dc: i32,
}

/// python `WSS_PROBE_TARGETS`: каждое имя kwsN проверяется на адресах входа
/// своего DC — на чужом адресе релей отвечает 302 или молчит.
#[must_use]
pub fn wss_probe_targets() -> Vec<WssProbeTarget> {
    let mut targets = Vec::new();
    for dc in [1, 2, 3, 4, 5, 203] {
        for address in relay_addresses(dc) {
            targets.push(WssProbeTarget {
                ip: address,
                domain: Box::leak(format!("kws{dc}.web.telegram.org").into_boxed_str()),
                dc,
            });
        }
    }
    targets
}

/// python `RELAY_ADDRESS_DCS`: адрес входа → какие DC он обслуживает.
/// Отдаётся упорядоченно по адресу — для стабильного вывода.
#[must_use]
pub fn relay_address_dcs() -> BTreeMap<&'static str, Vec<i32>> {
    let mut mapping: BTreeMap<&'static str, Vec<i32>> = BTreeMap::new();
    for dc in [1, 2, 3, 4, 5, 203] {
        for address in relay_addresses(dc) {
            mapping.entry(address).or_default().push(dc);
        }
    }
    mapping
}

/// Сетевые и платформенные проверки диагностики (python `_test_*`).
///
/// Каждое замыкание отвечает словарём-результатом как python: словарь
/// `serde_json` со статусом, задержками и текстом ошибки.
pub struct ProbesIo<'a> {
    /// python `_test_single_ip` — TCP+TLS до адреса Telegram с SNI
    /// `telegram.org`; строка вида `«IP  DC  123ms   456ms  OK»`.
    pub test_single_ip: &'a dyn Fn(&str, &str) -> String,
    /// python `_test_wss_relay` — WSS-рукопожатие до релея.
    pub test_wss_relay: &'a dyn Fn(&str, &str, i32) -> serde_json::Value,
    /// python `check_relay_reachable` (proxy/routing) — TCP+TLS до входа релея.
    pub check_relay_reachable: &'a dyn Fn(&str, f64) -> crate::proxy::routing::RelayReachability,
    /// python `_test_proxy_liveness` — жив ли локальный прокси.
    pub test_proxy_liveness: &'a dyn Fn(&str, i64) -> serde_json::Value,
    /// python `_test_upstream_proxy` — жив ли внешний SOCKS5; `None` — цели нет.
    pub test_upstream_proxy: &'a dyn Fn() -> Option<serde_json::Value>,
    /// python `_test_sni_vs_ip` — блокировка по SNI или по IP.
    pub test_sni_vs_ip: &'a dyn Fn() -> String,
    /// python `_test_http_port80` — блокируется ли HTTP-транспорт.
    pub test_http_port80: &'a dyn Fn() -> String,
    /// python `_check_winws2_running` — запущен ли движок zapret.
    pub check_winws2_running: &'a dyn Fn() -> bool,
}

/// Число DC из имени («DC2 media» → 2, «DC203 CDN» → 203).
#[must_use]
pub fn dc_number_of(name: &str) -> Option<i32> {
    let digits: String = name
        .strip_prefix("DC")?
        .chars()
        .take_while(|char| char.is_ascii_digit())
        .collect();
    if digits.is_empty() || digits.len() > 2 {
        return None;
    }
    digits.parse().ok()
}

/// Статусы DC по строкам прямых проверок (python-блок `_build_summary`).
#[must_use]
fn dc_status_from_lines(dc_lines: &[String]) -> BTreeMap<String, String> {
    let dc_names_ordered = [
        "DC203 CDN",
        "DC5 media",
        "DC5",
        "DC4 media",
        "DC4",
        "DC3 media",
        "DC3 (→DC1)",
        "DC2 media",
        "DC2",
        "DC1 media",
        "DC1",
    ];
    let mut dc_status: BTreeMap<String, String> = BTreeMap::new();
    for line in dc_lines {
        for dc_name in dc_names_ordered {
            if !line.contains(dc_name) {
                continue;
            }
            if line.trim_end().ends_with("OK") {
                dc_status
                    .entry((*dc_name).to_string())
                    .or_insert_with(|| "OK".to_string());
            } else if line.contains("BLOCKED") || line.contains("TIMEOUT") || line.contains("FAIL")
            {
                dc_status.insert((*dc_name).to_string(), "BLOCKED".to_string());
            }
            break;
        }
    }
    dc_status
}

/// Итоговая сводка диагностики (python `_build_summary`).
///
/// `dc_lines` — строки прямых проверок DC, `wss_results` — результаты
/// `_test_wss_relay`, `proxy_result` — результат `_test_proxy_liveness`.
#[must_use]
pub fn build_summary(
    dc_lines: &[String],
    wss_results: &[serde_json::Value],
    proxy_result: &serde_json::Value,
    winws2_running: bool,
) -> String {
    let dc_status = dc_status_from_lines(dc_lines);
    let blocked = dc_status
        .values()
        .filter(|status| status.as_str() == "BLOCKED")
        .count();
    let ok_count = dc_status
        .values()
        .filter(|status| status.as_str() == "OK")
        .count();

    fn status_of(result: &Value) -> &str {
        result.get("status").and_then(Value::as_str).unwrap_or("")
    }
    let wss_ok_dcs: Vec<i32> = wss_results
        .iter()
        .filter(|result| status_of(result) == "OK")
        .filter_map(|result| result.get("dc").and_then(Value::as_i64).map(|dc| dc as i32))
        .collect();
    let wss_redirect_dcs: Vec<i32> = wss_results
        .iter()
        .filter(|result| status_of(result) == "WS_REDIRECT")
        .filter_map(|result| result.get("dc").and_then(Value::as_i64).map(|dc| dc as i32))
        .collect();
    let relay_ok = !wss_ok_dcs.is_empty();
    let proxy_status = status_of(proxy_result).to_string();
    let proxy_running = proxy_status == "OK";
    let proxy_not_running = proxy_status == "NOT_RUNNING";

    let mut summary: Vec<String> = vec![
        "── Тип блокировки ──".to_string(),
        format!("  Доступно: {ok_count}  |  Заблокировано: {blocked}"),
    ];
    if blocked == 0 && ok_count > 0 {
        summary.push("  Блокировки не обнаружено".to_string());
    } else if blocked > 0 {
        summary.push("  Тип: блокировка TLS к IP Telegram (DPI)".to_string());
        summary.push("  (подробности в секции 'Определение типа блокировки' выше)".to_string());
    }

    summary.push(String::new());
    summary.push("── Статус дата-центров ──".to_string());
    for dc_name in [
        "DC1",
        "DC1 media",
        "DC2",
        "DC2 media",
        "DC3 (→DC1)",
        "DC3 media",
        "DC4",
        "DC4 media",
        "DC5",
        "DC5 media",
        "DC203 CDN",
    ] {
        let direct = dc_status.get(dc_name).map(String::as_str).unwrap_or("—");
        let dc_num = dc_number_of(dc_name);
        let wss_info = if dc_num.is_some_and(|num| wss_ok_dcs.contains(&num)) {
            "WSS relay"
        } else if dc_num.is_some_and(|num| wss_redirect_dcs.contains(&num)) {
            "нет relay"
        } else if dc_name == "DC203 CDN" {
            "TCP (CDN)"
        } else {
            "—"
        };
        let icon = if direct == "OK" {
            "+"
        } else if direct == "BLOCKED" && dc_num.is_some_and(|num| wss_ok_dcs.contains(&num)) {
            "~"
        } else {
            "x"
        };
        summary.push(format!(
            "  [{icon}] {dc_name:<10} напрямую: {direct:<10} прокси: {wss_info}"
        ));
    }

    summary.push(String::new());
    summary.push("── WSS relay ──".to_string());
    if relay_ok {
        let names: Vec<String> = wss_ok_dcs.iter().map(|dc| format!("kws{dc}")).collect();
        summary.push(format!("  Доступен: {}", names.join(", ")));
    } else {
        summary.push("  Недоступен".to_string());
    }
    if !wss_redirect_dcs.is_empty() {
        let names: Vec<String> = wss_redirect_dcs
            .iter()
            .map(|dc| format!("kws{dc}"))
            .collect();
        summary.push(format!("  Редирект (нет relay): {}", names.join(", ")));
    }

    summary.push(String::new());
    summary.push("── Сервисы ──".to_string());
    if proxy_running {
        summary.push("  Прокси: запущен".to_string());
    } else if proxy_not_running {
        summary.push("  Прокси: не запущен".to_string());
    } else {
        let error = proxy_result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("?");
        summary.push(format!("  Прокси: ошибка ({error})"));
    }
    summary.push(format!(
        "  {ENGINE_WINWS2}: {}",
        if winws2_running {
            "запущен"
        } else {
            "не запущен"
        }
    ));

    summary.push(String::new());
    summary.push("── Рекомендации ──".to_string());
    if blocked == 0 && ok_count > 0 {
        summary.push("  Telegram доступен напрямую, прокси не требуется.".to_string());
        return summary.join("\n");
    }

    let mut bypassed_dcs: Vec<String> = Vec::new();
    for (dc_name, status) in &dc_status {
        if status == "BLOCKED" && dc_number_of(dc_name).is_some_and(|num| wss_ok_dcs.contains(&num))
        {
            bypassed_dcs.push(dc_name.clone());
        }
    }
    bypassed_dcs.sort();
    let blocked_no_wss: Vec<String> = dc_status
        .iter()
        .filter(|(dc_name, status)| status.as_str() == "BLOCKED" && !bypassed_dcs.contains(dc_name))
        .map(|(dc_name, _)| dc_name.clone())
        .collect();

    if !bypassed_dcs.is_empty() && relay_ok {
        let names = bypassed_dcs.join(", ");
        if proxy_running {
            summary.push(format!(
                "  [+] {names}: заблокированы напрямую, обходятся через WSS прокси"
            ));
        } else {
            summary.push(format!(
                "  [~] {names}: WSS relay доступен, но прокси не запущен"
            ));
        }
    }

    if !blocked_no_wss.is_empty() {
        let names = blocked_no_wss.join(", ");
        summary.push(format!(
            "  [!] {names}: заблокированы, WSS relay нет — часть контента (эмодзи, стикеры) может не загружаться"
        ));
        if winws2_running {
            summary.push(format!(
                "  [~] {ENGINE_WINWS2} запущен — {names} могут работать через zapret"
            ));
        } else {
            summary.push(format!(
                "  [!] Для {names} запустите {ENGINE_WINWS2}/zapret на главной странице"
            ));
        }
    }

    if proxy_not_running {
        summary.push("  [!] Прокси не запущен — запустите его на этой странице".to_string());
    }

    if !relay_ok && blocked > 0 {
        summary.push(
            "  [x] прямой WSS relay сейчас недоступен — проверьте Telegram на практике".to_string(),
        );
        if !winws2_running {
            summary.push(format!(
                "  [!] Запустите {ENGINE_WINWS2}/zapret или используйте VPN"
            ));
        }
    }

    summary.join("\n")
}

use serde_json::Value;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn probe_target_tables_match_python() {
        assert_eq!(DC_TARGETS.len(), 17);
        assert_eq!(DC_TARGETS[0], ("149.154.167.220", "WSS relay", "—"));
        assert_eq!(DC_TARGETS[10], ("91.105.192.100", "DC203 CDN", "—"));

        let probes = wss_probe_targets();
        // Адреса входа релеев: DC1 и DC3 делят 149.154.174.100 и т. д.
        assert_eq!(
            probes[0],
            WssProbeTarget {
                ip: "149.154.174.100",
                domain: "kws1.web.telegram.org",
                dc: 1
            }
        );
        assert!(probes
            .iter()
            .any(|target| target.ip == "149.154.167.220" && target.dc == 2));
        assert!(probes
            .iter()
            .all(|target| [1, 2, 3, 4, 5, 203].contains(&target.dc)));

        let mapping = relay_address_dcs();
        assert_eq!(mapping.get("149.154.174.100"), Some(&vec![1, 3]));
        assert_eq!(mapping.get("149.154.167.220"), Some(&vec![2, 4]));
        assert_eq!(mapping.get("149.154.170.100"), Some(&vec![5]));
        assert_eq!(mapping.len(), 4);
    }

    #[test]
    fn dc_number_parsing() {
        assert_eq!(dc_number_of("DC2 media"), Some(2));
        // «DC203» из трёх цифр python не берёт — имя узнаётся отдельно.
        assert_eq!(dc_number_of("DC203 CDN"), None);
        assert_eq!(dc_number_of("DC3 (→DC1)"), Some(3));
        assert_eq!(dc_number_of("WSS relay"), None);
        assert_eq!(dc_number_of("DC"), None);
        assert_eq!(dc_number_of("DC1234"), None);
    }

    fn wss_result(dc: i32, status: &str) -> Value {
        json!({"dc": dc, "status": status, "error": Value::Null})
    }

    fn proxy_result(status: &str) -> Value {
        json!({"status": status, "error": "порт закрыт"})
    }

    fn dc_line(name: &str, verdict: &str) -> String {
        format!("  149.154.167.50   {name:<12}  {verdict}")
    }

    #[test]
    fn summary_reports_no_blocking_when_all_ok() {
        let lines: Vec<String> = ["DC1", "DC2", "DC5"]
            .iter()
            .map(|name| dc_line(name, "OK"))
            .collect();
        let wss = [
            wss_result(1, "OK"),
            wss_result(2, "OK"),
            wss_result(5, "OK"),
        ];
        let text = build_summary(&lines, &wss, &proxy_result("OK"), false);

        assert!(text.contains("── Тип блокировки ──"));
        assert!(text.contains("Доступно: 3  |  Заблокировано: 0"));
        assert!(text.contains("Блокировки не обнаружено"));
        assert!(text.contains("Telegram доступен напрямую, прокси не требуется."));
        assert!(text.contains("Прокси: запущен"));
        assert!(text.contains("[+] DC1") || text.contains("Доступен: kws1"));
        assert!(text.contains("winws2: не запущен"));
    }

    #[test]
    fn summary_reports_blocked_dcs_and_wss_bypass() {
        let lines: Vec<String> = [
            dc_line("DC1", "BLOCKED (ssl)"),
            dc_line("DC2", "OK"),
            dc_line("DC5", "TIMEOUT"),
        ]
        .to_vec();
        let wss = [wss_result(1, "OK"), wss_result(5, "WS_REDIRECT")];
        let text = build_summary(&lines, &wss, &proxy_result("NOT_RUNNING"), false);

        assert!(text.contains("Тип: блокировка TLS к IP Telegram (DPI)"));
        // DC1 заблокирован, но обходится WSS; DC5 заблокирован без relay.
        assert!(text.contains("[~] DC1: WSS relay доступен, но прокси не запущен"));
        assert!(text.contains("[!] DC5: заблокированы, WSS relay нет"));
        assert!(text.contains("[!] Прокси не запущен — запустите его на этой странице"));
        assert!(text.contains("Редирект (нет relay): kws5"));
    }

    #[test]
    fn summary_advises_zapret_when_relay_dead() {
        let lines: Vec<String> = [dc_line("DC1", "FAIL")].to_vec();
        let text = build_summary(&lines, &[], &proxy_result("OK"), true);
        assert!(text.contains("[x] прямой WSS relay сейчас недоступен"));
        assert!(text.contains("запущен — DC1 могут работать через zapret"));

        let text = build_summary(&lines, &[], &proxy_result("OK"), false);
        assert!(text.contains("[!] Для DC1 запустите winws2/zapret на главной странице"));
        assert!(text.contains("[!] Запустите winws2/zapret или используйте VPN"));
    }

    #[test]
    fn summary_matches_python_reference_text() {
        // Эталон собран вызовом python `_build_summary` на тех же данных.
        let lines: Vec<String> = [
            "  149.154.167.50   DC1          BLOCKED (ssl)",
            "  149.154.167.50   DC2          OK",
            "  149.154.167.50   DC5          TIMEOUT",
        ]
        .iter()
        .map(|line| (*line).to_string())
        .collect();
        let wss = [wss_result(1, "OK"), wss_result(5, "WS_REDIRECT")];
        let text = build_summary(&lines, &wss, &proxy_result("NOT_RUNNING"), false);
        let expected = [
            "\u{2500}\u{2500} Тип блокировки \u{2500}\u{2500}",
            "  Доступно: 1  |  Заблокировано: 2",
            "  Тип: блокировка TLS к IP Telegram (DPI)",
            "  (подробности в секции 'Определение типа блокировки' выше)",
            "",
            "\u{2500}\u{2500} Статус дата-центров \u{2500}\u{2500}",
            "  [~] DC1        напрямую: BLOCKED    прокси: WSS relay",
            "  [x] DC1 media  напрямую: \u{2014}          прокси: WSS relay",
            "  [+] DC2        напрямую: OK         прокси: \u{2014}",
            "  [x] DC2 media  напрямую: \u{2014}          прокси: \u{2014}",
            "  [x] DC3 (\u{2192}DC1) напрямую: \u{2014}          прокси: \u{2014}",
            "  [x] DC3 media  напрямую: \u{2014}          прокси: \u{2014}",
            "  [x] DC4        напрямую: \u{2014}          прокси: \u{2014}",
            "  [x] DC4 media  напрямую: \u{2014}          прокси: \u{2014}",
            "  [x] DC5        напрямую: BLOCKED    прокси: нет relay",
            "  [x] DC5 media  напрямую: \u{2014}          прокси: нет relay",
            "  [x] DC203 CDN  напрямую: \u{2014}          прокси: TCP (CDN)",
            "",
            "\u{2500}\u{2500} WSS relay \u{2500}\u{2500}",
            "  Доступен: kws1",
            "  Редирект (нет relay): kws5",
            "",
            "\u{2500}\u{2500} Сервисы \u{2500}\u{2500}",
            "  Прокси: не запущен",
            "  winws2: не запущен",
            "",
            "\u{2500}\u{2500} Рекомендации \u{2500}\u{2500}",
            "  [~] DC1: WSS relay доступен, но прокси не запущен",
            "  [!] DC5: заблокированы, WSS relay нет \u{2014} часть контента (эмодзи, стикеры) может не загружаться",
            "  [!] Для DC5 запустите winws2/zapret на главной странице",
            "  [!] Прокси не запущен \u{2014} запустите его на этой странице",
        ]
        .join("\n");
        assert_eq!(text, expected);
    }

    #[test]
    fn summary_shows_proxy_error_when_unknown_status() {
        let lines: Vec<String> = [dc_line("DC1", "OK")].to_vec();
        let text = build_summary(
            &lines,
            &[wss_result(1, "OK")],
            &json!({"status": "ERROR"}),
            false,
        );
        assert!(text.contains("Прокси: ошибка (?)"));
    }

    #[test]
    fn probes_io_runs_closures() {
        // Все проверки — замыкания: сводка строится без сети.
        let io = ProbesIo {
            test_single_ip: &|ip, dc| format!("{ip} {dc} OK"),
            test_wss_relay: &|ip, domain, dc| json!({"ip": ip, "domain": domain, "dc": dc, "status": "OK"}),
            check_relay_reachable: &|_ip, _timeout| crate::proxy::routing::RelayReachability {
                reachable: true,
                error: String::new(),
                ms: 12.3,
            },
            test_proxy_liveness: &|host, port| json!({"host": host, "port": port, "status": "OK"}),
            test_upstream_proxy: &|| None,
            test_sni_vs_ip: &|| "TLS с чужим SNI: OK".to_string(),
            test_http_port80: &|| "HTTP 80 → OK".to_string(),
            check_winws2_running: &|| false,
        };
        assert_eq!(
            (io.test_single_ip)("149.154.167.50", "DC2"),
            "149.154.167.50 DC2 OK"
        );
        let relay = (io.test_wss_relay)("149.154.174.100", "kws1.web.telegram.org", 1);
        assert_eq!(relay["dc"], 1);
        assert!((io.check_relay_reachable)("149.154.174.100", 5.0).reachable);
        assert_eq!((io.test_proxy_liveness)("127.0.0.1", 1353)["status"], "OK");
        assert!((io.test_upstream_proxy)().is_none());
        assert!((io.test_sni_vs_ip)().contains("SNI"));
        assert!((io.test_http_port80)().contains("80"));
        assert!(!(io.check_winws2_running)());
    }
}
