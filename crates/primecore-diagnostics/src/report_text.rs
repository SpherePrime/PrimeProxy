//! Порт `src/diagnostics/report_text.py` — слова отчёта BlockCheck.
//!
//! Проверка собирает факты в `run_context.Probe`. Здесь из них получаются:
//! строки журнала (`probe_lines`), запись о цели для экрана и файла
//! (`target_report`), строки и записи разделов. В сеть модуль не ходит и ничего
//! не решает: выводы уже сделаны, здесь им подбираются слова.
//!
//! Постепенно: сначала вещательные знания, что не зависят от непортированных
//! вердиктов (sentence, IP-списки, иконки, шаги); строки цели (`target_report`),
//! сводки разделов (`section_report`) и итог (`services_report`) дописываются,
//! когда портированы их исходники (freeze_check, verdict по голосам).

use crate::outside_check::{OUTSIDE_DOWN, OUTSIDE_UP};
use crate::quic_probe::{QUIC_BLOCKED_BY_NAME, QUIC_OK, QUIC_SILENT};
use crate::run_context::Probe;
use crate::{block_kind, cert_owner, limits};
use crate::telegram_check::DcResult;
use crate::verdict::{DnsState, Level, ReachState, describe_reach};

/// Молчание по QUIC — не поломка: сервер может его не поддерживать.
pub fn quic_icon(code: &str) -> &'static str {
    match code {
        QUIC_OK => "✅",
        QUIC_BLOCKED_BY_NAME => "❌",
        QUIC_SILENT => "ℹ️",
        _ => "――",
    }
}

/// Короткие названия шагов для строки «сколько шёл каждый шаг».
/// python `STAGE_TITLES`.
pub fn stage_title(name: &str) -> String {
    match name {
        "dns" => "адрес".to_string(),
        "reach" => "соединение".to_string(),
        "cause" => "причина".to_string(),
        "volume" => "объём".to_string(),
        "roads" => "дороги".to_string(),
        _ => name.to_string(),
    }
}

/// python `stages_text(stages)` — «соединение 6 с, причина 3 с» — только части
/// длиннее секунды, от долгих к коротким.
pub fn stages_text(stages: &std::collections::BTreeMap<String, f64>) -> String {
    let mut parts: Vec<(f64, String)> = stages
        .iter()
        .filter(|(_name, value)| **value >= 1.0)
        .map(|(name, value)| (*value, name.clone()))
        .collect();
    parts.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    parts
        .iter()
        .map(|(value, name)| format!("{} {} с", stage_title(name), value.round() as i64))
        .collect::<Vec<_>>()
        .join(", ")
}

/// python `LEVEL_ICON`.
pub fn level_icon(level: Level) -> &'static str {
    match level {
        Level::Ok => "✅",
        Level::Warn => "⚠️",
        Level::Fail => "❌",
        Level::Unknown => "❔",
    }
}

/// python `DNS_ICON`.
pub fn dns_icon(state: DnsState) -> &'static str {
    match state {
        DnsState::Ok => "✅",
        DnsState::Spoofed => "❌",
        DnsState::Local => "ℹ️",
        DnsState::Unknown => "❔",
    }
}

/// python `SOURCE_NOTE` — откуда взят адрес, к которому ходили.
pub fn source_note(source: &str) -> &'static str {
    match source {
        limits::SOURCE_HOSTS => ", адрес из файла hosts",
        limits::SOURCE_REFERENCE => ", адрес по DNS-over-HTTPS",
        _ => "",
    }
}

/// python `ips_text(ips, limit)` — «1.2.3.4, 5.6.7.8 и ещё 2» или «—».
pub fn ips_text(ips: &[String], limit: usize) -> String {
    if ips.is_empty() {
        return "—".to_string();
    }
    if ips.len() > limit {
        format!("{} и ещё {}", ips[..limit].join(", "), ips.len() - limit)
    } else {
        ips.join(", ")
    }
}

/// python `sentence(text)` — первая буква заглавной.
pub fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// python `timed_out_line(deadline)`.
pub fn timed_out_line(deadline: f64) -> String {
    format!("⚠️ Часть проверок не уложилась в {:.0} с и была прервана — их результат неизвестен.", deadline)
}

/// python `fail_text(probe)` — почему адрес не открылся, одной фразой.
pub fn fail_text(probe: &Probe) -> String {
    if let Some(volume) = probe.volume.as_ref() {
        if volume.code == crate::volume_probe::VOLUME_CUT {
            return format!("{} — так провайдер обрывает загрузку", volume.text);
        }
    }
    if probe.reach_state == ReachState::Cert {
        if let Some(cert) = probe.cert.as_ref() {
            return cert.text.clone();
        }
    }
    describe_reach(probe.reach.as_ref(), limits::HTTPS_TIMEOUT)
}

/// python `reach_text(probe)` — одна строка: открывается ли адрес и почему нет.
pub fn reach_text(probe: &Probe) -> String {
    let source = source_note(&probe.reach_source);
    let result = probe.reach.as_ref();
    if probe.reach_state == ReachState::Ok {
        if let Some(result) = result {
            let tls = if result
                .tls_version
                .is_empty()
            {
                String::new()
            } else {
                format!(", {}", result.tls_version.replace("TLSv", "TLS "))
            };
            if result.ip.contains(':') {
                return format!(
                    "открывается по IPv6, по IPv4 — нет ({:.0} мс{}, {})",
                    result.elapsed_ms, tls, result.ip
                );
            }
            let mut stale = String::new();
            if probe.hosts_stale {
                let what = match probe.cert.as_ref() {
                    Some(cert) => cert.text.clone(),
                    None => "адрес из файла hosts не работает, запись в нём устарела".to_string(),
                };
                stale = format!(" — {what}; браузер пойдёт по этой записи и сайт не откроет");
            }
            let mut again = if probe.rechecked == crate::run_context::RECHECK_OPENED {
                " — со второй проверки, поодиночке: первый сбой дала нагрузка самой проверки".to_string()
            } else {
                String::new()
            };
            if !probe.unstable.is_empty() {
                again = format!(" — но через раз: {}", probe.unstable);
            }
            return format!(
                "открывается ({:.0} мс{}, {}{}){}{}",
                result.elapsed_ms, tls, result.ip, source, stale, again
            );
        }
    }
    let text = fail_text(probe);
    let Some(result) = result else { return text };
    if result.ip.is_empty() {
        return text;
    }
    let addresses: std::collections::HashSet<&str> =
        probe.tried.iter().map(|(ip, _kind)| ip.as_str()).collect();
    let tries = if addresses.len() > 1 {
        format!(", не ответил ни один из {} адресов", addresses.len())
    } else if probe.attempts > 1 {
        format!(", попыток: {}", probe.attempts)
    } else {
        String::new()
    };
    let ipv6 = if probe.ipv6_result.is_some() { ", по IPv6 тоже не открылся" } else { "" };
    let again = if probe.rechecked == crate::run_context::RECHECK_SAME {
        ", повторная проверка поодиночке дала то же"
    } else {
        ""
    };
    format!("{text} ({}{}{}{}{})", result.ip, source, tries, ipv6, again)
}

/// python `dns_detail(probe)` — что ответили адресом сайта.
pub fn dns_detail(probe: &Probe) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !probe.hosts_ips.is_empty() {
        parts.push(format!("hosts: {}", ips_text(&probe.hosts_ips, 3)));
    }
    if !probe.dns.ips.is_empty() {
        let flaky = if probe.dns_nxdomain > 0 {
            format!(" (а {} из {} раз — «сайта нет»)", probe.dns_nxdomain, limits::DNS_ATTEMPTS)
        } else {
            String::new()
        };
        parts.push(format!("DNS системы: {}{}", ips_text(&probe.dns.ips, 3), flaky));
    } else {
        parts.push(format!("DNS системы: нет адреса ({})", probe.dns.detail));
    }
    if !probe.reference_ips.is_empty() {
        parts.push(format!("эталон: {}", ips_text(&probe.reference_ips, 3)));
    } else if !probe.reference_ok {
        parts.push("эталон: недоступен".to_string());
    }
    parts.join(" · ")
}

/// python `dns_lines(probe, indent)`.
pub fn dns_lines(probe: &Probe, indent: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(judgement) = probe.judgement.as_ref() {
        lines.push(format!("{indent}{} DNS: {}", dns_icon(judgement.state), judgement.reason));
    }
    lines.push(format!("{indent}   {}", dns_detail(probe)));
    lines
}

/// Что ответил сервер за рубежом.
fn outside_text(outside: &str) -> &'static str {
    match outside {
        OUTSIDE_UP => "открывается — значит, закрыт он именно на вашей линии",
        OUTSIDE_DOWN => "тоже не открывается — сайт не работает сам",
        _ => "",
    }
}

/// python `probe_lines(probe, full)` — строки журнала про сайт.
pub fn probe_lines(probe: &Probe, full: bool) -> Vec<String> {
    let title = format!("{} — {}", probe.host, probe.target.purpose);
    if !full {
        let mut lines = vec![title];
        if !probe.discovery_note.is_empty() {
            lines.push(format!("  ℹ️ {}", probe.discovery_note));
        }
        lines.extend(dns_lines(probe, "  "));
        return lines;
    }
    let mut icon = if probe.reach_state == ReachState::Ok { "✅" } else { "❌" };
    if probe.reach_state == ReachState::Unknown {
        icon = "❔";
    }
    if (probe.hosts_stale || !probe.unstable.is_empty()) && probe.reach_state == ReachState::Ok {
        // Проверка сайт открыла, а браузер по записи в hosts — не откроет.
        icon = "⚠️";
    }
    let mut lines = vec![format!("{icon} {title}: {}", reach_text(probe))];
    let kind = probe.kind();
    if !kind.is_empty() {
        lines.push(format!("   🏷 Вид блокировки: {}", block_kind::kind_info(&kind).map(|info| info.title).unwrap_or_default()));
    }
    if let Some(cause) = probe.cause.as_ref() {
        lines.push(format!("   🔎 {}", sentence(&cause.text)));
    }
    if let Some(volume) = probe.volume.as_ref() {
        if volume.code != crate::volume_probe::VOLUME_CUT {
            let volume_icon = if volume.code == crate::volume_probe::VOLUME_OK { "✅" } else { "ℹ️" };
            lines.push(format!("   {volume_icon} Обрыв после 16 КБ: {}", volume.text));
        }
    }
    if let Some(quic) = probe.quic.as_ref() {
        lines.push(format!("   {} QUIC (UDP 443): {}", quic_icon(&quic.code), quic.text));
    }
    if !probe.discovery_note.is_empty() {
        lines.push(format!("   ℹ️ {}", probe.discovery_note));
    }
    if !probe.outside.is_empty() {
        lines.push(format!(
            "   🌍 С сервера Zapret DNS в Нидерландах: {}",
            outside_text(&probe.outside)
        ));
    }
    lines.extend(dns_lines(probe, "   "));
    lines
}

/// python `short_text(probe)`.
pub fn short_text(probe: &Probe) -> String {
    if probe.reach_state != ReachState::Ok {
        return fail_text(probe);
    }
    if probe
        .reach
        .as_ref()
        .map(|result| result.ip.contains(':'))
        .unwrap_or_default()
    {
        return "открывается только по IPv6".to_string();
    }
    "открывается".to_string()
}

/// python `telegram_text(item)`.
pub fn telegram_text(item: &DcResult) -> String {
    match item.connected {
        None => "проверку прервали".to_string(),
        Some(true) => {
            let took = if item.ms.unwrap_or(0.0) < 1.0 {
                "меньше чем за 1 мс".to_string()
            } else {
                format!("за {:.0} мс", item.ms.unwrap_or(0.0))
            };
            format!("соединение {took}") + if item.attempts > 1 { " (со второй попытки)" } else { "" }
        }
        Some(false) => format!("не соединился, попыток: {}", item.attempts),
    }
}

/// python `telegram_state(item)`.
pub fn telegram_state(item: &DcResult) -> String {
    match item.connected {
        None => "unknown".to_string(),
        Some(true) => "ok".to_string(),
        Some(false) => "fail".to_string(),
    }
}

/// python `summary_lines(...)` — раздел «Итог» журнала: проблемы с советами,
/// что открывается и сколько шла проверка.
pub fn summary_lines(
    problems: &[crate::problems::Problem],
    working: &[String],
    timed_out: bool,
    deadline: f64,
    elapsed: f64,
) -> Vec<String> {
    let mut lines = vec![String::new(), "━━━━━━━━ 📊 Итог ━━━━━━━━".to_string()];
    if timed_out {
        lines.push(timed_out_line(deadline));
    }
    for item in problems {
        lines.push(format!("{} {}", level_icon(item.level), item.text));
        for advice in &item.advice {
            lines.push(format!("   👉 {advice}"));
        }
    }
    if !working.is_empty() {
        lines.push(format!("✅ Открываются: {}", working.join(", ")));
    }
    lines.push(format!("Проверка заняла {elapsed:.1} с."));
    lines
}

/// python `_STATUS_BY_LEVEL`.
pub fn status_by_level(level: Level) -> &'static str {
    match level {
        Level::Ok => "Открывается",
        Level::Warn => "Есть проблемы",
        Level::Fail => "Не открывается",
        Level::Unknown => "Не удалось проверить",
    }
}

/// python `_STATUS_BY_CERT`.
pub fn status_by_cert(code: &str) -> &'static str {
    match code {
        cert_owner::CERT_ANTIVIRUS => "Сертификат подменяет антивирус",
        cert_owner::CERT_DEBUG_PROXY => "Сертификат подменяет прокси-отладчик",
        cert_owner::CERT_STATE => "Сертификат государственного центра",
        cert_owner::CERT_HOSTS => "Адрес из hosts ведёт не туда",
        cert_owner::CERT_OTHER_SITE => "Отвечает другой сайт",
        cert_owner::CERT_SELF_SIGNED => "Самоподписанный сертификат",
        cert_owner::CERT_UNKNOWN_ISSUER => "Сертификат от неизвестного центра",
        _ => "Чужой сертификат",
    }
}

pub const HINT_QUIC: &str =
    "QUIC — быстрый способ соединения поверх UDP: им браузер открывает YouTube и многие крупные сайты. \
     Если он закрыт, браузер сам переходит на обычное соединение.";
pub const HINT_DNS: &str =
    "DNS — справочная, которая по имени сайта выдаёт его адрес. Провайдер может подменять её ответы.";

/// python `_CAUSE_WORDS`.
pub fn cause_word(code: &str) -> &'static str {
    match code {
        "by_name" => "блокировка по имени",
        "name_whitelist" => "проходят только разрешённые имена",
        "by_address" => "закрыт адрес",
        "stub_page" => "страница провайдера",
        "address_closed" => "адрес закрыт",
        "address_silent" => "адрес молчит",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_pieces() {
        assert_eq!(sentence("это пример"), "Это пример");
        assert_eq!(sentence(""), "");
        assert_eq!(ips_text(&[], 3), "—");
        let ips: Vec<String> = (0..5).map(|i| format!("{i}{i}{i}{i}.0.0")).collect();
        assert_eq!(ips_text(&ips, 3), "0000.0.0, 1111.0.0, 2222.0.0 и ещё 2");
        assert_eq!(
            timed_out_line(90.0),
            "⚠️ Часть проверок не уложилась в 90 с и была прервана — их результат неизвестен."
        );
        assert_eq!(level_icon(Level::Warn), "⚠️");
        assert_eq!(dns_icon(DnsState::Spoofed), "❌");
        assert_eq!(quic_icon(QUIC_SILENT), "ℹ️");
        assert_eq!(source_note(limits::SOURCE_HOSTS), ", адрес из файла hosts");
        assert_eq!(outside_text(OUTSIDE_UP), "открывается — значит, закрыт он именно на вашей линии");
        assert_eq!(status_by_level(Level::Fail), "Не открывается");
        assert_eq!(status_by_cert(cert_owner::CERT_OTHER_SITE), "Отвечает другой сайт");
        assert_eq!(cause_word("stub_page"), "страница провайдера");
    }

    #[test]
    fn stages() {
        let mut stages = std::collections::BTreeMap::new();
        stages.insert("reach".to_string(), 6.2);
        stages.insert("cause".to_string(), 3.9);
        stages.insert("dns".to_string(), 0.4);
        assert_eq!(stages_text(&stages), "соединение 6 с, причина 4 с");
    }

    #[test]
    fn telegram_pieces() {
        let mut item = DcResult::default();
        assert_eq!(telegram_text(&item), "проверку прервали");
        item.connected = Some(true);
        item.ms = Some(0.4);
        assert_eq!(telegram_text(&item), "соединение меньше чем за 1 мс");
        item.ms = Some(12.0);
        assert_eq!(telegram_text(&item), "соединение за 12 мс");
        item.attempts = 2;
        assert_eq!(telegram_text(&item), "соединение за 12 мс (со второй попытки)");
        item.connected = Some(false);
        assert_eq!(telegram_text(&item), "не соединился, попыток: 2");
        assert_eq!(telegram_state(&item), "fail");
    }
}
