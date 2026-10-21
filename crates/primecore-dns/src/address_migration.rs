//! Порт `src/dns/address_migration.py` — замена устаревших адресов
//! DNS-провайдеров в настройках сетевых адаптеров.
//!
//! Пользователь когда-то выбрал провайдера (например, Xbox DNS), и Windows
//! запомнила его адреса в ручных настройках адаптера. Когда провайдер меняет
//! адреса, старые перестают работать. При запуске программа находит на
//! адаптерах только адреса из `OUTDATED_DNS_ADDRESS_REPLACEMENTS` и меняет их
//! на новые. Автоматически полученные (DHCP) и любые другие адреса не
//! трогаются.
//!
//! Если провайдер закрылся, замена ведёт на другой сервер того же назначения.
//! Сервер только с шифрованием (обычный DNS у него закрыт) годится в замену
//! лишь там, где Windows умеет DoH: на остальных такие замены пропускаются, и
//! старые адреса остаются как были ([`usable_replacements`]).
//!
//! Сам запуск замены на адаптерах (`migrate_outdated_dns_addresses`) —
//! платформенный слой: Windows-запись DNS (`dns.winapi`) портируется следом.

use std::collections::HashMap;

/// python `_canonical_ip` — адрес в едином виде: у настоящего адреса —
/// сжатая запись, у остального текста — без различия регистров.
#[must_use]
pub fn canonical_ip(value: &str) -> String {
    let text = value.trim();
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    text.to_lowercase()
}

/// python `plan_dns_server_migration` — новый список DNS или None, если менять
/// нечего.
///
/// Порядок и чужие адреса сохраняются, старые адреса заменяются на месте,
/// повторы после замены убираются.
#[must_use]
pub fn plan_dns_server_migration(
    servers: &[String],
    replacements: &HashMap<String, String>,
) -> Option<Vec<String>> {
    let canonical_replacements: HashMap<String, String> = replacements
        .iter()
        .filter(|(old, new)| !old.trim().is_empty() && !new.trim().is_empty())
        .map(|(old, new)| (canonical_ip(old), new.trim().to_string()))
        .collect();
    let current: Vec<String> = servers
        .iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect();
    let mut replaced_any = false;
    let mut result: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for server in current {
        let mut server_text = server;
        if let Some(replacement) = canonical_replacements.get(&canonical_ip(&server_text)) {
            replaced_any = true;
            server_text = replacement.clone();
        }
        let key = canonical_ip(&server_text);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        result.push(server_text);
    }
    replaced_any.then_some(result)
}

/// python `usable_replacements` — замены, которые можно делать на этой
/// Windows.
///
/// Без DoH убирает замены на серверы только с шифрованием: спросить такой
/// сервер система не сможет, и адаптер остался бы без рабочего DNS.
#[must_use]
pub fn usable_replacements(
    replacements: &HashMap<String, String>,
    doh_supported: bool,
) -> HashMap<String, String> {
    let mut usable: HashMap<String, String> = HashMap::new();
    for (old, new) in replacements {
        let found = crate::providers::find_provider_by_address(new);
        if !doh_supported
            && found
                .as_ref()
                .is_some_and(|(_, _, data)| crate::providers::is_encrypted_only(data))
        {
            continue;
        }
        usable.insert(old.clone(), new.clone());
    }
    usable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacements(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(old, new)| ((*old).to_string(), (*new).to_string()))
            .collect()
    }

    #[test]
    fn old_addresses_replaced_in_place() {
        let plan = plan_dns_server_migration(
            &["111.88.96.54".to_string(), "8.8.8.8".to_string()],
            &replacements(&[("111.88.96.54", "192.144.59.14")]),
        )
        .expect("замена была");
        assert_eq!(
            plan,
            vec!["192.144.59.14".to_string(), "8.8.8.8".to_string()]
        );
        // Чужие адреса и порядок сохраняются.
        let plan = plan_dns_server_migration(
            &["9.9.9.9".to_string(), "1.1.1.1".to_string()],
            &replacements(&[]),
        );
        assert_eq!(plan, None, "менять нечего");
        // Пустые и пробельные записи отбрасываются.
        let plan = plan_dns_server_migration(
            &["  ".to_string(), "1.1.1.1".to_string()],
            &replacements(&[("1.1.1.1", "9.9.9.9")]),
        )
        .expect("замена была");
        assert_eq!(plan, vec!["9.9.9.9".to_string()]);
    }

    #[test]
    fn duplicates_removed_after_replacement() {
        // Два разных старых адреса одного сервера → один новый.
        let plan = plan_dns_server_migration(
            &[
                "111.88.96.54".to_string(),
                "87.228.47.200".to_string(),
                "8.8.8.8".to_string(),
            ],
            &replacements(&[
                ("111.88.96.54", "192.144.59.14"),
                ("87.228.47.200", "192.144.59.14"),
            ]),
        )
        .expect("замена была");
        assert_eq!(
            plan,
            vec!["192.144.59.14".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn canonical_form_matters() {
        // Один адрес, разные записи: «::0001» и «::1» — один и тот же.
        let plan = plan_dns_server_migration(
            &["::0001".to_string()],
            &replacements(&[("::1", "2606:4700::1111")]),
        )
        .expect("каноническая форма совпала");
        assert_eq!(plan, vec!["2606:4700::1111".to_string()]);
        // Не адрес — регистр не важен.
        let plan = plan_dns_server_migration(
            &["Custom-Host".to_string()],
            &replacements(&[("custom-host", "9.9.9.9")]),
        )
        .expect("регистр не важен");
        assert_eq!(plan, vec!["9.9.9.9".to_string()]);
    }

    #[test]
    fn encrypted_replacement_needs_doh() {
        let all = replacements(&[
            ("111.88.96.54", "192.144.59.14"),
            ("144.31.82.230", "83.217.211.149"),
        ]);
        // Windows 11: замены можно делать все.
        assert_eq!(usable_replacements(&all, true).len(), 2);
        // Windows 10: замена на сервер только с шифрованием (DNS-AI —
        // encrypted_only в списке) отбрасывается, на обычный сервер остаётся.
        let usable = usable_replacements(&all, false);
        assert_eq!(usable.len(), 1);
        assert!(usable.contains_key("144.31.82.230"));
    }
}
