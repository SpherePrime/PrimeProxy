//! Порт `src/dns/dns_providers.py` — список DNS-провайдеров для страницы.
//!
//! Значок ("icon") рисует профиль «Редактора hosts»; кроме имён Font Awesome
//! ("fa5s.*", "fa5b.*") подходят фирменные логотипы "simple:<имя>:<буквы>".
//! У серверов из раздела «Для ИИ» значок и цвет те же, что у одноимённого
//! DNS-профиля: один сервер — один значок во всей программе.
//!
//! "doh" — адрес шифрованного DNS поверх HTTPS, "dot" — имя сервера для
//! шифрованного DNS поверх TLS (порт 853): по этому имени проверяется его
//! сертификат. "dot" указан только там, где сервер действительно отвечает
//! по этому способу (проверено запросом 2026-10-07).
//!
//! "encrypted_only": true — сервер принимает только шифрованные запросы
//! (DoH, DoT), а обычный DNS на порту 53 у него закрыт намеренно (проверено
//! 2026-10-08). Спрашивать такой сервер сама умеет только Windows 11.
//!
//! "dnssec": true — сервер проверяет подписи DNSSEC.
//!
//! "status" — пометка состояния сервера в России (плитка показывает её
//! цветом): [`STATUS_BLOCKED`] — обычные запросы блокируются или
//! перехватываются по дороге; [`STATUS_AT_RISK`] — пока работает, но уже
//! попадал под ограничения. Пометка только предупреждает.
//!
//! Группа «Шифрованные» — не серверы, а режимы встроенного движка
//! dnscrypt-proxy ([`crate::local_proxy_catalog`]): ключ "local_proxy"
//! называет режим, а адрес у всех один — 127.0.0.1. Выбор такой плитки
//! сначала запускает движок и только потом прописывает адаптеру 127.0.0.1.
//!
//! Основные адреса (первый в "ipv4") не должны повторяться: по нему
//! программа узнаёт, какой сервер стоит на адаптере. Это и остальные правила
//! списка проверяет [`catalog_problems`].
//!
//! Данные списка — дословный python-словарь, встроенный JSON-текстом
//! (порядок групп и плиток сохраняется, как в python).

use std::sync::OnceLock;

use serde_json::{Map, Value};

pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_AT_RISK: &str = "at_risk";
pub const STATUSES: [&str; 2] = [STATUS_BLOCKED, STATUS_AT_RISK];

pub const LOCAL_PROXY_GROUP: &str = "Шифрованные";

/// python `DNS_PROVIDERS` — встроенный JSON с сохранённым порядком.
fn catalog() -> &'static Map<String, Value> {
    static CATALOG: OnceLock<Map<String, Value>> = OnceLock::new();
    CATALOG.get_or_init(|| serde_json::from_str(CATALOG_JSON).expect("встроенный список разобран"))
}

/// python `iter_providers` — (группа, название, данные) каждого сервера.
pub fn iter_providers() -> Vec<(String, String, Value)> {
    let mut result = Vec::new();
    for (group, providers) in catalog() {
        for (name, data) in providers.as_object().expect("группа — словарь") {
            result.push((group.clone(), name.clone(), data.clone()));
        }
    }
    result
}

/// python `network_providers` — список без режимов встроенного движка:
/// только настоящие серверы в сети.
#[must_use]
pub fn network_providers() -> Map<String, Value> {
    let mut result = Map::new();
    for (group, providers) in catalog() {
        let kept: Map<String, Value> = providers
            .as_object()
            .expect("группа — словарь")
            .iter()
            .filter(|(_name, data)| data.get("local_proxy").is_none_or(Value::is_null))
            .map(|(name, data)| (name.clone(), data.clone()))
            .collect();
        if !kept.is_empty() {
            result.insert(group.clone(), Value::Object(kept));
        }
    }
    result
}

/// python `is_encrypted_only` — сервер не отвечает на обычный DNS: спросить
/// его можно только шифрованным запросом.
#[must_use]
pub fn is_encrypted_only(data: &Value) -> bool {
    data.get("encrypted_only")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// python `proxy_upstreams` — серверы плитки для режима DoH встроенного
/// посредника; пусто — нет шаблона DoH или адреса IPv4.
#[must_use]
pub fn proxy_upstreams(data: &Value) -> Vec<crate::local_proxy_catalog::Upstream> {
    let doh = data.get("doh").and_then(Value::as_str).unwrap_or("");
    let empty: Vec<String> = Vec::new();
    let addresses: Vec<String> = data
        .get("ipv4")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or(empty);
    let dnssec = data.get("dnssec").and_then(Value::as_bool).unwrap_or(false);
    crate::local_proxy_catalog::doh_upstreams(doh, &addresses, dnssec)
}

/// python `proxy_mode_for` — режим встроенного шифрованного DNS, через
/// который надо ставить эту плитку. Пусто — ставить адресами.
///
/// У плитки-режима ("local_proxy") он есть всегда. Обычный сервер с
/// шифрованным адресом ("doh") идёт через посредника только там, где Windows
/// сама шифровать DNS не умеет (Windows 10): в Windows 11 запросы к нему
/// шифрует сама система, а без посредника в Windows 10 они шли бы открытым
/// текстом. Так плитка одна, а путь она выбирает сама.
#[must_use]
pub fn proxy_mode_for(data: &Value, doh_supported: bool) -> String {
    let mode = data
        .get("local_proxy")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !mode.is_empty() {
        return mode;
    }
    if doh_supported || proxy_upstreams(data).is_empty() {
        return String::new();
    }
    crate::local_proxy_catalog::MODE_DOH.to_string()
}

/// python `find_provider_by_address` — (группа, название, данные) сервера,
/// которому принадлежит адрес (IPv4 или IPv6).
#[must_use]
pub fn find_provider_by_address(address: &str) -> Option<(String, String, Value)> {
    let wanted = address.trim().to_lowercase();
    if wanted.is_empty() {
        return None;
    }
    for (group, name, data) in iter_providers() {
        if data.get("local_proxy").is_some_and(|item| !item.is_null()) {
            continue;
        }
        for key in ["ipv4", "ipv6"] {
            for item in data
                .get(key)
                .and_then(Value::as_array)
                .unwrap_or(&Vec::new())
            {
                if item.as_str().unwrap_or("").trim().to_lowercase() == wanted {
                    return Some((group, name, data));
                }
            }
        }
    }
    None
}

/// python `doh_templates` — {адрес сервера: шаблон DoH} для всех серверов
/// списка (IPv4 и IPv6).
///
/// Windows 11 по этим шаблонам сама шифрует DNS-запросы к известным
/// серверам, а при недоступности DoH откатывается на обычный DNS.
#[must_use]
pub fn doh_templates() -> Vec<(String, String)> {
    let mut templates: Vec<(String, String)> = Vec::new();
    let mut insert = |address: &str, template: &str| {
        let address = address.trim().to_string();
        if !templates.iter().any(|(known, _)| *known == address) {
            templates.push((address, template.to_string()));
        }
    };
    for providers in catalog().values() {
        for data in providers.as_object().expect("группа — словарь").values() {
            let template = data.get("doh").and_then(Value::as_str).unwrap_or("").trim();
            if template.is_empty() {
                continue;
            }
            for key in ["ipv4", "ipv6"] {
                for item in data
                    .get(key)
                    .and_then(Value::as_array)
                    .unwrap_or(&Vec::new())
                {
                    if let Some(address) = item.as_str() {
                        insert(address, template);
                    }
                }
            }
        }
    }
    templates
}

/// python `OUTDATED_DNS_ADDRESS_REPLACEMENTS` — старые адреса DNS и их замены.
///
/// Если пользователь когда-то выбрал этот DNS и адрес остался в настройках
/// сетевого адаптера, программа при запуске сама меняет его на новый.
/// При каждой смене адресов провайдера добавлять сюда пару «старый → новый».
///
/// Замена на сервер только с шифрованием ("encrypted_only") делается лишь
/// там, где Windows умеет DoH: иначе человек остался бы без DNS вовсе
/// (dns.address_migration.usable_replacements).
pub fn outdated_dns_address_replacements() -> &'static [(&'static str, &'static str)] {
    &[
        // Xbox DNS закрыл сервисы ИИ и отдаёт на них пустой адрес (2026-10-08).
        // Все его адреса — действующие, «v2» и старые — программа переводит
        // на DNS-AI: он открывает те же сайты.
        ("111.88.96.54", "192.144.59.14"),
        ("111.88.96.55", "186.246.49.127"),
        ("111.88.96.50", "192.144.59.14"),
        ("111.88.96.51", "186.246.49.127"),
        ("87.228.47.200", "192.144.59.14"),
        ("87.228.47.201", "186.246.49.127"),
        ("176.99.11.77", "192.144.59.14"),
        ("80.78.247.254", "186.246.49.127"),
        ("2a00:ab00:1233:26::50", "2a0d:8480:0:67c::14"),
        ("2a00:ab00:1233:26::51", "2a0a:2b41:0:500d::53"),
        // Первый адрес Zapret DNS закрыли в России по IP (2026-10-09):
        // сервер переехал.
        ("144.31.82.230", "83.217.211.149"),
        ("2a01:ecc0:500:8e::2", "2a03:afc0:9::235d"),
    ]
}

/// python `catalog_problems` — нарушения правил списка; у исправного — пусто.
///
/// Проверяет то, от чего зависит работа программы: адреса — настоящие IPv4 и
/// IPv6 без повторов, основной адрес не занят другим сервером, шифрованный
/// DoH задан адресом https (у сервера только с шифрованием он обязателен),
/// пометка состояния — из известных.
#[must_use]
pub fn catalog_problems() -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut owners: Vec<(String, String)> = Vec::new();
    let mut modes: Vec<String> = Vec::new();
    for (group, name, data) in iter_providers() {
        if names.contains(&name) {
            problems.push(format!("{name}: название повторяется"));
        }
        names.push(name.clone());
        let mode = data
            .get("local_proxy")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !mode.is_empty() || group == LOCAL_PROXY_GROUP {
            // Режим встроенного движка: адрес у всех один — этот компьютер.
            if !crate::local_proxy_catalog::MODES.contains(&mode.as_str())
                || modes.contains(&mode)
                || group != LOCAL_PROXY_GROUP
            {
                problems.push(format!(
                    "{name}: неверный или повторный режим шифрованного DNS «{mode}»"
                ));
            }
            modes.push(mode);
            let ipv4: Vec<String> = strings_of(&data, "ipv4");
            let ipv6: Vec<String> = strings_of(&data, "ipv6");
            if ipv4 != vec!["127.0.0.1".to_string()] || ipv6 != vec!["::1".to_string()] {
                problems.push(format!(
                    "{name}: у режима шифрованного DNS адреса должны быть 127.0.0.1 и ::1"
                ));
            }
            if data.get("doh").is_some_and(|item| !item.is_null())
                || data.get("dot").is_some_and(|item| !item.is_null())
                || data.get("status").is_some_and(|item| !item.is_null())
            {
                problems.push(format!(
                    "{name}: у режима шифрованного DNS не бывает DoH, DoT и пометки состояния"
                ));
            }
            if desc_or_icon_empty(&data) {
                problems.push(format!("{name}: нет пояснения или значка"));
            }
            continue;
        }
        let ipv4 = strings_of(&data, "ipv4");
        let ipv6 = strings_of(&data, "ipv6");
        if ipv4.is_empty() {
            problems.push(format!("{name}: нет адреса IPv4"));
        }
        for (version, addresses) in [(4, &ipv4), (6, &ipv6)] {
            let mut seen: Vec<&String> = Vec::new();
            for address in addresses {
                if seen.contains(&address) {
                    problems.push(format!("{name}: адрес IPv{version} записан дважды"));
                }
                seen.push(address);
                if !matches_version(address, version) {
                    problems.push(format!("{name}: «{address}» — не адрес IPv{version}"));
                } else if let Some((_, owner)) = owners.iter().find(|(known, _)| known == address) {
                    problems.push(format!("{name}: адрес {address} уже у сервера {owner}"));
                } else {
                    owners.push((address.clone(), name.clone()));
                }
            }
        }
        let doh = data.get("doh").and_then(Value::as_str).unwrap_or("");
        if !doh.is_empty() && !doh.starts_with("https://") {
            problems.push(format!("{name}: адрес DoH должен начинаться с https://"));
        }
        let dot = data.get("dot").and_then(Value::as_str).unwrap_or("");
        if !dot.is_empty() && (dot.contains('/') || dot.contains(':')) {
            problems.push(format!("{name}: в «dot» нужно только имя сервера"));
        }
        if is_encrypted_only(&data) && doh.is_empty() {
            problems.push(format!(
                "{name}: сервер только с шифрованием должен иметь адрес DoH"
            ));
        }
        let status = data.get("status").and_then(Value::as_str).unwrap_or("");
        if !status.is_empty() && !STATUSES.contains(&status) {
            problems.push(format!("{name}: неизвестная пометка состояния «{status}»"));
        }
        if desc_or_icon_empty(&data) {
            problems.push(format!("{name}: нет пояснения или значка"));
        }
    }
    problems
}

fn strings_of(data: &Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// python `ipaddress.ip_address(address).version == version`.
#[must_use]
pub fn matches_version(address: &str, version: u8) -> bool {
    match version {
        4 => crate::local_proxy_catalog::is_ipv4(address),
        6 => is_ipv6(address),
        _ => false,
    }
}

/// Настоящий адрес IPv6 (python `ip_address(address).version == 6`):
/// группы по 1–4 шестнадцатеричных знака, всего до 8, «::» не больше одного
/// (без сжатия адрес должен быть полным), встроенный IPv4 в хвосте разрешён
/// Настоящий адрес IPv6 (python `ip_address(address).version == 6`): группы
/// по 1–4 шестнадцатеричных знака, всего до 8, «::» не больше одного и не
/// тройное (без сжатия адрес должен быть полным), встроенный IPv4 только в
/// самом конце и считается за две группы. Зона («fe80::1%eth0») не
/// разбирается — адресов с зоной в списках не бывает.
#[must_use]
pub fn is_ipv6(text: &str) -> bool {
    let body = match text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner,
        None => text,
    };
    if !body.contains(':') || body.is_empty() {
        return false;
    }
    // «::» не больше одного и не «:::».
    if body.contains(":::") || body.match_indices("::").count() > 1 {
        return false;
    }
    let compressed = body.contains("::");
    let (head, tail) = match body.split_once("::") {
        Some((head, tail)) => (head, tail),
        None => (body, ""),
    };
    let mut total = 0usize;
    for (side, is_head) in [(head, true), (tail, false)] {
        if side.is_empty() {
            continue;
        }
        let parts: Vec<&str> = side.split(':').collect();
        for (index, group) in parts.iter().enumerate() {
            // Последняя группа всего адреса (IPv4-хвост бывает только там).
            let is_last_overall =
                if is_head { tail.is_empty() } else { true } && index + 1 == parts.len();
            if group.contains('.') {
                if !is_last_overall || !crate::local_proxy_catalog::is_ipv4(group) {
                    return false;
                }
                total += 2;
                continue;
            }
            if group.is_empty() || group.len() > 4 || !group.chars().all(|c| c.is_ascii_hexdigit())
            {
                return false;
            }
            total += 1;
        }
    }
    if compressed {
        total < 8
    } else {
        total == 8
    }
}

fn desc_or_icon_empty(data: &Value) -> bool {
    ["desc", "icon"].iter().any(|key| {
        data.get(*key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .is_empty()
    })
}

/// Встроенный список — дословный перенос python-словаря (ensure_ascii=False).
pub const CATALOG_JSON: &str = "{\"Шифрованные\": {\"DNSCrypt\": {\"ipv4\": [\"127.0.0.1\"], \"ipv6\": [\"::1\"], \"desc\": \"Шифрует запросы\", \"icon\": \"fa5s.key\", \"color\": \"#22d3ee\", \"dnssec\": true, \"local_proxy\": \"dnscrypt\"}, \"DNSCrypt анонимный\": {\"ipv4\": [\"127.0.0.1\"], \"ipv6\": [\"::1\"], \"desc\": \"Скрывает ваш адрес\", \"icon\": \"fa5s.user-secret\", \"color\": \"#a3e635\", \"dnssec\": true, \"local_proxy\": \"anonymized\"}, \"ODoH\": {\"ipv4\": [\"127.0.0.1\"], \"ipv6\": [\"::1\"], \"desc\": \"Через HTTPS, пробный\", \"icon\": \"fa5s.mask\", \"color\": \"#f472b6\", \"dnssec\": true, \"local_proxy\": \"odoh\"}}, \"Популярные\": {\"Cloudflare\": {\"ipv4\": [\"1.1.1.1\", \"1.0.0.1\"], \"ipv6\": [\"2606:4700:4700::1111\", \"2606:4700:4700::1001\"], \"desc\": \"Быстрый и приватный\", \"icon\": \"simple:cloudflare:CF\", \"color\": \"#f48120\", \"doh\": \"https://cloudflare-dns.com/dns-query\", \"dot\": \"cloudflare-dns.com\", \"dnssec\": true, \"status\": \"blocked\"}, \"Google DNS\": {\"ipv4\": [\"8.8.8.8\", \"8.8.4.4\"], \"ipv6\": [\"2001:4860:4860::8888\", \"2001:4860:4860::8844\"], \"desc\": \"Надёжный\", \"icon\": \"simple:google:G\", \"color\": \"#4285f4\", \"doh\": \"https://dns.google/dns-query\", \"dot\": \"dns.google\", \"dnssec\": true, \"status\": \"blocked\"}, \"Яндекс DNS\": {\"ipv4\": [\"77.88.8.8\", \"77.88.8.1\"], \"ipv6\": [\"2a02:6b8::feed:0ff\", \"2a02:6b8:0:1::feed:0ff\"], \"desc\": \"Российский, быстрый\", \"icon\": \"fa5b.yandex\", \"color\": \"#fc3f1d\", \"doh\": \"https://common.dot.dns.yandex.net/dns-query\", \"dot\": \"common.dot.dns.yandex.net\"}}, \"Безопасные\": {\"Quad9\": {\"ipv4\": [\"9.9.9.9\", \"149.112.112.112\"], \"ipv6\": [\"2620:fe::fe\", \"2620:fe::9\"], \"desc\": \"Антивирус\", \"icon\": \"simple:quad9:Q9\", \"color\": \"#e91e63\", \"doh\": \"https://dns.quad9.net/dns-query\", \"dot\": \"dns.quad9.net\", \"dnssec\": true}, \"AdGuard\": {\"ipv4\": [\"94.140.14.14\", \"94.140.15.15\"], \"ipv6\": [\"2a10:50c0::ad1:ff\", \"2a10:50c0::ad2:ff\"], \"desc\": \"Без рекламы\", \"icon\": \"simple:adguard:AG\", \"color\": \"#68bc71\", \"doh\": \"https://dns.adguard-dns.com/dns-query\", \"dot\": \"dns.adguard-dns.com\", \"dnssec\": true, \"status\": \"at_risk\"}, \"AdGuard Семейный\": {\"ipv4\": [\"94.140.14.15\", \"94.140.15.16\"], \"ipv6\": [\"2a10:50c0::bad1:ff\", \"2a10:50c0::bad2:ff\"], \"desc\": \"Без рекламы и 18+\", \"icon\": \"simple:adguard:AG\", \"color\": \"#3f9d8c\", \"doh\": \"https://family.adguard-dns.com/dns-query\", \"dot\": \"family.adguard-dns.com\", \"dnssec\": true, \"status\": \"at_risk\"}, \"OpenDNS\": {\"ipv4\": [\"208.67.222.222\", \"208.67.220.220\"], \"ipv6\": [\"2620:119:35::35\", \"2620:119:53::53\"], \"desc\": \"Фильтрация\", \"icon\": \"own:opendns:OD\", \"color\": \"#fe7702\", \"doh\": \"https://doh.opendns.com/dns-query\", \"dot\": \"dns.opendns.com\", \"dnssec\": true, \"status\": \"at_risk\"}, \"Яндекс Безопасный\": {\"ipv4\": [\"77.88.8.88\", \"77.88.8.2\"], \"ipv6\": [\"2a02:6b8::feed:bad\", \"2a02:6b8:0:1::feed:bad\"], \"desc\": \"Антивирус, российский\", \"icon\": \"fa5b.yandex\", \"color\": \"#f5a623\", \"doh\": \"https://safe.dot.dns.yandex.net/dns-query\", \"dot\": \"safe.dot.dns.yandex.net\"}, \"Яндекс Семейный\": {\"ipv4\": [\"77.88.8.7\", \"77.88.8.3\"], \"ipv6\": [\"2a02:6b8::feed:a11\", \"2a02:6b8:0:1::feed:a11\"], \"desc\": \"Без 18+, российский\", \"icon\": \"fa5b.yandex\", \"color\": \"#7b61ff\", \"doh\": \"https://family.dot.dns.yandex.net/dns-query\", \"dot\": \"family.dot.dns.yandex.net\"}, \"BI.ZONE\": {\"ipv4\": [\"185.191.32.7\", \"185.191.32.8\"], \"ipv6\": [], \"desc\": \"Антивирус, российский\", \"icon\": \"fa5s.shield-virus\", \"color\": \"#2dd4bf\", \"doh\": \"https://public.sdns.bi.zone/9c0205cf-e32e-418e-adc0-e2575ebcf394\", \"dot\": \"public.sdns.bi.zone\", \"dnssec\": true}, \"DNS4EU Защитный\": {\"ipv4\": [\"86.54.11.1\", \"86.54.11.201\"], \"ipv6\": [\"2a13:1001::86:54:11:1\", \"2a13:1001::86:54:11:201\"], \"desc\": \"Антивирус, Евросоюз\", \"icon\": \"simple:europeanunion:EU\", \"color\": \"#3b6fd4\", \"doh\": \"https://protective.joindns4.eu/dns-query\", \"dot\": \"protective.joindns4.eu\", \"dnssec\": true}, \"CleanBrowsing\": {\"ipv4\": [\"185.228.168.9\", \"185.228.169.9\"], \"ipv6\": [\"2a0d:2a00:1::2\", \"2a0d:2a00:2::2\"], \"desc\": \"Антивирус\", \"icon\": \"fa5s.broom\", \"color\": \"#38bdf8\", \"doh\": \"https://doh.cleanbrowsing.org/doh/security-filter/\", \"dot\": \"security-filter-dns.cleanbrowsing.org\", \"dnssec\": true}, \"Control D Без рекламы\": {\"ipv4\": [\"76.76.2.2\", \"76.76.10.2\"], \"ipv6\": [\"2606:1a40::2\", \"2606:1a40:1::2\"], \"desc\": \"Без рекламы и слежки\", \"icon\": \"fa5s.ban\", \"color\": \"#a78bfa\", \"doh\": \"https://freedns.controld.com/p2\", \"dnssec\": true}}, \"Малоизвестные\": {\"Dns.SB\": {\"ipv4\": [\"185.222.222.222\", \"45.11.45.11\"], \"ipv6\": [\"2a09::\", \"2a11::\"], \"desc\": \"Без цензуры\", \"icon\": \"fa5s.unlock-alt\", \"color\": \"#00bcd4\", \"doh\": \"https://doh.sb/dns-query\", \"dot\": \"dot.sb\", \"dnssec\": true}, \"dnsdoh.art\": {\"ipv4\": [\"194.180.189.33\"], \"ipv6\": [], \"desc\": \"Без рекламы и записи\", \"icon\": \"fa5s.lock\", \"color\": \"#9c27b0\", \"doh\": \"https://dnsdoh.art/dns-query\", \"dot\": \"dnsdoh.art\", \"dnssec\": true}, \"Control D\": {\"ipv4\": [\"76.76.2.0\", \"76.76.10.0\"], \"ipv6\": [\"2606:1a40::\", \"2606:1a40:1::\"], \"desc\": \"Без фильтров и записи\", \"icon\": \"fa5s.sliders-h\", \"color\": \"#8b5cf6\", \"doh\": \"https://freedns.controld.com/p0\", \"dnssec\": true}, \"DNS4EU\": {\"ipv4\": [\"86.54.11.100\", \"86.54.11.200\"], \"ipv6\": [\"2a13:1001::86:54:11:100\", \"2a13:1001::86:54:11:200\"], \"desc\": \"Без фильтров, Евросоюз\", \"icon\": \"simple:europeanunion:EU\", \"color\": \"#f5c518\", \"doh\": \"https://unfiltered.joindns4.eu/dns-query\", \"dot\": \"unfiltered.joindns4.eu\", \"dnssec\": true}, \"Gcore\": {\"ipv4\": [\"95.85.95.85\", \"2.56.220.2\"], \"ipv6\": [\"2a03:90c0:999d::1\", \"2a03:90c0:9992::1\"], \"desc\": \"Быстрый, без записи\", \"icon\": \"simple:gcore:GC\", \"color\": \"#ff4c00\", \"doh\": \"https://gcoredns.com/dns-query\", \"dot\": \"gcoredns.com\"}, \"DNS.Watch\": {\"ipv4\": [\"84.200.69.80\", \"84.200.70.40\"], \"ipv6\": [\"2001:1608:10:25::1c04:b12f\", \"2001:1608:10:25::9249:d69b\"], \"desc\": \"Без цензуры и записи\", \"icon\": \"fa5s.eye-slash\", \"color\": \"#4ade80\", \"dnssec\": true}, \"UltraDNS\": {\"ipv4\": [\"64.6.64.6\", \"64.6.65.6\"], \"ipv6\": [\"2620:74:1b::1:1\", \"2620:74:1c::2:2\"], \"desc\": \"Надёжный, без фильтров\", \"icon\": \"fa5s.bolt\", \"color\": \"#facc15\", \"dnssec\": true}, \"CZ.NIC\": {\"ipv4\": [\"193.17.47.1\", \"185.43.135.1\"], \"ipv6\": [\"2001:148f:ffff::1\", \"2001:148f:fffe::1\"], \"desc\": \"Без фильтров, Чехия\", \"icon\": \"fa5s.landmark\", \"color\": \"#60a5fa\", \"doh\": \"https://odvr.nic.cz/dns-query\", \"dot\": \"odvr.nic.cz\", \"dnssec\": true}, \"CIRA Canadian Shield\": {\"ipv4\": [\"149.112.121.10\", \"149.112.122.10\"], \"ipv6\": [\"2620:10a:80bb::10\", \"2620:10a:80bc::10\"], \"desc\": \"Без фильтров, Канада\", \"icon\": \"fa5b.canadian-maple-leaf\", \"color\": \"#ef4444\", \"doh\": \"https://private.canadianshield.cira.ca/dns-query\", \"dot\": \"private.canadianshield.cira.ca\", \"dnssec\": true}, \"Freifunk München\": {\"ipv4\": [\"5.1.66.255\", \"185.150.99.255\"], \"ipv6\": [\"2001:678:e68:f000::\", \"2001:678:ed0:f000::\"], \"desc\": \"Без цензуры и записи\", \"icon\": \"fa5s.broadcast-tower\", \"color\": \"#ec4899\", \"doh\": \"https://doh.ffmuc.net/dns-query\", \"dot\": \"dot.ffmuc.net\", \"dnssec\": true}, \"StormyCloud\": {\"ipv4\": [\"23.128.248.2\", \"23.128.248.4\"], \"ipv6\": [\"2602:fc05::2\", \"2602:fc05::4\"], \"desc\": \"Без цензуры и записи\", \"icon\": \"fa5s.cloud-rain\", \"color\": \"#93c5fd\", \"doh\": \"https://dns.stormycloud.org/dns-query\", \"dnssec\": true}, \"dnsforge.de\": {\"ipv4\": [\"176.9.93.198\", \"176.9.1.117\"], \"ipv6\": [\"2a01:4f8:151:34aa::198\", \"2a01:4f8:141:316d::117\"], \"desc\": \"Без рекламы и записи\", \"icon\": \"fa5s.hammer\", \"color\": \"#fb923c\", \"doh\": \"https://dnsforge.de/dns-query\", \"dot\": \"dnsforge.de\", \"dnssec\": true}, \"Surfshark DNS\": {\"ipv4\": [\"194.169.169.169\"], \"ipv6\": [\"2a09:a707:169::\"], \"desc\": \"Без записи запросов\", \"icon\": \"simple:surfshark:SS\", \"color\": \"#1ebfbf\", \"doh\": \"https://dns.surfsharkdns.com/dns-query\", \"dot\": \"dns.surfsharkdns.com\"}, \"Wikimedia DNS\": {\"ipv4\": [\"185.71.138.138\"], \"ipv6\": [\"2001:67c:930::1\"], \"desc\": \"Без фильтров, Википедия\", \"icon\": \"fa5b.wikipedia-w\", \"color\": \"#94a3b8\", \"doh\": \"https://wikimedia-dns.org/dns-query\", \"dot\": \"wikimedia-dns.org\", \"dnssec\": true, \"encrypted_only\": true}}, \"Для ИИ\": {\"Zapret DNS\": {\"ipv4\": [\"83.217.211.149\"], \"ipv6\": [\"2a03:afc0:9::235d\"], \"desc\": \"Нейросети и Spotify\", \"icon\": \"fa5s.rocket\", \"color\": \"#60CDFF\", \"doh\": \"https://dns.zapret.moe/dns-query\", \"dot\": \"dns.zapret.moe\", \"dnssec\": true}, \"Comss DNS\": {\"ipv4\": [\"83.220.169.155\", \"212.109.195.93\"], \"ipv6\": [], \"desc\": \"Нейросети, без рекламы\", \"icon\": \"fa5s.shield-alt\", \"color\": \"#2F80ED\", \"doh\": \"https://dns.comss.one/dns-query\", \"dot\": \"dns.comss.one\"}, \"AstraCat\": {\"ipv4\": [\"135.106.217.200\", \"135.106.197.22\"], \"ipv6\": [], \"desc\": \"ChatGPT, без рекламы\", \"icon\": \"fa5s.cat\", \"color\": \"#F59E0B\", \"doh\": \"https://dns.astracat.network/dns-query\", \"dot\": \"dns.astracat.network\", \"dnssec\": true}, \"GeoHide\": {\"ipv4\": [\"193.233.112.67\", \"193.233.112.68\"], \"ipv6\": [], \"desc\": \"ChatGPT, Grok, Notion\", \"icon\": \"fa5s.globe-europe\", \"color\": \"#8B5CF6\", \"doh\": \"https://geohide.ru/dns-query\", \"dot\": \"geohide.ru\"}, \"DNS-AI\": {\"ipv4\": [\"192.144.59.14\", \"186.246.49.127\"], \"ipv6\": [\"2a0d:8480:0:67c::14\", \"2a0a:2b41:0:500d::53\"], \"desc\": \"Нейросети, без рекламы\", \"icon\": \"fa5s.robot\", \"color\": \"#d946ef\", \"doh\": \"https://dns.dns-ai.ru/dns-query\", \"dot\": \"dns.dns-ai.ru\", \"dnssec\": true, \"encrypted_only\": true}}}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_shape_and_counts() {
        let catalog = catalog();
        assert_eq!(
            catalog.keys().cloned().collect::<Vec<_>>(),
            vec![
                "Шифрованные",
                "Популярные",
                "Безопасные",
                "Малоизвестные",
                "Для ИИ"
            ]
        );
        // Порядок и состав: 3 режима + Cloudflare первый среди обычных.
        let popular = catalog["Популярные"].as_object().expect("группа");
        assert_eq!(popular.keys().next().expect("первая плитка"), "Cloudflare");
    }

    #[test]
    fn catalog_rules_hold() {
        // python-список составлен правильно: нарушений правил нет.
        assert_eq!(catalog_problems(), Vec::<String>::new());
    }

    #[test]
    fn lookups_and_templates() {
        let (group, name, _data) = find_provider_by_address("8.8.8.8").expect("адрес найден");
        assert_eq!(group, "Популярные");
        assert_eq!(name, "Google DNS");
        assert!(
            find_provider_by_address("127.0.0.1").is_none(),
            "режимы пропускаются"
        );
        assert!(find_provider_by_address("  ").is_none());
        // Шаблоны: адрес → DoH без повторов.
        let templates = doh_templates();
        assert!(templates.contains(&(
            "1.1.1.1".to_string(),
            "https://cloudflare-dns.com/dns-query".to_string()
        )));
        // Сеть: режимы «Шифрованные» выброшены, остальные на месте.
        let network = network_providers();
        assert!(!network.contains_key(LOCAL_PROXY_GROUP));
        assert!(network.contains_key("Популярные"));
    }

    #[test]
    fn proxy_modes() {
        let (_, _, cloudflare) = find_provider_by_address("8.8.8.8").expect("найден");
        // Windows 11 умеет DoH сама — посредник не нужен.
        assert_eq!(proxy_mode_for(&cloudflare, true), "");
        // Windows 10: DoH только через встроенный движок.
        assert_eq!(proxy_mode_for(&cloudflare, false), "doh");
        // Плитка-режим всегда ставится через движок.
        let dnscrypt = catalog()["Шифрованные"]["DNSCrypt"].clone();
        assert_eq!(proxy_mode_for(&dnscrypt, true), "dnscrypt");
        // Серверы режима DoH для плитки: по одному на адрес IPv4.
        let upstreams = proxy_upstreams(&cloudflare);
        assert_eq!(upstreams.len(), 2);
        assert!(upstreams[0].stamp.starts_with("sdns://"));
    }

    #[test]
    fn ipv6_shapes_match_python() {
        // Эталоны python ipaddress: разобранное — IPv6, остальное — нет.
        for (text, expected) in [
            ("2001:db8::1", true),
            ("::1", true),
            ("::", true),
            ("1:2:3:4:5:6:7:8", true),
            ("1::", true),
            ("::1:2:3:4:5:6:7:8", false), // больше 8 групп даже со сжатием
            ("1:2:3:4:5:6:7::", true),
            ("::ffff:192.168.1.1", true),
            ("64:ff9b::1.2.3.4", true),
            ("1:2:3", false),
            ("1:2:3:4:5:6:7:8:9", false),
            ("1:::2", false),
            ("1::2::3", false),
            ("gggg::1", false),
            ("1.2.3.4", false),
            ("12345::1", false),
            ("1:2:3:4:5:6:7:1.2.3.4", false),
            ("::ffff:999.1.1.1", false),
        ] {
            assert_eq!(is_ipv6(text), expected, "{text}");
        }
        // IPv4-версия согласована с local_proxy_catalog.
        assert!(matches_version("1.2.3.4", 4));
        assert!(!matches_version("1.2.3", 4));
        assert!(!matches_version("::1", 4));
    }

    #[test]
    fn replacements_listed() {
        let replacements = outdated_dns_address_replacements();
        assert_eq!(replacements.len(), 12);
        assert!(replacements
            .iter()
            .all(|(old, new)| matches_version(old, 4) == matches_version(new, 4)));
    }
}
