//! Порт `src/dns/custom_servers.py` — свои DNS-серверы пользователя: разбор
//! введённого, список и плитки.
//!
//! Сервер хранится в settings.sqlite3 (dns → custom_servers) записью
//! `{"id", "name", "ipv4", "ipv6", "doh"}`. "doh" — адрес шифрованного DNS
//! поверх HTTPS (`https://имя/dns-query`) или пустая строка. Записи здесь —
//! [`serde_json::Value`], как у python-словарей, чтобы хранение и передача
//! совпадали дословно.
//!
//! Здесь нет ни окон, ни сети, ни чтения настроек: только правила. Страница
//! «Свой DNS» отдаёт сюда текст из полей ([`read_form`]) и получает либо
//! готовую запись, либо ошибку с названием поля. Сохранение и поиск адресов
//! делают dns.commands в фоновом потоке.
//!
//! Сервер можно задать тремя способами:
//! - только IP-адреса — обычный DNS;
//! - IP-адреса и адрес DoH — Windows 11 шифрует запросы к этим адресам;
//! - только адрес DoH — IP-адреса программа находит сама (dns.doh_lookup).

use serde_json::{json, Map, Value};

pub const CUSTOM_DNS_CATEGORY: &str = "Свои DNS";
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

pub const FIELD_NAME: &str = "name";
pub const FIELD_DOH: &str = "doh";
pub const FIELD_ADDRESSES: &str = "addresses";

/// python `DohTemplate` — разобранный адрес DoH. `url` — он же в едином виде,
/// как хранится в настройках.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohTemplate {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl DohTemplate {
    /// python `host_is_address` — в адресе вместо имени стоит IP.
    #[must_use]
    pub fn host_is_address(&self) -> bool {
        crate::providers::matches_version(&self.host, 4) || crate::providers::is_ipv6(&self.host)
    }
}

/// python `CustomServerForm` — итог разбора полей: запись сервера или ошибка
/// и поле, где она.
#[derive(Debug, Clone, Default)]
pub struct CustomServerForm {
    pub server: Option<Value>,
    pub error: String,
    pub field: String,
}

impl CustomServerForm {
    /// python `needs_lookup` — задан только адрес DoH: IP-адреса ещё
    /// предстоит найти.
    #[must_use]
    pub fn needs_lookup(&self) -> bool {
        match self.server.as_ref() {
            Some(server) => {
                !str_field(server, "doh").is_empty()
                    && array_field(server, "ipv4").is_empty()
                    && array_field(server, "ipv6").is_empty()
            }
            None => false,
        }
    }
}

fn str_field(server: &Value, key: &str) -> String {
    server
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn array_field(server: &Value, key: &str) -> Vec<String> {
    server
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

/// python `_ip(value)` — настоящий IP-адрес или None. Скобки IPv6 снимаются.
#[must_use]
pub fn parse_ip(value: &str) -> Option<std::net::IpAddr> {
    let text = value.trim().trim_start_matches('[').trim_end_matches(']');
    text.parse().ok()
}

/// Метка имени хоста (python `_HOST_LABEL`): буквы, цифры и дефисы, дефисы не
/// по краям, длина 1–63.
fn is_host_label(label: &str) -> bool {
    let bytes: Vec<char> = label.chars().collect();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let ordinary = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !ordinary(bytes[0]) || !ordinary(bytes[bytes.len() - 1]) {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|c| ordinary(*c) || *c == '-')
}

/// python `parse_doh_template` — адрес DoH из того, что вставил пользователь,
/// или None.
///
/// Понимает адрес без «https://» и хвост «{?dns}» из описаний серверов. Путь
/// по умолчанию — /dns-query. Только https: открытый http для DoH не годится.
#[must_use]
pub fn parse_doh_template(text: &str) -> Option<DohTemplate> {
    let raw = text.trim();
    if raw.is_empty() || raw.chars().any(char::is_whitespace) {
        return None;
    }
    let raw = raw.split('{').next().unwrap_or(raw);
    let raw = if !raw.contains("://") {
        format!("https://{raw}")
    } else {
        raw.to_string()
    };
    let (scheme, rest) = raw.split_once("://")?;
    // python urlsplit: порт после «:» имени; у IPv6-имени он после «]».
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path_and_more = rest.get(authority_end..).unwrap_or("");
    if path_and_more.contains(['?', '#']) {
        // query и fragment у DoH не бывают.
        return None;
    }
    let path = path_and_more;
    let (host_raw, port) = split_host_port(authority);
    if !scheme.eq_ignore_ascii_case("https") || host_raw.is_empty() || authority.contains('@') {
        return None;
    }
    // IPv6-имя годится только в скобках (python urlsplit без скобок порт не
    // разбирает и multi-colon имя не признаёт).
    if !authority.starts_with('[') && authority.matches(':').count() > 1 {
        return None;
    }
    let host = host_raw.to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    let host = if let Some(address) = parse_ip(&host) {
        match address {
            std::net::IpAddr::V4(v4) => (v4.to_string(), false),
            std::net::IpAddr::V6(v6) => (v6.to_string(), true),
        }
    } else {
        let labels: Vec<&str> = host.split('.').collect();
        if labels.len() < 2 || host.len() > 253 || !labels.iter().all(|label| is_host_label(label))
        {
            return None;
        }
        // Имя из одних цифр («149.112») — недописанный IP-адрес, а не сервер.
        if labels[labels.len() - 1].chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        (host.clone(), false)
    };
    let (host, is_v6) = host;
    let path = if path.is_empty() {
        DEFAULT_DOH_PATH
    } else {
        path
    };
    let shown_host = if is_v6 {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let shown_port = if port == 443 {
        String::new()
    } else {
        format!(":{port}")
    };
    Some(DohTemplate {
        url: format!("https://{shown_host}{shown_port}{path}"),
        host,
        port,
        path: path.to_string(),
    })
}

/// `имя[:порт]` из authority-части; порт по умолчанию 443.
fn split_host_port(authority: &str) -> (&str, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(443);
            return (host, port);
        }
        return (authority, 443);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => {
            (host, port.parse().expect("проверено"))
        }
        _ => (authority, 443),
    }
}

/// python `split_addresses` — IP-адреса из одной строки: (IPv4, IPv6, не
/// адреса).
///
/// Адреса разделяются пробелом, запятой или точкой с запятой; порядок
/// сохраняется (первый — основной), повторы убираются.
#[must_use]
pub fn split_addresses(text: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut ipv4: Vec<String> = Vec::new();
    let mut ipv6: Vec<String> = Vec::new();
    let mut bad: Vec<String> = Vec::new();
    for part in text.trim().split([' ', '\t', '\n', '\r', ',', ';']) {
        if part.is_empty() {
            continue;
        }
        let Some(address) = parse_ip(part) else {
            bad.push(part.to_string());
            continue;
        };
        let shown = address.to_string();
        let bucket = match address {
            std::net::IpAddr::V4(_) => &mut ipv4,
            std::net::IpAddr::V6(_) => &mut ipv6,
        };
        if !bucket.contains(&shown) {
            bucket.push(shown);
        }
    }
    (ipv4, ipv6, bad)
}

/// python `split_pasted` — текст «адрес DoH и IP-адреса вместе» → (адрес DoH,
/// IP-адреса) или None.
///
/// Так выглядит то, что кладёт в буфер «Копировать DNS» ([`clipboard_text`]),
/// и строка из описания сервера на его сайте. Вставленное в одно поле
/// раскладывается по двум, только если разбор однозначен: ровно один адрес
/// DoH и хотя бы один IP-адрес.
#[must_use]
pub fn split_pasted(text: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = text
        .trim()
        .split([' ', '\t', '\n', '\r', ',', ';'])
        .filter(|part| !part.is_empty())
        .collect();
    let addresses: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|part| parse_ip(part).is_some())
        .collect();
    let others: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|part| parse_ip(part).is_none())
        .collect();
    if addresses.is_empty() || others.len() != 1 || parse_doh_template(others[0]).is_none() {
        return None;
    }
    Some((others[0].to_string(), addresses.join(" ")))
}

/// python `new_server_id` — «custom-» и 12 шестнадцатеричных знаков.
#[must_use]
pub fn new_server_id() -> String {
    format!("custom-{:012x}", fastrand::u64(..) & 0xffff_ffff_ffff)
}

/// python `read_form` — запись сервера из текста полей страницы «Свой DNS».
///
/// Название можно не писать: им станет имя сервера из адреса DoH или первый
/// IP-адрес. Обязательно одно из двух — адрес DoH или хотя бы один IP.
#[must_use]
pub fn read_form(server_id: &str, name: &str, doh: &str, addresses: &str) -> CustomServerForm {
    let doh_text = doh.trim();
    let template = if doh_text.is_empty() {
        None
    } else {
        parse_doh_template(doh_text)
    };
    if !doh_text.is_empty() && template.is_none() {
        return CustomServerForm {
            error: "Адрес DoH должен выглядеть так: https://dns.example.com/dns-query".to_string(),
            field: FIELD_DOH.to_string(),
            ..Default::default()
        };
    }
    let (ipv4, ipv6, bad) = split_addresses(addresses);
    if !bad.is_empty() {
        return CustomServerForm {
            error: format!(
                "«{}» — не IP-адрес. Пишите адреса через пробел, например: 9.9.9.9 149.112.112.112",
                bad[0]
            ),
            field: FIELD_ADDRESSES.to_string(),
            ..Default::default()
        };
    }
    if template.is_none() && ipv4.is_empty() && ipv6.is_empty() {
        return CustomServerForm {
            error: "Вставьте адрес DoH или впишите хотя бы один IP-адрес сервера.".to_string(),
            field: FIELD_DOH.to_string(),
            ..Default::default()
        };
    }
    let mut clean_name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean_name.is_empty() {
        clean_name = match template.as_ref() {
            Some(template) => template.host.clone(),
            None => ipv4.first().or(ipv6.first()).cloned().unwrap_or_default(),
        };
    }
    CustomServerForm {
        server: Some(json!({
            "id": if server_id.trim().is_empty() { new_server_id() } else { server_id.trim().to_string() },
            "name": clean_name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "doh": template.map(|template| template.url).unwrap_or_default(),
        })),
        ..Default::default()
    }
}

/// python `copy_server` — запись с полями ровно нужных видов.
#[must_use]
pub fn copy_server(server: Option<&Value>) -> Value {
    let data = server.cloned().unwrap_or(Value::Null);
    json!({
        "id": data.get("id").map(value_text).unwrap_or_default(),
        "name": data.get("name").map(value_text).unwrap_or_default(),
        "ipv4": data.get("ipv4").map(list_of_text).unwrap_or_default(),
        "ipv6": data.get("ipv6").map(list_of_text).unwrap_or_default(),
        "doh": data.get("doh").map(value_text).unwrap_or_default(),
    })
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn list_of_text(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_default()
}

/// python `addresses_text` — IP-адреса сервера одной строкой — так, как их
/// пишут в поле страницы.
#[must_use]
pub fn addresses_text(server: Option<&Value>) -> String {
    let data = copy_server(server);
    let mut parts = array_field(&data, "ipv4");
    parts.extend(array_field(&data, "ipv6"));
    parts.join(" ")
}

/// python `clipboard_text` — что уходит в буфер обмена: адрес DoH (если есть)
/// и IP-адреса.
#[must_use]
pub fn clipboard_text(server: Option<&Value>) -> String {
    let data = copy_server(server);
    let mut parts = vec![str_field(&data, "doh")];
    parts.extend(array_field(&data, "ipv4"));
    parts.extend(array_field(&data, "ipv6"));
    parts
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

// ── список серверов ───────────────────────────────────────────────────────

/// python `_name_key` — название без пробелов по краям и без различия регистров.
fn name_key(name: &str) -> String {
    name.trim().to_lowercase()
}

/// python `upsert_server` — список с добавленным или заменённым (по id)
/// сервером и текст ошибки.
///
/// Название — ключ плитки, поэтому оно не может совпадать ни с другим своим
/// сервером, ни с сервером из списка программы (`reserved_names`).
#[must_use]
pub fn upsert_server(
    servers: &[Value],
    server: &Value,
    reserved_names: &[&str],
) -> (Vec<Value>, String) {
    let new = copy_server(Some(server));
    let mut taken: Vec<String> = reserved_names.iter().map(|name| name_key(name)).collect();
    for item in servers {
        if str_field(item, "id") != str_field(&new, "id") {
            taken.push(name_key(&str_field(item, "name")));
        }
    }
    if taken.contains(&name_key(&str_field(&new, "name"))) {
        return (
            servers.to_vec(),
            format!(
                "Сервер с названием «{}» уже есть. Впишите другое название.",
                str_field(&new, "name")
            ),
        );
    }
    let mut result: Vec<Value> = servers.iter().map(|item| copy_server(Some(item))).collect();
    for item in &mut result {
        if str_field(item, "id") == str_field(&new, "id") {
            *item = new;
            return (result, String::new());
        }
    }
    result.push(new);
    (result, String::new())
}

/// python `remove_server` — список без сервера с этим id.
#[must_use]
pub fn remove_server(servers: &[Value], server_id: &str) -> Vec<Value> {
    servers
        .iter()
        .filter(|item| str_field(item, "id") != server_id.trim())
        .map(|item| copy_server(Some(item)))
        .collect()
}

/// python `unique_copy_name` — «основание копия», «основание копия 2», …
#[must_use]
pub fn unique_copy_name(base_name: &str, existing_names: &[&str]) -> String {
    let base = if base_name.trim().is_empty() {
        "Свой DNS"
    } else {
        base_name.trim()
    };
    let existing: Vec<String> = existing_names.iter().map(|name| name_key(name)).collect();
    let first = format!("{base} копия");
    if !existing.contains(&name_key(&first)) {
        return first;
    }
    let mut index = 2;
    while existing.contains(&name_key(&format!("{first} {index}"))) {
        index += 1;
    }
    format!("{first} {index}")
}

/// python `duplicate_server` — список с копией сервера в конце; неизвестный id
/// список не меняет.
#[must_use]
pub fn duplicate_server(servers: &[Value], server_id: &str, reserved_names: &[&str]) -> Vec<Value> {
    let mut result: Vec<Value> = servers.iter().map(|item| copy_server(Some(item))).collect();
    let source = result
        .iter()
        .find(|item| str_field(item, "id") == server_id.trim())
        .cloned();
    let Some(source) = source else {
        return result;
    };
    let mut clone = copy_server(Some(&source));
    let id = Value::String(new_server_id());
    if let Some(object) = clone.as_object_mut() {
        object.insert("id".to_string(), id);
    }
    let mut names: Vec<&str> = reserved_names.to_vec();
    let own: Vec<String> = result.iter().map(|item| str_field(item, "name")).collect();
    let own: Vec<&str> = own.iter().map(String::as_str).collect();
    names.extend(own);
    let new_name = unique_copy_name(&str_field(&source, "name"), &names);
    if let Some(object) = clone.as_object_mut() {
        object.insert("name".to_string(), Value::String(new_name));
    }
    result.push(clone);
    result
}

// ── плитки и запись в Windows ─────────────────────────────────────────────

/// python `build_dns_providers_with_custom` — серверы программы и группа
/// «Свои DNS» в том же виде, что dns_providers.
#[must_use]
pub fn build_dns_providers_with_custom(
    base_providers: &Map<String, Value>,
    custom_servers: &[Value],
) -> Map<String, Value> {
    let mut providers = base_providers.clone();
    let mut custom_group = Map::new();
    for server in custom_servers {
        let data = copy_server(Some(server));
        let ipv4: Vec<String> = array_field(&data, "ipv4")
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect();
        let ipv6: Vec<String> = array_field(&data, "ipv6")
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect();
        let name = str_field(&data, "name").trim().to_string();
        if name.is_empty() || (ipv4.is_empty() && ipv6.is_empty()) {
            continue;
        }
        let mut entry = Map::new();
        entry.insert("ipv4".to_string(), json!(ipv4));
        entry.insert("ipv6".to_string(), json!(ipv6));
        entry.insert("desc".to_string(), json!("Пользовательский"));
        entry.insert("icon".to_string(), json!("fa5s.edit"));
        entry.insert("color".to_string(), json!("#22c55e"));
        entry.insert("custom_id".to_string(), json!(str_field(&data, "id")));
        let doh = str_field(&data, "doh");
        if !doh.is_empty() {
            entry.insert("doh".to_string(), json!(doh));
        }
        custom_group.insert(name, Value::Object(entry));
    }
    if !custom_group.is_empty() {
        providers.insert(CUSTOM_DNS_CATEGORY.to_string(), Value::Object(custom_group));
    }
    providers
}

/// python `custom_doh_templates` — {адрес сервера: шаблон DoH} для своих
/// серверов — как `providers::doh_templates`.
#[must_use]
pub fn custom_doh_templates(custom_servers: &[Value]) -> Vec<(String, String)> {
    let mut templates: Vec<(String, String)> = Vec::new();
    for server in custom_servers {
        let data = copy_server(Some(server));
        let doh = str_field(&data, "doh");
        if doh.is_empty() {
            continue;
        }
        let mut addresses = array_field(&data, "ipv4");
        addresses.extend(array_field(&data, "ipv6"));
        for address in addresses {
            let address = address.trim().to_string();
            if !templates.iter().any(|(known, _)| *known == address) {
                templates.push((address, doh.clone()));
            }
        }
    }
    templates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_template_parsed_and_normalized() {
        let template = parse_doh_template("dns.quad9.net").expect("разобран");
        assert_eq!(
            template,
            DohTemplate {
                url: "https://dns.quad9.net/dns-query".to_string(),
                host: "dns.quad9.net".to_string(),
                port: 443,
                path: "/dns-query".to_string(),
            }
        );
        // Явный путь и порт; IPv6 в скобках; хвост-плейсхолдер срезан.
        assert_eq!(
            parse_doh_template("https://dns.quad9.net:8443/private{?dns}")
                .expect("разобран")
                .url,
            "https://dns.quad9.net:8443/private"
        );
        assert_eq!(
            parse_doh_template("HTTPS://DNS.EXAMPLE.COM.")
                .expect("разобран")
                .host,
            "dns.example.com"
        );
        assert_eq!(
            parse_doh_template("[2606:4700:4700::1111]")
                .expect("разобран")
                .url,
            "https://[2606:4700:4700::1111]/dns-query"
        );
        assert!(parse_doh_template("[2606:4700:4700::1111]")
            .expect("разобран")
            .host_is_address());
        // Отказы: http, пробелы, одно слово, имя из цифр, query.
        assert!(parse_doh_template("http://dns.example.com").is_none());
        assert!(parse_doh_template("dns quad9 net").is_none());
        assert!(parse_doh_template("localhost").is_none());
        assert!(parse_doh_template("149.112").is_none());
        assert!(parse_doh_template("https://dns.example.com/dns-query?x=1").is_none());
    }

    #[test]
    fn addresses_split_and_dedup() {
        let (ipv4, ipv6, bad) =
            split_addresses("9.9.9.9, 149.112.112.112; 9.9.9.9  2606:4700::1111 ерунда");
        assert_eq!(
            ipv4,
            vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()]
        );
        assert_eq!(ipv6, vec!["2606:4700::1111".to_string()]);
        assert_eq!(bad, vec!["ерунда".to_string()]);
        // IPv6 в скобках тоже адрес.
        let (ipv4, ipv6, bad) = split_addresses("[2606:4700::1111] 1.1.1.1");
        assert!(ipv4.len() == 1 && ipv6.len() == 1 && bad.is_empty());
    }

    #[test]
    fn pasted_text_splits_only_unambiguously() {
        // Ровно один адрес DoH и адреса — раскладывается.
        assert_eq!(
            split_pasted("https://dns.quad9.net/dns-query, 9.9.9.9 149.112.112.112"),
            Some((
                "https://dns.quad9.net/dns-query".to_string(),
                "9.9.9.9 149.112.112.112".to_string()
            ))
        );
        // Два не-адреса — неоднозначно.
        assert_eq!(split_pasted("dns.quad9.net 9.9.9.9 описание"), None);
        // Без адресов — тоже.
        assert_eq!(split_pasted("dns.quad9.net"), None);
        // Только адреса — раскладывать нечего.
        assert_eq!(split_pasted("9.9.9.9 1.1.1.1"), None);
    }

    #[test]
    fn form_reads_and_names_itself() {
        // Название из адреса DoH.
        let form = read_form("", "", "dns.quad9.net", "9.9.9.9 149.112.112.112");
        let needs_lookup = form.needs_lookup();
        let server = form.server.expect("запись собрана");
        assert_eq!(server["name"], "dns.quad9.net");
        assert!(server["id"].as_str().expect("id").starts_with("custom-"));
        assert!(!needs_lookup);
        // Только DoH: адреса ещё предстоит найти.
        let form = read_form("", "", "dns.quad9.net", "");
        assert!(form.needs_lookup());
        // Ошибки с полем.
        assert_eq!(read_form("", "", "http://x", "").field, FIELD_DOH);
        assert_eq!(read_form("", "", "", "ерунда").field, FIELD_ADDRESSES);
        assert_eq!(read_form("", "", "", "").field, FIELD_DOH);
        // Название из первого адреса.
        let form = read_form("", "", "", "9.9.9.9");
        assert_eq!(form.server.expect("запись")["name"], "9.9.9.9");
        // Свой id сохраняется.
        let form = read_form("custom-abc", "Мой", "", "1.1.1.1");
        assert_eq!(form.server.expect("запись")["id"], "custom-abc");
    }

    #[test]
    fn list_operations() {
        let first = read_form("", "Первый", "", "1.1.1.1")
            .server
            .expect("первый");
        let second = read_form("", "Второй", "", "9.9.9.9")
            .server
            .expect("второй");
        // Повтор названия не проходит.
        let (list, error) = upsert_server(std::slice::from_ref(&first), &second, &["второй"]);
        assert_eq!(
            error,
            "Сервер с названием «Второй» уже есть. Впишите другое название."
        );
        assert_eq!(list.len(), 1);
        // Замена по id.
        let mut replaced = copy_server(Some(&second));
        replaced["name"] = json!("Заменённый");
        replaced["id"] = second["id"].clone();
        let (list, error) = upsert_server(&[first.clone(), second.clone()], &replaced, &[]);
        assert!(error.is_empty());
        assert_eq!(list.len(), 2);
        assert_eq!(list[1]["name"], "Заменённый");
        // Удаление и копирование.
        assert_eq!(
            remove_server(
                &[first.clone(), second.clone()],
                first["id"].as_str().expect("id")
            )
            .len(),
            1
        );
        let cloned = duplicate_server(
            &[first.clone(), second.clone()],
            second["id"].as_str().expect("id"),
            &["Первый"],
        );
        assert_eq!(cloned.len(), 3);
        assert_eq!(cloned[2]["name"], "Второй копия");
        assert_ne!(cloned[2]["id"], second["id"]);
        // Неизвестный id список не меняет.
        assert_eq!(
            duplicate_server(std::slice::from_ref(&first), "нет такого", &[]).len(),
            1
        );
    }

    #[test]
    fn copy_names_unique() {
        assert_eq!(unique_copy_name("Quad9", &[]), "Quad9 копия");
        assert_eq!(unique_copy_name("Quad9", &["quad9 копия"]), "Quad9 копия 2");
        assert_eq!(
            unique_copy_name("Quad9", &["quad9 копия", "quad9 копия 2"]),
            "Quad9 копия 3"
        );
        assert_eq!(unique_copy_name("", &[]), "Свой DNS копия");
    }

    #[test]
    fn texts_and_tiles() {
        let server = read_form("", "Свой", "dns.quad9.net", "9.9.9.9")
            .server
            .expect("запись");
        assert_eq!(addresses_text(Some(&server)), "9.9.9.9");
        assert_eq!(
            clipboard_text(Some(&server)),
            "https://dns.quad9.net/dns-query, 9.9.9.9"
        );
        // Плитки из списка программы + группа «Свои DNS».
        let base = serde_json::Map::new();
        let providers = build_dns_providers_with_custom(&base, std::slice::from_ref(&server));
        let group = providers[CUSTOM_DNS_CATEGORY].as_object().expect("группа");
        let entry = group["Свой"].as_object().expect("плитка");
        assert_eq!(entry["desc"], "Пользовательский");
        assert_eq!(entry["custom_id"], server["id"]);
        assert_eq!(entry["doh"], "https://dns.quad9.net/dns-query");
        // Пустое имя или без адресов — плитки нет.
        let mut empty = copy_server(Some(&server));
        empty["name"] = json!("");
        assert!(build_dns_providers_with_custom(&base, &[empty])
            .get(CUSTOM_DNS_CATEGORY)
            .is_none());
        // Шаблоны по адресам.
        assert_eq!(
            custom_doh_templates(&[server]),
            vec![(
                "9.9.9.9".to_string(),
                "https://dns.quad9.net/dns-query".to_string()
            )]
        );
    }
}
