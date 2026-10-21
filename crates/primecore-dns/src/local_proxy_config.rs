//! Порт `src/dns/local_proxy_config.py` — файл настроек dnscrypt-proxy для
//! выбранного режима шифрованного DNS.
//!
//! Файл — единственное место, где записано, в каком режиме работает движок:
//! первая строка `# zapret-mode: <режим>`. Программа читает её обратно
//! ([`read_mode`]), а не хранит режим отдельно, поэтому показанное на
//! странице всегда совпадает с тем, что на самом деле запущено. У режима DoH
//! вторая строка называет плитку, чей сервер запущен:
//! `# zapret-server: <название>` ([`read_server`]), а сами серверы читаются
//! обратно из разделов `[static]` ([`read_upstreams`]) — этого хватает, чтобы
//! поднять службу заново.
//!
//! Серверы перечислены в файле целиком, штампами из
//! [`crate::local_proxy_catalog`]: списки из сети движок не скачивает.

use crate::local_proxy_catalog::{self as catalog, Upstream};

pub const MODE_MARKER: &str = "# zapret-mode: ";
pub const SERVER_MARKER: &str = "# zapret-server: ";
pub const LISTEN_IPV4: &str = "127.0.0.1";
pub const LISTEN_IPV6: &str = "::1";

/// python `_text` — строка TOML. Путь Windows пишется как есть, в одинарных
/// кавычках.
#[must_use]
pub fn text_value(value: &str) -> String {
    if !value.contains('\'') && !value.contains('\n') {
        // Двойные кавычки в одинарных TOML допускает — как python `_text`.
        return format!("'{value}'");
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// python `_list(values)` — массив TOML.
fn list_value(items: impl IntoIterator<Item = String>) -> String {
    let parts: Vec<String> = items.into_iter().map(|item| text_value(&item)).collect();
    format!("[{}]", parts.join(", "))
}

/// python `build_config` — текст dnscrypt-proxy.toml: слушать 127.0.0.1:53
/// (и [::1]:53), серверы режима.
///
/// `upstreams` и `server_name` нужны только режиму DoH: серверы плитки и её
/// название.
#[must_use]
pub fn build_config(
    mode: &str,
    log_path: &str,
    listen_ipv6: bool,
    upstreams: &[Upstream],
    server_name: &str,
) -> String {
    let doh = mode == catalog::MODE_DOH;
    let odoh = mode == catalog::MODE_ODOH;
    // python `catalog.servers` для DoH без серверов бросает ValueError.
    let servers = match catalog::servers(mode, upstreams) {
        Ok(servers) => servers,
        Err(message) if doh => panic!("{message}"),
        Err(_) => Vec::new(),
    };
    let relays = catalog::relays(mode).unwrap_or_default();
    let mut listen = vec![format!("{LISTEN_IPV4}:53")];
    if listen_ipv6 {
        listen.push(format!("[{LISTEN_IPV6}]:53"));
    }

    let mut lines: Vec<String> = vec![
        format!("{MODE_MARKER}{mode}"),
        "# Файл пишет PrimeBypass при выборе шифрованного DNS; правки руками будут затёрты."
            .to_string(),
        String::new(),
        format!("listen_addresses = {}", list_value(listen)),
        format!(
            "server_names = {}",
            list_value(servers.iter().map(|item| item.name.clone()))
        ),
        "ipv4_servers = true".to_string(),
        "ipv6_servers = false".to_string(),
        format!(
            "dnscrypt_servers = {}",
            if odoh || doh { "false" } else { "true" }
        ),
        format!("doh_servers = {}", if doh { "true" } else { "false" }),
        format!("odoh_servers = {}", if odoh { "true" } else { "false" }),
        // Свои запросы движок не отдаёт DNS системы: там теперь стоит он сам.
        "ignore_system_dns = true".to_string(),
        format!(
            "bootstrap_resolvers = {}",
            list_value(
                catalog::BOOTSTRAP_RESOLVERS
                    .iter()
                    .map(|item| item.to_string())
            )
        ),
        "netprobe_timeout = 60".to_string(),
        "netprobe_address = '9.9.9.9:53'".to_string(),
        "timeout = 5000".to_string(),
        "keepalive = 30".to_string(),
        "cache = true".to_string(),
        "log_level = 2".to_string(),
        format!("log_file = {}", text_value(log_path)),
        "log_files_max_size = 2".to_string(),
        "log_files_max_age = 7".to_string(),
        "log_files_max_backups = 1".to_string(),
    ];
    if doh {
        lines.insert(
            1,
            format!(
                "{SERVER_MARKER}{}",
                server_name.split_whitespace().collect::<Vec<_>>().join(" ")
            ),
        );
    }
    let routes = catalog::routes(mode).unwrap_or_default();
    if !routes.is_empty() {
        lines.push(String::new());
        lines.push("[anonymized_dns]".to_string());
        lines.push("routes = [".to_string());
        for (server, via) in routes {
            lines.push(format!(
                "  {{ server_name = {}, via = {} }},",
                text_value(&server),
                list_value(via)
            ));
        }
        // Сервер, который через посредника не отвечает, пропускается, а не
        // идёт напрямую.
        lines.push("]".to_string());
        lines.push("skip_incompatible = true".to_string());
    }
    for item in servers.iter().chain(relays.iter()) {
        lines.push(String::new());
        lines.push(format!("[static.{}]", text_value(&item.name)));
        lines.push(format!("stamp = {}", text_value(&item.stamp)));
    }
    format!("{}\n", lines.join("\n"))
}

/// python `read_server` — название плитки, чей сервер запущен в режиме DoH; у
/// остальных режимов — пусто.
#[must_use]
pub fn read_server(config_text: &str) -> String {
    if read_mode(config_text) != catalog::MODE_DOH {
        return String::new();
    }
    for line in config_text.lines().skip(1).take(3) {
        if let Some(rest) = line.strip_prefix(SERVER_MARKER) {
            return rest.trim().to_string();
        }
    }
    String::new()
}

/// python `read_upstreams` — серверы из разделов `[static]` файла настроек —
/// чтобы запустить тот же режим DoH заново.
#[must_use]
pub fn read_upstreams(config_text: &str) -> Vec<Upstream> {
    let mut found: Vec<Upstream> = Vec::new();
    let mut lines = config_text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(section) = extract_static_section(line) else {
            continue;
        };
        // Следующая строка «stamp = '…'».
        if let Some(stamp_line) = lines.peek() {
            if let Some(stamp) = stamp_line.trim().strip_prefix("stamp = '") {
                let stamp = stamp.strip_suffix('\'').unwrap_or(stamp);
                found.push(Upstream {
                    name: section,
                    operator: String::new(),
                    stamp: stamp.to_string(),
                });
            }
        }
    }
    found
}

/// `[static.'имя']` из строки заголовка раздела; None — не тот раздел.
fn extract_static_section(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("[static.'")?;
    let name = rest.strip_suffix("']")?;
    Some(name.to_string())
}

/// python `read_mode` — режим из первой строки файла настроек или пустая
/// строка.
#[must_use]
pub fn read_mode(config_text: &str) -> String {
    let first = config_text
        .trim_start_matches('\u{FEFF}')
        .lines()
        .next()
        .unwrap_or("")
        .trim();
    let Some(mode) = first.strip_prefix(MODE_MARKER) else {
        return String::new();
    };
    let mode = mode.trim();
    if catalog::MODES.contains(&mode) {
        mode.to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_proxy_catalog::{up, MODE_DNSCRYPT, MODE_DOH, MODE_ODOH};

    /// Эталонный текст от python build_config — сверяется в тесте ниже.
    #[test]
    fn config_matches_python_shape() {
        let config = build_config(MODE_DNSCRYPT, "C:/log/dns.log", true, &[], "");
        // Первая строка — маркер режима; потом — плитка только у DoH.
        let lines: Vec<&str> = config.lines().collect();
        assert_eq!(lines[0], "# zapret-mode: dnscrypt");
        assert!(!lines[1].starts_with(SERVER_MARKER));
        assert!(config.contains("listen_addresses = ['127.0.0.1:53', '[::1]:53']"));
        assert!(config.contains("dnscrypt_servers = true"));
        assert!(config.contains("doh_servers = false"));
        assert!(config.contains("odoh_servers = false"));
        assert!(config.contains("ignore_system_dns = true"));
        assert!(config.contains("bootstrap_resolvers = ['9.9.9.11:53', '77.88.8.8:53']"));
        assert!(config.contains("log_file = 'C:/log/dns.log'"));
        // Серверы — штампами в [static].
        assert!(config.contains("[static.'quad9-dnscrypt-ip4-nofilter-pri']"));
        assert!(config.contains("stamp = 'sdns://AQcAAAAAAAAADTku"));
        // Анонимные маршруты.
        let config = build_config(catalog::MODE_ANONYMIZED, "", false, &[], "");
        assert!(config.contains("[anonymized_dns]"));
        assert!(config.contains("skip_incompatible = true"));
        // DoH: серверы плитки и её название.
        let upstreams = vec![up("doh-1", "dns.quad9.net", "sdns://AgEAAAAAAAAABzEu")];
        let config = build_config(MODE_DOH, "", false, &upstreams, "Quad9");
        assert!(config.starts_with("# zapret-mode: doh\n# zapret-server: Quad9\n"));
        assert!(config.contains("dnscrypt_servers = false"));
        assert!(config.contains("doh_servers = true"));
        assert!(!config.contains("[anonymized_dns]"));
        // ODoH.
        let config = build_config(MODE_ODOH, "", false, &[], "");
        assert!(config.contains("odoh_servers = true"));
        assert!(config.contains("dnscrypt_servers = false"));
    }

    #[test]
    fn read_mode_and_server() {
        let config = build_config(MODE_DOH, "", false, &[up("doh-1", "h", "s")], "Quad9");
        assert_eq!(read_mode(&config), "doh");
        assert_eq!(read_server(&config), "Quad9");
        // Не-DoH: плитки нет.
        let config = build_config(MODE_DNSCRYPT, "", false, &[], "");
        assert_eq!(read_mode(&config), "dnscrypt");
        assert_eq!(read_server(&config), "");
        // Пустой и мусорный текст.
        assert_eq!(read_mode(""), "");
        assert_eq!(read_mode("random text"), "");
        assert_eq!(read_mode("# zapret-mode: неизвестный"), "");
        // BOM не мешает.
        assert_eq!(read_mode("\u{FEFF}# zapret-mode: odoh\n"), "odoh");
    }

    #[test]
    fn read_upstreams_from_static_sections() {
        let config = build_config(
            MODE_DOH,
            "",
            false,
            &[up("doh-1", "h", "sdns://AgEAAA")],
            "Quad9",
        );
        let upstreams = read_upstreams(&config);
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].name, "doh-1");
        assert_eq!(upstreams[0].stamp, "sdns://AgEAAA");
        assert!(
            upstreams[0].operator.is_empty(),
            "оператор в файле не записан"
        );
        // У каждого режима читаются обратно все его серверы и посредники.
        // dnscrypt: 16 серверов и ни одного посредника.
        let config = build_config(MODE_DNSCRYPT, "", false, &[], "");
        assert_eq!(read_upstreams(&config).len(), 16, "серверы dnscrypt");
        let config = build_config(catalog::MODE_ANONYMIZED, "", false, &[], "");
        assert_eq!(
            read_upstreams(&config).len(),
            15 + 13,
            "серверы и посредники anonymized"
        );
        let config = build_config(MODE_ODOH, "", false, &[], "");
        assert_eq!(
            read_upstreams(&config).len(),
            3 + 2,
            "серверы и посредники odoh"
        );
    }

    #[test]
    #[should_panic(expected = "Для режима DoH не задан сервер")]
    fn doh_without_servers_is_rejected() {
        // python: `build_config("doh", ...)` без upstreams бросает ValueError.
        let _ = build_config(MODE_DOH, "", false, &[], "");
    }

    #[test]
    fn text_value_quotes() {
        assert_eq!(text_value("C:/путь/без кавычек"), "'C:/путь/без кавычек'");
        assert_eq!(text_value("с 'кавычкой'"), "\"с 'кавычкой'\"");
        assert_eq!(text_value("со \"двойной\""), "'со \"двойной\"'");
        // Перенос строки python не экранирует — он остаётся как есть внутри
        // двойных кавычек.
        assert_eq!(text_value("строка\nс переносом"), "\"строка\nс переносом\"");
    }
}
