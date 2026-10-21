//! Порт `src/dns/local_proxy_catalog.py` — серверы для шифрованного DNS
//! через встроенный dnscrypt-proxy.
//!
//! Windows сама умеет только обычный DNS и DoH, поэтому для DNSCrypt и ODoH
//! программа запускает на компьютере маленький посредник dnscrypt-proxy: он
//! принимает обычные запросы на адресе 127.0.0.1 и шифрует их по дороге.
//!
//! Режимы:
//! - [`MODE_DNSCRYPT`] — DNSCrypt: запрос зашифрован, имени сервера в открытом
//!   виде нет, поэтому его не подменить и не закрыть по имени, как DoH;
//! - [`MODE_ANONYMIZED`] — анонимный DNSCrypt: зашифрованный запрос идёт через
//!   посредника (relay), и DNS-сервер не видит адрес пользователя;
//! - [`MODE_ODOH`] — Oblivious DoH: то же самое, но поверх HTTPS. Посредников
//!   в мире всего два, сами авторы считают поддержку пробной;
//! - [`MODE_DOH`] — обычный DoH к одному серверу из списка программы.
//!   Отдельной плитки у режима нет: его включает плитка самого сервера там,
//!   где Windows шифровать DNS не умеет (Windows 10), — иначе запросы к
//!   серверу шли бы открытым текстом и ответ можно было бы подменить по
//!   дороге. Серверы этого режима не записаны здесь, а собираются из данных
//!   плитки ([`doh_upstreams`]).
//!
//! Каждый сервер записан своим «штампом» (`sdns://…`) из официальных списков
//! DNSCrypt/dnscrypt-resolvers (v3: public-resolvers, relays, odoh-servers,
//! odoh-relays): в штампе адрес и ключ сервера, поэтому списки из сети не
//! скачиваются и запуск не зависит от посторонних сайтов. Все серверы — без
//! записи запросов, без фильтров и с проверкой DNSSEC; каждый отвечал при
//! проверке с Windows 2026-10-07. Движок сам выбирает самый быстрый из живых.
//!
//! `operator` — кто держит сервер. В анонимных режимах посредник и сервер
//! обязаны быть у разных владельцев, иначе один владелец видит и адрес
//! пользователя, и запрос: [`routes`] это соблюдает.

use serde::{Deserialize, Serialize};

pub const MODE_DNSCRYPT: &str = "dnscrypt";
pub const MODE_ANONYMIZED: &str = "anonymized";
pub const MODE_ODOH: &str = "odoh";
pub const MODE_DOH: &str = "doh";
/// Режимы движка; [`providers`] проверяет режимы плиток по этому списку.
pub const MODES: [&str; 4] = [MODE_DNSCRYPT, MODE_ANONYMIZED, MODE_ODOH, MODE_DOH];

/// Обычный DNS для первого шага: узнать адреса ODoH-серверов, записанных именем.
pub const BOOTSTRAP_RESOLVERS: [&str; 2] = ["9.9.9.11:53", "77.88.8.8:53"];

/// python `Upstream` — сервер или посредник движка.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub name: String,
    pub operator: String,
    pub stamp: String,
}

/// python `Upstream(...)`: кортеж в структуру (для краткости записи списков).
#[must_use]
pub fn up(name: &str, operator: &str, stamp: &str) -> Upstream {
    Upstream {
        name: name.to_string(),
        operator: operator.to_string(),
        stamp: stamp.to_string(),
    }
}

/// DNSCrypt-серверы.
#[must_use]
pub fn dnscrypt_servers() -> Vec<Upstream> {
    vec![
    up("quad9-dnscrypt-ip4-nofilter-pri", "quad9", "sdns://AQcAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA"),
    up("scaleway-fr", "scaleway", "sdns://AQcAAAAAAAAADjIxMi40Ny4yMjguMTM2IOgBuE6mBr-wusDOQ0RbsV66ZLAvo8SqMa4QY2oHkDJNHzIuZG5zY3J5cHQtY2VydC5mci5kbnNjcnlwdC5vcmc"),
    up("scaleway-ams", "scaleway", "sdns://AQcAAAAAAAAADTUxLjE1LjEyMi4yNTAg6Q3ZfapcbHgiHKLF7QFoli0Ty1Vsz3RXs1RUbxUrwZAcMi5kbnNjcnlwdC1jZXJ0LnNjYWxld2F5LWFtcw"),
    up("dct-de", "dct", "sdns://AQcAAAAAAAAADzE5NC4xNjQuMTk0LjIxNiACT6z2dYj94msaKqctjIpBaeDHG2JVOfPTqDH_0KzZkBYyLmRuc2NyeXB0LWNlcnQuZGN0LWRl"),
    up("dct-fr", "dct", "sdns://AQcAAAAAAAAADTQ1LjE0Ny45OC4yMjMgxrLxuUBUIK0uhJptc75BSbkhou5kHDMi2p4AHf0zHgMWMi5kbnNjcnlwdC1jZXJ0LmRjdC1mcg"),
    up("nwps.fi", "nwps", "sdns://AQcAAAAAAAAAEzk1LjIxNi4xMzguMTQxOjg0NDMguorzbtc_JWEU0KBhGLZWuvInIeGd-R5CcEHYS-SIz7cXMi5kbnNjcnlwdC1jZXJ0Lm53cHMuZmk"),
    up("serbica", "serbica", "sdns://AQcAAAAAAAAAEzE4NS42Ni4xNDMuMTc4OjUzNTMg-Y2MQmGOXiggAEKulN-ITGEn_Kj3TIP1UK1X2wh3o7wXMi5kbnNjcnlwdC1jZXJ0LnNlcmJpY2E"),
    up("dnscry.pt-moscow-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADjkzLjE4My4xMDYuMjIyIBQ6uCceRUNVJGFB1kGltuW_Jr2Nsizvc06BfMI30iIBGTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
    up("dnscry.pt-frankfurt-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADDQ1LjgyLjEyMC42MSD79MPkuIliP7zrXMgYVK5wcSD_shP7dPfHx9haFaux6RkyLmRuc2NyeXB0LWNlcnQuZG5zY3J5LnB0"),
    up("dnscry.pt-helsinki-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADjM3LjIyOC4xMjkuMTYwIPlYPWSML8DlYbkp1ycL3CBER_3aJHp7GLvX_TRvbojGGTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
    up("dnscry.pt-amsterdam-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADjE5OC4xNDAuMTQxLjQ2IFqbafOxgXuKwOgYxQ6XUqHWkMUt_5LI2nDkdVFU5hm7GTIuZG5zY3J5cHQtY2VydC5kbnNjcnkucHQ"),
    up("dnscry.pt-warsaw-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADTE5NS4zLjIyMS4xNjIg9OBpbJKxZJGY-YUI3xWNXp-k_MgEzf9NFZruBsmXR7oZMi5kbnNjcnlwdC1jZXJ0LmRuc2NyeS5wdA"),
    up("dnscry.pt-istanbul-ipv4", "dnscry.pt", "sdns://AQcAAAAAAAAADzE4OC4xMzIuMTkyLjE2OCBcrSjt8C0Ztuqwxafp4VzylDf9N_disPrgL1m4GNX6XRkyLmRuc2NyeXB0LWNlcnQuZG5zY3J5LnB0"),
    up("cs-de", "cryptostorm", "sdns://AQcAAAAAAAAACzE0Ni43MC44Mi4zIDEzcq1ZVjLCQWuHLwmPhRvduWUoTGy-mk8ZCWQw26laHjIuZG5zY3J5cHQtY2VydC5jcnlwdG9zdG9ybS5pcw"),
    up("cs-finland", "cryptostorm", "sdns://AQcAAAAAAAAADTgzLjE0My4yNDIuNDMgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz"),
    up("cs-nl", "cryptostorm", "sdns://AQcAAAAAAAAADTE4NS4xMDcuODAuODQgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz"),
    ]
}

/// Посредники анонимного DNSCrypt.
#[must_use]
pub fn dnscrypt_relays() -> Vec<Upstream> {
    vec![
        up(
            "anon-cs-nl",
            "cryptostorm",
            "sdns://gRExODUuMTA3LjgwLjg0OjQ0Mw",
        ),
        up(
            "anon-cs-finland",
            "cryptostorm",
            "sdns://gRE4My4xNDMuMjQyLjQzOjQ0Mw",
        ),
        up(
            "anon-cs-de",
            "cryptostorm",
            "sdns://gQ8xNDYuNzAuODIuMzo0NDM",
        ),
        up(
            "anon-cs-poland",
            "cryptostorm",
            "sdns://gREzNy4xMjAuMjExLjkxOjQ0Mw",
        ),
        up(
            "anon-scaleway",
            "scaleway",
            "sdns://gRIyMTIuNDcuMjI4LjEzNjo0NDM",
        ),
        up(
            "anon-scaleway-ams",
            "scaleway",
            "sdns://gRE1MS4xNS4xMjIuMjUwOjQ0Mw",
        ),
        up(
            "anon-serbica",
            "serbica",
            "sdns://gRMxODUuNjYuMTQzLjE3ODo1MzUz",
        ),
        up("anon-kama", "kama", "sdns://gQ4xMzcuNzQuMjIzLjIzNA"),
        up(
            "anon-dnswarden-swiss",
            "dnswarden",
            "sdns://gRQxODguMjQ0LjExNy4xMTQ6MTQ0Mw",
        ),
        up(
            "dnscry.pt-anon-frankfurt02-ipv4",
            "dnscry.pt",
            "sdns://gQ00NS4xNDcuNTEuMTIz",
        ),
        up(
            "dnscry.pt-anon-helsinki-ipv4",
            "dnscry.pt",
            "sdns://gQ4zNy4yMjguMTI5LjE2MA",
        ),
        up(
            "dnscry.pt-anon-amsterdam-ipv4",
            "dnscry.pt",
            "sdns://gQ4xOTguMTQwLjE0MS40Ng",
        ),
        up(
            "dnscry.pt-anon-riga-ipv4",
            "dnscry.pt",
            "sdns://gQ8xOTUuMTIzLjIxMi4yMDA",
        ),
    ]
}

/// ODoH-серверы.
#[must_use]
pub fn odoh_servers() -> Vec<Upstream> {
    vec![
        up(
            "odoh-cloudflare",
            "cloudflare",
            "sdns://BQcAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk",
        ),
        up(
            "odoh-crypto-sx",
            "crypto.sx",
            "sdns://BQcAAAAAAAAADm9kb2guY3J5cHRvLnN4Ci9kbnMtcXVlcnk",
        ),
        up(
            "odoh-snowstorm",
            "snowstorm",
            "sdns://BQcAAAAAAAAAE2RvcGUuc25vd3N0b3JtLmxvdmUKL2Rucy1xdWVyeQ",
        ),
    ]
}

/// Посредники ODoH.
#[must_use]
pub fn odoh_relays() -> Vec<Upstream> {
    vec![
        up(
            "odohrelay-crypto-sx",
            "crypto.sx",
            "sdns://hQcAAAAAAAAAAAAab2RvaC1yZWxheS5lZGdlY29tcHV0ZS5hcHABLw",
        ),
        up(
            "odohrelay-numa",
            "numa",
            "sdns://hQcAAAAAAAAAAAASb2RvaC1yZWxheS5udW1hLnJzBi9yZWxheQ",
        ),
    ]
}

/// Через посредников Quad9 не отвечает — в анонимный режим не входит.
const NOT_ANONYMIZABLE: [&str; 1] = ["quad9"];

/// Свойства сервера в штампе (первый байт набора): проверяет подписи DNSSEC.
const PROP_DNSSEC: u64 = 1;
const STAMP_DOH: u8 = 0x02;

/// python `_lp(data)` — строка штампа: байт длины и сама строка.
fn lp(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() > 255 {
        return Err("слишком длинная строка для штампа DNS".to_string());
    }
    let mut out = Vec::with_capacity(data.len() + 1);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(out)
}

/// python `doh_stamp` — штамп `sdns://` сервера DoH: адрес, имя для
/// сертификата и путь запроса.
///
/// Адрес записан в самом штампе, поэтому имя сервера узнавать обычным DNS не
/// нужно: движок сразу идёт на адрес, а имя называет только для сертификата.
#[must_use]
pub fn doh_stamp(address: &str, host: &str, path: &str, port: u16, dnssec: bool) -> Option<String> {
    let target = if port == 443 {
        address.to_string()
    } else {
        format!("{address}:{port}")
    };
    let mut props = [0u8; 8];
    if dnssec {
        // python: (`_PROP_DNSSEC`).to_bytes(8, "little").
        props[0] = PROP_DNSSEC as u8;
    }
    // Отпечатков сертификата нет: один пустой элемент списка.
    let host = idna::domain_to_ascii(host).ok()?;
    let raw: Vec<u8> = [
        vec![STAMP_DOH],
        props.to_vec(),
        lp(target.as_bytes()).ok()?,
        vec![0x00],
        lp(host.as_bytes()).ok()?,
        lp(path.as_bytes()).ok()?,
    ]
    .concat();
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    Some(format!("sdns://{encoded}"))
}

/// python `doh_upstreams` — серверы режима [`MODE_DOH`] для одной плитки: по
/// одному на каждый её адрес IPv4.
///
/// Пусто — у плитки нет шаблона DoH или адреса IPv4 (движок ходит по IPv4),
/// значит через посредника её не поставить.
#[must_use]
pub fn doh_upstreams(doh_url: &str, addresses: &[String], dnssec: bool) -> Vec<Upstream> {
    let doh_url = doh_url.trim();
    let Some((scheme, rest)) = doh_url.split_once("://") else {
        return Vec::new();
    };
    if scheme != "https" {
        return Vec::new();
    }
    // python urlsplit: имя до «/», «?» или «#»; порт после «:» имени.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path_part = rest
        .get(authority_end..)
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let (host_raw, port) = split_host_port(authority);
    if host_raw.is_empty() {
        return Vec::new();
    }
    let host = host_raw.to_ascii_lowercase();
    let path = if path_part.is_empty() {
        "/dns-query"
    } else {
        path_part
    };
    let mut result: Vec<Upstream> = Vec::new();
    for address in addresses {
        let address = address.trim();
        if !is_ipv4(address) {
            continue;
        }
        let stamp = doh_stamp(address, &host, path, port, dnssec);
        let Some(stamp) = stamp else {
            continue;
        };
        result.push(up(&format!("doh-{}", result.len() + 1), &host, &stamp));
    }
    result
}

/// `имя[:порт]` из authority-части URL (python `urlsplit(...).hostname/.port`).
fn split_host_port(authority: &str) -> (&str, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 в скобках.
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(443);
            return (host, port);
        }
        return (authority, 443);
    }
    // Без скобок порт есть только когда «:» в адресе одно (IPv6 без скобок —
    // не адрес с портом, а само имя).
    if authority.matches(':').count() > 1 {
        return (authority, 443);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => {
            (host, port.parse().expect("проверено"))
        }
        _ => (authority, 443),
    }
}

/// Настоящий адрес IPv4 (python `ip_address(...).version == 4`).
#[must_use]
pub fn is_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|c| c.is_ascii_digit())
                && part.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// python `servers(mode, upstreams)` — серверы режима. У [`MODE_DOH`] своих
/// нет: их передают (`upstreams`).
pub fn servers(mode: &str, upstreams: &[Upstream]) -> Result<Vec<Upstream>, String> {
    match mode {
        MODE_DNSCRYPT => Ok(dnscrypt_servers()),
        MODE_ANONYMIZED => Ok(dnscrypt_servers()
            .into_iter()
            .filter(|item| !NOT_ANONYMIZABLE.contains(&item.operator.as_str()))
            .collect()),
        MODE_ODOH => Ok(odoh_servers()),
        MODE_DOH => {
            if upstreams.is_empty() {
                return Err("Для режима DoH не задан сервер".to_string());
            }
            Ok(upstreams.to_vec())
        }
        _ => Err(format!("Неизвестный режим шифрованного DNS: {mode}")),
    }
}

/// python `relays(mode)` — посредники режима; у обычного DNSCrypt их нет.
pub fn relays(mode: &str) -> Result<Vec<Upstream>, String> {
    match mode {
        MODE_ANONYMIZED => Ok(dnscrypt_relays()),
        MODE_ODOH => Ok(odoh_relays()),
        MODE_DNSCRYPT | MODE_DOH => Ok(Vec::new()),
        _ => Err(format!("Неизвестный режим шифрованного DNS: {mode}")),
    }
}

/// python `routes(mode)` — (сервер, его посредники): посредник всегда другого
/// владельца.
pub fn routes(mode: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    if mode == MODE_DOH {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for server in servers(mode, &[])? {
        let via: Vec<String> = relays(mode)?
            .into_iter()
            .filter(|relay| relay.operator != server.operator)
            .map(|relay| relay.name)
            .collect();
        if !via.is_empty() {
            result.push((server.name, via));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_match_python_counts() {
        assert_eq!(dnscrypt_servers().len(), 16);
        assert_eq!(dnscrypt_relays().len(), 13);
        assert_eq!(odoh_servers().len(), 3);
        assert_eq!(odoh_relays().len(), 2);
        // Первый штамп — Quad9 DNSCrypt, как в python-списке.
        assert_eq!(
            dnscrypt_servers()[0].name,
            "quad9-dnscrypt-ip4-nofilter-pri"
        );
        assert!(dnscrypt_servers()[0]
            .stamp
            .starts_with("sdns://AQcAAAAAAAAADTku"));
    }

    #[test]
    fn stamp_matches_python_reference() {
        // Эталоны python `doh_stamp` — дословно (base64url без хвоста).
        assert_eq!(
            doh_stamp("1.1.1.1", "cloudflare-dns.com", "/dns-query", 443, true).expect("штамп"),
            "sdns://AgEAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5"
        );
        assert_eq!(
            doh_stamp("2606:4700:4700::1111", "cloudflare-dns.com", "/dns-query", 443, false)
                .expect("штамп"),
            "sdns://AgAAAAAAAAAAFDI2MDY6NDcwMDo0NzAwOjoxMTExABJjbG91ZGZsYXJlLWRucy5jb20KL2Rucy1xdWVyeQ"
        );
        // Порт не 443 пишется в адрес штампа.
        assert_eq!(
            doh_stamp("9.9.9.11", "dns.quad9.net", "/dns-query", 8443, false).expect("штамп"),
            "sdns://AgAAAAAAAAAADTkuOS45LjExOjg0NDMADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ"
        );
    }

    #[test]
    fn upstreams_only_ipv4_with_template() {
        let items = doh_upstreams(
            "https://dns.example.com/dns-query",
            &[
                "1.1.1.1".to_string(),
                "2606:4700::1".to_string(),
                "плохо".to_string(),
            ],
            false,
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "doh-1");
        assert_eq!(items[0].operator, "dns.example.com");
        // Без шаблона или без адресов — пусто.
        assert!(doh_upstreams("", &["1.1.1.1".to_string()], false).is_empty());
        assert!(doh_upstreams("https://dns.example.com", &[], false).is_empty());
        assert!(
            doh_upstreams("http://dns.example.com", &["1.1.1.1".to_string()], false).is_empty()
        );
    }

    #[test]
    fn servers_and_routes_by_mode() {
        assert_eq!(servers(MODE_DNSCRYPT, &[]).expect("режим").len(), 16);
        // Quad9 не входит в анонимный режим.
        let anonymized = servers(MODE_ANONYMIZED, &[]).expect("режим");
        assert_eq!(anonymized.len(), 15);
        assert!(anonymized.iter().all(|item| item.operator != "quad9"));
        assert_eq!(servers(MODE_ODOH, &[]).expect("режим").len(), 3);
        assert!(servers(MODE_DOH, &[]).is_err());
        assert_eq!(
            servers(MODE_DOH, &[up("x", "op", "sdns://x")])
                .expect("режим")
                .len(),
            1
        );
        assert!(servers("нет", &[]).is_err());
        // Посредники DNSCrypt: пусто; анонимного — 13.
        assert!(relays(MODE_DNSCRYPT).expect("режим").is_empty());
        assert_eq!(relays(MODE_ANONYMIZED).expect("режим").len(), 13);
        // В маршрутах у каждого сервера посредник другого владельца.
        let pairs = routes(MODE_ANONYMIZED).expect("режим");
        assert_eq!(pairs.len(), 15);
        for (server, via) in pairs {
            assert!(!via.is_empty(), "{server}");
        }
        assert!(routes(MODE_DOH).expect("режим").is_empty());
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(split_host_port("dns.example.com"), ("dns.example.com", 443));
        assert_eq!(
            split_host_port("dns.example.com:8443"),
            ("dns.example.com", 8443)
        );
        assert_eq!(split_host_port("[2001:db8::1]:53"), ("2001:db8::1", 53));
        // IPv6 без скобок — имя без порта (порт у него разобрать нельзя).
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1", 443));
    }
}
