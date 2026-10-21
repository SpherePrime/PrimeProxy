//! Проверка своих доменов Cloudflare и воркеров; встроенный код воркера.
//!
//! Порт чистой части `telegram_proxy/proxy/cloudflare.py`. Сама проверка —
//! сетевое действие: она идёт через замыкание `connect`, крейт соединений не
//! открывает.

use crate::proxy::route_catalog::{CDN_FRONTS, WSS_PATH};
use crate::proxy::ws::WsTarget;

/// Настройки своего домена Cloudflare и своего воркера.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareFallbackConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub worker_enabled: bool,
    pub worker_domains: Vec<String>,
}

/// DNS-запись своего домена для DC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsRecord {
    pub dc: i32,
    pub host: &'static str,
    pub ip: &'static str,
}

/// Итог проверки одного хоста.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CloudflareCheckEntry {
    pub kind: String,
    pub host: String,
    pub path: String,
    pub ok: bool,
    pub error: String,
}

/// Итог проверки набора хостов.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CloudflareCheckResult {
    pub kind: String,
    pub entries: Vec<CloudflareCheckEntry>,
}

impl CloudflareCheckResult {
    /// Хотя бы один хост отвечает.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.entries.iter().any(|entry| entry.ok)
    }

    /// Сколько хостов проверено.
    #[must_use]
    pub fn checked(&self) -> usize {
        self.entries.len()
    }

    /// Сколько хостов отвечает.
    #[must_use]
    pub fn working(&self) -> usize {
        self.entries.iter().filter(|entry| entry.ok).count()
    }

    /// Сколько хостов не отвечает.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.checked() - self.working()
    }

    /// Короткий текст для пользователя.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.checked() == 0 {
            return "Нет доменов для проверки.".into();
        }
        if self.ok() {
            return format!("Работает: {} из {}.", self.working(), self.checked());
        }
        format!("Не отвечает: 0 из {}.", self.checked())
    }
}

/// DNS-записи для своего домена Cloudflare.
pub const CLOUDFLARE_DNS_RECORDS: &[CloudflareDnsRecord] = &[
    CloudflareDnsRecord {
        dc: 1,
        host: "kws1",
        ip: "149.154.175.50",
    },
    CloudflareDnsRecord {
        dc: 2,
        host: "kws2",
        ip: "149.154.167.51",
    },
    CloudflareDnsRecord {
        dc: 3,
        host: "kws3",
        ip: "149.154.175.100",
    },
    CloudflareDnsRecord {
        dc: 4,
        host: "kws4",
        ip: "149.154.167.91",
    },
    CloudflareDnsRecord {
        dc: 5,
        host: "kws5",
        ip: "149.154.171.5",
    },
    CloudflareDnsRecord {
        dc: 203,
        host: "kws203",
        ip: "91.105.192.100",
    },
];

/// Встроенные фронты: один список с routes.py (route_catalog.CDN_FRONTS).
#[must_use]
pub fn auto_cloudflare_domains() -> Vec<String> {
    CDN_FRONTS
        .iter()
        .map(|front| front.domain.to_string())
        .collect()
}

fn dns_record_by_dc(dc: i32) -> Option<&'static CloudflareDnsRecord> {
    CLOUDFLARE_DNS_RECORDS.iter().find(|record| record.dc == dc)
}

/// Код воркера Cloudflare (zastogram-ws-worker/worker.js) для своего домена.
#[must_use]
pub fn build_cfworker_code() -> String {
    CFWORKER_CODE.into()
}

const CFWORKER_CODE: &str = r#"import { connect } from "cloudflare:sockets";

function toBytes(data) {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }
  if (data && typeof data.arrayBuffer === "function") {
    return data.arrayBuffer().then((ab) => new Uint8Array(ab));
  }
  return new Uint8Array();
}

export default {
  async fetch(request) {
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/apiws") {
      return new Response("Not found", { status: 404 });
    }

    const dst = url.searchParams.get("dst");
    if (!dst) {
      return new Response("dst is required", { status: 400 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const socket = connect({ hostname: dst, port: 443 });
    const tcpWriter = socket.writable.getWriter();
    const tcpReader = socket.readable.getReader();

    server.addEventListener("message", async (event) => {
      try {
        await tcpWriter.write(await toBytes(event.data));
      } catch {
        try { server.close(1011, "tcp write failed"); } catch {}
      }
    });

    server.addEventListener("close", async () => {
      try { await tcpWriter.close(); } catch {}
      try { socket.close(); } catch {}
    });

    (async () => {
      try {
        for (;;) {
          const { value, done } = await tcpReader.read();
          if (done) {
            break;
          }
          if (value) {
            server.send(value);
          }
        }
      } catch {
      } finally {
        try { server.close(); } catch {}
        try { tcpReader.releaseLock(); } catch {}
        try { socket.close(); } catch {}
      }
    })();

    return new Response(null, { status: 101, webSocket: client });
  },
};
"#;

/// Домен годится для настроек Cloudflare: точечные метки, латиница, не односимвольный TLD.
#[must_use]
fn is_valid_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in labels.iter() {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    labels[labels.len() - 1].len() >= 2
        && labels[labels.len() - 1]
            .bytes()
            .any(|byte| byte.is_ascii_alphabetic())
}

/// Список доменов из строки или коллекции: запятые, точки с запятой и пробелы.
#[must_use]
pub fn normalize_domain_list(items: &[String]) -> Vec<String> {
    let mut raw_items: Vec<String> = Vec::new();
    for item in items {
        for piece in item.replace([',', ';'], " ").split(' ') {
            if !piece.is_empty() {
                raw_items.push(piece.to_string());
            }
        }
    }
    let mut result: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in raw_items {
        let domain = item.trim().to_lowercase();
        if !seen.insert(domain.clone()) || !is_valid_domain(&domain) {
            continue;
        }
        result.push(domain);
    }
    result
}

/// Путь запроса к воркеру: /apiws?dst=<ip>&dc=<dc>.
#[must_use]
pub fn build_worker_path(dst: &str, dc: i32) -> String {
    format!(
        "{WSS_PATH}?dst={}&dc={}",
        crate::proxy::mtproxy::urlencode(dst),
        dc
    )
}

/// Текст с DNS-записями для своего домена Cloudflare.
#[must_use]
pub fn build_cfproxy_dns_records_text() -> String {
    let mut lines = vec![
        "DNS-записи Cloudflare для своего домена:".to_string(),
        String::new(),
        "Тип: A".to_string(),
        "Статус прокси: включён (Proxied)".to_string(),
        String::new(),
    ];
    for record in CLOUDFLARE_DNS_RECORDS {
        lines.push(format!("{} A {}", record.host, record.ip));
    }
    lines.join("\n")
}

/// Цели проверки: (хост, путь) по виду проверки и доменам.
#[must_use]
pub fn probe_targets(kind: &str, domains: &[String], dcs: &[i32]) -> Vec<(String, String)> {
    let normalized_kind = kind.trim().to_lowercase();
    let mut normalized_domains = normalize_domain_list(domains);
    if normalized_kind == "domain" && normalized_domains.is_empty() {
        normalized_domains = auto_cloudflare_domains();
    }
    if normalized_domains.is_empty() {
        return Vec::new();
    }
    let mut targets = Vec::new();
    for domain in &normalized_domains {
        if normalized_kind == "worker" {
            for dc in dcs {
                if let Some(record) = dns_record_by_dc(*dc) {
                    targets.push((domain.clone(), build_worker_path(record.ip, record.dc)));
                }
            }
            continue;
        }
        for dc in dcs {
            if let Some(record) = dns_record_by_dc(*dc) {
                targets.push((format!("{}.{}", record.host, domain), "/apiws".to_string()));
            }
        }
    }
    targets
}

/// Проверяет доступность доменов/воркеров через замыкание подключения.
///
/// Замыкание получает цель (`WsTarget`) и таймаут и возвращает ошибку строкой.
/// В python-версии проверки идут параллельно; решения и тексты те же.
#[must_use]
pub fn check_cloudflare_connectivity(
    kind: &str,
    domains: &[String],
    dcs: &[i32],
    timeout: f64,
    connect: &dyn Fn(&WsTarget, f64) -> Result<(), String>,
) -> CloudflareCheckResult {
    let normalized_kind = match kind.trim().to_lowercase().as_str() {
        "worker" => "worker".to_string(),
        "domain" => "domain".to_string(),
        _ => "domain".to_string(),
    };
    let targets = probe_targets(&normalized_kind, domains, dcs);
    let mut entries = Vec::new();
    for (host, path) in targets {
        let target = WsTarget {
            connect_host: host.clone(),
            sni: host.clone(),
            path: path.clone(),
            port: 443,
        };
        match connect(&target, timeout) {
            Ok(()) => entries.push(CloudflareCheckEntry {
                kind: normalized_kind.clone(),
                host,
                path,
                ok: true,
                error: String::new(),
            }),
            Err(error) => entries.push(CloudflareCheckEntry {
                kind: normalized_kind.clone(),
                host,
                path,
                ok: false,
                error,
            }),
        }
    }
    CloudflareCheckResult {
        kind: normalized_kind,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation_follows_python_rules() {
        // python3 -c "
        // import sys; sys.path.insert(0, '/home/kalinov/Документы/zapretgui/src')
        // from telegram_proxy.proxy.cloudflare import _is_valid_domain, normalize_domain_list
        // print(_is_valid_domain('a.co'), _is_valid_domain('a.c'), _is_valid_domain('-a.co'),
        //       _is_valid_domain('a-.co'), _is_valid_domain('single'), _is_valid_domain('bad..d'))"
        assert!(is_valid_domain("pclead.co.uk"));
        assert!(is_valid_domain("a.co"));
        assert!(!is_valid_domain("a.c"));
        assert!(!is_valid_domain("-a.co"));
        assert!(!is_valid_domain("a-.co"));
        assert!(!is_valid_domain("single"));
        assert!(!is_valid_domain("bad..d"));
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn normalize_domain_list_splits_and_deduplicates() {
        // python3 -c "...; print(normalize_domain_list('a.co, b.co; a.co; BAD..D'))"
        let items: Vec<String> = vec!["a.co, b.co; a.co; BAD..D".into()];
        assert_eq!(
            normalize_domain_list(&items),
            vec!["a.co".to_string(), "b.co".to_string()]
        );
        assert!(normalize_domain_list(&[]).is_empty());
    }

    #[test]
    fn worker_path_matches_python_urlencode() {
        // python3 -c "
        // import sys; sys.path.insert(0, '/home/kalinov/Документы/zapretgui/src')
        // from telegram_proxy.proxy.cloudflare import build_worker_path
        // print(build_worker_path('149.154.167.51', 2))"
        assert_eq!(
            build_worker_path("149.154.167.51", 2),
            "/apiws?dst=149.154.167.51&dc=2"
        );
    }

    #[test]
    fn dns_records_text_lists_all_records() {
        let text = build_cfproxy_dns_records_text();
        assert!(text.starts_with("DNS-записи Cloudflare для своего домена:"));
        assert!(text.contains("kws2 A 149.154.167.51"));
        assert!(text.contains("kws203 A 91.105.192.100"));
        assert_eq!(text.matches(" A ").count(), 6);
    }

    #[test]
    fn worker_code_is_the_zastogram_worker() {
        let code = build_cfworker_code();
        assert!(code.contains("cloudflare:sockets"));
        assert!(code.contains("dst is required"));
        assert!(code.contains("status: 101"));
    }

    #[test]
    fn probe_targets_cover_all_dcs() {
        // python3 -c "import sys; sys.path.insert(0, '/home/kalinov/Документы/zapretgui/src');
        //   from telegram_proxy.proxy.cloudflare import _probe_targets;
        //   t=_probe_targets('domain', [], (1,2,203)); print(len(t), t[0], t[1])"
        // → 60 ('kws1.pclead.co.uk', '/apiws') ('kws2.pclead.co.uk', '/apiws')
        let targets = probe_targets("domain", &[], &[1, 2, 203]);
        assert_eq!(targets.len(), 60);
        assert_eq!(
            targets[0],
            ("kws1.pclead.co.uk".to_string(), "/apiws".to_string())
        );
        assert_eq!(
            targets[1],
            ("kws2.pclead.co.uk".to_string(), "/apiws".to_string())
        );
        let worker_targets = probe_targets("worker", &["w.example.dev".to_string()], &[2]);
        assert_eq!(
            worker_targets,
            vec![(
                "w.example.dev".to_string(),
                "/apiws?dst=149.154.167.51&dc=2".to_string()
            )]
        );
        assert!(probe_targets("worker", &[], &[1]).is_empty());
    }

    #[test]
    fn connectivity_check_collects_entries_and_summary() {
        // Один явный домен → по записи на каждый DC (как в python при непустом списке).
        let result = check_cloudflare_connectivity(
            "domain",
            &["pclead.co.uk".to_string()],
            &[1, 2],
            6.0,
            &|target, _timeout| {
                if target.sni.starts_with("kws1.") {
                    Err("timeout".into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.entries.len(), 2);
        assert!(!result.entries[0].ok);
        assert_eq!(result.entries[0].error, "timeout");
        assert!(result.entries[1].ok);
        assert!(result.ok());
        assert_eq!(result.working(), 1);
        assert_eq!(result.failed(), 1);
        assert_eq!(result.summary(), "Работает: 1 из 2.");

        let all_fail = check_cloudflare_connectivity(
            "domain",
            &["pclead.co.uk".to_string()],
            &[1],
            1.0,
            &|_, _| Err("x".into()),
        );
        assert_eq!(all_fail.summary(), "Не отвечает: 0 из 1.");
        let empty = CloudflareCheckResult {
            kind: "domain".into(),
            entries: Vec::new(),
        };
        assert_eq!(empty.summary(), "Нет доменов для проверки.");
    }

    #[test]
    fn unknown_kind_falls_back_to_domain() {
        let result = check_cloudflare_connectivity("???", &[], &[], 1.0, &|_, _| Ok(()));
        assert_eq!(result.kind, "domain");
        assert!(result.entries.is_empty());
    }
}
