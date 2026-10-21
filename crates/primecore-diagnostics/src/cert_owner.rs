//! Порт `src/diagnostics/cert_owner.py` — кто ответил вместо сайта: чей
//! сертификат пришёл, когда он не прошёл проверку.
//!
//! «Чужой сертификат» — не блокировка: соединение установилось, но с кем-то
//! другим. Что делать, зависит от того, кто это, и по одной ошибке проверки
//! этого не понять. Сертификат запрашивается ещё раз без проверки (`collect`,
//! сетевая часть с TLS-клиентом, портируется следом) и читается как справка
//! (`utils.cert_reader`, будет отдельным модулем). Здесь — чистая часть:
//! вывод `judge` по прочитанным именам сертификата.

pub const TIMEOUT_S: f64 = 4.0;

pub const CERT_ANTIVIRUS: &str = "antivirus";
pub const CERT_DEBUG_PROXY: &str = "debug_proxy";
pub const CERT_STATE: &str = "state_ca";
pub const CERT_HOSTS: &str = "hosts";
pub const CERT_OTHER_SITE: &str = "other_site";
pub const CERT_SELF_SIGNED: &str = "self_signed";
pub const CERT_UNKNOWN_ISSUER: &str = "unknown_issuer";
/// Сертификат прочитать не удалось: кто ответил, неизвестно.
pub const CERT_UNKNOWN: &str = "unknown";

/// Слово в имени издателя → как назвать программу. Порядок важен: первое совпадение.
const ANTIVIRUS: [(&str, &str); 19] = [
    ("kaspersky", "Kaspersky"),
    ("eset", "ESET"),
    ("avast", "Avast"),
    ("avg ", "AVG"),
    ("bitdefender", "Bitdefender"),
    ("dr.web", "Dr.Web"),
    ("drweb", "Dr.Web"),
    ("adguard", "AdGuard"),
    ("norton", "Norton"),
    ("mcafee", "McAfee"),
    ("sophos", "Sophos"),
    ("fortinet", "Fortinet (фильтр сети)"),
    ("fortigate", "Fortinet (фильтр сети)"),
    ("zscaler", "Zscaler (фильтр сети)"),
    ("netskope", "Netskope (фильтр сети)"),
    ("cisco umbrella", "Cisco Umbrella (фильтр сети)"),
    ("kerio", "Kerio (фильтр сети)"),
    ("usergate", "UserGate (фильтр сети)"),
    ("traffic inspector", "Traffic Inspector (фильтр сети)"),
];
const DEBUG_PROXIES: [(&str, &str); 7] = [
    ("fiddler", "Fiddler"),
    ("mitmproxy", "mitmproxy"),
    ("charles proxy", "Charles"),
    ("burp", "Burp Suite"),
    ("portswigger", "Burp Suite"),
    ("http toolkit", "HTTP Toolkit"),
    ("proxyman", "Proxyman"),
];
const STATE_CA: [&str; 1] = ["russian trusted"];

/// python `utils.cert_reader.CertNames` — что прочитано из сертификата.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertNames {
    pub issuer: String,
    pub issuer_org: String,
    pub subject: String,
    /// Организация владельца (python `subject_org`).
    pub subject_org: String,
    pub names: Vec<String>,
    pub self_signed: bool,
}

/// python `CertVerdict`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertVerdict {
    pub code: String,
    /// Одной фразой: кто ответил вместо сайта.
    pub text: String,
    /// Что с этим делать. Пусто — совет общий.
    pub advice: String,
    /// Что написано в сертификате — для подробностей.
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
}

impl CertVerdict {
    fn with_facts(mut self, subject: String, issuer: String, names: Vec<String>) -> Self {
        self.subject = subject;
        self.issuer = issuer;
        self.names = names;
        self
    }
}

const ADVICE_HOSTS: &str =
    "Адрес этого сайта записан в файле hosts и больше не подходит: сервер-посредник сменился или перестал \
     работать. Откройте «Редактор hosts», выключите и снова включите этот сервис или выберите для него \
     другой профиль — запишется рабочий адрес.";
const ADVICE_ROAD: &str =
    "Так выглядит заглушка провайдера или перехват соединения по дороге. Включите шифрованный DNS \
     («Настройка DNS») и проверьте, не включён ли в системе прокси.";

fn known(issuer: &str, table: &[(&str, &str)]) -> String {
    if let Some((_, title)) = table
        .iter()
        .find(|(word, _)| format!("{issuer} ").to_lowercase().contains(word))
    {
        title.to_string()
    } else {
        String::new()
    }
}

fn covers(names: &[String], host: &str) -> bool {
    let host = host.to_lowercase().trim_end_matches('.').to_string();
    for name in names {
        if *name == host {
            return true;
        }
        if let Some(pattern) = name.strip_prefix("*.") {
            let (_, rest) = host.split_once('.').unwrap_or(("", ""));
            if host.matches('.').count() >= 2 && rest == pattern {
                return true;
            }
        }
    }
    false
}

/// python `judge(cert, host, problem='', from_hosts=False)` — кто ответил вместо сайта.
pub fn judge(cert: Option<&CertNames>, host: &str, problem: &str, from_hosts: bool) -> CertVerdict {
    let problem = problem.to_string();
    let Some(cert) = cert else {
        return CertVerdict {
            code: CERT_UNKNOWN.to_string(),
            text: format!(
                "вместо сайта отвечает кто-то другой ({}); прочитать сам сертификат не удалось",
                if problem.is_empty() {
                    "сертификат не прошёл проверку"
                } else {
                    &problem
                }
            ),
            ..Default::default()
        };
    };
    let issuer = if cert.issuer.is_empty() && cert.issuer_org.is_empty() {
        "не указан".to_string()
    } else {
        let mut parts = Vec::new();
        if !cert.issuer.is_empty() {
            parts.push(cert.issuer.clone());
        }
        if !cert.issuer_org.is_empty() {
            parts.push(cert.issuer_org.clone());
        }
        parts.join(" / ")
    };
    let subject = if cert.subject.is_empty() {
        cert.names
            .first()
            .cloned()
            .unwrap_or_else(|| "не указан".to_string())
    } else {
        cert.subject.clone()
    };
    let set_facts = |verdict: CertVerdict| {
        verdict.with_facts(subject.clone(), issuer.clone(), cert.names.clone())
    };

    let antivirus = known(&issuer, &ANTIVIRUS);
    if !antivirus.is_empty() {
        return set_facts(CertVerdict {
            code: CERT_ANTIVIRUS.to_string(),
            text: format!(
                "шифрованное соединение просматривает {antivirus}: сертификат выдан им, а не сайту"
            ),
            advice: format!(
                "Это не блокировка провайдера. В настройках {antivirus} отключите проверку защищённых (HTTPS/SSL) \
                 соединений или добавьте сайт в исключения — иначе браузер будет считать сайт подделкой.",
            ),
            ..Default::default()
        });
    }
    let proxy = known(&issuer, &DEBUG_PROXIES);
    if !proxy.is_empty() {
        return set_facts(CertVerdict {
            code: CERT_DEBUG_PROXY.to_string(),
            text: format!(
                "между компьютером и сайтом стоит отладочный прокси {proxy}: сертификат выдан им"
            ),
            advice: format!("Закройте {proxy} или уберите его из настроек прокси Windows."),
            ..Default::default()
        });
    }
    if format!("{issuer} ").to_lowercase().contains(STATE_CA[0]) {
        return set_facts(CertVerdict {
            code: CERT_STATE.to_string(),
            text: format!(
                "сайт отдаёт сертификат российского государственного центра ({})",
                cert.issuer
            ),
            advice: (
                "Это не перехват: сайт сам перешёл на такой сертификат. Браузер примет его после установки \
                 корневого сертификата Минцифры, либо откройте сайт в Яндекс Браузере."
            )
                .to_string(),
            ..Default::default()
        });
    }
    if cert.self_signed {
        let (where_text, advice) = if from_hosts {
            (
                "запись в файле hosts ведёт на сервер, который",
                ADVICE_HOSTS,
            )
        } else {
            ("вместо сайта отвечает сервер, который", ADVICE_ROAD)
        };
        return set_facts(CertVerdict {
            code: CERT_SELF_SIGNED.to_string(),
            text: format!(
                "{where_text} показывает самодельный сертификат (выдан сам себе: {subject})"
            ),
            advice: advice.to_string(),
            ..Default::default()
        });
    }
    if !cert.names.is_empty() && !covers(&cert.names, host) {
        let shown = cert
            .names
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
            + if cert.names.len() > 3 {
                " и другим"
            } else {
                ""
            };
        let (code, where_text, advice) = if from_hosts {
            (
                CERT_HOSTS,
                "запись в файле hosts ведёт на чужой сервер",
                ADVICE_HOSTS,
            )
        } else {
            (
                CERT_OTHER_SITE,
                "вместо сайта отвечает чужой сервер",
                ADVICE_ROAD,
            )
        };
        return set_facts(CertVerdict {
            code: code.to_string(),
            text: format!(
                "{}: его сертификат выдан сайту {shown}, а не {host}",
                where_text
            ),
            advice: advice.to_string(),
            ..Default::default()
        });
    }
    set_facts(CertVerdict {
        code: CERT_UNKNOWN_ISSUER.to_string(),
        text: format!(
            "сертификат сайта не прошёл проверку ({}); выдан: {issuer}",
            if problem.is_empty() { "причина не названа" } else { &problem }
        ),
        advice: (
            "Проверьте дату и время Windows: при неверных часах любой сертификат выглядит просроченным. \
             Если часы верны — соединение перехватывает программа на компьютере или сеть."
        )
            .to_string(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Транспорт: сертификат без проверки (python `cert_owner.collect`)
// ---------------------------------------------------------------------------

use crate::block_cause::{tls_stream, TLS_ANY};
use crate::cert_reader::read_names;
use primecore_socketcancel::SocketCancel;

/// python `collect(host, ip, cancel)` — сертификат, который отдаёт адрес `ip`
/// для сайта `host`, — без проверки. None — получить не удалось.
pub fn collect(host: &str, ip: &str, cancel: &SocketCancel) -> Option<CertNames> {
    collect_with_port(host, ip, 443, cancel)
}

/// То же с явным портом — для живых тестов на локальном сервере.
pub fn collect_with_port(
    host: &str,
    ip: &str,
    port: u16,
    cancel: &SocketCancel,
) -> Option<CertNames> {
    if cancel.cancelled() {
        return None;
    }
    let secured = tls_stream(ip, Some(host), port, TIMEOUT_S, cancel, TLS_ANY).ok()?;
    // Сертификат сервера лежит в установленном соединении.
    let certificates = secured.conn.peer_certificates()?;
    let der = certificates.first()?.as_ref().to_vec();
    read_names(Some(&der))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(issuer: &str, subject: &str, items: &[&str], self_signed: bool) -> CertNames {
        CertNames {
            issuer: issuer.to_string(),
            issuer_org: String::new(),
            subject: subject.to_string(),
            subject_org: String::new(),
            names: items.iter().map(|item| item.to_string()).collect(),
            self_signed,
        }
    }

    #[test]
    fn verdict_codes() {
        assert!(judge(None, "ya.ru", "", false)
            .text
            .contains("прочитать сам сертификат не удалось"));
        let site = names("Let's Encrypt", "ya.ru", &["ya.ru"], false);
        assert_eq!(
            judge(Some(&site), "ya.ru", "", false).code,
            CERT_UNKNOWN_ISSUER
        );
        assert_eq!(
            judge(
                Some(&names("Kaspersky Helper", "site", &[], false)),
                "ya.ru",
                "",
                false
            )
            .code,
            CERT_ANTIVIRUS
        );
        assert_eq!(
            judge(
                Some(&names("The mitmproxy CA", "", &[], false)),
                "ya.ru",
                "",
                false
            )
            .code,
            CERT_DEBUG_PROXY
        );
        assert_eq!(
            judge(
                Some(&names("Russian Trusted CA", "", &[], false)),
                "ya.ru",
                "",
                false
            )
            .code,
            CERT_STATE
        );
    }

    #[test]
    fn self_signed_and_other_site() {
        let quiet = names("", "", &[], true);
        let verdict = judge(Some(&quiet), "site.example", "", false);
        assert_eq!(verdict.code, CERT_SELF_SIGNED);
        assert!(verdict
            .text
            .starts_with("вместо сайта отвечает сервер, который"));
        let verdict = judge(Some(&quiet), "site.example", "", true);
        assert!(verdict
            .text
            .starts_with("запись в файле hosts ведёт на сервер, который"));
        assert!(!verdict.advice.is_empty());
        let other = names(
            "",
            "",
            &["other.example", "extra.example", "ab.example", "cd.example"],
            false,
        );
        assert_eq!(
            judge(Some(&other), "site.example", "", false).code,
            CERT_OTHER_SITE
        );
        assert_eq!(
            judge(Some(&other), "site.example", "", true).code,
            CERT_HOSTS
        );
    }

    #[test]
    fn wildcard_covers() {
        assert!(covers(&["cdn.example".to_string()], "cdn.example"));
        // Python сравнивает хвост с первым убранным узлом: «*.subs.example»
        // закрывает «a.subs.example», но не «ya.example» (там только одна точка).
        assert!(!covers(&["*.example".to_string()], "ya.example"));
        assert!(covers(&["*.subs.example".to_string()], "a.subs.example"));
    }
    // --- Живая проверка: сертификат читается из локального TLS-сервера ---

    use std::net::TcpListener;
    use std::sync::Arc;

    /// Локальный TLS-сервер с самоподписанным сертификатом на example.test.
    fn spawn_tls_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
        let port = listener.local_addr().expect("адрес").port();
        let certified = rcgen::generate_simple_self_signed(vec!["example.test".to_string()])
            .expect("сертификат");
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("версии сервера доступны")
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
            )
            .expect("конфиг сервера собран"),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                let Ok(mut server) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                for _ in 0..10 {
                    if server.complete_io(&mut stream).is_ok() {
                        break;
                    }
                }
            }
        });
        port
    }

    #[test]
    fn collect_reads_names_without_verification() {
        let port = spawn_tls_server();
        let cancel = SocketCancel::new();
        let names = collect_with_port("example.test", "127.0.0.1", port, &cancel)
            .expect("сертификат прочитан");
        assert_eq!(names.names, vec!["example.test".to_string()]);
        assert!(names.self_signed);
        assert!(!names.subject.is_empty() || !names.names.is_empty());

        // По адресу без сервера — None, а не сбой машины прогона.
        let listener = TcpListener::bind("127.0.0.1:0").expect("сокет");
        let dead = listener.local_addr().expect("адрес").port();
        drop(listener);
        assert!(collect_with_port("example.test", "127.0.0.1", dead, &cancel).is_none());
    }
}
