//! Адреса входа веб-релеев Telegram, фронты Cloudflare и воркеры-туннели.
//!
//! Порт `telegram_proxy/proxy/route_catalog.py`. Адреса те же, что в ZaStoGram
//! (jni/tgnet/wss/WssSocket.cpp, OfficialRelayIngresses). Новый адрес — строка
//! здесь и в обоих клиентах.

/// Путь WebSocket-upgrade на релеях и фронтах.
pub const WSS_PATH: &str = "/apiws";

/// Адреса входа веб-релеев Telegram (kwsN.web.telegram.org/apiws).
///
/// Каждый адрес обслуживает только свои DC: на чужое имя адрес DC2/DC4
/// отвечает 302 с X-Redirect-Host, адрес DC1/DC3 молчит. У DC2/DC4 адресов
/// два: 149.154.167.99 отдаёт DNS, 149.154.167.220 месяцами держали зашитым
/// все клиенты. Провайдер, закрывший один по IP, оставляет второй.
#[must_use]
pub fn relay_addresses(dc: i32) -> &'static [&'static str] {
    match dc {
        1 => &["149.154.174.100"],
        2 | 4 => &["149.154.167.220", "149.154.167.99"],
        3 => &["149.154.174.100"],
        5 => &["149.154.170.100"],
        _ => &[],
    }
}

/// Имя релея: kwsN для обычных соединений, kwsN-1 для медиа.
#[must_use]
pub fn relay_domain(dc: i32, is_media: bool) -> String {
    format!(
        "kws{dc}{}.web.telegram.org",
        if is_media { "-1" } else { "" }
    )
}

/// Фронт Cloudflare: домен зоны и два её адреса (104.21.x и 172.67.x).
///
/// Хост для DC строится как kwsN.<domain>; SNI и Host совпадают с ним (это не
/// domain fronting). Подключение идёт сразу по адресу, без DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnFront {
    pub domain: &'static str,
    pub addresses: [&'static str; 2],
}

impl CdnFront {
    /// Хост DC на этом фронте.
    #[must_use]
    pub fn host_for(&self, dc: i32) -> String {
        format!("kws{dc}.{}", self.domain)
    }
}

/// Фронты tg-ws-proxy (github.com/Flowseal/tg-ws-proxy) в том же порядке, что
/// и в ZaStoGram (jni/tgnet/wss/WssSocket.cpp, kCdnFronts).
pub const CDN_FRONTS: &[CdnFront] = &[
    CdnFront {
        domain: "pclead.co.uk",
        addresses: ["104.21.80.254", "172.67.155.165"],
    },
    CdnFront {
        domain: "offshor.co.uk",
        addresses: ["104.21.43.90", "172.67.177.105"],
    },
    CdnFront {
        domain: "cakeisalie.co.uk",
        addresses: ["104.21.41.25", "172.67.159.17"],
    },
    CdnFront {
        domain: "noskomnadzor.co.uk",
        addresses: ["104.21.70.196", "172.67.138.236"],
    },
    CdnFront {
        domain: "lovetrue.co.uk",
        addresses: ["104.21.21.168", "172.67.199.162"],
    },
    CdnFront {
        domain: "sorokdva.co.uk",
        addresses: ["104.21.69.145", "172.67.209.89"],
    },
    CdnFront {
        domain: "pyatdesyatdva.co.uk",
        addresses: ["104.21.73.83", "172.67.189.26"],
    },
    CdnFront {
        domain: "kartoshka.co.uk",
        addresses: ["104.21.39.36", "172.67.142.232"],
    },
    CdnFront {
        domain: "sorokodin.co.uk",
        addresses: ["104.21.84.223", "172.67.197.117"],
    },
    CdnFront {
        domain: "pyatdesyatodin.co.uk",
        addresses: ["104.21.48.178", "172.67.155.85"],
    },
    CdnFront {
        domain: "notelega.co.uk",
        addresses: ["104.21.33.146", "172.67.146.105"],
    },
    CdnFront {
        domain: "ebally.co.uk",
        addresses: ["104.21.78.6", "172.67.214.68"],
    },
    CdnFront {
        domain: "nebally.co.uk",
        addresses: ["104.21.7.253", "172.67.156.145"],
    },
    CdnFront {
        domain: "havegreatday.co.uk",
        addresses: ["104.21.25.159", "172.67.134.93"],
    },
    CdnFront {
        domain: "pomogite.co.uk",
        addresses: ["104.21.44.55", "172.67.195.218"],
    },
    CdnFront {
        domain: "fixtelega.co.uk",
        addresses: ["104.21.64.155", "172.67.152.37"],
    },
    CdnFront {
        domain: "sadnews.co.uk",
        addresses: ["104.21.51.133", "172.67.180.160"],
    },
    CdnFront {
        domain: "onedaychamp.co.uk",
        addresses: ["104.21.37.105", "172.67.207.129"],
    },
    CdnFront {
        domain: "stopblocking.co.uk",
        addresses: ["104.21.35.206", "172.67.179.145"],
    },
    CdnFront {
        domain: "nothingthere.co.uk",
        addresses: ["104.21.78.5", "172.67.214.67"],
    },
];

/// Фронты несут DC1–DC5 и DC203: у DC203 (медиа без Premium) нет веб-релея
/// Telegram, но kws203.<домен фронта> отвечает настоящим resPQ.
pub const CDN_FRONT_DCS: &[i32] = &[1, 2, 3, 4, 5, 203];

/// Туннель через воркеры Cloudflare (zastogram-ws-worker/worker.js):
/// wss://<host>/apiws?dst=<IPv4 DC>, дальше воркер идёт на DC обычным TCP.
/// Воркеры лежат на разных учётных записях Cloudflare: у бесплатной записи
/// 100 000 запросов в сутки, после них воркер до 00:00 UTC отвечает 429.
pub const TUNNEL_HOSTS: &[&str] = &[
    "edge.amberwick.workers.dev",
    "fuckyourkn.copperbrook.workers.dev",
    "nodeone.brackencombe.workers.dev",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_addresses_match_python_catalog() {
        // python3 -c "
        // import sys; sys.path.insert(0, '/home/kalinov/Документы/zapretgui/src')
        // from telegram_proxy.proxy.route_catalog import RELAY_INGRESS
        // print(RELAY_INGRESS)"
        assert_eq!(relay_addresses(1), &["149.154.174.100"]);
        assert_eq!(relay_addresses(2), &["149.154.167.220", "149.154.167.99"]);
        assert_eq!(relay_addresses(3), &["149.154.174.100"]);
        assert_eq!(relay_addresses(4), &["149.154.167.220", "149.154.167.99"]);
        assert_eq!(relay_addresses(5), &["149.154.170.100"]);
        assert!(relay_addresses(203).is_empty());
    }

    #[test]
    fn relay_domain_uses_minus_one_for_media() {
        assert_eq!(relay_domain(2, false), "kws2.web.telegram.org");
        assert_eq!(relay_domain(4, true), "kws4-1.web.telegram.org");
    }

    #[test]
    fn front_hosts_and_counts_match_python() {
        assert_eq!(CDN_FRONTS.len(), 20);
        assert_eq!(CDN_FRONT_DCS, &[1, 2, 3, 4, 5, 203]);
        assert_eq!(CDN_FRONTS[0].host_for(2), "kws2.pclead.co.uk");
        assert_eq!(CDN_FRONTS[0].addresses, ["104.21.80.254", "172.67.155.165"]);
        assert_eq!(TUNNEL_HOSTS.len(), 3);
        assert_eq!(WSS_PATH, "/apiws");
    }
}
