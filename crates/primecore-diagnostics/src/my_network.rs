//! Порт `src/diagnostics/my_network.py` — ваша сеть: под каким адресом вас
//! видит интернет и чей это провайдер.
//!
//! Зачем это в проверке:
//! - отчёт без провайдера мало что говорит: блокировки у операторов разные;
//! - если снаружи виден адрес чужой сети (VPN, прокси), вся проверка описывает
//!   сеть вместе с ним — об этом нужно сказать сразу;
//! - адрес компьютера из диапазона 100.64.0.0/10 значит, что провайдер держит
//!   вас за общим адресом (так устроены мобильные и многие домашние сети).
//!
//! Внешний адрес спрашивается у Cloudflare по его собственному адресу, без DNS:
//! страница `/cdn-cgi/trace` отвечает строками `ip=…`, `loc=…`. Владелец сети
//! узнаётся по службе Team Cymru шифрованным запросом ([`crate::ip_owner`]).
//!
//! Связь внутри своей сети. Сбой проверки сайта часто даёт не провайдер, а
//! слабый Wi‑Fi или второй роутер. Поэтому меряется по пять пингов до трёх
//! точек: до роутера (первый узел), до узла сразу за ним и до сервера в
//! интернете. Потери до роутера — беда дома, потери только дальше — у провайдера.
//!
//! Здесь только сбор фактов и чистый вывод; чем ходить в сеть, решает вызывающий.

use crate::address_kinds::{address_kind, AddressKind};
use crate::ip_owner::IpOwner;

/// Хост для служебного запроса «кто я».
pub const TRACE_HOST: &str = "one.one.one.one";
/// Путь для служебного запроса «кто я» (Cloudflare).
pub const TRACE_PATH: &str = "/cdn-cgi/trace";
/// Два адреса одного владельца: провайдер иногда закрывает один из них.
pub const TRACE_SERVERS: [&str; 2] = ["1.1.1.1", "1.0.0.1"];

pub const PING_COUNT: usize = 5;
pub const PING_TIMEOUT_MS: u32 = 1000;
/// Срок жизни пакета, которого хватает до любого сервера.
pub const FAR_TTL: u32 = 64;
/// Роутер в своей комнате отвечает за единицы миллисекунд; дольше — слабый Wi‑Fi.
pub const SLOW_ROUTER_MS: f64 = 30.0;
/// Сколько потерянных из пяти — уже не случайность.
pub const LOSS_LIMIT: u32 = 2;

/// Несколько пингов до одной точки дороги.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HopSample {
    /// Адрес узла, который ответил (первый из ответивших).
    pub address: String,
    pub sent: u32,
    pub answered: u32,
    pub avg_ms: Option<f64>,
}

impl HopSample {
    /// Сколько отправленных пакетов не доехало.
    #[must_use]
    pub fn lost(&self) -> u32 {
        self.sent.saturating_sub(self.answered)
    }
}

/// Замер пинга: `probe(срок жизни)` → `(адрес ответившего, время)` или `None`, если
/// ответа нет, — и `None` целиком, если пинг в системе недоступен.
pub type Prober<'a> = dyn Fn(u32) -> Option<(String, Option<f64>)> + 'a;

/// Пять пингов с этим сроком жизни пакета: адрес, потери и среднее время.
pub fn measure_hop(probe: &Prober, ttl: u32) -> Option<HopSample> {
    measure_hop_count(probe, ttl, PING_COUNT)
}

pub fn measure_hop_count(probe: &Prober, ttl: u32, count: usize) -> Option<HopSample> {
    let mut address = String::new();
    let mut answered = 0u32;
    let mut times: Vec<f64> = Vec::new();
    for _attempt in 0..count {
        match probe(ttl) {
            Some(got) => {
                answered += 1;
                if address.is_empty() {
                    address = got.0;
                }
                if let Some(ms) = got.1 {
                    times.push(ms);
                }
            }
            None => continue,
        }
    }
    let average = if times.is_empty() {
        None
    } else {
        Some(times.iter().sum::<f64>() / times.len() as f64)
    };
    Some(HopSample {
        address,
        sent: count as u32,
        answered,
        avg_ms: average,
    })
}

/// Факты о сети, собранные вокруг внешнего адреса и пингов.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetworkFacts {
    /// Адрес, под которым нас видит интернет. Пусто — узнать не удалось.
    pub external_ip: String,
    /// Страна по мнению Cloudflare (двухбуквенный код).
    pub country: String,
    pub owner: Option<IpOwner>,
    /// Адрес сетевого адаптера, через который компьютер выходит в сеть.
    pub local_ip: String,
    /// Пинги до роутера, до узла за ним и до сервера в интернете. None — не меряли.
    pub router: Option<HopSample>,
    pub beyond: Option<HopSample>,
    pub internet: Option<HopSample>,
}

/// Одна строка отчёта о сети: состояние (`ok`/`warn`/`info`/`unknown`), название, описание.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkLine {
    pub state: &'static str,
    pub name: &'static str,
    pub text: String,
}

impl NetworkLine {
    pub fn new(state: &'static str, name: &'static str, text: &str) -> Self {
        NetworkLine {
            state,
            name,
            text: text.to_string(),
        }
    }
}

/// `(адрес, страна)` из ответа `/cdn-cgi/trace`. Пустые строки — нет в ответе.
pub fn parse_trace(body: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(body);
    let mut ip = String::new();
    let mut loc = String::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once('=') {
            match name.trim() {
                "ip" => ip = value.trim().to_string(),
                "loc" => loc = value.trim().to_ascii_uppercase(),
                _ => {}
            }
        }
    }
    if address_kind(&ip) == AddressKind::INVALID {
        ip = String::new();
    }
    (ip, loc)
}

fn ms(value: Option<f64>) -> String {
    match value {
        None => String::new(),
        Some(time) if time < 1.0 => "меньше 1 мс".to_string(),
        Some(time) => format!("{} мс", time.round() as i64),
    }
}

/// Связь до роутера, за ним и до интернета. Потери называются там, где они начинаются.
fn link_lines(facts: &NetworkFacts) -> Vec<NetworkLine> {
    let (router, internet) = match (&facts.router, &facts.internet) {
        (Some(router), Some(internet)) => (router.clone(), internet.clone()),
        _ => return Vec::new(),
    };
    let mut lines = Vec::new();
    let home = router.answered > 0 && address_kind(&router.address) == AddressKind::LOCAL;
    let router_bad;
    if router.answered == 0 {
        if internet.answered > 0 {
            lines.push(NetworkLine::new(
                "info",
                "Роутер",
                "на пинг не отвечает — оценить связь с ним нельзя, но интернет отвечает",
            ));
        }
        router_bad = false;
    } else if !home {
        lines.push(NetworkLine::new(
            "info",
            "Роутер",
            &format!(
                "первый узел {} — уже сеть провайдера: компьютер подключён без домашнего роутера",
                router.address
            ),
        ));
        router_bad = false;
    } else if router.lost() >= LOSS_LIMIT {
        router_bad = true;
        lines.push(NetworkLine::new(
            "warn",
            "Роутер",
            &format!(
                "{} — теряется {} из {} пакетов. Так бывает при слабом Wi‑Fi или плохом кабеле; сайты в проверке могут \
                 «не открываться» именно из-за этого",
                router.address,
                router.lost(),
                router.sent
            ),
        ));
    } else if router.avg_ms.is_some_and(|avg| avg > SLOW_ROUTER_MS) {
        router_bad = true;
        lines.push(NetworkLine::new(
            "warn",
            "Роутер",
            &format!(
                "{} — отвечает медленно ({}). Похоже на слабый сигнал Wi‑Fi: подойдите ближе к роутеру или \
                 подключитесь кабелем",
                router.address,
                ms(router.avg_ms)
            ),
        ));
    } else {
        router_bad = false;
        lines.push(NetworkLine::new(
            "ok",
            "Роутер",
            &format!(
                "{} — отвечает за {}, потерь нет",
                router.address,
                ms(router.avg_ms)
            ),
        ));
    }

    if home {
        if let Some(beyond) = &facts.beyond {
            if beyond.answered > 0 {
                let kind = address_kind(&beyond.address);
                if beyond.address.starts_with("192.168.") {
                    lines.push(NetworkLine::new(
                        "info",
                        "За роутером",
                        &format!("{} — ещё один роутер (двойная сеть). Работать не мешает, но входящие соединения усложняет", beyond.address),
                    ));
                } else if kind == AddressKind::CARRIER {
                    lines.push(NetworkLine::new(
                        "info",
                        "За роутером",
                        &format!("{} — общий адрес провайдера (CGNAT)", beyond.address),
                    ));
                } else if kind == AddressKind::LOCAL {
                    lines.push(NetworkLine::new(
                        "info",
                        "За роутером",
                        &format!("{} — внутренняя сеть провайдера", beyond.address),
                    ));
                } else {
                    lines.push(NetworkLine::new(
                        "info",
                        "За роутером",
                        &format!("{} — сеть провайдера", beyond.address),
                    ));
                }
            }
        }
    }

    if internet.answered == 0 {
        lines.push(NetworkLine::new(
            "unknown",
            "Связь с интернетом",
            "сервер на пинг не ответил — провайдер может резать пинг, это не поломка",
        ));
    } else if internet.lost() >= LOSS_LIMIT {
        let where_text = if router_bad {
            "они начинаются уже до роутера"
        } else {
            "до роутера потерь нет — теряется дальше, у провайдера"
        };
        lines.push(NetworkLine::new(
            "warn",
            "Связь с интернетом",
            &format!(
                "теряется {} из {} пакетов ({}). При таких потерях результаты проверки ненадёжны",
                internet.lost(),
                internet.sent,
                where_text
            ),
        ));
    } else {
        lines.push(NetworkLine::new(
            "ok",
            "Связь с интернетом",
            &format!("ответ за {}, потерь нет", ms(internet.avg_ms)),
        ));
    }
    lines
}

fn owner_text(owner: Option<&IpOwner>) -> String {
    let Some(owner) = owner else {
        return String::new();
    };
    let mut parts = vec![owner.owner.clone()];
    if !owner.asn.is_empty() {
        parts.push(format!("AS{}", owner.asn));
    }
    let kept: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| !part.is_empty())
        .collect();
    kept.join(" · ")
}

/// Строки для отчёта. Вывод о VPN не делается: названа только сеть, которую видно снаружи.
pub fn judge(facts: &NetworkFacts, bypass_tools: &[String]) -> Vec<NetworkLine> {
    let mut lines = Vec::new();
    if !facts.external_ip.is_empty() {
        let place = if facts.country.is_empty() {
            String::new()
        } else {
            format!(" ({})", facts.country)
        };
        lines.push(NetworkLine::new(
            "info",
            "Внешний адрес",
            &format!("{}{}", facts.external_ip, place),
        ));
        let owner = owner_text(facts.owner.as_ref());
        if !owner.is_empty() {
            let owner_struct = facts.owner.as_ref().unwrap();
            let country = &owner_struct.country;
            lines.push(NetworkLine::new(
                "info",
                "Провайдер",
                &format!(
                    "{owner}{}",
                    if country.is_empty() {
                        String::new()
                    } else {
                        format!(", {country}")
                    }
                ),
            ));
            if !owner_struct.prefix.is_empty() {
                lines.push(NetworkLine::new("info", "Сеть", &owner_struct.prefix));
            }
        } else {
            lines.push(NetworkLine::new(
                "unknown",
                "Провайдер",
                "узнать не удалось",
            ));
        }
    } else {
        lines.push(NetworkLine::new(
            "unknown",
            "Внешний адрес",
            "узнать не удалось: сервер Cloudflare не ответил",
        ));
    }

    let kind = if facts.local_ip.is_empty() {
        AddressKind::INVALID
    } else {
        address_kind(&facts.local_ip)
    };
    if kind == AddressKind::CARRIER {
        lines.push(NetworkLine::new(
            "info",
            "Адрес компьютера",
            &format!(
                "{} — провайдер держит вас за общим адресом: входящие соединения снаружи невозможны",
                facts.local_ip
            ),
        ));
    } else if !facts.local_ip.is_empty()
        && !facts.external_ip.is_empty()
        && facts.local_ip == facts.external_ip
    {
        lines.push(NetworkLine::new(
            "info",
            "Адрес компьютера",
            &format!(
                "{} — совпадает с внешним, прямое подключение",
                facts.local_ip
            ),
        ));
    } else if !facts.local_ip.is_empty()
        && kind == AddressKind::PUBLIC
        && !facts.external_ip.is_empty()
    {
        // У компьютера свой адрес в интернете, а снаружи виден другой: между ними кто-то есть.
        lines.push(NetworkLine::new(
            "info",
            "Адрес компьютера",
            &format!(
                "{} — а снаружи виден другой адрес: между ними прокси, VPN или общий адрес провайдера",
                facts.local_ip
            ),
        ));
    } else if !facts.local_ip.is_empty() {
        lines.push(NetworkLine::new(
            "info",
            "Адрес компьютера",
            &format!("{} — за роутером", facts.local_ip),
        ));
    }

    lines.extend(link_lines(facts));
    let tools: Vec<&String> = bypass_tools
        .iter()
        .filter(|item| !item.is_empty())
        .collect();
    if !tools.is_empty() {
        lines.push(NetworkLine::new(
            "warn",
            "Другие программы обхода и VPN",
            &format!(
                "работают: {} — внешний адрес и вся проверка описывают сеть вместе с ними",
                tools
                    .iter()
                    .map(|item| item.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ),
        ));
    }
    lines
}

/// Сбор фактов: `fetch(адрес сервера)` отдаёт тело `/cdn-cgi/trace` или None;
/// `owner_of(адрес)` — владельца сети; `local()` — адрес адаптера; `probe` — пинги.
pub fn collect(
    fetch: impl Fn(&str) -> Option<Vec<u8>>,
    owner_of: impl Fn(&str) -> Option<IpOwner>,
    local: impl Fn() -> String,
    probe: Option<&Prober>,
) -> NetworkFacts {
    let mut external = String::new();
    let mut country = String::new();
    for server in TRACE_SERVERS {
        if let Some(body) = fetch(server) {
            let (ip, place) = parse_trace(&body);
            external = ip;
            country = place;
            if !external.is_empty() {
                break;
            }
        }
    }
    let owner = if external.is_empty() {
        None
    } else {
        owner_of(&external)
    };
    let (router, beyond, internet) = match probe {
        None => (None, None, None),
        Some(prober) => (
            measure_hop(prober, 1),
            measure_hop(prober, 2),
            measure_hop(prober, FAR_TTL),
        ),
    };
    NetworkFacts {
        external_ip: external,
        country,
        owner,
        local_ip: local(),
        router,
        beyond,
        internet,
    }
}

/// python `local_address` — адрес адаптера, через который идёт выход в интернет.
/// Пакеты при этом не отправляются: UDP-сокет только выбирает дорогу.
#[must_use]
pub fn local_address() -> String {
    let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return String::new();
    };
    if sock.connect((TRACE_SERVERS[0], 53)).is_err() {
        return String::new();
    }
    sock.local_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_text(lines: &[NetworkLine]) -> Vec<String> {
        lines
            .iter()
            .map(|line| format!("{} | {} | {}", line.state, line.name, line.text))
            .collect()
    }

    #[test]
    fn full_facts_text() {
        let facts = NetworkFacts {
            external_ip: "77.88.8.88".to_string(),
            country: "RU".to_string(),
            owner: Some(IpOwner {
                asn: "13238".to_string(),
                prefix: "77.88.8.0/24".to_string(),
                country: "RU".to_string(),
                owner: "YANDEX LLC".to_string(),
            }),
            local_ip: "77.88.8.11".to_string(),
            router: Some(HopSample {
                address: "192.168.1.1".to_string(),
                sent: 5,
                answered: 5,
                avg_ms: Some(1.2),
            }),
            beyond: Some(HopSample {
                address: "100.64.0.1".to_string(),
                sent: 5,
                answered: 5,
                avg_ms: Some(8.0),
            }),
            internet: Some(HopSample {
                address: "1.1.1.1".to_string(),
                sent: 5,
                answered: 4,
                avg_ms: Some(22.0),
            }),
        };
        let got = lines_text(&judge(&facts, &[]));
        assert_eq!(
            got,
            vec![
                "info | Внешний адрес | 77.88.8.88 (RU)",
                "info | Провайдер | YANDEX LLC · AS13238, RU",
                "info | Сеть | 77.88.8.0/24",
                "info | Адрес компьютера | 77.88.8.11 — а снаружи виден другой адрес: между ними прокси, VPN или общий адрес провайдера",
                "ok | Роутер | 192.168.1.1 — отвечает за 1 мс, потерь нет",
                "info | За роутером | 100.64.0.1 — общий адрес провайдера (CGNAT)",
                "ok | Связь с интернетом | ответ за 22 мс, потерь нет",
            ]
        );
    }

    #[test]
    fn router_losses_and_silent_cloudflare() {
        let facts = NetworkFacts {
            external_ip: String::new(),
            local_ip: "192.168.1.5".to_string(),
            router: Some(HopSample {
                address: "192.168.1.1".to_string(),
                sent: 5,
                answered: 2,
                avg_ms: Some(2.0),
            }),
            beyond: Some(HopSample::default()),
            internet: Some(HopSample {
                address: "1.1.1.1".to_string(),
                sent: 5,
                answered: 5,
                avg_ms: Some(30.0),
            }),
            ..Default::default()
        };
        let got = lines_text(&judge(&facts, &[]));
        assert_eq!(
            got,
            vec![
                "unknown | Внешний адрес | узнать не удалось: сервер Cloudflare не ответил",
                "info | Адрес компьютера | 192.168.1.5 — за роутером",
                "warn | Роутер | 192.168.1.1 — теряется 3 из 5 пакетов. Так бывает при слабом Wi‑Fi или плохом кабеле; сайты в проверке могут «не открываться» именно из-за этого",
                "ok | Связь с интернетом | ответ за 30 мс, потерь нет",
            ]
        );
    }

    #[test]
    fn slow_router_and_leftover_tools() {
        let facts = NetworkFacts {
            external_ip: "77.88.8.88".to_string(),
            local_ip: "10.0.0.5".to_string(),
            router: Some(HopSample {
                address: "192.168.1.1".to_string(),
                sent: 5,
                answered: 5,
                avg_ms: Some(45.0),
            }),
            internet: Some(HopSample {
                address: "1.1.1.1".to_string(),
                sent: 5,
                answered: 5,
                avg_ms: Some(2.0),
            }),
            ..Default::default()
        };
        let got = lines_text(&judge(&facts, &["v2rayN".to_string()]));
        assert!(got.iter().any(
            |line| line.starts_with("warn | Роутер | 192.168.1.1 — отвечает медленно (45 мс)")
        ));
        assert!(got.iter().any(
            |line| line.starts_with("warn | Другие программы обхода и VPN | работают: v2rayN")
        ));
    }

    #[test]
    fn parse_trace_fields() {
        assert_eq!(
            parse_trace(b"ip=77.88.8.88\nloc=ru\nh=cf\n"),
            ("77.88.8.88".to_string(), "RU".to_string())
        );
        assert_eq!(
            parse_trace(b"ip=not-an-ip\nloc=us\n"),
            (String::new(), "US".to_string())
        );
    }

    #[test]
    fn measure_hop_collects_samples() {
        let answers: Vec<Option<(String, Option<f64>)>> = vec![
            Some(("192.168.1.1".to_string(), Some(2.0))),
            None,
            Some(("192.168.1.1".to_string(), Some(3.0))),
            Some(("192.168.1.1".to_string(), None)),
            Some(("192.168.1.1".to_string(), Some(1.0))),
        ];
        let index = std::cell::RefCell::new(0usize);
        let sample = measure_hop(
            &|_ttl| {
                let got = answers[*index.borrow()].clone();
                *index.borrow_mut() += 1;
                got
            },
            1,
        )
        .unwrap();
        assert_eq!(sample.address, "192.168.1.1");
        assert_eq!(sample.sent, 5);
        assert_eq!(sample.answered, 4);
        assert_eq!(sample.avg_ms, Some(2.0));
        assert_eq!(sample.lost(), 1);
    }

    #[test]
    fn collect_uses_first_live_trace() {
        let facts = collect(
            |server| {
                if server == "1.1.1.1" {
                    None
                } else {
                    Some(b"ip=2.2.2.2\nloc=de\n".to_vec())
                }
            },
            |ip| {
                assert_eq!(ip, "2.2.2.2");
                None
            },
            || "192.168.1.4".to_string(),
            None,
        );
        assert_eq!(facts.external_ip, "2.2.2.2");
        assert_eq!(facts.country, "DE");
        assert!(facts.owner.is_none());
        assert!(facts.router.is_none());
        assert_eq!(facts.local_ip, "192.168.1.4");
    }
}
