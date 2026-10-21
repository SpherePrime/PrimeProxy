//! Порт `src/dns/answering.py` — кто на самом деле отвечает на DNS-запросы
//! компьютера: для панели «Сейчас DNS».
//!
//! На адаптере может стоять 1.1.1.1, а отвечать — провайдер: он перехватывает
//! обычные DNS-запросы по пути. Проверка из трёх вопросов:
//!
//! 1. выбранному серверу — служебное имя `whoami.akamai.net`: в ответе адрес,
//!    с которого к Akamai пришёл запрос, то есть сеть того, кто на самом деле
//!    разбирает имена;
//! 2. чья это сеть — по DNS-службе Team Cymru, но шифрованным путём через
//!    эталоны: иначе о владельце ответил бы тот же перехватчик;
//! 3. канарейка — вопрос адресу, где DNS-сервера нет: ответ на него
//!    доказывает перехват ([`crate::interception`]).
//!
//! Жёсткий вывод «перехват» делается только по канарейке. Несовпадение сети с
//! выбранным сервером фактом не подаётся: у anycast-сервисов оно бывает и без
//! перехвата.

use crate::interception::canary_answered;
use primecore_dnswire::net::query_udp;

/// Общий срок проверки: эталоны бывают закрыты и молчат подолгу.
pub const BUDGET_S: f64 = 8.0;

/// python `dns.server_check.UDP_TIMEOUT_S` / `WHOAMI_DOMAIN`.
pub const UDP_TIMEOUT_S: f64 = 2.0;
pub const WHOAMI_DOMAIN: &str = "whoami.akamai.net";

/// python `utils.ip_owner.IpOwner` — владелец сети адреса.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpOwner {
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub owner: String,
}

/// python `Answering`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answering {
    /// Короткое имя сети, которая разбирает имена; пусто — не узнали.
    pub owner: String,
    pub asn: String,
    /// Ответил адрес, где DNS-сервера нет: обычные запросы перехватывают по
    /// пути.
    pub intercepted: bool,
}

/// python `short_owner` — «CLOUDFLARENET - Cloudflare, Inc., US» →
/// «Cloudflare»: без кода сети, страны и формы компании.
#[must_use]
pub fn short_owner(owner: Option<&IpOwner>) -> String {
    let Some(owner) = owner else {
        return String::new();
    };
    let name = owner.owner.trim();
    if name.is_empty() {
        return String::new();
    }
    let name = match name.split_once(" - ") {
        Some((_head, tail)) => tail,
        None => name,
    };
    // Хвост-страна из двух букв убрать (python rpartition(",")).
    let name = match name.rsplit_once(',') {
        Some((head, tail))
            if tail.trim().len() == 2 && tail.trim().chars().all(char::is_alphabetic) =>
        {
            head
        }
        _ => name,
    };
    name.split(',').next().unwrap_or(name).trim().to_string()
}

/// Служебный вопрос выбранному серверу (адрес, срок) → ответ.
pub type Whoami<'a> = Box<dyn Fn(&str, f64) -> primecore_dnswire::DnsQueryResult + 'a>;
/// Владелец сети адреса шифрованным вопросом к эталону.
pub type OwnerOf<'a> = Box<dyn Fn(&str) -> Option<IpOwner> + 'a>;
/// Канарейка: ответил ли адрес, где DNS-сервера нет.
pub type Canary<'a> = Box<dyn Fn() -> bool + 'a>;

/// Ввод проверки (python: `query_udp` + `lookup_ip_owner(reference_ask)` +
/// `canary_answered`). Разнесён замыканиями, чтобы живые тесты подставляли
/// серверы, а движок — настоящий ввод.
pub struct AnsweringIo<'a> {
    pub whoami: Whoami<'a>,
    pub owner_of: OwnerOf<'a>,
    pub canary: Canary<'a>,
}

/// python `check_answering(address, cancel)` — проверка для адреса DNS-сервера,
/// который сейчас стоит на адаптере.
#[must_use]
pub fn check_answering_with(address: &str, io: &AnsweringIo<'_>) -> Answering {
    let whoami = (io.whoami)(address, UDP_TIMEOUT_S);
    let egress = whoami.values(primecore_dnswire::TYPE_A);
    let owner = egress.first().and_then(|ip| (io.owner_of)(ip));
    Answering {
        owner: short_owner(owner.as_ref()),
        asn: owner.map(|item| item.asn).unwrap_or_default(),
        intercepted: (io.canary)(),
    }
}

/// python `check_answering` с настоящими запросами. Владелец сети приходит
/// замыканием (эталонный вопрос Cymru — слой движка); общий срок BUDGET_S
/// держит машина прогона через её отмену.
#[must_use]
pub fn check_answering(
    address: &str,
    owner_of: &dyn Fn(&str) -> Option<IpOwner>,
    cancel: &std::sync::Arc<primecore_socketcancel::SocketCancel>,
) -> Answering {
    let whoami_cancel = std::sync::Arc::clone(cancel);
    let canary_cancel = std::sync::Arc::clone(cancel);
    let io = AnsweringIo {
        whoami: Box::new(move |server, timeout| {
            query_udp(
                server,
                WHOAMI_DOMAIN,
                primecore_dnswire::TYPE_A,
                timeout,
                53,
                Some(&whoami_cancel),
            )
        }),
        owner_of: Box::new(owner_of),
        canary: Box::new(move || canary_answered(Some(&canary_cancel))),
    };
    check_answering_with(address, &io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_name_is_shortened() {
        let owner = |text: &str| IpOwner {
            owner: text.to_string(),
            asn: "13335".to_string(),
            ..Default::default()
        };
        assert_eq!(
            short_owner(Some(&owner("CLOUDFLARENET - Cloudflare, Inc., US"))),
            "Cloudflare"
        );
        assert_eq!(short_owner(Some(&owner("Google LLC"))), "Google LLC");
        assert_eq!(short_owner(Some(&owner("Quad9, CH"))), "Quad9");
        assert_eq!(short_owner(Some(&owner(""))), "");
        assert_eq!(short_owner(None), "");
    }

    /// Ответ с одной A-записью: заголовок + вопрос + ответ (имя указателем).
    fn a_reply(ip: [u8; 4]) -> Vec<u8> {
        let mut packet: Vec<u8> = Vec::new();
        packet.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        for label in ["whoami", "akamai", "net"] {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        packet.extend_from_slice(&[0xC0, 0x0C]); // указатель на вопрос
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet.extend_from_slice(&[0, 0, 0, 0]); // ttl
        packet.extend_from_slice(&[0, 4]);
        packet.extend_from_slice(&ip);
        packet
    }

    #[test]
    fn answering_from_whoami_reply() {
        // whoami-ответ содержит адрес сети, разбирающей имена; здесь он
        // подставлен замыканием.
        let io = AnsweringIo {
            whoami: Box::new(move |_server, _timeout| {
                primecore_dnswire::answered_result(
                    "udp",
                    primecore_dnswire::parse_response(&a_reply([203, 0, 113, 1]))
                        .expect("разобран"),
                    14.0,
                )
            }),
            owner_of: Box::new(|_ip| {
                Some(IpOwner {
                    owner: "CYMRU - Team Cymru, US".to_string(),
                    asn: "26598".to_string(),
                    ..Default::default()
                })
            }),
            canary: Box::new(|| true),
        };
        let answer = check_answering_with("127.0.0.1", &io);
        assert_eq!(answer.owner, "Team Cymru");
        assert_eq!(answer.asn, "26598");
        assert!(answer.intercepted, "канарейка решила");
    }

    #[test]
    fn no_reply_means_no_owner() {
        let io = AnsweringIo {
            whoami: Box::new(|_server, _timeout| primecore_dnswire::DnsQueryResult {
                transport: "udp".to_string(),
                failure: primecore_dnswire::FAILURE_TIMEOUT.to_string(),
                ..Default::default()
            }),
            owner_of: Box::new(|_ip| panic!("владельца не спрашивают без адреса")),
            canary: Box::new(|| false),
        };
        let answer = check_answering_with("127.0.0.1", &io);
        assert_eq!(answer.owner, "");
        assert_eq!(answer.asn, "");
        assert!(!answer.intercepted);
    }
}
