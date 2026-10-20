//! Порт `src/diagnostics/dns_place.py` — где перехватывают обычные DNS-запросы.
//!
//! Провайдер умеет отвечать на DNS-запрос сам, не пропуская его до сервера,
//! которому тот адресован. Место такого перехвата находится тем же приёмом, что
//! и место фильтра: срок жизни пакета (TTL).
//!
//! Запрос к известному зарубежному серверу (`8.8.8.8`) уходит со сроком жизни
//! `k` узлов. До Google он при малом `k` заведомо не доходит — пакет гибнет на
//! `k`-м узле. Если ответ всё же пришёл, ответил не Google, а кто-то на дороге,
//! не дальше `k`-го узла. Наименьший такой `k` и есть место перехвата.
//! Расстояние до самого сервера берётся из трассировки: ответ при `k`, равном
//! этому расстоянию — честный ответ сервера, перехвата не видно.
//!
//! Это место может не совпадать с местом фильтра по имени сайта: тогда устройств
//! на дороге не меньше двух. Способу не нужны особые права.
//!
//! Сбор фактов ([`collect`]) отделён от вывода ([`judge`]). Сетевая часть
//! ([`ask_with_ttl`], UDP-сокет с `IP_TTL`) — в транспортном слое.

/// Известный зарубежный DNS-сервер: перехват ищется на дороге к нему.
pub const DNS_SERVER: &str = "8.8.8.8";
/// Имя, о котором спрашивают: несуществующий домен для скорости ответа.
pub const PROBE_NAME: &str = "example.com";
pub const MAX_TTL: u32 = 20;
pub const REPLY_TIMEOUT_S: f64 = 1.5;

pub const PLACE_FOUND: &str = "found";
pub const PLACE_NONE: &str = "none";
pub const PLACE_UNKNOWN: &str = "unknown";

/// DNS-запрос записи A к `name` с рекурсией и номером `ident`.
#[must_use]
pub fn dns_query(name: &str, ident: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(1 + name.len());
    for part in name.trim_matches('.').split('.') {
        header.push(part.len() as u8);
        header.extend_from_slice(part.as_bytes());
    }
    let mut query = Vec::with_capacity(header.len() + 18);
    query.extend_from_slice(&ident.to_be_bytes());
    // Обычный запрос записи A с рекурсией: flags 0x0100, вопрос 1, остальное 0.
    query.extend_from_slice(&[0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&header);
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

/// Пришёл ли ответ на DNS-запрос со сроком жизни `ttl` — сетевая часть,
/// которую движок даёт как замыкание. `None` — проверку сняли.
pub type TtlAsk<'a> = dyn Fn(u32) -> Option<bool> + 'a;

/// Факты о дороге DNS-запросов (python `DnsPlaceFacts`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsPlaceFacts {
    pub server: String,
    /// Сроки жизни, при которых пришёл ответ.
    pub answered: Vec<u32>,
    pub checked_up_to: u32,
    /// Сколько узлов до самого сервера по трассировке. 0 — неизвестно.
    pub distance: u32,
    pub cancelled: bool,
}

/// Вывод о месте перехвата (python `DnsPlaceVerdict`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsPlaceVerdict {
    pub code: &'static str,
    pub text: String,
    /// Перехват не дальше этого узла (между `hop - 1` и `hop`).
    pub hop: Option<u32>,
}

/// Спрашиваются все сроки жизни разом: это отдельные пакеты. Rust-порт
/// собирает ответы подряд — передача замыкания Injectable, потому как параллель
/// решает движок.
#[must_use]
pub fn collect(ask: &TtlAsk, distance: u32, max_ttl: u32, server: &str) -> DnsPlaceFacts {
    let last = max_ttl.max(1);
    let mut answered = Vec::new();
    let mut cancelled = false;
    for ttl in 1..=last {
        match ask(ttl) {
            Some(true) => answered.push(ttl),
            Some(false) => continue,
            None => cancelled = true,
        }
    }
    DnsPlaceFacts {
        server: server.to_string(),
        answered,
        checked_up_to: last,
        distance,
        cancelled,
    }
}

/// Где перехватывают DNS. None — проверку сняли.
#[must_use]
pub fn judge(facts: Option<&DnsPlaceFacts>) -> Option<DnsPlaceVerdict> {
    let Some(facts) = facts else { return None };
    if facts.cancelled {
        return None;
    }
    if facts.answered.is_empty() {
        return Some(DnsPlaceVerdict {
            code: PLACE_UNKNOWN,
            text: format!(
                "на обычный DNS-запрос к {} ответа нет ни с каким сроком жизни — место не определить",
                facts.server
            ),
            ..DnsPlaceVerdict::default()
        });
    }
    let first = *facts.answered.iter().min().unwrap();
    if facts.distance == 0 {
        return Some(DnsPlaceVerdict {
            code: PLACE_UNKNOWN,
            text: format!(
                "ответ на DNS-запрос к {} приходит начиная с {}-го узла, но сколько узлов до самого сервера, узнать \
                 не удалось — перехват это или сам сервер, не различить",
                facts.server, first
            ),
            ..DnsPlaceVerdict::default()
        });
    }
    if first < facts.distance {
        let (where_text, hop) = if first == 1 {
            ("не дальше первого узла — это ваш роутер".to_string(), first)
        } else {
            (format!("между узлами {} и {}", first - 1, first), first)
        };
        return Some(DnsPlaceVerdict {
            code: PLACE_FOUND,
            text: format!(
                "обычные DNS-запросы перехватывают {}: ответ приходит, когда пакету хватает срока жизни только на {} \
                 узл., а до {} их {}",
                where_text, first, facts.server, facts.distance
            ),
            hop: Some(hop),
        });
    }
    Some(DnsPlaceVerdict {
        code: PLACE_NONE,
        text: format!(
            "перехвата обычных DNS-запросов по дороге не видно: {} отвечает сам, с {}-го узла",
            facts.server, facts.distance
        ),
        ..DnsPlaceVerdict::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_facts(answered: Vec<u32>, distance: u32, cancelled: bool) -> Option<DnsPlaceVerdict> {
        judge(Some(&DnsPlaceFacts {
            server: "8.8.8.8".to_string(),
            answered,
            checked_up_to: 20,
            distance,
            cancelled,
        }))
    }

    #[test]
    fn dns_query_wire_matches_python() {
        assert_eq!(
            dns_query("example.com", 0x1234).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "123401000001000000000000076578616d706c6503636f6d0000010001"
        );
        assert_eq!(
            dns_query("a.b", 1).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "000101000001000000000000016101620000010001"
        );
    }

    #[test]
    fn judge_routes_python_text() {
        let found = invalid_facts(vec![3, 4], 10, false).unwrap();
        assert_eq!(found.code, PLACE_FOUND);
        assert_eq!(found.hop, Some(3));
        assert_eq!(
            found.text,
            "обычные DNS-запросы перехватывают между узлами 2 и 3: ответ приходит, когда пакету хватает срока жизни \
             только на 3 узл., а до 8.8.8.8 их 10"
        );
        let no_answers = invalid_facts(Vec::new(), 10, false).unwrap();
        assert_eq!(no_answers.code, PLACE_UNKNOWN);
        assert_eq!(
            no_answers.text,
            "на обычный DNS-запрос к 8.8.8.8 ответа нет ни с каким сроком жизни — место не определить"
        );
        let router = invalid_facts(vec![1], 4, false).unwrap();
        assert_eq!(
            router.text,
            "обычные DNS-запросы перехватывают не дальше первого узла — это ваш роутер: ответ приходит, когда пакету \
             хватает срока жизни только на 1 узл., а до 8.8.8.8 их 4"
        );
        assert_eq!(router.hop, Some(1));
        let honest = invalid_facts(vec![7, 8], 7, false).unwrap();
        assert_eq!(honest.code, PLACE_NONE);
        assert_eq!(
            honest.text,
            "перехвата обычных DNS-запросов по дороге не видно: 8.8.8.8 отвечает сам, с 7-го узла"
        );
        let no_distance = invalid_facts(vec![6], 0, false).unwrap();
        assert_eq!(
            no_distance.text,
            "ответ на DNS-запрос к 8.8.8.8 приходит начиная с 6-го узла, но сколько узлов до самого сервера, узнать \
             не удалось — перехват это или сам сервер, не различить"
        );
        assert!(judge(Some(&DnsPlaceFacts { server: "8.8.8.8".into(), cancelled: true, ..Default::default() }))
            .is_none());
        assert!(judge(None).is_none());
    }

    #[test]
    fn collect_walks_every_ttl() {
        let facts = collect(
            &|ttl| {
                if ttl >= 3 && ttl <= 5 {
                    Some(true)
                } else if ttl == 2 {
                    Some(false)
                } else if ttl < 3 {
                    Some(false)
                } else {
                    None
                }
            },
            7,
            8,
            "8.8.8.8",
        );
        assert_eq!(facts.answered, vec![3, 4, 5]);
        assert!(facts.cancelled);
        assert_eq!(facts.checked_up_to, 8);
        assert_eq!(facts.distance, 7);
    }
}
