//! Порт `src/diagnostics/path_trace.py` — путь до сервера по узлам и место, где стоит фильтр.
//!
//! У пакета есть срок жизни — число узлов, которые он может пройти. Отправляя
//! пинг со сроком 1, 2, 3…, получаем по порядку адреса узлов, на которых он
//! истекал. Видно, сколько узлов до сервера и где ответы прекращаются.
//!
//! Фильтр же обычно пинг пропускает и режет лишь соединение с запрещённым
//! сайтом. Его место ищется наименьшим сроком жизни `k`, при котором поток после
//! запрещённого имени гаснет: фильтр стоит между узлами `k - 1` и `k`.
//!
//! Сбор фактов ([`trace_route`], [`tcp_distance`], [`locate_filter`]) отделён от
//! вывода ([`judge_filter`]). Сетевая часть (QUIC-пара `send_pair`, TCP-пара
//! `tcp_pair`, соединение с TTL) — замыканиями из транспортного слоя, как в
//! python передаются `pair`/`connects`/`probe`.

use crate::icmp::{TraceHopResult, HOP_ROUTER, HOP_SILENT, HOP_TARGET, HOP_UNSUPPORTED};

pub const MAX_HOPS: u32 = 30;
pub const HOP_ATTEMPTS: u32 = 2;
pub const HOP_TIMEOUT_MS: u32 = 1200;
/// Сколько ждать ответа сервера на обычный пакет.
pub const REPLY_TIMEOUT_S: f64 = 1.5;
/// Пауза между запрещённым пакетом и обычным: фильтр должен успеть его увидеть.
pub const SETTLE_S: f64 = 0.15;
pub const FULL_TTL: u32 = 128;

pub const FILTER_FOUND: &str = "found";
pub const FILTER_NO_CONTROL: &str = "no_control";
pub const FILTER_NOT_STATEFUL: &str = "not_stateful";
pub const FILTER_NOT_ON_PATH: &str = "not_on_path";
/// Место вроде бы найдено, но контроль его не подтвердил.
pub const FILTER_UNSURE: &str = "unsure";
/// Расстояние до сервера измерить не удалось: без него нельзя отличить фильтр
/// от самого сервера.
pub const FILTER_NO_DISTANCE: &str = "no_distance";
/// Поток гаснет, только когда пакет доходит до сервера: на дороге к нему
/// фильтра не видно.
pub const FILTER_AT_TARGET: &str = "at_target";

/// Сколько ждать соединения при измерении расстояния и сброса при поиске по TCP.
pub const DISTANCE_TIMEOUT_S: f64 = 1.5;
/// Сколько соединений разом при измерении расстояния и на сколько узлов в обе
/// стороны проверяется подсказка трассировки.
pub const DISTANCE_AT_ONCE: u32 = 10;
pub const DISTANCE_AROUND: u32 = 3;
/// Сколько узлов трассировка спрашивает одновременно.
pub const TRACE_AT_ONCE: u32 = 10;
pub const TCP_WINDOW_S: f64 = 1.2;

/// Имя, которое не блокируют: с ним тот же опыт должен проходить.
pub const NEUTRAL_NAME: &str = "example.com";

/// Один узел трассировки (python `Hop`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hop {
    pub ttl: u32,
    pub kind: &'static str,
    pub address: String,
    pub rtt_ms: Option<f64>,
}

/// Трасса до адреса (python `RouteTrace`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouteTrace {
    pub target: String,
    pub hops: Vec<Hop>,
    /// Дошли ли до самого адреса.
    pub reached: bool,
    /// False — трассировка в этой системе недоступна (не Windows или нет IPv4).
    pub supported: bool,
}

impl RouteTrace {
    #[must_use]
    pub fn hop(&self, ttl: u32) -> Option<&Hop> {
        self.hops.iter().find(|hop| hop.ttl == ttl)
    }
}

/// Трассировка узлами со сроками жизни `1..=max_hops`. `probe(ttl)` — сетевой
/// пинг со сроком (как python `trace_hop_ipv4`, ip/timeout замыкание захватывает),
/// `should_stop` — «Стоп». Rust-порт спрашивает узлы подряд: параллель решает
/// движок, порядок узлов и итог от него не зависят.
#[must_use]
pub fn trace_route(
    ip: &str,
    max_hops: u32,
    attempts: u32,
    should_stop: &dyn Fn() -> bool,
    probe: &dyn Fn(u32) -> TraceHopResult,
) -> RouteTrace {
    if ip.contains(':') {
        return RouteTrace {
            target: ip.to_string(),
            reached: false,
            supported: false,
            hops: Vec::new(),
        };
    }
    // Как только ответил сам адрес, узлы дальше него не спрашиваются.
    let mut reached_at = max_hops + 1;
    let mut hops = Vec::new();
    for ttl in 1..=max_hops {
        let mut result = TraceHopResult::new(HOP_SILENT);
        for _attempt in 0..attempts.max(1) {
            if should_stop() {
                break;
            }
            if ttl > reached_at {
                break;
            }
            result = probe(ttl);
            if result.kind != HOP_SILENT {
                break;
            }
        }
        if result.kind == HOP_TARGET {
            reached_at = reached_at.min(ttl);
        }
        hops.push(Hop {
            ttl,
            kind: result.kind,
            address: result.address,
            rtt_ms: result.rtt_ms,
        });
    }
    if hops.iter().any(|hop| hop.kind == HOP_UNSUPPORTED) {
        return RouteTrace {
            target: ip.to_string(),
            reached: false,
            supported: false,
            hops: Vec::new(),
        };
    }
    if let Some(index) = hops.iter().position(|hop| hop.kind == HOP_TARGET) {
        hops.truncate(index + 1);
        return RouteTrace {
            target: ip.to_string(),
            hops,
            reached: true,
            supported: true,
        };
    }
    // До адреса не дошли: хвост из одних молчащих узлов ничего не сообщает.
    let last = hops
        .iter()
        .filter(|hop| hop.kind == HOP_ROUTER)
        .map(|hop| hop.ttl)
        .max()
        .unwrap_or(0);
    hops.truncate(last as usize);
    RouteTrace {
        target: ip.to_string(),
        hops,
        reached: false,
        supported: true,
    }
}

// --------------------------------------------------------------------------
// Место фильтра
// --------------------------------------------------------------------------

/// Факты проб места фильтра (python `FilterFacts`).
#[derive(Debug, Clone, PartialEq)]
pub struct FilterFacts {
    /// Обычный пакет один получил ответ.
    pub control_ok: Option<bool>,
    /// После запрещённого пакета с полным сроком жизни обычный ответа не получил.
    pub stateful: Option<bool>,
    /// Наименьший срок жизни запрещённого пакета, при котором обычный остался без ответа.
    pub first_blocked_ttl: Option<u32>,
    /// До какого срока жизни дошёл перебор.
    pub checked_up_to: u32,
    pub cancelled: bool,
    /// Контроль на найденном узле: с безобидным именем обычный пакет проходит.
    pub neutral_passes: Option<bool>,
    /// На следующем узле запрещённый пакет тоже гасит поток.
    pub next_blocked: Option<bool>,
    /// Сколько узлов до сервера. None — измерить не удалось. 0 — не измеряли.
    pub distance: Option<u32>,
}

impl Default for FilterFacts {
    /// Python-дефолты: `distance = 0` (не измеряли), а не «не удалось».
    fn default() -> Self {
        Self {
            control_ok: None,
            stateful: None,
            first_blocked_ttl: None,
            checked_up_to: 0,
            cancelled: false,
            neutral_passes: None,
            next_blocked: None,
            distance: Some(0),
        }
    }
}

/// Вывод о месте фильтра (python `FilterVerdict`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FilterVerdict {
    pub code: &'static str,
    pub text: String,
    /// Фильтр стоит между узлами `hop - 1` и `hop`.
    pub hop: Option<u32>,
}

/// Пара пакетов: (имя, срок жизни) → отвечал ли поток. None — проверку сняли.
pub type PathPair<'a> = dyn Fn(&str, u32) -> Option<bool> + 'a;
/// Измеритель расстояния до сервера, уже привязанный к адресу и «Стоп».
pub type DistanceOf<'a> = dyn Fn() -> Option<u32> + 'a;

/// Обычный пакет пропал дважды подряд: одна потеря — ещё не фильтр.
fn silent_twice(pair: &PathPair, name: &str, ttl: u32) -> Option<bool> {
    for _attempt in 0..2 {
        let answered = pair(name, ttl)?;
        if answered {
            return Some(false);
        }
    }
    Some(true)
}

/// Перебирает срок жизни запрещённого пакета, пока обычный не останется без
/// ответа. `pair(name, ttl)` даёт пару на тот же сокет; `distance_of()` —
/// расстояние до сервера (учёт «Стоп» внутри). Перебор идёт только по узлам до
/// сервера: пакет, которому хватило срока жизни до сервера, о фильтре на дороге
/// ничего не говорит.
#[must_use]
pub fn locate_filter(
    max_ttl: u32,
    cancelled: &dyn Fn() -> bool,
    distance_of: &DistanceOf,
    pair: &PathPair,
) -> FilterFacts {
    let distance = distance_of();
    if cancelled() {
        return FilterFacts {
            cancelled: true,
            ..FilterFacts::default()
        };
    }
    let Some(distance) = distance else {
        return FilterFacts {
            distance: None,
            ..FilterFacts::default()
        };
    };
    // Последний узел, на котором пакет ещё не у сервера.
    let last = max_ttl.max(1).min(distance.saturating_sub(1));

    let mut control = pair(NEUTRAL_NAME, FULL_TTL);
    if !matches!(control, Some(true)) {
        control = pair(NEUTRAL_NAME, FULL_TTL);
    }
    let Some(control) = control else {
        return FilterFacts {
            cancelled: true,
            distance: Some(distance),
            ..FilterFacts::default()
        };
    };
    if !control {
        return FilterFacts {
            control_ok: Some(false),
            distance: Some(distance),
            ..FilterFacts::default()
        };
    }
    let stateful = silent_twice(pair, "blocked-name", FULL_TTL);
    let Some(stateful) = stateful else {
        return FilterFacts {
            control_ok: Some(true),
            cancelled: true,
            distance: Some(distance),
            ..FilterFacts::default()
        };
    };
    if !stateful {
        return FilterFacts {
            control_ok: Some(true),
            stateful: Some(false),
            distance: Some(distance),
            ..FilterFacts::default()
        };
    }
    for ttl in 1..=last {
        let blocked = silent_twice(pair, "blocked-name", ttl);
        let Some(blocked) = blocked else {
            return FilterFacts {
                control_ok: Some(true),
                stateful: Some(true),
                checked_up_to: ttl.saturating_sub(1),
                cancelled: true,
                distance: Some(distance),
                ..FilterFacts::default()
            };
        };
        if !blocked {
            continue;
        }
        // Два контроля, прежде чем называть место: тот же срок жизни с
        // безобидным именем (поток должен выжить) и следующий узел (поток должен
        // пропасть снова).
        let neutral = pair(NEUTRAL_NAME, ttl);
        let beyond = match neutral {
            Some(true) if ttl < last => silent_twice(pair, "blocked-name", ttl + 1),
            Some(true) => Some(true),
            _ => None,
        };
        return FilterFacts {
            control_ok: Some(true),
            stateful: Some(true),
            first_blocked_ttl: Some(ttl),
            checked_up_to: ttl,
            cancelled: neutral.is_none() || (neutral == Some(true) && beyond.is_none()),
            neutral_passes: neutral,
            next_blocked: beyond,
            distance: Some(distance),
        };
    }
    FilterFacts {
        control_ok: Some(true),
        stateful: Some(true),
        first_blocked_ttl: None,
        checked_up_to: last,
        cancelled: false,
        neutral_passes: None,
        next_blocked: None,
        distance: Some(distance),
    }
}

fn hop_name(trace: Option<&RouteTrace>, ttl: u32) -> String {
    let hop = trace.and_then(|trace| trace.hop(ttl));
    match hop {
        Some(hop) if !hop.address.is_empty() => format!("узлом {ttl} ({})", hop.address),
        _ => format!("узлом {ttl}"),
    }
}

const NO_CONTROL_QUIC: &str =
    "сервер не ответил даже на обычный пакет QUIC — искать место фильтра этим способом не на чем";
const NO_CONTROL_TCP: &str =
    "сервер не ответил на приветствие с безобидным именем — без этого сброс от фильтра \
     не отличить от отказа самого сервера";
const NOT_STATEFUL_QUIC: &str =
    "после пакета с запрещённым именем обычный пакет всё равно проходит: фильтр не \
     запоминает соединение, и найти его место этим способом нельзя";
const NOT_STATEFUL_TCP: &str =
    "на приветствие с запрещённым именем сброс не приходит: фильтр здесь не шлёт его сам (он молчит или портит \
     ответ сервера), и найти его место этим способом нельзя";

/// Вывод о месте фильтра или None, если проверку сняли. `method` — способ
/// поиска, от него зависят слова.
#[must_use]
pub fn judge_filter(
    facts: &FilterFacts,
    trace: Option<&RouteTrace>,
    method: &str,
) -> Option<FilterVerdict> {
    if facts.cancelled {
        return None;
    }
    let distance = facts.distance;
    let verdict = |code: &'static str, text: String| {
        Some(FilterVerdict {
            code,
            text,
            hop: None,
        })
    };
    let Some(distance) = distance else {
        return verdict(
            FILTER_NO_DISTANCE,
            "не удалось измерить, сколько узлов до сервера, — без этого фильтр на дороге не отличить от самого \
             сервера"
                .to_string(),
        );
    };
    if distance == 1 {
        return verdict(
            FILTER_NO_DISTANCE,
            "соединение с сервером устанавливается уже на первом узле: его принимает не сервер, а роутер, прокси, \
             VPN или антивирус по дороге — искать место фильтра за ними нельзя"
                .to_string(),
        );
    }
    if facts.control_ok == Some(false) {
        return verdict(
            FILTER_NO_CONTROL,
            (if method == "tcp" {
                NO_CONTROL_TCP
            } else {
                NO_CONTROL_QUIC
            })
            .to_string(),
        );
    }
    if facts.stateful == Some(false) {
        return verdict(
            FILTER_NOT_STATEFUL,
            (if method == "tcp" {
                NOT_STATEFUL_TCP
            } else {
                NOT_STATEFUL_QUIC
            })
            .to_string(),
        );
    }
    let mut hop = facts.first_blocked_ttl;
    // Сервер по трассе пингом может оказаться ближе, чем по TCP: берём меньшее.
    let traced_at = if trace.map(|trace| trace.reached).unwrap_or(false) {
        trace.expect("reached trace").hops.len() as u32
    } else {
        0
    };
    let target_at = [distance, traced_at]
        .into_iter()
        .filter(|value| *value > 0)
        .min()
        .unwrap_or(0);
    if let Some(found_at) = hop {
        if target_at > 0 && found_at >= target_at {
            hop = None;
        }
    }
    if hop.is_none() {
        if target_at > 0
            && (facts.first_blocked_ttl.is_some()
                || facts.checked_up_to >= target_at.saturating_sub(1))
        {
            return verdict(
                FILTER_AT_TARGET,
                format!(
                    "на {} узлах до сервера фильтр не найден: соединение гаснет, только когда пакет доходит до \
                     самого сервера или последнего участка перед ним",
                    target_at.saturating_sub(1)
                ),
            );
        }
        return verdict(
            FILTER_NOT_ON_PATH,
            format!("на первых {} узлах фильтр не найден", facts.checked_up_to),
        );
    }
    let found_at = hop.expect("hop есть");
    if facts.neutral_passes == Some(false) {
        return verdict(
            FILTER_UNSURE,
            format!(
                "на узле {found_at} поток пропадает и с безобидным именем — так ведёт себя роутер, а не фильтр по \
                 имени; найти место фильтра этим способом здесь нельзя"
            ),
        );
    }
    if facts.next_blocked == Some(false) {
        return verdict(
            FILTER_UNSURE,
            format!(
                "узел {found_at} один раз погасил поток, но на следующем узле это не повторилось — похоже на \
                 случайную потерю пакетов, место фильтра не подтверждено"
            ),
        );
    }
    if found_at == 1 {
        return Some(FilterVerdict {
            code: FILTER_FOUND,
            text: format!(
                "фильтр стоит не дальше первого узла — это ваш роутер или программа на самом компьютере (перед {})",
                hop_name(trace, 1)
            ),
            hop: Some(found_at),
        });
    }
    Some(FilterVerdict {
        code: FILTER_FOUND,
        text: format!(
            "фильтр стоит между {} и {}",
            hop_name(trace, found_at - 1),
            hop_name(trace, found_at)
        ),
        hop: Some(found_at),
    })
}

// --------------------------------------------------------------------------
// Расстояние до сервера
// --------------------------------------------------------------------------

/// Наименьший срок жизни, с которым соединились, если следом соединились ещё
/// дважды. `reached[ttl - 1]` — соединился ли ttl.
///
/// Дорога одна: если хватило `first` узлов, должно хватать и большего срока.
/// Разрозненные попадания (балансировка по дорогам, потери) — не расстояние.
fn first_reaching(reached: &[bool]) -> Option<u32> {
    let first = reached.iter().position(|positive| *positive)? as u32 + 1;
    let grew = |ttl: u32| reached.get(ttl as usize - 1).copied().unwrap_or(false);
    (grew(first + 1) && grew(first + 2)).then_some(first)
}

/// Сколько узлов до сервера: наименьший срок жизни, с которым соединение
/// устанавливается. `connects(ttl)` — удалось ли соединиться со сроком `ttl`
/// (учёт «Стоп» внутри); `around` — подсказка от трассировки пингом: если она
/// есть, сначала проверяются только сроки жизни рядом с ней.
#[must_use]
pub fn tcp_distance(
    max_hops: u32,
    cancelled: &dyn Fn() -> bool,
    connects: &dyn Fn(u32) -> bool,
    around: u32,
) -> Option<u32> {
    let mut reached: Vec<bool> = Vec::new();
    let grew = |ttl: u32, reached: &[bool]| {
        if ttl == 0 {
            return false;
        }
        reached.get(ttl as usize - 1).copied().unwrap_or(false)
    };
    let ask = |ttls: &[u32], reached: &mut Vec<bool>| {
        for ttl in ttls {
            while reached.len() < *ttl as usize {
                reached.push(false);
            }
            reached[*ttl as usize - 1] = connects(*ttl);
        }
    };
    if around > 0 {
        let low = around.saturating_sub(DISTANCE_AROUND).max(1);
        let high = max_hops.min(around + DISTANCE_AROUND);
        ask(&(low..=high).collect::<Vec<_>>(), &mut reached);
        if cancelled() {
            return None;
        }
        // Годится, только если ниже найденного срока есть несоединившийся: иначе сервер может быть ещё ближе.
        if let Some(first) = first_reaching(&reached) {
            if first == 1 || !grew(first - 1, &reached) {
                return Some(first);
            }
        }
    }
    let mut start = 1;
    while start <= max_hops {
        let high = max_hops.min(start + DISTANCE_AT_ONCE - 1);
        let wave: Vec<u32> = (start..=high).filter(|ttl| !grew(*ttl, &reached)).collect();
        if !wave.is_empty() {
            ask(&wave, &mut reached);
        }
        if cancelled() {
            return None;
        }
        // Дальше идти незачем: всё от первого узла до двух следующих за найденным уже проверено.
        let first = reached
            .iter()
            .position(|positive| *positive)
            .map(|index| index as u32 + 1);
        if let Some(first) = first {
            if (1..=first + 2).all(|ttl| grew(ttl, &reached)) {
                break;
            }
        }
        start += DISTANCE_AT_ONCE;
    }
    first_reaching(&reached)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn active(borrowed: std::cell::Ref<'_, Vec<u32>>) -> Vec<u32> {
        borrowed.clone()
    }

    fn fact(
        control_ok: Option<bool>,
        stateful: Option<bool>,
        first_blocked_ttl: Option<u32>,
        checked_up_to: u32,
        distance: Option<u32>,
        neutral_passes: Option<bool>,
        next_blocked: Option<bool>,
    ) -> FilterFacts {
        FilterFacts {
            control_ok,
            stateful,
            first_blocked_ttl,
            checked_up_to,
            neutral_passes,
            next_blocked,
            distance,
            cancelled: false,
        }
    }

    fn found_facts(blocked: u32, distance: u32) -> FilterFacts {
        fact(
            Some(true),
            Some(true),
            Some(blocked),
            blocked,
            Some(distance),
            Some(true),
            Some(true),
        )
    }

    fn traced(target_ttl: u32, target: &str) -> RouteTrace {
        // Как в python-сценариях: до цели пройдено два узла (3-й — роутер, 4-й — адрес).
        RouteTrace {
            target: target.to_string(),
            hops: vec![
                Hop {
                    ttl: 3,
                    kind: HOP_ROUTER,
                    address: "10.0.0.1".to_string(),
                    rtt_ms: Some(1.0),
                },
                Hop {
                    ttl: target_ttl,
                    kind: HOP_TARGET,
                    address: target.to_string(),
                    rtt_ms: Some(1.0),
                },
            ],
            reached: true,
            supported: true,
        }
    }

    #[test]
    fn judge_filter_matches_python() {
        let len_trace = traced(4, "1.2.3.4");
        let verdict = judge_filter(&found_facts(4, 10), None, "quic").unwrap();
        assert_eq!((verdict.code, verdict.hop), (FILTER_FOUND, Some(4)));
        assert_eq!(verdict.text, "фильтр стоит между узлом 3 и узлом 4");

        let at_target = judge_filter(&found_facts(4, 10), Some(&len_trace), "quic").unwrap();
        assert_eq!(at_target.code, FILTER_AT_TARGET);
        assert_eq!(
            at_target.text,
            "на 1 узлах до сервера фильтр не найден: соединение гаснет, только когда пакет доходит до самого \
             сервера или последнего участка перед ним"
        );

        let first_hop = judge_filter(&found_facts(1, 10), Some(&len_trace), "quic").unwrap();
        assert_eq!(first_hop.hop, Some(1));
        assert_eq!(
            first_hop.text,
            "фильтр стоит не дальше первого узла — это ваш роутер или программа на самом компьютере (перед узлом 1)"
        );

        let no_control = judge_filter(
            &fact(Some(false), None, None, 0, Some(10), None, None),
            None,
            "tcp",
        )
        .unwrap();
        assert_eq!(no_control.code, FILTER_NO_CONTROL);
        assert_eq!(
            no_control.text,
            "сервер не ответил на приветствие с безобидным именем — без этого сброс от фильтра не отличить от \
             отказа самого сервера"
        );
        let quic_no_control = judge_filter(
            &fact(Some(false), None, None, 0, Some(10), None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(
            quic_no_control.text,
            "сервер не ответил даже на обычный пакет QUIC — искать место фильтра этим способом не на чем"
        );

        let not_stateful_tcp = judge_filter(
            &fact(Some(true), Some(false), None, 0, Some(10), None, None),
            None,
            "tcp",
        )
        .unwrap();
        assert_eq!(
            not_stateful_tcp.text,
            "на приветствие с запрещённым именем сброс не приходит: фильтр здесь не шлёт его сам (он молчит или \
             портит ответ сервера), и найти его место этим способом нельзя"
        );
        let not_stateful_quic = judge_filter(
            &fact(Some(true), Some(false), None, 0, Some(10), None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(
            not_stateful_quic.text,
            "после пакета с запрещённым именем обычный пакет всё равно проходит: фильтр не запоминает соединение, \
             и найти его место этим способом нельзя"
        );

        let unsure_neutral =
            judge_filter(&found_facts(4, 10).with_neutral(Some(false)), None, "quic").unwrap();
        assert_eq!(unsure_neutral.code, FILTER_UNSURE);
        assert_eq!(
            unsure_neutral.text,
            "на узле 4 поток пропадает и с безобидным именем — так ведёт себя роутер, а не фильтр по имени; найти \
             место фильтра этим способом здесь нельзя"
        );

        let unsure_next = judge_filter(
            &FilterFacts {
                next_blocked: Some(false),
                ..found_facts(4, 10)
            },
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(
            unsure_next.text,
            "узел 4 один раз погасил поток, но на следующем узле это не повторилось — похоже на случайную потерю \
             пакетов, место фильтра не подтверждено"
        );

        let no_distance = judge_filter(
            &fact(Some(true), Some(false), None, 0, None, None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(no_distance.code, FILTER_NO_DISTANCE);
        assert_eq!(
            no_distance.text,
            "не удалось измерить, сколько узлов до сервера, — без этого фильтр на дороге не отличить от самого \
             сервера"
        );
        let router_takeover = judge_filter(
            &fact(Some(true), Some(false), None, 0, Some(1), None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(
            router_takeover.text,
            "соединение с сервером устанавливается уже на первом узле: его принимает не сервер, а роутер, прокси, \
             VPN или антивирус по дороге — искать место фильтра за ними нельзя"
        );
        let not_on_path = judge_filter(
            &fact(Some(true), Some(true), None, 3, Some(10), None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(not_on_path.code, FILTER_NOT_ON_PATH);
        assert_eq!(not_on_path.text, "на первых 3 узлах фильтр не найден");
        let at_target_tail = judge_filter(
            &fact(Some(true), Some(true), None, 9, Some(10), None, None),
            None,
            "quic",
        )
        .unwrap();
        assert_eq!(at_target_tail.code, FILTER_AT_TARGET);
        assert_eq!(
            at_target_tail.text,
            "на 9 узлах до сервера фильтр не найден: соединение гаснет, только когда пакет доходит до самого \
             сервера или последнего участка перед ним"
        );
        // Сняли проверку — вывода нет.
        assert!(judge_filter(
            &FilterFacts {
                cancelled: true,
                ..found_facts(4, 10)
            },
            None,
            "quic"
        )
        .is_none());
    }

    impl FilterFacts {
        fn with_neutral(self, neutral_passes: Option<bool>) -> Self {
            Self {
                neutral_passes,
                ..self
            }
        }
    }

    #[test]
    fn trace_route_walks_and_truncates() {
        let supported = trace_route("2001:db8::1", MAX_HOPS, HOP_ATTEMPTS, &|| false, &|_ttl| {
            TraceHopResult::new(HOP_TARGET)
        });
        assert!(!supported.supported);
        assert_eq!(supported.target, "2001:db8::1");

        let asked: RefCell<Vec<u32>> = RefCell::new(Vec::new());
        let reached = trace_route("1.2.3.4", 5, HOP_ATTEMPTS, &|| false, &|ttl: u32| {
            asked.borrow_mut().push(ttl);
            if ttl == 3 {
                TraceHopResult {
                    kind: HOP_TARGET,
                    address: "1.2.3.4".into(),
                    rtt_ms: Some(1.0),
                }
            } else {
                TraceHopResult {
                    kind: HOP_ROUTER,
                    address: format!("10.0.0.{ttl}"),
                    rtt_ms: Some(1.0),
                }
            }
        });
        assert_eq!(active(asked.borrow()), vec![1, 2, 3]);
        assert!(reached.reached);
        assert_eq!(reached.hops.len(), 3);
        assert_eq!(reached.hop(2).unwrap().address, "10.0.0.2");
        assert!(matches!(reached.hop(3), Some(hop) if hop.kind == HOP_TARGET));
        assert!(reached.hop(4).is_none());

        let unsupported = trace_route("1.2.3.4", 4, 1, &|| false, &|_ttl| {
            TraceHopResult::new(HOP_UNSUPPORTED)
        });
        assert!(!unsupported.supported);

        let silent = trace_route("1.2.3.4", 4, 1, &|| false, &|ttl| TraceHopResult {
            kind: HOP_ROUTER,
            address: format!("10.0.0.{ttl}"),
            rtt_ms: Some(1.0),
        });
        assert!(!silent.reached);
        assert_eq!(silent.hops.len(), 4);
    }

    #[test]
    fn trace_route_respects_stop_and_reached() {
        // «Стоп» до первой пробы: ни один узел не пингуется.
        let stopped = trace_route("1.2.3.4", 10, 3, &|| true, &|_ttl: u32| {
            panic!("проба не должна идти после «Стоп»")
        });
        // Хвост из одних молчащих узлов ничего не сообщает — python срезает его до пустого.
        assert!(stopped.hops.is_empty());
        assert!(!stopped.reached);

        // Узел дальше ответившего адреса не спрашивается и в молчащей трассе.
        let seen: RefCell<Vec<u32>> = RefCell::new(Vec::new());
        let truncated = trace_route("1.2.3.4", 6, 1, &|| false, &|ttl| {
            seen.borrow_mut().push(ttl);
            if ttl == 3 {
                TraceHopResult {
                    kind: HOP_TARGET,
                    address: "1.2.3.4".into(),
                    rtt_ms: Some(1.0),
                }
            } else {
                TraceHopResult::new(HOP_SILENT)
            }
        });
        assert_eq!(active(seen.borrow()), vec![1, 2, 3]);
        assert!(truncated.reached);
        assert_eq!(truncated.hops.len(), 3);
    }

    #[test]
    fn tcp_distance_walks_waves() {
        // До сервера 7 узлов: соединение ставится со сроком жизни 7 и больше.
        let distance = tcp_distance(12, &|| false, &|ttl| ttl >= 7, 0);
        assert_eq!(distance, Some(7));
        // Подсказка трассировки: соединившиеся 5..=7, ниже 4 тишина — годится.
        let hinted = tcp_distance(12, &|| false, &|ttl| ttl >= 5, 5);
        assert_eq!(hinted, Some(5));
        // Подсказка не подтверждается (все соединились и ниже) — полный перебор.
        let weak_hint = tcp_distance(12, &|| false, &|ttl| ttl >= 7, 7);
        assert_eq!(weak_hint, Some(7));
        // Разрозненные попадания — не расстояние.
        let flaky = tcp_distance(12, &|| false, &|ttl| ttl == 3, 0);
        assert_eq!(flaky, None);
        // «Стоп» после воли — None.
        let stopped = tcp_distance(30, &|| true, &|ttl| ttl >= 3, 30);
        assert_eq!(stopped, None);
    }

    #[test]
    fn locate_filter_walks_ttls() {
        // Расстояния нет — facts.distance: None.
        let no_distance = locate_filter(MAX_HOPS, &|| false, &|| None, &|_name, _ttl| Some(true));
        assert_eq!(no_distance.distance, None);
        // Проверку сняли при измерении расстояния.
        let cancelled = locate_filter(
            MAX_HOPS,
            &|| true,
            &|| None,
            &|_name, _ttl: u32| unreachable!(),
        );
        assert!(cancelled.cancelled);
        // Фильтр на 4-м узле: контроль жив, при ttl >= 4 поток гаснет, безобидное имя на 4-м проходит.
        let found = locate_filter(
            MAX_HOPS,
            &|| false,
            &|| Some(10),
            &|name, ttl| match (name, ttl) {
                (NEUTRAL_NAME, _) => Some(true),
                // С сервером по QUIC с запрещённым именем у нас не сговоришься: до конца потока тишина.
                (_, t) if t == FULL_TTL => Some(false),
                (_, t) => Some(t < 4),
            },
        );
        assert_eq!(found.first_blocked_ttl, Some(4));
        assert_eq!(found.checked_up_to, 4);
        assert_eq!(found.neutral_passes, Some(true));
        assert_eq!(found.next_blocked, Some(true));
        assert!(!found.cancelled);
        // Сервер ближе max_ttl: перебор ограничен расстоянием.
        let capped = locate_filter(
            MAX_HOPS,
            &|| false,
            &|| Some(3),
            &|name, ttl| match (name, ttl) {
                (NEUTRAL_NAME, _) => Some(true),
                // Поток молчит и на серверном сроке жизни: stateful считается true.
                (_, FULL_TTL) => Some(false),
                // По узлам до сервера (1..=2) поток отвечает: блокировки нет.
                (_, _) => Some(true),
            },
        );
        assert_eq!(capped.first_blocked_ttl, None);
        assert_eq!(capped.checked_up_to, 2);
        assert_eq!(capped.stateful, Some(true));
        // Контроль не прошёл.
        let dead = locate_filter(MAX_HOPS, &|| false, &|| Some(10), &|_name, _ttl| {
            Some(false)
        });
        assert_eq!(dead.control_ok, Some(false));
    }
}
