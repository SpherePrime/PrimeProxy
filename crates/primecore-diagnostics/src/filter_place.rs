//! Порт `src/diagnostics/filter_place.py` — где стоит фильтр провайдера (ТСПУ).
//!
//! Это «умная трассировка». Обычная показывает узлы по дороге до сервера; эта
//! ещё находит, после какого узла соединение с заблокированным сайтом начинают
//! резать. Как именно ищется место на одном сайте — в [`crate::path_trace`].
//!
//! Зачем несколько сайтов. Один сайт — одна дорога и одна случайность. Если по
//! трём сайтам с разными адресами фильтр оказался на одном и том же узле — это
//! место фильтра. Если на разных — так и говорим, без одной общей цифры.
//!
//! Здесь нет сети: пробы, трассировка и поиск владельцев передаются снаружи.
//! Сбор фактов ([`collect`]) отделён от выводов ([`judge_site`], [`aggregate`]).

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::address_kinds::{address_kind, AddressKind};
use crate::path_trace::{
    judge_filter, FilterFacts, RouteTrace, FILTER_AT_TARGET, FILTER_FOUND, FILTER_NOT_ON_PATH,
    FILTER_NOT_STATEFUL, FILTER_UNSURE,
};

pub const METHOD_QUIC: &str = "quic";
pub const METHOD_TCP: &str = "tcp";

pub const MAX_SITES: usize = 4;

/// Итог по всем сайтам.
pub const STATE_FOUND: &str = "found";
/// Сайты дали разные узлы.
pub const STATE_DISAGREE: &str = "disagree";
/// Искали, но на дороге фильтра не видно или способ не сработал.
pub const STATE_NOT_FOUND: &str = "not_found";
/// Искать было не по чему: блокировок по имени в этой проверке нет.
pub const STATE_NONE: &str = "none";
/// «Фильтр» на первом узле при работающей программе обхода: это она, а не провайдер.
pub const STATE_DISTURBED: &str = "disturbed";

pub const CONFIDENCE_HIGH: &str = "high";
pub const CONFIDENCE_MEDIUM: &str = "medium";
pub const CONFIDENCE_LOW: &str = "low";

/// Чей узел.
pub const OWNER_ROUTER: &str = "router";
pub const OWNER_PROVIDER: &str = "provider";
pub const OWNER_OTHER: &str = "other";
pub const OWNER_SILENT: &str = "silent";
pub const OWNER_UNKNOWN: &str = "unknown";

fn method_title(method: &str) -> &'static str {
    if method == METHOD_QUIC {
        "QUIC (UDP 443)"
    } else {
        "TCP (сброс соединения)"
    }
}

fn confidence_text(confidence: &str) -> &'static str {
    if confidence == CONFIDENCE_HIGH {
        "высокая"
    } else if confidence == CONFIDENCE_MEDIUM {
        "средняя"
    } else {
        "низкая"
    }
}

/// Сайт, по которому можно искать фильтр, и способы, которые к нему применимы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub host: String,
    pub ip: String,
    pub methods: Vec<&'static str>,
}

/// Факты по одному сайту.
#[derive(Debug, Clone, Default)]
pub struct SiteFacts {
    pub host: String,
    pub ip: String,
    pub trace: Option<RouteTrace>,
    /// (способ, что нашёл) — по одному на применимый способ.
    pub found: Vec<(&'static str, FilterFacts)>,
}

/// Вывод по одному способу на сайте.
#[derive(Debug, Clone, Default)]
pub struct MethodVerdict {
    pub method: &'static str,
    pub code: &'static str,
    pub hop: Option<u32>,
    pub text: String,
}

/// Вывод по одному сайту.
#[derive(Debug, Clone, Default)]
pub struct SiteVerdict {
    pub host: String,
    pub ip: String,
    /// [`FILTER_FOUND`] — место названо; иначе код причины из `path_trace`.
    pub code: &'static str,
    pub hop: Option<u32>,
    /// Сколько узлов до сервера (наименьшее из измеренного). 0 — неизвестно.
    pub distance: u32,
    pub text: String,
    pub methods: Vec<MethodVerdict>,
    /// Сколько способов назвали этот узел.
    pub agreeing: usize,
    /// Самое дальнее место, где режут этот сайт. 0 — то же, что `hop`.
    pub far_hop: u32,
}

/// Узел дороги с владельцем.
#[derive(Debug, Clone, PartialEq)]
pub struct HopInfo {
    pub ttl: u32,
    pub address: String,
    pub rtt_ms: Option<f64>,
    pub owner_kind: &'static str,
    /// Как назвать владельца человеку: «ваш роутер», «ваш провайдер»…
    pub owner: String,
    pub asn: String,
}

impl Default for HopInfo {
    /// Python-дефолты: `owner_kind` — «неизвестно», остальное пусто.
    fn default() -> Self {
        Self {
            ttl: 0,
            address: String::new(),
            rtt_ms: None,
            owner_kind: OWNER_UNKNOWN,
            owner: String::new(),
            asn: String::new(),
        }
    }
}

/// Общий вывод по всем сайтам.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Placement {
    pub state: &'static str,
    pub sentence: String,
    pub hop: Option<u32>,
    pub confidence: String,
    /// Наименьшее расстояние до сервера среди сайтов, где фильтр найден.
    pub distance: u32,
    /// Что из этого следует для стратегий обхода. Пусто — сказать нечего.
    pub ttl_advice: String,
    /// На чём держится вывод и что его ослабляет.
    pub reasons: Vec<String>,
}

fn network_of(ip: &str) -> String {
    ip.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// Сайты для поиска: `(имя, адрес, QUIC режут по имени, TCP рвут сбросом по имени)`.
///
/// Берутся только сайты, где блокировка по имени уже доказана сравнением.
/// Сначала по одному из каждой сети: разные адреса — разные дороги и независимые ответы.
pub fn pick_candidates(sites: &[(String, String, bool, bool)], limit: usize) -> Vec<Candidate> {
    let mut usable: Vec<Candidate> = Vec::new();
    for (host, ip, quic_blocked, tcp_reset) in sites {
        if ip.is_empty() || ip.contains(':') || address_kind(ip) != AddressKind::PUBLIC {
            continue;
        }
        let mut methods: Vec<&'static str> = Vec::new();
        if *quic_blocked {
            methods.push(METHOD_QUIC);
        }
        if *tcp_reset {
            methods.push(METHOD_TCP);
        }
        if !methods.is_empty() && usable.iter().all(|item| item.ip != *ip) {
            usable.push(Candidate {
                host: host.clone(),
                ip: ip.clone(),
                methods,
            });
        }
    }
    // Больше способов — надёжнее сайт; при равенстве порядок отчёта: stable sort.
    usable.sort_by_key(|item| std::cmp::Reverse(item.methods.len()));
    let mut picked: Vec<Candidate> = Vec::new();
    let mut networks: Vec<String> = Vec::new();
    for item in &usable {
        if !networks.contains(&network_of(&item.ip)) {
            picked.push(item.clone());
            networks.push(network_of(&item.ip));
        }
    }
    for item in &usable {
        if !picked.contains(item) {
            picked.push(item.clone());
        }
    }
    picked.truncate(limit);
    picked
}

/// Факты по каждому сайту. Сайты идут одновременно (движком), способы на одном
/// сайте — по очереди, поэтому `locate` принимается `&mut` в порядке сайта.
///
/// `trace(адрес)` — узлы по дороге, `locate(способ, имя, адрес, дорога)` ищет
/// место фильтра. Сначала дорога: по ней видно, сколько узлов до сервера, и
/// поиску не приходится перебирать все сроки жизни. Способы по очереди — потому
/// что фильтр запоминает соединение, и две пробы к одному адресу разом мешали
/// бы друг другу.
pub type TraceOf<'a> = dyn Fn(&str) -> Option<RouteTrace> + 'a;
pub type LocateOf<'a> = dyn FnMut(&str, &str, &str, Option<&RouteTrace>) -> FilterFacts + 'a;

pub fn collect(
    candidates: &[Candidate],
    locate: &mut LocateOf<'_>,
    trace: &TraceOf<'_>,
) -> Vec<SiteFacts> {
    candidates
        .iter()
        .map(|candidate| {
            let traced = trace(&candidate.ip);
            let found = candidate
                .methods
                .iter()
                .map(|method| {
                    (
                        *method,
                        locate(method, &candidate.host, &candidate.ip, traced.as_ref()),
                    )
                })
                .collect();
            SiteFacts {
                host: candidate.host.clone(),
                ip: candidate.ip.clone(),
                trace: traced,
                found,
            }
        })
        .collect()
}

/// Вывод по одному сайту. None — проверку сняли.
#[must_use]
pub fn judge_site(facts: &SiteFacts) -> Option<SiteVerdict> {
    let mut methods: Vec<MethodVerdict> = Vec::new();
    let mut distances: Vec<u32> = Vec::new();
    let trace = facts.trace.as_ref().filter(|item| item.supported);
    if let Some(item) = trace {
        if item.reached {
            distances.push(item.hops.len() as u32);
        }
    }
    for (method, found) in &facts.found {
        let verdict = judge_filter(found, trace, method)?;
        if let Some(distance) = found.distance.filter(|value| *value != 0) {
            distances.push(distance);
        }
        methods.push(MethodVerdict {
            method,
            code: verdict.code,
            hop: verdict.hop,
            text: verdict.text,
        });
    }
    if methods.is_empty() {
        return None;
    }
    let distance = distances.iter().copied().min().unwrap_or(0);
    let named_index: Vec<usize> = methods
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            (item.code == FILTER_FOUND && item.hop.is_some()).then_some(index)
        })
        .collect();
    let hops: Vec<u32> = named_index
        .iter()
        .filter_map(|index| methods[*index].hop)
        .collect();
    let unique: Vec<u32> = {
        let mut seen = Vec::new();
        for value in hops {
            if !seen.contains(&value) {
                seen.push(value);
            }
        }
        seen
    };
    let far_hop = if unique.len() > 1 {
        named_index
            .iter()
            .filter_map(|index| methods[*index].hop)
            .max()
            .unwrap_or(0)
    } else {
        0
    };
    let verdict = if unique.len() == 1 {
        let best = &methods[named_index[0]];
        SiteVerdict {
            host: facts.host.clone(),
            ip: facts.ip.clone(),
            code: FILTER_FOUND,
            hop: best.hop,
            distance,
            text: best.text.clone(),
            methods,
            agreeing: named_index.len(),
            far_hop: 0,
        }
    } else if unique.len() > 1 {
        // Способы меряют разные механизмы (QUIC и сброс TCP), и стоять они могут
        // на разных устройствах. Это не противоречие: место сайта — ближайшее,
        // где его поток гаснет.
        let near_index = *named_index
            .iter()
            .min_by_key(|index| methods[**index].hop)?;
        let near = &methods[near_index];
        let both = named_index
            .iter()
            .map(|index| {
                let item = &methods[*index];
                format!(
                    "{} — на узле {}",
                    method_title(item.method),
                    item.hop.unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        SiteVerdict {
            host: facts.host.clone(),
            ip: facts.ip.clone(),
            code: FILTER_FOUND,
            hop: near.hop,
            distance,
            text: format!(
                "режут в разных местах ({both}) — это разные устройства; ближайшее — на узле {}",
                near.hop.unwrap_or(0)
            ),
            methods,
            agreeing: 1,
            far_hop,
        }
    } else {
        // Ни один способ места не назвал: показываем самый содержательный отказ.
        let order = [
            FILTER_AT_TARGET,
            FILTER_UNSURE,
            FILTER_NOT_ON_PATH,
            FILTER_NOT_STATEFUL,
        ];
        let best_index = methods
            .iter()
            .enumerate()
            .min_by_key(|(_, item)| {
                order
                    .iter()
                    .position(|value| *value == item.code)
                    .unwrap_or(order.len())
            })
            .map(|(index, _)| index)?;
        let best = &methods[best_index];
        SiteVerdict {
            host: facts.host.clone(),
            ip: facts.ip.clone(),
            code: best.code,
            hop: None,
            distance,
            text: best.text.clone(),
            methods,
            agreeing: 0,
            far_hop: 0,
        }
    };
    Some(verdict)
}

/// Узлы дороги с владельцами. `owner_of(адрес)` → (номер сети AS, название) или None.
pub type OwnerOf<'a> = dyn Fn(&str) -> Option<(String, String)> + 'a;

#[must_use]
pub fn describe_hops(
    trace: Option<&RouteTrace>,
    own_asn: &str,
    owner_of: &OwnerOf<'_>,
) -> Vec<HopInfo> {
    let Some(item) = trace else {
        return Vec::new();
    };
    if !item.supported {
        return Vec::new();
    }
    let mut hops: Vec<HopInfo> = Vec::new();
    for hop in &item.hops {
        if hop.address.is_empty() {
            hops.push(HopInfo {
                ttl: hop.ttl,
                owner_kind: OWNER_SILENT,
                owner: "не отвечает на пинг".to_string(),
                ..HopInfo::default()
            });
            continue;
        }
        let kind = address_kind(&hop.address);
        if kind == AddressKind::LOCAL {
            let first = hop.ttl == 1;
            hops.push(HopInfo {
                ttl: hop.ttl,
                address: hop.address.clone(),
                rtt_ms: hop.rtt_ms,
                owner_kind: if first { OWNER_ROUTER } else { OWNER_PROVIDER },
                owner: if first {
                    "ваш роутер".to_string()
                } else {
                    "внутренняя сеть провайдера".to_string()
                },
                asn: String::new(),
            });
            continue;
        }
        if kind == AddressKind::CARRIER {
            hops.push(HopInfo {
                ttl: hop.ttl,
                address: hop.address.clone(),
                rtt_ms: hop.rtt_ms,
                owner_kind: OWNER_PROVIDER,
                owner: "сеть провайдера (общий адрес, CGNAT)".to_string(),
                asn: String::new(),
            });
            continue;
        }
        let found = if kind == AddressKind::PUBLIC {
            owner_of(&hop.address)
        } else {
            None
        };
        let Some((asn, name)) = found else {
            hops.push(HopInfo {
                ttl: hop.ttl,
                address: hop.address.clone(),
                rtt_ms: hop.rtt_ms,
                ..HopInfo::default()
            });
            continue;
        };
        if !own_asn.is_empty() && asn == own_asn {
            hops.push(HopInfo {
                ttl: hop.ttl,
                address: hop.address.clone(),
                rtt_ms: hop.rtt_ms,
                owner_kind: OWNER_PROVIDER,
                owner: format!(
                    "ваш провайдер ({})",
                    if name.is_empty() {
                        format!("AS{asn}")
                    } else {
                        name.clone()
                    }
                ),
                asn,
            });
        } else {
            let label = if !name.is_empty() && !asn.is_empty() {
                format!("{name} (AS{asn})")
            } else if !name.is_empty() {
                name.clone()
            } else if !asn.is_empty() {
                format!("AS{asn}")
            } else {
                String::new()
            };
            hops.push(HopInfo {
                ttl: hop.ttl,
                address: hop.address.clone(),
                rtt_ms: hop.rtt_ms,
                owner_kind: if label.is_empty() {
                    OWNER_UNKNOWN
                } else {
                    OWNER_OTHER
                },
                owner: label,
                asn,
            });
        }
    }
    hops
}

/// Чья сеть на участке перед узлом `hop`. Пусто — сказать нечего.
fn whose(hop: u32, hops: &[HopInfo]) -> String {
    if hop == 1 {
        return "в вашем роутере или на самом компьютере".to_string();
    }
    let by_ttl: BTreeMap<u32, &HopInfo> = hops.iter().map(|item| (item.ttl, item)).collect();
    let before = by_ttl.get(&(hop - 1)).copied();
    let after = by_ttl.get(&hop).copied();
    let kinds = (
        before.map_or(OWNER_UNKNOWN, |item| item.owner_kind),
        after.map_or(OWNER_UNKNOWN, |item| item.owner_kind),
    );
    let home = [OWNER_ROUTER, OWNER_PROVIDER];
    if home.contains(&kinds.0) && home.contains(&kinds.1) {
        return "в сети вашего провайдера".to_string();
    }
    if home.contains(&kinds.0) && kinds.1 == OWNER_OTHER {
        return format!(
            "на выходе из сети вашего провайдера, на стыке с {}",
            after.map_or("", |item| item.owner.as_str())
        );
    }
    if kinds.0 == OWNER_OTHER && kinds.1 == OWNER_OTHER {
        let same = before
            .map(|item| {
                !item.asn.is_empty() && Some(item.asn.clone()) == after.map(|next| next.asn.clone())
            })
            .unwrap_or(false);
        if same {
            return format!(
                "у вышестоящего оператора {}",
                after.map_or("", |item| item.owner.as_str())
            );
        }
        return format!(
            "у вышестоящих операторов, на стыке {} и {}",
            before.map_or("", |item| item.owner.as_str()),
            after.map_or("", |item| item.owner.as_str())
        );
    }
    if home.contains(&kinds.0) {
        // Следующий узел молчит или неизвестен: фильтр сразу за сетью провайдера.
        return "в сети вашего провайдера или сразу за ней".to_string();
    }
    String::new()
}

fn ttl_advice(hop: u32, distance: u32) -> String {
    if distance == 0 || distance <= hop {
        return format!(
            "Поддельным пакетам стратегии нужен срок жизни (TTL) не меньше {hop}: с меньшим они \
             погибнут раньше фильтра, и он их не увидит."
        );
    }
    if distance - 1 == hop {
        return format!(
            "Поддельным пакетам стратегии подходит срок жизни (TTL) ровно {hop}: с меньшим они не дойдут до \
             фильтра, а с {distance} и больше дойдут до сервера и сломают соединение."
        );
    }
    format!(
        "Поддельным пакетам стратегии подходит срок жизни (TTL) от {hop} до {}: с меньшим они не \
         дойдут до фильтра, а с {distance} и больше дойдут до сервера и сломают соединение.",
        distance - 1
    )
}

fn sites_word(count: usize) -> String {
    if count % 10 == 1 && count % 100 != 11 {
        format!("{count} сайту")
    } else {
        format!("{count} сайтам")
    }
}

/// (ближайшее место, сколько сайтов его назвали, самое дальнее место). None — согласия нет.
///
/// Места считаются по каждому способу отдельно: QUIC и сброс TCP — разные
/// механизмы и могут стоять на разных устройствах. Внутри способа место
/// берётся по большинству сайтов; один сайт с другим узлом — это его дорога
/// или его CDN, а не повод отказаться от вывода. Ничья согласием не считается.
fn counter_most_common(counter: &[(u32, usize)], top: usize) -> Vec<(u32, usize)> {
    let mut items: Vec<(u32, usize)> = counter.to_vec();
    // python Counter.most_common ничьи держит в порядке вставки — стабильный sort.
    items.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    items.truncate(top);
    items
}

fn consensus(found: &[&SiteVerdict]) -> Option<(u32, usize, u32)> {
    let mut by_method: Vec<(&'static str, Vec<(u32, usize)>)> = Vec::new();
    for item in found {
        let parts: Vec<&MethodVerdict> = item
            .methods
            .iter()
            .filter(|part| part.code == FILTER_FOUND && part.hop.is_some())
            .collect();
        let mut bump = |method: &'static str, hop: u32| {
            let found_entry = by_method
                .iter_mut()
                .find(|(key, _)| *key == method)
                .is_some();
            if !found_entry {
                by_method.push((method, Vec::new()));
            }
            let entry = &mut by_method
                .iter_mut()
                .find(|(key, _)| *key == method)
                .unwrap()
                .1;
            match entry.iter_mut().find(|(value, _)| *value == hop) {
                Some(item) => item.1 += 1,
                None => entry.push((hop, 1)),
            }
        };
        if parts.is_empty() {
            bump("", item.hop.unwrap_or(0));
        } else {
            for part in parts {
                bump(part.method, part.hop.unwrap_or(0));
            }
        }
    }
    let mut places: Vec<(u32, usize)> = Vec::new();
    for (_, counter) in &by_method {
        let top = counter_most_common(counter, 2);
        if top.len() == 1 || top[0].1 > top[1].1 {
            places.push(top[0]);
        }
    }
    if places.is_empty() {
        return None;
    }
    let hop = places.iter().map(|(place, _)| *place).min()?;
    let votes = places
        .iter()
        .filter(|(place, _)| *place == hop)
        .map(|(_, count)| *count)
        .max()?;
    let far = places.iter().map(|(place, _)| *place).max()?;
    Some((hop, votes, far))
}

/// Общий вывод по всем сайтам. `hops` — узлы дороги того сайта, по которому называем место.
#[must_use]
pub fn aggregate(
    verdicts: &[SiteVerdict],
    hops: &[HopInfo],
    zapret_running: Option<bool>,
    other_tools: &[String],
) -> Placement {
    let tools: Vec<&str> = other_tools.iter().map(String::as_str).collect();
    let zapret = zapret_running.unwrap_or(false);
    let mut local: Vec<String> = Vec::new();
    if zapret {
        local.push("Zapret".to_string());
    }
    local.extend(other_tools.iter().cloned());
    let _ = tools;
    if verdicts.is_empty() {
        let why = if zapret {
            " Возможно, потому что сейчас работает Zapret: место фильтра ищется на сети без обхода."
        } else {
            ""
        };
        return Placement {
            state: STATE_NONE,
            sentence: format!(
                "Блокировок по имени сайта в этой проверке не видно — искать место фильтра не по чему.{why}"
            ),
            ..Placement::default()
        };
    }
    let found: Vec<&SiteVerdict> = verdicts
        .iter()
        .filter(|item| item.code == FILTER_FOUND && item.hop.is_some())
        .collect();
    if found.is_empty() {
        let best = &verdicts[0];
        if !local.is_empty() {
            // Программа обхода переделывает пакеты с запрещённым именем: фильтр на них не
            // срабатывает, и поиск видит «фильтра нет» там, где он есть.
            return Placement {
                state: STATE_DISTURBED,
                sentence: format!(
                    "Место фильтра не найдено, но во время поиска работал {}: программа обхода \
                     переделывает пакеты с запрещённым именем, и фильтр на них не срабатывает. \
                     Остановите её и повторите проверку — место фильтра ищется только на сети без обхода.",
                    local.join(", ")
                ),
                reasons: verdicts
                    .iter()
                    .map(|item| format!("{}: {}", item.host, item.text))
                    .collect(),
                ..Placement::default()
            };
        }
        return Placement {
            state: STATE_NOT_FOUND,
            sentence: format!("Место фильтра определить не удалось: {}.", best.text),
            reasons: verdicts
                .iter()
                .map(|item| format!("{}: {}", item.host, item.text))
                .collect(),
            ..Placement::default()
        };
    }
    // python Counter: порядок вставки хранит порядок первых появлений узлов.
    let mut counts: Vec<(u32, usize)> = Vec::new();
    for item in &found {
        let value = item.hop.unwrap_or(0);
        if let Some(entry) = counts.iter_mut().find(|(known, _)| *known == value) {
            entry.1 += 1;
        } else {
            counts.push((value, 1));
        }
    }
    let agreed = consensus(&found);
    let (hop, votes, mut far) = match agreed {
        Some(value) => value,
        None => {
            // python most_common(1): максимум по количеству; при равенстве — раньше появившийся.
            // python most_common(1): максимум по количеству; при равенстве — раньше появившийся.
            let pick = counts
                .iter()
                .enumerate()
                .min_by_key(|(index, (_, count))| (std::cmp::Reverse(*count), *index))
                .map(|(_, (value, count))| (*value, *count));
            match pick {
                Some((value, count)) => (value, count, 0),
                None => (0, 0, 0),
            }
        }
    };
    let mut reasons: Vec<String> = found
        .iter()
        .map(|item| {
            format!(
                "{}: узел {}{}{}",
                item.host,
                item.hop.unwrap_or(0),
                if item.distance != 0 {
                    format!(", сервер на узле {}", item.distance)
                } else {
                    String::new()
                },
                if item.agreeing > 1 {
                    " (двумя способами)"
                } else {
                    ""
                }
            )
        })
        .collect();
    reasons.extend(
        verdicts
            .iter()
            .filter(|item| {
                !found
                    .iter()
                    .any(|one| std::ptr::eq::<SiteVerdict>(*one, *item))
            })
            .map(|item| format!("{}: {}", item.host, item.text)),
    );
    if hop == 1 && !local.is_empty() {
        return Placement {
            state: STATE_DISTURBED,
            sentence: format!(
                "Соединение гасится уже на первом узле, но на компьютере работает {} — так выглядит \
                 и своя программа обхода. Остановите её и повторите проверку: тогда будет видно \
                 место фильтра провайдера.",
                local.join(", ")
            ),
            reasons,
            ..Placement::default()
        };
    }
    if agreed.is_none() {
        let mut spread_values: Vec<u32> = counts.iter().map(|(value, _)| *value).collect();
        spread_values.sort_unstable();
        let spread = spread_values
            .iter()
            .map(|value| format!("узел {value}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Placement {
            state: STATE_DISAGREE,
            sentence: format!(
                "По разным сайтам фильтр оказался на разных узлах ({spread}). Так бывает, когда \
                 фильтров несколько или дороги к сайтам расходятся раньше фильтра — одного места \
                 назвать нельзя."
            ),
            reasons,
            ..Placement::default()
        };
    }
    let agreeing = found.iter().map(|item| item.agreeing).max().unwrap_or(1);
    let mut confidence = if votes >= 3 || (votes >= 2 && agreeing > 1) {
        CONFIDENCE_HIGH
    } else if votes >= 2 || agreeing > 1 {
        CONFIDENCE_MEDIUM
    } else {
        CONFIDENCE_LOW
    };
    let distance = found
        .iter()
        .filter(|item| item.distance != 0)
        .map(|item| item.distance)
        .min()
        .unwrap_or(0);
    let whose = whose(hop, hops);
    // Подделка должна дожить до самого дальнего фильтра: ближний её пропустит, а дальний иначе не увидит.
    far = far.max(hop);
    let where_word = if hop == 1 {
        "не дальше первого узла от вас".to_string()
    } else {
        format!("между узлами {} и {hop} от вас", hop - 1)
    };
    let basis = if votes > 1 {
        format!("совпало по {}", sites_word(votes))
    } else {
        "найдено по одному сайту".to_string()
    };
    if !local.is_empty() {
        reasons.push(format!(
            "во время поиска работали: {} — они могли исказить результат",
            local.join(", ")
        ));
        // Программа обхода на этом компьютере гасила бы поток уже на первом узле; раз место дальше,
        // это не она. Уверенность всё же на ступень ниже: VPN мог изменить саму дорогу.
        confidence = if confidence == CONFIDENCE_HIGH {
            CONFIDENCE_MEDIUM
        } else {
            CONFIDENCE_LOW
        };
    }
    let several = far > hop;
    if several {
        reasons.push(format!(
            "дальше по дороге есть ещё одно место, где режут: узел {far} (другим способом)"
        ));
    }
    Placement {
        state: STATE_FOUND,
        sentence: format!(
            "{}{where_word}{}. Уверенность {}: {basis}.{}",
            if several {
                "Ближайший фильтр стоит "
            } else {
                "Фильтр стоит "
            },
            if whose.is_empty() {
                String::new()
            } else {
                format!(" — {whose}")
            },
            confidence_text(confidence),
            if several {
                format!(" Фильтров на дороге не меньше двух: ещё один — на узле {far}.")
            } else {
                String::new()
            }
        ),
        hop: Some(hop),
        confidence: confidence.to_string(),
        distance,
        ttl_advice: ttl_advice(far, distance),
        reasons,
    }
}

/// Итог для экрана. `shown` — сайт, по дороге которого показаны узлы.
#[must_use]
pub fn report(
    placement: &Placement,
    verdicts: &[SiteVerdict],
    hops: &[HopInfo],
    shown: Option<&SiteVerdict>,
) -> Value {
    let found = placement.state == STATE_FOUND;
    let mut object = Map::new();
    object.insert("state".into(), json!(placement.state));
    object.insert("found".into(), json!(found));
    object.insert("hop".into(), json!(placement.hop));
    object.insert("confidence".into(), json!(placement.confidence));
    object.insert("distance".into(), json!(placement.distance));
    object.insert("text".into(), json!(placement.sentence));
    object.insert("ttl_advice".into(), json!(placement.ttl_advice));
    object.insert("reasons".into(), json!(placement.reasons));
    object.insert(
        "host".into(),
        json!(shown.map_or(String::new(), |item| item.host.clone())),
    );
    object.insert(
        "address".into(),
        json!(shown.map_or(String::new(), |item| item.ip.clone())),
    );
    object.insert(
        "sites".into(),
        json!(verdicts
            .iter()
            .map(|item| json!({
                "host": item.host,
                "address": item.ip,
                "found": item.code == FILTER_FOUND,
                "code": item.code,
                "hop": item.hop,
                "distance": item.distance,
                "text": item.text,
                "methods": item.methods.iter().map(|part| json!({
                    "method": part.method,
                    "title": method_title(part.method),
                    "code": part.code,
                    "hop": part.hop,
                    "text": part.text,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()),
    );
    object.insert(
        "hops".into(),
        json!(hops
            .iter()
            .map(|hop| json!({
                "ttl": hop.ttl,
                "address": hop.address,
                "rtt_ms": hop.rtt_ms,
                "owner": hop.owner,
                "owner_kind": hop.owner_kind,
                "asn": hop.asn,
            }))
            .collect::<Vec<_>>()),
    );
    Value::Object(object)
}

pub const MECHANISM_QUIC_TITLE: &str = "QUIC по имени сайта";
pub const MECHANISM_TCP_TITLE: &str = "TLS по имени сайта (сброс соединения)";
pub const MECHANISM_DNS_TITLE: &str = "Перехват обычных DNS-запросов";

/// Механизмы, место которых обычным соединением не найти, и почему.
pub const UNMEASURED: [(&str, &str); 2] = [
    (
        "Бан по адресу",
        "пакет к закрытому адресу пропадает так же, как пакет с истёкшим сроком жизни, — где именно, \
         обычным соединением не различить",
    ),
    (
        "Обрыв загрузки на 16–20 КБ",
        "обрыв случается на ответе сервера, а его срок жизни задаёт сервер — приём со сроком жизни здесь не работает",
    ),
];

/// Место каждого механизма по отдельности: фильтров на дороге бывает несколько.
///
/// Поиск по одному механизму видит только первое место, где поток гаснет, —
/// второе устройство за ним не разглядеть. Зато у разных механизмов места
/// находятся независимо: разошлись — устройств не меньше двух. `dns` — вывод
/// [`crate::dns_place::judge`] или None.
#[must_use]
pub fn mechanisms(
    verdicts: &[SiteVerdict],
    dns: Option<&crate::dns_place::DnsPlaceVerdict>,
) -> Value {
    let mut found: Vec<Value> = Vec::new();
    for method in [METHOD_QUIC, METHOD_TCP] {
        let mut tried: Vec<(&SiteVerdict, &MethodVerdict)> = Vec::new();
        for site in verdicts {
            for part in &site.methods {
                if part.method == method {
                    tried.push((site, part));
                }
            }
        }
        if tried.is_empty() {
            continue;
        }
        // python Counter: порядок вставки, потом максимум по количеству.
        let mut hops: Vec<(u32, usize)> = Vec::new();
        for (_site, part) in &tried {
            if part.code == FILTER_FOUND && part.hop.is_some() {
                let value = part.hop.unwrap_or(0);
                if let Some(entry) = hops.iter_mut().find(|(known, _)| *known == value) {
                    entry.1 += 1;
                } else {
                    hops.push((value, 1));
                }
            }
        }
        let (hop, text) = if hops.is_empty() {
            (None, format!("место не найдено: {}", tried[0].1.text))
        } else {
            let (best, votes) = counter_most_common(&hops, 1)[0];
            let where_word = if best == 1 {
                "не дальше первого узла".to_string()
            } else {
                format!("между узлами {} и {best}", best - 1)
            };
            let spread = if hops.len() == 1 {
                String::new()
            } else {
                let mut values: Vec<u32> = hops.iter().map(|(value, _)| *value).collect();
                values.sort_unstable();
                format!(
                    "; на других сайтах — узлы {}",
                    values
                        .iter()
                        .filter(|value| **value != best)
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            (
                Some(best),
                format!(
                    "{where_word} — совпало по {} из {}{spread}",
                    sites_word(votes),
                    tried.len()
                ),
            )
        };
        let title = if method == METHOD_QUIC {
            MECHANISM_QUIC_TITLE
        } else {
            MECHANISM_TCP_TITLE
        };
        found.push(json!({"key": method, "title": title, "hop": hop, "text": text}));
    }
    if let Some(item) = dns {
        found.push(json!({
            "key": "dns",
            "title": MECHANISM_DNS_TITLE,
            "hop": item.hop,
            "text": item.text,
        }));
    }
    let mut places: Vec<u32> = found
        .iter()
        .filter_map(|item| item["hop"].as_u64().map(|value| value as u32))
        .collect();
    places.sort_unstable();
    places.dedup();
    let named = found
        .iter()
        .filter(|item| item["hop"].as_u64().is_some())
        .count();
    let same = if places.len() > 1 {
        format!(
            "Места у механизмов разные (узлы {}): устройств на дороге не меньше двух.",
            places
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if !places.is_empty() && named > 1 {
        "Места у механизмов совпали: это может быть одно устройство. Второе, стоящее дальше, этим способом не увидеть.".to_string()
    } else if !places.is_empty() {
        "Место найдено по одному механизму. Поиск видит только первое место, где соединение гаснет: \
         второй фильтр, стоящий дальше, за ним не разглядеть."
            .to_string()
    } else {
        String::new()
    };
    json!({
        "mechanisms": found,
        "same_place": same,
        "unmeasured": UNMEASURED.iter().map(|(title, text)| json!({
            "title": title,
            "text": text,
        })).collect::<Vec<_>>(),
    })
}

/// Раздел «Где стоит фильтр» для текстового отчёта.
#[must_use]
pub fn lines(place: &Value) -> Vec<String> {
    let mut out = vec![
        String::new(),
        "━━━━━━━━ Где стоит фильтр ━━━━━━━━".to_string(),
    ];
    let state = place["state"].as_str().unwrap_or("");
    let icon = match state {
        STATE_FOUND => "📍",
        STATE_DISAGREE | STATE_DISTURBED => "⚠️",
        _ => "ℹ️",
    };
    out.push(format!("{} {}", icon, place["text"].as_str().unwrap_or("")));
    if let Some(advice) = place["ttl_advice"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        out.push(format!("   👉 {advice}"));
    }
    for site in place["sites"].as_array().unwrap_or(&Vec::new()) {
        let mark = if site["found"].as_bool().unwrap_or(false) {
            "📍"
        } else {
            "❔"
        };
        let distance = if site["distance"].as_u64().unwrap_or(0) == 0 {
            String::new()
        } else {
            format!(
                ", до сервера {} узлов",
                site["distance"].as_u64().unwrap_or(0)
            )
        };
        out.push(format!(
            "   {} {} ({}{}): {}",
            mark,
            site["host"].as_str().unwrap_or(""),
            site["address"].as_str().unwrap_or(""),
            distance,
            site["text"].as_str().unwrap_or("")
        ));
        for method in site["methods"].as_array().unwrap_or(&Vec::new()) {
            out.push(format!(
                "        {}: {}",
                method["title"].as_str().unwrap_or(""),
                method["text"].as_str().unwrap_or("")
            ));
        }
    }
    if place["mechanisms"].as_array().is_some() {
        out.push("   Чем и где режут:".to_string());
        for item in place["mechanisms"].as_array().unwrap_or(&Vec::new()) {
            out.push(format!(
                "      {} {}: {}",
                if item["hop"].as_u64().is_some() {
                    "📍"
                } else {
                    "❔"
                },
                item["title"].as_str().unwrap_or(""),
                item["text"].as_str().unwrap_or("")
            ));
        }
        if let Some(same) = place["same_place"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            out.push(format!("      ℹ️ {same}"));
        }
        for item in place["unmeasured"].as_array().unwrap_or(&Vec::new()) {
            out.push(format!(
                "      ➖ {}: место не измеряется — {}",
                item["title"].as_str().unwrap_or(""),
                item["text"].as_str().unwrap_or("")
            ));
        }
    }
    let hops = place["hops"].as_array().cloned().unwrap_or_default();
    if !hops.is_empty() {
        out.push(format!(
            "   Дорога до {}:",
            place["host"].as_str().unwrap_or("")
        ));
        for hop in hops {
            if place["found"].as_bool().unwrap_or(false)
                && hop["ttl"].as_u64().unwrap_or(0) == place["hop"].as_u64().unwrap_or(0)
            {
                out.push("      ── здесь стоит фильтр ──".to_string());
            }
            let rtt = match hop["rtt_ms"].as_f64() {
                Some(value) => {
                    if value < 1.0 {
                        "< 1 мс".to_string()
                    } else {
                        // python round: половины к чётным.
                        let lowered = (value).floor();
                        let diff = value - lowered;
                        let rounded = if (diff - 0.5).abs() < f64::EPSILON {
                            if lowered % 2.0 == 0.0 {
                                lowered
                            } else {
                                lowered + 1.0
                            }
                        } else if diff > 0.5 {
                            lowered + 1.0
                        } else {
                            lowered
                        };
                        format!("{rounded} мс")
                    }
                }
                None => String::new(),
            };
            let address = hop["address"]
                .as_str()
                .filter(|value| !value.is_empty())
                .unwrap_or("не ответил");
            let owner = hop["address"]
                .as_str()
                .filter(|value| !value.is_empty())
                .map_or("", |_| hop["owner"].as_str().unwrap_or(""));
            let parts: Vec<&str> = [address, rtt.as_str(), owner]
                .iter()
                .copied()
                .filter(|part| !part.is_empty())
                .collect();
            out.push(format!(
                "      {:>2}. {}",
                hop["ttl"].as_u64().unwrap_or(0),
                parts.join(" · ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_place::{DnsPlaceVerdict, PLACE_FOUND};
    use crate::icmp::{HOP_ROUTER, HOP_SILENT, HOP_TARGET};
    use crate::path_trace::Hop;

    const OWN_ASN: &str = "8359";
    const ROAD: [&str; 6] = [
        "192.168.1.1",
        "100.64.0.1",
        "212.188.1.1",
        "195.34.50.1",
        "62.115.1.1",
        "",
    ];

    fn owner_of(ip: &str) -> Option<(String, String)> {
        match ip {
            "212.188.1.1" | "195.34.50.1" => Some((OWN_ASN.to_string(), "MTS".to_string())),
            "62.115.1.1" => Some(("1299".to_string(), "Arelion".to_string())),
            _ => None,
        }
    }

    fn trace(target: &str, addresses: &[&str]) -> RouteTrace {
        let mut hops: Vec<Hop> = addresses
            .iter()
            .enumerate()
            .map(|(index, address)| Hop {
                ttl: index as u32 + 1,
                kind: if address.is_empty() {
                    HOP_SILENT
                } else {
                    HOP_ROUTER
                },
                address: (*address).to_string(),
                rtt_ms: if address.is_empty() {
                    None
                } else {
                    Some(2.0 * (index as f64 + 1.0))
                },
            })
            .collect();
        hops.push(Hop {
            ttl: hops.len() as u32 + 1,
            kind: HOP_TARGET,
            address: target.to_string(),
            rtt_ms: Some(30.0),
        });
        RouteTrace {
            target: target.to_string(),
            hops,
            reached: true,
            supported: true,
        }
    }

    fn found(hop: u32, distance: u32) -> FilterFacts {
        FilterFacts {
            control_ok: Some(true),
            stateful: Some(true),
            first_blocked_ttl: Some(hop),
            checked_up_to: hop,
            cancelled: false,
            neutral_passes: Some(true),
            next_blocked: Some(true),
            distance: Some(distance),
        }
    }

    fn site(host: &str, ip: &str, found_pair: &[(&'static str, FilterFacts)]) -> SiteFacts {
        SiteFacts {
            host: host.to_string(),
            ip: ip.to_string(),
            trace: Some(trace(ip, &ROAD)),
            found: found_pair.to_vec(),
        }
    }

    fn hops_of_road() -> Vec<HopInfo> {
        describe_hops(Some(&trace("5.5.5.5", &ROAD)), OWN_ASN, &owner_of)
    }

    #[test]
    fn only_sites_blocked_by_name_with_a_public_ipv4_address_are_used() {
        let picked = pick_candidates(
            &[
                (
                    "open.example".to_string(),
                    "1.1.1.1".to_string(),
                    false,
                    false,
                ),
                (
                    "quic.example".to_string(),
                    "2.2.2.2".to_string(),
                    true,
                    false,
                ),
                (
                    "both.example".to_string(),
                    "3.3.3.3".to_string(),
                    true,
                    true,
                ),
                (
                    "v6.example".to_string(),
                    "2001:db8::1".to_string(),
                    true,
                    true,
                ),
                (
                    "lan.example".to_string(),
                    "192.168.1.5".to_string(),
                    true,
                    true,
                ),
                ("noaddr.example".to_string(), String::new(), true, true),
            ],
            MAX_SITES,
        );
        let listing: Vec<(&str, Vec<&str>)> = picked
            .iter()
            .map(|item| (item.host.as_str(), item.methods.clone()))
            .collect();
        assert_eq!(
            listing,
            [
                ("both.example", vec![METHOD_QUIC, METHOD_TCP]),
                ("quic.example", vec![METHOD_QUIC])
            ]
        );
    }

    #[test]
    fn different_networks_go_first_and_one_address_is_used_once() {
        let mut sites: Vec<(String, String, bool, bool)> = (0..3)
            .map(|item| {
                (
                    format!("s{item}.example"),
                    format!("45.{item}.0.1"),
                    true,
                    false,
                )
            })
            .collect();
        sites.insert(
            1,
            (
                "same-net.example".to_string(),
                "45.0.9.9".to_string(),
                true,
                false,
            ),
        );
        sites.push((
            "same-ip.example".to_string(),
            "45.0.0.1".to_string(),
            true,
            false,
        ));
        let picked = pick_candidates(&sites, 3);
        let hosts: Vec<&str> = picked.iter().map(|item| item.host.as_str()).collect();
        assert_eq!(hosts, ["s0.example", "s1.example", "s2.example"]);
        assert_eq!(pick_candidates(&sites, 9).len(), 4);
    }

    #[test]
    fn two_methods_naming_one_hop_agree() {
        let verdict = judge_site(&site(
            "x.com",
            "5.5.5.5",
            &[(METHOD_QUIC, found(4, 7)), (METHOD_TCP, found(4, 7))],
        ))
        .unwrap();
        assert_eq!(
            (
                verdict.code,
                verdict.hop,
                verdict.agreeing,
                verdict.distance
            ),
            (FILTER_FOUND, Some(4), 2, 7)
        );
    }

    #[test]
    fn two_methods_naming_different_hops_are_two_devices_not_a_contradiction() {
        let verdict = judge_site(&site(
            "x.com",
            "5.5.5.5",
            &[(METHOD_QUIC, found(4, 7)), (METHOD_TCP, found(2, 7))],
        ))
        .unwrap();
        assert_eq!(
            (verdict.code, verdict.hop, verdict.far_hop, verdict.agreeing),
            (FILTER_FOUND, Some(2), 4, 1)
        );
        assert!(verdict.text.contains("разные устройства"));
    }

    #[test]
    fn placement_names_the_nearest_filter_and_keeps_fakes_alive_to_the_farthest() {
        let verdicts: Vec<SiteVerdict> = [
            ("a.com", "5.5.5.5"),
            ("b.com", "6.6.6.6"),
            ("c.com", "7.7.7.7"),
        ]
        .iter()
        .map(|(host, ip)| {
            judge_site(&site(
                host,
                ip,
                &[(METHOD_QUIC, found(2, 7)), (METHOD_TCP, found(4, 7))],
            ))
            .unwrap()
        })
        .collect();
        let placement = aggregate(&verdicts, &[], None, &[]);
        assert_eq!((placement.state, placement.hop), (STATE_FOUND, Some(2)));
        assert!(placement.sentence.contains("Ближайший фильтр"));
        assert!(placement.sentence.contains("не меньше двух"));
        assert!(placement.ttl_advice.contains("от 4"));
        assert!(!placement.ttl_advice.contains("от 2"));
    }

    #[test]
    fn one_method_failing_does_not_cancel_the_other() {
        let silent = FilterFacts {
            control_ok: Some(true),
            stateful: Some(false),
            distance: Some(7),
            ..FilterFacts::default()
        };
        let verdict = judge_site(&site(
            "x.com",
            "5.5.5.5",
            &[(METHOD_TCP, silent), (METHOD_QUIC, found(4, 7))],
        ))
        .unwrap();
        assert_eq!(
            (verdict.code, verdict.hop, verdict.agreeing),
            (FILTER_FOUND, Some(4), 1)
        );
    }

    #[test]
    fn server_distance_is_the_smallest_of_what_was_measured() {
        let verdict = judge_site(&site("x.com", "5.5.5.5", &[(METHOD_QUIC, found(6, 6))])).unwrap();
        assert_eq!(
            (verdict.code, verdict.hop, verdict.distance),
            (FILTER_AT_TARGET, None, 6)
        );
    }

    #[test]
    fn cancelled_search_gives_no_verdict() {
        let cancelled = SiteFacts {
            host: "x.com".to_string(),
            ip: "5.5.5.5".to_string(),
            trace: Some(trace("5.5.5.5", &ROAD)),
            found: vec![(
                METHOD_QUIC,
                FilterFacts {
                    cancelled: true,
                    ..FilterFacts::default()
                },
            )],
        };
        assert!(judge_site(&cancelled).is_none());
    }

    #[test]
    fn hops_are_named_by_whose_network_they_are() {
        let listed = hops_of_road();
        let kinds: Vec<(u32, &str)> = listed.iter().map(|hop| (hop.ttl, hop.owner_kind)).collect();
        assert_eq!(
            kinds,
            [
                (1, OWNER_ROUTER),
                (2, OWNER_PROVIDER),
                (3, OWNER_PROVIDER),
                (4, OWNER_PROVIDER),
                (5, OWNER_OTHER),
                (6, OWNER_SILENT),
                (7, OWNER_UNKNOWN)
            ]
        );
        assert_eq!(listed[0].owner, "ваш роутер");
        assert!(listed[1].owner.contains("CGNAT"));
        assert_eq!(listed[2].owner, "ваш провайдер (MTS)");
        assert_eq!(listed[4].owner, "Arelion (AS1299)");
    }

    #[test]
    fn private_address_beyond_the_first_hop_is_the_provider_not_the_router() {
        let listed = describe_hops(
            Some(&trace("5.5.5.5", &["192.168.1.1", "10.20.0.1"])),
            OWN_ASN,
            &owner_of,
        );
        assert_eq!(listed[0].owner, "ваш роутер");
        assert_eq!(listed[1].owner, "внутренняя сеть провайдера");
    }

    #[test]
    fn unsupported_trace_gives_no_hops() {
        assert!(describe_hops(
            Some(&RouteTrace {
                target: "5.5.5.5".to_string(),
                supported: false,
                ..RouteTrace::default()
            }),
            OWN_ASN,
            &owner_of
        )
        .is_empty());
        assert!(describe_hops(None, OWN_ASN, &owner_of).is_empty());
    }

    fn verdicts_by_hops(listing: &[u32], distance: u32, agreeing: usize) -> Vec<SiteVerdict> {
        listing
            .iter()
            .enumerate()
            .map(|(index, hop)| SiteVerdict {
                host: format!("s{index}.example"),
                ip: format!("45.{index}.0.1"),
                code: FILTER_FOUND,
                hop: Some(*hop),
                distance,
                text: format!("узел {hop}"),
                methods: Vec::new(),
                agreeing,
                far_hop: 0,
            })
            .collect()
    }

    #[test]
    fn three_sites_on_one_hop_is_a_confident_place_in_the_provider_network() {
        let place = aggregate(
            &verdicts_by_hops(&[4, 4, 4], 7, 1),
            &hops_of_road(),
            None,
            &[],
        );
        assert_eq!(
            (
                place.state,
                place.hop,
                place.confidence.as_str(),
                place.distance
            ),
            (STATE_FOUND, Some(4), CONFIDENCE_HIGH, 7)
        );
        assert!(place
            .sentence
            .contains("между узлами 3 и 4 от вас — в сети вашего провайдера"));
        assert!(place.sentence.contains("совпало по 3 сайтам"));
    }

    #[test]
    fn confidence_follows_how_much_agreed() {
        assert_eq!(
            aggregate(&verdicts_by_hops(&[4], 7, 1), &hops_of_road(), None, &[]).confidence,
            CONFIDENCE_LOW
        );
        assert_eq!(
            aggregate(&verdicts_by_hops(&[4, 4], 7, 1), &hops_of_road(), None, &[]).confidence,
            CONFIDENCE_MEDIUM
        );
        assert_eq!(
            aggregate(&verdicts_by_hops(&[4], 7, 2), &hops_of_road(), None, &[]).confidence,
            CONFIDENCE_MEDIUM
        );
        assert_eq!(
            aggregate(&verdicts_by_hops(&[4, 4], 7, 2), &hops_of_road(), None, &[]).confidence,
            CONFIDENCE_HIGH
        );
    }

    #[test]
    fn ttl_range_for_fakes_is_from_the_filter_to_just_before_the_server() {
        assert!(
            aggregate(&verdicts_by_hops(&[4], 7, 1), &hops_of_road(), None, &[])
                .ttl_advice
                .contains("от 4 до 6")
        );
        assert!(
            aggregate(&verdicts_by_hops(&[4], 5, 1), &hops_of_road(), None, &[])
                .ttl_advice
                .contains("ровно 4")
        );
        assert!(
            aggregate(&verdicts_by_hops(&[4], 0, 1), &hops_of_road(), None, &[])
                .ttl_advice
                .contains("не меньше 4")
        );
        // Берётся ближайший сервер: поддельный пакет не должен дойти ни до одного.
        let mut mixed = verdicts_by_hops(&[4], 7, 1);
        mixed.push(SiteVerdict {
            host: "near.example".to_string(),
            ip: "46.0.0.1".to_string(),
            code: FILTER_FOUND,
            hop: Some(4),
            distance: 6,
            text: "узел 4".to_string(),
            methods: Vec::new(),
            agreeing: 0,
            far_hop: 0,
        });
        assert!(aggregate(&mixed, &hops_of_road(), None, &[])
            .ttl_advice
            .contains("от 4 до 5"));
    }

    #[test]
    fn place_is_named_by_the_border_it_stands_on() {
        assert!(
            aggregate(&verdicts_by_hops(&[5], 7, 1), &hops_of_road(), None, &[])
                .sentence
                .contains("на стыке с Arelion (AS1299)")
        );
        assert!(
            aggregate(&verdicts_by_hops(&[1], 7, 1), &hops_of_road(), None, &[])
                .sentence
                .contains("в вашем роутере или на самом компьютере")
        );
        // Узлы неизвестны — место названо числом, без догадок о владельце.
        let sentence = aggregate(&verdicts_by_hops(&[4], 7, 1), &[], None, &[]).sentence;
        assert!(!sentence.contains("провайдер"));
    }

    #[test]
    fn one_site_with_another_hop_does_not_cancel_the_majority() {
        // Живой случай (стенд): QUIC у трёх сайтов на узле 6, у четвёртого — на 12, а TCP у него же на 9.
        let site = |host: &str, quic: u32, tcp: Option<u32>| {
            let mut methods = vec![MethodVerdict {
                method: METHOD_QUIC,
                code: FILTER_FOUND,
                hop: Some(quic),
                text: "текст".to_string(),
            }];
            if let Some(value) = tcp {
                methods.push(MethodVerdict {
                    method: METHOD_TCP,
                    code: FILTER_FOUND,
                    hop: Some(value),
                    text: "текст".to_string(),
                });
            }
            SiteVerdict {
                host: host.to_string(),
                ip: "45.1.0.1".to_string(),
                code: FILTER_FOUND,
                hop: Some(quic.min(tcp.unwrap_or(quic))),
                distance: 20,
                text: "текст".to_string(),
                methods,
                agreeing: 0,
                far_hop: 0,
            }
        };
        let listing = vec![
            site("fb", 12, Some(9)),
            site("a", 6, None),
            site("b", 6, None),
            site("c", 6, None),
        ];
        let place = aggregate(&listing, &hops_of_road(), None, &[]);
        assert_eq!(
            (place.state, place.hop, place.confidence.as_str()),
            (STATE_FOUND, Some(6), CONFIDENCE_HIGH)
        );
        assert!(place.sentence.contains("Ближайший фильтр"));
        assert!(place.sentence.contains("ещё один — на узле 9"));
    }

    #[test]
    fn sites_disagreeing_give_no_single_place() {
        let place = aggregate(&verdicts_by_hops(&[3, 5], 7, 1), &hops_of_road(), None, &[]);
        assert_eq!(
            (place.state, place.hop, place.ttl_advice.is_empty()),
            (STATE_DISAGREE, None, true)
        );
        assert!(place.sentence.contains("узел 3, узел 5"));
    }

    #[test]
    fn first_hop_with_a_bypass_tool_running_is_the_tool_not_the_provider() {
        let zap = zap();
        let place = aggregate(
            &verdicts_by_hops(&[1, 1], 7, 1),
            &hops_of_road(),
            Some(true),
            &[],
        );
        assert_eq!((place.state, place.hop), (STATE_DISTURBED, None));
        let tools_place = aggregate(
            &verdicts_by_hops(&[1, 1], 7, 1),
            &hops_of_road(),
            Some(false),
            &["Xray".to_string()],
        );
        assert_eq!(
            (tools_place.state, tools_place.hop),
            (STATE_DISTURBED, None)
        );
        assert_eq!(
            aggregate(
                &verdicts_by_hops(&[1, 1], 7, 1),
                &hops_of_road(),
                Some(false),
                &[]
            )
            .state,
            STATE_FOUND
        );
        let _ = zap;
    }

    fn zap() -> u32 {
        0
    }

    #[test]
    fn running_bypass_tool_lowers_the_confidence_of_a_farther_place() {
        let place = aggregate(
            &verdicts_by_hops(&[4, 4, 4], 7, 1),
            &hops_of_road(),
            Some(true),
            &[],
        );
        // Три сайта сошлись: уверенность была бы высокой, с работающим обходом — на ступень ниже.
        assert_eq!(
            (place.state, place.confidence.as_str()),
            (STATE_FOUND, CONFIDENCE_MEDIUM)
        );
        let lowered = aggregate(
            &verdicts_by_hops(&[4, 4], 7, 1),
            &hops_of_road(),
            Some(true),
            &[],
        );
        assert_eq!(lowered.confidence, CONFIDENCE_LOW);
        assert!(place.reasons.last().unwrap().contains("Zapret"));
    }

    #[test]
    fn nothing_found_and_nothing_to_search_are_different_answers() {
        let nothing = aggregate(&[], &hops_of_road(), Some(true), &[]);
        assert_eq!(nothing.state, STATE_NONE);
        assert!(nothing.sentence.contains("работает Zapret"));
        let at_target = SiteVerdict {
            host: "x.com".to_string(),
            ip: "5.5.5.5".to_string(),
            code: FILTER_AT_TARGET,
            hop: None,
            distance: 7,
            text: "гаснет только у сервера".to_string(),
            methods: Vec::new(),
            agreeing: 0,
            far_hop: 0,
        };
        let missed = aggregate(&[at_target], &hops_of_road(), None, &[]);
        assert_eq!(missed.state, STATE_NOT_FOUND);
        assert!(missed.sentence.contains("гаснет только у сервера"));
    }

    #[test]
    fn nothing_found_while_a_bypass_tool_runs_is_blamed_on_the_tool() {
        let silent = vec![SiteVerdict {
            host: "x.com".to_string(),
            ip: "5.5.5.5".to_string(),
            code: FILTER_NOT_STATEFUL,
            hop: None,
            distance: 7,
            text: "фильтр не запоминает соединение".to_string(),
            methods: Vec::new(),
            agreeing: 0,
            far_hop: 0,
        }];
        let zapret_place = aggregate(&silent, &hops_of_road(), Some(true), &[]);
        assert_eq!(zapret_place.state, STATE_DISTURBED);
        assert!(zapret_place.sentence.contains("Остановите"));
        let tools_place = aggregate(&silent, &hops_of_road(), Some(false), &["Xray".to_string()]);
        assert_eq!(tools_place.state, STATE_DISTURBED);
        assert!(tools_place.sentence.contains("Остановите"));
        assert_eq!(
            aggregate(&silent, &hops_of_road(), Some(false), &[]).state,
            STATE_NOT_FOUND
        );
    }

    fn mechanism_site(
        host: &str,
        quic: Option<u32>,
        tcp: Option<u32>,
        tcp_text: &str,
    ) -> SiteVerdict {
        let mut methods = Vec::new();
        let fallback_hop = quic.or(tcp).unwrap_or(0);
        if quic.is_some() {
            methods.push(MethodVerdict {
                method: METHOD_QUIC,
                code: if quic.unwrap_or(0) != 0 {
                    FILTER_FOUND
                } else {
                    FILTER_NOT_ON_PATH
                },
                hop: quic.filter(|value| *value != 0),
                text: "текст".to_string(),
            });
        }
        if tcp.is_some() {
            methods.push(MethodVerdict {
                method: METHOD_TCP,
                code: if tcp.unwrap_or(0) != 0 {
                    FILTER_FOUND
                } else {
                    FILTER_NOT_STATEFUL
                },
                hop: tcp.filter(|value| *value != 0),
                text: tcp_text.to_string(),
            });
        }
        SiteVerdict {
            host: host.to_string(),
            ip: "45.1.0.1".to_string(),
            code: FILTER_FOUND,
            hop: Some(fallback_hop),
            distance: 9,
            text: "текст".to_string(),
            methods,
            agreeing: 0,
            far_hop: 0,
        }
    }

    #[test]
    fn each_mechanism_gets_its_own_place() {
        let dns = DnsPlaceVerdict {
            code: PLACE_FOUND,
            text: "перехватывают между узлами 3 и 4".to_string(),
            hop: Some(4),
        };
        let listing = vec![
            mechanism_site("a.example", Some(2), Some(2), "сброс не приходит"),
            mechanism_site("b.example", Some(2), Some(0), "сброс не приходит"),
        ];
        let result = mechanisms(&listing, Some(&dns));
        let by_key = |key: &str| {
            result["mechanisms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["key"].as_str() == Some(key))
                .unwrap()
                .clone()
        };
        assert_eq!(
            (
                by_key("quic")["hop"].as_u64(),
                by_key("tcp")["hop"].as_u64(),
                by_key("dns")["hop"].as_u64()
            ),
            (Some(2), Some(2), Some(4))
        );
        assert!(by_key("quic")["text"]
            .as_str()
            .unwrap()
            .contains("совпало по 2 сайтам из 2"));
        assert!(by_key("tcp")["text"]
            .as_str()
            .unwrap()
            .contains("совпало по 1 сайту из 2"));
        assert!(result["same_place"]
            .as_str()
            .unwrap()
            .contains("не меньше двух"));
        let titles: Vec<&str> = result["unmeasured"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, ["Бан по адресу", "Обрыв загрузки на 16–20 КБ"]);
    }

    #[test]
    fn same_place_is_not_called_one_device_and_a_single_mechanism_says_so() {
        let both = mechanisms(
            &[mechanism_site(
                "a.example",
                Some(2),
                Some(2),
                "сброс не приходит",
            )],
            None,
        );
        assert!(both["same_place"]
            .as_str()
            .unwrap()
            .contains("может быть одно устройство"));
        assert!(both["same_place"].as_str().unwrap().contains("не увидеть"));

        let single = mechanisms(
            &[mechanism_site(
                "a.example",
                Some(2),
                Some(0),
                "сброс не приходит",
            )],
            None,
        );
        assert!(single["same_place"]
            .as_str()
            .unwrap()
            .contains("по одному механизму"));
        let tcp = single["mechanisms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"].as_str() == Some("tcp"))
            .unwrap();
        assert_eq!(tcp["hop"].as_u64(), None);
        assert_eq!(
            tcp["text"].as_str(),
            Some("место не найдено: сброс не приходит")
        );

        assert_eq!(
            mechanisms(&[], None)["mechanisms"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(mechanisms(&[], None)["same_place"].as_str(), Some(""));
    }

    #[test]
    fn report_text_shows_the_place_the_road_and_the_ttl() {
        let candidates = [
            Candidate {
                host: "a.example".to_string(),
                ip: "45.1.0.1".to_string(),
                methods: vec![METHOD_QUIC, METHOD_TCP],
            },
            Candidate {
                host: "b.example".to_string(),
                ip: "45.2.0.1".to_string(),
                methods: vec![METHOD_QUIC],
            },
        ];
        let mut locate_calls: Vec<(String, String)> = Vec::new();
        let mut locate =
            |method: &str, host: &str, ip: &str, traced: Option<&RouteTrace>| -> FilterFacts {
                // Дорога к этому времени уже известна: по ней поиск знает расстояние до сервера.
                let item = traced.expect("trace must exist");
                assert!(item.reached);
                locate_calls.push((method.to_string(), format!("{host}:{ip}")));
                found(4, 7)
            };
        let road = |ip: &str| Some(trace(ip, &ROAD));
        let facts = collect(&candidates, &mut locate, &road);
        let asked: Vec<(String, String)> = locate_calls
            .iter()
            .map(|(method, item)| (method.clone(), item.clone()))
            .collect();
        let mut expected: Vec<(String, String)> = vec![
            ("quic".to_string(), "a.example:45.1.0.1".to_string()),
            ("quic".to_string(), "b.example:45.2.0.1".to_string()),
            ("tcp".to_string(), "a.example:45.1.0.1".to_string()),
        ];
        let mut actual = asked.clone();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
        assert_eq!(
            facts
                .iter()
                .map(|item| item.found.len())
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert!(facts
            .iter()
            .all(|item| item.trace.as_ref().is_some_and(|item| item.reached)));

        let verdicts: Vec<SiteVerdict> = facts
            .iter()
            .map(judge_site)
            .map(|value| value.unwrap())
            .collect();
        let listed = hops_of_road();
        let place = report(
            &aggregate(&verdicts, &listed, None, &[]),
            &verdicts,
            &listed,
            Some(&verdicts[0]),
        );
        assert_eq!(place["found"].as_bool(), Some(true));
        assert_eq!(place["hop"].as_u64(), Some(4));
        assert_eq!(place["confidence"].as_str(), Some(CONFIDENCE_HIGH));
        assert_eq!(place["host"].as_str(), Some("a.example"));
        let site_hops: Vec<u64> = place["sites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["hop"].as_u64().unwrap())
            .collect();
        assert_eq!(site_hops, [4, 4]);

        let text = lines(&place);
        let joined = text.join("\n");
        assert!(joined.contains("📍 Фильтр стоит между узлами 3 и 4 от вас"));
        assert!(
            joined.contains("👉 Поддельным пакетам стратегии подходит срок жизни (TTL) от 4 до 6")
        );
        let marker = joined.find("── здесь стоит фильтр ──").unwrap();
        let node = joined.find(" 4. 195.34.50.1").unwrap();
        assert!(marker < node);
        assert!(joined.contains(" 3. 212.188.1.1 · 6 мс · ваш провайдер (MTS)"));
    }

    #[test]
    fn method_verdicts_get_titles_in_report() {
        let verdict = SiteVerdict {
            host: "x.com".to_string(),
            ip: "5.5.5.5".to_string(),
            code: FILTER_FOUND,
            hop: Some(3),
            distance: 7,
            text: "текст".to_string(),
            methods: vec![
                MethodVerdict {
                    method: METHOD_QUIC,
                    code: FILTER_FOUND,
                    hop: Some(3),
                    text: "найдено".to_string(),
                },
                MethodVerdict {
                    method: METHOD_TCP,
                    code: FILTER_FOUND,
                    hop: Some(3),
                    text: "тоже".to_string(),
                },
            ],
            agreeing: 2,
            far_hop: 0,
        };
        let verdicts = vec![verdict];
        let place = report(&aggregate(&verdicts, &[], None, &[]), &verdicts, &[], None);
        let methods = place["sites"].as_array().unwrap()[0]["methods"].clone();
        assert_eq!(methods[0]["title"].as_str(), Some("QUIC (UDP 443)"));
        assert_eq!(methods[1]["title"].as_str(), Some("TCP (сброс соединения)"));
    }
}
