//! Чистые решения сессии Telegram: сторож, гонка релея с фронтом, ключ
//! медиа-сессии.
//!
//! Порт `telegram_proxy/proxy/session.py` без asyncio. Сама пересылка
//! (`run`, насос клиента, `_relay`) — сетевой слой python-версии; здесь —
//! константы сроков, решения по маршруту и по кластеру ключа, тексты журнала.
//! Решения вызываются сетевым слоем вызывающего кода.

use std::collections::HashSet;

use crate::proxy::key_clusters::{cluster_title, is_key_not_found, key_id_of, KeyClusters};
use crate::proxy::routes::Route;

/// Сторож первого ответа: после последнего отправленного пакета сервер должен
/// ответить за это время. Медиа-соединения отвечают медленнее (ZaStoGram).
pub const WATCHDOG_SECONDS: f64 = 5.5;
pub const MEDIA_WATCHDOG_SECONDS: f64 = 20.0;
/// Сколько ждать первый MTProto-пакет от Desktop.
pub const FIRST_PACKET_TIMEOUT: f64 = 15.0;
/// Таймаут прямого TCP-подключения.
pub const DIRECT_CONNECT_TIMEOUT: f64 = 3.0;
/// Через сколько после релея, ещё не доказавшего себя, к нему в гонку
/// добавляется фронт (Happy Eyeballs, RFC 8305 — 250 мс; ZaStoGram — 500 мс).
pub const FRONT_RACE_DELAY: f64 = 0.5;
/// Релей без TCP винится за проигрыш, только если ждал хотя бы столько.
pub const RACE_LOSS_MIN_WAIT: f64 = 1.0;
/// Пока маршрут не выбран, пакеты клиента копятся для повтора. Больше этого
/// чтение клиента приостанавливается.
pub const MAX_REPLAY_BYTES: usize = 4 * 1024 * 1024;

/// Что делать после -404 на медиа-соединении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMissAction {
    /// Перейти на путь другого кластера, Desktop ничего не видит.
    Switch,
    /// Отдать -404: Desktop создаст ключ заново.
    Deliver,
    /// Закрыть без байта: Desktop переподключится со своим ключом.
    Quiet,
    /// Путей другого кластера не осталось — решить в конце плана.
    End,
}

/// Состояние ключа медиа-сессии внутри сессии.
#[derive(Debug, Default)]
pub struct MediaKeyState {
    pub key_id: Vec<u8>,
    pub key_home: String,
    pub rejected_clusters: HashSet<String>,
}

impl MediaKeyState {
    /// Запомнить ключ первого пакета и его дом (если он известен).
    pub fn observe_first_packet(&mut self, packets: &[Vec<u8>], clusters: &KeyClusters) {
        if self.key_id.is_empty() {
            if let Some(first) = packets.first() {
                self.key_id = key_id_of(first);
            }
        }
        if self.key_home.is_empty() && !self.key_id.is_empty() {
            self.key_home = clusters.home(&self.key_id);
        }
    }
}

/// Следующий индекс плана (`None` — план кончился).
#[must_use]
pub fn next_index(plan_len: usize, index: Option<usize>) -> Option<usize> {
    let index = index?;
    if index + 1 >= plan_len {
        None
    } else {
        Some(index + 1)
    }
}

/// Гонять ли релею наперегонки с фронтом.
///
/// Релей должен быть ещё не доказан, а фронт — следующим в плане; ключ сессии
/// должен жить на кластере релея (или быть неизвестным), иначе фронт другого
/// кластера ответил бы -404.
#[must_use]
pub fn should_race(
    route: &Route,
    next_route: Option<&Route>,
    key_home: &str,
    relay_unproven: bool,
) -> bool {
    route.kind == crate::proxy::routes::KIND_RELAY
        && next_route.is_some_and(|next| next.kind == crate::proxy::routes::KIND_FRONT)
        && (key_home.is_empty() || next_route.is_some_and(|next| next.cluster == key_home))
        && relay_unproven
}

/// Путь ответил -404: перейти на другой кластер или отдать -404?
///
/// `log` получает текст смены кластера (как `_log_key_switch` в python).
/// Кластер промаха запоминается в `rejected`.
pub fn key_miss_action(
    route: &Route,
    remaining: &[Route],
    rejected: &mut HashSet<String>,
    log: &mut dyn FnMut(&str),
) -> KeyMissAction {
    rejected.insert(route.cluster.clone());
    let others: Vec<&Route> = remaining
        .iter()
        .filter(|item| !rejected.contains(&item.cluster))
        .collect();
    if others.is_empty() {
        return KeyMissAction::End;
    }
    if route.is_primary() && !others[0].is_primary() {
        // Основной путь жив, а к дому ключа ведут только воркеры и SOCKS:
        // ключу лучше переехать, чем гонять медиа через запасные пути.
        return KeyMissAction::Deliver;
    }
    log(&format!(
        "not found on {} via {} ({}); -404 hidden, trying {}",
        cluster_title(&route.cluster),
        route.label(),
        route.describe(),
        cluster_title(&others[0].cluster)
    ));
    KeyMissAction::Switch
}

/// План кончился после промахов ключа: отдать -404 или закрыть молча?
///
/// Молча — только если ключ знает один кластер и он недавно работал, но сейчас
/// недоступен ([`KeyClusters::may_close_quietly`]).
#[must_use]
pub fn end_after_misses(
    key_clusters: &mut KeyClusters,
    key_id: &[u8],
    route_cluster: &str,
    rejected_count: usize,
) -> KeyMissAction {
    if rejected_count < 2 && key_clusters.may_close_quietly(key_id, route_cluster) {
        return KeyMissAction::Quiet;
    }
    KeyMissAction::Deliver
}

/// Текст завершения промаха ключа (python: `_finish_key_miss`).
#[must_use]
pub fn key_miss_log_text(
    action: KeyMissAction,
    key_id_hex: &str,
    route: &Route,
    why: &str,
) -> String {
    let tag = format!("DC media key={key_id_hex}");
    match action {
        KeyMissAction::Quiet => format!(
            "{tag}: not found on {} via {}, its own cluster is unreachable right now; \
             closed without -404 so Telegram retries with its key",
            cluster_title(&route.cluster),
            route.label()
        ),
        _ => format!("{tag}: -404 passed to Telegram ({why}); it will create a new key"),
    }
}

/// Отметка «ключ принят новым кластером»: только для настоящего ответа.
///
/// Короткий пакет — ошибка транспорта (-429 и др.), а не ответ на ключ.
#[must_use]
pub fn should_remember_key_home(is_media: bool, key_id: &[u8], first_packet: &[u8]) -> bool {
    is_media && !key_id.is_empty() && first_packet.len() > 4 && !is_key_not_found(first_packet)
}

/// Текст ошибки для журнала (python: `_error_text`).
#[must_use]
pub fn error_text(kind: &str, message: &str) -> String {
    if message.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}: {message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::key_clusters::key_not_found_packet;
    use crate::proxy::routes::{KIND_FRONT, KIND_RELAY, KIND_TUNNEL};

    fn clock_keys(now: f64) -> KeyClusters {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(now));
        let clone = shared.clone();
        KeyClusters::new(Box::new(move || *clone.lock().unwrap()), 16)
    }

    fn route(kind: &str, cluster: &str) -> Route {
        let mut route = Route::new(kind);
        route.cluster = cluster.to_string();
        route.sni = "target".into();
        route.path = "/apiws".into();
        route
    }

    #[test]
    fn watchdog_follows_media_flag() {
        assert!((WATCHDOG_SECONDS - 5.5).abs() < f64::EPSILON);
        assert!((MEDIA_WATCHDOG_SECONDS - 20.0).abs() < f64::EPSILON);
        assert!((FRONT_RACE_DELAY - 0.5).abs() < f64::EPSILON);
        assert_eq!(MAX_REPLAY_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn race_starts_only_for_unproven_relay_before_front() {
        let relay = route(KIND_RELAY, crate::proxy::key_clusters::CLUSTER_MEDIA);
        let front = route(KIND_FRONT, crate::proxy::key_clusters::CLUSTER_REGULAR);
        let tunnel = route(KIND_TUNNEL, crate::proxy::key_clusters::CLUSTER_MEDIA);
        assert!(should_race(&relay, Some(&front), "", true));
        // Ключ живёт на медиа-кластере: фронт другого кластера ответил бы -404.
        assert!(!should_race(
            &relay,
            Some(&front),
            crate::proxy::key_clusters::CLUSTER_MEDIA,
            true
        ));
        assert!(should_race(
            &relay,
            Some(&front),
            crate::proxy::key_clusters::CLUSTER_REGULAR,
            true
        ));
        // Доказанный релей гонки не требует.
        assert!(!should_race(&relay, Some(&front), "", false));
        // Не релей — гонки нет.
        assert!(!should_race(&tunnel, Some(&front), "", true));
        // Фронта после релея нет — гонки нет.
        assert!(!should_race(&relay, Some(&tunnel), "", true));
    }

    #[test]
    fn next_index_walks_the_plan() {
        assert_eq!(next_index(3, Some(0)), Some(1));
        assert_eq!(next_index(3, Some(2)), None);
        assert_eq!(next_index(3, None), None);
        assert_eq!(next_index(0, Some(0)), None);
    }

    #[test]
    fn key_miss_switches_to_other_cluster_and_remembers_rejection() {
        let mut rejected = HashSet::new();
        let relay = route(KIND_RELAY, crate::proxy::key_clusters::CLUSTER_MEDIA);
        let front = route(KIND_FRONT, crate::proxy::key_clusters::CLUSTER_REGULAR);
        let remaining = vec![
            front.clone(),
            route(KIND_TUNNEL, crate::proxy::key_clusters::CLUSTER_MEDIA),
        ];
        let mut log_lines = Vec::new();
        let action = key_miss_action(&relay, &remaining, &mut rejected, &mut |line| {
            log_lines.push(line.to_string());
        });
        assert_eq!(action, KeyMissAction::Switch);
        assert!(rejected.contains(crate::proxy::key_clusters::CLUSTER_MEDIA));
        assert!(log_lines[0].contains("trying обычный кластер"));
    }

    #[test]
    fn key_miss_delivers_when_only_fallbacks_reach_the_other_cluster() {
        let mut rejected = HashSet::new();
        let front = route(KIND_FRONT, crate::proxy::key_clusters::CLUSTER_REGULAR);
        let tunnel = route(KIND_TUNNEL, crate::proxy::key_clusters::CLUSTER_MEDIA);
        let action = key_miss_action(&front, &[tunnel], &mut rejected, &mut |_| {});
        assert_eq!(action, KeyMissAction::Deliver);
    }

    #[test]
    fn key_miss_ends_when_no_other_cluster_remains() {
        let mut rejected = HashSet::new();
        // Единственный оставшийся путь того же кластера, что уже промахнулся
        // (python: others = [r for r in remaining if r.cluster not in rejected]).
        let tunnel = route(KIND_TUNNEL, crate::proxy::key_clusters::CLUSTER_REGULAR);
        let front = route(KIND_FRONT, crate::proxy::key_clusters::CLUSTER_REGULAR);
        let action = key_miss_action(
            &front,
            std::slice::from_ref(&tunnel),
            &mut rejected,
            &mut |_| {},
        );
        assert_eq!(action, KeyMissAction::End);
        // Второй промах (другой кластер) тоже заканчивает план: оба кластера в наборе.
        let action = key_miss_action(&tunnel, &[], &mut rejected, &mut |_| {});
        assert_eq!(action, KeyMissAction::End);
    }

    #[test]
    fn end_after_misses_quiets_once_then_delivers() {
        let mut keys = clock_keys(1000.0);
        let key = b"kkkkkkkk".as_slice();
        keys.note_ok(key, crate::proxy::key_clusters::CLUSTER_REGULAR);
        assert_eq!(
            end_after_misses(
                &mut keys,
                key,
                crate::proxy::key_clusters::CLUSTER_REGULAR,
                1
            ),
            KeyMissAction::Deliver,
            "дом — тот же кластер, промахнувшийся маршрут"
        );
        assert_eq!(
            end_after_misses(&mut keys, key, crate::proxy::key_clusters::CLUSTER_MEDIA, 1),
            KeyMissAction::Quiet
        );
        assert_eq!(
            end_after_misses(&mut keys, key, crate::proxy::key_clusters::CLUSTER_MEDIA, 1),
            KeyMissAction::Deliver,
            "второй раз подряд — ключу пора переехать"
        );
        // Оба кластера промахнулись: -404 отдаётся.
        let mut keys = clock_keys(1000.0);
        keys.note_ok(key, crate::proxy::key_clusters::CLUSTER_REGULAR);
        assert_eq!(
            end_after_misses(&mut keys, key, crate::proxy::key_clusters::CLUSTER_MEDIA, 2),
            KeyMissAction::Deliver
        );
    }

    #[test]
    fn key_home_is_remembered_only_for_real_answers() {
        assert!(should_remember_key_home(
            true,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[0_u8; 8]
        ));
        assert!(!should_remember_key_home(
            true,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &key_not_found_packet()
        ));
        assert!(!should_remember_key_home(
            false,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[0_u8; 8]
        ));
        assert!(!should_remember_key_home(true, &[], &[0_u8; 8]));
    }

    #[test]
    fn media_key_state_learns_home_from_first_packet() {
        let mut keys = clock_keys(1000.0);
        let key_id = b"abcdabcd".to_vec();
        keys.note_ok(&key_id, crate::proxy::key_clusters::CLUSTER_MEDIA);
        let mut state = MediaKeyState::default();
        let packets = vec![{
            let mut packet = key_id.clone();
            packet.extend_from_slice(&[0_u8; 40]);
            packet
        }];
        state.observe_first_packet(&packets, &keys);
        assert_eq!(state.key_home, crate::proxy::key_clusters::CLUSTER_MEDIA);
        // Пакет без ключа не меняет ничего.
        let mut empty = MediaKeyState::default();
        empty.observe_first_packet(&[key_not_found_packet()], &keys);
        assert_eq!(empty.key_home, "");
    }

    #[test]
    fn error_text_matches_python() {
        assert_eq!(error_text("TimeoutError", ""), "TimeoutError");
        assert_eq!(error_text("TimeoutError", "dead"), "TimeoutError: dead");
        assert_eq!(
            key_miss_log_text(
                KeyMissAction::Quiet,
                "aabb",
                &route(KIND_FRONT, "regular"),
                ""
            ),
            "DC media key=aabb: not found on обычный кластер via Cloudflare, its own cluster is unreachable right now; closed without -404 so Telegram retries with its key"
        );
        assert!(key_miss_log_text(
            KeyMissAction::Deliver,
            "aabb",
            &route(KIND_FRONT, "regular"),
            "unknown on both clusters"
        )
        .contains("-404 passed to Telegram (unknown on both clusters)"));
    }
}
