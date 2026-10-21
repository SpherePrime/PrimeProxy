//! Здоровье маршрутов WSS: какие отказывают, на сколько их отключить, какой
//! фронт рабочий.
//!
//! Порт `telegram_proxy/proxy/health.py`; правила перенесены из ZaStoGram
//! (jni/tgnet/wss/WssSocket.cpp): подавление после серии отказов с удвоением
//! срока, слив отказов в одну пачку, пометка «потерянный SYN», воркеры с
//! исчерпанным лимитом подавляются с первого отказа, подавления переживают
//! перезапуск с потолком 10 минут.

use std::collections::HashMap;

pub const FAILURES_BEFORE_SUPPRESS: usize = 3;
pub const CDN_FAILURES_BEFORE_SUPPRESS: usize = 6;
/// Отказы в пределах 2 с — одна пачка стартовых соединений, это один отказ.
pub const FAILURE_COALESCE_SECONDS: f64 = 2.0;
pub const RECENT_TCP_SECONDS: f64 = 30.0;
pub const SUPPRESS_BASE_SECONDS: f64 = 120.0;
pub const SUPPRESS_MAX_SECONDS: f64 = 30.0 * 60.0;
pub const RESTORED_SUPPRESS_MAX_SECONDS: f64 = 10.0 * 60.0;
/// Рабочий адрес фронтов забывается после стольких отказов TCP подряд на нём.
pub const FRONT_FAMILY_FORGET_FAILURES: u32 = 2;
/// Отказавший адрес входа релея уступает очередь другому адресу DC на это время.
pub const RELAY_ADDRESS_RETRY_SECONDS: f64 = SUPPRESS_BASE_SECONDS;

/// Ключ здоровья адреса входа релея.
#[must_use]
pub fn address_key(ip: &str) -> String {
    format!("addr-{ip}")
}

/// Ключ здоровья фронтов одного DC.
#[must_use]
pub fn cdn_key(dc: i32) -> String {
    format!("cdn-kws{dc}")
}

/// Ключ здоровья прямого TCP DC (для медиа ключ тот же: делят историю пауз).
#[must_use]
pub fn direct_key(dc: i32) -> String {
    format!("direct-dc{}", dc.abs())
}

struct Entry {
    failures: u32,
    suppressions: u32,
    suppressed_until: f64,
    last_failure_at: f64,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            failures: 0,
            suppressions: 0,
            suppressed_until: 0.0,
            last_failure_at: -1.0e9,
        }
    }
}

/// Состояние здоровья маршрутов с сохранением подавлений в json-файл.
pub struct RouteHealth {
    path: Option<std::path::PathBuf>,
    clock: Box<dyn Fn() -> f64>,
    wall: Box<dyn Fn() -> f64>,
    entries: HashMap<String, Entry>,
    tcp_ok_at: HashMap<String, f64>,
    /// Маршруты, ответившие с запуска прокси. Только в памяти: новая сеть
    /// после перезапуска доказывает релей заново.
    answered: std::collections::HashSet<String>,
    front_slots: usize,
    front_cursor: usize,
    front_family: Option<u32>,
    front_family_failures: u32,
    /// Адрес входа релея, ответивший последним (ключ — первый адрес списка DC),
    /// и когда какой адрес отказал. Только в памяти, как и `answered`.
    relay_preferred: HashMap<String, String>,
    relay_failed_at: HashMap<String, f64>,
    /// С какого воркера-туннеля эта установка начинает перебор.
    pub tunnel_start: u32,
}

impl RouteHealth {
    /// Новое состояние. `path` — файл подавлений, `front_count` — число
    /// фронтов (слоты = фронты × 2 адреса), `tunnel_start` — стартовый воркер.
    #[must_use]
    pub fn new(
        path: Option<std::path::PathBuf>,
        clock: Box<dyn Fn() -> f64>,
        wall: Box<dyn Fn() -> f64>,
        front_count: usize,
        tunnel_start: Option<u32>,
    ) -> Self {
        let front_slots = front_count * 2;
        let mut cursor = 0;
        if front_slots > 0 {
            let mut random = [0_u8; 2];
            fastrand::fill(&mut random);
            cursor = u16::from_le_bytes(random) as usize % front_slots;
        }
        let tunnel = match tunnel_start {
            Some(value) => value,
            None => {
                let mut random = [0_u8; 2];
                fastrand::fill(&mut random);
                u16::from_le_bytes(random) as u32
            }
        };
        let mut health = Self {
            path,
            clock,
            wall,
            entries: HashMap::new(),
            tcp_ok_at: HashMap::new(),
            answered: std::collections::HashSet::new(),
            front_slots,
            front_cursor: cursor,
            front_family: None,
            front_family_failures: 0,
            relay_preferred: HashMap::new(),
            relay_failed_at: HashMap::new(),
            tunnel_start: tunnel,
        };
        health.load();
        health
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Маршрут сейчас подавлен.
    #[must_use]
    pub fn is_suppressed(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.suppressed_until > self.now())
    }

    /// Сколько секунд ещё подавлен (0 — не подавлен).
    #[must_use]
    pub fn suppressed_for(&self, key: &str) -> f64 {
        match self.entries.get(key) {
            Some(entry) => (entry.suppressed_until - self.now()).max(0.0),
            None => 0.0,
        }
    }

    /// Учесть отказ. Возвращает `true`, если маршрут только что подавлен.
    pub fn note_failure(
        &mut self,
        key: &str,
        threshold: usize,
        tcp_reached: bool,
        address: &str,
    ) -> bool {
        let now = self.now();
        if !tcp_reached && !address.is_empty() && self.tcp_recently_connected(address) {
            return false;
        }
        let entry = self.entries.entry(key.to_string()).or_default();
        if now - entry.last_failure_at < FAILURE_COALESCE_SECONDS {
            return false;
        }
        entry.last_failure_at = now;
        entry.failures += 1;
        if entry.failures < threshold.max(1) as u32 {
            return false;
        }
        let duration = SUPPRESS_BASE_SECONDS * (1_u64 << entry.suppressions.min(4)) as f64;
        entry.suppressed_until = now + duration.min(SUPPRESS_MAX_SECONDS);
        entry.suppressions += 1;
        entry.failures = 0;
        self.save();
        true
    }

    /// Сервер ответил: серия отказов прервана, но подавления ещё помнятся.
    pub fn note_answer(&mut self, key: &str) {
        self.answered.insert(key.to_string());
        if let Some(entry) = self.entries.get_mut(key) {
            entry.failures = 0;
        }
    }

    /// Маршрут передал настоящий объём данных: забыть все подавления.
    pub fn note_proven(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            if entry.suppressions > 0 {
                self.save();
            }
        }
    }

    /// Маршрут ещё не отвечал с запуска или в его серии (или у адреса) есть отказ.
    #[must_use]
    pub fn is_unproven(&self, key: &str, address: &str) -> bool {
        let failing = |name: &str| {
            self.entries
                .get(name)
                .is_some_and(|entry| entry.failures > 0)
        };
        !self.answered.contains(key) || failing(key) || (!address.is_empty() && failing(address))
    }

    /// Запомнить, что до адреса дошёл TCP.
    pub fn note_tcp_connected(&mut self, address: &str) {
        if !address.is_empty() {
            self.tcp_ok_at.insert(address.to_string(), self.now());
        }
    }

    /// К этому адресу кто-то подключился за последние [`RECENT_TCP_SECONDS`].
    #[must_use]
    pub fn tcp_recently_connected(&self, address: &str) -> bool {
        self.tcp_ok_at
            .get(address)
            .is_some_and(|at| self.now() - at < RECENT_TCP_SECONDS)
    }

    /// Адреса входа DC в порядке попыток: ответивший последним — первым,
    /// отказавшие за последние [`RELAY_ADDRESS_RETRY_SECONDS`] — в конце.
    #[must_use]
    pub fn relay_address_order(&self, addresses: &[&str]) -> Vec<String> {
        if addresses.is_empty() {
            return Vec::new();
        }
        let preferred = self.relay_preferred.get(addresses[0]).cloned();
        let mut order: Vec<String> = Vec::new();
        if let Some(preferred) = &preferred {
            if addresses.contains(&preferred.as_str()) {
                order.push(preferred.clone());
            }
        }
        for address in addresses {
            if Some(*address) != preferred.as_deref() {
                order.push((*address).to_string());
            }
        }
        let now = self.now();
        order.sort_by_key(|address| {
            now - self.relay_failed_at.get(address).copied().unwrap_or(-1.0e9)
                < RELAY_ADDRESS_RETRY_SECONDS
        });
        order
    }

    /// Адрес входа отказал: следующие соединения DC берут другой его адрес.
    pub fn note_relay_address_failed(&mut self, addresses: &[&str], address: &str) {
        if address.is_empty() || !addresses.contains(&address) {
            return;
        }
        self.relay_failed_at.insert(address.to_string(), self.now());
        if addresses.len() > 1
            && self.relay_preferred.get(addresses[0]).map(String::as_str) == Some(address)
        {
            self.relay_preferred.remove(addresses[0]);
        }
    }

    /// Адрес входа ответил: он становится первым для своего DC.
    pub fn note_relay_address_answered(&mut self, addresses: &[&str], address: &str) {
        if address.is_empty() || !addresses.contains(&address) {
            return;
        }
        if addresses.len() > 1
            && self.relay_preferred.get(addresses[0]).map(String::as_str) != Some(address)
        {
            // (журнал в python-версии: relay address %s answered)
        }
        self.relay_preferred
            .insert(addresses[0].to_string(), address.to_string());
        self.relay_failed_at.remove(address);
    }

    /// Следующие (номер фронта, адрес 0/1) начиная с курсора.
    ///
    /// Если известен рабочий адрес, каждый следующий слот — следующий фронт на
    /// том же адресе; иначе соседние слоты чередуют адреса одного фронта.
    #[must_use]
    pub fn next_front_slots(&self, count: usize) -> Vec<(usize, u32)> {
        if self.front_slots == 0 {
            return Vec::new();
        }
        let fronts = self.front_slots / 2;
        let mut result = Vec::new();
        for step in 0..count {
            let slot = (self.front_cursor + step) % self.front_slots;
            if let Some(family) = self.front_family {
                result.push(((self.front_cursor / 2 + step) % fronts, family));
            } else {
                result.push((slot / 2, (slot % 2) as u32));
            }
        }
        result
    }

    /// Результат попытки фронта: рабочий адрес запоминается, отказавший
    /// адрес забывается после [`FRONT_FAMILY_FORGET_FAILURES`] отказов подряд.
    pub fn note_front_result(
        &mut self,
        front_index: usize,
        family: u32,
        tcp_ok: bool,
        answered: bool,
    ) {
        if tcp_ok {
            self.front_family = Some(family);
            self.front_family_failures = 0;
        } else if self.front_family == Some(family) {
            self.front_family_failures += 1;
            if self.front_family_failures >= FRONT_FAMILY_FORGET_FAILURES {
                self.front_family = None;
                self.front_family_failures = 0;
            }
        }
        if self.front_slots == 0 {
            return;
        }
        let slot = front_index * 2 + family as usize;
        if answered {
            self.front_cursor = slot % self.front_slots;
        } else if let Some(current) = self.front_family {
            let fronts = self.front_slots / 2;
            self.front_cursor = ((front_index + 1) % fronts) * 2 + current as usize;
        } else {
            self.front_cursor = (slot + 1) % self.front_slots;
        }
        self.save();
    }

    fn load(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) else {
            return;
        };
        let now = self.now();
        let wall = (self.wall)();
        if let Some(routes) = data.get("routes").and_then(|value| value.as_object()) {
            for (key, item) in routes {
                let suppressions = item
                    .get("suppressions")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                let until = item
                    .get("until")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                if suppressions <= 0 {
                    continue;
                }
                let remaining = until - wall;
                let entry = Entry {
                    suppressions: suppressions as u32,
                    suppressed_until: if remaining > 0.0 {
                        now + remaining.min(RESTORED_SUPPRESS_MAX_SECONDS)
                    } else {
                        0.0
                    },
                    ..Entry::default()
                };
                self.entries.insert(key.clone(), entry);
            }
        }
        if let Some(front) = data.get("front") {
            let family = front.get("family").and_then(serde_json::Value::as_i64);
            self.front_family = match family {
                Some(0) => Some(0),
                Some(1) => Some(1),
                _ => None,
            };
            if let Some(cursor) = front.get("cursor").and_then(serde_json::Value::as_i64) {
                if self.front_slots > 0 {
                    self.front_cursor = (cursor as usize) % self.front_slots;
                }
            }
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let now = self.now();
        let wall = (self.wall)();
        let mut routes = serde_json::Map::new();
        for (key, entry) in &self.entries {
            if entry.suppressions == 0 {
                continue;
            }
            // python: round(wall + max(0, until - now), 1) — округляется только
            // остаток, а не всё значение целиком.
            let remaining = ((entry.suppressed_until - now).max(0.0) * 10.0).round() / 10.0;
            routes.insert(
                key.clone(),
                serde_json::json!({
                    "suppressions": entry.suppressions,
                    "until": wall + remaining,
                }),
            );
        }
        let payload = serde_json::json!({
            "routes": routes,
            "front": {
                "family": self.front_family.map(i64::from).unwrap_or(-1),
                "cursor": self.front_cursor,
            },
        });
        // Курсор сохраняется как в python (family None → null), поэтому при
        // чтении family -1 превращается в None.
        let payload = if self.front_family.is_none() {
            let mut object = payload;
            object["front"]["family"] = serde_json::Value::Null;
            object
        } else {
            payload
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let temporary = path.with_extension(format!(
            "{}tmp",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("")
        ));
        if std::fs::write(
            &temporary,
            serde_json::to_string(&payload).unwrap_or_default(),
        )
        .is_ok()
        {
            let _ = std::fs::rename(&temporary, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type SharedClock = std::sync::Arc<std::sync::Mutex<f64>>;

    fn clock_pair(start: f64) -> (SharedClock, Box<dyn Fn() -> f64>) {
        let shared: SharedClock = std::sync::Arc::new(std::sync::Mutex::new(start));
        let clone = shared.clone();
        (shared, Box::new(move || *clone.lock().unwrap()))
    }

    struct Health {
        health: RouteHealth,
        clock: SharedClock,
    }

    impl Health {
        fn new(front_count: usize) -> Self {
            let (clock, boxed) = clock_pair(1000.0);
            Self {
                health: RouteHealth::new(None, boxed, Box::new(|| 5000.0), front_count, None),
                clock,
            }
        }

        fn advance(&self, seconds: f64) {
            *self.clock.lock().unwrap() += seconds;
        }

        fn suppress(&mut self, key: &str) {
            for _ in 0..6 {
                self.health.note_failure(key, 6, true, "");
                self.advance(3.0);
            }
            assert!(self.health.is_suppressed(key));
        }
    }

    #[test]
    fn three_failures_suppress_and_duration_doubles() {
        let mut state = Health::new(0);
        for _ in 0..2 {
            state
                .health
                .note_failure("kws2.web.telegram.org", 3, true, "");
            state.advance(3.0);
        }
        assert!(!state.health.is_suppressed("kws2.web.telegram.org"));
        state
            .health
            .note_failure("kws2.web.telegram.org", 3, true, "");
        // python-цикл двигает часы после каждого вызова, включая последний.
        state.advance(3.0);
        assert!((state.health.suppressed_for("kws2.web.telegram.org") - 117.0).abs() <= 1.0);
        state.advance(200.0);
        for _ in 0..3 {
            state
                .health
                .note_failure("kws2.web.telegram.org", 3, true, "");
            state.advance(3.0);
        }
        assert!((state.health.suppressed_for("kws2.web.telegram.org") - 237.0).abs() <= 1.0);
    }

    #[test]
    fn failures_in_one_burst_count_once() {
        let mut state = Health::new(0);
        for _ in 0..5 {
            state.health.note_failure("k", 3, true, "");
            state.advance(0.5);
        }
        assert!(!state.health.is_suppressed("k"));
    }

    #[test]
    fn lost_syn_ignored_when_address_recently_connected() {
        let mut state = Health::new(0);
        state.health.note_tcp_connected("149.154.167.220");
        for _ in 0..5 {
            state.health.note_failure("k", 3, false, "149.154.167.220");
            state.advance(3.0);
        }
        assert!(!state.health.is_suppressed("k"));
    }

    #[test]
    fn answer_breaks_series_but_only_proof_clears_suppressions() {
        let mut state = Health::new(0);
        for _ in 0..2 {
            state.health.note_failure("k", 3, true, "");
            state.advance(3.0);
        }
        state.health.note_answer("k");
        for _ in 0..2 {
            state.health.note_failure("k", 3, true, "");
            state.advance(3.0);
        }
        assert!(!state.health.is_suppressed("k"));
        state.health.note_failure("k", 3, true, "");
        assert!(state.health.is_suppressed("k"));
        state.health.note_proven("k");
        assert!(!state.health.is_suppressed("k"));
    }

    #[test]
    fn suppression_survives_restart_but_capped_to_ten_minutes() {
        let directory = std::env::temp_dir().join("primecore-telegram-health-test");
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("health.json");
        let _ = std::fs::remove_file(&path);
        let (clock, boxed) = clock_pair(1000.0);
        {
            let mut health =
                RouteHealth::new(Some(path.clone()), boxed, Box::new(|| 5000.0), 20, None);
            // 2 + 4 + 8 + 16 минут подавлений.
            for _ in 0..4 {
                for _ in 0..3 {
                    health.note_failure("k", 3, true, "");
                    *clock.lock().unwrap() += 3.0;
                }
            }
        }
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("\"k\""));
        let restored = RouteHealth::new(
            Some(path),
            Box::new(|| {
                *std::sync::Arc::new(std::sync::Mutex::new(1000.0))
                    .lock()
                    .unwrap()
            }),
            Box::new(|| 5000.0),
            20,
            None,
        );
        assert!(restored.is_suppressed("k"));
        assert!(restored.suppressed_for("k") <= 600.0);
    }

    #[test]
    fn working_front_address_family_is_kept() {
        let mut state = Health::new(20);
        let (index, family) = state.health.next_front_slots(1)[0];
        state.health.note_front_result(index, family, true, false);
        let slots = state.health.next_front_slots(3);
        let families: std::collections::HashSet<u32> =
            slots.iter().map(|(_, family)| *family).collect();
        assert_eq!(families, std::iter::once(family).collect());
        assert_eq!(
            slots
                .iter()
                .map(|(index, _)| *index)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        assert_ne!(slots[0].0, index);
    }

    #[test]
    fn keys_follow_python_format() {
        assert_eq!(address_key("149.154.167.220"), "addr-149.154.167.220");
        assert_eq!(cdn_key(203), "cdn-kws203");
        assert_eq!(direct_key(2), "direct-dc2");
        assert_eq!(direct_key(-2), "direct-dc2");
    }

    #[test]
    fn failed_ingress_yields_to_the_other_and_answer_keeps_it_first() {
        let mut state = Health::new(20);
        let addresses = ["149.154.167.220", "149.154.167.99"];
        state
            .health
            .note_relay_address_failed(&addresses, "149.154.167.220");
        assert_eq!(
            state.health.relay_address_order(&addresses),
            vec!["149.154.167.99", "149.154.167.220"]
        );
        state
            .health
            .note_relay_address_answered(&addresses, "149.154.167.99");
        state.advance(600.0);
        assert_eq!(
            state.health.relay_address_order(&addresses)[0],
            "149.154.167.99"
        );
        state
            .health
            .note_relay_address_failed(&addresses, "149.154.167.99");
        assert_eq!(
            state.health.relay_address_order(&addresses)[0],
            "149.154.167.220"
        );
    }

    #[test]
    fn tunnel_start_is_taken_from_explicit_value() {
        let (_, boxed) = clock_pair(0.0);
        let health = RouteHealth::new(None, boxed, Box::new(|| 0.0), 0, Some(2 + 4 * 10));
        assert_eq!(health.tunnel_start, 42);
    }

    #[test]
    fn suppress_helper_is_used_by_plan_tests() {
        let mut state = Health::new(20);
        state.suppress(&cdn_key(1));
        assert!(state.health.is_suppressed(&cdn_key(1)));
    }
}
