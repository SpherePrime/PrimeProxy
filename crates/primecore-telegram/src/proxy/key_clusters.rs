//! На каком кластере дата-центра живёт ключ медиа-сессии Telegram Desktop.
//!
//! Порт `telegram_proxy/key_clusters.py`. У каждого DC два кластера: обычный и
//! медиа. Временный ключ шифрования, созданный на одном, другой не знает и
//! отвечает транспортной ошибкой -404. Номер ключа (первые 8 байт пакета) идёт
//! открыто, поэтому прокси запоминает, какой кластер принял ключ, и молча
//! переводит соединение, если сервер ответил -404. Только в памяти: ключи
//! Desktop живут сутки, а после перезапуска прокси память наполняется заново.

use std::collections::HashMap;

pub const CLUSTER_REGULAR: &str = "regular";
pub const CLUSTER_MEDIA: &str = "media";

pub const KEY_NOT_FOUND: i32 = -404;

/// Пакет ошибки «ключ не найден»: 4 байта -404 little-endian со знаком.
#[must_use]
pub fn key_not_found_packet() -> Vec<u8> {
    KEY_NOT_FOUND.to_le_bytes().to_vec()
}

/// Ёмкость памяти кластеров по умолчанию.
pub const CAPACITY: usize = 512;
/// Кластер, принявший ключ не дольше этого назад, считается домом ключа, до
/// которого просто не дотянулись: -404 с запасного пути тогда не отдаётся Desktop.
pub const HOME_FRESH_SECONDS: f64 = 120.0;
/// Не чаще одного раза за это время соединение закрывается молча вместо -404.
pub const QUIET_MISS_SECONDS: f64 = 60.0;

/// Номер ключа из пакета клиента; пусто — пакет без ключа (создание ключа).
#[must_use]
pub fn key_id_of(packet: &[u8]) -> Vec<u8> {
    if packet.len() < 8 {
        return Vec::new();
    }
    let key_id = packet[..8].to_vec();
    if key_id == [0; 8] {
        return Vec::new();
    }
    key_id
}

/// Пакет ровно совпадает с ошибкой «ключ не найден».
#[must_use]
pub fn is_key_not_found(packet: &[u8]) -> bool {
    packet == &key_not_found_packet()[..]
}

/// Название кластера для журнала.
#[must_use]
pub fn cluster_title(cluster: &str) -> &'static str {
    if cluster == CLUSTER_MEDIA {
        "медиа-кластер"
    } else {
        "обычный кластер"
    }
}

struct Home {
    cluster: String,
    ok_at: f64,
    quiet_at: f64,
}

/// Память «ключ → кластер» с вытеснением самых старых ключей.
pub struct KeyClusters {
    clock: Box<dyn Fn() -> f64>,
    capacity: usize,
    order: Vec<Vec<u8>>,
    homes: HashMap<Vec<u8>, Home>,
}

impl KeyClusters {
    /// Новая память с собственными часами (в тестах — управляемое время).
    #[must_use]
    pub fn new(clock: Box<dyn Fn() -> f64>, capacity: usize) -> Self {
        Self {
            clock,
            capacity: capacity.max(1),
            order: Vec::new(),
            homes: HashMap::new(),
        }
    }

    /// Память с системным монотонным временем и штатной ёмкостью.
    #[must_use]
    pub fn with_system_clock() -> Self {
        Self::new(
            Box::new(|| {
                std::time::Instant::now().elapsed().as_secs_f64()
                    + start_monotonic().elapsed().as_secs_f64()
            }),
            CAPACITY,
        )
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Кластер, принявший ключ, или пустая строка.
    #[must_use]
    pub fn home(&self, key_id: &[u8]) -> String {
        if key_id.is_empty() {
            return String::new();
        }
        self.homes
            .get(key_id)
            .map(|entry| entry.cluster.clone())
            .unwrap_or_default()
    }

    /// Запомнить кластер, который принял ключ.
    pub fn note_ok(&mut self, key_id: &[u8], cluster: &str) {
        if key_id.is_empty() || cluster.is_empty() {
            return;
        }
        let now = self.now();
        match self.homes.get_mut(key_id) {
            Some(entry) if entry.cluster == cluster => entry.ok_at = now,
            _ => {
                self.homes.insert(
                    key_id.to_vec(),
                    Home {
                        cluster: cluster.to_string(),
                        ok_at: now,
                        quiet_at: -1.0e9,
                    },
                );
            }
        }
        if let Some(position) = self.order.iter().position(|key| key == key_id) {
            let key = self.order.remove(position);
            self.order.push(key);
        } else {
            self.order.push(key_id.to_vec());
        }
        while self.order.len() > self.capacity {
            let oldest = self.order.remove(0);
            self.homes.remove(&oldest);
        }
    }

    /// Забыть ключ: он создан заново.
    pub fn forget(&mut self, key_id: &[u8]) {
        self.homes.remove(key_id);
        if let Some(position) = self.order.iter().position(|key| key == key_id) {
            self.order.remove(position);
        }
    }

    /// Ключ недавно работал на другом кластере, а сейчас тот недоступен.
    ///
    /// Тогда соединение лучше закрыть без -404: Desktop переподключится со
    /// своим ключом, и путь его кластера, скорее всего, уже ответит. Не чаще
    /// раза в [`QUIET_MISS_SECONDS`]: если дом ключа не возвращается, ключу
    /// пора переехать, и -404 уходит в Desktop.
    #[must_use]
    pub fn may_close_quietly(&mut self, key_id: &[u8], rejected_cluster: &str) -> bool {
        let (matches_rejected, ok_at, quiet_at) = match self.homes.get(key_id) {
            Some(entry) => (
                entry.cluster == rejected_cluster,
                entry.ok_at,
                entry.quiet_at,
            ),
            None => return false,
        };
        if matches_rejected {
            return false;
        }
        let now = self.now();
        if now - ok_at > HOME_FRESH_SECONDS || now - quiet_at < QUIET_MISS_SECONDS {
            return false;
        }
        if let Some(entry) = self.homes.get_mut(key_id) {
            entry.quiet_at = now;
        }
        true
    }
}

fn start_monotonic() -> std::time::Instant {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    *START.get_or_init(std::time::Instant::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClock(f64);

    impl FakeClock {
        fn clock(&self) -> Box<dyn Fn() -> f64> {
            let value = std::sync::Arc::new(std::sync::Mutex::new(self.0));
            Box::new(move || *value.lock().unwrap())
        }
    }

    fn make_keys(
        now: f64,
        capacity: usize,
    ) -> (KeyClusters, std::sync::Arc<std::sync::Mutex<f64>>) {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(now));
        let clock_value = shared.clone();
        (
            KeyClusters::new(Box::new(move || *clock_value.lock().unwrap()), capacity),
            shared,
        )
    }

    #[test]
    fn home_is_remembered_and_oldest_key_is_dropped() {
        let (mut keys, _clock) = make_keys(1000.0, 2);
        keys.note_ok(b"k1k1k1k1", CLUSTER_MEDIA);
        keys.note_ok(b"k2k2k2k2", CLUSTER_REGULAR);
        keys.note_ok(b"k1k1k1k1", CLUSTER_MEDIA);
        keys.note_ok(b"k3k3k3k3", CLUSTER_REGULAR);
        assert_eq!(keys.home(b"k1k1k1k1"), CLUSTER_MEDIA);
        assert_eq!(keys.home(b"k2k2k2k2"), "");
        assert_eq!(keys.home(b""), "");
    }

    #[test]
    fn quiet_close_only_for_a_fresh_home_and_once_a_minute() {
        let (mut keys, clock) = make_keys(1000.0, CAPACITY);
        let key = b"k1k1k1k1".as_slice();
        assert!(!keys.may_close_quietly(key, CLUSTER_MEDIA));
        keys.note_ok(key, CLUSTER_REGULAR);
        assert!(!keys.may_close_quietly(key, CLUSTER_REGULAR));
        assert!(keys.may_close_quietly(key, CLUSTER_MEDIA));
        *clock.lock().unwrap() += 30.0;
        assert!(!keys.may_close_quietly(key, CLUSTER_MEDIA));
        *clock.lock().unwrap() += 100.0;
        // Дом ключа не отвечал больше двух минут: ключу пора переехать.
        assert!(!keys.may_close_quietly(key, CLUSTER_MEDIA));
    }

    #[test]
    fn forget_removes_home() {
        let (mut keys, _clock) = make_keys(1000.0, CAPACITY);
        keys.note_ok(b"k1k1k1k1", CLUSTER_MEDIA);
        keys.forget(b"k1k1k1k1");
        assert_eq!(keys.home(b"k1k1k1k1"), "");
    }

    #[test]
    fn key_id_helpers_follow_packet_layout() {
        assert!(key_id_of(&[0; 8]).is_empty());
        assert!(key_id_of(&[1, 2, 3]).is_empty());
        assert_eq!(
            key_id_of(&[1, 2, 3, 4, 5, 6, 7, 8, 9]),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
        // python3 -c "print((-404).to_bytes(4, 'little', signed=True).hex())"
        assert_eq!(key_not_found_packet(), vec![0x6C, 0xFE, 0xFF, 0xFF]);
        assert!(is_key_not_found(&key_not_found_packet()));
        assert!(!is_key_not_found(&[1, 2, 3, 4]));
        assert_eq!(cluster_title(CLUSTER_MEDIA), "медиа-кластер");
        assert_eq!(cluster_title(CLUSTER_REGULAR), "обычный кластер");
    }

    #[test]
    fn empty_cluster_notes_are_ignored() {
        let (mut keys, _clock) = make_keys(1000.0, CAPACITY);
        keys.note_ok(b"k1k1k1k1", "");
        keys.note_ok(&[], CLUSTER_MEDIA);
        assert_eq!(keys.home(b"k1k1k1k1"), "");
    }

    #[test]
    fn fake_clock_helper_is_used() {
        let clock = FakeClock(1.0);
        let _ = clock.clock();
    }
}
