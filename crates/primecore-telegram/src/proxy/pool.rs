//! Пул запасных WebSocket: решения о прогреве и взятии сокетов.
//!
//! Порт чистой части `telegram_proxy/proxy/pool.py` (правила из ZaStoGram,
//! jni/tgnet/wss/WssPool.cpp). Сам asyncio-цикл пополнения — сетевой слой
//! python-версии; здесь — правила: когда запасной сокет ещё пригоден, сколько
//! их держать во всплеске загрузки и какой выдержкой пополнять.

/// Маршруты прогреваются только 2 минуты после последнего запроса.
pub const DEMAND_TTL: f64 = 120.0;
/// Первый запасной открывается через 3 с после первого запроса.
pub const FIRST_OPEN_DELAY: f64 = 3.0;
/// Запасной живёт не дольше 70 с: релеи kws закрывают молчащий сокет через ~100 с.
pub const MAX_IDLE: f64 = 70.0;
/// Окно всплеска: если за 3 с после взятия пришёл ещё запрос, держатся два.
pub const BURST_WINDOW: f64 = 3.0;
/// Сколько держатся два запасных после всплеска.
pub const BURST_HOLD: f64 = 30.0;
/// Пауза после неудачи растёт от 2 до 60 с.
pub const RETRY_MIN: f64 = 2.0;
pub const RETRY_MAX: f64 = 60.0;

/// Пригоден ли запасной сокет: не закрывается, ничего не прислал без запроса
/// и открыт не дольше [`MAX_IDLE`] назад.
#[must_use]
pub fn spare_usable(is_closing: bool, has_unread_data: bool, opened_at: f64, now: f64) -> bool {
    !is_closing && !has_unread_data && now - opened_at < MAX_IDLE
}

/// Сколько запасных соединений держать: 2 во время всплеска (`now < burst_until`), иначе 1.
#[must_use]
pub fn wanted_spares(burst_until: f64, now: f64) -> usize {
    // python: want = 2 if now < self._burst_until.get(key, 0.0) else 1
    1 + usize::from(now < burst_until)
}

/// Выдержка перед следующим запасным после неудачи: удвоение от 2 до 60 с.
#[must_use]
pub fn retry_delay(previous_backoff: f64) -> f64 {
    RETRY_MAX.min(RETRY_MIN.max(previous_backoff * 2.0))
}

/// Задержка пополнения, когда запасной уже есть: до конца его срока жизни.
#[must_use]
pub fn idle_hold_delay(oldest_opened_at: f64, now: f64) -> f64 {
    (MAX_IDLE - (now - oldest_opened_at) + 0.1).max(0.05)
}

/// Маршрут ещё прогревается: с последнего запроса прошло меньше [`DEMAND_TTL`].
#[must_use]
pub fn demand_alive(last_demand_at: f64, now: f64) -> bool {
    now - last_demand_at <= DEMAND_TTL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spare_rules_match_python_constants() {
        assert!(spare_usable(false, false, 1000.0, 1069.9));
        assert!(!spare_usable(false, false, 1000.0, 1070.1));
        assert!(!spare_usable(true, false, 1000.0, 1001.0));
        assert!(!spare_usable(false, true, 1000.0, 1001.0));
        assert_eq!(wanted_spares(1000.0 + BURST_HOLD, 1030.0), 1);
        // 1030 < 1031 — всплеск ещё активен, python даёт 2.
        assert_eq!(wanted_spares(1031.0, 1030.0), 2);
        // python: want = 2 if now < burst_until else 1 — активный всплеск даёт 2.
        assert_eq!(wanted_spares(1060.0, 1030.0), 2);
    }

    #[test]
    fn backoff_doubles_from_two_to_sixty() {
        assert!((retry_delay(0.0) - RETRY_MIN).abs() < f64::EPSILON);
        assert!((retry_delay(2.0) - 4.0).abs() < f64::EPSILON);
        assert!((retry_delay(100.0) - RETRY_MAX).abs() < f64::EPSILON);
    }

    #[test]
    fn idle_hold_and_demand_windows() {
        assert!((idle_hold_delay(1000.0, 1030.0) - 40.1).abs() < f64::EPSILON);
        assert!((idle_hold_delay(1000.0, 1100.0) - 0.05).abs() < f64::EPSILON);
        assert!(demand_alive(1000.0, 1119.9));
        assert!(!demand_alive(1000.0, 1120.1));
    }
}
