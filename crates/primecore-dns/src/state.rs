//! Порт `src/dns/state.py` — снимок DNS-слоя для страницы и итоги команд.

use crate::adapters::DnsAdapter;

/// python `LineCheck` — прошлая проверка «DNS-серверов» на линии
/// пользователя (dns.line_check).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineCheck {
    /// Когда проверяли, ISO-время записи истории.
    pub time: String,
    /// (сервер, вывод CARD_*, коротко что не так) — по одному на сервер.
    pub cards: Vec<(String, String, String)>,
}

impl LineCheck {
    /// python `card(server)` — отметка одного сервера: (статус, пояснение).
    #[must_use]
    pub fn card(&self, server: &str) -> Option<(String, String)> {
        self.cards
            .iter()
            .find(|(name, _, _)| name == server)
            .map(|(_, status, note)| (status.clone(), note.clone()))
    }
}

/// python `DnsState` — снимок DNS-слоя для страницы: адаптеры с их DNS, есть
/// ли IPv6 и DoH, свои серверы.
#[derive(Debug, Clone, Default)]
pub struct DnsState {
    pub adapters: Vec<DnsAdapter>,
    pub ipv6_available: bool,
    pub doh_supported: bool,
    /// Режим работающего шифрованного DNS (dns.local_proxy) или пустая строка.
    pub local_proxy_mode: String,
    /// Название плитки, чей сервер работает через шифрованный DNS в режиме
    /// DoH; иначе пусто.
    pub local_proxy_server: String,
    /// Свои DNS-серверы пользователя из настроек (записи dns.custom_servers).
    pub custom_servers: Vec<serde_json::Value>,
    /// Прошлая проверка серверов на этой линии; None — её нет или она устарела.
    pub line_check: Option<LineCheck>,
}

/// python `DnsCommandResult` — итог команды DNS-слоя.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsCommandResult {
    pub success: bool,
    pub message: String,
    pub affected_count: u32,
    pub total_count: u32,
    /// Движок шифрованного DNS слушает ещё и ::1 (ответ start_local_proxy).
    pub listen_ipv6: bool,
    /// DNS поставлен, но DoH до сервера не доходит: Windows спрашивает без
    /// шифрования.
    pub doh_closed: bool,
}

/// python `CustomServerResult` — итог действия со своими DNS: новый список
/// или ошибка.
///
/// `field` — поле страницы «Свой DNS», к которому относится ошибка (имена из
/// dns.custom_servers). `notice` — оговорка к удачному сохранению.
#[derive(Debug, Clone, Default)]
pub struct CustomServerResult {
    pub success: bool,
    pub message: String,
    pub servers: Vec<serde_json::Value>,
    pub field: String,
    pub notice: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_check_card_lookup() {
        let check = LineCheck {
            time: "2026-10-18T12:00:00".to_string(),
            cards: vec![(
                "9.9.9.9".to_string(),
                "blocked".to_string(),
                "порт закрыт".to_string(),
            )],
        };
        assert_eq!(
            check.card("9.9.9.9"),
            Some(("blocked".to_string(), "порт закрыт".to_string()))
        );
        assert_eq!(check.card("8.8.8.8"), None);
    }
}
