//! Порт `src/diagnostics/telegram_check.py` — принимают ли соединения
//! дата-центры Telegram.
//!
//! Сайт ``telegram.org`` и само приложение — разные вещи. Приложение ходит не
//! на сайт, а прямо по адресам пяти дата-центров Telegram, и блокируют их
//! отдельно от сайта: сайт может открываться, а приложение — висеть на
//! «Соединение…».
//!
//! Проверка устанавливает обычное TCP-соединение с портом 443 каждого
//! дата-центра. Этого достаточно, чтобы увидеть, доходит ли дорога: дальше у
//! Telegram свой шифрованный протокол, и без учётной записи его не проверить.
//! Поэтому «принимают соединения» не значит «Telegram работает»: само
//! приложение могут резать уже после соединения — по его «почерку» (так
//! сообщали с 2026 года).
//!
//! Неудавшееся соединение повторяется после паузы. Один молчащий дата-центр —
//! не вывод: у Telegram они живут в разных сетях, и приложение переключается
//! между ними. Вывод «не принимают соединения» делается, только когда молчат
//! все, — и то с оговоркой, что это показывает дорогу без обхода и прокси.
//!
//! Сбор (`check_telegram`, `connect_once`) — сетевая часть (TCP), портится со
//! `probe_result`; здесь — константы, типы и чистый свод.

use crate::verdict::Level;

pub const CONNECT_TIMEOUT_S: f64 = 4.0;
pub const RETRY_PAUSE_S: f64 = 1.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCenter {
    pub name: &'static str,
    pub address: &'static str,
    pub port: u16,
}

impl DataCenter {
    const fn new(name: &'static str, address: &'static str) -> Self {
        Self { name, address, port: 443 }
    }
}

/// Адреса дата-центров Telegram (те же, что зашиты в его приложения).
pub static DATA_CENTERS: [DataCenter; 5] = [
    DataCenter::new("DC1 (Майами)", "149.154.175.53"),
    DataCenter::new("DC2 (Амстердам)", "149.154.167.51"),
    DataCenter::new("DC3 (Майами)", "149.154.175.100"),
    DataCenter::new("DC4 (Амстердам)", "149.154.167.91"),
    DataCenter::new("DC5 (Сингапур)", "91.108.56.130"),
];

/// python `DcResult`. `None` — проверку сняли.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DcResult {
    pub name: String,
    pub address: String,
    pub connected: Option<bool>,
    pub ms: Option<f64>,
    pub attempts: u32,
}

/// python `TelegramReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct TelegramReport {
    pub level: Level,
    pub headline: String,
    pub servers: Vec<DcResult>,
    pub advice: Vec<String>,
}

/// python `summarize_telegram(servers)`.
pub fn summarize_telegram(servers: &[DcResult]) -> TelegramReport {
    let with_servers = |level: Level, headline: String, advice: Vec<String>| TelegramReport {
        level,
        headline,
        servers: servers.to_vec(),
        advice,
    };
    let checked: Vec<&DcResult> = servers.iter().filter(|item| item.connected.is_some()).collect();
    let answered: Vec<&&DcResult> = checked.iter().filter(|item| item.connected == Some(true)).collect();
    if checked.is_empty() {
        return with_servers(
            Level::Unknown,
            "Дата-центры Telegram проверить не удалось".to_string(),
            Vec::new(),
        );
    }
    if answered.len() == checked.len() {
        return TelegramReport {
            level: Level::Ok,
            headline: format!(
                "Дорога до дата-центров Telegram открыта: соединение принимают {answered} из {total}. \
                 Режут ли само приложение после соединения, эта проверка не видит",
                answered = answered.len(),
                total = checked.len()
            ),
            servers: servers.to_vec(),
            advice: Vec::new(),
        };
    }
    if !answered.is_empty() {
        return TelegramReport {
            level: Level::Warn,
            headline: format!(
                "Часть дата-центров Telegram не принимает соединения: отвечают {answered} из {total}",
                answered = answered.len(),
                total = checked.len()
            ),
            servers: servers.to_vec(),
            advice: vec![
                "Приложение Telegram само переключается на доступный дата-центр; если оно не соединяется — включите встроенный Telegram Proxy.".to_string(),
            ],
        };
    }
    TelegramReport {
        level: Level::Fail,
        headline: format!(
            "Дата-центры Telegram не принимают соединения: ни один из {total}, каждый проверен дважды",
            total = checked.len()
        ),
        servers: servers.to_vec(),
        advice: vec![
            "Приложение Telegram напрямую не соединится. Включите встроенный Telegram Proxy: он ведёт приложение другой дорогой.".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(name: &str, connected: Option<bool>) -> DcResult {
        DcResult { name: name.to_string(), address: "1.2.3.4".to_string(), connected, ..Default::default() }
    }

    #[test]
    fn summarize() {
        assert_eq!(summarize_telegram(&[]).level, Level::Unknown);
        let report = summarize_telegram(&[result("DC1", Some(true)), result("DC2", Some(true))]);
        assert_eq!(report.level, Level::Ok);
        assert!(report.advice.is_empty());
        let report = summarize_telegram(&[result("DC1", Some(true)), result("DC2", Some(false))]);
        assert_eq!(report.level, Level::Warn);
        assert_eq!(report.advice.len(), 1);
        let report = summarize_telegram(&[result("DC1", Some(false)), result("DC2", Some(false))]);
        assert_eq!(report.level, Level::Fail);
        assert!(report.headline.contains("каждый проверен дважды"));
    }

    #[test]
    fn data_centers() {
        assert_eq!(DATA_CENTERS.len(), 5);
        assert!(DATA_CENTERS.iter().all(|center| center.port == 443));
    }
}
