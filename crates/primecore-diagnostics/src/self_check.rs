//! Порт `src/diagnostics/self_check.py` — самопроверка компьютера: не принимает
//! ли что-то на нём все соединения подряд.
//!
//! Адрес 192.0.2.1 зарезервирован для документации (RFC 5737): в интернете его
//! нет, и соединение с ним честно не устанавливается — пакеты пропадают или
//! приходит «сети нет». Если же соединение «установилось», ответил не интернет,
//! а программа на этом компьютере: антивирус с проверкой HTTPS, прозрачный
//! прокси, VPN в режиме fake-ip. Тогда и остальные пробы видят её, а не сеть,
//! и выводы о блокировках ненадёжны. Так же перед проверкой делает ByeByeVPN
//! (preflight).
//!
//! Тревога — только при установившемся соединении. Молчание и отказ — норма:
//! по ним ничего не утверждается.
//!
//! Сетевое подключение здесь не реализовано (как в остальных пробах):
//! `collect` принимает результат попытки соединения, движок подаёт факт.

use std::net::{IpAddr, SocketAddr};

use crate::system_state::{SystemItem, LEVEL_WARN};

pub const DOCUMENTATION_ADDRESS: &str = "192.0.2.1";
pub const PORT: u16 = 443;
pub const TIMEOUT_S: f64 = 1.5;

/// python `SelfFacts`: соединение с несуществующим адресом установилось.
/// `None` — проверку сняли.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelfFacts {
    pub accepted: Option<bool>,
}

/// Первый взгляд на адрес: куда стучимся (python делает это перед сокетом).
#[must_use]
pub fn try_target() -> Option<SocketAddr> {
    // python: socket.connect((DOCUMENTATION_ADDRESS, PORT)); адрес не DNS-имя.
    match DOCUMENTATION_ADDRESS.parse::<IpAddr>() {
        Ok(ip) => Some(SocketAddr::new(ip, PORT)),
        Err(_) => None,
    }
}

/// Судьба попытки соединения: потянулся ли сокет и снята ли проверка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Соединение установилось.
    Accepted,
    /// OSError — обычные «пропали»/«отказано»; сравниваем с отменой.
    Refused { cancelled: bool },
}

/// python `collect`: итог один — установилось ли соединение (или сняли проверку).
#[must_use]
pub fn collect(outcome: ConnectOutcome) -> SelfFacts {
    match outcome {
        ConnectOutcome::Accepted => SelfFacts {
            accepted: Some(true),
        },
        ConnectOutcome::Refused { cancelled } => SelfFacts {
            accepted: if cancelled { None } else { Some(false) },
        },
    }
}

/// Строка раздела «Компьютер». `None` — всё честно или проверку сняли.
#[must_use]
pub fn judge(facts: &SelfFacts) -> Option<SystemItem> {
    if facts.accepted != Some(true) {
        return None;
    }
    Some(SystemItem {
        key: "self_check".to_string(),
        title: "Перехват соединений".to_string(),
        level: LEVEL_WARN.to_string(),
        text: format!(
            "соединение с адресом, которого нет в интернете ({DOCUMENTATION_ADDRESS}), «установилось» — его \
             перехватывает программа на этом компьютере: антивирус с проверкой HTTPS, прокси или VPN. \
             Выводы о блокировках могут быть неверны"
        ),
        advice: "Отключите такую программу на время проверки и повторите её.".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_is_documentation_address() {
        let target = try_target().unwrap();
        assert_eq!(target.ip().to_string(), DOCUMENTATION_ADDRESS);
        assert_eq!(target.port(), PORT);
    }

    #[test]
    fn collect_python_branches() {
        assert_eq!(collect(ConnectOutcome::Accepted).accepted, Some(true));
        assert_eq!(
            collect(ConnectOutcome::Refused { cancelled: false }).accepted,
            Some(false)
        );
        assert_eq!(
            collect(ConnectOutcome::Refused { cancelled: true }).accepted,
            None
        );
    }

    #[test]
    fn judge_only_on_accepted() {
        assert!(judge(&SelfFacts {
            accepted: Some(false)
        })
        .is_none());
        assert!(judge(&SelfFacts { accepted: None }).is_none());
        let item = judge(&SelfFacts {
            accepted: Some(true),
        })
        .unwrap();
        assert_eq!(item.key, "self_check");
        assert_eq!(item.title, "Перехват соединений");
        assert_eq!(item.level, LEVEL_WARN);
        assert_eq!(
            item.text,
            "соединение с адресом, которого нет в интернете (192.0.2.1), «установилось» — его перехватывает \
             программа на этом компьютере: антивирус с проверкой HTTPS, прокси или VPN. Выводы о блокировках \
             могут быть неверны"
        );
        assert_eq!(
            item.advice,
            "Отключите такую программу на время проверки и повторите её."
        );
    }
}
