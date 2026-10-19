//! Порт `src/diagnostics/quic_probe.py` — чистая часть: вывод по пакетам QUIC.
//!
//! QUIC — протокол поверх UDP (порт 443), которым браузеры открывают YouTube
//! и многие сайты. Блокируют его так же, как обычное шифрованное соединение —
//! по имени сайта в первом пакете, только пакет при этом молча пропадает.
//! Сбор (`quic_hello`, `collect`) — сетевая часть (сборка QUIC Initial из
//! `utils.quic_initial`), портируется со STUN/TLS-пробами. Здесь — данные и
//! вывод (`judge`).

pub const NEUTRAL_NAME: &str = "example.com";
pub const QUIC_PORT: u16 = 443;
/// UDP теряется и сам по себе: одного молчания мало, чтобы назвать пакет заблокированным.
pub const ATTEMPTS: u32 = 2;
pub const ATTEMPT_TIMEOUT_S: f64 = 1.5;

pub const QUIC_OK: &str = "ok";
pub const QUIC_BLOCKED_BY_NAME: &str = "blocked_by_name";
pub const QUIC_SILENT: &str = "silent";

/// python `QuicFacts` — время ответа в мс на каждый из пакетов; None — ответа не было.
#[derive(Debug, Clone, Default)]
pub struct QuicFacts {
    pub host: String,
    pub real_ms: Option<f64>,
    pub neutral_ms: Option<f64>,
    pub nameless_ms: Option<f64>,
    /// Настоящее имя ещё раз — только когда оно промолчало, а постороннее прошло.
    pub real_again_ms: Option<f64>,
    /// Проверку сняли раньше, чем она закончилась.
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicVerdict {
    pub code: String,
    pub text: String,
}

/// python `judge(facts)` — вывод по пакетам или None, если проверку сняли.
///
/// «По имени» говорится, только когда настоящее имя промолчало дважды
/// (`collect` повторяет его), а постороннее или пустое прошло.
pub fn judge(facts: &QuicFacts) -> Option<QuicVerdict> {
    if let Some(real_ms) = facts.real_ms {
        return Some(QuicVerdict {
            code: QUIC_OK.to_string(),
            text: format!("отвечает за {} мс", (real_ms.round() as i64).max(1)),
        });
    }
    if facts.cancelled {
        return None;
    }
    if facts.neutral_ms.is_some() || facts.nameless_ms.is_some() {
        let other = if facts.neutral_ms.is_some() { "с посторонним именем" } else { "без имени" };
        return Some(QuicVerdict {
            code: QUIC_BLOCKED_BY_NAME.to_string(),
            text: format!(
                "блокируется по имени сайта: пакет с именем {host} пропадает и на повторе, а {other} тот же сервер отвечает",
                host = facts.host
            ),
        });
    }
    Some(QuicVerdict {
        code: QUIC_SILENT.to_string(),
        text: "сервер не отвечает ни с каким именем — он не поддерживает QUIC или UDP 443 закрыт целиком".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(setup: impl FnOnce(&mut QuicFacts)) -> QuicFacts {
        let mut value = QuicFacts { host: "site.example".to_string(), ..Default::default() };
        setup(&mut value);
        value
    }

    #[test]
    fn verdicts() {
        assert_eq!(judge(&facts(|f| f.real_ms = Some(250.9))).unwrap().text, "отвечает за 251 мс");
        assert_eq!(judge(&facts(|f| f.real_ms = Some(0.2))).unwrap().text, "отвечает за 1 мс");
        assert_eq!(judge(&facts(|f| f.cancelled = true)), None);
        assert_eq!(
            judge(&facts(|f| f.nameless_ms = Some(12.0))).unwrap().code,
            QUIC_BLOCKED_BY_NAME
        );
        assert!(judge(&facts(|_f| {})).unwrap().code == QUIC_SILENT);
    }
}
