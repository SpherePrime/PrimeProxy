//! Порт `src/diagnostics/quic_probe.py` — проверка QUIC: сбор (`quic_hello`)
//! и вывод (`judge`).
//!
//! QUIC — протокол поверх UDP (порт 443), которым браузеры открывают YouTube
//! и многие сайты. Блокируют его так же, как обычное шифрованное соединение —
//! по имени сайта в первом пакете, только пакет при этом молча пропадает.
//! Первый пакет собирается в [`crate::quic_initial`] — тот же настоящий пакет,
//! с правильным шифрованием и приветствием TLS 1.3 внутри.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;

use crate::quic_initial::{build_initial, is_reply_to};

/// Как часто при чтении между отрезками проверяется «Стоп».
const POLL_SLICE_S: f64 = 0.2;

pub const NEUTRAL_NAME: &str = "example.com";
pub const QUIC_PORT: u16 = 443;
/// UDP теряется и сам по себе: одного молчания мало, чтобы назвать пакет заблокированным.
pub const ATTEMPTS: u32 = 2;
pub const ATTEMPT_TIMEOUT_S: f64 = 1.5;

/// python `quic_hello` — отправляет первый пакет QUIC с именем `name` и ждёт
/// любой ответ сервера. Возвращает время до ответа в мс или None, если сервер
/// молчит.
pub fn quic_hello(
    ip: &str,
    name: Option<&str>,
    port: u16,
    attempts: u32,
    timeout: f64,
    cancel: &SocketCancel,
) -> Option<f64> {
    for _attempt in 0..attempts.max(1) {
        // Каждая попытка — новое соединение со своим номером: повтор старого
        // пакета сервер мог бы принять за дубль.
        let packet = build_initial(name);
        let socket = if ip.contains(':') {
            UdpSocket::bind("[::]:0")
        } else {
            UdpSocket::bind("0.0.0.0:0")
        };
        let Ok(socket) = socket else {
            // python: OSError — ответа нет.
            return None;
        };
        let started = Instant::now();
        let deadline = started + Duration::from_secs_f64(timeout);
        if socket.send_to(&packet.datagram, (ip, port)).is_err() {
            if cancel.cancelled() {
                return None;
            }
            continue;
        }
        let mut buffer = [0u8; 4096];
        loop {
            if cancel.cancelled() {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ =
                socket.set_read_timeout(Some(remaining.min(Duration::from_secs_f64(POLL_SLICE_S))));
            match socket.recv_from(&mut buffer) {
                Ok((size, _)) if is_reply_to(&buffer[..size], &packet) => {
                    return Some(started.elapsed().as_secs_f64() * 1000.0);
                }
                // Чужой пакет — не наш ответ, ждём дальше.
                Ok(_) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                // Тайм-аут, «порт недоступен», закрытый по отмене сокет:
                // ответа нет — следующая попытка.
                Err(_) => break,
            }
        }
        if cancel.cancelled() {
            return None;
        }
    }
    None
}

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
        let other = if facts.neutral_ms.is_some() {
            "с посторонним именем"
        } else {
            "без имени"
        };
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
        let mut value = QuicFacts {
            host: "site.example".to_string(),
            ..Default::default()
        };
        setup(&mut value);
        value
    }

    #[test]
    fn verdicts() {
        assert_eq!(
            judge(&facts(|f| f.real_ms = Some(250.9))).unwrap().text,
            "отвечает за 251 мс"
        );
        assert_eq!(
            judge(&facts(|f| f.real_ms = Some(0.2))).unwrap().text,
            "отвечает за 1 мс"
        );
        assert_eq!(judge(&facts(|f| f.cancelled = true)), None);
        assert_eq!(
            judge(&facts(|f| f.nameless_ms = Some(12.0))).unwrap().code,
            QUIC_BLOCKED_BY_NAME
        );
        assert!(judge(&facts(|_f| {})).unwrap().code == QUIC_SILENT);
    }
}
