//! Исполнитель подключений к внешнему SOCKS: очередь рукопожатий.
//!
//! Порт чистой части `telegram_proxy/proxy/upstream_runtime.py`. Сам исполняющий
//! цикл живёт в asyncio python-версии; здесь — константы контракта, виды
//! ошибок и чистые решения очереди (когда соединение ждёт, а когда
//! отклоняется). Сетевые действия — замыкания вызывающего кода.

use crate::proxy::upstream_controller::{endpoint_display_name, UpstreamTransition};

/// Сколько соединений может одновременно согласовывать рукопожатие.
pub const MAX_QUEUED_CONNECTIONS: i64 = 64;
/// Сколько секунд соединение ждёт слота в очереди рукопожатий.
pub const QUEUE_TIMEOUT: f64 = 2.0;
/// Общий срок на ожидание слота и полное подключение.
pub const FULL_CONNECT_TIMEOUT: f64 = 5.0;

/// Ошибки открытия соединения через внешний SOCKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamOpenError {
    /// Внешний SOCKS временно недоступен.
    Unavailable,
    /// Очередь рукопожатий переполнена или ожидание вышло.
    Busy(String),
    /// Сервер отклонил цель по правилам доступа.
    TargetRejected(String),
    /// Соединение не удалось.
    Connect(String),
    /// Сервер сменился, пока подключались.
    Stale,
}

impl UpstreamOpenError {
    /// Текст для журнала (совпадает с `str(exception)` в python).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unavailable => "внешний SOCKS временно недоступен".to_string(),
            Self::Busy(text) => text.clone(),
            Self::TargetRejected(text) | Self::Connect(text) => text.clone(),
            Self::Stale => "сервер сменился во время подключения".to_string(),
        }
    }
}

/// Решение очереди рукопожатий для одного соединения.
#[derive(Debug, Clone, PartialEq)]
pub enum QueueDecision {
    /// Слот получен сразу: рукопожатие начинается.
    Proceed,
    /// Встать в очередь на `wait_seconds` секунд.
    Wait(f64),
    /// Очередь переполнена — соединение отклонено.
    Reject { reason: &'static str },
}

/// Решение очереди: свободен ли слот, ждать или отклонить.
///
/// `slot_free` — есть ли свободный слот рукопожатий; `queued` — сколько
/// соединений уже ждут; `remaining` — сколько осталось от общего срока.
#[must_use]
pub fn queue_decision(slot_free: bool, queued: i64, remaining: f64) -> QueueDecision {
    if slot_free {
        return QueueDecision::Proceed;
    }
    if queued >= MAX_QUEUED_CONNECTIONS {
        return QueueDecision::Reject {
            reason: "очередь подключения переполнена",
        };
    }
    let wait = QUEUE_TIMEOUT.min(FULL_CONNECT_TIMEOUT - remaining);
    if wait <= 0.0 {
        QueueDecision::Reject {
            reason: "истекло общее время ожидания подключения",
        }
    } else {
        QueueDecision::Wait(wait)
    }
}

/// Текст перехода очереди: сколько ждёт и сколько отклонено.
#[must_use]
pub fn queue_state_text(queued: i64, rejected: i64) -> String {
    format!("очередь: {queued}, отклонено: {rejected}")
}

/// Лог-строка смены сервера (python: `_handle_transition`).
#[must_use]
pub fn transition_log_text(transition: &UpstreamTransition) -> String {
    let old_name = {
        let name = endpoint_display_name(transition.old_endpoint.as_ref());
        if name.is_empty() {
            "нет".to_string()
        } else {
            name
        }
    };
    let new_name = {
        let name = endpoint_display_name(transition.new_endpoint.as_ref());
        if name.is_empty() {
            "временно недоступно".to_string()
        } else {
            name
        }
    };
    let wait_text = if transition.retry_after > 0.0 {
        format!(", повтор через {} с", transition.retry_after as i64)
    } else {
        String::new()
    };
    format!(
        "SOCKS переключён: {old_name} -> {new_name}; причина: {}{wait_text}",
        transition.reason
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_match_the_public_contract() {
        // python: test_limits_match_the_public_contract
        assert_eq!(MAX_QUEUED_CONNECTIONS, 64);
        const { assert!(QUEUE_TIMEOUT <= 2.0) };
        const { assert!(FULL_CONNECT_TIMEOUT <= 5.0) };
    }

    #[test]
    fn queue_decisions_follow_python_semantics() {
        assert_eq!(queue_decision(true, 0, 0.0), QueueDecision::Proceed);
        assert_eq!(
            queue_decision(false, MAX_QUEUED_CONNECTIONS, 1.0),
            QueueDecision::Reject {
                reason: "очередь подключения переполнена"
            }
        );
        let wait = queue_decision(false, 0, 0.0);
        assert_eq!(wait, QueueDecision::Wait(QUEUE_TIMEOUT));
        let truncated = queue_decision(false, 0, FULL_CONNECT_TIMEOUT);
        assert_eq!(
            truncated,
            QueueDecision::Reject {
                reason: "истекло общее время ожидания подключения"
            }
        );
    }

    #[test]
    fn error_messages_match_python_texts() {
        assert_eq!(
            UpstreamOpenError::Unavailable.message(),
            "внешний SOCKS временно недоступен"
        );
        assert_eq!(
            UpstreamOpenError::Stale.message(),
            "сервер сменился во время подключения"
        );
        assert_eq!(
            UpstreamOpenError::Busy("ожидание в очереди превысило 2 секунды".into()).message(),
            "ожидание в очереди превысило 2 секунды"
        );
    }

    #[test]
    fn queue_state_and_transition_text() {
        assert_eq!(queue_state_text(3, 7), "очередь: 3, отклонено: 7");
    }
}
