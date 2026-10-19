//! Порт `src/utils/socket_cancel.py` — общая кнопка «Стоп» для сетевых
//! запросов из разных потоков.
//!
//! Отличие от python: блокирующий сокет у std нельзя прервать закрытием из
//! другого потока без unsafe. Поэтому сетевой слой (primecore-dnswire) ждёт
//! данные короткими отрезками (read timeout) и между ними читает
//! [`SocketCancel::cancelled`]; «Стоп» срабатывает в пределах одного отрезка,
//! а не сразу, как у python (там сокет закрывается и read падает моментально).
//! Вид сбоя при отмене тот же — `FAILURE_CANCELLED`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Признак отмены одной пачки запросов и пауза, которую «Стоп» обрывает сразу.
#[derive(Debug, Default)]
pub struct SocketCancel {
    cancelled: AtomicBool,
    active: AtomicUsize,
    event: Mutex<bool>,
    signal: Condvar,
}

impl SocketCancel {
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            event: Mutex::new(false),
            signal: Condvar::new(),
        }
    }

    /// «Стоп» уже нажат?
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Нажать «Стоп»: текущие операции заметят это между отрезками ожидания,
    /// а паузы (`sleep`) обрываются сразу.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let mut fired = self.event.lock().expect("замок события");
        *fired = true;
        self.signal.notify_all();
    }

    /// Пауза, которую «Стоп» обрывает сразу. `false` — проверку сняли.
    pub fn sleep(&self, seconds: f64) -> bool {
        if self.cancelled() {
            return false;
        }
        let mut fired: MutexGuard<bool> = self.event.lock().expect("замок события");
        let deadline = std::time::Instant::now() + Duration::from_secs_f64(seconds.max(0.0));
        while !*fired {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            let (guard, waited) = self
                .signal
                .wait_timeout(fired, deadline - now)
                .expect("замок события");
            fired = guard;
            if waited.timed_out() {
                break;
            }
        }
        !self.cancelled()
    }

    /// Взять операцию под отмену. `None` — отмена уже была, запрос начинать
    /// нельзя (адрес линейки `_Cancelled` у python).
    ///
    /// У python тут же регистрируется сам сокет, чтобы «Стоп» закрыл его и
    /// прервал блокирующий вызов; здесь достаточно признака — сетевой слой
    /// сам проверяет его между отрезками ожидания.
    pub fn track(&self) -> Option<Activity<'_>> {
        if self.cancelled() {
            return None;
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(Activity { cancel: self })
    }

    /// Сколько операций сейчас идёт. Для отладки пачек.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// Одна операция под отменой. Уходит со счёта и отдельным `release()`,
/// и через `Drop`, если запрос упал и счёт снять банально забыли.
pub struct Activity<'a> {
    cancel: &'a SocketCancel,
}

impl Activity<'_> {
    /// Завершить операцию штатно (аналог release у python).
    pub fn release(self) {}

    /// «Стоп» отменил саму операцию: как `cancel()`, но для одной ветки.
    pub fn mark_cancelled(&self) -> bool {
        self.cancel.cancelled()
    }
}

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        let _ = self.cancel.active.fetch_sub(1, Ordering::SeqCst);
    }
}
