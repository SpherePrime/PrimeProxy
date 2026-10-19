//! Тесты поведения «Стоп» (аналог SocketCancel у python).

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use primecore_socketcancel::SocketCancel;

#[test]
fn sleep_survives_without_cancel() {
    let cancel = SocketCancel::new();
    let started = Instant::now();
    assert!(cancel.sleep(0.05));
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(!cancel.cancelled());
}

#[test]
fn break_sleep_ends_false() {
    let cancel = Arc::new(SocketCancel::new());
    let handle = thread::spawn({
        let cancel = Arc::clone(&cancel);
        move || {
            // После cancel() (как у python: событие остаётся взведённым)
            // любая новая пауза кончается сразу.
            let started = std::time::Instant::now();
            let surviving = cancel.sleep(30.0);
            assert!(started.elapsed() < Duration::from_secs(10));
            let quick = cancel.sleep(30.0);
            assert!(!quick);
            (surviving, cancel.cancelled())
        }
    });
    thread::sleep(Duration::from_millis(100));
    cancel.cancel();
    let (surviving, cancelled) = handle.join().unwrap();
    assert!(!surviving);
    assert!(cancelled);
}

#[test]
fn sleep_false_when_already_cancelled() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    assert!(!cancel.sleep(1.0));
}

#[test]
fn quick_sleep_after_cancel_is_false_immediately() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    let started = Instant::now();
    assert!(!cancel.sleep(5.0));
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[test]
fn track_refuses_after_cancel() {
    let cancel = SocketCancel::new();
    let activity = cancel.track().expect("до отмены берёт");
    assert_eq!(cancel.active(), 1);
    cancel.cancel();
    assert!(cancel.track().is_none());
    drop(activity);
    assert_eq!(cancel.active(), 0);
}

#[test]
fn release_lifts_activity_count() {
    let cancel = SocketCancel::new();
    let activity = cancel.track().unwrap();
    assert_eq!(cancel.active(), 1);
    drop(activity);
    assert_eq!(cancel.active(), 0);
    let activity = cancel.track().unwrap();
    activity.release();
    assert_eq!(cancel.active(), 0);
}
