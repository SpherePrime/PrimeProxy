//! Живые тесты QUIC-пробы: пакеты Initial против подставного QUIC-сервера на
//! локальном UDP-сокете (внешней сети нет; расшифровка ответа не нужна —
//! ответом считается любой пакет на наше соединение).

use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use primecore_diagnostics::net_transport::quic_collect_with;
use primecore_diagnostics::quic_probe::{judge, quic_hello, QuicFacts, QUIC_PORT};
use primecore_diagnostics::run_context::Run;
use primecore_socketcancel::SocketCancel;

/// Что отвечает подставной сервер: всем или только указанным по счёту пакетам.
#[derive(Clone, Copy)]
enum Policy {
    All,
    Only(&'static [usize]),
}

/// Подставной QUIC-сервер: читает пакет, достаёт наш номер соединения
/// (source id) и отвечает длинным заголовком с ним в качестве получателя.
fn spawn_quic_server(policy: Policy) -> (u16, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("сокет слушается");
    let port = socket.local_addr().expect("адрес").port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while let Ok((size, from)) = socket.recv_from(&mut buffer) {
            let number = counter.fetch_add(1, Ordering::SeqCst) + 1;
            match policy {
                Policy::All => {}
                Policy::Only(list) => {
                    if !list.contains(&number) {
                        continue;
                    }
                }
            }
            // Наш source id: после версии и длины чужого номера.
            let datagram = &buffer[..size];
            if datagram.len() < 7 {
                continue;
            }
            let destination_len = datagram[5] as usize;
            if datagram.len() < 6 + destination_len + 1 {
                continue;
            }
            let source_len = datagram[6 + destination_len] as usize;
            let Some(source) = datagram.get(7 + destination_len..7 + destination_len + source_len)
            else {
                continue;
            };
            let mut reply = vec![0xC0u8, 0, 0, 0, 1, source.len() as u8];
            reply.extend_from_slice(source);
            let _ = socket.send_to(&reply, from);
        }
    });
    (port, seen)
}

#[test]
fn quic_hello_hears_reply() {
    let (port, seen) = spawn_quic_server(Policy::All);
    let result = quic_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        1,
        2.0,
        &SocketCancel::new(),
    );
    assert!(result.is_some(), "ответ сервера не услышан");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    // Имя сайта в пакете есть — значит, пакет настоящий и достаточно большой.
    assert!(result.unwrap() >= 0.0);
}

#[test]
fn quic_hello_silence_is_none() {
    // Сервер отвечает всем, но по чужому порту — до нашей пробы ответ не дойдёт.
    let result = quic_hello(
        "127.0.0.1",
        Some("example.test"),
        1,
        1,
        0.3,
        &SocketCancel::new(),
    );
    assert_eq!(result, None);
}

#[test]
fn quic_hello_cancelled() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    let (port, _seen) = spawn_quic_server(Policy::All);
    assert_eq!(
        quic_hello("127.0.0.1", Some("example.test"), port, 1, 2.0, &cancel),
        None
    );
}

#[test]
fn collect_blocked_by_name_with_real_silent() {
    // Настоящее имя молчит (пакет 1), постороннее и без имени отвечают
    // (пакеты 2 и 3, уходят параллельно), настоящее имя на повторе молчит.
    let (port, _seen) = spawn_quic_server(Policy::Only(&[2, 3]));
    let run = Run::new(None, 4, None);
    let facts =
        quic_collect_with("site.test", "127.0.0.1", port, &run, 1, 0.5).expect("сбор не сорвался");
    assert_eq!(facts.real_ms, None);
    assert!(facts.neutral_ms.is_some(), "постороннее имя должно пройти");
    assert!(facts.nameless_ms.is_some(), "пакет без имени должен пройти");
    assert_eq!(facts.real_again_ms, None);
    let verdict = judge(&facts).expect("проверку не снимали");
    assert_eq!(verdict.code, "blocked_by_name");
}

#[test]
fn collect_silent_everywhere() {
    // Отвечает только первый настоящий пакет — всё остальное молчит.
    let (port, _seen) = spawn_quic_server(Policy::Only(&[1]));
    let run = Run::new(None, 4, None);
    let facts =
        quic_collect_with("site.test", "127.0.0.1", port, &run, 1, 0.3).expect("сбор не сорвался");
    assert!(facts.real_ms.is_some());
    let verdict = judge(&facts).expect("проверку не снимали");
    assert_eq!(verdict.code, "ok");
    // Совсем тишина: ни один сервер не ответил.
    let facts = QuicFacts {
        host: "site.test".to_string(),
        ..QuicFacts::default()
    };
    assert_eq!(judge(&facts).expect("вывод").code, "silent");
    // Порт не QUIC (порт 1 зарезервирован и молчит): тишина — не блокировка.
    let run = Run::new(None, 4, None);
    let facts =
        quic_collect_with("site.test", "127.0.0.1", port, &run, 1, 0.2).expect("сбор не сорвался");
    assert_eq!(facts.real_ms, None);
    assert_eq!(
        judge(&facts).expect("вывод").code,
        "silent",
        "полная тишина — не блокировка по имени"
    );
}

#[test]
fn collect_cancelled_reports_itself() {
    let run = Run::new(None, 4, None);
    run.probe_cancel.cancel();
    let facts = quic_collect_with("site.test", "127.0.0.1", QUIC_PORT, &run, 1, 0.3)
        .expect("сбор не сорвался");
    assert!(facts.cancelled);
    assert_eq!(judge(&facts), None, "по обрывкам вывод не делается");
}

/// Счётчик пакетов не обязателен для соседних тестов — проверяем, что подставной
/// сервер считает их (иначе «Only»-политика была бы фикцией).
#[test]
fn server_counts_packets() {
    let (port, seen) = spawn_quic_server(Policy::All);
    let socket = UdpSocket::bind("127.0.0.1:0").expect("сокет");
    let _ = socket.send_to(&[0u8; 1200], ("127.0.0.1", port));
    let _ = socket.send_to(&[0u8; 1200], ("127.0.0.1", port));
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(seen.load(Ordering::SeqCst) >= 2);
}
