//! Живые тесты уточнения причины: приветствия TLS против локальных серверов
//! (rustls с самоподписанным сертификатом, обычный HTTP, обрыв, тишина) и
//! сбор проб на машине прогона. Внешней сети нет.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use primecore_diagnostics::block_cause::{
    http_probe, judge, tls_hello, HELLO_ALERT, HELLO_CANCELLED, HELLO_CONNECT, HELLO_GARBAGE,
    HELLO_OK, HELLO_RESET, HELLO_TIMEOUT, TLS_1_2, TLS_1_3,
};
use primecore_diagnostics::probe_result::{ProbeResult, KIND_CONNECT, STAGE_CONNECT};
use primecore_diagnostics::protocol_probe::{
    collect_with_port as protocols_collect, judge as protocols_judge,
};
use primecore_diagnostics::run_context::Run;
use primecore_socketcancel::SocketCancel;

/// Самоподписанный сертификат для локального TLS-сервера.
fn tls_server_config(
    versions: &'static [&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ServerConfig> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["example.test".to_string()]).expect("сертификат");
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .expect("версии сервера доступны")
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
        )
        .expect("конфиг сервера собран"),
    )
}

/// Локальный TLS-сервер: принимает соединение и доводит рукопожатие.
fn spawn_tls_server(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
    let port = listener.local_addr().expect("адрес").port();
    let config = tls_server_config(versions);
    std::thread::spawn(move || {
        // Соединений может быть несколько (пробы идут по очереди с шагом).
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
            let Ok(mut server) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            for _ in 0..10 {
                match server.complete_io(&mut stream) {
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
        }
    });
    port
}

/// Локальный сервер по сценарию; запрос клиента вычитывается.
fn spawn_script(script: impl FnOnce(&mut TcpStream) + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
    let port = listener.local_addr().expect("адрес").port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            script(&mut stream);
        }
    });
    port
}

#[test]
fn tls_hello_ok_with_self_signed() {
    // Проверки сертификата нет: с самоподписанным сертификатом рукопожатие
    // всё равно считается состоявшимся — сервер ответил.
    const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    let port = spawn_tls_server(TLS13_ONLY);
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        4.0,
        &SocketCancel::new(),
        "",
    );
    assert_eq!(result.kind, HELLO_OK, "{}", result.detail);
    assert!(result.ms.is_some());
    assert!(result.answered());
}

#[test]
fn tls_hello_reset_on_silent_close() {
    let port = spawn_script(|stream| {
        // Сервер закрыл соединение на приветствии.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        2.0,
        &SocketCancel::new(),
        "",
    );
    assert_eq!(result.kind, HELLO_RESET, "{}", result.detail);
    assert!(!result.answered());
}

#[test]
fn tls_hello_garbage_on_plain_http() {
    let port = spawn_script(|stream| {
        // На приветствие TLS отвечает обычный HTTP — это не сервер шифрования.
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    });
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        2.0,
        &SocketCancel::new(),
        "",
    );
    assert_eq!(result.kind, HELLO_GARBAGE, "{}", result.detail);
}

#[test]
fn tls_hello_connect_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет");
    let port = listener.local_addr().expect("адрес").port();
    drop(listener);
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        2.0,
        &SocketCancel::new(),
        "",
    );
    assert_eq!(result.kind, HELLO_CONNECT, "{}", result.detail);
}

#[test]
fn tls_hello_timeout_on_silence() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
    let port = listener.local_addr().expect("адрес").port();
    std::thread::spawn(move || {
        // Принимаем и молчим: рукопожатие не двигается.
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_secs(30));
            drop(stream);
        }
    });
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        0.5,
        &SocketCancel::new(),
        "",
    );
    assert_eq!(result.kind, HELLO_TIMEOUT, "{}", result.detail);
}

#[test]
fn tls_hello_cancelled() {
    let cancel = SocketCancel::new();
    cancel.cancel();
    const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    let port = spawn_tls_server(TLS13_ONLY);
    assert_eq!(
        tls_hello("127.0.0.1", Some("example.test"), port, 2.0, &cancel, "").kind,
        HELLO_CANCELLED
    );
}

#[test]
fn tls_hello_version_pinned() {
    // Клиент просит только TLS 1.2, сервер умеет только TLS 1.3: сервер
    // отвечает отказом — «нет у сервера», а не блокировка.
    const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    let port = spawn_tls_server(TLS13_ONLY);
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        2.0,
        &SocketCancel::new(),
        TLS_1_2,
    );
    assert_eq!(result.kind, HELLO_ALERT, "{}", result.detail);
    // Сервер ответил отказом — дорога есть, это не блокировка.
    assert!(result.answered());
    // И наоборот: клиент просит только TLS 1.3 у сервера с TLS 1.3 — работает.
    let result = tls_hello(
        "127.0.0.1",
        Some("example.test"),
        port,
        2.0,
        &SocketCancel::new(),
        TLS_1_3,
    );
    assert_eq!(result.kind, HELLO_OK, "{}", result.detail);
}

#[test]
fn http_probe_reads_status_and_location() {
    let port = spawn_script(|stream| {
        let _ =
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/stop\r\n\r\n");
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    let facts = http_probe("site.test", "127.0.0.1", port, 2.0, &SocketCancel::new());
    assert_eq!(facts.status, Some(302));
    assert_eq!(facts.location, "https://warning.rt.ru/stop");
    // Страница-заглушка распознаётся по адресу перенаправления.
    assert_eq!(
        primecore_diagnostics::block_cause::stub_reason("site.test", Some(&facts)),
        "перенаправление на страницу о блокировке warning.rt.ru"
    );
}

#[test]
fn http_probe_silent_port_is_empty() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет");
    let port = listener.local_addr().expect("адрес").port();
    drop(listener);
    let facts = http_probe("site.test", "127.0.0.1", port, 1.0, &SocketCancel::new());
    assert_eq!(facts.status, None);
    assert!(facts.body.is_empty());
}

#[test]
fn cause_collect_connect_branch_with_ping() {
    // Соединение не состоялось: проба порта 80 (молчит) и пинг (отвечает) —
    // вывод «адрес закрыт, но жив».
    let listener = TcpListener::bind("127.0.0.1:0").expect("сокет");
    drop(listener);
    let run = Run::new(None, 4, None);
    let mut result = ProbeResult::new("site.test", KIND_CONNECT);
    result.ip = "127.0.0.1".to_string();
    result.stage = STAGE_CONNECT;
    let ping: primecore_diagnostics::engine::PingFn = Arc::new(|_ip| Some(true));
    let facts =
        primecore_diagnostics::block_cause::collect("site.test", &result, &run, Some(&ping))
            .expect("сбор не сорвался");
    assert_eq!(facts.ping_ok, Some(true));
    assert_eq!(facts.http.as_ref().expect("проба порта 80").status, None);
    let cause = judge(&facts).expect("вывод есть");
    assert_eq!(cause.code, "address_closed");
}

#[test]
fn protocols_collect_three_roads() {
    // Локальный сервер умеет обе версии шифрования — обе простые дороги
    // работают; вывод строится по фактом.
    let tls_port = spawn_tls_server(rustls::DEFAULT_VERSIONS);
    let run = Run::new(None, 4, None);
    let facts =
        protocols_collect("site.test", "127.0.0.1", tls_port, &run).expect("сбор не сорвался");
    assert_eq!(
        facts.tls12.as_ref().expect("TLS 1.2 пробовался").kind,
        HELLO_OK
    );
    assert_eq!(
        facts.tls13.as_ref().expect("TLS 1.3 пробовался").kind,
        HELLO_OK
    );
    assert!(!facts.cancelled);
    let lines = protocols_judge(Some(&facts), None);
    assert!(lines.iter().any(|line| line.state == "ok"));
}
