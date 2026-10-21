//! Клиент unix-сокета демон-помощника `privd`.
//!
//! Протокол: одна строка-запрос (JSON или старый `ping`), одна строка
//! ответа. Используется сервером для привилегированных операций и для
//! проверок, что повышение прошло и сокет отвечает.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Таймаут чтения ответа: на случай зависшего демона соединение не должно
/// блокировать клиента навсегда.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Подключиться к сокету `sock_path`, отправить одну строку-запрос
/// (перевод строки добавляется) и прочитать одну строку-ответ. Ответ
/// возвращается без завершающего перевода строки. Любая ошибка —
/// человеко-читаемый текст в `String`.
///
/// # Errors
/// Ошибка соединения, записи или чтения — текст в `String`.
pub fn request(sock_path: &str, request_line: &str) -> Result<String, String> {
    request_with_timeout(sock_path, request_line, READ_TIMEOUT)
}

/// То же, что [`request`], но с явным таймаутом чтения (тесты).
///
/// # Errors
/// Ошибка соединения, записи или чтения — текст в `String`.
pub(crate) fn request_with_timeout(
    sock_path: &str,
    request_line: &str,
    timeout: Duration,
) -> Result<String, String> {
    let stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("primecore-privilege: не удалось подключиться к {sock_path}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("primecore-privilege: не удалось задать таймаут сокета: {e}"))?;

    let mut stream = stream;
    writeln!(stream, "{request_line}")
        .map_err(|e| format!("primecore-privilege: не удалось отправить запрос: {e}"))?;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("primecore-privilege: не удалось прочитать ответ: {e}"))?;
    if line.trim().is_empty() {
        return Err("primecore-privilege: демон закрыл соединение без ответа".to_string());
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Подключиться к сокету `sock_path`, отправить `ping` и дождаться
/// ответа `{"ok": true}`. Любая ошибка — текст в `String`.
///
/// # Errors
/// Ошибка соединения или неожиданный ответ — текст в `String`.
pub fn connect_and_ping(sock_path: &str) -> Result<(), String> {
    let reply = request(sock_path, "ping")?;
    let parsed: serde_json::Value = serde_json::from_str(&reply)
        .map_err(|e| format!("primecore-privilege: ответ не JSON: {e}"))?;
    if parsed.get("ok") == Some(&serde_json::Value::Bool(true)) {
        Ok(())
    } else {
        Err(format!("primecore-privilege: неожиданный ответ: {reply}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::tests_support::{serve_bounded, tmpdir, FakeExecutor};
    use crate::ops::{Ops, PrivilegedOps};
    use std::os::unix::net::UnixListener;

    #[test]
    fn request_returns_reply_without_newline() {
        let dir = tmpdir("client");
        let sock_path = dir.join("client.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        // Руки реального обработчика на фейковом исполнителе: команды не
        // запускаются, но протокол настоящий.
        serve_bounded(listener, Box::new(Ops::new(FakeExecutor::new())), 2);
        let sock = sock_path.to_string_lossy().into_owned();

        let reply = request(&sock, r#"{"op":"ping"}"#).expect("ответ");
        assert!(!reply.contains('\n'), "перевода строки быть не должно");
        let parsed: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
        assert_eq!(parsed["ok"], true);

        // Второй запрос в новом соединении — протокол многоразовый.
        let reply = request(&sock, r#"{"op":"nft","script":"add table inet t"}"#).expect("ответ");
        let parsed: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["output"], "правила применены\n");

        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn request_reports_missing_socket() {
        let dir = tmpdir("missing");
        let missing = dir.join("нет-такого.sock");
        let error =
            request(&missing.to_string_lossy(), r#"{"op":"ping"}"#).expect_err("сокета нет");
        assert!(error.contains("не удалось подключиться"), "{error}");
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn request_times_out_on_silent_server() {
        let dir = tmpdir("timeout");
        let sock_path = dir.join("silent.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        std::thread::spawn(move || {
            // Принимаем соединение и молчим.
            let _stream = listener.incoming().next();
            std::thread::sleep(Duration::from_secs(5));
        });
        let error = request_with_timeout(
            &sock_path.to_string_lossy(),
            "ping",
            Duration::from_millis(300),
        )
        .expect_err("сервер молчит");
        assert!(error.contains("не удалось прочитать ответ"), "{error}");
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn connect_and_ping_accepts_ok_and_rejects_failure() {
        let dir = tmpdir("ping");
        let sock_path = dir.join("ping.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        serve_bounded(listener, Box::new(Ops::new(FakeExecutor::new())), 1);
        connect_and_ping(&sock_path.to_string_lossy()).expect("пинг прошёл");

        // Сервер, отвечающий не ok — ошибка пинга.
        struct BadOps;
        impl PrivilegedOps for BadOps {
            fn handle(&mut self, _request: &str) -> String {
                r#"{"ok":false,"error":"нет"}"#.to_string()
            }
        }
        let bad = dir.join("bad.sock");
        let listener = UnixListener::bind(&bad).expect("сокет привязан");
        serve_bounded(listener, Box::new(BadOps), 1);
        assert!(connect_and_ping(&bad.to_string_lossy()).is_err());

        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }

    #[test]
    fn ops_module_wires_into_client_protocol() {
        // Дымовая связка: Ops<FakeExecutor> через сокет отвечает как демон.
        let dir = tmpdir("wiring");
        let sock_path = dir.join("ops.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        serve_bounded(listener, Box::new(Ops::new(FakeExecutor::new())), 1);
        let reply =
            request(&sock_path.to_string_lossy(), r#"{"op":"status","pid":42}"#).expect("ответ");
        let parsed: serde_json::Value = serde_json::from_str(&reply).expect("JSON");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["running"], false);
        std::fs::remove_dir_all(&dir).expect("убрали tmpdir");
    }
}
