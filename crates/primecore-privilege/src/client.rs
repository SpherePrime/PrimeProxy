//! Клиент unix-сокета демон-помощника `privd`.
//!
//! Протокол живой, но действий пока нет: клиент шлёт строку-запрос
//! `ping`, демон отвечает JSON `{"ok": true}`. Используется для
//! проверок, что повышение прошло и сокет отвечает.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;

/// Подключиться к сокету `sock_path`, отправить `ping` и дождаться
/// ответа `{"ok": true}`. Любая ошибка — текст в `String`.
pub fn connect_and_ping(sock_path: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("primecore-privilege: не удалось подключиться к {sock_path}: {e}"))?;
    writeln!(stream, "ping")
        .map_err(|e| format!("primecore-privilege: не удалось отправить запрос: {e}"))?;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("primecore-privilege: не удалось прочитать ответ: {e}"))?;
    if line.trim().is_empty() {
        return Err("primecore-privilege: демон закрыл соединение без ответа".to_string());
    }

    let reply: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|e| format!("primecore-privilege: ответ не JSON: {e}"))?;
    if reply.get("ok") == Some(&serde_json::Value::Bool(true)) {
        Ok(())
    } else {
        Err(format!(
            "primecore-privilege: неожиданный ответ: {}",
            line.trim()
        ))
    }
}
