//! Транспорт клиента на unix: соединение с unix-сокетом демона `privd`.
//!
//! Здесь только платформенная часть — подключение и таймаут чтения.
//! Протокол (строка-запрос, строка-ответ) общий и живёт в `client.rs`.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::Transport;

/// Подключиться к unix-сокету `sock_path` и выставить таймаут чтения.
/// Обмен строками делает общий протокол в `client.rs`.
///
/// # Errors
/// Ошибка соединения или установки таймаута — текст в `String`.
pub(super) fn connect(sock_path: &str, timeout: Duration) -> Result<Box<dyn Transport>, String> {
    let stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("primecore-privilege: не удалось подключиться к {sock_path}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("primecore-privilege: не удалось задать таймаут сокета: {e}"))?;
    Ok(Box::new(stream))
}

impl Transport for UnixStream {}
