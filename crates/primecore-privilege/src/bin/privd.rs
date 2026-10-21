//! Демон-помощник `privd`.
//!
//! Слушает unix-сокет (путь из `PRIMECORE_PRIV_SOCK`, по умолчанию
//! `/tmp/primecore-privd.sock`); протокол — одна строка = один JSON-запрос,
//! одна строка = один JSON-ответ. Операции описаны в
//! [`primecore_privilege::ops`]: `ping`, `nft`, `nft_delete`, `daemon`,
//! `kill`, `status`; любая не-JSON строка отвечает `{"ok":true}`
//! (совместимость со старым клиентом).
//!
//! Запускается один раз через `pkexec`/`sudo` при первом старте; дальше
//! демон держит привилегии, повторные sudo-запросы не нужны.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;

use primecore_privilege::ops::{PrivilegedOps, RealExecutor, RealOps};

const DEFAULT_SOCK_PATH: &str = "/tmp/primecore-privd.sock";

fn main() -> std::io::Result<()> {
    let sock_path =
        std::env::var("PRIMECORE_PRIV_SOCK").unwrap_or_else(|_| DEFAULT_SOCK_PATH.to_string());

    // Захватываем путь заново: после перезагрузки сокет-файл не живёт,
    // но при повторном старте демона без перезагрузки остаток надо убрать.
    match std::fs::remove_file(&sock_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("privd: не удалось удалить старый сокет {sock_path}: {e}");
        }
    }

    let listener = UnixListener::bind(&sock_path)?;
    eprintln!("privd: слушаю {sock_path}");

    let mut ops = RealOps::new(RealExecutor);
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("privd: ошибка соединения: {e}");
                continue;
            }
        };
        // Одна строка-запрос — один JSON-ответ. Строк может быть несколько.
        let mut reader = std::io::BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // соединение закрыто
                Ok(_) => {
                    let reply = ops.handle(&line);
                    if let Err(e) = writeln!(stream, "{reply}") {
                        eprintln!("privd: не удалось ответить: {e}");
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("privd: ошибка чтения запроса: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}
