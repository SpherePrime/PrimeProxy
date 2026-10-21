//! Журнал Telegram Proxy: файл с ротацией и кольцевой буфер для интерфейса.
//!
//! Порт `telegram_proxy/proxy_logger.py`. Записи идут в
//! `LOGS_FOLDER/tg_proxy.log` с ротацией (лимит файла, запасные копии) и
//! дублируются в кольцевой буфер последних строк для показа в окне.
//!
//! Разделение как в python: формат строки и буферы — чистые функции и
//! структуры, а запись в файл — замыкание ([`WriteLogFn`]); стандартная
//! ротация файлов даёт [`rotating_file_writer`]. python держал журнал
//! глобальным синглтоном с `threading.Lock` — здесь владение журналом у
//! вызывающего кода (менеджера прокси), а защита буферов — [`std::sync::Mutex`].

use std::collections::VecDeque;
use std::sync::Mutex;

/// Имя файла журнала Telegram Proxy.
pub const LOG_FILENAME: &str = "tg_proxy.log";
/// Лимит размера файла журнала: 10 МБ.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Сколько запасных файлов хранится при ротации.
pub const BACKUP_COUNT: usize = 5;
/// Размер кольцевого буфера последних строк.
pub const RING_BUFFER_SIZE: usize = 100;
/// Лимит неотданных интерфейсу строк (python `ui.log_limits`).
pub const PENDING_MAX_LINES: usize = 1_000;

/// python `ui.log_limits.append_bounded_line`: добавляет строку и оставляет
/// только последние `max_lines`.
pub fn append_bounded_line(lines: &mut Vec<String>, line: &str, max_lines: usize) {
    let limit = max_lines.max(1);
    lines.push(line.to_string());
    let overflow = lines.len().saturating_sub(limit);
    if overflow > 0 {
        lines.drain(..overflow);
    }
}

/// Метка времени строки файла: `%Y-%m-%d %H:%M:%S` по часам UTC
/// (python `logging` писал локальное время — фасад может подставить свою).
#[must_use]
pub fn format_timestamp(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let seconds_of_day = unix_seconds % 86_400;
    // Обратный алгоритм Гаусса: гражданская дата по числу дней.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

/// Строка файла журнала: `%Y-%m-%d %H:%M:%S` и сообщение через два пробела.
#[must_use]
pub fn format_log_line(timestamp: &str, message: &str) -> String {
    format!("{timestamp}  {message}")
}

/// Запись строки в файл журнала (python `RotatingFileHandler.emit`).
/// Ошибки записи python глотал — здесь замыкание ничего не возвращает.
pub type WriteLogFn = dyn Fn(&str) + Send + Sync;

/// Буферы журнала: кольцо последних строк и неотданные интерфейсу строки.
#[derive(Debug, Default)]
struct LoggerBuffers {
    ring: VecDeque<String>,
    pending: Vec<String>,
}

/// Журнал Telegram Proxy: пишет строки в файл и держит буферы для интерфейса.
///
/// Использование как в python:
/// ```ignore
/// logger.log("Connection from 127.0.0.1:54321");
/// let recent = logger.get_recent(); // последние строки для показа
/// let fresh = logger.drain();       // новые строки с прошлого drain
/// ```
pub struct ProxyLogger {
    ring_size: usize,
    buffers: Mutex<LoggerBuffers>,
    write: Box<WriteLogFn>,
    log_file_path: String,
}

impl ProxyLogger {
    /// Новый журнал. `write` — запись строки в файл (python `logger.info`),
    /// `log_file_path` — путь файла для показа пользователю.
    #[must_use]
    pub fn new(log_file_path: impl Into<String>, write: Box<WriteLogFn>) -> Self {
        Self {
            ring_size: RING_BUFFER_SIZE,
            buffers: Mutex::new(LoggerBuffers::default()),
            write,
            log_file_path: log_file_path.into(),
        }
    }

    /// Пишет строку в файл и в буферы. Ошибки записи глотаются, как в python.
    pub fn log(&self, message: &str) {
        let stamp = format_log_line(&format_timestamp(now_unix()), message);
        // python глотал исключения записи файла; паника замыкания здесь
        // тоже не должна ронять журнал.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.write)(&stamp)));

        let mut buffers = match self.buffers.lock() {
            Ok(buffers) => buffers,
            Err(poisoned) => poisoned.into_inner(),
        };
        buffers.ring.push_back(message.to_string());
        while buffers.ring.len() > self.ring_size {
            buffers.ring.pop_front();
        }
        append_bounded_line(&mut buffers.pending, message, PENDING_MAX_LINES);
    }

    /// Возвращает и очищает строки, накопившиеся с прошлого вызова.
    /// Пустой список, если ничего нового.
    #[must_use]
    pub fn drain(&self) -> Vec<String> {
        let mut buffers = match self.buffers.lock() {
            Ok(buffers) => buffers,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut buffers.pending)
    }

    /// Снимок кольцевого буфера: последние `ring_size` строк.
    #[must_use]
    pub fn get_recent(&self) -> Vec<String> {
        let buffers = match self.buffers.lock() {
            Ok(buffers) => buffers,
            Err(poisoned) => poisoned.into_inner(),
        };
        buffers.ring.iter().cloned().collect()
    }

    /// Путь файла журнала (python-свойство `log_file_path`).
    #[must_use]
    pub fn log_file_path(&self) -> &str {
        &self.log_file_path
    }
}

/// Текущее время в секундах Unix (python `logging` брал время сам).
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_secs())
        .unwrap_or(0)
}

/// Стандартная запись в файл с ротацией (python `RotatingFileHandler` с
/// `delay=True`): файл создаётся только на первой реальной строке.
///
/// Ротация: при достижении `max_bytes` файлы сдвигаются `tg_proxy.log.1` →
/// `.2` и так далее до `backup_count`, самый старый удаляется.
pub fn rotating_file_writer(logs_dir: &str) -> Box<WriteLogFn> {
    rotating_file_writer_with(logs_dir, MAX_BYTES, BACKUP_COUNT)
}

/// То же с настраиваемыми лимитами — для быстрых тестов ротации.
pub fn rotating_file_writer_with(
    logs_dir: &str,
    max_bytes: u64,
    backup_count: usize,
) -> Box<WriteLogFn> {
    let logs_dir = logs_dir.to_string();
    let log_path = std::path::Path::new(&logs_dir).join(LOG_FILENAME);
    Box::new(move |line: &str| {
        let _ = std::fs::create_dir_all(&logs_dir);
        if let Ok(metadata) = std::fs::metadata(&log_path) {
            if metadata.len() >= max_bytes {
                rotate(&log_path, backup_count);
            }
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            use std::io::Write;
            let _ = writeln!(file, "{line}");
        }
    })
}

/// python `RotatingFileHandler.doRollover`: сдвиг запасных файлов.
fn rotate(log_path: &std::path::Path, backup_count: usize) {
    if backup_count == 0 {
        let _ = std::fs::remove_file(log_path);
        return;
    }
    let oldest = log_path.with_extension(format!("log.{backup_count}"));
    let _ = std::fs::remove_file(&oldest);
    for index in (1..backup_count).rev() {
        let from = log_path.with_extension(format!("log.{index}"));
        let to = log_path.with_extension(format!("log.{}", index + 1));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    let first = log_path.with_extension("log.1");
    let _ = std::fs::rename(log_path, &first);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Уникальная временная папка, удаляется при выходе.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tg-proxy-log-{tag}-{}-{}",
                std::process::id(),
                fastrand::u64(..)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn log_line_format_matches_python() {
        assert_eq!(
            format_log_line("2026-10-21 13:16:07", "первая строка"),
            "2026-10-21 13:16:07  первая строка"
        );
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
        // 2026-10-21 08:16:07 UTC = 1792570567 секунд.
        assert_eq!(format_timestamp(1_792_570_567), "2026-10-21 08:16:07");
        assert_eq!(format_timestamp(86_399), "1970-01-01 23:59:59");
        assert_eq!(format_timestamp(951_868_800), "2000-03-01 00:00:00");
    }

    #[test]
    fn pending_drains_once() {
        let logger = ProxyLogger::new("ignored", Box::new(|_| {}));
        logger.log("первая");
        logger.log("вторая");

        assert_eq!(
            logger.drain(),
            vec!["первая".to_string(), "вторая".to_string()]
        );
        // После drain новых строк нет.
        assert!(logger.drain().is_empty());
        logger.log("третья");
        assert_eq!(logger.drain(), vec!["третья".to_string()]);
    }

    #[test]
    fn ring_keeps_last_lines() {
        let logger = ProxyLogger::new("ignored", Box::new(|_| {}));
        for index in 0..150 {
            logger.log(&format!("строка {index}"));
        }
        let recent = logger.get_recent();
        assert_eq!(recent.len(), RING_BUFFER_SIZE);
        assert_eq!(recent.last().unwrap(), "строка 149");
        assert_eq!(recent.first().unwrap(), "строка 50");
    }

    #[test]
    fn pending_bounded_by_limit() {
        let mut lines: Vec<String> = Vec::new();
        for index in 0..1_100 {
            append_bounded_line(&mut lines, &format!("{index}"), PENDING_MAX_LINES);
        }
        assert_eq!(lines.len(), PENDING_MAX_LINES);
        assert_eq!(lines.first().unwrap(), "100");
        assert_eq!(lines.last().unwrap(), "1099");
        // Лимит меньше 1 приравнивается к 1 — как python `max(1, ...)`.
        let mut single: Vec<String> = Vec::new();
        append_bounded_line(&mut single, "a", 0);
        append_bounded_line(&mut single, "b", 0);
        assert_eq!(single, vec!["b".to_string()]);
    }

    #[test]
    fn log_file_is_created_only_on_first_real_log_line() {
        let temp = TempDir::new("delay");
        let logs_dir = temp.0.to_string_lossy().to_string();
        let writer = rotating_file_writer(&logs_dir);
        let logger = ProxyLogger::new(
            std::path::Path::new(&logs_dir)
                .join(LOG_FILENAME)
                .to_string_lossy()
                .to_string(),
            writer,
        );
        let log_path = std::path::PathBuf::from(logger.log_file_path());

        // Файл не создан до первой строки (python `delay=True`).
        assert!(!log_path.exists());

        logger.log("первая строка Telegram Proxy");

        assert!(log_path.exists());
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            content.contains("первая строка Telegram Proxy"),
            "{content}"
        );
        // Строка файла с меткой времени и сообщением.
        let line = content.lines().next().unwrap();
        assert!(line.ends_with("  первая строка Telegram Proxy"), "{line}");
        assert_eq!(line.split("  ").count(), 2);
    }

    #[test]
    fn write_errors_are_swallowed() {
        let writes = AtomicUsize::new(0);
        let logger = ProxyLogger::new(
            "ignored",
            Box::new(move |_| {
                writes.fetch_add(1, Ordering::SeqCst);
                // Падение записи не должно ронять журнал.
                panic!("disk on fire");
            }),
        );
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| logger.log("boom")));
        assert_eq!(logger.drain(), vec!["boom".to_string()]);
    }

    #[test]
    fn rotation_shifts_backups() {
        let temp = TempDir::new("rotate");
        let logs_dir = temp.0.to_string_lossy().to_string();
        // Лимит 100 байт, две запасные копии. Строки по 17 байт: шесть строк
        // дают 102 байта — седьмая запись вызывает ротацию.
        let writer = rotating_file_writer_with(&logs_dir, 100, 2);
        for index in 0..14 {
            writer(&format!("line {index:03} padding"));
        }

        let read = |name: &str| std::fs::read_to_string(temp.0.join(name)).unwrap_or_default();
        // Текущий файл — последние строки.
        let current = read(LOG_FILENAME);
        assert!(current.starts_with("line 012"), "{current}");
        assert!(current.contains("line 013"), "{current}");
        // Запасные копии — предыдущие порции.
        assert!(
            read("tg_proxy.log.1").starts_with("line 006"),
            "{}",
            read("tg_proxy.log.1")
        );
        assert!(
            read("tg_proxy.log.2").starts_with("line 000"),
            "{}",
            read("tg_proxy.log.2")
        );
        // Третей запасной копии нет: python хранит только backup_count.
        assert!(read("tg_proxy.log.3").is_empty());
        assert!(!temp.0.join("tg_proxy.log.3").exists());
        // Всего записей — 14, ни одна не потерялась.
        let total: usize = [LOG_FILENAME, "tg_proxy.log.1", "tg_proxy.log.2"]
            .iter()
            .map(|name| read(name).lines().count())
            .sum();
        assert_eq!(total, 14);
    }
}
