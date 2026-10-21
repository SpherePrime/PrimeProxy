//! Записи сайтов Telegram в файле hosts Windows.
//!
//! Порт `telegram_proxy/telegram_hosts.py`. Блок строк «149.154.167.220
//! домен» нужен только браузеру: с ним открываются web.telegram.org, t.me,
//! telegram.org и загрузки desktop.telegram.org. Самому Telegram Proxy он не
//! нужен — прокси подключается к серверам по IP.
//!
//! Файл hosts меняется только по явной кнопке на странице Telegram Proxy
//! («Прописать» / «Убрать»); открытие страницы лишь читает файл.
//!
//! Модуль делится на две части: чистые функции над текстом hosts
//! (`*_from_text`, `*_to_text`) и обёртки с чтением и записью файла — файл
//! передаётся замыканиями ([`ReadHostsFn`], [`WriteHostsFn`]), крейт сам файл
//! не открывает.

/// Адрес входа веб-релеев Telegram, который прописывается в hosts.
pub const TELEGRAM_RELAY_IP: &str = "149.154.167.220";

/// Известные, но не используемые домены Telegram — их в hosts не добавляют:
/// `kws1.web.telegram.org`, `kws1-1.web.telegram.org`, `kws5.web.telegram.org`,
/// `kws5-1.web.telegram.org`, `zws1.web.telegram.org`,
/// `zws1-1.web.telegram.org`, `zws5.web.telegram.org`,
/// `zws5-1.web.telegram.org`, `pluto.web.telegram.org`,
/// `pluto-1.web.telegram.org`, `flora.web.telegram.org`.
/// Домены Telegram, которые ведутся на relay IP в hosts.
pub const TELEGRAM_DOMAINS: &[&str] = &[
    "zws4.web.telegram.org",
    "vesta.web.telegram.org",
    "core.telegram.org",
    "my.telegram.org",
    "oauth.telegram.org",
    "vesta-1.web.telegram.org",
    "venus-1.web.telegram.org",
    "telegram.me",
    "telegram.dog",
    "telegram.space",
    "telesco.pe",
    "cdn.telesco.pe",
    "cdn1.telesco.pe",
    "cdn2.telesco.pe",
    "cdn3.telesco.pe",
    "cdn4.telesco.pe",
    "cdn5.telesco.pe",
    "cdn6.telesco.pe",
    "tg.dev",
    "oauth.tg.dev",
    "telegram.org",
    "desktop.telegram.org",
    "macos.telegram.org",
    "t.me",
    "api.telegram.org",
    "td.telegram.org",
    "venus.web.telegram.org",
    "web.telegram.org",
    "kws2-1.web.telegram.org",
    "kws2.web.telegram.org",
    "kws4-1.web.telegram.org",
    "kws4.web.telegram.org",
    "zws2-1.web.telegram.org",
    "zws2.web.telegram.org",
    "zws4-1.web.telegram.org",
];

/// Заголовок блока Telegram в hosts.
pub const TELEGRAM_HOSTS_MARKER: &str = "# --- Telegram Proxy (auto-managed by PrimeBypass) ---";
/// Заголовок, который писала прежняя версия программы.
const LEGACY_TELEGRAM_HOSTS_MARKER: &str =
    "# --- Telegram Proxy (auto-managed by Zapret 2 GUI) ---";

/// Ошибка чтения или записи файла hosts. Текст — для пользователя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramHostsError {
    pub message: String,
}

impl std::fmt::Display for TelegramHostsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TelegramHostsError {}

/// Сколько доменов Telegram сейчас ведут на relay IP в файле hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelegramHostsStatus {
    pub present: usize,
    pub total: usize,
    pub block_present: bool,
}

impl TelegramHostsStatus {
    /// Все домены прописаны.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total > 0 && self.present >= self.total
    }

    /// Записей Telegram нет.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.present == 0
    }
}

/// python `_parse_entry`: (ip, домен в нижнем регистре) или `None`.
#[must_use]
fn parse_entry(line: &str) -> Option<(String, String)> {
    let stripped = line.trim();
    if stripped.is_empty() || stripped.starts_with('#') {
        return None;
    }
    let mut parts = stripped.split_whitespace();
    let ip = parts.next()?;
    let domain = parts.next()?;
    Some((ip.to_string(), domain.to_lowercase()))
}

/// Строки текста с сохранением переводов строк (python `splitlines(True)`).
fn split_keepends(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = Vec::new();
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            lines.push(&text[start..=index]);
            start = index + 1;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// python `_trim_trailing_blank_lines`.
fn trim_trailing_blank_lines(lines: &mut Vec<String>) {
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
}

/// Считает домены Telegram, которые по файлу hosts ведут на relay IP.
///
/// Windows берёт первую подходящую строку, поэтому для каждого домена
/// учитывается только первая запись.
#[must_use]
pub fn telegram_hosts_status_from_text(content: &str) -> TelegramHostsStatus {
    let mut first_ip: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut block_present = false;
    for line in content.lines() {
        let stripped = line.trim();
        if stripped == TELEGRAM_HOSTS_MARKER || stripped == LEGACY_TELEGRAM_HOSTS_MARKER {
            block_present = true;
            continue;
        }
        let Some((ip, domain)) = parse_entry(line) else {
            continue;
        };
        first_ip.entry(domain).or_insert(ip);
    }
    let present = TELEGRAM_DOMAINS
        .iter()
        .filter(|domain| first_ip.get(**domain).map(String::as_str) == Some(TELEGRAM_RELAY_IP))
        .count();
    TelegramHostsStatus {
        present,
        total: TELEGRAM_DOMAINS.len(),
        block_present,
    }
}

/// Убирает старые строки доменов Telegram и дописывает блок в конец.
///
/// Строки доменов Telegram на любой IP заменяются блоком, иначе Windows может
/// взять старую запись. Повторный вызов даёт тот же текст.
#[must_use]
pub fn add_telegram_hosts_to_text(content: &str) -> String {
    let mut new_lines: Vec<String> = Vec::new();
    for line in split_keepends(content) {
        let stripped = line.trim();
        if stripped == TELEGRAM_HOSTS_MARKER || stripped == LEGACY_TELEGRAM_HOSTS_MARKER {
            continue;
        }
        if let Some((_, domain)) = parse_entry(line) {
            if TELEGRAM_DOMAINS.contains(&domain.as_str()) {
                continue;
            }
        }
        new_lines.push(line.to_string());
    }

    trim_trailing_blank_lines(&mut new_lines);
    if let Some(last) = new_lines.last_mut() {
        if !last.ends_with('\n') {
            last.push('\n');
        }
        new_lines.push("\n".to_string());
    }
    new_lines.push(format!("{TELEGRAM_HOSTS_MARKER}\n"));
    for domain in TELEGRAM_DOMAINS {
        new_lines.push(format!("{TELEGRAM_RELAY_IP} {domain}\n"));
    }
    new_lines.concat()
}

/// Убирает строку-маркер и строки «relay IP → домен Telegram».
///
/// Остальные строки, в том числе домены Telegram на другом IP, остаются.
/// Если убирать нечего, возвращается исходный текст без изменений.
#[must_use]
pub fn remove_telegram_hosts_from_text(content: &str) -> String {
    let mut new_lines: Vec<String> = Vec::new();
    let mut removed = false;
    for line in split_keepends(content) {
        let stripped = line.trim();
        if stripped == TELEGRAM_HOSTS_MARKER || stripped == LEGACY_TELEGRAM_HOSTS_MARKER {
            removed = true;
            continue;
        }
        if let Some((ip, domain)) = parse_entry(line) {
            if ip == TELEGRAM_RELAY_IP && TELEGRAM_DOMAINS.contains(&domain.as_str()) {
                removed = true;
                continue;
            }
        }
        new_lines.push(line.to_string());
    }

    if !removed {
        return content.to_string();
    }
    // Пустая строка, которую добавлял блок перед маркером, не должна копиться.
    trim_trailing_blank_lines(&mut new_lines);
    if let Some(last) = new_lines.last_mut() {
        if !last.ends_with('\n') {
            last.push('\n');
        }
    }
    new_lines.concat()
}

/// python `hosts.public.read_hosts_file`: текст файла hosts или сбой.
/// `Ok(None)` — python получил `None` (файл не прочитан), `Err(причина)` —
/// исключение чтения с текстом причины.
pub type ReadHostsFn<'a> = dyn Fn() -> Result<Option<String>, String> + 'a;

/// python `hosts.public.write_hosts_file`: записывает текст и отвечает,
/// удалась ли запись; `Err(причина)` — исключение записи.
pub type WriteHostsFn<'a> = dyn Fn(&str) -> Result<bool, String> + 'a;

/// Журнал программы (python `log.log`) — ввод вызывающего кода.
pub type LogFn<'a> = dyn Fn(&str) + 'a;

/// Текст ошибки записи hosts: файл защищён или нет прав администратора.
const WRITE_ERROR_TEXT: &str = "Не удалось записать файл hosts: он защищён от записи \
(атрибут «только для чтения») или у программы нет прав администратора. Снять защиту \
можно кнопкой «Восстановить права доступа» на странице Hosts.";

/// python `_read_hosts_text`: текст hosts или понятная ошибка.
fn read_hosts_text(read: &ReadHostsFn<'_>) -> Result<String, TelegramHostsError> {
    match read() {
        Ok(Some(content)) => Ok(content),
        Ok(None) => Err(TelegramHostsError {
            message: "Не удалось прочитать файл hosts".to_string(),
        }),
        Err(cause) => Err(TelegramHostsError {
            message: format!("Не удалось прочитать файл hosts: {cause}"),
        }),
    }
}

/// python `_write_hosts_text`: запись hosts или понятная ошибка.
fn write_hosts_text(content: &str, write: &WriteHostsFn<'_>) -> Result<(), TelegramHostsError> {
    match write(content) {
        Ok(true) => Ok(()),
        Ok(false) => Err(TelegramHostsError {
            message: WRITE_ERROR_TEXT.to_string(),
        }),
        Err(cause) => Err(TelegramHostsError {
            message: format!("{WRITE_ERROR_TEXT}\n{cause}"),
        }),
    }
}

/// Только читает файл hosts и считает записи Telegram.
/// # Errors
/// Файл hosts не прочитан ([`TelegramHostsError`]).
pub fn get_telegram_hosts_status(
    read: &ReadHostsFn<'_>,
) -> Result<TelegramHostsStatus, TelegramHostsError> {
    Ok(telegram_hosts_status_from_text(&read_hosts_text(read)?))
}

/// Прописывает блок Telegram в hosts. Возвращает `(изменён ли файл, сообщение)`.
/// # Errors
/// Файл hosts не прочитан или не записан ([`TelegramHostsError`]).
pub fn add_telegram_hosts(
    read: &ReadHostsFn<'_>,
    write: &WriteHostsFn<'_>,
    log: &LogFn<'_>,
) -> Result<(bool, String), TelegramHostsError> {
    let content = read_hosts_text(read)?;
    let new_content = add_telegram_hosts_to_text(&content);
    let total = TELEGRAM_DOMAINS.len();
    if new_content == content {
        return Ok((
            false,
            format!("Все {total} записей Telegram уже прописаны в hosts"),
        ));
    }
    write_hosts_text(&new_content, write)?;
    let message = format!("Записи Telegram прописаны в hosts: {total}");
    log(&format!("Telegram hosts: {message}"));
    Ok((true, message))
}

/// Убирает блок Telegram из hosts. Возвращает `(изменён ли файл, сообщение)`.
///
/// Если убирать нечего, файл не записывается.
/// # Errors
/// Файл hosts не прочитан или не записан ([`TelegramHostsError`]).
pub fn remove_telegram_hosts(
    read: &ReadHostsFn<'_>,
    write: &WriteHostsFn<'_>,
    log: &LogFn<'_>,
) -> Result<(bool, String), TelegramHostsError> {
    let content = read_hosts_text(read)?;
    let new_content = remove_telegram_hosts_from_text(&content);
    if new_content == content {
        return Ok((false, "Записей Telegram в hosts нет".to_string()));
    }
    write_hosts_text(&new_content, write)?;
    let message = "Записи Telegram убраны из hosts";
    log(&format!("Telegram hosts: {message}"));
    Ok((true, message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_LINES: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\n\
127.0.0.1 localhost\n\
10.0.0.5 nas.home\n";

    fn block() -> String {
        let mut text = format!("{TELEGRAM_HOSTS_MARKER}\n");
        for domain in TELEGRAM_DOMAINS {
            text.push_str(&format!("{TELEGRAM_RELAY_IP} {domain}\n"));
        }
        text
    }

    #[test]
    fn status_counts_none_partial_and_all() {
        let total = TELEGRAM_DOMAINS.len();

        let none = telegram_hosts_status_from_text(USER_LINES);
        assert_eq!(
            (none.present, none.total, none.block_present),
            (0, total, false)
        );
        assert!(none.is_empty());

        let partial_text =
            format!("{USER_LINES}{TELEGRAM_RELAY_IP} t.me\n{TELEGRAM_RELAY_IP} web.telegram.org\n");
        let partial = telegram_hosts_status_from_text(&partial_text);
        assert_eq!(
            (partial.present, partial.total, partial.block_present),
            (2, total, false)
        );
        assert!(!partial.is_empty());
        assert!(!partial.is_complete());

        let full = telegram_hosts_status_from_text(&add_telegram_hosts_to_text(USER_LINES));
        assert_eq!(
            (full.present, full.total, full.block_present),
            (total, total, true)
        );
        assert!(full.is_complete());
    }

    #[test]
    fn status_ignores_comments_and_other_ip() {
        let text = format!("# {TELEGRAM_RELAY_IP} t.me\n1.2.3.4 web.telegram.org\n");
        assert_eq!(telegram_hosts_status_from_text(&text).present, 0);
    }

    #[test]
    fn status_uses_first_entry_like_windows() {
        let text = format!("1.2.3.4 t.me\n{TELEGRAM_RELAY_IP} t.me\n");
        assert_eq!(telegram_hosts_status_from_text(&text).present, 0);
    }

    #[test]
    fn add_writes_telegram_cdn_and_download_domains() {
        let text = add_telegram_hosts_to_text(USER_LINES);

        assert!(text.starts_with(USER_LINES));
        assert!(text.contains(TELEGRAM_HOSTS_MARKER));
        for domain in [
            "cdn1.telesco.pe",
            "cdn.telesco.pe",
            "cdn4.telesco.pe",
            "cdn6.telesco.pe",
            "oauth.telegram.org",
            "oauth.tg.dev",
            "desktop.telegram.org",
            "macos.telegram.org",
            "web.telegram.org",
            "t.me",
        ] {
            assert!(text.contains(&format!("{TELEGRAM_RELAY_IP} {domain}\n")));
        }
    }

    #[test]
    fn add_is_idempotent() {
        let once = add_telegram_hosts_to_text(USER_LINES);
        let twice = add_telegram_hosts_to_text(&once);

        assert_eq!(once, twice);
        assert_eq!(twice.matches(TELEGRAM_HOSTS_MARKER).count(), 1);
    }

    #[test]
    fn add_replaces_telegram_domain_on_other_ip() {
        let text = add_telegram_hosts_to_text(&format!("{USER_LINES}1.2.3.4 t.me\n"));

        assert!(!text.contains("1.2.3.4 t.me"));
        assert_eq!(
            text.matches(&format!("{TELEGRAM_RELAY_IP} t.me\n")).count(),
            1
        );
    }

    #[test]
    fn remove_keeps_foreign_lines_and_telegram_domain_on_other_ip() {
        let foreign = format!("{USER_LINES}1.2.3.4 t.me\n");
        let text = format!("{foreign}\n{}", block());

        let cleaned = remove_telegram_hosts_from_text(&text);

        assert_eq!(cleaned, foreign);
        assert!(!cleaned.contains(TELEGRAM_HOSTS_MARKER));
        assert_eq!(telegram_hosts_status_from_text(&cleaned).present, 0);
    }

    #[test]
    fn remove_after_add_restores_original() {
        assert_eq!(
            remove_telegram_hosts_from_text(&add_telegram_hosts_to_text(USER_LINES)),
            USER_LINES
        );
    }

    #[test]
    fn remove_without_telegram_entries_returns_same_text() {
        let text = format!("{USER_LINES}\n\n1.2.3.4 t.me\n");
        assert_eq!(remove_telegram_hosts_from_text(&text), text);
    }

    #[test]
    fn remove_accepts_legacy_marker_and_crlf() {
        // Прежняя версия программы писала другой заголовок — блок с ним тоже
        // убирается, а строки с \r\n разбираются.
        let legacy = LEGACY_TELEGRAM_HOSTS_MARKER;
        let text = format!("{USER_LINES}\r\n{legacy}\r\n{TELEGRAM_RELAY_IP} t.me\r\n");
        let cleaned = remove_telegram_hosts_from_text(&text);
        assert!(!cleaned.contains(legacy));
        assert!(!cleaned.contains(&format!("{TELEGRAM_RELAY_IP} t.me")));
        assert!(!telegram_hosts_status_from_text(&cleaned).block_present);
    }

    /// Чтение и запись hosts из замыканий теста.
    struct FakeHosts {
        content: std::cell::RefCell<String>,
        written: std::cell::RefCell<Vec<String>>,
    }

    impl FakeHosts {
        fn new(content: &str) -> Self {
            Self {
                content: std::cell::RefCell::new(content.to_string()),
                written: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn read(&self) -> Result<Option<String>, String> {
            Ok(Some(self.content.borrow().clone()))
        }

        fn write(&self, text: &str) -> Result<bool, String> {
            self.written.borrow_mut().push(text.to_string());
            Ok(true)
        }
    }

    #[test]
    fn status_only_reads() {
        let hosts = FakeHosts::new(USER_LINES);
        let status = get_telegram_hosts_status(&|| hosts.read()).unwrap();
        assert_eq!(status.present, 0);
        assert!(hosts.written.borrow().is_empty());
    }

    #[test]
    fn add_writes_block_and_second_add_does_not_write() {
        let hosts = FakeHosts::new(USER_LINES);
        let log_lines: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let (changed, message) =
            add_telegram_hosts(&|| hosts.read(), &|text| hosts.write(text), &|line| {
                log_lines.lock().unwrap().push(line.to_string())
            })
            .unwrap();
        assert!(changed);
        assert_eq!(hosts.written.borrow().len(), 1);
        assert_eq!(
            message,
            format!(
                "Записи Telegram прописаны в hosts: {}",
                TELEGRAM_DOMAINS.len()
            )
        );
        assert_eq!(log_lines.lock().unwrap().len(), 1);

        *hosts.content.borrow_mut() = hosts.written.borrow()[0].clone();
        let log_lines: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let (changed, _) =
            add_telegram_hosts(&|| hosts.read(), &|text| hosts.write(text), &|line| {
                log_lines.lock().unwrap().push(line.to_string())
            })
            .unwrap();
        assert!(!changed);
        assert_eq!(hosts.written.borrow().len(), 1);
        assert!(log_lines.lock().unwrap().is_empty());
    }

    #[test]
    fn remove_without_changes_does_not_write() {
        let hosts = FakeHosts::new(&format!("{USER_LINES}1.2.3.4 t.me\n"));
        let (changed, _) =
            remove_telegram_hosts(&|| hosts.read(), &|text| hosts.write(text), &|_| {}).unwrap();
        assert!(!changed);
        assert!(hosts.written.borrow().is_empty());
    }

    #[test]
    fn remove_writes_cleaned_text() {
        let hosts = FakeHosts::new(&format!("{USER_LINES}\n{}", block()));
        let (changed, _) =
            remove_telegram_hosts(&|| hosts.read(), &|text| hosts.write(text), &|_| {}).unwrap();
        assert!(changed);
        assert_eq!(hosts.written.borrow().len(), 1);
        assert_eq!(hosts.written.borrow()[0], USER_LINES);
    }

    #[test]
    fn write_failure_raises_readable_error() {
        let hosts = FakeHosts::new(USER_LINES);
        for write_result in [
            Ok::<bool, String>(false),
            Err("PermissionError: read-only".to_string()),
        ] {
            let error = add_telegram_hosts(&|| hosts.read(), &|_| write_result.clone(), &|_| {})
                .unwrap_err();
            assert!(
                error.message.contains("только для чтения"),
                "{}",
                error.message
            );
        }
    }

    #[test]
    fn unreadable_hosts_raises() {
        // python `None` от чтения — файл не прочитан.
        let error = get_telegram_hosts_status(&|| Ok(None)).unwrap_err();
        assert_eq!(error.message, "Не удалось прочитать файл hosts");
        // Исключение чтения — с текстом причины.
        let error =
            get_telegram_hosts_status(&|| Err("PermissionError: denied".to_string())).unwrap_err();
        assert_eq!(
            error.message,
            "Не удалось прочитать файл hosts: PermissionError: denied"
        );
    }
}
