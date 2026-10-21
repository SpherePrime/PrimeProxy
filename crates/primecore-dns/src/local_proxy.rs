//! Порт `src/dns/local_proxy.py` — шифрованный DNS через встроенный
//! dnscrypt-proxy: запуск, остановка, починка.
//!
//! Windows сама не умеет DNSCrypt и ODoH, поэтому при выборе такого режима
//! программа ставит на компьютер службу Windows «ZapretDnsCrypt» с движком
//! dnscrypt-proxy. Движок слушает обычные DNS-запросы на 127.0.0.1 (и ::1) и
//! шифрует их по дороге, а в сетевой адаптер прописывается адрес 127.0.0.1.
//!
//! Почему служба, а не процесс программы: DNS должен работать и после
//! закрытия окна, и после перезагрузки. Упал движок — Windows сама поднимает
//! его снова.
//!
//! Порядок запуска ([`start`]) защищает интернет пользователя: адаптеры
//! получают 127.0.0.1 только после того, как движок реально ответил на
//! DNS-запрос. Не ответил — служба убирается (или возвращается прежний
//! режим), адаптеры не тронуты, причина уходит на страницу.
//!
//! Движок копируется из установки (`exe\dnscrypt-proxy.exe`) в свою папку
//! `user\dnscrypt`. Обновление программы заменяет файлы в `exe\` и снимает
//! все её процессы; копию оно не трогает, и Windows тут же перезапускает
//! службу — интернет не пропадает на время установки. Новую версию движка
//! копия получает при следующем запуске программы ([`repair`]).
//!
//! Режим нигде отдельно не хранится: он записан в первой строке файла
//! настроек движка (`dns.local_proxy_config`), поэтому страница показывает
//! то, что запущено на самом деле.
//!
//! Платформенный слой (python `dns.local_proxy_windows`) — служба Windows,
//! порт 53, ответы движка, права на папку — передаётся в функции как трейт
//! [`LocalProxySystem`]. Файлы в рабочей папке движка (настройки, копия exe,
//! журнал) — обычные файлы по путям из `work_dir()`/`shipped_exe()`, они
//! читаются и пишутся как в python-тестах — во временной папке; сравнение
//! копии движка с оригиналом (python `hashlib.sha256`) сделано прямым
//! сравнением содержимого: результат тот же, а отдельная зависимость не
//! нужна. Журналирование (python `log.log`) остаётся слою фасада: функции
//! возвращают итоги значениями.

use std::path::{Path, PathBuf};

use crate::local_proxy_catalog::{self as catalog, Upstream};
use crate::local_proxy_config::{
    build_config, read_mode, read_server, read_upstreams, LISTEN_IPV4, LISTEN_IPV6,
};

pub const SERVICE_NAME: &str = "ZapretDnsCrypt";
pub const SERVICE_DISPLAY_NAME: &str = "Zapret: шифрованный DNS (dnscrypt-proxy)";
pub const SERVICE_DESCRIPTION: &str = "Шифрует DNS-запросы этого компьютера (DNSCrypt, ODoH). Ставится и убирается в PrimeBypass: «Настройка DNS».";
pub const EXE_NAME: &str = "dnscrypt-proxy.exe";
pub const CONFIG_NAME: &str = "dnscrypt-proxy.toml";
pub const LOG_NAME: &str = "dnscrypt-proxy.log";
/// Адреса, на которых движок слушает DNS-запросы.
pub const LOCAL_ADDRESSES: [&str; 2] = [LISTEN_IPV4, LISTEN_IPV6];
/// Движок сначала опрашивает серверы; на медленной линии это занимает
/// несколько секунд.
pub const START_TIMEOUT_S: f64 = 25.0;
const POLL_S: f64 = 0.5;

/// python `LocalProxyResult` — итог запуска шифрованного DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalProxyResult {
    pub success: bool,
    pub message: String,
    /// Слушает ли движок ещё и ::1 — тогда его можно прописать адаптеру как
    /// IPv6 DNS.
    pub listen_ipv6: bool,
}

/// Платформенный слой (python `dns.local_proxy_windows`): служба Windows,
/// порт 53 и ответы движка. Подставив свою реализацию, вся логика этого
/// модуля проверяется без Windows.
pub trait LocalProxySystem {
    /// Рабочая папка движка (python `user\dnscrypt`).
    fn work_dir(&self) -> PathBuf;
    /// Движок из установки (python `exe\dnscrypt-proxy.exe`).
    fn shipped_exe(&self) -> PathBuf;
    /// python `service_state`: состояние службы; пустая строка — службы нет.
    fn service_state(&self, name: &str) -> String;
    /// python `service_image_path`: команда запуска службы.
    fn service_image_path(&self, name: &str) -> String;
    /// python `create_service` → (создалась?, причина отказа).
    fn create_service(
        &mut self,
        name: &str,
        command: &str,
        display_name: &str,
        description: &str,
    ) -> Result<(), String>;
    /// python `start_service` → (запустилась?, причина отказа).
    fn start_service(&mut self, name: &str) -> Result<(), String>;
    /// python `stop_service`.
    fn stop_service(&mut self, name: &str);
    /// python `delete_service`.
    fn delete_service(&mut self, name: &str);
    /// python `ipv6_loopback_available` — живёт ли ::1 на этом компьютере.
    fn ipv6_loopback_available(&self) -> bool;
    /// python `port_53_free(ipv6=…)` — порт 53 свободен (и для IPv6 тоже).
    fn port_53_free(&self, ipv6: bool) -> bool;
    /// python `check_config` → движок принял настройки? (`Err` — его вывод.)
    fn check_config(&self, exe: &Path, config: &Path) -> Result<(), String>;
    /// python `answers(address)` — движок уже отвечает на DNS-запрос.
    fn answers(&self, address: &str) -> bool;
    /// python `sleep(seconds)`.
    fn sleep(&mut self, seconds: f64);
    /// python `grant_service_access(folder)` — право службы читать папку.
    fn grant_service_access(&mut self, folder: &Path);
}

/// python `_config_path` — файл настроек движка в его рабочей папке.
fn config_path(system: &dyn LocalProxySystem) -> PathBuf {
    system.work_dir().join(CONFIG_NAME)
}

/// python `_read` — текст файла; пусто — файла нет или он не читается.
fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// python `_same_file` — один и тот же файл (размер и содержимое).
fn same_file(first: &Path, second: &Path) -> bool {
    match (std::fs::read(first), std::fs::read(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

/// python `_command` — командная строка службы.
#[must_use]
pub fn command(exe: &Path, config: &Path) -> String {
    format!("\"{}\" -config \"{}\"", exe.display(), config.display())
}

/// python `output[-300:]` — последние `count` символов строки.
fn tail_chars(text: &str, count: usize) -> String {
    let total = text.chars().count();
    if total <= count {
        return text.to_string();
    }
    text.chars().skip(total - count).collect()
}

/// python `_log_tail` — последние строки журнала движка одной строкой.
fn log_tail(system: &dyn LocalProxySystem, count: usize) -> String {
    let text = read(&system.work_dir().join(LOG_NAME));
    let lines: Vec<&str> = text.trim().lines().collect();
    let skip = lines.len().saturating_sub(count);
    lines[skip..].join(" | ")
}

/// python `active_mode` — режим работающего шифрованного DNS или пустая
/// строка.
///
/// Режим есть, только когда есть и служба, и её файл настроек: без службы на
/// 127.0.0.1 никто не отвечает, что бы ни было записано в файле.
#[must_use]
pub fn active_mode(system: &dyn LocalProxySystem) -> String {
    if system.service_state(SERVICE_NAME).is_empty() {
        return String::new();
    }
    read_mode(&read(&config_path(system)))
}

/// python `active_server` — название плитки, чей сервер работает в режиме
/// DoH; у остальных режимов и без службы — пусто.
#[must_use]
pub fn active_server(system: &dyn LocalProxySystem) -> String {
    if system.service_state(SERVICE_NAME).is_empty() {
        return String::new();
    }
    read_server(&read(&config_path(system)))
}

/// python `uses_local_proxy` — есть ли среди адресов DNS адаптеров адрес
/// встроенного движка.
#[must_use]
pub fn uses_local_proxy<'a, I>(addresses: I) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    addresses
        .into_iter()
        .any(|item| LOCAL_ADDRESSES.contains(&item.trim()))
}

/// python `_wait_answer` — ждёт ответа движка до [`START_TIMEOUT_S`].
fn wait_answer(system: &mut dyn LocalProxySystem) -> bool {
    let mut waited = 0.0;
    while waited < START_TIMEOUT_S {
        if system.answers(LISTEN_IPV4) {
            return true;
        }
        system.sleep(POLL_S);
        waited += POLL_S;
    }
    false
}

/// python `_remove_service` — убирает службу, если она была.
fn remove_service(system: &mut dyn LocalProxySystem) {
    if !system.service_state(SERVICE_NAME).is_empty() {
        system.stop_service(SERVICE_NAME);
        system.delete_service(SERVICE_NAME);
    }
}

/// python `_ensure_service` — служба с нужной командой запуска; чужая или
/// устаревшая запись пересоздаётся.
fn ensure_service(
    system: &mut dyn LocalProxySystem,
    exe: &Path,
    config: &Path,
) -> Result<(), String> {
    let command = command(exe, config);
    if !system.service_state(SERVICE_NAME).is_empty() {
        if system
            .service_image_path(SERVICE_NAME)
            .trim()
            .to_lowercase()
            == command.to_lowercase()
        {
            return Ok(());
        }
        system.stop_service(SERVICE_NAME);
        system.delete_service(SERVICE_NAME);
    }
    system.create_service(
        SERVICE_NAME,
        &command,
        SERVICE_DISPLAY_NAME,
        SERVICE_DESCRIPTION,
    )
}

/// python `_roll_back` — запуск не удался: вернуть прежний режим, а если его
/// не было — убрать службу.
fn roll_back(system: &mut dyn LocalProxySystem, exe: &Path, config: &Path, previous_config: &str) {
    if previous_config.is_empty() {
        remove_service(system);
        let _ = std::fs::remove_file(config);
        return;
    }
    if std::fs::write(config, previous_config).is_err() {
        // python пишет в журнал и оставляет компьютер как есть: служба уже
        // остановлена, но настройки прежнего режима целы в движке.
        return;
    }
    if ensure_service(system, exe, config).is_ok() {
        let _ = system.start_service(SERVICE_NAME);
    }
}

/// python `start` — запускает шифрованный DNS в режиме `mode` и ждёт, пока
/// он ответит на запрос.
///
/// Режиму DoH нужны серверы плитки (`upstreams`) и её название
/// (`server_name`).
pub fn start(
    mode: &str,
    upstreams: &[Upstream],
    server_name: &str,
    system: &mut dyn LocalProxySystem,
) -> LocalProxyResult {
    let fail = |message: &str| LocalProxyResult {
        success: false,
        message: message.to_string(),
        listen_ipv6: false,
    };
    if !catalog::MODES.contains(&mode) {
        return fail(&format!("Неизвестный режим шифрованного DNS: {mode}"));
    }
    if mode == catalog::MODE_DOH && upstreams.is_empty() {
        return fail(
            "У сервера нет шифрованного адреса (DoH) или адреса IPv4: через посредника его не поставить.",
        );
    }
    let shipped = system.shipped_exe();
    if !shipped.is_file() {
        return fail(
            "В установке нет файла exe\\dnscrypt-proxy.exe. Переустановите программу или обновите её.",
        );
    }
    let work = system.work_dir();
    let exe = work.join(EXE_NAME);
    let config = work.join(CONFIG_NAME);
    let had_service = !system.service_state(SERVICE_NAME).is_empty();
    let previous_config = if had_service {
        read(&config)
    } else {
        String::new()
    };

    // Свою службу останавливаем до проверки порта: иначе порт занят ею самой.
    if had_service {
        system.stop_service(SERVICE_NAME);
    }
    let listen_ipv6 = system.ipv6_loopback_available();
    if !system.port_53_free(listen_ipv6) {
        roll_back(system, &exe, &config, &previous_config);
        return fail(
            "Порт 53 на этом компьютере занят другой программой. Обычно это служба Windows \
             «Общий доступ к подключению к Интернету» (раздача интернета, Hyper-V, WSL) \
             или другой DNS-посредник. Закройте её и выберите шифрованный DNS снова.",
        );
    }

    let prepared = (|| -> Result<(), String> {
        std::fs::create_dir_all(&work).map_err(|error| error.to_string())?;
        if !same_file(&shipped, &exe) {
            std::fs::copy(&shipped, &exe).map_err(|error| error.to_string())?;
        }
        std::fs::write(
            &config,
            build_config(
                mode,
                &work.join(LOG_NAME).display().to_string(),
                listen_ipv6,
                upstreams,
                server_name,
            ),
        )
        .map_err(|error| error.to_string())?;
        system.grant_service_access(&work);
        Ok(())
    })();
    if let Err(error) = prepared {
        roll_back(system, &exe, &config, &previous_config);
        return fail(&format!(
            "Не удалось подготовить папку шифрованного DNS: {error}"
        ));
    }

    if let Err(output) = system.check_config(&exe, &config) {
        roll_back(system, &exe, &config, &previous_config);
        return fail(&format!(
            "dnscrypt-proxy не принял настройки: {}",
            tail_chars(&output, 300)
        ));
    }
    if let Err(error) = ensure_service(system, &exe, &config) {
        roll_back(system, &exe, &config, &previous_config);
        return fail(&format!(
            "Не удалось создать службу Windows {SERVICE_NAME}: {error}"
        ));
    }
    if let Err(reason) = system.start_service(SERVICE_NAME) {
        roll_back(system, &exe, &config, &previous_config);
        return fail(&format!(
            "Служба Windows {SERVICE_NAME} не запустилась: {reason}"
        ));
    }
    if !wait_answer(system) {
        let tail = log_tail(system, 3);
        roll_back(system, &exe, &config, &previous_config);
        let mut message = "Шифрованный DNS не ответил: серверы этого режима недоступны на вашей \
             линии. DNS на адаптерах не менялся."
            .to_string();
        if !tail.is_empty() {
            message.push_str(&format!(" Последние строки журнала: {tail}"));
        }
        return fail(&message);
    }
    LocalProxyResult {
        success: true,
        message: String::new(),
        listen_ipv6,
    }
}

/// python `stop` — убирает службу шифрованного DNS и её файл настроек.
pub fn stop(system: &mut dyn LocalProxySystem) {
    let had_service = !system.service_state(SERVICE_NAME).is_empty();
    remove_service(system);
    let _ = std::fs::remove_file(config_path(system));
    // python при былой службе пишет в журнал «шифрованный DNS остановлен»;
    // журналирование остаётся слою фасада.
    let _ = had_service;
}

/// python `stop_if_unused` — останавливает движок, если ни один адаптер
/// больше не смотрит на 127.0.0.1.
pub fn stop_if_unused<'a, I>(adapter_addresses: I, system: &mut dyn LocalProxySystem) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    if uses_local_proxy(adapter_addresses) || system.service_state(SERVICE_NAME).is_empty() {
        return false;
    }
    stop(system);
    true
}

/// python `repair` — проверка при запуске программы: что сделано — строкой
/// для журнала, иначе пусто.
///
/// - адаптеры смотрят на 127.0.0.1, режим известен, а служба не работает или
///   движок в ней старый — служба поднимается заново;
/// - служба есть, а ни один адаптер ею не пользуется — она убирается.
pub fn repair<'a, I>(adapter_addresses: I, system: &mut dyn LocalProxySystem) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let state = system.service_state(SERVICE_NAME);
    let work = system.work_dir();
    let exe = work.join(EXE_NAME);
    let config = work.join(CONFIG_NAME);
    let config_text = read(&config);
    let mode = read_mode(&config_text);
    if !uses_local_proxy(adapter_addresses) {
        if !state.is_empty() {
            stop(system);
            return "шифрованный DNS не используется ни одним адаптером — служба убрана"
                .to_string();
        }
        return String::new();
    }
    if mode.is_empty() {
        return String::new();
    }
    let shipped = system.shipped_exe();
    let outdated = shipped.is_file() && !same_file(&shipped, &exe);
    let wrong_command = !state.is_empty()
        && system
            .service_image_path(SERVICE_NAME)
            .trim()
            .to_lowercase()
            != command(&exe, &config).to_lowercase();
    if state == "running" && !outdated && !wrong_command {
        return String::new();
    }
    // Режим DoH поднимается с теми же серверами, что записаны в файле настроек.
    let result = start(
        &mode,
        &read_upstreams(&config_text),
        &read_server(&config_text),
        system,
    );
    if result.success {
        return format!("шифрованный DNS ({mode}) поднят заново");
    }
    format!(
        "шифрованный DNS ({mode}) не удалось поднять: {}",
        result.message
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// python `FakeSystem` — Windows для тестов: служба, порт 53 и ответы
    /// движка — в памяти; файлы рабочей папки — настоящие (временная папка).
    struct FakeSystem {
        root: PathBuf,
        exe: PathBuf,
        state: String,
        image_path: String,
        port_free: bool,
        ipv6: bool,
        config_ok: bool,
        create_ok: bool,
        start_ok: bool,
        granted: Option<PathBuf>,
        answers_after_start: VecDeque<bool>,
        answering: bool,
        calls: RefCell<Vec<String>>,
        slept: f64,
    }

    impl FakeSystem {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "primecore-dns-local-proxy-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let exe_dir = root.join("exe");
            std::fs::create_dir_all(&exe_dir).expect("папка установки создана");
            let exe = exe_dir.join("dnscrypt-proxy.exe");
            std::fs::write(&exe, b"engine v1").expect("движок записан");
            Self {
                exe,
                state: String::new(),
                image_path: String::new(),
                port_free: true,
                ipv6: true,
                config_ok: true,
                create_ok: true,
                start_ok: true,
                granted: None,
                answers_after_start: VecDeque::from(vec![true]),
                answering: false,
                calls: RefCell::new(Vec::new()),
                slept: 0.0,
                root,
            }
        }

        fn config(&self) -> PathBuf {
            self.work_dir().join("dnscrypt-proxy.toml")
        }

        fn work_exe(&self) -> PathBuf {
            self.work_dir().join("dnscrypt-proxy.exe")
        }
    }

    impl Drop for FakeSystem {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl LocalProxySystem for FakeSystem {
        fn work_dir(&self) -> PathBuf {
            self.root.join("user").join("dnscrypt")
        }

        fn shipped_exe(&self) -> PathBuf {
            self.exe.clone()
        }

        fn service_state(&self, _name: &str) -> String {
            self.state.clone()
        }

        fn service_image_path(&self, _name: &str) -> String {
            self.image_path.clone()
        }

        fn create_service(
            &mut self,
            _name: &str,
            command: &str,
            _display_name: &str,
            _description: &str,
        ) -> Result<(), String> {
            self.calls.borrow_mut().push("create".to_string());
            if !self.create_ok {
                return Err("Отказано в доступе".to_string());
            }
            self.state = "stopped".to_string();
            self.image_path = command.to_string();
            Ok(())
        }

        fn start_service(&mut self, _name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push("start".to_string());
            if !self.start_ok {
                return Err("Отказано в доступе.".to_string());
            }
            self.state = "running".to_string();
            self.answering = self.answers_after_start.pop_front().unwrap_or(true);
            Ok(())
        }

        fn grant_service_access(&mut self, folder: &Path) {
            self.granted = Some(folder.to_path_buf());
        }

        fn stop_service(&mut self, _name: &str) {
            self.calls.borrow_mut().push("stop".to_string());
            self.state = "stopped".to_string();
            self.answering = false;
        }

        fn delete_service(&mut self, _name: &str) {
            self.calls.borrow_mut().push("delete".to_string());
            self.state = String::new();
            self.image_path = String::new();
        }

        fn ipv6_loopback_available(&self) -> bool {
            self.ipv6
        }

        fn port_53_free(&self, _ipv6: bool) -> bool {
            self.port_free && self.state != "running"
        }

        fn check_config(&self, _exe: &Path, _config: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push("check".to_string());
            if self.config_ok {
                Ok(())
            } else {
                Err("bad stamp".to_string())
            }
        }

        fn answers(&self, _address: &str) -> bool {
            self.answering
        }

        fn sleep(&mut self, seconds: f64) {
            self.slept += seconds;
        }
    }

    fn doh_upstream() -> Vec<Upstream> {
        catalog::doh_upstreams(
            "https://dns.zapret.moe/dns-query",
            &["83.217.211.149".to_string()],
            false,
        )
    }

    #[test]
    fn start_copies_engine_creates_service_and_waits_for_an_answer() {
        let mut system = FakeSystem::new();

        let result = start("dnscrypt", &[], "", &mut system);

        assert!(result.success);
        assert!(result.listen_ipv6);
        assert_eq!(
            *system.calls.borrow(),
            vec![
                "check".to_string(),
                "create".to_string(),
                "start".to_string()
            ]
        );
        assert_eq!(
            std::fs::read(system.work_exe()).expect("движок скопирован"),
            b"engine v1"
        );
        assert_eq!(
            system.image_path,
            format!(
                "\"{}\" -config \"{}\"",
                system.work_exe().display(),
                system.config().display()
            )
        );
        assert_eq!(active_mode(&system), "dnscrypt");
        assert_eq!(system.granted, Some(system.work_dir()));
    }

    #[test]
    fn service_that_windows_refuses_to_start_reports_the_reason() {
        let mut system = FakeSystem::new();
        system.start_ok = false;

        let result = start("dnscrypt", &[], "", &mut system);

        assert!(!result.success);
        assert!(result
            .message
            .contains("не запустилась: Отказано в доступе."));
        assert_eq!(system.state, "");
        assert_eq!(system.slept, 0.0);
    }

    #[test]
    fn no_ipv6_loopback_means_no_ipv6_listener() {
        let mut system = FakeSystem::new();
        system.ipv6 = false;

        let result = start("odoh", &[], "", &mut system);

        assert!(result.success);
        assert!(!result.listen_ipv6);
        let config = std::fs::read_to_string(system.config()).expect("настройки записаны");
        assert!(!config.contains("[::1]"));
    }

    #[test]
    fn busy_port_53_stops_before_anything_is_installed() {
        let mut system = FakeSystem::new();
        system.port_free = false;

        let result = start("dnscrypt", &[], "", &mut system);

        assert!(!result.success);
        assert!(result.message.contains("Порт 53"));
        assert!(system.calls.borrow().is_empty());
        assert!(!system.config().exists());
    }

    #[test]
    fn engine_that_never_answers_is_removed_again() {
        let mut system = FakeSystem::new();
        system.answers_after_start = VecDeque::from(vec![false]);

        let result = start("anonymized", &[], "", &mut system);

        assert!(!result.success);
        assert!(result.message.contains("DNS на адаптерах не менялся"));
        assert_eq!(system.state, "");
        assert!(!system.config().exists());
        assert!(system.slept >= START_TIMEOUT_S);
        assert_eq!(active_mode(&system), "");
    }

    #[test]
    fn failed_switch_brings_the_previous_mode_back() {
        let mut system = FakeSystem::new();
        assert!(start("dnscrypt", &[], "", &mut system).success);
        system.answers_after_start = VecDeque::from(vec![false, true]);

        let result = start("odoh", &[], "", &mut system);

        assert!(!result.success);
        // Интернет пользователя уже шёл через движок: прежний режим снова работает.
        assert_eq!(system.state, "running");
        assert_eq!(active_mode(&system), "dnscrypt");
        assert!(system.answers("127.0.0.1"));
    }

    #[test]
    fn rejected_config_and_refused_service_are_reported() {
        let mut system = FakeSystem::new();
        system.config_ok = false;
        let result = start("dnscrypt", &[], "", &mut system);
        assert!(!result.success);
        assert!(result.message.contains("не принял настройки"));
        assert_eq!(system.state, "");

        system.config_ok = true;
        system.create_ok = false;
        let result = start("dnscrypt", &[], "", &mut system);
        assert!(!result.success);
        assert!(result.message.contains("Отказано в доступе"));
    }

    #[test]
    fn missing_engine_and_unknown_mode_are_refused() {
        let mut system = FakeSystem::new();
        assert!(!start("doh", &[], "", &mut system).success);
        std::fs::remove_file(&system.exe).expect("движок убран");

        let result = start("dnscrypt", &[], "", &mut system);

        assert!(!result.success);
        assert!(result.message.contains("dnscrypt-proxy.exe"));
    }

    #[test]
    fn switching_mode_reuses_the_service() {
        let mut system = FakeSystem::new();
        start("dnscrypt", &[], "", &mut system);
        system.calls.borrow_mut().clear();

        assert!(start("anonymized", &[], "", &mut system).success);

        assert_eq!(
            *system.calls.borrow(),
            vec!["stop".to_string(), "check".to_string(), "start".to_string()]
        );
        assert_eq!(active_mode(&system), "anonymized");
    }

    #[test]
    fn doh_mode_needs_the_servers_of_a_tile_and_remembers_its_name() {
        let mut system = FakeSystem::new();
        assert!(!start("doh", &[], "", &mut system).success);
        assert_eq!(system.service_state(SERVICE_NAME), "");

        let result = start("doh", &doh_upstream(), "Zapret DNS", &mut system);

        assert!(result.success, "{}", result.message);
        assert_eq!(active_mode(&system), "doh");
        assert_eq!(active_server(&system), "Zapret DNS");
    }

    #[test]
    fn repair_restarts_doh_mode_with_the_same_servers() {
        let mut system = FakeSystem::new();
        let servers = doh_upstream();
        start("doh", &servers, "Zapret DNS", &mut system);
        system.stop_service(SERVICE_NAME);

        let summary = repair(["127.0.0.1"], &mut system);

        assert!(summary.contains("поднят заново"));
        assert_eq!(active_server(&system), "Zapret DNS");
        let config = std::fs::read_to_string(system.config()).expect("настройки записаны");
        assert!(config.contains(&servers[0].stamp));
    }

    #[test]
    fn stop_if_unused_keeps_engine_while_an_adapter_points_at_it() {
        let mut system = FakeSystem::new();
        start("dnscrypt", &[], "", &mut system);

        assert!(!stop_if_unused(["9.9.9.9", "::1"], &mut system));
        assert_eq!(system.state, "running");

        assert!(stop_if_unused(["9.9.9.9"], &mut system));
        assert_eq!(system.state, "");
        assert!(!system.config().exists());
        assert!(!stop_if_unused([], &mut system));
    }

    #[test]
    fn repair_restarts_a_stopped_engine_and_updates_an_old_one() {
        let mut system = FakeSystem::new();
        start("dnscrypt", &[], "", &mut system);
        assert_eq!(repair(["127.0.0.1"], &mut system), "");

        system.stop_service(SERVICE_NAME);
        assert!(repair(["127.0.0.1"], &mut system).contains("поднят заново"));
        assert_eq!(system.state, "running");

        // Программа обновилась и принесла новый движок.
        std::fs::write(&system.exe, b"engine v2!").expect("новый движок записан");
        assert!(repair(["127.0.0.1"], &mut system).contains("поднят заново"));
        assert_eq!(
            std::fs::read(system.work_exe()).expect("движок обновлён"),
            b"engine v2!"
        );
    }

    #[test]
    fn repair_removes_a_service_nobody_uses_and_ignores_foreign_local_dns() {
        let mut system = FakeSystem::new();
        start("dnscrypt", &[], "", &mut system);
        assert!(repair(["8.8.8.8"], &mut system).contains("служба убрана"));
        assert_eq!(system.state, "");

        // 127.0.0.1 на адаптере без наших настроек — чужой локальный DNS: не трогаем.
        system.calls.borrow_mut().clear();
        assert_eq!(repair(["127.0.0.1"], &mut system), "");
        assert!(system.calls.borrow().is_empty());
    }

    #[test]
    fn uses_local_proxy_recognizes_engine_addresses() {
        assert!(uses_local_proxy(["9.9.9.9", " 127.0.0.1 "]));
        assert!(uses_local_proxy(["::1"]));
        assert!(!uses_local_proxy(["9.9.9.9", "8.8.8.8"]));
        assert!(!uses_local_proxy(Vec::<&str>::new()));
    }

    #[test]
    fn command_quotes_both_paths() {
        let text = command(Path::new("C:/x/exe"), Path::new("C:/x/dnscrypt-proxy.toml"));
        assert_eq!(text, "\"C:/x/exe\" -config \"C:/x/dnscrypt-proxy.toml\"");
    }
}
