//! Runtime-слой: планы, команды и фоновые воркеры.
//!
//! Порт чистой части `telegram_proxy/runtime/`:
//!
//! * `plans.py` — структуры решений для страницы диагностики и итогов
//!   действий ([`TelegramProxyDiagnosticsStartPlan`], [`TelegramProxyActionResult`],
//!   [`TelegramHostsActionResult`]);
//! * `commands.py` — команды страницы: сборка конфига запуска из хранилища,
//!   буфер обмена, файл hosts, открытие лога и ссылок, диспетчер сохранения
//!   настроек;
//! * `workers.py` — решения QThread-воркеров: какой результат к какому
//!   сигналу относится. Сами QThread не переносятся: фон остаётся у
//!   вызывающего кода, а здесь — функции, возвращающие «события»
//!   (варианты, соответствующие сигналам python-воркеров).
//!
//! Команды, требующие сети или программ платформы (`run_diagnostics` с
//! реальными пробами, `webbrowser`, `subprocess`), оформлены замыканиями:
//! чистые решения — тексты и порядок действий, сетевые действия — у
//! вызывающего кода.

use serde_json::{Map, Value};

use crate::config::settings::{
    build_cloudflare_config, build_dc_endpoint_overrides, build_upstream_config,
    ensure_mtproxy_secret_for_mode, normalize_buffer_kb, normalize_pool_size, normalize_proxy_mode,
    set_auto_deeplink, set_buffer_kb, set_cloudflare_domains, set_dc_ip, set_fake_tls_domain,
    set_host, set_manual_upstream, set_mtproxy_secret, set_pool_size, set_port, set_proxy_enabled,
    set_proxy_mode, set_proxy_protocol, set_upstream_enabled, set_upstream_mode,
    set_upstream_preset, set_upstream_udp_enabled, TelegramSettingsReader, TelegramSettingsWriter,
    TelegramSettingsWriterReader, DEFAULT_HOST, DEFAULT_PORT,
};
use crate::config::upstream_catalog::UpstreamPresetResolver;
use crate::manager::ProxyStartParams;
use crate::proxy::cloudflare::{
    build_cfproxy_dns_records_text, build_cfworker_code, CloudflareCheckResult,
};
use crate::proxy::fake_tls::{build_fake_tls_nginx_config, normalize_fake_tls_domain};
use crate::proxy::routing::{RelayReachability, UpstreamProxyConfig};
use crate::proxy_logger::ProxyLogger;
use crate::telegram_hosts::{
    add_telegram_hosts, get_telegram_hosts_status, remove_telegram_hosts, LogFn, ReadHostsFn,
    TelegramHostsStatus, WriteHostsFn,
};

/// План запуска диагностики (python `TelegramProxyDiagnosticsStartPlan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramProxyDiagnosticsStartPlan {
    /// Кнопка диагностики отключена на время проверки.
    pub button_enabled: bool,
    /// Текст кнопки во время проверки.
    pub button_text: String,
    /// Начальный текст области результатов.
    pub initial_text: String,
    /// Интервал опроса результатов, мс.
    pub poll_interval_ms: i64,
}

/// План одного опроса диагностики (python `TelegramProxyDiagnosticsPollPlan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramProxyDiagnosticsPollPlan {
    /// Новый текст области результатов, если воркер что-то вернул.
    pub updated_text: Option<String>,
    /// Остановить таймер опроса.
    pub should_stop_timer: bool,
    /// Завершить диагностику (воркер закончил работу).
    pub should_finish: bool,
}

/// План завершения диагностики (python `TelegramProxyDiagnosticsFinishPlan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramProxyDiagnosticsFinishPlan {
    /// Кнопка диагностики снова доступна.
    pub button_enabled: bool,
    /// Обычный текст кнопки.
    pub button_text: String,
}

/// Итог действия для пользователя (python `TelegramProxyActionResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramProxyActionResult {
    /// Действие удалось.
    pub ok: bool,
    /// Строка для журнала Telegram Proxy.
    pub log_line: String,
    /// Заголовок уведомления.
    pub info_title: String,
    /// Текст уведомления.
    pub info_content: String,
}

impl TelegramProxyActionResult {
    /// Успешное действие с уведомлением и строкой журнала.
    #[must_use]
    pub fn success(log_line: &str, info_title: &str, info_content: &str) -> Self {
        Self {
            ok: true,
            log_line: log_line.to_string(),
            info_title: info_title.to_string(),
            info_content: info_content.to_string(),
        }
    }

    /// Неудачное действие: python возвращает четыре пустые строки.
    #[must_use]
    pub fn failure() -> Self {
        Self {
            ok: false,
            log_line: String::new(),
            info_title: String::new(),
            info_content: String::new(),
        }
    }

    /// Неудачное действие с сообщением об ошибке в строке журнала.
    #[must_use]
    pub fn failure_with(log_line: &str) -> Self {
        Self {
            ok: false,
            log_line: log_line.to_string(),
            info_title: String::new(),
            info_content: String::new(),
        }
    }
}

/// Действия с записями Telegram в hosts (python `TELEGRAM_HOSTS_ACTIONS`).
pub const TELEGRAM_HOSTS_ACTIONS: [&str; 3] = ["status", "add", "remove"];

/// Итог действия с записями Telegram в hosts
/// (python `TelegramHostsActionResult`).
///
/// `status` — состояние файла после действия (`None`, если его не удалось
/// прочитать). `message` — текст успеха или ошибки для пользователя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramHostsActionResult {
    /// Какое действие выполнялось (`status`, `add` или `remove`).
    pub action: String,
    /// Действие удалось.
    pub ok: bool,
    /// Файл hosts был изменён.
    pub changed: bool,
    /// Текст успеха или ошибки для пользователя.
    pub message: String,
    /// Состояние записей Telegram в файле hosts после действия.
    pub status: Option<TelegramHostsStatus>,
}

/// python `build_diagnostics_start_plan`: кнопка отключена, «Тестирование...».
#[must_use]
pub fn build_diagnostics_start_plan() -> TelegramProxyDiagnosticsStartPlan {
    TelegramProxyDiagnosticsStartPlan {
        button_enabled: false,
        button_text: "Тестирование...".to_string(),
        initial_text: "Запуск диагностики Telegram DC...\n".to_string(),
        poll_interval_ms: 200,
    }
}

/// python `build_diagnostics_poll_plan`: текст обновляется, если воркер его
/// вернул; остановка таймера и завершение — только когда воркер закончил.
#[must_use]
pub fn build_diagnostics_poll_plan(
    result_text: Option<&str>,
    thread_done: bool,
) -> TelegramProxyDiagnosticsPollPlan {
    TelegramProxyDiagnosticsPollPlan {
        updated_text: result_text.map(str::to_string),
        should_stop_timer: thread_done,
        should_finish: thread_done,
    }
}

/// python `build_diagnostics_finish_plan`: кнопка снова «Запустить диагностику».
#[must_use]
pub fn build_diagnostics_finish_plan() -> TelegramProxyDiagnosticsFinishPlan {
    TelegramProxyDiagnosticsFinishPlan {
        button_enabled: true,
        button_text: "Запустить диагностику".to_string(),
    }
}

/// Действия применения настроек из `runtime/settings_save_flow.py` уже
/// перенесены в [`crate::config::settings`]; здесь они доступны под теми же
/// именами, что и в python-модуле `runtime`.
pub use crate::config::settings::{merge_restart_request, normalize_restart_request};

/// Параметры запуска прокси (python `TelegramProxyStartConfig`).
pub use crate::manager::ProxyStartParams as TelegramProxyStartConfig;

/// Чтение значений Telegram Proxy из хранилища настроек
/// (python `settings.store.get_tg_proxy_*`).
///
/// Хранилище — платформа: реализация остаётся у вызывающего кода, крейт
/// работает с уже прочитанными значениями. Значения «по умолчанию» (`or` в
/// python) применяются в командах, а не в хранилище.
pub trait TelegramProxyStoreReader: TelegramSettingsReader {
    /// python `get_tg_proxy_enabled`.
    fn get_tg_proxy_enabled(&self) -> bool;
    /// python `get_tg_proxy_host` — без значения даёт пустую строку.
    fn get_tg_proxy_host(&self) -> String;
    /// python `get_tg_proxy_port` — без значения даёт `0`.
    fn get_tg_proxy_port(&self) -> i64;
    /// python `get_tg_proxy_mode` — исходное значение (может быть любым).
    fn get_tg_proxy_mode(&self) -> Value;
    /// python `get_tg_proxy_mtproxy_secret`.
    fn get_tg_proxy_mtproxy_secret(&self) -> String;
    /// python `get_tg_proxy_pool_size` — исходное значение.
    fn get_tg_proxy_pool_size(&self) -> Value;
    /// python `get_tg_proxy_buffer_kb` — исходное значение.
    fn get_tg_proxy_buffer_kb(&self) -> Value;
    /// python `get_tg_proxy_fake_tls_domain`.
    fn get_tg_proxy_fake_tls_domain(&self) -> String;
    /// python `get_tg_proxy_proxy_protocol`.
    fn get_tg_proxy_proxy_protocol(&self) -> bool;
}

/// Читатель и писатель значений Telegram Proxy в одном
/// (`get_start_config` генерирует и сохраняет секрет MTProxy).
pub trait TelegramProxyStore: TelegramProxyStoreReader + TelegramSettingsWriterReader {}

impl<T: TelegramProxyStoreReader + TelegramSettingsWriterReader> TelegramProxyStore for T {}

/// python `commands.get_start_config`: настройки запуска из хранилища.
///
/// Страница и трей не передают значения полей: всё, что уйдёт в прокси,
/// берётся из хранилища в момент запуска. Секрет MTProxy в режиме MTProxy
/// генерируется и сохраняется, если его ещё нет.
#[must_use]
pub fn get_start_config(
    store: &mut dyn TelegramProxyStore,
    resolver: &UpstreamPresetResolver,
) -> TelegramProxyStartConfig {
    let mode_value = store.get_tg_proxy_mode();
    let mode = normalize_proxy_mode(&mode_value);
    let mtproxy_secret =
        ensure_mtproxy_secret_for_mode(&mode_value, &store.get_tg_proxy_mtproxy_secret(), store);
    let host = store.get_tg_proxy_host();
    let port = store.get_tg_proxy_port();
    TelegramProxyStartConfig {
        host: if host.is_empty() {
            DEFAULT_HOST.to_string()
        } else {
            host
        },
        port: if port == 0 { DEFAULT_PORT } else { port },
        mode,
        upstream_config: build_upstream_config(store, resolver),
        cloudflare_config: Some(build_cloudflare_config(store)),
        mtproxy_secret,
        dc_endpoint_overrides: build_dc_endpoint_overrides(store),
        pool_size: normalize_pool_size(&store.get_tg_proxy_pool_size()),
        buffer_kb: normalize_buffer_kb(&store.get_tg_proxy_buffer_kb()),
        fake_tls_domain: normalize_fake_tls_domain(&store.get_tg_proxy_fake_tls_domain()),
        proxy_protocol: store.get_tg_proxy_proxy_protocol(),
    }
}

/// Писатель в системный буфер обмена (платформа — у вызывающего кода).
pub type ClipboardWriter<'a> = dyn Fn(&str) -> Result<(), String> + 'a;

/// python `commands.copy_text`: запись текста в буфер обмена.
///
/// Пустой текст и отсутствие писателя — неудача без уведомления, как python.
pub fn copy_text(
    text: &str,
    clipboard_writer: Option<&ClipboardWriter<'_>>,
    success_title: &str,
    success_content: &str,
    success_log: &str,
) -> TelegramProxyActionResult {
    if text.is_empty() {
        return TelegramProxyActionResult::failure();
    }
    let Some(writer) = clipboard_writer else {
        return TelegramProxyActionResult::failure();
    };
    match writer(text) {
        Ok(()) => TelegramProxyActionResult::success(success_log, success_title, success_content),
        Err(_) => TelegramProxyActionResult::failure(),
    }
}

/// python `commands.run_telegram_hosts_action`: действие с записями Telegram
/// в hosts и перечитывание состояния.
///
/// `status` только читает файл. `add` и `remove` меняют его и вызываются
/// лишь по кнопке пользователя.
pub fn run_telegram_hosts_action(
    action: &str,
    read: &ReadHostsFn<'_>,
    write: &WriteHostsFn<'_>,
    log: &LogFn<'_>,
) -> TelegramHostsActionResult {
    let action = action.trim();
    if !TELEGRAM_HOSTS_ACTIONS.contains(&action) {
        return TelegramHostsActionResult {
            action: action.to_string(),
            ok: false,
            changed: false,
            message: format!("Неизвестное действие с hosts: {action}"),
            status: None,
        };
    }

    let mut changed = false;
    let mut message = String::new();
    let mut ok = true;
    let change_result = match action {
        "add" => Some(add_telegram_hosts(read, write, log)),
        "remove" => Some(remove_telegram_hosts(read, write, log)),
        _ => None,
    };
    if let Some(result) = change_result {
        match result {
            Ok((file_changed, text)) => {
                changed = file_changed;
                message = text;
            }
            Err(error) => {
                ok = false;
                message = python_error_text(&error.message, "Не удалось изменить файл hosts");
            }
        }
    }

    let mut status = None;
    match get_telegram_hosts_status(read) {
        Ok(found) => status = Some(found),
        Err(error) => {
            if ok {
                ok = false;
                message = python_error_text(&error.message, "Не удалось прочитать файл hosts");
            }
        }
    }

    TelegramHostsActionResult {
        action: action.to_string(),
        ok,
        changed,
        message,
        status,
    }
}

/// python `str(exc) or fallback`: пустой текст исключения заменяется запасным.
#[must_use]
fn python_error_text(message: &str, fallback: &str) -> String {
    if message.is_empty() {
        fallback.to_string()
    } else {
        message.to_string()
    }
}

/// python `commands.set_enabled`: включение или выключение прокси в хранилище.
pub fn set_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    set_proxy_enabled(enabled, store);
}

/// python `commands.append_log_line`: строка в журнал Telegram Proxy.
pub fn append_log_line(message: &str, logger: &ProxyLogger) {
    logger.log(message);
}

/// python `commands.consume_auto_deeplink_request` — переносится без изменений
/// из [`crate::config::settings`].
pub use crate::config::settings::consume_auto_deeplink_request;

/// Нормализация пути к файлу лога (python `os.path.normpath`).
///
/// В python путь всегда Windows: разделители приводятся к `\`, повторные
/// разделители схлопываются, компоненты `.` убираются, `..` разрешается
/// лексически. Пустая строка даёт `.`.
#[must_use]
pub fn normalize_log_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let text = path.replace('/', "\\");
    if let Some((prefix, rest)) = split_path_prefix(&text) {
        if rest.starts_with('\\') {
            return format!("{prefix}\\{}", join_path_components(rest));
        }
        return format!("{prefix}{}", join_path_components(rest));
    }
    let absolute = text.starts_with('\\');
    let joined = join_path_components(&text);
    if joined.is_empty() {
        if absolute {
            "\\".to_string()
        } else {
            ".".to_string()
        }
    } else if absolute {
        format!("\\{joined}")
    } else {
        joined
    }
}

/// Собирает компоненты пути: схлопывает разделители, убирает `.`, лексически
/// разрешает `..` (выход выше корня отбрасывается).
#[must_use]
fn join_path_components(text: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in text.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("\\")
}

/// Отделяет префикс пути (`C:` или UNC `\\server\share`) от остального.
#[must_use]
fn split_path_prefix(text: &str) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        let (prefix, rest) = text.split_at(2);
        return Some((prefix.to_string(), rest));
    }
    if !text.starts_with("\\\\") {
        return None;
    }
    let body = &text[2..];
    let server_end = body.find('\\')?;
    let after_server = &body[server_end + 1..];
    let share_end = after_server.find('\\').unwrap_or(after_server.len());
    let prefix_end = 2 + server_end + 1 + share_end;
    Some((text[..prefix_end].to_string(), &text[prefix_end..]))
}

/// python `commands.open_log_file`: открытие файла лога в проводнике.
///
/// Само открытие — платформа: замыкание `open` запускает проводник
/// (`explorer /select, <путь>`), существование файла проверяет `exists`.
pub fn open_log_file(
    path: &str,
    exists: impl Fn(&str) -> bool,
    open: impl Fn(&str) -> Result<(), String>,
) -> TelegramProxyActionResult {
    let target = normalize_log_path(path);
    if exists(&target) {
        return match open(&target) {
            Ok(()) => TelegramProxyActionResult::success("", "", ""),
            Err(error) => TelegramProxyActionResult::failure_with(&format!(
                "Failed to open log file: {error}"
            )),
        };
    }
    TelegramProxyActionResult::failure_with(&format!("Log file not found: {target}"))
}

/// python `commands.open_external_link`: открытие ссылки в браузере.
///
/// Само открытие — платформа: замыкание `open` вызывает браузер системы.
pub fn open_external_link(
    url: &str,
    open: impl Fn(&str) -> Result<(), String>,
    success_log: &str,
    error_prefix: &str,
) -> TelegramProxyActionResult {
    let target = url.trim();
    if target.is_empty() {
        return TelegramProxyActionResult::failure_with(&format!("{error_prefix}: empty url"));
    }
    match open(target) {
        Ok(()) => TelegramProxyActionResult::success(success_log, "", ""),
        Err(error) => TelegramProxyActionResult::failure_with(&format!("{error_prefix}: {error}")),
    }
}

/// python `commands.check_relay_reachable` — переносится из
/// [`crate::proxy::routing`].
pub use crate::proxy::routing::check_relay_reachable;

/// python `commands.check_relay_http`: открывается ли TCP-порт 80 релея.
///
/// Само подключение — замыкание `connect` (сеть у вызывающего кода).
pub fn check_relay_http(
    relay_ip: &str,
    timeout: f64,
    connect: impl Fn(&str, f64) -> Result<(), String>,
) -> bool {
    connect(relay_ip, timeout).is_ok()
}

/// python `commands.check_cloudflare_connectivity` — переносится из
/// [`crate::proxy::cloudflare`].
pub use crate::proxy::cloudflare::check_cloudflare_connectivity;

/// python `commands.get_cloudflare_dns_records_text`.
#[must_use]
pub fn get_cloudflare_dns_records_text() -> String {
    build_cfproxy_dns_records_text()
}

/// python `commands.get_cloudflare_worker_code`.
#[must_use]
pub fn get_cloudflare_worker_code() -> String {
    build_cfworker_code()
}

/// python `commands.get_fake_tls_nginx_config`.
#[must_use]
pub fn get_fake_tls_nginx_config(
    fake_tls_domain: &str,
    upstream_host: &str,
    upstream_port: i64,
) -> String {
    build_fake_tls_nginx_config(fake_tls_domain, upstream_host, upstream_port)
}

/// Значения для сохранения настройки (аргументы python `save_settings_action`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SettingsSaveParams {
    /// Хост ручного upstream.
    pub host: String,
    /// Порт ручного upstream.
    pub port: i64,
    /// Пользователь ручного upstream.
    pub user: String,
    /// Пароль ручного upstream.
    pub password: String,
    /// Идентификатор выбранного пресета.
    pub preset_id: String,
    /// Флаг (включение прокси, протокол, автоссылка...).
    pub enabled: bool,
    /// Произвольное значение (домены, режим, secret, dc_ip...).
    pub value: Value,
}

/// python `commands.save_settings_action`: диспетчер сохранения настроек.
///
/// Для upstream-действий перед сохранением пишется строка в общий журнал
/// (`log`). Неизвестное действие — ошибка, как python `ValueError`.
///
/// # Errors
/// Неизвестное действие настройки.
pub fn save_settings_action(
    action: &str,
    params: &SettingsSaveParams,
    store: &mut dyn TelegramSettingsWriter,
    log: &dyn Fn(&str),
) -> Result<Value, String> {
    let action_name = action.trim();
    if action_name.starts_with("upstream") || action_name == "manual_upstream" {
        let detail = if action_name == "upstream_preset" {
            params.preset_id.clone()
        } else if action_name == "manual_upstream" {
            format!("{}:{}", params.host, params.port)
        } else {
            format!("enabled={}", params.enabled)
        };
        log(&format!(
            "Telegram Proxy: сохранение настройки {action_name} ({detail})"
        ));
    }
    let value = match action_name {
        "host" => Value::String(set_host(&params.host, store)),
        "port" => Value::from(set_port(params.port, store)),
        "proxy_enabled" => {
            set_proxy_enabled(params.enabled, store);
            Value::Null
        }
        "proxy_mode" => Value::String(set_proxy_mode(&params.value, store)),
        "mtproxy_secret" => Value::String(set_mtproxy_secret(value_as_str(&params.value), store)),
        "dc_ip" => Value::Array(
            set_dc_ip(&params.value, store)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
        "pool_size" => Value::from(set_pool_size(&params.value, store)),
        "buffer_kb" => Value::from(set_buffer_kb(&params.value, store)),
        "fake_tls_domain" => Value::String(set_fake_tls_domain(value_as_str(&params.value), store)),
        "proxy_protocol" => {
            set_proxy_protocol(params.enabled, store);
            Value::Null
        }
        "auto_deeplink" => {
            set_auto_deeplink(params.enabled, store);
            Value::Null
        }
        "upstream_enabled" => {
            set_upstream_enabled(params.enabled, store);
            Value::Null
        }
        "upstream_preset" => {
            set_upstream_preset(value_as_str(&params.value), store);
            Value::Null
        }
        "manual_upstream" => {
            set_manual_upstream(
                &params.host,
                params.port,
                &params.user,
                &params.password,
                store,
            );
            Value::Null
        }
        "upstream_mode" => {
            set_upstream_mode(params.enabled, store);
            Value::Null
        }
        "upstream_udp_enabled" => {
            set_upstream_udp_enabled(params.enabled, store);
            Value::Null
        }
        "cloudflare_enabled" => {
            crate::config::settings::set_cloudflare_enabled(params.enabled, store);
            Value::Null
        }
        "cloudflare_domains" => Value::Array(
            set_cloudflare_domains(&params.value, store)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
        "cloudflare_worker_enabled" => {
            crate::config::settings::set_cloudflare_worker_enabled(params.enabled, store);
            Value::Null
        }
        "cloudflare_worker_domains" => Value::Array(
            crate::config::settings::set_cloudflare_worker_domains(&params.value, store)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
        other => return Err(format!("Неизвестная настройка Telegram Proxy: {other}")),
    };
    Ok(value)
}

/// python `str(value or "")` для значения настройки: не-строковые значения
/// дают пустую строку (в хранилище эти настройки хранятся строками).
#[must_use]
fn value_as_str(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

/// python `commands.load_page_initial_state` — переносится без изменений из
/// [`crate::config::settings::load_page_initial_state`].
pub use crate::config::settings::load_page_initial_state;

/// Собственный модуль воркеров: решения QThread-воркеров python-пакета.
///
/// Сами QThread и pyqtSignal не переносятся. Каждая функция принимает
/// платформенные действия замыканиями и возвращает «событие» — вариант,
/// соответствующий сигналу python-воркера.
pub mod workers {
    use super::*;

    /// python `TelegramProxyInitialStateWorker`: начальное состояние страницы.
    #[derive(Debug, Clone, PartialEq)]
    pub enum InitialStateEvent {
        /// Сигнал `completed(request_id, result)`.
        Completed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Состояние страницы (python-словарь).
            result: Value,
        },
        /// Сигнал `failed(request_id, error)`.
        Failed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Текст исключения.
            error: String,
        },
    }

    /// Запуск воркера начального состояния.
    pub fn run_initial_state(
        request_id: i64,
        load: impl FnOnce() -> Result<Value, String>,
    ) -> InitialStateEvent {
        match load() {
            Ok(result) => InitialStateEvent::Completed { request_id, result },
            Err(error) => InitialStateEvent::Failed { request_id, error },
        }
    }

    /// python `TelegramProxyStartWorker`: сигналу `completed(bool)`
    /// соответствует итог запуска; сбой чтения конфига — это `false`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StartWorkerEvent {
        /// Прокси запущен.
        pub ok: bool,
        /// Строка предупреждения для общего журнала.
        pub warning: Option<String>,
    }

    /// Запуск воркера старта: конфиг читается в фоновом потоке, затем прокси
    /// стартует. Сбой чтения конфига даёт `ok = false` и предупреждение.
    pub fn run_start_worker(
        load: impl FnOnce() -> Result<ProxyStartParams, String>,
        start: impl FnOnce(ProxyStartParams) -> bool,
    ) -> StartWorkerEvent {
        match load() {
            Ok(config) => StartWorkerEvent {
                ok: start(config),
                warning: None,
            },
            Err(error) => StartWorkerEvent {
                ok: false,
                warning: Some(format!(
                    "TelegramProxyStartWorker: ошибка запуска proxy: {error}"
                )),
            },
        }
    }

    /// python `TelegramProxyUpstreamApplyWorker`: горячая замена upstream-конфига.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UpstreamApplyEvent {
        /// Конфиг применён.
        pub applied: bool,
        /// Строка успеха для журнала Telegram Proxy.
        pub info: Option<String>,
        /// Строка предупреждения для общего журнала.
        pub warning: Option<String>,
    }

    /// Запуск воркера замены upstream-конфига без рестарта.
    pub fn run_upstream_apply(
        build: impl FnOnce() -> Result<Option<UpstreamProxyConfig>, String>,
        apply: impl FnOnce(Option<UpstreamProxyConfig>) -> bool,
    ) -> UpstreamApplyEvent {
        match build() {
            Ok(config) => {
                let applied = apply(config);
                UpstreamApplyEvent {
                    applied,
                    info: applied.then(|| {
                        "Telegram Proxy: upstream-конфиг применён без рестарта".to_string()
                    }),
                    warning: None,
                }
            }
            Err(error) => UpstreamApplyEvent {
                applied: false,
                info: None,
                warning: Some(format!(
                    "TelegramProxyUpstreamApplyWorker: ошибка применения upstream: {error}"
                )),
            },
        }
    }

    /// Способ остановки прокси (python `TelegramProxyStopRuntimeWorker`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StopMode {
        /// `stop_proxy`: полная остановка с сигналом статуса.
        Full,
        /// `_stop_runtime_only`: остановка только runtime, без сигнала.
        RuntimeOnly,
    }

    /// python `TelegramProxyStopRuntimeWorker`: `emit_status` выбирает способ
    /// остановки — полный останов со сигналом или тихая остановка runtime.
    #[must_use]
    pub fn stop_mode(emit_status: bool) -> StopMode {
        if emit_status {
            StopMode::Full
        } else {
            StopMode::RuntimeOnly
        }
    }

    /// Сигналу `stopped()` соответствует завершение остановки.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StopRuntimeEvent {
        /// Остановка прошла.
        pub stopped: bool,
        /// Строка предупреждения для общего журнала.
        pub warning: Option<String>,
    }

    /// Запуск воркера остановки: остановка прокси выбранным способом и, если
    /// переданы оба значения, переключение тумблера прокси в новое состояние.
    pub fn run_stop_runtime(
        emit_status: bool,
        stop: impl FnOnce(StopMode),
        set_enabled: Option<&dyn Fn(bool)>,
        enabled_after_stop: Option<bool>,
    ) -> StopRuntimeEvent {
        stop(stop_mode(emit_status));
        if let (Some(set_enabled), Some(enabled)) = (set_enabled, enabled_after_stop) {
            set_enabled(enabled);
        }
        StopRuntimeEvent {
            stopped: true,
            warning: None,
        }
    }

    /// python `TelegramProxyOpenLogFileWorker`: сигналу `completed(object)`
    /// соответствует итог команды [`open_log_file`], сигналу `failed(str)` —
    /// текст исключения.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OpenLogFileEvent {
        /// Сигнал `completed(result)`.
        Completed(TelegramProxyActionResult),
        /// Сигнал `failed(error)`.
        Failed(String),
    }

    /// Запуск воркера открытия файла лога.
    pub fn run_open_log_file(
        path: &str,
        open_log_file_fn: impl FnOnce(&str) -> Result<TelegramProxyActionResult, String>,
    ) -> OpenLogFileEvent {
        match open_log_file_fn(path) {
            Ok(result) => OpenLogFileEvent::Completed(result),
            Err(error) => OpenLogFileEvent::Failed(error),
        }
    }

    /// Параметры воркера внешней ссылки
    /// (python `TelegramProxyExternalLinkWorker`).
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct ExternalLinkRequest {
        /// Ссылка для открытия.
        pub url: String,
        /// Строка журнала при успехе.
        pub success_log: String,
        /// Префикс сообщения об ошибке.
        pub error_prefix: String,
    }

    /// Сигналу `completed(object)` соответствует итог команды
    /// [`open_external_link`], сигналу `failed(str)` — текст исключения.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExternalLinkEvent {
        /// Сигнал `completed(result)`.
        Completed(TelegramProxyActionResult),
        /// Сигнал `failed(error)`.
        Failed(String),
    }

    /// Запуск воркера внешней ссылки: команда вызывается с параметрами воркера.
    pub fn run_external_link(
        request: &ExternalLinkRequest,
        open_external_link_fn: impl FnOnce(
            &ExternalLinkRequest,
        ) -> Result<TelegramProxyActionResult, String>,
    ) -> ExternalLinkEvent {
        match open_external_link_fn(request) {
            Ok(result) => ExternalLinkEvent::Completed(result),
            Err(error) => ExternalLinkEvent::Failed(error),
        }
    }

    /// python `TelegramProxyLogLineWorker`: строка журнала с идентификатором
    /// запроса.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LogLineEvent {
        /// Сигнал `completed(request_id)`.
        Completed(i64),
        /// Сигнал `failed(request_id, error)`.
        Failed(i64, String),
    }

    /// Запуск воркера строки журнала.
    pub fn run_log_line(
        request_id: i64,
        append: impl FnOnce(&str) -> Result<(), String>,
        message: &str,
    ) -> LogLineEvent {
        match append(message) {
            Ok(()) => LogLineEvent::Completed(request_id),
            Err(error) => LogLineEvent::Failed(request_id, error),
        }
    }

    /// python `TelegramProxyAutoDeeplinkWorker`: проверка автоссылки `tg://`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AutoDeeplinkEvent {
        /// Сигнал `completed(request_id, should_open)`.
        Completed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Открыть ссылку `tg://`.
            should_open: bool,
        },
        /// Сигнал `failed(request_id, error)`.
        Failed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Текст исключения.
            error: String,
        },
    }

    /// Запуск воркера автоссылки.
    pub fn run_auto_deeplink(
        request_id: i64,
        consume: impl FnOnce() -> Result<bool, String>,
    ) -> AutoDeeplinkEvent {
        match consume() {
            Ok(should_open) => AutoDeeplinkEvent::Completed {
                request_id,
                should_open,
            },
            Err(error) => AutoDeeplinkEvent::Failed { request_id, error },
        }
    }

    /// python `TelegramProxyRelayCheckWorker`: итог проверки релея.
    #[derive(Debug, Clone, PartialEq)]
    pub enum RelayCheckEvent {
        /// Сигнал `completed(generation, diag)`.
        Completed {
            /// Поколение проверки (страница игнорирует устаревшие ответы).
            generation: i64,
            /// Словарь диагностики: `ok` с задержкой или `fail` с признаками.
            diag: Value,
        },
        /// Сигнал `warning(message)`.
        Warning {
            /// Текст ошибки проверки.
            message: String,
        },
    }

    /// Запуск воркера проверки релея: пауза 2 с, до трёх попыток с паузами
    /// 2 с между ними; успех даёт `{"status": "ok", "ms": ...}`, полный
    /// провал — `{"status": "fail", "http_ok": ..., "zapret_running": ...}`.
    ///
    /// `sleep` — замыкание паузы (время у вызывающего кода).
    pub fn run_relay_check(
        generation: i64,
        check: &dyn Fn() -> Result<RelayReachability, String>,
        check_http: &dyn Fn() -> bool,
        zapret_running: &dyn Fn() -> bool,
        sleep: &mut dyn FnMut(f64),
    ) -> RelayCheckEvent {
        sleep(2.0);
        let mut best: Option<RelayReachability> = None;
        for attempt in 0..3 {
            match check() {
                Ok(result) => {
                    if result.reachable {
                        best = Some(result);
                        break;
                    }
                    if attempt < 2 {
                        sleep(2.0);
                    }
                }
                Err(error) => {
                    return RelayCheckEvent::Warning {
                        message: format!("Relay check error: {error}"),
                    }
                }
            }
        }
        let diag = match best {
            Some(best) if best.reachable => serde_json::json!({
                "status": "ok",
                "ms": best.ms,
            }),
            _ => serde_json::json!({
                "status": "fail",
                "http_ok": check_http(),
                "zapret_running": zapret_running(),
            }),
        };
        RelayCheckEvent::Completed { generation, diag }
    }

    /// python `TelegramProxyCloudflareCheckWorker`: первый текст проверки.
    #[must_use]
    pub fn cloudflare_check_intro(kind: &str) -> &'static str {
        let kind = if kind.is_empty() { "domain" } else { kind };
        if kind == "worker" {
            "Проверяем Cloudflare Worker..."
        } else {
            "Проверяем Cloudflare-домен..."
        }
    }

    /// Строки журнала по итогу проверки: сводка и по строке на хост.
    #[must_use]
    pub fn cloudflare_check_log_lines(result: &CloudflareCheckResult) -> Vec<String> {
        let mut lines = vec![format!("Проверка Cloudflare: {}", result.summary())];
        for entry in &result.entries {
            let status = if entry.ok { "OK" } else { "FAIL" };
            let suffix = if entry.error.is_empty() {
                String::new()
            } else {
                format!(" - {}", entry.error)
            };
            lines.push(format!("Cloudflare {status}: {}{suffix}", entry.host));
        }
        lines
    }

    /// python `TelegramProxyCloudflareCheckWorker`: итог проверки.
    #[derive(Debug, Clone, PartialEq)]
    pub enum CloudflareCheckEvent {
        /// Сигнал `completed(request_id, result)`.
        Completed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Итог проверки.
            result: CloudflareCheckResult,
        },
        /// Сигнал `failed(request_id, error)`.
        Failed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Текст исключения.
            error: String,
        },
    }

    /// Запуск воркера проверки Cloudflare: сам пишет подробности в журнал
    /// Telegram Proxy, страница получает только итог для уведомления.
    pub fn run_cloudflare_check(
        request_id: i64,
        kind: &str,
        check: impl FnOnce() -> Result<CloudflareCheckResult, String>,
        append_log: &dyn Fn(&str),
    ) -> CloudflareCheckEvent {
        append_log(cloudflare_check_intro(kind));
        match check() {
            Ok(result) => {
                for line in cloudflare_check_log_lines(&result) {
                    append_log(&line);
                }
                CloudflareCheckEvent::Completed { request_id, result }
            }
            Err(error) => {
                append_log(&format!("Ошибка проверки Cloudflare: {error}"));
                CloudflareCheckEvent::Failed { request_id, error }
            }
        }
    }

    /// python `TelegramProxyDiagnosticsWorker`: сигналу `completed(str)`
    /// соответствует текст диагностики; исключение тоже становится текстом.
    /// Прогресс уходит в замыкание, переданное вместе с `run`.
    pub fn run_diagnostics_worker(
        run: impl FnOnce(&dyn Fn(&str)) -> Result<String, String>,
    ) -> String {
        match run(&|_| {}) {
            Ok(result_text) => result_text,
            Err(error) => error,
        }
    }

    /// python `TelegramHostsWorker`: сигналу `completed(request_id, result)`
    /// всегда соответствует итог действия — даже при ошибке, чтобы страница
    /// снова включила кнопку.
    #[must_use]
    pub fn run_hosts_worker(
        request_id: i64,
        action: &str,
        run_action: impl FnOnce(&str) -> Result<TelegramHostsActionResult, String>,
    ) -> (i64, TelegramHostsActionResult) {
        let result = match run_action(action) {
            Ok(result) => result,
            Err(error) => TelegramHostsActionResult {
                action: action.to_string(),
                ok: false,
                changed: false,
                message: error,
                status: None,
            },
        };
        (request_id, result)
    }

    /// Запрос сохранения настройки (python `TelegramProxySettingsSaveWorker`).
    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct SettingsSaveRequest {
        /// Идентификатор запроса.
        pub request_id: i64,
        /// Название настройки (как в [`save_settings_action`]).
        pub action: String,
        /// Хост ручного upstream.
        pub host: String,
        /// Порт ручного upstream.
        pub port: i64,
        /// Пользователь ручного upstream.
        pub user: String,
        /// Пароль ручного upstream.
        pub password: String,
        /// Идентификатор пресета.
        pub preset_id: String,
        /// Флаг.
        pub enabled: bool,
        /// Произвольное значение.
        pub value: Value,
        /// Дополнительные поля контекста для страницы.
        pub context_extra: Map<String, Value>,
    }

    impl SettingsSaveRequest {
        /// python `__init__`: строки обрезаются.
        #[must_use]
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            request_id: i64,
            action: &str,
            host: &str,
            port: i64,
            user: &str,
            password: &str,
            preset_id: &str,
            enabled: bool,
            value: Value,
            context_extra: Map<String, Value>,
        ) -> Self {
            Self {
                request_id,
                action: action.trim().to_string(),
                host: host.trim().to_string(),
                port,
                user: user.trim().to_string(),
                password: password.to_string(),
                preset_id: preset_id.trim().to_string(),
                enabled,
                value,
                context_extra,
            }
        }

        /// Контекст результата для страницы (python `context`).
        #[must_use]
        pub fn context(&self) -> Map<String, Value> {
            let mut context = Map::new();
            context.insert("host".to_string(), Value::String(self.host.clone()));
            context.insert("port".to_string(), Value::from(self.port));
            context.insert("user".to_string(), Value::String(self.user.clone()));
            context.insert("password".to_string(), Value::String(self.password.clone()));
            context.insert(
                "preset_id".to_string(),
                Value::String(self.preset_id.clone()),
            );
            context.insert("enabled".to_string(), Value::Bool(self.enabled));
            context.insert("value".to_string(), self.value.clone());
            for (key, value) in &self.context_extra {
                context.insert(key.clone(), value.clone());
            }
            context
        }
    }

    /// python `TelegramProxySettingsSaveWorker`: итог сохранения настройки.
    #[derive(Debug, Clone, PartialEq)]
    pub enum SettingsSaveEvent {
        /// Сигнал `completed(request_id, action, result, context)`.
        Completed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Название настройки.
            action: String,
            /// Результат сохранения (нормализованное значение или `null`).
            result: Value,
            /// Контекст для страницы.
            context: Map<String, Value>,
        },
        /// Сигнал `failed(request_id, action, error, context)`.
        Failed {
            /// Идентификатор запроса.
            request_id: i64,
            /// Название настройки.
            action: String,
            /// Текст исключения.
            error: String,
            /// Контекст для страницы.
            context: Map<String, Value>,
        },
    }

    /// Запуск воркера сохранения настройки.
    pub fn run_settings_save(
        request: &SettingsSaveRequest,
        save: impl FnOnce(&SettingsSaveRequest) -> Result<Value, String>,
    ) -> SettingsSaveEvent {
        let context = request.context();
        match save(request) {
            Ok(result) => SettingsSaveEvent::Completed {
                request_id: request.request_id,
                action: request.action.clone(),
                result,
                context,
            },
            Err(error) => SettingsSaveEvent::Failed {
                request_id: request.request_id,
                action: request.action.clone(),
                error,
                context,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn result(action: &str, ok: bool, changed: bool, message: &str) -> TelegramHostsActionResult {
        TelegramHostsActionResult {
            action: action.to_string(),
            ok,
            changed,
            message: message.to_string(),
            status: None,
        }
    }

    /// Писатель в буфер обмена, который всегда падает.
    fn failing_writer(text: &str) -> Result<(), String> {
        Err(format!("нет буфера: {text}"))
    }

    /// Писатель в буфер обмена, который копит текст.
    fn collecting_writer(sink: Rc<RefCell<String>>) -> impl Fn(&str) -> Result<(), String> {
        move |text| {
            sink.borrow_mut().push_str(text);
            Ok(())
        }
    }

    #[test]
    fn diagnostics_start_plan_matches_python() {
        let plan = build_diagnostics_start_plan();
        assert!(!plan.button_enabled);
        assert_eq!(plan.button_text, "Тестирование...");
        assert_eq!(plan.initial_text, "Запуск диагностики Telegram DC...\n");
        assert_eq!(plan.poll_interval_ms, 200);
    }

    #[test]
    fn diagnostics_poll_plan_updates_text_only_when_thread_done() {
        let poll = build_diagnostics_poll_plan(Some("DC1: OK\n"), false);
        assert_eq!(poll.updated_text.as_deref(), Some("DC1: OK\n"));
        assert!(!poll.should_stop_timer);
        assert!(!poll.should_finish);

        let silent = build_diagnostics_poll_plan(None, false);
        assert!(silent.updated_text.is_none());

        let done = build_diagnostics_poll_plan(None, true);
        assert!(done.should_stop_timer);
        assert!(done.should_finish);
    }

    #[test]
    fn diagnostics_finish_plan_reenables_button() {
        let plan = build_diagnostics_finish_plan();
        assert!(plan.button_enabled);
        assert_eq!(plan.button_text, "Запустить диагностику");
    }

    #[test]
    fn copy_text_reports_success_with_log_line() {
        let written = Rc::new(RefCell::new(String::new()));
        let writer = collecting_writer(written.clone());
        let result = copy_text(
            "https://example.com",
            Some(&writer),
            "Скопировано",
            "Ссылка в буфере обмена",
            "Ссылка скопирована",
        );
        assert!(result.ok);
        assert_eq!(result.log_line, "Ссылка скопирована");
        assert_eq!(result.info_title, "Скопировано");
        assert_eq!(result.info_content, "Ссылка в буфере обмена");
        assert_eq!(*written.borrow(), "https://example.com");
    }

    #[test]
    fn copy_text_fails_on_empty_text_and_writer_errors() {
        let failed = copy_text(
            "текст",
            Some(&failing_writer),
            "Скопировано",
            "Содержимое",
            "журнал",
        );
        assert!(!failed.ok);
        assert!(failed.log_line.is_empty());

        let empty = copy_text(
            "",
            Some(&failing_writer),
            "Скопировано",
            "Содержимое",
            "журнал",
        );
        assert!(!empty.ok);

        let no_writer = copy_text("текст", None, "Скопировано", "Содержимое", "журнал");
        assert!(!no_writer.ok);
    }

    #[test]
    fn hosts_action_unknown_action_reports_error() {
        let read: &ReadHostsFn<'_> = &|| Ok(Some(String::new()));
        let write: &WriteHostsFn<'_> = &|_| Ok(true);
        let log: &LogFn<'_> = &|_| {};
        let result = run_telegram_hosts_action("replace", read, write, log);
        assert!(!result.ok);
        assert_eq!(result.action, "replace");
        assert_eq!(result.message, "Неизвестное действие с hosts: replace");
        assert!(result.status.is_none());
    }

    #[test]
    fn hosts_action_status_only_reads_file() {
        let reads = Rc::new(RefCell::new(0));
        let writes = Rc::new(RefCell::new(0));
        let read_sink = reads.clone();
        let write_sink = writes.clone();
        let read: &ReadHostsFn<'_> = &|| {
            *read_sink.borrow_mut() += 1;
            Ok(Some("127.0.0.1 localhost\n".to_string()))
        };
        let write: &WriteHostsFn<'_> = &|_| {
            *write_sink.borrow_mut() += 1;
            Ok(true)
        };
        let log: &LogFn<'_> = &|_| {};
        let result = run_telegram_hosts_action(" status ", read, write, log);
        assert!(result.ok);
        assert!(!result.changed);
        assert!(result.message.is_empty());
        assert_eq!(*writes.borrow(), 0);
        // Действие `status` читает файл ровно один раз.
        assert_eq!(*reads.borrow(), 1);
    }

    #[test]
    fn hosts_action_add_reports_change_and_rereads_status() {
        let text = Rc::new(RefCell::new("127.0.0.1 localhost\n".to_string()));
        let read_text = text.clone();
        let read: &ReadHostsFn<'_> = &|| Ok(Some(read_text.borrow().clone()));
        let write: &WriteHostsFn<'_> = &|new_text| {
            *read_text.borrow_mut() = new_text.to_string();
            Ok(true)
        };
        let logs: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let log_sink = logs.clone();
        let log: &LogFn<'_> = &move |line| log_sink.borrow_mut().push(line.to_string());

        let result = run_telegram_hosts_action("add", read, write, log);
        assert!(result.ok);
        assert!(result.changed);
        assert_eq!(
            result.message,
            format!(
                "Записи Telegram прописаны в hosts: {}",
                crate::telegram_hosts::TELEGRAM_DOMAINS.len()
            )
        );
        let status = result.status.expect("status re-read");
        assert!(status.is_complete());
        assert_eq!(
            *logs.borrow(),
            vec![format!(
                "Telegram hosts: Записи Telegram прописаны в hosts: {}",
                crate::telegram_hosts::TELEGRAM_DOMAINS.len()
            )]
        );
    }

    #[test]
    fn hosts_action_write_error_is_reported_with_real_state() {
        let read: &ReadHostsFn<'_> = &|| Ok(Some(String::new()));
        let write: &WriteHostsFn<'_> = &|_| Err("read-only".to_string());
        let log: &LogFn<'_> = &|_| {};
        let result = run_telegram_hosts_action("add", read, write, log);
        assert!(!result.ok);
        assert!(!result.message.is_empty());
    }

    #[test]
    fn hosts_action_status_read_error_fails_result() {
        let read: &ReadHostsFn<'_> = &|| Err::<Option<String>, String>("нет доступа".to_string());
        let write: &WriteHostsFn<'_> = &|_| Ok(true);
        let log: &LogFn<'_> = &|_| {};
        let result = run_telegram_hosts_action("status", read, write, log);
        assert!(!result.ok);
        assert_eq!(
            result.message,
            "Не удалось прочитать файл hosts: нет доступа"
        );
        assert!(result.status.is_none());
    }

    #[test]
    fn log_path_normalization_collapses_separators() {
        assert_eq!(
            normalize_log_path("logs//tg_proxy.log"),
            "logs\\tg_proxy.log"
        );
        assert_eq!(normalize_log_path("logs\\sub\\..\\tg.log"), "logs\\tg.log");
        assert_eq!(normalize_log_path(""), ".");
        assert_eq!(normalize_log_path("C:\\logs\\a.log"), "C:\\logs\\a.log");
        assert_eq!(normalize_log_path("C:/logs/a.log"), "C:\\logs\\a.log");
    }

    #[test]
    fn open_log_file_reports_missing_and_failed_open() {
        let missing = open_log_file("logs/tg.log", |_| false, |_| Ok(()));
        assert!(!missing.ok);
        assert_eq!(missing.log_line, "Log file not found: logs\\tg.log");

        let opened = open_log_file("logs\\tg.log", |_| true, |_| Ok(()));
        assert!(opened.ok);
        assert!(opened.log_line.is_empty());

        let failed = open_log_file("logs\\tg.log", |_| true, |_| Err("нет доступа".to_string()));
        assert!(!failed.ok);
        assert_eq!(failed.log_line, "Failed to open log file: нет доступа");
    }

    #[test]
    fn open_external_link_reports_empty_url_and_errors() {
        let empty = open_external_link("  ", |_| Ok(()), "открыто", "Не открылось");
        assert!(!empty.ok);
        assert_eq!(empty.log_line, "Не открылось: empty url");

        let ok = open_external_link(
            " https://example.com ",
            |_| Ok(()),
            "открыто",
            "Не открылось",
        );
        assert!(ok.ok);
        assert_eq!(ok.log_line, "открыто");

        let failed = open_external_link(
            "https://example.com",
            |_| Err("нет сети".to_string()),
            "открыто",
            "Не открылось",
        );
        assert!(!failed.ok);
        assert_eq!(failed.log_line, "Не открылось: нет сети");
    }

    #[test]
    fn relay_http_reports_reachability() {
        assert!(check_relay_http("149.154.167.220", 5.0, |_, _| Ok(())));
        assert!(!check_relay_http("149.154.167.220", 5.0, |_, _| {
            Err("timeout".to_string())
        }));
    }

    #[test]
    fn generated_texts_match_python_helpers() {
        assert!(
            !get_cloudflare_worker_code().is_empty(),
            "код воркера непустой"
        );
        assert!(!get_cloudflare_dns_records_text().is_empty());
        let nginx = get_fake_tls_nginx_config("example.com", "127.0.0.1", 8446);
        assert!(nginx.contains("example.com"));
    }

    #[test]
    fn restart_request_merge_uses_stronger_action() {
        assert_eq!(normalize_restart_request(" Now "), "now");
        assert_eq!(normalize_restart_request("unknown"), "");
        assert_eq!(merge_restart_request("upstream", "schedule"), "schedule");
        assert_eq!(merge_restart_request("now", "upstream"), "now");
    }

    #[test]
    fn save_settings_action_dispatches_to_setters() {
        let mut store = TestStore::default();
        let params = SettingsSaveParams {
            host: " 10.0.0.5 ".to_string(),
            port: 8443,
            user: "user".to_string(),
            password: "pass".to_string(),
            preset_id: "manual".to_string(),
            enabled: true,
            value: json!(""),
        };
        let result = save_settings_action("host", &params, &mut store, &|_| {});
        assert_eq!(result.unwrap(), json!("10.0.0.5"));
        assert_eq!(store.host_set, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn save_settings_action_logs_upstream_actions() {
        let mut store = TestStore::default();
        let logs = Rc::new(RefCell::new(Vec::new()));
        let sink = logs.clone();
        let params = SettingsSaveParams {
            preset_id: "uk".to_string(),
            ..SettingsSaveParams::default()
        };
        let result = save_settings_action("upstream_preset", &params, &mut store, &move |line| {
            sink.borrow_mut().push(line.to_string());
        });
        assert!(result.is_ok());
        assert_eq!(
            *logs.borrow(),
            vec!["Telegram Proxy: сохранение настройки upstream_preset (uk)".to_string()]
        );

        let manual = SettingsSaveParams {
            host: "1.2.3.4".to_string(),
            port: 1080,
            ..SettingsSaveParams::default()
        };
        save_settings_action("manual_upstream", &manual, &mut store, &|_| {}).unwrap();
        assert_eq!(
            store.upstream_preset_id_set,
            vec!["".to_string(), "".to_string()]
        );
        assert_eq!(
            store.upstream_host_set,
            vec!["".to_string(), "1.2.3.4".to_string()]
        );
        assert_eq!(store.upstream_port_set, vec![1080, 1080]);

        let logs2 = Rc::new(RefCell::new(Vec::new()));
        let sink2 = logs2.clone();
        save_settings_action(
            "upstream_enabled",
            &SettingsSaveParams {
                enabled: true,
                ..SettingsSaveParams::default()
            },
            &mut store,
            &move |line| {
                sink2.borrow_mut().push(line.to_string());
            },
        )
        .unwrap();
        assert_eq!(
            *logs2.borrow(),
            vec![
                "Telegram Proxy: сохранение настройки upstream_enabled (enabled=true)".to_string()
            ]
        );
    }

    #[test]
    fn save_settings_action_rejects_unknown_action() {
        let mut store = TestStore::default();
        let error = save_settings_action(
            "mystery",
            &SettingsSaveParams::default(),
            &mut store,
            &|_| {},
        )
        .unwrap_err();
        assert_eq!(error, "Неизвестная настройка Telegram Proxy: mystery");
    }

    #[test]
    fn save_settings_action_normalizes_values() {
        let mut store = TestStore::default();
        let params = SettingsSaveParams {
            value: json!("mtproxy"),
            ..SettingsSaveParams::default()
        };
        let result = save_settings_action("proxy_mode", &params, &mut store, &|_| {}).unwrap();
        assert_eq!(result, json!("mtproxy"));

        let params = SettingsSaveParams {
            value: json!("150"),
            ..SettingsSaveParams::default()
        };
        let result = save_settings_action("pool_size", &params, &mut store, &|_| {}).unwrap();
        assert_eq!(result, json!(32));

        let params = SettingsSaveParams {
            value: json!([" a ", "b"]),
            ..SettingsSaveParams::default()
        };
        let result =
            save_settings_action("cloudflare_domains", &params, &mut store, &|_| {}).unwrap();
        assert!(result.is_array());
    }

    #[test]
    fn get_start_config_reads_store_with_defaults() {
        let resolver = UpstreamPresetResolver::new(&[]);
        let mut store = TestStore {
            tg_mode: json!("mtproxy"),
            tg_pool_size: json!(99),
            tg_buffer_kb: json!(1),
            ..TestStore::default()
        };
        let config = get_start_config(&mut store, &resolver);
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 1353);
        assert_eq!(config.mode, "mtproxy");
        assert!(!config.mtproxy_secret.is_empty(), "секрет сгенерирован");
        assert!(!config.mtproxy_secret.contains('\n'));
        assert_eq!(config.pool_size, 32);
        assert_eq!(config.buffer_kb, 4);
        assert!(config.cloudflare_config.is_some());
        assert!(config.upstream_config.is_none(), "upstream выключен");
        assert!(config.dc_endpoint_overrides.is_empty());
        assert!(!config.proxy_protocol);
    }

    #[test]
    fn get_start_config_keeps_saved_secret_in_socks_mode() {
        let resolver = UpstreamPresetResolver::new(&[]);
        let mut store = TestStore {
            tg_mode: json!("socks5"),
            tg_secret: "abcdef".to_string(),
            ..TestStore::default()
        };
        let config = get_start_config(&mut store, &resolver);
        assert_eq!(config.mode, "socks5");
        assert_eq!(config.mtproxy_secret, "");
    }

    // ---- workers ----

    #[test]
    fn initial_state_worker_maps_result_and_error() {
        let ok = workers::run_initial_state(7, || Ok(json!({"port": 1353})));
        assert_eq!(
            ok,
            workers::InitialStateEvent::Completed {
                request_id: 7,
                result: json!({"port": 1353}),
            }
        );
        let failed = workers::run_initial_state(7, || Err("нет хранилища".to_string()));
        assert_eq!(
            failed,
            workers::InitialStateEvent::Failed {
                request_id: 7,
                error: "нет хранилища".to_string(),
            }
        );
    }

    #[test]
    fn start_worker_maps_config_and_errors() {
        let ok = workers::run_start_worker(
            || {
                Ok(ProxyStartParams {
                    port: 1353,
                    ..ProxyStartParams::default()
                })
            },
            |_| true,
        );
        assert!(ok.ok);
        assert!(ok.warning.is_none());

        let failed =
            workers::run_start_worker(|| Err("хранилище недоступно".to_string()), |_| true);
        assert!(!failed.ok);
        assert_eq!(
            failed.warning.as_deref(),
            Some("TelegramProxyStartWorker: ошибка запуска proxy: хранилище недоступно")
        );
    }

    #[test]
    fn upstream_apply_worker_reports_applied_config() {
        let applied = workers::run_upstream_apply(|| Ok(None), |_| true);
        assert!(applied.applied);
        assert_eq!(
            applied.info.as_deref(),
            Some("Telegram Proxy: upstream-конфиг применён без рестарта")
        );

        let failed = workers::run_upstream_apply(|| Err("нет каталога".to_string()), |_| true);
        assert!(!failed.applied);
        assert_eq!(
            failed.warning.as_deref(),
            Some("TelegramProxyUpstreamApplyWorker: ошибка применения upstream: нет каталога")
        );

        let rejected = workers::run_upstream_apply(|| Ok(None), |_| false);
        assert!(!rejected.applied);
        assert!(rejected.info.is_none());
    }

    #[test]
    fn stop_mode_selects_full_or_quiet_stop() {
        assert_eq!(workers::stop_mode(true), workers::StopMode::Full);
        assert_eq!(workers::stop_mode(false), workers::StopMode::RuntimeOnly);
    }

    #[test]
    fn stop_runtime_worker_toggles_enabled_only_with_both_values() {
        let stops = Rc::new(RefCell::new(Vec::new()));
        let sink = stops.clone();
        let toggles = Rc::new(RefCell::new(Vec::new()));
        let toggle_sink = toggles.clone();

        let event = workers::run_stop_runtime(
            true,
            |mode| sink.borrow_mut().push(mode),
            Some(&|value| toggle_sink.borrow_mut().push(value)),
            Some(false),
        );
        assert!(event.stopped);
        assert_eq!(*stops.borrow(), vec![workers::StopMode::Full]);
        assert_eq!(*toggles.borrow(), vec![false]);

        // Без обоих значений тумблер не трогается.
        let stops2 = Rc::new(RefCell::new(Vec::new()));
        let sink2 = stops2.clone();
        let toggles2 = Rc::new(RefCell::new(Vec::new()));
        let toggle_sink2 = toggles2.clone();
        let event = workers::run_stop_runtime(
            false,
            |mode| sink2.borrow_mut().push(mode),
            Some(&|value| toggle_sink2.borrow_mut().push(value)),
            None,
        );
        assert!(event.stopped);
        assert_eq!(*stops2.borrow(), vec![workers::StopMode::RuntimeOnly]);
        assert!(toggles2.borrow().is_empty());
    }

    #[test]
    fn open_log_file_and_external_link_workers_map_results() {
        let ok = workers::run_open_log_file("a.log", |path| {
            Ok(TelegramProxyActionResult::success("", "", path))
        });
        assert_eq!(
            ok,
            workers::OpenLogFileEvent::Completed(TelegramProxyActionResult::success(
                "", "", "a.log"
            ))
        );
        let failed = workers::run_open_log_file("a.log", |_| Err("нет файла".to_string()));
        assert_eq!(
            failed,
            workers::OpenLogFileEvent::Failed("нет файла".to_string())
        );

        let request = workers::ExternalLinkRequest {
            url: "https://example.com".to_string(),
            success_log: "открыто".to_string(),
            error_prefix: "Не открылось".to_string(),
        };
        let ok = workers::run_external_link(&request, |req| {
            Ok(TelegramProxyActionResult::success(&req.success_log, "", ""))
        });
        assert!(matches!(ok, workers::ExternalLinkEvent::Completed(_)));
        let failed = workers::run_external_link(&request, |_| Err("нет сети".to_string()));
        assert_eq!(
            failed,
            workers::ExternalLinkEvent::Failed("нет сети".to_string())
        );
    }

    #[test]
    fn log_line_and_auto_deeplink_workers_map_request_ids() {
        let ok = workers::run_log_line(3, |_| Ok(()), "строка");
        assert_eq!(ok, workers::LogLineEvent::Completed(3));
        let failed = workers::run_log_line(3, |_| Err("нет журнала".to_string()), "строка");
        assert_eq!(
            failed,
            workers::LogLineEvent::Failed(3, "нет журнала".to_string())
        );

        let open = workers::run_auto_deeplink(5, || Ok(true));
        assert_eq!(
            open,
            workers::AutoDeeplinkEvent::Completed {
                request_id: 5,
                should_open: true,
            }
        );
        let failed = workers::run_auto_deeplink(5, || Err("нет хранилища".to_string()));
        assert_eq!(
            failed,
            workers::AutoDeeplinkEvent::Failed {
                request_id: 5,
                error: "нет хранилища".to_string(),
            }
        );
    }

    #[test]
    fn relay_check_worker_stops_on_first_reachable_attempt() {
        let sleeps = Rc::new(RefCell::new(Vec::new()));
        let sink = sleeps.clone();
        let attempts = Rc::new(RefCell::new(0));
        let attempt_sink = attempts.clone();
        let check = move || {
            let mut count = attempt_sink.borrow_mut();
            *count += 1;
            if *count >= 2 {
                Ok(RelayReachability {
                    reachable: true,
                    error: String::new(),
                    ms: 42.5,
                })
            } else {
                Ok(RelayReachability {
                    reachable: false,
                    error: "timeout".to_string(),
                    ms: 0.0,
                })
            }
        };
        let event = workers::run_relay_check(4, &check, &|| true, &|| false, &mut |seconds| {
            sink.borrow_mut().push(seconds)
        });
        // Пауза перед первой попыткой + пауза после первой неудачи.
        assert_eq!(*sleeps.borrow(), vec![2.0, 2.0]);
        match event {
            workers::RelayCheckEvent::Completed { generation, diag } => {
                assert_eq!(generation, 4);
                assert_eq!(diag["status"], "ok");
                assert_eq!(diag["ms"], 42.5);
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
    }

    #[test]
    fn relay_check_worker_reports_fail_with_http_and_zapret() {
        let sleeps = Rc::new(RefCell::new(Vec::new()));
        let sink = sleeps.clone();
        let check = || {
            Ok(RelayReachability {
                reachable: false,
                error: "Connection refused".to_string(),
                ms: 0.0,
            })
        };
        let event = workers::run_relay_check(1, &check, &|| false, &|| true, &mut |seconds| {
            sink.borrow_mut().push(seconds)
        });
        assert_eq!(*sleeps.borrow(), vec![2.0, 2.0, 2.0]);
        match event {
            workers::RelayCheckEvent::Completed { diag, .. } => {
                assert_eq!(diag["status"], "fail");
                assert_eq!(diag["http_ok"], false);
                assert_eq!(diag["zapret_running"], true);
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
    }

    #[test]
    fn relay_check_worker_maps_error_to_warning() {
        let check = || Err::<RelayReachability, String>("нет сети".to_string());
        let event = workers::run_relay_check(2, &check, &|| true, &|| false, &mut |_| {});
        match event {
            workers::RelayCheckEvent::Warning { message } => {
                assert_eq!(message, "Relay check error: нет сети");
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
    }

    #[test]
    fn cloudflare_check_intro_selects_text_by_kind() {
        assert_eq!(
            workers::cloudflare_check_intro("worker"),
            "Проверяем Cloudflare Worker..."
        );
        assert_eq!(
            workers::cloudflare_check_intro("domain"),
            "Проверяем Cloudflare-домен..."
        );
        assert_eq!(
            workers::cloudflare_check_intro(""),
            "Проверяем Cloudflare-домен..."
        );
    }

    #[test]
    fn cloudflare_check_lines_summarize_entries() {
        use crate::proxy::cloudflare::CloudflareCheckEntry;
        let result = CloudflareCheckResult {
            kind: "domain".to_string(),
            entries: vec![
                CloudflareCheckEntry {
                    kind: "domain".to_string(),
                    host: "a.example".to_string(),
                    path: "/apiws".to_string(),
                    ok: true,
                    error: String::new(),
                },
                CloudflareCheckEntry {
                    kind: "domain".to_string(),
                    host: "b.example".to_string(),
                    path: "/apiws".to_string(),
                    ok: false,
                    error: "timeout".to_string(),
                },
            ],
        };
        assert_eq!(
            workers::cloudflare_check_log_lines(&result),
            vec![
                "Проверка Cloudflare: Работает: 1 из 2.".to_string(),
                "Cloudflare OK: a.example".to_string(),
                "Cloudflare FAIL: b.example - timeout".to_string(),
            ]
        );
    }

    #[test]
    fn cloudflare_check_worker_writes_log_and_emits_result() {
        let logs = Rc::new(RefCell::new(Vec::new()));
        let sink = logs.clone();
        let check = || {
            Ok(CloudflareCheckResult {
                kind: "worker".to_string(),
                entries: vec![],
            })
        };
        let event = workers::run_cloudflare_check(9, "worker", check, &move |line| {
            sink.borrow_mut().push(line.to_string());
        });
        assert!(matches!(
            event,
            workers::CloudflareCheckEvent::Completed { request_id: 9, .. }
        ));
        assert_eq!(
            *logs.borrow(),
            vec![
                "Проверяем Cloudflare Worker...".to_string(),
                "Проверка Cloudflare: Нет доменов для проверки.".to_string(),
            ]
        );

        let logs2 = Rc::new(RefCell::new(Vec::new()));
        let sink2 = logs2.clone();
        let event = workers::run_cloudflare_check(
            9,
            "domain",
            || Err("нет сети".to_string()),
            &move |line| sink2.borrow_mut().push(line.to_string()),
        );
        match event {
            workers::CloudflareCheckEvent::Failed { error, .. } => {
                assert_eq!(error, "нет сети");
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
        assert_eq!(
            *logs2.borrow(),
            vec![
                "Проверяем Cloudflare-домен...".to_string(),
                "Ошибка проверки Cloudflare: нет сети".to_string(),
            ]
        );
    }

    #[test]
    fn diagnostics_worker_turns_error_into_result_text() {
        let text = workers::run_diagnostics_worker(|progress| {
            progress("DC1: OK");
            Ok("DC1: OK\n".to_string())
        });
        assert_eq!(text, "DC1: OK\n");
        let failed = workers::run_diagnostics_worker(|_| Err("сбой проб".to_string()));
        assert_eq!(failed, "сбой проб");
    }

    #[test]
    fn hosts_worker_always_completes_with_result() {
        let ok =
            workers::run_hosts_worker(1, "status", |action| Ok(result(action, true, false, "")));
        assert_eq!(ok.0, 1);
        assert!(ok.1.ok);

        let failed = workers::run_hosts_worker(2, "add", |_| Err("нет файла".to_string()));
        assert_eq!(failed.0, 2);
        assert!(!failed.1.ok);
        assert_eq!(failed.1.action, "add");
        assert_eq!(failed.1.message, "нет файла");
        assert!(failed.1.status.is_none());
    }

    #[test]
    fn settings_save_worker_builds_context_and_events() {
        let mut extra = Map::new();
        extra.insert("source".to_string(), json!("page"));
        let request = workers::SettingsSaveRequest::new(
            11,
            " upstream_enabled ",
            " host ",
            1080,
            " user ",
            "pass",
            " uk ",
            true,
            json!(""),
            extra,
        );
        assert_eq!(request.action, "upstream_enabled");
        assert_eq!(request.host, "host");
        assert_eq!(request.user, "user");
        assert_eq!(request.preset_id, "uk");

        let mut expected = Map::new();
        expected.insert("host".to_string(), json!("host"));
        expected.insert("port".to_string(), json!(1080));
        expected.insert("user".to_string(), json!("user"));
        expected.insert("password".to_string(), json!("pass"));
        expected.insert("preset_id".to_string(), json!("uk"));
        expected.insert("enabled".to_string(), json!(true));
        expected.insert("value".to_string(), json!(""));
        expected.insert("source".to_string(), json!("page"));
        assert_eq!(request.context(), expected);

        let completed = workers::run_settings_save(&request, |_| Ok(json!(null)));
        match completed {
            workers::SettingsSaveEvent::Completed {
                request_id,
                action,
                result,
                context,
            } => {
                assert_eq!(request_id, 11);
                assert_eq!(action, "upstream_enabled");
                assert_eq!(result, json!(null));
                assert_eq!(context, expected);
            }
            other => panic!("неожиданное событие: {other:?}"),
        }

        let failed = workers::run_settings_save(&request, |_| Err("сбой записи".to_string()));
        match failed {
            workers::SettingsSaveEvent::Failed {
                request_id,
                action,
                error,
                context,
            } => {
                assert_eq!(request_id, 11);
                assert_eq!(action, "upstream_enabled");
                assert_eq!(error, "сбой записи");
                assert_eq!(context, expected);
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
    }

    // ---- тестовое хранилище ----

    /// Реализация хранилища для тестов: значения в памяти, записи — списки.
    #[derive(Default)]
    struct TestStore {
        host_set: Vec<String>,
        upstream_preset_id_set: Vec<String>,
        upstream_host_set: Vec<String>,
        upstream_port_set: Vec<i64>,
        tg_enabled: bool,
        tg_host: String,
        tg_port: i64,
        tg_mode: Value,
        tg_secret: String,
        tg_pool_size: Value,
        tg_buffer_kb: Value,
        tg_fake_tls: String,
        tg_proxy_protocol: bool,
    }

    impl TelegramSettingsReader for TestStore {
        fn read_settings(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn get_auto_deeplink(&self) -> bool {
            false
        }
        fn get_deeplink_done(&self) -> bool {
            false
        }
        fn get_upstream_enabled(&self) -> bool {
            false
        }
        fn get_upstream_host(&self) -> String {
            String::new()
        }
        fn get_upstream_port(&self) -> i64 {
            0
        }
        fn get_upstream_user(&self) -> String {
            String::new()
        }
        fn get_upstream_pass(&self) -> String {
            String::new()
        }
        fn get_upstream_preset_id(&self) -> String {
            String::new()
        }
        fn get_upstream_mode(&self) -> String {
            String::new()
        }
        fn get_upstream_udp_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_domains(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_cloudflare_worker_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_worker_domains(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_dc_ip(&self) -> Vec<String> {
            Vec::new()
        }
    }

    impl TelegramProxyStoreReader for TestStore {
        fn get_tg_proxy_enabled(&self) -> bool {
            self.tg_enabled
        }
        fn get_tg_proxy_host(&self) -> String {
            self.tg_host.clone()
        }
        fn get_tg_proxy_port(&self) -> i64 {
            self.tg_port
        }
        fn get_tg_proxy_mode(&self) -> Value {
            self.tg_mode.clone()
        }
        fn get_tg_proxy_mtproxy_secret(&self) -> String {
            self.tg_secret.clone()
        }
        fn get_tg_proxy_pool_size(&self) -> Value {
            self.tg_pool_size.clone()
        }
        fn get_tg_proxy_buffer_kb(&self) -> Value {
            self.tg_buffer_kb.clone()
        }
        fn get_tg_proxy_fake_tls_domain(&self) -> String {
            self.tg_fake_tls.clone()
        }
        fn get_tg_proxy_proxy_protocol(&self) -> bool {
            self.tg_proxy_protocol
        }
    }

    impl TelegramSettingsWriter for TestStore {
        fn set_port(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_host(&mut self, value: &str) -> Result<(), String> {
            self.host_set.push(value.to_string());
            Ok(())
        }
        fn set_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_mode(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_mtproxy_secret(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_dc_ip(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn set_pool_size(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_buffer_kb(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_fake_tls_domain(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_proxy_protocol(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_auto_deeplink(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_deeplink_done(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_mode(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_udp_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_preset_id(&mut self, value: &str) -> Result<(), String> {
            self.upstream_preset_id_set.push(value.to_string());
            Ok(())
        }
        fn set_upstream_host(&mut self, value: &str) -> Result<(), String> {
            self.upstream_host_set.push(value.to_string());
            Ok(())
        }
        fn set_upstream_port(&mut self, value: i64) -> Result<(), String> {
            self.upstream_port_set.push(value);
            Ok(())
        }
        fn set_upstream_user(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_pass(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_domains(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_worker_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_worker_domains(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
    }
}
