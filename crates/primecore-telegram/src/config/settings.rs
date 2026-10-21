//! Настройки страницы Telegram Proxy: состояние, нормализация значений,
//! чтение и запись хранилища.
//!
//! Порт `telegram_proxy/config/settings.py`. Чистые решения — нормализация
//! host/порта/размеров, разбор сохранённых данных в состояние страницы,
//! сборка конфигов внешнего SOCKS и Cloudflare — обычные функции. Хранилище
//! настроек (python `settings.store`) — ввод вызывающего кода: оно передаётся
//! трейтами [`TelegramSettingsReader`] и [`TelegramSettingsWriter`], поэтому
//! вся логика проверяется без Windows и без базы настроек.
//!
//! Python глотал все ошибки записи (`except: pass`) — здесь ошибка записи
//! остаётся значением `Err` в трейте, а функции-обёртки повторяют поведение
//! python: нормализованное значение возвращается независимо от записи.
//!
//! Здесь же — слияние отложенных перезапусков очереди сохранения
//! (`runtime/settings_save_flow.py`): побеждает более «сильное» действие.

use serde_json::Value;

use crate::config::upstream_catalog::{
    BuildSecrets, UpstreamCatalog, UpstreamPresetResolver, UpstreamTestTarget,
};
use crate::proxy::cloudflare::{
    auto_cloudflare_domains, normalize_domain_list, CloudflareFallbackConfig,
};
use crate::proxy::dc_map::parse_dc_endpoint_overrides;
use crate::proxy::fake_tls::normalize_fake_tls_domain;
use crate::proxy::mtproxy::{build_mtproxy_link, generate_secret, normalize_secret};
use crate::proxy::routing::UpstreamProxyConfig;

/// Хост по умолчанию.
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Порт локального прокси по умолчанию.
pub const DEFAULT_PORT: i64 = 1353;
/// Порт внешнего SOCKS5 по умолчанию.
pub const DEFAULT_UPSTREAM_PORT: i64 = 1080;

/// Состояние настроек страницы Telegram Proxy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TelegramProxySettingsState {
    pub host: String,
    pub port: i64,
    pub mode: String,
    pub upstream_enabled: bool,
    pub upstream_host: String,
    pub upstream_port: i64,
    pub upstream_preset_id: String,
    pub upstream_user: String,
    pub upstream_password: String,
    pub upstream_mode: String,
    pub upstream_udp_enabled: bool,
    pub upstream_preset_index: usize,
    pub cloudflare_enabled: bool,
    pub cloudflare_domains: Vec<String>,
    pub cloudflare_worker_enabled: bool,
    pub cloudflare_worker_domains: Vec<String>,
    pub mtproxy_secret: String,
    pub dc_ip: Vec<String>,
    pub pool_size: i64,
    pub buffer_kb: i64,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
    pub auto_deeplink: bool,
}

/// Начальное состояние страницы: каталог прокси и сохранённые настройки.
#[derive(Debug, Clone)]
pub struct TelegramProxyPageInitialStatePlan {
    pub upstream_catalog: UpstreamCatalog,
    pub settings: TelegramProxySettingsState,
}

/// Состояние по умолчанию: MTProxy на `127.0.0.1:1353`, внешний прокси
/// включён (выбор возьмёт первый пресет сборки), Cloudflare выключен.
#[must_use]
pub fn default_state() -> TelegramProxySettingsState {
    TelegramProxySettingsState {
        host: DEFAULT_HOST.to_string(),
        port: DEFAULT_PORT,
        mode: "mtproxy".to_string(),
        upstream_enabled: true,
        upstream_host: String::new(),
        upstream_port: DEFAULT_UPSTREAM_PORT,
        upstream_preset_id: String::new(),
        upstream_user: String::new(),
        upstream_password: String::new(),
        upstream_mode: "fallback".to_string(),
        upstream_udp_enabled: false,
        upstream_preset_index: 0,
        cloudflare_enabled: false,
        cloudflare_domains: Vec::new(),
        cloudflare_worker_enabled: false,
        cloudflare_worker_domains: Vec::new(),
        mtproxy_secret: String::new(),
        dc_ip: Vec::new(),
        pool_size: 4,
        buffer_kb: 256,
        fake_tls_domain: String::new(),
        proxy_protocol: false,
        auto_deeplink: true,
    }
}

/// python-истинность значения (пустая строка, 0, `null`, `false` — ложь).
#[must_use]
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|float| float != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// python `str(value)`.
#[must_use]
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// python `str(value or "")` — пусто для ложных значений.
#[must_use]
fn or_empty_str(value: &Value) -> String {
    if py_truthy(value) {
        py_str(value)
    } else {
        String::new()
    }
}

/// python `int(value)`: `None` и негодные строки — `None` (python даёт
/// исключение), числа и строки-числа — значение.
#[must_use]
fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float as i64)),
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Поле сохранённых данных как python `raw.get(key)`; отсутствующее поле —
/// `None` (`Value::Null`).
fn raw_field<'a>(raw: &'a Value, key: &str) -> Option<&'a Value> {
    raw.as_object().and_then(|fields| fields.get(key))
}

/// Поле с python-дефолтом: `raw.get(key, default)`.
#[must_use]
fn raw_field_or<'a>(raw: &'a Value, key: &str, default: &'a Value) -> &'a Value {
    raw_field(raw, key).unwrap_or(default)
}

/// Строки значения для списков (`dc_ip`, домены Cloudflare): строка или
/// список строк, как в python.
#[must_use]
fn strings_from_value(value: &Value) -> Vec<String> {
    match value {
        Value::String(text) => vec![text.clone()],
        Value::Array(items) => items
            .iter()
            .filter(|item| item.is_string())
            .filter_map(|item| item.as_str())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Домен подходит для хоста прокси: четыре числа 0..=255.
#[must_use]
pub fn validate_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| {
        part.parse::<i64>()
            .is_ok_and(|number| (0..=255).contains(&number))
    })
}

/// Хост прокси: подходящий IPv4 остаётся, остальное — `127.0.0.1`.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    let text = host.trim();
    if validate_host(text) {
        return text.to_string();
    }
    DEFAULT_HOST.to_string()
}

/// Порт локального прокси: 1024..=65535, остальное — 1353.
#[must_use]
pub fn normalize_port(port: Option<&Value>) -> i64 {
    let number = match port {
        Some(value) if py_truthy(value) => py_int(value),
        _ => Some(0),
    };
    match number {
        Some(value) if (1024..=65535).contains(&value) => value,
        _ => DEFAULT_PORT,
    }
}

/// Порт внешнего SOCKS5: 1..=65535, остальное — 1080.
#[must_use]
pub fn normalize_upstream_port(port: Option<&Value>) -> i64 {
    let number = match port {
        Some(value) if py_truthy(value) => py_int(value),
        _ => Some(0),
    };
    match number {
        Some(value) if (1..=65535).contains(&value) => value,
        _ => DEFAULT_UPSTREAM_PORT,
    }
}

/// Режим локального прокси: только `mtproxy`, всё остальное — `socks5`.
#[must_use]
pub fn normalize_proxy_mode(mode: &Value) -> String {
    if py_str(mode).trim().to_lowercase() == "mtproxy" {
        return "mtproxy".to_string();
    }
    "socks5".to_string()
}

/// Размер пула запасных соединений: 0..=32.
#[must_use]
pub fn normalize_pool_size(value: &Value) -> i64 {
    match py_int(value) {
        Some(number) => number.clamp(0, 32),
        None => 4,
    }
}

/// Размер буфера в КБ: 4..=4096.
#[must_use]
pub fn normalize_buffer_kb(value: &Value) -> i64 {
    match py_int(value) {
        Some(number) => number.clamp(4, 4096),
        None => 256,
    }
}

/// Ссылка для кнопки «Подключить» в Telegram.
#[must_use]
pub fn build_proxy_url(
    host: &str,
    port: i64,
    mode: &Value,
    mtproxy_secret: &str,
    fake_tls_domain: &str,
) -> String {
    let normalized_host = normalize_host(host);
    let port_value = Value::from(port);
    let normalized_port = normalize_port(Some(&port_value));
    if normalize_proxy_mode(mode) == "mtproxy" {
        return build_mtproxy_link(
            &normalized_host,
            normalized_port as u32,
            mtproxy_secret,
            &normalize_fake_tls_domain(fake_tls_domain),
        );
    }
    format!("tg://socks?server={normalized_host}&port={normalized_port}")
}

/// Список доменов Cloudflare из значения хранилища (строка или список).
#[must_use]
fn normalize_domain_list_value(value: &Value) -> Vec<String> {
    normalize_domain_list(&strings_from_value(value))
}

/// Разбор сохранённых данных в состояние страницы.
#[must_use]
pub fn settings_state_from_data(
    data: &Value,
    upstream_catalog: &UpstreamCatalog,
) -> TelegramProxySettingsState {
    let defaults = default_state();
    let empty = Value::Object(serde_json::Map::new());
    let raw = raw_field_or(data, "telegram_proxy", &empty);

    let mode = normalize_proxy_mode(raw_field_or(
        raw,
        "mode",
        &Value::String(defaults.mode.clone()),
    ));
    let upstream_host = or_empty_str(raw_field_or(raw, "upstream_host", &Value::Null));
    let upstream_port = normalize_upstream_port(raw_field(raw, "upstream_port"));
    let upstream_preset_id = or_empty_str(raw_field_or(raw, "upstream_preset_id", &Value::Null));
    let upstream_user = or_empty_str(raw_field_or(raw, "upstream_user", &Value::Null));
    let upstream_password = or_empty_str(raw_field_or(raw, "upstream_pass", &Value::Null));
    let upstream_mode = {
        let text = or_empty_str(raw_field_or(
            raw,
            "upstream_mode",
            &Value::String("fallback".to_string()),
        ))
        .to_lowercase();
        if text.is_empty() {
            "fallback".to_string()
        } else {
            text
        }
    };
    let cloudflare_domains =
        normalize_domain_list_value(raw_field_or(raw, "cloudflare_domains", &Value::Null));
    let cloudflare_worker_domains =
        normalize_domain_list_value(raw_field_or(raw, "cloudflare_worker_domains", &Value::Null));
    let mtproxy_secret = normalize_secret(&or_empty_str(raw_field_or(
        raw,
        "mtproxy_secret",
        &Value::Null,
    )));
    let dc_ip = parse_dc_endpoint_overrides(&strings_from_value(raw_field_or(
        raw,
        "dc_ip",
        &Value::Null,
    )))
    .into_iter()
    .map(|(dc, ip)| format!("{dc}:{ip}"))
    .collect();
    let pool_size = normalize_pool_size(raw_field_or(raw, "pool_size", &Value::from(4)));
    let buffer_kb = normalize_buffer_kb(raw_field_or(raw, "buffer_kb", &Value::from(256)));
    let fake_tls_domain = normalize_fake_tls_domain(&or_empty_str(raw_field_or(
        raw,
        "fake_tls_domain",
        &Value::Null,
    )));
    let proxy_protocol = raw_field_or(raw, "proxy_protocol", &Value::Bool(false))
        .as_bool()
        .unwrap_or(false);

    let upstream_preset_index =
        upstream_catalog.find_choice_index(upstream_host.as_str(), upstream_preset_id.as_str());

    TelegramProxySettingsState {
        host: normalize_host(&or_empty_str(raw_field_or(raw, "host", &Value::Null))),
        port: normalize_port(raw_field(raw, "port")),
        mode,
        upstream_enabled: raw_field_or(
            raw,
            "upstream_enabled",
            &Value::Bool(defaults.upstream_enabled),
        )
        .as_bool()
        .unwrap_or(false),
        upstream_host,
        upstream_port,
        upstream_preset_id,
        upstream_user,
        upstream_password,
        upstream_mode,
        upstream_udp_enabled: raw_field_or(raw, "upstream_udp_enabled", &Value::Bool(false))
            .as_bool()
            .unwrap_or(false),
        upstream_preset_index,
        cloudflare_enabled: raw_field_or(raw, "cloudflare_enabled", &Value::Bool(false))
            .as_bool()
            .unwrap_or(false),
        cloudflare_domains,
        cloudflare_worker_enabled: raw_field_or(
            raw,
            "cloudflare_worker_enabled",
            &Value::Bool(false),
        )
        .as_bool()
        .unwrap_or(false),
        cloudflare_worker_domains,
        mtproxy_secret,
        dc_ip,
        pool_size,
        buffer_kb,
        fake_tls_domain,
        proxy_protocol,
        auto_deeplink: raw_field_or(raw, "auto_deeplink", &Value::Bool(defaults.auto_deeplink))
            .as_bool()
            .unwrap_or(false),
    }
}

/// Чтение настроек (python `settings.store`, только нужные функции).
///
/// Каждый метод может не удаться — сбой хранилища остаётся значением.
pub trait TelegramSettingsReader {
    /// python `read_settings` — весь документ настроек.
    /// # Errors
    /// Хранилище не прочитано.
    fn read_settings(&self) -> Result<Value, String>;
    fn get_auto_deeplink(&self) -> bool;
    fn get_deeplink_done(&self) -> bool;
    fn get_upstream_enabled(&self) -> bool;
    fn get_upstream_host(&self) -> String;
    fn get_upstream_port(&self) -> i64;
    fn get_upstream_user(&self) -> String;
    fn get_upstream_pass(&self) -> String;
    fn get_upstream_preset_id(&self) -> String;
    fn get_upstream_mode(&self) -> String;
    fn get_upstream_udp_enabled(&self) -> bool;
    fn get_cloudflare_enabled(&self) -> bool;
    fn get_cloudflare_domains(&self) -> Vec<String>;
    fn get_cloudflare_worker_enabled(&self) -> bool;
    fn get_cloudflare_worker_domains(&self) -> Vec<String>;
    fn get_dc_ip(&self) -> Vec<String>;
}

/// Запись настроек (python `settings.store.set_tg_proxy_*`).
pub trait TelegramSettingsWriter {
    /// # Errors
    /// Хранилище не приняло значение (python глотал такие сбои).
    fn set_port(&mut self, value: i64) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_host(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_enabled(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_mode(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_mtproxy_secret(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_dc_ip(&mut self, value: &[String]) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_pool_size(&mut self, value: i64) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_buffer_kb(&mut self, value: i64) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_fake_tls_domain(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_proxy_protocol(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_auto_deeplink(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_deeplink_done(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_enabled(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_mode(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_udp_enabled(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_preset_id(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_host(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_port(&mut self, value: i64) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_user(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_upstream_pass(&mut self, value: &str) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_cloudflare_enabled(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_cloudflare_domains(&mut self, value: &[String]) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_cloudflare_worker_enabled(&mut self, value: bool) -> Result<(), String>;
    /// # Errors
    /// Хранилище не приняло значение.
    fn set_cloudflare_worker_domains(&mut self, value: &[String]) -> Result<(), String>;
}

/// python `set_port`: приводит порт и сохраняет его.
pub fn set_port(port: i64, store: &mut dyn TelegramSettingsWriter) -> i64 {
    let normalized = normalize_port(Some(&Value::from(port)));
    let _ = store.set_port(normalized);
    normalized
}

/// python `set_host`: приводит хост и сохраняет его.
#[must_use]
pub fn set_host(host: &str, store: &mut dyn TelegramSettingsWriter) -> String {
    let normalized = normalize_host(host);
    let _ = store.set_host(&normalized);
    normalized
}

/// python `set_proxy_enabled`.
pub fn set_proxy_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_enabled(enabled);
}

/// python `set_proxy_mode`: нормализует режим и сохраняет его.
#[must_use]
pub fn set_proxy_mode(mode: &Value, store: &mut dyn TelegramSettingsWriter) -> String {
    let normalized = normalize_proxy_mode(mode);
    let _ = store.set_mode(&normalized);
    normalized
}

/// python `generate_mtproxy_secret`.
#[must_use]
pub fn generate_mtproxy_secret() -> String {
    generate_secret()
}

/// python `set_mtproxy_secret`: приводит секрет и сохраняет его.
#[must_use]
pub fn set_mtproxy_secret(secret: &str, store: &mut dyn TelegramSettingsWriter) -> String {
    let normalized = normalize_secret(secret);
    let _ = store.set_mtproxy_secret(&normalized);
    normalized
}

/// python `ensure_mtproxy_secret_for_mode`: в режиме MTProxy секрет
/// генерируется и сохраняется, если его ещё нет; в SOCKS5 секрет пустой.
#[must_use]
pub fn ensure_mtproxy_secret_for_mode(
    mode: &Value,
    secret: &str,
    store: &mut dyn TelegramSettingsWriter,
) -> String {
    if normalize_proxy_mode(mode) != "mtproxy" {
        return String::new();
    }
    let normalized = normalize_secret(secret);
    if !normalized.is_empty() {
        return normalized;
    }
    let generated = generate_mtproxy_secret();
    let _ = set_mtproxy_secret(&generated, store);
    generated
}

/// python `set_dc_ip`: разбирает переопределения адресов DC и сохраняет их.
#[must_use]
pub fn set_dc_ip(value: &Value, store: &mut dyn TelegramSettingsWriter) -> Vec<String> {
    let result: Vec<String> = parse_dc_endpoint_overrides(&strings_from_value(value))
        .into_iter()
        .map(|(dc, ip)| format!("{dc}:{ip}"))
        .collect();
    let _ = store.set_dc_ip(&result);
    result
}

/// python `set_pool_size`.
pub fn set_pool_size(value: &Value, store: &mut dyn TelegramSettingsWriter) -> i64 {
    let normalized = normalize_pool_size(value);
    let _ = store.set_pool_size(normalized);
    normalized
}

/// python `set_buffer_kb`.
pub fn set_buffer_kb(value: &Value, store: &mut dyn TelegramSettingsWriter) -> i64 {
    let normalized = normalize_buffer_kb(value);
    let _ = store.set_buffer_kb(normalized);
    normalized
}

/// python `set_fake_tls_domain`.
#[must_use]
pub fn set_fake_tls_domain(value: &str, store: &mut dyn TelegramSettingsWriter) -> String {
    let domain = normalize_fake_tls_domain(value);
    let _ = store.set_fake_tls_domain(&domain);
    domain
}

/// python `set_proxy_protocol`.
pub fn set_proxy_protocol(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_proxy_protocol(enabled);
}

/// python `set_auto_deeplink`.
pub fn set_auto_deeplink(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_auto_deeplink(enabled);
}

/// python `set_upstream_enabled`.
pub fn set_upstream_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_upstream_enabled(enabled);
}

/// python `set_upstream_mode`: `true` — «весь TCP», `false` — запасной режим.
pub fn set_upstream_mode(always_enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_upstream_mode(if always_enabled { "always" } else { "fallback" });
}

/// python `set_upstream_udp_enabled`.
pub fn set_upstream_udp_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_upstream_udp_enabled(enabled);
}

/// python `set_upstream_preset`: выбран пресет — ручные поля сбрасываются.
pub fn set_upstream_preset(preset_id: &str, store: &mut dyn TelegramSettingsWriter) {
    let normalized_preset_id = preset_id.trim();
    let _ = store.set_upstream_preset_id(normalized_preset_id);
    let _ = store.set_upstream_host("");
    let _ = store.set_upstream_port(DEFAULT_UPSTREAM_PORT);
    let _ = store.set_upstream_user("");
    let _ = store.set_upstream_pass("");
}

/// python `set_manual_upstream`: ручной ввод сбрасывает выбор пресета.
pub fn set_manual_upstream(
    host: &str,
    port: i64,
    user: &str,
    password: &str,
    store: &mut dyn TelegramSettingsWriter,
) {
    let _ = store.set_upstream_preset_id("");
    let _ = store.set_upstream_host(host.trim());
    let _ = store.set_upstream_port(normalize_upstream_port(Some(&Value::from(port))));
    let _ = store.set_upstream_user(user.trim());
    let _ = store.set_upstream_pass(password);
}

/// python `set_cloudflare_enabled`.
pub fn set_cloudflare_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_cloudflare_enabled(enabled);
}

/// python `set_cloudflare_domains`.
#[must_use]
pub fn set_cloudflare_domains(
    value: &Value,
    store: &mut dyn TelegramSettingsWriter,
) -> Vec<String> {
    let domains = normalize_domain_list_value(value);
    let _ = store.set_cloudflare_domains(&domains);
    domains
}

/// python `set_cloudflare_worker_enabled`.
pub fn set_cloudflare_worker_enabled(enabled: bool, store: &mut dyn TelegramSettingsWriter) {
    let _ = store.set_cloudflare_worker_enabled(enabled);
}

/// python `set_cloudflare_worker_domains`.
#[must_use]
pub fn set_cloudflare_worker_domains(
    value: &Value,
    store: &mut dyn TelegramSettingsWriter,
) -> Vec<String> {
    let domains = normalize_domain_list_value(value);
    let _ = store.set_cloudflare_worker_domains(&domains);
    domains
}

/// Конфиг своего домена Cloudflare из хранилища.
///
/// Без своих доменов берутся встроенные фронты; воркер без своих доменов
/// отключается.
#[must_use]
pub fn build_cloudflare_config(store: &dyn TelegramSettingsReader) -> CloudflareFallbackConfig {
    let mut domains = normalize_domain_list(&store.get_cloudflare_domains());
    let cloudflare_enabled = store.get_cloudflare_enabled();
    if cloudflare_enabled && domains.is_empty() {
        domains = auto_cloudflare_domains();
    }
    let worker_domains = normalize_domain_list(&store.get_cloudflare_worker_domains());
    CloudflareFallbackConfig {
        enabled: cloudflare_enabled && !domains.is_empty(),
        domains,
        worker_enabled: store.get_cloudflare_worker_enabled() && !worker_domains.is_empty(),
        worker_domains,
    }
}

/// Переопределения адресов DC из хранилища (python `build_dc_endpoint_overrides`).
#[must_use]
pub fn build_dc_endpoint_overrides(store: &dyn TelegramSettingsReader) -> Vec<(i32, String)> {
    parse_dc_endpoint_overrides(&store.get_dc_ip())
}

/// Рабочий конфиг внешнего SOCKS5 (python `build_upstream_config`).
///
/// Выбранный пресет сборки даёт свои учётные данные и остальные пресеты
/// как запасные; ручной ввод без хоста падает на первый пресет сборки.
#[must_use]
pub fn build_upstream_config(
    store: &dyn TelegramSettingsReader,
    resolver: &UpstreamPresetResolver,
) -> Option<UpstreamProxyConfig> {
    if !store.get_upstream_enabled() {
        return None;
    }

    let preset_id = store.get_upstream_preset_id().trim().to_string();
    let preset = if preset_id.is_empty() {
        None
    } else {
        resolver.socks5_by_id(&preset_id)
    };
    let mut selected_preset_id = preset_id;
    let mut selected_preset_name = String::new();
    let mut fallback_presets: Vec<crate::config::upstream_catalog::Socks5Preset> = Vec::new();

    let (host, port, username, password, tls, tls_server_name, tls_verify) =
        if let Some(preset) = &preset {
            let host = preset.host.clone();
            let port = normalize_upstream_port(Some(&Value::from(preset.port)));
            selected_preset_name = preset.name.clone();
            fallback_presets = resolver.socks5_fallbacks(&selected_preset_id);
            (
                host,
                port,
                preset.username.clone(),
                preset.password.clone(),
                preset.tls,
                preset.tls_server_name.clone(),
                preset.tls_verify,
            )
        } else {
            let host = store.get_upstream_host().trim().to_string();
            let port = normalize_upstream_port(Some(&Value::from(store.get_upstream_port())));
            let username = store.get_upstream_user().trim().to_string();
            let password = store.get_upstream_pass();
            if host.is_empty() {
                let preset = resolver.first_socks5()?;
                selected_preset_id = preset.id.clone();
                selected_preset_name = preset.name.clone();
                fallback_presets = resolver.socks5_fallbacks(&selected_preset_id);
                (
                    preset.host,
                    normalize_upstream_port(Some(&Value::from(preset.port))),
                    preset.username,
                    preset.password,
                    preset.tls,
                    preset.tls_server_name,
                    preset.tls_verify,
                )
            } else {
                (host, port, username, password, false, String::new(), false)
            }
        };

    if host.is_empty() || port <= 0 {
        return None;
    }

    let fallback_proxies = fallback_presets
        .iter()
        .filter(|item| {
            !item.host.trim().is_empty()
                && normalize_upstream_port(Some(&Value::from(item.port))) > 0
        })
        .map(|item| crate::proxy::routing::UpstreamProxyEndpoint {
            host: item.host.clone(),
            port: normalize_upstream_port(Some(&Value::from(item.port))),
            username: item.username.clone(),
            password: item.password.clone(),
            tls: item.tls,
            tls_server_name: item.tls_server_name.clone(),
            tls_verify: item.tls_verify,
            preset_id: item.id.clone(),
            preset_name: item.name.trim().to_string(),
        })
        .collect();

    Some(UpstreamProxyConfig {
        enabled: true,
        host,
        port,
        mode: {
            let mode = store.get_upstream_mode();
            if mode.is_empty() {
                "fallback".to_string()
            } else {
                mode
            }
        },
        udp_enabled: store.get_upstream_udp_enabled(),
        username,
        password,
        tls,
        tls_server_name,
        tls_verify,
        preset_id: selected_preset_id,
        preset_name: selected_preset_name,
        fallback_proxies,
    })
}

/// Цель проверки внешнего прокси (python `load_upstream_test_target`).
#[must_use]
pub fn load_upstream_test_target(
    store: &dyn TelegramSettingsReader,
    resolver: &UpstreamPresetResolver,
) -> Option<UpstreamTestTarget> {
    if !store.get_upstream_enabled() {
        return None;
    }
    let preset_id = store.get_upstream_preset_id().trim().to_string();
    let target = if preset_id.is_empty() {
        None
    } else {
        resolver.test_target_by_id(&preset_id)
    };
    if let Some(target) = target {
        return Some(target);
    }
    let host = store.get_upstream_host().trim().to_string();
    let port = normalize_upstream_port(Some(&Value::from(store.get_upstream_port())));
    if host.is_empty() {
        let preset = resolver.first_socks5()?;
        return Some(UpstreamTestTarget {
            host: preset.host,
            port: preset.port,
            username: preset.username,
            password: preset.password,
            tls: preset.tls,
            tls_server_name: preset.tls_server_name,
            tls_verify: preset.tls_verify,
        });
    }
    if port <= 0 {
        return None;
    }
    Some(UpstreamTestTarget {
        host,
        port,
        username: store.get_upstream_user().trim().to_string(),
        password: store.get_upstream_pass(),
        tls: false,
        tls_server_name: String::new(),
        tls_verify: false,
    })
}

/// Ссылка MTProxy-пресета из каталога (python `get_upstream_mtproxy_link`).
#[must_use]
pub fn get_upstream_mtproxy_link(preset_id: &str, resolver: &UpstreamPresetResolver) -> String {
    resolver.mtproxy_link_by_id(preset_id)
}

/// Начальное состояние страницы из хранилища.
///
/// Сбой чтения хранилища даёт состояние по умолчанию, как python.
#[must_use]
pub fn load_page_initial_state(
    store: &dyn TelegramSettingsReader,
    secrets: &BuildSecrets,
) -> TelegramProxyPageInitialStatePlan {
    let upstream_catalog = UpstreamCatalog::load_from_runtime(secrets);
    let settings = store
        .read_settings()
        .map(|data| settings_state_from_data(&data, &upstream_catalog))
        .unwrap_or_else(|_| default_state());
    TelegramProxyPageInitialStatePlan {
        upstream_catalog,
        settings,
    }
}

/// Есть ли в Windows программа для ссылок `tg://` (обычно это Telegram).
///
/// Без неё открытие ссылки показало бы системное окно «выберите приложение».
/// Реестр Windows — ввод вызывающего кода.
pub type LinkHandlerCheck<'a> = dyn Fn() -> bool + 'a;

/// python `consume_auto_deeplink_request`: `true` только один раз —
/// авто-настройка включена, Telegram установлен и ссылку ещё не открывали.
///
/// Пока Telegram не установлен, отметка не ставится: ссылка откроется,
/// когда он появится.
pub fn consume_auto_deeplink_request(
    store: &mut dyn TelegramSettingsWriterReader,
    telegram_installed: impl Fn() -> bool,
) -> bool {
    if !store.get_auto_deeplink() {
        return false;
    }
    if store.get_deeplink_done() {
        return false;
    }
    if !telegram_installed() {
        return false;
    }
    let _ = store.set_deeplink_done(true);
    true
}

/// Читатель и писатель в одном (удобно для реализаций над одним хранилищем).
pub trait TelegramSettingsWriterReader: TelegramSettingsReader + TelegramSettingsWriter {}

impl<T: TelegramSettingsReader + TelegramSettingsWriter> TelegramSettingsWriterReader for T {}

/// python `normalize_restart_request`: неизвестные значения — отложенного
/// действия нет.
#[must_use]
pub fn normalize_restart_request(value: &str) -> String {
    let restart = value.trim().to_lowercase();
    if matches!(
        restart.as_str(),
        "" | "upstream_schedule" | "upstream" | "schedule" | "now"
    ) {
        return restart;
    }
    String::new()
}

/// python `merge_restart_request`: побеждает более «сильное» действие.
#[must_use]
pub fn merge_restart_request(current: &str, requested: &str) -> String {
    let current_restart = normalize_restart_request(current);
    let requested_restart = normalize_restart_request(requested);
    if restart_priority(&requested_restart) > restart_priority(&current_restart) {
        return requested_restart;
    }
    current_restart
}

/// «Сила» действия перезапуска (python `_RESTART_PRIORITY`).
#[must_use]
fn restart_priority(restart: &str) -> u8 {
    match restart {
        "upstream_schedule" => 1,
        "upstream" => 2,
        "schedule" => 3,
        "now" => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    use crate::config::upstream_catalog::{BuildSecrets, Socks5Preset};

    /// Тестовое хранилище: записывает вызовы, отдаёт заготовленные значения.
    #[derive(Default)]
    struct TestStore {
        data: serde_json::Map<String, Value>,
        saved: RefCell<Vec<(String, String)>>,
    }

    impl TestStore {
        fn with(data: Value) -> Self {
            let mut store = Self::default();
            if let Value::Object(fields) = data {
                store.data = fields;
            }
            store
        }

        fn get_str(&self, key: &str) -> String {
            self.data
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        }

        fn get_bool(&self, key: &str) -> bool {
            self.data.get(key).and_then(Value::as_bool).unwrap_or(false)
        }
    }

    impl TelegramSettingsReader for TestStore {
        fn read_settings(&self) -> Result<Value, String> {
            Ok(json!({"telegram_proxy": self.data.clone()}))
        }
        fn get_auto_deeplink(&self) -> bool {
            self.get_bool("auto_deeplink") || !self.data.contains_key("auto_deeplink")
        }
        fn get_deeplink_done(&self) -> bool {
            self.get_bool("deeplink_done")
        }
        fn get_upstream_enabled(&self) -> bool {
            self.get_bool("upstream_enabled")
        }
        fn get_upstream_host(&self) -> String {
            self.get_str("upstream_host")
        }
        fn get_upstream_port(&self) -> i64 {
            self.data
                .get("upstream_port")
                .and_then(Value::as_i64)
                .unwrap_or(0)
        }
        fn get_upstream_user(&self) -> String {
            self.get_str("upstream_user")
        }
        fn get_upstream_pass(&self) -> String {
            self.get_str("upstream_pass")
        }
        fn get_upstream_preset_id(&self) -> String {
            self.get_str("upstream_preset_id")
        }
        fn get_upstream_mode(&self) -> String {
            self.get_str("upstream_mode")
        }
        fn get_upstream_udp_enabled(&self) -> bool {
            self.get_bool("upstream_udp_enabled")
        }
        fn get_cloudflare_enabled(&self) -> bool {
            self.get_bool("cloudflare_enabled")
        }
        fn get_cloudflare_domains(&self) -> Vec<String> {
            self.data
                .get("cloudflare_domains")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }
        fn get_cloudflare_worker_enabled(&self) -> bool {
            self.get_bool("cloudflare_worker_enabled")
        }
        fn get_cloudflare_worker_domains(&self) -> Vec<String> {
            self.data
                .get("cloudflare_worker_domains")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }
        fn get_dc_ip(&self) -> Vec<String> {
            self.data
                .get("dc_ip")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    impl TelegramSettingsWriter for TestStore {
        fn set_port(&mut self, value: i64) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("port".into(), value.to_string()));
            Ok(())
        }
        fn set_host(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("host".into(), value.to_string()));
            Ok(())
        }
        fn set_enabled(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("enabled".into(), value.to_string()));
            Ok(())
        }
        fn set_mode(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("mode".into(), value.to_string()));
            Ok(())
        }
        fn set_mtproxy_secret(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("mtproxy_secret".into(), value.to_string()));
            Ok(())
        }
        fn set_dc_ip(&mut self, value: &[String]) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("dc_ip".into(), value.join(",")));
            Ok(())
        }
        fn set_pool_size(&mut self, value: i64) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("pool_size".into(), value.to_string()));
            Ok(())
        }
        fn set_buffer_kb(&mut self, value: i64) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("buffer_kb".into(), value.to_string()));
            Ok(())
        }
        fn set_fake_tls_domain(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("fake_tls_domain".into(), value.to_string()));
            Ok(())
        }
        fn set_proxy_protocol(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("proxy_protocol".into(), value.to_string()));
            Ok(())
        }
        fn set_auto_deeplink(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("auto_deeplink".into(), value.to_string()));
            Ok(())
        }
        fn set_deeplink_done(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("deeplink_done".into(), value.to_string()));
            self.data.insert("deeplink_done".into(), Value::Bool(value));
            Ok(())
        }
        fn set_upstream_enabled(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_enabled".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_mode(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_mode".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_udp_enabled(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_udp_enabled".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_preset_id(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_preset_id".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_host(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_host".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_port(&mut self, value: i64) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_port".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_user(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_user".into(), value.to_string()));
            Ok(())
        }
        fn set_upstream_pass(&mut self, value: &str) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("upstream_pass".into(), value.to_string()));
            Ok(())
        }
        fn set_cloudflare_enabled(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("cloudflare_enabled".into(), value.to_string()));
            Ok(())
        }
        fn set_cloudflare_domains(&mut self, value: &[String]) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("cloudflare_domains".into(), value.join(",")));
            Ok(())
        }
        fn set_cloudflare_worker_enabled(&mut self, value: bool) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("cloudflare_worker_enabled".into(), value.to_string()));
            Ok(())
        }
        fn set_cloudflare_worker_domains(&mut self, value: &[String]) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push(("cloudflare_worker_domains".into(), value.join(",")));
            Ok(())
        }
    }

    fn bundled_preset() -> Value {
        json!({
            "id": "bundled",
            "name": "Готовый прокси",
            "type": "socks5",
            "host": "203.0.113.10",
            "port": 443,
            "username": "preset_user",
            "password": "preset_password",
            "tls": true,
            "tls_server_name": "proxy.example.test",
        })
    }

    fn catalog_with(presets: &[Value]) -> UpstreamCatalog {
        UpstreamCatalog::new(presets)
    }

    fn resolver_with(presets: &[Value]) -> UpstreamPresetResolver {
        UpstreamPresetResolver::new(presets)
    }

    #[test]
    fn normalize_host_matches_python() {
        assert!(validate_host("192.168.1.1"));
        assert!(!validate_host("256.1.1.1"));
        assert!(!validate_host("1.2.3"));
        assert!(!validate_host(""));
        assert_eq!(normalize_host(" 10.0.0.2 "), "10.0.0.2");
        assert_eq!(normalize_host("bad"), DEFAULT_HOST);
        assert_eq!(normalize_host(""), DEFAULT_HOST);
    }

    #[test]
    fn normalize_ports_match_python() {
        let none = || None;
        assert_eq!(normalize_port(none()), DEFAULT_PORT);
        assert_eq!(normalize_port(Some(&Value::Null)), DEFAULT_PORT);
        assert_eq!(normalize_port(Some(&json!(0))), DEFAULT_PORT);
        assert_eq!(normalize_port(Some(&json!(1353))), 1353);
        assert_eq!(normalize_port(Some(&json!(1023))), DEFAULT_PORT);
        assert_eq!(normalize_port(Some(&json!(65535))), 65535);
        assert_eq!(normalize_port(Some(&json!(65536))), DEFAULT_PORT);
        assert_eq!(normalize_port(Some(&json!("7777"))), 7777);

        assert_eq!(normalize_upstream_port(none()), DEFAULT_UPSTREAM_PORT);
        assert_eq!(
            normalize_upstream_port(Some(&json!(0))),
            DEFAULT_UPSTREAM_PORT
        );
        assert_eq!(normalize_upstream_port(Some(&json!(1))), 1);
        assert_eq!(normalize_upstream_port(Some(&json!(1081))), 1081);
        assert_eq!(
            normalize_upstream_port(Some(&json!(65536))),
            DEFAULT_UPSTREAM_PORT
        );
    }

    #[test]
    fn normalize_mode_pool_and_buffer_match_python() {
        assert_eq!(normalize_proxy_mode(&Value::Null), "socks5");
        assert_eq!(normalize_proxy_mode(&json!("  MTPROXY ")), "mtproxy");
        assert_eq!(normalize_proxy_mode(&json!("socks5")), "socks5");
        assert_eq!(normalize_proxy_mode(&json!("x")), "socks5");

        assert_eq!(normalize_pool_size(&Value::Null), 4);
        assert_eq!(normalize_pool_size(&json!(-5)), 0);
        assert_eq!(normalize_pool_size(&json!(0)), 0);
        assert_eq!(normalize_pool_size(&json!(7)), 7);
        assert_eq!(normalize_pool_size(&json!(100)), 32);
        assert_eq!(normalize_pool_size(&json!("8")), 8);

        assert_eq!(normalize_buffer_kb(&Value::Null), 256);
        assert_eq!(normalize_buffer_kb(&json!(1)), 4);
        assert_eq!(normalize_buffer_kb(&json!(256)), 256);
        assert_eq!(normalize_buffer_kb(&json!(100000)), 4096);
        assert_eq!(normalize_buffer_kb(&json!("512")), 512);
    }

    #[test]
    fn proxy_url_matches_python() {
        assert_eq!(
            build_proxy_url("127.0.0.1", 1353, &json!("socks5"), "", ""),
            "tg://socks?server=127.0.0.1&port=1353"
        );
        // Негодный порт и хост приводятся к норме.
        assert_eq!(
            build_proxy_url("10.1.2.3", 99_999, &json!("socks5"), "", ""),
            "tg://socks?server=10.1.2.3&port=1353"
        );
        assert_eq!(
            build_proxy_url("127.0.0.1", 1353, &json!("mtproxy"), "", ""),
            "tg://proxy?server=127.0.0.1&port=1353&secret=dd"
        );
    }

    #[test]
    fn default_state_matches_python() {
        let state = default_state();
        assert_eq!(state.host, "127.0.0.1");
        assert_eq!(state.port, 1353);
        assert_eq!(state.mode, "mtproxy");
        assert!(state.upstream_enabled);
        assert_eq!(state.upstream_port, 1080);
        assert_eq!(state.upstream_mode, "fallback");
        assert!(!state.upstream_udp_enabled);
        assert_eq!(state.pool_size, 4);
        assert_eq!(state.buffer_kb, 256);
        assert!(!state.proxy_protocol);
        assert!(state.auto_deeplink);
        assert!(state.cloudflare_domains.is_empty());
    }

    #[test]
    fn state_from_data_matches_python() {
        let catalog = catalog_with(&[]);
        let data = json!({
            "telegram_proxy": {
                "host": "10.0.0.2",
                "port": 1443,
                "mode": "socks5",
                "upstream_enabled": true,
                "upstream_preset_id": "",
                "upstream_host": "",
                "upstream_port": 1080,
                "upstream_user": "",
                "upstream_pass": "",
                "upstream_mode": "fallback",
                "cloudflare_domains": "a.com, b.com;  c.com ",
                "cloudflare_worker_enabled": true,
                "dc_ip": ["4:1.2.3.4"],
                "pool_size": 9,
                "buffer_kb": 128,
                "fake_tls_domain": "Example.COM",
                "proxy_protocol": true,
                "auto_deeplink": false,
                "mtproxy_secret": "ABCdef0123456789ABCdef0123456789A",
            }
        });
        let state = settings_state_from_data(&data, &catalog);
        assert_eq!(state.host, "10.0.0.2");
        assert_eq!(state.port, 1443);
        assert_eq!(state.mode, "socks5");
        assert_eq!(state.cloudflare_domains, vec!["a.com", "b.com", "c.com"]);
        assert!(state.cloudflare_worker_enabled);
        // Секрет из 33 букв не подходит — он пустой.
        assert_eq!(state.mtproxy_secret, "");
        assert_eq!(state.dc_ip, vec!["4:1.2.3.4"]);
        assert_eq!(state.pool_size, 9);
        assert_eq!(state.buffer_kb, 128);
        assert_eq!(state.fake_tls_domain, "example.com");
        assert!(state.proxy_protocol);
        assert!(!state.auto_deeplink);
    }

    #[test]
    fn empty_data_gives_defaults_with_mtproxy_mode() {
        let catalog = catalog_with(&[]);
        let state = settings_state_from_data(&json!({"telegram_proxy": {}}), &catalog);
        assert_eq!(state, default_state());
        assert_eq!(state.mode, "mtproxy");
    }

    #[test]
    fn preset_index_resolves_from_catalog() {
        let catalog = catalog_with(&[bundled_preset()]);
        let data = json!({
            "telegram_proxy": {
                "upstream_enabled": true,
                "upstream_preset_id": "bundled",
                "upstream_host": "",
                "upstream_port": DEFAULT_UPSTREAM_PORT,
                "upstream_user": "",
                "upstream_pass": "",
                "upstream_mode": "fallback",
            }
        });
        let state = settings_state_from_data(&data, &catalog);
        assert_eq!(state.upstream_preset_id, "bundled");
        assert_eq!(state.upstream_preset_index, 0);

        let manual = settings_state_from_data(
            &json!({"telegram_proxy": {"upstream_preset_id": "manual", "upstream_host": "1.2.3.4", "upstream_port": 1081}}),
            &catalog,
        );
        assert_eq!(manual.upstream_preset_index, 1);
        assert_eq!(manual.upstream_port, 1081);
    }

    #[test]
    fn auto_deeplink_consumed_once_and_only_with_telegram() {
        // Авто-настройка выключена — ссылка не открывается.
        let mut store = TestStore::with(json!({"auto_deeplink": false}));
        assert!(!consume_auto_deeplink_request(&mut store, || true));
        assert_eq!(store.saved.borrow().len(), 0);

        // Включена — ссылка открывается один раз: после отметки повтор нет.
        let mut store = TestStore::with(json!({"auto_deeplink": true}));
        assert!(consume_auto_deeplink_request(&mut store, || true));
        assert_eq!(store.saved.borrow().len(), 1);
        assert!(!consume_auto_deeplink_request(&mut store, || true));

        // Без программы для tg:// ссылка не открывается и отметка не ставится:
        // после установки Telegram она откроется.
        let mut store = TestStore::with(json!({"auto_deeplink": true}));
        assert!(!consume_auto_deeplink_request(&mut store, || false));
        assert_eq!(store.saved.borrow().len(), 0);
        assert!(consume_auto_deeplink_request(&mut store, || true));
    }

    #[test]
    fn default_state_has_auto_deeplink_enabled() {
        let state = settings_state_from_data(
            &json!({"telegram_proxy": {"auto_deeplink": false}}),
            &catalog_with(&[]),
        );
        assert!(!state.auto_deeplink);
        assert!(default_state().auto_deeplink);
    }

    #[test]
    fn upstream_config_none_when_disabled() {
        let store = TestStore::with(json!({"upstream_enabled": false}));
        let resolver = resolver_with(&[bundled_preset()]);
        assert!(build_upstream_config(&store, &resolver).is_none());
        assert!(load_upstream_test_target(&store, &resolver).is_none());
    }

    #[test]
    fn upstream_config_resolves_bundled_preset_credentials() {
        let store = TestStore::with(json!({
            "upstream_enabled": true,
            "upstream_preset_id": "bundled",
            "upstream_host": "",
            "upstream_port": DEFAULT_UPSTREAM_PORT,
            "upstream_user": "",
            "upstream_pass": "",
            "upstream_mode": "fallback",
        }));
        let presets = [bundled_preset()];
        let resolver = resolver_with(&presets);

        let upstream = build_upstream_config(&store, &resolver).unwrap();
        assert_eq!(upstream.host, "203.0.113.10");
        assert_eq!(upstream.port, 443);
        assert_eq!(upstream.username, "preset_user");
        assert_eq!(upstream.password, "preset_password");
        assert!(upstream.tls);
        assert_eq!(upstream.tls_server_name, "proxy.example.test");
        assert!(!upstream.tls_verify);
        assert_eq!(upstream.preset_id, "bundled");
        assert_eq!(upstream.preset_name, "Готовый прокси");

        assert_eq!(
            load_upstream_test_target(&store, &resolver).unwrap(),
            UpstreamTestTarget {
                host: "203.0.113.10".to_string(),
                port: 443,
                username: "preset_user".to_string(),
                password: "preset_password".to_string(),
                tls: true,
                tls_server_name: "proxy.example.test".to_string(),
                tls_verify: false,
            }
        );
    }

    #[test]
    fn empty_upstream_falls_back_to_first_bundled_preset() {
        let store = TestStore::with(json!({
            "upstream_enabled": true,
            "upstream_preset_id": "",
            "upstream_host": "",
            "upstream_port": DEFAULT_UPSTREAM_PORT,
            "upstream_user": "",
            "upstream_pass": "",
            "upstream_mode": "always",
        }));
        let resolver = resolver_with(&[json!({
            "id": "first",
            "name": "Первый прокси",
            "type": "socks5",
            "host": "203.0.113.10",
            "port": 443,
            "username": "preset_user",
            "password": "preset_password",
            "tls": true,
        })]);

        let upstream = build_upstream_config(&store, &resolver).unwrap();
        assert_eq!(upstream.host, "203.0.113.10");
        assert_eq!(upstream.port, 443);
        assert_eq!(upstream.username, "preset_user");
        assert!(upstream.tls);
        assert_eq!(upstream.mode, "always");

        let target = load_upstream_test_target(&store, &resolver).unwrap();
        // SNI без явного значения выведен из пароля пресета.
        assert_eq!(
            target,
            UpstreamTestTarget {
                host: "203.0.113.10".to_string(),
                port: 443,
                username: "preset_user".to_string(),
                password: "preset_password".to_string(),
                tls: true,
                tls_server_name: crate::config::upstream_catalog::derive_bundled_tls_server_name(
                    "preset_password"
                ),
                tls_verify: false,
            }
        );
    }

    #[test]
    fn selected_bundled_preset_gets_other_presets_as_fallbacks() {
        let store = TestStore::with(json!({
            "upstream_enabled": true,
            "upstream_preset_id": "uk",
            "upstream_host": "",
            "upstream_port": DEFAULT_UPSTREAM_PORT,
            "upstream_user": "",
            "upstream_pass": "",
            "upstream_mode": "always",
        }));
        let resolver = resolver_with(&[
            json!({
                "id": "uk", "name": "Великобритания", "type": "socks5",
                "host": "203.0.113.10", "port": 443,
                "username": "uk_user", "password": "uk_password", "tls": true,
            }),
            json!({
                "id": "no", "name": "Норвегия", "type": "socks5",
                "host": "203.0.113.20", "port": 443,
                "username": "no_user", "password": "no_password", "tls": true,
            }),
        ]);

        let upstream = build_upstream_config(&store, &resolver).unwrap();
        assert_eq!(upstream.host, "203.0.113.10");
        assert_eq!(upstream.preset_id, "uk");
        assert_eq!(upstream.preset_name, "Великобритания");
        assert_eq!(upstream.fallback_proxies.len(), 1);
        let fallback = &upstream.fallback_proxies[0];
        assert_eq!(fallback.host, "203.0.113.20");
        assert_eq!(fallback.preset_id, "no");
        assert_eq!(fallback.preset_name, "Норвегия");
        assert_eq!(fallback.username, "no_user");
        assert_eq!(fallback.password, "no_password");
    }

    #[test]
    fn preset_and_manual_saves_write_expected_fields() {
        let mut store = TestStore::default();
        set_upstream_preset("bundled", &mut store);
        assert_eq!(
            store.saved.borrow().clone(),
            vec![
                ("upstream_preset_id".to_string(), "bundled".to_string()),
                ("upstream_host".to_string(), String::new()),
                (
                    "upstream_port".to_string(),
                    DEFAULT_UPSTREAM_PORT.to_string()
                ),
                ("upstream_user".to_string(), String::new()),
                ("upstream_pass".to_string(), String::new()),
            ]
        );

        store.saved.borrow_mut().clear();
        set_manual_upstream(
            "198.51.100.20",
            1081,
            "manual_user",
            "manual_pass",
            &mut store,
        );
        assert_eq!(
            store.saved.borrow().clone(),
            vec![
                ("upstream_preset_id".to_string(), String::new()),
                ("upstream_host".to_string(), "198.51.100.20".to_string()),
                ("upstream_port".to_string(), "1081".to_string()),
                ("upstream_user".to_string(), "manual_user".to_string()),
                ("upstream_pass".to_string(), "manual_pass".to_string()),
            ]
        );
    }

    #[test]
    fn mode_change_touches_only_mode() {
        let mut store = TestStore::default();
        assert_eq!(set_proxy_mode(&json!("mtproxy"), &mut store), "mtproxy");
        assert_eq!(
            store.saved.borrow().clone(),
            vec![("mode".to_string(), "mtproxy".to_string())]
        );
    }

    #[test]
    fn ensure_secret_only_for_mtproxy_mode() {
        let mut store = TestStore::default();
        // SOCKS5 — секрет пустой и ничего не пишется.
        assert_eq!(
            ensure_mtproxy_secret_for_mode(&json!("socks5"), "", &mut store),
            ""
        );
        assert_eq!(store.saved.borrow().len(), 0);
        // MTProxy без секрета — генерируется и сохраняется.
        let generated = ensure_mtproxy_secret_for_mode(&json!("mtproxy"), "", &mut store);
        assert_eq!(generated.len(), 32);
        assert_eq!(store.saved.borrow().len(), 1);
        // Готовый секрет остаётся как есть.
        // Негодный секрет (33 буквы) заменяется сгенерированным.
        assert_eq!(
            ensure_mtproxy_secret_for_mode(
                &json!("mtproxy"),
                "ABCdef0123456789ABCdef0123456789A",
                &mut store
            )
            .len(),
            32
        );
        // Секрет из 32 шестнадцатеричных букв остаётся как есть.
        assert_eq!(
            ensure_mtproxy_secret_for_mode(
                &json!("mtproxy"),
                "ABCdef0123456789ABCdef0123456789",
                &mut store
            ),
            "abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn cloudflare_config_from_store() {
        // Выключено — пустой конфиг.
        let store = TestStore::with(json!({"cloudflare_enabled": false}));
        assert_eq!(
            build_cloudflare_config(&store),
            CloudflareFallbackConfig::default()
        );

        // Включено без своих доменов — встроенные фронты.
        let store = TestStore::with(json!({"cloudflare_enabled": true}));
        let config = build_cloudflare_config(&store);
        assert!(config.enabled);
        assert_eq!(config.domains, auto_cloudflare_domains());

        // Воркер без своих доменов не включается.
        let store = TestStore::with(json!({
            "cloudflare_enabled": true,
            "cloudflare_domains": ["my.example.com"],
            "cloudflare_worker_enabled": true,
        }));
        let config = build_cloudflare_config(&store);
        assert_eq!(config.domains, vec!["my.example.com"]);
        assert!(!config.worker_enabled);
        assert!(config.worker_domains.is_empty());

        let store = TestStore::with(json!({
            "cloudflare_enabled": true,
            "cloudflare_domains": ["my.example.com"],
            "cloudflare_worker_enabled": true,
            "cloudflare_worker_domains": ["worker.example.com"],
        }));
        let config = build_cloudflare_config(&store);
        assert!(config.worker_enabled);
        assert_eq!(config.worker_domains, vec!["worker.example.com"]);
    }

    #[test]
    fn dc_overrides_from_store() {
        let store = TestStore::with(json!({"dc_ip": ["4:1.2.3.4", "bogus", "203:149.154.167.99"]}));
        let overrides = build_dc_endpoint_overrides(&store);
        assert_eq!(
            overrides,
            vec![
                (4, "1.2.3.4".to_string()),
                (203, "149.154.167.99".to_string())
            ]
        );
    }

    #[test]
    fn setters_normalize_before_store() {
        let mut store = TestStore::default();
        assert_eq!(set_port(70000, &mut store), DEFAULT_PORT);
        assert_eq!(set_host(" bad ", &mut store), DEFAULT_HOST);
        assert_eq!(set_pool_size(&json!(99), &mut store), 32);
        assert_eq!(set_buffer_kb(&json!(1), &mut store), 4);
        assert_eq!(
            set_fake_tls_domain("Example.COM", &mut store),
            "example.com"
        );
        assert_eq!(
            set_dc_ip(&json!("4:1.2.3.4"), &mut store),
            vec!["4:1.2.3.4".to_string()]
        );
        assert_eq!(
            set_cloudflare_domains(&json!("a.com, b.com"), &mut store),
            vec!["a.com".to_string(), "b.com".to_string()]
        );
        let saved = store.saved.borrow().clone();
        assert_eq!(saved[0], ("port".to_string(), DEFAULT_PORT.to_string()));
        assert!(saved.iter().any(|(name, _)| name == "pool_size"));
    }

    #[test]
    fn upstream_mode_switch_saves_store_value() {
        let mut store = TestStore::default();
        set_upstream_mode(true, &mut store);
        set_upstream_mode(false, &mut store);
        let saved = store.saved.borrow().clone();
        assert_eq!(
            saved[0],
            ("upstream_mode".to_string(), "always".to_string())
        );
        assert_eq!(
            saved[1],
            ("upstream_mode".to_string(), "fallback".to_string())
        );
    }

    #[test]
    fn page_initial_state_reads_store() {
        let store = TestStore::with(json!({"port": 1444, "mode": "socks5"}));
        let plan = load_page_initial_state(&store, &BuildSecrets::default());
        assert_eq!(plan.settings.port, 1444);
        assert_eq!(plan.settings.mode, "socks5");
        assert!(!plan.upstream_catalog.has_bundled_presets());
    }

    #[test]
    fn restart_requests_merge_by_priority() {
        assert_eq!(normalize_restart_request(" NOW "), "now");
        assert_eq!(normalize_restart_request("bogus"), "");
        assert_eq!(merge_restart_request("", "now"), "now");
        assert_eq!(merge_restart_request("now", ""), "now");
        // Немедленный полный рестарт сильнее debounced upstream-замены...
        assert_eq!(merge_restart_request("schedule", "upstream"), "schedule");
        assert_eq!(merge_restart_request("upstream", "schedule"), "schedule");
        // ...а немедленная upstream-замена сильнее upstream_schedule.
        assert_eq!(
            merge_restart_request("upstream_schedule", "upstream"),
            "upstream"
        );
        assert_eq!(
            merge_restart_request("upstream", "upstream_schedule"),
            "upstream"
        );
        // Рестарт-семейство сильнее горячей замены upstream.
        assert_eq!(merge_restart_request("now", "upstream"), "now");
        assert_eq!(merge_restart_request("upstream", "now"), "now");
    }

    #[test]
    fn socks5_preset_fields_match() {
        let resolver = resolver_with(&[bundled_preset()]);
        let preset = resolver.socks5_by_id("bundled").unwrap();
        assert_eq!(
            preset,
            Socks5Preset {
                id: "bundled".to_string(),
                name: "Готовый прокси".to_string(),
                host: "203.0.113.10".to_string(),
                port: 443,
                username: "preset_user".to_string(),
                password: "preset_password".to_string(),
                tls: true,
                tls_server_name: "proxy.example.test".to_string(),
                tls_verify: false,
            }
        );
    }
}
