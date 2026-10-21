//! Каталог внешних прокси для Telegram Proxy: список собирается только из
//! build-секретов программы.
//!
//! Порт `telegram_proxy/config/upstream_catalog.py`. Контракт:
//! - выбираемый список прокси приходит только из секретов сборки;
//! - ручной ввод — отдельный режим интерфейса и в каталог не входит;
//! - реестра прокси на время работы не ведётся.
//!
//! Пресеты python держит словарями — здесь они `serde_json::Value`, чтобы
//! семантика `get`/дефолтов и дедупликации повторялась один в один. Чтение
//! секретов сборки (python `config._build_secrets`) — ввод вызывающего кода:
//! он передаётся структурой [`BuildSecrets`].

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::crypto::sha256;

/// Идентификатор варианта «Ручной ввод».
pub const MANUAL_PRESET_ID: &str = "manual";

/// Префикс выведения SNI встроенного TLS-прокси.
const SNI_DERIVATION_PREFIX: &[u8] = b"zapret-socks-sni-v1\0";

/// Секреты сборки (python `config._build_secrets`): ввод вызывающего кода.
#[derive(Debug, Default, Clone)]
pub struct BuildSecrets {
    /// python `PROXY_PRESETS` — список пресетов socks5/mtproxy.
    pub proxy_presets: Option<Value>,
    /// python `MTPROXY_LINK` — ссылка встроенного MTProxy.
    pub mtproxy_link: Option<String>,
}

/// python `str(value)`: так python превращает JSON-значение в строку.
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

/// python-истинность значения (пустая строка, 0, `None`, `False` — ложь).
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

/// python `str(value or "").strip()` — пусто для ложных значений.
#[must_use]
fn or_empty_str(value: &Value) -> String {
    if py_truthy(value) {
        py_str(value).trim().to_string()
    } else {
        String::new()
    }
}

/// python `str(value or fallback).strip()`.
#[must_use]
fn or_fallback_str(value: &Value, fallback: &str) -> String {
    let text = or_empty_str(value);
    if text.is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

/// Поле пресета как python `preset.get(key)`.
#[must_use]
fn preset_get<'a>(preset: &'a Value, key: &str) -> &'a Value {
    preset
        .as_object()
        .and_then(|fields| fields.get(key))
        .unwrap_or(&Value::Null)
}

/// Поле пресета как python `str(preset.get(key) or "").strip()`.
#[must_use]
fn preset_str(preset: &Value, key: &str) -> String {
    or_empty_str(preset_get(preset, key))
}

/// Поле пресета как python `bool(preset.get(key, False))`.
#[must_use]
fn preset_bool(preset: &Value, key: &str) -> bool {
    preset_get(preset, key).as_bool().unwrap_or(false)
}

/// python `_coerce_port`: порт вне 0..=65535 или не число — 0.
#[must_use]
pub fn coerce_port(value: &Value) -> i64 {
    let number = match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float as i64)),
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    };
    match number {
        Some(port) if (0..=65535).contains(&port) => port,
        _ => 0,
    }
}

/// Выводит закрытый SNI, не храня второй секрет в каталоге сборки.
#[must_use]
pub fn derive_bundled_tls_server_name(password: &str) -> String {
    let digest = sha256(&[SNI_DERIVATION_PREFIX, password.as_bytes()]);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}.invalid", &hex[..32])
}

/// python `_normalize_name`.
#[must_use]
fn normalize_name(value: &Value, fallback: &str) -> String {
    or_fallback_str(value, fallback)
}

/// Приводит сырой пресет сборки к каноническому виду; негодный — `None`.
#[must_use]
pub fn normalize_upstream_preset(
    raw: Option<&Value>,
    fallback_name: &str,
    fallback_id: &str,
    source: &str,
) -> Option<Value> {
    let raw = raw?;
    let fields = raw.as_object()?;

    let preset_type =
        or_fallback_str(fields.get("type").unwrap_or(&Value::Null), "socks5").to_lowercase();
    let preset_type = if preset_type.is_empty() {
        "socks5".to_string()
    } else {
        preset_type
    };
    let preset_id = {
        let text = or_fallback_str(fields.get("id").unwrap_or(&Value::Null), fallback_id);
        if text.is_empty() {
            fallback_id.to_string()
        } else {
            text
        }
    };

    let mut preset = Map::new();
    preset.insert("id".to_string(), Value::String(preset_id));
    preset.insert(
        "name".to_string(),
        Value::String(normalize_name(
            fields.get("name").unwrap_or(&Value::Null),
            fallback_name,
        )),
    );
    preset.insert("type".to_string(), Value::String(preset_type.clone()));
    preset.insert("source".to_string(), Value::String(source.to_string()));

    if preset_type == "mtproxy" {
        let link = or_empty_str(fields.get("link").unwrap_or(&Value::Null));
        if link.is_empty() {
            return None;
        }
        preset.insert("link".to_string(), Value::String(link));
        return Some(Value::Object(preset));
    }
    if preset_type != "socks5" {
        return None;
    }

    let host = or_empty_str(fields.get("host").unwrap_or(&Value::Null));
    let port = coerce_port(fields.get("port").unwrap_or(&Value::Null));
    if host.is_empty() || port <= 0 {
        return None;
    }

    let password = or_empty_str(fields.get("password").unwrap_or(&Value::Null));
    let tls = fields.get("tls").is_some_and(py_truthy);
    let mut tls_server_name = or_empty_str(fields.get("tls_server_name").unwrap_or(&Value::Null));
    if source == "build" && tls && !password.is_empty() && tls_server_name.is_empty() {
        tls_server_name = derive_bundled_tls_server_name(&password);
    }

    preset.insert("host".to_string(), Value::String(host));
    preset.insert("port".to_string(), Value::from(port));
    preset.insert(
        "username".to_string(),
        Value::String(or_empty_str(fields.get("username").unwrap_or(&Value::Null))),
    );
    preset.insert("password".to_string(), Value::String(password));
    preset.insert("tls".to_string(), Value::Bool(tls));
    preset.insert(
        "tls_server_name".to_string(),
        Value::String(tls_server_name),
    );
    preset.insert(
        "tls_verify".to_string(),
        Value::Bool(fields.get("tls_verify").is_some_and(py_truthy)),
    );
    Some(Value::Object(preset))
}

/// Ключ дедупликации пресета: `None` для типов, кроме socks5/mtproxy.
#[must_use]
fn preset_identity_key(preset: &Value) -> Option<Value> {
    let preset_type = {
        let text = preset_str(preset, "type");
        if text.is_empty() {
            "socks5".to_string()
        } else {
            text
        }
    };
    if preset_type == "mtproxy" {
        return Some(Value::String(format!(
            "mtproxy:{}",
            preset_str(preset, "link")
        )));
    }
    if preset_type != "socks5" {
        return None;
    }
    Some(serde_json::json!([
        preset_str(preset, "host").to_lowercase(),
        coerce_port(preset_get(preset, "port")),
        preset_str(preset, "username"),
        preset_str(preset, "password"),
        preset_bool(preset, "tls"),
        preset_str(preset, "tls_server_name").to_lowercase(),
        preset_bool(preset, "tls_verify"),
    ]))
}

/// Безопасный вариант выбора: только идентификатор, имя и тип.
#[must_use]
fn safe_choice_from_preset(preset: &Value) -> Value {
    let mut choice = Map::new();
    choice.insert("id".to_string(), Value::String(preset_str(preset, "id")));
    choice.insert(
        "name".to_string(),
        Value::String(normalize_name(preset_get(preset, "name"), "Прокси")),
    );
    let preset_type = preset_str(preset, "type").to_lowercase();
    choice.insert(
        "type".to_string(),
        Value::String(if preset_type.is_empty() {
            "socks5".to_string()
        } else {
            preset_type
        }),
    );
    Value::Object(choice)
}

/// Читает пресеты из секретов сборки (python `_load_build_upstream_presets`).
#[must_use]
pub fn load_build_upstream_presets(secrets: &BuildSecrets) -> Vec<Value> {
    let mut presets: Vec<Value> = Vec::new();

    if let Some(Value::Array(raw_presets)) = &secrets.proxy_presets {
        for (index, raw) in raw_presets.iter().enumerate() {
            if let Some(preset) = normalize_upstream_preset(
                Some(raw),
                &format!("Прокси {}", index + 1),
                &format!("build:{}", index + 1),
                "build",
            ) {
                presets.push(preset);
            }
        }
    }

    if let Some(link) = &secrets.mtproxy_link {
        if !link.is_empty()
            && !presets
                .iter()
                .any(|preset| preset_str(preset, "type") == "mtproxy")
        {
            let raw = serde_json::json!({
                "id": "build:mtproxy",
                "name": "MTProxy",
                "type": "mtproxy",
                "link": link,
            });
            if let Some(preset) =
                normalize_upstream_preset(Some(&raw), "MTProxy", "build:mtproxy", "build")
            {
                presets.push(preset);
            }
        }
    }

    presets
}

/// python `_build_choice_list`: уникальные пресеты плюс «Ручной ввод».
#[must_use]
fn build_choice_list(build_presets: &[Value]) -> Vec<Value> {
    let mut choices: Vec<Value> = Vec::new();
    let mut seen: Vec<Value> = Vec::new();

    for preset in build_presets {
        let Some(normalized) = normalize_upstream_preset(
            Some(preset),
            "Прокси",
            &or_fallback_str(preset_get(preset, "id"), "build"),
            &or_fallback_str(preset_get(preset, "source"), "build"),
        ) else {
            continue;
        };
        let Some(key) = preset_identity_key(&normalized) else {
            continue;
        };
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        choices.push(safe_choice_from_preset(&normalized));
    }

    choices.push(serde_json::json!({
        "id": MANUAL_PRESET_ID,
        "name": "Ручной ввод",
        "type": "socks5",
    }));

    choices
}

/// Подпись пресета для выпадающего списка.
#[must_use]
pub fn format_preset_label(preset: &Value) -> String {
    let base_name = {
        let text = preset_str(preset, "name");
        if text.is_empty() {
            "Прокси".to_string()
        } else {
            text
        }
    };
    if preset_str(preset, "type") == "mtproxy" {
        return format!("{base_name} (MTProxy)");
    }
    base_name
}

/// Каталог вариантов прокси для страницы.
#[derive(Debug, Clone, Default)]
pub struct UpstreamCatalog {
    /// Варианты списка: пресеты сборки и последним — «Ручной ввод».
    pub choices: Vec<Value>,
}

impl UpstreamCatalog {
    /// Каталог из пресетов сборки.
    #[must_use]
    pub fn new(build_presets: &[Value]) -> Self {
        Self {
            choices: build_choice_list(build_presets),
        }
    }

    /// Каталог из секретов сборки (python `load_from_runtime`).
    #[must_use]
    pub fn load_from_runtime(secrets: &BuildSecrets) -> Self {
        Self::new(&load_build_upstream_presets(secrets))
    }

    /// Есть ли в каталоге что-то, кроме «Ручного ввода».
    #[must_use]
    pub fn has_bundled_presets(&self) -> bool {
        self.choices
            .iter()
            .any(|preset| preset_str(preset, "id") != MANUAL_PRESET_ID)
    }

    /// Варианты с подписями (python `items`).
    #[must_use]
    pub fn items(&self) -> Vec<(String, &Value)> {
        self.choices
            .iter()
            .map(|preset| (format_preset_label(preset), preset))
            .collect()
    }

    /// Пресет по позиции списка.
    #[must_use]
    pub fn preset_at(&self, index: usize) -> Option<&Value> {
        self.choices.get(index)
    }

    /// Пресет по идентификатору.
    #[must_use]
    pub fn preset_by_id(&self, preset_id: &str) -> Option<&Value> {
        let target_id = preset_id.trim();
        if target_id.is_empty() {
            return None;
        }
        self.choices
            .iter()
            .find(|preset| preset_str(preset, "id") == target_id)
    }

    /// Позиция выбранного варианта в списке.
    ///
    /// `host` и `preset_id` — как в python; порт, логин и пароль в выборе
    /// позиции не участвуют.
    #[must_use]
    pub fn find_choice_index(&self, host: &str, preset_id: &str) -> usize {
        let target_id = preset_id.trim();
        if !target_id.is_empty() {
            for (index, preset) in self.choices.iter().enumerate() {
                if preset_str(preset, "id") == target_id {
                    return index;
                }
            }
        }
        if !host.trim().is_empty() {
            for (index, preset) in self.choices.iter().enumerate() {
                if preset_str(preset, "id") == MANUAL_PRESET_ID {
                    return index;
                }
            }
        }
        0
    }

    /// Это позиция «Ручного ввода»?
    #[must_use]
    pub fn is_manual(&self, index: usize) -> bool {
        self.preset_at(index)
            .is_some_and(|preset| preset_str(preset, "id") == MANUAL_PRESET_ID)
    }

    /// Это позиция MTProxy-пресета?
    #[must_use]
    pub fn is_mtproxy(&self, index: usize) -> bool {
        self.preset_at(index)
            .is_some_and(|preset| preset_str(preset, "type") == "mtproxy")
    }
}

/// Разрешённый socks5-пресет: все поля с дефолтами (python `_socks5_from_preset`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Preset {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub tls_server_name: String,
    pub tls_verify: bool,
}

/// Цель проверки внешнего прокси (python-кортеж `test_target_by_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTestTarget {
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub tls_server_name: String,
    pub tls_verify: bool,
}

/// Разрешитель пресетов сборки: полные данные вместо «безопасного» выбора.
#[derive(Debug, Clone, Default)]
pub struct UpstreamPresetResolver {
    presets: Vec<Value>,
    by_id: HashMap<String, Value>,
}

impl UpstreamPresetResolver {
    /// Разрешитель из пресетов сборки.
    #[must_use]
    pub fn new(build_presets: &[Value]) -> Self {
        let mut presets: Vec<Value> = Vec::new();
        let mut seen: Vec<Value> = Vec::new();
        for preset in build_presets {
            let Some(normalized) = normalize_upstream_preset(
                Some(preset),
                "Прокси",
                &preset_str(preset, "id"),
                &or_fallback_str(preset_get(preset, "source"), "build"),
            ) else {
                continue;
            };
            let Some(key) = preset_identity_key(&normalized) else {
                continue;
            };
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            presets.push(normalized);
        }
        let by_id = presets
            .iter()
            .map(|preset| (preset_str(preset, "id"), preset.clone()))
            .collect();
        Self { presets, by_id }
    }

    /// Разрешитель из секретов сборки (python `load_from_runtime`).
    #[must_use]
    pub fn load_from_runtime(secrets: &BuildSecrets) -> Self {
        Self::new(&load_build_upstream_presets(secrets))
    }

    fn socks5_from_preset(preset: &Value) -> Option<Socks5Preset> {
        let host = preset_str(preset, "host");
        let port = coerce_port(preset_get(preset, "port"));
        if host.is_empty() || port <= 0 {
            return None;
        }
        Some(Socks5Preset {
            id: preset_str(preset, "id"),
            name: normalize_name(preset_get(preset, "name"), "Прокси"),
            host,
            port,
            username: preset_str(preset, "username"),
            password: preset_str(preset, "password"),
            tls: preset_bool(preset, "tls"),
            tls_server_name: preset_str(preset, "tls_server_name"),
            tls_verify: preset_bool(preset, "tls_verify"),
        })
    }

    /// socks5-пресет по идентификатору.
    #[must_use]
    pub fn socks5_by_id(&self, preset_id: &str) -> Option<Socks5Preset> {
        let preset = self.by_id.get(preset_id.trim())?;
        if preset_str(preset, "type") != "socks5" {
            return None;
        }
        Self::socks5_from_preset(preset)
    }

    /// Остальные socks5-пресеты как запасные (в порядке каталога).
    #[must_use]
    pub fn socks5_fallbacks(&self, primary_preset_id: &str) -> Vec<Socks5Preset> {
        let primary_id = primary_preset_id.trim();
        let mut fallbacks: Vec<Socks5Preset> = Vec::new();
        for preset in &self.presets {
            if preset_str(preset, "type") != "socks5" {
                continue;
            }
            if !primary_id.is_empty() && preset_str(preset, "id") == primary_id {
                continue;
            }
            if let Some(resolved) = Self::socks5_from_preset(preset) {
                fallbacks.push(resolved);
            }
        }
        fallbacks
    }

    /// Первый socks5-пресет каталога.
    #[must_use]
    pub fn first_socks5(&self) -> Option<Socks5Preset> {
        self.presets
            .iter()
            .find(|preset| preset_str(preset, "type") == "socks5")
            .and_then(Self::socks5_from_preset)
    }

    /// Ссылка MTProxy-пресета по идентификатору (пусто, если это не mtproxy).
    #[must_use]
    pub fn mtproxy_link_by_id(&self, preset_id: &str) -> String {
        let Some(preset) = self.by_id.get(preset_id.trim()) else {
            return String::new();
        };
        if preset_str(preset, "type") != "mtproxy" {
            return String::new();
        }
        preset_str(preset, "link")
    }

    /// Цель проверки внешнего прокси по идентификатору.
    #[must_use]
    pub fn test_target_by_id(&self, preset_id: &str) -> Option<UpstreamTestTarget> {
        let preset = self.socks5_by_id(preset_id)?;
        Some(UpstreamTestTarget {
            host: preset.host,
            port: preset.port,
            username: preset.username,
            password: preset.password,
            tls: preset.tls,
            tls_server_name: preset.tls_server_name,
            tls_verify: preset.tls_verify,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bundled() -> Value {
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

    #[test]
    fn bundled_socks_proxy_is_first_choice_and_choice_hides_credentials() {
        let catalog = UpstreamCatalog::new(&[bundled()]);

        assert_eq!(catalog.choices[0]["id"], "bundled");
        assert_eq!(catalog.choices[0]["name"], "Готовый прокси");
        // В выборе только id, имя и тип — без host, username и password.
        let choice = catalog.choices[0].as_object().unwrap();
        assert_eq!(choice.len(), 3);
        assert!(!choice.contains_key("host"));
        assert!(!choice.contains_key("username"));
        assert!(!choice.contains_key("password"));
        assert_eq!(catalog.choices[1]["id"], MANUAL_PRESET_ID);
        assert!(catalog.is_manual(1));
        assert!(!catalog.is_mtproxy(0));
        assert!(catalog.has_bundled_presets());
    }

    #[test]
    fn bundled_tls_without_explicit_sni_derives_one_from_password() {
        assert_eq!(
            derive_bundled_tls_server_name("preset_password"),
            "8333870ca40a40c6f84b65ecd3090e7a.invalid"
        );
        assert_eq!(
            derive_bundled_tls_server_name("private_password_for_tls_sni"),
            "5a74dd877d6d4f918a407147b1172c7e.invalid"
        );
        assert_eq!(
            derive_bundled_tls_server_name(""),
            "f07aaaba3d49194989e57443e44331fd.invalid"
        );

        let resolver = UpstreamPresetResolver::new(&[json!({
            "id": "derived-sni",
            "name": "Derived SNI",
            "type": "socks5",
            "host": "203.0.113.10",
            "port": 9443,
            "username": "preset_user",
            "password": "private_password_for_tls_sni",
            "tls": true,
        })]);
        let preset = resolver.socks5_by_id("derived-sni").unwrap();
        assert_eq!(
            preset.tls_server_name,
            derive_bundled_tls_server_name("private_password_for_tls_sni")
        );
        assert!(preset.tls_server_name.ends_with(".invalid"));
    }

    #[test]
    fn catalog_preserves_source_order() {
        let fixture = [
            json!({
                "id": "de1", "name": "Германия 1", "type": "socks5",
                "host": "198.51.100.30", "port": 9443,
                "username": "germany_user", "password": "germany_password",
                "tls": true, "tls_server_name": "proxy.example.test", "tls_verify": true,
            }),
            json!({
                "id": "uk", "name": "Великобритания", "type": "socks5",
                "host": "203.0.113.10", "port": 443,
                "username": "preset_user", "password": "preset_password",
                "tls": true,
            }),
        ];
        let catalog = UpstreamCatalog::new(&fixture);
        let resolver = UpstreamPresetResolver::new(&fixture);

        assert_eq!(catalog.choices[0]["id"], "de1");
        assert_eq!(catalog.choices[1]["id"], "uk");
        assert!(!catalog.is_mtproxy(0));
        assert_eq!(resolver.first_socks5().unwrap().id, "de1");
        let de1 = resolver.socks5_by_id("de1").unwrap();
        assert_eq!(de1.tls_server_name, "proxy.example.test");
        assert!(de1.tls_verify);
        assert_eq!(resolver.socks5_fallbacks("de1")[0].id, "uk");
        assert_eq!(
            resolver.test_target_by_id("de1").unwrap(),
            UpstreamTestTarget {
                host: "198.51.100.30".to_string(),
                port: 9443,
                username: "germany_user".to_string(),
                password: "germany_password".to_string(),
                tls: true,
                tls_server_name: "proxy.example.test".to_string(),
                tls_verify: true,
            }
        );
    }

    #[test]
    fn mtproxy_preset_and_dedupe() {
        let fixture = [
            json!({"id": "mt", "name": "Релей", "type": "mtproxy", "link": "https://t.me/proxy?server=x"}),
            json!({"id": "mt2", "name": "Релей копия", "type": "mtproxy", "link": "https://t.me/proxy?server=x"}),
            json!({"id": "bad", "type": "socks5", "host": "", "port": 443}),
            json!({"id": "weird", "type": "http", "host": "1.2.3.4", "port": 80}),
        ];
        let catalog = UpstreamCatalog::new(&fixture);
        // Второй mtproxy с той же ссылкой выкинут дедупликацией, битые пресеты тоже.
        assert_eq!(catalog.choices.len(), 2);
        assert_eq!(catalog.choices[0]["id"], "mt");
        assert_eq!(format_preset_label(&catalog.choices[0]), "Релей (MTProxy)");
        assert!(catalog.is_mtproxy(0));
        assert!(!catalog.is_manual(0));

        let resolver = UpstreamPresetResolver::new(&fixture);
        assert_eq!(
            resolver.mtproxy_link_by_id("mt"),
            "https://t.me/proxy?server=x"
        );
        assert_eq!(resolver.mtproxy_link_by_id("weird"), "");
        assert_eq!(resolver.socks5_by_id("weird"), None);
        assert_eq!(resolver.first_socks5(), None);
    }

    #[test]
    fn coerce_port_matches_python() {
        assert_eq!(coerce_port(&json!(443)), 443);
        assert_eq!(coerce_port(&json!("443")), 443);
        assert_eq!(coerce_port(&json!(0)), 0);
        assert_eq!(coerce_port(&json!(65535)), 65535);
        assert_eq!(coerce_port(&json!(65536)), 0);
        assert_eq!(coerce_port(&json!(-1)), 0);
        assert_eq!(coerce_port(&Value::Null), 0);
        assert_eq!(coerce_port(&json!("abc")), 0);
        assert_eq!(coerce_port(&json!(true)), 1);
    }

    #[test]
    fn build_secrets_become_presets() {
        let secrets = BuildSecrets {
            proxy_presets: Some(json!([
                {"id": "de1", "name": "Германия 1", "type": "socks5", "host": "198.51.100.30", "port": "9443"},
            ])),
            mtproxy_link: Some("tg://proxy?server=1.2.3.4&port=443&secret=ddabc".to_string()),
        };
        let presets = load_build_upstream_presets(&secrets);
        assert_eq!(presets.len(), 2);
        assert_eq!(presets[0]["id"], "de1");
        assert_eq!(presets[0]["port"], 9443);
        assert_eq!(presets[0]["source"], "build");
        assert_eq!(presets[1]["id"], "build:mtproxy");
        assert_eq!(presets[1]["type"], "mtproxy");

        let catalog = UpstreamCatalog::load_from_runtime(&secrets);
        // Список: socks5-пресет, MTProxy-пресет, последним — «Ручной ввод».
        assert_eq!(catalog.choices.len(), 3);
        assert_eq!(catalog.find_choice_index("", "de1"), 0);
        assert_eq!(catalog.find_choice_index("", "manual"), 2);
        assert_eq!(catalog.items()[2].0, "Ручной ввод");
        // Пустые секреты дают один «Ручной ввод».
        assert_eq!(
            UpstreamCatalog::load_from_runtime(&BuildSecrets::default())
                .choices
                .len(),
            1
        );
    }

    #[test]
    fn find_choice_index_prefers_preset_then_manual_by_host() {
        let catalog = UpstreamCatalog::new(&[bundled()]);
        assert_eq!(catalog.find_choice_index("", "bundled"), 0);
        // Ручной ввод по host: у пользователя прописан свой сервер.
        assert_eq!(catalog.find_choice_index("1.2.3.4", ""), 1);
        // Неизвестный preset_id и пустой host — первый вариант.
        assert_eq!(catalog.find_choice_index("", "unknown"), 0);
        // Пресет по host: первый вариант списка.
        assert!(catalog.preset_by_id("bundled").is_some());
        assert!(catalog.preset_by_id("").is_none());
        assert!(catalog.preset_at(9).is_none());
        assert_eq!(catalog.items()[1].0, "Ручной ввод");
        assert_eq!(catalog.items()[0].0, "Готовый прокси");
    }
}
