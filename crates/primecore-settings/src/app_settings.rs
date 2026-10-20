//! Порт `src/settings/normalize.py` — нормализация всех секций настроек.
//! Локальные части из других модулей, которые settings тянет напрямую:
//! `fakes.user_fakes.normalize_user_fake_row`, `folders.store.normalize_folder_state`,
//! `profile.identity.normalize_identity_registry`.

use serde_json::Value::{Array, Null, Object, String as JString};
use serde_json::{Map, Value};

use crate::normalize::{
    as_bool, as_clean_str, as_dict, as_int, as_nullable_int, as_nullable_str, as_str, as_str_in,
    normalize_custom_dns_servers, normalize_domain, normalize_hex_secret, normalize_lookup_key,
    unique_dc_ip_list, unique_domain_list, unique_int_list, unique_str_list,
};
use crate::schema;

fn obj(value: &Value) -> Map<String, Value> {
    as_dict(value)
}

/// bool(value) в python-смысле: любая непустая строка/список/объект True.
fn truthy(value: &Value) -> bool {
    match value {
        Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(nr) => nr.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// python str(value): строка как есть, число — repr, bool — True/False,
/// остальные (None/список/словарь) — как python repr. Для секции настроек
/// числа/булы-значений достаточно; сложные структуры не встречаются.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(nr) => nr.to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        _ => String::new(),
    }
}

/// python `str(value or "")`: falsy-значения (пустая строка, 0, false, null)
/// превращаются в "", остальное — python_str.
fn python_str_or_empty(value: &Value) -> String {
    if truthy(value) {
        python_str(value)
    } else {
        String::new()
    }
}

/// python `float(value)` как попытка: None для нечитаемого.
fn py_float_option(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    match value {
        Value::Number(nr) => nr.as_f64(),
        Value::Bool(true) => Some(1.0),
        Value::Bool(false) => Some(0.0),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// python `float(value or 0.0)` с except-фолбэком 0.0 (updater-поля).
fn py_float_or_zero(value: Option<&Value>) -> f64 {
    py_float_option(value).unwrap_or(0.0)
}

fn max_0(f: f64) -> f64 {
    if f < 0.0 {
        0.0
    } else {
        f
    }
}

/// python `value[:limit]` по символам.
fn chars_limit(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn str_in(list: &[&str], text: &str) -> bool {
    list.contains(&text)
}

fn vec_json(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(JString).collect())
}

fn vec_i_json(items: Vec<i64>) -> Value {
    Value::Array(items.iter().map(|n| Value::from(*n)).collect())
}

#[allow(dead_code)]
fn default_str(default: &Value, key: &str) -> String {
    default
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[allow(dead_code)]
fn default_str_or(default: &Value, key: &str, fallback: &str) -> String {
    default
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

#[allow(dead_code)]
fn default_i64(default: &Value, key: &str) -> i64 {
    default.get(key).and_then(Value::as_i64).unwrap_or(0)
}

// ------------------------------------------------------------- program

pub fn normalize_program(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_program();
    let flag = |key: &str| {
        as_bool(
            raw.get(key).unwrap_or(&Null),
            default.get(key).and_then(Value::as_bool).unwrap_or(false),
        )
    };
    const KEY1: &str = "selected_source_preset_file_name_winws1";
    const KEY2: &str = "selected_source_preset_file_name_winws2";
    Object(Map::from_iter([
        ("dpi_autostart".into(), Value::Bool(flag("dpi_autostart"))),
        (
            "gui_autostart_enabled".into(),
            Value::Bool(flag("gui_autostart_enabled")),
        ),
        (
            "strategy_launch_method".into(),
            JString(as_str_in(
                raw.get("strategy_launch_method").unwrap_or(&Null),
                schema::VALID_LAUNCH_METHODS,
                "zapret2_mode",
            )),
        ),
        (
            KEY1.into(),
            Value::String(as_clean_str(raw.get(KEY1).unwrap_or(&Null), "")),
        ),
        (
            KEY2.into(),
            Value::String(as_clean_str(raw.get(KEY2).unwrap_or(&Null), "")),
        ),
        (
            "auto_update_enabled".into(),
            Value::Bool(flag("auto_update_enabled")),
        ),
        (
            "discord_auto_restart".into(),
            Value::Bool(flag("discord_auto_restart")),
        ),
        ("max_blocked".into(), Value::Bool(flag("max_blocked"))),
        (
            "russian_state_media_blocked".into(),
            Value::Bool(flag("russian_state_media_blocked")),
        ),
        (
            "defender_disabled".into(),
            Value::Bool(flag("defender_disabled")),
        ),
        (
            "last_seen_version".into(),
            Value::String(as_clean_str(
                raw.get("last_seen_version").unwrap_or(&Null),
                "",
            )),
        ),
    ]))
}

// -------------------------------------------------------------- window

pub fn normalize_window(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_window();
    let nullable = |key: &str| {
        as_nullable_int(raw.get(key).unwrap_or(&Null))
            .map(Value::from)
            .unwrap_or(Null)
    };
    Object(Map::from_iter([
        ("x".into(), nullable("x")),
        ("y".into(), nullable("y")),
        ("width".into(), nullable("width")),
        ("height".into(), nullable("height")),
        (
            "maximized".into(),
            Value::Bool(as_bool(
                raw.get("maximized").unwrap_or(&Null),
                default
                    .get("maximized")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )),
        ),
        (
            "opacity".into(),
            Value::from(as_int(
                raw.get("opacity").unwrap_or(&Null),
                default
                    .get("opacity")
                    .and_then(Value::as_i64)
                    .unwrap_or(100),
                Some(0),
                Some(100),
            )),
        ),
        (
            "tray_close_mode".into(),
            JString(as_str_in(
                raw.get("tray_close_mode").unwrap_or(&Null),
                &schema::VALID_TRAY_CLOSE_MODES,
                "normal",
            )),
        ),
    ]))
}

// ---------------------------------------------------------- appearance

pub fn normalize_appearance(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_appearance();
    let flag = |key: &str| {
        as_bool(
            raw.get(key).unwrap_or(&Null),
            default.get(key).and_then(Value::as_bool).unwrap_or(false),
        )
    };
    let nullable_str = |key: &str| {
        as_nullable_str(raw.get(key).unwrap_or(&Null))
            .map(JString)
            .unwrap_or(Null)
    };
    Object(Map::from_iter([
        (
            "display_mode".into(),
            JString(as_str_in(
                raw.get("display_mode").unwrap_or(&Null),
                &schema::VALID_DISPLAY_MODES,
                "dark",
            )),
        ),
        (
            "ui_language".into(),
            JString(as_str_in(
                raw.get("ui_language").unwrap_or(&Null),
                &schema::VALID_UI_LANGUAGES,
                "ru",
            )),
        ),
        ("accent_color".into(), nullable_str("accent_color")),
        (
            "follow_windows_accent".into(),
            Value::Bool(flag("follow_windows_accent")),
        ),
        (
            "tinted_background".into(),
            Value::Bool(flag("tinted_background")),
        ),
        (
            "tinted_background_intensity".into(),
            Value::from(as_int(
                raw.get("tinted_background_intensity").unwrap_or(&Null),
                default
                    .get("tinted_background_intensity")
                    .and_then(Value::as_i64)
                    .unwrap_or(schema::DEFAULT_TINTED_INTENSITY),
                Some(0),
                Some(schema::MAX_TINTED_INTENSITY),
            )),
        ),
        (
            "background_preset".into(),
            JString(as_str_in(
                raw.get("background_preset").unwrap_or(&Null),
                &schema::VALID_BACKGROUND_PRESETS,
                "standard",
            )),
        ),
        ("rkn_background".into(), nullable_str("rkn_background")),
        (
            "animations_enabled".into(),
            Value::Bool(flag("animations_enabled")),
        ),
        (
            "smooth_scroll_enabled".into(),
            Value::Bool(flag("smooth_scroll_enabled")),
        ),
        (
            "editor_smooth_scroll_enabled".into(),
            Value::Bool(flag("editor_smooth_scroll_enabled")),
        ),
        (
            "live_animations_enabled".into(),
            Value::Bool(flag("live_animations_enabled")),
        ),
        (
            "sidebar_icon_style".into(),
            JString(as_str_in(
                raw.get("sidebar_icon_style").unwrap_or(&Null),
                &schema::VALID_SIDEBAR_ICON_STYLES,
                "standard",
            )),
        ),
        (
            "garland_enabled".into(),
            Value::Bool(flag("garland_enabled")),
        ),
        (
            "snowflakes_enabled".into(),
            Value::Bool(flag("snowflakes_enabled")),
        ),
        (
            "selected_theme".into(),
            Value::String(as_clean_str(raw.get("selected_theme").unwrap_or(&Null), "")),
        ),
    ]))
}

// ------------------------------------------------------------ warnings

pub fn normalize_warnings(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_warnings();
    let mut result = Map::new();
    for key in [
        "tray_hint_shown",
        "disable_telega_warning",
        "disable_kaspersky_warning",
        "isp_dns_info_shown",
        "tg_proxy_deeplink_done",
        "onboarding_tour_done",
        "profile_display_order_hint_shown",
    ] {
        result.insert(
            key.to_string(),
            Value::Bool(as_bool(
                raw.get(key).unwrap_or(&Null),
                default.get(key).and_then(Value::as_bool).unwrap_or(false),
            )),
        );
    }
    Object(result)
}

// ----------------------------------------------------- telegram_proxy

pub fn normalize_telegram_proxy(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_telegram_proxy();
    let flag = |key: &str, fallback: bool| {
        as_bool(
            raw.get(key).unwrap_or(&Null),
            default
                .get(key)
                .and_then(Value::as_bool)
                .unwrap_or(fallback),
        )
    };
    let default_str = |key: &str| {
        default
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mode = as_str_in(
        raw.get("mode").unwrap_or(&Null),
        &schema::VALID_TG_PROXY_MODES,
        "mtproxy",
    );
    let host = {
        let cleaned = as_clean_str(raw.get("host").unwrap_or(&Null), "");
        if cleaned.is_empty() {
            default
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        } else {
            cleaned
        }
    };
    Object(Map::from_iter([
        ("enabled".into(), Value::Bool(flag("enabled", true))),
        ("host".into(), JString(host)),
        (
            "port".into(),
            Value::from(as_int(
                raw.get("port").unwrap_or(&Null),
                schema::DEFAULT_TG_PROXY_PORT,
                Some(1024),
                Some(65535),
            )),
        ),
        ("mode".into(), JString(mode)),
        (
            "upstream_enabled".into(),
            Value::Bool(flag("upstream_enabled", true)),
        ),
        (
            "upstream_host".into(),
            Value::String(as_clean_str(raw.get("upstream_host").unwrap_or(&Null), "")),
        ),
        (
            "upstream_port".into(),
            Value::from(as_int(
                raw.get("upstream_port").unwrap_or(&Null),
                schema::DEFAULT_TG_PROXY_UPSTREAM_PORT,
                Some(1),
                Some(65535),
            )),
        ),
        (
            "upstream_preset_id".into(),
            Value::String(as_clean_str(
                raw.get("upstream_preset_id").unwrap_or(&Null),
                "",
            )),
        ),
        (
            "upstream_mode".into(),
            JString(as_str_in(
                raw.get("upstream_mode").unwrap_or(&Null),
                &schema::VALID_TG_PROXY_UPSTREAM_MODES,
                "fallback",
            )),
        ),
        (
            "upstream_udp_enabled".into(),
            Value::Bool(flag("upstream_udp_enabled", false)),
        ),
        (
            "upstream_user".into(),
            Value::String(as_clean_str(raw.get("upstream_user").unwrap_or(&Null), "")),
        ),
        (
            "upstream_pass".into(),
            Value::String(as_str(
                raw.get("upstream_pass").unwrap_or(&Null),
                &default_str("upstream_pass"),
            )),
        ),
        (
            "cloudflare_enabled".into(),
            Value::Bool(flag("cloudflare_enabled", false)),
        ),
        (
            "cloudflare_domains".into(),
            vec_json(unique_domain_list(
                raw.get("cloudflare_domains").unwrap_or(&Null),
            )),
        ),
        (
            "cloudflare_worker_enabled".into(),
            Value::Bool(flag("cloudflare_worker_enabled", false)),
        ),
        (
            "cloudflare_worker_domains".into(),
            vec_json(unique_domain_list(
                raw.get("cloudflare_worker_domains").unwrap_or(&Null),
            )),
        ),
        (
            "mtproxy_secret".into(),
            Value::String(normalize_hex_secret(
                raw.get("mtproxy_secret").unwrap_or(&Null),
            )),
        ),
        (
            "dc_ip".into(),
            vec_json(unique_dc_ip_list(raw.get("dc_ip").unwrap_or(&Null))),
        ),
        (
            "pool_size".into(),
            Value::from(as_int(
                raw.get("pool_size").unwrap_or(&Null),
                default
                    .get("pool_size")
                    .and_then(Value::as_i64)
                    .unwrap_or(4),
                Some(0),
                Some(32),
            )),
        ),
        (
            "buffer_kb".into(),
            Value::from(as_int(
                raw.get("buffer_kb").unwrap_or(&Null),
                default
                    .get("buffer_kb")
                    .and_then(Value::as_i64)
                    .unwrap_or(256),
                Some(4),
                Some(4096),
            )),
        ),
        (
            "fake_tls_domain".into(),
            Value::String(normalize_domain(
                raw.get("fake_tls_domain").unwrap_or(&Null),
            )),
        ),
        (
            "proxy_protocol".into(),
            Value::Bool(flag("proxy_protocol", false)),
        ),
        (
            "auto_deeplink".into(),
            Value::Bool(flag("auto_deeplink", true)),
        ),
    ]))
}

// ----------------------------------------------------------------- dns

pub fn normalize_dns(data: &Value) -> Value {
    let raw = obj(data);
    Object(Map::from_iter([(
        "custom_servers".into(),
        Value::Array(
            normalize_custom_dns_servers(raw.get("custom_servers").unwrap_or(&Null))
                .into_iter()
                .map(Object)
                .collect(),
        ),
    )]))
}

// --------------------------------------------------------------- hosts

pub fn normalize_hosts(data: &Value) -> Value {
    let raw = obj(data);
    let mut selection = Map::new();
    for (raw_service_name, raw_profile_name) in obj(raw.get("selection").unwrap_or(&Null)) {
        let service_name = as_clean_str(&JString(raw_service_name), "");
        let profile_name = as_clean_str(&raw_profile_name, "");
        if !service_name.is_empty() && !profile_name.is_empty() {
            selection.insert(service_name, JString(profile_name));
        }
    }
    Object(Map::from_iter([
        (
            "active_domains".into(),
            vec_json(unique_str_list(raw.get("active_domains").unwrap_or(&Null))),
        ),
        ("selection".into(), Object(selection)),
        (
            "engine".into(),
            normalize_hosts_engine(raw.get("engine").unwrap_or(&Null)),
        ),
    ]))
}

/// Смысл проверяет hosts.catalog_overlay; здесь — только типы строк/пар.
pub fn normalize_hosts_engine(data: &Value) -> Value {
    let raw = obj(data);
    let mut services: Map<String, Value> = Map::new();
    for (service_id_raw, profiles) in obj(raw.get("services").unwrap_or(&Null)) {
        let mut kept: Map<String, Value> = Map::new();
        for (profile_id_raw, rows) in obj(&profiles) {
            let mut pairs: Vec<Value> = Vec::new();
            if let Array(items) = rows {
                for row in items.iter() {
                    if let Array(pair) = row {
                        if pair.len() != 2 {
                            continue;
                        }
                        let first = as_clean_str(&pair[0], "");
                        let second = as_clean_str(&pair[1], "");
                        if first.is_empty() || second.is_empty() {
                            continue;
                        }
                        pairs.push(Array(vec![JString(first), JString(second)]));
                    }
                }
            }
            let profile_id = as_clean_str(&JString(profile_id_raw), "");
            if !pairs.is_empty() && !profile_id.is_empty() {
                kept.insert(profile_id, Array(pairs));
            }
        }
        let service_id = as_clean_str(&JString(service_id_raw), "");
        if !kept.is_empty() && !service_id.is_empty() {
            services.insert(service_id, Object(kept));
        }
    }
    let mut pool: Map<String, Value> = Map::new();
    for (service_id_raw, hosts) in obj(raw.get("pool").unwrap_or(&Null)) {
        let mut found: Map<String, Value> = Map::new();
        for (host_raw, addresses) in obj(&hosts) {
            let host = as_clean_str(&JString(host_raw), "");
            let normalized = unique_str_list(&addresses);
            if !host.is_empty() && !normalized.is_empty() {
                found.insert(host, vec_json(normalized));
            }
        }
        let service_id = as_clean_str(&JString(service_id_raw), "");
        if !found.is_empty() && !service_id.is_empty() {
            pool.insert(service_id, Object(found));
        }
    }
    Object(Map::from_iter([
        (
            "catalog".into(),
            Value::String(as_clean_str(raw.get("catalog").unwrap_or(&Null), "")),
        ),
        (
            "checked_at".into(),
            Value::String(as_clean_str(raw.get("checked_at").unwrap_or(&Null), "")),
        ),
        (
            "suspects".into(),
            vec_json(unique_str_list(raw.get("suspects").unwrap_or(&Null))),
        ),
        ("services".into(), Object(services)),
        ("pool".into(), Object(pool)),
    ]))
}

// ------------------------------------------------------------ ui_state

pub fn normalize_ui_state(data: &Value) -> Value {
    let raw = obj(data);
    Object(Map::from_iter([(
        "sidebar_expanded".into(),
        Value::Bool(as_bool(raw.get("sidebar_expanded").unwrap_or(&Null), true)),
    )]))
}

// --------------------------------------- profile_strategy_state

pub const STRATEGY_LIST_GROUPINGS: [&str; 2] = ["series", "source"];

/// `^[a-z][a-z0-9_]{0,31}$`.
fn strategy_group_key_ok(text: &str) -> bool {
    if text.is_empty() || text.len() > 32 {
        return false;
    }
    let first = text.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return false;
    }
    text.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub fn normalize_profile_strategy_state(data: &Value) -> Value {
    let raw = obj(data);
    let mut profiles = Map::new();
    for (raw_profile_key, raw_profile_row) in obj(raw.get("profiles").unwrap_or(&Null)) {
        let profile_key = as_clean_str(&JString(raw_profile_key), "");
        if !(profile_key.starts_with("uid:")
            || profile_key.starts_with("name:")
            || profile_key.starts_with("sig:"))
        {
            continue;
        }
        let profile_row = obj(&raw_profile_row);
        let mut strategies = Map::new();
        for (raw_strategy_id, raw_strategy_row) in
            obj(profile_row.get("strategies").unwrap_or(&Null))
        {
            let strategy_id = as_clean_str(&JString(raw_strategy_id), "");
            if strategy_id.is_empty() || strategy_id == "none" || strategy_id == "custom" {
                continue;
            }
            let strategy_row = obj(&raw_strategy_row);
            let mut rating =
                as_clean_str(strategy_row.get("rating").unwrap_or(&Null), "").to_lowercase();
            if !str_in(&["", "work", "notwork"], &rating) {
                rating = String::new();
            }
            let favorite = as_bool(strategy_row.get("favorite").unwrap_or(&Null), false);
            if rating.is_empty() && !favorite {
                continue;
            }
            let mut normalized_row = Map::new();
            normalized_row.insert("favorite".into(), Value::Bool(favorite));
            normalized_row.insert("rating".into(), JString(rating));
            let updated_at = as_clean_str(strategy_row.get("updated_at").unwrap_or(&Null), "");
            if !updated_at.is_empty() {
                normalized_row.insert("updated_at".into(), JString(updated_at));
            }
            strategies.insert(strategy_id, Object(normalized_row));
        }
        let mut normalized_profile_row = Map::new();
        if !strategies.is_empty() {
            normalized_profile_row.insert("strategies".into(), Object(strategies));
        }
        if let Some(open_text) = profile_row.get("open_group").and_then(Value::as_str) {
            let open_group = open_text.trim();
            if open_group.is_empty() || strategy_group_key_ok(open_group) {
                normalized_profile_row.insert("open_group".into(), JString(open_group.to_string()));
            }
        }
        if !normalized_profile_row.is_empty() {
            profiles.insert(profile_key, Object(normalized_profile_row));
        }
    }
    let mut normalized = Map::new();
    normalized.insert("version".into(), Value::from(1));
    normalized.insert("profiles".into(), Object(profiles));
    let grouping = as_clean_str(raw.get("grouping").unwrap_or(&Null), "").to_lowercase();
    if str_in(&STRATEGY_LIST_GROUPINGS, &grouping) {
        normalized.insert("grouping".into(), JString(grouping));
    }
    Object(normalized)
}

// ------------------------------------------------------- user_profiles

pub fn normalize_user_profiles(data: &Value) -> Value {
    let raw = obj(data);
    let mut profiles = Map::new();
    for (raw_profile_id, raw_profile) in obj(raw.get("profiles").unwrap_or(&Null)) {
        let profile_id = normalize_lookup_key(&JString(raw_profile_id));
        let profile = obj(&raw_profile);
        let name = as_clean_str(profile.get("name").unwrap_or(&Null), "");
        let protocol = as_clean_str(profile.get("protocol").unwrap_or(&Null), "").to_lowercase();
        let ports = as_clean_str(profile.get("ports").unwrap_or(&Null), "");
        let hostlist = as_clean_str(profile.get("hostlist").unwrap_or(&Null), "");
        let ipset = as_clean_str(profile.get("ipset").unwrap_or(&Null), "");
        if profile_id.is_empty()
            || name.is_empty()
            || !str_in(&["tcp", "udp", "l7"], &protocol)
            || ports.is_empty()
            || hostlist.is_empty()
            || ipset.is_empty()
        {
            continue;
        }
        profiles.insert(
            profile_id,
            Object(Map::from_iter([
                ("name".into(), JString(name)),
                ("protocol".into(), JString(protocol)),
                ("ports".into(), JString(ports)),
                ("hostlist".into(), JString(hostlist)),
                ("ipset".into(), JString(ipset)),
            ])),
        );
    }
    Object(Map::from_iter([
        ("version".into(), Value::from(1)),
        ("profiles".into(), Object(profiles)),
    ]))
}

// --------------------------------------------------------- user_fakes

const FAKE_KINDS: [&str; 10] = [
    "tls",
    "quic",
    "http",
    "stun",
    "dht",
    "discord",
    "wireguard",
    "dtls",
    "zeros",
    "other",
];
pub const USER_FAKE_DESCRIPTION_MAX_LENGTH: usize = 200;

fn user_fake_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_plain_bin_file_name(value: &str) -> bool {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value == "."
        || value == ".."
    {
        return false;
    }
    value.to_lowercase().ends_with(".bin") && value.len() > ".bin".len()
}

/// Порт `fakes.user_fakes.normalize_user_fake_row`: строка секции или None.
pub fn normalize_user_fake_row(name: &str, raw: &Value) -> Option<Value> {
    if !user_fake_name_ok(name) || !raw.is_object() {
        return None;
    }
    let row = obj(raw);
    let file_name = python_str_or_empty(row.get("file_name").unwrap_or(&Null))
        .trim()
        .to_string();
    if !is_plain_bin_file_name(&file_name) {
        return None;
    }
    let mut kind = python_str_or_empty(row.get("kind").unwrap_or(&Null))
        .trim()
        .to_lowercase();
    if !FAKE_KINDS.contains(&kind.as_str()) {
        kind = "other".to_string();
    }
    let sni = row
        .get("sni")
        .and_then(Value::as_str)
        .map(|t| t.trim().to_string())
        .unwrap_or_default();
    let description = chars_limit(
        python_str_or_empty(row.get("description").unwrap_or(&Null)).trim(),
        USER_FAKE_DESCRIPTION_MAX_LENGTH,
    );
    let created_at = python_str_or_empty(row.get("created_at").unwrap_or(&Null))
        .trim()
        .to_string();
    Some(Object(Map::from_iter([
        ("file_name".into(), JString(file_name)),
        ("kind".into(), JString(kind)),
        (
            "sni".into(),
            if sni.is_empty() { Null } else { JString(sni) },
        ),
        ("description".into(), JString(description)),
        ("created_at".into(), JString(created_at)),
    ])))
}

pub fn normalize_user_fakes(data: &Value) -> Value {
    let raw = obj(data);
    let mut fakes = Map::new();
    for (raw_name, raw_row) in obj(raw.get("fakes").unwrap_or(&Null)) {
        // python: str(raw_name or "").strip(); пустое имя отсеется регуляркой.
        let name = raw_name.trim().to_string();
        if let Some(row) = normalize_user_fake_row(&name, &raw_row) {
            fakes.insert(name, row);
        }
    }
    Object(Map::from_iter([
        ("version".into(), Value::from(1)),
        ("fakes".into(), Object(fakes)),
    ]))
}

// ----------------------------------------------------------- orchestra

pub fn normalize_orchestra_settings(data: &Value) -> Value {
    let raw = obj(data);
    let default = schema::default_orchestra_settings();
    let flag = |key: &str| {
        as_bool(
            raw.get(key).unwrap_or(&Null),
            default.get(key).and_then(Value::as_bool).unwrap_or(false),
        )
    };
    let bounded = |key: &str| {
        as_int(
            raw.get(key).unwrap_or(&Null),
            default.get(key).and_then(Value::as_i64).unwrap_or(1),
            Some(1),
            None,
        )
    };
    Object(Map::from_iter([
        (
            "strict_detection".into(),
            Value::Bool(flag("strict_detection")),
        ),
        (
            "keep_debug_file".into(),
            Value::Bool(flag("keep_debug_file")),
        ),
        (
            "auto_restart_on_discord_fail".into(),
            Value::Bool(flag("auto_restart_on_discord_fail")),
        ),
        (
            "discord_fails_for_restart".into(),
            Value::from(bounded("discord_fails_for_restart")),
        ),
        (
            "lock_successes".into(),
            Value::from(bounded("lock_successes")),
        ),
        ("unlock_fails".into(), Value::from(bounded("unlock_fails"))),
    ]))
}

pub fn normalize_orchestra_locked_maps(data: &Value) -> Value {
    let raw = obj(data);
    let mut normalized = Map::new();
    for askey in schema::ORCHESTRA_ASKEYS {
        let mut entries = Map::new();
        for (key, strategy) in obj(raw.get(askey).unwrap_or(&Null)) {
            let target = normalize_lookup_key(&JString(key));
            if target.is_empty() {
                continue;
            }
            entries.insert(target, Value::from(as_int(&strategy, 0, Some(0), None)));
        }
        normalized.insert((*askey).to_string(), Object(entries));
    }
    Object(normalized)
}

pub fn normalize_orchestra_user_locked_maps(data: &Value) -> Value {
    let raw = obj(data);
    let mut normalized = Map::new();
    for askey in schema::ORCHESTRA_ASKEYS {
        let kept: Vec<Value> = unique_str_list(raw.get(askey).unwrap_or(&Null))
            .into_iter()
            .map(|item| normalize_lookup_key(&JString(item)))
            .filter(|item| !item.is_empty())
            .map(JString)
            .collect();
        normalized.insert((*askey).to_string(), Value::Array(kept));
    }
    Object(normalized)
}

pub fn normalize_orchestra_user_blocked_maps(data: &Value) -> Value {
    let raw = obj(data);
    let mut normalized = Map::new();
    for askey in schema::ORCHESTRA_ASKEYS {
        let mut entries = Map::new();
        for (key, strategies) in obj(raw.get(askey).unwrap_or(&Null)) {
            let target = normalize_lookup_key(&JString(key));
            if !target.is_empty() {
                entries.insert(target, vec_i_json(unique_int_list(&strategies)));
            }
        }
        normalized.insert((*askey).to_string(), Object(entries));
    }
    Object(normalized)
}

pub fn normalize_orchestra_history(data: &Value) -> Value {
    let mut normalized = Map::new();
    for (key, strategies) in as_dict(data) {
        let target = normalize_lookup_key(&JString(key.clone()));
        if target.is_empty() {
            continue;
        }
        let mut strategies_out = Map::new();
        for (strategy_key, metrics) in obj(&strategies) {
            let strategy_name = as_clean_str(&JString(strategy_key), "");
            if strategy_name.is_empty() {
                continue;
            }
            let metrics_raw = obj(&metrics);
            strategies_out.insert(
                strategy_name,
                Object(Map::from_iter([
                    (
                        "successes".into(),
                        Value::from(as_int(
                            metrics_raw.get("successes").unwrap_or(&Null),
                            0,
                            Some(0),
                            None,
                        )),
                    ),
                    (
                        "failures".into(),
                        Value::from(as_int(
                            metrics_raw.get("failures").unwrap_or(&Null),
                            0,
                            Some(0),
                            None,
                        )),
                    ),
                ])),
            );
        }
        normalized.insert(target, Object(strategies_out));
    }
    Object(normalized)
}

pub fn normalize_orchestra(data: &Value) -> Value {
    let raw = obj(data);
    Object(Map::from_iter([
        (
            "settings".into(),
            normalize_orchestra_settings(raw.get("settings").unwrap_or(&Null)),
        ),
        (
            "whitelist".into(),
            Object(Map::from_iter([(
                "user_domains".into(),
                Value::Array(
                    unique_str_list(
                        obj(raw.get("whitelist").unwrap_or(&Null))
                            .get("user_domains")
                            .unwrap_or(&Null),
                    )
                    .into_iter()
                    .map(|item| normalize_lookup_key(&JString(item)))
                    .filter(|item| !item.is_empty())
                    .map(JString)
                    .collect(),
                ),
            )])),
        ),
        (
            "locked".into(),
            normalize_orchestra_locked_maps(raw.get("locked").unwrap_or(&Null)),
        ),
        (
            "user_locked".into(),
            normalize_orchestra_user_locked_maps(raw.get("user_locked").unwrap_or(&Null)),
        ),
        (
            "user_blocked".into(),
            normalize_orchestra_user_blocked_maps(raw.get("user_blocked").unwrap_or(&Null)),
        ),
        (
            "history".into(),
            normalize_orchestra_history(raw.get("history").unwrap_or(&Null)),
        ),
    ]))
}

// ------------------------------------------------------------- updater

pub const SELF_REPAIR_ATTEMPTS_KEPT: usize = 20;

pub fn normalize_self_repair(data: &Value) -> Value {
    let raw = obj(data);
    let mut attempts = Vec::new();
    if let Array(items) = raw.get("attempts").unwrap_or(&Null) {
        for item in items.iter() {
            let stamp = as_int(item, 0, Some(0), None);
            if stamp != 0 {
                attempts.push(stamp);
            }
        }
    }
    attempts.sort();
    let start = attempts.len().saturating_sub(SELF_REPAIR_ATTEMPTS_KEPT);
    Object(Map::from_iter([(
        "attempts".into(),
        Value::Array(attempts[start..].iter().map(|n| Value::from(*n)).collect()),
    )]))
}

pub const AUTO_INSTALL_OUTCOMES: [&str; 3] = ["started", "failed", "missed"];
pub const AUTO_INSTALL_VIA: [&str; 2] = ["files", "setup"];

pub fn auto_install_token_ok(text: &str) -> bool {
    if text.is_empty() || text.len() > 16 {
        return false;
    }
    let mut chars = text.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn normalize_auto_install(data: &Value) -> Value {
    let raw = obj(data);
    let version = as_clean_str(raw.get("version").unwrap_or(&Null), "");
    let granted_at = max_0(py_float_or_zero(raw.get("granted_at")));
    let mut outcome = as_clean_str(raw.get("outcome").unwrap_or(&Null), "");
    if !(str_in(&AUTO_INSTALL_OUTCOMES, &outcome) && !version.is_empty()) {
        outcome = String::new();
    }
    Object(Map::from_iter([
        ("version".into(), JString(version.clone())),
        (
            "attempts".into(),
            Value::from(if version.is_empty() {
                0
            } else {
                as_int(raw.get("attempts").unwrap_or(&Null), 0, Some(0), None)
            }),
        ),
        (
            "from_version".into(),
            Value::String(if version.is_empty() {
                String::new()
            } else {
                as_clean_str(raw.get("from_version").unwrap_or(&Null), "")
            }),
        ),
        (
            "granted_at".into(),
            Value::from(if version.is_empty() { 0.0 } else { granted_at }),
        ),
        ("outcome".into(), JString(outcome.clone())),
        (
            "why".into(),
            Value::String({
                let why = as_clean_str(raw.get("why").unwrap_or(&Null), "");
                if str_in(&["failed", "missed"], &outcome) && auto_install_token_ok(&why) {
                    why
                } else {
                    String::new()
                }
            }),
        ),
        (
            "who".into(),
            Value::String({
                let who = as_clean_str(raw.get("who").unwrap_or(&Null), "");
                if outcome == "failed" && auto_install_token_ok(&who) {
                    who
                } else {
                    String::new()
                }
            }),
        ),
        (
            "via".into(),
            Value::String({
                let via = as_clean_str(raw.get("via").unwrap_or(&Null), "");
                if !version.is_empty() && str_in(&AUTO_INSTALL_VIA, &via) {
                    via
                } else {
                    String::new()
                }
            }),
        ),
        (
            "dl_kib".into(),
            Value::from(if version.is_empty() {
                0
            } else {
                as_int(raw.get("dl_kib").unwrap_or(&Null), 0, Some(0), None)
            }),
        ),
    ]))
}

pub fn normalize_updater(data: &Value) -> Value {
    let raw = obj(data);
    Object(Map::from_iter([
        (
            "auto_check".into(),
            Object(Map::from_iter([(
                "last_success_at".into(),
                Value::from(max_0(py_float_or_zero(
                    obj(raw.get("auto_check").unwrap_or(&Null)).get("last_success_at"),
                ))),
            )])),
        ),
        (
            "self_repair".into(),
            normalize_self_repair(raw.get("self_repair").unwrap_or(&Null)),
        ),
        (
            "skipped_version".into(),
            Value::String(as_clean_str(
                raw.get("skipped_version").unwrap_or(&Null),
                "",
            )),
        ),
        (
            "auto_install".into(),
            normalize_auto_install(raw.get("auto_install").unwrap_or(&Null)),
        ),
        (
            "whats_new".into(),
            normalize_whats_new(raw.get("whats_new").unwrap_or(&Null)),
        ),
    ]))
}

pub const WHATS_NEW_HISTORY_KEPT: usize = 40;
pub const WHATS_NEW_NOTES_MAX_CHARS: usize = 20000;

pub fn normalize_whats_new(data: &Value) -> Value {
    let raw = obj(data);
    let pending_raw = obj(raw.get("pending").unwrap_or(&Null));
    let mut history: Vec<Value> = Vec::new();
    if let Array(items) = pending_raw.get("history").unwrap_or(&Null) {
        for item in items.iter() {
            let entry = obj(item);
            let version = as_clean_str(entry.get("version").unwrap_or(&Null), "");
            if version.is_empty() {
                continue;
            }
            let notes = chars_limit(
                &python_str_or_empty(entry.get("notes").unwrap_or(&Null)),
                WHATS_NEW_NOTES_MAX_CHARS,
            );
            history.push(Object(Map::from_iter([
                ("version".into(), JString(version)),
                ("notes".into(), JString(notes)),
                (
                    "published_at".into(),
                    Value::String(as_clean_str(entry.get("published_at").unwrap_or(&Null), "")),
                ),
                (
                    "url".into(),
                    Value::String(as_clean_str(entry.get("url").unwrap_or(&Null), "")),
                ),
                (
                    "is_new".into(),
                    Value::Bool(truthy(entry.get("is_new").unwrap_or(&Value::Bool(true)))),
                ),
            ])));
        }
    }
    Object(Map::from_iter([
        (
            "seen_version".into(),
            Value::String(as_clean_str(raw.get("seen_version").unwrap_or(&Null), "")),
        ),
        (
            "pending".into(),
            Object(Map::from_iter([
                (
                    "version".into(),
                    Value::String(as_clean_str(
                        pending_raw.get("version").unwrap_or(&Null),
                        "",
                    )),
                ),
                (
                    "history".into(),
                    Value::Array(history.into_iter().take(WHATS_NEW_HISTORY_KEPT).collect()),
                ),
            ])),
        ),
    ]))
}

// ---------------------------------------------------------- blockcheck

pub fn normalize_blockcheck_strategy_history(data: &Value) -> Value {
    let mut history = Map::new();
    for (raw_key, raw_value) in as_dict(data) {
        let key = as_clean_str(&JString(raw_key.clone()), "").to_lowercase();
        if key.is_empty() {
            continue;
        }
        let entry = obj(&raw_value);
        let confirmed: Vec<Value> = unique_str_list(entry.get("confirmed").unwrap_or(&Null))
            .into_iter()
            .filter(|item| !item.is_empty())
            .map(JString)
            .collect();
        let mut failed = Map::new();
        for (raw_id, raw_time) in obj(entry.get("failed").unwrap_or(&Null)) {
            let strategy_id = as_clean_str(&JString(raw_id), "");
            if strategy_id.is_empty() {
                continue;
            }
            if let Some(stamp) = py_float_option(Some(&raw_time)) {
                failed.insert(strategy_id, Value::from(max_0(stamp)));
            }
        }
        history.insert(
            key,
            Object(Map::from_iter([
                ("confirmed".into(), Value::Array(confirmed)),
                ("failed".into(), Object(failed)),
            ])),
        );
    }
    Object(history)
}

fn history_text(value: &Value) -> String {
    chars_limit(
        as_clean_str(value, "").as_str(),
        schema::CHECK_HISTORY_TEXT_LIMIT,
    )
}

pub fn normalize_check_history(data: &Value) -> Value {
    let mut runs = Vec::new();
    if let Array(items) = data {
        for raw_run in items.iter() {
            let run = obj(raw_run);
            let kind = as_clean_str(run.get("kind").unwrap_or(&Null), "");
            let time_text = as_clean_str(run.get("time").unwrap_or(&Null), "");
            if kind.is_empty() || time_text.is_empty() {
                continue;
            }
            let mut states = Map::new();
            for (raw_name, raw_level) in obj(run.get("states").unwrap_or(&Null)) {
                let name = history_text(&JString(raw_name));
                let level = as_clean_str(&raw_level, "");
                if !name.is_empty()
                    && str_in(&schema::CHECK_HISTORY_LEVELS, &level)
                    && states.len() < schema::CHECK_HISTORY_STATES_LIMIT
                {
                    states.insert(name, JString(level));
                }
            }
            let mut problems = Vec::new();
            if let Array(items) = run.get("problems").unwrap_or(&Null) {
                for item in items.iter() {
                    let text = history_text(item);
                    if text.is_empty() {
                        continue;
                    }
                    problems.push(JString(text));
                    if problems.len() >= schema::CHECK_HISTORY_PROBLEMS_LIMIT {
                        break;
                    }
                }
            }
            runs.push(Object(Map::from_iter([
                ("kind".into(), JString(chars_limit(&kind, 40))),
                ("time".into(), JString(chars_limit(&time_text, 40))),
                (
                    "title".into(),
                    JString(history_text(run.get("title").unwrap_or(&Null))),
                ),
                (
                    "level".into(),
                    JString(as_str_in(
                        run.get("level").unwrap_or(&Null),
                        &schema::CHECK_HISTORY_LEVELS,
                        "unknown",
                    )),
                ),
                (
                    "headline".into(),
                    JString(history_text(run.get("headline").unwrap_or(&Null))),
                ),
                ("problems".into(), Value::Array(problems)),
                ("states".into(), Object(states)),
                (
                    "log_file".into(),
                    JString(chars_limit(
                        &as_clean_str(run.get("log_file").unwrap_or(&Null), ""),
                        520,
                    )),
                ),
                (
                    "zapret".into(),
                    JString(as_str_in(
                        run.get("zapret").unwrap_or(&Null),
                        &schema::CHECK_HISTORY_ZAPRET,
                        "",
                    )),
                ),
                (
                    "preset".into(),
                    JString(history_text(run.get("preset").unwrap_or(&Null))),
                ),
                (
                    "tools".into(),
                    Value::Bool(matches!(
                        run.get("tools").unwrap_or(&Null),
                        Value::Bool(true)
                    )),
                ),
                (
                    "habit".into(),
                    JString(chars_limit(
                        &as_clean_str(run.get("habit").unwrap_or(&Null), ""),
                        40,
                    )),
                ),
            ])));
        }
    }
    let start = runs.len().saturating_sub(schema::CHECK_HISTORY_LIMIT);
    Value::Array(runs.split_off(start))
}

pub fn normalize_blockcheck(data: &Value) -> Value {
    let raw = obj(data);
    let user_domains: Vec<Value> = unique_str_list(raw.get("user_domains").unwrap_or(&Null))
        .into_iter()
        .map(|item| normalize_lookup_key(&JString(item)))
        .filter(|item| !item.is_empty())
        .map(JString)
        .collect();
    let mut result = Map::new();
    result.insert("user_domains".into(), Value::Array(user_domains));
    result.insert(
        "strategy_history".into(),
        normalize_blockcheck_strategy_history(raw.get("strategy_history").unwrap_or(&Null)),
    );
    result.insert(
        "check_history".into(),
        normalize_check_history(raw.get("check_history").unwrap_or(&Null)),
    );
    for key in schema::TAB_HISTORY_KEYS {
        let normalized = normalize_check_history(raw.get(*key).unwrap_or(&Null));
        let mut runs = match normalized {
            Array(items) => items,
            _ => Vec::new(),
        };
        let start = runs.len().saturating_sub(schema::TAB_HISTORY_LIMIT);
        result.insert((*key).to_string(), Value::Array(runs.split_off(start)));
    }
    Object(result)
}

// -------------------------------------------------------------- folders

fn folder_clean_name(name_value: Option<&Value>, first_piece: &str) -> String {
    // python: str(value or "").strip() и ключ карты в python всегда строка.
    let text = name_value
        .map(python_str_or_empty)
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| first_piece.to_string())
        .trim()
        .to_string();
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        "Новая папка".to_string()
    } else {
        chars_limit(&collapsed, 80)
    }
}

fn folder_as_nullable_int(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    match value {
        Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::Bool(true) => Some(1),
        Value::Bool(false) => Some(0),
        Value::Number(nr) => nr
            .as_i64()
            .or_else(|| nr.as_f64().map(|f| f as i64))
            .map(|n| n.max(0)),
        Value::String(text) => text.trim().parse::<i64>().ok().map(|n| n.max(0)),
        _ => None,
    }
}

fn make_order_slot(folders: &mut Map<String, Value>, order: i64) {
    for folder in folders.values_mut() {
        if !folder.is_object() {
            continue;
        }
        let current_order = folder
            .get("order")
            .and_then(Value::as_i64)
            .map(|n| n.max(0))
            .unwrap_or(0);
        if current_order >= order {
            folder["order"] = Value::from(current_order + 1);
        }
    }
}

fn normalize_folders_map(value: &Value, fallback: Map<String, Value>) -> Map<String, Value> {
    let mut folders: Map<String, Value> = Map::new();
    if let Object(raw_map) = value {
        for (raw_key, raw_folder) in raw_map {
            let key = raw_key.trim().to_string();
            if key.is_empty() || !raw_folder.is_object() {
                continue;
            }
            let name = folder_clean_name(raw_folder.get("name"), &key);
            folders.insert(
                key.clone(),
                Object(Map::from_iter([
                    ("name".into(), JString(name)),
                    (
                        "order".into(),
                        Value::from(as_int(
                            raw_folder.get("order").unwrap_or(&Null),
                            folders.len() as i64,
                            Some(0),
                            None,
                        )),
                    ),
                    (
                        "collapsed".into(),
                        Value::Bool(truthy(
                            raw_folder.get("collapsed").unwrap_or(&Value::Bool(false)),
                        )),
                    ),
                    (
                        "system".into(),
                        Value::Bool(truthy(
                            raw_folder.get("system").unwrap_or(&Value::Bool(false)),
                        )),
                    ),
                ])),
            );
        }
    }
    if !folders.is_empty() {
        return folders;
    }
    fallback
}

fn merge_default_folders(
    folders: Map<String, Value>,
    default_folders: Map<String, Value>,
) -> Map<String, Value> {
    let mut result = folders;
    if result.is_empty() {
        return default_folders;
    }
    for (key, default_folder) in default_folders.iter() {
        match result.get(key).cloned() {
            Some(existing) => {
                let mut merged = default_folder.as_object().cloned().unwrap_or_default();
                for (k, v) in existing.as_object().cloned().unwrap_or_default() {
                    merged.insert(k, v);
                }
                let system = truthy(default_folder.get("system").unwrap_or(&Value::Bool(false)))
                    || truthy(existing.get("system").unwrap_or(&Value::Bool(false)));
                merged.insert("system".into(), Value::Bool(system));
                result.insert(key.clone(), Object(merged));
            }
            None => {
                let mut folder = default_folder.clone();
                let wanted_order = as_int(
                    folder.get("order").unwrap_or(&Null),
                    result.len() as i64,
                    Some(0),
                    None,
                );
                make_order_slot(&mut result, wanted_order);
                folder["order"] = Value::from(wanted_order);
                result.insert(key.clone(), folder);
            }
        }
    }
    result
}

pub fn normalize_folder_state(data: &Value, default_state: &Value) -> Value {
    let defaults = if default_state.is_object() {
        default_state.clone()
    } else {
        Object(Map::new())
    };
    let default_folders =
        normalize_folders_map(defaults.get("folders").unwrap_or(&Null), Map::new());
    let raw = if data.is_object() {
        data.clone()
    } else {
        Object(Map::new())
    };
    let mut folders =
        normalize_folders_map(raw.get("folders").unwrap_or(&Null), default_folders.clone());
    if !default_folders.is_empty() {
        folders = merge_default_folders(folders, default_folders.clone());
    }
    if let Some(common_default) = default_folders.get(schema::FOLDER_COMMON_KEY) {
        let mut common = common_default.as_object().cloned().unwrap_or_default();
        if let Object(existing) = folders
            .get(schema::FOLDER_COMMON_KEY)
            .cloned()
            .unwrap_or(Null)
        {
            for (k, v) in existing {
                common.insert(k, v);
            }
        }
        common.insert("system".into(), Value::Bool(true));
        folders.insert(schema::FOLDER_COMMON_KEY.to_string(), Object(common));
    }
    // python: `if not folders: folders = default_folders`
    if folders.is_empty() {
        folders = default_folders;
    }
    let mut items = Map::new();
    if let Object(raw_items) = raw.get("items").unwrap_or(&Null) {
        for (raw_key, raw_meta) in raw_items {
            let key = raw_key.trim().to_string();
            if key.is_empty() || !raw_meta.is_object() {
                continue;
            }
            let mut folder_key = python_str_or_empty(raw_meta.get("folder_key").unwrap_or(&Null))
                .trim()
                .to_string();
            if folder_key.is_empty() {
                folder_key = schema::FOLDER_COMMON_KEY.to_string();
            }
            if !folders.contains_key(&folder_key) {
                folder_key = schema::FOLDER_COMMON_KEY.to_string();
            }
            let order = folder_as_nullable_int(raw_meta.get("order"));
            let rating = as_int(
                raw_meta.get("rating").unwrap_or(&Null),
                0,
                Some(0),
                Some(10),
            );
            let mut meta = Map::new();
            meta.insert("folder_key".into(), JString(folder_key));
            meta.insert("order".into(), order.map(Value::from).unwrap_or(Null));
            meta.insert("rating".into(), Value::from(rating));
            if truthy(raw_meta.get("pinned").unwrap_or(&Value::Bool(false))) {
                meta.insert("pinned".into(), Value::Bool(true));
            }
            items.insert(key, Object(meta));
        }
    }
    Object(Map::from_iter([
        ("version".into(), Value::from(1)),
        ("folders".into(), Object(folders)),
        ("items".into(), Object(items)),
    ]))
}

pub fn normalize_folders(data: &Value) -> Value {
    let raw = obj(data);
    let raw_presets = obj(raw.get("presets").unwrap_or(&Null));
    Object(Map::from_iter([
        ("version".into(), Value::from(1)),
        (
            "presets".into(),
            Object(Map::from_iter([
                (
                    "winws2".into(),
                    normalize_folder_state(
                        raw_presets.get("winws2").unwrap_or(&Null),
                        &schema::default_preset_folders("winws2"),
                    ),
                ),
                (
                    "winws1".into(),
                    normalize_folder_state(
                        raw_presets.get("winws1").unwrap_or(&Null),
                        &schema::default_preset_folders("winws1"),
                    ),
                ),
            ])),
        ),
        (
            "profiles".into(),
            normalize_folder_state(
                raw.get("profiles").unwrap_or(&Null),
                &schema::default_profile_folders(),
            ),
        ),
    ]))
}

// ----------------------------------------------------- profile_identity

/// Порт `profile.identity.normalize_identity_registry`.
pub fn normalize_identity_registry(raw: &Value) -> Value {
    let mut result = Map::new();
    if !raw.is_object() {
        return Object(result);
    }
    for (raw_uid, raw_meta) in as_dict(raw) {
        let uid = raw_uid.trim().to_string();
        if uid.is_empty() || !raw_meta.is_object() {
            continue;
        }
        result.insert(
            uid,
            Object(Map::from_iter([
                (
                    "name".into(),
                    JString(
                        python_str_or_empty(raw_meta.get("name").unwrap_or(&Null))
                            .trim()
                            .to_string(),
                    ),
                ),
                (
                    "sig".into(),
                    JString(
                        python_str_or_empty(raw_meta.get("sig").unwrap_or(&Null))
                            .trim()
                            .to_string(),
                    ),
                ),
            ])),
        );
    }
    Object(result)
}

// ------------------------------------------------------ remote_presets

fn normalize_remote_preset_binding(data: &Value) -> Option<Value> {
    let raw = obj(data);
    let field = |key: &str, fallback: &str| {
        raw.get(key)
            .map(python_str_or_empty)
            .unwrap_or_else(|| fallback.to_string())
    };
    let url = field("url", "").trim().to_string();
    if url.is_empty() {
        return None;
    }
    Some(Object(Map::from_iter([
        ("url".into(), JString(url)),
        ("etag".into(), JString(field("etag", ""))),
        ("last_modified".into(), JString(field("last_modified", ""))),
        ("synced_hash".into(), JString(field("synced_hash", ""))),
        ("checked_at".into(), JString(field("checked_at", ""))),
        ("updated_at".into(), JString(field("updated_at", ""))),
        ("error".into(), JString(field("error", ""))),
        (
            "auto".into(),
            Value::Bool(truthy(raw.get("auto").unwrap_or(&Value::Bool(true)))),
        ),
        (
            "detached".into(),
            Value::Bool(truthy(raw.get("detached").unwrap_or(&Value::Bool(false)))),
        ),
    ])))
}

pub fn normalize_remote_presets(data: &Value) -> Value {
    let raw = obj(data);
    let mut result = Map::new();
    for scope in ["winws2", "winws1"] {
        let mut scope_bindings = Map::new();
        for (file_name, binding) in obj(raw.get(scope).unwrap_or(&Null)) {
            let key = file_name.trim().to_string();
            if key.is_empty() {
                continue;
            }
            if let Some(normalized) = normalize_remote_preset_binding(&binding) {
                scope_bindings.insert(key, normalized);
            }
        }
        result.insert(scope.to_string(), Object(scope_bindings));
    }
    Object(result)
}

// ---------------------------------------------------------- probe_gate

pub fn normalize_probe_gate(data: &Value) -> Value {
    let raw = obj(data);
    let mut last_run = Map::new();
    for (key, value) in obj(raw.get("last_run").unwrap_or(&Null)) {
        let name = if key.is_empty() {
            String::new()
        } else {
            key.trim().to_string()
        };
        if let Some(when) = py_float_option(Some(&value)) {
            if !name.is_empty() && when > 0.0 {
                last_run.insert(name, Value::from(when));
            }
        }
    }
    Object(Map::from_iter([("last_run".into(), Object(last_run))]))
}

// --------------------------------------------------------------- сборка

/// Итоговая нормализация настроек: python normalize_settings.
pub fn normalize_settings(data: &Value) -> Value {
    let raw = obj(data);
    let section = |key: &str| raw.get(key).cloned().unwrap_or(Null);
    let identity = obj(&section("profile_identity"));
    Object(Map::from_iter([
        ("version".into(), Value::from(schema::SETTINGS_VERSION)),
        ("program".into(), normalize_program(&section("program"))),
        ("window".into(), normalize_window(&section("window"))),
        (
            "appearance".into(),
            normalize_appearance(&section("appearance")),
        ),
        ("warnings".into(), normalize_warnings(&section("warnings"))),
        (
            "telegram_proxy".into(),
            normalize_telegram_proxy(&section("telegram_proxy")),
        ),
        ("dns".into(), normalize_dns(&section("dns"))),
        ("hosts".into(), normalize_hosts(&section("hosts"))),
        ("ui_state".into(), normalize_ui_state(&section("ui_state"))),
        (
            "profile_strategy_state".into(),
            normalize_profile_strategy_state(&section("profile_strategy_state")),
        ),
        (
            "user_profiles".into(),
            normalize_user_profiles(&section("user_profiles")),
        ),
        (
            "user_fakes".into(),
            normalize_user_fakes(&section("user_fakes")),
        ),
        (
            "orchestra".into(),
            normalize_orchestra(&section("orchestra")),
        ),
        ("updater".into(), normalize_updater(&section("updater"))),
        (
            "blockcheck".into(),
            normalize_blockcheck(&section("blockcheck")),
        ),
        ("folders".into(), normalize_folders(&section("folders"))),
        (
            "profile_identity".into(),
            Object(Map::from_iter([
                (
                    "winws2".into(),
                    normalize_identity_registry(identity.get("winws2").unwrap_or(&Null)),
                ),
                (
                    "winws1".into(),
                    normalize_identity_registry(identity.get("winws1").unwrap_or(&Null)),
                ),
            ])),
        ),
        (
            "remote_presets".into(),
            normalize_remote_presets(&section("remote_presets")),
        ),
        (
            "probe_gate".into(),
            normalize_probe_gate(&section("probe_gate")),
        ),
    ]))
}
