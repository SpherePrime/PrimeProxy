//! Порт `src/settings/schema.py`: константы настроек и дефолтные секции.

use serde_json::{json, Map, Value};
use serde_json::Value::Object;


/// Секция настроек `program`. Отдаётся как JSON-объект, ключи те же, что
/// в питоновском `default_program()`.
pub const ORCHESTRA_ASK_EXAMPLE_DEFAULT: &str = ORCHESTRA_ASK_TLS;

pub fn orchestra_askey_is_known(askey: &str) -> bool {
    ORCHESTRA_ASKEYS.contains(&askey)
}

pub const SETTINGS_DIR_NAME: &str = "user";
pub const SETTINGS_DATABASE_FILE_NAME: &str = "settings.sqlite3";
pub const SETTINGS_VERSION: i64 = 1;

pub const DEFAULT_WINDOW_OPACITY: i64 = 100;
pub const DEFAULT_TINTED_INTENSITY: i64 = 15;
pub const MAX_TINTED_INTENSITY: i64 = 100;
pub const DEFAULT_TG_PROXY_HOST: &str = "127.0.0.1";
pub const DEFAULT_TG_PROXY_PORT: i64 = 1353;
pub const DEFAULT_TG_PROXY_UPSTREAM_PORT: i64 = 1080;

pub use primecore_mode::ALL_LAUNCH_METHODS;
pub use primecore_mode::{
    ENGINE_WINWS1, ENGINE_WINWS2, SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS1,
    SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS2,
};

pub const ORCHESTRA_ASK_TLS: &str = "tls";
pub const ORCHESTRA_ASK_HTTP: &str = "http";
pub const ORCHESTRA_ASK_QUIC: &str = "quic";
pub const ORCHESTRA_ASK_DISCORD: &str = "discord";
pub const ORCHESTRA_ASK_WIREGUARD: &str = "wireguard";
pub const ORCHESTRA_ASK_MTPROTO: &str = "mtproto";
pub const ORCHESTRA_ASK_DNS: &str = "dns";
pub const ORCHESTRA_ASK_STUN: &str = "stun";
pub const ORCHESTRA_ASK_UNKNOWN: &str = "unknown";

pub const ORCHESTRA_ASKEYS: [&str; 9] = [
    ORCHESTRA_ASK_TLS,
    ORCHESTRA_ASK_HTTP,
    ORCHESTRA_ASK_QUIC,
    ORCHESTRA_ASK_DISCORD,
    ORCHESTRA_ASK_WIREGUARD,
    ORCHESTRA_ASK_MTPROTO,
    ORCHESTRA_ASK_DNS,
    ORCHESTRA_ASK_STUN,
    ORCHESTRA_ASK_UNKNOWN,
];

pub static VALID_LAUNCH_METHODS: &[&str] = &primecore_mode::ALL_LAUNCH_METHODS;
pub const VALID_DISPLAY_MODES: [&str; 3] = ["dark", "light", "system"];
pub const VALID_UI_LANGUAGES: [&str; 2] = ["ru", "en"];
pub const VALID_BACKGROUND_PRESETS: [&str; 3] = ["standard", "amoled", "rkn_chan"];
pub const VALID_SIDEBAR_ICON_STYLES: [&str; 2] = ["standard", "windows11_fluent"];
pub const VALID_TG_PROXY_MODES: [&str; 2] = ["socks5", "mtproxy"];
pub const VALID_TG_PROXY_UPSTREAM_MODES: [&str; 2] = ["fallback", "always"];
pub const TRAY_CLOSE_MODE_MINIMIZE_AND_CLOSE: &str = "minimize_and_close";
pub const TRAY_CLOSE_MODE_MINIMIZE_ONLY: &str = "minimize_only";
pub const TRAY_CLOSE_MODE_NORMAL: &str = "normal";
pub const VALID_TRAY_CLOSE_MODES: [&str; 3] = [
    TRAY_CLOSE_MODE_MINIMIZE_AND_CLOSE,
    TRAY_CLOSE_MODE_MINIMIZE_ONLY,
    TRAY_CLOSE_MODE_NORMAL,
];
/// Сколько прошлых проверок сети помнит программа.
pub const CHECK_HISTORY_LIMIT: usize = 50;
/// История вкладок «Проверка домена» и «DNS подмена»: свои списки, короче общего.
pub static TAB_HISTORY_KEYS: &[&str] = &["domain_history", "dns_history", "servers_history"];
pub const TAB_HISTORY_LIMIT: usize = 20;
/// Ограничения на одну запись истории.
pub const CHECK_HISTORY_TEXT_LIMIT: usize = 400;
pub const CHECK_HISTORY_PROBLEMS_LIMIT: usize = 12;
pub const CHECK_HISTORY_STATES_LIMIT: usize = 80;
pub const CHECK_HISTORY_LEVELS: [&str; 4] = ["ok", "warn", "fail", "unknown"];
/// Работал ли Zapret во время проверки; пусто — узнать не удалось.
pub const CHECK_HISTORY_ZAPRET: [&str; 3] = ["on", "off", ""];

pub const FAKE_KINDS: [&str; 10] = [
    "tls", "quic", "http", "stun", "dht", "discord", "wireguard", "dtls", "zeros", "other",
];

pub fn string_in(text: &str, set: &[&str]) -> bool {
    set.contains(&text)
}

pub fn default_program() -> Value {
    json_object([
        ("dpi_autostart", Value::Bool(true)),
        ("gui_autostart_enabled", Value::Bool(false)),
        (
            "strategy_launch_method",
            Value::String(primecore_mode::DEFAULT_LAUNCH_METHOD.to_string()),
        ),
        (
            SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS1,
            Value::String(String::new()),
        ),
        (
            SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS2,
            Value::String(String::new()),
        ),
        ("auto_update_enabled", Value::Bool(true)),
        ("discord_auto_restart", Value::Bool(true)),
        ("max_blocked", Value::Bool(false)),
        ("russian_state_media_blocked", Value::Bool(false)),
        ("defender_disabled", Value::Bool(false)),
        (
            "last_seen_version",
            Value::String(String::new()),
        ),
    ])
}

pub fn default_window() -> Value {
    json_object([
        ("x", Value::Null),
        ("y", Value::Null),
        ("width", Value::Null),
        ("height", Value::Null),
        ("maximized", Value::Bool(false)),
        ("opacity", Value::from(DEFAULT_WINDOW_OPACITY)),
        (
            "tray_close_mode",
            Value::String(TRAY_CLOSE_MODE_NORMAL.to_string()),
        ),
    ])
}

pub fn default_appearance() -> Value {
    json_object([
        ("display_mode", Value::String("dark".into())),
        ("ui_language", Value::String("ru".into())),
        ("accent_color", Value::Null),
        ("follow_windows_accent", Value::Bool(false)),
        ("tinted_background", Value::Bool(false)),
        (
            "tinted_background_intensity",
            Value::from(DEFAULT_TINTED_INTENSITY),
        ),
        ("background_preset", Value::String("standard".into())),
        ("rkn_background", Value::Null),
        ("animations_enabled", Value::Bool(false)),
        ("smooth_scroll_enabled", Value::Bool(false)),
        ("editor_smooth_scroll_enabled", Value::Bool(false)),
        ("live_animations_enabled", Value::Bool(true)),
        ("sidebar_icon_style", Value::String("standard".into())),
        ("garland_enabled", Value::Bool(false)),
        ("snowflakes_enabled", Value::Bool(false)),
        ("selected_theme", Value::String(String::new())),
    ])
}

pub fn default_warnings() -> Value {
    json_object([
        ("tray_hint_shown", Value::Bool(false)),
        ("disable_telega_warning", Value::Bool(false)),
        ("disable_kaspersky_warning", Value::Bool(false)),
        ("isp_dns_info_shown", Value::Bool(false)),
        ("tg_proxy_deeplink_done", Value::Bool(false)),
        ("onboarding_tour_done", Value::Bool(false)),
        ("profile_display_order_hint_shown", Value::Bool(false)),
    ])
}

pub fn default_telegram_proxy() -> Value {
    json_object([
        ("enabled", Value::Bool(true)),
        ("host", Value::String(DEFAULT_TG_PROXY_HOST.into())),
        ("port", Value::from(DEFAULT_TG_PROXY_PORT)),
        ("mode", Value::String("mtproxy".into())),
        ("upstream_enabled", Value::Bool(true)),
        ("upstream_host", Value::String(String::new())),
        ("upstream_port", Value::from(DEFAULT_TG_PROXY_UPSTREAM_PORT)),
        ("upstream_preset_id", Value::String(String::new())),
        ("upstream_mode", Value::String("fallback".into())),
        ("upstream_udp_enabled", Value::Bool(false)),
        ("upstream_user", Value::String(String::new())),
        ("upstream_pass", Value::String(String::new())),
        ("cloudflare_enabled", Value::Bool(false)),
        ("cloudflare_domains", Value::Array(Vec::new())),
        ("cloudflare_worker_enabled", Value::Bool(false)),
        ("cloudflare_worker_domains", Value::Array(Vec::new())),
        ("mtproxy_secret", Value::String(String::new())),
        ("dc_ip", Value::Array(Vec::new())),
        ("pool_size", Value::from(4)),
        ("buffer_kb", Value::from(256)),
        ("fake_tls_domain", Value::String(String::new())),
        ("proxy_protocol", Value::Bool(false)),
        ("auto_deeplink", Value::Bool(true)),
    ])
}

pub fn default_dns() -> Value {
    json_object([("custom_servers", Value::Array(Vec::new()))])
}

pub fn default_hosts() -> Value {
    let engine = json_object([
        ("catalog", Value::String(String::new())),
        ("checked_at", Value::String(String::new())),
        ("suspects", Value::Array(Vec::new())),
        ("services", Object(Map::new())),
        ("pool", Object(Map::new())),
    ]);
    json_object([
        ("active_domains", Value::Array(Vec::new())),
        ("selection", Object(Map::new())),
        ("engine", engine),
    ])
}

pub fn default_ui_state() -> Value {
    json_object([("sidebar_expanded", Value::Bool(true))])
}

pub fn default_profile_strategy_state() -> Value {
    json_object([
        ("version", Value::from(1)),
        ("profiles", Object(Map::new())),
    ])
}

pub fn default_user_profiles() -> Value {
    json_object([
        ("version", Value::from(1)),
        ("profiles", Object(Map::new())),
    ])
}

pub fn default_user_fakes() -> Value {
    json_object([
        ("version", Value::from(1)),
        ("fakes", Object(Map::new())),
    ])
}

pub fn default_orchestra_settings() -> Value {
    json_object([
        ("strict_detection", Value::Bool(true)),
        ("keep_debug_file", Value::Bool(false)),
        ("auto_restart_on_discord_fail", Value::Bool(true)),
        ("discord_fails_for_restart", Value::from(3)),
        ("lock_successes", Value::from(3)),
        ("unlock_fails", Value::from(3)),
    ])
}

pub fn default_orchestra_locked_maps() -> Value {
    askey_maps_with(Object(Map::new()))
}

pub fn default_orchestra_user_locked_maps() -> Value {
    askey_maps_with(Value::Array(Vec::new()))
}

pub fn default_orchestra_user_blocked_maps() -> Value {
    askey_maps_with(Object(Map::new()))
}

pub fn default_orchestra() -> Value {
    json_object([
        ("settings", default_orchestra_settings()),
        (
            "whitelist",
            json_object([("user_domains", Value::Array(Vec::new()))]),
        ),
        ("locked", default_orchestra_locked_maps()),
        ("user_locked", default_orchestra_user_locked_maps()),
        ("user_blocked", default_orchestra_user_blocked_maps()),
        ("history", Object(Map::new())),
    ])
}

pub fn default_updater() -> Value {
    json_object([
        (
            "auto_check",
            json_object([("last_success_at", Value::from(0.0))]),
        ),
        (
            "self_repair",
            json_object([("attempts", Value::Array(Vec::new()))]),
        ),
        ("skipped_version", Value::String(String::new())),
        (
            "auto_install",
            json_object([
                ("version", Value::String(String::new())),
                ("attempts", Value::from(0)),
                ("from_version", Value::String(String::new())),
                ("granted_at", Value::from(0.0)),
                ("outcome", Value::String(String::new())),
                ("why", Value::String(String::new())),
                ("who", Value::String(String::new())),
                ("via", Value::String(String::new())),
                ("dl_kib", Value::from(0)),
            ]),
        ),
        (
            "whats_new",
            json_object([
                ("seen_version", Value::String(String::new())),
                (
                    "pending",
                    json_object([
                        ("version", Value::String(String::new())),
                        ("history", Value::Array(Vec::new())),
                    ]),
                ),
            ]),
        ),
    ])
}

pub fn default_blockcheck() -> Value {
    json_object([
        ("user_domains", Value::Array(Vec::new())),
        ("strategy_history", Object(Map::new())),
        ("check_history", Value::Array(Vec::new())),
        ("domain_history", Value::Array(Vec::new())),
        ("dns_history", Value::Array(Vec::new())),
        ("servers_history", Value::Array(Vec::new())),
    ])
}

pub fn default_folders() -> Value {
    json_object([
        ("version", Value::from(1)),
        (
            "presets",
            json_object([
                ("winws2", default_preset_folders("winws2")),
                ("winws1", default_preset_folders("winws1")),
            ]),
        ),
        ("profiles", default_profile_folders()),
    ])
}

pub fn default_profile_identity() -> Value {
    json_object([
        ("winws2", Object(Map::new())),
        ("winws1", Object(Map::new())),
    ])
}

pub fn default_probe_gate() -> Value {
    json_object([("last_run", Object(Map::new()))])
}

pub fn default_remote_presets() -> Value {
    json_object([
        ("winws2", Object(Map::new())),
        ("winws1", Object(Map::new())),
    ])
}

pub fn build_default_settings() -> Value {
    json_object([
        ("version", Value::from(SETTINGS_VERSION)),
        ("program", default_program()),
        ("window", default_window()),
        ("appearance", default_appearance()),
        ("warnings", default_warnings()),
        ("telegram_proxy", default_telegram_proxy()),
        ("dns", default_dns()),
        ("hosts", default_hosts()),
        ("ui_state", default_ui_state()),
        ("profile_strategy_state", default_profile_strategy_state()),
        ("user_profiles", default_user_profiles()),
        ("user_fakes", default_user_fakes()),
        ("orchestra", default_orchestra()),
        ("updater", default_updater()),
        ("blockcheck", default_blockcheck()),
        ("folders", default_folders()),
        ("profile_identity", default_profile_identity()),
        ("remote_presets", default_remote_presets()),
        ("probe_gate", default_probe_gate()),
    ])
}

// ---------------------------------------------------------------- папки

pub const FOLDER_COMMON_KEY: &str = "common";
pub const FOLDER_PINNED_KEY: &str = "pinned";
pub const FOLDER_VOICE_KEY: &str = "voice";

type FolderSpec = (&'static str, &'static str, bool);

pub const WINWS2_PRESET_FOLDERS: &[FolderSpec] = &[
    ("all-tcp-udp", "ALL TCP & UDP", false),
    (FOLDER_COMMON_KEY, "Общие", true),
    ("1-10-3", "1.10.3", false),
    ("1-10-0", "1.10.0", false),
    ("1-9-9", "1.9.9", false),
    ("game-filter", "Game filter", false),
    ("circular", "Circular", false),
];

pub const WINWS1_PRESET_FOLDERS: &[FolderSpec] = &[
    ("all-sites", "Все сайты", false),
    ("1-10-3", "1.10.3", false),
    ("1-10-0", "1.10.0", false),
    ("1-9-9a", "1.9.9a", false),
    ("alt", "ALT", false),
    ("games", "Игры", false),
    ("youtube", "YouTube", false),
    ("discord", "Discord", false),
    ("providers", "Провайдеры", false),
    ("bolvan", "Bolvan", false),
    ("fake-tls", "Fake TLS", false),
    ("split-md5-ttl", "Split / MD5 / TTL", false),
    (FOLDER_COMMON_KEY, "Общие", true),
];

pub const PROFILE_FOLDERS: &[FolderSpec] = &[
    ("youtube", "YouTube", false),
    ("discord", "Discord", false),
    (FOLDER_VOICE_KEY, "Голосовые звонки (Discord, Telegram)", false),
    ("github", "GitHub", false),
    ("telegram", "Telegram", false),
    ("whatsapp", "WhatsApp", false),
    ("messengers", "Мессенджеры", false),
    ("social", "Соцсети", false),
    ("games", "Игры", false),
    ("roblox", "Roblox", false),
    ("amazon", "Amazon", false),
    ("hosters", "Хостеры", false),
    ("sites", "Сайты", false),
    ("zapretkvn", "ZapretKVN", false),
    (FOLDER_COMMON_KEY, "Общие", true),
    ("all-sites", "Все сайты", false),
];

/// Папки, которые появились позже остальных: {новая папка: старое место}.
pub const PROFILE_FOLDER_SPLITS: [(&str, &str); 3] = [
    (FOLDER_VOICE_KEY, "discord"),
    ("telegram", "messengers"),
    ("whatsapp", "messengers"),
];

fn build_default_state(specs: &[FolderSpec]) -> Value {
    let folder_entries: Vec<(String, Value)> = specs
        .iter()
        .enumerate()
        .map(|(index, (key, name, system))| {
            (
                (*key).to_string(),
                json_object([
                    ("name", Value::String((*name).to_string())),
                    ("order", Value::from(index as i64)),
                    ("collapsed", Value::Bool(false)),
                    ("system", Value::Bool(*system)),
                ]),
            )
        })
        .collect();
    json_object([
        ("version", Value::from(1)),
        ("folders", Value::Object(to_map(folder_entries))),
        ("items", Object(Map::new())),
    ])
}

pub fn default_preset_folders(scope_key: &str) -> Value {
    let specs = if scope_key.trim().to_lowercase() == "winws1"
    {
        WINWS1_PRESET_FOLDERS
    } else {
        WINWS2_PRESET_FOLDERS
    };
    build_default_state(specs)
}

pub fn default_profile_folders() -> Value {
    build_default_state(PROFILE_FOLDERS)
}

// --------------------------------------------------------------- утилиты

pub fn json_object<I>(entries: I) -> Value
where
    I: IntoIterator<Item = (&'static str, Value)>,
{
    Object(to_map(
        entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    ))
}

fn to_map(entries: Vec<(String, Value)>) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key, value);
    }
    map
}

fn askey_maps_with(empty: Value) -> Value {
    let mut map = Map::new();
    for askey in ORCHESTRA_ASKEYS {
        map.insert((*askey).to_string(), empty.clone());
    }
    Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cursor_invariants() {
        let settings = build_default_settings();
        assert_eq!(settings.get("version"), Some(&Value::from(SETTINGS_VERSION)));
        assert_eq!(
            settings
                .get("program")
                .and_then(|p| p.get("strategy_launch_method")),
            Some(&Value::String("zapret2_mode".into()))
        );
    }

}
