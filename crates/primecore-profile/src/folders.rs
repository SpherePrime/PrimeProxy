//! Порт `src/folders/` (defaults.py + store.py + ordering.py) и адаптер
//! `src/profile/folders.py` — состояние папок пресетов и профилей.
//!
//! python-словари здесь — `serde_json::Value::Object` c `preserve_order`
//! (порядок вставки maintained). Сортировки — стабильные, как python `sorted`.

use serde_json::{json, Map, Value};

pub const COMMON_FOLDER_KEY: &str = "common";
pub const PINNED_FOLDER_KEY: &str = "pinned";
pub const VOICE_FOLDER_KEY: &str = "voice";

const WINWS2_PRESET_FOLDERS: [(&str, &str, bool); 7] = [
    ("all-tcp-udp", "ALL TCP & UDP", false),
    ("common", "Общие", true),
    ("1-10-3", "1.10.3", false),
    ("1-10-0", "1.10.0", false),
    ("1-9-9", "1.9.9", false),
    ("game-filter", "Game filter", false),
    ("circular", "Circular", false),
];

const WINWS1_PRESET_FOLDERS: [(&str, &str, bool); 13] = [
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
    ("common", "Общие", true),
];

/// публичный общий список папок профилей.
pub const PROFILE_FOLDERS: [(&str, &str, bool); 16] = [
    ("youtube", "YouTube", false),
    ("discord", "Discord", false),
    // Звонки по STUN — один профиль на весь пресет.
    ("voice", "Голосовые звонки (Discord, Telegram)", false),
    ("github", "GitHub", false),
    // У больших мессенджеров свои группы.
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
    ("common", "Общие", true),
    ("all-sites", "Все сайты", false),
];

/// Папки, появившиеся позже: {новая папка: старое место таких профилей}.
pub fn profile_folder_splits() -> Vec<(&'static str, &'static str)> {
    vec![
        ("voice", "discord"),
        ("telegram", "messengers"),
        ("whatsapp", "messengers"),
    ]
}

fn default_state(folder_specs: &[(&str, &str, bool)]) -> Value {
    let mut folders = Map::new();
    for (index, (key, name, system)) in folder_specs.iter().enumerate() {
        folders.insert(
            (*key).to_string(),
            json!({
                "name": name,
                "order": index,
                "collapsed": false,
                "system": system,
            }),
        );
    }
    json!({"version": 1, "folders": folders, "items": {}})
}

/// python build_default_preset_folders.
pub fn build_default_preset_folders(scope_key: &str) -> Value {
    default_state(if winws1_scope(scope_key) {
        &WINWS1_PRESET_FOLDERS
    } else {
        &WINWS2_PRESET_FOLDERS
    })
}

/// python build_default_profile_folders.
pub fn build_default_profile_folders() -> Value {
    default_state(&PROFILE_FOLDERS)
}

// ---------------------------------------------------------------- классификаторы

/// python classify_preset_folder.
pub fn classify_preset_folder(name: &str, scope_key: &str) -> String {
    let text = name.trim().to_lowercase();
    if winws1_scope(scope_key) {
        return classify_winws1_preset_folder(&text);
    }
    classify_default_winws2_preset_folder(&text)
}

fn classify_default_winws2_preset_folder(text: &str) -> String {
    if text.contains("all tcp") && text.contains("udp") {
        return "all-tcp-udp".to_string();
    }
    if text.contains("1.10.3") {
        return "1-10-3".to_string();
    }
    if text.contains("1.10.0") {
        return "1-10-0".to_string();
    }
    if text.contains("1.9.9") {
        return "1-9-9".to_string();
    }
    if text.contains("game filter") {
        return "game-filter".to_string();
    }
    if text.contains("circular") {
        return "circular".to_string();
    }
    COMMON_FOLDER_KEY.to_string()
}

/// python classify_profile_folder.
pub fn classify_profile_folder(text: &str) -> String {
    classify_profile_folder_text(text.trim().to_lowercase())
}

/// Чистая функция текста, python lru_cache на 4096 emulate by mutex map.
fn classify_profile_folder_text(value: String) -> String {
    if value.is_empty() {
        return COMMON_FOLDER_KEY.to_string();
    }
    if has_any_token(&value, &["youtube", "googlevideo", "ytimg"]) {
        return "youtube".to_string();
    }
    if shared_voice_filter_matches(&value) {
        return VOICE_FOLDER_KEY.to_string();
    }
    if has_any_token(&value, &["discord", "vencord"]) {
        return "discord".to_string();
    }
    if has_any_token(&value, &["github", "ghcr.io"]) {
        return "github".to_string();
    }
    if has_any_token(&value, &["telegram", "mtproto"]) {
        return "telegram".to_string();
    }
    if has_any_token(&value, &["whatsapp"]) {
        return "whatsapp".to_string();
    }
    if has_any_token(&value, &["viber", "signal"]) {
        return "messengers".to_string();
    }
    if has_any_token(
        &value,
        &["facebook", "instagram", "tiktok", "twitter", "x.com", "vk"],
    ) {
        return "social".to_string();
    }
    if has_any_token(&value, &["roblox", "rbxcdn"]) {
        return "roblox".to_string();
    }
    if has_any_token(
        &value,
        &["amazon", "awsapps", "awsglobalaccelerator", "cloudfront"],
    ) {
        return "amazon".to_string();
    }
    if has_any_token(
        &value,
        &[
            "game",
            "epicgames",
            "epic games",
            "fortnite",
            "unrealengine",
            "ubisoft",
            "ubi.com",
            "uplay",
            "valorant",
            "riot",
            "steam",
            "itch.io",
            "tanki",
            "tankix",
            "lol",
            "league of legends",
            "battlenet",
            "battle.net",
            "wow",
            "dead by daylight",
        ],
    ) {
        return "games".to_string();
    }
    if has_any_token(
        &value,
        &[
            "akamai",
            "cloudflare",
            "datacamp",
            "digitalocean",
            "fastly",
            "frantech",
            "google cloud",
            "ipset-google",
            "hetzner",
            "novoserve",
            "ovh",
            "railway",
            "usa google",
            "warp",
            "worldstream",
        ],
    ) {
        return "hosters".to_string();
    }
    if has_any_token(&value, &["timeweb", "zapretkvn"]) {
        return "zapretkvn".to_string();
    }
    if looks_like_all_sites_profile(&value) {
        return "all-sites".to_string();
    }
    if mentions_site_or_list(&value) {
        return "sites".to_string();
    }
    COMMON_FOLDER_KEY.to_string()
}

/// Регулярное выражение из python:
/// r"--filter-l7=\S*(?<![a-z0-9_])stun(?![a-z0-9_])"
fn shared_voice_filter_matches(value: &str) -> bool {
    static VOICE_RE: std::sync::LazyLock<fancy_regex::Regex> = std::sync::LazyLock::new(|| {
        fancy_regex::Regex::new(r"--filter-l7=\S*(?<![a-z0-9_])stun(?![a-z0-9_])").expect("regex")
    });
    VOICE_RE.is_match(value).unwrap_or(false)
}

/// Токен обязан начинаться на границе слова: `x.com` не находится в
/// `wix.com`. Правая граница не требуется.
fn has_any_token(value: &str, tokens: &[&str]) -> bool {
    tokens
        .iter()
        .any(|token| token_pattern(token).is_match(value).unwrap_or(false))
}

/// python _token_pattern с кэшем: (?<![a-z0-9а-яё])token
fn token_pattern(token: &str) -> fancy_regex::Regex {
    TOKEN_PATTERNS.with(|cache| {
        cache
            .borrow_mut()
            .entry(token.to_string())
            .or_insert_with(|| {
                fancy_regex::Regex::new(&format!("(?<![a-z0-9а-яё]){}", regex::escape(token)))
                    .expect("token regex")
            })
            .clone()
    })
}

thread_local! {
    /// python @lru_cache(maxsize=256) на _token_pattern.
    static TOKEN_PATTERNS: std::cell::RefCell<std::collections::HashMap<String, fancy_regex::Regex>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

fn winws1_scope(scope_key: &str) -> bool {
    scope_key.trim().to_lowercase() == "winws1"
}

fn classify_winws1_preset_folder(text: &str) -> String {
    if text.is_empty() {
        return COMMON_FOLDER_KEY.to_string();
    }
    if text.contains("1.10.3") {
        return "1-10-3".to_string();
    }
    if text.contains("1.10.0") {
        return "1-10-0".to_string();
    }
    if text.contains("1.9.9a") {
        return "1-9-9a".to_string();
    }
    if ["allsite", "allsites", "all-site", "all sites", "все сайты"]
        .iter()
        .any(|token| text.contains(token))
    {
        return "all-sites".to_string();
    }
    if text.contains("alt") {
        return "alt".to_string();
    }
    if [
        "game filter",
        "game",
        "valorant",
        "lol",
        "league of legends",
    ]
    .iter()
    .any(|token| text.contains(token))
    {
        return "games".to_string();
    }
    if ["ytdis", "bystro", "youtube"]
        .iter()
        .any(|token| text.contains(token))
    {
        return "youtube".to_string();
    }
    if text.contains("discord") {
        return "discord".to_string();
    }
    if ["mgts", "rosmts", "rosmega", "ufanet", "shigulovski"]
        .iter()
        .any(|token| text.contains(token))
    {
        return "providers".to_string();
    }
    if text.contains("bolvan") {
        return "bolvan".to_string();
    }
    if text.contains("faketls") {
        return "fake-tls".to_string();
    }
    if [
        "split",
        "md5sig",
        "ttl",
        "padencap",
        "wssize",
        "badseq",
        "sniext",
        "datanoack",
        "multisplit",
    ]
    .iter()
    .any(|token| text.contains(token))
    {
        return "split-md5-ttl".to_string();
    }
    COMMON_FOLDER_KEY.to_string()
}

fn looks_like_all_sites_profile(text: &str) -> bool {
    if ["allsite", "all-site", "all sites", "все сайты"]
        .iter()
        .any(|token| text.contains(token))
    {
        return true;
    }
    let has_include = [
        "--hostlist=",
        "--hostlist-domains=",
        "--ipset=",
        "--ipset-ip=",
    ]
    .iter()
    .any(|token| text.contains(token));
    let has_exclude = ["--hostlist-exclude", "--ipset-exclude"]
        .iter()
        .any(|token| text.contains(token));
    has_exclude && !has_include
}

fn mentions_site_or_list(text: &str) -> bool {
    if [
        "--hostlist=",
        "--hostlist-domains=",
        "--ipset=",
        "--ipset-ip=",
    ]
    .iter()
    .any(|token| text.contains(token))
    {
        return true;
    }
    static SITE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\b[a-z0-9-]+\.(?:ru|com|org|net|io|gg|tv)\b").expect("regex")
    });
    SITE_RE.is_match(text)
}
