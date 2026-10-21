//! Порт классификаторов из `folders/defaults.py`.
//!
//! `classify_preset_folder` раскладывает имена файлов пресетов по папкам
//! пресетов (winws2/winws1), `classify_profile_folder` — тексты профилей по
//! профилям. Токены проверяются по левой границе слова
//! (`(?<![a-z0-9а-яё])<токен>`, правой границы нет: `game` покрывает
//! `games`, `steam` — `steamcommunity`), поэтому используются регулярные
//! выражения с ретроспективной проверкой — крейт `fancy-regex` (std `regex`
//! lookbehind не поддерживает).

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::{COMMON_FOLDER_KEY, VOICE_FOLDER_KEY};

/// python `_SHARED_VOICE_FILTER`: stun — общий протокол звонков
/// (`--filter-l7=stun`), а не признак Discord, хотя в одном фильтре с ним
/// обычно стоит и discord.
static VOICE_FILTER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"--filter-l7=\S*(?<![a-z0-9_])stun(?![a-z0-9_])").ok());

/// python `_mentions_site_or_list`: упоминание домена сайта.
static SITE_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b[a-z0-9-]+\.(?:ru|com|org|net|io|gg|tv)\b").ok());

macro_rules! token_group {
    ($name:ident, [$($token:expr),* $(,)?]) => {
        static $name: LazyLock<Vec<Regex>> =
            LazyLock::new(|| compile_token_patterns(&[$($token),*]));
    };
}

token_group!(YOUTUBE_TOKENS, ["youtube", "googlevideo", "ytimg"]);
token_group!(DISCORD_TOKENS, ["discord", "vencord"]);
token_group!(GITHUB_TOKENS, ["github", "ghcr.io"]);
token_group!(TELEGRAM_TOKENS, ["telegram", "mtproto"]);
token_group!(WHATSAPP_TOKENS, ["whatsapp"]);
token_group!(MESSENGERS_TOKENS, ["viber", "signal"]);
token_group!(
    SOCIAL_TOKENS,
    ["facebook", "instagram", "tiktok", "twitter", "x.com", "vk"]
);
token_group!(ROBLOX_TOKENS, ["roblox", "rbxcdn"]);
token_group!(
    AMAZON_TOKENS,
    ["amazon", "awsapps", "awsglobalaccelerator", "cloudfront"]
);
token_group!(
    GAMES_TOKENS,
    [
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
    ]
);
token_group!(
    HOSTERS_TOKENS,
    [
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
    ]
);
token_group!(ZAPRETKVN_TOKENS, ["timeweb", "zapretkvn"]);

/// python `classify_preset_folder(name, scope_key)`.
///
/// Текст имени приводится к `strip().lower()`, затем проверяются маркеры
/// версии/фильтра. Для `winws1` действует отдельная ветка правил.
#[must_use]
pub fn classify_preset_folder(name: &str, scope_key: &str) -> String {
    let text = name.trim().to_lowercase();
    if is_winws1_scope(scope_key) {
        return classify_winws1_preset_folder(&text);
    }
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

/// python `classify_profile_folder(text)`.
#[must_use]
pub fn classify_profile_folder(text: &str) -> String {
    classify_profile_folder_text(&text.trim().to_lowercase())
}

/// python `_classify_profile_folder_text`: порядок правил значим — первый
/// совпавший маркер определяет папку.
#[must_use]
pub fn classify_profile_folder_text(value: &str) -> String {
    if value.is_empty() {
        return COMMON_FOLDER_KEY.to_string();
    }
    if has_any_token(value, &YOUTUBE_TOKENS) {
        return "youtube".to_string();
    }
    if voice_filter_matches(value) {
        return VOICE_FOLDER_KEY.to_string();
    }
    if has_any_token(value, &DISCORD_TOKENS) {
        return "discord".to_string();
    }
    if has_any_token(value, &GITHUB_TOKENS) {
        return "github".to_string();
    }
    if has_any_token(value, &TELEGRAM_TOKENS) {
        return "telegram".to_string();
    }
    if has_any_token(value, &WHATSAPP_TOKENS) {
        return "whatsapp".to_string();
    }
    if has_any_token(value, &MESSENGERS_TOKENS) {
        return "messengers".to_string();
    }
    if has_any_token(value, &SOCIAL_TOKENS) {
        return "social".to_string();
    }
    if has_any_token(value, &ROBLOX_TOKENS) {
        return "roblox".to_string();
    }
    if has_any_token(value, &AMAZON_TOKENS) {
        return "amazon".to_string();
    }
    if has_any_token(value, &GAMES_TOKENS) {
        return "games".to_string();
    }
    if has_any_token(value, &HOSTERS_TOKENS) {
        return "hosters".to_string();
    }
    if has_any_token(value, &ZAPRETKVN_TOKENS) {
        return "zapretkvn".to_string();
    }
    if looks_like_all_sites_profile(value) {
        return "all-sites".to_string();
    }
    if mentions_site_or_list(value) {
        return "sites".to_string();
    }
    COMMON_FOLDER_KEY.to_string()
}

/// python `_has_any_token`: токен обязан начинаться на границе слова —
/// `x.com` не находится в `wix.com`, `lol` — в `trololo`. Правой границы
/// нет: `game` покрывает `games`, `steam` — `steamcommunity`.
fn has_any_token(value: &str, patterns: &[Regex]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern.is_match(value).unwrap_or(false))
}

/// python `_token_pattern`: `(?<![a-z0-9а-яё])<escaped token>`.
fn compile_token_patterns(tokens: &[&str]) -> Vec<Regex> {
    tokens
        .iter()
        .filter_map(|token| Regex::new(&format!("(?<![a-z0-9а-яё]){}", escape_regex(token))).ok())
        .collect()
}

/// Минимальное экранирование метасимволов регулярных выражений в токене
/// (python использует `re.escape`).
fn escape_regex(token: &str) -> String {
    let mut escaped = String::with_capacity(token.len());
    for character in token.chars() {
        if "\\.+*?()|[]{}^$".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn voice_filter_matches(value: &str) -> bool {
    VOICE_FILTER_RE
        .as_ref()
        .is_some_and(|pattern| pattern.is_match(value).unwrap_or(false))
}

/// python `_looks_like_all_sites_profile`: явные маркеры «все сайты» либо
/// только исключения (`--hostlist-exclude`/`--ipset-exclude`) без включений.
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

/// python `_mentions_site_or_list`: явные hostlist/ipset либо домен сайта.
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
    SITE_RE
        .as_ref()
        .is_some_and(|pattern| pattern.is_match(text).unwrap_or(false))
}

/// python `_is_winws1_scope`.
fn is_winws1_scope(scope_key: &str) -> bool {
    scope_key.trim().to_lowercase() == "winws1"
}

/// python `_classify_winws1_preset_folder`: проверка простым вхождением
/// подстроки (`token in text`), версия важнее остальных маркеров.
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
