//! Порт `src/profile/icons.py` — значок профиля по имени и match-строкам.

use crate::match_filters::filter_values;

/// python ProfileIconSpec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIconSpec {
    pub icon_name: String,
    pub color: String,
}

#[inline]
fn icon(icon_name: &'static str, color: &'static str) -> ProfileIconSpec {
    ProfileIconSpec {
        icon_name: icon_name.to_string(),
        color: color.to_string(),
    }
}

/// python _KNOWN_ICONS (порядок вставки — словарь; доступ по ключу).
fn known_icons(key: &str) -> Option<ProfileIconSpec> {
    let spec = match key {
        "youtube" | "googlevideo" => icon("simple:youtube:YT", "#FF0000"),
        "discord" | "discord-updates" => icon("simple:discord:DI", "#5865F2"),
        "vencord" => icon("simple:vencord:VC", "#EB7396"),
        "telegram" => icon("simple:telegram:TG", "#229ED9"),
        "whatsapp" => icon("simple:whatsapp:WA", "#25D366"),
        "facebook" => icon("simple:facebook:FB", "#1877F2"),
        "instagram" => icon("simple:instagram:IN", "#E4405F"),
        "twitter" | "twimg" => icon("simple:x:X", "#000000"),
        "steam" => icon("simple:steam:ST", "#66C0F4"),
        "epicgames" => icon("simple:epicgames:EG", "#313131"),
        "ubisoft" => icon("simple:ubisoft:UB", "#006EF5"),
        "github" => icon("simple:github:GH", "#F0F3F6"),
        "twitch" => icon("simple:twitch:TW", "#9146FF"),
        "soundcloud" => icon("simple:soundcloud:SC", "#FF5500"),
        "tiktok" => icon("simple:tiktok:TT", "#000000"),
        "itch" => icon("simple:itchdotio:IT", "#FA5C5C"),
        "google" => icon("simple:google:GO", "#4285F4"),
        "googlecloud" => icon("simple:googlecloud:GC", "#4285F4"),
        "gemini" => icon("simple:googlegemini:GE", "#8E75B2"),
        "amazon" => icon("fa5b.amazon", "#FF9900"),
        "fandom" => icon("simple:fandom:FA", "#FA005A"),
        "microsoft" | "microsoft-store" => icon("fa5b.microsoft", "#00BCF2"),
        "anydesk" => icon("simple:anydesk:AD", "#EF443B"),
        "speedtest" => icon("simple:speedtest:ST", "#141526"),
        "akamai" => icon("simple:akamai:AK", "#0096D6"),
        "cloudflare" => icon("simple:cloudflare:CF", "#F38020"),
        "datacamp" => icon("fa5s.cloud", "#60A5FA"),
        "digitalocean" => icon("simple:digitalocean:DO", "#0080FF"),
        "fastly" => icon("simple:fastly:FS", "#FF282D"),
        "frantech" => icon("fa5s.server", "#F59E0B"),
        "hetzner" => icon("simple:hetzner:HE", "#D50C2D"),
        "novoserve" => icon("fa5s.server", "#2563EB"),
        "ovh" => icon("simple:ovh:OV", "#123F6D"),
        "railway" => icon("simple:railway:RW", "#A855F7"),
        "warp" => icon("simple:cloudflare:CF", "#F6821F"),
        "worldstream" => icon("fa5s.server", "#0EA5E9"),
        "roblox" => icon("simple:roblox:RB", "#E2231A"),
        "lol" => icon("simple:leagueoflegends:LO", "#C89B3C"),
        "riot" => icon("simple:riotgames:RI", "#D13639"),
        "valorant" => icon("simple:valorant:VA", "#FA4454"),
        "deepseek" => icon("simple:deepseek:DS", "#4D6BFE"),
        "claude" => icon("simple:claude:CL", "#D97757"),
        "chatgpt" => icon("own:openai:AI", "#10A37F"),
        "apple" => icon("simple:apple:AP", "#A2AAAD"),
        "notion" => icon("simple:notion:NO", "#B0B6BE"),
        "linkedin" => icon("fa5b.linkedin", "#0A66C2"),
        "zapret-moe" => icon("simple:forgejo:FJ", "#FB923C"),
        "lordfilm" => icon("fa5s.film", "#F59E0B"),
        "obsidian" => icon("simple:obsidian:OB", "#7C3AED"),
        "rutracker" => icon("fa5s.magnet", "#6AA2FF"),
        "rutor" => icon("fa5s.magnet", "#6AA2FF"),
        "timeweb" => icon("fa5s.server", "#2F80ED"),
        "zapretkvn" => icon("fa5s.server", "#31C48D"),
        "tankix" => icon("fa5s.gamepad", "#8B5CF6"),
        "7tv" => icon("fa5s.tv", "#60A5FA"),
        "porn" => icon("fa5s.user-shield", "#EC4899"),
        "all" => icon("fa5s.globe", "#60A5FA"),
        "general" => icon("fa5s.list-ul", "#94A3B8"),
        "faceinsta" => icon("fa5s.users", "#E4405F"),
        "myhostlist" => icon("fa5s.list-ul", "#94A3B8"),
        "mycdnlist" => icon("fa5s.cloud", "#60A5FA"),
        "ntc" => icon("fa5s.globe", "#60A5FA"),
        "z-library" => icon("fa5s.book", "#22C55E"),
        "net-cdn77" => icon("fa5s.cloud", "#60A5FA"),
        _ => return None,
    };
    Some(spec)
}

/// python _ICON_ALIASES.
fn icon_alias(identity: &str) -> Option<&'static str> {
    let alias = match identity {
        "youtube-v2" | "youtubeq" | "youtubegv" | "ytimg" | "i-ytimg" | "russia-youtubeq"
        | "russia-youtube-rtmps" => "youtube",
        "russia-discord" => "discord",
        "cloudflare-ipset" | "cloudflare-ipset-v6" | "cloudflare1" | "com-cloudflarecp" | "txrevive" => {
            "cloudflare"
        }
        "cloudfront" => "amazon",
        "usa-google" => "googlecloud",
        "google-backend" => "google",
        "lol-ru" | "lol-euw" | "com-leagueoflegends" => "lol",
        "com-riotcdn" => "riot",
        "com-valorant" => "valorant",
        "com-z-library" => "z-library",
        "githubusercontent" => "github",
        "10tv" => "7tv",
        "rbxcdn" => "roblox",
        "epicgames-fortnite" | "unrealengine" => "epicgames",
        "ubi" | "uplay" => "ubisoft",
        _ => return None,
    };
    Some(alias)
}

/// python _NAMED_COLORS.
fn named_color(identity: &str) -> Option<&'static str> {
    let color = match identity {
        "akamai" => "#0096D6",
        "cloudflare" => "#F38020",
        "datacamp" => "#60A5FA",
        "digitalocean" => "#0080FF",
        "fastly" => "#FF282D",
        "frantech" => "#F59E0B",
        "hetzner" => "#D50C2D",
        "novoserve" => "#2563EB",
        "ovh" => "#123F6D",
        "railway" => "#A855F7",
        "warp" => "#F6821F",
        "worldstream" => "#0EA5E9",
        "timeweb" => "#2F80ED",
        "zapretkvn" => "#31C48D",
        "roblox" => "#E2231A",
        "lol" | "lol-ru" | "lol-euw" => "#C89B3C",
        "rutracker" | "rutor" => "#6AA2FF",
        _ => return None,
    };
    Some(color)
}

const FALLBACK_PALETTE: [&str; 8] = [
    "#14B8A6",
    "#3B82F6",
    "#8B5CF6",
    "#EC4899",
    "#F97316",
    "#22C55E",
    "#06B6D4",
    "#EAB308",
];

/// python resolve_profile_icon: explicit → semantic → инициалы.
pub fn resolve_profile_icon(display_name: &str, match_lines: &[String]) -> ProfileIconSpec {
    let identities = profile_identities(display_name, match_lines);
    for identity in &identities {
        if let Some(found) = explicit_icon_for_identity(identity) {
            return found;
        }
    }
    if let Some(semantic) = semantic_icon_from_text(display_name, match_lines, &identities) {
        return semantic;
    }
    let identity = identities.first().cloned().unwrap_or_else(|| "profile".to_string());
    let color = named_color(&identity)
        .map(str::to_string)
        .unwrap_or_else(|| color_from_seed(&identity));
    let initials = initials_from_identity(&identity);
    ProfileIconSpec {
        icon_name: format!("profile-initials:{initials}"),
        color,
    }
}

/// python _profile_identity.
pub fn profile_identity(display_name: &str, match_lines: &[String]) -> String {
    let identities = profile_identities(display_name, match_lines);
    identities
        .first()
        .cloned()
        .unwrap_or_else(|| "profile".to_string())
}

/// python _profile_identities.
pub fn profile_identities(display_name: &str, match_lines: &[String]) -> Vec<String> {
    let mut candidates: Vec<String> = resource_values(match_lines);
    candidates.push(display_name.to_string());
    let mut identities: Vec<String> = Vec::new();
    for candidate in candidates {
        let normalized = normalize_identity(&candidate);
        if !normalized.is_empty() && !identities.contains(&normalized) {
            identities.push(normalized);
        }
    }
    if identities.is_empty() {
        identities.push("profile".to_string());
    }
    identities
}

fn explicit_icon_for_identity(identity: &str) -> Option<ProfileIconSpec> {
    let key = icon_alias(identity).unwrap_or(identity);
    known_icons(key)
}

fn semantic_icon_from_text(
    display_name: &str,
    match_lines: &[String],
    identities: &[String],
) -> Option<ProfileIconSpec> {
    let haystack = [
        display_name.to_string(),
        match_lines.join(" "),
        identities.join(" "),
    ]
    .join(" ")
    .to_lowercase();
    let has_any = |tokens: &[&str]| tokens.iter().any(|token| haystack.contains(token));
    if has_any(&["исключения", "exclude", "exclusion"]) {
        return Some(icon("fa5s.minus-circle", "#FACC15"));
    }
    if has_any(&["blacklist", "rublacklist", "russia-blacklist"]) {
        return Some(icon("fa5s.shield-alt", "#94A3B8"));
    }
    if has_any(&["голос", "звон", "voice"]) {
        return Some(icon("fa5s.microphone", "#38BDF8"));
    }
    if has_any(&["league of legends", "riotgames", "riot games"]) {
        return known_icons("lol");
    }
    if haystack.contains("valorant") {
        return known_icons("valorant");
    }
    if haystack.contains("riot") {
        return known_icons("riot");
    }
    if has_any(&["game", "games", "игр"]) {
        return Some(icon("fa5s.gamepad", "#8B5CF6"));
    }
    if haystack.contains("general") {
        return known_icons("general");
    }
    if has_any(&["все сайты", "мои сайты", "all sites"]) {
        return known_icons("all");
    }
    if has_any(&["18+", "porn", "xvideos", "xnxx"]) {
        return known_icons("porn");
    }
    None
}

fn resource_values(match_lines: &[String]) -> Vec<String> {
    [
        filter_values(match_lines, "--hostlist"),
        filter_values(match_lines, "--ipset"),
        filter_values(match_lines, "--hostlist-domains"),
        filter_values(match_lines, "--ipset-ip"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// python _normalize_identity: PurePosixPath.name / PureWindowsPath.name,
/// суффиксы, префиксы, доменная вторая-с-конца часть, не-буквы → '-'.
pub fn normalize_identity(value: &str) -> String {
    let mut text = value.trim().replace('\\', "/").to_lowercase();
    if text.is_empty() {
        return String::new();
    }
    if text.contains('/') {
        // PurePosixPath(text).name
        text = match text.rsplit('/').next() {
            Some(name) => name.trim().to_string(),
            None => String::new(),
        };
    } else if text.len() == 2 && text.as_bytes()[1] == b':' {
        // PureWindowsPath("c:").name == ''
        return String::new();
    }
    // python re.sub(r"\.(txt|lst|list|json)$", "", text, flags=re.I)
    for suffix in [".txt", ".lst", ".list", ".json"] {
        if text.ends_with(suffix) {
            text.truncate(text.len() - suffix.len());
            break;
        }
    }
    for prefix in ["ipset-", "hostlist-", "list-"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.to_string();
            break;
        }
    }
    // python re.split(r"[\s(]", text, maxsplit=1)[0]
    if let Some(index) = text.find(|c: char| c.is_whitespace() || c == '(') {
        text.truncate(index);
    }
    text = text
        .trim_matches(|c| c == '.' || c == '-' || c == '_')
        .to_string();
    if let Some(second_to_last) = second_to_last_domain(&text) {
        text = second_to_last;
    }
    // python re.sub(r"[^a-z0-9а-яё-]+", "-", text) — text уже в lowercase.
    let mut normalized = String::with_capacity(text.len());
    let mut pending_dash = false;
    for ch in text.chars() {
        let keep = ch.is_ascii_digit()
            || ch.is_ascii_lowercase()
            || ('а'..='я').contains(&ch)
            || ch == 'ё';
        if keep {
            if pending_dash && !normalized.is_empty() {
                normalized.push('-');
            }
            pending_dash = false;
            normalized.push(ch);
        } else {
            pending_dash = true;
        }
    }
    let normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        return "profile".to_string();
    }
    normalized
}

/// python: если в тексте есть точки и >=2 непустых частей — вторая с конца.
fn second_to_last_domain(text: &str) -> Option<String> {
    if !text.contains('.') {
        return None;
    }
    let parts: Vec<&str> = text.split('.').filter(|part| !part.is_empty()).collect();
    if parts.len() >= 2 {
        return Some(parts[parts.len() - 2].to_string());
    }
    None
}

/// python _initials_from_identity.
pub fn initials_from_identity(identity: &str) -> String {
    let words: Vec<&str> = identity
        .split(|c: char| {
            !(c.is_ascii_digit() || c.is_ascii_lowercase() || ('а'..='я').contains(&c) || c == 'ё')
        })
        .filter(|part| !part.is_empty())
        .collect();
    if words.is_empty() {
        return "P".to_string();
    }
    if words.len() == 1 {
        let chars: Vec<char> = words[0].chars().collect();
        let take = if chars.len() > 1 { 2 } else { 1 };
        let initials: String = chars.iter().take(take).collect();
        // python .upper() — кириллица тоже.
        return initials
            .chars()
            .map(|c| c.to_uppercase().next().unwrap_or(c))
            .collect();
    }
    let first = words[0].chars().next().unwrap_or('p');
    let second = words[1].chars().next().unwrap_or('p');
    format!(
        "{}{}",
        first.to_uppercase().next().unwrap_or(first),
        second.to_uppercase().next().unwrap_or(second)
    )
}

/// python _color_from_seed: первый байт sha1(seed) % 8.
pub fn color_from_seed(seed: &str) -> String {
    let digest = crate::sha1::sha1_bytes(seed.as_bytes());
    // python digest[0] — первый байт SHA-1.
    FALLBACK_PALETTE[(digest[0] as usize) % FALLBACK_PALETTE.len()].to_string()
}
