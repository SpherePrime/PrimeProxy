//! Порт `src/profile/strategy_shape.py` — форма стратегии WinWS2.
//!
//! Диапазоны `--in-range`/`--out-range` до первой `--lua-desync` — настройки
//! профиля; остальное по порядку — сама стратегия. Стратегия «составная»,
//! если после первой `--lua-desync` встречается внутрипрофильный фильтр
//! (`--payload`/диапазоны): она из нескольких веток, но ОДНА стратегия.

pub const PAYLOAD_OPTION: &str = "--payload";
pub const RANGE_OPTIONS: [&str; 2] = ["--in-range", "--out-range"];
pub const FILTER_OPTIONS: [&str; 3] = ["--payload", "--in-range", "--out-range"];
pub const LUA_DESYNC_PREFIX: &str = "--lua-desync=";
pub const PAYLOAD_ALL: &str = "all";
pub const PAYLOAD_BADGE_SEPARATOR: &str = " · ";

pub fn option_name(line: &str) -> String {
    line.trim()
        .split_once('=')
        .map(|(before, _)| before)
        .unwrap_or_else(|| line.trim())
        .trim()
        .to_lowercase()
}

pub fn option_value(line: &str) -> String {
    line.trim()
        .split_once('=')
        .map(|(_, after)| after.trim().to_string())
        .unwrap_or_default()
}

pub fn is_lua_desync_line(line: &str) -> bool {
    line.trim().to_lowercase().starts_with(LUA_DESYNC_PREFIX)
}

pub fn is_filter_line(line: &str) -> bool {
    let name = option_name(line);
    FILTER_OPTIONS.iter().any(|option| *option == name.as_str())
}

pub fn is_range_line(line: &str) -> bool {
    let name = option_name(line);
    RANGE_OPTIONS.iter().any(|option| *option == name.as_str())
}

/// Форма стратегии (python StrategyShape). Диапазоны до первой lua —
/// настройки профиля; остальное по порядку — тело.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct StrategyShape {
    /// Диапазоны до первой --lua-desync: настройки профиля.
    pub profile_range_lines: Vec<String>,
    /// Остальные строки стратегии по порядку.
    pub body_lines: Vec<String>,
    /// После первой --lua-desync есть внутрипрофильный фильтр.
    pub composite: bool,
    /// --payload каждой ветки (группы подряд идущих --lua-desync) по порядку.
    pub payload_scopes: Vec<String>,
}

impl StrategyShape {
    /// Lua-строки тела (python lua_lines).
    pub fn lua_lines(&self) -> Vec<String> {
        self.body_lines
            .iter()
            .filter(|line| is_lua_desync_line(line))
            .cloned()
            .collect()
    }
}

pub fn strategy_shape(lines: &[String]) -> StrategyShape {
    let clean: Vec<String> = lines
        .iter()
        .map(|raw| raw.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    let first_lua = clean
        .iter()
        .position(|line| is_lua_desync_line(line));
    let mut profile_ranges: Vec<String> = Vec::new();
    let mut body: Vec<String> = Vec::new();
    for (index, line) in clean.iter().enumerate() {
        let before_lua_or_none = match first_lua {
            Some(boundary) => index < boundary,
            None => true,
        };
        if is_range_line(line) && before_lua_or_none {
            profile_ranges.push(line.clone());
        } else {
            body.push(line.clone());
        }
    }
    let composite = first_lua.is_some()
        && clean
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                first_lua.map(|boundary| *index > boundary).unwrap_or(false)
            })
            .any(|(_, line)| is_filter_line(line));
    StrategyShape {
        payload_scopes: payload_scopes(&body),
        profile_range_lines: profile_ranges,
        body_lines: body,
        composite,
    }
}

/// python: группы веток — последующий фильт-начинает новую ветвь ветвь ветвь.
fn payload_scopes(body_lines: &[String]) -> Vec<String> {
    let mut payload = PAYLOAD_ALL.to_string();
    let mut scopes: Vec<String> = Vec::new();
    let mut in_branch = false;
    for line in body_lines {
        if is_lua_desync_line(line) {
            if !in_branch {
                scopes.push(payload.clone());
                in_branch = true;
            }
            continue;
        }
        if is_filter_line(line) {
            in_branch = false;
            if option_name(line) == PAYLOAD_OPTION {
                payload = if option_value(line).is_empty() {
                    PAYLOAD_ALL.to_string()
                } else {
                    option_value(line)
                };
            }
        }
    }
    scopes
}

/// Токены --payload со снятием дублей (python _payload_tokens).
pub fn payload_tokens(value: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    for part in value.split(',') {
        let token = part.trim().to_lowercase();
        if !token.is_empty() && !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    if tokens.is_empty() {
        tokens.push(PAYLOAD_ALL.to_string());
    }
    tokens
}

/// Отпечаток составной стратегии: сравнение с каталогом.
///
/// Порядок строк важен. ``--payload`` сравнивается как набор типов,
/// отсутствие ``--payload`` перед первой ``--lua-desync`` равно
/// ``--payload=all``, из нескольких ``--payload`` подряд действует последний.
///
/// Хвост после последней `--lua-desync` отбрасывается.
pub fn composite_identity(body_lines: &[String]) -> Vec<(String, String)> {
    let mut items: Vec<(String, String)> = Vec::new();
    for raw in body_lines {
        let clean = raw.trim().to_string();
        if clean.is_empty() {
            continue;
        }
        let name = option_name(&clean);
        if is_lua_desync_line(&clean) {
            if !items.iter().any(|(kind, _)| kind == "payload") {
                items.insert(0, ("payload".to_string(), PAYLOAD_ALL.to_string()));
            }
            items.push(("lua".to_string(), clean));
            continue;
        }
        if name == PAYLOAD_OPTION {
            let mut tokens = payload_tokens(&option_value(&clean));
            tokens.sort();
            let value = tokens.join(",");
            if let Some(last) = items.last_mut() {
                if last.0 == "payload" {
                    *last = ("payload".to_string(), value);
                    continue;
                }
            }
            items.push(("payload".to_string(), value));
            continue;
        }
        if RANGE_OPTIONS.contains(&name.as_str()) {
            items.push((
                "range".to_string(),
                format!("{name}={}", option_value(&clean)),
            ));
            continue;
        }
        items.push(("other".to_string(), clean));
    }
    while let Some(last) = items.last() {
        if last.0 != "lua" {
            items.pop();
        } else {
            break;
        }
    }
    items
}

/// Один `--payload` вместо нескольких веток: объединение типов, all поглощает.
pub const GAME_PAYLOAD_TOKENS: [&str; 4] = ["wireguard_initiation", "dht", "discord_ip_discovery", "stun"];

pub fn payload_token_label(token: &str) -> &str {
    match token {
        "tls_client_hello" => "TLS",
        "http_req" => "HTTP",
        "quic_initial" => "QUIC",
        "wireguard_initiation" => "WireGuard",
        "dht" => "DHT",
        "discord_ip_discovery" => "Discord",
        "stun" => "STUN",
        "unknown" => "прочее",
        "known" => "известные",
        "empty" => "пустые",
        other => other,
    }
}


pub fn payload_scope_label(scope: &str, only: bool) -> String {
    let tokens = payload_tokens(scope);
    if tokens.len() == 1 && tokens[0] == PAYLOAD_ALL {
        return if only { "всё".to_string() } else { "прочее".to_string() };
    }
    if tokens.len() == GAME_PAYLOAD_TOKENS.len()
        && tokens.iter().all(|token| GAME_PAYLOAD_TOKENS.contains(&token.as_str()))
    {
        return "игры".to_string();
    }
    tokens
        .iter()
        .map(|token| payload_token_label(token))
        .collect::<Vec<&str>>()
        .join("+")
}

/// Подпись типов пакетов составной стратегии: «TLS · HTTP · TLS+HTTP».
pub fn payload_badge_text(scopes: &[String]) -> String {
    if scopes.len() < 2 {
        return String::new();
    }
    let unique = {
        let mut token_sets: Vec<Vec<String>> = scopes
            .iter()
            .map(|scope| {
                let mut tokens = payload_tokens(scope);
                tokens.sort();
                tokens
            })
            .collect();
        token_sets.sort();
        token_sets.dedup();
        token_sets.len() == 1
    };
    let mut labels: Vec<String> = Vec::new();
    for scope in scopes {
        let label = payload_scope_label(scope, unique);
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels.join(PAYLOAD_BADGE_SEPARATOR)
}

/// Значок типов пакетов для экранного диктора.
pub fn payload_badge_accessible_text(badge: &str) -> String {
    let clean = badge.trim();
    if clean.is_empty() {
        String::new()
    } else {
        format!("типы пакетов: {clean}")
    }
}

pub fn union_payload(scopes: &[String]) -> String {
    let mut tokens: Vec<String> = Vec::new();
    for scope in scopes {
        for token in payload_tokens(scope) {
            if token == PAYLOAD_ALL {
                return PAYLOAD_ALL.to_string();
            }
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }
    if tokens.is_empty() {
        PAYLOAD_ALL.to_string()
    } else {
        tokens.join(",")
    }
}
