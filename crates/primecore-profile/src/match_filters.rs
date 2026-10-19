//! Порт profile/match_filters.py: протоколы, порты и каталог по match-строкам.

pub const TCP_L7: [&str; 5] = ["http", "tls", "xmpp", "mtproto", "bt"];

/// python l7_transport: транспорт для значений --filter-l7.
pub fn l7_transport(values: &[String]) -> Option<&'static str> {
    let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for value in values {
        for token in value.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                names.insert(token.to_lowercase());
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    if names
        .iter()
        .all(|name| TCP_L7.iter().any(|known| known == name))
    {
        Some("tcp")
    } else {
        Some("udp")
    }
}

/// python strategy_catalog_from_match_lines: каталог по match-строкам.
pub fn strategy_catalog_from_match_lines(match_lines: &[String]) -> String {
    if is_voice_match(match_lines) {
        return "voice".to_string();
    }
    let has_tcp = !filter_values(match_lines, "--filter-tcp").is_empty();
    let has_udp = !filter_values(match_lines, "--filter-udp").is_empty();
    if has_udp && !has_tcp {
        return "udp".to_string();
    }
    if has_tcp && !has_udp {
        if is_http80_match(match_lines) {
            return "http80".to_string();
        }
        return "tcp".to_string();
    }
    l7_transport(&filter_values(match_lines, "--filter-l7"))
        .unwrap_or("tcp")
        .to_string()
}

/// python protocol_label_from_match_lines: протокол словами.
pub fn protocol_label_from_match_lines(match_lines: &[String]) -> String {
    let has_l7 = !filter_values(match_lines, "--filter-l7").is_empty();
    let has_udp = !filter_values(match_lines, "--filter-udp").is_empty();
    let has_tcp = !filter_values(match_lines, "--filter-tcp").is_empty();
    if is_voice_match(match_lines) {
        return "Voice".to_string();
    }
    if has_tcp && (has_udp || has_l7) {
        return "TCP/UDP".to_string();
    }
    if has_l7 {
        return "L7".to_string();
    }
    if has_udp {
        return "UDP".to_string();
    }
    if is_http80_match(match_lines) {
        return "TCP/HTTP".to_string();
    }
    "TCP".to_string()
}

/// python ports_label_from_match_lines: порты словами.
pub fn ports_label_from_match_lines(match_lines: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (label, option_name) in [("TCP", "--filter-tcp"), ("UDP", "--filter-udp")] {
        let values = filter_values(match_lines, option_name);
        if !values.is_empty() {
            parts.push(format!("{label} {}", values.join(", ")));
        }
    }
    parts.join("; ")
}

/// python filter_values: значения одной опции из match-строк.
pub fn filter_values(match_lines: &[String], option_name: &str) -> Vec<String> {
    let prefix = format!("{}=", option_name.to_lowercase().trim_end_matches('=').to_string());
    match_lines
        .iter()
        .filter(|line| {
            line.to_lowercase().starts_with(&prefix)
                && line.split_once('=').is_some()
        })
        .filter_map(|line| line.split_once('='))
        .map(|(_head, value)| value.trim().to_string())
        .collect()
}

/// python is_voice_match: голосовой ли профиль.
pub fn is_voice_match(match_lines: &[String]) -> bool {
    let l7_values = filter_values(match_lines, "--filter-l7").join(",").to_lowercase();
    if ["stun", "discord", "wireguard"].iter().any(|token| l7_values.contains(token)) {
        return true;
    }
    let udp_values = filter_values(match_lines, "--filter-udp");
    let match_text = match_lines.join(" ").to_lowercase();
    if !["discord", "stun", "voice", "голос"].iter().any(|token| match_text.contains(token)) {
        return false;
    }
    udp_values.iter().any(|value| ports_overlap(value, 50000, 59000))
}

/// python is_http80_match: только HTTP на 80-м порту.
pub fn is_http80_match(match_lines: &[String]) -> bool {
    let tcp_values = filter_values(match_lines, "--filter-tcp");
    if tcp_values.is_empty() || !filter_values(match_lines, "--filter-udp").is_empty() {
        return false;
    }
    if l7_transport(&filter_values(match_lines, "--filter-l7")) == Some("udp") {
        return false;
    }
    let ports = parse_ports(&tcp_values.join(",").to_string());
    match ports {
        Some(ports) if ports.len() == 1 && ports.contains(&80) => true,
        _ => false,
    }
}

fn ports_overlap(raw_ports: &str, start: i64, end: i64) -> bool {
    for token in raw_ports.split(',') {
        let Some(bounds) = parse_port_token(token) else {
            continue;
        };
        if bounds.0 <= end && bounds.1 >= start {
            return true;
        }
    }
    false
}

fn parse_ports(raw_ports: &str) -> Option<std::collections::BTreeSet<i64>> {
    let mut ports: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for token in raw_ports.split(',') {
        let Some(bounds) = parse_port_token(token) else {
            continue;
        };
        let (start, end) = bounds;
        if start == end {
            ports.insert(start);
            continue;
        }
        if end - start <= 512 {
            ports.extend(start..=end);
        } else {
            ports.insert(start);
            ports.insert(end);
        }
    }
    Some(ports).filter(|ports| !ports.is_empty())
}

fn parse_port_token(token: &str) -> Option<(i64, i64)> {
    let stripped = token.trim();
    if stripped.is_empty() {
        return None;
    }
    if let Some((left, right)) = stripped.split_once('-') {
        if !left.trim().chars().all(|symbol| symbol.is_ascii_digit())
            || !right.trim().chars().all(|symbol| symbol.is_ascii_digit())
            || left.trim().is_empty()
            || right.trim().is_empty()
        {
            return None;
        }
        let start: i64 = left.trim().parse().ok()?;
        let end: i64 = right.trim().parse().ok()?;
        if start > end {
            return Some((end, start));
        }
        return Some((start, end));
    }
    if !stripped.chars().all(|symbol| symbol.is_ascii_digit()) {
        return None;
    }
    let port: i64 = stripped.parse().ok()?;
    Some((port, port))
}
