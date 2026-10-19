//! Порт profile/winws2_transport.py: диапазоны пакетов winws2.

use serde::{Deserialize, Serialize};

/// python OutRangeSettings: разобранный диапазон пакетов.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OutRangeSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub value: i64,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub raw_line: String,
}

fn default_mode() -> String {
    "n".to_string()
}

/// python WINWS2_PAYLOAD_NAMES: типы данных winws2 в порядке protocol.c.
pub const WINWS2_PAYLOAD_NAMES: [&str; 31] = [
    "all",
    "unknown",
    "empty",
    "known",
    "ipv4",
    "ipv6",
    "icmp",
    "http_req",
    "http_reply",
    "tls_client_hello",
    "tls_server_hello",
    "dtls_client_hello",
    "dtls_server_hello",
    "quic_initial",
    "wireguard_initiation",
    "wireguard_response",
    "wireguard_cookie",
    "wireguard_keepalive",
    "wireguard_data",
    "dht",
    "discord_ip_discovery",
    "stun",
    "xmpp_stream",
    "xmpp_starttls",
    "xmpp_proceed",
    "xmpp_features",
    "dns_query",
    "dns_response",
    "mtproto_initial",
    "bt_handshake",
    "utp_bt_handshake",
];

static BOUND_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

/// python _OUT_RANGE_RANGE_RE целиком.
fn is_range_shape(expr: &str) -> bool {
    let re = BOUND_RE.get_or_init(|| {
        regex::Regex::new(r"(?i)^(?:[ndspb]\d+(?:-|<)[ndspb]\d+|(?:-|<)[ndspb]\d+|[ndspb]\d+-)$").expect("regex")
    });
    re.is_match(expr)
}

static SIMPLE_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

/// python _OUT_RANGE_SIMPLE_RE: -(n|d)<число>.
fn is_simple_shape(expr: &str) -> bool {
    let re = SIMPLE_RE.get_or_init(|| {
        regex::Regex::new(r"(?i)^-[nd]\d+$").expect("regex")
    });
    re.is_match(expr)
}

/// python normalize_out_range_expression: без кавычек и в нижнем регистре.
pub fn normalize_out_range_expression(expression: &str) -> String {
    strip_outer_quotes(expression).to_lowercase()
}

/// python parse_out_range_expression: разбор выражения диапазона.
pub fn parse_out_range_expression(expression: &str, raw_line: &str) -> Option<OutRangeSettings> {
    let expr = normalize_out_range_expression(expression);
    if expr.is_empty() {
        return None;
    }
    let lowered = expr.to_lowercase();
    if lowered == "a" || lowered == "x" {
        return Some(OutRangeSettings {
            enabled: true,
            value: 0,
            mode: lowered.clone(),
            expression: lowered.clone(),
            raw_line: raw_line.to_string(),
        });
    }
    if is_simple_shape(&lowered) {
        let mode = lowered
            .chars()
            .nth(1)
            .expect("режим после прочерка")
            .to_string();
        let value: i64 = lowered[2..].parse().expect("число");
        return Some(OutRangeSettings {
            enabled: true,
            value,
            mode: mode.clone(),
            expression: format!("-{mode}{value}"),
            raw_line: raw_line.to_string(),
        });
    }
    if is_range_shape(&lowered) {
        return Some(OutRangeSettings {
            enabled: true,
            value: 0,
            mode: String::new(),
            expression: lowered,
            raw_line: raw_line.to_string(),
        });
    }
    None
}

/// python validate_winws2_payload_filter: имена типов через запятую.
pub fn validate_winws2_payload_filter(value: &str) -> bool {
    let raw = value.trim().to_lowercase();
    if raw.is_empty() {
        return false;
    }
    for item in raw.split(',') {
        let name = item.trim();
        if !WINWS2_PAYLOAD_NAMES.iter().any(|known| *known == name) {
            return false;
        }
        if name == "all" {
            return true;
        }
    }
    true
}

fn strip_outer_quotes(value: &str) -> String {
    let text = value.trim().to_string();
    if text.len() >= 2
        && ((text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\'')))
    {
        return text[1..text.len() - 1].trim().to_string();
    }
    text
}
