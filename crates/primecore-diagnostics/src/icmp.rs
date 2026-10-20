//! Ядро `src/utils/windows_icmp.py` — пинг и шаг трассировки без запуска ping.exe.
//!
//! Сам вызов Windows ICMP API винапи-системы компилируется с `unsafe` и живёт
//! в отдельном слое платформенного вызова; здесь только переносимая логика:
//! итог сводки пинга [`summarize`], разбор hop-ответа [`classify_hop`] и
//! [`WindowsPingResult`]/[`TraceHopResult`]. Провайдер [`IcmpProvider`] умеет
//! отдавать фиктивные ответы в тестах и незаметно сообщать «пинг недоступен»
//! тем же результатом, что python на не-Windows.
//!
//! Python личные константы: `IP_SUCCESS = 0`, `IP_REQ_TIMED_OUT = 11010`,
//! `IP_TTL_EXPIRED_TRANSIT = 11013`.

/// Ответ прошёл полностью.
pub const IP_SUCCESS: u32 = 0;
/// Никто не ответил вовремя.
pub const IP_REQ_TIMED_OUT: u32 = 11010;
/// Срок жизни пакета истёк на промежуточном узле.
pub const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;

// Виды шага трассировки: кто ответил, когда у пакета кончается срок жизни.
/// Ответил промежуточный узел: срок жизни пакета истёк на нём.
pub const HOP_ROUTER: &str = "router";
/// Ответил сам адрес назначения.
pub const HOP_TARGET: &str = "target";
/// Никто не ответил за отведённое время.
pub const HOP_SILENT: &str = "silent";
/// Пинг в этой системе недоступен.
pub const HOP_UNSUPPORTED: &str = "unsupported";

/// Итог нескольких пингов хоста (python `WindowsPingResult`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WindowsPingResult {
    pub ok: bool,
    pub average_ms: Option<f64>,
    pub sent: u32,
    pub received: u32,
    pub resolved_ip: Option<String>,
    pub error_code: Option<String>,
    pub detail: String,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub ttl: Option<u32>,
}

/// Ответ одного шага трассировки (python `TraceHopResult`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TraceHopResult {
    pub kind: &'static str,
    pub address: String,
    pub rtt_ms: Option<f64>,
}

impl TraceHopResult {
    pub fn new(kind: &'static str) -> Self {
        TraceHopResult {
            kind,
            ..Default::default()
        }
    }
}

/// `IPAddr` для IcmpSendEcho: байты адреса в памяти идут в сетевом порядке.
///
/// Поэтому число собирается в порядке байтов процессора (little-endian), а не как
/// big-endian: иначе пинговался адрес задом наперёд (142.251.150.4 →
/// 4.150.251.142), и проверка честно писала «таймаут» у живого сервера.
#[must_use]
pub fn ipv4_to_dword(ip: &str) -> u32 {
    let octets: [u8; 4] = {
        let mut parsed = [0u8; 4];
        for (index, piece) in ip.split('.').enumerate().take(4) {
            parsed[index] = piece.parse().unwrap_or(0);
        }
        parsed
    };
    u32::from_le_bytes(octets)
}

/// Адрес из ответа ICMP (DWORD в сетевом порядке байтов памяти, как python
/// `pack("<I", reply.Address)` + `inet_ntoa`).
#[must_use]
pub fn dword_to_ipv4(value: u32) -> String {
    let bytes = value.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Сводка ответов пинга: среднее, разброс и «почему не доехало» (python `_summarize`).
#[must_use]
pub fn summarize(
    rtts: &[f64],
    sent: u32,
    ip: &str,
    last_status: Option<u32>,
    ttl: Option<u32>,
) -> WindowsPingResult {
    let received = rtts.len() as u32;
    if received > 0 {
        let average_ms = rtts.iter().sum::<f64>() / rtts.len() as f64;
        return WindowsPingResult {
            ok: true,
            average_ms: Some(average_ms),
            sent,
            received,
            resolved_ip: Some(ip.to_string()),
            error_code: None,
            detail: format!("{}ms", round_half_away(average_ms)),
            min_ms: rtts.iter().copied().reduce(f64::min),
            max_ms: rtts.iter().copied().reduce(f64::max),
            ttl,
        };
    }
    if last_status == Some(IP_REQ_TIMED_OUT) {
        return WindowsPingResult {
            ok: false,
            sent,
            received: 0,
            resolved_ip: Some(ip.to_string()),
            error_code: Some("TIMEOUT".to_string()),
            detail: "Timeout".to_string(),
            ..Default::default()
        };
    }
    WindowsPingResult {
        ok: false,
        sent,
        received: 0,
        resolved_ip: Some(ip.to_string()),
        error_code: Some(format!("ICMP_{}", last_status.unwrap_or(0))),
        detail: format!("ICMP status {}", last_status.unwrap_or(0)),
        ..Default::default()
    }
}

/// python `f"{value:.0f}"` — округление .5 к ближайшему чётному.
fn round_half_away(value: f64) -> i64 {
    // python format spam: 1.5 → "2", 2.5 → "2".
    if value.fract() == 0.5 {
        let floor = value.floor();
        if (floor as i64) % 2 == 0 {
            floor as i64
        } else {
            (floor + 1.0) as i64
        }
    } else {
        value.round() as i64
    }
}

/// Разбор ответа одного шага: успех назначения, истёкший срок жизни или молчание.
#[must_use]
pub fn classify_hop(status: u32, address: &str, rtt_ms: f64) -> TraceHopResult {
    if status == IP_SUCCESS {
        return TraceHopResult {
            kind: HOP_TARGET,
            address: address.to_string(),
            rtt_ms: Some(rtt_ms),
        };
    }
    if status == IP_TTL_EXPIRED_TRANSIT {
        return TraceHopResult {
            kind: HOP_ROUTER,
            address: address.to_string(),
            rtt_ms: Some(rtt_ms),
        };
    }
    TraceHopResult::new(HOP_SILENT)
}

/// Пинг-вызовы для [`crate::my_network`] и net_access: переносимые, без сети.
///
/// Настоящие ответы даст слой платформенного вызова; до него все функции
/// отвечают «в этой системе недоступен» — ровно как python на не-Windows.
pub struct IcmpUnavailable;

impl IcmpUnavailable {
    /// Python `ping_ipv4_host_winapi` при недоступном API: `resolved_ip` пуст.
    #[must_use]
    pub fn ping_ipv4(&self, count: u32) -> WindowsPingResult {
        WindowsPingResult {
            ok: false,
            sent: count,
            received: 0,
            error_code: Some("UNSUPPORTED".to_string()),
            detail: "Windows ICMP API unavailable".to_string(),
            ..WindowsPingResult::default()
        }
    }

    /// Python `ping_ipv6_winapi` при недоступном API.
    #[must_use]
    pub fn ping_ipv6(&self, count: u32) -> WindowsPingResult {
        WindowsPingResult {
            ok: false,
            sent: count,
            received: 0,
            error_code: Some("UNSUPPORTED".to_string()),
            detail: "Windows ICMPv6 API unavailable".to_string(),
            ..Default::default()
        }
    }

    /// Python `trace_hop_ipv4` при недоступном API.
    #[must_use]
    pub fn trace_hop(&self) -> TraceHopResult {
        TraceHopResult::new(HOP_UNSUPPORTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dword_roundtrip_matches_python() {
        // python: int(struct.unpack("<I", socket.inet_aton("142.251.150.4"))[0]) == 0x496fb8e
        assert_eq!(ipv4_to_dword("142.251.150.4"), 0x0496FB8E);
        assert_eq!(ipv4_to_dword("192.168.1.1"), 0x0101A8C0);
        assert_eq!(dword_to_ipv4(0x040200CB), "203.0.2.4");
        assert_eq!(dword_to_ipv4(0x0496FB8E), "142.251.150.4");
    }

    #[test]
    fn summarize_python_formats() {
        let good = summarize(&[1.4, 2.7], 2, "1.1.1.1", None, Some(64));
        assert!(good.ok);
        assert_eq!(good.detail, "2ms");
        assert_eq!(good.min_ms, Some(1.4));
        assert_eq!(good.max_ms, Some(2.7));
        assert_eq!(good.ttl, Some(64));
        let timeout = summarize(&[], 3, "1.1.1.1", Some(IP_REQ_TIMED_OUT), None);
        assert_eq!(timeout.error_code.as_deref(), Some("TIMEOUT"));
        assert_eq!(timeout.detail, "Timeout");
        assert_eq!(timeout.sent, 3);
        assert_eq!(timeout.resolved_ip.as_deref(), Some("1.1.1.1"));
        let other = summarize(&[], 3, "1.1.1.1", Some(5), None);
        assert_eq!(other.error_code.as_deref(), Some("ICMP_5"));
        assert_eq!(other.detail, "ICMP status 5");
    }

    #[test]
    fn hop_classification() {
        let target = classify_hop(IP_SUCCESS, "1.1.1.1", 12.0);
        assert_eq!(target.kind, HOP_TARGET);
        assert_eq!(target.rtt_ms, Some(12.0));
        let router = classify_hop(IP_TTL_EXPIRED_TRANSIT, "10.0.0.1", 1.0);
        assert_eq!(router.kind, HOP_ROUTER);
        let silent = classify_hop(5, "", 0.0);
        assert_eq!(silent.kind, HOP_SILENT);
        assert!(IcmpUnavailable.trace_hop().kind == HOP_UNSUPPORTED);
        let cannot = IcmpUnavailable.ping_ipv6(3);
        assert_eq!(cannot.sent, 3);
        assert_eq!(cannot.error_code.as_deref(), Some("UNSUPPORTED"));
    }
}
