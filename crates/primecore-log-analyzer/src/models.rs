//! Порт `src/winws_log_analyzer/models.py` — модели результата разбора
//! debug-лога winws2.

use std::collections::{BTreeMap, HashMap};

/// python `VERDICT_UNMODIFIED` — пакет не изменён.
pub const VERDICT_UNMODIFIED: &str = "unmodified";
/// python `VERDICT_MODIFIED` — пакет изменён (reinject modified).
pub const VERDICT_MODIFIED: &str = "modified";
/// python `VERDICT_DROP` — пакет отброшен.
pub const VERDICT_DROP: &str = "drop";
/// python `VERDICT_NONE` — блок оборван (лог обрезан) либо терминатор
/// не встретился.
pub const VERDICT_NONE: &str = "";

/// Ключ агрегата соединений: python `(proto, remote_ip, remote_port)`.
pub type ConnectionKey = (String, String, i64);

/// python `ListCheckRecord` — одна positive-проверка hostlist/ipset
/// внутри пакетного блока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCheckRecord {
    /// Путь списка из лога либо "fixed".
    pub list_path: String,
    /// "hostlist" | "ipset".
    pub kind: String,
    pub profile_id: i64,
    /// Hostname либо IP, для которого проверка дала positive.
    pub target: String,
}

/// python `PacketRecord` — один пакетный блок лога.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRecord {
    pub packet_id: i64,
    /// Строка заголовка блока (1-based).
    pub line_no: i64,
    /// "out" | "in".
    pub direction: String,
    pub length: i64,
    /// 4 | 6.
    pub ip_version: i64,
    pub src_ip: String,
    pub src_port: i64,
    pub dst_ip: String,
    pub dst_port: i64,
    /// tcp | udp | ...
    pub proto: String,
    pub ttl: Option<i64>,
    pub tcp_flags: String,
    /// tls/quic/http/unknown.
    pub l7proto: String,
    pub hostname: String,
    pub payload_type: String,
    pub profile_id: Option<i64>,
    pub profile_name: String,
    pub profile_cached: bool,
    /// Вердикт-терминатор блока: [`VERDICT_NONE`] по умолчанию.
    pub verdict: String,
    pub tls_details: Vec<String>,
    pub positive_checks: Vec<ListCheckRecord>,
    /// lua-функции, реально сделавшие desync.
    pub lua_applied: Vec<String>,
    /// DELAY desync / delayed-обработка внутри блока.
    pub delayed: bool,
    pub replay_count: i64,
}

impl Default for PacketRecord {
    fn default() -> Self {
        Self {
            packet_id: 0,
            line_no: 0,
            direction: String::new(),
            length: 0,
            ip_version: 0,
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            proto: String::new(),
            ttl: None,
            tcp_flags: String::new(),
            l7proto: String::new(),
            hostname: String::new(),
            payload_type: String::new(),
            profile_id: None,
            profile_name: String::new(),
            profile_cached: false,
            verdict: VERDICT_NONE.to_string(),
            tls_details: Vec::new(),
            positive_checks: Vec::new(),
            lua_applied: Vec::new(),
            delayed: false,
            replay_count: 0,
        }
    }
}

/// python `ConnectionRecord` — агрегат пакетов по удалённой стороне
/// (proto, remote_ip, remote_port).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectionRecord {
    pub proto: String,
    pub remote_ip: String,
    pub remote_port: i64,
    pub hostname: String,
    pub l7proto: String,
    pub profile_ids: Vec<i64>,
    pub profile_names: Vec<String>,
    pub packets_total: i64,
    pub packets_out: i64,
    pub packets_in: i64,
    /// Счётчик по каждому вердикту (python `dict[str, int]`).
    pub verdict_counts: HashMap<String, i64>,
    /// Basename списков с positive-проверками.
    pub positive_lists: Vec<String>,
    pub lua_applied: Vec<String>,
    pub packets: Vec<PacketRecord>,
    pub packets_truncated: bool,
    pub first_line_no: i64,
}

impl ConnectionRecord {
    /// python-свойство `key` — `(proto, remote_ip, remote_port)`.
    #[must_use]
    pub fn key(&self) -> ConnectionKey {
        (self.proto.clone(), self.remote_ip.clone(), self.remote_port)
    }
}

/// python `WinwsLogParseResult` — итог разбора файла.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WinwsLogParseResult {
    pub file_path: String,
    /// id -> "имя: func1, func2" (python строит словарь в порядке
    /// возрастания id — [`BTreeMap`] сохраняет это свойство).
    pub profiles: BTreeMap<i64, String>,
    /// (путь, загружено hostов).
    pub hostlists: Vec<(String, i64)>,
    /// (путь, загружено подсетей).
    pub ipsets: Vec<(String, i64)>,
    pub packets_total: i64,
    pub connections: Vec<ConnectionRecord>,
    pub positive_checks_total: i64,
    /// Блоки без распознанной IP-строки.
    pub unparsed_blocks: i64,
    /// "packet: id=..." строки неизвестного формата (например, Linux
    /// nfqws — намеренно не поддерживается, GUI только для Windows).
    pub unrecognized_packet_lines: i64,
    pub cancelled: bool,
}
