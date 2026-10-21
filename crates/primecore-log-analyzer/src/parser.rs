//! Порт `src/winws_log_analyzer/parser.py` — потоковый парсер
//! debug-лога winws2.
//!
//! Ключевая тонкость формата: строки `packet: id=N ...` встречаются в
//! двух ролях — заголовок блока (содержит `len=` и `outbound|inbound`)
//! и терминатор-вердикт (`reinject unmodified|reinject modified|drop`).
//! Внутри одного блока при reassembly встречаются `REPLAY IP4:` /
//! `REPLAYING/SENDING delayed packet` — они не открывают новых пакетов.
//!
//! Поддерживается только Windows-формат (winws2). Linux-формат nfqws
//! (заголовок `packet: id=N len=N mark=...` без outbound/inbound,
//! вердикты `pass modified/unmodified`) намеренно не поддерживается —
//! GUI работает только под Windows. Такие строки учитываются в
//! `unrecognized_packet_lines`, чтобы дрейф формата был виден в сводке,
//! а не выглядел как пустой лог.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use regex::Regex;

use crate::models::{
    ConnectionKey, ConnectionRecord, ListCheckRecord, PacketRecord, WinwsLogParseResult,
    VERDICT_DROP, VERDICT_MODIFIED, VERDICT_UNMODIFIED,
};

/// python `DEFAULT_MAX_PACKETS_PER_CONNECTION` — сколько пакетов
/// соединения хранить для таблицы: первая половина — начало соединения
/// (рукопожатие, SNI, профиль), вторая — его конец. Счётчики и вердикты
/// считаются по всем пакетам.
pub const DEFAULT_MAX_PACKETS_PER_CONNECTION: usize = 200;
/// python `DEFAULT_MAX_RETAINED_PACKETS` — общий предел хранимых пакетов
/// на весь журнал: отладочный журнал winws2 бывает в сотни мегабайт, а
/// каждый пакет — отдельный объект в памяти.
pub const DEFAULT_MAX_RETAINED_PACKETS: i64 = 200_000;

/// python `_CALLBACK_LINE_INTERVAL` — как часто (в строках) дёргать
/// прогресс и отмену.
const CALLBACK_LINE_INTERVAL: i64 = 2000;

static RE_PACKET_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^packet: id=(\d+) len=(\d+) (outbound|inbound) IPv6=(\d)").expect("regex")
});
// У "reinject modified" в новых сборках есть хвост "len 74 => 148" (nfqws.c).
static RE_PACKET_VERDICT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^packet: id=(\d+) (reinject unmodified|reinject modified|drop)(?: len \d+ => \d+)?\s*$",
    )
    .expect("regex")
});
static RE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^IP([46]): (\S+) => (\S+) proto=(\w+) ttl=(\d+)(?: sport=(\d+) dport=(\d+))?(?:.*? flags=(\S+))?",
    )
    .expect("regex")
});
// Между port= и l7proto= в разных сборках бывают доп. поля (icmp=0:0),
// а вместо ip= — пара ip1=/ip2= (desync.c), поэтому середина не фиксируется.
static RE_PROFILE_SEARCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^desync profile search for \w+ .*?l7proto=(\S+) ssid='[^']*' hostname='([^']*)'")
        .expect("regex")
});
static RE_LIST_CHECK_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\* (hostlist|ipset) check for profile (\d+)").expect("regex"));
static RE_LIST_CHECK_RESULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[([^\]]+)\] (?:include|exclude) (?:hostlist|ipset) check for (\S+) : (positive|negative)")
        .expect("regex")
});
static RE_PROFILE_MATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^desync profile (\d+) \(([^)]*)\) matches").expect("regex"));
static RE_PROFILE_CACHED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^using cached desync profile (\d+) \(([^)]*)\)").expect("regex"));
static RE_PROFILE_CONNTRACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^using desync profile (\d+) \(([^)]*)\) from conntrack entry").expect("regex")
});
static RE_DPI_DESYNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^dpi desync .*connection_proto=(\S+) payload_type=(\S*)").expect("regex")
});
static RE_TLS_DETAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^TLS ([\w ]+?) (?:ext )?: (.+)$").expect("regex"));
static RE_HOSTNAME_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^hostname: (\S+)").expect("regex"));
static RE_LUA_APPLIED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\* lua '([^']+)' : desync\s*$").expect("regex"));
static RE_DELAYED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(DELAY desync|REPLAYING delayed packet|SENDING delayed packet)").expect("regex")
});
static RE_REPLAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^REPLAYING delayed packet").expect("regex"));
// Преамбула
static RE_PREAMBLE_PROFILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^profile (\d+) \(([^)]*)\) lua (\w+)\(").expect("regex"));
static RE_PREAMBLE_LOADED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Loaded (\d+) (hosts|ip/subnets) from (.+)$").expect("regex"));

fn verdict_of(reinject: &str) -> String {
    match reinject {
        "reinject unmodified" => VERDICT_UNMODIFIED.to_string(),
        "reinject modified" => VERDICT_MODIFIED.to_string(),
        "drop" => VERDICT_DROP.to_string(),
        other => other.to_string(),
    }
}

/// python `WinwsLogParser` — построчный конечный автомат:
/// преамбула → пакетные блоки.
pub struct WinwsLogParser {
    head_packets: usize,
    tail_packets: usize,
    retained_left: i64,
    /// Хвост последних пакетов соединения; склеивается с началом в
    /// [`WinwsLogParser::finish`].
    tails: HashMap<ConnectionKey, VecDeque<PacketRecord>>,
    result: WinwsLogParseResult,
    profiles: HashMap<i64, (String, Vec<String>)>,
    hostlists: Vec<(String, i64)>,
    ipsets: Vec<(String, i64)>,
    connections: HashMap<ConnectionKey, usize>,
    current: Option<PacketRecord>,
    /// Изменяемые накопители текущего блока (в [`PacketRecord`] — векторы).
    cur_tls: Vec<String>,
    cur_checks: Vec<ListCheckRecord>,
    cur_lua: Vec<String>,
    cur_check_context: Option<(String, i64)>,
}

impl Default for WinwsLogParser {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_PACKETS_PER_CONNECTION,
            DEFAULT_MAX_RETAINED_PACKETS,
        )
    }
}

impl WinwsLogParser {
    /// python `__init__` с теми же пределами хранения.
    #[must_use]
    pub fn new(max_packets_per_connection: usize, max_retained_packets: i64) -> Self {
        let max_packets = max_packets_per_connection.max(1);
        let head_packets = (max_packets / 2).max(1);
        let tail_packets = max_packets - head_packets;
        Self {
            head_packets,
            tail_packets,
            retained_left: max_retained_packets.max(0),
            tails: HashMap::new(),
            result: WinwsLogParseResult::default(),
            profiles: HashMap::new(),
            hostlists: Vec::new(),
            ipsets: Vec::new(),
            connections: HashMap::new(),
            current: None,
            cur_tls: Vec::new(),
            cur_checks: Vec::new(),
            cur_lua: Vec::new(),
            cur_check_context: None,
        }
    }

    /// python `feed_line` — одна строка лога (нумерация 1-based).
    pub fn feed_line(&mut self, line: &str, line_no: i64) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.starts_with("packet: id=") {
            if let Some(m) = RE_PACKET_HEADER.captures(line) {
                self.close_current();
                self.current = Some(PacketRecord {
                    packet_id: m[1].parse().unwrap_or(0),
                    line_no,
                    direction: if &m[3] == "outbound" { "out" } else { "in" }.to_string(),
                    length: m[2].parse().unwrap_or(0),
                    ip_version: if &m[4] == "1" { 6 } else { 4 },
                    ..PacketRecord::default()
                });
                return;
            }
            if let Some(m) = RE_PACKET_VERDICT.captures(line) {
                if let Some(current) = self.current.as_mut() {
                    current.verdict = verdict_of(&m[2]);
                    self.close_current();
                }
                return;
            }
            self.result.unrecognized_packet_lines += 1;
            return;
        }
        if self.current.is_some() {
            self.feed_block_line(line);
        } else {
            self.feed_preamble_line(line);
        }
    }

    fn feed_block_line(&mut self, line: &str) {
        // Проверки, меняющие накопители текущего блока, идут в порядке
        // python-эталона; первые IP-строки распознаются только раз.
        if RE_DELAYED.captures(line).is_some() {
            if let Some(pkt) = self.current.as_mut() {
                pkt.delayed = true;
                if RE_REPLAY.captures(line).is_some() {
                    pkt.replay_count += 1;
                }
            }
            return;
        }
        if let Some(pkt) = self.current.as_mut() {
            if pkt.src_ip.is_empty() {
                if let Some(m) = RE_IP.captures(line) {
                    pkt.ip_version = m[1].parse().unwrap_or(0);
                    pkt.src_ip = m[2].to_string();
                    pkt.dst_ip = m[3].to_string();
                    pkt.proto = m[4].to_string();
                    pkt.ttl = m[5].parse().ok();
                    pkt.src_port = m.get(6).and_then(|g| g.as_str().parse().ok()).unwrap_or(0);
                    pkt.dst_port = m.get(7).and_then(|g| g.as_str().parse().ok()).unwrap_or(0);
                    pkt.tcp_flags = m.get(8).map_or(String::new(), |g| g.as_str().to_string());
                    return;
                }
            }
        }
        let Some(pkt) = self.current.as_mut() else {
            return;
        };
        if let Some(m) = RE_PROFILE_SEARCH.captures(line) {
            if &m[1] != "unknown" {
                pkt.l7proto = m[1].to_string();
            }
            if !m[2].is_empty() {
                pkt.hostname = m[2].to_string();
            }
            return;
        }
        if let Some(m) = RE_LIST_CHECK_CONTEXT.captures(line) {
            self.cur_check_context = Some((m[1].to_string(), m[2].parse().unwrap_or(-1)));
            return;
        }
        if let Some(m) = RE_LIST_CHECK_RESULT.captures(line) {
            if &m[3] == "positive" {
                let (kind, profile_id) = self
                    .cur_check_context
                    .clone()
                    .unwrap_or_else(|| (String::new(), -1));
                self.cur_checks.push(ListCheckRecord {
                    list_path: m[1].to_string(),
                    kind,
                    profile_id,
                    target: m[2].to_string(),
                });
            }
            return;
        }
        let profile_match = RE_PROFILE_MATCH
            .captures(line)
            .or_else(|| RE_PROFILE_CACHED.captures(line))
            .or_else(|| RE_PROFILE_CONNTRACK.captures(line));
        if let Some(m) = profile_match {
            pkt.profile_id = m[1].parse().ok();
            pkt.profile_name = m[2].to_string();
            // "using cached ..." и "using ... from conntrack entry" —
            // профиль из кэша.
            pkt.profile_cached = line.starts_with("using");
            return;
        }
        if let Some(m) = RE_DPI_DESYNC.captures(line) {
            if &m[1] != "unknown" && pkt.l7proto.is_empty() {
                pkt.l7proto = m[1].to_string();
            }
            if !m[2].is_empty() && &m[2] != "unknown" {
                pkt.payload_type = m[2].to_string();
            }
            return;
        }
        if let Some(m) = RE_HOSTNAME_LINE.captures(line) {
            if pkt.hostname.is_empty() {
                pkt.hostname = m[1].to_string();
            }
            return;
        }
        if let Some(m) = RE_TLS_DETAIL.captures(line) {
            let detail = format!("{}: {}", &m[1], &m[2]);
            if !self.cur_tls.contains(&detail) {
                self.cur_tls.push(detail);
            }
            return;
        }
        if let Some(m) = RE_LUA_APPLIED.captures(line) {
            let name = m[1].to_string();
            if !self.cur_lua.contains(&name) {
                self.cur_lua.push(name);
            }
        }
    }

    fn feed_preamble_line(&mut self, line: &str) {
        if let Some(m) = RE_PREAMBLE_PROFILE.captures(line) {
            let profile_id = m[1].parse().unwrap_or(0);
            let entry = self
                .profiles
                .entry(profile_id)
                .or_insert_with(|| (m[2].to_string(), Vec::new()));
            let func = m[3].to_string();
            if !entry.1.contains(&func) {
                entry.1.push(func);
            }
            return;
        }
        if let Some(m) = RE_PREAMBLE_LOADED.captures(line) {
            let entry = (m[3].to_string(), m[1].parse().unwrap_or(0));
            if &m[2] == "hosts" {
                self.hostlists.push(entry);
            } else {
                self.ipsets.push(entry);
            }
        }
    }

    /// python `_close_current` — завершает текущий пакетный блок и
    /// относит его к соединению.
    fn close_current(&mut self) {
        let Some(mut pkt) = self.current.take() else {
            return;
        };
        pkt.tls_details = std::mem::take(&mut self.cur_tls);
        pkt.positive_checks = std::mem::take(&mut self.cur_checks);
        pkt.lua_applied = std::mem::take(&mut self.cur_lua);
        self.cur_check_context = None;

        self.result.packets_total += 1;
        self.result.positive_checks_total += pkt.positive_checks.len() as i64;
        if pkt.src_ip.is_empty() {
            self.result.unparsed_blocks += 1;
            return;
        }
        let (remote_ip, remote_port) = if pkt.direction == "out" {
            (pkt.dst_ip.clone(), pkt.dst_port)
        } else {
            (pkt.src_ip.clone(), pkt.src_port)
        };
        let key: ConnectionKey = (pkt.proto.clone(), remote_ip, remote_port);
        let conn_index = match self.connections.get(&key) {
            Some(&index) => index,
            None => {
                let index = self.result.connections.len();
                self.result.connections.push(ConnectionRecord {
                    proto: pkt.proto.clone(),
                    remote_ip: key.1.clone(),
                    remote_port: key.2,
                    first_line_no: pkt.line_no,
                    ..ConnectionRecord::default()
                });
                self.connections.insert(key.clone(), index);
                index
            }
        };
        let conn = &mut self.result.connections[conn_index];
        conn.packets_total += 1;
        if pkt.direction == "out" {
            conn.packets_out += 1;
        } else {
            conn.packets_in += 1;
        }
        *conn.verdict_counts.entry(pkt.verdict.clone()).or_insert(0) += 1;
        if !pkt.hostname.is_empty() && conn.hostname.is_empty() {
            conn.hostname = pkt.hostname.clone();
        }
        if !pkt.l7proto.is_empty() && conn.l7proto.is_empty() {
            conn.l7proto = pkt.l7proto.clone();
        }
        if let Some(profile_id) = pkt.profile_id {
            if !conn.profile_ids.contains(&profile_id) {
                conn.profile_ids.push(profile_id);
                conn.profile_names.push(pkt.profile_name.clone());
            }
        }
        for check in &pkt.positive_checks {
            // python: os.path.basename(check.list_path.replace("\\", "/")).
            let name = check.list_path.replace('\\', "/");
            let name = name.rsplit('/').next().unwrap_or_default().to_string();
            if !conn.positive_lists.contains(&name) {
                conn.positive_lists.push(name);
            }
        }
        for lua_name in &pkt.lua_applied {
            if !conn.lua_applied.contains(lua_name) {
                conn.lua_applied.push(lua_name.clone());
            }
        }
        self.retain_packet(&key, pkt);
    }

    fn retain_packet(&mut self, key: &ConnectionKey, pkt: PacketRecord) {
        let conn = &mut self.result.connections[self.connections[key]];
        if conn.packets.len() < self.head_packets && self.retained_left > 0 {
            conn.packets.push(pkt);
            self.retained_left -= 1;
            return;
        }
        conn.packets_truncated = true;
        if self.tail_packets == 0 {
            return;
        }
        let tail = self
            .tails
            .entry(key.clone())
            .or_insert_with(|| VecDeque::with_capacity(self.tail_packets));
        if tail.len() < self.tail_packets {
            if self.retained_left <= 0 {
                return;
            }
            self.retained_left -= 1;
        }
        // Полный хвост вытесняет старый пакет — общий счёт не растёт.
        if tail.len() == self.tail_packets {
            tail.pop_front();
        }
        tail.push_back(pkt);
    }

    /// python `finish` — завершает оборванный блок, приклеивает хвосты
    /// и отдаёт итог разбора.
    #[must_use]
    pub fn finish(mut self) -> WinwsLogParseResult {
        self.close_current();
        let Self {
            tails,
            connections,
            result,
            profiles,
            hostlists,
            ipsets,
            ..
        } = &mut self;
        for (key, tail) in tails.drain() {
            if let Some(&index) = connections.get(&key) {
                result.connections[index].packets.extend(tail);
            }
        }
        let mut ids: Vec<(i64, String, Vec<String>)> = profiles
            .iter()
            .map(|(id, (name, funcs))| (*id, name.clone(), funcs.clone()))
            .collect();
        ids.sort_by_key(|(id, _, _)| *id);
        result.profiles = ids
            .into_iter()
            .map(|(id, name, funcs)| {
                let name = if name.is_empty() {
                    "noname"
                } else {
                    name.as_str()
                };
                (id, format!("{name}: {}", funcs.join(", ")))
            })
            .collect();
        result.hostlists = std::mem::take(hostlists);
        result.ipsets = std::mem::take(ipsets);
        std::mem::take(result)
    }
}

/// python `parse_winws_log_stream` — разбор готового текста лога.
///
/// `total_bytes` — размер файла для прогресс-бара (0 — считать по
/// содержимому). Замыкания прогресса и отмены вызываются раз в
/// [`CALLBACK_LINE_INTERVAL`] строк; отмена завершает разбор с
/// `cancelled = true`. `file_path` проставляет вызывающий слой —
/// чтение файла остаётся платформенным.
#[must_use]
pub fn parse_winws_log_stream(
    text: &str,
    file_path: &str,
    total_bytes: u64,
    progress_cb: Option<&dyn Fn(u64, u64)>,
    cancel_cb: Option<&dyn Fn() -> bool>,
    max_packets_per_connection: usize,
) -> WinwsLogParseResult {
    let mut parser = WinwsLogParser::new(max_packets_per_connection, DEFAULT_MAX_RETAINED_PACKETS);
    let mut bytes_read: u64 = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_no = (index + 1) as i64;
        parser.feed_line(line, line_no);
        // Приближение (символы ≈ байты) — достаточно для прогресс-бара.
        bytes_read += line.len() as u64;
        if line_no % CALLBACK_LINE_INTERVAL == 0 {
            if let Some(cancel) = cancel_cb {
                if cancel() {
                    let mut result = parser.finish();
                    result.cancelled = true;
                    return result;
                }
            }
            if let Some(progress) = progress_cb {
                progress(bytes_read, total_bytes);
            }
        }
    }
    let mut result = parser.finish();
    result.file_path = file_path.to_string();
    if let Some(progress) = progress_cb {
        let total = if total_bytes == 0 {
            bytes_read
        } else {
            total_bytes
        };
        progress(total, total);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::filter_connections;
    use crate::models::VERDICT_NONE;

    /// python-фикстура test_winws_log_analyzer_page.py отсутствует в
    /// репозитории — эталонный лог собран вручную и все значения сверены
    /// с python-парсером (python3 + parse_winws_log_file).
    const SAMPLE: &str = include_str!("../tests/winws2_sample.log");

    fn parse_default() -> WinwsLogParseResult {
        parse_winws_log_stream(SAMPLE, "sample.log", SAMPLE.len() as u64, None, None, 200)
    }

    #[test]
    fn sample_summary_matches_python() {
        let result = parse_default();
        assert_eq!(result.file_path, "sample.log");
        assert!(!result.cancelled);
        assert_eq!(result.packets_total, 6);
        assert_eq!(result.connections.len(), 4);
        assert_eq!(result.positive_checks_total, 1);
        assert_eq!(result.unparsed_blocks, 1);
        assert_eq!(result.unrecognized_packet_lines, 2);
        // Профили и преамбула.
        let mut profiles: Vec<(&i64, &String)> = result.profiles.iter().collect();
        profiles.sort_by_key(|(id, _)| **id);
        assert_eq!(
            profiles,
            vec![
                (&1, &"Основной: fake, autottl".to_string()),
                (&2, &"Fallback: fake".to_string()),
            ]
        );
        assert_eq!(
            result.hostlists,
            vec![("/tmp/zapret/user_hostlist.txt".to_string(), 42)]
        );
        assert_eq!(
            result.ipsets,
            vec![("/tmp/zapret/user_ipset.txt".to_string(), 7)]
        );
    }

    #[test]
    fn sample_connections_match_python() {
        let result = parse_default();
        let endpoints: Vec<(&str, &str, i64)> = result
            .connections
            .iter()
            .map(|c| (c.proto.as_str(), c.remote_ip.as_str(), c.remote_port))
            .collect();
        assert_eq!(
            endpoints,
            vec![
                ("tcp", "104.18.32.7", 443),
                ("tcp", "13.107.246.53", 443),
                ("tcp", "185.26.182.94", 80),
                ("tcp", "2a00:1450:4001:81b::200e", 443),
            ]
        );
        let hosts: Vec<&str> = result
            .connections
            .iter()
            .map(|c| c.hostname.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec![
                "merchandise.opera-api.com",
                "update.microsoft.com",
                "",
                "example.org",
            ]
        );
        let l7: Vec<&str> = result
            .connections
            .iter()
            .map(|c| c.l7proto.as_str())
            .collect();
        assert_eq!(l7, vec!["tls", "quic", "http", ""]);
        let profiles: Vec<(Vec<i64>, Vec<&str>)> = result
            .connections
            .iter()
            .map(|c| {
                (
                    c.profile_ids.clone(),
                    c.profile_names.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            profiles,
            vec![
                (vec![1], vec!["Основной"]),
                (Vec::<i64>::new(), Vec::<&str>::new()),
                (vec![3], vec!["Резерв"]),
                (vec![1], vec!["Основной"]),
            ]
        );
        let totals: Vec<(i64, i64, i64)> = result
            .connections
            .iter()
            .map(|c| (c.packets_total, c.packets_out, c.packets_in))
            .collect();
        assert_eq!(totals, vec![(2, 1, 1), (1, 1, 0), (1, 1, 0), (1, 1, 0)]);
        let lists: Vec<Vec<&str>> = result
            .connections
            .iter()
            .map(|c| c.positive_lists.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(
            lists,
            vec![vec!["user_hostlist.txt"], vec![], vec![], vec![]]
        );
        let lua: Vec<Vec<&str>> = result
            .connections
            .iter()
            .map(|c| c.lua_applied.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(
            lua,
            vec![vec!["fake", "autottl"], vec!["fake"], vec![], vec![],]
        );
        let extras: Vec<(bool, i64)> = result
            .connections
            .iter()
            .map(|c| (c.packets_truncated, c.first_line_no))
            .collect();
        assert_eq!(
            extras,
            vec![(false, 6), (false, 25), (false, 35), (false, 40)]
        );
        // Вердикты соединений.
        let verdicts: Vec<Vec<(String, i64)>> = result
            .connections
            .iter()
            .map(|c| {
                let mut pairs: Vec<(String, i64)> = c
                    .verdict_counts
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                pairs.sort();
                pairs
            })
            .collect();
        assert_eq!(
            verdicts,
            vec![
                vec![("modified".into(), 1), ("unmodified".into(), 1)],
                vec![("modified".into(), 1)],
                vec![("drop".into(), 1)],
                vec![("unmodified".into(), 1)],
            ]
        );
    }

    #[test]
    fn sample_packets_match_python() {
        let result = parse_default();
        let c0 = &result.connections[0];
        let p1 = &c0.packets[0];
        assert_eq!(p1.packet_id, 1);
        assert_eq!(p1.direction, "out");
        assert_eq!(p1.length, 74);
        assert_eq!(p1.ip_version, 4);
        assert_eq!(p1.src_ip, "192.168.1.10");
        assert_eq!(p1.src_port, 51412);
        assert_eq!(p1.dst_ip, "104.18.32.7");
        assert_eq!(p1.dst_port, 443);
        assert_eq!(p1.proto, "tcp");
        assert_eq!(p1.ttl, Some(64));
        assert_eq!(p1.tcp_flags, "PA");
        assert_eq!(p1.l7proto, "tls");
        assert_eq!(p1.hostname, "merchandise.opera-api.com");
        assert_eq!(p1.payload_type, "tls_client_hello");
        assert_eq!(p1.profile_id, Some(1));
        assert_eq!(p1.profile_name, "Основной");
        assert!(!p1.profile_cached);
        assert_eq!(p1.verdict, VERDICT_MODIFIED);
        // Дубликат TLS-детали отброшен (python: "if detail not in").
        assert_eq!(
            p1.tls_details,
            vec!["SNI: merchandise.opera-api.com", "ALPN: h2"]
        );
        assert_eq!(
            p1.positive_checks,
            vec![ListCheckRecord {
                list_path: "user_hostlist.txt".to_string(),
                kind: "hostlist".to_string(),
                profile_id: 1,
                target: "merchandise.opera-api.com".to_string(),
            }]
        );
        assert_eq!(p1.lua_applied, vec!["fake", "autottl"]);
        assert!(!p1.delayed);
        assert_eq!(p1.replay_count, 0);

        // Второй пакет того же соединения — входящий, unmodified.
        let p2 = &c0.packets[1];
        assert_eq!(p2.direction, "in");
        assert_eq!(p2.ttl, Some(57));
        assert_eq!(p2.profile_id, Some(1));
        assert_eq!(p2.verdict, VERDICT_UNMODIFIED);
        assert!(p2.tls_details.is_empty());

        // QUIC-пакет: delayed + replay, профиль не распознан.
        let p3 = &result.connections[1].packets[0];
        assert_eq!(p3.packet_id, 3);
        assert!(p3.delayed);
        assert_eq!(p3.replay_count, 1);
        assert_eq!(p3.payload_type, "quic_initial");
        assert_eq!(p3.profile_id, None);
        assert_eq!(p3.profile_name, "");
        assert_eq!(p3.lua_applied, vec!["fake"]);

        // drop-пакет.
        let p4 = &result.connections[2].packets[0];
        assert_eq!(p4.verdict, VERDICT_DROP);
        assert_eq!(p4.profile_name, "Резерв");

        // IPv6-пакет: профиль из кэша ("using cached ...").
        let p5 = &result.connections[3].packets[0];
        assert_eq!(p5.ip_version, 6);
        assert!(p5.profile_cached);
        assert_eq!(p5.profile_id, Some(1));
        assert_eq!(p5.hostname, "example.org");
    }

    #[test]
    fn unparsed_block_has_no_verdict_connection() {
        // Блок id=6 без IP-строки: unparsed, в соединения не попадает,
        // вердикт-терминатор обработан без паники.
        let result = parse_default();
        assert_eq!(result.connections.len(), 4);
        assert_eq!(result.unparsed_blocks, 1);
        assert!(result
            .connections
            .iter()
            .all(|c| c.remote_ip != "broken.example"));
    }

    #[test]
    fn nfqws_lines_counted_as_unrecognized() {
        // Linux-формат (mark=, "pass modified") — не распознаётся.
        let result = parse_default();
        assert_eq!(result.unrecognized_packet_lines, 2);
    }

    #[test]
    fn filter_tests_match_python() {
        let result = parse_default();
        let by_text = filter_connections(&result.connections, "opera-api", false, false);
        assert_eq!(by_text.len(), 1);
        assert_eq!(by_text[0].hostname, "merchandise.opera-api.com");

        // python-эталон искал "85.172." — в нашем логе такого IP нет.
        assert!(filter_connections(&result.connections, "85.172.", false, false).is_empty());
        // Подстрока IP-адреса работает.
        let by_ip = filter_connections(&result.connections, "104.18.", false, false);
        assert_eq!(by_ip.len(), 1);
        assert_eq!(by_ip[0].remote_ip, "104.18.32.7");

        let with_hostname = filter_connections(&result.connections, "", true, false);
        assert_eq!(
            with_hostname
                .iter()
                .map(|c| c.remote_ip.as_str())
                .collect::<Vec<_>>(),
            vec!["104.18.32.7", "13.107.246.53", "2a00:1450:4001:81b::200e",]
        );

        let affected = filter_connections(&result.connections, "", false, true);
        let mut ips: Vec<&str> = affected.iter().map(|c| c.remote_ip.as_str()).collect();
        ips.sort_unstable();
        assert_eq!(ips, vec!["104.18.32.7", "13.107.246.53", "185.26.182.94"]);

        // Без критериев — весь список, порядок сохранён.
        let all = filter_connections(&result.connections, "", false, false);
        assert_eq!(all.len(), result.connections.len());
        assert_eq!(all[0].remote_ip, result.connections[0].remote_ip);
    }

    #[test]
    fn head_tail_retention_respects_limits() {
        // 300 пакетов одного соединения при лимите 20: 10 в начале,
        // 10 в конце, truncated = true; счётчики по всем пакетам.
        let mut text = String::from("profile 1 (P) lua fake(\n");
        for id in 1..=300 {
            text.push_str(&format!(
                "packet: id={id} len=100 outbound IPv6=0\n\
                 IP4: 10.0.0.1 => 1.2.3.4 proto=tcp ttl=64 sport=1 dport=2 flags=A\n\
                 packet: id={id} reinject modified\n"
            ));
        }
        let result = parse_winws_log_stream(&text, "", 0, None, None, 20);
        assert_eq!(result.connections.len(), 1);
        let conn = &result.connections[0];
        assert_eq!(conn.packets_total, 300);
        assert_eq!(conn.packets.len(), 20);
        assert!(conn.packets_truncated);
        // Первая половина — начало соединения, вторая — его конец.
        assert_eq!(conn.packets[0].packet_id, 1);
        assert_eq!(conn.packets[9].packet_id, 10);
        assert_eq!(conn.packets[10].packet_id, 291);
        assert_eq!(conn.packets[19].packet_id, 300);
        // Вердикты посчитаны по всем пакетам.
        assert_eq!(conn.verdict_counts.get(VERDICT_MODIFIED), Some(&300));
    }

    #[test]
    fn cancel_cb_stops_parsing() {
        // Отмена срабатывает на первой же интервальной проверке (2000 строк).
        let text = "packet: id=1 len=1 outbound IPv6=0\n".repeat(5000);
        let calls = std::cell::Cell::new(0_i64);
        let result = parse_winws_log_stream(
            &text,
            "",
            0,
            None,
            Some(&|| {
                calls.set(calls.get() + 1);
                true
            }),
            200,
        );
        assert!(result.cancelled);
        assert!(calls.get() >= 1);
        assert!(result.connections.is_empty());
    }

    #[test]
    fn progress_cb_reports_and_finishes() {
        let text = "x\n".repeat(6000);
        let last = std::cell::Cell::new((0_u64, 0_u64));
        let result = parse_winws_log_stream(
            &text,
            "",
            12_345,
            Some(&|read, total| last.set((read, total))),
            None,
            200,
        );
        assert!(!result.cancelled);
        // Последний вызов — в конце разбора, с total_bytes.
        assert_eq!(last.get(), (12_345, 12_345));
    }

    #[test]
    fn truncated_block_keeps_default_verdict() {
        // Оборванный блок без терминатора — вердикт остался пустым.
        let text = "packet: id=1 len=10 outbound IPv6=0\n\
                    IP4: 1.1.1.1 => 2.2.2.2 proto=tcp ttl=64 sport=1 dport=2 flags=A\n";
        let result = parse_winws_log_stream(text, "", 0, None, None, 200);
        assert_eq!(result.connections.len(), 1);
        assert_eq!(result.connections[0].packets[0].verdict, VERDICT_NONE);
    }
}
