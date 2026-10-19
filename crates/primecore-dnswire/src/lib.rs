//! Порт `src/utils/dns_wire.py` — ручной DNS-кодек RFC 1035 и сетевой слой.
//!
//! Реализованы сборка запроса и разбор ответа (включая сжатие имён),
//! обратные имена, текстовая классификация результата; UDP/TCP-транспорт и
//! общий лимит времени — в модуле `net`. DoT и DoH по TLS — следом.

use serde_json::Value;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;

pub const RCODE_OK: u16 = 0;
pub const RCODE_NXDOMAIN: u16 = 3;

pub const STATUS_OK: &str = "ok";
pub const STATUS_EMPTY: &str = "empty";
pub const STATUS_NXDOMAIN: &str = "nxdomain";
pub const STATUS_REFUSED: &str = "refused";
pub const STATUS_TIMEOUT: &str = "timeout";
pub const STATUS_ERROR: &str = "error";

/// Каким способом шёл запрос.
pub const TRANSPORT_UDP: &str = "udp";
pub const TRANSPORT_TCP: &str = "tcp";
pub const TRANSPORT_DOT: &str = "dot";
pub const TRANSPORT_DOH: &str = "doh";

/// Виды сбоя (utils.net_failure) — часть строки, не задействуют сети.
pub const FAILURE_TIMEOUT: &str = "timeout";
pub const FAILURE_REFUSED: &str = "refused";
pub const FAILURE_RESET: &str = "reset";
pub const FAILURE_CLOSED: &str = "closed";
pub const FAILURE_UNREACHABLE: &str = "unreachable";
pub const FAILURE_TLS: &str = "tls";
pub const FAILURE_CERT: &str = "cert";
pub const FAILURE_HTTP: &str = "http";
pub const FAILURE_MALFORMED: &str = "malformed";
pub const FAILURE_CANCELLED: &str = "cancelled";
pub const FAILURE_OTHER: &str = "other";

pub const DEFAULT_TIMEOUT_S: f64 = 2.0;
/// Шифрованный запрос — ещё соединение и рукопожатие TLS.
pub const ENCRYPTED_TIMEOUT_S: f64 = 4.0;
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";
/// EDNS-размер: за 512 UDP сервер идёт только по нашей просьбе.
const EDNS_UDP_SIZE: u16 = 1232;
const MAX_POINTER_HOPS: u32 = 32;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;

const FAILURE_TEXT: [(&str, &str); 9] = [
    (FAILURE_TIMEOUT, "сервер молчит"),
    (FAILURE_REFUSED, "порт закрыт"),
    (FAILURE_RESET, "соединение оборвано"),
    (FAILURE_CLOSED, "сервер закрыл соединение, не ответив"),
    (FAILURE_UNREACHABLE, "до адреса нет дороги"),
    (FAILURE_TLS, "шифрование не установилось"),
    (FAILURE_CERT, "сервер предъявил чужой сертификат"),
    (FAILURE_MALFORMED, "пришёл не DNS-ответ"),
    (FAILURE_CANCELLED, "проверка остановлена"),
];

/// Одна DNS-запись ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub value: String,
}

/// Разобранный ответ (parity с python dataclass DnsMessage).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsMessage {
    pub query_id: u16,
    pub is_response: bool,
    pub truncated: bool,
    pub rcode: u16,
    pub question: String,
    pub answers: Vec<DnsRecord>,
    /// Флаг AA: отвечающий называет себя первоисточником записей.
    pub authoritative: bool,
    /// Число записей раздела «полномочия»: у честного отказа там SOA.
    pub authority_count: u16,
}

/// Разбор по сети дампа ошибок — понятно пользователю.
pub type DnsWireResult<T> = Result<T, DnsWireError>;

/// Ответ сервера не разбирается как DNS-пакет (python DnsWireError).
pub type DnsWireError = String;

/// Итог одного запроса: сетевые сбои — это статус, а не исключение.
/// (Сетевой слой ниже будет строить его же.)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsQueryResult {
    pub status: String,
    pub rcode: Option<u16>,
    pub records: Vec<DnsRecord>,
    pub elapsed_ms: Option<f64>,
    pub detail: String,
    pub transport: String,
    pub failure: String,
    pub truncated: bool,
    pub authoritative: bool,
    pub authority_count: u16,
}

impl DnsQueryResult {
    /// «Такого домена нет» с подписью подставного ответа (см. python-докстрок):
    /// у честного резолвера есть SOA в полномочиях, у подставки — нет.
    pub fn forged_denial(&self) -> bool {
        self.rcode == Some(RCODE_NXDOMAIN) && self.authoritative && self.authority_count == 0
    }

    /// Сервер ответил хоть что-то (включая «такого домена нет»).
    pub fn answered(&self) -> bool {
        self.rcode.is_some()
    }

    /// Уникальные значения записей нужного типа, в порядке прихода.
    pub fn values(&self, rtype: u16) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for record in &self.records {
            if record.rtype == rtype && !seen.contains(&record.value) {
                seen.push(record.value.clone());
            }
        }
        seen
    }

    /// Почему сервер не ответил — словами для отчёта; пусто, если ответил.
    pub fn failure_text(&self) -> String {
        if self.answered() || self.failure.is_empty() {
            return String::new();
        }
        if self.failure == FAILURE_HTTP {
            return if self.detail.is_empty() {
                "сервер ответил ошибкой".to_string()
            } else {
                format!("сервер ответил ошибкой ({})", self.detail)
            };
        }
        for (failure, text) in FAILURE_TEXT {
            if *failure == self.failure {
                return text.to_string();
            }
        }
        if !self.detail.is_empty() {
            return self.detail.clone();
        }
        "запрос не выполнился".to_string()
    }
}

/// Статус по разобранному сообщению (python _status_for).
pub fn status_for(message: &DnsMessage) -> String {
    if message.rcode == RCODE_NXDOMAIN {
        return STATUS_NXDOMAIN.to_string();
    }
    if message.rcode != RCODE_OK {
        return STATUS_REFUSED.to_string();
    }
    if message.answers.is_empty() {
        STATUS_EMPTY.to_string()
    } else {
        STATUS_OK.to_string()
    }
}

/// Результат _answered сетевого слоя: сообщение → результат.
pub fn answered_result(transport: &str, message: DnsMessage, elapsed_ms: f64) -> DnsQueryResult {
    let rcode = message.rcode;
    DnsQueryResult {
        status: status_for(&message),
        rcode: Some(rcode),
        records: message.answers.clone(),
        elapsed_ms: Some(elapsed_ms),
        detail: if rcode != RCODE_OK && rcode != RCODE_NXDOMAIN {
            format!("rcode {rcode}")
        } else {
            String::new()
        },
        transport: transport.to_string(),
        failure: String::new(),
        truncated: message.truncated,
        authoritative: message.authoritative,
        authority_count: message.authority_count,
    }
}

/// Имя в формате DNS: метки с длиной впереди. Кириллица — через idna/punycode.
///
/// Отличие от python: питоновский кодек idna работает по IDNA 2003, rust idna
/// — по UTS46 (nontransitional). На практически важных именах результаты
/// совпадают (проверяется золотым тестом); различаются отдельные символы
/// («ß» и другие deviation), для них python даёт свой ответ.
pub fn encode_name(name: &str) -> DnsWireResult<Vec<u8>> {
    let cleaned = name.trim().trim_matches('.');
    if cleaned.is_empty() {
        return Err("пустое имя".to_string());
    }
    let mut encoded: Vec<u8> = Vec::new();
    for label in cleaned.split('.') {
        let raw = if label.is_ascii() {
            label.as_bytes().to_vec()
        } else {
            match idna::domain_to_ascii_cow(label.as_bytes(), idna::AsciiDenyList::EMPTY) {
                Ok(cow) => cow.into_owned().into_bytes(),
                Err(_) => return Err(format!("недопустимое имя: {name}")),
            }
        };
        if raw.is_empty() || raw.len() > 63 {
            return Err(format!("недопустимое имя: {name}"));
        }
        encoded.push(raw.len() as u8);
        encoded.extend_from_slice(&raw);
    }
    if encoded.len() > 253 {
        return Err(format!("слишком длинное имя: {name}"));
    }
    encoded.push(0);
    Ok(encoded)
}

/// DNS-запрос с флагом «рекурсия нужна» и разрешением на большой ответ.
pub fn build_query(query_id: u16, name: &str, rtype: u16) -> DnsWireResult<Vec<u8>> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // флаги: RD
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT: EDNS0
    packet.extend_from_slice(&encode_name(name)?);
    packet.extend_from_slice(&rtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    packet.extend_from_slice(&[0x00]); // корень OPT
    packet.extend_from_slice(&41u16.to_be_bytes()); // OPT RR
    packet.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // extended rcode/flags
    packet.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    Ok(packet)
}

/// Имя для обратного запроса: 1.2.3.4 → 4.3.2.1.in-addr.arpa.
pub fn reverse_name(ip: &str) -> DnsWireResult<String> {
    let address = ip.trim();
    if let Some(octet) = parse_ipv4(address) {
        return Ok(format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octet[3], octet[2], octet[1], octet[0]
        ));
    }
    if let Some(octets) = parse_ipv6(address) {
        return reverse_ipv6(&octets);
    }
    Err(format!("'{address}' does not appear to be an IPv4 or IPv6 address"))
}

/// python ip_address("1.2.3.4") → IPv4Address; ручка разбора точек.
fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        // python ip_address отбрасывает ведущие нули (у 4.x — жалуется).
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        bytes[index] = part.parse::<u8>().ok()?;
    }
    Some(bytes)
}

fn reverse_ipv6(octets: &[u8]) -> DnsWireResult<String> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(32);
    for octet in octets.iter().rev() {
        nibbles.push(octet & 0x0F);
        nibbles.push(octet >> 4);
    }
    let mut result = String::new();
    for nibble in nibbles {
        result.push_str(&format!("{nibble:x}."));
    }
    result.push_str("ip6.arpa");
    Ok(result)
}

/// Разбор IPv6-литерала в 16 байт (python ip_address понимает '::', группы).
fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    let text = text.to_lowercase();
    let (head_part, tail) = match text.split_once("::") {
        Some((head, tail)) => (head.to_string(), Some(tail.to_string())),
        None => (text.clone(), None),
    };
    if tail.is_some() && text.matches("::").count() > 1 {
        return None;
    }
    let head_groups: Vec<u32> = if head_part.is_empty() {
        Vec::new()
    } else {
        head_part
            .split(':')
            .map(parse_group)
            .collect::<Option<Vec<_>>>()?
    };
    let tail_groups: Vec<u32> = match tail.as_deref() {
        Some(t) if t.is_empty() => Vec::new(),
        Some(t) => t.split(':').map(parse_group).collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
    };
    let total = head_groups.len() + tail_groups.len();
    if tail.is_none() && total != 8 {
        return None;
    }
    if tail.is_some() && total > 7 {
        return None;
    }
    let mut groups: Vec<u32> = Vec::with_capacity(8);
    for group in head_groups {
        groups.push(group);
    }
    if tail.is_some() {
        for _ in total..8 {
            groups.push(0);
        }
        groups.extend(tail_groups);
    }
    let mut octets = [0u8; 16];
    for (index, group) in groups.iter().enumerate() {
        octets[index * 2] = (*group >> 8) as u8;
        octets[index * 2 + 1] = (*group & 0xFF) as u8;
    }
    Some(octets)
}

fn parse_group(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 4 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

/// Читает имя с учётом сжатия (ссылок на уже встречавшиеся имена).
fn read_name(packet: &[u8], mut offset: usize) -> DnsWireResult<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut hops = 0;
    loop {
        if offset >= packet.len() {
            return Err("имя выходит за границы пакета".to_string());
        }
        let length = packet[offset];
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err("оборванная ссылка в имени".to_string());
            }
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = ((length as usize & 0x3F) << 8) | packet[offset + 1] as usize;
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return Err("зацикленные ссылки в имени".to_string());
            }
            continue;
        }
        if length & 0xC0 != 0 {
            return Err("неизвестный тип метки".to_string());
        }
        let start = offset + 1;
        if start + length as usize > packet.len() {
            return Err("метка выходит за границы пакета".to_string());
        }
        labels.push(decode_ascii_replace(&packet[start..start + length as usize]));
        offset = start + length as usize;
    }
    Ok((labels.join("."), end.unwrap_or(offset)))
}

/// python bytes.decode("ascii", "replace"): не-ascii байты → U+FFFD каждый.
fn decode_ascii_replace(bytes: &[u8]) -> String {
    let mut result = String::new();
    for &byte in bytes {
        if byte < 0x80 {
            result.push(byte as char);
        } else {
            result.push('\u{FFFD}');
        }
    }
    result
}

/// python bytes.decode("utf-8", "replace").
fn decode_utf8_replace(bytes: &[u8]) -> String {
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => text,
        Err(error) => error.as_bytes().iter()
            .map(|&byte| char::from_u32(byte as u32).filter(|c| c.is_ascii()))
            .collect::<Option<String>>()
            .unwrap_or_default(),
    }
}

fn read_txt(data: &[u8]) -> String {
    let mut chunks: Vec<String> = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let size = data[index];
        let end = (index + 1 + size as usize).min(data.len());
        chunks.push(decode_utf8_replace(&data[index + 1..end]));
        index += 1 + size as usize;
    }
    chunks.join("")
}

/// inet_ntoa (Rust вместо socket.inet_ntoa).
fn inet_ntoa(data: &[u8]) -> String {
    format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
}

/// inet_ntop для AF_INET6 (стандартная форма с '::').
fn inet_ntop6(data: &[u8]) -> String {
    let mut groups: Vec<u16> = Vec::with_capacity(8);
    for group in data.chunks(2) {
        groups.push(((group[0] as u16) << 8) | group[1] as u16);
    }
    // Собираем все последовательности нулей, чтобы выбрать самую длинную.
    let mut best_start: i64 = -1;
    let mut best_len: i64 = 0;
    let mut current_start: i64 = -1;
    for (index, group) in groups.iter().enumerate() {
        if *group == 0 {
            if current_start < 0 {
                current_start = index as i64;
            }
            let run = index as i64 - current_start + 1;
            if run > best_len {
                best_len = run;
                best_start = current_start;
            }
        } else {
            current_start = -1;
        }
    }
    let mut result = String::new();
    let mut index = 0;
    while index < groups.len() {
        if best_start >= 0 && (index as i64) == best_start {
            result.push_str("::");
            index += best_len as usize;
        } else {
            if !result.is_empty() && !result.ends_with(':') && index > 0 {
                result.push(':');
            }
            result.push_str(&format!("{:x}", groups[index]));
            index += 1;
        }
    }
    result
}

/// Разбирает ответ: код результата и записи раздела «ответы».
pub fn parse_response(packet: &[u8]) -> DnsWireResult<DnsMessage> {
    if packet.len() < 12 {
        return Err("слишком короткий пакет".to_string());
    }
    let be16 = |bytes: &[u8]| -> u16 { ((bytes[0] as u16) << 8) | bytes[1] as u16 };
    let query_id = be16(&packet[0..2]);
    let flags = be16(&packet[2..4]);
    let questions = be16(&packet[4..6]) as usize;
    let answers = be16(&packet[6..8]) as usize;
    let authority = be16(&packet[8..10]);
    let offset_start = 12;
    let mut offset = offset_start;
    let mut question = String::new();
    for index in 0..questions {
        let (name, next) = read_name(packet, offset)?;
        offset = next + 4;
        if index == 0 {
            question = name.to_lowercase();
        }
    }
    let mut records: Vec<DnsRecord> = Vec::new();
    for _ in 0..answers {
        let (name, next) = read_name(packet, offset)?;
        offset = next;
        if offset + 10 > packet.len() {
            return Err("оборванная запись".to_string());
        }
        let rtype = be16(&packet[offset..offset + 2]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let size = be16(&packet[offset + 8..offset + 10]) as usize;
        offset += 10;
        if offset + size > packet.len() {
            return Err("данные записи выходят за границы пакета".to_string());
        }
        let data = &packet[offset..offset + size];
        let value: Option<String> = if rtype == TYPE_A && size == 4 {
            Some(inet_ntoa(data))
        } else if rtype == TYPE_AAAA && size == 16 {
            Some(inet_ntop6(data))
        } else if rtype == TYPE_CNAME || rtype == TYPE_PTR || rtype == TYPE_NS {
            // Имя внутри записи тоже может ссылаться на начало пакета.
            Some(read_name(packet, offset)?.0.to_lowercase())
        } else if rtype == TYPE_TXT {
            Some(read_txt(data))
        } else {
            None
        };
        offset += size;
        if let Some(value) = value {
            records.push(DnsRecord {
                name: name.to_lowercase(),
                rtype,
                ttl,
                value,
            });
        }
    }
    Ok(DnsMessage {
        query_id,
        is_response: flags & FLAG_QR != 0,
        truncated: flags & FLAG_TC != 0,
        rcode: flags & 0x000F,
        question,
        answers: records,
        authoritative: flags & FLAG_AA != 0,
        authority_count: authority,
    })
}

/// python _read_txt не входит в __all__, но тесты есть; открыто для паритета.
pub fn read_txt_public(data: &[u8]) -> String {
    read_txt(data)
}

/// Каноническое представление для ярких сбоев в золоте (JSON-аппарат тестов).
pub fn result_to_json(result: &DnsQueryResult) -> Value {
    serde_json::json!({
        "status": result.status,
        "rcode": result.rcode,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail,
        "transport": result.transport,
        "failure": result.failure,
        "truncated": result.truncated,
        "authoritative": result.authoritative,
        "authority_count": result.authority_count,
        "records": result.records.iter().map(|r| serde_json::json!({
            "name": r.name, "rtype": r.rtype, "ttl": r.ttl, "value": r.value,
        })).collect::<Vec<_>>(),
    })
}

pub mod doh;
pub mod dot;
pub mod net;
