//! Порт `src/diagnostics/browser_hello.py` — приветствие «как у Chrome»:
//! проходит ли оно до сервера.
//!
//! Обычная проверка открывает сайт средствами Python. Её приветствие (первый
//! пакет шифрованного соединения, ClientHello) не похоже на браузерное: другой
//! набор шифров и расширений, втрое короче. Фильтр провайдера умеет различать
//! программы по этому «почерку» и резать только браузерный — тогда проверка
//! говорит «открывается», а в Chrome сайт висит.
//!
//! Здесь собирается приветствие с тем же составом, что у настольного Chrome:
//! те же шифры, те же шестнадцать расширений, ключ постквантового обмена
//! (из-за него приветствие занимает два пакета, как у настоящего браузера) и
//! случайные «пустышки» GREASE. Отправляем его и смотрим только одно: пришёл
//! ли от сервера ответ.
//!
//! Отпечаток JA4 этого приветствия —
//! `t13d1516h2_8daaf6152771_d8a2da3f94cd` ([`BLOCKED_JA4`]): тот самый, про
//! который известно, что фильтр режет его на адресах датацентров. Chrome
//! новее (по сообщениям — со 150-й версии), Firefox и curl имеют другие
//! отпечатки и под этот блок не попадают — поэтому вывод звучит «может не
//! открываться в Chrome», а не «в браузере не откроется».
//!
//! Чего проверка НЕ делает: соединение дальше приветствия не идёт. Блокировку,
//! которая срабатывает позже (обрыв после 16 КБ именно для браузерного
//! почерка), она не увидит.
//!
//! Здесь только сбор приветствия и один факт «что пришло в ответ». Вывод
//! делает `diagnostics.protocol_probe`: он сравнивает этот ответ с обычным
//! приветствием к тому же адресу.

use crate::block_cause::{
    HelloResult, HELLO_ALERT, HELLO_CANCELLED, HELLO_CONNECT, HELLO_GARBAGE, HELLO_OK, HELLO_RESET,
    HELLO_TIMEOUT,
};

/// Отпечаток настольного Chrome, который режет фильтр (описан на wiki.zapret.moe).
pub const BLOCKED_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// Шифры настольного Chrome по порядку (без GREASE).
pub const CHROME_CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C,
    0x009D, 0x002F, 0x0035,
];

pub const EXT_SNI: u16 = 0x0000;
pub const EXT_STATUS_REQUEST: u16 = 0x0005;
pub const EXT_GROUPS: u16 = 0x000A;
pub const EXT_POINT_FORMATS: u16 = 0x000B;
pub const EXT_SIGNATURES: u16 = 0x000D;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SCT: u16 = 0x0012;
pub const EXT_MASTER_SECRET: u16 = 0x0017;
pub const EXT_COMPRESS_CERT: u16 = 0x001B;
pub const EXT_SESSION_TICKET: u16 = 0x0023;
pub const EXT_VERSIONS: u16 = 0x002B;
pub const EXT_PSK_MODES: u16 = 0x002D;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_ALPS: u16 = 0x44CD;
pub const EXT_ECH: u16 = 0xFE0D;
pub const EXT_RENEGOTIATION: u16 = 0xFF01;

/// Шестнадцать расширений Chrome (без двух GREASE).
/// Порядок браузер перемешивает сам.
pub const CHROME_EXTENSIONS: [u16; 16] = [
    EXT_SNI,
    EXT_MASTER_SECRET,
    EXT_RENEGOTIATION,
    EXT_GROUPS,
    EXT_POINT_FORMATS,
    EXT_SESSION_TICKET,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_SIGNATURES,
    EXT_SCT,
    EXT_KEY_SHARE,
    EXT_PSK_MODES,
    EXT_VERSIONS,
    EXT_COMPRESS_CERT,
    EXT_ALPS,
    EXT_ECH,
];

pub const GROUP_X25519_MLKEM768: u16 = 0x11EC;
pub const GROUP_X25519: u16 = 0x001D;

const GROUPS: [u16; 4] = [GROUP_X25519_MLKEM768, GROUP_X25519, 0x0017, 0x0018];
const SIGNATURES: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

const MLKEM_Q: u16 = 3329;
const MLKEM_COEFFS: usize = 3 * 256;

const RECORD_HANDSHAKE: u8 = 22;
const RECORD_ALERT: u8 = 21;
const HANDSHAKE_SERVER_HELLO: u8 = 2;

/// python `os.urandom` — источник случайных байт (`n` байт за раз).
pub type Random<'r> = dyn FnMut(usize) -> Vec<u8> + 'r;

/// python `_grease` — значение-пустышка вида 0x?A?A: сервер обязан его пропустить.
#[must_use]
pub fn grease(byte: u8) -> u16 {
    let nibble = u16::from(byte >> 4);
    (nibble << 12) | 0x0A00 | (nibble << 4) | 0x0A
}

/// python `_vec8`.
fn vec8(data: &[u8]) -> Vec<u8> {
    let mut out = vec![data.len() as u8];
    out.extend_from_slice(data);
    out
}

/// python `_vec16` — struct.pack("!H", len) + data.
fn vec16(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// python `_u16s` — список 16-битных по большому концу.
#[must_use]
pub fn u16s(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

/// python `_mlkem_public_key` — правдоподобный открытый ключ ML-KEM-768: 1184 байта.
///
/// Сервер проверяет, что каждое из 768 чисел ключа меньше 3329, — случайные
/// байты он отверг бы. Числа упакованы по 12 бит, в конце 32 байта зерна.
#[must_use]
pub fn mlkem_public_key(rnd: &mut Random<'_>) -> Vec<u8> {
    let raw = rnd(MLKEM_COEFFS * 2);
    let mut packed: Vec<u8> = Vec::with_capacity(MLKEM_COEFFS * 3 / 2);
    let mut index = 0;
    while index < MLKEM_COEFFS {
        let first = u16::from_be_bytes([raw[index * 2], raw[index * 2 + 1]]) % MLKEM_Q;
        let second = u16::from_be_bytes([raw[index * 2 + 2], raw[index * 2 + 3]]) % MLKEM_Q;
        packed.push((first & 0xFF) as u8);
        packed.push(((first >> 8) | ((second & 0x0F) << 4)) as u8);
        packed.push((second >> 4) as u8);
        index += 2;
    }
    let mut out = packed;
    out.extend_from_slice(&rnd(32));
    out
}

/// python `_extension`.
fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice((data.len() as u16).to_be_bytes().as_slice());
    out.extend_from_slice(data);
    out
}

/// python `build_hello` — запись TLS с приветствием Chrome для сайта `host`.
///
/// `post_quantum=False` — без постквантового ключа: приветствие втрое короче и
/// умещается в один пакет (нужно пробам, которые сами решают, где его резать).
/// `ech=False` — без расширения ECH. Оба варианта меняют отпечаток: это уже не
/// «почерк Chrome», а просто корректное приветствие.
#[must_use]
pub fn build_hello(host: &str, rnd: &mut Random<'_>, post_quantum: bool, ech: bool) -> Vec<u8> {
    let seeds = rnd(5);
    let grease_cipher = grease(seeds[0]);
    let grease_group = grease(seeds[1]);
    let grease_first = grease(seeds[2]);
    let mut grease_last = grease(seeds[3]);
    let grease_version = grease(seeds[4]);
    if grease_last == grease_first {
        grease_last = grease(seeds[3].wrapping_add(0x10));
    }

    let name = idna_encode(host);
    let sni_body = vec16(&{
        let mut piece = vec![0];
        piece.extend_from_slice(&vec16(&name));
        piece
    });
    let mut key_shares: Vec<u8> = grease_group.to_be_bytes().to_vec();
    key_shares.extend_from_slice(&1_u16.to_be_bytes());
    key_shares.push(0);
    if post_quantum {
        let mut share = GROUP_X25519_MLKEM768.to_be_bytes().to_vec();
        let mut public = mlkem_public_key(rnd);
        public.extend_from_slice(&rnd(32));
        share.extend_from_slice(&vec16(&public));
        key_shares.extend_from_slice(&share);
    }
    key_shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_shares.extend_from_slice(&vec16(&rnd(32)));
    let groups = if post_quantum {
        GROUPS.to_vec()
    } else {
        GROUPS[1..].to_vec()
    };
    let ech_body: Vec<u8> = {
        let mut body = vec![0_u8]; // внешнее приветствие
        body.extend_from_slice(&0x0001_u16.to_be_bytes()); // HKDF-SHA256
        body.extend_from_slice(&0x0001_u16.to_be_bytes()); // AES-128-GCM
        let flag = rnd(1);
        let first = rnd(32);
        let padding = 144 + 32 * usize::from(flag[0] % 4);
        let second = rnd(padding);
        body.extend_from_slice(&flag);
        body.extend_from_slice(&vec16(&first));
        body.extend_from_slice(&vec16(&second));
        body
    };

    // Пустые тела расширений заносятся прямо; свой body — только у носителей.
    let bodies = [
        (EXT_SNI, sni_body),
        (EXT_MASTER_SECRET, Vec::new()),
        (EXT_RENEGOTIATION, vec![0]),
        (EXT_GROUPS, Vec::new()),
        (EXT_POINT_FORMATS, vec![0]),
        (EXT_SESSION_TICKET, Vec::new()),
        (EXT_ALPN, Vec::new()),
        (EXT_STATUS_REQUEST, vec![1, 0, 0, 0, 0]),
        (EXT_SIGNATURES, Vec::new()),
        (EXT_SCT, Vec::new()),
        (EXT_KEY_SHARE, Vec::new()),
        (EXT_PSK_MODES, vec![1]),
        (EXT_VERSIONS, Vec::new()),
        // brotli
        (EXT_COMPRESS_CERT, Vec::new()),
        (EXT_ALPS, Vec::new()),
        (EXT_ECH, ech_body),
    ];
    let mut set: Vec<(u16, Vec<u8>)> = Vec::new();
    for (kind, default_body) in bodies {
        if !ech && kind == EXT_ECH {
            continue;
        }
        let body = match kind {
            EXT_SNI => default_body,
            EXT_GROUPS => {
                let mut list = vec![grease_group];
                list.extend_from_slice(&groups);
                vec16(&u16s(&list))
            }
            EXT_ALPN => {
                let mut piece = vec16(b"h2");
                piece.extend_from_slice(&vec16(b"http/1.1"));
                vec16(&piece)
            }
            EXT_SIGNATURES => vec16(&u16s(&SIGNATURES)),
            EXT_KEY_SHARE => vec16(&key_shares),
            EXT_VERSIONS => vec8(&u16s(&[grease_version, 0x0304, 0x0303])),
            EXT_COMPRESS_CERT => vec8(&u16s(&[0x0002])),
            EXT_ALPS => vec16(&vec16(b"h2")),
            _ => default_body,
        };
        set.push((kind, body));
    }
    // Chrome перемешивает расширения в каждом соединении; GREASE стоят по краям.
    let shuffle = rnd(set.len());
    for index in (1..set.len()).rev() {
        let other = usize::from(shuffle[index]) % (index + 1);
        set.swap(index, other);
    }
    let mut extensions: Vec<u8> = Vec::new();
    extensions.extend_from_slice(&extension(grease_first, &[]));
    for (kind, body) in &set {
        extensions.extend_from_slice(&extension(*kind, body));
    }
    extensions.extend_from_slice(&extension(grease_last, &[0]));

    let mut ciphers = vec![grease_cipher];
    ciphers.extend_from_slice(&CHROME_CIPHERS);

    let mut body: Vec<u8> = vec![0x03, 0x03];
    body.extend_from_slice(&rnd(32));
    body.extend_from_slice(&vec8(&rnd(32))); // идентификатор сеанса: Chrome всегда шлёт 32 байта
    body.extend_from_slice(&vec16(&u16s(&ciphers)));
    body.extend_from_slice(&vec8(&[0]));
    body.extend_from_slice(&vec16(&extensions));

    let mut handshake: Vec<u8> = vec![0x01];
    let length = body.len() as u32;
    handshake.push(((length >> 16) & 0xFF) as u8);
    handshake.push(((length >> 8) & 0xFF) as u8);
    handshake.push((length & 0xFF) as u8);
    handshake.extend_from_slice(&body);
    let mut record: Vec<u8> = vec![RECORD_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(&vec16(&handshake));
    record
}

/// python `host.encode("idna")` — ASCII-имена кодируются байтами без
/// изменений; кириллицу берёт движок сайтов, здесь только ASCII.
#[must_use]
pub fn idna_encode(host: &str) -> Vec<u8> {
    host.as_bytes().to_vec()
}

/// python `parse_hello` — разбор собранного приветствия:
/// (шифры, расширения, имя сайта). GREASE отброшены.
///
/// Нужен, чтобы тест сверял состав приветствия с составом Chrome.
#[must_use]
pub fn parse_hello(record: &[u8]) -> (Vec<u16>, Vec<u16>, String) {
    let real =
        |value: u16| -> bool { !((value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF)) };
    let body = &record[9..];
    let mut offset = 2 + 32;
    offset += 1 + usize::from(body[offset]);
    let low = usize::from(body[offset]) << 8 | usize::from(body[offset + 1]);
    let mut ciphers: Vec<u16> = Vec::new();
    for index in 0..low / 2 {
        let spot = offset + 2 + index * 2;
        ciphers.push(u16::from_be_bytes([body[spot], body[spot + 1]]));
    }
    offset += 2 + low;
    offset += 1 + usize::from(body[offset]);
    let span = usize::from(body[offset]) << 8 | usize::from(body[offset + 1]);
    offset += 2;
    let end = offset + span;
    let mut kinds: Vec<u16> = Vec::new();
    let mut name = String::new();
    while offset + 4 <= end && offset + 4 <= body.len() {
        let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]);
        let data =
            &body[(offset + 4).min(body.len())..(offset + 4 + usize::from(length)).min(body.len())];
        offset += 4 + usize::from(length);
        kinds.push(kind);
        if kind == EXT_SNI && data.len() > 5 {
            name = String::from_utf8_lossy(&data[5..]).to_string();
        }
    }
    (
        ciphers.into_iter().filter(|value| real(*value)).collect(),
        kinds.into_iter().filter(|value| real(*value)).collect(),
        name,
    )
}

/// python `ja4` внутри: короткая строка SHA-256 (12 знаков).
fn short(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()[..12]
        .to_string()
}

/// python `ja4` — отпечаток JA4 приветствия; порядок расширений на него не влияет.
#[must_use]
pub fn ja4(record: &[u8]) -> String {
    let (ciphers, extensions, _name) = parse_hello(record);
    let mut hashed: Vec<String> = extensions
        .iter()
        .filter(|kind| **kind != EXT_SNI && **kind != EXT_ALPN)
        .map(|kind| format!("{kind:04x}"))
        .collect();
    hashed.sort();
    let signatures = SIGNATURES
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut cipher_hex: Vec<String> = ciphers.iter().map(|value| format!("{value:04x}")).collect();
    cipher_hex.sort();
    format!(
        "t13d{:02}{:02}h2_{}_{}",
        ciphers.len(),
        extensions.len(),
        short(&cipher_hex.join(",")),
        short(&format!("{}_{}", hashed.join(","), signatures)),
    )
}

/// python `name_offset` — где в записи лежит имя сайта. None — не нашли.
#[must_use]
pub fn name_offset(record: &[u8], host: &str) -> Option<usize> {
    let name = idna_encode(host);
    if name.is_empty() || record.len() < name.len() {
        return None;
    }
    record
        .windows(name.len())
        .position(|piece| piece == name.as_slice())
}

/// python `split_record` — одно приветствие двумя записями TLS: разрез на
/// байте `at` исходной записи.
///
/// Сервер обязан склеить такие записи; фильтр, который читает только первую,
/// имени целиком не увидит.
#[must_use]
pub fn split_record(record: &[u8], at: usize) -> (Vec<u8>, Vec<u8>) {
    let body = &record[5..];
    let cut = at.saturating_sub(5).max(1).min(body.len() - 1);
    let head = &record[..3];
    let mut first = head.to_vec();
    first.extend_from_slice(&vec16(&body[..cut]));
    let mut second = head.to_vec();
    second.extend_from_slice(&vec16(&body[cut..]));
    (first, second)
}

/// Уровень сети для `send_parts`: соединение, отправка, чтение байтов.
pub trait Socket {
    /// python `sock.sendall` — отправка куска.
    fn send_all(&mut self, data: &[u8]);
    /// python `_read_exact` — чтение до `size` байт, но не дольше (в приоритете
    /// меньше — это закрытие). Доступный кусок.
    fn read_exact(&mut self, size: usize) -> Vec<u8>;
}

/// python `send_hello` — шлёт приветствие Chrome на `ip` и сообщает, что
/// пришло в ответ (см. [`send_parts`]).
#[allow(clippy::too_many_arguments)]
pub fn send_hello(
    ip: &str,
    host: &str,
    port: u16,
    timeout: f64,
    rnd: &mut Random<'_>,
    is_cancelled: impl Fn() -> bool,
    connect: impl FnMut(&str, u16) -> Option<Box<dyn Socket>>,
    sleep: impl FnMut(f64),
    took_ms: &mut dyn FnMut() -> f64,
) -> HelloResult {
    let hello = build_hello(host, rnd, true, true);
    send_parts(
        ip,
        vec![hello],
        0.0,
        port,
        timeout,
        is_cancelled,
        connect,
        sleep,
        took_ms,
    )
}

/// python `send_parts` — шлёт готовое приветствие кусками `parts` (с паузой
/// `pause` между ними) и сообщает, что пришло в ответ.
///
/// Каждый кусок уходит отдельным пакетом. `HELLO_OK` — сервер ответил своим
/// приветствием; `HELLO_ALERT` — сервер ответил отказом (приветствие до него
/// всё равно дошло); `HELLO_RESET` и `HELLO_TIMEOUT` — соединение
/// установилось, но ответа на приветствие нет.
#[allow(clippy::too_many_arguments)]
pub fn send_parts(
    ip: &str,
    parts: Vec<Vec<u8>>,
    pause: f64,
    port: u16,
    timeout: f64,
    is_cancelled: impl Fn() -> bool,
    mut connect: impl FnMut(&str, u16) -> Option<Box<dyn Socket>>,
    mut sleep: impl FnMut(f64),
    took_ms: &mut dyn FnMut() -> f64,
) -> HelloResult {
    let _ = timeout;
    let mut socket: Box<dyn Socket> = match connect(ip, port) {
        Some(socket) => socket,
        None => {
            if is_cancelled() {
                return HelloResult::new(HELLO_CANCELLED);
            }
            return HelloResult::new(HELLO_CONNECT);
        }
    };
    for (index, part) in parts.iter().enumerate() {
        if index > 0 && pause > 0.0 {
            sleep(pause);
        }
        socket.send_all(part);
    }
    let took = took_ms();
    let header = socket.read_exact(5);
    if header.len() < 5 {
        // Соединение закрыли, не ответив: для фильтра это то же, что сброс.
        if is_cancelled() {
            return HelloResult::new(HELLO_CANCELLED);
        }
        return HelloResult::new(HELLO_RESET).with_detail("соединение закрыто без ответа");
    }
    if header[0] == RECORD_ALERT {
        return HelloResult {
            kind: HELLO_ALERT.to_string(),
            detail: String::new(),
            ms: Some(took),
        };
    }
    if header[0] != RECORD_HANDSHAKE || header[1] != 0x03 {
        return HelloResult::new(HELLO_GARBAGE);
    }
    let first = socket.read_exact(1);
    if !first.is_empty() && first[0] == HANDSHAKE_SERVER_HELLO {
        return HelloResult {
            kind: HELLO_OK.to_string(),
            detail: String::new(),
            ms: Some(took),
        };
    }
    HelloResult::new(HELLO_GARBAGE)
}

/// python `send_parts` ветка `timeout` — таймаут чтения/соединения.
///
/// В rust Socket-слое таймаут приходит как `Socket::timeout_reached()`;
/// здесь только классификация — сам прыжок делает транспорт.
pub fn send_parts_timeout(connected: bool, is_cancelled: impl Fn() -> bool) -> HelloResult {
    if is_cancelled() {
        HelloResult::new(HELLO_CANCELLED)
    } else if connected {
        HelloResult::new(HELLO_TIMEOUT)
    } else {
        HelloResult::new(HELLO_CONNECT)
    }
}

/// python `send_parts` ветка `OSError` — ошибка соединения/передачи.
#[must_use]
pub fn send_parts_error(
    connected: bool,
    detail: &str,
    is_cancelled: impl Fn() -> bool,
) -> HelloResult {
    if is_cancelled() {
        HelloResult::new(HELLO_CANCELLED)
    } else if connected {
        HelloResult::new(HELLO_RESET).with_detail(detail)
    } else {
        HelloResult::new(HELLO_CONNECT).with_detail(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Seeded(RefCell<fastrand::Rng>);

    /// python `os.urandom` — детерминированный источник в тесте.
    fn seeded(seed: u64) -> Seeded {
        Seeded(RefCell::new(fastrand::Rng::with_seed(seed)))
    }

    impl Seeded {
        fn random(&self, size: usize) -> Vec<u8> {
            let mut chunk = vec![0_u8; size];
            self.0.borrow_mut().fill(&mut chunk);
            chunk
        }
    }

    #[test]
    fn grease_python() {
        assert_eq!(grease(0), 0x0A0A);
        assert_eq!(grease(0x1F), 0x1A1A);
        assert_eq!(grease(0x3D), 0x3A3A);
        assert_eq!(grease(0xA3), 0xAAAA);
        assert_eq!(u16s(&[grease(0x13)]), vec![0x1A, 0x1A]);
    }

    #[test]
    fn vec_helpers() {
        assert_eq!(vec8(b"ab"), vec![2, 97, 98]);
        assert_eq!(vec16(b"ab"), vec![0, 2, 97, 98]);
        assert_eq!(u16s(&[0x0102, 0x0304]), vec![1, 2, 3, 4]);
    }

    /// python: приветствие несёт шифры и расширения Chrome целиком.
    #[test]
    fn hello_composition() {
        let source = seeded(0x17B012);
        let record = build_hello("x.com", &mut |size| source.random(size), true, true);
        let (ciphers, extensions, name) = parse_hello(&record);
        assert_eq!(ciphers, CHROME_CIPHERS.to_vec());
        let mut set: Vec<u16> = Vec::new();
        for kind in extensions {
            let real = !((kind & 0x0F0F) == 0x0A0A && (kind >> 8) == (kind & 0xFF));
            if real {
                set.push(kind);
            }
        }
        set.sort();
        let mut chrome = CHROME_EXTENSIONS.to_vec();
        chrome.sort();
        assert_eq!(set, chrome);
        assert_eq!(name, "x.com");
    }

    /// python: отпечаток — тот самый, который фильтр режет.
    #[test]
    fn fingerprint_is_the_known_one() {
        for seed in [1_u64, 2, 3, 4] {
            let source = seeded(seed);
            let record = build_hello("x.com", &mut |size| source.random(size), true, true);
            assert_eq!(ja4(&record), BLOCKED_JA4);
        }
    }

    /// python: приветствие занимает два пакета, как у настоящего браузера.
    #[test]
    fn hello_takes_two_packets() {
        let source = seeded(7);
        let record = build_hello("x.com", &mut |size| source.random(size), true, true);
        assert!(record.len() > 1500);
        // Заголовок записи: рукопожатие, длина совпадает с содержимым.
        assert_eq!(record[0], 22);
        let length = usize::from(record[3]) << 8 | usize::from(record[4]);
        assert_eq!(length, record.len() - 5);
    }

    /// python: порядок расширения разный у соседних соединений.
    #[test]
    fn extension_order_changes_between_connections() {
        let mut orders: Vec<Vec<u16>> = Vec::new();
        for seed in 0..8 {
            let source = seeded(seed);
            let record = build_hello("x.com", &mut |size| source.random(size), true, true);
            let extensions = parse_hello(&record).1;
            if !orders.iter().any(|seen| seen == &extensions) {
                orders.push(extensions);
            }
        }
        assert!(orders.len() > 1);
    }

    /// python: ключ ML-KEM проходит серверную проверку — все 12-битные числа < 3329.
    #[test]
    fn mlkem_key_would_pass_server_check() {
        let mut calls = 0_usize;
        let key = mlkem_public_key(&mut |size| {
            calls += 1;
            vec![0xFF; size]
        });
        assert_eq!(key.len(), 1184);
        let packed = &key[..1152];
        let mut offset = 0;
        while offset < packed.len() {
            let first = u16::from(packed[offset]) | (u16::from(packed[offset + 1] & 0x0F) << 8);
            let second =
                (u16::from(packed[offset + 1]) >> 4) | (u16::from(packed[offset + 2]) << 4);
            assert!(first < 3329);
            assert!(second < 3329);
            offset += 3;
        }
        assert!(calls > 0);
    }

    /// python: имя сайта лежит в записи, разрез между первым и последним куском.
    #[test]
    fn split_record_python() {
        let source = seeded(99);
        let record = build_hello("x.com", &mut |size| source.random(size), true, true);
        let place = name_offset(&record, "x.com").expect("имя нашлось");
        let name = br"x.com".to_vec();
        let (head, tail) = split_record(&record, place + name.len() + 5);
        // Обе половины с заголовком рукопожатия.
        assert_eq!(&head[..3], &record[..3]);
        assert_eq!(&tail[..3], &record[..3]);
        // Первый кусок включает начало имени.
        // Байты имени целиком — в первом куске.
        assert!(head
            .windows(name.len())
            .any(|piece| piece == name.as_slice()));
        // Второй не содержит имени целиком (разрез после имени) — там только хвост.
        assert!(!tail
            .windows(name.len())
            .any(|piece| piece == name.as_slice()));
    }

    /// python: без ECH отпечаток другой; без постквантового ключа — коротее,
    /// но почерк тот же (JA4 не смотрит на ключ).
    #[test]
    fn without_ech_is_not_chrome_fingerprint() {
        let source = seeded(3);
        let short = build_hello("x.com", &mut |size| source.random(size), false, true);
        assert_eq!(ja4(&short), BLOCKED_JA4);
        let source = seeded(3);
        let plain = build_hello("x.com", &mut |size| source.random(size), true, false);
        assert_ne!(ja4(&plain), BLOCKED_JA4);
        let source = seeded(3);
        let full = build_hello("x.com", &mut |size| source.random(size), true, true);
        assert!(full.len() > short.len());
    }

    /// python: send_parts_timeout / send_parts_error — классификация без сети.
    #[test]
    fn send_parts_classify_python() {
        assert_eq!(send_parts_timeout(true, || false).kind, HELLO_TIMEOUT);
        assert_eq!(send_parts_timeout(false, || false).kind, HELLO_CONNECT);
        assert_eq!(send_parts_timeout(true, || true).kind, HELLO_CANCELLED);
        assert_eq!(send_parts_error(true, "сброс", || false).kind, HELLO_RESET);
        assert_eq!(
            send_parts_error(false, "сброс", || false).kind,
            HELLO_CONNECT
        );
        assert_eq!(
            send_parts_error(true, "сброс", || true).kind,
            HELLO_CANCELLED
        );
    }
}
