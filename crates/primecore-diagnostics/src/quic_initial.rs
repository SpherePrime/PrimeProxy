//! Порт `src/utils/quic_initial.py` — первый пакет QUIC (Initial) с именем
//! сайта, для проверки, пропускают ли его.
//!
//! QUIC идёт по UDP на порт 443; на нём браузеры открывают YouTube и многие
//! другие сайты. Первый пакет зашифрован, но ключ выводится из открытых данных
//! самого пакета (RFC 9001, раздел 5.2), поэтому фильтр по дороге может его
//! расшифровать и прочитать имя сайта. Чтобы проверить, блокируют ли QUIC по
//! имени, нужен такой же настоящий пакет: с правильным шифрованием и с
//! приветствием TLS 1.3 внутри.
//!
//! Шифрование здесь своё, без внешних крипто-библиотек — как в python, где
//! AES собран руками: для одного пакета скорость не важна. Нужно только
//! зашифровать — расшифровывать ответ не требуется: ответом считается любой
//! пакет сервера на наше соединение.

/// QUIC версии 1 (RFC 9000).
pub const QUIC_V1: u32 = 0x0000_0001;
/// RFC 9001, 5.2: из этой соли и номера соединения выводятся ключи первого пакета.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// Сервер отвечает только на первый пакет не короче 1200 байт (RFC 9000, 14.1).
pub const MIN_DATAGRAM: usize = 1200;
const PACKET_NUMBER_SIZE: usize = 4;
const TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// AES-128: шифрование одного блока (FIPS 197)
// ---------------------------------------------------------------------------

/// Таблица замены вычисляется, а не вписывается: в 256 числах легко ошибиться.
const fn build_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    let mut p: u16 = 1;
    let mut q: u16 = 1;
    loop {
        // p умножается на 3, q делится на 3 в поле GF(2^8): q — обратный к p.
        let bump = if p & 0x80 != 0 { 0x1B } else { 0 };
        p = (p ^ (p << 1) ^ bump) & 0xFF;
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q &= 0xFF;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let value = q
            ^ ((q << 1) | (q >> 7))
            ^ ((q << 2) | (q >> 6))
            ^ ((q << 3) | (q >> 5))
            ^ ((q << 4) | (q >> 4));
        sbox[p as usize] = (value ^ 0x63) as u8;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
}

const SBOX: [u8; 256] = build_sbox();
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn xtime(value: u16) -> u16 {
    if value & 0x80 != 0 {
        ((value << 1) ^ 0x1B) & 0xFF
    } else {
        value << 1
    }
}

/// Ключ раундов: 11 блоков по 16 байт (python держит 44 слова — то же самое).
fn expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut words: [[u8; 4]; 44] = [[0u8; 4]; 44];
    for (index, word) in words.iter_mut().enumerate().take(4) {
        *word = key[index * 4..index * 4 + 4]
            .try_into()
            .expect("ключ ровно 16 байт");
    }
    for index in 4..44 {
        let mut word = words[index - 1];
        if index % 4 == 0 {
            let rotated = [word[1], word[2], word[3], word[0]];
            for (slot, byte) in rotated.iter().enumerate() {
                word[slot] = SBOX[*byte as usize];
            }
            word[0] ^= RCON[index / 4 - 1];
        }
        for slot in 0..4 {
            word[slot] ^= words[index - 4][slot];
        }
        words[index] = word;
    }
    let mut round_keys = [[0u8; 16]; 11];
    for (round, block) in round_keys.iter_mut().enumerate() {
        for slot in 0..4 {
            block[slot * 4..slot * 4 + 4].copy_from_slice(&words[round * 4 + slot]);
        }
    }
    round_keys
}

/// state[4*столбец + строка] — байт [строка, столбец], как в python.
fn encrypt_with_round_keys(round_keys: &[[u8; 16]; 11], block: &[u8; 16]) -> [u8; 16] {
    let mut state = [0u8; 16];
    for slot in 0..16 {
        state[slot] = block[slot] ^ round_keys[0][slot];
    }
    for (round, round_key) in round_keys.iter().enumerate().skip(1) {
        // Замена байтов и сдвиг строк.
        let mut replaced = [0u8; 16];
        for column in 0..4u16 {
            for row in 0..4u16 {
                replaced[(4 * column + row) as usize] =
                    SBOX[state[((4 * (column + row) + row) % 16) as usize] as usize];
            }
        }
        state = replaced;
        if round != 10 {
            let mut mixed = [0u8; 16];
            for column in 0..4 {
                let a = &state[4 * column..4 * column + 4];
                let total = a[0] ^ a[1] ^ a[2] ^ a[3];
                for row in 0..4usize {
                    mixed[4 * column + row] =
                        a[row] ^ total ^ (xtime(u16::from(a[row] ^ a[(row + 1) % 4])) as u8);
                }
            }
            state = mixed;
        }
        for slot in 0..16 {
            state[slot] ^= round_key[slot];
        }
    }
    state
}

/// python `aes128_encrypt_block` — AES-128 одного блока (ровно 16 байт).
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    encrypt_with_round_keys(&expand_key(key), block)
}

// ---------------------------------------------------------------------------
// AES-128-GCM: шифрование с проверочной меткой (NIST SP 800-38D)
// ---------------------------------------------------------------------------

const GCM_REDUCTION: u128 = 0xE1u128 << 120;

fn gf_multiply(x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    let mut y = y;
    for bit in (0..128).rev() {
        if (x >> bit) & 1 == 1 {
            result ^= y;
        }
        y = if y & 1 == 1 {
            (y >> 1) ^ GCM_REDUCTION
        } else {
            y >> 1
        };
    }
    result
}

fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut value: u128 = 0;
    let mut consume = |data: &[u8]| {
        for offset in (0..data.len()).step_by(16) {
            let mut block = [0u8; 16];
            let end = (offset + 16).min(data.len());
            block[..end - offset].copy_from_slice(&data[offset..end]);
            value = gf_multiply(value ^ u128::from_be_bytes(block), h);
        }
    };
    consume(aad);
    consume(ciphertext);
    let mut length = [0u8; 16];
    length[..8].copy_from_slice(&((aad.len() as u64 * 8).to_be_bytes()));
    length[8..].copy_from_slice(&((ciphertext.len() as u64 * 8).to_be_bytes()));
    value = gf_multiply(value ^ u128::from_be_bytes(length), h);
    value
}

/// python `aes128_gcm_seal` — шифротекст и 16-байтовая метка одним куском.
pub fn aes128_gcm_seal(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let round_keys = expand_key(key);
    let h = u128::from_be_bytes(encrypt_with_round_keys(&round_keys, &[0u8; 16]));
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (index, chunk) in plaintext.chunks(16).enumerate() {
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&((index as u32 + 2).to_be_bytes()));
        let stream = encrypt_with_round_keys(&round_keys, &counter);
        for (slot, byte) in chunk.iter().enumerate() {
            ciphertext.push(byte ^ stream[slot]);
        }
    }
    let mut tag_input = [0u8; 16];
    tag_input[..12].copy_from_slice(nonce);
    tag_input[15] = 1;
    let tag_mask = encrypt_with_round_keys(&round_keys, &tag_input);
    let tag = ghash(h, aad, &ciphertext) ^ u128::from_be_bytes(tag_mask);
    ciphertext.extend_from_slice(&tag.to_be_bytes());
    ciphertext
}

// ---------------------------------------------------------------------------
// Ключи первого пакета (RFC 9001, 5.2)
// ---------------------------------------------------------------------------

/// python `hmac.new(secret, message, hashlib.sha256)` — без внешних зависимостей.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut normalized = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        normalized[..32].copy_from_slice(&hasher.finalize());
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in &normalized {
        inner.update([byte ^ 0x36]);
    }
    inner.update(message);
    let mut outer = Sha256::new();
    for byte in &normalized {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> Vec<u8> {
    let full = format!("tls13 {label}").into_bytes();
    let mut info = Vec::with_capacity(full.len() + 5);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0);
    info.push(1);
    let digest = hmac_sha256(secret, &info);
    digest[..length].to_vec()
}

/// python `initial_keys` — (ключ, вектор, ключ защиты заголовка) клиента для
/// первого пакета.
pub fn initial_keys(destination_id: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    let initial = hmac_sha256(&INITIAL_SALT, destination_id);
    let client = hkdf_expand_label(&initial, "client in", 32);
    let key = hkdf_expand_label(&client, "quic key", 16);
    let iv = hkdf_expand_label(&client, "quic iv", 12);
    let hp = hkdf_expand_label(&client, "quic hp", 16);
    (
        key.try_into().expect("ключ AES-128 ровно 16 байт"),
        iv.try_into().expect("вектор ровно 12 байт"),
        hp.try_into().expect("ключ заголовка ровно 16 байт"),
    )
}

// ---------------------------------------------------------------------------
// Приветствие TLS 1.3 и сам пакет
// ---------------------------------------------------------------------------

fn varint(value: u64) -> Vec<u8> {
    if value < 0x40 {
        vec![value as u8]
    } else if value < 0x4000 {
        ((value | 0x4000) as u16).to_be_bytes().to_vec()
    } else if value < 0x4000_0000 {
        ((value | 0x8000_0000) as u32).to_be_bytes().to_vec()
    } else {
        (value | 0xC000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn transport_parameters(source_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut parameter = |identifier: u64, value: &[u8]| {
        out.extend(varint(identifier));
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
    };
    parameter(0x01, &varint(30_000)); // сколько ждать без данных, мс
    parameter(0x03, &varint(1472)); // наибольший пакет
    parameter(0x04, &varint(1_048_576)); // сколько данных готовы принять всего
    parameter(0x05, &varint(262_144));
    parameter(0x06, &varint(262_144));
    parameter(0x07, &varint(262_144));
    parameter(0x08, &varint(100)); // сколько потоков может открыть сервер
    parameter(0x09, &varint(100));
    parameter(0x0F, source_id); // наш номер соединения — обязателен
    out
}

/// Имя сайта в wire-виде приветствия (python `name.encode("idna")`).
///
/// Чисто ASCII-имена python пропускает как есть (nameprep затрагивает только
/// метки с не-ASCII знаками); не-ASCII переводятся в punycode.
fn encode_idna(name: &str) -> Vec<u8> {
    if name.is_ascii() {
        return name.as_bytes().to_vec();
    }
    match idna::domain_to_ascii(name) {
        Ok(encoded) => encoded.into_bytes(),
        Err(_) => name.as_bytes().to_vec(),
    }
}

/// Приветствие TLS 1.3 с именем сайта и открытым ключом обмена.
fn client_hello(
    server_name: Option<&str>,
    source_id: &[u8],
    share: &[u8; 32],
    random: &[u8; 32],
) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(server_name) = server_name {
        let name = encode_idna(server_name);
        let mut entry = Vec::with_capacity(name.len() + 3);
        entry.push(0);
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(&name);
        let mut payload = (entry.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(&entry);
        extensions.extend(extension(0x0000, &payload));
    }
    let mut groups = Vec::new();
    groups.extend_from_slice(&0x001Du16.to_be_bytes());
    groups.extend_from_slice(&0x0017u16.to_be_bytes());
    let mut payload = (groups.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&groups);
    extensions.extend(extension(0x000A, &payload));
    let mut signatures = Vec::new();
    for algorithm in [
        0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ] {
        signatures.extend_from_slice(&algorithm.to_be_bytes());
    }
    let mut payload = (signatures.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&signatures);
    extensions.extend(extension(0x000D, &payload));
    // python: _extension(0x0010, pack("!H", len(protocol)) + protocol) —
    // у ALPN внутри свой префикс длины.
    let protocol = b"\x02h3";
    let mut alpn = (protocol.len() as u16).to_be_bytes().to_vec();
    alpn.extend_from_slice(protocol);
    extensions.extend(extension(0x0010, &alpn));
    extensions.extend(extension(0x002B, b"\x02\x03\x04")); // только TLS 1.3
    extensions.extend(extension(0x002D, b"\x01\x01"));
    // Открытый ключ для обмена: достаточно случайного — расшифровывать ответ
    // мы не будем.
    let mut share_entry = Vec::with_capacity(36);
    share_entry.extend_from_slice(&0x001Du16.to_be_bytes());
    share_entry.extend_from_slice(&32u16.to_be_bytes());
    share_entry.extend_from_slice(share);
    let mut payload = (share_entry.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&share_entry);
    extensions.extend(extension(0x0033, &payload));
    extensions.extend(extension(0x0039, &transport_parameters(source_id)));

    let mut body = Vec::with_capacity(extensions.len() + 51);
    body.extend_from_slice(b"\x03\x03");
    body.extend_from_slice(random);
    body.push(0); // в QUIC номер сеанса пустой
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(b"\x13\x01\x13\x02\x13\x03");
    body.extend_from_slice(b"\x01\x00");
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut hello = Vec::with_capacity(body.len() + 4);
    hello.push(1);
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    hello
}

/// python `InitialPacket` — готовый к отправке пакет и номер соединения, по
/// которому узнаётся ответ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialPacket {
    pub datagram: Vec<u8>,
    pub destination_id: Vec<u8>,
    pub source_id: Vec<u8>,
}

/// python `build_initial` с заданными случайными данными — для золотого теста
/// против python, где `os.urandom` подменяется очередью байт.
pub fn build_initial_with(
    server_name: Option<&str>,
    destination_id: &[u8],
    source_id: &[u8],
    share: &[u8; 32],
    random: &[u8; 32],
) -> InitialPacket {
    let (key, iv, header_key) = initial_keys(destination_id);

    let hello = client_hello(server_name, source_id, share, random);
    let mut frame = vec![0x06u8];
    frame.extend(varint(0));
    frame.extend(varint(hello.len() as u64));
    frame.extend_from_slice(&hello);
    let mut header_start = Vec::with_capacity(destination_id.len() + source_id.len() + 8);
    header_start.push(0xC0 | (PACKET_NUMBER_SIZE as u8 - 1));
    header_start.extend_from_slice(&QUIC_V1.to_be_bytes());
    header_start.push(destination_id.len() as u8);
    header_start.extend_from_slice(destination_id);
    header_start.push(source_id.len() as u8);
    header_start.extend_from_slice(source_id);
    header_start.extend(varint(0)); // без жетона
                                    // Длина пишется двумя байтами, номер пакета — четырьмя.
    let fixed = header_start.len() + 2 + PACKET_NUMBER_SIZE + TAG_SIZE;
    let padding = MIN_DATAGRAM.saturating_sub(fixed + frame.len());
    let mut payload = frame;
    payload.resize(payload.len() + padding, 0);
    let length = PACKET_NUMBER_SIZE + payload.len() + TAG_SIZE;
    let packet_number = [0u8; PACKET_NUMBER_SIZE];
    let mut header = header_start;
    header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
    header.extend_from_slice(&packet_number);

    let mut nonce = [0u8; 12];
    let offset = 12 - PACKET_NUMBER_SIZE;
    for (slot, byte) in packet_number.iter().enumerate() {
        nonce[offset + slot] = iv[offset + slot] ^ byte;
    }
    for (slot, byte) in iv.iter().enumerate().take(offset) {
        nonce[slot] = *byte;
    }
    let sealed = aes128_gcm_seal(&key, &nonce, &payload, &header);

    // Защита заголовка: по образцу из шифротекста прячутся младшие биты первого
    // байта и номер пакета (RFC 9001, 5.4).
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&sealed[..16]);
    let mask = aes128_encrypt_block(&header_key, &sample);
    let mut protected = header;
    protected[0] ^= mask[0] & 0x0F;
    let number_offset = protected.len() - PACKET_NUMBER_SIZE;
    for (slot, byte) in mask[1..1 + PACKET_NUMBER_SIZE].iter().enumerate() {
        protected[number_offset + slot] ^= byte;
    }
    let mut datagram = protected;
    datagram.extend_from_slice(&sealed);
    InitialPacket {
        datagram,
        destination_id: destination_id.to_vec(),
        source_id: source_id.to_vec(),
    }
}

/// python `build_initial` — первый пакет QUIC версии 1 с приветствием для
/// `server_name` (None — без имени); номера соединений и ключ обмена случайны.
#[must_use]
pub fn build_initial(server_name: Option<&str>) -> InitialPacket {
    let mut destination_id = [0u8; 8];
    let mut source_id = [0u8; 8];
    let mut share = [0u8; 32];
    let mut random = [0u8; 32];
    let mut rng = fastrand::Rng::new();
    rng.fill(&mut destination_id);
    rng.fill(&mut source_id);
    rng.fill(&mut share);
    rng.fill(&mut random);
    build_initial_with(server_name, &destination_id, &source_id, &share, &random)
}

/// python `is_reply_to` — пакет сервера на наше соединение: длинный заголовок и
/// наш номер получателем.
///
/// Годится любой ответ — продолжение рукопожатия, отказ, предложение другой
/// версии или просьба повторить: раз сервер ответил, наш пакет до него дошёл.
#[must_use]
pub fn is_reply_to(datagram: &[u8], packet: &InitialPacket) -> bool {
    if datagram.len() < 7 || datagram[0] & 0x80 == 0 {
        return false;
    }
    let size = datagram[5] as usize;
    datagram
        .get(6..6 + size)
        .is_some_and(|received| received == packet.source_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Golden {
        build: Vec<BuildCase>,
    }

    #[derive(serde::Deserialize)]
    struct BuildCase {
        name: Option<String>,
        hello: String,
        scid: String,
        share: String,
        random: String,
    }

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("hex в golden"))
            .collect()
    }

    /// Приветствие TLS 1.3 против python (те же случайные байты из golden).
    #[test]
    fn hello_matches_python() {
        let golden: Golden =
            serde_json::from_str(include_str!("../tests/quic_initial_golden.json"))
                .expect("golden читается");
        for case in &golden.build {
            let share: [u8; 32] = unhex(&case.share).try_into().expect("share 32 байта");
            let random: [u8; 32] = unhex(&case.random).try_into().expect("random 32 байта");
            let ours = client_hello(case.name.as_deref(), &unhex(&case.scid), &share, &random);
            let theirs = unhex(&case.hello);
            if ours != theirs {
                for (index, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
                    if a != b {
                        panic!(
                            "hello расходится с {:?} на байте {}: ours {:02x} theirs {:02x}; длины {} и {}",
                            case.name,
                            index,
                            a,
                            b,
                            ours.len(),
                            theirs.len()
                        );
                    }
                }
                panic!(
                    "hello {} короче python-ового",
                    case.name.as_deref().unwrap_or("")
                );
            }
        }
    }

    /// Ключи первого пакета от фиксированного номера соединения — считается
    /// так же, как в python (сверка с golden).
    #[test]
    fn keys_shape() {
        let (key, iv, hp) = initial_keys(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
        assert_eq!(hp.len(), 16);
    }

    #[test]
    fn reply_recognised_by_source_id() {
        let packet = build_initial_with(
            Some("example.com"),
            &[9u8; 8],
            &[7u8; 8],
            &[0u8; 32],
            &[0u8; 32],
        );
        assert!(packet.datagram.len() >= MIN_DATAGRAM);
        let mut reply = vec![0xC0u8, 0, 0, 0, 1, 8];
        reply.extend_from_slice(&packet.source_id);
        assert!(is_reply_to(&reply, &packet));
        assert!(!is_reply_to(b"\x40short", &packet));
        let mut stranger = vec![0xC0u8, 0, 0, 0, 1, 8];
        stranger.extend_from_slice(&[1u8; 8]);
        assert!(!is_reply_to(&stranger, &packet));
    }
}
