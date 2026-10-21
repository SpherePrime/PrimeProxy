//! Obfuscated2 для прокси: разбор потока клиента и сборка нового потока к Telegram.
//!
//! Порт `telegram_proxy/proxy/obfs.py`. Telegram Desktop шлёт прокси свой
//! поток: через SOCKS5 — abridged (0xef) без секрета, через MTProxy с секретом
//! dd/ee — padded intermediate (0xdd). Прокси расшифровывает его, режет на
//! MTProto-пакеты и собирает для каждого маршрута новый заголовок obfuscated2
//! уже без секрета и всегда в abridged. Правила сверены с ZaStoGram и tdesktop.

use crate::crypto::sha256;
use crate::proxy::aes_ctr::AesCtrStream;

pub const HEADER_LEN: usize = 64;

/// Форматы пакетов MTProto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framing {
    Abridged,
    Intermediate,
    Padded,
}

impl Framing {
    /// Имя формата в сообщениях об ошибках (как в python-версии).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abridged => "abridged",
            Self::Intermediate => "intermediate",
            Self::Padded => "padded",
        }
    }
}

const TAG_ABRIDGED: [u8; 4] = [0xEF; 4];
const TAG_INTERMEDIATE: [u8; 4] = [0xEE; 4];
const TAG_PADDED: [u8; 4] = [0xDD; 4];

/// Больше MTProto-пакет быть не может (tdesktop: kPacketSizeMax).
pub const MAX_PACKET_LEN: usize = 64 * 1024 * 1024;

/// Как заполнять байты 60..61 заголовка к серверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcField {
    /// Релей kwsN: DC задаёт имя хоста, байты случайные.
    Random,
    /// Фронты Cloudflare: всегда +dc, даже для медиа.
    Plus,
    /// Туннель и прямой TCP: -dc для медиа.
    Signed,
}

/// Ошибка протокола MTProto: текст — для журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfsError(pub String);

impl std::fmt::Display for ObfsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ObfsError {}

/// Пара шифров одной стороны: чем расшифровывать входящее и шифровать исходящее.
pub struct StreamCipher {
    pub decryptor: AesCtrStream,
    pub encryptor: AesCtrStream,
}

/// Разобранный заголовок клиента: формат пакетов, DC и шифры.
pub struct ClientSide {
    pub framing: Framing,
    /// Номер DC из заголовка: медиа приходит с отрицательным номером.
    pub dc: i32,
    pub is_media: bool,
    pub cipher: StreamCipher,
}

/// Шифр «от инициатора» и шифр «к инициатору» по 48 байтам заголовка.
fn pair_from_prekey(prekey_iv: &[u8], secret: &[u8]) -> (AesCtrStream, AesCtrStream) {
    let mut forward_key = [0_u8; 32];
    forward_key.copy_from_slice(&prekey_iv[..32]);
    let mut forward_iv = [0_u8; 16];
    forward_iv.copy_from_slice(&prekey_iv[32..48]);
    let reverse: Vec<u8> = prekey_iv.iter().rev().copied().collect();
    let mut backward_key = [0_u8; 32];
    backward_key.copy_from_slice(&reverse[..32]);
    let mut backward_iv = [0_u8; 16];
    backward_iv.copy_from_slice(&reverse[32..48]);
    if !secret.is_empty() {
        forward_key = sha256(&[&forward_key, secret]);
        backward_key = sha256(&[&backward_key, secret]);
    }
    (
        AesCtrStream::from_arrays(forward_key, forward_iv),
        AesCtrStream::from_arrays(backward_key, backward_iv),
    )
}

fn parse_client(init: &[u8], secret: &[u8]) -> Option<ClientSide> {
    if init.len() < HEADER_LEN {
        return None;
    }
    let prekey_iv = &init[8..56];
    let (mut from_client, to_client) = pair_from_prekey(prekey_iv, secret);
    // update возвращает данные XOR keystream — это и есть расшифровка.
    let plain: Vec<u8> = from_client.update(&init[..HEADER_LEN]);
    let tag = [plain[56], plain[57], plain[58], plain[59]];
    let framing = if tag == TAG_ABRIDGED {
        Framing::Abridged
    } else if tag == TAG_INTERMEDIATE {
        Framing::Intermediate
    } else if tag == TAG_PADDED {
        Framing::Padded
    } else {
        return None;
    };
    let dc_raw = i16::from_le_bytes([plain[60], plain[61]]);
    Some(ClientSide {
        framing,
        dc: i32::from(dc_raw.unsigned_abs()),
        is_media: dc_raw < 0,
        cipher: StreamCipher {
            decryptor: from_client,
            encryptor: to_client,
        },
    })
}

/// Заголовок клиента SOCKS5: ключи лежат прямо в заголовке.
#[must_use]
pub fn parse_plain_client(init: &[u8]) -> Option<ClientSide> {
    parse_client(init, &[])
}

/// Заголовок клиента MTProxy: ключи смешаны с секретом.
#[must_use]
pub fn parse_secret_client(init: &[u8], secret_hex: &str) -> Option<ClientSide> {
    let secret = hex_to_bytes(secret_hex)?;
    if secret.len() != 16 {
        return None;
    }
    parse_client(init, &secret)
}

fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(
                std::str::from_utf8(&text[index * 2..index * 2 + 2]).ok()?,
                16,
            )
            .ok()
        })
        .collect()
}

/// Значение байтов 60..61 заголовка к серверу; `None` — случайные.
#[must_use]
pub fn dc_field_value(policy: DcField, dc: i32, is_media: bool) -> Option<i16> {
    match policy {
        DcField::Random => None,
        DcField::Plus => Some(dc as i16),
        DcField::Signed => {
            if is_media {
                Some(-(dc as i16))
            } else {
                Some(dc as i16)
            }
        }
    }
}

/// Начала заголовка, которые сервер принял бы за другой протокол.
fn forbidden_start(header: &[u8]) -> bool {
    const FORBIDDEN: [&[u8; 4]; 6] = [
        b"HEAD",
        b"POST",
        b"GET ",
        b"OPTI",
        &TAG_INTERMEDIATE,
        &TAG_PADDED,
    ];
    FORBIDDEN.iter().any(|start| *start == &header[..4])
}

/// Новый заголовок к Telegram (abridged, без секрета) и шифры этой связи.
#[must_use]
pub fn build_server_header(dc_value: Option<i16>) -> (Vec<u8>, StreamCipher) {
    let mut header = loop {
        let mut header = [0_u8; HEADER_LEN];
        fastrand::fill(&mut header);
        if header[0] == 0xEF || forbidden_start(&header) || header[4..8] == [0; 4] {
            continue;
        }
        break header;
    };
    let prekey_iv: Vec<u8> = header[8..56].to_vec();
    let dc_bytes: [u8; 2] = match dc_value {
        None => {
            let mut bytes = [0_u8; 2];
            fastrand::fill(&mut bytes);
            bytes
        }
        Some(value) => value.to_le_bytes(),
    };
    let mut tail_plain = Vec::with_capacity(8);
    tail_plain.extend_from_slice(&TAG_ABRIDGED);
    tail_plain.extend_from_slice(&dc_bytes);
    tail_plain.extend_from_slice(&[0, 0]);

    let (mut to_server, from_server) = pair_from_prekey(&prekey_iv, &[]);
    // Keystream первых 64 байт: свежий поток «к серверу», продвинутый нулями,
    // даёт те же байты, которыми шифруется хвост заголовка.
    let keystream = to_server.update(&[0_u8; HEADER_LEN]);
    for index in 0..8 {
        header[56 + index] = tail_plain[index] ^ keystream[56 + index];
    }
    let cipher = StreamCipher {
        decryptor: from_server,
        encryptor: to_server,
    };
    (header.to_vec(), cipher)
}

/// Убирает случайную добивку padded intermediate по устройству MTProto.
///
/// Незашифрованный пакет: auth_key_id=0 (8) + msg_id (8) + длина (4) + тело.
/// Зашифрованный: auth_key_id (8) + msg_key (16) + данные кратно 16. Добивка
/// всегда меньше 16 байт, поэтому длина восстанавливается однозначно.
///
/// # Errors
/// Возвращает [`ObfsError`], если заявленная длина тела больше пакета.
pub fn strip_padding(data: &[u8]) -> Result<Vec<u8>, ObfsError> {
    let size = data.len();
    if size >= 20 && data[..8] == [0; 8] {
        let declared = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let exact = 20 + declared;
        if exact <= size {
            return Ok(data[..exact].to_vec());
        }
        return Err(ObfsError("padded: длина тела больше пакета".into()));
    }
    // python: (size - 8) % 16 — остаток всегда неотрицательный.
    let exact = size as i64 - (size as i64 - 8).rem_euclid(16);
    if exact < 24 {
        // Короткий служебный пакет (например, код ошибки транспорта).
        return Ok(data[..size - (size % 4)].to_vec());
    }
    Ok(data[..exact as usize].to_vec())
}

/// Режет расшифрованный поток на MTProto-пакеты (без длины и добивки).
pub struct PacketReader {
    framing: Framing,
    buffer: Vec<u8>,
}

impl PacketReader {
    /// Новый разборщик для формата `framing`.
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            buffer: Vec::new(),
        }
    }

    /// Сколько байт ещё ждут целого пакета.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Добавляет кусок расшифрованного потока и возвращает целые пакеты.
    ///
    /// # Errors
    /// Возвращает [`ObfsError`] при неверной длине пакета.
    pub fn feed(&mut self, plain: &[u8]) -> Result<Vec<Vec<u8>>, ObfsError> {
        self.buffer.extend_from_slice(plain);
        let mut packets = Vec::new();
        while let Some(packet) = self.next()? {
            packets.push(packet);
        }
        Ok(packets)
    }

    fn next(&mut self) -> Result<Option<Vec<u8>>, ObfsError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        let (size, head): (usize, usize) = if self.framing == Framing::Abridged {
            let first = (self.buffer[0] & 0x7F) as usize;
            if first == 0x7F {
                if self.buffer.len() < 4 {
                    return Ok(None);
                }
                let words = u32::from(self.buffer[1])
                    | (u32::from(self.buffer[2]) << 8)
                    | (u32::from(self.buffer[3]) << 16);
                ((words as usize) * 4, 4)
            } else {
                (first * 4, 1)
            }
        } else {
            if self.buffer.len() < 4 {
                return Ok(None);
            }
            let raw = u32::from_le_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) & 0x7FFF_FFFF;
            (raw as usize, 4)
        };
        if size == 0 || size > MAX_PACKET_LEN {
            return Err(ObfsError(format!(
                "{}: неверная длина пакета {size}",
                self.framing.as_str()
            )));
        }
        if self.buffer.len() < head + size {
            return Ok(None);
        }
        let mut payload: Vec<u8> = self.buffer[head..head + size].to_vec();
        self.buffer.drain(..head + size);
        if self.framing == Framing::Padded {
            payload = strip_padding(&payload)?;
        }
        Ok(Some(payload))
    }
}

/// Длина + пакет в нужном формате. Бит quick ack никогда не ставится.
///
/// # Errors
/// Возвращает [`ObfsError`] для abridged-пакета некратной длины 4.
pub fn encode_packet(framing: Framing, payload: &[u8]) -> Result<Vec<u8>, ObfsError> {
    let size = payload.len();
    match framing {
        Framing::Abridged => {
            if size % 4 != 0 {
                return Err(ObfsError("abridged: длина пакета не кратна 4".into()));
            }
            let words = size / 4;
            if words < 0x7F {
                let mut result = vec![words as u8];
                result.extend_from_slice(payload);
                return Ok(result);
            }
            let mut result = vec![0x7F];
            result.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            result.extend_from_slice(payload);
            Ok(result)
        }
        Framing::Intermediate => {
            let mut result = (size as u32).to_le_bytes().to_vec();
            result.extend_from_slice(payload);
            Ok(result)
        }
        Framing::Padded => {
            // Ошибку транспорта (-404 и др., ровно 4 байта) Desktop узнаёт
            // только по длине пакета в одно слово: с хвостом он её не видит.
            let padding = if size == 4 {
                Vec::new()
            } else {
                let count = fastrand::u8(..) % 16;
                let mut padding = vec![0_u8; count as usize];
                fastrand::fill(&mut padding);
                padding
            };
            let mut result = ((size + padding.len()) as u32).to_le_bytes().to_vec();
            result.extend_from_slice(payload);
            result.extend_from_slice(&padding);
            Ok(result)
        }
    }
}

/// Первые байты похожи на HTTP-транспорт Telegram (порт 80), а не на MTProto.
#[must_use]
pub fn is_http_transport(data: &[u8]) -> bool {
    data.starts_with(b"POST ")
        || data.starts_with(b"GET ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает заголовок клиента, как это делает тест python-версии.
    fn build_client_header(tag: [u8; 4], dc: i16, secret: &[u8]) -> Vec<u8> {
        use crate::proxy::aes_ctr::aes_ctr_keystream;
        let mut header = [0_u8; 64];
        fastrand::fill(&mut header);
        header[0] = 0x42;
        header[4..8].copy_from_slice(&[0x11; 4]);
        let prekey = header[8..40].to_vec();
        let iv = header[40..56].to_vec();
        let mut key = prekey.clone();
        if !secret.is_empty() {
            key = sha256(&[&key, secret]).to_vec();
        }
        let mut tail = tag.to_vec();
        tail.extend_from_slice(&dc.to_le_bytes());
        tail.extend_from_slice(&[0, 0]);
        let keystream = aes_ctr_keystream(&key, &iv, 64).unwrap();
        for (index, byte) in tail.iter().enumerate() {
            header[56 + index] = *byte ^ keystream[56 + index];
        }
        header.to_vec()
    }

    #[test]
    fn parse_secret_client_reads_dc_and_media() {
        let secret_hex = "aabbccddeeff00112233445566778899";
        let secret = hex_to_bytes(secret_hex).unwrap();
        let init = build_client_header(TAG_INTERMEDIATE, -4, &secret);
        let parsed = parse_secret_client(&init, secret_hex).expect("parsed");
        assert_eq!(parsed.dc, 4);
        assert!(parsed.is_media);
        assert_eq!(parsed.framing, Framing::Intermediate);
        assert!(parse_secret_client(&init, "00112233445566778899aabbccddeeff").is_none());
        assert!(parse_plain_client(&init).is_none());
    }

    #[test]
    fn parse_plain_client_reads_positive_dc() {
        let init = build_client_header(TAG_ABRIDGED, 2, &[]);
        let parsed = parse_plain_client(&init).expect("parsed");
        assert_eq!(parsed.dc, 2);
        assert!(!parsed.is_media);
        assert_eq!(parsed.framing, Framing::Abridged);
    }

    #[test]
    fn short_init_is_rejected() {
        assert!(parse_plain_client(&[0_u8; 63]).is_none());
        assert!(parse_secret_client(&[0_u8; 64], "zz").is_none());
        assert!(parse_secret_client(&[0_u8; 64], "aabb").is_none());
    }

    #[test]
    fn abridged_packet_reader_roundtrip() {
        let mut reader = PacketReader::new(Framing::Abridged);
        let first = vec![0xAA; 4];
        let second = vec![0xBB; 0x7F * 4];
        let mut stream = encode_packet(Framing::Abridged, &first).unwrap();
        stream.extend(encode_packet(Framing::Abridged, &second).unwrap());
        let packets = reader.feed(&stream).unwrap();
        assert_eq!(packets, vec![first, second]);
        assert_eq!(reader.pending_bytes(), 0);
    }

    #[test]
    fn abridged_partial_packet_waits_for_rest() {
        let mut reader = PacketReader::new(Framing::Abridged);
        let packet = vec![0x11; 8];
        let stream = encode_packet(Framing::Abridged, &packet).unwrap();
        assert!(reader.feed(&stream[..5]).unwrap().is_empty());
        let packets = reader.feed(&stream[5..]).unwrap();
        assert_eq!(packets, vec![packet]);
    }

    #[test]
    fn bad_abridged_length_is_an_error() {
        // python: first = buf[0] & 0x7F; размер 0 → «неверная длина пакета 0».
        // Расширенная длина 0xFFFFFF*4 = 67108860 не превышает MAX_PACKET_LEN,
        // поэтому читатель честно ждёт остаток пакета.
        // python: first = buf[0] & 0x7F; размер 0 → «неверная длина пакета 0».
        // Расширенная длина 0xFFFFFF*4 = 67108860 не превышает MAX_PACKET_LEN,
        // поэтому читатель честно ждёт остаток пакета (буфер копится).
        let mut reader = PacketReader::new(Framing::Abridged);
        assert!(reader.feed(&[0x7F, 0xFF, 0xFF, 0xFF]).unwrap().is_empty());
        let mut reader = PacketReader::new(Framing::Abridged);
        let error = reader.feed(&[0x00]).unwrap_err();
        assert!(error.0.contains("неверная длина"));
    }

    #[test]
    fn intermediate_reader_keeps_high_bit_masked() {
        let mut reader = PacketReader::new(Framing::Intermediate);
        let packet = vec![1_u8; 4];
        let mut stream = (u32::MAX).to_le_bytes().to_vec();
        stream.extend_from_slice(&packet);
        let error = reader.feed(&stream).unwrap_err();
        assert!(error.0.contains("неверная длина"));
    }

    #[test]
    fn padded_reader_strips_random_tail() {
        let mut reader = PacketReader::new(Framing::Padded);
        let body = vec![0_u8; 8];
        let msg_id = [9_u8; 8];
        let mut packet = vec![0_u8; 8];
        packet.extend_from_slice(&msg_id);
        packet.extend_from_slice(&(8_u32).to_le_bytes());
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&[0xEE; 5]); // добивка
        let stream = encode_packet(Framing::Padded, &packet).unwrap();
        let packets = reader.feed(&stream).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 28);
        assert_eq!(&packets[0][8..16], &msg_id);
    }

    #[test]
    fn padded_transport_error_packet_stays_four_bytes() {
        let mut reader = PacketReader::new(Framing::Padded);
        let error_packet = vec![0xFF_u8; 4];
        let stream = encode_packet(Framing::Padded, &error_packet).unwrap();
        let packets = reader.feed(&stream).unwrap();
        assert_eq!(packets, vec![error_packet]);
    }

    #[test]
    fn padded_length_beyond_packet_is_an_error() {
        let mut packet = vec![0_u8; 20];
        packet.extend_from_slice(&[0xEE; 3]);
        packet[16..20].copy_from_slice(&100_u32.to_le_bytes());
        let error = strip_padding(&packet).unwrap_err();
        assert_eq!(error.0, "padded: длина тела больше пакета");
    }

    #[test]
    fn encode_rejects_unaligned_abridged_payload() {
        let error = encode_packet(Framing::Abridged, &[0; 3]).unwrap_err();
        assert_eq!(error.0, "abridged: длина пакета не кратна 4");
    }

    #[test]
    fn dc_field_follows_route_policy() {
        assert_eq!(dc_field_value(DcField::Random, 2, false), None);
        assert_eq!(dc_field_value(DcField::Plus, 2, true), Some(2));
        assert_eq!(dc_field_value(DcField::Signed, 2, true), Some(-2));
        assert_eq!(dc_field_value(DcField::Signed, 2, false), Some(2));
    }

    #[test]
    fn server_header_decodes_with_receiver_cipher() {
        let (header, mut cipher) = build_server_header(Some(2));
        assert_eq!(header.len(), 64);
        assert_ne!(header[0], 0xEF);
        // Приёмник (Telegram) расшифровывает заголовок шифром «от
        // инициатора»: ключ и IV лежат открыто в байтах 8..56.
        let mut decryptor =
            crate::proxy::aes_ctr::AesCtrStream::new(&header[8..40], &header[40..56])
                .expect("длины фиксированы");
        let plain = decryptor.update(&header);
        assert_eq!(&plain[56..60], &[0xEF; 4]);
        assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), 2);
        // Шифратор уже продвинут на длину заголовка (python: to_server.update
        // из 64 нулей), приёмник — тоже: пакет шифруется и расшифровывается
        // одной и той же гаммой.
        let message = [0xAB_u8; 32];
        let encrypted = cipher.encryptor.update(&message);
        assert_eq!(decryptor.update(&encrypted), message.to_vec());
    }

    #[test]
    fn http_transport_detection() {
        assert!(is_http_transport(b"POST /api HTTP/1.1"));
        assert!(is_http_transport(b"GET /"));
        assert!(is_http_transport(b"HEAD "));
        assert!(is_http_transport(b"OPTIONS "));
        assert!(!is_http_transport(b"POST".as_slice()));
        assert!(!is_http_transport(b"\xef\xef\xef\xef"));
    }
}
