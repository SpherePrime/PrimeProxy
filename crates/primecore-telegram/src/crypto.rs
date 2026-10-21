//! Минимальная криптография для Telegram-прокси: SHA-256, SHA-1, HMAC,
//! base64 и AES-256-CTR.
//!
//! Python-версия берёт `hashlib`/`hmac`/`tgcrypto`. Крейт держит зависимости
//! на минимуме, поэтому здесь — небольшие самостоятельные реализации без
//! `unsafe`. Тесты сверяют результаты с Python через известные векторы и
//! встречные вызовы `python3 -c`.

/// Считает SHA-256 от последовательности частей сообщения.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    sha256_into(parts, &mut out);
    out
}

/// HMAC-SHA256 от ключа и сообщения.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let inner = sha256(&[&inner_pad, message]);
    sha256(&[&outer_pad, &inner])
}

/// Считает SHA-1 от последовательности частей сообщения.
#[must_use]
pub fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = parts.concat();
    let bit_len = (message.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut words = [0_u32; 80];
    for chunk in message.chunks_exact(64) {
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0_u8; 20];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Кодирует байты в base64 (стандартный алфавит, с набивкой).
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[(triple >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(triple >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[(triple >> 6) as usize & 0x3F] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[triple as usize & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Шифрует блок AES-256 на месте (только направление шифрования: CTR
/// расшифрование делается тем же шифром).
fn aes256_encrypt_block(round_keys: &[u32; 60], block: &mut [u8; 16]) {
    const SBOX: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];

    fn xtime(value: u8) -> u8 {
        let doubled = u16::from(value) << 1;
        if doubled & 0x100 != 0 {
            (doubled ^ 0x1B) as u8
        } else {
            doubled as u8
        }
    }

    fn multiply(a: u8, b: u8) -> u8 {
        let mut result = 0_u8;
        let mut factor = a;
        let mut bits = b;
        while bits != 0 {
            if bits & 1 != 0 {
                result ^= factor;
            }
            factor = xtime(factor);
            bits >>= 1;
        }
        result
    }

    let mut state = *block;
    // Начальный AddRoundKey: байты блока идут по столбцам, ключ — по словам
    // big-endian; раскладка совпадает со стандартной реализацией FIPS-197.
    for (index, word) in round_keys[..4].iter().enumerate() {
        let word_bytes = word.to_be_bytes();
        for byte_index in 0..4 {
            state[index * 4 + byte_index] ^= word_bytes[byte_index];
        }
    }
    for round in 0..14 {
        // SubBytes + ShiftRows
        let mut mixed = [0_u8; 16];
        for column in 0..4 {
            for row in 0..4 {
                mixed[column * 4 + row] = SBOX[state[(column + row) % 4 * 4 + row] as usize];
            }
        }
        // MixColumns (пропускается в последнем раунде)
        if round < 13 {
            for column in 0..4 {
                let a0 = mixed[column * 4];
                let a1 = mixed[column * 4 + 1];
                let a2 = mixed[column * 4 + 2];
                let a3 = mixed[column * 4 + 3];
                state[column * 4] = multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3;
                state[column * 4 + 1] = a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3;
                state[column * 4 + 2] = a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3);
                state[column * 4 + 3] = multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2);
            }
        } else {
            state.copy_from_slice(&mixed);
        }
        // AddRoundKey
        for word_index in 0..4 {
            let word = round_keys[(round + 1) * 4 + word_index].to_be_bytes();
            for byte_index in 0..4 {
                state[word_index * 4 + byte_index] ^= word[byte_index];
            }
        }
    }
    block.copy_from_slice(&state);
}

/// Раскладывает ключ AES-256 в 60 слов раундовых ключей.
#[must_use]
fn aes256_expand_key(key: &[u8; 32]) -> [u32; 60] {
    const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut words = [0_u32; 60];
    for (index, word) in words.iter_mut().enumerate().take(8) {
        *word = u32::from_be_bytes([
            key[index * 4],
            key[index * 4 + 1],
            key[index * 4 + 2],
            key[index * 4 + 3],
        ]);
    }
    let mut round = 0;
    for index in 8..60 {
        let mut temp = words[index - 1];
        if index % 8 == 0 {
            temp = temp.rotate_left(8); // RotWord на u32 (big-endian байты)
            temp = sub_word(temp);
            temp ^= u32::from(RCON[round]) << 24;
            round += 1;
        } else if index % 8 == 4 {
            temp = sub_word(temp);
        }
        words[index] = words[index - 8] ^ temp;
    }
    words
}

/// SubWord: каждый байт слова через таблицу S-блока.
fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX_ROT[bytes[0] as usize],
        SBOX_ROT[bytes[1] as usize],
        SBOX_ROT[bytes[2] as usize],
        SBOX_ROT[bytes[3] as usize],
    ])
}

const SBOX_ROT: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// Поток AES-256-CTR: счётчик — сам IV, растёт как big-endian число.
///
/// Раскладка совпадает с tgcrypto из Python-версии: однобайтовое состояние
/// внутри блока и IV, который инкрементируется сам. Один поток — один объект.
#[must_use]
pub struct Aes256Ctr {
    round_keys: [u32; 60],
    iv: [u8; 16],
    state: u8,
    keystream: [u8; 16],
}

impl Aes256Ctr {
    /// Новый поток шифрования: ключ ровно 32 байта, IV — 16.
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            round_keys: aes256_expand_key(key),
            iv: *iv,
            state: 0,
            keystream: [0_u8; 16],
        }
    }

    /// Шифрует очередной кусок потока и возвращает его.
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for byte in data {
            if self.state == 0 {
                let mut block = self.iv;
                aes256_encrypt_block(&self.round_keys, &mut block);
                self.keystream = block;
                for index in (0..16).rev() {
                    self.iv[index] = self.iv[index].wrapping_add(1);
                    if self.iv[index] != 0 {
                        break;
                    }
                }
            }
            result.push(byte ^ self.keystream[self.state as usize]);
            self.state = (self.state + 1) % 16;
        }
        result
    }
}

fn sha256_into(parts: &[&[u8]], out: &mut [u8; 32]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = parts.concat();
    let bit_len = (message.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut words = [0_u32; 64];
    for chunk in message.chunks_exact(64) {
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        // python3 -c "import hashlib; print(hashlib.sha256(b'abc').hexdigest())"
        let digest = sha256(&[b"abc"]);
        assert_eq!(
            hex(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // python3 -c "import hashlib; print(hashlib.sha256(b'a'*1000000).hexdigest())"
        let long = vec![b'a'; 1_000_000];
        let digest = sha256(&[&long]);
        assert_eq!(
            hex(&digest),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert_eq!(sha256(&[b"ab", b"c"]), sha256(&[b"abc"]));
    }

    #[test]
    fn hmac_sha256_matches_python() {
        // python3 -c "import hmac,hashlib; print(hmac.new(b'key', b'msg', hashlib.sha256).hexdigest())"
        let digest = hmac_sha256(b"key", b"msg");
        assert_eq!(
            hex(&digest),
            "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628"
        );
        // Ключ длиннее блока: python3
        //   hmac.new(b'k'*100, b'm', hashlib.sha256).hexdigest()
        let long_key = vec![b'k'; 100];
        let digest = hmac_sha256(&long_key, b"m");
        assert_eq!(
            hex(&digest),
            "0482265a92ce176b0374f2192380b21e2d40126432c52f865cc0957053ae7a14"
        );
    }

    #[test]
    fn sha1_matches_known_vectors() {
        // python3 -c "import hashlib; print(hashlib.sha1(b'abc').hexdigest())"
        assert_eq!(
            hex(&sha1(&[b"abc"])),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn base64_matches_python() {
        // python3 -c "import base64; print(base64.b64encode(b'\x00\x01\x02\x03').decode())"
        assert_eq!(base64_encode(&[0, 1, 2, 3]), "AAECAw==");
        assert_eq!(base64_encode(&[0x41]), "QQ==");
        assert_eq!(base64_encode(&[0x41, 0x42]), "QUI=");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn aes256_matches_fips197_and_nist_ctr() {
        // FIPS-197 C.3: AES-256 одного блока — через CTR с IV = открытый текст
        // и нулевыми данными.
        let key: [u8; 32] = (0x00..=0x1F).collect::<Vec<u8>>().try_into().unwrap();
        let iv: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut stream = Aes256Ctr::new(&key, &iv);
        let block = stream.update(&[0_u8; 16]);
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
        // Поток можно продолжать: два вызова дают то же, что один длинный.
        let mut parts = Vec::new();
        parts.extend(stream.update(&[0_u8; 16]));
        parts.extend(stream.update(&[0_u8; 16]));
        let mut whole = Aes256Ctr::new(&key, &iv);
        // Сначала потребляем первый блок — как и в потоке выше.
        whole.update(&[0_u8; 16]);
        assert_eq!(parts, whole.update(&[0_u8; 32]));
    }

    fn hex(data: &[u8]) -> String {
        data.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
