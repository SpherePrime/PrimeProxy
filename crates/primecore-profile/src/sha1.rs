//! SHA-1 без зависимостей: нужен для ключей открытых групп (python hashlib).

const ROUNDS: [u32; 80] = {
    let mut table = [0u32; 80];
    let mut index = 0;
    while index < 20 {
        table[index] = 0x5A827999;
        index += 1;
    }
    while index < 40 {
        table[index] = 0x6ED9EBA1;
        index += 1;
    }
    while index < 60 {
        table[index] = 0x8F1BBCDC;
        index += 1;
    }
    while index < 80 {
        table[index] = 0xCA62C1D6;
        index += 1;
    }
    table
};

/// Хеш-сумма SHA-1 в шестнадцатеричном виде (как python hashlib.hexdigest()).
pub fn sha1_hex(data: &[u8]) -> String {
    let state = sha1_state(data);
    state.iter().map(|word| format!("{word:08x}")).collect()
}

/// python hashlib.sha1(...).digest() — 20 байт.
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let state = sha1_state(data);
    let mut out = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha1_state(data: &[u8]) -> [u32; 5] {
    let mut words: Vec<u8> = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    words.push(0x80);
    while words.len() % 64 != 56 {
        words.push(0);
    }
    words.extend_from_slice(&bit_length.to_be_bytes());

    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk_start in (0..words.len()).step_by(64) {
        let chunk = &words[chunk_start..chunk_start + 64];
        let mut schedule = [0u32; 80];
        for index in 0..16 {
            schedule[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            schedule[index] =
                (schedule[index - 3] ^ schedule[index - 8] ^ schedule[index - 14] ^ schedule[index - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for index in 0..80 {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), ROUNDS[index]),
                20..=39 => (b ^ c ^ d, ROUNDS[index]),
                40..=59 => ((b & c) | (b & d) | (c & d), ROUNDS[index]),
                _ => (b ^ c ^ d, ROUNDS[index]),
            };
            let next = (a.rotate_left(5).wrapping_add(f))
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(schedule[index]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    state
}

/// Асоциация ключей открытых групп — отпечаток названия.
pub fn digest_prefix(prefix: &str, title: &str) -> String {
    let lowered = title.trim().to_lowercase();
    format!("{prefix}_{}", &sha1_hex(lowered.as_bytes())[..10])
}
