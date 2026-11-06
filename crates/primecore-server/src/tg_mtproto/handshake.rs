use primecore_telegram::proxy::aes_ctr::AesCtrStream;
use sha2::{Digest, Sha256};

pub const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

pub const TAG_ABRIDGED: [u8; 4] = [0xef; 4];
pub const TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
pub const TAG_SECURE: [u8; 4] = [0xdd; 4];

const RESERVED_STARTS: [[u8; 4]; 7] = [
    *b"HEAD",
    *b"POST",
    *b"GET ",
    [0xee; 4],
    [0xdd; 4],
    [0x16, 0x03, 0x01, 0x02],
    *b"OPTI",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub dc: i32,
    pub is_media: bool,
    pub proto: Proto,
    pub proto_tag: [u8; 4],
    prekey_iv: [u8; PREKEY_LEN + IV_LEN],
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn key_iv(prekey_iv: &[u8], secret: Option<&[u8; 16]>) -> ([u8; 32], [u8; 16]) {
    let key = match secret {
        Some(secret) => sha256(&[&prekey_iv[..PREKEY_LEN], secret]),
        None => prekey_iv[..PREKEY_LEN].try_into().expect("32 байта ключа"),
    };
    let iv = prekey_iv[PREKEY_LEN..PREKEY_LEN + IV_LEN]
        .try_into()
        .expect("16 байт IV");
    (key, iv)
}

#[must_use]
pub fn parse_client_hello(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<ClientHello> {
    let mut prekey_iv = [0_u8; PREKEY_LEN + IV_LEN];
    prekey_iv.copy_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let (key, iv) = key_iv(&prekey_iv, Some(secret));
    let decrypted = AesCtrStream::from_arrays(key, iv).update(handshake);

    let mut proto_tag = [0_u8; 4];
    proto_tag.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
    let proto = match proto_tag {
        TAG_ABRIDGED => Proto::Abridged,
        TAG_INTERMEDIATE => Proto::Intermediate,
        TAG_SECURE => Proto::PaddedIntermediate,
        _ => return None,
    };
    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);
    Some(ClientHello {
        dc: i32::from(dc_idx).abs(),
        is_media: dc_idx < 0,
        proto,
        proto_tag,
        prekey_iv,
    })
}

fn is_reserved(candidate: &[u8; HANDSHAKE_LEN]) -> bool {
    candidate[0] == 0xef
        || RESERVED_STARTS.iter().any(|start| candidate[..4] == *start)
        || candidate[4..8] == [0, 0, 0, 0]
}

#[must_use]
pub fn build_relay_init(proto_tag: [u8; 4], dc_idx: i16, fill: &mut dyn FnMut(&mut [u8])) -> [u8; HANDSHAKE_LEN] {
    let mut random = [0_u8; HANDSHAKE_LEN];
    loop {
        fill(&mut random);
        if !is_reserved(&random) {
            break;
        }
    }
    let (key, iv) = key_iv(&random[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN], None);
    let encrypted = AesCtrStream::from_arrays(key, iv).update(&random);

    let mut tail_plain = [0_u8; 8];
    tail_plain[..4].copy_from_slice(&proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    let mut padding = [0_u8; 2];
    fill(&mut padding);
    tail_plain[6..].copy_from_slice(&padding);

    let mut result = random;
    for index in 0..8 {
        let keystream = encrypted[PROTO_TAG_POS + index] ^ random[PROTO_TAG_POS + index];
        result[PROTO_TAG_POS + index] = tail_plain[index] ^ keystream;
    }
    result
}

pub struct CryptoCtx {
    pub clt_dec: AesCtrStream,
    pub clt_enc: AesCtrStream,
    pub tg_enc: AesCtrStream,
    pub tg_dec: AesCtrStream,
}

fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

#[must_use]
pub fn build_crypto(hello: &ClientHello, secret: &[u8; 16], relay_init: &[u8; HANDSHAKE_LEN]) -> CryptoCtx {
    let zero = [0_u8; HANDSHAKE_LEN];

    let (key, iv) = key_iv(&hello.prekey_iv, Some(secret));
    let mut clt_dec = AesCtrStream::from_arrays(key, iv);
    let _ = clt_dec.update(&zero);

    let (key, iv) = key_iv(&reversed(&hello.prekey_iv), Some(secret));
    let clt_enc = AesCtrStream::from_arrays(key, iv);

    let relay_prekey_iv = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let (key, iv) = key_iv(relay_prekey_iv, None);
    let mut tg_enc = AesCtrStream::from_arrays(key, iv);
    let _ = tg_enc.update(&zero);

    let (key, iv) = key_iv(&reversed(relay_prekey_iv), None);
    let tg_dec = AesCtrStream::from_arrays(key, iv);

    CryptoCtx {
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_fill(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut state = seed;
        move |buffer: &mut [u8]| {
            for byte in buffer {
                state = state.wrapping_mul(31).wrapping_add(17);
                *byte = state;
            }
        }
    }

    fn client_handshake(secret: &[u8; 16], tag: [u8; 4], dc_idx: i16) -> ([u8; 64], AesCtrStream) {
        let mut fill = pseudo_fill(7);
        let mut random = [0_u8; 64];
        loop {
            fill(&mut random);
            if !is_reserved(&random) {
                break;
            }
        }
        let (key, iv) = key_iv(&random[8..56], Some(secret));
        let mut encryptor = AesCtrStream::from_arrays(key, iv);
        let encrypted = encryptor.update(&random);
        let mut tail = [0_u8; 8];
        tail[..4].copy_from_slice(&tag);
        tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
        let mut result = random;
        for index in 0..8 {
            result[56 + index] = tail[index] ^ encrypted[56 + index] ^ random[56 + index];
        }
        (result, encryptor)
    }

    #[test]
    fn parses_dc_media_and_protocol() {
        let secret = [0x42_u8; 16];
        let (handshake, _) = client_handshake(&secret, TAG_INTERMEDIATE, -4);
        let hello = parse_client_hello(&handshake, &secret).expect("рукопожатие разобрано");
        assert_eq!(hello.dc, 4);
        assert!(hello.is_media);
        assert_eq!(hello.proto, Proto::Intermediate);
    }

    #[test]
    fn rejects_wrong_secret() {
        let (handshake, _) = client_handshake(&[1; 16], TAG_ABRIDGED, 2);
        assert!(parse_client_hello(&handshake, &[2; 16]).is_none());
    }

    #[test]
    fn relay_init_carries_tag_and_dc() {
        let init = build_relay_init(TAG_SECURE, -2, &mut pseudo_fill(3));
        let (key, iv) = key_iv(&init[8..56], None);
        let plain = AesCtrStream::from_arrays(key, iv).update(&init);
        assert_eq!(plain[56..60], TAG_SECURE);
        assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), -2);
        assert!(!is_reserved(&init));
    }

    #[test]
    fn client_payload_survives_reencryption() {
        let secret = [0x11_u8; 16];
        let (handshake, mut client_enc) = client_handshake(&secret, TAG_ABRIDGED, 2);
        let hello = parse_client_hello(&handshake, &secret).expect("рукопожатие");
        let relay_init = build_relay_init(hello.proto_tag, 2, &mut pseudo_fill(9));
        let mut ctx = build_crypto(&hello, &secret, &relay_init);

        let message = b"hello telegram datacenter";
        let on_wire = client_enc.update(message);
        let plain = ctx.clt_dec.update(&on_wire);
        assert_eq!(plain, message);

        let to_telegram = ctx.tg_enc.update(&plain);
        let (key, iv) = key_iv(&relay_init[8..56], None);
        let mut telegram_dec = AesCtrStream::from_arrays(key, iv);
        let _ = telegram_dec.update(&[0; 64]);
        assert_eq!(telegram_dec.update(&to_telegram), message);
    }
}
