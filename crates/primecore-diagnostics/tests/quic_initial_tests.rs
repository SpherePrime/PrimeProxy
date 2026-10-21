//! Золотой тест первого пакета QUIC против python (`utils/quic_initial.py`):
//! сборка пакета с подменённым `os.urandom`, ключи RFC 9001, шифрование
//! AES-128-GCM и распознавание ответа сервера.

use primecore_diagnostics::quic_initial::{
    aes128_gcm_seal, build_initial_with, initial_keys, is_reply_to, InitialPacket,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    build: Vec<BuildCase>,
    keys: Vec<KeysCase>,
    seal: Vec<SealCase>,
    reply: Vec<ReplyCase>,
}

#[derive(Deserialize)]
struct BuildCase {
    name: Option<String>,
    dcid: String,
    scid: String,
    share: String,
    random: String,
    datagram: String,
    source_id: String,
    destination_id: String,
}

#[derive(Deserialize)]
struct KeysCase {
    dcid: String,
    key: String,
    iv: String,
    hp: String,
}

#[derive(Deserialize)]
struct SealCase {
    key: String,
    nonce: String,
    plaintext: String,
    aad: String,
    sealed: String,
}

#[derive(Deserialize)]
struct ReplyCase {
    datagram: String,
    source_id: String,
    expected: bool,
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("hex в golden"))
        .collect()
}

fn fixed16(value: &[u8]) -> [u8; 16] {
    value.try_into().expect("16 байт в golden")
}

fn fixed32(value: &[u8]) -> [u8; 32] {
    value.try_into().expect("32 байта в golden")
}

fn fixed12(value: &[u8]) -> [u8; 12] {
    value.try_into().expect("12 байт в golden")
}

#[test]
fn build_matches_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("quic_initial_golden.json")).expect("golden читается");
    for case in &golden.build {
        let packet = build_initial_with(
            case.name.as_deref(),
            &unhex(&case.dcid),
            &unhex(&case.scid),
            &fixed32(&unhex(&case.share)),
            &fixed32(&unhex(&case.random)),
        );
        assert_eq!(
            packet.datagram,
            unhex(&case.datagram),
            "пакет: {:?}",
            case.name
        );
        assert_eq!(
            packet.source_id,
            unhex(&case.source_id),
            "наш номер: {:?}",
            case.name
        );
        assert_eq!(
            packet.destination_id,
            unhex(&case.destination_id),
            "чужой номер: {:?}",
            case.name
        );
        // Сервер отвечает только на пакет не короче 1200 байт.
        assert!(packet.datagram.len() >= 1200, "длина: {:?}", case.name);
    }
}

#[test]
fn keys_match_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("quic_initial_golden.json")).expect("golden читается");
    for case in &golden.keys {
        let (key, iv, hp) = initial_keys(&unhex(&case.dcid));
        assert_eq!(key, fixed16(&unhex(&case.key)), "ключ: {}", case.dcid);
        assert_eq!(iv, fixed12(&unhex(&case.iv)), "вектор: {}", case.dcid);
        assert_eq!(
            hp,
            fixed16(&unhex(&case.hp)),
            "ключ заголовка: {}",
            case.dcid
        );
    }
}

#[test]
fn seal_matches_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("quic_initial_golden.json")).expect("golden читается");
    for case in &golden.seal {
        let sealed = aes128_gcm_seal(
            &fixed16(&unhex(&case.key)),
            &fixed12(&unhex(&case.nonce)),
            &unhex(&case.plaintext),
            &unhex(&case.aad),
        );
        assert_eq!(
            sealed,
            unhex(&case.sealed),
            "шифротекст: {}",
            case.plaintext.len()
        );
    }
}

#[test]
fn reply_matches_python() {
    let golden: Golden =
        serde_json::from_str(include_str!("quic_initial_golden.json")).expect("golden читается");
    for case in &golden.reply {
        let packet = InitialPacket {
            datagram: Vec::new(),
            destination_id: Vec::new(),
            source_id: unhex(&case.source_id),
        };
        assert_eq!(
            is_reply_to(&unhex(&case.datagram), &packet),
            case.expected,
            "ответ: {}",
            case.datagram
        );
    }
}
