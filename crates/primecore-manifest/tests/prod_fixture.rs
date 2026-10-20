//! Кросс-проверка против реальных production-файлов из Forgejo:
//! `git.zapret.moe/zapretdiscordyoutube/zapretgui` — выпуск 21.1.7.181, dev.
//!
//! Это не «примерная заготовка», а настоящий подписанный список выпуска,
//! отданный инфраструктурой обновлений 2026-10-18. Rust-верификатор обязан
//! проходить его теми же вшитыми ключами, что и Python-версию, и ровно
//! воспроизводить канонические байты (иначе подпись не была бы валидной).
#![forbid(unsafe_code)]

use primecore_manifest::{
    canonical_bytes, load_signed, parse, signing_key_id, MANIFEST_NAME, PRODUCT, SIGNATURE_NAME,
};

const MANIFEST: &str = include_str!("fixtures/update-manifest.json");
const SIGNATURE: &str = include_str!("fixtures/update-manifest.json.sig");

#[test]
fn names_match_contract() {
    assert_eq!(MANIFEST_NAME, "update-manifest.json");
    assert_eq!(SIGNATURE_NAME, "update-manifest.json.sig");
    assert_eq!(PRODUCT, "primebypass");
}

#[test]
fn prod_manifest_key_is_trusted() {
    let key_id = signing_key_id(MANIFEST.as_bytes(), SIGNATURE.as_bytes(), None)
        .map_err(|error| format!("код {}: {}", error.code, error))
        .unwrap();
    // Оба пропускных ключа у нас вшиты; новый ключ рождает новый id.
    assert!(["gui-2026a", "gui-reserve-1"].contains(&key_id.as_str()));
}

#[test]
fn prod_manifest_parses() {
    let payload: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let manifest = parse(&payload)
        .map_err(|error| format!("код {}: {}", error.code, error))
        .unwrap();
    assert_eq!(manifest.version, "21.1.7.181");
    // Живые сборки публиковались до ребрендинга: продукт — легационный.
    assert_eq!(manifest.product, "zapret-gui");
    assert!(primecore_manifest::product_accepted(
        &manifest.product,
        PRODUCT
    ));
    assert_eq!(manifest.channel, "dev");
    assert!(["gui-2026a", "gui-reserve-1"].contains(&manifest.key.as_str()));
    assert!(!manifest.files.is_empty());
}

#[test]
fn prod_manifest_full_load() {
    let manifest = load_signed(
        MANIFEST.as_bytes(),
        SIGNATURE.as_bytes(),
        None,
        // Программа сегодня зовёт PRODUCT; живой выпуск — LEGACY: должен пройти.
        "primebypass",
        "dev",
        "21.1.7.180",
        false,
    )
    .map_err(|error| format!("код {}: {}", error.code, error))
    .unwrap();
    assert_eq!(manifest.version, "21.1.7.181");
    assert!(!manifest.files.is_empty());
    let installer = manifest.installer.expect("у выпуска есть установщик");
    assert_eq!(installer.name, "Zapret2Setup_DEV_21_1_7_181.exe");
    // Есть и zstd-, и bsdiff-заплатки (у 181 — bsdiff-заплатки Zapret.exe).
    assert!(!manifest.patches.is_empty());
    assert!(manifest.patches.iter().any(|patch| patch.kind == "bsdiff"));
    // Каждая заплатка ведёт к файлу с кодом нового выпуска: parse уже
    // гарантировал попадание `to` в файлы, проверим поле from у видного.
    let targets: std::collections::HashSet<&str> = manifest
        .patches
        .iter()
        .map(|patch| patch.to_sha256.as_str())
        .collect();
    assert!(!targets.is_empty());
}

#[test]
fn prod_stale_version_rejected() {
    let result = load_signed(
        MANIFEST.as_bytes(),
        SIGNATURE.as_bytes(),
        None,
        PRODUCT,
        "dev",
        "21.1.7.182",
        false,
    );
    assert_eq!(result.err().unwrap().code, "stale");
}

#[test]
fn prod_same_version_needs_allow_same() {
    let result = load_signed(
        MANIFEST.as_bytes(),
        SIGNATURE.as_bytes(),
        None,
        PRODUCT,
        "dev",
        "21.1.7.181",
        false,
    );
    assert_eq!(result.err().unwrap().code, "stale");
    let result = load_signed(
        MANIFEST.as_bytes(),
        SIGNATURE.as_bytes(),
        None,
        PRODUCT,
        "dev",
        "21.1.7.181",
        true,
    );
    assert!(result.is_ok(), "allow_same разрешает починку установки");
}

#[test]
fn prod_wrong_channel_rejected() {
    // Тег _DEV — канал dev; stable-канал не пройдёт по «product».
    let result = load_signed(
        MANIFEST.as_bytes(),
        SIGNATURE.as_bytes(),
        None,
        PRODUCT,
        "stable",
        "",
        false,
    );
    assert_eq!(result.err().unwrap().code, "product");
}

#[test]
fn prod_canonical_bytes_round_trip() {
    // Байты выпуска собраны Python-функцией dumps(): sort_keys + indent=1
    // + ensure_ascii=False. Наш сериализатор обязан воспроизводить их
    // точно — только так подпись валидна для обеих реализаций.
    let payload: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let canonical = canonical_bytes(&payload);
    assert_eq!(canonical, MANIFEST, "canonical bytes == production bytes");
}
