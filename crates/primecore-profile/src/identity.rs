//! Порт profile/identity.py: стабильная идентичность профилей —
//! sidecar-реестр uid ↔ последний известный контент.
//!
//! Единственное место, где контент профиля участвует в идентичности.
//! Реестр хранится в settings (`profile_identity.<launch_method>`) и
//! сопоставляет uid последнему известному (имя, логическая match-сигнатура).
//! Resolver чистый: без I/O, детерминированный — одинаковый вход даёт
//! одинаковый выход.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;

pub const UID_PREFIX: &str = "uid:";

/// Результат сопоставления парса с реестром.
///
/// uids — по одному на профиль, в порядке входа; new_uids — впервые
/// появившиеся; registry — следующий снапшот реестра (несопоставленные старые
/// uid сохраняются: удалённый и возвращённый профиль снова получает свою
/// мету). python registry — dict с порядком вставки: список пар.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityResolution {
    pub uids: Vec<String>,
    /// python frozenset — сохраняется отсортированным.
    pub new_uids: BTreeSet<String>,
    /// {uid: (name, sig)} в порядке python-словаря.
    pub registry: Vec<(String, (String, String))>,
}

/// python `_clean`: str(value or "").strip() — числа и true тоже приводятся.
fn clean(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                number.to_string().trim().to_string()
            } else {
                number
                    .as_f64()
                    .map_or_else(|| number.to_string(), |float| format!("{float}"))
                    .trim()
                    .to_string()
            }
        }
        Value::Bool(_bool) => "True".to_string(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string(),
        _ => String::new(),
    }
}

fn clean_str(value: &str) -> String {
    value.trim().to_string()
}

/// python generate_profile_uid (uuid4.hex v4).
pub fn generate_profile_uid() -> String {
    let mut bytes = [0u8; 16];
    // uuid4: версия 4 в старшем полубайте 7-го байта, RFC-вариант в 9-м.
    for byte in &mut bytes {
        *byte = fastrand::u64(..=255u64) as u8;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{UID_PREFIX}{hex}")
}

pub fn is_profile_uid(value: &Value) -> bool {
    value.as_str().unwrap_or("").starts_with(UID_PREFIX)
}

pub fn is_profile_uid_text(value: &str) -> bool {
    value.starts_with(UID_PREFIX)
}

type Known = Vec<(String, (String, String))>;

fn normalize_registry(raw: &Value) -> Known {
    let mut result: Known = Vec::new();
    let Some(mapping) = raw.as_object() else {
        return result;
    };
    for (raw_uid, raw_meta) in mapping {
        let uid = clean(&Value::String(raw_uid.clone()));
        if uid.is_empty() {
            continue;
        }
        match raw_meta {
            Value::Object(meta) => {
                let name = clean(meta.get("name").unwrap_or(&Value::Null));
                let sig = clean(meta.get("sig").unwrap_or(&Value::Null));
                result.push((uid, (name, sig)));
            }
            _ => continue,
        }
    }
    result
}

/// Нормализация снапшота реестра для settings: только uid-ключи с
/// строковыми name/sig.
pub fn normalize_identity_registry(raw: &Value) -> Known {
    normalize_registry(raw)
}

/// Сопоставляет профили парса (пары (имя, сигнатура) в порядке пресета)
/// с реестром {uid: {"name": ..., "sig": ...}}.
pub fn resolve_profile_identities(
    profiles: &[(String, String)],
    registry: &Value,
    mut generate_uid: impl FnMut() -> String,
) -> IdentityResolution {
    let entries: Vec<(String, String)> = profiles
        .iter()
        .map(|(name, sig)| (clean_str(name), clean_str(sig)))
        .collect();
    let known = normalize_registry(registry);
    let known_lookup: HashMap<String, (String, String)> = known.iter().cloned().collect();

    let mut claimed: HashSet<String> = HashSet::new();
    let mut resolved: HashMap<usize, String> = HashMap::new();

    fn match_pass(
        pass: usize,
        known: &Known,
        entries: &[(String, String)],
        claimed: &mut HashSet<String>,
        resolved: &mut HashMap<usize, String>,
    ) {
        // Ключи проходов: 1 — (имя, сигнатура), 2 — только сигнатура,
        // 3 — только имя. Пустые части ключом не являются.
        let mut candidates: HashMap<String, Vec<String>> = HashMap::new();
        for (uid, (name, sig)) in known {
            if claimed.contains(uid) {
                continue;
            }
            let key = match pass {
                1 => format!("{name}\u{1}{sig}"),
                2 => format!("\u{1}{sig}"),
                _ => format!("{name}\u{1}"),
            };
            let key = match pass {
                2 if sig.is_empty() => continue,
                3 if name.is_empty() => continue,
                _ => key,
            };
            candidates.entry(key).or_default().push(uid.clone());
        }
        for (index, (name, sig)) in entries.iter().enumerate() {
            if resolved.contains_key(&index) {
                continue;
            }
            let key = match pass {
                1 => Some(format!("{name}\u{1}{sig}")),
                2 => {
                    if sig.is_empty() {
                        None
                    } else {
                        Some(format!("\u{1}{sig}"))
                    }
                }
                _ => {
                    if name.is_empty() {
                        None
                    } else {
                        Some(format!("{name}\u{1}"))
                    }
                }
            };
            let Some(key) = key else { continue };
            let held = match candidates.get_mut(&key) {
                Some(bucket) if !bucket.is_empty() => bucket,
                _ => continue,
            };
            let uid = held.remove(0);
            claimed.insert(uid.clone());
            resolved.insert(index, uid);
        }
    }

    // 1. Точное совпадение имени и сигнатуры.
    match_pass(1, &known, &entries, &mut claimed, &mut resolved);
    // 2. Только сигнатура (переименование); пустая сигнатура не является привязкой.
    match_pass(2, &known, &entries, &mut claimed, &mut resolved);
    // 3. Только имя (правка match-строк); пустое имя не является привязкой.
    match_pass(3, &known, &entries, &mut claimed, &mut resolved);

    let mut uids: Vec<String> = Vec::new();
    let mut new_uids: BTreeSet<String> = BTreeSet::new();
    for index in 0..entries.len() {
        let uid = match resolved.get(&index) {
            Some(uid) => uid.clone(),
            None => {
                let mut uid = clean_str(&generate_uid());
                if uid.is_empty() {
                    uid = generate_profile_uid();
                }
                while known_lookup.contains_key(&uid) || new_uids.contains(&uid) {
                    uid = generate_profile_uid();
                }
                new_uids.insert(uid.clone());
                uid
            }
        };
        uids.push(uid);
    }

    let mut registry = known
        .into_iter()
        .filter(|(uid, _)| !claimed.contains(uid))
        .collect::<Vec<_>>();
    for (index, uid) in uids.iter().enumerate() {
        let entry = &entries[index];
        match registry.iter_mut().find(|(known_uid, _)| known_uid == uid) {
            Some((_, meta)) => *meta = entry.clone(),
            None => registry.push((uid.clone(), entry.clone())),
        }
    }
    IdentityResolution {
        uids,
        new_uids,
        registry,
    }
}
