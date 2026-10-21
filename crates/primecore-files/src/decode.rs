//! Порт `utils/atomic_text.py::decode_preset_bytes` — чтение текста
//! пресета: UTF-8 (с BOM или без), иначе cp1251.
//!
//! Старые пресеты, сохранённые в Блокноте Windows, бывают в cp1251.
//! Чтение с `errors="replace"` превращало русские буквы в U+FFFD, а
//! следующее сохранение навсегда записывало эту порчу в файл.
//!
//! Один битый байт в UTF-8 файле (обрезанный символ, вставка из другого
//! файла) не повод читать весь файл как cp1251: иначе вся кириллица
//! превратилась бы в «РњРѕР№», и следующее сохранение закрепило бы это.
//! Кириллица в cp1251 почти никогда не складывается в корректные
//! многобайтные последовательности UTF-8, поэтому признак надёжный:
//! сравниваем, сколько не-ASCII символов UTF-8 прочитал правильно и
//! сколько пришлось заменить.

/// cp1251 для байтов 0x80–0xFF; байт 0x98 не определён — U+FFFD
/// (таблица снята с python-кодека cp1251).
const CP1251_HIGH: [u16; 128] = [
    1026, 1027, 8218, 1107, 8222, 8230, 8224, 8225, 8364, 8240, 1033, 8249, 1034, 1036, 1035, 1039,
    1106, 8216, 8217, 8220, 8221, 8226, 8211, 8212, 0xFFFD, 8482, 1113, 8250, 1114, 1116, 1115,
    1119, 160, 1038, 1118, 1032, 164, 1168, 166, 167, 1025, 169, 1028, 171, 172, 173, 174, 1031,
    176, 177, 1030, 1110, 1169, 181, 182, 183, 1105, 8470, 1108, 187, 1112, 1029, 1109, 1111, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
    1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072,
    1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
    1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103,
];

/// python `decode('utf-8-sig')` — UTF-8 со снятым BOM, строго.
fn utf8_bom_strict(raw: &[u8]) -> Option<String> {
    let body = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(raw);
    String::from_utf8(body.to_vec()).ok()
}

/// python `decode('utf-8-sig', errors="replace")` — каждый битый байт
/// даёт один U+FFFD (python заменяет побайтно, Rust `from_utf8_lossy`
/// сливает подряд идущие битые байты в один символ — потому вручную).
#[must_use]
fn utf8_bom_lossy_python(raw: &[u8]) -> String {
    let body = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(raw);
    let mut out = String::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        match decode_utf8_one(&body[index..]) {
            Some((character, size)) => {
                out.push(character);
                index += size;
            }
            None => {
                out.push('\u{FFFD}');
                index += 1;
            }
        }
    }
    out
}

/// Декодирует один валидный UTF-8 символ с начала среза; `None` — байт
/// битый (python выдаст для него один U+FFFD).
fn decode_utf8_one(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    let (character, size) = match first {
        0x00..=0x7F => (char::from(first), 1),
        0xC2..=0xDF => decode_two(bytes)?,
        0xE0..=0xEF => decode_three(bytes)?,
        0xF0..=0xF4 => decode_four(bytes)?,
        // 0x80..=0xBF (продолжение без начала) и 0xC0/0xC1/0xF5..=0xFF —
        // неверные начала последовательностей.
        _ => return None,
    };
    Some((character, size))
}

fn decode_two(bytes: &[u8]) -> Option<(char, usize)> {
    if bytes.len() < 2 || bytes[1] & 0xC0 != 0x80 {
        return None;
    }
    let mut buffer = [0_u8; 2];
    buffer.copy_from_slice(&bytes[..2]);
    let text = std::str::from_utf8(&buffer).ok()?;
    let character = text.chars().next()?;
    Some((character, 2))
}

fn decode_three(bytes: &[u8]) -> Option<(char, usize)> {
    if bytes.len() < 3 {
        return None;
    }
    if bytes[1..3].iter().any(|byte| byte & 0xC0 != 0x80) {
        return None;
    }
    std::str::from_utf8(&bytes[..3])
        .ok()
        .and_then(|text| text.chars().next())
        .map(|c| (c, 3))
}

fn decode_four(bytes: &[u8]) -> Option<(char, usize)> {
    if bytes.len() < 4 {
        return None;
    }
    if bytes[1..4].iter().any(|byte| byte & 0xC0 != 0x80) {
        return None;
    }
    std::str::from_utf8(&bytes[..4])
        .ok()
        .and_then(|text| text.chars().next())
        .map(|c| (c, 4))
}

/// python `decode('cp1251', errors="replace")` — однобайтовая таблица.
#[must_use]
fn cp1251_lossy(raw: &[u8]) -> String {
    raw.iter()
        .map(|&byte| {
            if byte < 0x80 {
                char::from(byte)
            } else {
                char::from_u32(u32::from(CP1251_HIGH[(byte - 0x80) as usize])).unwrap_or('\u{FFFD}')
            }
        })
        .collect()
}

/// python `decode_preset_bytes` — UTF-8, а cp1251 — только если файл по
/// сути не UTF-8.
#[must_use]
pub fn decode_preset_bytes(raw: &[u8]) -> String {
    if let Some(text) = utf8_bom_strict(raw) {
        return text;
    }
    let as_utf8 = utf8_bom_lossy_python(raw);
    let replaced = as_utf8.chars().filter(|&c| c == '\u{FFFD}').count();
    let decoded_non_ascii = as_utf8.chars().filter(|c| *c as u32 > 127).count() - replaced;
    if decoded_non_ascii >= replaced {
        return as_utf8;
    }
    cp1251_lossy(raw)
}

/// python `read_preset_file_text` — читает текстовый файл пресета.
pub fn read_preset_file_text(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read(path).map_err(|error| error.to_string())?;
    Ok(decode_preset_bytes(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Эталоны сняты запуском python decode_preset_bytes (см. доку).
    #[test]
    fn decode_matches_python() {
        // cp1251-пресет.
        assert_eq!(
            decode_preset_bytes(b"\xcf\xf0\xe5\xf1\xe5\xf2\n"),
            "Пресет\n"
        );
        assert_eq!(
            decode_preset_bytes(b"\xd0\xf3\xf1\xf1\xea\xe8\xe9 \xf2\xe5\xea\xf1\xf2"),
            "Русский текст"
        );
        // UTF-8 с BOM.
        assert_eq!(
            decode_preset_bytes(b"\xef\xbb\xbf\xd0\xb0\xd0\xb1\n"),
            "аб\n"
        );
        // Один битый байт в UTF-8 — файл остаётся UTF-8, порча — один FFFD.
        assert_eq!(
            decode_preset_bytes(b"\xd0\xb0\xff\xd0\xb1\n"),
            "а\u{FFFD}б\n"
        );
        assert_eq!(
            decode_preset_bytes(b"\xd0\xa0\xd1\x83\xff\xd1\x81\n"),
            "Ру\u{FFFD}с\n"
        );
        // ASCII.
        assert_eq!(decode_preset_bytes(b"plain\n"), "plain\n");
        // Кириллица cp1251 доминирует — весь файл cp1251.
        assert_eq!(
            decode_preset_bytes(b"\xcf\xf0\xee\xe2\xe5\xf0\xea\xe0 \xe7\xe0\xef\xf3\xf1\xea\xe0"),
            "Проверка запуска"
        );
    }

    #[test]
    fn lossy_replaces_byte_by_byte_like_python() {
        // python: b'\xff\xff'.decode('utf-8', 'replace') → два FFFD;
        // b'\xe0\x80' → два FFFD.
        assert_eq!(utf8_bom_lossy_python(b"\xff\xff"), "\u{FFFD}\u{FFFD}");
        assert_eq!(utf8_bom_lossy_python(b"\xe0\x80"), "\u{FFFD}\u{FFFD}");
        assert_eq!(utf8_bom_lossy_python(b"\xd0\xb0\xff\xd0\xb1"), "а\u{FFFD}б");
        // Оборванная последовательность в конце.
        assert_eq!(utf8_bom_lossy_python(b"\xd0"), "\u{FFFD}");
        assert_eq!(utf8_bom_lossy_python(b"\xc3"), "\u{FFFD}");
        // BOM снят и в lossy-ветке.
        assert_eq!(utf8_bom_lossy_python(b"\xef\xbb\xbf\xff"), "\u{FFFD}");
    }

    #[test]
    fn utf8_bom_strict_rejects_broken() {
        assert_eq!(
            utf8_bom_strict(b"\xef\xbb\xbf\xd0\xb0"),
            Some("а".to_string())
        );
        assert_eq!(utf8_bom_strict(b"\xd0\xb0"), Some("а".to_string()));
        assert_eq!(utf8_bom_strict(b"\xff"), None);
    }

    #[test]
    fn cp1251_table_matches_python_codec() {
        // Эталонные байты python-кодека cp1251.
        assert_eq!(cp1251_lossy(&[0xCF]), "П");
        assert_eq!(cp1251_lossy(&[0x70]), "p");
        assert_eq!(cp1251_lossy(&[0x98]), "\u{FFFD}"); // не определён
        assert_eq!(cp1251_lossy(&[0xA0]), "\u{00A0}"); // nbsp
        assert_eq!(cp1251_lossy(&[0xB9]), "\u{2116}"); // №
    }
}
