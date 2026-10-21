//! Порт `src/utils/cert_reader.py` — кому и кем выдан сертификат, из его
//! двоичной записи (DER), без сторонних библиотек.
//!
//! Python отдаёт разобранный сертификат только после успешной проверки. Здесь
//! же он нужен как раз тогда, когда проверка не прошла: чтобы назвать, кто
//! ответил вместо сайта. Поэтому запись разбирается вручную — ровно настолько,
//! чтобы достать имена владельца и издателя и список сайтов, для которых он
//! выдан.
//!
//! Читается только начало сертификата (до расширений), подпись не проверяется:
//! это справка «что написано в сертификате», а не доверие к нему.

use crate::cert_owner::CertNames;

const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
const OID_ORGANIZATION: [u8; 3] = [0x55, 0x04, 0x0A];
const OID_ALT_NAMES: [u8; 3] = [0x55, 0x1D, 0x11];
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTETS: u8 = 0x04;
const VERSION_TAG: u8 = 0xA0;
const EXTENSIONS_TAG: u8 = 0xA3;
const DNS_NAME_TAG: u8 = 0x82;
/// BMPString — двухбайтные знаки (UTF-16 BE).
const BMP_STRING_TAG: u8 = 0x1E;

/// python `_item(data, offset)` — (метка, содержимое, где начинается следующий элемент).
fn item(data: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(offset)?;
    let first = *data.get(offset + 1)?;
    let mut start = offset + 2;
    let mut length = usize::from(first);
    if first & 0x80 != 0 {
        let count = usize::from(first & 0x7F);
        if !(1..=4).contains(&count) {
            // Длина элемента записана не так, как в сертификатах.
            return None;
        }
        let head = data.get(start..start + count)?;
        length = head
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        start += count;
    }
    let end = start.checked_add(length)?;
    if end > data.len() {
        // Элемент выходит за конец записи.
        return None;
    }
    Some((tag, &data[start..end], end))
}

/// python `_items(data)` — все элементы подряд.
fn items(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut found = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (tag, body, next) = item(data, offset)?;
        found.push((tag, body));
        offset = next;
    }
    Some(found)
}

/// python `_text(tag, body)` — BMPString читается как UTF-16 BE, остальное как UTF-8.
fn text(tag: u8, body: &[u8]) -> String {
    let decoded = if tag == BMP_STRING_TAG {
        bmp_string(body)
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    decoded.trim().to_string()
}

/// UTF-16 BE с заменой испорченных знаков (python `decode("utf-16-be", errors="replace")`).
fn bmp_string(body: &[u8]) -> String {
    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    let mut out = String::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xD800..0xDC00).contains(&unit) {
            let low = units.get(index + 1).copied();
            if low.is_some_and(|low| (0xDC00..0xE000).contains(&low)) {
                let low = low.expect("половинная пара есть");
                let value =
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                out.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                index += 2;
            } else {
                out.push('\u{FFFD}');
                index += 1;
            }
        } else if (0xDC00..0xE000).contains(&unit) {
            // Одинокая младшая половинная пара.
            out.push('\u{FFFD}');
            index += 1;
        } else {
            out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}'));
            index += 1;
        }
    }
    // Лишний байт без пары — заменён.
    if !body.len().is_multiple_of(2) {
        out.push('\u{FFFD}');
    }
    out
}

/// python `_name(body)` — (CN, O) из записи имени.
fn name(body: &[u8]) -> Option<(String, String)> {
    let mut common = String::new();
    let mut organization = String::new();
    for (set_tag, part) in items(body)? {
        if set_tag != SET {
            continue;
        }
        for (_, attribute) in items(part)? {
            let fields = items(attribute)?;
            let Some((oid_tag, oid)) = fields.first().copied() else {
                continue;
            };
            if fields.len() < 2 || oid_tag != OID {
                continue;
            }
            let (value_tag, value) = fields[1];
            if oid == OID_COMMON_NAME {
                common = text(value_tag, value);
            } else if oid == OID_ORGANIZATION {
                organization = text(value_tag, value);
            }
        }
    }
    Some((common, organization))
}

/// python `_alt_names(extensions)` — сайты из расширения «альтернативные имена».
fn alt_names(extensions: &[u8]) -> Option<Vec<String>> {
    for (_, wrapped) in items(extensions)? {
        for (_, extension) in items(wrapped)? {
            let fields = items(extension)?;
            let Some(first) = fields.first() else {
                continue;
            };
            if first.0 != OID || first.1 != OID_ALT_NAMES {
                continue;
            }
            let value = fields
                .get(1..)
                .and_then(|rest| rest.iter().find(|(tag, _)| *tag == OCTETS))
                .map(|(_, body)| *body)
                .unwrap_or(&[]);
            let mut names: Vec<String> = Vec::new();
            for (_, listing) in items(value)? {
                for (tag, body) in items(listing)? {
                    if tag == DNS_NAME_TAG {
                        names.push(String::from_utf8_lossy(body).to_lowercase());
                    }
                }
            }
            // Повторы убираются, порядок сохраняется (python dict.fromkeys).
            let mut seen = Vec::new();
            names.retain(|name| match seen.contains(name) {
                true => false,
                false => {
                    seen.push(name.clone());
                    true
                }
            });
            return Some(names);
        }
    }
    Some(Vec::new())
}

/// python `read_names(der)` — имена из сертификата. None — записи нет или она не разбирается.
pub fn read_names(der: Option<&[u8]>) -> Option<CertNames> {
    let der = der?;
    if der.is_empty() {
        return None;
    }
    let parsed = (|| {
        let (_, certificate, _) = item(der, 0)?;
        let (_, body, _) = item(certificate, 0)?;
        let mut fields = items(body)?;
        if fields.first().is_some_and(|(tag, _)| *tag == VERSION_TAG) {
            fields.remove(0);
        }
        // Номер, алгоритм подписи, издатель, срок, владелец, ключ, [расширения].
        let issuer_field = fields.get(2)?.1;
        let subject_field = fields.get(4)?.1;
        let (issuer, issuer_org) = name(issuer_field)?;
        let (subject, subject_org) = name(subject_field)?;
        let extensions = fields
            .iter()
            .skip(6)
            .find(|(tag, _)| *tag == EXTENSIONS_TAG)
            .map(|(_, body)| *body);
        let mut names = match extensions {
            Some(extensions) if !extensions.is_empty() => alt_names(extensions)?,
            _ => Vec::new(),
        };
        if names.is_empty() && subject.contains('.') {
            names.push(subject.to_lowercase());
        }
        Some(CertNames {
            subject,
            subject_org,
            issuer,
            issuer_org,
            names,
            self_signed: issuer_field == subject_field,
        })
    })();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Подписанный ключом сертификат с заданными SAN и CN.
    fn certificate(sans: &[&str], common_name: &str) -> rcgen::Certificate {
        let key = rcgen::KeyPair::generate().expect("ключ");
        let sans: Vec<String> = sans.iter().map(|name| (*name).to_string()).collect();
        let mut params = rcgen::CertificateParams::new(sans).expect("параметры сертификата");
        if !common_name.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, common_name);
        }
        params.self_signed(&key).expect("сертификат")
    }

    #[test]
    fn names_from_generated_certificate() {
        // Настоящий DER от rcgen: CN, O и альтернативные имена читаются.
        let key = rcgen::KeyPair::generate().expect("ключ");
        let mut params = rcgen::CertificateParams::new(vec!["site.test".to_string()])
            .expect("параметры сертификата");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Тестовый Сайт");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Тест Орг");
        let certified = params.self_signed(&key).expect("сертификат");
        let der = certified.der().as_ref();
        let names = read_names(Some(der)).expect("имена прочитаны");
        assert_eq!(names.subject, "Тестовый Сайт");
        assert_eq!(names.subject_org, "Тест Орг");
        assert!(names.self_signed, "самоподписанный: издатель == владелец");
        assert_eq!(names.names, vec!["site.test".to_string()]);
    }

    #[test]
    fn issuer_and_san_list_read() {
        // Сертификат, подписанный другим: издатель не совпадает с владельцем,
        // имена — из SAN.
        let issuer_key = rcgen::KeyPair::generate().expect("ключ издателя");
        let issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("параметры издателя");
        let issuer = issuer_params.self_signed(&issuer_key).expect("издатель");
        let key = rcgen::KeyPair::generate().expect("ключ");
        let mut params =
            rcgen::CertificateParams::new(vec!["a.test".to_string(), "b.test".to_string()])
                .expect("параметры");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "a.test");
        let certified = params
            .signed_by(&key, &issuer, &issuer_key)
            .expect("сертификат");
        let names = read_names(Some(certified.der().as_ref())).expect("имена прочитаны");
        assert_eq!(names.subject, "a.test");
        assert!(!names.self_signed);
        assert_eq!(
            names.names,
            vec!["a.test".to_string(), "b.test".to_string()]
        );
    }

    /// Повтор имени в SAN оставлен один раз (python dict.fromkeys).
    #[test]
    fn duplicate_san_names_deduplicated() {
        let certified = certificate(&["same.test", "same.test"], "same.test");
        let names = read_names(Some(certified.der().as_ref())).expect("имена прочитаны");
        assert_eq!(names.names, vec!["same.test".to_string()]);
    }

    #[test]
    fn broken_and_empty_der_return_none() {
        assert!(read_names(None).is_none());
        assert!(read_names(Some(&[])).is_none());
        assert!(read_names(Some(b"junk data")).is_none());
        // Обрезанный DER: заявленная длина больше записи.
        let certified = certificate(&["x.test"], "x.test");
        let der = certified.der().as_ref();
        assert!(read_names(Some(&der[..der.len() / 2])).is_none());
    }

    #[test]
    fn bmp_string_decodes_utf16_be() {
        assert_eq!(bmp_string(&[0x00, 0x41, 0x00, 0x42]), "AB");
        // Суррогатная пара: U+1F600.
        assert_eq!(bmp_string(&[0xD8, 0x3D, 0xDE, 0x00]), "\u{1F600}");
        // Одинокая половинная пара и лишний байт — заменены.
        assert_eq!(bmp_string(&[0xD8, 0x3D, 0x41]), "\u{FFFD}\u{FFFD}");
    }
}
