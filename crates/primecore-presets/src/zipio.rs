//! Минимальный читатель/писатель ZIP для переносимых архивов пресетов
//! ([`crate::portable_archive`]) — Rust-заменитель python `zipfile`.
//!
//! Достаточно для формата `primebypass-portable-preset`: имена файлов
//! UTF-8, сжатие — method 8 (deflate, как python `ZIP_DEFLATED`) и method 0
//! (stored). ZIP64 не поддерживается — архивы пресета ограничены 128 МиБ,
//! классического формата хватает; python `zipfile` такие архивы читает.

use std::io::{Read, Write};
use std::path::Path;

/// Причина отказа работы с ZIP-архивом.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ZipError(pub String);

const LOCAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const UTF8_FLAG: u16 = 0x0800;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

const MAX_TOTAL_SIZE: usize = 128 * 1024 * 1024;

/// Запись архива: имя и несжатое содержимое.
pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// python `zipfile.is_zipfile`: в конце файла (с учётом комментария) есть
/// сигнатура EOCD.
#[must_use]
pub fn is_zip_archive(path: &Path) -> bool {
    let Ok(raw) = std::fs::read(path) else {
        return false;
    };
    find_eocd(&raw).is_some()
}

/// python `ZipFile(...).namelist()` + содержимое всех файлов архива
/// (папки пропускаются). CRC проверяется при распаковке.
pub fn read_archive(path: &Path) -> Result<Vec<ZipEntry>, ZipError> {
    let raw = std::fs::read(path).map_err(|error| ZipError(error.to_string()))?;
    let eocd = find_eocd(&raw).ok_or_else(|| ZipError("File is not a zip file".to_string()))?;
    let entry = &raw[eocd..eocd + 22];
    let central_size = read_u32(entry, 12) as usize;
    let central_offset = read_u32(entry, 16) as usize;
    if central_offset + central_size > raw.len() {
        return Err(ZipError("File is not a zip file".to_string()));
    }

    let mut entries: Vec<ZipEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cursor = central_offset;
    let central_end = central_offset + central_size;
    while cursor + 4 <= central_end && raw[cursor..cursor + 4] == CENTRAL_SIGNATURE {
        if cursor + 46 > raw.len() {
            return Err(ZipError("Bad central directory".to_string()));
        }
        let header = &raw[cursor..cursor + 46];
        let method = read_u16(header, 10);
        let crc = read_u32(header, 16);
        let compressed_size = read_u32(header, 20) as usize;
        let uncompressed_size = read_u32(header, 24) as usize;
        let name_len = read_u16(header, 28) as usize;
        let extra_len = read_u16(header, 30) as usize;
        let comment_len = read_u16(header, 32) as usize;
        let local_offset = read_u32(header, 42) as usize;
        let name_end = 46 + name_len;
        let record_len = name_end + extra_len + comment_len;
        if cursor + record_len > central_end {
            return Err(ZipError("Bad central directory".to_string()));
        }
        let name = String::from_utf8(raw[cursor + 46..cursor + name_end].to_vec())
            .map_err(|_| ZipError("Bad file name encoding".to_string()))?;
        cursor += record_len;

        if name.ends_with('/') {
            continue;
        }
        if !seen.insert(name.clone()) {
            return Err(ZipError(format!("Duplicate name: {name}")));
        }
        let data = read_entry_data(
            &raw,
            local_offset,
            method,
            compressed_size,
            uncompressed_size,
        )?;
        if crc32(&data) != crc {
            return Err(ZipError(format!("Bad CRC-32 for {name}")));
        }
        entries.push(ZipEntry { name, data });
    }
    Ok(entries)
}

/// python `ZipFile.read(name)`.
pub fn read_entry<'a>(entries: &'a [ZipEntry], name: &str) -> Option<&'a [u8]> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.data.as_slice())
}

/// python `ZipFile.writestr(..., compression=ZIP_DEFLATED)`: пишет архив с
/// UTF-8 именами и deflate-сжатием каждого файла.
pub fn write_archive(path: &Path, entries: &[ZipEntry]) -> Result<(), ZipError> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut count = 0u16;

    for entry in entries {
        let name_bytes = entry.name.as_bytes();
        let crc = crc32(&entry.data);
        let uncompressed = entry.data.len() as u32;
        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder =
                flate2::write::DeflateEncoder::new(&mut compressed, flate2::Compression::default());
            encoder
                .write_all(&entry.data)
                .map_err(|error| ZipError(error.to_string()))?;
            encoder
                .finish()
                .map_err(|error| ZipError(error.to_string()))?;
        }
        // Для крошечных записей deflate может выйти длиннее: python оставляет
        // method 8 в любом случае — повторяем (совместимость важнее размера).
        let method = METHOD_DEFLATE;
        let compressed_size = compressed.len() as u32;
        let local_offset = out.len() as u32;

        let mut local = Vec::with_capacity(30 + name_bytes.len());
        local.extend_from_slice(&LOCAL_HEADER_SIGNATURE);
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&UTF8_FLAG.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // DOS time
        local.extend_from_slice(&0u16.to_le_bytes()); // DOS date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&compressed_size.to_le_bytes());
        local.extend_from_slice(&uncompressed.to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local.extend_from_slice(name_bytes);
        out.extend_from_slice(&local);
        out.extend_from_slice(&compressed);

        let mut dir = Vec::with_capacity(46 + name_bytes.len());
        dir.extend_from_slice(&CENTRAL_SIGNATURE);
        dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
        dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
        dir.extend_from_slice(&UTF8_FLAG.to_le_bytes());
        dir.extend_from_slice(&method.to_le_bytes());
        dir.extend_from_slice(&0u16.to_le_bytes()); // DOS time
        dir.extend_from_slice(&0u16.to_le_bytes()); // DOS date
        dir.extend_from_slice(&crc.to_le_bytes());
        dir.extend_from_slice(&compressed_size.to_le_bytes());
        dir.extend_from_slice(&uncompressed.to_le_bytes());
        dir.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        dir.extend_from_slice(&0u16.to_le_bytes()); // extra len
        dir.extend_from_slice(&0u16.to_le_bytes()); // comment len
        dir.extend_from_slice(&0u16.to_le_bytes()); // disk number
        dir.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        dir.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        dir.extend_from_slice(&local_offset.to_le_bytes());
        dir.extend_from_slice(name_bytes);
        central.extend_from_slice(&dir);
        count += 1;
    }

    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    let mut eocd = Vec::with_capacity(22);
    eocd.extend_from_slice(&EOCD_SIGNATURE);
    eocd.extend_from_slice(&0u16.to_le_bytes()); // disk number
    eocd.extend_from_slice(&0u16.to_le_bytes()); // central dir disk
    eocd.extend_from_slice(&count.to_le_bytes());
    eocd.extend_from_slice(&count.to_le_bytes());
    eocd.extend_from_slice(&central_size.to_le_bytes());
    eocd.extend_from_slice(&central_offset.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out.extend_from_slice(&eocd);

    std::fs::write(path, &out).map_err(|error| ZipError(error.to_string()))
}

fn find_eocd(raw: &[u8]) -> Option<usize> {
    if raw.len() < 22 {
        return None;
    }
    // Комментарий архива может быть до 65 535 байт; ищем сигнатуру с конца.
    let window_start = raw.len().saturating_sub(22 + 65_535);
    let mut index = raw.len() - 22;
    loop {
        if raw[index..index + 4] == EOCD_SIGNATURE {
            let comment_len = read_u16(raw, index + 20) as usize;
            if index + 22 + comment_len == raw.len() {
                return Some(index);
            }
        }
        if index == window_start {
            return None;
        }
        index -= 1;
    }
}

fn read_entry_data(
    raw: &[u8],
    local_offset: usize,
    method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
) -> Result<Vec<u8>, ZipError> {
    if local_offset + 30 > raw.len()
        || raw[local_offset..local_offset + 4] != LOCAL_HEADER_SIGNATURE
    {
        return Err(ZipError("Bad local header".to_string()));
    }
    let name_len = read_u16(raw, local_offset + 26) as usize;
    let extra_len = read_u16(raw, local_offset + 28) as usize;
    let data_start = local_offset + 30 + name_len + extra_len;
    let data_end = data_start
        .checked_add(compressed_size)
        .ok_or_else(|| ZipError("Bad local header".to_string()))?;
    if data_end > raw.len() {
        return Err(ZipError("Bad local header".to_string()));
    }
    let compressed = &raw[data_start..data_end];
    let mut data = match method {
        METHOD_STORED => compressed.to_vec(),
        METHOD_DEFLATE => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut out = Vec::with_capacity(uncompressed_size);
            decoder
                .read_to_end(&mut out)
                .map_err(|error| ZipError(error.to_string()))?;
            out
        }
        other => return Err(ZipError(format!("Unsupported compression method {other}"))),
    };
    if data.len() != uncompressed_size {
        return Err(ZipError("Bad decompressed size".to_string()));
    }
    if uncompressed_size > MAX_TOTAL_SIZE {
        return Err(ZipError("Archive entry too large".to_string()));
    }
    Ok(std::mem::take(&mut data))
}

fn read_u16(raw: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([raw[offset], raw[offset + 1]])
}

fn read_u32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ])
}

/// CRC-32 (IEEE) без внешних крейтов — python `zipfile` проверяет его на
/// каждом чтении.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_python_zipfile_layout() {
        let dir = std::env::temp_dir().join("primecore-presets-zipio-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("t.zip");
        let entries = vec![
            ZipEntry {
                name: "manifest.json".to_string(),
                data: b"{\"format\": \"primebypass-portable-preset\"}".to_vec(),
            },
            ZipEntry {
                name: "lists/\u{41c}\u{43e}\u{439}.txt".to_string(),
                data: "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}\n"
                    .as_bytes()
                    .to_vec(),
            },
        ];
        write_archive(&zip_path, &entries).unwrap();
        assert!(is_zip_archive(&zip_path));
        let read_back = read_archive(&zip_path).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].name, "manifest.json");
        assert_eq!(read_back[1].name, "lists/\u{41c}\u{43e}\u{439}.txt");
        assert_eq!(
            read_back[1].data,
            "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}\n".as_bytes()
        );
        assert_eq!(
            read_entry(&read_back, "manifest.json").unwrap(),
            entries[0].data
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crc32_matches_known_values() {
        // python zlib.crc32(b"123456789") == 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
