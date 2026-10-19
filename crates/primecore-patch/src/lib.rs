//! Применение заплаток BSDIFF40 (порт src/primebypass_update/bsdiff.py).
//!
//! Формат совпадает с bsdiff4: magic BSDIFF40, три off_t little-endian
//! (control_size, diff_size, new_size), за ними три сжатых bz2-блока
//! подряд: control (тройки copy/insert/seek по 24 байта), diff (байты
//! «new - old, mod 256»), extra (вставляемые байты). Контракт тройки —
//! ванильный bspatch:
//!
//! * `out[new_pos .. + copy] = old[old_pos ..] + diff` (вне границ old
//!   читается как ноль);
//! * `out[new_pos + copy ..] = extra` (вставка);
//! * `new_pos += copy + insert`; `old_pos += copy + seek`.
//!
//! В Python-версии control читается целиком, а diff/extra идут потоково.
//! Здесь то же: один `MultiBzDecoder` раскладывает три склеенных bz2-потока
//! последовательно (control целиком, diff ровно diff_size декодированных
//! байт в память — diff-окно всегда, что нужно для страниц добавления,
//! остаток — extra).

use std::io::{Cursor, Read};

/// Ошибка применения заплатки. Код один — «patch», как в Python-версии;
/// подробности в `message`.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct PatchError {
    pub code: &'static str,
    pub message: String,
}

fn invalid(message: String) -> PatchError {
    PatchError {
        code: "patch",
        message,
    }
}

/// Применяет BSDIFF-заплатку к старому файлу, возвращает новый файл.
pub fn apply(old: &[u8], patch: &[u8]) -> Result<Vec<u8>, PatchError> {
    if patch.len() < 32 {
        return Err(invalid(format!("слишком коротко: {}", patch.len())));
    }
    if patch[..8] != *b"BSDIFF40" {
        let head = patch[..patch.len().min(8)].to_vec();
        return Err(invalid(format!("magic не BSDIFF40: {head:x?}")));
    }
    let off = |start: usize| -> i64 {
        i64::from_le_bytes(patch[start..start + 8].try_into().expect("offset 8 байт"))
    };
    let (control_size, diff_size, new_size) = (off(8), off(16), off(24));
    if control_size < 0 || diff_size < 0 || new_size < 0 {
        return Err(invalid(format!(
            "отрицательные размеры: {control_size},{diff_size},{new_size}"
        )));
    }
    let (control_size, diff_size, new_size) =
        (control_size as usize, diff_size as usize, new_size as usize);

    // Три bz2-потока идут подряд; MultiBzDecoder прозрачно склеивает их.
    let mut streams = bzip2::read::MultiBzDecoder::new(Cursor::new(patch[32..].to_vec()));
    let mut control = vec![0u8; control_size];
    streams
        .read_exact(&mut control)
        .map_err(|e| invalid(format!("control не прочитался: {e}")))?;
    let mut diff = vec![0u8; diff_size];
    streams
        .read_exact(&mut diff)
        .map_err(|e| invalid(format!("diff не прочитался: {e}")))?;
    let mut extra = Vec::new();
    streams
        .read_to_end(&mut extra)
        .map_err(|e| invalid(format!("extra не прочитался: {e}")))?;

    if control.len() % 24 != 0 {
        return Err(invalid(format!("control не кратен 24: {}", control.len())));
    }
    let mut control_reader = Cursor::new(control);
    let mut diff_reader = Cursor::new(diff);
    let mut extra_reader = Cursor::new(extra);

    let mut out = vec![0u8; new_size];
    let mut new_pos: usize = 0;
    let mut old_pos: i64 = 0;
    let mut triple = [0u8; 24];
    while control_reader.read_exact(&mut triple).is_ok() {
        let read_off = |start: usize| -> i64 {
            i64::from_le_bytes(triple[start..start + 8].try_into().expect("triple 8 байт"))
        };
        let (copy_len, insert_len, seek) = (read_off(0), read_off(8), read_off(16));
        if copy_len < 0 || insert_len < 0 {
            return Err(invalid(format!(
                "отрицательный размер тройки: {copy_len},{insert_len}"
            )));
        }
        let (copy_len, insert_len) = (copy_len as usize, insert_len as usize);
        if new_pos + copy_len + insert_len > new_size {
            return Err(invalid(format!(
                "тройка вылезает за new_size: {new_pos}+{copy_len}+{insert_len}>{new_size}"
            )));
        }

        // Копирование: старые байты + diff (модуль 256) кусками по STEP,
        // как STEP в bsdiff.py: не держим всю страницу diff-окна разом.
        let mut consumed = 0usize;
        while consumed < copy_len {
            let part = 8192.min(copy_len - consumed);
            let src = diff_slice(&mut diff_reader, part)?;
            for (offset, delta) in src.iter().enumerate() {
                let index = old_pos + (consumed + offset) as i64;
                let source = if 0 <= index && index < old.len() as i64 {
                    old[index as usize]
                } else {
                    0
                };
                out[new_pos + consumed + offset] = source.wrapping_add(*delta);
            }
            consumed += part;
            new_pos += part;
            old_pos += part as i64;
        }
        // Вставка из extra.
        read_exact_from(&mut extra_reader, &mut out[new_pos..new_pos + insert_len])?;
        new_pos += insert_len;
        old_pos += seek;
    }
    if new_pos != new_size {
        return Err(invalid(format!(
            "заплатка накрыла не весь новый файл: {new_pos}!={new_size}"
        )));
    }
    Ok(out)
}

fn diff_slice(diff: &mut Cursor<Vec<u8>>, part: usize) -> Result<&[u8], PatchError> {
    let pos = diff.position() as usize;
    let need = pos + part;
    if need > diff.get_ref().len() {
        return Err(invalid(format!("diff закончился: {} < {need}", diff.get_ref().len())));
    }
    diff.set_position(need as u64);
    Ok(&diff.get_ref()[pos..need])
}

fn read_exact_from(
    reader: &mut Cursor<Vec<u8>>,
    target: &mut [u8],
) -> Result<(), PatchError> {
    let pos = reader.position() as usize;
    let need = pos + target.len();
    if need > reader.get_ref().len() {
        return Err(invalid(format!("extra закончился: {} < {need}", reader.get_ref().len())));
    }
    target.copy_from_slice(&reader.get_ref()[pos..need]);
    reader.set_position(need as u64);
    Ok(())
}
