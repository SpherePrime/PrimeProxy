//! Порт `presets/cache_signatures.py` — подписи файлов для кэшей.

use std::path::Path;

/// python `path_stat_signature`: `(mtime_ns, size)`; нечитаемый путь — `(0, 0)`.
#[must_use]
pub fn path_stat_signature(path: &Path) -> (u64, u64) {
    match path.metadata() {
        Ok(metadata) => (signature_mtime_ns(&metadata), metadata.len()),
        Err(_) => (0, 0),
    }
}

/// python `path_cache_signature`: `(mtime_ns, size, blake2b-digest-16)`;
/// нечитаемый путь — `(0, 0, "")`; пустая/нечитаемая выгрузка — пустой хэш.
#[must_use]
pub fn path_cache_signature(path: &Path) -> (u64, u64, String) {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return (0, 0, String::new()),
    };
    let digest = if metadata.is_file() {
        match std::fs::read(path) {
            Ok(bytes) => blake2b_hex_16(&bytes),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };
    (signature_mtime_ns(&metadata), metadata.len(), digest)
}

fn signature_mtime_ns(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// python `hashlib.blake2b(data, digest_size=16).hexdigest()` — нижний регистр.
#[must_use]
pub fn blake2b_hex_16(data: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(16)
        .to_state()
        .update(data)
        .finalize()
        .to_hex()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_digest() {
        // python: hashlib.blake2b(b"hello", digest_size=16).hexdigest()
        assert_eq!(blake2b_hex_16(b"hello"), "46fb7408d4f285228f4af516ea25851b");
    }

    #[test]
    fn missing_file_gives_zero_signature() {
        assert_eq!(
            path_stat_signature(Path::new("/definitely/missing/x")),
            (0, 0)
        );
        assert_eq!(
            path_cache_signature(Path::new("/definitely/missing/x")),
            (0, 0, String::new())
        );
    }
}
