//! Потоковый AES-CTR над внутренним шифром ([`crate::crypto`]).
//!
//! Python-версия держит `AesCtrStream` поверх tgcrypto; здесь — та же
//! раскладка: IV и однобайтовое состояние живут внутри потока, `update`
//! можно вызывать кусками любого размера.

use crate::crypto::Aes256Ctr;

/// Ошибки создания потока: тексты совпадают с python-версией.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCtrError(pub String);

impl std::fmt::Display for AesCtrError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AesCtrError {}

/// Потоковый AES-CTR поверх AES-256.
pub struct AesCtrStream {
    inner: Aes256Ctr,
}

impl std::fmt::Debug for AesCtrStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AesCtrStream")
    }
}

impl AesCtrStream {
    /// Создаёт поток: ключ ровно 32 байта, IV — 16.
    ///
    /// # Errors
    /// Возвращает [`AesCtrError`] с текстом python-версии при неверной длине.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, AesCtrError> {
        if key.len() != 32 {
            return Err(AesCtrError("AES-CTR key must be exactly 32 bytes".into()));
        }
        if iv.len() != 16 {
            return Err(AesCtrError("AES-CTR IV must be exactly 16 bytes".into()));
        }
        let mut key_array = [0_u8; 32];
        key_array.copy_from_slice(key);
        let mut iv_array = [0_u8; 16];
        iv_array.copy_from_slice(iv);
        Ok(Self::from_arrays(key_array, iv_array))
    }

    /// Поток из массивов фиксированной длины: для мест, где длины гарантированы
    /// структурой данных (48 байт prekey заголовка obfuscated2).
    #[must_use]
    pub fn from_arrays(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            inner: Aes256Ctr::new(&key, &iv),
        }
    }

    /// Шифрует очередной кусок потока.
    #[must_use]
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        self.inner.update(data)
    }
}

/// Разовое шифрование куска данных.
///
/// # Errors
/// Возвращает [`AesCtrError`] при неверной длине ключа или IV.
pub fn aes_ctr_crypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, AesCtrError> {
    AesCtrStream::new(key, iv).map(|mut stream| stream.update(data))
}

/// Отрезок keystream нужной длины (python шифрует нулевые байты).
///
/// # Errors
/// Возвращает [`AesCtrError`] при неверной длине ключа или IV.
pub fn aes_ctr_keystream(key: &[u8], iv: &[u8], size: usize) -> Result<Vec<u8>, AesCtrError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    aes_ctr_crypt(key, iv, &vec![0_u8; size])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_and_iv_lengths_match_python_messages() {
        let error = AesCtrStream::new(&[0_u8; 31], &[0_u8; 16]).unwrap_err();
        assert_eq!(error.0, "AES-CTR key must be exactly 32 bytes");
        let error = AesCtrStream::new(&[0_u8; 32], &[0_u8; 15]).unwrap_err();
        assert_eq!(error.0, "AES-CTR IV must be exactly 16 bytes");
    }

    #[test]
    fn keystream_matches_nist_aes256_ctr_vector() {
        // NIST SP 800-38A F.5.5 (AES-256-CTR): keystream = шифртекст ^ открытый
        // текст первого блока примера.
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let iv_hex = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        let key: Vec<u8> = (0..32)
            .map(|index| u8_from_hex(&key_hex[index * 2..index * 2 + 2]))
            .collect();
        let iv: Vec<u8> = (0..16)
            .map(|index| u8_from_hex(&iv_hex[index * 2..index * 2 + 2]))
            .collect();
        let cipher_hex = "601ec313775789a5b7a7f504bbf3d228";
        let plain_hex = "6bc1bee22e409f96e93d7e117393172a";
        let expected: Vec<u8> = (0..16)
            .map(|index| {
                u8_from_hex(&cipher_hex[index * 2..index * 2 + 2])
                    ^ u8_from_hex(&plain_hex[index * 2..index * 2 + 2])
            })
            .collect();
        assert_eq!(aes_ctr_keystream(&key, &iv, 16).unwrap(), expected);
    }

    fn u8_from_hex(text: &str) -> u8 {
        u8::from_str_radix(text, 16).unwrap()
    }
}
