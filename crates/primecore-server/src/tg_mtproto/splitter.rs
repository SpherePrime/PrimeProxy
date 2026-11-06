use super::handshake::Proto;

pub struct MsgSplitter {
    proto: Proto,
    cipher: Vec<u8>,
    plain: Vec<u8>,
    disabled: bool,
}

impl MsgSplitter {
    #[must_use]
    pub fn new(proto: Proto) -> Self {
        Self {
            proto,
            cipher: Vec::new(),
            plain: Vec::new(),
            disabled: false,
        }
    }

    pub fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if cipher.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![cipher.to_vec()];
        }
        self.cipher.extend_from_slice(cipher);
        self.plain.extend_from_slice(plain);

        let mut parts = Vec::new();
        let mut offset = 0;
        let total = self.cipher.len();
        while offset < total {
            let Some(length) = self.next_len(offset, total - offset) else {
                break;
            };
            if length == 0 {
                parts.push(self.cipher[offset..].to_vec());
                offset = total;
                self.disabled = true;
                break;
            }
            parts.push(self.cipher[offset..offset + length].to_vec());
            offset += length;
        }
        if offset > 0 {
            self.cipher.drain(..offset);
            self.plain.drain(..offset);
        }
        parts
    }

    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher.is_empty() {
            return None;
        }
        self.plain.clear();
        Some(std::mem::take(&mut self.cipher))
    }

    fn next_len(&self, offset: usize, available: usize) -> Option<usize> {
        match self.proto {
            Proto::Abridged => self.abridged_len(offset, available),
            Proto::Intermediate | Proto::PaddedIntermediate => self.intermediate_len(offset, available),
        }
    }

    fn abridged_len(&self, offset: usize, available: usize) -> Option<usize> {
        let first = self.plain[offset];
        let (payload, header) = if first == 0x7f || first == 0xff {
            if available < 4 {
                return None;
            }
            let raw = [self.plain[offset + 1], self.plain[offset + 2], self.plain[offset + 3], 0];
            (u32::from_le_bytes(raw) as usize * 4, 4)
        } else {
            (usize::from(first & 0x7f) * 4, 1)
        };
        if payload == 0 {
            return Some(0);
        }
        let length = header + payload;
        (available >= length).then_some(length)
    }

    fn intermediate_len(&self, offset: usize, available: usize) -> Option<usize> {
        if available < 4 {
            return None;
        }
        let raw = [
            self.plain[offset],
            self.plain[offset + 1],
            self.plain[offset + 2],
            self.plain[offset + 3],
        ];
        let payload = (u32::from_le_bytes(raw) & 0x7fff_ffff) as usize;
        if payload == 0 {
            return Some(0);
        }
        let length = 4 + payload;
        (available >= length).then_some(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intermediate(payload: &[u8]) -> Vec<u8> {
        let mut packet = (payload.len() as u32).to_le_bytes().to_vec();
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn splits_intermediate_packets_across_reads() {
        let mut stream = intermediate(&[1; 8]);
        stream.extend(intermediate(&[2; 12]));
        let mut splitter = MsgSplitter::new(Proto::Intermediate);
        let first = splitter.split(&stream[..14], &stream[..14]);
        assert_eq!(first, vec![intermediate(&[1; 8])]);
        let second = splitter.split(&stream[14..], &stream[14..]);
        assert_eq!(second, vec![intermediate(&[2; 12])]);
        assert!(splitter.flush().is_none());
    }

    #[test]
    fn splits_abridged_short_and_long_headers() {
        let mut stream = vec![2_u8];
        stream.extend([7; 8]);
        stream.extend([0x7f, 1, 0, 0]);
        stream.extend([9; 4]);
        let mut splitter = MsgSplitter::new(Proto::Abridged);
        let parts = splitter.split(&stream, &stream);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 9);
        assert_eq!(parts[1].len(), 8);
    }

    #[test]
    fn cuts_ciphertext_by_plaintext_lengths() {
        let plain = intermediate(&[5; 4]);
        let cipher: Vec<u8> = plain.iter().map(|byte| byte ^ 0xaa).collect();
        let mut splitter = MsgSplitter::new(Proto::Intermediate);
        assert_eq!(splitter.split(&cipher, &plain), vec![cipher.clone()]);
    }
}
