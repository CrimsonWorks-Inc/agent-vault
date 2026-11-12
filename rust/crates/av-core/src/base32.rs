//! Crockford base32, lowercase, no padding. Ports `src/core/base32.js`.
//!
//! The alphabet excludes `i`, `l`, `o` and `u` so a placeholder survives being
//! read aloud, retyped by a model, or logged by a tool that lowercases. It
//! matches the grammar's `[0-9a-hjkmnp-tv-z]`.

/// The 32-character alphabet, in value order. Ports `ALPHABET` in
/// `src/core/base32.js`.
pub const ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";

/// True when every character of `s` is in the alphabet and `s` is non-empty.
/// Ports `isBase32` in `src/core/base32.js`.
pub fn is_base32(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| ALPHABET.as_bytes().contains(&b))
}

/// Encode `bytes` into exactly `chars` base32 characters, most significant bit
/// first. Bits beyond `chars * 5` are dropped; a short buffer is zero-extended.
/// Ports `encode` in `src/core/base32.js`.
pub fn encode(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    for i in 0..chars {
        let mut v = 0usize;
        for j in 0..5 {
            let bit = i * 5 + j;
            v = (v << 1)
                | usize::from(bytes.get(bit / 8).copied().unwrap_or(0) >> (7 - bit % 8) & 1);
        }
        out.push(ALPHABET.as_bytes()[v] as char);
    }
    out
}

/// Decode base32 characters back to the first `byte_len` bytes they encode
/// (zero-filled if `s` is too short). Returns `None` where the JS throws
/// `Error('not base32')`. Ports `decode` in `src/core/base32.js`.
pub fn decode(s: &str, byte_len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0; byte_len];
    let mut bit = 0;
    for c in s.bytes() {
        if bit / 8 >= byte_len {
            break;
        }
        let v = ALPHABET.as_bytes().iter().position(|b| *b == c)?;
        for j in 0..5 {
            if bit / 8 < byte_len {
                out[bit / 8] |= (((v >> (4 - j)) & 1) as u8) << (7 - bit % 8);
            }
            bit += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoding_roundtrip_and_zero_extension() {
        for byte in 0..=255 {
            let bytes = [byte; 16];
            let s = encode(&bytes, 26);
            assert!(is_base32(&s));
            assert_eq!(decode(&s, 16).unwrap(), bytes);
        }
        assert_eq!(encode(&[], 4), "0000");
        assert_eq!(decode("0", 3).unwrap(), [0; 3]);
        assert!(!is_base32(""));
        assert!(!is_base32("ilouAé"));
        assert!(decode("i", 1).is_none());
    }
}
