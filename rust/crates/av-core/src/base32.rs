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
    todo!()
}

/// Encode `bytes` into exactly `chars` base32 characters, most significant bit
/// first. Bits beyond `chars * 5` are dropped; a short buffer is zero-extended.
/// Ports `encode` in `src/core/base32.js`.
pub fn encode(bytes: &[u8], chars: usize) -> String {
    todo!()
}

/// Decode base32 characters back to the first `byte_len` bytes they encode
/// (zero-filled if `s` is too short). Returns `None` where the JS throws
/// `Error('not base32')`. Ports `decode` in `src/core/base32.js`.
pub fn decode(s: &str, byte_len: usize) -> Option<Vec<u8>> {
    todo!()
}
