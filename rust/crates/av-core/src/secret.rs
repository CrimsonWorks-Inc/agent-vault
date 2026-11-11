//! Secret-holding types shared by every crate.
//!
//! Nothing here implements `Debug` or `Display` with its contents, and every
//! buffer is zeroized on drop (rust/PLAN.md, "Crypto contract"). These are the
//! Rust homes of the JS `Buffer`s that `src/store/crypto.js` wipes with
//! `wipe()`.

use zeroize::Zeroizing;

pub use secrecy::{ExposeSecret, SecretBox, SecretSlice, SecretString};

/// A 32-byte symmetric key: the VMK, a KEK, a DEK, `kPh`, `kToken`, `kAudit`,
/// `kFingerprint`. Ports the 32-byte `Buffer` keys of `src/store/crypto.js`
/// (`randomKey`, `hkdf`, `deriveKek`, `dek`, `kPh`, …).
#[derive(Clone)]
pub struct Key32(Zeroizing<[u8; 32]>);

impl Key32 {
    /// Wrap raw key bytes. The caller's copy should be zeroized.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key32(Zeroizing::new(bytes))
    }

    /// Borrow the key bytes for a crypto primitive. Never log or store them.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32([REDACTED])")
    }
}

/// Secret bytes of any length (a credential field value, a decrypted
/// plaintext, a passphrase-derived factor). Ports the plaintext `Buffer`s
/// returned by `openBytes` in `src/store/crypto.js`.
pub type SecretBytes = SecretSlice<u8>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_debug_never_shows_bytes() {
        let k = Key32::from_bytes([0x41; 32]);
        let shown = format!("{k:?}");
        assert!(!shown.contains("41") && !shown.contains("65"), "{shown}");
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        let s = SecretString::from("test-secret-not-real".to_string());
        assert!(!format!("{s:?}").contains("test-secret"));
    }
}
