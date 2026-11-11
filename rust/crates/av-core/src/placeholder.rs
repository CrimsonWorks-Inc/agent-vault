//! Placeholder grammar, minting, parsing and keyed verification. Ports
//! `src/core/placeholder.js`.

/// A placeholder-shaped run found in text. Ports the object returned by
/// `parseAt` in `src/core/placeholder.js`
/// (`{ text, offset, end, sid, label, slug, field, nonce, chk }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPlaceholder {
    /// The whole placeholder text.
    pub text: String,
    /// Byte offset where it starts.
    pub offset: usize,
    /// Byte offset one past its end.
    pub end: usize,
    /// Session id (12 base32 chars).
    pub sid: String,
    /// `<slug>_<field>`.
    pub label: String,
    /// Credential slug.
    pub slug: String,
    /// Field name.
    pub field: String,
    /// Nonce (26 base32 chars).
    pub nonce: String,
    /// Check characters (6 base32 chars).
    pub chk: String,
}
