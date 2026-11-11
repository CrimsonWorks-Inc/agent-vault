//! Placeholder grammar, minting, parsing and keyed verification. Ports
//! `src/core/placeholder.js`.
//!
//! ```text
//! placeholder := "av1" "." sid "." label "." nonce "." chk
//! sid   := 12 x base32   session id, 60 bits
//! label := slug "_" field   slug [a-z0-9-]{1,24}, field [a-z0-9]{1,16}
//! nonce := 26 x base32   128 bits from the CSPRNG
//! chk   := 6 x base32    first 30 bits of HMAC-SHA256(K_ph, "av1."sid"."label"."nonce)
//! ```

use crate::secret::Key32;

/// The fixed prefix. Ports `PREFIX` in `src/core/placeholder.js`.
pub const PREFIX: &str = "av1.";
/// Session id length in base32 chars. Ports `SID_LEN`.
pub const SID_LEN: usize = 12;
/// Nonce length in base32 chars. Ports `NONCE_LEN`.
pub const NONCE_LEN: usize = 26;
/// Check length in base32 chars. Ports `CHK_LEN`.
pub const CHK_LEN: usize = 6;
/// Longest credential slug. Ports `SLUG_MAX`.
pub const SLUG_MAX: usize = 24;
/// Longest field name. Ports `FIELD_MAX`.
pub const FIELD_MAX: usize = 16;

/// Shortest possible placeholder (54). Ports `PH_MIN_LEN` in
/// `src/core/placeholder.js`.
pub const PH_MIN_LEN: usize = 3 + 1 + SID_LEN + 1 + 3 + 1 + NONCE_LEN + 1 + CHK_LEN;
/// Longest possible placeholder (92). Ports `PH_MAX_LEN`.
pub const PH_MAX_LEN: usize =
    3 + 1 + SID_LEN + 1 + (SLUG_MAX + 1 + FIELD_MAX) + 1 + NONCE_LEN + 1 + CHK_LEN;
/// Shortest base64 run worth decoding (72 = ceil(54 * 4 / 3)). Ports
/// `B64_MIN_RUN`.
pub const B64_MIN_RUN: usize = (PH_MIN_LEN * 4).div_ceil(3);
/// Overlap a streaming scan keeps (278), enough to cover a fully
/// percent-encoded token. Ports `SCAN_OVERLAP`.
pub const SCAN_OVERLAP: usize = 3 * PH_MAX_LEN + 2;

/// Slug grammar. Ports `SLUG_RE` in `src/core/placeholder.js`.
pub const SLUG_PATTERN: &str = "^[a-z0-9-]{1,24}$";
/// Field grammar. Ports `FIELD_RE` in `src/core/placeholder.js`.
pub const FIELD_PATTERN: &str = "^[a-z0-9]{1,16}$";

/// The single pattern secret scanners are given (gitleaks, push protection).
/// Ports `SCANNER_PATTERN` in `src/core/placeholder.js`.
pub const SCANNER_PATTERN: &str = "av1\\.[0-9a-hjkmnp-tv-z]{12}\\.[a-z0-9-]{1,24}_[a-z0-9]{1,16}\\.[0-9a-hjkmnp-tv-z]{26}\\.[0-9a-hjkmnp-tv-z]{6}";

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

/// True when `s` is a valid credential slug. Ports `isValidSlug` in
/// `src/core/placeholder.js`.
pub fn is_valid_slug(s: &str) -> bool {
    todo!()
}

/// True when `s` is a valid field name. Ports `isValidField` in
/// `src/core/placeholder.js`.
pub fn is_valid_field(s: &str) -> bool {
    todo!()
}

/// A new session id: 60 bits from the CSPRNG as 12 base32 characters
/// (`encode(randomBytes(8), 12)`). Ports `newSid` in
/// `src/core/placeholder.js`.
pub fn new_sid() -> String {
    todo!()
}

/// Input to [`mint`]. Ports the `{ kPh, sid, slug, field }` argument of
/// `mint` in `src/core/placeholder.js`.
#[derive(Debug, Clone, Copy)]
pub struct MintInput<'a> {
    /// The placeholder key (`kPh`).
    pub k_ph: &'a Key32,
    /// Session id.
    pub sid: &'a str,
    /// Credential slug.
    pub slug: &'a str,
    /// Field name.
    pub field: &'a str,
}

/// A freshly minted placeholder. Ports the
/// `{ text, sid, slug, field, nonce, nonceHash }` object returned by `mint` in
/// `src/core/placeholder.js`. The text and nonce are bearer material returned
/// once and never persisted, so `Debug` is redacted.
#[derive(Clone)]
pub struct Minted {
    /// The full placeholder text.
    pub text: String,
    /// Session id.
    pub sid: String,
    /// Credential slug.
    pub slug: String,
    /// Field name.
    pub field: String,
    /// The nonce (never stored).
    pub nonce: String,
    /// `hashNonce(nonce)`, the key the daemon stores it under (`nonceHash`).
    pub nonce_hash: String,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted")
            .field("sid", &self.sid)
            .field("slug", &self.slug)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}

/// Why [`mint`] refused. Ports the plain `Error`s thrown by `mint` in
/// `src/core/placeholder.js`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    /// `invalid credential slug: <slug>`
    #[error("invalid credential slug: {0}")]
    Slug(String),
    /// `invalid field name: <field>`
    #[error("invalid field name: {0}")]
    Field(String),
    /// `invalid sid`
    #[error("invalid sid")]
    Sid,
}

/// Mint a placeholder with a fresh 128-bit nonce and its keyed check. Ports
/// `mint` in `src/core/placeholder.js`.
pub fn mint(input: &MintInput<'_>) -> Result<Minted, MintError> {
    todo!()
}

/// Lowercase hex HMAC-SHA256 keyed with the literal `"av/nonce/v1"` over the
/// nonce: the primary key the daemon looks a placeholder up by. Ports
/// `hashNonce` in `src/core/placeholder.js`.
pub fn hash_nonce(nonce: &str) -> String {
    todo!()
}

/// Parse at byte `offset` in `s`, anchored on the fixed-width tail. `None`
/// when the text there is not shaped like a placeholder (including a longer
/// base32 run after `chk`). Shape only: no keyed verification. Ports `parseAt`
/// in `src/core/placeholder.js`.
pub fn parse_at(s: &str, offset: usize) -> Option<ParsedPlaceholder> {
    todo!()
}

/// Verify the keyed check characters, comparing in constant time. Ports
/// `verify` in `src/core/placeholder.js`.
pub fn verify(k_ph: &Key32, parsed: &ParsedPlaceholder) -> bool {
    todo!()
}

/// Explain, in terms an agent can act on, why a malformed placeholder is
/// malformed (e.g. `expected groups of 12/26/6 chars, got 12/25/6`). Ports
/// `diagnose` in `src/core/placeholder.js`.
pub fn diagnose(s: &str) -> String {
    todo!()
}

/// Every placeholder-shaped run in `s`, in order; after a miss the scan
/// resumes one byte in, so `av1.av1.<real>` still finds the real one. Ports
/// `findAll` in `src/core/placeholder.js`.
pub fn find_all(s: &str) -> Vec<ParsedPlaceholder> {
    todo!()
}
