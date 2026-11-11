//! Canonical serialization for anything that gets hashed: presence operation
//! hashes, approval request hashes and the audit chain. Ports
//! `src/core/canon.js`.
//!
//! Object keys are sorted by their UTF-8 bytes, floats are refused, arrays keep
//! their order. Two structurally equal values produce identical bytes.

use crate::secret::Key32;

/// Why a value cannot be canonicalized. Ports the `Error('canon: …')` throws
/// in `canonicalize` in `src/core/canon.js`. (`serde_json::Value` cannot hold
/// a non-finite number or `undefined`, so only the float case remains.)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    /// `canon: floats are not canonicalizable`
    #[error("canon: floats are not canonicalizable")]
    Float,
}

/// The canonical JSON text of `value`. Ports `canonicalize` in
/// `src/core/canon.js`.
pub fn canonicalize(value: &serde_json::Value) -> Result<String, CanonError> {
    todo!()
}

/// Lowercase hex SHA-256 of `canonicalize(value)`. Ports `hash` in
/// `src/core/canon.js`.
pub fn hash(value: &serde_json::Value) -> Result<String, CanonError> {
    todo!()
}

/// Lowercase hex HMAC-SHA256 under `key` of `canonicalize(value)`. Ports
/// `hmac` in `src/core/canon.js`. Comparing two of these must be constant
/// time.
pub fn hmac(key: &Key32, value: &serde_json::Value) -> Result<String, CanonError> {
    todo!()
}

/// Input to [`request_hash`]. Ports the destructured argument
/// `{ method, host, path, query, bodySha256, credentials, headers }` of
/// `requestHash` in `src/core/canon.js`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestHashInput<'a> {
    /// Request method; uppercased (`''` when absent).
    pub method: Option<&'a str>,
    /// Destination host; lowercased (`''` when absent).
    pub host: Option<&'a str>,
    /// Decided path (`'/'` when absent).
    pub path: Option<&'a str>,
    /// Query without `?` (`''` when absent).
    pub query: Option<&'a str>,
    /// Hex SHA-256 of the body (`bodySha256`, `''` when absent).
    pub body_sha256: Option<&'a str>,
    /// `<grant>:<field>` of every injected credential field; sorted.
    pub credentials: &'a [String],
    /// The headers that will be forwarded, in order; names lowercased and
    /// stably sorted by name only.
    pub headers: &'a [(String, String)],
}

/// The approval and idempotency key for a proxied request: lowercase hex
/// SHA-256 of the canonical `{method, host, path, query, body, credentials,
/// headers}` object. Ports `requestHash` in `src/core/canon.js`.
pub fn request_hash(input: &RequestHashInput<'_>) -> String {
    todo!()
}

/// Lowercase hex SHA-256 of `buf`. Ports `sha256` in `src/core/canon.js`.
pub fn sha256(buf: &[u8]) -> String {
    todo!()
}
