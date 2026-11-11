//! The detector: where does a placeholder appear in the request, in any
//! encoding a tool might have applied? Ports `src/core/detect.js`.
//!
//! Deliberately a superset of what the substituter understands: it also sees
//! percent-encoding, JSON string escapes and base64 anywhere.

use serde::{Deserialize, Serialize};

use crate::placeholder::ParsedPlaceholder;

/// The base64-ish character class a run is made of. Ports `B64_CHARS` in
/// `src/core/detect.js`.
pub const B64_CHARS_PATTERN: &str = "[A-Za-z0-9+/=_-]";

/// How a detected placeholder was encoded. Ports the `encoding` strings
/// pushed by `detectAll` in `src/core/detect.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HitEncoding {
    /// `'raw'`
    #[serde(rename = "raw")]
    Raw,
    /// `'percent'`
    #[serde(rename = "percent")]
    Percent,
    /// `'percent-double'`
    #[serde(rename = "percent-double")]
    PercentDouble,
    /// `'json-escape'`
    #[serde(rename = "json-escape")]
    JsonEscape,
    /// `'base64'`
    #[serde(rename = "base64")]
    Base64,
}

impl HitEncoding {
    /// The JS string, e.g. `"percent-double"`. Ports the `encoding` values in
    /// `src/core/detect.js`.
    pub fn as_str(self) -> &'static str {
        todo!()
    }
}

/// One placeholder found in text, with how it was encoded. Ports the
/// `{ ...parsed, encoding }` objects returned by `detectAll` in
/// `src/core/detect.js`. `parsed.offset`/`parsed.end` are meaningful only for
/// [`HitEncoding::Raw`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectHit {
    /// The parsed placeholder.
    pub parsed: ParsedPlaceholder,
    /// The encoding it was carried in.
    pub encoding: HitEncoding,
}

/// A maximal run of base64-ish characters. Ports the `{ start, text }`
/// objects returned by `base64Runs` in `src/core/detect.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Run {
    /// Byte offset where the run starts.
    pub start: usize,
    /// The run itself.
    pub text: String,
}

/// Tolerant percent-decoder: never fails, leaves malformed escapes in place,
/// and maps each decoded byte to the char of the same code (latin1), as
/// `String.fromCharCode` does. Ports `percentDecode` in `src/core/detect.js`.
pub fn percent_decode(s: &str) -> String {
    todo!()
}

/// Undo the JSON string escapes that can hide a placeholder: `\uXXXX` and
/// `\/`. Ports `jsonUnescape` in `src/core/detect.js`.
pub fn json_unescape(s: &str) -> String {
    todo!()
}

/// Every maximal run of base64-ish characters at least `min` long (the JS
/// default is [`crate::placeholder::B64_MIN_RUN`]). Ports `base64Runs` in
/// `src/core/detect.js`.
pub fn base64_runs(s: &str, min: usize) -> Vec<Base64Run> {
    todo!()
}

/// Every placeholder in `text`, in any encoding (raw, percent, double
/// percent, JSON escape, base64 at every alignment and in both alphabets,
/// including whitespace-wrapped base64), de-duplicated. Ports `detectAll` in
/// `src/core/detect.js`.
pub fn detect_all(text: &str) -> Vec<DetectHit> {
    todo!()
}

/// True when any encoding other than raw text carried a placeholder. Ports
/// `hasEncodedHit` in `src/core/detect.js`.
pub fn has_encoded_hit(hits: &[DetectHit]) -> bool {
    todo!()
}
