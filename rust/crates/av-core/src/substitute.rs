//! The substitution engine: location-bound, fail-closed. Ports
//! `src/core/substitute.js`.
//!
//! [`locate`] finds every placeholder occurrence anywhere in the request, in
//! any encoding, and labels where it is; [`apply`] replaces a placeholder at
//! one declared site. Between them the pipeline checks each occurrence's
//! location against the field's declared sites; anywhere else is
//! `AV_BAD_LOCATION` and the request never reaches an upstream.

// `VaultError` (errors.rs, not owned here) is ~208 bytes, so clippy's
// `result_large_err` fires on every `Result<T>` signature. The fix belongs in
// errors.rs (box the extras); until then it is allowed in this module only.
#![allow(clippy::result_large_err)]

use serde::{Deserialize, Serialize};

use crate::detect::{DetectHit, HitEncoding};
use crate::errors::Result;
use crate::placeholder::ParsedPlaceholder;
use crate::secret::SecretString;
use crate::sites::Site;

/// Largest body buffered and scanned (16 MiB); request-body streaming is not
/// implemented. Ports `MAX_BUFFERED_BODY` in `src/core/substitute.js`.
pub const MAX_BUFFERED_BODY: usize = 16 * 1024 * 1024;

/// The `unscannable` reason for an oversized body. Ports the string returned
/// by `locate` in `src/core/substitute.js`.
pub const UNSCANNABLE_TOO_LARGE: &str = "body exceeds the 16 MiB buffered limit, and request-body streaming is not implemented, so this body cannot be scanned for placeholders";

/// The request being proxied. Ports the `Req` typedef
/// `{ method, path, query, headers, body }` of `src/core/substitute.js`.
/// After [`apply`] it carries a real secret, so `Debug` is redacted.
#[derive(Clone, Default)]
pub struct ProxyRequest {
    /// Method.
    pub method: String,
    /// Path, as sent.
    pub path: String,
    /// Query without `?`.
    pub query: String,
    /// Header pairs in order, repeats kept.
    pub headers: Vec<(String, String)>,
    /// Body, if any.
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for ProxyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRequest")
            .field("method", &self.method)
            .field("headers", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Where in the request an occurrence sits. Ports the `region` strings of
/// the `Location` typedef in `src/core/substitute.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Region {
    /// `path`: never a site.
    Path,
    /// `query-key`: never a site.
    QueryKey,
    /// `query`
    Query,
    /// `header-name`: never a site.
    HeaderName,
    /// `header`
    Header,
    /// `basic`: inside `Authorization: Basic`.
    Basic,
    /// `json`
    Json,
    /// `form-key`: never a site.
    FormKey,
    /// `form`
    Form,
    /// `body`: never a site.
    Body,
}

/// Where an occurrence was found. Ports the `Location` typedef
/// `{ region, name, key, pointer, part, scheme, index, encoding, hidden_by }`
/// in `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The region.
    pub region: Region,
    /// Header name, lowercased (`header`, `header-name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Decoded query or form key (`query`, `query-key`, `form`, `form-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// RFC 6901 pointer (`json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// `user` or `pass` (`basic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// The scheme token before a raw header hit, e.g. `Bearer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Which header entry (`header`, `header-name`, `basic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    /// How it was encoded.
    pub encoding: HitEncoding,
    /// For a body hit the parser did not expose: `the body parser`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_by: Option<String>,
}

/// One placeholder occurrence. Ports the `{ text, parsed, location }`
/// objects of `locate` in `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// The placeholder text.
    pub text: String,
    /// The parsed placeholder.
    pub parsed: ParsedPlaceholder,
    /// Where it is.
    pub location: Location,
}

impl Occurrence {
    /// Build from a detector hit. Ports `add` inside `locate` in
    /// `src/core/substitute.js`.
    pub fn from_hit(hit: DetectHit, location: Location) -> Self {
        todo!()
    }
}

/// The result of [`locate`]. Ports `{ occurrences, unscannable? }` in
/// `src/core/substitute.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocateResult {
    /// Every occurrence found, in scan order.
    pub occurrences: Vec<Occurrence>,
    /// Why the body could not be scanned, if it could not.
    pub unscannable: Option<String>,
}

/// The first header value named `name`, case-insensitively. Ports
/// `getHeader` in `src/core/substitute.js`.
pub fn get_header<'a>(req: &'a ProxyRequest, name: &str) -> Option<&'a str> {
    todo!()
}

/// Find every placeholder occurrence in the request (path, query keys and
/// values, header names and values, Basic auth parts, JSON/form/raw body,
/// including those a body parser hides) and label its location. Ports
/// `locate` in `src/core/substitute.js`.
pub fn locate(req: &ProxyRequest) -> LocateResult {
    todo!()
}

/// The first occurrence still in `req` whose nonce is one of `nonces`, or
/// `None`. Run on the request about to be sent. Ports `unsubstituted` in
/// `src/core/substitute.js`.
pub fn unsubstituted(req: &ProxyRequest, nonces: &[String]) -> Option<Occurrence> {
    todo!()
}

/// Whether an occurrence sits at a declared site; only raw (unencoded) text
/// ever does. Ports `matchesSite` in `src/core/substitute.js`.
pub fn matches_site(location: &Location, site: &Site) -> bool {
    todo!()
}

/// A short agent-readable description, e.g. `header authorization` or
/// `request body (base64-encoded)`. Ports `describeLocation` in
/// `src/core/substitute.js`.
pub fn describe_location(location: &Location) -> String {
    todo!()
}

/// Replace one placeholder with `secret` at one location already checked
/// against a declared site (not re-checked here). Returns a new request; the
/// input is untouched. Headers are written by index, query/form values
/// percent-encoded in place, JSON spliced into the one string literal, and
/// `content-length` updated for body changes. Fails (`AV_INTERNAL`) for a
/// region that is never a site or a JSON pointer with no string. Ports
/// `apply` in `src/core/substitute.js`.
pub fn apply(
    req: &ProxyRequest,
    location: &Location,
    placeholder_text: &str,
    secret: &SecretString,
) -> Result<ProxyRequest> {
    todo!()
}
