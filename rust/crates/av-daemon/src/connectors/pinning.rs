//! TLS public-key pinning for upstream requests: the network and TLS half.
//! Ports `src/connectors/pinning.js`.
//!
//! The pure half of `pinning.js` (`PIN_RE`, `pinListState`, `urlHostOf`,
//! `hostHeaderMatches`, `pinsFor`) lives in `av_core::pins` and will be
//! re-exported here once that module is settled. `urlIdentity` is small and
//! pure but takes a parsed URL, so it stays here.

use serde_json::Value;

/// Upstream request timeout. Ports `UPSTREAM_TIMEOUT_MS` (module-private) in
/// `src/connectors/pinning.js`.
pub const UPSTREAM_TIMEOUT_MS: u64 = 30_000;
/// Most certificates walked up a presented chain. Ports `CHAIN_HOPS`
/// (module-private) in `src/connectors/pinning.js`.
pub const CHAIN_HOPS: usize = 16;
/// Most pins per credential host. Ports `MAX_PINS` (module-private) in
/// `src/connectors/pinning.js`.
pub const MAX_PINS: usize = 4;

/// `sha256/<base64 SHA-256 of the DER SPKI>` of one DER certificate. Ports
/// `spkiOf(x509Cert)` in `src/connectors/pinning.js`.
pub fn spki_of(der_cert: &[u8]) -> Result<String, String> {
    todo!()
}

/// The pins of every certificate the peer presented, leaf first, whether or
/// not the chain verified. Ports `chainPins(tlsSocket)` in
/// `src/connectors/pinning.js`.
pub fn chain_pins(presented: &[Vec<u8>]) -> Vec<String> {
    todo!()
}

/// The pins of a chain that verified against the trust store, or `None`
/// when it did not. Ports `verifiedChainPins(tlsSocket)` in
/// `src/connectors/pinning.js`.
pub fn verified_chain_pins(presented: &[Vec<u8>], verified: bool) -> Option<Vec<String>> {
    todo!()
}

/// The URL's host as a certificate names it: no IPv6 brackets. Ports
/// `urlIdentity(parsed)` in `src/connectors/pinning.js`.
pub fn url_identity(parsed: &url::Url) -> String {
    todo!()
}

/// A pin check failed. Ports the error made by `pinError(presented,
/// reason)` (module-private) in `src/connectors/pinning.js`; code
/// `AV_PIN_MISMATCH`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("certificate pin mismatch")]
pub struct PinMismatch {
    /// Pins the peer presented.
    pub presented: Vec<String>,
    /// Why, e.g. `pin_format`, `unverified_chain`.
    pub reason: Option<String>,
}

/// One upstream request. Ports the argument of
/// `pinnedRequest({ url, method, headers, body, pins })` in
/// `src/connectors/pinning.js`.
#[derive(Debug, Clone, Default)]
pub struct PinnedRequest {
    /// Absolute upstream URL.
    pub url: String,
    /// HTTP method.
    pub method: String,
    /// Headers to send.
    pub headers: Vec<(String, String)>,
    /// Body to send.
    pub body: Vec<u8>,
    /// `None` or empty: ordinary CA verification. Otherwise an exact leaf
    /// pin stands in for CA trust; any other pin also needs a verified chain.
    pub pins: Option<Vec<String>>,
}

/// The upstream's answer head and body. Ports the `{ status, headers, res }`
/// result of `pinnedRequest` in `src/connectors/pinning.js`.
#[derive(Debug, Clone, Default)]
pub struct UpstreamResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body (the daemon worker may turn this into a stream).
    pub body: Vec<u8>,
}

/// Errors from [`pinned_request`].
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The presented key was not pinned.
    #[error(transparent)]
    Pin(#[from] PinMismatch),
    /// Connect, TLS or I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Send one request upstream, checking pins after the handshake and before
/// any application byte. Drop-in for the pipeline's `defaultUpstream`. Ports
/// `pinnedRequest(...)` in `src/connectors/pinning.js`.
pub async fn pinned_request(req: PinnedRequest) -> Result<UpstreamResponse, UpstreamError> {
    todo!()
}

/// The certificates a host presents, for a human to read before pinning:
/// `[{ subject, issuer, spki, not_after }]`. Sends no credential and no HTTP
/// request. Ports `fetchChainPins(host, port)` in
/// `src/connectors/pinning.js`.
pub async fn fetch_chain_pins(host: &str, port: u16) -> std::io::Result<Vec<Value>> {
    todo!()
}
