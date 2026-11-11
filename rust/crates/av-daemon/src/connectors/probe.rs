//! A connector's fixed read-only probe (`cred test`). Ports
//! `src/connectors/probe.js`.

use serde_json::Value;

use crate::VaultRef;

/// One probe per credential per window. Ports `PROBE_WINDOW_MS`
/// (module-private) in `src/connectors/probe.js`.
pub const PROBE_WINDOW_MS: u64 = 60_000;
/// Most response bytes read before closing. Ports `DRAIN_LIMIT_BYTES`
/// (module-private) in `src/connectors/probe.js`.
pub const DRAIN_LIMIT_BYTES: usize = 64 * 1024;
/// Longest the drain waits. Ports `DRAIN_TIMEOUT_MS` (module-private) in
/// `src/connectors/probe.js`.
pub const DRAIN_TIMEOUT_MS: u64 = 2_000;

/// The probe throttle's monotonic clock in milliseconds; tests replace it.
/// Ports `probeClock.now` in `src/connectors/probe.js`.
pub fn probe_clock_now() -> u64 {
    todo!()
}

/// The probe's result. Ports the `{ ok, status, http_status, latency_ms,
/// scopes, ratelimit_remaining, observed_expires_at, checked_at }` result of
/// `runProbe` in `src/connectors/probe.js`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProbeResult {
    /// Whether the upstream accepted the credential.
    pub ok: bool,
    /// Health status word.
    pub status: String,
    /// Upstream HTTP status, if it answered.
    pub http_status: Option<u16>,
    /// Round trip.
    pub latency_ms: u64,
    /// Scopes the upstream reported.
    pub scopes: Option<Vec<String>>,
    /// Rate-limit remaining the upstream reported.
    pub ratelimit_remaining: Option<u64>,
    /// Token expiry the upstream reported.
    pub observed_expires_at: Option<String>,
    /// When, ISO 8601.
    pub checked_at: String,
}

/// Run the credential's fixed read-only probe. A caller-supplied path,
/// method or body is never used (that is the point). Ports
/// `runProbe({ vault, cred, profile, upstream })` in
/// `src/connectors/probe.js`.
pub async fn run_probe(
    vault: &VaultRef,
    cred: &Value,
    profile: &Value,
) -> av_core::errors::Result<ProbeResult> {
    todo!()
}
