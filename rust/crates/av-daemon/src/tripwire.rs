//! Tripwires (F16): a run of suspicious denials ends the session that made
//! them. Ports `src/daemon/tripwire.js`.

use std::sync::Weak;

use serde::{Deserialize, Serialize};

use crate::pipeline::Pipeline;
use crate::VaultRef;

/// One tripwire rule. Ports the rule objects of `DEFAULT_RULES` in
/// `src/daemon/tripwire.js` (and the shape `POST /v1/tripwires` stores).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwireRule {
    /// Rule id.
    pub id: String,
    /// `AV_*` codes that count, or absent when `rule_prefix` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<Vec<String>>,
    /// Denial rule-name prefix that counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_prefix: Option<String>,
    /// Denials within the window that trip it.
    pub threshold: u32,
    /// Window in seconds.
    pub window_s: u32,
    /// `revoke_session`, `quarantine_credential` or `panic`.
    pub action: String,
}

/// The rules used when tripwires are on and none were saved: `(id, codes,
/// rule_prefix, threshold, window_s, action)`. Ports `DEFAULT_RULES` in
/// `src/daemon/tripwire.js`.
#[allow(clippy::type_complexity)]
pub const DEFAULT_RULES: [(&str, &[&str], Option<&str>, u32, u32, &str); 4] = [
    ("replay", &["AV_PH_REPLAY"], None, 1, 600, "revoke_session"),
    (
        "bad_location",
        &["AV_BAD_LOCATION"],
        None,
        3,
        600,
        "revoke_session",
    ),
    (
        "cross_session",
        &["AV_PH_CROSS_SESSION", "AV_PH_WRONG_CONNECTOR"],
        None,
        3,
        600,
        "revoke_session",
    ),
    (
        "deny_paths",
        &[],
        Some("deny_paths:"),
        5,
        600,
        "revoke_session",
    ),
];

/// [`DEFAULT_RULES`] as rule values. Ports `DEFAULT_RULES` in
/// `src/daemon/tripwire.js`.
pub fn default_rules() -> Vec<TripwireRule> {
    todo!()
}

/// One authenticated denial fed to [`Tripwires::observe`]. Ports the
/// `{ sessionId, credentialId, code, rule, preflight }` argument in
/// `src/daemon/tripwire.js`.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    /// Session that made the request.
    pub session_id: String,
    /// Credential it was for.
    pub credential_id: Option<String>,
    /// `AV_*` code of the denial.
    pub code: String,
    /// Rule name of the denial.
    pub rule: Option<String>,
    /// Preflight denials are never counted.
    pub preflight: bool,
}

/// Per-session denial counters. Ports `class Tripwires` in
/// `src/daemon/tripwire.js`.
pub struct Tripwires {
    _private: (),
}

impl Tripwires {
    /// Ports `new Tripwires(vault, pipeline)` in `src/daemon/tripwire.js`.
    pub fn new(vault: VaultRef, pipeline: Weak<Pipeline>) -> Self {
        todo!()
    }

    /// Forget a session's counters. Ports `Tripwires.reset(sessionId)` in
    /// `src/daemon/tripwire.js`.
    pub fn reset(&self, session_id: &str) {
        todo!()
    }

    /// Count one denial and fire the rule's action when it trips; returns the
    /// action taken, if any. Ports `Tripwires.observe(...)` in
    /// `src/daemon/tripwire.js`.
    pub fn observe(&self, observation: &Observation) -> Option<String> {
        todo!()
    }
}
