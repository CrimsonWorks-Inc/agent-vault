//! Ports `src/pending.js`: everything waiting for a human, and how to
//! describe it, once, for the CLI and the web UI alike.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A kind of decision. Ports the `kind` values of `SOURCES` in
/// `src/pending.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingKind {
    /// A held request (one call).
    Request,
    /// A session request (hours of access).
    Session,
}

/// Where one kind of decision is listed. Ports the entries of `SOURCES` in
/// `src/pending.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSource {
    /// The kind.
    pub kind: PendingKind,
    /// The control route that lists it.
    pub path: &'static str,
}

/// Where to look. Ports `SOURCES` in `src/pending.js`.
pub const SOURCES: [PendingSource; 2] = [
    PendingSource {
        kind: PendingKind::Request,
        path: "/v1/approvals",
    },
    PendingSource {
        kind: PendingKind::Session,
        path: "/v1/session-requests",
    },
];

/// The dimensions a human may narrow on a session request. Ports the
/// `narrowable` list in `describe` in `src/pending.js`.
pub const SESSION_NARROWABLE: [&str; 14] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "rate",
    "max_concurrent",
    "quota",
    "routes",
    "payload",
    "redirects",
    "spend_tokens",
    "spend_usd",
    "grant_ttl_minutes",
];

/// What only the owner can add to a session request. Ports the
/// `owner_settable` list in `describe` in `src/pending.js`.
pub const SESSION_OWNER_SETTABLE: [&str; 2] = ["approval", "infinite"];

/// The caution shown on a session request. Ports the `caution` literal in
/// `describe` in `src/pending.js`.
pub const SESSION_CAUTION: &str = "This grants hours of access, not one call.";

/// The route that answers a decision. Ports `decide` in `describe` in
/// `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideRoute {
    /// Control route.
    pub path: String,
    /// The body key the id goes under.
    #[serde(rename = "idField")]
    pub id_field: String,
}

/// One decision, in the terms a human needs to make it. Session items carry
/// `proposal`; request items carry `grant_id` and `preview` (both possibly
/// null, and then serialized as null). Ports the objects `describe` returns
/// in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingItem {
    /// Id.
    pub id: String,
    /// Kind.
    pub kind: PendingKind,
    /// The summary.
    pub headline: Value,
    /// Whatever the agent typed. Shown, never believed.
    pub claim: Option<String>,
    /// ISO time.
    pub created_at: Value,
    /// A warning, for sessions.
    pub caution: Option<String>,
    /// Narrowable dimensions.
    pub narrowable: Vec<String>,
    /// Owner-only additions.
    pub owner_settable: Vec<String>,
    /// The agent's proposal (session items).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<Value>,
    /// The grant a held request would spend (request items; null allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<Option<String>>,
    /// Scrubbed preview (request items; null allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    /// Where to answer.
    pub decide: DecideRoute,
}

/// One decision from a raw route row. Ports `describe` in `src/pending.js`.
pub fn describe(kind: PendingKind, raw: &Value) -> PendingItem {
    todo!()
}

/// Everything waiting, oldest first. `get(path)` is the caller's transport;
/// a source it cannot read (`None`) is treated as empty. Sync: an async
/// caller fetches each of [`SOURCES`] itself and uses [`collect_pending`].
/// Ports `fetchPending` in `src/pending.js`.
pub fn fetch_pending<F>(get: F) -> Vec<PendingItem>
where
    F: FnMut(&str) -> Option<Vec<Value>>,
{
    todo!()
}

/// Describe already-fetched rows per kind and sort oldest first. No JS
/// function: the body of `fetchPending` in `src/pending.js` without the
/// transport.
pub fn collect_pending(rows: Vec<(PendingKind, Vec<Value>)>) -> Vec<PendingItem> {
    todo!()
}

/// The control call that answers one decision. Ports the return value of
/// `decision` in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionCall {
    /// Route.
    pub path: String,
    /// `{ <idField>: id, granted, overrides? }`.
    pub body: Value,
}

/// The call that answers one decision; overrides are included only when
/// non-empty. The verdict is a `bool` by type (the JS throws a TypeError
/// otherwise). Ports `decision` in `src/pending.js`.
pub fn decision(
    item: &PendingItem,
    granted: bool,
    overrides: Option<&Map<String, Value>>,
) -> DecisionCall {
    todo!()
}

/// The keys `parse_overrides` reads. Ports `OVERRIDE_KEYS` in
/// `src/pending.js`.
pub const OVERRIDE_KEYS: [&str; 23] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "ttl_minutes",
    "ttl-minutes",
    "grant_ttl_minutes",
    "grant-ttl",
    "grant_ttl",
    "max_concurrent",
    "concurrency",
    "redirects",
    "spend_tokens",
    "spend-tokens",
    "spend_usd",
    "spend-usd",
    "rate",
    "quota",
    "routes",
    "route",
    "payload",
    "approval",
    "infinite",
];

/// A narrowing value that cannot be one. Never dropped: a dropped narrowing
/// approves what the agent asked for. Ports the `TypeError` with `field`
/// that `parseOverrides` throws in `src/pending.js`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {why}")]
pub struct OverrideError {
    /// The key at fault.
    pub field: String,
    /// Why.
    pub why: String,
}

/// Narrowing flags, normalized. Serializes with only the keys set. Ports
/// the `out` object of `parseOverrides` in `src/pending.js`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Overrides {
    /// Upper-cased methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    /// Path globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<f64>,
    /// Placeholder uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<f64>,
    /// Session lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_minutes: Option<f64>,
    /// Grant lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ttl_minutes: Option<f64>,
    /// Concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<f64>,
    /// Redirects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirects: Option<f64>,
    /// Token spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_tokens: Option<f64>,
    /// USD spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_usd: Option<f64>,
    /// Rate (`60/min`, passed through for the daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Value>,
    /// Quota (passed through).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Value>,
    /// Routes (JSON or `METHODS:/path` pairs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Value>,
    /// Payload rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Approval mode (owner only, validated by the daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    /// Never expires (owner only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infinite: Option<bool>,
}

/// Parse narrowing flags the same way wherever they are typed; an unknown
/// key or an unusable value is an error naming the field. Ports
/// `parseOverrides` in `src/pending.js`.
pub fn parse_overrides(args: &Map<String, Value>) -> Result<Overrides, OverrideError> {
    todo!()
}

/// Record an approved session where local clients look: calls `remember`
/// with `answered.session` when the item is a session and it carries a
/// token, and returns it. Ports `collectApproved` in `src/pending.js`.
pub fn collect_approved<F>(item: &PendingItem, answered: &Value, remember: F) -> Option<Value>
where
    F: FnOnce(&Value),
{
    todo!()
}

/// What a human granted, in their own words (`session for <cred> · …`).
/// Takes the raw grant summary. Ports `describeGranted` in `src/pending.js`.
pub fn describe_granted(granted: &Value) -> String {
    todo!()
}

/// Most decisions one act of presence may answer. Ports
/// `MAX_BULK_DECISIONS` in `src/pending.js`.
pub const MAX_BULK_DECISIONS: usize = 25;

/// Keys a bulk decision may have. Ports `DECISION_KEYS` in `src/pending.js`.
pub const DECISION_KEYS: [&str; 4] = ["id", "kind", "granted", "overrides"];

/// Why a bulk decision list is not usable, or none. Validation only: the
/// signature binds the bytes as sent. Ports `checkDecisions` in
/// `src/pending.js`.
pub fn check_decisions(raw: &Value) -> Option<String> {
    todo!()
}
