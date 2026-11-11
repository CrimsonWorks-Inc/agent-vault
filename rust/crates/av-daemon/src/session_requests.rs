//! Agent-proposed sessions held for a human: the proposal shape, elevation,
//! template resolution, and the persisted request store. Ports
//! `src/daemon/session-requests.js`.

use serde_json::Value;

use crate::VaultRef;

/// Session requests pending at once. Ports `MAX_PENDING` in
/// `src/daemon/session-requests.js`.
pub const MAX_PENDING: usize = 64;
/// A pending request nobody answered expires after this. Ports
/// `PENDING_TTL_MS` in `src/daemon/session-requests.js`.
pub const PENDING_TTL_MS: u64 = 30 * 60_000;
/// An approved request's token can be collected for this long. Ports
/// `COLLECT_TTL_MS` in `src/daemon/session-requests.js`.
pub const COLLECT_TTL_MS: u64 = 5 * 60_000;
/// Settled requests are kept visible for this long. Ports `SETTLED_TTL_MS`
/// in `src/daemon/session-requests.js`.
pub const SETTLED_TTL_MS: u64 = 30 * 60_000;
/// Requests stored at once, any state. Ports `MAX_ITEMS` (module-private) in
/// `src/daemon/session-requests.js`.
pub const MAX_ITEMS: usize = MAX_PENDING * 4;
/// Default session lifetime for a request, hours. Ports `DEFAULT_TTL_HOURS`
/// (module-private) in `src/daemon/session-requests.js`.
pub const DEFAULT_TTL_HOURS: u64 = 8;

/// The fields an agent may propose. Ports `FIELDS` (module-private) in
/// `src/daemon/session-requests.js`.
pub const FIELDS: [&str; 15] = [
    "cred",
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

/// The fields only the owner may set. Ports `OWNER_FIELDS` in
/// `src/daemon/session-requests.js`.
pub const OWNER_FIELDS: [&str; 2] = ["approval", "infinite"];

/// What a template override may name. Ports `TEMPLATE_OVERRIDES`
/// (module-private) in `src/daemon/session-requests.js`.
pub const TEMPLATE_OVERRIDES: [&str; 9] = [
    "methods",
    "paths",
    "budget",
    "uses",
    "grant_ttl_minutes",
    "approval",
    "ttl_hours",
    "infinite",
    "label",
];

/// The proposal: only [`FIELDS`] that are set. Ports `proposalOf(input)` in
/// `src/daemon/session-requests.js`.
pub fn proposal_of(input: &Value) -> Value {
    todo!()
}

/// A human's overrides: [`FIELDS`] plus [`OWNER_FIELDS`]. Ports
/// `overridesOf(input)` in `src/daemon/session-requests.js`.
pub fn overrides_of(input: &Value) -> Value {
    todo!()
}

/// Why a human's overrides cannot be applied as sent, or `None`. Ports
/// `overridesProblem(input)` in `src/daemon/session-requests.js`.
pub fn overrides_problem(input: Option<&Value>) -> Option<String> {
    todo!()
}

/// The field names and list lengths of a proposal, never a value (C25).
/// Ports `shapeOf(p)` in `src/daemon/session-requests.js`.
pub fn shape_of(p: &Value) -> Value {
    todo!()
}

/// Names of the fields a human's decision changed. Ports
/// `narrowedOf(proposal, final)` in `src/daemon/session-requests.js`.
pub fn narrowed_of(proposal: &Value, final_: &Value) -> Vec<String> {
    todo!()
}

/// Why a session spec needs fresh presence (`infinite`,
/// `approval_auto_writes`, …); empty when it does not. Fail-closed. Ports
/// `elevationOf(spec)` in `src/daemon/session-requests.js`.
pub fn elevation_of(spec: &Value) -> Vec<String> {
    todo!()
}

/// A stable hash of exactly what was proposed. Ports
/// `fingerprint(proposal)` in `src/daemon/session-requests.js`.
pub fn fingerprint(proposal: &Value) -> String {
    todo!()
}

/// One-line human summary of a proposal. Ports `summarize(p)` in
/// `src/daemon/session-requests.js`.
pub fn summarize(p: &Value) -> String {
    todo!()
}

/// The profile's default budget for a credential slug, if it has one. Ports
/// the `budgetDefault` option of `resolveTemplate` in
/// `src/daemon/session-requests.js`.
pub type BudgetDefault<'a> = &'a dyn Fn(&str) -> Option<u64>;

/// Apply narrowing-only overrides to a stored template, producing a
/// session-create spec; refuses any widening. Ports
/// `resolveTemplate(template, overrides, { budgetDefault })` in
/// `src/daemon/session-requests.js`.
pub fn resolve_template(
    template: &Value,
    overrides: &Value,
    budget_default: Option<BudgetDefault<'_>>,
) -> av_core::errors::Result<Value> {
    todo!()
}

/// The grant specs of a session-create input, whichever form it has. Ports
/// `grantSpecsOf(spec)` in `src/daemon/session-requests.js`.
pub fn grant_specs_of(spec: &Value) -> Vec<Value> {
    todo!()
}

/// The credentials a template covers, in order. Ports
/// `templateCreds(spec)` in `src/daemon/session-requests.js`.
pub fn template_creds(spec: &Value) -> Vec<String> {
    todo!()
}

/// One line per template, joined with ` + `. Ports `templateSummary(spec)`
/// in `src/daemon/session-requests.js`.
pub fn template_summary(spec: &Value) -> String {
    todo!()
}

/// The persisted session-request store. Ports `class SessionRequests` in
/// `src/daemon/session-requests.js`.
pub struct SessionRequests {
    _private: (),
}

impl SessionRequests {
    /// Load the store (from the vault when there is one). Ports
    /// `new SessionRequests(vault)` in `src/daemon/session-requests.js`.
    pub fn new(vault: Option<VaultRef>) -> Self {
        todo!()
    }

    /// Hold a new request; refuses owner fields and past [`MAX_PENDING`].
    /// Returns the record (with its one-time collect secret). Ports
    /// `SessionRequests.propose({ proposal, reason, fromTemplate })` in
    /// `src/daemon/session-requests.js`.
    pub fn propose(
        &self,
        proposal: &Value,
        reason: Option<&str>,
        from_template: bool,
    ) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// One request by id, after sweeping expired ones. Ports
    /// `SessionRequests.get(id)` in `src/daemon/session-requests.js`.
    pub fn get(&self, id: &str) -> Option<Value> {
        todo!()
    }

    /// Save after a settle or collect. Ports `SessionRequests.persist()` in
    /// `src/daemon/session-requests.js`.
    pub fn persist(&self) {
        todo!()
    }

    /// Every pending request. Ports `SessionRequests.pending()` in
    /// `src/daemon/session-requests.js`.
    pub fn pending(&self) -> Vec<Value> {
        todo!()
    }

    /// Whether `secret` collects this record (constant-time over SHA-256
    /// digests). Ports `static SessionRequests.mayCollect(record, secret)` in
    /// `src/daemon/session-requests.js`.
    pub fn may_collect(record: &Value, secret: &str) -> bool {
        todo!()
    }

    /// The public view of a record, never the token. Ports
    /// `static SessionRequests.redact(r)` in `src/daemon/session-requests.js`.
    pub fn redact(record: &Value) -> Value {
        todo!()
    }
}
