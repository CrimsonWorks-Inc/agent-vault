//! The gateway request pipeline: authenticate the session, route to a grant,
//! check policy, budget, rate, quota and spend, substitute placeholders, hold
//! for approval, proxy upstream, scrub the response. Ports
//! `src/daemon/pipeline.js`.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::VaultRef;

/// Hosts the gateway accepts in `Host`. Ports `ALLOWED_HOSTS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const ALLOWED_HOSTS: [&str; 6] = [
    "127.0.0.1",
    "localhost",
    "::1",
    "[::1]",
    "host.docker.internal",
    "host.containers.internal",
];

/// Request headers the gateway consumes and never forwards. Ports `CONSUMED`
/// (module-private) in `src/daemon/pipeline.js`.
pub const CONSUMED: [&str; 3] = ["av-session", "av-reason", "av-expect-placeholders"];

/// A held request nobody answered is denied after this. Ports
/// `PENDING_TTL_MS` (module-private) in `src/daemon/pipeline.js`.
pub const PENDING_TTL_MS: u64 = 15 * 60_000;
/// Replay window for an approved request. Ports `REPLAY_TTL_MS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const REPLAY_TTL_MS: u64 = 5 * 60_000;
/// How long decided approvals stay visible. Ports `DECIDED_TTL_MS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const DECIDED_TTL_MS: u64 = 60 * 60_000;
/// Approvals held at once. Ports `MAX_APPROVALS` (module-private) in
/// `src/daemon/pipeline.js`.
pub const MAX_APPROVALS: usize = 1000;
/// Denials remembered for `explainDenial`. Ports `MAX_DENIALS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const MAX_DENIALS: usize = 1000;
/// How long a denial stays explainable. Ports `DENIAL_TTL_MS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const DENIAL_TTL_MS: u64 = 60 * 60_000;
/// Largest decompressed response the scrubber reads. Ports
/// `MAX_DECOMPRESSED` (module-private) in `src/daemon/pipeline.js`.
pub const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
/// Largest buffered upstream response. Ports `MAX_RESPONSE_BYTES`
/// (module-private) in `src/daemon/pipeline.js`.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Largest single SSE event. Ports `MAX_EVENT_BYTES` (module-private) in
/// `src/daemon/pipeline.js`.
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
/// SSE JSON paths tracked for split-secret reassembly. Ports `MAX_SSE_PATHS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const MAX_SSE_PATHS: usize = 1024;
/// SSE index fields tracked per path. Ports `MAX_SSE_INDEXES`
/// (module-private) in `src/daemon/pipeline.js`.
pub const MAX_SSE_INDEXES: usize = 4;
/// Largest approval preview body. Ports `PREVIEW_MAX` (module-private) in
/// `src/daemon/pipeline.js`.
pub const PREVIEW_MAX: usize = 8192;

/// One proxied request as the gateway received it. Ports the `req` argument
/// shape `{method, path, query, headers, body, listener?}` of
/// `Pipeline.handle` in `src/daemon/pipeline.js`.
#[derive(Debug, Clone, Default)]
pub struct GatewayRequest {
    /// HTTP method.
    pub method: String,
    /// Path, beginning `/p/<slug>/`.
    pub path: String,
    /// Raw query string, without `?`.
    pub query: String,
    /// Headers in arrival order (names lower-cased).
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
    /// The listener id it arrived on, if not the loopback gateway.
    pub listener: Option<String>,
    /// Peer address, for listener CIDR checks.
    pub remote_address: Option<String>,
}

/// The gateway's answer. Ports the `{status, headers, body, requestId}`
/// result of `Pipeline.handle` in `src/daemon/pipeline.js`. A streamed
/// (SSE) body is represented by the daemon worker as it sees fit.
#[derive(Debug, Clone, Default)]
pub struct GatewayResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Scrubbed response body.
    pub body: Vec<u8>,
    /// The request id the agent can pass to `vault_explain_denial`.
    pub request_id: Option<String>,
}

/// Construction options. Ports the `opts` of `new Pipeline(vault, opts)` in
/// `src/daemon/pipeline.js` (`approvals`, `allowedHosts`, `fetchImpl`,
/// `approvalHoldMs`, `scrubBudget`, `expiryMs`, `extractHealth`); test hooks
/// beyond these are the daemon worker's to add.
#[derive(Debug, Clone, Default)]
pub struct PipelineOptions {
    /// Override for [`ALLOWED_HOSTS`]. Ports `opts.allowedHosts`.
    pub allowed_hosts: Option<Vec<String>>,
    /// How long `handle` waits for a decision before answering 202. Ports
    /// `opts.approvalHoldMs`.
    pub approval_hold_ms: u64,
    /// Scrubber layered-decode budget override. Ports `opts.scrubBudget`.
    pub scrub_budget: Option<usize>,
}

/// The gateway pipeline. Ports `class Pipeline` in
/// `src/daemon/pipeline.js`.
pub struct Pipeline {
    _private: (),
}

impl Pipeline {
    /// Ports `new Pipeline(vault, opts)` in `src/daemon/pipeline.js`.
    pub fn new(vault: VaultRef, opts: PipelineOptions) -> Self {
        todo!()
    }

    /// Handle one proxied request end to end. Ports `Pipeline.handle(req)`
    /// in `src/daemon/pipeline.js`.
    pub async fn handle(&self, req: GatewayRequest) -> GatewayResponse {
        todo!()
    }

    /// Would this request pass? Runs every check, sends nothing. Ports
    /// `Pipeline.preflight(req, { assumePlaceholder })` in
    /// `src/daemon/pipeline.js`.
    pub async fn preflight(
        &self,
        req: GatewayRequest,
        assume_placeholder: bool,
    ) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// The rule, hint and alternatives behind a remembered denial. Ports
    /// `Pipeline.explainDenial(requestId, sessionId)` in
    /// `src/daemon/pipeline.js`.
    pub fn explain_denial(&self, request_id: &str, session_id: &str) -> Option<Value> {
        todo!()
    }

    /// Live rate/quota/concurrency state for a grant. Ports
    /// `Pipeline.limitsFor(grantId)` in `src/daemon/pipeline.js`.
    pub fn limits_for(&self, grant_id: &str) -> Option<Value> {
        todo!()
    }

    /// Token/USD spend state for a grant. Ports `Pipeline.spendFor(grantId)`
    /// in `src/daemon/pipeline.js`.
    pub fn spend_for(&self, grant_id: &str) -> Option<Value> {
        todo!()
    }

    /// Deny every held approval matching `filter` (`{all}`, `{session_id}`,
    /// `{credential_id}`, …); returns how many. Ports
    /// `Pipeline.denyApprovals(filter, reason)` in `src/daemon/pipeline.js`.
    pub fn deny_approvals(&self, filter: &Value, reason: &str) -> usize {
        todo!()
    }

    /// Deny everything held. Ports `Pipeline.denyAllPending(reason)` in
    /// `src/daemon/pipeline.js`.
    pub fn deny_all_pending(&self, reason: &str) -> usize {
        todo!()
    }

    /// Revoke every session, deny everything waiting, optionally lock. Ports
    /// `Pipeline.panic({ reason, lock })` in `src/daemon/pipeline.js`.
    pub async fn panic(
        &self,
        reason: Option<String>,
        lock: bool,
    ) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// State of one approval (pending/approved/denied/expired). Ports
    /// `Pipeline.approvalStatus(approvalId)` in `src/daemon/pipeline.js`.
    pub fn approval_status(&self, approval_id: &str) -> Option<Value> {
        todo!()
    }

    /// Settle one held request. Ports
    /// `Pipeline.decideApproval(approvalId, granted)` in
    /// `src/daemon/pipeline.js`.
    pub fn decide_approval(
        &self,
        approval_id: &str,
        granted: bool,
    ) -> av_core::errors::Result<Value> {
        todo!()
    }

    /// Every held request, for `approvals` and the UI. Ports
    /// `Pipeline.pendingApprovals()` in `src/daemon/pipeline.js`.
    pub fn pending_approvals(&self) -> Vec<Value> {
        todo!()
    }
}

/// The scrubbed, untrusted preview of a held request's body, query and
/// headers shown to the human. Ports
/// `approvalPreview({ req, decision, substitutions, scrub })` in
/// `src/daemon/pipeline.js`.
pub fn approval_preview(
    req: &GatewayRequest,
    decision: &Value,
    substitutions: &BTreeMap<String, Value>,
    scrub: &dyn Fn(&str) -> String,
) -> Value {
    todo!()
}
