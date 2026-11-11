//! The error registry. Ports `src/core/errors.js`.
//!
//! Codes and exit codes are frozen for 1.x: adding is allowed, changing the
//! meaning of an existing one is not. Every denial an agent can see carries a
//! code, a rule name, a hint and a concrete next step.

use serde::{Deserialize, Serialize};

/// Process exit codes. Ports `EXIT` in `src/core/errors.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Exit {
    /// `EXIT.OK`
    Ok = 0,
    /// `EXIT.FAILURE`
    Failure = 1,
    /// `EXIT.USAGE`
    Usage = 2,
    /// `EXIT.DAEMON_UNREACHABLE`
    DaemonUnreachable = 3,
    /// `EXIT.LOCKED`
    Locked = 4,
    /// `EXIT.PRESENCE`
    Presence = 5,
    /// `EXIT.POLICY_DENIED`
    PolicyDenied = 6,
    /// `EXIT.NOT_FOUND`
    NotFound = 7,
    /// `EXIT.PLACEHOLDER`
    Placeholder = 8,
    /// `EXIT.SESSION`
    Session = 9,
    /// `EXIT.APPROVAL`
    Approval = 10,
    /// `EXIT.CONFLICT`
    Conflict = 11,
    /// `EXIT.UPSTREAM`
    Upstream = 12,
    /// `EXIT.NOT_SETUP`
    NotSetup = 13,
    /// `EXIT.HEADLESS_LOCKED`
    HeadlessLocked = 14,
    /// `EXIT.VERSION_SKEW`
    VersionSkew = 15,
    /// `EXIT.CLIENT_CERT`
    ClientCert = 16,
    /// `EXIT.LISTENER`
    Listener = 17,
    /// `EXIT.INTERNAL`
    Internal = 70,
}

impl Exit {
    /// The numeric process exit status. Ports the values of `EXIT`.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Every `AV_*` code. The registered ones are the keys of `CODES` in
/// `src/core/errors.js`; the rest are codes the JS throws with
/// `new VaultError(code, …)` without registering them, which therefore take the
/// `AV_INTERNAL` spec (`CODES[code] || CODES.AV_INTERNAL`) while keeping their
/// own code string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// `AV_NO_GRANT`
    #[serde(rename = "AV_NO_GRANT")]
    NoGrant,
    /// `AV_POLICY_DENIED`
    #[serde(rename = "AV_POLICY_DENIED")]
    PolicyDenied,
    /// `AV_BAD_LOCATION`
    #[serde(rename = "AV_BAD_LOCATION")]
    BadLocation,
    /// `AV_ENCODED_BODY`
    #[serde(rename = "AV_ENCODED_BODY")]
    EncodedBody,
    /// `AV_UNSCANNABLE`
    #[serde(rename = "AV_UNSCANNABLE")]
    Unscannable,
    /// `AV_BROWSER_ORIGIN`
    #[serde(rename = "AV_BROWSER_ORIGIN")]
    BrowserOrigin,
    /// `AV_PH_MALFORMED`
    #[serde(rename = "AV_PH_MALFORMED")]
    PhMalformed,
    /// `AV_PH_EXHAUSTED`
    #[serde(rename = "AV_PH_EXHAUSTED")]
    PhExhausted,
    /// `AV_PH_STALE`
    #[serde(rename = "AV_PH_STALE")]
    PhStale,
    /// `AV_PH_REPLAY`
    #[serde(rename = "AV_PH_REPLAY")]
    PhReplay,
    /// `AV_PH_CROSS_SESSION`
    #[serde(rename = "AV_PH_CROSS_SESSION")]
    PhCrossSession,
    /// `AV_PH_WRONG_CONNECTOR`
    #[serde(rename = "AV_PH_WRONG_CONNECTOR")]
    PhWrongConnector,
    /// `AV_SESSION_EXPIRED`
    #[serde(rename = "AV_SESSION_EXPIRED")]
    SessionExpired,
    /// `AV_SESSION_REVOKED`
    #[serde(rename = "AV_SESSION_REVOKED")]
    SessionRevoked,
    /// `AV_SESSION_REQUIRED`
    #[serde(rename = "AV_SESSION_REQUIRED")]
    SessionRequired,
    /// `AV_LOCKED`
    #[serde(rename = "AV_LOCKED")]
    Locked,
    /// `AV_REMOTE_FORBIDDEN`
    #[serde(rename = "AV_REMOTE_FORBIDDEN")]
    RemoteForbidden,
    /// `AV_PRESENCE_REQUIRED`
    #[serde(rename = "AV_PRESENCE_REQUIRED")]
    PresenceRequired,
    /// `AV_PRESENCE_DENIED`
    #[serde(rename = "AV_PRESENCE_DENIED")]
    PresenceDenied,
    /// `AV_RATE_LIMITED`
    #[serde(rename = "AV_RATE_LIMITED")]
    RateLimited,
    /// `AV_UPSTREAM_UNREACHABLE`
    #[serde(rename = "AV_UPSTREAM_UNREACHABLE")]
    UpstreamUnreachable,
    /// `AV_QUOTA_EXCEEDED`
    #[serde(rename = "AV_QUOTA_EXCEEDED")]
    QuotaExceeded,
    /// `AV_GRANT_EXPIRED`
    #[serde(rename = "AV_GRANT_EXPIRED")]
    GrantExpired,
    /// `AV_QUARANTINED`
    #[serde(rename = "AV_QUARANTINED")]
    Quarantined,
    /// `AV_PIN_MISMATCH`
    #[serde(rename = "AV_PIN_MISMATCH")]
    PinMismatch,
    /// `AV_MCP_PROTOCOL`
    #[serde(rename = "AV_MCP_PROTOCOL")]
    McpProtocol,
    /// `AV_MCP_SESSION_UNKNOWN`
    #[serde(rename = "AV_MCP_SESSION_UNKNOWN")]
    McpSessionUnknown,
    /// `AV_NOT_FOUND`
    #[serde(rename = "AV_NOT_FOUND")]
    NotFound,
    /// `AV_INTERNAL`
    #[serde(rename = "AV_INTERNAL")]
    Internal,
    /// `AV_TOO_MANY_REQUESTS` (unregistered; thrown in `src/daemon/server.js`).
    #[serde(rename = "AV_TOO_MANY_REQUESTS")]
    TooManyRequests,
    /// `AV_APPROVAL_PENDING` (unregistered; used by the CLI and session requests).
    #[serde(rename = "AV_APPROVAL_PENDING")]
    ApprovalPending,
    /// `AV_OWNER_ONLY` (unregistered; `src/ui/server.js`).
    #[serde(rename = "AV_OWNER_ONLY")]
    OwnerOnly,
    /// `AV_BAD_CURSOR` (`PagingError` in `src/ui/list-paging.js`).
    #[serde(rename = "AV_BAD_CURSOR")]
    BadCursor,
    /// `AV_BAD_LIMIT` (`PagingError` in `src/ui/list-paging.js`).
    #[serde(rename = "AV_BAD_LIMIT")]
    BadLimit,
}

/// One row of the registry: `code -> { http, exit, audit, consumes, hint }`.
/// Ports the value shape of `CODES` in `src/core/errors.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSpec {
    /// The code string, e.g. `"AV_NO_GRANT"`.
    pub code: &'static str,
    /// HTTP status for the problem+json response.
    pub http: u16,
    /// CLI exit code.
    pub exit: Exit,
    /// Audit record kind written for this denial.
    pub audit: &'static str,
    /// Whether the denial consumes a placeholder use.
    pub consumes: bool,
    /// Default hint shown to the agent.
    pub hint: &'static str,
}

macro_rules! spec {
    ($code:literal, $http:literal, $exit:ident, $audit:literal, $consumes:literal, $hint:literal) => {
        CodeSpec {
            code: $code,
            http: $http,
            exit: Exit::$exit,
            audit: $audit,
            consumes: $consumes,
            hint: $hint,
        }
    };
}

/// The registered codes, verbatim from `CODES` in `src/core/errors.js`.
pub const CODES: &[CodeSpec] = &[
    spec!("AV_NO_GRANT", 403, PolicyDenied, "request.denied", false,
        "This session has no grant for that destination."),
    spec!("AV_POLICY_DENIED", 403, PolicyDenied, "request.denied", false,
        "The grant exists but this method or path is outside it."),
    spec!("AV_BAD_LOCATION", 403, PolicyDenied, "placeholder.misplaced", false,
        "A placeholder appeared somewhere it is never substituted. Put it only where the usage says."),
    spec!("AV_ENCODED_BODY", 422, PolicyDenied, "request.denied", false,
        "Request bodies must not be compressed; send identity encoding."),
    spec!("AV_UNSCANNABLE", 502, Upstream, "response.unscannable", true,
        "The upstream response could not be decoded for scrubbing, so it was not returned."),
    spec!("AV_BROWSER_ORIGIN", 403, PolicyDenied, "request.denied", false,
        "Requests carrying Origin or Sec-Fetch-Site are refused; this endpoint is not for browsers."),
    spec!("AV_PH_MALFORMED", 400, Placeholder, "placeholder.denied", false,
        "The placeholder was altered in transit."),
    spec!("AV_PH_EXHAUSTED", 401, Placeholder, "placeholder.exhausted_reuse", false,
        "This placeholder has no uses left. A successor is in the next_placeholder field."),
    spec!("AV_PH_STALE", 401, Placeholder, "placeholder.stale", false,
        "This placeholder is no longer live. Fetch a new one; nothing is wrong."),
    spec!("AV_PH_REPLAY", 403, Placeholder, "placeholder.replay", false,
        "This placeholder was burned or revoked. Reuse is treated as hostile."),
    spec!("AV_PH_CROSS_SESSION", 403, Placeholder, "placeholder.cross_session", false,
        "That placeholder belongs to a different session."),
    spec!("AV_PH_WRONG_CONNECTOR", 403, Placeholder, "placeholder.cross_grant", false,
        "That placeholder is for a different credential than the route it was sent to."),
    spec!("AV_SESSION_EXPIRED", 401, Session, "session.ended", false,
        "The session expired. A human must start a new one."),
    spec!("AV_SESSION_REVOKED", 401, Session, "session.ended", false,
        "The session was revoked."),
    spec!("AV_SESSION_REQUIRED", 401, Session, "request.denied", false,
        "Send the session token in Authorization: Bearer, or a placeholder at a declared header site."),
    spec!("AV_LOCKED", 423, Locked, "request.denied", false,
        "The vault is locked. A human must unlock it."),
    spec!("AV_REMOTE_FORBIDDEN", 403, PolicyDenied, "remote.denied", false,
        "That operation is never reachable from a network listener."),
    spec!("AV_PRESENCE_REQUIRED", 401, Presence, "presence.required", false,
        "This change needs a human; confirm your passphrase."),
    spec!("AV_PRESENCE_DENIED", 403, Presence, "presence.denied", false,
        "The passphrase did not verify."),
    spec!("AV_RATE_LIMITED", 429, Presence, "presence.throttled", false,
        "Too many failed attempts. Wait for the backoff to expire and try again."),
    spec!("AV_UPSTREAM_UNREACHABLE", 502, Upstream, "request.upstream_failed", false,
        "The upstream could not be reached. If the failure happened before a connection existed, the placeholder use was refunded; the `refunded` field says which."),
    spec!("AV_QUOTA_EXCEEDED", 429, PolicyDenied, "request.throttled", false,
        "A rate, concurrency or quota limit on this grant was reached. Wait retry_after seconds and try again."),
    spec!("AV_GRANT_EXPIRED", 401, Session, "request.denied", false,
        "This grant's lifetime ran out; the session may still hold others. Ask a human for a new grant."),
    spec!("AV_QUARANTINED", 403, PolicyDenied, "request.denied", false,
        "A human quarantined this credential. Nothing can use it until they release it."),
    spec!("AV_PIN_MISMATCH", 502, Upstream, "request.pin_mismatch", false,
        "The upstream presented a certificate that matches none of the pins for this host. Nothing was sent."),
    spec!("AV_MCP_PROTOCOL", 400, Failure, "mcp.protocol_rejected", false,
        "Unsupported or missing MCP-Protocol-Version."),
    spec!("AV_MCP_SESSION_UNKNOWN", 404, Failure, "mcp.protocol_rejected", false,
        "Unknown Mcp-Session-Id; call initialize again."),
    spec!("AV_NOT_FOUND", 404, NotFound, "request.denied", false,
        "No such object."),
    spec!("AV_INTERNAL", 500, Internal, "request.denied", false,
        "Internal error; see the audit log."),
];

impl ErrorCode {
    /// The wire string, e.g. `"AV_NO_GRANT"`. Ports the `code` keys of `CODES`.
    pub fn as_str(self) -> &'static str {
        todo!()
    }

    /// Parse a wire string. Unknown strings return `None`. Ports the
    /// `CODES[code]` lookup in `src/core/errors.js` / `src/cli/index.js`.
    pub fn parse(code: &str) -> Option<Self> {
        todo!()
    }

    /// The registry row for this code, falling back to `AV_INTERNAL` for
    /// unregistered codes exactly as `CODES[code] || CODES.AV_INTERNAL` does in
    /// the `VaultError` constructor (`src/core/errors.js`).
    pub fn spec(self) -> &'static CodeSpec {
        todo!()
    }
}

/// Extra fields for a denial. Ports the `extra` argument of the `VaultError`
/// constructor in `src/core/errors.js`
/// (`{ hint, rule, next, requestId, nextPlaceholder, factors, refunded,
/// retryAfter | retry_after_s }`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DenyExtra {
    /// Overrides the registry hint.
    pub hint: Option<String>,
    /// The rule name that refused the request.
    pub rule: Option<String>,
    /// The concrete next step (a command or tool call).
    pub next: Option<String>,
    /// The request id, so `vault_explain_denial` can find it.
    pub request_id: Option<String>,
    /// A successor placeholder (for `AV_PH_EXHAUSTED`).
    pub next_placeholder: Option<String>,
    /// Which human factors would satisfy this refusal.
    pub factors: Option<Vec<String>>,
    /// Whether a placeholder use was given back.
    pub refunded: Option<bool>,
    /// Seconds until a retry is worth it (integer only, as in the JS).
    pub retry_after: Option<u64>,
}

/// A denial or failure an agent can see. Ports `class VaultError` in
/// `src/core/errors.js`. The `Display` form is `"<code>: <detail>"`, like the
/// JS `message`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", code.as_str())]
pub struct VaultError {
    /// The code.
    pub code: ErrorCode,
    /// What happened, in the agent's terms. Never contains a secret.
    pub detail: String,
    /// HTTP status (from the registry).
    pub http: u16,
    /// CLI exit code (from the registry).
    pub exit: Exit,
    /// Audit record kind (`auditKind` in the JS).
    pub audit_kind: &'static str,
    /// `extra.hint` or the registry hint.
    pub hint: String,
    /// `extra.rule`.
    pub rule: Option<String>,
    /// `extra.next`.
    pub next: Option<String>,
    /// `extra.requestId`.
    pub request_id: Option<String>,
    /// `extra.nextPlaceholder`.
    pub next_placeholder: Option<String>,
    /// `extra.factors`.
    pub factors: Option<Vec<String>>,
    /// `extra.refunded`.
    pub refunded: Option<bool>,
    /// `extra.retryAfter ?? extra.retry_after_s`, kept only when an integer.
    pub retry_after: Option<u64>,
}

impl VaultError {
    /// Build an error from a code, a detail and extras. Ports the
    /// `VaultError` constructor in `src/core/errors.js`.
    pub fn new(code: ErrorCode, detail: impl Into<String>, extra: DenyExtra) -> Self {
        todo!()
    }

    /// RFC 9457 problem+json body, the shape every denied HTTP request
    /// returns: `type, code, detail, hint` and, when set, `rule, request_id,
    /// next, factors, refunded, next_placeholder, retry_after`, in that order.
    /// Ports `VaultError.prototype.toProblem` in `src/core/errors.js`.
    pub fn to_problem(&self) -> serde_json::Value {
        todo!()
    }
}

/// Shorthand used throughout the pipeline. Ports `deny` in
/// `src/core/errors.js`.
pub fn deny(code: ErrorCode, detail: impl Into<String>, extra: DenyExtra) -> VaultError {
    VaultError::new(code, detail, extra)
}

/// `Result` with a [`VaultError`].
pub type Result<T, E = VaultError> = std::result::Result<T, E>;
