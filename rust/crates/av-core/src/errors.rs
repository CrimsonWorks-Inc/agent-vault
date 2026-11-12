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
    /// The wire string, e.g. `"AV_NO_GRANT"`. Ports the `code` keys of `CODES` in
    /// `src/core/errors.js`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGrant => "AV_NO_GRANT",
            Self::PolicyDenied => "AV_POLICY_DENIED",
            Self::BadLocation => "AV_BAD_LOCATION",
            Self::EncodedBody => "AV_ENCODED_BODY",
            Self::Unscannable => "AV_UNSCANNABLE",
            Self::BrowserOrigin => "AV_BROWSER_ORIGIN",
            Self::PhMalformed => "AV_PH_MALFORMED",
            Self::PhExhausted => "AV_PH_EXHAUSTED",
            Self::PhStale => "AV_PH_STALE",
            Self::PhReplay => "AV_PH_REPLAY",
            Self::PhCrossSession => "AV_PH_CROSS_SESSION",
            Self::PhWrongConnector => "AV_PH_WRONG_CONNECTOR",
            Self::SessionExpired => "AV_SESSION_EXPIRED",
            Self::SessionRevoked => "AV_SESSION_REVOKED",
            Self::SessionRequired => "AV_SESSION_REQUIRED",
            Self::Locked => "AV_LOCKED",
            Self::RemoteForbidden => "AV_REMOTE_FORBIDDEN",
            Self::PresenceRequired => "AV_PRESENCE_REQUIRED",
            Self::PresenceDenied => "AV_PRESENCE_DENIED",
            Self::RateLimited => "AV_RATE_LIMITED",
            Self::UpstreamUnreachable => "AV_UPSTREAM_UNREACHABLE",
            Self::QuotaExceeded => "AV_QUOTA_EXCEEDED",
            Self::GrantExpired => "AV_GRANT_EXPIRED",
            Self::Quarantined => "AV_QUARANTINED",
            Self::PinMismatch => "AV_PIN_MISMATCH",
            Self::McpProtocol => "AV_MCP_PROTOCOL",
            Self::McpSessionUnknown => "AV_MCP_SESSION_UNKNOWN",
            Self::NotFound => "AV_NOT_FOUND",
            Self::Internal => "AV_INTERNAL",
            Self::TooManyRequests => "AV_TOO_MANY_REQUESTS",
            Self::ApprovalPending => "AV_APPROVAL_PENDING",
            Self::OwnerOnly => "AV_OWNER_ONLY",
            Self::BadCursor => "AV_BAD_CURSOR",
            Self::BadLimit => "AV_BAD_LIMIT",
        }
    }

    /// Parse a wire string. Unknown strings return `None`. Ports the
    /// `CODES[code]` lookup in `src/core/errors.js` / `src/cli/index.js`.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "AV_NO_GRANT" => Some(Self::NoGrant),
            "AV_POLICY_DENIED" => Some(Self::PolicyDenied),
            "AV_BAD_LOCATION" => Some(Self::BadLocation),
            "AV_ENCODED_BODY" => Some(Self::EncodedBody),
            "AV_UNSCANNABLE" => Some(Self::Unscannable),
            "AV_BROWSER_ORIGIN" => Some(Self::BrowserOrigin),
            "AV_PH_MALFORMED" => Some(Self::PhMalformed),
            "AV_PH_EXHAUSTED" => Some(Self::PhExhausted),
            "AV_PH_STALE" => Some(Self::PhStale),
            "AV_PH_REPLAY" => Some(Self::PhReplay),
            "AV_PH_CROSS_SESSION" => Some(Self::PhCrossSession),
            "AV_PH_WRONG_CONNECTOR" => Some(Self::PhWrongConnector),
            "AV_SESSION_EXPIRED" => Some(Self::SessionExpired),
            "AV_SESSION_REVOKED" => Some(Self::SessionRevoked),
            "AV_SESSION_REQUIRED" => Some(Self::SessionRequired),
            "AV_LOCKED" => Some(Self::Locked),
            "AV_REMOTE_FORBIDDEN" => Some(Self::RemoteForbidden),
            "AV_PRESENCE_REQUIRED" => Some(Self::PresenceRequired),
            "AV_PRESENCE_DENIED" => Some(Self::PresenceDenied),
            "AV_RATE_LIMITED" => Some(Self::RateLimited),
            "AV_UPSTREAM_UNREACHABLE" => Some(Self::UpstreamUnreachable),
            "AV_QUOTA_EXCEEDED" => Some(Self::QuotaExceeded),
            "AV_GRANT_EXPIRED" => Some(Self::GrantExpired),
            "AV_QUARANTINED" => Some(Self::Quarantined),
            "AV_PIN_MISMATCH" => Some(Self::PinMismatch),
            "AV_MCP_PROTOCOL" => Some(Self::McpProtocol),
            "AV_MCP_SESSION_UNKNOWN" => Some(Self::McpSessionUnknown),
            "AV_NOT_FOUND" => Some(Self::NotFound),
            "AV_INTERNAL" => Some(Self::Internal),
            "AV_TOO_MANY_REQUESTS" => Some(Self::TooManyRequests),
            "AV_APPROVAL_PENDING" => Some(Self::ApprovalPending),
            "AV_OWNER_ONLY" => Some(Self::OwnerOnly),
            "AV_BAD_CURSOR" => Some(Self::BadCursor),
            "AV_BAD_LIMIT" => Some(Self::BadLimit),
            _ => None,
        }
    }

    /// The registry row for this code, falling back to `AV_INTERNAL` for
    /// unregistered codes exactly as `CODES[code] || CODES.AV_INTERNAL` does in
    /// the `VaultError` constructor (`src/core/errors.js`).
    pub fn spec(self) -> &'static CodeSpec {
        CODES
            .iter()
            .find(|s| s.code == self.as_str())
            .unwrap_or_else(|| CODES.last().expect("registry is nonempty"))
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
    /// The concrete next step: a command string, or `{cli, mcp}` recovery instructions.
    pub next: Option<serde_json::Value>,
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
///
/// The JS fields `http`, `exit` and `auditKind` come from the registry, so
/// they are methods here ([`VaultError::http`], …) rather than stored copies.
/// The optional `extra` fields are boxed so `Result<T, VaultError>` stays
/// small (clippy's `result_large_err`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", code.as_str())]
pub struct VaultError {
    /// The code.
    pub code: ErrorCode,
    /// What happened, in the agent's terms. Never contains a secret.
    pub detail: String,
    /// `extra` as given to the constructor: hint override, rule, next,
    /// requestId, nextPlaceholder, factors, refunded, retryAfter.
    pub extra: Box<DenyExtra>,
}

impl VaultError {
    /// Build an error from a code, a detail and extras. Ports the
    /// `VaultError` constructor in `src/core/errors.js`.
    pub fn new(code: ErrorCode, detail: impl Into<String>, extra: DenyExtra) -> Self {
        Self {
            code,
            detail: detail.into(),
            extra: Box::new(extra),
        }
    }

    /// HTTP status: `this.http` (`spec.http`) in `src/core/errors.js`.
    pub fn http(&self) -> u16 {
        self.code.spec().http
    }

    /// CLI exit code: `this.exit` (`spec.exit`) in `src/core/errors.js`.
    pub fn exit(&self) -> Exit {
        self.code.spec().exit
    }

    /// Audit record kind: `this.auditKind` (`spec.audit`) in
    /// `src/core/errors.js`.
    pub fn audit_kind(&self) -> &'static str {
        self.code.spec().audit
    }

    /// `this.hint`: `extra.hint || spec.hint` in `src/core/errors.js`.
    pub fn hint(&self) -> &str {
        self.extra
            .hint
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(self.code.spec().hint)
    }

    /// RFC 9457 problem+json body, the shape every denied HTTP request
    /// returns: `type, code, detail, hint` and, when set, `rule, request_id,
    /// next, factors, refunded, next_placeholder, retry_after`, in that order.
    /// Ports `VaultError.prototype.toProblem` in `src/core/errors.js`.
    pub fn to_problem(&self) -> serde_json::Value {
        let mut body = serde_json::json!({"type":format!("https://agent-vault.dev/errors/{}",self.code.as_str()),"code":self.code.as_str(),"detail":self.detail,"hint":self.hint()});
        for (key, value) in [
            ("rule", &self.extra.rule),
            ("request_id", &self.extra.request_id),
            ("next_placeholder", &self.extra.next_placeholder),
        ] {
            if let Some(v) = value.as_ref().filter(|s| !s.is_empty()) {
                body[key] = v.clone().into();
            }
        }
        if let Some(v) = self.extra.next.as_ref().filter(|v| match v {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(v) => *v,
            serde_json::Value::String(s) => !s.is_empty(),
            serde_json::Value::Number(n) => n.as_f64() != Some(0.0),
            _ => true,
        }) {
            body["next"] = v.clone();
        }
        if let Some(v) = &self.extra.factors {
            body["factors"] = serde_json::json!(v);
        }
        if let Some(v) = self.extra.refunded {
            body["refunded"] = v.into();
        }
        if let Some(v) = self.extra.retry_after {
            body["retry_after"] = v.into();
        }
        body
    }
}

/// Shorthand used throughout the pipeline. Ports `deny` in
/// `src/core/errors.js`.
pub fn deny(code: ErrorCode, detail: impl Into<String>, extra: DenyExtra) -> VaultError {
    VaultError::new(code, detail, extra)
}

/// `Result` with a [`VaultError`].
pub type Result<T, E = VaultError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_and_problem_match_reference() {
        for spec in CODES {
            let code = ErrorCode::parse(spec.code).unwrap();
            assert_eq!(code.as_str(), spec.code);
            assert_eq!(code.spec(), spec);
            let e = deny(code, "test refusal", DenyExtra::default());
            assert_eq!(e.http(), spec.http);
            assert_eq!(e.exit(), spec.exit);
            assert_eq!(e.audit_kind(), spec.audit);
            assert_eq!(e.hint(), spec.hint);
            assert_eq!(e.to_problem()["code"], spec.code);
        }
        let e = deny(
            ErrorCode::OwnerOnly,
            "test refusal",
            DenyExtra {
                hint: Some(String::new()),
                refunded: Some(false),
                retry_after: Some(0),
                rule: Some("test_rule".into()),
                ..Default::default()
            },
        );
        assert_eq!(e.http(), 500);
        assert_eq!(e.hint(), ErrorCode::Internal.spec().hint);
        assert_eq!(e.to_problem()["refunded"], false);
        assert_eq!(e.to_problem()["retry_after"], 0);
        assert_eq!(e.to_problem()["rule"], "test_rule");
        assert!(ErrorCode::parse("UNKNOWN").is_none());
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn structured_and_string_next_match_javascript() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/error-next-vectors.json"))
                .unwrap();
        for row in vectors.as_array().unwrap() {
            let error = deny(
                ErrorCode::parse(row["code"].as_str().unwrap()).unwrap(),
                "test refusal",
                DenyExtra {
                    next: Some(row["next"].clone()),
                    ..Default::default()
                },
            );
            assert_eq!(error.to_problem(), row["problem"]);
            let serialized = serde_json::to_string(&error.to_problem()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, row["problem"]);
        }
    }
}
