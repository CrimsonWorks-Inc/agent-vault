//! Ports `src/store/activity.js`: one session's activity and the access
//! review report (F19). Pure: both read audit rows and records the caller
//! hands them, and write nothing. They copy only the fields named here, never
//! a record's free-text detail. Incomplete history is never read as zero
//! activity: the answer says so (`complete: false` with a `note`).

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::error::Result;
use crate::model::{CredentialRecord, GrantRecord, HealthStatus, SessionRecord};
use crate::vault::ExpiryWarning;

/// Record kinds that mean history may be missing. Ports `ANOMALIES` in
/// `src/store/activity.js`.
pub const ANOMALIES: [&str; 2] = ["audit.anchor_missing", "audit.truncation_detected"];
/// Most paths one session summary lists. Ports `MAX_PATHS` in
/// `src/store/activity.js`.
pub const MAX_PATHS: usize = 50;
/// Methods a grant allows when its policy names none. Ports
/// `DEFAULT_METHODS` in `src/store/activity.js`.
pub const DEFAULT_METHODS: [&str; 2] = ["GET", "HEAD"];

/// Request counts. Ports `requests` in `summarizeSession` in
/// `src/store/activity.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestCounts {
    /// Allowed and used (holds excluded).
    pub allowed: u64,
    /// Denied.
    pub denied: u64,
    /// Held for approval.
    pub held: u64,
}

/// Approval counts. Ports `approvals` in `summarizeSession` in
/// `src/store/activity.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApprovalCounts {
    /// `approval.requested`.
    pub requested: u64,
    /// `approval.granted`.
    pub granted: u64,
    /// `approval.denied`.
    pub denied: u64,
    /// `approval.replayed`.
    pub replayed: u64,
}

/// One method+path a session touched. The path is scrubbed, without a query,
/// with any placeholder replaced by `[[av:placeholder]]`. Ports the entries
/// of `paths` in `summarizeSession` in `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathActivity {
    /// Upper-cased method, if the record had one.
    pub method: Option<String>,
    /// Scrubbed path, if the record had one.
    pub path: Option<String>,
    /// How many times.
    pub count: u64,
    /// ISO time last seen.
    pub last_at: Option<String>,
}

/// One kind of denial. Ports the entries of `denials` in `summarizeSession`
/// in `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialCount {
    /// `reason_code`.
    pub code: Option<String>,
    /// `rule`.
    pub rule: Option<String>,
    /// How many times.
    pub count: u64,
}

/// A tripwire that fired on the session. Ports the entries of `tripwires`
/// in `summarizeSession` in `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwireHit {
    /// The rule.
    pub rule_id: Option<String>,
    /// ISO time.
    pub at: String,
}

/// One session's activity. Ports the return value of `summarizeSession` in
/// `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionActivity {
    /// The log covers the whole session.
    pub complete: bool,
    /// Why not, when not.
    pub note: Option<String>,
    /// First seq concerning it.
    pub from_seq: Option<u64>,
    /// Last seq concerning it.
    pub to_seq: Option<u64>,
    /// ISO time of `from_seq`.
    pub first_at: Option<String>,
    /// ISO time of `to_seq`.
    pub last_at: Option<String>,
    /// Request counts.
    pub requests: RequestCounts,
    /// Top paths by count, then recency (at most [`MAX_PATHS`]).
    pub paths: Vec<PathActivity>,
    /// Denials by count.
    pub denials: Vec<DenialCount>,
    /// Approval counts.
    pub approvals: ApprovalCounts,
    /// Tripwires that fired.
    pub tripwires: Vec<TripwireHit>,
}

/// One session's activity, from the rows that concern it (its own, its
/// grants', and its approvals'). Ports `summarizeSession` in
/// `src/store/activity.js`.
pub fn summarize_session(
    rows: &[AuditRecord],
    session: &SessionRecord,
    grants: &[GrantRecord],
) -> SessionActivity {
    todo!()
}

/// What an access review is over. Ports the options of `accessReport` in
/// `src/store/activity.js`.
#[derive(Debug, Clone, Copy)]
pub struct AccessReportInput<'a> {
    /// Every session.
    pub sessions: &'a [SessionRecord],
    /// Every grant.
    pub grants: &'a [GrantRecord],
    /// Every credential.
    pub credentials: &'a [CredentialRecord],
    /// ISO date; rows before it are not counted.
    pub since: &'a str,
}

/// One credential in an access review. Ports the `credReport` entries in
/// `accessReport` in `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReport {
    /// Slug.
    pub slug: String,
    /// Sessions with a grant of it that are active now.
    pub sessions_active: u64,
    /// Sessions with a grant of it.
    pub sessions_total: u64,
    /// Requests that used it, in the window.
    pub requests: u64,
    /// Denials naming it, in the window.
    pub denials: u64,
    /// ISO time last used (whole log).
    pub last_used_at: Option<String>,
    /// The human's expiry.
    pub expires_at: Option<String>,
    /// Expiry warning.
    pub expiry_warning: Option<ExpiryWarning>,
    /// Last health status.
    pub health_status: Option<HealthStatus>,
    /// Quarantined now.
    pub quarantined: bool,
}

/// One session in an access review. Ports the `sessionReport` entries in
/// `accessReport` in `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    /// Sid.
    pub id: String,
    /// Label.
    pub label: Option<String>,
    /// State now (an active one past its end is `expired`).
    pub state: String,
    /// Slugs it holds grants of.
    pub creds: Vec<String>,
    /// Requests in the window.
    pub requests: u64,
    /// Denials in the window.
    pub denials: u64,
    /// ISO time last seen.
    pub last_seen_at: Option<String>,
    /// Elevations, from the session or its creation record.
    pub elevated: Option<Vec<String>>,
    /// Granted methods never used, sorted.
    pub unused_methods: Vec<String>,
}

/// The access review report. Ports the return value of `accessReport` in
/// `src/store/activity.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessReport {
    /// ISO time generated.
    pub generated_at: String,
    /// Normalized `since`.
    pub since: String,
    /// No anomaly and no session missing its creation record.
    pub complete: bool,
    /// Per credential.
    pub credentials: Vec<CredentialReport>,
    /// Per session reported (active now, or created/seen since `since`).
    pub sessions: Vec<SessionReport>,
}

/// Every credential and every session in the window, for an access review.
/// Refuses (AV_POLICY_DENIED, rule `report_since`) a `since` that is not a
/// date. Ports `accessReport` in `src/store/activity.js`.
pub fn access_report(rows: &[AuditRecord], input: AccessReportInput<'_>) -> Result<AccessReport> {
    todo!()
}
