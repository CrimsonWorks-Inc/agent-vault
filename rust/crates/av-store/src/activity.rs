//! Ports `src/store/activity.js`: one session's activity and the access
//! review report (F19). Pure: both read audit rows and records the caller
//! hands them, and write nothing. They copy only the fields named here, never
//! a record's free-text detail. Incomplete history is never read as zero
//! activity: the answer says so (`complete: false` with a `note`).

use std::collections::{HashMap, HashSet};

use av_core::{deny, DenyExtra, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::AuditRecord;
use crate::error::Result;
use crate::model::{CredentialRecord, GrantRecord, HealthStatus, SessionRecord, SessionState};
use crate::vault::{expiry_warning, session_expiry_ms, ExpiryWarning};

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
    let grant_ids: HashSet<&str> = grants
        .iter()
        .filter(|g| g.session_id == session.id)
        .map(|g| g.id.as_str())
        .collect();
    let approval_ids: HashSet<String> = rows
        .iter()
        .filter(|r| r.kind == "approval.requested" && str_of(r, "grant_id").is_some_and(|g| grant_ids.contains(g)))
        .filter_map(|r| r.fields.get("approval_id").map(js_key))
        .collect();
    let own: Vec<&AuditRecord> = rows
        .iter()
        .filter(|r| {
            str_of(r, "session_id") == Some(session.id.as_str())
                || str_of(r, "grant_id").is_some_and(|g| grant_ids.contains(g))
                || r.fields
                    .get("approval_id")
                    .filter(|v| !v.is_null())
                    .is_some_and(|v| approval_ids.contains(&js_key(v)))
        })
        .collect();
    let anomaly = anomaly_note(rows);
    let created = rows
        .iter()
        .any(|r| r.kind == "session.created" && str_of(r, "session_id") == Some(session.id.as_str()));
    let note = anomaly.or_else(|| {
        (!created).then(|| {
            "the audit log starts after this session was created, so its early activity is not in it"
                .to_string()
        })
    });
    let is_hold = holds_of(rows);
    let mut requests = RequestCounts::default();
    let mut approvals = ApprovalCounts::default();
    let mut paths: Vec<PathActivity> = Vec::new();
    let mut denials: Vec<DenialCount> = Vec::new();
    let mut tripwires = Vec::new();
    let mut from: Option<&AuditRecord> = None;
    let mut to: Option<&AuditRecord> = None;
    for r in own {
        if from.is_none_or(|f| r.seq < f.seq) {
            from = Some(r);
        }
        if to.is_none_or(|t| r.seq > t.seq) {
            to = Some(r);
        }
        let mine = str_of(r, "session_id") == Some(session.id.as_str());
        let allowed = r.kind == "request.allowed" && !is_hold(r);
        let request = allowed || (is_denial(r) && mine);
        if r.kind == "request.allowed" {
            if allowed {
                requests.allowed += 1;
            }
        } else if is_denial(r) && mine {
            requests.denied += 1;
            let code = str_of(r, "reason_code").map(str::to_string);
            let rule = str_of(r, "rule").map(str::to_string);
            match denials.iter_mut().find(|d| d.code == code && d.rule == rule) {
                Some(d) => d.count += 1,
                None => denials.push(DenialCount { code, rule, count: 1 }),
            }
        } else if r.kind == "approval.requested" {
            requests.held += 1;
            approvals.requested += 1;
        } else if r.kind == "approval.granted" {
            approvals.granted += 1;
        } else if r.kind == "approval.denied" {
            approvals.denied += 1;
        } else if r.kind == "approval.replayed" {
            approvals.replayed += 1;
        } else if r.kind == "tripwire.fired" && mine {
            tripwires.push(TripwireHit {
                rule_id: str_of(r, "rule_id").map(str::to_string),
                at: r.ts.clone(),
            });
        }
        if request {
            let method = method_of(r);
            let path = path_of(r);
            match paths.iter_mut().find(|p| p.method == method && p.path == path) {
                Some(p) => {
                    p.count += 1;
                    if p.last_at.as_deref().is_none_or(|l| r.ts.as_str() > l) {
                        p.last_at = Some(r.ts.clone());
                    }
                }
                None => paths.push(PathActivity {
                    method,
                    path,
                    count: 1,
                    last_at: Some(r.ts.clone()),
                }),
            }
        }
    }
    // Stable sorts, as Array.prototype.sort is.
    paths.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.last_at.cmp(&a.last_at)));
    paths.truncate(MAX_PATHS);
    denials.sort_by(|a, b| b.count.cmp(&a.count));
    SessionActivity {
        complete: note.is_none(),
        note,
        from_seq: from.map(|r| r.seq),
        to_seq: to.map(|r| r.seq),
        first_at: from.map(|r| r.ts.clone()),
        last_at: to.map(|r| r.ts.clone()),
        requests,
        paths,
        denials,
        approvals,
        tripwires,
    }
}

/// A field as a string, if it is one.
fn str_of<'a>(r: &'a AuditRecord, k: &str) -> Option<&'a str> {
    r.fields.get(k).and_then(Value::as_str)
}

/// A value as the JS `Set` / `===` sees it, for ids of any type.
fn js_key(v: &Value) -> String {
    v.to_string()
}

fn is_denial(r: &AuditRecord) -> bool {
    str_of(r, "decision") == Some("deny")
}

fn req_of<'a>(r: &'a AuditRecord, k: &str) -> Option<&'a Value> {
    r.fields.get("req").and_then(|q| q.get(k))
}

/// Whether a `request.allowed` row is a hold. Ports `holdsOf`.
fn holds_of(rows: &[AuditRecord]) -> impl Fn(&AuditRecord) -> bool {
    let ids: HashSet<String> = rows
        .iter()
        .filter(|r| r.kind == "approval.requested")
        .filter_map(|r| r.fields.get("request_id").filter(|v| !v.is_null()).map(js_key))
        .collect();
    move |r: &AuditRecord| {
        str_of(r, "decision") == Some("held")
            || r.fields.get("request_id").is_some_and(|v| ids.contains(&js_key(v)))
            || (req_of(r, "status").and_then(Value::as_u64) == Some(202)
                && req_of(r, "path").is_none_or(Value::is_null))
    }
}

fn method_of(r: &AuditRecord) -> Option<String> {
    req_of(r, "method").and_then(Value::as_str).map(str::to_uppercase)
}

/// The path a record names, as it may be shown: no query, placeholders
/// replaced. Ports `pathOf`.
fn path_of(r: &AuditRecord) -> Option<String> {
    let p = req_of(r, "path")?.as_str()?;
    let mut out = p.split('?').next().unwrap_or("").to_string();
    let hits = av_core::placeholder::find_all(&out);
    for hit in hits.iter().rev() {
        out = format!("{}[[av:placeholder]]{}", &out[..hit.offset], &out[hit.end..]);
    }
    Some(out)
}

fn anomaly_note(rows: &[AuditRecord]) -> Option<String> {
    let hit = rows.iter().find(|r| ANOMALIES.contains(&r.kind.as_str()))?;
    Some(if hit.kind == "audit.truncation_detected" {
        "the audit log was cut back at some point, so records may be missing".into()
    } else {
        "the audit log lost its head anchor at some point, so records may be missing".into()
    })
}

/// The state a session is in now: an active one past its end has expired.
/// Ports `stateNow`.
fn state_now(s: &SessionRecord, now: i64) -> &'static str {
    match s.state {
        SessionState::Active if session_expiry_ms(s) <= now as f64 => "expired",
        SessionState::Active => "active",
        SessionState::Expired => "expired",
        SessionState::Revoked => "revoked",
    }
}

fn parse_or_nan(s: &str) -> f64 {
    crate::util::parse_ms(s).map_or(f64::NAN, |m| m as f64)
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
    let since_ms = crate::util::parse_ms(input.since).ok_or_else(|| {
        crate::error::Error::from(deny(
            ErrorCode::PolicyDenied,
            "since must be a date",
            DenyExtra {
                rule: Some("report_since".into()),
                ..Default::default()
            },
        ))
    })?;
    let since_f = since_ms as f64;
    let now = crate::util::now_ms();
    let is_hold = holds_of(rows);
    let used = |r: &AuditRecord| r.kind == "request.allowed" && !is_hold(r);
    let in_window: Vec<&AuditRecord> = rows.iter().filter(|r| parse_or_nan(&r.ts) >= since_f).collect();
    let slug_by_id: HashMap<&str, &str> = input
        .credentials
        .iter()
        .map(|c| (c.id.as_str(), c.slug.as_str()))
        .collect();
    let mut created_row: HashMap<String, &AuditRecord> = HashMap::new();
    for r in rows.iter().filter(|r| r.kind == "session.created") {
        let key = r.fields.get("session_id").map(js_key).unwrap_or_default();
        created_row.insert(key, r);
    }
    let session_key = |s: &SessionRecord| Value::from(s.id.clone()).to_string();
    let reported: Vec<&SessionRecord> = input
        .sessions
        .iter()
        .filter(|s| {
            state_now(s, now) == "active"
                || parse_or_nan(&s.created_at) >= since_f
                || parse_or_nan(&s.last_seen_at) >= since_f
        })
        .collect();
    let missing = reported
        .iter()
        .filter(|s| parse_or_nan(&s.created_at) >= since_f && !created_row.contains_key(&session_key(s)))
        .count();
    let anomaly = anomaly_note(rows);
    let count = |pred: &dyn Fn(&AuditRecord) -> bool| in_window.iter().filter(|r| pred(r)).count() as u64;

    let credentials = input
        .credentials
        .iter()
        .map(|c| {
            let session_ids: HashSet<&str> = input
                .grants
                .iter()
                .filter(|g| g.credential_id == c.id)
                .map(|g| g.session_id.as_str())
                .collect();
            let theirs: Vec<&SessionRecord> = input
                .sessions
                .iter()
                .filter(|s| session_ids.contains(s.id.as_str()))
                .collect();
            let slug = c.slug.as_str();
            let mut used_at: Vec<&str> = rows
                .iter()
                .filter(|r| used(r) && str_of(r, "credential_slug") == Some(slug))
                .map(|r| r.ts.as_str())
                .collect();
            used_at.sort_unstable();
            CredentialReport {
                slug: c.slug.clone(),
                sessions_active: theirs.iter().filter(|s| state_now(s, now) == "active").count() as u64,
                sessions_total: theirs.len() as u64,
                requests: count(&|r| used(r) && str_of(r, "credential_slug") == Some(slug)),
                denials: count(&|r| is_denial(r) && str_of(r, "credential_slug") == Some(slug)),
                last_used_at: used_at.last().map(|s| s.to_string()),
                expires_at: c.expires_at.clone(),
                expiry_warning: expiry_warning(c, now),
                health_status: c.health.as_ref().map(|h| h.status),
                quarantined: c.quarantine.is_some(),
            }
        })
        .collect();

    let sessions = reported
        .iter()
        .map(|s| {
            let their_grants: Vec<&GrantRecord> =
                input.grants.iter().filter(|g| g.session_id == s.id).collect();
            let used_methods: HashSet<Option<String>> = rows
                .iter()
                .filter(|r| used(r) && str_of(r, "session_id") == Some(s.id.as_str()))
                .map(method_of)
                .collect();
            let mut granted: Vec<String> = Vec::new();
            for g in &their_grants {
                let policy = serde_json::to_value(&g.policy).unwrap_or(Value::Null);
                let methods: Vec<String> = match policy.get("methods") {
                    Some(Value::Array(a)) => a
                        .iter()
                        .map(|m| match m {
                            Value::String(s) => s.to_uppercase(),
                            other => other.to_string().to_uppercase(),
                        })
                        .collect(),
                    _ => DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
                };
                for m in methods {
                    if !granted.contains(&m) {
                        granted.push(m);
                    }
                }
            }
            let mut unused: Vec<String> = granted
                .into_iter()
                .filter(|m| !used_methods.contains(&Some(m.clone())))
                .collect();
            unused.sort();
            let elevated = if !s.elevated.is_empty() || created_row.get(&session_key(s)).is_none() {
                Some(s.elevated.clone())
            } else {
                created_row
                    .get(&session_key(s))
                    .and_then(|r| r.fields.get("elevated"))
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
                    .or(Some(s.elevated.clone()))
            };
            let mut creds: Vec<String> = Vec::new();
            for g in &their_grants {
                if let Some(slug) = slug_by_id.get(g.credential_id.as_str()) {
                    if !creds.iter().any(|c| c == slug) {
                        creds.push(slug.to_string());
                    }
                }
            }
            let sid = s.id.as_str();
            SessionReport {
                id: s.id.clone(),
                label: Some(s.label.clone()),
                state: state_now(s, now).to_string(),
                creds,
                requests: count(&|r| used(r) && str_of(r, "session_id") == Some(sid)),
                denials: count(&|r| is_denial(r) && str_of(r, "session_id") == Some(sid)),
                last_seen_at: Some(s.last_seen_at.clone()),
                elevated,
                unused_methods: unused,
            }
        })
        .collect();

    Ok(AccessReport {
        generated_at: crate::util::iso(now),
        since: crate::util::iso(since_ms),
        complete: anomaly.is_none() && missing == 0,
        credentials,
        sessions,
    })
}
