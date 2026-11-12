//! Ports `test/security/store-activity.test.js`. The JS drives traffic
//! through the gateway pipeline to produce the rows; the functions under test
//! are pure over audit rows, so here the rows are written the way the
//! pipeline writes them (request.allowed with `req`, denials with
//! `decision: deny`, holds as a 202 with `decision: held`, approvals by id).

use serde_json::{json, Value};

use super::helpers::*;
use crate::activity::*;
use crate::audit::AuditRecord;
use crate::model::{GrantRecord, SessionRecord};
use crate::vault::*;

struct Fixture {
    fx: Fx,
    session: SessionRecord,
    grant: GrantRecord,
}

fn fixture() -> Fixture {
    let mut fx = fresh();
    let s = session_with(
        &mut fx.vault,
        CreateSessionOptions {
            label: Some("gw".into()),
            ..Default::default()
        },
    );
    let g = fx
        .vault
        .create_grant(CreateGrantOptions {
            policy: policy_from(json!({ "hosts": ["api.example.com"], "methods": ["GET", "POST", "DELETE"], "paths": ["/repos/**"], "approval": "on-write" })),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    Fixture {
        fx,
        session: s,
        grant: g,
    }
}

fn write(v: &mut Vault, kind: &str, f: Value) {
    v.audit_mut()
        .unwrap()
        .write(kind, f.as_object().unwrap().clone())
        .unwrap();
}

/// Three reads of one path, one of another, a write held then granted, and
/// one request outside the grant: what `traffic()` in the JS produces.
fn traffic(f: &mut Fixture) {
    let (sid, gid) = (f.session.id.clone(), f.grant.id.clone());
    let v = &mut f.fx.vault;
    let allowed = |n: u32, path: &str| {
        json!({ "decision": "allow", "session_id": sid, "grant_id": gid, "request_id": format!("req_{n}"), "credential_slug": "demo",
                "req": { "method": "GET", "path": path, "status": 200 } })
    };
    for i in 0..3 {
        write(v, "request.allowed", allowed(i, "/repos/one"));
    }
    write(v, "request.allowed", allowed(3, "/repos/two"));
    write(
        v,
        "approval.requested",
        json!({ "approval_id": "ap_1", "grant_id": gid, "request_id": "req_held" }),
    );
    write(
        v,
        "request.allowed",
        json!({ "decision": "held", "session_id": sid, "grant_id": gid, "request_id": "req_held", "credential_slug": "demo",
                                       "req": { "method": "POST", "status": 202 } }),
    );
    write(
        v,
        "request.denied",
        json!({ "decision": "deny", "reason_code": "AV_POLICY_DENIED", "rule": "paths", "session_id": sid, "credential_slug": "demo",
                                      "detail": "path /p/a/admin/x is outside the grant", "req": { "method": "GET", "path": "/p/a/admin/x" } }),
    );
    write(v, "approval.granted", json!({ "approval_id": "ap_1" }));
}

fn rows_of(v: &Vault) -> Vec<AuditRecord> {
    v.audit()
        .unwrap()
        .read(&crate::audit::ReadFilter {
            limit: 0,
            ..Default::default()
        })
        .unwrap()
}

fn rec(seq: u64, ts: &str, kind: &str, f: Value) -> AuditRecord {
    AuditRecord {
        seq,
        ts: ts.into(),
        kind: kind.into(),
        fields: f.as_object().unwrap().clone(),
        prev_hash: String::new(),
        hash: String::new(),
    }
}

fn path_list(a: &SessionActivity) -> Vec<String> {
    let mut v: Vec<String> = a
        .paths
        .iter()
        .map(|p| {
            format!(
                "{} {} {}",
                p.method.clone().unwrap_or_default(),
                p.path.clone().unwrap_or_default(),
                p.count
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn a_normal_session_reports_complete_activity_with_the_right_counts() {
    let mut f = fixture();
    traffic(&mut f);
    let rows = rows_of(&f.fx.vault);
    let a = summarize_session(&rows, &f.session, std::slice::from_ref(&f.grant));
    assert!(a.complete);
    assert_eq!(a.note, None);
    assert_eq!(
        a.requests,
        RequestCounts {
            allowed: 4,
            denied: 1,
            held: 1
        }
    );
    assert_eq!(
        a.approvals,
        ApprovalCounts {
            requested: 1,
            granted: 1,
            denied: 0,
            replayed: 0
        }
    );
    assert_eq!(
        (
            a.paths[0].path.as_deref(),
            a.paths[0].method.as_deref(),
            a.paths[0].count
        ),
        (Some("/repos/one"), Some("GET"), 3)
    );
    assert_eq!(
        path_list(&a),
        vec!["GET /p/a/admin/x 1", "GET /repos/one 3", "GET /repos/two 1"]
    );
    assert_eq!(a.denials.len(), 1);
    assert_eq!(
        (a.denials[0].code.as_deref(), a.denials[0].count),
        (Some("AV_POLICY_DENIED"), 1)
    );
    let mut keys: Vec<String> = serde_json::to_value(&a.denials[0])
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(keys, vec!["code", "count", "rule"]);
    assert!(a.from_seq < a.to_seq && a.first_at <= a.last_at);
    assert!(a.tripwires.is_empty());
}

#[test]
fn a_log_written_before_holds_were_marked_reads_the_same() {
    let mut f = fixture();
    traffic(&mut f);
    let rows: Vec<AuditRecord> = rows_of(&f.fx.vault)
        .into_iter()
        .map(|mut r| {
            if r.fields.get("decision") == Some(&json!("held")) {
                r.fields.insert("decision".into(), json!("allow"));
            }
            r
        })
        .collect();
    assert!(rows
        .iter()
        .all(|r| r.fields.get("decision") != Some(&json!("held"))));
    let a = summarize_session(&rows, &f.session, std::slice::from_ref(&f.grant));
    assert_eq!(
        a.requests,
        RequestCounts {
            allowed: 4,
            denied: 1,
            held: 1
        }
    );
    assert_eq!(
        path_list(&a),
        vec!["GET /p/a/admin/x 1", "GET /repos/one 3", "GET /repos/two 1"]
    );
}

#[test]
fn the_activity_carries_no_placeholder_no_query_no_secret_and_no_detail_text() {
    let mut f = fixture();
    let ph =
        f.fx.vault
            .issue_placeholder(IssueOptions {
                grant_id: f.grant.id.clone(),
                ..Default::default()
            })
            .unwrap()
            .placeholder;
    let sid = f.session.id.clone();
    let detail = format!("the path /p/a/admin/{ph} is outside the grant");
    write(
        &mut f.fx.vault,
        "request.allowed",
        json!({ "decision": "allow", "session_id": sid, "req": { "method": "GET", "path": format!("/repos/{ph}?token={SECRET}"), "status": 200 } }),
    );
    write(
        &mut f.fx.vault,
        "request.denied",
        json!({ "decision": "deny", "reason_code": "AV_POLICY_DENIED", "rule": "paths", "session_id": sid, "detail": detail, "req": { "method": "GET", "path": format!("/p/a/admin/{ph}") } }),
    );
    let a = summarize_session(
        &rows_of(&f.fx.vault),
        &f.session,
        std::slice::from_ref(&f.grant),
    );
    assert_eq!(a.requests.allowed + a.requests.denied, 2);
    let text = serde_json::to_string(&a).unwrap();
    for bad in [ph.as_str(), SECRET, "token=", detail.as_str()] {
        assert!(!text.contains(bad), "{bad} reached the activity");
    }
    assert!(!text.contains("\"detail\""));
    let synthetic = vec![rec(
        1,
        "2026-01-01T00:00:00.000Z",
        "request.allowed",
        json!({ "session_id": sid, "req": { "method": "get", "path": format!("/x/{ph}/y?q={SECRET}") } }),
    )];
    let b = summarize_session(&synthetic, &f.session, &[]);
    let got: Vec<(Option<String>, Option<String>)> = b
        .paths
        .iter()
        .map(|p| (p.method.clone(), p.path.clone()))
        .collect();
    assert_eq!(
        got,
        vec![(Some("GET".into()), Some("/x/[[av:placeholder]]/y".into()))]
    );
}

#[test]
fn a_log_that_starts_after_the_session_or_was_cut_back_is_reported_incomplete() {
    let mut f = fixture();
    traffic(&mut f);
    let rows = rows_of(&f.fx.vault);
    let created = rows
        .iter()
        .find(|r| {
            r.kind == "session.created" && r.fields.get("session_id") == Some(&json!(f.session.id))
        })
        .unwrap()
        .seq;
    let after: Vec<AuditRecord> = rows.iter().filter(|r| r.seq > created).cloned().collect();
    let late = summarize_session(&after, &f.session, std::slice::from_ref(&f.grant));
    assert!(!late.complete);
    assert!(late.note.unwrap().contains("starts after this session"));
    assert_eq!(late.requests.allowed, 4);
    for kind in ["audit.truncation_detected", "audit.anchor_missing"] {
        let mut more = rows.clone();
        more.push(rec(9999, &iso(now()), kind, json!({})));
        let cut = summarize_session(&more, &f.session, std::slice::from_ref(&f.grant));
        assert!(!cut.complete, "{kind}");
        let note = cut.note.unwrap();
        assert!(note.contains("cut back") || note.contains("anchor"));
    }
}

#[test]
fn another_sessions_rows_are_not_this_sessions_activity() {
    let mut f = fixture();
    traffic(&mut f);
    let other = session_with(
        &mut f.fx.vault,
        CreateSessionOptions {
            label: Some("other".into()),
            ..Default::default()
        },
    );
    let og = grant_for(&mut f.fx.vault, &other.id, &f.fx.cred.id);
    let a = summarize_session(&rows_of(&f.fx.vault), &other, &[og, f.grant.clone()]);
    assert_eq!(a.requests, RequestCounts::default());
    assert_eq!(a.approvals, ApprovalCounts::default());
    assert!(a.paths.is_empty());
    assert!(a.complete);
}

#[test]
fn a_tripwire_that_fired_on_the_session_is_listed() {
    let f = fixture();
    let mut rows = rows_of(&f.fx.vault);
    rows.push(rec(
        500,
        "2026-10-26T00:00:00.000Z",
        "tripwire.fired",
        json!({ "session_id": f.session.id, "rule_id": "replay", "detail": "nope" }),
    ));
    let a = summarize_session(&rows, &f.session, std::slice::from_ref(&f.grant));
    assert_eq!(
        a.tripwires,
        vec![TripwireHit {
            rule_id: Some("replay".into()),
            at: "2026-10-26T00:00:00.000Z".into()
        }]
    );
}

#[test]
fn the_access_report_counts_use_per_credential_and_per_session_and_names_granted_methods_never_used(
) {
    let mut f = fixture();
    traffic(&mut f);
    f.fx.vault
        .set_credential_expiry("demo", Some(&iso(now() + 2 * DAY)))
        .unwrap();
    let since = iso(now() - HOUR);
    let rows = rows_of(&f.fx.vault);
    let sessions = vec![session_row(&f.fx.vault, &f.session.id)];
    let grants = f.fx.vault.grants().unwrap();
    let creds: Vec<crate::model::CredentialRecord> =
        f.fx.vault
            .credential_records()
            .unwrap()
            .into_iter()
            .filter(|c| c.slug == "demo")
            .collect();
    let r = access_report(
        &rows,
        AccessReportInput {
            sessions: &sessions,
            grants: &grants,
            credentials: &creds,
            since: &since,
        },
    )
    .unwrap();
    assert!(r.complete);
    assert_eq!(r.since, since);
    let last_used = rows
        .iter()
        .rfind(|x| x.kind == "request.allowed" && x.fields["req"]["status"] == json!(200))
        .unwrap()
        .ts
        .clone();
    assert_eq!(
        serde_json::to_value(&r.credentials).unwrap(),
        json!([{ "slug": "demo", "sessions_active": 1, "sessions_total": 1, "requests": 4, "denials": 1, "last_used_at": last_used,
                 "expires_at": creds[0].expires_at, "expiry_warning": "soon", "health_status": null, "quarantined": false }])
    );
    assert_eq!(
        serde_json::to_value(&r.sessions).unwrap(),
        json!([{ "id": f.session.id, "label": "gw", "state": "active", "creds": ["demo"], "requests": 4, "denials": 1,
                 "last_seen_at": sessions[0].last_seen_at, "elevated": [], "unused_methods": ["DELETE", "POST"] }])
    );
    assert!(!serde_json::to_string(&r).unwrap().contains(SECRET));
}

#[test]
fn the_report_window_an_expired_session_and_a_missing_creation_record_are_all_honest() {
    let mut f = fixture();
    traffic(&mut f);
    let rows = rows_of(&f.fx.vault);
    let grants = f.fx.vault.grants().unwrap();
    let creds: Vec<crate::model::CredentialRecord> =
        f.fx.vault
            .credential_records()
            .unwrap()
            .into_iter()
            .filter(|c| c.slug == "demo")
            .collect();
    let sessions = vec![session_row(&f.fx.vault, &f.session.id)];
    let input = |sessions: &'_ [SessionRecord], since: &'_ str| -> AccessReport {
        access_report(
            &rows,
            AccessReportInput {
                sessions,
                grants: &grants,
                credentials: &creds,
                since,
            },
        )
        .unwrap()
    };
    let future = input(&sessions, &iso(now() + 60_000));
    assert_eq!(future.credentials[0].requests, 0);
    assert_eq!(
        future.sessions.len(),
        1,
        "an active session is reviewed whatever the window"
    );
    let mut ended = sessions.clone();
    ended[0].expires_at = Some(iso(now() - 1000));
    let expired = input(&ended, &iso(now() - HOUR));
    assert_eq!(expired.sessions[0].state, "expired");
    assert_eq!(expired.credentials[0].sessions_active, 0);
    let without: Vec<AuditRecord> = rows
        .iter()
        .filter(|x| x.kind != "session.created")
        .cloned()
        .collect();
    let r = access_report(
        &without,
        AccessReportInput {
            sessions: &sessions,
            grants: &grants,
            credentials: &creds,
            since: &iso(now() - HOUR),
        },
    )
    .unwrap();
    assert!(!r.complete);
    for since in ["7d", "garbage", ""] {
        let e = access_report(
            &rows,
            AccessReportInput {
                sessions: &[],
                grants: &[],
                credentials: &[],
                since,
            },
        );
        assert_eq!(code(e), rule("AV_POLICY_DENIED", Some("report_since")));
    }
}

#[test]
fn a_row_the_gateway_marks_as_held_is_a_hold_whatever_else_it_says() {
    let f = fixture();
    let created = rows_of(&f.fx.vault)
        .into_iter()
        .find(|r| r.kind == "session.created")
        .unwrap();
    let rows = vec![
        created,
        rec(
            900,
            &iso(now()),
            "request.allowed",
            json!({ "decision": "held", "session_id": f.session.id, "request_id": "req_x", "grant_id": f.grant.id,
                                                          "req": { "method": "DELETE", "path": "/repos/one", "status": 202 } }),
        ),
    ];
    let a = summarize_session(&rows, &f.session, std::slice::from_ref(&f.grant));
    assert_eq!(a.requests.allowed, 0);
    assert!(a.paths.is_empty());
    let sessions = vec![f.session.clone()];
    let grants = vec![f.grant.clone()];
    let r = access_report(
        &rows,
        AccessReportInput {
            sessions: &sessions,
            grants: &grants,
            credentials: &[],
            since: &iso(0),
        },
    )
    .unwrap();
    assert!(r.sessions[0].unused_methods.contains(&"DELETE".to_string()));
}
