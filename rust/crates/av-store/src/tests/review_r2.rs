//! Ports `test/security/store-review-r2.test.js`.

use av_core::secret::ExposeSecret;
use serde_json::{json, Value};

use super::backup::v1_bundle;
use super::helpers::*;
use crate::backup::*;
use crate::model::{GrantState, PlaceholderState};
use crate::vault::*;

const RECOVERY: &str = "correct horse battery staple";
const FIRST: &str = "ghp_RESTOREFIRST0011223344556677889900";
const SECOND: &str = "ghp_RESTORESECOND011223344556677889900";
const THIRD: &str = "ghp_RESTORETHIRD0011223344556677889900";

fn entry(slug: &str, value: &str, scrub: &[&str]) -> Value {
    json!({
        "slug": slug, "kind": "http", "connector": { "host": "api.example.com", "scheme": "https" }, "created_at": iso(now()),
        "fields": [{ "name": "token", "value": value, "sites": ["header:authorization:Bearer"] }],
        "scrub_patterns": scrub.iter().map(|s| json!({ "source": s })).collect::<Vec<_>>(), "pins": {}, "expires_at": "2031-01-01"
    })
}

fn templates() -> Value {
    json!([{ "name": "restored-a", "spec": { "cred": "first", "methods": ["GET"] } }, { "name": "restored-b", "spec": { "cred": "third" } }])
}

/// Refused with `expected`, the vault as it was, and one `backup.refused`.
fn refused_whole(v: &mut Vault, bundle: &Value, expected: (&str, &str)) {
    let before = snapshot(v);
    let seq = v.audit().unwrap().seq();
    assert_eq!(code(restore_backup(v, bundle, &s(RECOVERY), ConflictMode::Skip)), rule(expected.0, Some(expected.1)));
    assert_eq!(snapshot(v).0, before.0, "a refused restore changed the vault");
    let added: Vec<(String, Value)> = v
        .audit()
        .unwrap()
        .read(&crate::audit::ReadFilter { limit: 0, ..Default::default() })
        .unwrap()
        .into_iter()
        .filter(|r| r.seq > seq)
        .map(|r| (r.kind.clone(), field(&r, "reason").clone()))
        .collect();
    assert_eq!(added, vec![("backup.refused".to_string(), json!(expected.1))]);
}

#[test]
fn a_restore_that_fails_at_the_first_a_middle_or_the_last_item_leaves_the_vault_exactly_as_it_was() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let b = |creds: Value| v1_bundle(&json!({ "credentials": creds, "templates": templates() }), RECOVERY);
    refused_whole(v, &b(json!([entry("first", FIRST, &["ab"]), entry("second", SECOND, &[]), entry("third", THIRD, &[])])), ("AV_POLICY_DENIED", "scrub_pattern"));
    let sess = session(v);
    let g = grant_for(v, &sess.id, &fx.cred.id);
    let ph = v.issue_placeholder(IssueOptions { grant_id: g.id, ..Default::default() }).unwrap().placeholder;
    refused_whole(v, &b(json!([entry("first", FIRST, &["acme_[a-z]{8}"]), entry("second", SECOND, &[ph.as_str()]), entry("third", THIRD, &[])])), ("AV_POLICY_DENIED", "scrub_pattern"));
    let long = "x".repeat(257);
    refused_whole(v, &b(json!([entry("first", FIRST, &[]), entry("second", SECOND, &[]), entry("third", THIRD, &[long.as_str()])])), ("AV_POLICY_DENIED", "scrub_pattern"));
    let carries = format!("id={FIRST}");
    refused_whole(v, &b(json!([entry("first", FIRST, &[]), entry("second", SECOND, &[]), entry("third", THIRD, &[carries.as_str()])])), ("AV_POLICY_DENIED", "scrub_pattern"));
}

#[test]
fn a_restore_whose_last_template_does_not_fit_writes_none_of_the_credentials_before_it() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for i in 0..63 {
        v.save_template(&format!("t{i}"), &json!({ "cred": "demo" })).unwrap();
    }
    let b = v1_bundle(&json!({ "credentials": [entry("first", FIRST, &[]), entry("second", SECOND, &[])], "templates": templates() }), RECOVERY);
    refused_whole(v, &b, ("AV_POLICY_DENIED", "template_size"));
}

#[test]
fn a_restore_whose_one_write_fails_is_undone_and_leaves_the_database_as_it_was() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let b = v1_bundle(&json!({ "credentials": [entry("first", FIRST, &["acme_[a-z]{8}"]), entry("second", SECOND, &[])], "templates": templates() }), RECOVERY);
    exec(v, "CREATE TRIGGER fail_restore BEFORE INSERT ON credentials WHEN NEW.slug = 'second' BEGIN SELECT RAISE(ABORT, 'disk full'); END", &[]);
    refused_whole(v, &b, ("AV_INTERNAL", "backup_persist"));
    assert!(v.find_credential("first").unwrap().is_none());
    assert!(v.get_template("restored-a").unwrap().is_none());
    exec(v, "DROP TRIGGER fail_restore", &[]);
    let out = restore_backup(v, &b, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert_eq!((out.restored, out.templates.restored), (vec!["first".to_string(), "second".to_string()], vec!["restored-a".to_string(), "restored-b".to_string()]));
    let id = v.find_credential("second").unwrap().unwrap().id;
    assert_eq!(v.reveal_field(&id, "token").unwrap().expose_secret(), SECOND);
    let src: Vec<String> = v.find_credential("first").unwrap().unwrap().scrub_patterns.into_iter().map(|p| p.source).collect();
    assert_eq!(src, vec!["acme_[a-z]{8}"]);
}

#[test]
fn an_ordinary_restore_stores_everything_in_one_write_and_records_each_item() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let before = v.audit().unwrap().seq();
    let b = v1_bundle(&json!({ "credentials": [entry("first", FIRST, &["acme_[a-z]{8}"]), entry("second", SECOND, &[]), entry("third", THIRD, &[])], "templates": templates() }), RECOVERY);
    let out = restore_backup(v, &b, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert_eq!(out.restored, vec!["first", "second", "third"]);
    let mut slugs: Vec<String> = v.credential_records().unwrap().into_iter().map(|c| c.slug).collect();
    slugs.sort();
    assert_eq!(slugs, vec!["demo", "first", "other", "second", "third"]);
    assert_eq!(v.find_credential("third").unwrap().unwrap().expires_at.as_deref(), Some("2031-01-01T00:00:00.000Z"));
    let kinds: Vec<String> = v
        .audit()
        .unwrap()
        .read(&crate::audit::ReadFilter { limit: 0, ..Default::default() })
        .unwrap()
        .into_iter()
        .filter(|r| r.seq > before)
        .map(|r| r.kind)
        .collect();
    assert_eq!(
        kinds,
        vec!["cred.added", "cred.expiry_set", "cred.scrub_pattern_added", "cred.added", "cred.expiry_set", "cred.added", "cred.expiry_set", "template.saved", "template.saved", "backup.restored"]
    );
}

#[test]
fn touching_a_session_that_has_ended_does_not_bring_it_back_in_whatever_order() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let t0 = parse("2032-06-01T00:00:00.000Z");
    let idle = at(t0, || session_with(v, CreateSessionOptions { label: Some("idle".into()), ..Default::default() }));
    assert!(!at(t0 + 9 * HOUR, || v.touch_session(&idle.id)).unwrap());
    assert_eq!(session_row(v, &idle.id).expires_at, idle.expires_at, "an idle-expired session was extended");
    assert_eq!(at(t0 + 9 * HOUR, || code_of(v.assert_session_live(Some(&idle)))), "AV_SESSION_EXPIRED");
    assert!(!at(t0 + 9 * HOUR, || v.touch_session(&idle.id)).unwrap());
    let mut pushed = session_row(v, &idle.id);
    pushed.expires_at = Some(iso(t0 + 10 * HOUR));
    assert_eq!(at(t0 + 9 * HOUR, || code_of(v.assert_session_live(Some(&pushed)))), "AV_SESSION_EXPIRED");
    let revoked = at(t0, || session_with(v, CreateSessionOptions { label: Some("revoked".into()), ..Default::default() }));
    v.revoke_session(&revoked.id, "revoked").unwrap();
    assert!(!at(t0 + HOUR, || v.touch_session(&revoked.id)).unwrap());
    assert_eq!(session_row(v, &revoked.id).expires_at, revoked.expires_at);
}

#[test]
fn a_touch_never_moves_an_end_earlier_nor_past_the_ceiling_and_does_extend_a_live_session() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let t0 = parse("2032-06-01T00:00:00.000Z");
    let sx = at(t0, || session_with(v, CreateSessionOptions { label: Some("busy".into()), ..Default::default() }));
    assert!(at(t0 + HOUR, || v.touch_session(&sx.id)).unwrap());
    assert_eq!(parse(session_row(v, &sx.id).expires_at.as_deref().unwrap()), t0 + 8 * HOUR);
    at(t0 + 7 * HOUR, || v.touch_session(&sx.id)).unwrap();
    assert_eq!(parse(session_row(v, &sx.id).expires_at.as_deref().unwrap()), t0 + 9 * HOUR);
    let mut t = 8.5;
    while t <= 23.5 {
        at(t0 + (t * HOUR as f64) as i64, || v.touch_session(&sx.id)).unwrap();
        t += 1.5;
    }
    let now_s = session_row(v, &sx.id);
    assert_eq!(now_s.expires_at, now_s.max_expires_at);
    let odd = at(t0, || session_with(v, CreateSessionOptions { label: Some("odd".into()), ..Default::default() }));
    exec(v, "UPDATE sessions SET max_expires_at = 'garbage' WHERE id = ?1", &[&odd.id]);
    at(t0 + 7 * HOUR, || v.touch_session(&odd.id)).unwrap();
    assert_eq!(parse(session_row(v, &odd.id).expires_at.as_deref().unwrap()), t0 + 8 * HOUR);
}

#[test]
fn a_quarantine_stops_a_placeholder_issued_before_it_at_consume_and_at_reveal_until_released() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let sess = session(v);
    let g = grant_for(v, &sess.id, &fx.cred.id);
    let row = v.issue_placeholder(IssueOptions { grant_id: g.id.clone(), uses: Some(3), ..Default::default() }).unwrap().row;
    v.set_quarantine("demo", QuarantineOptions { reason: Some("review".into()), ..Default::default() }).unwrap();
    assert_eq!(code(v.consume_placeholder(&row.id)), rule("AV_QUARANTINED", Some("quarantine")));
    assert_eq!(code(v.reveal_field(&fx.cred.id, "token")), rule("AV_QUARANTINED", Some("quarantine")));
    let r = ph_row(v, &row.id);
    assert_eq!((r.uses, r.state, grant_row(v, &g.id).budget_used), (0, PlaceholderState::Active, 0));
    assert!(v.all_secrets().unwrap().iter().any(|x| x.secret.expose_secret() == SECRET));
    let g2 = grant_for(v, &sess.id, &fx.other.id);
    let r2 = issue(v, &g2.id);
    v.consume_placeholder(&r2.id).unwrap();
    v.clear_quarantine("demo").unwrap();
    assert_eq!(v.consume_placeholder(&row.id).unwrap().uses, 1);
    assert_eq!(v.reveal_field(&fx.cred.id, "token").unwrap().expose_secret(), SECRET);
}

#[test]
fn a_quarantined_credential_can_still_be_rotated_and_backed_up() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.set_quarantine("demo", QuarantineOptions::default()).unwrap();
    let out = export_backup(v, &s(RECOVERY)).unwrap();
    assert!(!out.bundle.ct.is_empty());
    let new = "ghp_ROTATEDQUARANTINE0011223344556677";
    v.rotate_credential("demo", RotateOptions { field: None, value: s(new), mode: RotateMode::Keep, retire_ms: DAY_MS, expires_at: None }).unwrap();
    v.clear_quarantine("demo").unwrap();
    assert_eq!(v.reveal_field(&fx.cred.id, "token").unwrap().expose_secret(), new);
}

fn budgeted(v: &mut Vault, cred: &str, limit: Value) -> crate::model::GrantRecord {
    let sess = session(v);
    let mut p = serde_json::to_value(policy()).unwrap();
    if limit.is_null() {
        p["budget"] = json!({ "unit": "requests" });
    } else {
        p["budget"] = json!({ "unit": "requests", "limit": limit });
    }
    v.create_grant(CreateGrantOptions { policy: policy_from(p), ..grant_opts(&sess.id, cred) }).unwrap()
}

#[test]
fn a_budget_of_0_issues_nothing_and_consume_rereads_the_budget_and_ceiling_as_they_are_now() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let cred = fx.cred.id.clone();
    for zero in [json!(0), json!("0")] {
        let g = budgeted(v, &cred, zero);
        let rows = v.list_placeholders(None).unwrap().len();
        assert_eq!(code(v.issue_placeholder(IssueOptions { grant_id: g.id.clone(), ..Default::default() })), rule("AV_POLICY_DENIED", Some("budget")));
        assert_eq!(v.list_placeholders(None).unwrap().len(), rows);
    }
    let g3 = budgeted(v, &cred, json!(3));
    let row = issue(v, &g3.id);
    assert_eq!(row.max_uses, 3);
    for _ in 0..3 {
        assert!(v.charge_grant(&g3.id, 1).unwrap());
    }
    assert_eq!(code(v.consume_placeholder(&row.id)), rule("AV_POLICY_DENIED", Some("budget")));
    assert_eq!((ph_row(v, &row.id).uses, grant_row(v, &g3.id).budget_used), (0, 3));
    let g100 = budgeted(v, &cred, json!(100));
    let wide = issue(v, &g100.id);
    assert_eq!(wide.max_uses, 100);
    v.consume_placeholder(&wide.id).unwrap();
    v.narrow_grant(&g100.id, &json!({ "placeholder_policy": { "max_uses": 1 } })).unwrap();
    assert_eq!(code_of(v.consume_placeholder(&wide.id)), "AV_PH_EXHAUSTED");
    assert_eq!(grant_row(v, &g100.id).budget_used, 1);
    let lots = budgeted(v, &cred, json!("lots"));
    let lots_row = issue(v, &lots.id);
    assert_eq!(code(v.consume_placeholder(&lots_row.id)), rule("AV_POLICY_DENIED", Some("budget")));
    assert_eq!(ph_row(v, &lots_row.id).uses, 0);
}

#[test]
fn an_ordinary_budget_spends_to_its_limit_and_a_layer_that_names_no_limit_is_not_refused() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let cred = fx.cred.id.clone();
    let g = budgeted(v, &cred, json!("2"));
    let row = issue(v, &g.id);
    v.consume_placeholder(&row.id).unwrap();
    v.consume_placeholder(&row.id).unwrap();
    assert_eq!(grant_row(v, &g.id).budget_used, 2);
    assert_eq!(code_of(v.consume_placeholder(&row.id)), "AV_PH_EXHAUSTED");
    let open = budgeted(v, &cred, Value::Null);
    let r = issue(v, &open.id);
    for _ in 0..5 {
        v.consume_placeholder(&r.id).unwrap();
    }
    assert_eq!(grant_row(v, &open.id).budget_used, 5);
    let sess = session(v);
    let none = v
        .create_grant(CreateGrantOptions { policy: policy_from(json!({ "hosts": ["api.example.com"] })), ..grant_opts(&sess.id, &cred) })
        .unwrap();
    assert_eq!(issue(v, &none.id).max_uses, 1000);
}

#[test]
fn a_forked_grant_ends_no_later_than_the_grant_it_copies_or_its_own_session() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let t0 = parse("2032-06-01T00:00:00.000Z");
    let (cred, other) = (fx.cred.id.clone(), fx.other.id.clone());
    let parent = at(t0, || {
        let sess = session_with(v, CreateSessionOptions { label: Some("parent".into()), ttl_ms: Some(2 * HOUR), ..Default::default() });
        let short = v.create_grant(CreateGrantOptions { ttl_ms: Some(30 * 60_000), ..grant_opts(&sess.id, &cred) }).unwrap();
        let whole = grant_for(v, &sess.id, &other);
        let child = v.fork_session(&sess.id, ForkOptions { label: Some("child".into()), ..Default::default() }).unwrap().session;
        let grants = v.grants().unwrap();
        let of = |c: &str| grants.iter().find(|g| g.session_id == child.id && g.credential_id == c).cloned().unwrap();
        assert_eq!(of(&cred).expires_at, short.expires_at);
        assert_eq!(whole.expires_at, None);
        assert_eq!(of(&other).expires_at, None);
        let brief = v.fork_session(&sess.id, ForkOptions { label: Some("brief".into()), ttl_ms: Some(10 * 60_000), ..Default::default() }).unwrap().session;
        let bg = v.grants().unwrap().into_iter().find(|g| g.session_id == brief.id && g.credential_id == cred).unwrap();
        assert_eq!(bg.expires_at, Some(iso(t0 + 10 * 60_000)));
        sess
    });
    at(t0 + 45 * 60_000, || {
        let late = v.fork_session(&parent.id, ForkOptions { label: Some("late".into()), ..Default::default() }).unwrap().session;
        let copied: Vec<String> = v.grants().unwrap().into_iter().filter(|g| g.session_id == late.id).map(|g| g.credential_id).collect();
        assert_eq!(copied, vec![other.clone()]);
    });
    let _ = GrantState::Active;
}
