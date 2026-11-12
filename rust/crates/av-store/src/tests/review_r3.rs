//! Ports `test/security/store-review-r3.test.js`: a quarantine travels with
//! its credential through a backup, and a restore never releases one.

use av_core::secret::ExposeSecret;
use serde_json::{json, Value};

use super::backup::v1_bundle;
use super::helpers::*;
use crate::backup::*;
use crate::model::{QuarantineBy, QuarantineRecord};
use crate::vault::*;

const RECOVERY: &str = "correct horse battery staple";

fn old_entry(slug: &str, value: &str) -> Value {
    json!({ "slug": slug, "kind": "http", "connector": { "host": "api.example.com", "scheme": "https" }, "created_at": iso(now()),
            "fields": [{ "name": "token", "value": value, "sites": ["header:authorization:Bearer"] }], "scrub_patterns": [], "pins": {}, "expires_at": null })
}

fn restore(v: &mut Vault, bundle: &Value, mode: ConflictMode) -> crate::error::Result<RestoreResult> {
    restore_backup(v, bundle, &s(RECOVERY), mode)
}

fn quarantine_of(v: &Vault, slug: &str) -> Option<QuarantineRecord> {
    let c = v.find_credential(slug).unwrap().unwrap();
    v.public_credential(&c).quarantine
}

fn reveal(v: &Vault, slug: &str) -> (String, Option<String>) {
    let id = v.find_credential(slug).unwrap().unwrap().id;
    code(v.reveal_field(&id, "token"))
}

fn quarantined() -> (String, Option<String>) {
    rule("AV_QUARANTINED", Some("quarantine"))
}

fn empty() -> Fx {
    let mut t = fresh();
    t.vault.delete_credential("demo").unwrap();
    t.vault.delete_credential("other").unwrap();
    t
}

fn export(v: &mut Vault) -> Value {
    serde_json::to_value(export_backup(v, &s(RECOVERY)).unwrap().bundle).unwrap()
}

fn tripwire(rule_id: &str, reason: Option<&str>) -> QuarantineOptions {
    QuarantineOptions { by: QuarantineBy::Tripwire, rule_id: Some(rule_id.into()), reason: reason.map(str::to_string) }
}

#[test]
fn a_a_bundle_carries_each_credentials_quarantine_record_exactly_as_stored() {
    let mut v = fresh();
    let stored = v.vault.set_quarantine("demo", tripwire("many-404s", Some("probing /admin"))).unwrap();
    let bundle = export(&mut v.vault);
    let plain = serde_json::to_value(open_bundle(&bundle, &s(RECOVERY)).unwrap()).unwrap();
    let by = |slug: &str| plain["credentials"].as_array().unwrap().iter().find(|c| c["slug"] == slug).cloned().unwrap();
    assert_eq!(by("demo")["quarantine"], serde_json::to_value(&stored).unwrap());
    let mut keys: Vec<String> = by("demo")["quarantine"].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, vec!["by", "reason_untrusted", "rule_id", "since"]);
    assert_eq!(by("other")["quarantine"], Value::Null);
    let seen = inspect_backup(&bundle, &s(RECOVERY)).unwrap();
    let got: Vec<(String, bool)> = seen.credentials.iter().map(|c| (c.slug.clone(), c.quarantined)).collect();
    assert_eq!(got, vec![("demo".into(), true), ("other".into(), false)]);
}

#[test]
fn b_a_credential_quarantined_at_backup_time_is_quarantined_after_restore_until_released() {
    let mut v = fresh();
    let mut t = empty();
    let stored = v.vault.set_quarantine("demo", tripwire("many-404s", Some("probing /admin"))).unwrap();
    let bundle = export(&mut v.vault);
    let seq = t.vault.audit().unwrap().seq();
    assert_eq!(restore(&mut t.vault, &bundle, ConflictMode::Skip).unwrap().restored, vec!["demo", "other"]);
    assert_eq!(quarantine_of(&t.vault, "demo"), Some(stored.clone()));
    assert_eq!(reveal(&t.vault, "demo"), quarantined());
    let sess = session(&mut t.vault);
    let demo_id = t.vault.find_credential("demo").unwrap().unwrap().id;
    assert_eq!(code(t.vault.create_grant(grant_opts(&sess.id, &demo_id))), quarantined());
    let recs: Vec<Value> = records(&t.vault, "cred.quarantined")
        .into_iter()
        .filter(|r| r.seq > seq)
        .map(|r| json!([field(&r, "credential_slug"), field(&r, "by"), field(&r, "rule_id"), field(&r, "reason_untrusted"), field(&r, "since"), field(&r, "restored")]))
        .collect();
    assert_eq!(recs, vec![json!(["demo", "tripwire", "many-404s", "probing /admin", stored.since, true])]);
    assert_eq!(quarantine_of(&t.vault, "other"), None);
    let oid = t.vault.find_credential("other").unwrap().unwrap().id;
    assert_eq!(t.vault.reveal_field(&oid, "token").unwrap().expose_secret(), OTHER_SECRET);
    assert!(t.vault.clear_quarantine("demo").unwrap());
    assert_eq!(t.vault.reveal_field(&demo_id, "token").unwrap().expose_secret(), SECRET);
}

#[test]
fn c_a_credential_quarantined_in_this_vault_keeps_its_restored_copy_quarantined() {
    let mut v = fresh();
    let clean = export(&mut v.vault);
    let live = v
        .vault
        .set_quarantine("demo", QuarantineOptions { reason: Some("leaked in a log".into()), ..Default::default() })
        .unwrap();
    let once = restore(&mut v.vault, &clean, ConflictMode::Rename).unwrap();
    let to: Vec<String> = once.renamed.iter().map(|r| r.to.clone()).collect();
    assert_eq!(to, vec!["demo-restored", "other-restored"]);
    assert_eq!(quarantine_of(&v.vault, "demo-restored"), Some(live.clone()));
    assert_eq!(reveal(&v.vault, "demo-restored"), quarantined());
    assert_eq!(quarantine_of(&v.vault, "other-restored"), None);
    v.vault.clear_quarantine("demo").unwrap();
    restore(&mut v.vault, &clean, ConflictMode::Rename).unwrap();
    assert_eq!(quarantine_of(&v.vault, "demo-restored-2"), Some(live.clone()));
    v.vault.delete_credential("demo").unwrap();
    let back = restore(&mut v.vault, &clean, ConflictMode::Rename).unwrap();
    assert!(back.restored.contains(&"demo".to_string()));
    assert_eq!(quarantine_of(&v.vault, "demo"), Some(live));
    assert_eq!(reveal(&v.vault, "demo"), quarantined());
    let mut t = fresh();
    let own = t.vault.set_quarantine("demo", tripwire("burst", None)).unwrap();
    let b = export(&mut t.vault);
    restore(&mut t.vault, &b, ConflictMode::Rename).unwrap();
    assert_eq!(quarantine_of(&t.vault, "demo-restored"), Some(own));
}

#[test]
fn c_only_the_same_credential_holds_a_restore() {
    let mut v = fresh();
    let bundle = export(&mut v.vault);
    v.vault.set_quarantine("other", QuarantineOptions::default()).unwrap();
    v.vault.add_credential(new_cred("demo-x", "http", "api.example.com", &[("token", "tok_DEMOXLOOKALIKE00112233445566")])).unwrap();
    v.vault.set_quarantine("demo-x", QuarantineOptions::default()).unwrap();
    restore(&mut v.vault, &bundle, ConflictMode::Rename).unwrap();
    assert_eq!(quarantine_of(&v.vault, "demo-restored"), None);
    let id = v.vault.find_credential("demo-restored").unwrap().unwrap().id;
    assert_eq!(v.vault.reveal_field(&id, "token").unwrap().expose_secret(), SECRET);
    assert_eq!(quarantine_of(&v.vault, "other-restored"), quarantine_of(&v.vault, "other"));
}

#[test]
fn d_a_bundle_with_no_quarantine_field_restores_as_not_quarantined_and_c_still_holds() {
    let mut v = fresh();
    let old = v1_bundle(
        &json!({ "credentials": [old_entry("demo", "ghp_OLDBUNDLEDEMO0011223344556677889900"), old_entry("third", "ghp_OLDBUNDLETHIRD011223344556677889900")], "templates": [] }),
        RECOVERY,
    );
    v.vault.set_quarantine("demo", QuarantineOptions { reason: Some("rotating".into()), ..Default::default() }).unwrap();
    let out = restore(&mut v.vault, &old, ConflictMode::Rename).unwrap();
    assert_eq!(out.restored, vec!["demo-restored", "third"]);
    assert_eq!(serde_json::to_value(&out.renamed).unwrap(), json!([{ "from": "demo", "to": "demo-restored" }]));
    assert_eq!(quarantine_of(&v.vault, "third"), None);
    let id = v.vault.find_credential("third").unwrap().unwrap().id;
    assert_eq!(v.vault.reveal_field(&id, "token").unwrap().expose_secret(), "ghp_OLDBUNDLETHIRD011223344556677889900");
    assert_eq!(quarantine_of(&v.vault, "demo-restored"), quarantine_of(&v.vault, "demo"));
    assert_eq!(reveal(&v.vault, "demo-restored"), quarantined());
}

#[test]
fn an_ordinary_restore_of_credentials_never_quarantined_stores_no_quarantine_and_records_none() {
    let mut v = fresh();
    let mut t = empty();
    let bundle = export(&mut v.vault);
    let seq = t.vault.audit().unwrap().seq();
    assert_eq!(restore(&mut t.vault, &bundle, ConflictMode::Skip).unwrap().restored, vec!["demo", "other"]);
    for slug in ["demo", "other"] {
        assert_eq!(quarantine_of(&t.vault, slug), None);
    }
    assert!(records(&t.vault, "cred.quarantined").iter().all(|r| r.seq <= seq));
    let sess = session(&mut t.vault);
    let demo_id = t.vault.find_credential("demo").unwrap().unwrap().id;
    let g = grant_for(&mut t.vault, &sess.id, &demo_id);
    let row = issue(&mut t.vault, &g.id);
    assert_eq!(t.vault.consume_placeholder(&row.id).unwrap().uses, 1);
    assert_eq!(t.vault.reveal_field(&demo_id, "token").unwrap().expose_secret(), SECRET);
}

#[test]
fn a_quarantine_record_that_cannot_be_read_refuses_the_whole_restore_rather_than_being_dropped() {
    let mut v = fresh();
    let since = iso(now());
    for q in [
        json!("yes"), json!([]), json!({}), json!({ "since": since, "by": "agent" }), json!({ "since": "not a date", "by": "control" }),
        json!({ "since": since, "by": "control", "rule_id": "NOT A RULE" }), json!({ "since": since, "by": "control", "reason_untrusted": "x".repeat(201) }),
        json!({ "since": since, "by": "control", "released": true }),
    ] {
        let before = snapshot(&v.vault);
        let seq = v.vault.audit().unwrap().seq();
        let mut e = old_entry("third", "ghp_MALFORMEDQ00112233445566778899aa");
        e["quarantine"] = q.clone();
        let bundle = v1_bundle(&json!({ "credentials": [e], "templates": [] }), RECOVERY);
        assert_eq!(code(restore(&mut v.vault, &bundle, ConflictMode::Skip)), rule("AV_POLICY_DENIED", Some("backup_format")), "{q}");
        assert_eq!(snapshot(&v.vault).0, before.0);
        let added: Vec<Value> = v.vault.audit().unwrap().read(&crate::audit::ReadFilter { limit: 0, ..Default::default() }).unwrap()
            .into_iter().filter(|r| r.seq > seq).map(|r| json!([r.kind, field(&r, "reason")])).collect();
        assert_eq!(added, vec![json!(["backup.refused", "backup_format"])]);
    }
    let mut e = old_entry("third", "ghp_MALFORMEDQ00112233445566778899aa");
    e["quarantine"] = json!({ "since": since, "by": "control", "rule_id": null, "reason_untrusted": null });
    let ok = v1_bundle(&json!({ "credentials": [e], "templates": [] }), RECOVERY);
    assert_eq!(restore(&mut v.vault, &ok, ConflictMode::Skip).unwrap().restored, vec!["third"]);
    assert_eq!(quarantine_of(&v.vault, "third").unwrap().by, QuarantineBy::Control);
}
