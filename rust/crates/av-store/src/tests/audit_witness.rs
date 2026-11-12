//! Ports `test/security/store-audit-witness.test.js`, plus the store-level
//! audit cases of `fix-control-audit` (anchor, truncation, corruption).
//!
//! The JS edits `audit.jsonl` to tamper with the log; here the log is the
//! `audit` table, so a test drops its insert-only triggers first, as someone
//! with write access to the file could.

use serde_json::{json, Value};

use super::helpers::*;
use crate::audit::{AuditRecord, AuditRow, ExportOptions, ReadFilter, CHAIN_FIELDS, GENESIS};
use crate::vault::*;

fn busy(fx: &mut Fx) -> String {
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            label: Some("busy".into()),
            ..Default::default()
        },
    );
    let g = grant_for(v, &s.id, &fx.cred.id);
    let issued = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id,
            ..Default::default()
        })
        .unwrap();
    v.consume_placeholder(&issued.row.id).unwrap();
    issued.placeholder
}

fn log_rows(v: &Vault) -> Vec<AuditRecord> {
    v.audit()
        .unwrap()
        .rows()
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            AuditRow::Record(r) => Some(r),
            AuditRow::Unreadable { .. } => None,
        })
        .collect()
}

fn audit_key(v: &Vault) -> av_core::secret::Key32 {
    crate::crypto::k_audit(&crate::vault::tests_support::vmk(v))
}

fn mac(v: &Vault, msg: &str) -> String {
    crate::crypto::hex(&crate::crypto::hmac_sha256(&audit_key(v), msg.as_bytes()))
}

/// Remove the insert-only triggers, as a tamperer with the file would.
pub(super) fn unprotect(v: &Vault) {
    exec(v, "DROP TRIGGER audit_no_update", &[]);
    exec(v, "DROP TRIGGER audit_no_delete", &[]);
}

#[test]
fn export_returns_the_records_after_since_seq_exactly_as_stored_and_is_recorded_after_reading() {
    let mut fx = fresh();
    let placeholder = busy(&mut fx);
    let v = &mut fx.vault;
    let (seq, head) = (
        v.audit().unwrap().seq(),
        v.audit().unwrap().head().to_string(),
    );
    let out = v
        .audit_mut()
        .unwrap()
        .export(ExportOptions {
            since_seq: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!((out.head.seq, out.head.hash.clone()), (seq, head));
    let want: Vec<AuditRecord> = log_rows(v)
        .into_iter()
        .filter(|r| r.seq > 2 && r.seq <= seq)
        .collect();
    assert_eq!(out.rows, want);
    assert_eq!(out.next_seq, seq);
    for w in out.rows.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].hash);
    }
    let text = serde_json::to_string(&out).unwrap();
    assert!(!text.contains(SECRET) && !text.contains(&placeholder));
    let rec = &records(v, "audit.exported")[0];
    assert_eq!(
        (
            field(rec, "from_seq"),
            field(rec, "to_seq"),
            field(rec, "rows")
        ),
        (&json!(3), &json!(seq), &json!(seq - 2))
    );
    assert_eq!(rec.seq, seq + 1);
    assert!(v.audit().unwrap().verify().unwrap().ok);
    let now_seq = v.audit().unwrap().seq();
    let tail = v
        .audit_mut()
        .unwrap()
        .export(ExportOptions {
            since_seq: now_seq,
            ..Default::default()
        })
        .unwrap();
    assert_eq!((tail.rows.len(), tail.next_seq), (0, now_seq));
    let second = &records(v, "audit.exported")[1];
    assert_eq!(
        (field(second, "from_seq"), field(second, "to_seq")),
        (&Value::Null, &Value::Null)
    );
}

#[test]
fn the_export_limit_is_clamped_to_1_to_5000() {
    let mut fx = fresh();
    busy(&mut fx);
    let a = fx.vault.audit_mut().unwrap();
    assert_eq!(
        a.export(ExportOptions {
            since_seq: 0,
            limit: 0
        })
        .unwrap()
        .rows
        .len(),
        1
    );
    assert_eq!(
        a.export(ExportOptions {
            since_seq: 0,
            limit: 2
        })
        .unwrap()
        .rows
        .len(),
        2
    );
    let all = a.seq() as usize;
    assert_eq!(
        a.export(ExportOptions {
            since_seq: 0,
            limit: 1_000_000_000
        })
        .unwrap()
        .rows
        .len(),
        all
    );
    assert_eq!(
        a.export(ExportOptions {
            since_seq: 0,
            limit: 3
        })
        .unwrap()
        .next_seq,
        3
    );
}

#[test]
fn an_export_range_that_is_not_a_whole_number_is_refused_and_nothing_is_recorded() {
    // Negative, fractional and string ranges cannot be typed; the one
    // spelling left is past the JS safe-integer range.
    let mut fx = fresh();
    refused_cleanly(
        &mut fx.vault,
        |v| {
            v.audit_mut().unwrap().export(ExportOptions {
                since_seq: u64::MAX,
                limit: 10,
            })
        },
        ("AV_POLICY_DENIED", Some("audit_range")),
    );
}

#[test]
fn a_checkpoint_names_a_stable_vault_id_the_head_and_a_mac_and_keeps_the_chain_intact() {
    let mut fx = fresh();
    busy(&mut fx);
    let v = &mut fx.vault;
    let (seq, head) = (
        v.audit().unwrap().seq(),
        v.audit().unwrap().head().to_string(),
    );
    let c = v.audit_mut().unwrap().checkpoint().unwrap();
    assert_eq!((c.seq, c.head.clone()), (seq, head));
    assert!(c.vault_id.starts_with("vlt_") && c.vault_id.len() == 30);
    assert_eq!(
        c.mac,
        mac(
            v,
            &format!("witness|{}|{}|{}|{}", c.vault_id, c.seq, c.head, c.ts)
        )
    );
    let rec = &records(v, "audit.checkpoint_issued")[0];
    assert_eq!(field(rec, "checkpoint_seq"), &json!(seq));
    assert_eq!(rec.seq, seq + 1);
    assert!(v.audit().unwrap().verify().unwrap().ok);
    assert_eq!(
        v.audit_mut().unwrap().checkpoint().unwrap().vault_id,
        c.vault_id
    );
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    assert_eq!(
        again.audit_mut().unwrap().checkpoint().unwrap().vault_id,
        c.vault_id,
        "the vault id survives a restart"
    );
}

#[test]
fn an_untouched_log_reports_its_witnesses_ok_the_genesis_one_included() {
    let mut fx = fresh();
    let mut w =
        vec![serde_json::to_value(fx.vault.audit_mut().unwrap().checkpoint().unwrap()).unwrap()];
    busy(&mut fx);
    w.push(serde_json::to_value(fx.vault.audit_mut().unwrap().checkpoint().unwrap()).unwrap());
    busy(&mut fx);
    w.push(serde_json::to_value(fx.vault.audit_mut().unwrap().checkpoint().unwrap()).unwrap());
    let ts = iso(now());
    let id = w[0]["vault_id"].as_str().unwrap().to_string();
    let m = mac(&fx.vault, &format!("witness|{id}|0|{GENESIS}|{ts}"));
    w.push(json!({ "vault_id": id, "seq": 0, "head": GENESIS, "ts": ts, "mac": m }));
    let out = fx.vault.audit_mut().unwrap().verify_witness(&w).unwrap();
    assert_eq!(
        serde_json::to_value(&out).unwrap(),
        json!({ "ok": true, "checked": 4, "ahead": [], "mismatched": [], "forged": [], "other_vault": [] })
    );
    let rec = &records(&fx.vault, "audit.witness_verified")[0];
    assert_eq!(
        [
            field(rec, "ok"),
            field(rec, "checked"),
            field(rec, "ahead"),
            field(rec, "mismatched"),
            field(rec, "forged")
        ],
        [&json!(true), &json!(4), &json!(0), &json!(0), &json!(0)]
    );
}

#[test]
fn a_log_cut_back_after_a_witness_reports_it_ahead() {
    let mut fx = fresh();
    busy(&mut fx);
    let early = serde_json::to_value(fx.vault.audit_mut().unwrap().checkpoint().unwrap()).unwrap();
    busy(&mut fx);
    let late = fx.vault.audit_mut().unwrap().checkpoint().unwrap();
    unprotect(&fx.vault);
    exec(
        &fx.vault,
        "DELETE FROM audit WHERE seq > ?1",
        &[&((late.seq - 3) as i64)],
    );
    let late_seq = late.seq;
    let out = fx
        .vault
        .audit_mut()
        .unwrap()
        .verify_witness(&[early, serde_json::to_value(late).unwrap()])
        .unwrap();
    assert!(!out.ok);
    assert_eq!(out.ahead, vec![late_seq]);
    assert!(out.mismatched.is_empty());
}

#[test]
fn a_record_whose_hash_was_changed_reports_mismatched_and_a_changed_witness_reports_forged() {
    let mut fx = fresh();
    busy(&mut fx);
    let c = fx.vault.audit_mut().unwrap().checkpoint().unwrap();
    unprotect(&fx.vault);
    let row = log_rows(&fx.vault)
        .into_iter()
        .find(|r| r.seq == c.seq)
        .unwrap();
    let mut changed = serde_json::to_value(&row).unwrap();
    changed["hash"] = json!("f".repeat(64));
    exec(
        &fx.vault,
        "UPDATE audit SET hash = ?1, record = ?2 WHERE seq = ?3",
        &[&"f".repeat(64), &changed.to_string(), &(c.seq as i64)],
    );
    let cv = serde_json::to_value(&c).unwrap();
    assert_eq!(
        fx.vault
            .audit_mut()
            .unwrap()
            .verify_witness(std::slice::from_ref(&cv))
            .unwrap()
            .mismatched,
        vec![c.seq]
    );
    let with = |k: &str, val: Value| {
        let mut x = cv.clone();
        if val.is_null() {
            x.as_object_mut().unwrap().remove(k);
        } else {
            x[k] = val;
        }
        x
    };
    let forged = vec![
        with("seq", json!(c.seq - 1)),
        with("head", json!("a".repeat(64))),
        with("ts", json!(iso(0))),
        with("mac", json!("zz")),
        with("mac", Value::Null),
        Value::Null,
        json!("checkpoint"),
        json!([]),
        with("seq", json!("3")),
    ];
    let out = fx
        .vault
        .audit_mut()
        .unwrap()
        .verify_witness(&forged)
        .unwrap();
    assert_eq!(out.forged, (0..forged.len()).collect::<Vec<_>>());
    assert!(!out.ok);
}

#[test]
fn a_witness_for_another_vault_is_reported_and_does_not_by_itself_fail_the_check() {
    let mut fx = fresh();
    let c = serde_json::to_value(fx.vault.audit_mut().unwrap().checkpoint().unwrap()).unwrap();
    let mut other = c.clone();
    other["vault_id"] = json!("vlt_SOMEWHEREELSE0000000000000");
    let m = mac(
        &fx.vault,
        &format!(
            "witness|{}|{}|{}|{}",
            other["vault_id"].as_str().unwrap(),
            other["seq"],
            other["head"].as_str().unwrap(),
            other["ts"].as_str().unwrap()
        ),
    );
    other["mac"] = json!(m);
    let out = fx
        .vault
        .audit_mut()
        .unwrap()
        .verify_witness(&[c, other])
        .unwrap();
    assert!(out.ok);
    assert_eq!(out.other_vault, vec![1]);
    assert!(out.forged.is_empty());
}

#[test]
fn a_witness_list_that_is_too_long_is_refused() {
    let mut fx = fresh();
    let many: Vec<Value> = (0..10_001).map(|_| json!({})).collect();
    refused_cleanly(
        &mut fx.vault,
        |v| v.audit_mut().unwrap().verify_witness(&many),
        ("AV_POLICY_DENIED", Some("audit_range")),
    );
}

#[test]
fn a_caller_cannot_set_a_chain_field_write_refuses_it_naming_the_field_and_appends_nothing() {
    let mut fx = fresh();
    for k in CHAIN_FIELDS {
        let before = snapshot(&fx.vault);
        let seq = fx.vault.audit().unwrap().seq();
        let mut f = serde_json::Map::new();
        f.insert(k.into(), json!(7));
        f.insert("other".into(), json!(1));
        let e = fx
            .vault
            .audit_mut()
            .unwrap()
            .write("test.reserved", f)
            .unwrap_err();
        let ve = e.as_vault().expect("a refusal");
        assert_eq!(ve.code.as_str(), "AV_INTERNAL", "{k}");
        assert!(ve.detail.contains(k), "{}", ve.detail);
        assert_eq!(snapshot(&fx.vault), before, "{k}: something was appended");
        assert_eq!(fx.vault.audit().unwrap().seq(), seq);
    }
    let mut sorted = CHAIN_FIELDS.to_vec();
    sorted.sort_unstable();
    assert_eq!(sorted, vec!["hash", "kind", "prev_hash", "seq", "ts"]);
    let f = json!({ "checkpoint_seq": 3, "template_hash": "ab", "kinds": 1, "from_seq": 2 });
    fx.vault
        .audit_mut()
        .unwrap()
        .write("test.ordinary", f.as_object().unwrap().clone())
        .unwrap();
    assert!(fx.vault.audit().unwrap().verify().unwrap().ok);
}

/// The top-level keys of every `json!({ ... })` handed to an audit write in
/// this crate's source.
fn audit_literal_keys(src: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for marker in ["audit_required(", "t.audit(", ".write("] {
        let mut from = 0;
        while let Some(i) = src[from..].find(marker) {
            let start = from + i;
            from = start + marker.len();
            let rest = &src[from..];
            let Some(j) = rest.find("json!({") else {
                continue;
            };
            // Only a literal inside this call's own argument list.
            if rest[..j].contains(';') {
                continue;
            }
            let body_start = from + j + "json!(".len();
            let mut depth = 0i32;
            let mut top = String::new();
            for ch in src[body_start..].chars() {
                if matches!(ch, '{' | '[' | '(') {
                    depth += 1;
                }
                if depth == 1 {
                    top.push(ch);
                }
                if matches!(ch, '}' | ']' | ')') {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            let keys = top
                .split(',')
                .filter_map(|part| {
                    let p = part.trim().trim_start_matches('{').trim();
                    p.strip_prefix('"')
                        .and_then(|q| q.split('"').next())
                        .map(str::to_string)
                })
                .collect();
            out.push(keys);
        }
    }
    out
}

#[test]
fn no_audit_write_in_the_store_passes_a_chain_field() {
    let mut calls = 0;
    let mut bad = Vec::new();
    for (name, src) in [
        ("vault.rs", include_str!("../vault.rs")),
        ("backup.rs", include_str!("../backup.rs")),
        ("audit.rs", include_str!("../audit.rs")),
        ("migrate.rs", include_str!("../migrate.rs")),
    ] {
        for keys in audit_literal_keys(src) {
            calls += 1;
            for k in keys {
                if CHAIN_FIELDS.contains(&k.as_str()) {
                    bad.push(format!("{name}: {k}"));
                }
            }
        }
    }
    assert!(
        calls > 40,
        "found only {calls} audit writes; the scan has stopped reading the source"
    );
    assert!(bad.is_empty(), "{bad:?}");
    let probe = audit_literal_keys("t.audit(\"x\", json!({ \"a\": 1, \"seq\": n }))");
    assert_eq!(probe, vec![vec!["a".to_string(), "seq".to_string()]]);
}

// --------------------------------------------- anchor, truncation, corruption

#[test]
fn a_log_cut_back_while_stopped_is_reported_and_the_report_survives_new_writes() {
    let mut fx = fresh();
    busy(&mut fx);
    let n = fx.vault.audit().unwrap().seq();
    fx.vault.lock().unwrap();
    unprotect(&fx.vault);
    exec(
        &fx.vault,
        "DELETE FROM audit WHERE seq > ?1",
        &[&((n - 3) as i64)],
    );
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    let a = again.audit().unwrap();
    assert!(a.truncation().is_some());
    let r = a.verify().unwrap();
    assert!(!r.ok);
    assert!(r.reason.unwrap().contains("removed from the end"));
    busy_on(&mut again);
    assert!(
        !again.audit().unwrap().verify().unwrap().ok,
        "the finding is permanent"
    );
}

fn busy_on(v: &mut Vault) {
    v.audit_mut()
        .unwrap()
        .write("test.more", serde_json::Map::new())
        .unwrap();
}

#[test]
fn a_removed_anchor_on_an_anchored_vault_is_tampering_not_an_upgrade() {
    let mut fx = fresh();
    busy(&mut fx);
    fx.vault.lock().unwrap();
    std::fs::remove_file(fx.dir.path().join("vault.db.head")).unwrap();
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    let missing = again.audit().unwrap().anchor_missing().cloned().unwrap();
    assert!(missing.was_anchored);
    let r = again.audit().unwrap().verify().unwrap();
    assert!(!r.ok);
    assert!(r.reason.unwrap().contains("head anchor was removed"));
}

#[test]
fn an_unreadable_row_is_reported_as_corruption_and_does_not_lock_the_owner_out() {
    let mut fx = fresh();
    busy(&mut fx);
    fx.vault.lock().unwrap();
    unprotect(&fx.vault);
    exec(
        &fx.vault,
        "UPDATE audit SET record = '{}' WHERE seq = 2",
        &[],
    );
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again
        .unlock(None)
        .expect("a bad row must not cost the owner the vault");
    let c = again.audit().unwrap().corruption().cloned().unwrap();
    assert_eq!(c.lines, vec![2]);
    let r = again.audit().unwrap().verify().unwrap();
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(2));
    assert!(!records(&again, "audit.corruption_detected").is_empty());
}

#[test]
fn an_ordinary_restart_reports_nothing_and_verifies() {
    let mut fx = fresh();
    busy(&mut fx);
    fx.vault.lock().unwrap();
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    let a = again.audit().unwrap();
    assert!(a.truncation().is_none() && a.anchor_missing().is_none() && a.corruption().is_none());
    assert!(a.verify().unwrap().ok);
}

#[test]
fn read_filters_by_kind_session_since_and_request_and_keeps_the_newest() {
    let mut fx = fresh();
    busy(&mut fx);
    let a = fx.vault.audit().unwrap();
    let all = a
        .read(&ReadFilter {
            limit: 0,
            ..Default::default()
        })
        .unwrap();
    let sessions = a
        .read(&ReadFilter {
            limit: 100,
            kind: Some("session".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(sessions.iter().all(|r| r.kind.starts_with("session.")));
    let two = a
        .read(&ReadFilter {
            limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(two[1].seq, all.last().unwrap().seq);
}

// ------------------- fix-control-audit and audit-content, store-level parts

fn audit_fixture() -> Fx {
    let mut fx = fresh();
    for i in 0..5 {
        fx.vault
            .audit_mut()
            .unwrap()
            .write("test.event", json!({ "n": i }).as_object().unwrap().clone())
            .unwrap();
    }
    fx.vault.lock().unwrap();
    fx
}

fn reopen(fx: &Fx) -> Vault {
    let mut v = Vault::open(fx.dir.path()).unwrap();
    v.unlock_with(&UnlockMaterial::default()).unwrap();
    v
}

#[test]
fn an_untouched_log_reopens_and_verifies_clean() {
    let fx = audit_fixture();
    let v = reopen(&fx);
    assert!(v.audit().unwrap().verify().unwrap().ok);
}

#[test]
fn a_brand_new_vault_verifies_clean() {
    let fx = fresh();
    let r = fx.vault.audit().unwrap().verify().unwrap();
    assert!(r.ok, "{:?}", r.reason);
    assert_eq!(r.note, None);
}

#[test]
fn emptying_the_log_is_not_a_fresh_start() {
    // "deleting the log is not a fresh start": the table emptied, the anchor
    // left in place.
    let fx = audit_fixture();
    unprotect(&fx.vault);
    exec(&fx.vault, "DELETE FROM audit", &[]);
    let v = reopen(&fx);
    let t = v.audit().unwrap().truncation().cloned().unwrap();
    assert_eq!(t.found_seq, 0);
    assert!(t.expected_seq > 0);
    assert!(!v.audit().unwrap().verify().unwrap().ok);
}

#[test]
fn emptying_the_log_and_deleting_its_anchor_together_is_not_a_fresh_start() {
    let fx = audit_fixture();
    unprotect(&fx.vault);
    exec(&fx.vault, "DELETE FROM audit", &[]);
    std::fs::remove_file(fx.dir.path().join("vault.db.head")).unwrap();
    let v = reopen(&fx);
    let m = v.audit().unwrap().anchor_missing().cloned().unwrap();
    assert_eq!((m.found_seq, m.was_anchored), (0, true));
    assert!(!v.audit().unwrap().verify().unwrap().ok);
}

#[test]
fn a_log_emptied_while_the_vault_is_open_is_reported_not_passed() {
    let mut fx = fresh();
    busy(&mut fx);
    unprotect(&fx.vault);
    exec(&fx.vault, "DELETE FROM audit", &[]);
    let r = fx.vault.audit().unwrap().verify().unwrap();
    assert!(!r.ok);
    assert!(r.reason.unwrap().contains("removed from the end"));
}

#[test]
fn a_float_in_caller_fields_is_recorded_not_thrown_after_the_fact() {
    let mut fx = fresh();
    let rec = fx
        .vault
        .audit_mut()
        .unwrap()
        .write("test.float", json!({ "reason": 1.5, "nested": [2.25, 3], "whole": 4.0 }).as_object().unwrap().clone())
        .unwrap();
    assert_eq!(rec.fields["reason"], json!("1.5"));
    assert_eq!(rec.fields["nested"], json!(["2.25", 3]));
    assert_eq!(rec.fields["whole"], json!(4));
    assert!(fx.vault.audit().unwrap().verify().unwrap().ok);
}

#[test]
fn ordinary_records_checkpoints_included_are_all_recognised_as_records() {
    let mut fx = fresh();
    for i in 0..1005 {
        fx.vault
            .audit_mut()
            .unwrap()
            .write("test.event", json!({ "n": i }).as_object().unwrap().clone())
            .unwrap();
    }
    assert_eq!(records(&fx.vault, "checkpoint").len(), 1);
    fx.vault.lock().unwrap();
    let v = reopen(&fx);
    let a = v.audit().unwrap();
    assert!(a.corruption().is_none());
    assert!(a.verify().unwrap().ok);
}

#[test]
fn a_record_shaped_wrongly_is_unreadable_even_when_it_parses() {
    // isRecord: parsing is not enough; a hash that is not 64 hex characters
    // is not a record.
    let mut fx = fresh();
    busy(&mut fx);
    fx.vault.lock().unwrap();
    unprotect(&fx.vault);
    exec(
        &fx.vault,
        "UPDATE audit SET record = '{\"seq\":2,\"ts\":\"x\",\"kind\":\"k\",\"prev_hash\":\"zz\",\"hash\":\"zz\"}' WHERE seq = 2",
        &[],
    );
    let v = reopen(&fx);
    assert_eq!(v.audit().unwrap().corruption().map(|c| c.lines.clone()), Some(vec![2]));
}

#[test]
fn the_chain_verifies_and_editing_a_record_breaks_it() {
    let mut fx = fresh();
    busy(&mut fx);
    assert!(fx.vault.audit().unwrap().verify().unwrap().ok);
    unprotect(&fx.vault);
    let row = log_rows(&fx.vault).into_iter().find(|r| r.seq == 3).unwrap();
    let mut edited = serde_json::to_value(&row).unwrap();
    edited["kind"] = json!("nothing.to.see");
    exec(&fx.vault, "UPDATE audit SET record = ?1 WHERE seq = 3", &[&edited.to_string()]);
    let r = fx.vault.audit().unwrap().verify().unwrap();
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(3));
}

#[test]
fn truncating_and_then_deleting_the_anchor_does_not_launder_the_truncation() {
    let mut fx = fresh();
    for i in 0..10 {
        fx.vault.audit_mut().unwrap().write("test.event", json!({ "n": i }).as_object().unwrap().clone()).unwrap();
    }
    assert!(fx.vault.audit().unwrap().verify().unwrap().ok);
    let mut v = fx.vault;
    for round in 1..=3 {
        unprotect_if_needed(&v);
        let max: i64 = v.conn().query_row("SELECT max(seq) FROM audit", [], |r| r.get(0)).unwrap();
        exec(&v, "DELETE FROM audit WHERE seq > ?1", &[&(max - 3)]);
        let _ = std::fs::remove_file(fx.dir.path().join("vault.db.head"));
        drop(v);
        v = Vault::open(fx.dir.path()).unwrap();
        v.unlock_with(&UnlockMaterial::default()).unwrap();
        let r = v.audit().unwrap().verify().unwrap();
        assert!(!r.ok, "round {round}: the truncation was laundered");
        let reason = r.reason.unwrap();
        assert!(reason.contains("anchor was removed") || reason.contains("removed from the end"), "{reason}");
    }
}

fn unprotect_if_needed(v: &Vault) {
    let n: i64 = v
        .conn()
        .query_row("SELECT count(*) FROM sqlite_schema WHERE type = 'trigger' AND name LIKE 'audit_no_%'", [], |r| r.get(0))
        .unwrap();
    if n > 0 {
        unprotect(v);
    }
}

#[test]
fn a_vault_upgraded_from_a_build_without_anchors_is_not_accused_of_tampering() {
    let mut fx = fresh();
    for i in 0..4 {
        fx.vault.audit_mut().unwrap().write("test.event", json!({ "n": i }).as_object().unwrap().clone()).unwrap();
    }
    // Exactly what a pre-anchor build left behind: a log, no anchor, no stamp.
    exec(&fx.vault, "DELETE FROM kv WHERE key = 'audit_anchored'", &[]);
    std::fs::remove_file(fx.dir.path().join("vault.db.head")).unwrap();
    let upgraded = reopen(&fx);
    let r = upgraded.audit().unwrap().verify().unwrap();
    assert!(r.ok, "an upgrade must not read as tampering: {:?}", r.reason);
    assert!(r.unanchored_before.is_some());
    assert!(r.note.unwrap().contains("nothing proves how many records preceded"));
    assert!(!records(&upgraded, "audit.anchor_missing").is_empty());
    drop(upgraded);
    std::fs::remove_file(fx.dir.path().join("vault.db.head")).unwrap();
    let after = reopen(&fx);
    assert!(!after.audit().unwrap().verify().unwrap().ok, "once anchored, a later removal must be reported");
}
