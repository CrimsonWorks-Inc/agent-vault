//! Fixes from the first av-store review (`review-store-1.md`): grant runtime
//! state, restore and create atomicity, checkpoints, the busy checkpoint,
//! and the production backup KDF check. Each has a named shape and a control.

use serde_json::{json, Value};

use super::helpers::*;
use crate::backup::*;
use crate::model::GrantRuntime;
use crate::vault::*;

const RECOVERY: &str = "correct horse battery staple";

fn wal_len(dir: &std::path::Path) -> u64 {
    std::fs::metadata(dir.join("vault.db-wal"))
        .map(|m| m.len())
        .unwrap_or(0)
}

fn runtime() -> GrantRuntime {
    GrantRuntime {
        quota_state: Some(
            json!({ "window_ms": 86_400_000u64, "start": 1_700_000_000_000u64, "count": 7, "prev": 2 }),
        ),
        spend: Some(json!({
            "tokens_used": 40, "usd_micros_used": 9,
            "reserved": { "rq_kept": { "tokens": 12, "usd_micros": 3, "at": 1_700_000_000_500u64 } }
        })),
    }
}

// ------------------------------------------------------ grant runtime

#[test]
fn grant_runtime_round_trips_and_a_new_grant_starts_at_the_js_default() {
    let mut fx = fresh();
    let sid = session(&mut fx.vault).id;
    let g = grant_for(&mut fx.vault, &sid, &fx.cred.id);
    // Control: a fresh grant has no window and no spend yet.
    assert_eq!(
        fx.vault.grant_runtime(&g.id).unwrap(),
        Some(GrantRuntime::default())
    );
    let rt = runtime();
    fx.vault.set_grant_runtime(&g.id, &rt).unwrap();
    assert_eq!(fx.vault.grant_runtime(&g.id).unwrap(), Some(rt.clone()));
    // Key order is kept as written (the JS object's order).
    let text =
        serde_json::to_string(&fx.vault.grant_runtime(&g.id).unwrap().unwrap().spend).unwrap();
    assert!(text.starts_with(r#"{"tokens_used":40,"usd_micros_used":9,"reserved":"#));
    // A later grant_put (a charge, a narrow) leaves the runtime alone.
    fx.vault.charge_grant(&g.id, 1).ok();
    assert_eq!(fx.vault.grant_runtime(&g.id).unwrap(), Some(rt));
    // Clearing goes back to the default.
    fx.vault
        .set_grant_runtime(&g.id, &GrantRuntime::default())
        .unwrap();
    assert_eq!(
        fx.vault.grant_runtime(&g.id).unwrap(),
        Some(GrantRuntime::default())
    );
}

#[test]
fn grant_runtime_survives_a_reopen() {
    let mut fx = fresh();
    let sid = session(&mut fx.vault).id;
    let g = grant_for(&mut fx.vault, &sid, &fx.cred.id);
    fx.vault.set_grant_runtime(&g.id, &runtime()).unwrap();
    let path = fx.dir.path().to_path_buf();
    drop(fx.vault);
    let mut v = Vault::open(&path).unwrap();
    // Readable locked too: the pipeline only runs unlocked, but the row is
    // not secret.
    assert_eq!(v.grant_runtime(&g.id).unwrap(), Some(runtime()));
    v.unlock(None).unwrap();
    assert_eq!(v.grant_runtime(&g.id).unwrap(), Some(runtime()));
}

#[test]
fn grant_runtime_of_a_missing_grant_is_none_and_setting_it_is_refused() {
    let mut fx = fresh();
    assert_eq!(fx.vault.grant_runtime("gr_NOPE").unwrap(), None);
    let e = fx.vault.set_grant_runtime("gr_NOPE", &runtime());
    assert_eq!(code_of(e), "AV_NOT_FOUND");
    // Control: a real grant is accepted.
    let sid = session(&mut fx.vault).id;
    let g = grant_for(&mut fx.vault, &sid, &fx.cred.id);
    fx.vault.set_grant_runtime(&g.id, &runtime()).unwrap();
}

#[test]
fn the_schema_refuses_runtime_state_that_is_not_json() {
    let mut fx = fresh();
    let sid = session(&mut fx.vault).id;
    let g = grant_for(&mut fx.vault, &sid, &fx.cred.id);
    let r = fx.vault.conn().execute(
        "UPDATE grants SET spend = 'not json' WHERE id = ?1",
        [&g.id],
    );
    assert!(r.is_err(), "a non-JSON spend was stored");
}

// ------------------------------------------------- minor 1: restore

#[test]
fn backup_restored_commits_with_the_restore_or_not_at_all() {
    let mut src = fresh();
    let bundle =
        serde_json::to_value(export_backup(&mut src.vault, &s(RECOVERY)).unwrap().bundle).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut t = Vault::create(dir.path(), CreateOptions::default()).unwrap();
    // Shape: the summary record cannot be written. The whole restore must
    // roll back, not leave credentials behind a reported failure.
    t.conn()
        .execute_batch(
            "CREATE TEMP TRIGGER refuse_restored BEFORE INSERT ON main.audit
             WHEN NEW.kind = 'backup.restored'
             BEGIN SELECT RAISE(ABORT, 'refused by the test'); END",
        )
        .unwrap();
    assert!(restore_backup(&mut t, &bundle, &s(RECOVERY), ConflictMode::Skip).is_err());
    assert!(
        t.credential_records().unwrap().is_empty(),
        "credentials committed although backup.restored was not written"
    );
    assert!(records(&t, "cred.added").is_empty());
    // Control: without the trigger the same restore commits with its record.
    t.conn()
        .execute_batch("DROP TRIGGER temp.refuse_restored")
        .unwrap();
    restore_backup(&mut t, &bundle, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert_eq!(t.credential_records().unwrap().len(), 2);
    let r = records(&t, "backup.restored");
    assert_eq!(r.len(), 1);
    assert_eq!(field(&r[0], "restored"), &json!(["demo", "other"]));
    assert_eq!(
        field(&r[0], "bundle_sha256"),
        &Value::from(bundle_digest(&bundle))
    );
    // backup.restored follows the per-credential records, as in the JS.
    let added = records(&t, "cred.added");
    assert!(added.iter().all(|a| a.seq < r[0].seq));
}

// ------------------------------------------------- minor 2: create

#[test]
fn create_writes_the_first_wrap_with_vault_created_and_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::create(dir.path(), CreateOptions::default()).unwrap();
    assert_eq!(
        wal_len(dir.path()),
        0,
        "the first wrap was left in the WAL after create"
    );
    let created = records(&v, "vault.created");
    assert_eq!(created.len(), 1);
    let wraps: i64 = v
        .conn()
        .query_row("SELECT count(*) FROM vmk_wraps", [], |r| r.get(0))
        .unwrap();
    assert_eq!(wraps, 1);
    // Control: an ordinary operation after create does use the WAL, so the
    // zero above is the checkpoint, not a WAL that is never written.
    let mut v = v;
    session(&mut v);
    assert!(wal_len(dir.path()) > 0);
}

// ------------------------------------------- minor 3: sign count

#[test]
fn a_new_sign_count_checkpoints_the_wal() {
    let mut fx = fresh();
    fx.vault.set_presence_key(&authenticator(P256_A)).unwrap();
    session(&mut fx.vault);
    assert!(wal_len(fx.dir.path()) > 0, "control: the WAL holds a write");
    fx.vault.record_presence_sign_count(9).unwrap();
    assert_eq!(
        wal_len(fx.dir.path()),
        0,
        "the WebAuthn row change was left in the WAL"
    );
    assert_eq!(fx.vault.presence_key().unwrap().unwrap().sign_count, 9);
}

// ------------------------------------------ minor 7: busy checkpoint

#[test]
fn a_busy_checkpoint_is_an_error() {
    assert!(checkpoint_outcome(0).is_ok());
    assert!(checkpoint_outcome(1).is_err());
}

#[test]
fn a_checkpoint_blocked_by_a_reader_is_reported_not_ignored() {
    let mut fx = fresh();
    session(&mut fx.vault);
    // A second connection holding a read snapshot keeps TRUNCATE from
    // finishing (busy = 1).
    let reader = rusqlite::Connection::open(fx.dir.path().join("vault.db")).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    session(&mut fx.vault);
    let busy = {
        let c = fx.vault.conn();
        c.busy_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        crate::vault::checkpoint_truncate(&c)
    };
    assert!(busy.is_err(), "a busy checkpoint was reported as done");
    // Control: once the reader ends, the same checkpoint succeeds.
    reader.execute_batch("COMMIT").unwrap();
    let c = fx.vault.conn();
    crate::vault::checkpoint_truncate(&c).unwrap();
    drop(c);
    assert_eq!(wal_len(fx.dir.path()), 0);
}

// ------------------------------- the production backup KDF, not cfg(test)

#[test]
fn a_bundle_with_the_production_argon2id_parameters_passes_the_production_check() {
    let b64 = |n: usize| crate::crypto::b64(&vec![7u8; n]);
    let bundle = |m: u32, t: u32, p: u32| {
        json!({
            "format": BACKUP_FORMAT, "version": 2, "created_at": "2026-11-11T00:00:00.000Z",
            "kdf": { "alg": "argon2id", "m": m, "t": t, "p": p, "salt": b64(16) },
            "cipher": CIPHER_V2, "nonce": b64(crate::crypto::V2_NONCE_LEN), "ct": b64(48)
        })
    };
    let prod = BACKUP_KDF_V2;
    assert_eq!((prod.m, prod.t, prod.p), (256 * 1024, 3, 1));
    let shipped = bundle(prod.m, prod.t, prod.p);
    assert!(
        check_envelope_with(&shipped, &prod).is_ok(),
        "a production v2 bundle is refused by the production check"
    );
    // Control: a bundle under other parameters is refused by that check, and
    // the production bundle is refused by the cheap test set (so this test is
    // not reading the cfg(test) set).
    assert!(check_envelope_with(&bundle(512, 1, 1), &prod).is_err());
    assert!(check_envelope_with(&bundle(prod.m, 2, 1), &prod).is_err());
    assert!(check_envelope(&shipped).is_err());
}
