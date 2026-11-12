//! Old key material is gone from the files after it is replaced: after a
//! passphrase change the old VMK wrap, and after a credential delete its
//! ciphertext, appear nowhere in `vault.db` or its `-wal` (rust/PLAN.md,
//! "Storage contract": `secure_delete=ON`, and `wal_checkpoint(TRUNCATE)`
//! after every factor or credential-secret change). Each has a control that
//! the scan finds the material while it is still live.

use super::helpers::*;
use crate::model::FactorClass;
use crate::vault::*;

/// Every byte of the database and its WAL (and the shared-memory index).
fn file_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        if let Ok(b) = std::fs::read(dir.join(name)) {
            out.extend_from_slice(&b);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// The parts of a sealed value that identify it: its nonce and the first 40
/// characters of its ciphertext, as stored (base64 text).
fn marks(sealed: &crate::crypto::SealedV2) -> [String; 2] {
    [
        sealed.n.clone(),
        sealed.c[..40.min(sealed.c.len())].to_string(),
    ]
}

fn passphrase_wrap(v: &Vault) -> crate::model::VmkWrap {
    let c = v.conn();
    crate::rows::wraps_get(&c)
        .unwrap()
        .into_iter()
        .find(|w| w.class == FactorClass::Passphrase)
        .unwrap()
}

#[test]
fn after_a_passphrase_change_the_old_wrap_is_in_neither_the_database_nor_the_wal() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some("the-first-passphrase"));
    let old = passphrase_wrap(&fx.vault);
    // Control: while it is live, the scan finds it.
    let live = file_bytes(fx.dir.path());
    for m in marks(&old.sealed) {
        assert!(
            contains(&live, &m),
            "the scan cannot see a live wrap; it proves nothing"
        );
    }
    // Ordinary traffic after the wrap was written, so pages move around.
    for i in 0..50 {
        fx.vault
            .update_settings(&serde_json::json!({ "note": i }))
            .unwrap();
    }
    fx.vault
        .set_passphrase(
            &s("the-second-passphrase"),
            Some(&s("the-first-passphrase")),
        )
        .unwrap();
    let new = passphrase_wrap(&fx.vault);
    assert_ne!(new.sealed, old.sealed);
    let after = file_bytes(fx.dir.path());
    for m in marks(&old.sealed) {
        assert!(
            !contains(&after, &m),
            "the old VMK wrap survived in vault.db or its WAL"
        );
    }
    for m in marks(&new.sealed) {
        assert!(
            contains(&after, &m),
            "the new wrap is missing; the scan is not reading the files"
        );
    }
    let wal = std::fs::metadata(fx.dir.path().join("vault.db-wal"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert_eq!(wal, 0, "the WAL was not truncated after a factor change");
}

#[test]
fn after_a_credential_delete_its_ciphertext_is_in_neither_the_database_nor_the_wal() {
    let mut fx = fresh();
    let sealed = fx.vault.find_credential("demo").unwrap().unwrap().fields[0]
        .sealed
        .clone();
    let keep = fx.vault.find_credential("other").unwrap().unwrap().fields[0]
        .sealed
        .clone();
    let live = file_bytes(fx.dir.path());
    for m in marks(&sealed) {
        assert!(
            contains(&live, &m),
            "the scan cannot see a live ciphertext; it proves nothing"
        );
    }
    let sess = session(&mut fx.vault);
    let g = grant_for(&mut fx.vault, &sess.id, &fx.cred.id);
    issue(&mut fx.vault, &g.id);
    fx.vault.delete_credential("demo").unwrap();
    let after = file_bytes(fx.dir.path());
    for m in marks(&sealed) {
        assert!(
            !contains(&after, &m),
            "the deleted credential's ciphertext survived"
        );
    }
    for m in marks(&keep) {
        assert!(
            contains(&after, &m),
            "another credential's ciphertext is missing; the scan is not reading the files"
        );
    }
    // Its grants outlive it, revoked, as the JS keeps them.
    assert_eq!(
        grant_row(&fx.vault, &g.id).state,
        crate::model::GrantState::Revoked
    );
}

#[test]
fn after_a_rotation_with_no_retire_window_the_old_ciphertext_is_gone() {
    let mut fx = fresh();
    let sealed = fx.vault.find_credential("demo").unwrap().unwrap().fields[0]
        .sealed
        .clone();
    fx.vault
        .rotate_credential(
            "demo",
            RotateOptions {
                field: None,
                value: s("ghp_ROTATEDAWAY00112233445566778899aabb"),
                mode: RotateMode::Keep,
                retire_ms: 0,
                expires_at: None,
            },
        )
        .unwrap();
    let after = file_bytes(fx.dir.path());
    for m in marks(&sealed) {
        assert!(
            !contains(&after, &m),
            "the rotated-out ciphertext survived with no retire window"
        );
    }
}

#[test]
fn no_plaintext_value_is_ever_written_to_the_files() {
    let mut fx = fresh();
    fx.vault
        .set_notify_webhook(
            &s("https://hooks.example/T/B/NOTIFYPATHSECRET"),
            crate::model::NotifyDetail::Minimal,
        )
        .unwrap();
    let bytes = file_bytes(fx.dir.path());
    for secret in [SECRET, OTHER_SECRET, "NOTIFYPATHSECRET"] {
        assert!(
            !contains(&bytes, secret),
            "a plaintext reached the database"
        );
    }
}
