//! Ports `test/core/passphrase.test.js`.

use super::helpers::*;
use crate::model::FactorClass;
use crate::vault::*;

fn none_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::create(dir.path(), CreateOptions::default()).unwrap();
    (dir, v)
}

fn prf(bytes: &[u8]) -> av_core::secret::SecretBytes {
    av_core::secret::SecretBytes::from(bytes.to_vec())
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_none_vault_unlocks_with_no_secret_and_a_passphrase_vault_does_not() {
    let (dir, mut v) = none_vault();
    assert!(!v.has_passphrase().unwrap());
    v.set_passphrase(&s("correct horse battery"), None).unwrap();
    assert!(v.has_passphrase().unwrap());
    v.lock().unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    assert_eq!(code_of(r.unlock(None)), "AV_LOCKED");
    assert_eq!(code_of(r.unlock(Some(&s("wrong")))), "AV_LOCKED");
    assert!(r.unlock(Some(&s("correct horse battery"))).unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn locking_a_passphrase_vault_zeroizes_a_key_that_disk_alone_cannot_recover() {
    let (dir, mut v) = none_vault();
    v.add_credential(new_cred(
        "x",
        "http",
        "h",
        &[("token", "super-secret-value")],
    ))
    .unwrap();
    v.set_passphrase(&s("correct horse battery"), None).unwrap();
    v.lock().unwrap();
    let r = Vault::open(dir.path()).unwrap();
    let id = r.find_credential("x").unwrap().unwrap().id;
    assert_eq!(code_of(r.reveal_field(&id, "token")), "AV_LOCKED");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn changing_a_passphrase_requires_the_current_one() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("first-passphrase"), None).unwrap();
    let e = v.set_passphrase(&s("second-passphrase"), Some(&s("wrong")));
    assert!(err_msg(e).contains("current passphrase is required"));
    v.set_passphrase(&s("second-passphrase"), Some(&s("first-passphrase")))
        .unwrap();
    v.lock().unwrap();
    assert!(Vault::open(dir.path())
        .unwrap()
        .unlock(Some(&s("second-passphrase")))
        .unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn removing_a_passphrase_requires_the_current_one_then_unlock_needs_no_secret() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("the-passphrase"), None).unwrap();
    v.set_presence_key(&authenticator(P256_A)).unwrap();
    assert!(err_msg(v.remove_passphrase(&s("wrong"))).contains("current passphrase is required"));
    v.remove_passphrase(&s("the-passphrase")).unwrap();
    assert!(!v.has_passphrase().unwrap());
    v.lock().unwrap();
    assert!(Vault::open(dir.path()).unwrap().unlock(None).unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_passphrase_cannot_be_removed_while_it_is_the_last_human_factor() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("the-passphrase"), None).unwrap();
    let before = snapshot(&v);
    let r = v.remove_passphrase(&s("the-passphrase"));
    let e = r.unwrap_err();
    let ve = e.as_vault().unwrap();
    assert_eq!(ve.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(ve.extra.rule.as_deref(), Some("last_factor"));
    assert!(ve.extra.hint.as_deref().unwrap().contains("agent-vault ui"));
    assert!(v.has_passphrase().unwrap());
    assert_eq!(snapshot(&v), before, "a refusal must not write anything");
    v.lock().unwrap();
    assert_eq!(
        code_of(Vault::open(dir.path()).unwrap().unlock(None)),
        "AV_LOCKED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_passphrase_under_8_characters_is_refused() {
    let (_dir, mut v) = none_vault();
    assert!(err_msg(v.set_passphrase(&s("short"), None)).contains("at least 8"));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn touch_id_a_prf_secret_unlocks_the_vault_alongside_the_passphrase() {
    let (dir, mut v) = none_vault();
    let e = v.add_webauthn_unlock("cred-1", &prf(&[7u8; 32]));
    assert!(err_msg(e).contains("set a passphrase first"));
    v.set_passphrase(&s("recovery-passphrase"), None).unwrap();
    let secret = [9u8; 32];
    v.add_webauthn_unlock("cred-1", &prf(&secret)).unwrap();
    assert!(v.has_webauthn_unlock().unwrap());
    assert_eq!(
        v.webauthn_unlock_credential_id().unwrap().as_deref(),
        Some("cred-1")
    );
    v.lock().unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    let wrong = UnlockMaterial {
        prf_secret: Some(prf(&[1u8; 32])),
        passphrase: None,
    };
    assert_eq!(code_of(r.unlock_with(&wrong)), "AV_LOCKED");
    let right = UnlockMaterial {
        prf_secret: Some(prf(&secret)),
        passphrase: None,
    };
    assert_eq!(r.unlock_with(&right).unwrap(), FactorClass::WebauthnPrf);
    r.lock().unwrap();
    let mut r2 = Vault::open(dir.path()).unwrap();
    let pass = UnlockMaterial {
        passphrase: Some(s("recovery-passphrase")),
        prf_secret: None,
    };
    assert_eq!(r2.unlock_with(&pass).unwrap(), FactorClass::Passphrase);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_passphrase_cannot_be_removed_while_touch_id_is_the_other_factor() {
    let (_dir, mut v) = none_vault();
    v.set_passphrase(&s("recovery-passphrase"), None).unwrap();
    v.add_webauthn_unlock("cred-1", &prf(&[3u8; 32])).unwrap();
    let e = v.remove_passphrase(&s("recovery-passphrase")).unwrap_err();
    assert_eq!(
        e.as_vault().unwrap().extra.rule.as_deref(),
        Some("last_factor")
    );
    assert!(e.to_string().contains("remove Touch ID unlock first"));
    v.remove_webauthn_unlock().unwrap();
    let e = v.remove_passphrase(&s("recovery-passphrase")).unwrap_err();
    assert_eq!(
        e.as_vault().unwrap().extra.rule.as_deref(),
        Some("last_factor")
    );
    v.set_presence_key(&authenticator(P256_A)).unwrap();
    assert!(v.remove_passphrase(&s("recovery-passphrase")).unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn removing_the_last_unlock_factor_leaves_the_vault_openable_not_destroyed() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("recovery-passphrase"), None).unwrap();
    v.add_webauthn_unlock("cred-1", &prf(&[5u8; 32])).unwrap();
    // Corrupt it the way the JS test does: only the PRF wrap left.
    exec(
        &v,
        "DELETE FROM vmk_wraps WHERE class != 'webauthn-prf'",
        &[],
    );
    v.remove_webauthn_unlock().unwrap();
    let n: i64 = v
        .conn()
        .query_row("SELECT count(*) FROM vmk_wraps", [], |r| r.get(0))
        .unwrap();
    assert!(n > 0, "the vault was left with no way to open it");
    v.lock().unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    assert_eq!(
        r.unlock_with(&UnlockMaterial::default()).unwrap(),
        FactorClass::None
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn setting_a_passphrase_keeps_an_existing_touch_id_factor() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("first-passphrase"), None).unwrap();
    let secret = [6u8; 32];
    v.add_webauthn_unlock("cred-1", &prf(&secret)).unwrap();
    v.set_passphrase(&s("second-passphrase"), Some(&s("first-passphrase")))
        .unwrap();
    assert!(v.has_webauthn_unlock().unwrap());
    v.lock().unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    let m = UnlockMaterial {
        prf_secret: Some(prf(&secret)),
        passphrase: None,
    };
    assert_eq!(r.unlock_with(&m).unwrap(), FactorClass::WebauthnPrf);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_passphrase_vault_comes_up_locked_after_a_restart_not_crashed() {
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("the-passphrase"), None).unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    assert!(!r.start_in_recorded_state(None).unwrap());
    assert!(r.locked());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_failed_unlock_leaves_nothing_half_open() {
    // The JS made audit.jsonl a directory. Here the anchor beside vault.db
    // is made one, so the log cannot be opened and anchored.
    let (dir, mut v) = none_vault();
    v.add_credential(new_cred(
        "x",
        "http",
        "h",
        &[("token", "a-secret-value-here")],
    ))
    .unwrap();
    v.set_passphrase(&s("the-owners-passphrase"), None).unwrap();
    v.lock().unwrap();
    let anchor = dir.path().join("vault.db.head");
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();
    std::fs::write(anchor.join("keep"), "x").unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    let m = UnlockMaterial {
        passphrase: Some(s("the-owners-passphrase")),
        prf_secret: None,
    };
    assert_eq!(
        code_of(r.unlock_with(&m)),
        "AV_LOCKED",
        "a vault whose log cannot be opened must not report success"
    );
    assert!(r.locked());
    assert!(r.audit().is_none());
    let id = r.find_credential("x").unwrap().unwrap().id;
    assert_eq!(code_of(r.reveal_field(&id, "token")), "AV_LOCKED");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_permissive_vault_file_is_reset_to_0600_on_open() {
    // Ports "a leftover temp file cannot hand the vault a permissive mode":
    // SQLite has no temp file; the database itself is held to 0600.
    use std::os::unix::fs::PermissionsExt;
    let (dir, v) = none_vault();
    drop(v);
    let db = dir.path().join("vault.db");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o666)).unwrap();
    let mut v = Vault::open(dir.path()).unwrap();
    v.unlock(None).unwrap();
    v.add_credential(new_cred(
        "x",
        "http",
        "example.com",
        &[("token", "value-long-enough")],
    ))
    .unwrap();
    let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the vault ended up mode {mode:o}");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_placeholder_ledger_does_not_grow_without_bound() {
    let (_dir, mut v) = none_vault();
    let cred = v
        .add_credential(new_cred(
            "x",
            "http",
            "h",
            &[("token", "a-secret-value-here")],
        ))
        .unwrap();
    let sess = session(&mut v);
    let g = v
        .create_grant(CreateGrantOptions {
            policy: policy_from(serde_json::json!({ "hosts": ["h"], "methods": ["GET"], "paths": ["/**"], "budget": { "unit": "requests", "limit": 100000 } })),
            ..grant_opts(&sess.id, &cred.id)
        })
        .unwrap();
    for _ in 0..900 {
        issue(&mut v, &g.id);
    }
    let rows = v.list_placeholders(None).unwrap();
    assert!(rows.len() <= 600, "900 mints left {} rows", rows.len());
    assert!(rows
        .iter()
        .any(|p| p.state == crate::model::PlaceholderState::Active));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_wrap_made_with_the_production_argon2id_parameters_opens() {
    // The suite uses cheap Argon2id parameters; this one derives with the
    // PLAN's (m = 64 MiB, t = 3, p = 1) and proves the stored parameters are
    // what verification reads.
    let (dir, mut v) = none_vault();
    v.set_passphrase(&s("production-params"), None).unwrap();
    let device = crate::vault::tests_support::device_key(dir.path());
    let real_vmk = crate::vault::tests_support::vmk(&v);
    let mut salt = [0u8; 16];
    crate::crypto::fill_random(&mut salt).unwrap();
    let params = crate::crypto::PASSPHRASE_ARGON2;
    let fk = crate::crypto::passphrase_factor(&s("production-params"), &salt, &params).unwrap();
    let kek = crate::crypto::derive_kek(&device, fk.expose());
    let sealed = crate::crypto::seal(
        &kek,
        crate::crypto::b64(real_vmk.expose()).as_bytes(),
        "av/vmk/passphrase",
    )
    .unwrap();
    exec(
        &v,
        "UPDATE vmk_wraps SET salt = ?1, kdf = ?2, sealed = ?3 WHERE class = 'passphrase'",
        &[
            &crate::crypto::b64(&salt),
            &serde_json::to_string(&params).unwrap(),
            &serde_json::to_string(&sealed).unwrap(),
        ],
    );
    v.lock().unwrap();
    let mut r = Vault::open(dir.path()).unwrap();
    assert!(r.unlock(Some(&s("production-params"))).unwrap());
    assert!(r.verify_passphrase(&s("production-params")).unwrap());
    assert!(!r.verify_passphrase(&s("not-the-passphrase")).unwrap());
}
