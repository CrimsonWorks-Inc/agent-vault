//! Ports the store-level parts of `test/security/fix-control-factors.test.js`.
//! What goes through the control socket (status codes, the presence window,
//! the gate on an unsigned widening) is the daemon's and conformance's.

use serde_json::{json, Value};

use super::helpers::*;
use crate::error::Error;
use crate::model::FactorClass;
use crate::vault::*;

fn deny_of<T>(r: crate::error::Result<T>) -> av_core::VaultError {
    match r {
        Err(Error::Vault(v)) => *v,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("not refused"),
    }
}

fn authenticator_only() -> Fx {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    fx.vault.set_presence_key(&authenticator(P256_A)).unwrap();
    fx.vault.remove_passphrase(&s(PASSPHRASE)).unwrap();
    assert!(!fx.vault.has_passphrase().unwrap());
    fx
}

#[test]
fn f1_the_only_passphrase_cannot_be_removed() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    let before = snapshot(&fx.vault);
    let e = deny_of(fx.vault.remove_passphrase(&s(PASSPHRASE)));
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some("last_factor"));
    assert!(e
        .extra
        .hint
        .as_deref()
        .unwrap()
        .contains("presence authenticator"));
    assert!(fx.vault.has_passphrase().unwrap());
    assert_eq!(
        snapshot(&fx.vault),
        before,
        "a refusal must not write the vault"
    );
    fx.vault.lock().unwrap();
    assert_eq!(code_of(fx.vault.unlock(None)), "AV_LOCKED");
    assert!(fx.vault.unlock(Some(&s(PASSPHRASE))).unwrap());
}

#[test]
fn f1_removing_touch_id_unlock_first_does_not_make_the_passphrase_removable() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    fx.vault.add_webauthn_unlock("c", &prf_secret()).unwrap();
    let first = deny_of(fx.vault.remove_passphrase(&s(PASSPHRASE)));
    assert_eq!(first.extra.rule.as_deref(), Some("last_factor"));
    assert!(first.detail.contains("remove Touch ID unlock first"));
    fx.vault.remove_webauthn_unlock().unwrap();
    let second = deny_of(fx.vault.remove_passphrase(&s(PASSPHRASE)));
    assert_eq!(second.extra.rule.as_deref(), Some("last_factor"));
    assert!(fx.vault.has_passphrase().unwrap());
}

#[test]
fn a_wrong_passphrase_is_still_a_failed_proof_not_a_factor_refusal() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    assert_eq!(
        code_of(fx.vault.remove_passphrase(&s("not the passphrase"))),
        "AV_LOCKED"
    );
}

#[test]
fn control_with_a_presence_authenticator_left_the_passphrase_can_be_removed() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    fx.vault.set_presence_key(&authenticator(P256_A)).unwrap();
    assert!(fx.vault.remove_passphrase(&s(PASSPHRASE)).unwrap());
    assert!(!fx.vault.has_passphrase().unwrap());
    assert_eq!(human_factors_of(&fx.vault), vec!["authenticator"]);
}

fn human_factors_of(v: &Vault) -> Vec<&'static str> {
    let c = v.conn();
    let state = crate::model::FactorState {
        vmk_wraps: crate::rows::wraps_get(&c).unwrap(),
        webauthn: crate::rows::webauthn_get(&c).unwrap(),
    };
    human_factors(&state)
}

#[test]
fn an_authenticator_only_vault_keeps_an_authenticator_as_its_human_factor() {
    let fx = authenticator_only();
    assert_eq!(human_factors_of(&fx.vault), vec!["authenticator"]);
    // The none wrap it fell back to opens the vault; the gate is the key.
    assert_eq!(fx.vault.factors().unwrap(), vec![FactorClass::None]);
}

#[test]
fn control_a_vault_with_no_factor_at_all_has_no_human_factor() {
    let fx = fresh();
    assert!(human_factors_of(&fx.vault).is_empty());
}

#[test]
fn control_a_passphrase_changes_with_the_current_one() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    fx.vault
        .set_passphrase(&s("a brand new passphrase"), Some(&s(PASSPHRASE)))
        .unwrap();
    assert!(fx
        .vault
        .verify_passphrase(&s("a brand new passphrase"))
        .unwrap());
    assert!(!fx.vault.verify_passphrase(&s(PASSPHRASE)).unwrap());
}

fn broken() -> Vec<(&'static str, Value)> {
    vec![
        ("an empty record", json!({})),
        (
            "the reviewer's broken key",
            json!({ "credentialId": "broken", "publicKeySpki": "not-a-public-key", "signCount": 0 }),
        ),
        (
            "no public key",
            json!({ "credentialId": cred_id(16), "signCount": 0 }),
        ),
        (
            "a public key that does not parse",
            json!({ "credentialId": cred_id(16), "publicKeySpki": crate::crypto::b64(&[0u8; 91]), "signCount": 0 }),
        ),
        (
            "an Ed25519 key",
            json!({ "credentialId": cred_id(16), "publicKeySpki": ED25519, "signCount": 0 }),
        ),
        (
            "a P-384 key",
            json!({ "credentialId": cred_id(16), "publicKeySpki": P384, "signCount": 0 }),
        ),
        (
            "a credential id too short",
            json!({ "credentialId": "aGVsbG8", "publicKeySpki": P256_B, "signCount": 0 }),
        ),
        (
            "a negative counter",
            json!({ "credentialId": cred_id(16), "publicKeySpki": P256_B, "signCount": -1 }),
        ),
        (
            "a counter past 32 bits",
            json!({ "credentialId": cred_id(16), "publicKeySpki": P256_B, "signCount": 1u64 << 40 }),
        ),
    ]
}

#[test]
fn f2_a_rotation_to_an_unusable_key_is_refused_and_the_sole_key_keeps_working() {
    let mut fx = authenticator_only();
    let original = fx.vault.presence_key().unwrap();
    for (name, body) in broken() {
        let before = snapshot(&fx.vault);
        let e = deny_of(fx.vault.set_presence_key(&body));
        assert_eq!(e.code.as_str(), "AV_POLICY_DENIED", "{name}");
        assert_eq!(e.extra.rule.as_deref(), Some("presence_key"), "{name}");
        assert_eq!(
            fx.vault.presence_key().unwrap(),
            original,
            "{name}: the old key was replaced"
        );
        assert_eq!(snapshot(&fx.vault), before, "{name}");
    }
    let next = authenticator(P256_C);
    assert!(fx.vault.set_presence_key(&next).unwrap(), "replaced");
    assert_eq!(
        fx.vault.presence_key().unwrap().unwrap().credential_id,
        next["credentialId"].as_str().unwrap()
    );
}

#[test]
fn f2_a_rotation_stores_the_credential_and_nothing_else_the_caller_sent() {
    let mut fx = authenticator_only();
    let mut body = authenticator(P256_C);
    body["attestation"] = json!("x".repeat(64));
    body["extra"] = json!({ "anything": true });
    fx.vault.set_presence_key(&body).unwrap();
    let stored = serde_json::to_value(fx.vault.presence_key().unwrap().unwrap()).unwrap();
    let mut keys: Vec<&String> = stored.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["credentialId", "enrolledAt", "publicKeySpki", "signCount"]
    );
}

#[test]
fn f2_a_first_enrolment_is_held_to_the_same_shape() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    let e = deny_of(fx.vault.set_presence_key(
        &json!({ "credentialId": "broken", "publicKeySpki": "not-a-public-key", "signCount": 0 }),
    ));
    assert_eq!(e.extra.rule.as_deref(), Some("presence_key"));
    assert!(fx.vault.presence_key().unwrap().is_none());
}

#[test]
fn a_presence_key_that_fails_to_save_leaves_the_old_one_in_place() {
    // The JS made the directory read-only so the temp-file write failed. A
    // SQLite write fails inside its transaction instead: make the table
    // refuse the row, and the old key must still be there.
    let mut fx = fresh();
    fx.vault.set_passphrase(&s(PASSPHRASE), None).unwrap();
    fx.vault.set_presence_key(&authenticator(P256_A)).unwrap();
    let original = fx.vault.presence_key().unwrap();
    exec(
        &fx.vault,
        "CREATE TRIGGER fail_presence BEFORE UPDATE ON webauthn BEGIN SELECT RAISE(ABORT, 'disk full'); END",
        &[],
    );
    assert!(fx.vault.set_presence_key(&authenticator(P256_B)).is_err());
    assert_eq!(fx.vault.presence_key().unwrap(), original);
}

#[test]
fn f3_the_store_factory_refuses_a_touch_id_unlock_wrap_with_no_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("v");
    let e = deny_of(Vault::create(
        &target,
        CreateOptions {
            factor: FactorClass::WebauthnPrf,
            passphrase: None,
        },
    ));
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some("factor_order"));
    assert!(!target.join("vault.db").exists(), "no vault was written");
    assert!(
        !target.join("device.key").exists(),
        "nothing was written at all"
    );
}

#[test]
fn control_a_vault_created_with_a_passphrase_opens_with_it_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = Vault::create(
        dir.path(),
        CreateOptions {
            factor: FactorClass::Passphrase,
            passphrase: Some(s(PASSPHRASE)),
        },
    )
    .unwrap();
    assert_eq!(v.factors().unwrap(), vec![FactorClass::Passphrase]);
    v.lock().unwrap();
    assert_eq!(
        code_of(Vault::open(dir.path()).unwrap().unlock(None)),
        "AV_LOCKED"
    );
    assert!(Vault::open(dir.path())
        .unwrap()
        .unlock(Some(&s(PASSPHRASE)))
        .unwrap());
}

#[test]
fn control_a_vault_with_no_passphrase_keeps_its_none_wrap() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = Vault::create(dir.path(), CreateOptions::default()).unwrap();
    assert_eq!(v.factors().unwrap(), vec![FactorClass::None]);
    assert!(!v.remove_webauthn_unlock().unwrap());
    assert!(!v.remove_passphrase(&s("anything")).unwrap());
    v.lock().unwrap();
    assert!(Vault::open(dir.path()).unwrap().unlock(None).unwrap());
}
