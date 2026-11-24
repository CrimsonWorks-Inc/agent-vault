//! The companion's presence key in the store: enrolment validates the key and
//! derives its id, a replacement and a removal are audited, a row that does
//! not match its own key is no key at all, and a locked vault changes
//! nothing. New with the native companion; no JS source.

use base64::Engine as _;
use p256::pkcs8::EncodePublicKey as _;
use serde_json::json;

use super::helpers::*;
use crate::model::FactorClass;
use crate::vault::{companion_key_id, UnlockMaterial};

fn der(seed: u8) -> Vec<u8> {
    p256::SecretKey::from_slice(&[seed; 32])
        .unwrap()
        .public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn spki(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode(der(seed))
}

#[test]
fn enrolling_keeps_the_key_under_an_id_derived_from_it_and_is_audited() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    assert_eq!(v.companion_key().unwrap(), None);
    // An apostrophe is not a plain label; nothing was stored.
    assert_eq!(
        code_of(v.set_companion_key(&json!({"publicKeySpki": spki(7), "label": "Eric's Mac"}))),
        "AV_POLICY_DENIED"
    );
    assert_eq!(v.companion_key().unwrap(), None);

    assert!(!v
        .set_companion_key(
            &json!({"publicKeySpki": spki(7), "label": "Erics Mac", "keyId": "chosen-by-caller"})
        )
        .unwrap());
    let k = v.companion_key().unwrap().unwrap();
    assert_eq!(
        k.key_id,
        companion_key_id(&der(7)),
        "the id is the key's, never the caller's"
    );
    assert_eq!(
        (k.label.as_str(), k.public_key_spki.as_str()),
        ("Erics Mac", spki(7).as_str())
    );
    let added = records(v, "presence.factor_added");
    assert_eq!(added.len(), 1);
    assert_eq!(
        field(&added[0], "class"),
        &json!("companion-secure-enclave")
    );
    assert_eq!(field(&added[0], "key_id"), &json!(k.key_id));
    assert_eq!(field(&added[0], "replaced_existing"), &json!(false));

    // Another key replaces it, and says so.
    assert!(v
        .set_companion_key(&json!({"publicKeySpki": spki(8)}))
        .unwrap());
    let k = v.companion_key().unwrap().unwrap();
    assert_eq!(
        (k.key_id, k.label.as_str()),
        (companion_key_id(&der(8)), "agent-vault companion")
    );
    let added = records(v, "presence.factor_added");
    assert_eq!(field(&added[1], "replaced_existing"), &json!(true));
}

#[test]
fn only_a_p256_key_and_a_plain_label_are_kept() {
    let mut fx = fresh();
    for input in [
        json!({}),
        json!([]),
        json!("a string"),
        json!({"publicKeySpki": ""}),
        json!({"publicKeySpki": 3}),
        json!({"publicKeySpki": "not base64!"}),
        json!({"publicKeySpki": format!("{} ", spki(7))}),
        json!({"publicKeySpki": base64::engine::general_purpose::STANDARD.encode(b"not a key at all")}),
        json!({"publicKeySpki": spki(7), "label": ""}),
        json!({"publicKeySpki": spki(7), "label": " padded"}),
        json!({"publicKeySpki": spki(7), "label": "x".repeat(41)}),
        json!({"publicKeySpki": spki(7), "label": "bidi\u{202e}label"}),
        json!({"publicKeySpki": spki(7), "label": 7}),
    ] {
        refused_cleanly(
            &mut fx.vault,
            |v| v.set_companion_key(&input),
            ("AV_POLICY_DENIED", Some("companion_key")),
        );
    }
    assert_eq!(fx.vault.companion_key().unwrap(), None);
}

#[test]
fn a_row_that_does_not_match_its_own_key_is_no_key() {
    let mut fx = fresh();
    fx.vault
        .set_companion_key(&json!({"publicKeySpki": spki(7)}))
        .unwrap();
    // The id no longer derives from the key (say, the row was edited).
    let mut row = serde_json::to_value(fx.vault.companion_key().unwrap().unwrap()).unwrap();
    row["keyId"] = json!(companion_key_id(&der(8)));
    fx.vault
        .conn()
        .execute(
            "UPDATE kv SET value = ?1 WHERE key = 'companion_key'",
            [row.to_string()],
        )
        .unwrap();
    assert_eq!(fx.vault.companion_key().unwrap(), None);
    // Nor does one whose key is not a key.
    row["keyId"] = json!(companion_key_id(b"junk"));
    row["publicKeySpki"] = json!(base64::engine::general_purpose::STANDARD.encode(b"junk"));
    fx.vault
        .conn()
        .execute(
            "UPDATE kv SET value = ?1 WHERE key = 'companion_key'",
            [row.to_string()],
        )
        .unwrap();
    assert_eq!(fx.vault.companion_key().unwrap(), None);
}

#[test]
fn removal_is_audited_once_and_a_locked_vault_changes_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    assert!(!v.remove_companion_key().unwrap(), "nothing to remove");
    assert!(records(v, "presence.factor_removed").is_empty());
    v.set_companion_key(&json!({"publicKeySpki": spki(7)}))
        .unwrap();
    assert!(v.remove_companion_key().unwrap());
    assert_eq!(v.companion_key().unwrap(), None);
    let removed = records(v, "presence.factor_removed");
    assert_eq!(removed.len(), 1);
    assert_eq!(
        field(&removed[0], "class"),
        &json!("companion-secure-enclave")
    );
    assert_eq!(
        field(&removed[0], "key_id"),
        &json!(companion_key_id(&der(7)))
    );

    v.set_companion_key(&json!({"publicKeySpki": spki(7)}))
        .unwrap();
    v.lock().unwrap();
    assert_eq!(
        code_of(v.set_companion_key(&json!({"publicKeySpki": spki(8)}))),
        "AV_LOCKED"
    );
    assert_eq!(code_of(v.remove_companion_key()), "AV_LOCKED");
}

// ------------------------------------------------------- Touch ID unlock

fn secret(seed: u8) -> av_core::secret::SecretBytes {
    av_core::secret::SecretBytes::from(vec![seed; 32])
}

fn by(secret: av_core::secret::SecretBytes) -> UnlockMaterial {
    UnlockMaterial {
        passphrase: None,
        prf_secret: Some(secret),
    }
}

/// A vault with a passphrase and the companion key from `seed` enrolled.
fn with_companion(seed: u8) -> (Fx, String) {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    fx.vault
        .set_companion_key(&json!({"publicKeySpki": spki(seed)}))
        .unwrap();
    let id = fx.vault.companion_key().unwrap().unwrap().key_id;
    (fx, id)
}

#[test]
fn touch_id_unlock_opens_the_vault_with_its_secret_only() {
    let (mut fx, id) = with_companion(7);
    let v = &mut fx.vault;
    assert!(!v.has_companion_unlock().unwrap());
    v.add_companion_unlock(&id, &secret(1)).unwrap();
    assert!(v.has_companion_unlock().unwrap());
    let added = records(v, "presence.factor_added");
    let last = added.last().unwrap();
    assert_eq!(field(last, "class"), &json!("companion-prf"));
    assert_eq!(field(last, "key_id"), &json!(id));

    v.lock().unwrap();
    assert!(v.has_companion_unlock().unwrap(), "readable while locked");
    assert_eq!(code_of(v.unlock_with(&by(secret(2)))), "AV_LOCKED");
    assert!(v.locked());
    assert_eq!(
        v.unlock_with(&by(secret(1))).unwrap(),
        FactorClass::CompanionPrf
    );
    let opened = records(v, "vault.unlock");
    assert_eq!(
        field(opened.last().unwrap(), "factor"),
        &json!("companion-prf")
    );

    // The browser's Touch ID unlock is a wrap of its own; each secret opens
    // only its own, and the passphrase still opens the vault.
    v.add_webauthn_unlock("browser", &secret(3)).unwrap();
    v.lock().unwrap();
    assert_eq!(
        v.unlock_with(&by(secret(3))).unwrap(),
        FactorClass::WebauthnPrf
    );
    v.lock().unwrap();
    assert_eq!(
        v.unlock_with(&by(secret(1))).unwrap(),
        FactorClass::CompanionPrf
    );
    v.lock().unwrap();
    assert!(v.unlock(Some(&s(PASSPHRASE))).unwrap());
}

#[test]
fn touch_id_unlock_needs_the_vault_open_the_passphrase_and_the_trusted_key() {
    // No passphrase to recover with.
    let mut fx = fresh();
    fx.vault
        .set_companion_key(&json!({"publicKeySpki": spki(7)}))
        .unwrap();
    let id = fx.vault.companion_key().unwrap().unwrap().key_id;
    refused_cleanly(
        &mut fx.vault,
        |v| v.add_companion_unlock(&id, &secret(1)),
        ("AV_POLICY_DENIED", Some("factor_order")),
    );

    let (mut fx, id) = with_companion(7);
    let before = snapshot(&fx.vault);
    // Another key's id: the wrap belongs to the key the vault trusts.
    let other = companion_key_id(&der(8));
    assert_eq!(
        code_of(fx.vault.add_companion_unlock(&other, &secret(1))),
        "AV_POLICY_DENIED"
    );
    // A secret shorter than 32 bytes is no secret.
    let short = av_core::secret::SecretBytes::from(vec![1u8; 31]);
    assert!(fx.vault.add_companion_unlock(&id, &short).is_err());
    assert_eq!(snapshot(&fx.vault), before, "a refusal writes nothing");
    assert!(!fx.vault.has_companion_unlock().unwrap());

    // No companion key at all.
    let mut bare = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    assert_eq!(
        code_of(bare.vault.add_companion_unlock(&id, &secret(1))),
        "AV_POLICY_DENIED"
    );

    // Locked.
    fx.vault.lock().unwrap();
    assert_eq!(
        code_of(fx.vault.add_companion_unlock(&id, &secret(1))),
        "AV_LOCKED"
    );
}

#[test]
fn touch_id_unlock_goes_with_the_key_it_belongs_to() {
    let (mut fx, id) = with_companion(7);
    let v = &mut fx.vault;
    v.add_companion_unlock(&id, &secret(1)).unwrap();
    // The same key again (a new label) keeps it.
    v.set_companion_key(&json!({"publicKeySpki": spki(7), "label": "Renamed"}))
        .unwrap();
    assert!(v.has_companion_unlock().unwrap());
    // Another key replaces it: the wrap opened only with the old key's
    // Secure Enclave, so it goes, and that is audited.
    v.set_companion_key(&json!({"publicKeySpki": spki(8)}))
        .unwrap();
    assert!(!v.has_companion_unlock().unwrap());
    let removed = records(v, "presence.factor_removed");
    assert_eq!(
        field(removed.last().unwrap(), "class"),
        &json!("companion-prf")
    );
    v.lock().unwrap();
    assert_eq!(code_of(v.unlock_with(&by(secret(1)))), "AV_LOCKED");
    assert!(v.unlock(Some(&s(PASSPHRASE))).unwrap());

    // Removing the key removes it too.
    let id = v.companion_key().unwrap().unwrap().key_id;
    v.add_companion_unlock(&id, &secret(4)).unwrap();
    assert!(v.remove_companion_key().unwrap());
    assert!(!v.has_companion_unlock().unwrap());
    v.lock().unwrap();
    assert_eq!(code_of(v.unlock_with(&by(secret(4)))), "AV_LOCKED");
}

#[test]
fn the_passphrase_stays_while_touch_id_unlock_is_on() {
    let (mut fx, id) = with_companion(7);
    fx.vault.add_companion_unlock(&id, &secret(1)).unwrap();
    let before = snapshot(&fx.vault);
    match fx.vault.remove_passphrase(&s(PASSPHRASE)) {
        Err(crate::error::Error::Vault(e)) => {
            assert_eq!(e.extra.rule.as_deref(), Some("last_factor"));
            assert!(
                e.detail.contains("remove Touch ID unlock first"),
                "{}",
                e.detail
            );
        }
        other => panic!("not refused: {:?}", other.map(|_| ())),
    }
    assert_eq!(snapshot(&fx.vault), before);
}
