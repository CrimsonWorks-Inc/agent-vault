//! The companion's presence key in the store: enrolment validates the key and
//! derives its id, a replacement and a removal are audited, a row that does
//! not match its own key is no key at all, and a locked vault changes
//! nothing. New with the native companion; no JS source.

use base64::Engine as _;
use p256::pkcs8::EncodePublicKey as _;
use serde_json::json;

use super::helpers::*;
use crate::vault::companion_key_id;

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
