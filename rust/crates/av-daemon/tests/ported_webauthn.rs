//! Public WebAuthn ceremony regressions with deterministic fake ES256 keys.
use av_daemon::ui::webauthn as wa;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde_json::{json, Value};
#[allow(dead_code)]
mod ported_common;
const ORIGIN: &str = "http://localhost:7799";
fn register(
    auth: &ported_common::FakeAuthenticator,
    challenge: &[u8],
    response: Option<Value>,
) -> Result<wa::EnrolledCredential, wa::WebauthnError> {
    let r = response.unwrap_or_else(|| auth.register(&B64.encode(challenge), ORIGIN));
    wa::verify_registration(&wa::RegistrationInput {
        attestation_object: &r["attestationObject"],
        client_data_json: &r["clientDataJSON"],
        expected_challenge: challenge,
        expected_origins: &[ORIGIN.into()],
        rp_id: "localhost",
    })
}
fn verify(
    enrolled: &wa::EnrolledCredential,
    r: &Value,
    challenge: &[u8],
) -> Result<u32, wa::WebauthnError> {
    wa::verify_assertion(&wa::AssertionInput {
        credential_id: &r["credentialId"],
        authenticator_data: &r["authenticatorData"],
        client_data_json: &r["clientDataJSON"],
        signature: &r["signature"],
        expected_challenge: challenge,
        expected_origins: &[ORIGIN.into()],
        rp_id: "localhost",
        enrolled,
    })
}
#[test]
fn registration_is_storable_and_registration_without_human_verification_is_refused() {
    let auth = ported_common::FakeAuthenticator::new(51);
    let challenge = wa::new_challenge();
    let enrolled = register(&auth, &challenge, None).unwrap();
    assert_eq!(enrolled.credential_id, auth.id());
    assert!(!enrolled.public_key_spki.is_empty());
    assert!(time::OffsetDateTime::parse(
        &enrolled.enrolled_at,
        &time::format_description::well_known::Rfc3339
    )
    .is_ok());
    let mut response = auth.register(&B64.encode(challenge), ORIGIN);
    let raw = B64
        .decode(response["attestationObject"].as_str().unwrap())
        .unwrap();
    let mut att: ciborium::value::Value = ciborium::de::from_reader(raw.as_slice()).unwrap();
    let ciborium::value::Value::Map(ref mut m) = att else {
        panic!("fixture map")
    };
    let (_, data) = m
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .unwrap();
    let ciborium::value::Value::Bytes(data) = data else {
        panic!("fixture bytes")
    };
    data[32] &= !4;
    let mut bytes = vec![];
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();
    response["attestationObject"] = json!(B64.encode(bytes));
    assert!(register(&auth, &challenge, Some(response))
        .unwrap_err()
        .message
        .contains("did not verify a human"));
    assert!(register(&auth, &challenge, None).is_ok());
}
#[test]
fn assertion_identity_signature_origin_type_uv_and_counter_have_valid_ceremony_controls() {
    let auth = ported_common::FakeAuthenticator::new(52);
    let enrolled = register(&auth, &wa::new_challenge(), None).unwrap();
    let challenge = wa::challenge_for_operation(&[7u8; 32], &json!({"op":"vault.lock"}));
    let encoded = B64.encode(challenge);
    let valid = auth.assertion(&encoded, ORIGIN);
    assert_eq!(verify(&enrolled, &valid, &challenge).unwrap(), 0);
    let attacker = ported_common::FakeAuthenticator::new(53);
    let mut copied = attacker.assertion(&encoded, ORIGIN);
    copied["credentialId"] = json!(auth.id());
    let cases = [
        (
            "other credential",
            attacker.assertion(&encoded, ORIGIN),
            "never enrolled",
        ),
        ("copied credential id", copied, "signature does not verify"),
        (
            "foreign origin",
            auth.assertion(&encoded, "https://evil.test"),
            "is not this server",
        ),
        (
            "registration as assertion",
            auth.assertion_options(&encoded, ORIGIN, true, 0, "webauthn.create"),
            "type is webauthn.create",
        ),
        (
            "unverified user",
            auth.assertion_options(&encoded, ORIGIN, false, 0, "webauthn.get"),
            "did not verify a human",
        ),
    ];
    for (name, response, reason) in cases {
        let e = verify(&enrolled, &response, &challenge).unwrap_err();
        assert!(e.message.contains(reason), "{name}: {e:?}");
        assert!(
            verify(&enrolled, &valid, &challenge).is_ok(),
            "{name} ordinary control"
        );
    }
    let mut counted = enrolled.clone();
    counted.sign_count = 10;
    let stale = auth.assertion_options(&encoded, ORIGIN, true, 5, "webauthn.get");
    assert!(verify(&counted, &stale, &challenge)
        .unwrap_err()
        .message
        .contains("may have been cloned"));
    assert_eq!(
        verify(
            &counted,
            &auth.assertion_options(&encoded, ORIGIN, true, 11, "webauthn.get"),
            &challenge
        )
        .unwrap(),
        11
    );
}
#[test]
fn operation_challenges_bind_every_field_and_nonce_and_wrong_operation_never_verifies() {
    let auth = ported_common::FakeAuthenticator::new(54);
    let enrolled = register(&auth, &wa::new_challenge(), None).unwrap();
    let nonce = [8u8; 32];
    let a =
        wa::challenge_for_operation(&nonce, &json!({"op":"approval.approve","id":"ap_harmless"}));
    let b = wa::challenge_for_operation(
        &nonce,
        &json!({"op":"approval.approve","id":"ap_dangerous"}),
    );
    let response = auth.assertion(&B64.encode(a), ORIGIN);
    assert!(verify(&enrolled, &response, &b)
        .unwrap_err()
        .message
        .contains("challenge does not match"));
    assert!(verify(&enrolled, &response, &a).is_ok());
    let base = wa::challenge_for_operation(
        &nonce,
        &json!({"op":"session.create","cred":"gh","paths":["/a"]}),
    );
    for other in [
        json!({"op":"session.create","cred":"slack","paths":["/a"]}),
        json!({"op":"session.create","cred":"gh","paths":["/**"]}),
    ] {
        assert_ne!(base, wa::challenge_for_operation(&nonce, &other));
    }
    let op = json!({"op":"vault.lock"});
    assert_ne!(
        wa::challenge_for_operation(&wa::new_challenge(), &op),
        wa::challenge_for_operation(&wa::new_challenge(), &op)
    );
    assert_eq!(
        base,
        wa::challenge_for_operation(
            &nonce,
            &json!({"paths":["/a"],"cred":"gh","op":"session.create"})
        )
    );
}
#[test]
fn unsupported_cose_cbor_and_oversized_assertion_fields_fail_before_parsing_with_ordinary_controls()
{
    use wa::Cbor as C;
    for (fields, reason) in [
        (vec![(1, 3), (3, -257)], "only EC2 is accepted"),
        (vec![(1, 2), (3, -257)], "only ES256 is accepted"),
        (vec![(1, 2), (3, -7), (-1, 2)], "only P-256 is accepted"),
    ] {
        let key = C::Map(
            fields
                .into_iter()
                .map(|(k, v)| (C::Int(k), C::Int(v)))
                .collect(),
        );
        assert!(wa::cose_to_public_key(&key)
            .unwrap_err()
            .message
            .contains(reason));
    }
    assert!(wa::decode_cbor(&[0xff], 0)
        .unwrap_err()
        .message
        .contains("cbor:"));
    assert_eq!(wa::decode_cbor(&[0x01], 0).unwrap(), (C::Int(1), 1));
    let auth = ported_common::FakeAuthenticator::new(55);
    let enrolled = register(&auth, &wa::new_challenge(), None).unwrap();
    let challenge = wa::new_challenge();
    let valid = auth.assertion(&B64.encode(challenge), ORIGIN);
    for field in ["authenticatorData", "clientDataJSON", "signature"] {
        let mut r = valid.clone();
        r[field] = json!("A".repeat(4 * 1024 * 1024));
        let e = verify(&enrolled, &r, &challenge).unwrap_err();
        assert_eq!(e.failure, "size");
        assert!(
            e.message
                .contains(&format!("{field} is 4194304 characters")),
            "{e:?}"
        );
        assert!(verify(&enrolled, &valid, &challenge).is_ok());
    }
}
