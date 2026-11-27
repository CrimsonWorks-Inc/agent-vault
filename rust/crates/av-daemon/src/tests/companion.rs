//! The companion's Secure Enclave presence factor through the daemon:
//! enrolment needs the passphrase first and fresh presence; a challenge is
//! bound to the exact request the daemon derives; a signature is single-use,
//! answers only a challenge minted for the companion, and verifies only under
//! the enrolled key. New with the native companion; no JS source.

use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePublicKey;
use serde_json::{json, Value};

use super::*;
use crate::ui::webauthn::testkit::SoftKey;

const PASS: &str = "test-passphrase-123";

/// A stand-in for the Secure Enclave: the same P-256 key, in memory.
struct Enclave {
    key: p256::ecdsa::SigningKey,
}

impl Enclave {
    fn new(seed: u8) -> Enclave {
        Enclave {
            key: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn der(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn spki(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.der())
    }

    fn sign_bytes(&self, msg: &[u8]) -> String {
        let sig: p256::ecdsa::Signature = self.key.sign(msg);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes())
    }

    /// What the companion does after Touch ID: sign the prefixed challenge.
    fn sign(&self, challenge: &str) -> String {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(challenge)
            .unwrap();
        let raw: [u8; 32] = raw.try_into().unwrap();
        self.sign_bytes(&crate::companion::signed_message(&raw))
    }
}

async fn with_passphrase() -> World {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    w
}

async fn enrol(w: &World, e: &Enclave) -> (u16, Value) {
    w.control(
        "POST",
        "/v1/presence/companion",
        json!({"publicKeySpki": e.spki(), "label": "Test Mac", "presence": {"passphrase": PASS}}),
    )
    .await
}

async fn enrolled() -> (World, Enclave) {
    let w = with_passphrase().await;
    let e = Enclave::new(7);
    let (s, v) = enrol(&w, &e).await;
    assert_eq!(s, 200, "{v}");
    (w, e)
}

async fn challenge(w: &World, route: &str, body: &Value) -> (u16, Value) {
    w.control(
        "POST",
        "/v1/presence/companion/challenge",
        json!({"route": route, "query": "", "body": body}),
    )
    .await
}

/// A challenge for issuing a placeholder, the signed proof, and the body.
async fn signed_issue(w: &World, e: &Enclave) -> Value {
    let body = json!({"cred": "demo", "sid": w.session_id});
    let (s, ch) = challenge(w, "POST /v1/placeholders", &body).await;
    assert_eq!(s, 200, "{ch}");
    let mut b = body;
    b["presence"] = json!({
        "challengeId": ch["challengeId"],
        "companionSignature": e.sign(ch["challenge"].as_str().unwrap()),
    });
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn enrolment_needs_a_passphrase_first_and_fresh_presence() {
    // No passphrase: whoever enrolled first could lock everyone else out.
    let w = World::seeded(json!({})).await;
    let e = Enclave::new(7);
    let (s, v) = w
        .control(
            "POST",
            "/v1/presence/companion",
            json!({"publicKeySpki": e.spki()}),
        )
        .await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("factor_order")), "{v}");

    let w = with_passphrase().await;
    // Not even inside a confirmation window: enrolment needs proof of its own.
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS}))
        .await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/presence/companion",
            json!({"publicKeySpki": e.spki()}),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str(), v["rule"].as_str()),
        (401, Some("AV_PRESENCE_REQUIRED"), Some("fresh_presence")),
        "{v}"
    );
    let (_, v) = w.control("GET", "/v1/presence/companion", json!({})).await;
    assert_eq!(v, json!({"enrolled": false, "unlock": false}));

    let (s, v) = enrol(&w, &e).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["replaced"], false);
    let id = av_store::vault::companion_key_id(&e.der());
    assert_eq!(v["key_id"], json!(id));
    let (_, v) = w.control("GET", "/v1/presence/companion", json!({})).await;
    assert_eq!(
        (
            v["enrolled"].as_bool(),
            v["key_id"].as_str(),
            v["label"].as_str()
        ),
        (Some(true), Some(id.as_str()), Some("Test Mac"))
    );
    let audit = w.audit().await;
    assert!(audit.iter().any(|r| r["kind"] == "presence.factor_added"
        && r["class"] == "companion-secure-enclave"
        && r["key_id"] == json!(id)));
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_p256_key_and_a_plain_label_are_enrolled() {
    let w = with_passphrase().await;
    let e = Enclave::new(7);
    for body in [
        json!({"publicKeySpki": "not base64!"}),
        json!({"publicKeySpki": base64::engine::general_purpose::STANDARD.encode(b"not a key at all")}),
        json!({"publicKeySpki": e.spki(), "label": "a\u{202e}b"}),
        json!({"publicKeySpki": e.spki(), "label": ""}),
        json!({"publicKeySpki": e.spki(), "label": "x".repeat(41)}),
        json!({}),
    ] {
        let mut b = body.clone();
        b["presence"] = json!({"passphrase": PASS});
        let (s, v) = w.control("POST", "/v1/presence/companion", b).await;
        assert_eq!(
            (s, v["rule"].as_str()),
            (403, Some("companion_key")),
            "{body}: {v}"
        );
    }
    let (_, v) = w.control("GET", "/v1/presence/companion", json!({})).await;
    assert_eq!(v["enrolled"], false, "nothing was stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signature_is_bound_to_one_request_one_use_and_the_enrolled_key() {
    let (w, e) = enrolled().await;
    let body = json!({"cred": "demo", "sid": w.session_id});
    // Without proof the request is refused, as before.
    let (s, _) = w.control("POST", "/v1/placeholders", body.clone()).await;
    assert_eq!(s, 401);

    // The challenge is bound to the operation the daemon derives itself.
    let (s, ch) = challenge(&w, "POST /v1/placeholders", &body).await;
    assert_eq!(s, 200, "{ch}");
    assert_eq!(
        ch["operation"],
        crate::util::operation_for("placeholder.issue", &body).unwrap()
    );
    let mut b = body.clone();
    b["presence"] = json!({
        "challengeId": ch["challengeId"],
        "companionSignature": e.sign(ch["challenge"].as_str().unwrap()),
    });
    let (s, v) = w.control("POST", "/v1/placeholders", b.clone()).await;
    assert_eq!(s, 200, "{v}");
    assert!(w
        .audit()
        .await
        .iter()
        .any(|r| r["kind"] == "presence.verified" && r["factor"] == "companion-secure-enclave"));

    // Single use.
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);
    assert!(w.audit_text().await.contains("companion_challenge_unknown"));

    // Signed for one request, sent as another.
    let mut b = signed_issue(&w, &e).await;
    b["uses"] = json!(1);
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);
    assert!(w.audit_text().await.contains("operation_mismatch"));

    // Another key's signature, or the challenge signed without the prefix.
    let other = Enclave::new(8);
    let mut b = signed_issue(&w, &other).await;
    let (s, _) = w.control("POST", "/v1/placeholders", b.clone()).await;
    assert_eq!(s, 401);
    assert!(w
        .audit_text()
        .await
        .contains("\"reason\":\"companion_signature\""));
    let (_, ch) = challenge(&w, "POST /v1/placeholders", &body).await;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ch["challenge"].as_str().unwrap())
        .unwrap();
    b["presence"] =
        json!({"challengeId": ch["challengeId"], "companionSignature": e.sign_bytes(&raw)});
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);

    // A signature never opens a window: the next widening needs its own.
    let (s, _) = w.control("POST", "/v1/placeholders", body).await;
    assert_eq!(s, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn each_kind_of_proof_answers_only_its_own_challenges() {
    let (w, e) = enrolled().await;
    let mut k = SoftKey::new();
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    let body = json!({"cred": "demo", "sid": w.session_id});
    let op = crate::util::operation_for("placeholder.issue", &body).unwrap();

    // A WebAuthn challenge, answered with the companion's key.
    let (_, wch) = w
        .control("POST", "/v1/presence/challenge", json!({"operation": op}))
        .await;
    let mut b = body.clone();
    b["presence"] = json!({
        "challengeId": wch["challengeId"],
        "companionSignature": e.sign(wch["challenge"].as_str().unwrap()),
    });
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);

    // A companion challenge, answered with a WebAuthn assertion.
    let (_, cch) = challenge(&w, "POST /v1/placeholders", &body).await;
    let raw = crate::util::b64url_lenient(cch["challenge"].as_str().unwrap());
    let mut proof = k.assert(&raw, "http://localhost:7412");
    proof["challengeId"] = cch["challengeId"].clone();
    let mut b = body;
    b["presence"] = proof;
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_needs_an_enrolled_key_and_a_request_that_widens() {
    let w = with_passphrase().await;
    let (s, v) = challenge(&w, "POST /v1/placeholders", &json!({"cred": "demo"})).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("companion_not_enrolled")),
        "{v}"
    );
    let e = Enclave::new(7);
    enrol(&w, &e).await;
    for route in ["GET /v1/status", "POST /v1/lock", "nonsense"] {
        let (s, v) = challenge(&w, route, &json!({})).await;
        assert_eq!(
            (s, v["rule"].as_str()),
            (403, Some("not_widening")),
            "{route}: {v}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_companion_key_proves_fresh_presence_and_can_replace_itself() {
    let (w, e) = enrolled().await;
    let next = Enclave::new(9);
    let body = json!({"publicKeySpki": next.spki(), "label": "Test Mac"});
    let (s, ch) = challenge(&w, "POST /v1/presence/companion", &body).await;
    assert_eq!(s, 200, "{ch}");
    let mut b = body;
    b["presence"] = json!({
        "challengeId": ch["challengeId"],
        "companionSignature": e.sign(ch["challenge"].as_str().unwrap()),
    });
    let (s, v) = w.control("POST", "/v1/presence/companion", b).await;
    assert_eq!((s, v["replaced"].as_bool()), (200, Some(true)), "{v}");
    // The old key no longer verifies; the new one does.
    let (s, _) = w
        .control("POST", "/v1/placeholders", signed_issue(&w, &e).await)
        .await;
    assert_eq!(s, 401);
    let (s, v) = w
        .control("POST", "/v1/placeholders", signed_issue(&w, &next).await)
        .await;
    assert_eq!(s, 200, "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn removal_needs_fresh_presence_and_then_nothing_the_key_signs_counts() {
    let (w, e) = enrolled().await;
    let (s, _) = w
        .control(
            "POST",
            "/v1/presence/companion",
            json!({"action": "remove"}),
        )
        .await;
    assert_eq!(s, 401);
    let pending = signed_issue(&w, &e).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/presence/companion",
            json!({"action": "remove", "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!((s, v["removed"].as_bool()), (200, Some(true)), "{v}");
    let (_, v) = w.control("GET", "/v1/presence/companion", json!({})).await;
    assert_eq!(v["enrolled"], false);
    // A signature made before removal is refused after it.
    let (s, _) = w.control("POST", "/v1/placeholders", pending).await;
    assert_eq!(s, 401);
    let audit = w.audit_text().await;
    assert!(audit.contains("companion_not_enrolled"));
    assert!(w.audit().await.iter().any(
        |r| r["kind"] == "presence.factor_removed" && r["class"] == "companion-secure-enclave"
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_request_is_decided_with_a_signature_bound_to_its_verdict() {
    let (w, e) = enrolled().await;
    let (s, asked) = w
        .control(
            "POST",
            "/v1/session-requests",
            json!({"cred": "demo", "methods": ["GET"], "reason": "need it"}),
        )
        .await;
    assert_eq!(s, 200, "{asked}");
    let id = asked["id"].as_str().unwrap().to_string();
    let approve = json!({"id": id, "granted": true});
    let (s, ch) = challenge(&w, "POST /v1/session-requests/decide", &approve).await;
    assert_eq!(s, 200, "{ch}");
    assert_eq!(ch["operation"]["op"], "session_request.decide");
    assert_eq!(ch["operation"]["granted"], true);
    // The signature covers the verdict: signed to approve, sent to deny.
    let mut deny = json!({"id": id, "granted": false});
    deny["presence"] = json!({"challengeId": ch["challengeId"], "companionSignature": e.sign(ch["challenge"].as_str().unwrap())});
    let (s, _) = w.control("POST", "/v1/session-requests/decide", deny).await;
    assert_eq!(s, 401);
    // Signed and sent to approve: the request is settled.
    let (_, ch) = challenge(&w, "POST /v1/session-requests/decide", &approve).await;
    let mut b = approve.clone();
    b["presence"] = json!({"challengeId": ch["challengeId"], "companionSignature": e.sign(ch["challenge"].as_str().unwrap())});
    let (s, v) = w.control("POST", "/v1/session-requests/decide", b).await;
    assert_eq!(s, 200, "{v}");
    // Nothing waiting any more, so no challenge for it either.
    let (s, v) = challenge(&w, "POST /v1/session-requests/decide", &approve).await;
    assert_eq!((s, v["code"].as_str()), (404, Some("AV_NOT_FOUND")), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proposed_credential_is_finished_with_a_signature_over_its_key_and_hosts() {
    let (w, e) = enrolled().await;
    let (record, _) = w
        .shared
        .run(|c| c.cp_propose(&json!({"slug": "linear", "host": "api.linear.app"})))
        .await
        .unwrap()
        .unwrap();
    let approve = json!({"id": record.id, "granted": true, "hosts": ["api.linear.app"], "value": "test-key-one-fake"});
    let (s, ch) = challenge(&w, "POST /v1/cred-proposals/decide", &approve).await;
    assert_eq!(s, 200, "{ch}");
    assert_eq!(ch["operation"]["op"], "cred_proposal.approve");
    assert_eq!(ch["operation"]["hosts"], json!(["api.linear.app"]));
    // The key is bound by its digest; it is never in what gets signed.
    assert!(ch["operation"].get("value").is_none());
    assert_eq!(
        ch["operation"]["value_sha256"],
        av_core::canon::sha256(b"test-key-one-fake")
    );
    let proof = json!({"challengeId": ch["challengeId"], "companionSignature": e.sign(ch["challenge"].as_str().unwrap())});
    // Signed for one key, sent with another: refused, nothing saved.
    let mut other = approve.clone();
    other["value"] = "test-key-two-fake".into();
    other["presence"] = proof.clone();
    let (s, _) = w.control("POST", "/v1/cred-proposals/decide", other).await;
    assert_eq!(s, 401);
    // No presence at all: refused.
    let (s, v) = w
        .control("POST", "/v1/cred-proposals/decide", approve.clone())
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (401, Some("AV_PRESENCE_REQUIRED")),
        "{v}"
    );
    // Signed and sent as signed: the credential is made.
    let (_, ch) = challenge(&w, "POST /v1/cred-proposals/decide", &approve).await;
    let mut b = approve.clone();
    b["presence"] = json!({"challengeId": ch["challengeId"], "companionSignature": e.sign(ch["challenge"].as_str().unwrap())});
    let (s, v) = w.control("POST", "/v1/cred-proposals/decide", b).await;
    assert_eq!((s, v["state"].as_str()), (200, Some("approved")), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn touch_id_unlock_is_set_up_with_fresh_presence_for_the_enrolled_key_only() {
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let route = "/v1/presence/companion/unlock";
    // No companion key: nothing to tie the unlock to.
    let w = with_passphrase().await;
    let (s, v) = w
        .control(
            "POST",
            route,
            json!({"prf_secret": secret, "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("companion_not_enrolled")),
        "{v}"
    );

    let (w, e) = enrolled().await;
    // Not 32 bytes of base64url: refused before any proof is looked at.
    let long = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 33]);
    for bad in [
        "",
        "short",
        "AAAA",
        &format!("{secret}="),
        &secret[..42],
        &long,
    ] {
        let (s, v) = w
            .control(
                "POST",
                route,
                json!({"prf_secret": bad, "presence": {"passphrase": PASS}}),
            )
            .await;
        assert_eq!(
            (s, v["code"].as_str()),
            (403, Some("AV_POLICY_DENIED")),
            "{bad}: {v}"
        );
    }
    // No proof, or only a confirmation window: fresh presence is needed.
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS}))
        .await;
    let (s, v) = w
        .control("POST", route, json!({"prf_secret": secret}))
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("fresh_presence")),
        "{v}"
    );
    let (_, v) = w.control("GET", "/v1/lockstate", json!({})).await;
    assert_eq!(v["has_companion_unlock"], false);

    // Signed by the companion, for exactly this secret.
    let body = json!({"prf_secret": secret});
    let (s, ch) = challenge(&w, &format!("POST {route}"), &body).await;
    assert_eq!(s, 200, "{ch}");
    assert_eq!(ch["operation"]["op"], "companion.unlock_enroll");
    assert!(
        ch["operation"].get("prf_secret").is_none(),
        "bound by digest only"
    );
    let mut b = body;
    b["presence"] = json!({
        "challengeId": ch["challengeId"],
        "companionSignature": e.sign(ch["challenge"].as_str().unwrap()),
    });
    let (s, v) = w.control("POST", route, b).await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = w.control("GET", "/v1/presence/companion", json!({})).await;
    assert_eq!(v["unlock"], true);

    // It opens a locked vault; another secret does not.
    let (s, _) = w.control("POST", "/v1/lock", json!({})).await;
    assert_eq!(s, 200);
    let (_, v) = w.control("GET", "/v1/lockstate", json!({})).await;
    assert_eq!(
        (v["locked"].as_bool(), v["has_companion_unlock"].as_bool()),
        (Some(true), Some(true))
    );
    let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
    let (s, _) = w
        .control("POST", "/v1/unlock", json!({"prf_secret": other}))
        .await;
    assert_ne!(s, 200);
    let (s, v) = w
        .control("POST", "/v1/unlock", json!({"prf_secret": secret}))
        .await;
    assert_eq!(
        (s, v["factor"].as_str()),
        (200, Some("companion-prf")),
        "{v}"
    );
}
