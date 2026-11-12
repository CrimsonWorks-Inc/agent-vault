//! Presence: the passphrase window, the fresh-presence gate, the passphrase
//! throttle, WebAuthn assertions bound to one operation, factor order. Ports
//! the internal parts of test/security/control-gate.test.js,
//! fix-control-presence.test.js, fix-control-factors.test.js,
//! fix-control-touchid.test.js, fix-control-webauthn.test.js and
//! integrate3-gates.test.js (see PORTED.md).

use serde_json::{json, Value};

use super::*;
use crate::ui::webauthn::testkit::SoftKey;

const PASS: &str = "test-passphrase-123";

async fn with_passphrase() -> World {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("POST", "/v1/passphrase", json!({"passphrase": PASS})).await;
    assert_eq!(s, 200, "{v}");
    w
}

#[tokio::test(flavor = "multi_thread")]
async fn with_no_factor_widening_is_open_and_audited_as_ungated() {
    let w = World::seeded(json!({})).await;
    let (s, _) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    assert_eq!(s, 200);
    assert!(w.audit_text().await.contains("control.widening_ungated"));
    let (_, v) = w.control("POST", "/v1/presence/window", json!({"passphrase": "x"})).await;
    assert_eq!((v["granted"].as_bool(), v["ungated"].as_bool()), (Some(false), Some(true)));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_passphrase_gates_widening_and_the_window_admits_and_records() {
    let w = with_passphrase().await;
    let (s, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    assert_eq!((s, v["code"].as_str(), v["rule"].as_str()), (401, Some("AV_PRESENCE_REQUIRED"), Some("human_presence")));
    assert_eq!(v["factors"], json!(["passphrase"]));
    let (s, v) = w.control("POST", "/v1/presence/window", json!({"passphrase": "wrong-guess"})).await;
    assert_eq!((s, v["code"].as_str()), (403, Some("AV_PRESENCE_DENIED")));
    let (s, v) = w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    assert_eq!(s, 200, "{v}");
    let (s, _) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    assert_eq!(s, 200);
    assert!(w.audit_text().await.contains("presence.window_used"));
    // Locking closes the window.
    w.control("POST", "/v1/lock", json!({})).await;
    w.control("POST", "/v1/unlock", json!({"passphrase": PASS})).await;
    let (s, _) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    assert_eq!(s, 401, "a lock that leaves the window open is not one");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_fresh_presence_never_rides_the_window() {
    let w = with_passphrase().await;
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    let body = json!({"cred": "demo", "approval": "auto", "methods": ["GET", "POST"]});
    let (s, v) = w.control("POST", "/v1/sessions", body.clone()).await;
    assert_eq!((s, v["rule"].as_str()), (401, Some("fresh_presence")), "{v}");
    let mut with = body;
    with["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/sessions", with).await;
    assert_eq!(s, 200, "{v}");
    let (_, list) = w.control("GET", "/v1/sessions", json!({})).await;
    assert!(list.as_array().unwrap().iter().any(|s| s["elevated"] == json!(["approval_auto_writes"])));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_failed_passphrases_back_off_and_a_right_one_resets() {
    let w = with_passphrase().await;
    for _ in 0..5 {
        let (s, _) = w.control("POST", "/v1/presence/window", json!({"passphrase": "nope-nope"})).await;
        assert_eq!(s, 403);
    }
    let (s, v) = w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    assert_eq!((s, v["code"].as_str(), v["rule"].as_str()), (429, Some("AV_RATE_LIMITED"), Some("passphrase_throttle")), "{v}");
    assert!(w.audit_text().await.contains("presence.throttled"));
    // The owner's worst case is short: wait it out.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (s, _) = w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    assert_eq!(s, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_an_authenticator_needs_a_passphrase_first_and_cannot_be_enrolled_by_the_window() {
    let w = World::seeded(json!({})).await;
    let k = SoftKey::new();
    let (s, v) = w.control("POST", "/v1/presence", k.record()).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("factor_order")));
    let (_, _) = w.control("POST", "/v1/passphrase", json!({"passphrase": PASS})).await;
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    let (s, v) = w.control("POST", "/v1/presence", k.record()).await;
    assert_eq!((s, v["rule"].as_str()), (401, Some("fresh_presence")), "the shared window cannot change presence factors");
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    let (_, stored) = w.control("GET", "/v1/presence", json!({})).await;
    assert!(stored.get("presence").is_none(), "the proof is never stored");
    assert_eq!(stored["credentialId"], json!(k.id));
}

async fn enrolled() -> (World, SoftKey) {
    let w = with_passphrase().await;
    let k = SoftKey::new();
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    (w, k)
}

async fn challenge(w: &World, operation: &Value) -> (String, Vec<u8>) {
    let (s, v) = w.control("POST", "/v1/presence/challenge", json!({"operation": operation})).await;
    assert_eq!(s, 200, "{v}");
    (v["challengeId"].as_str().unwrap().to_string(), crate::util::b64url_lenient(v["challenge"].as_str().unwrap()))
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_an_assertion_is_bound_to_one_operation_one_use_and_the_trusted_origin() {
    let (w, mut k) = enrolled().await;
    let body = json!({"cred": "demo", "sid": w.session_id});
    let op = crate::util::operation_for("placeholder.issue", &body).unwrap();
    // The right operation from the right origin.
    let (id, ch) = challenge(&w, &op).await;
    let mut proof = k.assert(&ch, "http://localhost:7412");
    proof["challengeId"] = id.clone().into();
    let mut b = body.clone();
    b["presence"] = proof.clone();
    let (s, v) = w.control("POST", "/v1/placeholders", b.clone()).await;
    assert_eq!(s, 200, "{v}");
    // Single use.
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);
    // Signed for one operation, submitted as another.
    let (id, ch) = challenge(&w, &op).await;
    let mut proof = k.assert(&ch, "http://localhost:7412");
    proof["challengeId"] = id.into();
    let (s, _) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id, "uses": 1, "presence": proof})).await;
    assert_eq!(s, 401);
    assert!(w.audit_text().await.contains("operation_mismatch"));
    // A look-alike page on another port.
    let (id, ch) = challenge(&w, &op).await;
    let mut proof = k.assert(&ch, "http://localhost:9999");
    proof["challengeId"] = id.into();
    let mut b = body;
    b["presence"] = proof;
    let (s, _) = w.control("POST", "/v1/placeholders", b).await;
    assert_eq!(s, 401);
    let audit = w.audit_text().await;
    assert!(audit.contains("\"reason\":\"origin\""), "the failure is recorded by code");
    assert!(!audit.contains("localhost:9999"), "never the client's own text (r5 F1)");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_reserved_field_cannot_rewrite_the_signed_operation() {
    let (w, _k) = enrolled().await;
    let (s, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id, "op": "something.else"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("reserved_operation_field")));
    let (s, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "value_sha256": "x"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("reserved_operation_field")));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_the_signature_counter_is_not_settable_and_a_trusted_origin_needs_fresh_presence() {
    let (w, _k) = enrolled().await;
    let (s, v) = w.control("PATCH", "/v1/presence", json!({"signCount": 300000})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("counter_not_settable")));
    let (s, v) = w.control("POST", "/v1/ui/origins", json!({"origin": "http://evil.test"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("ui_origin")));
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    let (s, _) = w.control("POST", "/v1/ui/origins", json!({"origin": "http://localhost:9999"})).await;
    assert_eq!(s, 401, "the window cannot trust another page");
    let (s, v) = w.control("POST", "/v1/ui/origins", json!({"origin": "http://localhost:9999", "presence": {"passphrase": PASS}})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["origins"].as_array().unwrap().contains(&json!("http://localhost:9999")));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_challenges_are_bounded_and_the_newest_always_works() {
    let (w, _k) = enrolled().await;
    let mut first = None;
    for i in 0..70 {
        let (id, _) = challenge(&w, &json!({"op": "x", "i": i})).await;
        if i == 0 {
            first = Some(id);
        }
    }
    let n = w.shared.run(|core| core.dm_open_challenges()).await.unwrap();
    assert!(n <= crate::server::MAX_OPEN_CHALLENGES);
    assert!(first.is_some());
    let big = json!({"op": "x", "blob": "a".repeat(9000)});
    let (s, _) = w.control("POST", "/v1/presence/challenge", json!({"operation": big})).await;
    assert_eq!(s, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_touch_id_enrollment_needs_a_recovery_factor_and_fresh_presence() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("POST", "/v1/factors/webauthn", json!({"credential_id": "abc", "prf_secret": "x".repeat(32)})).await;
    assert!(s >= 400, "{v}");
    let w = with_passphrase().await;
    w.control("POST", "/v1/presence/window", json!({"passphrase": PASS})).await;
    let (s, v) = w.control("POST", "/v1/factors/webauthn", json!({"credential_id": "abc", "prf_secret": "x".repeat(32)})).await;
    assert_eq!((s, v["rule"].as_str()), (401, Some("fresh_presence")), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn passphrase_set_change_and_remove_are_proved_by_the_current_one() {
    let w = with_passphrase().await;
    let (s, v) = w.control("POST", "/v1/passphrase", json!({"passphrase": "another-pass-1", "current": "wrong-one"})).await;
    assert!(s >= 400, "{v}");
    let (s, v) = w.control("POST", "/v1/passphrase", json!({"passphrase": "another-pass-1", "current": PASS})).await;
    assert_eq!(s, 200, "{v}");
    let (_, ls) = w.control("GET", "/v1/lockstate", json!({})).await;
    assert_eq!((ls["has_passphrase"].as_bool(), ls["needs_secret"].as_bool()), (Some(true), Some(true)));
    // The last human factor is never removed.
    let (s, v) = w.control("POST", "/v1/passphrase", json!({"action": "remove", "current": "another-pass-1"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("last_factor")), "{v}");
}
