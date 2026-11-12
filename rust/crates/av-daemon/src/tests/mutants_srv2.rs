//! More tests for the src/daemon/server.js entries of mutations.toml: the
//! widening gates with a factor enrolled, backup inspect, tripwires,
//! narrowing, rotation and template binding. Each names the protection (the
//! `what` of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::*;

const PASS: &str = "test-passphrase-123";
const RECOVERY: &str = "recovery-passphrase-0123456789";

async fn gated() -> World {
    let w = World::seeded(json!({"approval": "each"})).await;
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    w
}

fn human(v: &Value) -> bool {
    v["code"] == "AV_PRESENCE_REQUIRED"
}

/// The A.2 widening entries: each change needs a human once a factor is
/// enrolled.
#[tokio::test(flavor = "multi_thread")]
async fn every_widening_change_needs_a_human() {
    let w = gated().await;
    let calls = [
        (
            "POST",
            "/v1/credentials/rotate",
            json!({"slug": "demo", "value": "another-secret-0123456789abcdef"}),
        ),
        (
            "POST",
            "/v1/credentials/scrub",
            json!({"slug": "demo", "pattern": "zz-[0-9]{6}"}),
        ),
        (
            "DELETE",
            "/v1/credentials/scrub?slug=demo&id=sp_x",
            json!({}),
        ),
        (
            "POST",
            "/v1/credentials/expiry",
            json!({"slug": "demo", "expires_at": null}),
        ),
        (
            "POST",
            "/v1/credentials/pins",
            json!({"slug": "demo", "host": "api.example.test", "pins": [format!("sha256/{}=", "A".repeat(43))]}),
        ),
        ("POST", "/v1/credentials/release", json!({"slug": "demo"})),
        (
            "POST",
            "/v1/templates",
            json!({"name": "t", "spec": {"cred": "demo", "methods": ["GET"]}}),
        ),
        (
            "POST",
            "/v1/backup/restore",
            json!({"bundle": {}, "recovery_passphrase": RECOVERY}),
        ),
        (
            "POST",
            "/v1/notify",
            json!({"webhook_url": "https://hooks.example.test/x"}),
        ),
        ("POST", "/v1/tripwires", json!({"enabled": false})),
        ("POST", "/v1/tripwires", json!({"enabled": "true"})),
        ("POST", "/v1/tripwires", json!({"enabled": 1})),
    ];
    for (m, p, body) in calls {
        let (s, v) = w.control(m, p, body.clone()).await;
        assert!(s == 401 && human(&v), "{m} {p} {body}: {s} {v}");
    }
    let (s, v) = w
        .control("POST", "/v1/tripwires", json!({"enabled": true}))
        .await;
    assert_eq!(s, 200, "turning tripwires on needs no one: {v}");
}

/// 'backup export accepts the window instead of a fresh proof (F8)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_backup_export_needs_fresh_presence_even_inside_the_window() {
    let w = gated().await;
    let (s, v) = w
        .control("POST", "/v1/presence/window", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/backup/export",
            json!({"recovery_passphrase": RECOVERY}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("fresh_presence")),
        "{v}"
    );
}

async fn bundle(w: &World) -> Value {
    let (s, v) = w
        .control(
            "POST",
            "/v1/backup/export",
            json!({"recovery_passphrase": RECOVERY, "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    v["bundle"].clone()
}

async fn inspect(w: &World, b: &Value, pass: &str) -> (u16, Value) {
    w.control(
        "POST",
        "/v1/backup/inspect",
        json!({"bundle": b, "recovery_passphrase": pass}),
    )
    .await
}

/// 'a wrong recovery passphrase on inspect is not counted (F8)' and 'a right
/// recovery passphrase on inspect clears the vault passphrase throttle (F8)'.
#[tokio::test(flavor = "multi_thread")]
async fn inspect_counts_wrong_recovery_passphrases_and_a_right_one_clears_nothing() {
    let w = gated().await;
    let b = bundle(&w).await;
    assert!(b.is_object() || b.is_string(), "{b}");
    let free = crate::server::PASSPHRASE_FREE_ATTEMPTS;
    for _ in 0..free - 1 {
        let (s, v) = inspect(&w, &b, "wrong-recovery-passphrase").await;
        assert!(s >= 400 && v["rule"] == "backup_auth", "{s} {v}");
    }
    let (s, v) = inspect(&w, &b, RECOVERY).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = inspect(&w, &b, "wrong-recovery-passphrase").await;
    assert!(s >= 400 && v["rule"] == "backup_auth", "{s} {v}");
    let (s, v) = inspect(&w, &b, RECOVERY).await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (429, Some("passphrase_throttle")),
        "the right one did not clear the count: {v}"
    );
}

/// 'a narrowing that turns redirects on is only refused after the session
/// was shortened (F15)' and 'a narrowing silently ignores a field it cannot
/// narrow (F15)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_narrowing_that_widens_or_names_nothing_it_reads_is_refused_whole() {
    let w = World::seeded(json!({})).await;
    let before = w
        .shared
        .run({
            let sid = w.session_id.clone();
            move |c| c.vault.session(&sid).unwrap().unwrap().expires_at
        })
        .await
        .unwrap();
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions/narrow",
            json!({"sid": w.session_id, "narrow": {"redirects": 3}, "session_ttl_minutes": 5}),
        )
        .await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("narrow_widens")), "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions/narrow",
            json!({"sid": w.session_id, "narrow": {"zz_unread": 1}, "session_ttl_minutes": 5}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("policy_invalid")),
        "{v}"
    );
    let after = w
        .shared
        .run({
            let sid = w.session_id.clone();
            move |c| c.vault.session(&sid).unwrap().unwrap().expires_at
        })
        .await
        .unwrap();
    assert_eq!(before, after, "nothing was shortened");
}

/// 'rotation keeps the held approvals a human gave against the old key (F7)'
/// and 'a rotation retire window is read by coercion'.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_denies_held_approvals_and_reads_the_retire_window_as_written() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let r = w
        .send(
            "POST",
            "/x",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    assert_eq!(r.status, 202);
    for bad in [json!("5"), json!(5.5), json!(169), json!(-1)] {
        let (s, v) = w
            .control(
                "POST",
                "/v1/credentials/rotate",
                json!({"slug": "demo", "value": "another-secret-0123456789abcdef", "retire_hours": bad}),
            )
            .await;
        assert_eq!(
            (s, v["rule"].as_str()),
            (403, Some("retire_window")),
            "{bad}: {v}"
        );
    }
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/rotate",
            json!({"slug": "demo", "value": "another-secret-0123456789abcdef"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["invalidated_approvals"], 1, "{v}");
    let (_, held) = w.control("GET", "/v1/approvals", json!({})).await;
    assert_eq!(held, json!([]));
}

/// "a template create's signed operation binds the name but not
/// template_hash (F17)".
#[tokio::test(flavor = "multi_thread")]
async fn a_signature_over_a_template_name_alone_does_not_create_from_it() {
    let w = World::seeded(json!({})).await;
    let (s, t) = w
        .control(
            "POST",
            "/v1/templates",
            json!({"name": "t", "spec": {"cred": "demo", "methods": ["GET"]}}),
        )
        .await;
    assert_eq!(s, 200, "{t}");
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let mut k = crate::ui::webauthn::testkit::SoftKey::new();
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    let name_only =
        crate::util::operation_for("session.create", &json!({"template": "t"})).unwrap();
    let (s, ch) = w
        .control(
            "POST",
            "/v1/presence/challenge",
            json!({"operation": name_only}),
        )
        .await;
    assert_eq!(s, 200, "{ch}");
    let mut proof = k.assert(
        &crate::util::b64url_lenient(ch["challenge"].as_str().unwrap()),
        "http://localhost:7412",
    );
    proof["challengeId"] = ch["challengeId"].clone();
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"template": "t", "template_hash": t["hash"], "presence": proof}),
        )
        .await;
    assert_eq!(s, 401, "the hash the human looked at was not signed: {v}");
    // Control: the same proof over the whole operation creates it.
    let body = json!({"template": "t", "template_hash": t["hash"]});
    let full = crate::util::operation_for("session.create", &body).unwrap();
    let (_, ch) = w
        .control("POST", "/v1/presence/challenge", json!({"operation": full}))
        .await;
    let mut proof = k.assert(
        &crate::util::b64url_lenient(ch["challenge"].as_str().unwrap()),
        "http://localhost:7412",
    );
    proof["challengeId"] = ch["challengeId"].clone();
    let mut b = body;
    b["presence"] = proof;
    let (s, v) = w.control("POST", "/v1/sessions", b).await;
    assert_eq!(s, 200, "{v}");
}

/// 'a session request from a template is resolved again at approval, not
/// snapshotted (F17)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_template_request_is_approved_as_it_was_asked_not_as_the_template_now_reads() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/templates",
            json!({"name": "t", "spec": {"cred": "demo", "methods": ["GET"], "budget": 5}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, asked) = w
        .control("POST", "/v1/session-requests", json!({"template": "t"}))
        .await;
    assert_eq!(s, 200, "{asked}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/templates",
            json!({"name": "t", "spec": {"cred": "demo", "methods": ["GET", "DELETE"], "budget": 50}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": asked["id"], "granted": true}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let sid = v["session"]["session_id"].as_str().unwrap().to_string();
    let policies = w
        .shared
        .run(move |c| {
            c.vault
                .grants_for_session(&sid)
                .unwrap()
                .into_iter()
                .map(|g| serde_json::to_value(g.policy).unwrap())
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
    let text = crate::util::js_stringify(&Value::Array(policies));
    assert!(!text.contains("DELETE"), "{text}");
    assert!(!text.contains("\"limit\":50"), "{text}");
}

/// 'a panic that locks leaves the passphrase window open'.
#[tokio::test(flavor = "multi_thread")]
async fn a_panic_that_locks_closes_the_window() {
    let w = gated().await;
    let (s, v) = w
        .control("POST", "/v1/presence/window", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w.control("POST", "/v1/panic", json!({"lock": true})).await;
    assert_eq!((s, v["locked"].as_bool()), (200, Some(true)), "{v}");
    let (s, v) = w
        .control("POST", "/v1/unlock", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control("POST", "/v1/credentials/release", json!({"slug": "demo"}))
        .await;
    assert!(
        s == 401 && human(&v),
        "the window did not outlive the lock: {s} {v}"
    );
}
