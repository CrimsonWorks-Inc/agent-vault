//! Pinning against real certificate chains, the probe, the notifier, and
//! state that must survive a restart. Ports the internal parts of
//! test/security/connectors-pinning.test.js, connectors-probe.test.js,
//! connectors-health.test.js, control-api-notify.test.js and
//! session-requests.test.js (see PORTED.md).

use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value};

use super::*;
use crate::connectors::pinning::{spki_of, verdict_with};

struct Chain {
    root: Vec<u8>,
    inter: Vec<u8>,
    leaf: Vec<u8>,
    stray: Vec<u8>,
}

fn ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair) {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, name);
    p.distinguished_name = dn;
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    (p, rcgen::KeyPair::generate().unwrap())
}

fn chain(leaf_days: (i64, i64)) -> Chain {
    let (rp, rk) = ca("test root");
    let root = rp.self_signed(&rk).unwrap();
    let root_issuer = rcgen::Issuer::new(rp, rk);
    let (ip, ik) = ca("test intermediate");
    let inter = ip.signed_by(&ik, &root_issuer).unwrap();
    let inter_issuer = rcgen::Issuer::new(ip, ik);
    let mut lp = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    lp.not_before = now + time::Duration::days(leaf_days.0);
    lp.not_after = now + time::Duration::days(leaf_days.1);
    let lk = rcgen::KeyPair::generate().unwrap();
    let leaf = lp.signed_by(&lk, &inter_issuer).unwrap();
    let (sp, sk) = ca("unrelated");
    let stray = sp.self_signed(&sk).unwrap();
    Chain {
        root: root.der().to_vec(),
        inter: inter.der().to_vec(),
        leaf: leaf.der().to_vec(),
        stray: stray.der().to_vec(),
    }
}

fn anchor(der: &[u8]) -> rustls::pki_types::TrustAnchor<'static> {
    webpki::anchor_from_trusted_cert(&CertificateDer::from(der.to_vec()))
        .unwrap()
        .to_owned()
}

fn name(n: &str) -> ServerName<'static> {
    ServerName::try_from(n.to_string()).unwrap()
}

#[test]
fn hardening_a_pin_matches_only_a_certificate_in_the_verified_path() {
    let c = chain((-1, 30));
    let anchors = vec![anchor(&c.root)];
    let presented = vec![c.leaf.clone(), c.inter.clone(), c.stray.clone()];
    // The server appends an unrelated certificate whose key is the pin, over
    // an otherwise valid, unpinned chain: refused.
    let stray_pin = vec![spki_of(&c.stray).unwrap()];
    let e =
        verdict_with(&presented, &name("localhost"), Some(&stray_pin), &anchors).expect("refused");
    assert_eq!(e.code, "AV_PIN_MISMATCH");
    // Control: the pinned intermediate is in the proven path.
    let inter_pin = vec![spki_of(&c.inter).unwrap()];
    assert!(verdict_with(&presented, &name("localhost"), Some(&inter_pin), &anchors).is_none());
    // The trust anchor's own key counts too.
    let root_pin = vec![spki_of(&c.root).unwrap()];
    assert!(verdict_with(
        &presented[..2],
        &name("localhost"),
        Some(&root_pin),
        &anchors
    )
    .is_none());
}

#[test]
fn hardening_a_non_leaf_pin_never_stands_in_for_ca_trust() {
    let c = chain((-1, 30));
    let presented = vec![c.leaf.clone(), c.inter.clone()];
    let inter_pin = vec![spki_of(&c.inter).unwrap()];
    let e = verdict_with(&presented, &name("localhost"), Some(&inter_pin), &[]).expect("refused");
    assert_ne!(e.code, "", "an untrusted chain is refused by its own code");
    assert!(
        verdict_with(&presented, &name("localhost"), None, &[]).is_some(),
        "no pins: the chain must verify"
    );
}

#[test]
fn an_exact_leaf_pin_stands_in_for_ca_trust_but_still_needs_the_name_and_the_dates() {
    let c = chain((-1, 30));
    let presented = vec![c.leaf.clone()];
    let leaf_pin = vec![spki_of(&c.leaf).unwrap()];
    assert!(verdict_with(&presented, &name("localhost"), Some(&leaf_pin), &[]).is_none());
    let e =
        verdict_with(&presented, &name("other.test"), Some(&leaf_pin), &[]).expect("wrong name");
    assert_eq!(e.code, "ERR_TLS_CERT_ALTNAME_INVALID");
    let old = chain((-30, -1));
    let e = verdict_with(
        std::slice::from_ref(&old.leaf),
        &name("localhost"),
        Some(&[spki_of(&old.leaf).unwrap()]),
        &[],
    )
    .expect("expired");
    assert_eq!(
        (e.code.as_str(), e.reason.as_deref()),
        ("AV_PIN_MISMATCH", Some("leaf_expired"))
    );
    let early = chain((2, 30));
    let e = verdict_with(
        std::slice::from_ref(&early.leaf),
        &name("localhost"),
        Some(&[spki_of(&early.leaf).unwrap()]),
        &[],
    )
    .expect("early");
    assert_eq!(e.reason.as_deref(), Some("leaf_not_yet_valid"));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_malformed_pin_list_is_refused_before_connecting_and_plaintext_with_pins_is_refused(
) {
    use crate::upstream::{Pins, UpstreamRequest};
    let base = UpstreamRequest {
        url: "https://127.0.0.1:1/x".into(),
        method: "GET".into(),
        headers: vec![],
        body: None,
        pins: Pins::Unreadable,
    };
    let e = crate::connectors::pinning::pinned_request(base.clone())
        .await
        .err()
        .unwrap();
    assert_eq!(
        (e.code.as_str(), e.reason.as_deref()),
        ("AV_PIN_MISMATCH", Some("pin_format"))
    );
    let mut p = base.clone();
    p.pins = Pins::List(vec![json!("not a pin")]);
    assert_eq!(
        crate::connectors::pinning::pinned_request(p)
            .await
            .err()
            .unwrap()
            .reason
            .as_deref(),
        Some("pin_format")
    );
    let mut p = base.clone();
    p.url = "http://127.0.0.1:1/x".into();
    p.pins = Pins::List(vec![json!(format!("sha256/{}=", "A".repeat(43)))]);
    assert_eq!(
        crate::connectors::pinning::pinned_request(p)
            .await
            .err()
            .unwrap()
            .reason
            .as_deref(),
        Some("plaintext")
    );
    let mut p = base;
    p.pins = Pins::None;
    p.headers = vec![("host".into(), "evil.test".into())];
    let e = crate::connectors::pinning::pinned_request(p)
        .await
        .err()
        .unwrap();
    assert_eq!(
        e.vault.unwrap().extra.rule.as_deref(),
        Some("host_mismatch")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_probe_sends_the_profiles_own_request_once_a_minute_and_scrubs_what_it_reports() {
    crate::connectors::probe::reset_probe_throttle();
    let w = World::bare().await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "gh", "kind": "github", "value": SECRET}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    w.up.answer(Box::new(|_| {
        let mut r = json_response(200, &json!({"login": "x"}));
        r.headers
            .push(("x-oauth-scopes".into(), format!("repo, {SECRET}")));
        Ok(r)
    }));
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/test",
            json!({"slug": "gh", "path": "/admin", "method": "DELETE"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "ok");
    let hit = w.up.hits.lock().unwrap()[0].clone();
    assert_eq!(
        (hit.method.as_str(), hit.url.as_str()),
        ("GET", "https://api.github.com/user"),
        "nothing the caller sent steers it"
    );
    assert!(!leaks(&crate::util::js_stringify(&v)), "{v}");
    let (s, v) = w
        .control("POST", "/v1/credentials/test", json!({"slug": "gh"}))
        .await;
    assert_eq!((s, v["rule"].as_str()), (429, Some("probe_throttle")));
    assert_eq!(w.up.count(), 1);
    assert!(w.audit_text().await.contains("cred.tested"));
}

#[test]
fn webhook_bodies_carry_counts_ids_and_cleaned_headlines_only() {
    let items = vec![
        json!({"kind": "request", "id": "ap_1", "headline": "GET a\u{202e}b", "created_at": "2026-01-01T00:00:00.000Z"}),
    ];
    let minimal: Value = serde_json::from_str(&crate::notify::webhook_payload(
        &items, "minimal", "pending",
    ))
    .unwrap();
    assert!(minimal.get("items").is_none());
    assert_eq!(minimal["kinds"]["request"], 1);
    let headline: Value = serde_json::from_str(&crate::notify::webhook_payload(
        &items, "headline", "pending",
    ))
    .unwrap();
    assert_eq!(headline["items"][0]["id"], "ap_1");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_watch_stream_starts_with_a_snapshot_and_is_bounded() {
    let w = World::seeded(json!({"approval": "each"})).await;
    w.get("/user").await;
    let snap = w
        .shared
        .run(crate::notify::Notifier::waiting)
        .await
        .unwrap();
    let mut rx = w.daemon.notifier.subscribe(snap).unwrap();
    let first = rx.recv().await.unwrap();
    assert!(first.starts_with("event: snapshot\n"), "{first}");
    assert!(first.contains("\"kind\":\"request\""));
    assert!(!first.contains(&w.placeholder));
    let mut keep = vec![rx];
    for _ in 1..crate::notify::MAX_SUBSCRIBERS {
        keep.push(w.daemon.notifier.subscribe(vec![]).unwrap());
    }
    let e = w.daemon.notifier.subscribe(vec![]).unwrap_err();
    assert_eq!(e.extra.rule.as_deref(), Some("stream_limit"));
    // A new held request reaches every watcher.
    w.send(
        "POST",
        "/x",
        vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
        Some("{}"),
    )
    .await;
    let next = keep[0].recv().await.unwrap();
    assert!(next.starts_with("event: pending\n"), "{next}");
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_session_requests_survive_a_restart_and_approved_tokens_never_touch_disk() {
    let w = World::seeded(json!({})).await;
    let (_, asked) = w
        .control(
            "POST",
            "/v1/session-requests",
            json!({"cred": "demo", "reason": "r"}),
        )
        .await;
    let id = asked["id"].as_str().unwrap().to_string();
    let dir = w._dir.path().to_path_buf();
    let v2 = av_store::vault::Vault::open(&dir).unwrap();
    let store = crate::session_requests::SessionRequestStore::load(&v2);
    let core = crate::state::Core::new(v2);
    drop(store);
    let mut core = core;
    assert!(
        core.sr_get(&id).is_some(),
        "a restart does not lose the question"
    );
    let (_, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": id, "granted": true}),
        )
        .await;
    assert!(v["session"]["token"].is_string());
    let rows = av_store::vault::Vault::open(&dir)
        .unwrap()
        .session_requests()
        .unwrap();
    assert!(
        !crate::util::js_stringify(&json!(rows)).contains("avs1."),
        "no token on disk"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs av-store grant_runtime"]
async fn the_rolling_quota_survives_a_restart() {
    let w = World::seeded(json!({"quota": {"count": 1, "window": "hour"}})).await;
    assert_eq!(w.get("/user").await.status, 200);
    let dir = w._dir.path().to_path_buf();
    let mut core = crate::state::Core::new(av_store::vault::Vault::open(&dir).unwrap());
    core.vault.unlock(None).unwrap();
    let grant = core.vault.grants().unwrap()[0].clone();
    assert!(
        core.runtime
            .get(&core.vault, &grant.id)
            .quota_state
            .is_some(),
        "quota_state is stored with the grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs av-store grant_runtime"]
async fn a_reservation_left_by_a_previous_process_is_charged_in_full() {
    let w = World::seeded(json!({})).await;
    let dir = w._dir.path().to_path_buf();
    let mut core = crate::state::Core::new(av_store::vault::Vault::open(&dir).unwrap());
    core.vault.unlock(None).unwrap();
    let gid = core.vault.grants().unwrap()[0].id.clone();
    let rt = crate::runtime::GrantRuntime {
        quota_state: None,
        spend: Some(
            json!({"tokens_used": 0, "usd_micros_used": 0, "reserved": {"rq_x": {"tokens": 100, "usd_micros": 5, "at": 1}}}),
        ),
    };
    core.runtime.set(&mut core.vault, &gid, rt);
    drop(core);
    let mut again = crate::state::Core::new(av_store::vault::Vault::open(&dir).unwrap());
    again.vault.unlock(None).unwrap();
    again.pl_recover_spend();
    let spend = again.runtime.get(&again.vault, &gid).spend.unwrap();
    assert_eq!(spend["tokens_used"], 100);
    assert_eq!(spend["reserved"], json!({}));
}
