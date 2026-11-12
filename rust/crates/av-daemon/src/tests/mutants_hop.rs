//! Tests for the redirect-hop and method-override entries of
//! src/daemon/pipeline.js in mutations.toml. Each names the protection (the
//! `what` of test/mutation-check.js) it holds.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;

const PASS: &str = "test-passphrase-123";

/// A world whose upstream answers the first request with `status` and
/// `location`, and every later one with 200; it records what each got.
async fn hopping(session: Value, status: u16, location: &str) -> World {
    let w = World::seeded(session).await;
    let n = Arc::new(Mutex::new(0usize));
    let loc = location.to_string();
    w.up.answer(Box::new(move |_| {
        let mut k = n.lock().unwrap();
        *k += 1;
        if *k == 1 {
            let mut x = json_response(status, &json!({}));
            x.headers.push(("location".into(), loc.clone()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({"at": "next"})))
        }
    }));
    w
}

fn hop_of(w: &World) -> Option<crate::upstream::UpstreamRequest> {
    w.up.hits.lock().unwrap().get(1).cloned()
}

fn has(h: &crate::upstream::UpstreamRequest, name: &str) -> bool {
    h.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// "a redirect hop copies the request's headers, method overrides
/// included" and 'a hop drops the API-version headers a provider needs'.
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_forwards_an_allowlist_of_headers_only() {
    let w = hopping(json!({"redirects": 2}), 302, "/next").await;
    let h = vec![
        (
            "authorization".to_string(),
            format!("Bearer {}", w.placeholder),
        ),
        ("x-agent-chosen".to_string(), "1".to_string()),
        ("cookie".to_string(), "sid=agent".to_string()),
        ("x-forwarded-host".to_string(), "evil.test".to_string()),
        ("anthropic-version".to_string(), "2023-06-01".to_string()),
        ("x-github-api-version".to_string(), "2022-11-28".to_string()),
    ];
    let r = w.send("GET", "/start", h, None).await;
    assert_eq!(r.status, 200, "{:?}", r.error);
    let hop = hop_of(&w).expect("the hop was sent");
    for n in [
        "x-agent-chosen",
        "cookie",
        "x-forwarded-host",
        "x-forwarded-for",
    ] {
        assert!(!has(&hop, n), "{n}: {:?}", hop.headers);
    }
    assert!(
        has(&hop, "anthropic-version") && has(&hop, "x-github-api-version"),
        "{:?}",
        hop.headers
    );
    assert!(
        has(&hop, "authorization"),
        "the credential's own header rides the hop"
    );
}

/// 'a 307 or 308 hop is sent as a GET whatever the request was'.
#[tokio::test(flavor = "multi_thread")]
async fn a_head_request_hops_as_a_head() {
    let w = hopping(
        json!({"redirects": 2, "methods": ["GET", "HEAD"]}),
        307,
        "/next",
    )
    .await;
    let r = w
        .send(
            "HEAD",
            "/start",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.error);
    assert_eq!(hop_of(&w).unwrap().method, "HEAD");
}

/// 'a redirect hop follows a Location carrying a method-override field'.
#[tokio::test(flavor = "multi_thread")]
async fn a_location_carrying_a_method_override_is_not_followed() {
    let w = hopping(json!({"redirects": 2}), 302, "/next?_method=DELETE").await;
    let r = w.get("/start").await;
    assert_eq!(r.header("av-redirect-stopped"), Some("path"));
    assert_eq!(w.up.count(), 1);
}

/// 'a redirect hop sends a body or framing header a credential is declared
/// at'.
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_never_sends_a_framing_header_even_one_a_credential_uses() {
    let mut w = World::bare().await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "ct", "kind": "http", "host": "ct.example.test", "value": SECRET, "sites": ["header:content-type", "header:x-key"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "ct", "methods": ["GET"], "redirects": 2, "ttl_hours": 1}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    w.slug = "ct".into();
    w.token = v["token"].as_str().unwrap().into();
    w.placeholder = v["placeholder"].as_str().unwrap().into();
    let n = Arc::new(Mutex::new(0usize));
    w.up.answer(Box::new(move |_| {
        let mut k = n.lock().unwrap();
        *k += 1;
        if *k == 1 {
            let mut x = json_response(302, &json!({}));
            x.headers.push(("location".into(), "/next".into()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({})))
        }
    }));
    let r = w
        .send(
            "GET",
            "/start",
            vec![("x-key".into(), w.placeholder.clone())],
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.error);
    let hop = hop_of(&w).unwrap();
    assert!(!has(&hop, "content-type"), "{:?}", hop.headers);
    assert!(has(&hop, "x-key"));
}

/// 'a redirect hop skips the GraphQL rules'.
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_is_held_to_the_graphql_rules() {
    let doc = crate::util::encode_uri_component(
        "mutation { createDeployKey(input:{title:\"x\"}) { id } }",
    );
    let w = hopping(
        json!({"redirects": 2, "payload": {"graphql": {"operations": ["query"], "deny_fields": ["createDeployKey"]}}}),
        302,
        &format!("/graphql?query={doc}"),
    )
    .await;
    let r = w.get("/start").await;
    assert_eq!(r.header("av-redirect-stopped"), Some("path"));
    assert_eq!(w.up.count(), 1);
}

/// 'a redirect hop silently drops the body rules'.
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_answers_to_the_body_rules_as_a_body_less_request() {
    let w = hopping(
        json!({"redirects": 2, "payload": {"json": {"/confirm": {"required": true}}}}),
        302,
        "/next",
    )
    .await;
    let r = w
        .send(
            "GET",
            "/start",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("content-type".into(), "application/json".into()),
            ],
            Some(r#"{"confirm":true}"#),
        )
        .await;
    assert_eq!(
        r.header("av-redirect-stopped"),
        Some("path"),
        "{:?}",
        r.error
    );
    assert_eq!(w.up.count(), 1);
}

/// 'a method-override header is not held to the route pairs'.
#[tokio::test(flavor = "multi_thread")]
async fn a_method_override_is_held_to_the_route_pairs() {
    let mut w = World::bare().await;
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "demo", "kind": "http", "host": "api.example.test", "value": SECRET, "sites": ["header:authorization:Bearer"]})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "methods": ["GET", "POST"], "approval": "auto", "ttl_hours": 1,
                   "routes": [{"methods": ["GET"], "paths": ["/a/**"]}, {"methods": ["POST"], "paths": ["/b/**"]}],
                   "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    w.slug = "demo".into();
    w.token = v["token"].as_str().unwrap().into();
    w.placeholder = v["placeholder"].as_str().unwrap().into();
    let mut h = vec![(
        "authorization".to_string(),
        format!("Bearer {}", w.placeholder),
    )];
    h.push(("x-http-method-override".into(), "POST".into()));
    let r = w.send("GET", "/a/x", h, None).await;
    assert_eq!(
        r.status, 403,
        "POST is not paired with /a/**: {:?}",
        r.error
    );
    assert_eq!(w.up.count(), 0);
}

/// 'preflight reads headers that were never folded'.
#[tokio::test(flavor = "multi_thread")]
async fn preflight_refuses_a_single_valued_header_sent_twice() {
    let w = World::seeded(json!({})).await;
    let e = w
        .daemon
        .pipeline
        .preflight(
            crate::pipeline::GatewayRequest {
                method: "POST".into(),
                path: "/p/demo/x".into(),
                query: String::new(),
                headers: vec![
                    ("host".into(), "127.0.0.1".into()),
                    ("av-session".into(), w.token.clone()),
                    ("content-type".into(), "application/json".into()),
                    (
                        "Content-Type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                ],
                body: Some(b"{}".to_vec()),
                listener: None,
            },
            true,
        )
        .await
        .expect_err("refused");
    assert_eq!(e.extra.rule.as_deref(), Some("header_duplicate"));
}

/// "a hop's override check reads the raw URL instead of the view" and 'a
/// hop to a Location with a stray name is followed'.
#[tokio::test(flavor = "multi_thread")]
async fn a_location_is_read_through_the_request_view() {
    for loc in ["/next?_METHOD=DELETE", "/next?%5Bx=1"] {
        let w = hopping(json!({"redirects": 2}), 302, loc).await;
        let r = w.get("/start").await;
        assert_eq!(r.header("av-redirect-stopped"), Some("path"), "{loc}");
        assert_eq!(w.up.count(), 1, "{loc}");
    }
}

fn pin(c: char) -> String {
    format!("sha256/{}=", c.to_string().repeat(43))
}

/// "the gateway's upstream drops the credential's pins" and 'the gateway
/// looks pins up by exact key, so a malformed pin table means no pins'.
#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_call_carries_the_pins_for_the_url_host() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/pins",
            json!({"slug": "demo", "host": "api.example.test", "pins": [pin('A')]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(w.get("/x").await.status, 200);
    let pins = w.up.hits.lock().unwrap()[0].pins.as_value();
    assert_eq!(pins, json!([pin('A')]));
    // A key spelled another way still names the URL's host.
    let c = rusqlite::Connection::open(w._dir.path().join("vault.db")).unwrap();
    c.execute_batch("UPDATE pins SET host = 'API.Example.test.'")
        .unwrap();
    drop(c);
    assert_eq!(w.get("/y").await.status, 200);
    let pins = w.up.hits.lock().unwrap()[1].pins.as_value();
    assert_eq!(pins, json!([pin('A')]));
}

/// 'a refusal from pinnedRequest is reported as an unreachable upstream and
/// not refunded'.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_request_refusal_is_a_refunded_policy_denial() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Err(UpstreamError {
            vault: Some(Box::new(crate::err::dr(
                crate::err::C::PolicyDenied,
                "the Host header names a different host than the URL",
                "host_mismatch",
            ))),
            ..Default::default()
        })
    }));
    let sid = w.session_id.clone();
    let used = |w: &World| {
        let (shared, sid) = (w.shared.clone(), sid.clone());
        async move {
            shared
                .run(move |c| {
                    c.vault
                        .list_placeholders(Some(&sid))
                        .unwrap()
                        .iter()
                        .map(|p| p.uses)
                        .sum::<u64>()
                })
                .await
                .unwrap()
        }
    };
    let before = used(&w).await;
    let r = w.get("/x").await;
    assert_eq!(r.status, 403, "{:?}", r.error);
    let e = r.error.unwrap();
    assert_eq!(e.extra.rule.as_deref(), Some("host_mismatch"));
    assert_eq!(used(&w).await, before, "the use was refunded");
}
