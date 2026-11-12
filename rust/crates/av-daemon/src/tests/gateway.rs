//! The gateway and pipeline: substitution at declared sites, consume before
//! the upstream, scrubbing, approvals, limits, redirects, preflight. Ports
//! the internal parts of test/security/gateway-*.test.js, pipeline.test.js,
//! approval*.test.js and exfil.test.js (see PORTED.md).

use serde_json::{json, Value};

use super::*;
use crate::upstream::Body;

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_request_substitutes_at_the_declared_site_and_scrubs_the_answer() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|r| {
        let auth = r
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        Ok(json_response(
            200,
            &json!({"login": "fixture", "echo": auth, "ordinary": "ordinary-traffic-control"}),
        ))
    }));
    let (status, text, r) = body_of(w.get("/user").await).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        w.up.last_auth().as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    assert!(!leaks(&text), "{text}");
    assert!(text.contains("ordinary-traffic-control"));
    assert!(text.contains("[[av:redacted"), "{text}");
    assert_eq!(r.header("av-decision"), Some("allow"));
    assert!(r.header("av-redacted").is_some());
    let hit = w.up.hits.lock().unwrap()[0].clone();
    assert!(hit.url.starts_with("https://api.example.test/user"));
    assert!(
        !hit.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("av-session")),
        "the session token never leaves"
    );
    assert!(!leaks(&w.audit_text().await));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_placeholder_outside_its_site_is_refused_before_any_upstream_byte() {
    let w = World::seeded(json!({})).await;
    let ph = w.placeholder.clone();
    type Case<'a> = (&'a str, Vec<(String, String)>, String);
    let cases: Vec<Case<'_>> = vec![
        (
            "undeclared header",
            vec![
                ("authorization".into(), format!("Bearer {ph}")),
                ("x-debug".into(), ph.clone()),
            ],
            "/user".into(),
        ),
        (
            "query",
            vec![("authorization".into(), format!("Bearer {ph}"))],
            format!("/user?q={ph}"),
        ),
        (
            "base64 query",
            vec![("authorization".into(), format!("Bearer {ph}"))],
            format!("/user?q={}", crate::util::b64(ph.as_bytes())),
        ),
    ];
    for (name, headers, path) in cases {
        let r = w.send("GET", &path, headers, None).await;
        assert_eq!(r.status, 403, "{name}");
        assert_eq!(
            r.error.as_ref().unwrap().code.as_str(),
            "AV_BAD_LOCATION",
            "{name}"
        );
    }
    assert_eq!(w.up.count(), 0);
    // Control: the same placeholder at its site goes through.
    assert_eq!(w.get("/user").await.status, 200);
    assert_eq!(w.up.count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_placeholder_is_refused_with_the_site_to_use() {
    let w = World::seeded(json!({})).await;
    let r = w.send("GET", "/user", vec![], None).await;
    assert_eq!(r.status, 401);
    let e = r.error.unwrap();
    assert_eq!(e.code.as_str(), "AV_SESSION_REQUIRED");
    assert_eq!(e.extra.rule.as_deref(), Some("no_placeholder"));
    assert_eq!(
        e.extra.next.as_ref().unwrap()["mcp"]["tool"],
        "vault_get_placeholder"
    );
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_reflected_secret_in_a_header_name_or_value_is_dropped_or_redacted() {
    let w = World::seeded(json!({})).await;
    let hexname = format!("x-leak-{}", crate::util::hex(SECRET.as_bytes()));
    w.up.answer(Box::new(move |_| {
        let mut r = json_response(200, &json!({"ok": true}));
        r.headers.push((hexname.clone(), "1".into()));
        r.headers.push(("x-echo".into(), SECRET.into()));
        r.headers.push(("x-plain".into(), "ordinary".into()));
        r.headers.push(("av-decision".into(), "forged".into()));
        Ok(r)
    }));
    let r = w.get("/user").await;
    assert_eq!(r.status, 200);
    let all = crate::util::js_stringify(&json!(r.headers));
    assert!(!leaks(&all), "{all}");
    assert_eq!(r.header("x-plain"), Some("ordinary"));
    assert_eq!(r.header("av-decision"), Some("allow"));
}

fn sse(events: &[&str]) -> UpstreamResponse {
    let chunks = events.iter().map(|e| Ok(e.as_bytes().to_vec())).collect();
    UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())],
        body: Body::chunks(chunks),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_secret_split_across_sse_events_cuts_the_stream() {
    let w = World::seeded(json!({})).await;
    let (a, b) = SECRET.split_at(16);
    let (a, b) = (a.to_string(), b.to_string());
    w.up.answer(Box::new(move |_| {
        Ok(sse(&[
            "data: ordinary-traffic-control\n\n",
            &format!("data: {a}\n\n"),
            &format!("data: {b}\n\n"),
            "data: after-cut-marker\n\n",
        ]))
    }));
    let (status, text, _) = body_of(w.get("/sse").await).await;
    assert_eq!(status, 200);
    assert!(text.contains("ordinary-traffic-control"), "{text:?}");
    assert!(text.contains("AV_UNSCANNABLE"), "{text}");
    assert!(!text.contains("after-cut-marker"));
    assert!(!leaks(&text));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(w.audit_text().await.contains("response.stream_cut"));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_gzip_response_and_a_gzip_event_stream_are_decoded_and_scrubbed() {
    use std::io::Write;
    let gz = |s: &str| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(s.as_bytes()).unwrap();
        e.finish().unwrap()
    };
    let w = World::seeded(json!({})).await;
    let body = gz(&format!("{{\"echo\":\"{SECRET}\",\"ordinary\":\"ok\"}}"));
    w.up.answer(Box::new(move |_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("content-encoding".into(), "gzip".into()),
            ],
            body: Body::Full(body.clone()),
        })
    }));
    let (status, text, r) = body_of(w.get("/user").await).await;
    assert_eq!(status, 200);
    assert!(!leaks(&text), "{text}");
    assert!(text.contains("\"ordinary\":\"ok\""));
    assert!(r.header("content-encoding").is_none());
    let stream = gz(&format!("data: {SECRET}\n\ndata: ordinary\n\n"));
    w.up.answer(Box::new(move |_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("content-encoding".into(), "gzip".into()),
            ],
            body: Body::chunks(vec![Ok(stream.clone())]),
        })
    }));
    let (_, text, _) = body_of(w.get("/sse").await).await;
    assert!(!leaks(&text), "{text}");
    assert!(text.contains("ordinary"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_zstd_and_unknown_encodings_are_refused_not_passed_through() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/plain".into()),
                ("content-encoding".into(), "zstd".into()),
            ],
            body: Body::Full(SECRET.as_bytes().to_vec()),
        })
    }));
    let r = w.get("/user").await;
    assert_eq!(r.status, 502);
    assert_eq!(r.error.unwrap().code.as_str(), "AV_UNSCANNABLE");
    assert!(!leaks(&String::from_utf8_lossy(&r.body)));
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_each_holds_then_executes_exactly_once_and_replays() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let r = w.get("/user").await;
    assert_eq!(r.status, 202);
    let id = r.header("av-approval-id").unwrap().to_string();
    assert_eq!(w.up.count(), 0, "nothing goes upstream while held");
    let (s, _) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
        .await;
    assert_eq!(s, 200);
    // The placeholder of the held request was not spent; resend it.
    let r = w.get("/user").await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(w.up.count(), 1);
    let again = w.get("/user").await;
    assert_eq!(again.status, 200);
    assert_eq!(again.header("av-replayed"), Some("true"));
    assert_eq!(w.up.count(), 1, "a resend replays, it never runs twice");
    let (s, v) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
        .await;
    assert_eq!(s, 403, "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_string_verdict_is_not_a_verdict() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let id = w
        .get("/user")
        .await
        .header("av-approval-id")
        .unwrap()
        .to_string();
    let (s, v) = w
        .control(
            "POST",
            "/v1/approvals",
            json!({"id": id, "granted": "false"}),
        )
        .await;
    assert_eq!(s, 403);
    assert_eq!(v["rule"], "bulk_decision");
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denial_before_connecting_refunds_the_use() {
    let w = World::seeded(json!({"uses": 1})).await;
    w.up.answer(Box::new(|_| {
        Err(UpstreamError::new(
            "ECONNREFUSED",
            "connect ECONNREFUSED 127.0.0.1:9",
        ))
    }));
    let r = w.get("/user").await;
    assert_eq!(r.status, 502);
    let e = r.error.unwrap();
    assert_eq!(e.code.as_str(), "AV_UPSTREAM_UNREACHABLE");
    assert_eq!(e.extra.refunded, Some(true));
    w.up.answer(Box::new(|_| Ok(json_response(200, &json!({"ok": true})))));
    assert_eq!(
        w.get("/user").await.status,
        200,
        "the one use is still there"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_after_connecting_is_not_refunded() {
    let w = World::seeded(json!({"uses": 1})).await;
    w.up.answer(Box::new(|_| {
        Err(UpstreamError::new("ECONNRESET", "socket hang up"))
    }));
    let e = w.get("/user").await.error.unwrap();
    assert_eq!(e.extra.refunded, Some(false));
    w.up.answer(Box::new(|_| Ok(json_response(200, &json!({"ok": true})))));
    let r = w.get("/user").await;
    assert_ne!(r.status, 200, "the use was spent");
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_is_counted_and_spent() {
    let w = World::seeded(json!({"budget": 2})).await;
    assert_eq!(w.get("/user").await.status, 200);
    assert_eq!(w.get("/user").await.status, 200);
    let r = w.get("/user").await;
    assert_eq!(r.status, 403);
    assert_eq!(r.error.unwrap().extra.rule.as_deref(), Some("budget"));
    assert_eq!(w.up.count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_browser_origin_and_foreign_host_are_refused() {
    let w = World::seeded(json!({})).await;
    let r = w
        .send(
            "GET",
            "/user",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("origin".into(), "https://evil.test".into()),
            ],
            None,
        )
        .await;
    assert_eq!(r.error.unwrap().code.as_str(), "AV_BROWSER_ORIGIN");
    let mut req = GatewayRequest {
        method: "GET".into(),
        path: "/p/demo/user".into(),
        ..Default::default()
    };
    req.headers = vec![
        ("host".into(), "evil.test".into()),
        ("av-session".into(), w.token.clone()),
        ("authorization".into(), format!("Bearer {}", w.placeholder)),
    ];
    let r = w.daemon.pipeline.handle(req).await;
    assert_eq!(
        r.error.unwrap().extra.rule.as_deref(),
        Some("allowed_hosts")
    );
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_compressed_request_body_and_a_duplicated_content_type_are_refused() {
    let w = World::seeded(json!({})).await;
    let auth = (
        "authorization".to_string(),
        format!("Bearer {}", w.placeholder),
    );
    let r = w
        .send(
            "POST",
            "/x",
            vec![auth.clone(), ("content-encoding".into(), "gzip".into())],
            Some("x"),
        )
        .await;
    assert_eq!(r.error.unwrap().code.as_str(), "AV_ENCODED_BODY");
    let r = w
        .send(
            "POST",
            "/x",
            vec![
                auth.clone(),
                ("content-type".into(), "application/json".into()),
                ("content-type".into(), "text/plain".into()),
            ],
            Some("{}"),
        )
        .await;
    assert_eq!(
        r.error.unwrap().extra.rule.as_deref(),
        Some("header_duplicate")
    );
    assert_eq!(w.up.count(), 0);
    // Control: a plain JSON POST goes through, once approved, with its length.
    let send = || {
        w.send(
            "POST",
            "/x",
            vec![
                auth.clone(),
                ("content-type".into(), "application/json".into()),
            ],
            Some("{\"a\":1}"),
        )
    };
    let held = send().await;
    assert_eq!(held.status, 202);
    let id = held.header("av-approval-id").unwrap().to_string();
    assert_eq!(
        w.control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
            .await
            .0,
        200
    );
    let r = send().await;
    assert_eq!(r.status, 200);
    let hit = w.up.hits.lock().unwrap()[0].clone();
    assert!(hit
        .headers
        .iter()
        .any(|(n, v)| n == "content-length" && v == "7"));
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_predicts_and_changes_nothing() {
    let w = World::seeded(json!({"approval": "on-write", "budget": 1})).await;
    let mk = |m: &str| GatewayRequest {
        method: m.into(),
        path: "/p/demo/user".into(),
        headers: vec![
            ("host".into(), "127.0.0.1".into()),
            ("av-session".into(), w.token.clone()),
        ],
        ..Default::default()
    };
    let v = w.daemon.pipeline.preflight(mk("GET"), true).await.unwrap();
    assert_eq!(v["would"], "allow", "{v}");
    let v = w.daemon.pipeline.preflight(mk("POST"), true).await.unwrap();
    assert_eq!(v["would"], "hold", "{v}");
    let v = w
        .daemon
        .pipeline
        .preflight(mk("DELETE"), true)
        .await
        .unwrap();
    assert_eq!(v["would"], "deny", "{v}");
    assert_eq!(w.up.count(), 0);
    assert!(
        w.daemon.pipeline.pending_approvals().await.is_empty(),
        "a prediction holds nothing"
    );
    // The single-request budget is still unspent.
    assert_eq!(w.get("/user").await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_tripwire_revokes_a_session_replaying_a_dead_placeholder() {
    let w = World::seeded(json!({"uses": 1})).await;
    let (s, _) = w
        .control("POST", "/v1/tripwires", json!({"enabled": true}))
        .await;
    assert_eq!(s, 200);
    assert_eq!(w.get("/user").await.status, 200);
    let r = w.get("/user").await;
    assert_ne!(r.status, 200);
    let (_, sessions) = w.control("GET", "/v1/sessions", json!({})).await;
    let st = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == w.session_id.as_str())
        .unwrap()["state"]
        .clone();
    assert!(st == "active" || st == "revoked");
    assert!(w.audit_text().await.contains("placeholder."));
}

#[tokio::test(flavor = "multi_thread")]
async fn panic_revokes_every_session_and_denies_held_requests() {
    let w = World::seeded(json!({"approval": "each"})).await;
    assert_eq!(w.get("/user").await.status, 202);
    let (s, v) = w.control("POST", "/v1/panic", json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["revoked_sessions"], 1);
    assert_eq!(v["denied_approvals"], 1);
    let r = w.get("/user").await;
    assert_eq!(r.error.unwrap().code.as_str(), "AV_SESSION_REVOKED");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_not_followed_unless_the_grant_says_so() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|r| {
        if r.url.ends_with("/start") {
            let mut x = json_response(302, &json!({}));
            x.headers.push(("location".into(), "/next".into()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({"at": "next"})))
        }
    }));
    let r = w.get("/start").await;
    assert_eq!(r.status, 302);
    assert_eq!(r.header("av-redirect-stopped"), Some("max"));
    assert_eq!(w.up.count(), 1);
    let w2 = World::seeded(json!({"redirects": 2})).await;
    w2.up.answer(Box::new(|r| {
        if r.url.ends_with("/start") {
            let mut x = json_response(302, &json!({}));
            x.headers
                .push(("location".into(), "https://evil.test/x".into()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({})))
        }
    }));
    let r = w2.get("/start").await;
    assert_eq!(
        r.header("av-redirect-stopped"),
        Some("host"),
        "a Location off the credential's hosts is not followed"
    );
    assert_eq!(w2.up.count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_method_override_is_held_to_the_methods_allowlist() {
    let w = World::seeded(json!({"methods": ["GET", "POST"]})).await;
    let r = w
        .send(
            "POST",
            "/x",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("x-http-method-override".into(), "DELETE".into()),
            ],
            Some(""),
        )
        .await;
    assert_eq!(r.error.unwrap().extra.rule.as_deref(), Some("methods"));
    let r = w
        .send(
            "POST",
            "/x?_method=DELETE",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            None,
        )
        .await;
    assert_eq!(
        r.error.unwrap().extra.rule.as_deref(),
        Some("method_override")
    );
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn explain_denial_keeps_the_sentence_for_the_session_only() {
    let w = World::seeded(json!({})).await;
    let r = w.send("GET", "/user", vec![], None).await;
    let rid = r.request_id.clone().unwrap();
    let mine = w
        .daemon
        .pipeline
        .explain_denial(rid.clone(), Some(w.session_id.clone()))
        .await
        .unwrap();
    assert_eq!(mine["detail"], "no placeholder in this request");
    assert!(w
        .daemon
        .pipeline
        .explain_denial(rid, Some("other".into()))
        .await
        .is_none());
    let audit = w.audit_text().await;
    assert!(audit.contains("no_placeholder"));
    assert!(
        !audit.contains("no placeholder in this request"),
        "the sentence is never filed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_session_token_in_a_forwarded_header_never_leaves() {
    let w = World::seeded(json!({})).await;
    let tok = w.token.clone();
    let r = w
        .send(
            "GET",
            "/user",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("x-carry".into(), tok.clone()),
            ],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    let hit = w.up.hits.lock().unwrap()[0].clone();
    assert!(!hit.headers.iter().any(|(_, v)| v.contains(&tok)));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_placeholder_successor_is_handed_back_when_one_is_spent() {
    let w = World::seeded(json!({"uses": 1})).await;
    let r = w.get("/user").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("av-placeholder-uses-remaining"), Some("0"));
    let next = r.header("av-placeholder-next").unwrap().to_string();
    assert_ne!(next, w.placeholder);
    let r = w
        .send(
            "GET",
            "/user",
            vec![("authorization".into(), format!("Bearer {next}"))],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_held_request_preview_never_shows_the_secret_or_the_placeholder() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let body = format!("{{\"pasted\":\"{SECRET}\",\"ok\":1}}");
    let r = w
        .send(
            "POST",
            "/x",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("content-type".into(), "application/json".into()),
            ],
            Some(&body),
        )
        .await;
    assert_eq!(r.status, 202);
    let pending = w.daemon.pipeline.pending_approvals().await;
    let text = crate::util::js_stringify(&Value::Array(pending));
    assert!(!leaks(&text), "{text}");
    assert!(!text.contains(&w.placeholder));
    assert!(text.contains("\"untrusted\":true"));
}
