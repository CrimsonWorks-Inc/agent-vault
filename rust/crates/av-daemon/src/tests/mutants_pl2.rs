//! More tests for the src/daemon/pipeline.js entries of mutations.toml:
//! budgets, concurrency, redirects, tripwires, quarantine, grant liveness and
//! spend. Each names the protection (the `what` of test/mutation-check.js) it
//! holds.

use serde_json::{json, Value};

use super::*;

const PASS: &str = "test-passphrase-123";

fn auth(ph: &str) -> Vec<(String, String)> {
    vec![("authorization".into(), format!("Bearer {ph}"))]
}

/// `demo` and a session over it on `w` (as `World::seeded` does).
async fn seed(w: &mut World, session: Value) {
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "demo", "kind": "http", "host": "api.example.test", "value": SECRET, "sites": ["header:authorization:Bearer"]})).await;
    assert_eq!(s, 200, "{v}");
    seed_session(w, session).await;
}

async fn seed_session(w: &mut World, session: Value) {
    let mut spec = json!({"cred": "demo", "label": "test", "methods": ["GET", "POST"], "paths": ["/**"], "budget": 40, "approval": "on-write", "ttl_hours": 1});
    for (k, x) in session.as_object().unwrap() {
        spec[k] = x.clone();
    }
    let (s, v) = w.control("POST", "/v1/sessions", spec).await;
    assert_eq!(s, 200, "{v}");
    w.slug = "demo".into();
    w.token = v["token"].as_str().unwrap().into();
    w.placeholder = v["placeholder"].as_str().unwrap().into();
    w.session_id = v["session_id"].as_str().unwrap().into();
}

/// A session with `extra` that needs fresh presence: made with a passphrase.
async fn elevated(extra: Value) -> World {
    let mut w = World::bare().await;
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "demo", "kind": "http", "host": "api.example.test", "value": SECRET, "sites": ["header:authorization:Bearer"]})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let mut x = extra;
    x["presence"] = json!({"passphrase": PASS});
    seed_session(&mut w, x).await;
    w
}

fn sql(w: &World, stmt: &str) {
    let c = rusqlite::Connection::open(w._dir.path().join("vault.db")).unwrap();
    c.execute_batch(stmt).unwrap();
}

/// 'a response too nested to finish scanning is forwarded instead of
/// refused'.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_past_the_decode_budget_is_refused() {
    let mut w = World::bare_opts(Default::default(), Some((None, Some(4)))).await;
    seed(&mut w, json!({})).await;
    let b64 = crate::util::b64(SECRET.as_bytes());
    let raw = crate::util::encode_uri_component(&b64).replace('%', "\\u0025");
    let body = format!("{{\"echo\":\"{raw}\"}}");
    w.up.answer(Box::new(move |_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Body::Full(body.clone().into_bytes()),
        })
    }));
    let (s, text, _) = body_of(w.get("/x").await).await;
    assert_eq!(s, 502, "{text}");
    assert!(
        text.contains("AV_UNSCANNABLE") && !text.contains(&raw),
        "{text}"
    );
}

/// 'a concurrency slot is released only when the upstream answered'.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_request_gives_its_concurrency_slot_back() {
    let w = World::seeded(json!({"max_concurrent": 1})).await;
    w.up.answer(Box::new(|_| {
        Err(UpstreamError::new("ECONNREFUSED", "connect ECONNREFUSED"))
    }));
    for _ in 0..3 {
        let r = w.get("/x").await;
        assert_eq!(r.status, 502, "{:?}", r.error);
    }
    assert_eq!(w.up.count(), 3, "each one reached the upstream");
}

/// 'a stored scrub pattern that no longer compiles is skipped instead of
/// withholding the response'.
#[tokio::test(flavor = "multi_thread")]
async fn a_stored_pattern_that_does_not_compile_withholds_the_response() {
    let w = World::seeded(json!({})).await;
    sql(
        &w,
        r#"UPDATE credentials SET scrub_patterns = '[{"id":"sp_bad","source":"(unclosed","added_at":"2026-01-01T00:00:00.000Z"}]'"#,
    );
    let (s, text, _) = body_of(w.get("/x").await).await;
    assert!(
        s >= 500 && text.contains("scrub_pattern_invalid"),
        "{s} {text}"
    );
}

/// 'redirects are followed for every method' and 'a request a method
/// override made a DELETE has its redirect followed'.
#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_followed_only_for_a_read() {
    let w =
        elevated(json!({"redirects": 2, "approval": "auto", "methods": ["GET", "POST", "DELETE"]}))
            .await;
    w.up.answer(Box::new(|r| {
        if r.url.ends_with("/start") {
            let mut x = json_response(302, &json!({}));
            x.headers.push(("location".into(), "/next".into()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({"at": "next"})))
        }
    }));
    let r = w
        .send("POST", "/start", auth(&w.placeholder), Some("{}"))
        .await;
    assert_eq!(r.status, 302, "a POST's redirect is handed back");
    let mut h = auth(&w.placeholder);
    h.push(("x-http-method-override".into(), "DELETE".into()));
    let r = w.send("GET", "/start", h, None).await;
    assert_eq!(r.status, 302, "an override to DELETE is not a read");
    assert_eq!(w.up.count(), 2, "neither hop was followed");
    let r = w.get("/start").await;
    assert_eq!(r.status, 200, "a plain GET is followed");
}

/// 'a redirect may choose another port on an allowed host'.
#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_to_another_port_is_not_followed() {
    let w = World::seeded(json!({"redirects": 2})).await;
    w.up.answer(Box::new(|r| {
        if r.url.ends_with("/start") {
            let mut x = json_response(302, &json!({}));
            x.headers
                .push(("location".into(), "https://api.example.test:8443/x".into()));
            Ok(x)
        } else {
            Ok(json_response(200, &json!({})))
        }
    }));
    let r = w.get("/start").await;
    assert_eq!(r.header("av-redirect-stopped"), Some("host"));
    assert_eq!(w.up.count(), 1);
}

async fn tripwire(w: &World, code: &str) {
    let (s, v) = w
        .control(
            "POST",
            "/v1/tripwires",
            json!({"enabled": true, "rules": [{"id": "t", "codes": [code], "threshold": 1, "window_s": 600, "action": "revoke_session"}]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
}

/// 'a tripwire counts a denial against the session its placeholder names,
/// before authentication'.
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_denial_trips_nothing_against_the_named_session() {
    let w = World::seeded(json!({})).await;
    tripwire(&w, "AV_SESSION_REQUIRED").await;
    let r = w
        .daemon
        .pipeline
        .handle(crate::pipeline::GatewayRequest {
            method: "GET".into(),
            path: format!("/p/demo/{}", w.placeholder),
            query: String::new(),
            headers: vec![("host".into(), "127.0.0.1".into())],
            body: None,
            listener: None,
        })
        .await;
    assert!(r.status >= 400);
    assert_eq!(
        w.get("/user").await.status,
        200,
        "the named session is untouched"
    );
}

/// 'a preflight denial is fed to the tripwires'.
#[tokio::test(flavor = "multi_thread")]
async fn a_preflight_denial_trips_nothing() {
    let w = World::seeded(json!({})).await;
    tripwire(&w, "AV_POLICY_DENIED").await;
    let v = w
        .daemon
        .pipeline
        .preflight(
            crate::pipeline::GatewayRequest {
                method: "DELETE".into(),
                path: "/p/demo/x".into(),
                query: String::new(),
                headers: vec![
                    ("host".into(), "127.0.0.1".into()),
                    ("av-session".into(), w.token.clone()),
                ],
                body: None,
                listener: None,
            },
            true,
        )
        .await
        .unwrap();
    assert_eq!(v["would"], "deny", "{v}");
    assert_eq!(w.get("/user").await.status, 200, "the session is untouched");
}

/// 'a quarantined credential is not refused before its use is spent'.
#[tokio::test(flavor = "multi_thread")]
async fn a_quarantined_credential_is_refused_before_a_use_is_spent() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/quarantine",
            json!({"slug": "demo", "reason": "test"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let sid = w.session_id.clone();
    let uses = |w: &World| {
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
    let before = uses(&w).await;
    let r = w.get("/user").await;
    assert_eq!(
        r.error.map(|e| e.code.as_str().to_string()).as_deref(),
        Some("AV_QUARANTINED")
    );
    assert_eq!(uses(&w).await, before, "no use was spent");
}

/// 'the gateway does not ask the store whether the grant is still live'.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_grant_is_refused_at_the_gateway() {
    let w = World::seeded(json!({})).await;
    sql(
        &w,
        "UPDATE grants SET expires_at = '2020-01-01T00:00:00.000Z'",
    );
    let r = w.get("/user").await;
    assert!(r.status >= 400, "{:?}", r.error);
    assert_eq!(w.up.count(), 0);
}

/// 'the spend check ignores what calls in flight have reserved'.
#[tokio::test(flavor = "multi_thread")]
async fn the_spend_check_counts_what_calls_in_flight_reserved() {
    let mut w = World::bare().await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "ant", "kind": "openai", "value": SECRET}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "ant", "methods": ["GET", "POST"], "paths": ["/**"], "approval": "on-write", "ttl_hours": 1, "spend_tokens": 5000}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    w.slug = "ant".into();
    w.token = v["token"].as_str().unwrap().into();
    w.placeholder = v["placeholder"].as_str().unwrap().into();
    let gid = v["grant_id"].as_str().unwrap().to_string();
    let usage = v["usage"][0].as_str().unwrap_or("").to_string();
    let (name, value) = usage.split_once(": ").unwrap_or(("x-api-key", ""));
    let h = vec![
        (name.to_string(), value.to_string()),
        ("content-type".into(), "application/json".into()),
    ];
    let body = r#"{"model":"gpt-x","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}"#;
    // Control: nothing reserved, the call is admitted (to the human).
    let r = w
        .send("POST", "/v1/chat/completions", h.clone(), Some(body))
        .await;
    assert!(r.status == 202 || r.status == 200, "{:?}", r.error);
    w.shared
        .run(move |c| {
            c.vault
                .set_grant_runtime(
                    &gid,
                    &av_store::model::GrantRuntime {
                        quota_state: None,
                        spend: Some(json!({"tokens_used": 0, "usd_micros_used": 0, "reserved": {"rq_in_flight": {"tokens": 4500, "usd_micros": 0, "at": crate::util::now_ms()}}})),
                    },
                )
                .unwrap()
        })
        .await
        .unwrap();
    let r = w.send("POST", "/v1/chat/completions", h, Some(body)).await;
    assert_eq!(r.status, 403, "{:?}", r.error);
    assert_eq!(r.error.and_then(|e| e.extra.rule).as_deref(), Some("spend"));
}

/// The secret injected into a request, echoed by the upstream, comes back
/// as the placeholder the agent sent (response.test.js:94, :181, :212);
/// another stored secret gets the generic marker. Buffered, gzip, and an
/// event stream with the secret split across chunks.
#[tokio::test(flavor = "multi_thread")]
async fn an_echoed_injected_secret_comes_back_as_its_placeholder() {
    use std::io::Write;
    let gz = |s: &str| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(s.as_bytes()).unwrap();
        e.finish().unwrap()
    };
    let w = World::seeded(json!({})).await;
    let other = "another-stored-secret-0123456789abcdef";
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "other", "kind": "http", "host": "other.example.test", "value": other, "sites": ["header:authorization:Bearer"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let plain = format!("{{\"echo\":\"{SECRET}\",\"other\":\"{other}\"}}");
    let (a, b) = SECRET.split_at(SECRET.len() / 2);
    type Case = (Vec<(String, String)>, Vec<Vec<u8>>);
    let cases: Vec<Case> = vec![
        (
            vec![("content-type".into(), "application/json".into())],
            vec![plain.clone().into_bytes()],
        ),
        (
            vec![
                ("content-type".into(), "application/json".into()),
                ("content-encoding".into(), "gzip".into()),
            ],
            vec![gz(&format!("{plain}{}", " ".repeat(400)))],
        ),
        (
            vec![("content-type".into(), "text/event-stream".into())],
            vec![
                format!("data: {a}").into_bytes(),
                format!("{b}\n\ndata: {other}\n\n").into_bytes(),
            ],
        ),
        (
            vec![
                ("content-type".into(), "text/event-stream".into()),
                ("content-encoding".into(), "gzip".into()),
            ],
            vec![gz(&format!(
                "data: {SECRET}\n\ndata: {other}\n\n{}",
                "data: ordinary\n\n".repeat(64)
            ))],
        ),
    ];
    for (headers, chunks) in cases {
        let (h, c) = (headers.clone(), chunks.clone());
        w.up.answer(Box::new(move |_| {
            Ok(UpstreamResponse {
                status: 200,
                headers: h.clone(),
                body: Body::chunks(c.iter().cloned().map(Ok).collect()),
            })
        }));
        let (s, text, _) = body_of(w.get("/x").await).await;
        assert_eq!(s, 200, "{headers:?}: {text}");
        assert!(
            !leaks(&text) && !text.contains(other),
            "{headers:?}: {text}"
        );
        assert!(text.contains(&w.placeholder), "{headers:?}: {text}");
        assert!(
            text.contains("[[av:redacted:other]]"),
            "{headers:?}: {text}"
        );
    }
}

fn sse_stream(events: usize) -> UpstreamResponse {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        for i in 0..events {
            if tx
                .send(Ok(format!("data: event-{i}\n\n").into_bytes()))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())],
        body: Body::Stream(rx),
    }
}

/// Many event streams whose agents do not read never stall the daemon: the
/// SSE pump waits without blocking a runtime thread, so the control API
/// still answers on a two-thread runtime.
#[test]
fn slow_event_stream_readers_never_stall_the_daemon() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let w = World::seeded(json!({"budget": 1000})).await;
        w.up.answer(Box::new(|_| Ok(sse_stream(500))));
        let mut held = Vec::new();
        for _ in 0..60 {
            held.push(w.get("/s").await);
        }
        assert!(held.iter().all(|r| r.status == 200));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            w.control("GET", "/v1/sessions", json!({})),
        )
        .await;
        assert!(
            answered.is_ok(),
            "the control API answered while 60 streams waited"
        );
        drop(held);
    });
}

/// Every event of a long stream is delivered, and output starts before a
/// quarter of them were sent (response.test.js:218), on a current-thread
/// runtime.
#[test]
fn a_long_event_stream_starts_early_and_delivers_every_event() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let w = World::seeded(json!({})).await;
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let s2 = sent.clone();
        w.up.answer(Box::new(move |_| {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            let s3 = s2.clone();
            tokio::spawn(async move {
                for i in 0..200 {
                    if tx
                        .send(Ok(format!("data: e{i}\n\n").into_bytes()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    s3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
                body: Body::Stream(rx),
            })
        }));
        let mut r = w.get("/s").await;
        let mut rx = r.stream.take().expect("streamed");
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("output started")
            .unwrap();
        assert!(!first.is_empty());
        assert!(
            sent.load(std::sync::atomic::Ordering::SeqCst) < 50,
            "output started before a quarter of the events were sent"
        );
        let mut text = String::from_utf8_lossy(&first).into_owned();
        while let Ok(Some(c)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv()).await
        {
            text.push_str(&String::from_utf8_lossy(&c));
        }
        for i in 0..200 {
            assert!(
                text.contains(&format!("data: e{i}\n\n")),
                "event {i} missing"
            );
        }
    });
}
