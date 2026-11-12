//! Tests for the src/daemon/pipeline.js entries of mutations.toml (the
//! stream scrubber's are in src/sse.rs). Each names the protection (the
//! `what` of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::*;

fn kinds<'a>(rows: &'a [Value], kind: &str) -> Vec<&'a Value> {
    rows.iter().filter(|r| r["kind"] == kind).collect()
}

fn auth(w: &World) -> Vec<(String, String)> {
    vec![("authorization".into(), format!("Bearer {}", w.placeholder))]
}

/// "r6 F1 (Grok): response.streamed records the upstream's own Content-Type".
#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_is_recorded_as_an_event_stream_only() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![(
                "content-type".into(),
                "text/event-stream; zz-agent-chosen=1".into(),
            )],
            body: Body::chunks(vec![Ok(b"data: one\n\n".to_vec())]),
        })
    }));
    let (s, _, _) = body_of(w.get("/stream").await).await;
    assert_eq!(s, 200);
    let rows = w.audit().await;
    let st = kinds(&rows, "response.streamed");
    assert_eq!(st.len(), 1);
    assert_eq!(st[0]["content_type"], "text/event-stream", "{}", st[0]);
}

/// "a held request's reason is recorded unbounded (C28)".
#[tokio::test(flavor = "multi_thread")]
async fn a_held_request_reason_is_bounded() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let mut h = auth(&w);
    h.push(("av-reason".into(), "r".repeat(600)));
    let r = w.send("POST", "/x", h, Some("{}")).await;
    assert_eq!(r.status, 202);
    let (_, held) = w.control("GET", "/v1/approvals", json!({})).await;
    let reason = held[0]["reason"].as_str().unwrap();
    assert!(reason.encode_utf16().count() <= 201, "{}", reason.len());
}

/// 'a refused redirect records the host the upstream named (C28)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_redirect_off_the_hosts_records_no_host() {
    let w = World::seeded(json!({"redirects": 2})).await;
    w.up.answer(Box::new(|_| {
        let mut x = json_response(302, &json!({}));
        x.headers
            .push(("location".into(), "https://zz-agent-host.test/x".into()));
        Ok(x)
    }));
    let r = w.get("/start").await;
    assert_eq!(r.header("av-redirect-stopped"), Some("host"));
    let text = w.audit_text().await;
    assert!(text.contains("request.redirect_returned"));
    assert!(!text.contains("zz-agent-host"), "{text}");
}

/// 'a denial row records the method the agent sent, whatever it is (C28)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_denial_records_an_unknown_method_as_other() {
    let w = World::seeded(json!({})).await;
    let r = w.send("ZZAGENTVERB", "/x", auth(&w), None).await;
    assert!(r.status >= 400);
    let text = w.audit_text().await;
    assert!(!text.contains("ZZAGENTVERB"), "{text}");
    assert!(text.contains("\"method\":\"OTHER\""), "{text}");
}

/// 'the explain-denial sentences are not bounded by count (C28)' and 'an
/// explain-denial sentence is served past its hour (C28)'.
#[tokio::test(flavor = "multi_thread")]
async fn explain_denial_sentences_are_bounded_in_count_and_age() {
    let w = World::seeded(json!({})).await;
    let first = w
        .send("GET", "/user", vec![], None)
        .await
        .request_id
        .unwrap();
    let sid = Some(w.session_id.clone());
    for _ in 0..crate::pipeline::MAX_DENIALS {
        w.send("GET", "/user", vec![], None).await;
    }
    assert!(
        w.daemon
            .pipeline
            .explain_denial(first, sid.clone())
            .await
            .is_none(),
        "the oldest is forgotten past the count"
    );
    let last = w
        .send("GET", "/user", vec![], None)
        .await
        .request_id
        .unwrap();
    assert!(w
        .daemon
        .pipeline
        .explain_denial(last.clone(), sid.clone())
        .await
        .is_some());
    w.shared
        .run(|core| core.pl_age_denials(crate::pipeline::DENIAL_TTL_MS as i64 + 1))
        .await
        .unwrap();
    assert!(
        w.daemon.pipeline.explain_denial(last, sid).await.is_none(),
        "not past its hour"
    );
}

fn approval_id(r: &crate::pipeline::GatewayResponse) -> String {
    let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    v["approval_id"].as_str().unwrap_or("").to_string()
}

/// A credential `two` whose one field may sit in the `x-key` header or the
/// JSON body's `/token`, and a session over it: `(token, placeholder, grant)`.
async fn two_sites(w: &World, session: Value) -> (String, String, String) {
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "two", "kind": "http", "host": "two.example.test", "value": "two-secret-0123456789abcdef", "sites": ["header:x-key", "json:/token"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let mut spec = json!({"cred": "two", "label": "two", "methods": ["GET", "POST"], "paths": ["/**"], "ttl_hours": 1});
    for (k, x) in session.as_object().unwrap() {
        spec[k] = x.clone();
    }
    let (s, v) = w.control("POST", "/v1/sessions", spec).await;
    assert_eq!(s, 200, "{v}");
    (
        v["token"].as_str().unwrap().into(),
        v["placeholder"].as_str().unwrap().into(),
        v["grant_id"].as_str().unwrap().into(),
    )
}

async fn send_two(
    w: &World,
    token: &str,
    header: &str,
    body_token: &str,
) -> crate::pipeline::GatewayResponse {
    send_two_as(w, "POST", token, header, body_token).await
}

async fn send_two_as(
    w: &World,
    method: &str,
    token: &str,
    header: &str,
    body_token: &str,
) -> crate::pipeline::GatewayResponse {
    w.daemon
        .pipeline
        .handle(crate::pipeline::GatewayRequest {
            method: method.into(),
            path: "/p/two/x".into(),
            query: String::new(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), token.into()),
                ("content-type".into(), "application/json".into()),
                ("x-key".into(), header.into()),
            ],
            body: Some(crate::util::js_stringify(&json!({"token": body_token})).into_bytes()),
            listener: None,
        })
        .await
}

/// "a request carrying the hash marker's text literally collides with one
/// carrying the placeholder".
#[tokio::test(flavor = "multi_thread")]
async fn literal_marker_text_cannot_make_two_requests_hash_alike() {
    let w = World::seeded(json!({})).await;
    let (token, ph, grant) = two_sites(&w, json!({"approval": "each"})).await;
    let marker = format!("<av:{grant}:token>");
    let a = send_two(&w, &token, &ph, &marker).await;
    assert_eq!(a.status, 202);
    let (s, v) = w
        .control(
            "POST",
            "/v1/approvals",
            json!({"id": approval_id(&a), "granted": true}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let b = send_two(&w, &token, &marker, &ph).await;
    assert_eq!(b.status, 202, "B is not the request the human approved");
    assert_eq!(w.up.count(), 0);
}

/// 'a pre-connect failure refunds only the last placeholder'.
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_connect_failure_refunds_every_placeholder_it_spent() {
    let w = World::seeded(json!({})).await;
    let (token, _, _) = two_sites(&w, json!({})).await;
    let sid = w
        .shared
        .run({
            let t = token.clone();
            move |c| c.vault.session_by_token(&t).unwrap().unwrap().id
        })
        .await
        .unwrap();
    let mut ps = Vec::new();
    for _ in 0..2 {
        let (s, v) = w
            .control(
                "POST",
                "/v1/placeholders",
                json!({"cred": "two", "sid": sid, "uses": 1}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        ps.push(v["placeholder"].as_str().unwrap().to_string());
    }
    let (p1, p2) = (ps[0].clone(), ps[1].clone());
    w.up.answer(Box::new(|_| {
        Err(UpstreamError::new(
            "ECONNREFUSED",
            "connect ECONNREFUSED 127.0.0.1:1",
        ))
    }));
    let r = send_two_as(&w, "GET", &token, &p1, &p2).await;
    assert!(r.status >= 500, "{}", r.status);
    let live = w
        .shared
        .run(move |c| {
            c.vault
                .list_placeholders(Some(&sid))
                .unwrap()
                .into_iter()
                .filter(|p| p.state == av_store::model::PlaceholderState::Active)
                .count()
        })
        .await
        .unwrap();
    assert_eq!(live, 3, "both one-use placeholders were refunded");
}

/// 'a method-override header escapes the approval rule'.
#[tokio::test(flavor = "multi_thread")]
async fn a_method_override_to_a_write_is_held_for_a_human() {
    let w = World::seeded(json!({})).await;
    let mut h = auth(&w);
    h.push(("x-http-method-override".into(), "POST".into()));
    let r = w.send("GET", "/x", h, None).await;
    assert_eq!(r.status, 202, "on-write holds an override to POST");
    assert_eq!(w.up.count(), 0);
}

/// 'a spent approval with nothing to replay holds its resend forever'.
#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_approval_once_run_starts_a_new_question() {
    let w = World::seeded(json!({"approval": "each"})).await;
    w.up.answer(Box::new(|_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: Body::chunks(vec![Ok(b"data: one\n\n".to_vec())]),
        })
    }));
    let first = w.get("/s").await;
    assert_eq!(first.status, 202);
    let id = approval_id(&first);
    let (s, v) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, _, _) = body_of(w.get("/s").await).await;
    assert_eq!(s, 200);
    let again = w.get("/s").await;
    assert_eq!(again.status, 202);
    assert_ne!(approval_id(&again), id, "a new question, not the spent one");
}

/// 'a case-folded secret in a response header name reaches the agent'.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_header_named_by_the_secret_in_any_case_is_dropped() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        let mut r = json_response(200, &json!({}));
        r.headers.push((SECRET.to_uppercase(), "1".into()));
        Ok(r)
    }));
    let r = w.get("/x").await;
    assert_eq!(r.status, 200);
    assert!(
        !r.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(SECRET)),
        "{:?}",
        r.headers
    );
}

/// "an event stream's source is piped without its errors".
#[tokio::test(flavor = "multi_thread")]
async fn an_event_stream_that_fails_part_way_is_cut() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: Body::chunks(vec![Ok(b"data: one\n\n".to_vec()), Err("reset".into())]),
        })
    }));
    let (s, body, _) = body_of(w.get("/s").await).await;
    assert_eq!(s, 200);
    assert!(
        body.contains("AV_UNSCANNABLE"),
        "the failure is said: {body}"
    );
}

/// 'a forged placeholder touches the session it names'.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_placeholder_is_refused_as_malformed() {
    let w = World::seeded(json!({})).await;
    let mut forged = w.placeholder.clone();
    let last = forged.pop().unwrap();
    forged.push(if last == 'a' { 'b' } else { 'a' });
    let r = w
        .daemon
        .pipeline
        .handle(crate::pipeline::GatewayRequest {
            method: "GET".into(),
            path: "/p/demo/user".into(),
            query: String::new(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("authorization".into(), format!("Bearer {forged}")),
            ],
            body: None,
            listener: None,
        })
        .await;
    assert_eq!(
        r.error.map(|e| e.code),
        Some(crate::err::C::PhMalformed),
        "refused on its checksum before anything is looked up"
    );
}

/// '/t/https/ to an http credential goes out in the clear'.
#[tokio::test(flavor = "multi_thread")]
async fn a_t_https_route_to_an_http_credential_goes_out_over_https() {
    let w = World::bare().await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials",
            json!({"slug": "plain", "kind": "http", "host": "plain.example.test", "scheme": "http", "value": SECRET, "sites": ["header:authorization:Bearer"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "plain", "methods": ["GET"], "ttl_hours": 1}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let r = w
        .daemon
        .pipeline
        .handle(crate::pipeline::GatewayRequest {
            method: "GET".into(),
            path: "/t/https/plain.example.test/x".into(),
            query: String::new(),
            headers: vec![
                ("host".into(), "127.0.0.1".into()),
                ("av-session".into(), v["token"].as_str().unwrap().into()),
                (
                    "authorization".into(),
                    format!("Bearer {}", v["placeholder"].as_str().unwrap()),
                ),
            ],
            body: None,
            listener: None,
        })
        .await;
    assert_eq!(r.status, 200, "{:?}", r.error);
    let url = w.up.hits.lock().unwrap()[0].url.clone();
    assert!(url.starts_with("https://plain.example.test/"), "{url}");
}
