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
