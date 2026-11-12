//! Tests written for specific entries of mutations.toml: each names the
//! protection (the `what` of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::*;

const PASS: &str = "test-passphrase-123";

async fn gated() -> World {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("POST", "/v1/passphrase", json!({"passphrase": PASS})).await;
    assert_eq!(s, 200, "{v}");
    w
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_the_placeholder_checksum_is_checked() {
    let w = World::seeded(json!({})).await;
    let mut forged = w.placeholder.clone();
    let last = forged.pop().unwrap();
    forged.push(if last == 'a' { 'b' } else { 'a' });
    let r = w.send("GET", "/user", vec![("authorization".into(), format!("Bearer {forged}"))], None).await;
    assert_eq!(r.error.unwrap().code.as_str(), "AV_PH_MALFORMED");
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_error_details_reach_the_agent_scrubbed() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| Err(UpstreamError::new("ECONNRESET", format!("socket said {SECRET}")))));
    let r = w.get("/user").await;
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert!(body.contains("could not reach"), "{body}");
    assert!(!leaks(&body), "{body}");
    assert!(!leaks(&w.audit_text().await));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_resend_may_not_change_the_bytes_the_human_approved() {
    let w = World::seeded(json!({})).await;
    let post = |b: &'static str| w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder)), ("content-type".into(), "application/json".into())], Some(b));
    let held = post("{\"amount\":1}").await;
    let id = held.header("av-approval-id").unwrap().to_string();
    assert_eq!(w.control("POST", "/v1/approvals", json!({"id": id, "granted": true})).await.0, 200);
    let other = post("{\"amount\":9999}").await;
    assert_eq!(other.status, 202, "other bytes are another request");
    assert_eq!(w.up.count(), 0);
    assert_eq!(post("{\"amount\":1}").await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_survives_a_fresh_placeholder_on_the_resend() {
    let w = World::seeded(json!({})).await;
    let held = w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], Some("{}")).await;
    let id = held.header("av-approval-id").unwrap().to_string();
    assert_eq!(w.control("POST", "/v1/approvals", json!({"id": id, "granted": true})).await.0, 200);
    let (_, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    let fresh = v["placeholder"].as_str().unwrap().to_string();
    let r = w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {fresh}"))], Some("{}")).await;
    assert_eq!(r.status, 200, "the approval binds the capability, not which placeholder carried it");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denial_is_filed_with_the_session_it_refused_and_a_held_request_as_held() {
    let w = World::seeded(json!({})).await;
    w.send("GET", "/user", vec![], None).await;
    w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], Some("{}")).await;
    let rows = w.audit().await;
    let denied = rows.iter().find(|r| r["reason_code"] == "AV_SESSION_REQUIRED").unwrap();
    assert_eq!(denied["session_id"], json!(w.session_id));
    assert_eq!(denied["req"]["method"], "GET");
    let held = rows.iter().find(|r| r["kind"] == "request.allowed" && r["req"]["status"] == 202).unwrap();
    assert_eq!(held["decision"], "held");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_the_mcp_handshake_works_without_a_session_over_http() {
    let w = World::seeded(json!({})).await;
    let body = crate::util::js_stringify(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}));
    let inc = crate::server::Incoming { method: "POST".into(), target: "/mcp".into(), headers: vec![("host".into(), "127.0.0.1".into())], body: body.into_bytes() };
    let r = w.daemon.on_gateway(inc, None, None).await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("mcp-session-id").is_some());
    let inc = crate::server::Incoming { method: "POST".into(), target: "/mcp".into(), headers: vec![("origin".into(), "https://evil.test".into())], body: b"{}".to_vec() };
    assert_eq!(w.daemon.on_gateway(inc, None, None).await.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_every_answer_a_human_gives_needs_the_human() {
    let w = gated().await;
    // Hold one write and open one session request.
    let held = w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], Some("{}")).await;
    let aid = held.header("av-approval-id").unwrap().to_string();
    let (_, req) = w.control("POST", "/v1/session-requests", json!({"cred": "demo"})).await;
    let rid = req["id"].as_str().unwrap().to_string();
    for (path, body) in [
        ("/v1/approvals", json!({"id": aid, "granted": false})),
        ("/v1/approvals", json!({"id": aid, "granted": true})),
        ("/v1/session-requests/decide", json!({"id": rid, "granted": true})),
        ("/v1/pending/decide-many", json!({"decisions": [{"id": aid, "kind": "request", "granted": true}]})),
        ("/v1/placeholders/batch", json!({"sid": w.session_id, "items": [{"cred": "demo"}]})),
    ] {
        let (s, v) = w.control("POST", path, body.clone()).await;
        assert_eq!((s, v["code"].as_str()), (401, Some("AV_PRESENCE_REQUIRED")), "{path} {body}");
    }
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approved_session_request_is_made_from_what_was_approved() {
    let w = World::seeded(json!({})).await;
    let (_, req) = w.control("POST", "/v1/session-requests", json!({"cred": "demo", "budget": 30})).await;
    let id = req["id"].as_str().unwrap().to_string();
    let (_, v) = w.control("POST", "/v1/session-requests/decide", json!({"id": id, "granted": true, "overrides": {"budget": 2}})).await;
    let sid = v["session"]["session_id"].as_str().unwrap().to_string();
    let (_, d) = w.control("GET", &format!("/v1/sessions/detail?sid={sid}"), json!({})).await;
    assert_eq!(d["grants"][0]["budget"]["limit"], 2, "{d}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rolling_quota_refuses_the_request_that_would_pass_it() {
    let w = World::seeded(json!({"quota": {"count": 1, "window": "hour"}})).await;
    assert_eq!(w.get("/user").await.status, 200);
    let r = w.get("/user").await;
    let e = r.error.unwrap();
    assert_eq!((e.code.as_str(), e.extra.rule.as_deref()), ("AV_QUOTA_EXCEEDED", Some("quota")));
    assert_eq!(w.up.count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_parameter_name_servers_read_differently_is_refused() {
    let w = World::seeded(json!({})).await;
    let r = w.send("GET", "/user?[force]=1", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], None).await;
    assert_eq!(r.error.unwrap().extra.rule.as_deref(), Some("request_ambiguous"));
    assert_eq!(w.up.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_buffered_upstream_reset_mid_body_is_an_unreachable_upstream() {
    let w = World::seeded(json!({})).await;
    w.up.answer(Box::new(|_| {
        Ok(UpstreamResponse { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: crate::upstream::Body::chunks(vec![Ok(b"{\"a\":".to_vec()), Err("reset".into())]) })
    }));
    let e = w.get("/user").await.error.unwrap();
    assert_eq!((e.code.as_str(), e.extra.refunded), ("AV_UPSTREAM_UNREACHABLE", Some(false)));
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_touches_no_session_and_the_status_tool_shows_no_preview() {
    let w = World::seeded(json!({})).await;
    let shared = w.shared.clone();
    let sid = w.session_id.clone();
    let seen = move || {
        let (shared, sid) = (shared.clone(), sid.clone());
        async move { shared.run(move |c| c.vault.session(&sid).unwrap().unwrap().last_seen_at).await }
    };
    let before = seen().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let req = GatewayRequest { method: "GET".into(), path: "/p/demo/user".into(), headers: vec![("host".into(), "127.0.0.1".into()), ("av-session".into(), w.token.clone())], ..Default::default() };
    w.daemon.pipeline.preflight(req, true).await.unwrap();
    assert_eq!(seen().await.unwrap(), before);
    let held = w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], Some("{}")).await;
    let id = held.header("av-approval-id").unwrap().to_string();
    let st: Value = w.daemon.pipeline.approval_status(id).await.unwrap();
    assert!(st.get("preview").is_none(), "{st}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_allow_cidr_is_enforced_on_the_raw_connection() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("POST", "/v1/listeners", json!({"id": "far", "address": "127.0.0.1:0", "surfaces": ["gateway"], "allow_cidr": ["10.0.0.0/8"]})).await;
    assert_eq!(s, 200, "{v}");
    let rec: av_store::model::ListenerRecord = serde_json::from_value(v).unwrap();
    let (_, port) = w.daemon.bind_listener(&rec).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _ = s.write_all(b"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    assert!(out.is_empty(), "a peer outside the list gets nothing: {}", String::from_utf8_lossy(&out));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(w.audit_text().await.contains("listen.peer_refused"));
}
