//! The control API: session planning and its refusals, session requests,
//! bulk decisions, placeholder issue, listeners, narrowing, templates,
//! tripwires, audit paging. Ports the internal parts of
//! test/security/control-api-*.test.js, session-requests.test.js,
//! fix-control-*.test.js and requested-*.test.js (see PORTED.md).

use serde_json::{json, Value};

use super::*;

async fn refusal(w: &World, method: &str, path: &str, body: Value) -> (u16, String, String) {
    let (s, v) = w.control(method, path, body).await;
    (s, v["code"].as_str().unwrap_or("").to_string(), v["rule"].as_str().unwrap_or("").to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_plans_refuse_every_unreadable_shape_before_anything_is_made() {
    let w = World::seeded(json!({})).await;
    let cases = vec![
        (json!({"cred": "demo", "grants": [{"cred": "demo"}]}), "session_shape"),
        (json!({"grants": [{"cred": "demo"}, {"cred": "demo"}]}), "session_shape"),
        (json!({"cred": "demo", "approval": "sometimes"}), "approval"),
        (json!({"cred": "demo", "budget": 0}), "budget"),
        (json!({"cred": "demo", "budget": "1.5"}), "policy_invalid"),
        (json!({"cred": "demo", "ttl_hours": 0}), "ttl"),
        (json!({"cred": "demo", "ttl_hours": -1}), "ttl"),
        (json!({"cred": "demo", "infinite": true, "remote": true}), "infinite_remote"),
        (json!({"cred": "demo", "grant_ttl_minutes": 1.5}), "grant_ttl"),
        (json!({"cred": "demo", "methods": "GET"}), "policy_invalid"),
    ];
    let (_, before) = w.control("GET", "/v1/sessions", json!({})).await;
    for (body, rule) in cases {
        let (s, _, r) = refusal(&w, "POST", "/v1/sessions", body.clone()).await;
        assert!(s >= 400, "{body}");
        assert_eq!(r, rule, "{body}");
    }
    let (_, after) = w.control("GET", "/v1/sessions", json!({})).await;
    assert_eq!(before.as_array().unwrap().len(), after.as_array().unwrap().len(), "a refused plan makes no session");
    // Control: an ordinary body is made.
    let (s, v) = w.control("POST", "/v1/sessions", json!({"cred": "demo", "methods": ["GET"]})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["token"].as_str().unwrap().starts_with("avs1."));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_an_elevated_session_needs_a_factor_and_the_list_reports_its_elevation() {
    let w = World::seeded(json!({})).await;
    let (s, code, rule) = refusal(&w, "POST", "/v1/sessions", json!({"cred": "demo", "approval": "auto", "methods": ["GET", "POST"]})).await;
    assert_eq!((s, code.as_str(), rule.as_str()), (401, "AV_PRESENCE_REQUIRED", "factor_required"));
    let (s, _, rule) = refusal(&w, "POST", "/v1/sessions", json!({"cred": "demo", "approval": "first-use", "methods": ["DELETE"]})).await;
    assert_eq!((s, rule.as_str()), (401, "factor_required"), "first-use with a write is elevated (C26)");
    let (_, list) = w.control("GET", "/v1/sessions", json!({})).await;
    assert_eq!(list[0]["elevated"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_quarantined_credential_gets_no_session_and_no_batch_placeholder() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("POST", "/v1/credentials/quarantine", json!({"slug": "demo", "reason": "test"})).await;
    assert_eq!(s, 200, "{v}");
    let (_, code, _) = refusal(&w, "POST", "/v1/sessions", json!({"cred": "demo"})).await;
    assert_eq!(code, "AV_QUARANTINED");
    let (_, code, _) = refusal(&w, "POST", "/v1/placeholders/batch", json!({"sid": w.session_id, "items": [{"cred": "demo"}]})).await;
    assert_eq!(code, "AV_QUARANTINED");
    let r = w.get("/user").await;
    assert_eq!(r.error.unwrap().code.as_str(), "AV_QUARANTINED");
    assert_eq!(w.up.count(), 0);
    let (s, _) = w.control("POST", "/v1/credentials/release", json!({"slug": "demo"})).await;
    assert_eq!(s, 200);
    assert_eq!(w.get("/user").await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_requests_create_nothing_until_a_human_answers_and_only_the_asker_collects() {
    let w = World::seeded(json!({})).await;
    let (s, asked) = w.control("POST", "/v1/session-requests", json!({"cred": "demo", "methods": ["GET"], "reason": "need it"})).await;
    assert_eq!(s, 200, "{asked}");
    let id = asked["id"].as_str().unwrap().to_string();
    let secret = asked["collect_secret"].as_str().unwrap().to_string();
    let (_, list) = w.control("GET", "/v1/sessions", json!({})).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "asking made no session");
    let (s, v) = w.control("GET", &format!("/v1/session-requests/collect?id={id}&secret=wrong"), json!({})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("collect_secret")));
    let (_, v) = w.control("GET", &format!("/v1/session-requests/collect?id={id}&secret={secret}"), json!({})).await;
    assert_eq!(v["state"], "pending");
    let (s, v) = w.control("POST", "/v1/session-requests/decide", json!({"id": id, "granted": "true"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("bulk_decision")), "a string is not a verdict");
    let (s, v) = w.control("POST", "/v1/session-requests/decide", json!({"id": id, "granted": true, "overrides": {"hosts": ["x"]}})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("session_overrides")), "a narrowing nothing reads is refused");
    let (s, v) = w.control("POST", "/v1/session-requests/decide", json!({"id": id, "granted": true, "overrides": {"budget": 3}})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["session"]["token"].as_str().unwrap().starts_with("avs1."), "the approving client collects");
    assert_eq!(v["granted"]["budget"], 3);
    let (_, v) = w.control("GET", &format!("/v1/session-requests/collect?id={id}&secret={secret}"), json!({})).await;
    assert!(v.get("token").is_none(), "collected once: {v}");
    let audit = w.audit_text().await;
    assert!(!audit.contains("need it"), "the agent's words are not filed (C25)");
    assert!(audit.contains("session_request.approved"));
    assert!(audit.contains("\"narrowed\":[\"budget\"]"), "{audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_session_request_cannot_carry_an_owner_field() {
    let w = World::seeded(json!({})).await;
    for f in ["approval", "infinite"] {
        let mut body = json!({"cred": "demo"});
        body[f] = if f == "infinite" { json!(true) } else { json!("auto") };
        let (s, _, rule) = refusal(&w, "POST", "/v1/session-requests", body).await;
        assert_eq!((s, rule.as_str()), (403, "owner_only_field"));
    }
    let (s, _, _) = refusal(&w, "POST", "/v1/session-requests", json!({"cred": "nope"})).await;
    assert_eq!(s, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_bulk_decisions_log_only_ids_the_daemon_minted() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let held = w.get("/user").await.header("av-approval-id").unwrap().to_string();
    let (_, req) = w.control("POST", "/v1/session-requests", json!({"cred": "demo"})).await;
    let rid = req["id"].as_str().unwrap().to_string();
    let decisions = json!([
        {"id": held, "kind": "request", "granted": true},
        {"id": rid, "kind": "session", "granted": false},
        {"id": SECRET, "kind": "request", "granted": true},
    ]);
    let (s, v) = w.control("POST", "/v1/pending/decide-many", json!({"decisions": decisions})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["decided"].as_array().unwrap().len(), 3);
    assert_eq!(v["decided"][2]["outcome"], "skipped");
    let audit = w.audit_text().await;
    assert!(!audit.contains(SECRET), "an id nothing answers to is counted, never written");
    assert!(audit.contains("\"unknown\":1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn placeholder_issue_never_borrows_another_session() {
    let w = World::seeded(json!({})).await;
    let (s, _) = w.control("POST", "/v1/sessions", json!({"cred": "demo"})).await;
    assert_eq!(s, 200);
    let (s, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo"})).await;
    assert_eq!((s, v["rule"].as_str()), (401, Some("explicit_session")));
    let (s, v) = w.control("POST", "/v1/placeholders", json!({"cred": "demo", "sid": w.session_id})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w.control("POST", "/v1/placeholders/batch", json!({"sid": w.session_id, "items": [{"cred": "demo"}, {"cred": "demo"}]})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("batch_shape")));
    let (s, v) = w.control("POST", "/v1/placeholders/batch", json!({"sid": w.session_id, "items": [{"cred": "demo"}], "purpose": "env"})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["items"][0]["placeholder"].as_str().unwrap().starts_with("av1."));
    assert!(w.audit_text().await.contains("placeholder.issued_batch"));
}

#[tokio::test(flavor = "multi_thread")]
async fn listeners_are_validated_and_bound_and_unbound() {
    let w = World::seeded(json!({})).await;
    let (s, _, rule) = refusal(&w, "POST", "/v1/listeners", json!({"id": "net", "address": "0.0.0.0:0", "surfaces": ["gateway"]})).await;
    assert_eq!((s, rule.as_str()), (403, "listener_tls"));
    let (s, _, rule) = refusal(&w, "POST", "/v1/listeners", json!({"id": "x", "address": "nope"})).await;
    assert_eq!((s, rule.as_str()), (404, "listener_address"));
    let (s, _, rule) = refusal(&w, "POST", "/v1/listeners", json!({"id": "x", "address": "127.0.0.1:0", "allow_cidr": ["10.0.0.0/33"]})).await;
    assert_eq!((s, rule.as_str()), (403, "listener_allow_cidr"));
    let (s, v) = w.control("POST", "/v1/listeners", json!({"id": "lo", "address": "127.0.0.1:0", "surfaces": ["mcp"]})).await;
    assert_eq!(s, 200, "{v}");
    let rec: av_store::model::ListenerRecord = serde_json::from_value(v).unwrap();
    let (host, port) = w.daemon.bind_listener(&rec).await.unwrap();
    assert_eq!(host, "127.0.0.1");
    // A surface it does not serve is a 404.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"GET /p/demo/user HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
    assert!(out.contains("does not serve the gateway surface"));
    let (s, v) = w.control("DELETE", "/v1/listeners?id=lo", json!({})).await;
    assert_eq!((s, v["unbound"].as_bool()), (200, Some(true)));
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err(), "an unbound listener answers nothing");
}

#[test]
fn allow_lists_and_addresses_read_as_the_js_does() {
    use crate::server::{is_loopback_host, parse_address, parse_allow_cidr};
    let a = parse_allow_cidr(Some(&json!(["100.64.0.0/10", "fd7a:115c:a1e0::/48"]))).unwrap().unwrap();
    assert!(a.allows("100.100.1.2"));
    assert!(a.allows("::ffff:100.100.1.2"));
    assert!(a.allows("fd7a:115c:a1e0::9"));
    assert!(!a.allows("8.8.8.8"));
    assert!(!a.allows("garbage"));
    assert!(parse_allow_cidr(Some(&json!("10.0.0.0/8"))).is_err());
    assert!(parse_allow_cidr(Some(&json!(["10.0.0.0"]))).is_err());
    assert!(parse_allow_cidr(Some(&json!([]))).unwrap().is_none());
    assert_eq!(parse_address("[::1]:7443").unwrap(), ("::1".into(), 7443));
    assert_eq!(parse_address("127.0.0.1:0").unwrap(), ("127.0.0.1".into(), 0));
    assert!(parse_address("host:99999").is_err());
    assert!(parse_address("a:b:1").is_err());
    assert!(is_loopback_host("127.9.9.9"));
    assert!(!is_loopback_host("127.evil.com"), "a name is never loopback");
    assert!(!is_loopback_host("127.0.0.1.attacker.test"));
    assert!(!is_loopback_host("10.0.0.1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn narrowing_only_takes_away() {
    let w = World::seeded(json!({})).await;
    let (s, _, rule) = refusal(&w, "POST", "/v1/sessions/narrow", json!({"sid": w.session_id, "narrow": {"redirects": 3}})).await;
    assert_eq!((s, rule.as_str()), (403, "narrow_widens"));
    let (s, _, rule) = refusal(&w, "POST", "/v1/sessions/narrow", json!({"sid": w.session_id})).await;
    assert_eq!((s, rule.as_str()), (403, "narrow_empty"));
    let (s, _, _) = refusal(&w, "POST", "/v1/sessions/narrow", json!({"sid": w.session_id, "narrow": {"hosts": ["evil.test"], "uses": 1}})).await;
    assert_eq!(s, 403);
    let (s, v) = w.control("POST", "/v1/sessions/narrow", json!({"sid": w.session_id, "narrow": {"methods": ["GET"]}})).await;
    assert_eq!(s, 200, "{v}");
    let r = w.send("POST", "/x", vec![("authorization".into(), format!("Bearer {}", w.placeholder))], Some("{}")).await;
    assert_eq!(r.error.unwrap().extra.rule.as_deref(), Some("methods"));
}

#[tokio::test(flavor = "multi_thread")]
async fn templates_are_checked_like_a_create_and_a_changed_one_is_refused() {
    let w = World::seeded(json!({})).await;
    let (s, _, rule) = refusal(&w, "POST", "/v1/templates", json!({"name": "t", "spec": {"cred": "demo", "template": "x"}})).await;
    assert_eq!((s, rule.as_str()), (403, "session_shape"));
    let (s, v) = w.control("POST", "/v1/templates", json!({"name": "gh-read", "spec": {"cred": "demo", "methods": ["GET"], "budget": 5}})).await;
    assert_eq!(s, 200, "{v}");
    let hash = v["hash"].as_str().unwrap().to_string();
    let (s, _, rule) = refusal(&w, "POST", "/v1/sessions", json!({"template": "gh-read", "template_hash": "stale"})).await;
    assert_eq!((s, rule.as_str()), (403, "template_changed"));
    let (s, _, rule) = refusal(&w, "POST", "/v1/sessions", json!({"template": "gh-read", "template_hash": hash, "budget": 50})).await;
    assert_eq!(s, 200, "{rule}");
    let (s, v) = w.control("POST", "/v1/session-requests", json!({"template": "gh-read", "reason": "r"})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["summary"].as_str().unwrap().starts_with("template gh-read v1"));
    let (_, list) = w.control("GET", "/v1/templates", json!({})).await;
    assert_eq!(list[0]["creds"], json!(["demo"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn tripwires_turn_on_open_and_report_the_defaults() {
    let w = World::seeded(json!({})).await;
    let (_, v) = w.control("GET", "/v1/tripwires", json!({})).await;
    assert_eq!((v["enabled"].as_bool(), v["rules_saved"].as_bool()), (Some(false), Some(false)));
    assert_eq!(v["rules"].as_array().unwrap().len(), 4);
    let (s, _, rule) = refusal(&w, "POST", "/v1/tripwires", json!({"enabled": "true"})).await;
    assert_eq!((s, rule.as_str()), (403, "tripwire_rule"));
    let (s, v) = w.control("POST", "/v1/tripwires", json!({"enabled": true})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["enabled"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_paging_filters_kind_before_the_limit_and_walks_both_ways() {
    let w = World::seeded(json!({})).await;
    for _ in 0..3 {
        w.get("/user").await;
    }
    let (s, rows) = w.control("GET", "/v1/audit?kind=request&limit=2", json!({})).await;
    assert_eq!(s, 200);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["kind"].as_str().unwrap().starts_with("request.")));
    let last = rows[1]["seq"].as_u64().unwrap();
    let (_, older) = w.control("GET", &format!("/v1/audit?before={last}&limit=1"), json!({})).await;
    assert!(older[0]["seq"].as_u64().unwrap() < last);
    let (s, _, rule) = refusal(&w, "GET", "/v1/audit?kind=request&limit=501", json!({})).await;
    assert_eq!((s, rule.as_str()), (403, "audit_range"));
    let (s, _, rule) = refusal(&w, "GET", "/v1/audit?kind=Bad Kind", json!({})).await;
    assert_eq!((s, rule.as_str()), (403, "audit_range"));
    let (s, _, _) = refusal(&w, "GET", "/v1/audit?before=1&after=2", json!({})).await;
    assert_eq!(s, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_malformed_json_and_an_unknown_route_are_answers_not_crashes() {
    let w = World::bare().await;
    let inc = crate::server::Incoming { method: "POST".into(), target: "/v1/sessions".into(), headers: vec![], body: b"{not json".to_vec() };
    let r = w.daemon.on_control(inc).await;
    assert_eq!(r.status(), 400);
    let (s, v) = w.control("GET", "/v1/nope", json!({})).await;
    assert_eq!((s, v["code"].as_str()), (404, Some("AV_NOT_FOUND")));
    let (s, v) = w.control("GET", "/v1/status", json!({})).await;
    assert_eq!(s, 200, "still answering: {v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hardening_a_short_credential_is_stored_with_a_warning() {
    let w = World::bare().await;
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "short", "kind": "http", "host": "api.example.test", "value": "abc"})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["warnings"][0].as_str().unwrap().contains("under 8 characters"));
    assert!(v.get("value").is_none());
    let (s, v) = w.control("POST", "/v1/credentials", json!({"slug": "bad", "kind": "http", "host": "x.test", "value": SECRET, "expires_at": "soon"})).await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("expires_at")));
    let (_, list) = w.control("GET", "/v1/credentials", json!({})).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "a refused add stores nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_vault_says_so_on_every_read_that_needs_the_key() {
    let w = World::seeded(json!({})).await;
    let (s, _) = w.control("POST", "/v1/lock", json!({})).await;
    assert_eq!(s, 200);
    for p in ["/v1/audit", "/v1/audit/verify", "/v1/sessions/detail?sid=x", "/v1/report/access"] {
        let (s, v) = w.control("GET", p, json!({})).await;
        assert_eq!((s, v["code"].as_str()), (423, Some("AV_LOCKED")), "{p}");
    }
    let (s, v) = w.control("POST", "/v1/panic", json!({})).await;
    assert_eq!((s, v["already"].as_bool()), (423, Some(true)));
    let (s, v) = w.control("POST", "/v1/unlock", json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["factor"], "none");
}
