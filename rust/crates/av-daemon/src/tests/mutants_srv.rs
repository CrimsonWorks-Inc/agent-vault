//! Tests for the src/daemon/server.js entries of mutations.toml. Each names
//! the protection (the `what` of test/mutation-check.js) it holds.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use super::*;

fn kinds<'a>(rows: &'a [Value], kind: &str) -> Vec<&'a Value> {
    rows.iter().filter(|r| r["kind"] == kind).collect()
}

/// 'listen rm leaves pre-handshake TLS sockets connected'.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_listener_drops_its_idle_connections() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/listeners",
            json!({"id": "lo", "address": "127.0.0.1:0", "surfaces": ["gateway"]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let rec: av_store::model::ListenerRecord = serde_json::from_value(v).unwrap();
    let (_, port) = w.daemon.bind_listener(&rec).await.unwrap();
    let mut idle = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (s, v) = w.control("DELETE", "/v1/listeners?id=lo", json!({})).await;
    assert_eq!(s, 200, "{v}");
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(3), idle.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "the idle connection is closed: {r:?}"
    );
}

/// 'listen.bind_failed records the bind error message (C28)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_bind_is_recorded_by_its_code() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let mut vault = av_store::vault::Vault::create(dir.path(), Default::default()).unwrap();
    vault
        .add_listener(
            serde_json::from_value(json!({"id": "busy", "address": format!("127.0.0.1:{port}"), "surfaces": ["gateway"]}))
                .unwrap(),
        )
        .unwrap();
    let shared = crate::state::Shared::new(vault);
    let daemon = crate::server::Daemon::new(
        shared.clone(),
        crate::server::DaemonOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    daemon.start().await.unwrap();
    let rows = shared
        .run(|core| {
            core.vault
                .audit()
                .unwrap()
                .read(&av_store::audit::ReadFilter {
                    limit: 1000,
                    ..Default::default()
                })
                .unwrap()
                .into_iter()
                .map(|r| serde_json::to_value(r).unwrap())
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
    let failed = kinds(&rows, "listen.bind_failed");
    assert_eq!(failed.len(), 1, "{rows:?}");
    assert_eq!(failed[0]["reason"], "EADDRINUSE", "{}", failed[0]);
    drop(busy);
}

async fn ask(w: &World, body: Value) -> String {
    let (s, v) = w.control("POST", "/v1/session-requests", body).await;
    assert_eq!(s, 200, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// The C25 entries: what the session-request records hold.
#[tokio::test(flavor = "multi_thread")]
async fn session_request_records_hold_names_and_counts_never_values() {
    let w = World::seeded(json!({})).await;
    let a = ask(
        &w,
        json!({"cred": "demo", "methods": ["GET"], "paths": ["/zz-proposed/**"], "budget": 9}),
    )
    .await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": a, "granted": true, "overrides": {"budget": 3}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let b = ask(&w, json!({"cred": "demo", "paths": ["/zz-denied/**"]})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": b, "granted": false}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let _c = ask(&w, json!({"cred": "demo", "paths": ["/zz-panic/**"]})).await;
    let (s, v) = w.control("POST", "/v1/panic", json!({})).await;
    assert_eq!(s, 200, "{v}");
    let rows = w.audit().await;
    let approved = kinds(&rows, "session_request.approved");
    assert_eq!(approved.len(), 1);
    assert_eq!(
        approved[0]["granted"],
        json!(["cred", "methods", "paths", "budget"]),
        "{}",
        approved[0]
    );
    assert_eq!(
        approved[0]["narrowed"],
        json!(["budget"]),
        "{}",
        approved[0]
    );
    assert_eq!(
        approved[0]["proposed"],
        json!(["cred", "methods", "paths", "budget"]),
        "{}",
        approved[0]
    );
    let denied = kinds(&rows, "session_request.denied");
    assert_eq!(denied.len(), 2, "one by a human, one by panic");
    let text = crate::util::js_stringify(&Value::Array(rows.clone()));
    for p in ["zz-proposed", "zz-denied", "zz-panic"] {
        assert!(!text.contains(p), "{p} is a value from a proposal");
    }
    assert!(!text.contains("session for demo"), "no summary is filed");
    // The session and grant made from the request say so.
    let created = kinds(&rows, "session.created");
    let last = created.last().unwrap();
    assert!(last.get("has_expiry").is_some(), "{last}");
    let grant = kinds(&rows, "grant.created");
    assert!(
        grant.last().unwrap().get("has_expiry").is_some(),
        "{}",
        grant.last().unwrap()
    );
    assert!(
        created[0].get("has_expiry").is_none(),
        "an owner-made session is not marked"
    );
}

/// 'decide-many counts any session-request id as one the daemon minted (r4
/// F2)' and 'decide-many counts any held-request id as one the daemon
/// minted (r4 F2)'.
#[tokio::test(flavor = "multi_thread")]
async fn decide_many_files_only_ids_the_daemon_minted() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/pending/decide-many",
            json!({"decisions": [
                {"kind": "session", "id": "sr_forged-by-agent", "granted": false},
                {"kind": "request", "id": "ap_forged-by-agent", "granted": false},
            ]}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let rows = w.audit().await;
    let rec = kinds(&rows, "pending.decided_many");
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0]["unknown"], 2, "{}", rec[0]);
    assert!(
        !crate::util::js_stringify(rec[0]).contains("forged"),
        "{}",
        rec[0]
    );
}

/// 'the daemon approves a session request whose overrides name a key it does
/// not apply', 'a bulk decision drops a session override key it does not
/// apply', 'a bulk decision drops the narrowing sent with a held request'.
#[tokio::test(flavor = "multi_thread")]
async fn a_narrowing_nothing_reads_is_refused_everywhere() {
    let w = World::seeded(json!({"approval": "each"})).await;
    let id = ask(&w, json!({"cred": "demo"})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": id, "granted": true, "overrides": {"hosts": ["x"]}}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("session_overrides")),
        "{v}"
    );
    let (s, v) = w
        .control(
            "POST",
            "/v1/pending/decide-many",
            json!({"decisions": [{"kind": "session", "id": id, "granted": true, "overrides": {"hosts": ["x"]}}]}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("session_overrides")),
        "{v}"
    );
    let r = w
        .send(
            "POST",
            "/x",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    assert_eq!(r.status, 202);
    let (_, held) = w.control("GET", "/v1/approvals", json!({})).await;
    let ap = held[0]["id"].as_str().unwrap().to_string();
    let (s, v) = w
        .control(
            "POST",
            "/v1/pending/decide-many",
            json!({"decisions": [{"kind": "request", "id": ap, "granted": true, "overrides": {"budget": 1}}]}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("session_overrides")),
        "{v}"
    );
}

/// 'r6 B2: the preflight route ignores assume_placeholder', 'r6 B2: the
/// preflight route assumes a placeholder for a caller that did not ask',
/// 'r6 B2: assume_placeholder is not checked to be a boolean'.
#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_route_reads_assume_placeholder_as_a_boolean() {
    let w = World::seeded(json!({})).await;
    let pre = |body: Value| {
        let w = &w;
        async move {
            let r = w
                .daemon
                .on_gateway(
                    crate::server::Incoming {
                        method: "POST".into(),
                        target: "/v1/preflight".into(),
                        headers: vec![
                            ("host".into(), "127.0.0.1".into()),
                            ("authorization".into(), format!("Bearer {}", w.token)),
                            ("content-type".into(), "application/json".into()),
                        ],
                        body: crate::util::js_stringify(&body).into_bytes(),
                    },
                    None,
                    None,
                )
                .await;
            let status = r.status().as_u16();
            use http_body_util::BodyExt;
            let bytes = r.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let base = json!({"method": "GET", "path": "/p/demo/user"});
    let (s, plain) = pre(base.clone()).await;
    assert_eq!(s, 200, "{plain}");
    let mut assumed = base.clone();
    assumed["assume_placeholder"] = json!(true);
    let (s, with) = pre(assumed).await;
    assert_eq!(s, 200, "{with}");
    assert_ne!(
        plain, with,
        "assuming a placeholder changes the answer: {plain} / {with}"
    );
    let mut bad = base;
    bad["assume_placeholder"] = json!("yes");
    let (s, v) = pre(bad).await;
    assert_eq!(s, 403, "{v}");
}

/// 'r6 B1: rules never saved are null, which `tripwire show` cannot list'.
#[tokio::test(flavor = "multi_thread")]
async fn unsaved_tripwire_rules_read_as_the_defaults() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w.control("GET", "/v1/tripwires", json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["rules_saved"], false);
    assert!(v["rules"].is_array() && v["rules"] == v["defaults"], "{v}");
}

/// The U3 daemon entries: the audit tail and pages.
#[tokio::test(flavor = "multi_thread")]
async fn the_audit_route_filters_kind_before_the_limit_and_walks_by_seq() {
    let w = World::seeded(json!({})).await;
    for _ in 0..12 {
        w.send("DELETE", "/x", vec![], None).await;
    }
    let all = w.audit().await;
    let created = kinds(&all, "session.created").len();
    assert!(created >= 1);
    let get = |q: &str| {
        let q = q.to_string();
        let w = &w;
        async move { w.control("GET", &format!("/v1/audit?{q}"), json!({})).await }
    };
    // kind before the limit, on the tail and on pages
    let (s, v) = get("kind=session.created&limit=2").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v.as_array().unwrap().len(), created.min(2), "{v}");
    let top = all.last().unwrap()["seq"].as_u64().unwrap() + 1;
    let (s, v) = get(&format!("kind=session.created&before={top}&limit=5")).await;
    assert_eq!(s, 200, "{v}");
    assert!(
        v.as_array()
            .unwrap()
            .iter()
            .all(|r| r["kind"] == "session.created"),
        "{v}"
    );
    // before= walks
    let (_, p1) = get(&format!("before={top}&limit=3")).await;
    let first = p1[0]["seq"].as_u64().unwrap();
    let (_, p2) = get(&format!("before={first}&limit=3")).await;
    assert!(
        p2.as_array()
            .unwrap()
            .iter()
            .all(|r| r["seq"].as_u64().unwrap() < first),
        "{p2}"
    );
    // bounds
    let (s, _) = get(&format!("before={top}&limit=600")).await;
    assert_eq!(s, 403, "a page is at most 500 rows");
    let (s, _) = get("kind=session.created&limit=abc").await;
    assert_eq!(s, 403, "a kind-filtered tail is held to the page bound");
    let (s, v) = get("limit=5000").await;
    assert_eq!(s, 200, "the old unfiltered tail stays lenient: {v}");
}

/// 'the control API hands back an approval's cached upstream response'.
#[tokio::test(flavor = "multi_thread")]
async fn an_approval_answer_never_carries_the_stored_response() {
    let w = World::seeded(json!({"approval": "each"})).await;
    w.up.answer(Box::new(|_| {
        Ok(json_response(200, &json!({"upstream-only": "zz-body"})))
    }));
    let r = w
        .send(
            "POST",
            "/x",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    assert_eq!(r.status, 202);
    let (_, held) = w.control("GET", "/v1/approvals", json!({})).await;
    let id = held[0]["id"].as_str().unwrap().to_string();
    let (s, v) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
        .await;
    assert_eq!(s, 200, "{v}");
    let r = w
        .send(
            "POST",
            "/x",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    let (status, body, _) = body_of(r).await;
    assert_eq!(status, 200, "{body}");
    let (_, again) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": false}))
        .await;
    let (_, list) = w.control("GET", "/v1/approvals", json!({})).await;
    let st = w.daemon.pipeline.approval_status(id.clone()).await;
    let text = format!("{again} {list} {st:?}");
    assert!(!text.contains("zz-body"), "{text}");
}

/// 'the presence route stores whatever record it is sent'.
#[tokio::test(flavor = "multi_thread")]
async fn a_presence_record_that_is_not_a_webauthn_key_is_refused() {
    let w = World::seeded(json!({})).await;
    let (s, _) = w
        .control(
            "POST",
            "/v1/passphrase",
            json!({"passphrase": "test-passphrase-123"}),
        )
        .await;
    assert_eq!(s, 200);
    let k = crate::ui::webauthn::testkit::SoftKey::new();
    let mut rec = k.record();
    rec["credentialId"] = json!("abc");
    rec["presence"] = json!({"passphrase": "test-passphrase-123"});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_ne!(s, 200, "{v}");
    let (_, stored) = w.control("GET", "/v1/presence", json!({})).await;
    assert_eq!(stored, Value::Null);
}

const PASS: &str = "test-passphrase-123";

async fn with_pass(w: &World) {
    let (s, v) = w
        .control("POST", "/v1/passphrase", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
}

/// An unlimited session's token and placeholder (made with a passphrase).
async fn forever(w: &World) -> (String, String) {
    with_pass(w).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "label": "forever", "methods": ["GET"], "infinite": true, "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    (
        v["token"].as_str().unwrap().to_string(),
        v["placeholder"].as_str().unwrap().to_string(),
    )
}

fn remote() -> Option<crate::pipeline::ListenerInfo> {
    Some(crate::pipeline::ListenerInfo {
        id: "ls_net".into(),
        kind: "tls".into(),
        remote: true,
        advertise: vec![],
    })
}

async fn on_gateway(
    w: &World,
    method: &str,
    target: &str,
    headers: Vec<(String, String)>,
    body: &str,
    listener: Option<crate::pipeline::ListenerInfo>,
) -> (u16, Vec<(String, String)>, String) {
    let mut h = vec![("host".to_string(), "127.0.0.1".to_string())];
    h.extend(headers);
    let r = w
        .daemon
        .on_gateway(
            crate::server::Incoming {
                method: method.into(),
                target: target.into(),
                headers: h,
                body: body.as_bytes().to_vec(),
            },
            listener,
            None,
        )
        .await;
    let status = r.status().as_u16();
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    use http_body_util::BodyExt;
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn mcp_status() -> String {
    crate::util::js_stringify(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "vault_status", "arguments": {}}}),
    )
}

fn mcp_headers(token: &str) -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
        ("authorization".into(), format!("Bearer {token}")),
    ]
}

/// 'the MCP session is read from shared state again'.
#[tokio::test(flavor = "multi_thread")]
async fn the_mcp_endpoint_hands_each_call_its_own_session() {
    let w = World::seeded(json!({})).await;
    let (s, _, body) = on_gateway(
        &w,
        "POST",
        "/mcp",
        mcp_headers(&w.token),
        &mcp_status(),
        None,
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert!(body.contains(&w.session_id), "the caller's session: {body}");
}

/// 'the MCP endpoint checks liveness but not whether the session is usable on
/// this listener', 'discovery checks liveness but not whether the session is
/// usable on this listener', 'the listener never reaches the pipeline'.
#[tokio::test(flavor = "multi_thread")]
async fn an_unlimited_session_is_refused_on_a_network_listener_everywhere() {
    let w = World::seeded(json!({})).await;
    let (token, placeholder) = forever(&w).await;
    // MCP: the session is not handed to the tools.
    let (s, h, body) = on_gateway(
        &w,
        "POST",
        "/mcp",
        mcp_headers(&token),
        &mcp_status(),
        remote(),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert!(
        h.iter().any(|(k, _)| k == "av-session-invalid"),
        "{h:?} {body}"
    );
    let (_, _, local) =
        on_gateway(&w, "POST", "/mcp", mcp_headers(&token), &mcp_status(), None).await;
    assert!(!local.contains("\\\"session\\\":null"), "{local}");
    // Discovery.
    let auth = vec![("authorization".to_string(), format!("Bearer {token}"))];
    let (s, _, body) = on_gateway(&w, "GET", "/v1/session", auth.clone(), "", remote()).await;
    assert!(s >= 400 && body.contains("infinite_remote"), "{s} {body}");
    let (s, _, _) = on_gateway(&w, "GET", "/v1/session", auth, "", None).await;
    assert_eq!(s, 200);
    // The gateway.
    let h = vec![
        ("av-session".to_string(), token.clone()),
        ("authorization".to_string(), format!("Bearer {placeholder}")),
    ];
    let (s, _, body) = on_gateway(&w, "GET", "/p/demo/user", h.clone(), "", remote()).await;
    assert!(s >= 400 && body.contains("infinite_remote"), "{s} {body}");
    let (s, _, body) = on_gateway(&w, "GET", "/p/demo/user", h, "", None).await;
    assert_eq!(s, 200, "{body}");
}

/// 'an authenticator-only vault reports its socket as ungated'.
#[tokio::test(flavor = "multi_thread")]
async fn an_authenticator_only_vault_opens_no_window_and_says_it_is_gated() {
    let w = World::seeded(json!({})).await;
    with_pass(&w).await;
    let k = crate::ui::webauthn::testkit::SoftKey::new();
    let mut rec = k.record();
    rec["presence"] = json!({"passphrase": PASS});
    let (s, v) = w.control("POST", "/v1/presence", rec).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/passphrase",
            json!({"action": "remove", "current": PASS}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control("POST", "/v1/presence/window", json!({"passphrase": "x"}))
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        (v["granted"].as_bool(), v["ungated"].as_bool()),
        (Some(false), Some(false)),
        "{v}"
    );
}

/// 'the daemon asks for a tap before refusing Touch ID unlock without a
/// passphrase'.
#[tokio::test(flavor = "multi_thread")]
async fn touch_id_without_a_passphrase_is_refused_for_the_missing_factor() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/factors/webauthn",
            json!({"credential_id": "abc", "prf_secret": "x".repeat(32)}),
        )
        .await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("factor_order")), "{v}");
}

/// 'the single decide route takes any truthy verdict' (the verdict is read
/// before the gate, which asks for presence by what it says).
#[tokio::test(flavor = "multi_thread")]
async fn a_string_verdict_is_refused_before_anyone_is_asked() {
    let w = World::seeded(json!({})).await;
    let id = ask(&w, json!({"cred": "demo"})).await;
    with_pass(&w).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": id, "granted": "true"}),
        )
        .await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("bulk_decision")), "{v}");
}

/// 'approving a session request into auto with writes needs only the window'
/// and 'a bulk decision with an elevated item needs only the window'.
#[tokio::test(flavor = "multi_thread")]
async fn an_elevated_approval_needs_fresh_presence_even_inside_the_window() {
    let w = World::seeded(json!({})).await;
    let id = ask(&w, json!({"cred": "demo", "methods": ["GET", "POST"]})).await;
    with_pass(&w).await;
    let (s, v) = w
        .control("POST", "/v1/presence/window", json!({"passphrase": PASS}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": id, "granted": true, "overrides": {"approval": "auto"}}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("fresh_presence")),
        "{v}"
    );
    let (s, v) = w
        .control(
            "POST",
            "/v1/pending/decide-many",
            json!({"decisions": [{"kind": "session", "id": id, "granted": true, "overrides": {"approval": "auto"}}]}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (401, Some("fresh_presence")),
        "{v}"
    );
}

/// 'ttl_hours is not required to be a positive number'.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_lifetime_is_a_positive_number_of_hours() {
    let w = World::seeded(json!({})).await;
    for bad in [json!(-1), json!(0), json!("2"), json!(true)] {
        let (s, v) = w
            .control(
                "POST",
                "/v1/sessions",
                json!({"cred": "demo", "methods": ["GET"], "ttl_hours": bad}),
            )
            .await;
        assert_eq!((s, v["rule"].as_str()), (403, Some("ttl")), "{bad}: {v}");
    }
}

/// 'the daemon does not hand a session its elevation'.
#[tokio::test(flavor = "multi_thread")]
async fn an_elevated_session_is_stored_with_its_elevation() {
    let w = World::seeded(json!({})).await;
    with_pass(&w).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "label": "auto", "methods": ["GET", "POST"], "approval": "auto", "ttl_hours": 1, "presence": {"passphrase": PASS}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let sid = v["session_id"].as_str().unwrap().to_string();
    let (_, list) = w.control("GET", "/v1/sessions", json!({})).await;
    let me = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == json!(sid))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(me["elevated"], json!(["approval_auto_writes"]), "{list}");
}

/// 'a session for a quarantined credential is planned and gated' and 'a
/// session can be planned for a quarantined credential'.
#[tokio::test(flavor = "multi_thread")]
async fn a_quarantined_credential_is_refused_before_anyone_is_asked() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/quarantine",
            json!({"slug": "demo", "reason": "test"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    with_pass(&w).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "methods": ["GET"]}),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (403, Some("AV_QUARANTINED")),
        "{v}"
    );
}

/// 'a grant lifetime is accepted and never given to the store (F18)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_lifetime_reaches_the_store() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions",
            json!({"cred": "demo", "methods": ["GET"], "grant_ttl_minutes": 5, "ttl_hours": 1}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["grants"][0]["expires_at"].is_string(), "{v}");
}

/// 'a session request is opened without being built first, so one that
/// could never be created reaches a human'.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_request_that_could_never_be_made_is_refused_at_once() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests",
            json!({"cred": "demo", "budget": 0}),
        )
        .await;
    assert_eq!((s, v["rule"].as_str()), (403, Some("budget")), "{v}");
    let (_, list) = w.control("GET", "/v1/session-requests", json!({})).await;
    assert_eq!(list, json!([]));
}

/// "panic reads lock by truthiness, so 'true' panics without locking".
#[tokio::test(flavor = "multi_thread")]
async fn panic_refuses_a_lock_that_is_not_a_boolean_and_revokes_nothing() {
    let w = World::seeded(json!({})).await;
    for bad in [json!("true"), json!(1)] {
        let (s, v) = w.control("POST", "/v1/panic", json!({"lock": bad})).await;
        assert_eq!(
            (s, v["rule"].as_str()),
            (403, Some("policy_invalid")),
            "{v}"
        );
    }
    assert_eq!(w.get("/user").await.status, 200, "nothing was revoked");
}

/// 'an agent-written quarantine reason is stored with its placeholder and
/// secret in it (F16)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_quarantine_reason_is_stored_cleaned() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/credentials/quarantine",
            json!({"slug": "demo", "reason": format!("saw {SECRET} and {}", w.placeholder)}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let text = crate::util::js_stringify(&v);
    assert!(!leaks(&text), "{text}");
    assert!(!text.contains(&w.placeholder), "{text}");
}

/// 'the gateway preflight route ignores the listener it arrived on (C18)'.
#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_route_asks_about_its_own_listener() {
    let w = World::seeded(json!({})).await;
    let (token, _) = forever(&w).await;
    let h = vec![
        ("authorization".to_string(), format!("Bearer {token}")),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let body = r#"{"method":"GET","path":"/p/demo/user"}"#;
    let (s, _, out) = on_gateway(&w, "POST", "/v1/preflight", h.clone(), body, remote()).await;
    assert!(s >= 400 && out.contains("infinite_remote"), "{s} {out}");
    let (s, _, out) = on_gateway(&w, "POST", "/v1/preflight", h, body, None).await;
    assert_eq!(s, 200, "{out}");
}

/// 'a grant lifetime given twice in a narrowing is taken from one place
/// silently (C22)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_lifetime_given_twice_is_refused() {
    let w = World::seeded(json!({})).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/sessions/narrow",
            json!({"sid": w.session_id, "grant_ttl_minutes": 5, "narrow": {"grant_ttl_minutes": 9}}),
        )
        .await;
    assert_eq!(
        (s, v["rule"].as_str()),
        (403, Some("policy_invalid")),
        "{v}"
    );
}
