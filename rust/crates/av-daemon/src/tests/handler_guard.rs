//! `#guard` (src/daemon/server.js:1180-1192): a handler that panics costs one
//! request, not the daemon. PLAN 4905f8d.

use http_body_util::BodyExt;
use serde_json::{json, Value};

use super::*;

fn get(target: &str) -> crate::server::Incoming {
    crate::server::Incoming {
        method: "GET".into(),
        target: target.into(),
        headers: vec![],
        body: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_panics_is_recorded_answered_500_and_the_next_request_works() {
    let w = World::seeded(json!({})).await;
    let r = w.daemon.on_control(get("/v1/test-only/panic")).await;
    assert_eq!(r.status(), 500);
    assert_eq!(
        r.headers()["content-type"].to_str().unwrap(),
        "application/problem+json"
    );
    let body = r.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v,
        json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"})
    );
    let audit = w.audit_text().await;
    assert!(
        audit.contains("daemon.handler_error"),
        "the fault is recorded"
    );
    assert!(audit.contains(r#""error":"Error""#), "by class: {audit}");
    assert!(!audit.contains("s3cr3t"), "never by its message");
    // The daemon, and the lock the handler ran beside, still work.
    let r = w.daemon.on_control(get("/v1/status")).await;
    assert_eq!(r.status(), 200);
    let (s, _) = w.control("GET", "/v1/sessions", json!({})).await;
    assert_eq!(s, 200);
    let r = w.get("/user").await;
    assert_eq!(r.status, 200, "{:?}", r.error);
}

/// The guard needs panics to unwind. Cargo ignores a profile's `panic`
/// setting when it builds tests (they always unwind), so `cargo test
/// --release` cannot see `abort` come back; this reads the profile instead.
#[test]
fn release_builds_unwind_so_the_guard_can_run() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let text = std::fs::read_to_string(manifest).unwrap();
    let mut in_release = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_release = line == "[profile.release]";
            continue;
        }
        if in_release {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "panic" {
                    assert_ne!(
                        v.trim().trim_matches('"'),
                        "abort",
                        "[profile.release] panic = \"abort\" ends the daemon on any handler fault"
                    );
                }
            }
        }
    }
    assert!(text.contains("[profile.release]"));
}

fn set_column(w: &World, column: &str, json_text: &str) {
    let c = rusqlite::Connection::open(w._dir.path().join("vault.db")).unwrap();
    c.execute(
        &format!("UPDATE credentials SET {column} = ?1 WHERE slug = 'demo'"),
        [json_text],
    )
    .unwrap();
}

async fn body_of(r: crate::http::Resp) -> Value {
    let b = r.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}

/// A store failure that is not a refusal (here a stored column of the wrong
/// shape) answers the generic AV_INTERNAL and records the class only; the
/// store's own text, which quotes stored data, stays out of the answer and
/// the audit log (C28, as JS #guard).
#[tokio::test(flavor = "multi_thread")]
async fn a_store_fault_answers_the_generic_internal_and_records_only_its_class() {
    let w = World::seeded(json!({})).await;
    set_column(&w, "quarantine", r#""unreadable legacy marker""#);
    let r = w.daemon.on_control(get("/v1/credentials")).await;
    assert_eq!(r.status(), 500);
    let v = body_of(r).await;
    assert_eq!(v["code"], "AV_INTERNAL", "{v}");
    assert_eq!(v["detail"], "the request could not be handled", "{v}");
    let audit = w.audit_text().await;
    assert!(audit.contains("daemon.handler_error"), "recorded");
    assert!(audit.contains(r#""error":"Error""#), "{audit}");
    for leak in [
        "unreadable legacy marker",
        "Conversion",
        "sqlite",
        "invalid type",
    ] {
        assert!(!audit.contains(leak), "{leak} in the audit log");
    }
    // The same fault through the MCP endpoint.
    let s = w
        .shared
        .run({
            let t = w.token.clone();
            move |c| c.vault.session_by_token(&t).unwrap()
        })
        .await
        .unwrap();
    let msg = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "vault_list_creds", "arguments": {}}});
    let out = w
        .daemon
        .mcp
        .handle(msg, s, Some(w.token.clone()), None)
        .await
        .unwrap();
    let text = out.to_string();
    assert_eq!(
        out["error"]["message"], "the request could not be handled",
        "{out}"
    );
    for leak in ["unreadable legacy marker", "Conversion", "sqlite"] {
        assert!(!text.contains(leak), "{leak} reached the agent: {text}");
    }
    assert_eq!(
        w.audit_text().await.matches("daemon.handler_error").count(),
        2,
        "the MCP fault is recorded too"
    );
}

/// JS lists a credential whose stored health has another shape (it passes
/// the value through); the port reads it as no health instead of failing
/// the whole list.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_shape_health_value_does_not_fail_the_credential_list() {
    let w = World::seeded(json!({})).await;
    set_column(&w, "health", r#""unreadable legacy health""#);
    let r = w.daemon.on_control(get("/v1/credentials")).await;
    assert_eq!(r.status(), 200);
    let v = body_of(r).await;
    let demo = v
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["slug"] == "demo")
        .cloned()
        .expect("listed");
    assert_eq!(demo["health"], Value::Null, "{demo}");
    assert!(!w.audit_text().await.contains("daemon.handler_error"));
}
