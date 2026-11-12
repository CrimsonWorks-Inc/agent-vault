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
