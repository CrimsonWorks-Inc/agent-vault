//! Tests for the src/daemon/session-requests.js entries of mutations.toml.
//! Each names the protection (the `what` of test/mutation-check.js) it holds.

use serde_json::{json, Value};

use super::*;
use crate::session_requests::{overrides_problem, resolve_template, shape_of, MAX_PENDING};

async fn ask(w: &World, body: Value) -> (u16, Value) {
    w.control("POST", "/v1/session-requests", body).await
}

async fn decide(w: &World, id: &str, granted: bool) -> (u16, Value) {
    w.control(
        "POST",
        "/v1/session-requests/decide",
        json!({"id": id, "granted": granted}),
    )
    .await
}

/// 'an approved token is persisted to disk': only pending and denied
/// questions are kept (the row type has no field a token could ride in).
#[tokio::test(flavor = "multi_thread")]
async fn an_approved_session_request_is_not_written_to_disk() {
    let w = World::seeded(json!({})).await;
    let (_, a) = ask(&w, json!({"cred": "demo"})).await;
    let (_, b) = ask(&w, json!({"cred": "demo"})).await;
    let (s, v) = decide(&w, a["id"].as_str().unwrap(), true).await;
    assert_eq!(s, 200, "{v}");
    let rows = av_store::vault::Vault::open(w._dir.path())
        .unwrap()
        .session_requests()
        .unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec![b["id"].as_str().unwrap()], "only the pending one");
}

/// 'settled session requests count against the waiting-room cap'.
#[tokio::test(flavor = "multi_thread")]
async fn only_pending_requests_fill_the_waiting_room() {
    let w = World::seeded(json!({})).await;
    let mut first = String::new();
    for i in 0..MAX_PENDING {
        let (s, v) = ask(&w, json!({"cred": "demo"})).await;
        assert_eq!(s, 200, "{i}: {v}");
        if i == 0 {
            first = v["id"].as_str().unwrap().to_string();
        }
    }
    let (s, v) = ask(&w, json!({"cred": "demo"})).await;
    assert_ne!(s, 200, "the room is full");
    assert_eq!(v["rule"], "session_requests", "{v}");
    let (s, v) = decide(&w, &first, false).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = ask(&w, json!({"cred": "demo"})).await;
    assert_eq!(s, 200, "a denied question no longer waits: {v}");
}

/// 'a session request never tells the notifier it is waiting (F14)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_request_is_announced_to_watchers() {
    let w = World::seeded(json!({})).await;
    let mut rx = w.daemon.notifier.subscribe(Vec::new()).unwrap();
    let (_, v) = ask(&w, json!({"cred": "demo"})).await;
    let id = v["id"].as_str().unwrap().to_string();
    let mut seen = String::new();
    while let Ok(f) = rx.try_recv() {
        seen.push_str(&f);
    }
    assert!(
        seen.contains("event: pending") && seen.contains(&id),
        "{seen}"
    );
}

/// "a template override's approval mode replaces a stricter one (F17)".
#[test]
fn a_template_override_cannot_loosen_the_approval_mode() {
    let spec = json!({"cred": "gh", "approval": "each"});
    let out = resolve_template(&spec, &json!({"approval": "auto"}), None).unwrap();
    assert_eq!(out["approval"], "each");
    let spec = json!({"cred": "gh", "approval": "auto"});
    let out = resolve_template(&spec, &json!({"approval": "on-write"}), None).unwrap();
    assert_eq!(out["approval"], "on-write", "tightening is allowed");
}

/// 'overridesProblem accepts a narrowing that is not an object'.
#[test]
fn a_narrowing_that_is_not_an_object_is_a_problem() {
    for bad in [json!([1]), json!("budget"), json!(3), json!(true)] {
        assert_eq!(
            overrides_problem(Some(&bad)).as_deref(),
            Some("the narrowing must be an object"),
            "{bad}"
        );
    }
    assert_eq!(overrides_problem(Some(&json!({"budget": 2}))), None);
    assert_eq!(overrides_problem(None), None);
}

/// The C25 entries: the opened record names fields and counts, and quotes
/// nothing the agent wrote.
#[tokio::test(flavor = "multi_thread")]
async fn the_opened_record_carries_only_the_proposal_shape() {
    let w = World::seeded(json!({})).await;
    let (s, v) = ask(
        &w,
        json!({"cred": "demo", "methods": ["GET", "HEAD"], "paths": ["/x/**"]}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let rows = w.audit().await;
    let opened = rows
        .iter()
        .find(|r| r["kind"] == "session_request.opened")
        .expect("an opened record");
    let text = crate::util::js_stringify(opened);
    assert!(!text.contains("summary"), "no summary (C25): {text}");
    assert!(!text.contains("fingerprint"), "no digest (C25): {text}");
    assert!(!text.contains("/x/**"), "no list copied (C25): {text}");
}

/// 'shapeOf counts a list by copying it (C25)' and "shapeOf names fields
/// from the proposal's own keys, which the agent wrote (C25)".
#[test]
fn shape_of_counts_and_names_only_known_fields() {
    let p = json!({"cred": "a", "methods": ["GET", "POST"], "zz-agent-wrote-this": 1});
    let shape = shape_of(&p);
    assert_eq!(shape["fields"], json!(["cred", "methods"]));
    assert_eq!(shape["counts"], json!({"methods": 2}));
}
