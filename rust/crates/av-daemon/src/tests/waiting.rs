//! Waiting for a human inside a tool call: an agent that asked for a
//! session, proposed a credential or had a write held can wait for the
//! answer in the same turn, and the call returns the moment the human
//! answers. New with 0.6.0; no JS source.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;

/// One MCP tool call, with or without the world's session.
async fn tool(w: &World, name: &str, args: Value, with_session: bool) -> Value {
    call_on(w.daemon.clone(), w, name, args, with_session).await
}

async fn call_on(
    daemon: Arc<Daemon>,
    w: &World,
    name: &str,
    args: Value,
    with_session: bool,
) -> Value {
    let (session, token) = if with_session {
        let t = w.token.clone();
        let s = w
            .shared
            .run(move |c| c.vault.session_by_token(&t).unwrap())
            .await
            .unwrap();
        (s, Some(w.token.clone()))
    } else {
        (None, None)
    };
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    let r = daemon.mcp.handle(msg, session, token, None).await.unwrap();
    serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Start a waiting tool call in the background.
fn waiting(
    w: &World,
    name: &'static str,
    args: Value,
    with_session: bool,
) -> tokio::task::JoinHandle<(Value, Duration)> {
    let daemon = w.daemon.clone();
    let shared = w.shared.clone();
    let token = w.token.clone();
    tokio::spawn(async move {
        let started = Instant::now();
        let (session, tok) = if with_session {
            let t = token.clone();
            let s = shared
                .run(move |c| c.vault.session_by_token(&t).unwrap())
                .await
                .unwrap();
            (s, Some(token))
        } else {
            (None, None)
        };
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
        let r = daemon.mcp.handle(msg, session, tok, None).await.unwrap();
        let v = serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        (v, started.elapsed())
    })
}

#[test]
fn a_wait_is_whole_seconds_up_to_fifty_and_nothing_otherwise() {
    use crate::mcp::wait_of;
    assert_eq!(
        wait_of(&json!({"wait_seconds": 999})),
        Duration::from_secs(50)
    );
    assert_eq!(
        wait_of(&json!({"wait_seconds": 2.5})),
        Duration::from_millis(2500)
    );
    for none in [
        json!({}),
        json!({"wait_seconds": -5}),
        json!({"wait_seconds": "50"}),
        json!({"wait_seconds": null}),
    ] {
        assert_eq!(wait_of(&none), Duration::ZERO, "{none}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_request_answered_while_the_agent_waits_returns_at_once() {
    let w = World::seeded(json!({})).await;
    let asked = tool(
        &w,
        "vault_request_session",
        json!({"cred": "demo", "methods": ["GET"], "reason": "to read"}),
        false,
    )
    .await;
    assert!(
        asked["detail"]
            .as_str()
            .unwrap()
            .contains("wait_seconds: 50"),
        "{asked}"
    );
    let id = asked["request_id"].as_str().unwrap().to_string();
    let poll = waiting(
        &w,
        "vault_request_session",
        json!({"poll_id": id, "poll_secret": asked["poll_secret"], "wait_seconds": 30}),
        false,
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": id, "granted": true}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (answer, took) = poll.await.unwrap();
    // Approved from the CLI, the session went to the human's client state,
    // where the bridge finds it; the agent is told so.
    assert_eq!(answer["state"], "approved", "{answer}");
    assert!(
        took < Duration::from_secs(10),
        "woken by the decision, not the wait: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn asking_and_waiting_in_one_call_returns_the_answer_or_the_question_again() {
    let w = World::seeded(json!({})).await;
    // Nobody answers: after the wait the agent gets what it needs to poll again.
    let started = Instant::now();
    let asked = tool(
        &w,
        "vault_request_session",
        json!({"cred": "demo", "reason": "to read", "wait_seconds": 1}),
        false,
    )
    .await;
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(asked["state"], "pending", "{asked}");
    assert!(asked["poll_secret"].is_string() && asked["request_id"].is_string());
    // Answered meanwhile: the one call carries the answer and names the request.
    let call = waiting(
        &w,
        "vault_propose_credential",
        json!({"slug": "linear", "host": "api.linear.app", "wait_seconds": 30}),
        false,
    );
    let id = loop {
        let (_, listed) = w.control("GET", "/v1/cred-proposals", json!({})).await;
        if let Some(id) = listed[0]["id"].as_str() {
            break id.to_string();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let (s, v) = w
        .control(
            "POST",
            "/v1/cred-proposals/decide",
            json!({"id": id, "granted": true, "hosts": ["api.linear.app"], "value": SECRET}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (answer, took) = call.await.unwrap();
    assert_eq!(
        (answer["state"].as_str(), answer["cred"].as_str()),
        (Some("approved"), Some("linear")),
        "{answer}"
    );
    assert_eq!(answer["request_id"], id.as_str());
    assert!(answer.get("poll_secret").is_none());
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(!leaks(&answer.to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_write_is_waited_for_and_only_its_asker_waits_on_a_request() {
    let w = World::seeded(json!({})).await;
    let held = w
        .send(
            "POST",
            "/x",
            vec![
                ("authorization".into(), format!("Bearer {}", w.placeholder)),
                ("content-type".into(), "application/json".into()),
            ],
            Some("{\"a\":1}"),
        )
        .await;
    assert_eq!(held.status, 202);
    let id = held.header("av-approval-id").unwrap().to_string();
    let status = waiting(
        &w,
        "vault_approval_status",
        json!({"approval_id": id, "wait_seconds": 30}),
        true,
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (s, _) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": true}))
        .await;
    assert_eq!(s, 200);
    let (answer, took) = status.await.unwrap();
    assert_eq!(answer["state"], "granted", "{answer}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    // A poll with the wrong secret is told so at once; it never waits.
    let asked = tool(
        &w,
        "vault_request_session",
        json!({"cred": "demo", "reason": "r"}),
        false,
    )
    .await;
    let started = Instant::now();
    let wrong = tool(
        &w,
        "vault_request_session",
        json!({"poll_id": asked["request_id"], "poll_secret": "not-it", "wait_seconds": 30}),
        false,
    )
    .await;
    assert!(wrong["error"].as_str().unwrap().contains("poll_secret"));
    assert!(started.elapsed() < Duration::from_secs(2));
    let proposal = tool(
        &w,
        "vault_propose_credential",
        json!({"slug": "x1", "host": "api.example.com"}),
        false,
    )
    .await;
    let started = Instant::now();
    let wrong = tool(
        &w,
        "vault_propose_credential",
        json!({"poll_id": proposal["request_id"], "poll_secret": "not-it", "wait_seconds": 30}),
        false,
    )
    .await;
    assert!(wrong["error"].is_string(), "{wrong}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Each way a human answers wakes the waiters itself: the two-second tick
/// is only for an answer that comes another way.
#[tokio::test(flavor = "multi_thread")]
async fn every_answer_a_human_gives_wakes_the_waiters() {
    let w = World::seeded(json!({})).await;
    let mut rx = w.shared.run(|c| c.decisions.subscribe()).await.unwrap();
    let mut woke = |label: &str| {
        assert!(
            rx.has_changed().unwrap(),
            "{label} did not wake the waiters"
        );
        rx.borrow_and_update();
    };
    let asked = tool(
        &w,
        "vault_request_session",
        json!({"cred": "demo", "reason": "r"}),
        false,
    )
    .await;
    let (s, _) = w
        .control(
            "POST",
            "/v1/session-requests/decide",
            json!({"id": asked["request_id"], "granted": false}),
        )
        .await;
    assert_eq!(s, 200);
    woke("a session request's denial");
    let held = w
        .send(
            "POST",
            "/x",
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    let id = held.header("av-approval-id").unwrap().to_string();
    let (s, _) = w
        .control("POST", "/v1/approvals", json!({"id": id, "granted": false}))
        .await;
    assert_eq!(s, 200);
    woke("a held write's denial");
    let proposal = tool(
        &w,
        "vault_propose_credential",
        json!({"slug": "x1", "host": "api.example.com"}),
        false,
    )
    .await;
    let (s, _) = w
        .control(
            "POST",
            "/v1/cred-proposals/decide",
            json!({"id": proposal["request_id"], "granted": false}),
        )
        .await;
    assert_eq!(s, 200);
    woke("a credential proposal's denial");
    tool(
        &w,
        "vault_request_session",
        json!({"cred": "demo", "reason": "r"}),
        false,
    )
    .await;
    let (s, _) = w.control("POST", "/v1/panic", json!({})).await;
    assert_eq!(s, 200);
    woke("a panic");
}
