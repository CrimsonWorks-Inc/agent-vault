//! Tests for the src/daemon/notify.js entries of mutations.toml. Each names
//! the protection (the `what` of test/mutation-check.js) it holds.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::notify::NotifierOptions;

type Posts = Arc<Mutex<Vec<String>>>;

/// A world whose webhook sender records each body and answers `answer`.
async fn hooked(answer: Result<u16, String>, detail: &str) -> (World, Posts) {
    let posts: Posts = Arc::new(Mutex::new(Vec::new()));
    let p2 = posts.clone();
    let send: crate::notify::Sender = Arc::new(move |_url: String, body: String| {
        p2.lock().unwrap().push(body);
        let a = answer.clone();
        Box::pin(async move { a })
    });
    let w = World::seeded_with(
        json!({"approval": "each"}),
        NotifierOptions { send: Some(send) },
    )
    .await;
    let (s, v) = w
        .control(
            "POST",
            "/v1/notify",
            json!({"webhook_url": "https://hooks.example.test/x", "detail": detail}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    (w, posts)
}

/// Wait (up to 10 s) until at least `n` webhooks were posted.
async fn posted(posts: &Posts, n: usize) {
    for _ in 0..200 {
        if posts.lock().unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn hold(w: &World, path: &str) {
    let r = w
        .send(
            "POST",
            path,
            vec![("authorization".into(), format!("Bearer {}", w.placeholder))],
            Some("{}"),
        )
        .await;
    assert_eq!(r.status, 202, "held for a human");
}

/// 'the webhook is POSTed for every item, not once per interval (F14)'.
#[tokio::test(flavor = "multi_thread")]
async fn the_webhook_is_posted_once_per_interval() {
    let (w, posts) = hooked(Ok(204), "minimal").await;
    hold(&w, "/a").await;
    posted(&posts, 1).await;
    hold(&w, "/b").await;
    hold(&w, "/c").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(posts.lock().unwrap().len(), 1, "one post per interval");
}

/// 'a test notification is not throttled (F14)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_test_notification_inside_the_interval_is_refused() {
    let (w, posts) = hooked(Ok(204), "minimal").await;
    let (s, v) = w.control("POST", "/v1/notify/test", json!({})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = w.control("POST", "/v1/notify/test", json!({})).await;
    assert_eq!(s, 429, "{v}");
    assert_eq!(posts.lock().unwrap().len(), 1);
}

/// 'every webhook failure is recorded, so a dead endpoint floods the log
/// (F14)'.
#[tokio::test(flavor = "multi_thread")]
async fn webhook_failures_are_recorded_at_most_once_per_window() {
    let (w, posts) = hooked(Err("ECONNREFUSED".into()), "minimal").await;
    let (s, v) = w.control("POST", "/v1/notify/test", json!({})).await;
    assert_eq!((s, v["error"].as_str()), (200, Some("ECONNREFUSED")), "{v}");
    hold(&w, "/a").await;
    posted(&posts, 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(posts.lock().unwrap().len(), 2, "both were tried");
    let failed = w
        .audit()
        .await
        .into_iter()
        .filter(|r| r["kind"] == "notify.failed")
        .count();
    assert_eq!(failed, 1, "one record per window");
}

/// 'notify.failed records any string an error carries as its code (C28)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_code_that_is_not_an_errno_name_is_recorded_as_error() {
    let (w, _) = hooked(Err("token=abc refused".into()), "minimal").await;
    let (s, v) = w.control("POST", "/v1/notify/test", json!({})).await;
    assert_eq!((s, v["error"].as_str()), (200, Some("error")), "{v}");
    assert!(!w.audit_text().await.contains("token=abc"));
}

/// 'the minimal webhook payload carries headlines (F14)'.
#[tokio::test(flavor = "multi_thread")]
async fn a_minimal_webhook_carries_no_headline() {
    let (w, posts) = hooked(Ok(204), "minimal").await;
    hold(&w, "/secret-looking-path").await;
    posted(&posts, 1).await;
    let body = posts.lock().unwrap().join("\n");
    assert!(body.contains("\"waiting\":1"), "{body}");
    assert!(!body.contains("secret-looking-path"), "{body}");
}
