//! Tests for the src/pending.js entries of mutations.toml. pending.js is
//! ported in av-store (`av_store::pending`); these call it directly so a
//! scoped av-daemon run still catches each mutant. Each names the
//! protection (the `what` of test/mutation-check.js) it holds.

use av_store::pending::{describe, parse_overrides, PendingKind};
use serde_json::{json, Map, Value};

fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn refused(v: Value) -> String {
    match parse_overrides(&args(v.clone())) {
        Err(e) => e.field,
        Ok(o) => panic!("{v} parsed: {o:?}"),
    }
}

/// "a human's numeric override is coerced, so a typo becomes null and is
/// dropped", 'a numeric narrowing that is not finite is sent as NaN, which
/// JSON drops (C23)', 'a blank numeric narrowing becomes a limit of 0 (C23)'.
#[test]
fn a_numeric_narrowing_is_a_finite_number_or_refused() {
    for bad in [
        json!(true),
        json!([3]),
        json!({}),
        json!("lots"),
        json!("Infinity"),
        json!("-Infinity"),
        json!("   "),
    ] {
        assert_eq!(refused(json!({ "budget": bad })), "budget", "{bad}");
    }
    let o = parse_overrides(&args(json!({"budget": " 7 "}))).unwrap();
    assert_eq!(o.budget, Some(7.0));
}

/// 'a JSON-string routes narrowing is dropped, so the agent's wider routes
/// are approved (C21, C23)', 'a JSON-string payload narrowing is dropped
/// (C21, C23)', 'a routes or payload narrowing that is not JSON is dropped
/// instead of refused (C23)'.
#[test]
fn routes_and_payload_may_be_typed_as_json_text_and_bad_text_is_refused() {
    let routes = json!([{"methods": ["GET"], "paths": ["/a"]}]);
    let o = parse_overrides(&args(json!({"routes": routes.to_string()}))).unwrap();
    assert_eq!(o.routes, Some(routes));
    let payload = json!({"max_bytes": 10});
    let o = parse_overrides(&args(json!({"payload": payload.to_string()}))).unwrap();
    assert_eq!(o.payload, Some(payload));
    assert_eq!(refused(json!({"routes": "[{not json"})), "routes");
    assert_eq!(refused(json!({"payload": "{nope"})), "payload");
}

/// 'a rate or quota narrowing is stringified and not trimmed (C23)'.
#[test]
fn a_rate_is_trimmed_and_an_object_stays_an_object() {
    let o = parse_overrides(&args(
        json!({"rate": " 5/minute ", "quota": {"count": 2, "window": "hour"}}),
    ))
    .unwrap();
    assert_eq!(o.rate, Some(json!("5/minute")));
    assert_eq!(o.quota, Some(json!({"count": 2, "window": "hour"})));
}

/// "a held request's preview is dropped from the human's list (F13)".
#[test]
fn a_held_request_keeps_its_preview() {
    let preview = json!({"method": "POST", "body": "{\"a\":1}"});
    let item = describe(
        PendingKind::Request,
        &json!({"id": "ap_1", "summary": "POST /x", "preview": preview}),
    );
    assert_eq!(item.preview, Some(preview));
}
