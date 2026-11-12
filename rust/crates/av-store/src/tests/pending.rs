//! Ports the pure parts of the JS tests of `src/pending.js`
//! (`control-api-overrides`, `approval-verdict`, `ui-paging`,
//! `session-requests`); the rest of those files drive the daemon, the CLI or
//! the web UI and are theirs.

use serde_json::{json, Map, Value};

use crate::pending::*;

fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn field_of(r: Result<Overrides, OverrideError>) -> String {
    r.unwrap_err().field
}

#[test]
fn routes_and_payload_as_json_strings_are_parsed_a_value_passes_through_bad_json_throws() {
    let routes = json!([{ "methods": ["GET"], "paths": ["/only"] }]);
    let payload = json!({ "query": { "q": { "max_length": 8 } } });
    assert_eq!(parse_overrides(&args(json!({ "routes": routes.to_string() }))).unwrap().routes, Some(routes.clone()));
    assert_eq!(parse_overrides(&args(json!({ "routes": routes }))).unwrap().routes, Some(routes.clone()));
    assert_eq!(parse_overrides(&args(json!({ "payload": payload.to_string() }))).unwrap().payload, Some(payload.clone()));
    assert_eq!(parse_overrides(&args(json!({ "payload": payload }))).unwrap().payload, Some(payload));
    for (f, bad) in [("routes", "[{\"methods\":"), ("payload", "{oops"), ("routes", "null"), ("payload", "\"text\""), ("routes", "5")] {
        assert_eq!(field_of(parse_overrides(&args(json!({ f: bad })))), f, "{f} {bad}");
    }
    let both = parse_overrides(&args(json!({ "routes": routes.to_string(), "route": "POST:/wide" }))).unwrap();
    assert_eq!(both.routes, Some(routes));
}

#[test]
fn a_numeric_narrowing_is_number_v_and_anything_not_finite_throws_naming_the_field() {
    let o = parse_overrides(&args(json!({ "budget": "5", "uses": 2, "ttl_minutes": "15", "grant_ttl_minutes": "10", "max_concurrent": "4", "redirects": "0", "spend_tokens": "1000", "spend_usd": "1.25" }))).unwrap();
    assert_eq!(
        (o.budget, o.uses, o.ttl_minutes, o.grant_ttl_minutes, o.max_concurrent, o.redirects, o.spend_tokens, o.spend_usd),
        (Some(5.0), Some(2.0), Some(15.0), Some(10.0), Some(4.0), Some(0.0), Some(1000.0), Some(1.25))
    );
    let fields = [
        ("budget", "budget"), ("uses", "uses"), ("ttl_minutes", "ttl_minutes"), ("ttl-minutes", "ttl_minutes"),
        ("grant_ttl_minutes", "grant_ttl_minutes"), ("grant-ttl", "grant_ttl_minutes"), ("max_concurrent", "max_concurrent"),
        ("concurrency", "max_concurrent"), ("redirects", "redirects"), ("spend_tokens", "spend_tokens"), ("spend-tokens", "spend_tokens"),
        ("spend_usd", "spend_usd"), ("spend-usd", "spend_usd"),
    ];
    for (flag, field) in fields {
        for typo in [json!("abc"), json!("5x"), json!("   "), json!("Infinity"), json!(true), json!({})] {
            assert_eq!(field_of(parse_overrides(&args(json!({ flag: typo.clone() })))), field, "{flag}={typo}");
        }
    }
    assert_eq!(parse_overrides(&args(json!({ "budget": "", "uses": null }))).unwrap(), Overrides::default());
    assert_eq!(parse_overrides(&args(json!({ "spend-tokens": "1e3" }))).unwrap().spend_tokens, Some(1000.0));
}

#[test]
fn rate_and_quota_a_string_is_trimmed_anything_else_passes_through() {
    let o = parse_overrides(&args(json!({ "rate": "  60/min  ", "quota": " 1000/day " }))).unwrap();
    assert_eq!((o.rate, o.quota), (Some(json!("60/min")), Some(json!("1000/day"))));
    let o = parse_overrides(&args(json!({ "rate": 60, "quota": { "n": 1 } }))).unwrap();
    assert_eq!((o.rate, o.quota), (Some(json!(60)), Some(json!({ "n": 1 }))));
}

#[test]
fn lists_are_split_and_methods_upper_cased_routes_read_as_pairs_and_owner_fields_kept() {
    let o = parse_overrides(&args(json!({ "methods": "get, post", "paths": "/a/**,/b/**" }))).unwrap();
    assert_eq!(o.methods, Some(vec!["GET".into(), "POST".into()]));
    assert_eq!(o.paths, Some(vec!["/a/**".into(), "/b/**".into()]));
    assert_eq!(
        parse_overrides(&args(json!({ "route": "get,head:/repos/**" }))).unwrap().routes,
        Some(json!([{ "methods": ["GET", "HEAD"], "paths": ["/repos/**"] }]))
    );
    assert_eq!(
        parse_overrides(&args(json!({ "route": ["GET:/a", "POST:/b"] }))).unwrap().routes,
        Some(json!([{ "methods": ["GET"], "paths": ["/a"] }, { "methods": ["POST"], "paths": ["/b"] }]))
    );
    assert_eq!(parse_overrides(&args(json!({ "route": "no-colon" }))).unwrap().routes, Some(json!(["no-colon"])));
    assert_eq!(parse_overrides(&args(json!({ "approval": "auto" }))).unwrap().approval.as_deref(), Some("auto"));
    assert_eq!(parse_overrides(&args(json!({ "approval": "" }))).unwrap().approval, None);
    for (v, want) in [(json!(true), Some(true)), (json!("true"), Some(true)), (json!("yes"), None)] {
        assert_eq!(parse_overrides(&args(json!({ "infinite": v }))).unwrap().infinite, want);
    }
}

#[test]
fn an_unknown_key_is_refused_naming_it_and_every_known_key_is_read() {
    assert_eq!(field_of(parse_overrides(&args(json!({ "hosts": ["evil.example"] })))), "hosts");
    for k in OVERRIDE_KEYS {
        // Every key on the list is accepted by name (its value may still be
        // refused, which is a different error).
        let r = parse_overrides(&args(json!({ k: "" })));
        assert!(r.is_ok(), "{k}");
    }
}

#[test]
fn the_shared_decision_builder_includes_overrides_only_when_there_are_some() {
    let item = describe(PendingKind::Request, &json!({ "id": "ap_x", "summary": "GET /x", "created_at": "2026-01-01T00:00:00.000Z" }));
    assert_eq!(decision(&item, true, None).body, json!({ "id": "ap_x", "granted": true }));
    assert_eq!(decision(&item, false, Some(&Map::new())).body, json!({ "id": "ap_x", "granted": false }));
    let o = args(json!({ "budget": 5 }));
    let call = decision(&item, true, Some(&o));
    assert_eq!(call.path, "/v1/approvals");
    assert_eq!(call.body, json!({ "id": "ap_x", "granted": true, "overrides": { "budget": 5 } }));
}

#[test]
fn describe_gives_a_session_its_caution_and_narrowable_list_and_a_request_its_preview() {
    let s = describe(PendingKind::Session, &json!({ "id": "sr_1", "summary": "session for demo", "agent_reason_untrusted": "please", "created_at": "t", "proposal": { "cred": "demo" } }));
    assert_eq!(s.caution.as_deref(), Some(SESSION_CAUTION));
    assert_eq!(s.claim.as_deref(), Some("please"));
    assert_eq!(s.narrowable.len(), SESSION_NARROWABLE.len());
    assert!(s.narrowable.contains(&"ttl_minutes".to_string()));
    assert_eq!(s.owner_settable, vec!["approval", "infinite"]);
    assert_eq!(s.proposal, Some(json!({ "cred": "demo" })));
    assert_eq!(s.decide.path, "/v1/session-requests/decide");
    let r = describe(PendingKind::Request, &json!({ "id": "ap_1", "summary": "POST /x", "reason": "", "created_at": "t" }));
    assert_eq!(r.claim, None);
    assert_eq!(r.grant_id, Some(None));
    assert_eq!(r.preview, Some(Value::Null));
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!((v["grant_id"].clone(), v["preview"].clone(), v["decide"]["idField"].clone()), (Value::Null, Value::Null, json!("id")));
    assert!(v.get("proposal").is_none());
}

#[test]
fn everything_waiting_is_listed_oldest_first_and_a_missing_source_is_empty() {
    let items = fetch_pending(|path| match path {
        "/v1/approvals" => Some(vec![json!({ "id": "ap_2", "created_at": "2026-01-02T00:00:00.000Z" })]),
        "/v1/session-requests" => Some(vec![json!({ "id": "sr_1", "created_at": "2026-01-01T00:00:00.000Z" })]),
        _ => None,
    });
    let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, vec!["sr_1", "ap_2"]);
    let only = fetch_pending(|path| (path == "/v1/approvals").then(|| vec![json!({ "id": "ap_1" })]));
    assert_eq!(only.len(), 1);
}

#[test]
fn an_approved_session_is_remembered_only_when_it_carries_a_token() {
    let s = describe(PendingKind::Session, &json!({ "id": "sr_1" }));
    let r = describe(PendingKind::Request, &json!({ "id": "ap_1" }));
    let mut seen = Vec::new();
    let answered = json!({ "session": { "token": "avs1.abc.def", "session_id": "abc" } });
    assert!(collect_approved(&s, &answered, |v| seen.push(v.clone())).is_some());
    assert_eq!(seen.len(), 1);
    assert!(collect_approved(&r, &answered, |_| panic!("a request is not a session")).is_none());
    assert!(collect_approved(&s, &json!({ "session": {} }), |_| panic!("no token")).is_none());
}

#[test]
fn what_a_human_granted_is_said_in_their_own_words() {
    assert_eq!(
        describe_granted(&json!({ "cred": "demo", "methods": ["GET", "POST"], "paths": ["/a", "/b"], "budget": 50, "uses": 1, "approval": "each", "grant_ttl_minutes": 10, "ttl_minutes": 30 })),
        "session for demo · GET,POST · /a /b · 50 requests · 1-use placeholder · approval each · grant ends after 10 min · lasts 30 min"
    );
    assert_eq!(describe_granted(&json!({ "cred": "demo", "infinite": true, "ttl_minutes": 30 })), "session for demo · never expires");
}

#[test]
fn a_bulk_decision_list_is_held_to_one_narrow_shape() {
    let ok = json!([{ "id": "ap_1", "kind": "request", "granted": true }, { "id": "sr_1", "kind": "session", "granted": false, "overrides": {} }]);
    assert_eq!(check_decisions(&ok), None);
    let too_many: Vec<Value> = (0..26).map(|i| json!({ "id": format!("ap_{i}"), "kind": "request", "granted": true })).collect();
    for (bad, why) in [
        (json!({}), "decisions must be a list"),
        (json!([]), "nothing was selected"),
        (Value::Array(too_many), "too many at once"),
        (json!(["x"]), "each decision must be an object"),
        (json!([{ "id": "a", "kind": "request", "granted": true, "all": true }]), "cannot carry"),
        (json!([{ "kind": "request", "granted": true }]), "needs an id"),
        (json!([{ "id": "a", "kind": "everything", "granted": true }]), "unknown kind"),
        (json!([{ "id": "a", "kind": "request", "granted": "false" }]), "true or false"),
        (json!([{ "id": "a", "kind": "request", "granted": true, "overrides": [] }]), "must be an object"),
        (json!([{ "id": "a", "kind": "request", "granted": true }, { "id": "a", "kind": "request", "granted": false }]), "appears twice"),
    ] {
        let got = check_decisions(&bad).unwrap_or_default();
        assert!(got.contains(why), "{bad}: {got}");
    }
}
