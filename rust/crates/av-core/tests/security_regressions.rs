use av_core::{model_usage::*, payload::*, policy::*, profiles::*, scrub::*, secret::SecretString};
use serde_json::{json, Value as V};
#[test]
fn budget_reader_all_legacy_shapes() {
    assert_eq!(budget_limit(None), BudgetLimit::Unlimited);
    for budget in [
        json!(null),
        json!({"limit":null}),
        json!({"limit":""}),
        json!({"limit":"1e3"}),
        json!({"limit":5.5}),
        json!({"limit":"05"}),
        json!({"limit":" 5"}),
        json!({"limit":true}),
        json!({"limit":[5]}),
        json!({"limit":9007199254740992u64}),
        json!({"unit":"usd","limit":5}),
        json!({"invalid":true,"limit":5}),
        json!({"burst":9,"limit":5}),
        json!(5),
        json!({"limit":"lots"}),
        json!({"limit":"Infinity"}),
        json!({"limit":-1}),
    ] {
        let b: Checked<Budget> = serde_json::from_value(budget.clone()).unwrap();
        assert_eq!(budget_limit(Some(&b)), BudgetLimit::Unreadable, "{budget}");
    }
    for n in [0, 50] {
        for value in [json!(n), json!(n.to_string())] {
            let b = serde_json::from_value(json!({"unit":"requests","limit":value})).unwrap();
            assert_eq!(budget_limit(Some(&b)), BudgetLimit::Limit(n));
        }
    }
    let b = serde_json::from_value(json!({"unit":"requests"})).unwrap();
    assert_eq!(budget_limit(Some(&b)), BudgetLimit::Unlimited);
}
#[test]
fn path_parsing_hardening_and_ordinary_wire_controls() {
    let policy:Policy=serde_json::from_value(json!({"hosts":["api.github.com"],"methods":["GET","POST","DELETE"],"paths":["/**"],"deny_paths":["/user/keys","/user/keys/**","/user/gpg_keys","/repos/*/*/hooks","/repos/*/*/keys","/settings/**","/api/admin.*"]})).unwrap();
    let allows = |path: &str| {
        evaluate_http(
            &policy,
            &HttpTarget {
                method: Some("POST"),
                host: "api.github.com",
                path,
            },
        )
        .is_ok()
    };
    assert!(allows("/repos/o/r/issues"));
    for base in [
        "/user/keys",
        "/user/gpg_keys",
        "/repos/o/r/hooks",
        "/repos/o/r/keys",
        "/settings/x",
        "/api/admin.users",
    ] {
        assert!(!allows(base));
        for enc in ["%09", "%0a", "%0d", "%23", "%3Fz=1"] {
            assert!(!allows(&format!("{base}{enc}")));
        }
    }
    for path in [
        "/repos/%252e%252e/admin",
        "/repos/%25252e%25252e/admin",
        "/user/%25256beys",
        "/user%2Fkeys",
        "/a%5Cb",
        "/%09%09%09",
    ] {
        assert!(normalize_path(path).is_err());
    }
    for path in [
        "/v1beta/models/gemini-pro:generateContent",
        "/@scope/package",
        "/Products(1)/Name",
        "/a,b;c=d/e+f/g&h/i$j/k'l/m!n/o*p/q(r)s",
    ] {
        assert_eq!(encode_path_for_wire(path), path);
    }
    for (raw, wire) in [
        ("/a b", "/a%20b"),
        ("/a?b", "/a%3Fb"),
        ("/a#b", "/a%23b"),
        ("/a%b", "/a%25b"),
        ("/a\"b", "/a%22b"),
        ("/café", "/caf%C3%A9"),
    ] {
        assert_eq!(encode_path_for_wire(raw), wire);
    }
    assert_eq!(normalize_path("/repos/%2e%2e/admin").unwrap(), "/admin");
}
#[test]
fn health_invalid_metadata_and_ordinary_controls() {
    let github = get_profile("github").unwrap();
    let expiry = |s: &str| {
        extract_health(
            Some(github),
            &[("GitHub-Authentication-Token-Expiration".into(), s.into())],
        )
    };
    for raw in [
        "not-a-date",
        "2027-02-31 00:00:00 UTC",
        "yesterday",
        "2027-02-30T00:00:00+01:00",
        "2027-02-29T00:00:00-05:00",
        "2027-04-31T12:00:00+0200",
        "2027-01-31T25:00:00+01:00",
        "2027-01-31T23:59:60+01:00",
        "2027-01-31T00:00:00+99:99",
        "2027-01-31T00:00:00+14:01",
        "2027-01-31T00:00:00-15:00",
        "2027-01-31T00:00:00+01:60",
        "0000-01-01T00:00:00+01:00",
    ] {
        assert!(expiry(raw).is_none(), "{raw}");
    }
    for (raw, expected) in [
        ("2027-01-31T00:00:00+01:00", "2027-01-30T23:00:00.000Z"),
        ("2027-01-31T00:00:00-0530", "2027-01-31T05:30:00.000Z"),
        ("2027-01-01T00:30:00+01:00", "2026-12-31T23:30:00.000Z"),
    ] {
        assert_eq!(
            expiry(raw).unwrap().observed_expires_at.as_deref(),
            Some(expected)
        );
    }
    for value in ["nope", "-1", "1.5", "1e2"] {
        assert!(extract_health(
            Some(github),
            &[("x-ratelimit-remaining".into(), value.into())]
        )
        .is_none());
    }
    let headers = vec![
        ("x-oauth-scopes".into(), "repo".into()),
        ("x-oauth-scopes".into(), "read:org".into()),
    ];
    assert_eq!(
        extract_health(Some(github), &headers)
            .unwrap()
            .scopes
            .unwrap(),
        vec!["repo", "read:org"]
    );
    for profile in PROFILES.iter().filter(|p| p.kind != "github") {
        assert!(extract_health(Some(profile), &headers).is_none());
    }
    assert!(extract_health(
        Some(github),
        &[("date".into(), "Sun, 31 Jan 2027 00:00:00 GMT".into())]
    )
    .is_none());
}
#[test]
fn model_meter_missing_usage_and_overflow_controls() {
    let meter = Meter {
        metered: true,
        model: Some("gpt-4.1-mini".into()),
        input_estimate: 1,
        max_output: 1,
        ..Default::default()
    };
    let reserved = reservation_for("openai", &meter, ReservationOptions { usd: true }).unwrap();
    assert_eq!(
        reserved,
        Charge {
            tokens: 2,
            usd_micros: 2
        }
    );
    assert_eq!(
        charge_for("openai", &meter, &reserved, None).unwrap(),
        reserved
    );
    assert_eq!(
        charge_for(
            "openai",
            &meter,
            &reserved,
            Some(&Usage {
                input_tokens: 100,
                output_tokens: 100
            })
        )
        .unwrap(),
        Charge {
            tokens: 200,
            usd_micros: 200
        }
    );
    assert!(reservation_for(
        "openai",
        &Meter {
            input_estimate: MAX_SAFE_INTEGER,
            ..meter.clone()
        },
        Default::default()
    )
    .is_err());
    for kind in METERED_KINDS {
        assert!(usage_from_body(kind, &json!({})).is_none());
    }
    for raw in ["test-secret-marker", "null", "[]", "true", ""] {
        let err = meter_request(
            "openai",
            &MeterInput {
                method: Some("POST"),
                path: Some("/v1/responses"),
                content_type: Some("application/json"),
                body: Some(raw.as_bytes()),
            },
        )
        .unwrap_err();
        assert_eq!(err.extra.rule.as_deref(), Some("spend_unparseable"));
        assert!(!err.detail.contains("test-secret-marker"));
    }
    for (kind, path) in [
        ("openai", "/v1/chat/completions"),
        ("anthropic", "/v1/messages"),
        ("google-genai", "/v1/models/x:generateContent"),
    ] {
        for value in [
            V::Null,
            json!(0),
            json!(-1),
            json!(1.5),
            json!("500"),
            json!(true),
            json!(9007199254740992u64),
        ] {
            let body = if kind == "google-genai" {
                json!({"generationConfig":{"maxOutputTokens":value}})
            } else {
                json!({"max_tokens":value})
            }
            .to_string();
            let m = meter_request(
                kind,
                &MeterInput {
                    method: Some("POST"),
                    path: Some(path),
                    content_type: Some("application/json"),
                    body: Some(body.as_bytes()),
                },
            )
            .unwrap();
            assert_eq!(
                m.max_output,
                DEFAULT_OUTPUT.iter().find(|(k, _)| *k == kind).unwrap().1
            );
        }
    }
}
#[test]
fn graphql_malformed_documents_and_ordinary_controls() {
    let rules = GraphqlRules {
        operations: vec![GraphqlOperation::Query],
        deny_fields: Some(vec!["createDeployKey".into()]),
    };
    scan_graphql("query A($x: [Int!]! = [1,2]) @skip(if:false) { user(id:$x) { ...F ... on User { name } } } fragment F on User { x: id }",&rules).unwrap();
    scan_graphql("{ a(text:\"mutation createDeployKey\", block:\"\"\" mutation { createDeployKey } \"\"\") } # mutation{bad}",&rules).unwrap();
    for document in [
        "query",
        "query A {}",
        "query A { a( }",
        "query A { a } garbage",
        "{ a(text:\"unterminated) }",
        "fragment X on User {a}",
        "{ ... }",
        "query($x:) {a}",
        "query { a(arg: [1) }",
    ] {
        assert_eq!(
            scan_graphql(document, &rules)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some("graphql_unparseable"),
            "{document}"
        );
    }
    assert!(scan_graphql(&format!("{}{}", "{a".repeat(65), "}".repeat(65)), &rules).is_err());
    assert!(scan_graphql(&" ".repeat(300 * 1024), &rules).is_err());
}
#[test]
fn scrub_extra_patterns_validation_additivity_and_controls() {
    for source in [
        "(a+)+b",
        ".*",
        "a",
        "[a-z]+",
        "abc.*def+",
        "abc\\1",
        "abc(?=x)",
        "abc$",
        "abc[A-Z]{257}",
        "abc|",
        "abc|xy",
        "disk-usage_by_repository_over_time",
        "abc[[]",
        "abc\n[A-Z]{4}",
        "abc[A-Z]{3,1}",
        "abc[^Q]{0,256}[^Q]{256}Q",
    ] {
        assert!(compile_scrub_pattern(source).is_err(), "{source}");
    }
    for source in [
        "abc_[0-9]{1,64}",
        "abc\\d{2,20}",
        "abc\\.xyz|def_[A-Z]{0,40}",
        "acme_[A-Za-z0-9]{20,80}",
        "abc[\\d]{4}",
        "abc\\S{253}\\S{0,256}",
    ] {
        assert!(compile_scrub_pattern(source).is_ok(), "{source}");
    }
    assert!(Scrubber::new(
        &[],
        &ScrubberOptions {
            extra_patterns: vec![ExtraPattern {
                name: "bad".into(),
                source: "anything.*".into()
            }],
            ..Default::default()
        }
    )
    .is_err());
    let mut scrub = Scrubber::new(
        &[ScrubEntry {
            secret: SecretString::from("test-secret-fake".to_owned()),
            label: "fake".into(),
            replacement: None,
            always: false,
        }],
        &ScrubberOptions {
            extra_patterns: vec![ExtraPattern {
                name: "acme".into(),
                source: "acme_[A-Za-z0-9]{20,80}".into(),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let r = scrub.scrub(&format!(
        "acme_{} test-secret-fake ghp_{}",
        "Z".repeat(40),
        "Q".repeat(30)
    ));
    assert_eq!(r.redactions, 3);
    assert!(scrub.derived_seen().contains("acme"));
    assert!(scrub.derived_seen().contains("github"));
    for line in SCRUB_PATTERN_CORPUS {
        assert_eq!(scrub.scrub(line).text, *line);
    }
    let mut stream = scrub.stream();
    let mut out = stream.push("we use acme_ tooling here; ");
    for _ in 0..2000 {
        out += &stream.push("ordinary text that goes on and on. ");
    }
    assert!(out.len() > 60000);
    out += &stream.flush();
    assert!(out.starts_with("we use acme_ tooling here; "));
    assert_eq!(stream.redactions(), 0);
}
#[test]
fn integer_json_spellings_follow_js_number_semantics() {
    let p: Policy = serde_json::from_str(
        r#"{"max_concurrent":1.0,"budget":{"limit":5.0},"rate":{"count":2.0,"per":"second"}}"#,
    )
    .unwrap();
    assert!(validate(&p, &Default::default()).is_empty());
    assert_eq!(budget_limit(p.budget.as_ref()), BudgetLimit::Limit(5));
    assert_eq!(budget_integer(&json!(1.0)), Some(1));
    assert_eq!(av_core::canon::canonicalize(&json!(1.0)).unwrap(), "1");
    assert_eq!(av_core::canon::canonicalize(&json!(-0.0)).unwrap(), "0");
    assert!(av_core::canon::canonicalize(&json!(1.5)).is_err());
    assert_eq!(
        usage_from_body(
            "openai",
            &json!({"usage":{"input_tokens":1.0,"output_tokens":2.0}})
        ),
        Some(Usage {
            input_tokens: 1,
            output_tokens: 2
        })
    );
}
#[test]
fn invalid_policy_fields_poison_every_layer_order() {
    let values = [
        ("kind", json!(1)),
        ("hosts", json!("h")),
        ("methods", json!(["TRACE"])),
        ("paths", json!([1])),
        ("deny_paths", V::Null),
        ("approval", json!("each-time")),
        ("sql_profile", json!("write")),
        ("mode", json!("shell")),
        ("databases", json!([1])),
        ("rcpt", json!(false)),
        ("commands", json!([null])),
        ("graphql", json!(false)),
        ("stream_bodies", json!("true")),
        ("placeholder_policy", json!({"max_uses":0})),
        ("budget", json!({"unit":"tokens","limit":1})),
        ("spend", json!({"tokens":"5"})),
        ("rate", json!({"count":"5","per":"minute"})),
        ("quota", json!({"count":1,"window":"minute"})),
        ("max_concurrent", json!(1.5)),
        ("routes", json!([{"methods":["GET"],"paths":[]}])),
        (
            "payload",
            json!({"json":{"/x":{"required":true,"absent":true}}}),
        ),
    ];
    let good = Policy::default();
    for (field, value) in values {
        let raw = json!({field:value});
        assert!(
            validate_json(&raw, &Default::default())
                .iter()
                .any(|p| p.field == field),
            "{raw}"
        );
        let bad: Policy = serde_json::from_value(raw).unwrap();
        for layers in [[Some(&bad), Some(&good)], [Some(&good), Some(&bad)]] {
            let effective = intersect(&layers);
            assert!(
                !validate(&effective, &Default::default()).is_empty(),
                "{field}"
            );
            assert!(
                evaluate_http(
                    &effective,
                    &HttpTarget {
                        host: "example.test",
                        path: "/",
                        method: Some("GET")
                    }
                )
                .is_err(),
                "{field}"
            );
        }
    }
}
#[test]
fn explicit_null_schema_members_stay_invalid() {
    for raw in [
        json!({"budget":{"limit":null}}),
        json!({"budget":{"unit":null}}),
        json!({"spend":{"tokens":null}}),
        json!({"placeholder_policy":{"ttl":null}}),
        json!({"payload":{"query":null}}),
        json!({"payload":{"query":{"x":{"required":null}}}}),
        json!({"payload":{"query":{"x":{"min":null}}}}),
        json!({"payload":{"graphql":{"operations":["query"],"deny_fields":null}}}),
    ] {
        let policy: Policy = serde_json::from_value(raw.clone()).unwrap();
        assert!(!validate(&policy, &Default::default()).is_empty(), "{raw}");
        assert!(
            evaluate_http(
                &policy,
                &HttpTarget {
                    host: "example.test",
                    path: "/",
                    method: Some("GET")
                }
            )
            .is_err(),
            "{raw}"
        );
    }
    let ordinary: Policy = serde_json::from_value(
        json!({"graphql":{"legacy":null},"payload":{"query":{"x":{"one_of":[null,"ok"]}}}}),
    )
    .unwrap();
    assert!(validate(&ordinary, &Default::default()).is_empty());
}
#[test]
fn js_budget_absent_null_and_intersection_vectors() {
    let state = |budget: Option<&Checked<Budget>>| match budget_limit(budget) {
        BudgetLimit::Unlimited => json!({"kind":"unlimited"}),
        BudgetLimit::Unreadable => json!({"kind":"unreadable"}),
        BudgetLimit::Limit(n) => json!({"kind":"limit","limit":n}),
    };
    let rows: V = serde_json::from_str(include_str!("fixtures/budget-vectors.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let budget: Checked<Budget> = serde_json::from_value(row["budget"].clone()).unwrap();
        assert_eq!(state(Some(&budget)), row["state"], "{row}");
        for case in row["intersections"].as_array().unwrap() {
            let layers: Vec<Policy> = serde_json::from_value(case["layers"].clone()).unwrap();
            let effective = intersect(&layers.iter().map(Some).collect::<Vec<_>>());
            assert_eq!(state(effective.budget.as_ref()), case["state"], "{case}");
            assert_eq!(
                serde_json::to_value(effective.budget).unwrap(),
                case["budget"],
                "{case}"
            );
        }
    }
}
