//! Pure gateway-core cases use the same public av-core primitives as the pipeline.
#![forbid(unsafe_code)]
use av_core::{
    policy,
    scrub::{ScrubEntry, Scrubber},
    substitute as sub,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
const SECRET: &str = "test-secret-gateway-core-0123456789abcdef";
fn scrubber() -> Scrubber {
    Scrubber::new(
        &[ScrubEntry {
            secret: SECRET.to_owned().into(),
            label: "a".into(),
            replacement: Some("[x]".into()),
            always: true,
        }],
        &Default::default(),
    )
    .unwrap()
}
fn percent(s: &str, upper: bool) -> String {
    s.bytes()
        .map(|b| {
            if upper {
                format!("%{b:02X}")
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}
fn wrapped(s: &str, width: usize, br: &str) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|b| std::str::from_utf8(b).unwrap())
        .collect::<Vec<_>>()
        .join(br)
}
fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}
fn mixed_hex() -> String {
    let mut n = 0;
    hex(SECRET)
        .chars()
        .map(|c| {
            if ('a'..='f').contains(&c) {
                n += 1;
                if n % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect()
}
#[test]
fn escaped_and_wrapped_secret_shapes_are_redacted_with_ordinary_controls() {
    let b64 = STANDARD.encode(SECRET);
    let mixed = mixed_hex();
    let json_mixed: String = SECRET
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 1 {
                format!("\\u{:04x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect();
    let cases = vec![
        (
            "partialJsonEscape",
            format!(r#"{{"t":"\u0074{}"}}"#, &SECRET[1..]),
        ),
        ("mixedJsonEscape", format!(r#"{{"t":"{json_mixed}"}}"#)),
        ("fullPercentUpper", percent(SECRET, true)),
        ("fullPercentLower", percent(SECRET, false)),
        ("upperHex", hex(SECRET).to_uppercase()),
        (
            "wrappedB64",
            format!(
                "-----BEGIN-----\n{}\n-----END-----",
                wrapped(&b64, 16, "\n")
            ),
        ),
        ("wrappedB64Crlf", wrapped(&b64, 16, "\r\n")),
        (
            "wrappedB64JsonEscaped",
            format!(r#"{{"blob":"{}"}}"#, wrapped(&b64, 16, "\\n")),
        ),
        ("b64At4", wrapped(&b64, 4, "\n")),
        ("b64At8", wrapped(&b64, 8, "\n")),
        (
            "b64At12",
            format!("body:\n{}\nend", wrapped(&b64, 12, "\n")),
        ),
        ("b64At8Crlf", wrapped(&b64, 8, "\r\n")),
        ("b64Indented", format!("  {}", wrapped(&b64, 8, "\n  "))),
        ("b64TrailingSpace", wrapped(&b64, 8, " \n")),
        (
            "b64At8JsonEscaped",
            format!(r#"{{"blob":"{}"}}"#, wrapped(&b64, 8, "\\n")),
        ),
        ("mixedHex", format!("id={mixed};")),
        ("mixedHexWrapped", wrapped(&mixed, 10, "\n")),
        ("mixedHexWrapped8Crlf", wrapped(&mixed, 8, "\r\n")),
    ];
    for (name, input) in cases {
        let out = scrubber().scrub(&input);
        assert!(
            out.redactions > 0 && out.text.contains("[x]"),
            "{name}: {}",
            out.text
        );
        assert!(!out.text.contains(SECRET), "{name}");
        let joined = out
            .text
            .replace("\\n", "")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        assert!(
            !String::from_utf8_lossy(&STANDARD.decode(joined).unwrap_or_default()).contains(SECRET),
            "{name}"
        );
        assert!(!out.text.contains(&percent(SECRET, true)), "{name}");
    }
    ordinary_escaped_wrapped_and_partial_text_is_unchanged();
}
#[test]
fn ordinary_escaped_wrapped_and_partial_text_is_unchanged() {
    let texts = vec![
        r#"{"html":"\u003cb\u003ebold\u003c/b\u003e","path":"/a%20b/c%2Fd"}"#.into(),
        "line one\nline two\r\nline three\n".into(),
        wrapped(
            &STANDARD.encode("a perfectly ordinary blob of bytes that is not a secret at all"),
            16,
            "\n",
        ),
        format!("{}\n{}", &SECRET[..10], &SECRET[10..20]),
        "The quick brown fox\njumps over the lazy dog.\nconfiguration\nmanagement\n".into(),
        "a\nb\nc\nde\nfg\n".into(),
        wrapped(
            &STANDARD.encode("a perfectly ordinary blob of bytes that is not a secret at all"),
            8,
            "\n",
        ),
        "sha: 9F86d081884C7d659A2feaa0C55aD015a3BF4f1B2b0B822cd15D6c15B0F00A08".into(),
        "DeadBeef CafeBabe 0xDEADbeef\nFACEfeed\n".into(),
        wrapped(&hex(&SECRET[..12]).to_uppercase(), 4, "\n"),
    ];
    for text in texts {
        let out = scrubber().scrub(&text);
        assert_eq!(out.text, text);
        assert_eq!(out.redactions, 0);
    }
}
#[test]
fn percent_secret_and_derived_token_straddling_holdback_are_not_emitted_in_halves() {
    let mut sc = scrubber();
    let hold = sc.overlap();
    let mut stream = sc.stream();
    let enc = percent(SECRET, true);
    let mut out = stream.push(&format!("before {}", &enc[..40]));
    let second = format!("{} after ", &enc[40..]);
    out += &stream.push(&format!("{second}{}", ".".repeat(hold - second.len())));
    out += &stream.push(&".".repeat(400));
    out += &stream.flush();
    assert!(!out.contains(&enc));
    assert!(out.contains("before [x] after"));
    assert!(!out.contains(SECRET));
    let token = format!("ghp_{}", "A1b2C3d4E5".repeat(4));
    let mut sc = Scrubber::new(&[], &Default::default()).unwrap();
    let mut stream = sc.stream();
    let mut out = stream.push(&format!(": {}", &token[..10]));
    out += &stream.push(&format!("{}{}", &token[10..], " ".repeat(29)));
    out += &stream.push(&format!(" and then the stream goes on {}", ".".repeat(200)));
    out += &stream.flush();
    assert!(!(out.contains(&token[..10]) && out.contains(&token[10..])));
    assert!(out.contains("[[av:derived]]"));
    let text = format!(
        "the sk- prefix and gh tokens, ghp_ alone, a disk-usage_by_repository_over_time report {}",
        ".".repeat(300)
    );
    let mut sc = Scrubber::new(&[], &Default::default()).unwrap();
    let mut stream = sc.stream();
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(37) {
        out += &stream.push(std::str::from_utf8(chunk).unwrap());
    }
    out += &stream.flush();
    assert_eq!(out, text);
}
#[test]
fn each_wrapped_blob_is_searched_without_changing_neighbors() {
    let ordinary = wrapped(
        &STANDARD.encode("an ordinary blob that is long enough to search"),
        8,
        "\n",
    );
    let before = format!("first:\n{ordinary}\n\nsecond:\n");
    let after = format!("third:\n{ordinary}\n");
    let out = scrubber().scrub(&format!(
        "{before}{}\n\n{after}",
        wrapped(&STANDARD.encode(SECRET), 8, "\n")
    ));
    assert_eq!(out.redactions, 1);
    assert!(out.text.starts_with(&before));
    assert!(out.text.ends_with(&after));
    assert!(!out.text.contains(SECRET));
    ordinary_escaped_wrapped_and_partial_text_is_unchanged();
}
#[test]
fn wrapped_and_mixed_case_views_scale_linearly_on_large_ordinary_bodies() {
    use std::time::Instant;
    let shapes: [fn(usize) -> String; 4] = [
        |n| "ab\n".repeat(n),
        |n| "aB".repeat(n * 2),
        |n| "The quick brown fox\n".repeat(n / 5),
        |n| format!("ghp {}", "x\n".repeat(n)),
    ];
    let mut sc = scrubber();
    for shape in shapes {
        assert_eq!(sc.scrub(&shape(1_000_000)).redactions, 0);
        let small = shape(30_000);
        let large = shape(240_000);
        let mut times = [f64::INFINITY; 2];
        for _ in 0..3 {
            for (i, text) in [&small, &large].iter().enumerate() {
                let start = Instant::now();
                assert_eq!(sc.scrub(text).redactions, 0);
                times[i] = times[i].min(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        assert!(
            times[1] / times[0].max(0.5) < 40.0,
            "8x input ratio {}",
            times[1] / times[0].max(0.5)
        );
    }
}
#[test]
fn path_parser_refuses_reencoded_separators_but_preserves_ordinary_paths_and_literal_percent() {
    for path in [
        "/allowed/x%255c..%255c..%255cadmin",
        "/a/%255cb",
        "/a/%252fb",
    ] {
        assert_eq!(
            policy::normalize_path(path)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some("path_ambiguous_separator")
        );
    }
    assert_eq!(
        policy::normalize_path("/a/%25255cb")
            .unwrap_err()
            .extra
            .rule
            .as_deref(),
        Some("path_ambiguous_encoding")
    );
    for (path, normal, wire) in [
        ("/a/b%20c", "/a/b c", "/a/b%20c"),
        (
            "/v1beta/models/gemini-pro:generateContent",
            "/v1beta/models/gemini-pro:generateContent",
            "/v1beta/models/gemini-pro:generateContent",
        ),
        ("/repos/o/r/%2e%2e/x", "/repos/o/x", "/repos/o/x"),
        ("/files/100%25", "/files/100%", "/files/100%25"),
        ("/q/50%25%20off", "/q/50% off", "/q/50%25%20off"),
    ] {
        let got = policy::normalize_path(path).unwrap();
        assert_eq!(got, normal);
        assert_eq!(policy::encode_path_for_wire(&got), wire);
    }
    for path in [
        "/%2561dmin%25".into(),
        "/caf%25C3%25A9%25".into(),
        format!("/user/{}6beys", "%25".repeat(12)),
    ] {
        let e = policy::normalize_path(&path).unwrap_err();
        assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
        assert_eq!(e.extra.rule.as_deref(), Some("path_ambiguous_encoding"));
    }
    assert!(policy::normalize_path("/a%zz")
        .unwrap_err()
        .detail
        .contains("invalid percent-escape"));
}
fn intersection(a: Value, b: Value) -> Value {
    let a: policy::Policy = serde_json::from_value(a).unwrap();
    let b: policy::Policy = serde_json::from_value(b).unwrap();
    serde_json::to_value(policy::intersect(&[Some(&a), Some(&b)])).unwrap()
}
#[test]
fn rate_intersections_never_widen_and_invalid_units_are_refused() {
    for (a, b) in [
        (
            json!({"count":10,"per":"minute"}),
            json!({"count":100,"per":"hour"}),
        ),
        (
            json!({"count":100,"per":"hour"}),
            json!({"count":10,"per":"minute"}),
        ),
    ] {
        let r = intersection(json!({"rate":a}), json!({"rate":b}))["rate"].clone();
        let count = r["count"].as_f64().unwrap();
        let per = match r["per"].as_str().unwrap() {
            "minute" => 60_000.0,
            "hour" => 3_600_000.0,
            _ => panic!("unknown unit"),
        };
        assert!(count * 3_600_000.0 / per <= 100.0);
        assert!(count * 60_000.0 / per <= 10.0);
    }
    for (a, b, want) in [
        (
            json!({"rate":{"count":10,"per":"minute"}}),
            json!({"rate":{"count":5,"per":"minute"}}),
            json!({"count":5,"per":"minute"}),
        ),
        (
            json!({"rate":{"count":10,"per":"minute"}}),
            json!({}),
            json!({"count":10,"per":"minute"}),
        ),
        (
            json!({"rate":{"count":60,"per":"second"}}),
            json!({"rate":{"count":100,"per":"minute"}}),
            json!({"count":100,"per":"minute"}),
        ),
        (
            json!({"rate":{"count":5,"per":"minute"}}),
            json!({"rate":{"count":9,"per":"fortnight"}}),
            json!({"count":9,"per":"fortnight"}),
        ),
    ] {
        assert_eq!(intersection(a, b)["rate"], want);
    }
    let bad: policy::Policy =
        serde_json::from_value(json!({"rate":{"count":9,"per":"fortnight"}})).unwrap();
    assert_eq!(
        policy::evaluate_http(
            &bad,
            &policy::HttpTarget {
                method: Some("GET"),
                host: "example.test",
                path: "/"
            }
        )
        .unwrap_err()
        .extra
        .rule
        .as_deref(),
        Some("rate_invalid")
    );
    let policy = policy::grant_policy_from_input(
        &json!({"rate":"5/sec"}),
        &policy::GrantPolicyOptions {
            ceiling: policy::GrantCeiling::Hosts(vec!["example.test".into()]),
            defaults: true,
            profile: None,
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(policy).unwrap()["rate"],
        json!({"count":5,"per":"second"})
    );
}
#[test]
fn lint_accepts_valid_enforced_rate_concurrency_and_budget_limits() {
    for extra in [
        json!({"max_concurrent":2}),
        json!({"rate":{"count":1,"per":"minute"}}),
        json!({}),
    ] {
        let mut p = json!({"hosts":["h"],"budget":{"unit":"requests","limit":5}});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        let policy = serde_json::from_value(p).unwrap();
        let lint = policy::lint(&policy, &Default::default());
        assert!(!lint
            .iter()
            .any(|p| p.rule == "max_concurrent" || p.rule == "rate"));
    }
}
fn request(body: String) -> sub::ProxyRequest {
    sub::ProxyRequest {
        method: "POST".into(),
        path: "/".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: Some(body.into_bytes()),
        ..Default::default()
    }
}
#[test]
fn json_duplicate_pointer_and_basic_header_substitution_use_the_parser_selected_position() {
    let ph = "av1.PLACEHOLDER";
    let raw = format!(r#"{{"a/b":{{"t":"x"}},"k":"first","k":"{ph}","arr":["{ph}"]}}"#);
    let req = request(raw.clone());
    for (pointer, secret, expected) in [
        (
            "/k",
            "S\"1",
            raw.replace(&format!(r#""k":"{ph}""#), r#""k":"S\"1""#),
        ),
        (
            "/arr/0",
            "S2",
            raw.replace(&format!(r#"["{ph}"]"#), r#"["S2"]"#),
        ),
    ] {
        let loc =
            serde_json::from_value(json!({"region":"json","pointer":pointer,"encoding":"raw"}))
                .unwrap();
        let out = sub::apply(&req, &loc, ph, &secret.to_owned().into()).unwrap();
        assert_eq!(out.body.unwrap(), expected.as_bytes());
    }
    let req = sub::ProxyRequest {
        headers: vec![
            ("Authorization".into(), "Bearer x".into()),
            (
                "authorization".into(),
                format!("Basic {}", STANDARD.encode(format!("user:{ph}"))),
            ),
        ],
        ..Default::default()
    };
    let loc =
        serde_json::from_value(json!({"region":"basic","part":"pass","index":1,"encoding":"raw"}))
            .unwrap();
    let out = sub::apply(&req, &loc, ph, &"test-secret-basic".to_owned().into()).unwrap();
    assert_eq!(out.headers[0].1, "Bearer x");
    assert_eq!(
        out.headers[1].1,
        format!("Basic {}", STANDARD.encode("user:test-secret-basic"))
    );
}
#[test]
fn shadowed_placeholder_and_unsubstituted_nonce_are_detected_by_position() {
    use sub::Region;
    let ph = "av1.aaaaaaaaaaaa.a_key.aaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa";
    let req = request(format!(r#"{{"token":"{ph}","token":"{ph}"}}"#));
    let mut regions = sub::locate(&req)
        .occurrences
        .into_iter()
        .map(|o| o.location.region)
        .collect::<Vec<_>>();
    regions.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(regions, vec![Region::Body, Region::Json]);
    let req = request(format!(r#"{{"token":"{ph}","token":"SECRET"}}"#));
    assert_eq!(
        sub::unsubstituted(&req, &["aaaaaaaaaaaaaaaaaaaaaaaaaa".into()])
            .unwrap()
            .location
            .region,
        Region::Body
    );
    let control = request(r#"{"token":"SECRET","n":12345678901234567891}"#.into());
    assert!(sub::unsubstituted(&control, &["aaaaaaaaaaaaaaaaaaaaaaaaaa".into()]).is_none());
}

#[test]
fn repeated_header_values_keep_order_in_request_hash_but_header_names_do_not() {
    use av_core::canon::{request_hash, RequestHashInput};
    let credentials = vec!["g:f".to_string()];
    let hash = |headers: &[(String, String)]| {
        request_hash(&RequestHashInput {
            method: Some("POST"),
            host: Some("h"),
            path: Some("/x"),
            query: Some(""),
            body_sha256: Some(""),
            credentials: &credentials,
            headers,
        })
    };
    assert_ne!(
        hash(&[
            ("X-HTTP-Method-Override".into(), "POST".into()),
            ("X-HTTP-Method-Override".into(), "DELETE".into())
        ]),
        hash(&[
            ("X-HTTP-Method-Override".into(), "DELETE".into()),
            ("X-HTTP-Method-Override".into(), "POST".into())
        ])
    );
    assert_eq!(
        hash(&[("A".into(), "1".into()), ("b".into(), "2".into())]),
        hash(&[("B".into(), "2".into()), ("a".into(), "1".into())])
    );
}

// gateway-w2-policy.test.js: effective policies retain all ancestor sets.
fn intersect_all(layers: &[Value]) -> policy::Policy {
    let layers = layers
        .iter()
        .cloned()
        .map(|v| serde_json::from_value::<policy::Policy>(v).unwrap())
        .collect::<Vec<_>>();
    policy::intersect(&layers.iter().map(Some).collect::<Vec<_>>())
}
fn route_check(
    p: &policy::Policy,
    method: &str,
    path: &str,
) -> av_core::errors::Result<policy::HttpDecision> {
    policy::evaluate_http(
        p,
        &policy::HttpTarget {
            method: Some(method),
            host: "api.example.test",
            path,
        },
    )
}
fn route_denied(p: &policy::Policy, method: &str, path: &str, rule: &str) {
    let e = route_check(p, method, path).unwrap_err();
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some(rule));
}
#[test]
fn route_pairs_bind_methods_to_paths_and_every_inherited_set_applies() {
    let parent = json!({"routes":[{"methods":["GET"],"paths":["/repos/**"]},{"methods":["POST"],"paths":["/repos/*/issues"]}]});
    let effective = intersect_all(std::slice::from_ref(&parent));
    assert_eq!(
        route_check(&effective, "GET", "/repos/o/pulls")
            .unwrap()
            .route_rule,
        Some(0)
    );
    assert_eq!(
        route_check(&effective, "POST", "/repos/o/issues")
            .unwrap()
            .route_rule,
        Some(1)
    );
    route_denied(&effective, "POST", "/repos/o/pulls", "routes");
    let child = intersect_all(&[
        parent.clone(),
        json!({"routes":[{"methods":["POST"],"paths":["/repos/**"]}]}),
    ]);
    route_denied(&child, "POST", "/repos/o/pulls", "routes");
    route_denied(&child, "GET", "/repos/o/pulls", "routes");
    route_check(&child, "POST", "/repos/o/issues").unwrap();
    route_denied(
        &intersect_all(&[json!({"routes":[]})]),
        "GET",
        "/",
        "routes",
    );
    route_check(&intersect_all(&[json!({})]), "POST", "/").unwrap();
    route_denied(
        &intersect_all(&[parent, json!({"deny_paths":["/repos/o/issues"]})]),
        "POST",
        "/repos/o/issues",
        "deny_paths:0",
    );
}
#[test]
fn reused_effective_route_and_payload_sets_retain_every_ancestor_constraint() {
    let first = intersect_all(&[
        json!({"routes":[{"methods":["GET"],"paths":["/a/**"]}],"payload":{"query":{"first":{"required":true}}}}),
        json!({"routes":[{"methods":["GET"],"paths":["/a/b"]}],"payload":{"query":{"second":{"absent":true}}}}),
    ]);
    let first_json = serde_json::to_value(&first).unwrap();
    let reused = intersect_all(&[
        first_json.clone(),
        json!({"methods":["GET","POST"],"paths":["/**"]}),
    ]);
    let reused_json = serde_json::to_value(&reused).unwrap();
    assert!(reused_json.get("routes").is_none());
    assert!(reused_json.get("payload").is_none());
    assert_eq!(reused_json["payload_sets"], first_json["payload_sets"]);
    assert_eq!(reused_json["route_sets"], first_json["route_sets"]);
    assert_eq!(reused_json["payload_sets"].as_array().unwrap().len(), 2);
    route_check(&reused, "GET", "/a/b").unwrap();
    route_denied(&reused, "GET", "/a/c", "routes");
}
#[test]
fn malformed_stored_route_payload_and_unknown_approval_modes_fail_closed() {
    for layer in [
        json!({"route_sets":[null]}),
        json!({"payload_sets":[{"json":{"/x":{"min":null}}}]}),
    ] {
        assert!(!policy::validate_json(&layer, &Default::default()).is_empty());
        let p = serde_json::from_value(layer).unwrap();
        let e = route_check(&p, "GET", "/").unwrap_err();
        assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
        assert!(e.extra.rule.unwrap().ends_with("_invalid"));
    }
    for modes in [["unknown", "auto"], ["auto", "unknown"]] {
        let p = intersect_all(&[json!({"approval":modes[0]}), json!({"approval":modes[1]})]);
        assert!(policy::needs_approval(
            &p,
            &policy::ApprovalQuery {
                method: Some("GET"),
                first_use: false
            }
        ));
    }
}
#[test]
fn grant_creation_rejects_coercion_and_host_escape_but_allows_zero_limits() {
    let opts = policy::GrantPolicyOptions {
        ceiling: policy::GrantCeiling::Hosts(vec!["api.example.test".into()]),
        defaults: true,
        profile: None,
    };
    for spec in [
        json!({"budget":"5.5"}),
        json!({"max_concurrent":1.5}),
        json!({"quota":{"count":1,"window":"week"}}),
        json!({"spend_tokens":null}),
    ] {
        assert_eq!(
            policy::grant_policy_from_input(&spec, &opts)
                .unwrap_err()
                .extra
                .rule
                .as_deref(),
            Some("policy_invalid")
        );
    }
    assert_eq!(
        policy::grant_policy_from_input(&json!({"hosts":["evil.test"]}), &opts)
            .unwrap_err()
            .extra
            .rule
            .as_deref(),
        Some("credential_host")
    );
    let valid = policy::grant_policy_from_input(
        &json!({"budget":0,"spend_tokens":0,"spend_usd":0,"redirects":0}),
        &opts,
    )
    .unwrap();
    let v = serde_json::to_value(&valid).unwrap();
    assert_eq!(v["budget"]["limit"], 0);
    assert_eq!(v["spend"], json!({"tokens":0,"usd_micros":0}));
    assert!(policy::validate(&valid, &Default::default()).is_empty());
    let p = serde_json::from_value(
        json!({"routes":[{"methods":["POST"],"paths":["/**"]}],"budget":{"limit":1}}),
    )
    .unwrap();
    assert!(policy::lint(&p, &Default::default())
        .iter()
        .any(|p| p.rule == "routes" && serde_json::to_value(p.level).unwrap() == "warn"));
}
