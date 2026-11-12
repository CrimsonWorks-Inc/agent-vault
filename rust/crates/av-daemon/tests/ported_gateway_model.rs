//! The pure model meter used by gateway spend checks: gateway-w2-model.test.js.
#![forbid(unsafe_code)]
use av_core::model_usage::*;
use serde_json::{json, Value};
fn request(kind: &str, path: &str, v: Value) -> Meter {
    let bytes = serde_json::to_vec(&v).unwrap();
    meter_request(
        kind,
        &MeterInput {
            method: Some("POST"),
            path: Some(path),
            content_type: Some("application/json; charset=utf-8"),
            body: Some(&bytes),
        },
    )
    .unwrap()
}
fn denied(e: av_core::VaultError, rule: &str) {
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some(rule));
    assert!(!e.detail.contains("secret-marker"));
}
#[test]
fn model_endpoint_and_method_classification_is_contract_exact() {
    for (kind, paths) in [
        ("anthropic", vec!["/v1/messages"]),
        (
            "openai",
            vec![
                "/v1/chat/completions",
                "/v1/responses",
                "/v1/completions",
                "/v1/embeddings",
            ],
        ),
        (
            "google-genai",
            vec![
                "/v1/models/gemini-2.5-flash:generateContent",
                "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
            ],
        ),
    ] {
        for path in paths {
            assert!(request(kind, &format!("{path}?alt=sse"), json!({})).metered);
            for method in ["PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
                let m = meter_request(
                    kind,
                    &MeterInput {
                        method: Some(method),
                        path: Some(path),
                        content_type: Some("application/json"),
                        body: Some(b"{}"),
                    },
                )
                .unwrap();
                if ["HEAD", "OPTIONS"].contains(&method) {
                    assert!(m.free);
                } else {
                    assert!(m.unmodeled);
                }
            }
        }
        assert!(request(kind, "/v1/unknown", json!({})).unmodeled);
        assert!(
            meter_request(
                kind,
                &MeterInput {
                    method: Some("GET"),
                    path: Some("/v1/unknown"),
                    body: Some(b"invalid"),
                    ..Default::default()
                }
            )
            .unwrap()
            .free
        );
    }
    for (kind, path) in [
        ("anthropic", "/v1/messages/count_tokens"),
        ("google-genai", "/v1beta/models/x:countTokens"),
    ] {
        assert!(
            meter_request(
                kind,
                &MeterInput {
                    method: Some("POST"),
                    path: Some(path),
                    body: Some(b"invalid"),
                    ..Default::default()
                }
            )
            .unwrap()
            .free
        );
    }
    assert!(!request("github", "/anything", json!({})).unmodeled);
}
#[test]
fn malformed_metered_json_fails_without_echo_and_vendor_json_is_ordinary() {
    for body in [
        Some("secret-marker"),
        Some("null"),
        Some("[]"),
        Some("true"),
        Some(""),
        None,
    ] {
        denied(
            meter_request(
                "openai",
                &MeterInput {
                    method: Some("POST"),
                    path: Some("/v1/responses"),
                    content_type: Some("application/json; charset=utf-8"),
                    body: body.map(str::as_bytes),
                },
            )
            .unwrap_err(),
            "spend_unparseable",
        );
    }
    denied(
        meter_request(
            "anthropic",
            &MeterInput {
                method: Some("POST"),
                path: Some("/v1/messages"),
                content_type: Some("text/plain"),
                body: Some(b"{}"),
            },
        )
        .unwrap_err(),
        "spend_unparseable",
    );
    assert!(
        meter_request(
            "openai",
            &MeterInput {
                method: Some("POST"),
                path: Some("/v1/responses"),
                content_type: Some("application/vendor+json"),
                body: Some(b"{}")
            }
        )
        .unwrap()
        .metered
    );
}
#[test]
fn reservations_use_original_utf8_bytes_and_provider_output_limit_precedence() {
    let v = json!({"model":"gpt-4.1-mini","input":"雪🌲","max_completion_tokens":37,"max_tokens":99,"max_output_tokens":121});
    let m = request("openai", "/v1/responses", v.clone());
    assert_eq!(
        m.input_estimate,
        serde_json::to_vec(&v).unwrap().len().div_ceil(3) as u64
    );
    assert_eq!(m.max_output, 37);
    assert_eq!(m.model.as_deref(), Some("gpt-4.1-mini"));
    for (kind, path, v, max, model) in [
        (
            "openai",
            "/v1/completions",
            json!({"max_tokens":51}),
            51,
            None,
        ),
        (
            "openai",
            "/v1/responses",
            json!({"max_output_tokens":53}),
            53,
            None,
        ),
        (
            "anthropic",
            "/v1/messages",
            json!({"max_tokens":57}),
            57,
            None,
        ),
        (
            "google-genai",
            "/v1beta/models/gemini-2.5-flash:generateContent",
            json!({"generationConfig":{"maxOutputTokens":61}}),
            61,
            Some("gemini-2.5-flash"),
        ),
        (
            "openai",
            "/v1/embeddings",
            json!({"max_tokens":91}),
            0,
            None,
        ),
    ] {
        let m = request(kind, path, v);
        assert_eq!(m.max_output, max);
        if let Some(model) = model {
            assert_eq!(m.model.as_deref(), Some(model));
        }
    }
    for value in [
        None,
        Some(Value::Null),
        Some(json!(0)),
        Some(json!(-1)),
        Some(json!(1.5)),
        Some(json!("500")),
        Some(json!(true)),
        Some(json!(9_007_199_254_740_992u64)),
    ] {
        for (kind, path, expected) in [
            ("anthropic", "/v1/messages", 4096),
            ("openai", "/v1/chat/completions", 16384),
            ("google-genai", "/v1/models/x:generateContent", 8192),
        ] {
            let mut v = json!({});
            if let Some(value) = value.clone() {
                if kind == "google-genai" {
                    v["generationConfig"] = json!({"maxOutputTokens":value});
                } else {
                    v["max_tokens"] = value;
                }
            }
            assert_eq!(request(kind, path, v).max_output, expected);
        }
    }
}
#[test]
fn checked_model_prices_round_up_reservations_and_refuse_unknown_or_overflow() {
    assert!(av_core::jsre::compile(r"^\d{4}-\d{2}-\d{2}$")
        .unwrap()
        .is_match(PRICES_VERSION));
    assert_eq!(
        price_of("openai", Some("gpt-4.1-mini-2025-04-14")),
        Some(Price {
            input_micros_per_mtok: 400000,
            output_micros_per_mtok: 1600000
        })
    );
    assert_eq!(
        price_of("google-genai", Some("gemini-2.5-flash-lite")),
        Some(Price {
            input_micros_per_mtok: 100000,
            output_micros_per_mtok: 400000
        })
    );
    assert_eq!(
        price_of("anthropic", Some("claude-sonnet-4-5-20250929"))
            .unwrap()
            .output_micros_per_mtok,
        15000000
    );
    assert_eq!(
        price_of("anthropic", Some("claude-sonnet-4-20250514"))
            .unwrap()
            .input_micros_per_mtok,
        3000000
    );
    for model in [
        None,
        Some("unknown"),
        Some("gpt-4.1-mini-expensive"),
        Some("gpt-4.1-mini-audio"),
    ] {
        assert!(price_of("openai", model).is_none());
    }
    for (kind, model) in [
        ("google-genai", "gemini-2.5-flash-image"),
        ("github", "gpt-4.1-mini"),
        ("__proto__", "gpt-4.1-mini"),
    ] {
        assert!(price_of(kind, Some(model)).is_none());
    }
    let unknown = request("openai", "/v1/responses", json!({"model":"secret-marker"}));
    denied(
        reservation_for("openai", &unknown, ReservationOptions { usd: true }).unwrap_err(),
        "spend_unpriced",
    );
    let r = reservation_for("openai", &unknown, Default::default()).unwrap();
    assert_eq!(r.usd_micros, 0);
    assert!(r.tokens > 0);
    let mut m = Meter {
        metered: true,
        model: Some("gpt-4.1-mini".into()),
        input_estimate: 1,
        max_output: 1,
        ..Default::default()
    };
    assert_eq!(
        reservation_for("openai", &m, ReservationOptions { usd: true }).unwrap(),
        Charge {
            tokens: 2,
            usd_micros: 2
        }
    );
    m.max_output = 0;
    assert_eq!(
        reservation_for("openai", &m, Default::default()).unwrap(),
        Charge {
            tokens: 1,
            usd_micros: 1
        }
    );
    m.max_output = 1;
    m.input_estimate = 9_007_199_254_740_991;
    denied(
        reservation_for("openai", &m, Default::default()).unwrap_err(),
        "spend_unparseable",
    );
    assert_eq!(
        reservation_for("openai", &Meter::default(), Default::default()).unwrap(),
        Charge::default()
    );
}
fn usage(i: u64, o: u64) -> Option<Usage> {
    Some(Usage {
        input_tokens: i,
        output_tokens: o,
    })
}
#[test]
fn buffered_provider_usage_includes_cache_and_thinking_tokens_and_rejects_partial_counts() {
    for (kind, v, want) in [
        (
            "anthropic",
            json!({"usage":{"input_tokens":10,"cache_creation_input_tokens":20,"cache_read_input_tokens":30,"output_tokens":4}}),
            usage(60, 4),
        ),
        (
            "anthropic",
            json!({"usage":{"input_tokens":10,"output_tokens":4}}),
            usage(10, 4),
        ),
        (
            "openai",
            json!({"usage":{"prompt_tokens":31,"completion_tokens":7}}),
            usage(31, 7),
        ),
        (
            "openai",
            json!({"usage":{"input_tokens":31,"output_tokens":7}}),
            usage(31, 7),
        ),
        (
            "openai",
            json!({"usage":{"prompt_tokens":5,"total_tokens":5}}),
            usage(5, 0),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":3}}),
            usage(9, 3),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":20}}),
            usage(10, 25),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":10,"thoughtsTokenCount":20}}),
            usage(10, 20),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}),
            usage(10, 5),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":-1}}),
            None,
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":10}}),
            None,
        ),
    ] {
        assert_eq!(usage_from_body(kind, &v), want);
    }
    for v in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"usage":{}}),
        json!({"usage":{"input_tokens":4}}),
        json!({"usage":{"input_tokens":-1,"output_tokens":1}}),
        json!({"usage":{"input_tokens":"4","output_tokens":1}}),
        json!({"usage":{"input_tokens":0.5,"output_tokens":1}}),
        json!({"usage":{"input_tokens":9_007_199_254_740_991u64,"cache_read_input_tokens":1,"output_tokens":1}}),
    ] {
        assert_eq!(usage_from_body("anthropic", &v), None);
    }
    for (kind, v) in [
        ("openai", json!({"usage":{"prompt_tokens":4}})),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":4}}),
        ),
        (
            "github",
            json!({"usage":{"input_tokens":4,"output_tokens":1}}),
        ),
    ] {
        assert_eq!(usage_from_body(kind, &v), None);
    }
}
#[test]
fn cumulative_sse_usage_never_decreases_or_double_charges_and_survives_empty_chunks() {
    let start=json!({"type":"message_start","message":{"usage":{"input_tokens":5,"cache_creation_input_tokens":7,"cache_read_input_tokens":11,"output_tokens":0}}}).to_string();
    let before = usage_from_event("anthropic", SseEventData::Raw(start.as_bytes()), None);
    assert_eq!(before, usage(23, 0));
    let delta = json!({"type":"message_delta","usage":{"output_tokens":9}});
    let acc = usage_from_event("anthropic", SseEventData::Parsed(&delta), before);
    assert_eq!(acc, usage(23, 9));
    assert_eq!(
        usage_from_event(
            "anthropic",
            SseEventData::Parsed(&json!({"type":"message_delta","usage":{"output_tokens":7}})),
            acc
        ),
        acc
    );
    assert_eq!(
        usage_from_event("anthropic", SseEventData::Parsed(&delta), None),
        None
    );
    for (kind, event) in [
        (
            "openai",
            json!({"usage":{"prompt_tokens":17,"completion_tokens":6}}),
        ),
        (
            "openai",
            json!({"type":"response.completed","response":{"usage":{"input_tokens":17,"output_tokens":6}}}),
        ),
        (
            "google-genai",
            json!({"usageMetadata":{"promptTokenCount":17,"candidatesTokenCount":6}}),
        ),
    ] {
        assert_eq!(usage_from_event(kind, SseEventData::Raw(b"{}"), None), None);
        let text = event.to_string();
        let acc = usage_from_event(kind, SseEventData::Raw(text.as_bytes()), None);
        assert_eq!(acc, usage(17, 6));
        for next in ["[DONE]", "broken", "{}", text.as_str()] {
            assert_eq!(
                usage_from_event(kind, SseEventData::Raw(next.as_bytes()), acc),
                acc
            );
        }
    }
}
#[test]
fn missing_or_unreadable_usage_charges_full_reservation_but_actual_usage_can_exceed_it() {
    let m = Meter {
        metered: true,
        model: Some("gpt-4.1-mini".into()),
        input_estimate: 10,
        max_output: 10,
        ..Default::default()
    };
    let r = reservation_for("openai", &m, ReservationOptions { usd: true }).unwrap();
    assert_eq!(charge_for("openai", &m, &r, None).unwrap(), r);
    // Rust's Usage cannot represent NaN; the event parser turns that JS input
    // into None, which must retain the full reservation at the charge boundary.
    let invalid = usage_from_event(
        "openai",
        SseEventData::Raw(b"{\"usage\":{\"input_tokens\":NaN,\"output_tokens\":0}}"),
        None,
    );
    assert_eq!(invalid, None);
    assert_eq!(charge_for("openai", &m, &r, invalid.as_ref()).unwrap(), r);
    assert_eq!(
        charge_for("openai", &m, &r, usage(100, 100).as_ref()).unwrap(),
        Charge {
            tokens: 200,
            usd_micros: 200
        }
    );
    assert_eq!(
        charge_for("openai", &m, &r, usage(0, 0).as_ref()).unwrap(),
        Charge::default()
    );
}
