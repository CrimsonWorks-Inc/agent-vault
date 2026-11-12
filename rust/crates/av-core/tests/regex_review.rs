use av_core::{
    detect, errors::*, model_usage::*, payload::*, policy::*, profiles::*, request_view::*,
};
use serde_json::{json, Value};
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/regex-review-vectors.json")).unwrap()
}
fn compare(result: av_core::errors::Result<Value>, row: &Value) {
    if row["ok"] == true {
        assert_eq!(result.unwrap(), row["result"], "{row}");
    } else {
        assert_eq!(result.unwrap_err().to_problem(), row["error"], "{row}");
    }
}
#[test]
fn js_detector_feff_nel_and_prose_controls() {
    for row in vectors()["detect"].as_array().unwrap() {
        let hits: Vec<_> = detect::detect_all(row["text"].as_str().unwrap())
            .iter()
            .map(|h| json!({"text":h.parsed.text,"encoding":h.encoding.as_str()}))
            .collect();
        assert_eq!(json!(hits), row["hits"], "{row}");
    }
}
#[test]
fn js_multipart_feff_nel_and_ordinary_controls() {
    for row in vectors()["multipart"].as_array().unwrap() {
        let view = request_view(&RequestInput {
            method: Some("GET"),
            content_type: Some("multipart/form-data"),
            body: Some(row["body"].as_str().unwrap().as_bytes()),
            ..Default::default()
        });
        assert_eq!(
            json!({"headers":view.overrides.headers,"fields":view.overrides.fields}),
            row["overrides"],
            "{row}"
        );
    }
}
#[test]
fn js_model_content_types_ascii_word_and_whitespace_controls() {
    for row in vectors()["contentTypes"].as_array().unwrap() {
        compare(
            meter_request(
                "openai",
                &MeterInput {
                    method: Some("POST"),
                    path: Some("/v1/responses"),
                    content_type: row["contentType"].as_str(),
                    body: Some(br#"{"model":"gpt-4.1-mini"}"#),
                },
            )
            .map(|v| json!(v)),
            row,
        );
    }
}
#[test]
fn js_arabic_indic_digits_and_ascii_controls() {
    let vectors = vectors();
    for row in vectors["json"].as_array().unwrap() {
        compare(parse_strict_json(row["text"].as_str().unwrap()), row);
    }
    for row in vectors["graphql"].as_array().unwrap() {
        compare(
            scan_graphql(
                row["text"].as_str().unwrap(),
                &serde_json::from_value(json!({"operations":["query"]})).unwrap(),
            )
            .map(|_| Value::Null),
            row,
        );
    }
    for row in vectors["dates"].as_array().unwrap() {
        let headers = vec![(
            "GitHub-Authentication-Token-Expiration".into(),
            row["date"].as_str().unwrap().into(),
        )];
        assert_eq!(
            json!(extract_health(get_profile("github").ok(), &headers)),
            row["result"],
            "{row}"
        );
    }
    for row in vectors["snapshots"].as_array().unwrap() {
        assert_eq!(
            json!(price_of("openai", row["model"].as_str())),
            row["result"],
            "{row}"
        );
    }
}
#[test]
fn js_empty_on_write_method_and_problem_wire_order() {
    let vectors = vectors();
    let policy = serde_json::from_value(json!({"approval":"on-write"})).unwrap();
    for row in vectors["approval"].as_array().unwrap() {
        assert_eq!(
            needs_approval(
                &policy,
                &ApprovalQuery {
                    method: row["method"].as_str(),
                    first_use: false
                }
            ),
            row["result"].as_bool().unwrap()
        );
    }
    let error = deny(
        ErrorCode::SessionRequired,
        "test refusal",
        DenyExtra {
            rule: Some("test_rule".into()),
            request_id: Some("test-request".into()),
            next: Some(vectors["next"].clone()),
            factors: Some(vec!["passphrase".into()]),
            refunded: Some(false),
            next_placeholder: Some("test-fake-placeholder".into()),
            retry_after: Some(2),
            ..Default::default()
        },
    );
    assert_eq!(
        serde_json::to_string(&error.to_problem()).unwrap(),
        vectors["problem"].as_str().unwrap()
    );
}
#[test]
fn review_vectors_regenerate_from_javascript() {
    // Mutation copies contain rust/ only; stored vectors are still compared there.
    if !std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../legacy/js/src/core/detect.js"
    ))
    .exists()
    {
        return;
    }
    let output = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/regex-review-vectors.mjs"
        ))
        .output()
        .expect("Node reference implementation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    // Minting is intentionally random: compare encoded-hit shapes, then all deterministic probes.
    let mut actual = actual;
    let mut expected = vectors();
    for value in [&mut actual, &mut expected] {
        for row in value["detect"].as_array_mut().unwrap() {
            row.as_object_mut().unwrap().remove("text");
            for hit in row["hits"].as_array_mut().unwrap() {
                hit.as_object_mut().unwrap().remove("text");
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn js_insertion_order_keeps_canonical_hashes_and_operation_digests_stable() {
    use av_core::{canon, operation, secret::Key32};
    let vectors = vectors();
    let row = &vectors["order"];
    assert_eq!(
        canon::canonicalize(&row["value"]).unwrap(),
        row["canonical"]
    );
    assert_eq!(canon::hash(&row["value"]).unwrap(), row["hash"]);
    assert_eq!(
        canon::hmac(&Key32::from_bytes([42; 32]), &row["value"]).unwrap(),
        row["hmac"]
    );
    assert_eq!(
        operation::canonical_operation(&row["value"]),
        row["operationCanonical"]
    );
    let op = Value::Object(
        operation::operation_for("test.op", row["params"].as_object().unwrap()).unwrap(),
    );
    assert_eq!(serde_json::to_string(&op).unwrap(), row["operationWire"]);
    let challenge = operation::challenge_for_operation(b"fake-nonce", &op)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(challenge, row["challenge"]);
    assert_eq!(
        canon::request_hash(&canon::RequestHashInput {
            method: Some("POST"),
            host: Some("EXAMPLE.TEST"),
            headers: &[
                ("Z".into(), "a".into()),
                ("X".into(), "2".into()),
                ("X".into(), "1".into())
            ],
            credentials: &["z:token".into(), "a:token".into()],
            ..Default::default()
        }),
        row["requestHash"]
    );
}
