//! Gateway payload primitives from gateway-w2-payload.test.js.
#![forbid(unsafe_code)]
use av_core::{payload::*, policy::Checked, request_view::*};
use serde_json::{json, Value};
fn evaluate(sets: Value, input: Value) -> av_core::errors::Result<()> {
    let view = request_view(&RequestInput {
        method: input["method"].as_str(),
        query: input["query"].as_str(),
        content_type: input["contentType"].as_str(),
        body: input["body"].as_str().map(str::as_bytes),
        ..Default::default()
    });
    let sets: Checked<Vec<PayloadRuleSet>> = serde_json::from_value(sets).unwrap();
    evaluate_payload(
        Some(&sets),
        &PayloadInput {
            view: &view,
            path: input["path"].as_str().unwrap_or(""),
        },
    )
}
fn body(s: &str) -> Value {
    json!({"body":s,"contentType":"application/json"})
}
fn refuses(result: av_core::errors::Result<impl std::fmt::Debug>, rule: &str) {
    let e = result.unwrap_err();
    assert_eq!(e.code.as_str(), "AV_POLICY_DENIED");
    assert_eq!(e.extra.rule.as_deref(), Some(rule));
}
#[test]
fn json_constraints_are_strict_additive_and_pointer_aware() {
    let sets = json!([{"json":{"/channel":{"required":true,"one_of":["C1"]},"/a~1b/~0":{"min":1,"max":2},"/missing":{"absent":true}}}]);
    evaluate(sets.clone(), body(r#"{"channel":"C1","a/b":{"~":2}}"#)).unwrap();
    refuses(
        evaluate(sets.clone(), body(r#"{"channel":1}"#)),
        "payload:json:0:one_of",
    );
    refuses(evaluate(sets.clone(), json!({})), "payload:json:0:required");
    let mut layered = sets.clone();
    layered
        .as_array_mut()
        .unwrap()
        .push(json!({"json":{"/channel":{"one_of":["C2"]}}}));
    for text in [r#"{"channel":"C1"}"#, r#"{"channel":"C2"}"#] {
        refuses(
            evaluate(layered.clone(), body(text)),
            "payload:json:0:one_of",
        );
    }
    refuses(
        evaluate(
            sets,
            json!({"body":r#"{"channel":"C1"}"#,"contentType":"text/plain"}),
        ),
        "payload_content_type",
    );
    evaluate(json!([]), body("not json")).unwrap();
}
#[test]
fn strict_json_refuses_decoded_duplicate_names_malformed_input_and_excess_depth() {
    for text in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"x":{"a":1,"a":2}}"#,
    ] {
        refuses(parse_strict_json(text), "payload_duplicate_key");
    }
    for text in [
        r#"{"a":1,}"#,
        "[1,]",
        "01",
        "1e999",
        r#""\q""#,
        "true false",
    ] {
        refuses(parse_strict_json(text), "payload_unparseable");
    }
    refuses(
        parse_strict_json(&format!("{}0{}", "[".repeat(65), "]".repeat(65))),
        "payload_depth",
    );
    assert_eq!(
        parse_strict_json(r#"{"__proto__":2}"#).unwrap()["__proto__"],
        2
    );
}
#[test]
fn form_query_ambiguity_strict_names_and_body_size_are_enforced() {
    refuses(
        evaluate(json!([{"query":{"a":{}}}]), json!({"query":"a=1&%61=2"})),
        "payload_duplicate_key",
    );
    refuses(
        evaluate(
            json!([{"form":{"a":{}}}]),
            json!({"body":"a=1&a=2","contentType":"application/x-www-form-urlencoded"}),
        ),
        "payload_duplicate_key",
    );
    refuses(
        evaluate(
            json!([{"query_strict":true,"query":{"a":{}}}]),
            json!({"query":"b=2"}),
        ),
        "payload:query:0:strict",
    );
    evaluate(
        json!([{"form":{"a":{"one_of":["1"]}}}]),
        json!({"body":"a=1","contentType":"application/x-www-form-urlencoded; charset=utf-8"}),
    )
    .unwrap();
    refuses(
        evaluate(json!([{"max_body_bytes":1}]), body("12")),
        "payload_size",
    );
}
#[test]
fn payload_validation_refuses_unknown_keys_and_malformed_constraints() {
    for value in [
        Value::Null,
        json!([]),
        json!({"extra":1}),
        json!({"json":{"bad":{}}}),
        json!({"json":{"/a~2":{}}}),
        json!({"json":{"/a":{"required":true,"absent":true}}}),
        json!({"query":{"a":{"one_of":[{}]}}}),
        json!({"query":{"a":{"min":null}}}),
        json!({"max_body_bytes":-1}),
        json!({"graphql":{"operations":["bogus"]}}),
    ] {
        assert!(!validate_payload(&value).is_empty(), "{value}");
    }
    assert!(validate_payload(
        &json!({"graphql":{"operations":["query"],"deny_fields":["createDeployKey"]}})
    )
    .is_empty());
    refuses(evaluate(json!([{"what":1}]), json!({})), "payload_invalid");
}
fn rules() -> GraphqlRules {
    serde_json::from_value(json!({"operations":["query"],"deny_fields":["createDeployKey"]}))
        .unwrap()
}
#[test]
fn graphql_parser_checks_full_operations_fragments_arguments_and_strings() {
    let g = rules();
    for document in ["query A($x: [Int!]! = [1,2]) @skip(if:false) { user(id:$x) { ...F ... on User { name } } } fragment F on User { x: id }",r#"{ a(text:"mutation createDeployKey", block:""" mutation { createDeployKey } """) } # mutation{bad}"#]{scan_graphql(document,&g).unwrap();}
    refuses(
        scan_graphql("query A {a} mutation B {b}", &g),
        "payload:graphql:operation",
    );
    refuses(
        scan_graphql("{ x: createDeployKey }", &g),
        "payload:graphql:deny_field",
    );
    for document in [
        "query",
        "query A {}",
        "query A { a( }",
        "query A { a } garbage",
        r#"{ a(text:"unterminated) }"#,
        "fragment X on User {a}",
        "{ ... }",
        "query($x:) {a}",
        "query { a(arg: [1) }",
    ] {
        refuses(scan_graphql(document, &g), "graphql_unparseable");
    }
    refuses(
        scan_graphql(&format!("{}{}", "{a".repeat(65), "}".repeat(65)), &g),
        "graphql_unparseable",
    );
    refuses(
        scan_graphql(&" ".repeat(300 * 1024), &g),
        "graphql_unparseable",
    );
}
#[test]
fn graphql_request_classification_checks_batches_persisted_queries_and_decoded_duplicates() {
    let sets = json!([{"graphql":{"operations":["query"],"deny_fields":["createDeployKey"]}}]);
    evaluate(
        sets.clone(),
        json!({"method":"GET","query":"query=%7Ba%7D","path":"/graphql"}),
    )
    .unwrap();
    evaluate(sets.clone(), body(r#"[{"query":"{a}"},{"query":"{b}"}]"#)).unwrap();
    refuses(
        evaluate(
            sets.clone(),
            body(r#"[{"query":"{a}"},{"query":"mutation{b}"}]"#),
        ),
        "payload:graphql:operation",
    );
    refuses(
        evaluate(
            sets.clone(),
            body(r#"{"extensions":{"persistedQuery":{"sha256Hash":"test"}}}"#),
        ),
        "graphql_persisted",
    );
    refuses(
        evaluate(sets.clone(), json!({"path":"/graphql"})),
        "graphql_unreadable",
    );
    evaluate(sets.clone(), json!({"path":"/other"})).unwrap();
    refuses(
        evaluate(sets, body(r#"{"query":"{a}","query":"{b}"}"#)),
        "payload_duplicate_key",
    );
}
