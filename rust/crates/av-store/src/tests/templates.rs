//! Ports `test/security/store-templates.test.js`.

use serde_json::{json, Value};

use super::helpers::*;
use crate::vault::*;

fn spec() -> Value {
    json!({ "cred": "demo", "methods": ["GET"], "paths": ["/repos/**"], "budget": 50, "spend_usd": 0.25, "approval": "on-write" })
}

fn sha(v: &Value) -> String {
    crate::crypto::sha256_hex(av_core::operation::canonical_operation(v).as_bytes())
}

#[test]
fn a_template_is_saved_with_a_version_and_the_hash_of_its_canonical_form_and_audited() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let t = v.save_template("gh-read", &spec()).unwrap();
    assert_eq!(
        (
            t.name.as_str(),
            t.version,
            Value::Object(t.spec.clone()),
            t.hash.clone()
        ),
        ("gh-read", 1, spec(), sha(&spec()))
    );
    assert_eq!(t.created_at, t.updated_at);
    let reordered: serde_json::Map<String, Value> = spec()
        .as_object()
        .unwrap()
        .iter()
        .rev()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(sha(&Value::Object(reordered)), t.hash);
    let mut s2 = spec();
    s2["methods"] = json!(["GET", "HEAD"]);
    let t2 = v.save_template("gh-read", &s2).unwrap();
    assert_eq!(t2.version, 2);
    assert_ne!(t2.hash, t.hash);
    assert_eq!(t2.created_at, t.created_at);
    let got: Vec<Value> = records(v, "template.saved")
        .iter()
        .map(|r| {
            json!([
                field(r, "name"),
                field(r, "version"),
                field(r, "template_hash")
            ])
        })
        .collect();
    assert_eq!(
        got,
        vec![
            json!(["gh-read", 1, t.hash]),
            json!(["gh-read", 2, t2.hash])
        ]
    );
    let again = Vault::open(fx.dir.path()).unwrap();
    assert_eq!(again.get_template("gh-read").unwrap().unwrap(), t2);
    assert_eq!(
        sha(&Value::Object(
            again.get_template("gh-read").unwrap().unwrap().spec
        )),
        t2.hash
    );
}

#[test]
fn reads_hand_out_copies_sorted_and_know_nothing_of_names_that_are_not_templates() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.save_template("zeta", &spec()).unwrap();
    v.save_template("alpha", &spec()).unwrap();
    let names: Vec<String> = v
        .list_templates()
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, vec!["alpha", "zeta"]);
    let mut copy = v.get_template("alpha").unwrap().unwrap();
    copy.spec.insert("methods".into(), json!(["DELETE"]));
    assert_eq!(
        v.get_template("alpha").unwrap().unwrap().spec["methods"],
        json!(["GET"])
    );
    for name in ["nope", "__proto__", "constructor"] {
        assert!(v.get_template(name).unwrap().is_none(), "{name}");
    }
    assert!(!v.delete_template("__proto__").unwrap());
}

#[test]
fn deleting_a_template_removes_it_once_and_records_the_version_it_had() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.save_template("gh-read", &spec()).unwrap();
    let mut s2 = spec();
    s2["budget"] = json!(10);
    v.save_template("gh-read", &s2).unwrap();
    assert!(v.delete_template("gh-read").unwrap());
    assert!(!v.delete_template("gh-read").unwrap());
    assert!(v.get_template("gh-read").unwrap().is_none());
    let got: Vec<Value> = records(v, "template.deleted")
        .iter()
        .map(|r| json!([field(r, "name"), field(r, "version")]))
        .collect();
    assert_eq!(got, vec![json!(["gh-read", 2])]);
    assert_eq!(v.save_template("gh-read", &spec()).unwrap().version, 1);
}

#[test]
fn a_bad_template_name_shape_or_size_is_refused_and_nothing_is_kept() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let long = "a".repeat(33);
    for name in ["Bad", "-lead", long.as_str(), "", "a b", "a_b"] {
        refused_cleanly(
            v,
            |v| v.save_template(name, &spec()),
            ("AV_POLICY_DENIED", Some("template_name")),
        );
    }
    let with = |k: &str, val: Value| {
        let mut x = spec();
        x[k] = val;
        x
    };
    for bad in [
        Value::Null,
        json!([]),
        json!("spec"),
        json!(7),
        with("template", json!("x")),
        with("template_hash", json!("ab")),
        with("presence", json!({ "passphrase": "pw" })),
    ] {
        refused_cleanly(
            v,
            |v| v.save_template("ok", &bad),
            ("AV_POLICY_DENIED", Some("session_shape")),
        );
    }
    let big = json!({ "cred": "demo", "label": "x".repeat(16 * 1024) });
    refused_cleanly(
        v,
        |v| v.save_template("big", &big),
        ("AV_POLICY_DENIED", Some("template_size")),
    );
    v.save_template("fits", &json!({ "label": "x".repeat(16 * 1024 - 20) }))
        .unwrap();
    for i in 1..64 {
        v.save_template(&format!("t{i}"), &spec()).unwrap();
    }
    refused_cleanly(
        v,
        |v| v.save_template("one-more", &spec()),
        ("AV_POLICY_DENIED", Some("template_size")),
    );
    assert_eq!(
        v.save_template("t1", &with("budget", json!(1)))
            .unwrap()
            .version,
        2
    );
    v.lock().unwrap();
    assert_eq!(code_of(v.save_template("t2", &spec())), "AV_LOCKED");
    assert_eq!(code_of(v.delete_template("t2")), "AV_LOCKED");
    assert_eq!(v.get_template("t2").unwrap().unwrap().version, 1);
}

#[test]
fn session_created_records_the_template_and_version_a_session_came_from_or_null() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    session(v);
    let s2 = session_with(
        v,
        CreateSessionOptions {
            template: Some("gh-read".into()),
            template_version: Some(2),
            ..Default::default()
        },
    );
    assert_eq!(
        (s2.template.as_deref(), s2.template_version),
        (Some("gh-read"), Some(2))
    );
    let got: Vec<Value> = records(v, "session.created")
        .iter()
        .map(|r| json!([field(r, "template"), field(r, "template_version")]))
        .collect();
    assert_eq!(got, vec![json!([null, null]), json!(["gh-read", 2])]);
    for (template, version) in [
        (Some("gh-read"), None),
        (None, Some(2)),
        (Some("Bad Name"), Some(1)),
        (Some("gh-read"), Some(0)),
    ] {
        refused_cleanly(
            v,
            |v| {
                v.create_session(CreateSessionOptions {
                    template: template.map(str::to_string),
                    template_version: version,
                    ..Default::default()
                })
            },
            ("AV_POLICY_DENIED", Some("template_name")),
        );
    }
}
