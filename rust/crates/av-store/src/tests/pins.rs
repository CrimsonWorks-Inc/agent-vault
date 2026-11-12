//! Ports `test/security/store-pins.test.js`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::backup::{audit_text, refused_with_one_record, target, v1_bundle};
use super::helpers::*;
use crate::backup::*;
use crate::vault::*;

fn pin(c: char) -> String {
    format!("sha256/{}=", c.to_string().repeat(43))
}

const RECOVERY: &str = "correct horse battery staple";

fn pins_of(v: &Vault, slug: &str) -> BTreeMap<String, Vec<String>> {
    v.find_credential(slug).unwrap().unwrap().pins
}

fn table(entries: &[(&str, Vec<String>)]) -> BTreeMap<String, Vec<String>> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn pins_are_stored_under_the_canonical_host_counted_publicly_persisted_and_logged_as_a_count() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let (a, b, c) = (pin('A'), pin('B'), pin('C'));
    let out = v
        .set_pins(
            "demo",
            " API.Example.com. ",
            &[a.clone(), b.clone(), a.clone()],
        )
        .unwrap();
    assert_eq!(
        out,
        PinsSet {
            slug: "demo".into(),
            host: "api.example.com".into(),
            pins: 2
        }
    );
    assert_eq!(
        pins_of(v, "demo"),
        table(&[("api.example.com", vec![a.clone(), b.clone()])])
    );
    let pubc = v
        .list_credentials()
        .unwrap()
        .into_iter()
        .find(|c| c.slug == "demo")
        .unwrap();
    assert_eq!(pubc.pins.get("api.example.com"), Some(&2));
    assert!(!serde_json::to_string(&v.list_credentials().unwrap())
        .unwrap()
        .contains(&a));
    let r = &records(v, "cred.pins_set")[0];
    assert_eq!(
        (
            field(r, "credential_slug"),
            field(r, "host"),
            field(r, "pins")
        ),
        (&json!("demo"), &json!("api.example.com"), &json!(2))
    );
    assert!(!audit_text(v).contains(&"A".repeat(43)));
    v.set_pins("demo", "api.example.com", std::slice::from_ref(&c))
        .unwrap();
    assert_eq!(pins_of(v, "demo"), table(&[("api.example.com", vec![c])]));
    assert!(v
        .list_credentials()
        .unwrap()
        .into_iter()
        .find(|c| c.slug == "other")
        .unwrap()
        .pins
        .is_empty());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_malformed_pin_list_or_a_host_the_credential_cannot_reach_is_refused_and_changes_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let (a, b, c) = (pin('A'), pin('B'), pin('C'));
    v.set_pins("demo", "api.example.com", std::slice::from_ref(&a))
        .unwrap();
    for pins in [
        vec![],
        vec![a.clone(), b.clone(), c.clone(), pin('D'), pin('E')],
        vec!["sha256/short=".to_string()],
        vec![format!("sha1/{}=", "A".repeat(27))],
        vec![format!(" {a}")],
    ] {
        refused_cleanly(
            v,
            |v| v.set_pins("demo", "api.example.com", &pins),
            ("AV_POLICY_DENIED", Some("pin_format")),
        );
    }
    for host in [
        "api.other.example",
        "evil.example",
        "",
        "api.example.com.evil.test",
    ] {
        refused_cleanly(
            v,
            |v| v.set_pins("demo", host, std::slice::from_ref(&b)),
            ("AV_POLICY_DENIED", Some("pin_host")),
        );
    }
    refused_cleanly(
        v,
        |v| v.set_pins("nope", "api.example.com", std::slice::from_ref(&b)),
        ("AV_NOT_FOUND", None),
    );
    let cred_id = fx.cred.id.clone();
    let set_table = |v: &Vault, hosts: &[&str]| {
        exec(v, "DELETE FROM pins WHERE credential_id = ?1", &[&cred_id]);
        for h in hosts {
            exec(
                v,
                "INSERT INTO pins (credential_id, host, spki) VALUES (?1, ?2, ?3)",
                &[&cred_id, h, &pin('A')],
            );
        }
    };
    set_table(v, &["a.test", "b.test", "c.test", "d.test"]);
    refused_cleanly(
        v,
        |v| v.set_pins("demo", "api.example.com", std::slice::from_ref(&b)),
        ("AV_POLICY_DENIED", Some("pin_host")),
    );
    set_table(v, &["a.test", "b.test", "c.test", "api.example.com"]);
    assert_eq!(
        v.set_pins("demo", "api.example.com", std::slice::from_ref(&b))
            .unwrap()
            .pins,
        1
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_host_the_profile_reaches_can_be_pinned_on_a_profile_credential() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let mut gh = new_cred(
        "gh",
        "github",
        "",
        &[("token", "ghp_PINSTORE0000111122223333444455556666")],
    );
    gh.connector = serde_json::Map::new();
    v.add_credential(gh).unwrap();
    assert_eq!(
        v.set_pins("gh", "uploads.github.com", &[pin('A')])
            .unwrap()
            .host,
        "uploads.github.com"
    );
    refused_cleanly(
        v,
        |v| v.set_pins("gh", "api.example.com", &[pin('A')]),
        ("AV_POLICY_DENIED", Some("pin_host")),
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn clear_pins_removes_one_pin_or_all_of_a_host_records_a_count_and_does_nothing_when_nothing_matches(
) {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let (a, b, c) = (pin('A'), pin('B'), pin('C'));
    v.set_pins("demo", "api.example.com", &[a.clone(), b.clone()])
        .unwrap();
    assert_eq!(
        v.clear_pins("demo", "API.EXAMPLE.COM", Some(&a)).unwrap(),
        1
    );
    assert_eq!(
        pins_of(v, "demo"),
        table(&[("api.example.com", vec![b.clone()])])
    );
    refused_cleanly(
        v,
        |v| {
            v.clear_pins("demo", "api.example.com", Some(&c))
                .map(|n| assert_eq!(n, 1))
        },
        ("none", None),
    );
    refused_cleanly(
        v,
        |v| {
            v.clear_pins("demo", "other.example", None)
                .map(|n| assert_eq!(n, 0))
        },
        ("none", None),
    );
    refused_cleanly(
        v,
        |v| v.clear_pins("demo", "api.example.com", Some("not-a-pin")),
        ("AV_POLICY_DENIED", Some("pin_format")),
    );
    assert_eq!(v.clear_pins("demo", "api.example.com", None).unwrap(), 0);
    assert!(pins_of(v, "demo").is_empty());
    let got: Vec<(Value, Value)> = records(v, "cred.pins_removed")
        .iter()
        .map(|r| (field(r, "host").clone(), field(r, "pins").clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (json!("api.example.com"), json!(1)),
            (json!("api.example.com"), json!(1))
        ]
    );
    v.lock().unwrap();
    assert_eq!(
        code_of(v.set_pins("demo", "api.example.com", &[a])),
        "AV_LOCKED"
    );
    assert_eq!(
        code_of(v.clear_pins("demo", "api.example.com", None)),
        "AV_LOCKED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_backup_carries_pins_and_a_restore_puts_them_back_under_the_same_rules() {
    let mut fx = fresh();
    let (_t, mut t) = target();
    let (a, b) = (pin('A'), pin('B'));
    fx.vault
        .set_pins("demo", "api.example.com", &[a.clone(), b.clone()])
        .unwrap();
    let bundle =
        serde_json::to_value(export_backup(&mut fx.vault, &s(RECOVERY)).unwrap().bundle).unwrap();
    let seen = inspect_backup(&bundle, &s(RECOVERY)).unwrap();
    let mut has: Vec<(String, bool)> = seen
        .credentials
        .iter()
        .map(|c| (c.slug.clone(), c.has_pins))
        .collect();
    has.sort();
    assert_eq!(has, vec![("demo".into(), true), ("other".into(), false)]);
    let mut out = restore_backup(&mut t, &bundle, &s(RECOVERY), ConflictMode::Skip)
        .unwrap()
        .restored;
    out.sort();
    assert_eq!(out, vec!["demo", "other"]);
    assert_eq!(
        pins_of(&t, "demo"),
        table(&[("api.example.com", vec![a, b])])
    );
    let got: Vec<Value> = records(&t, "cred.pins_set")
        .iter()
        .map(|r| {
            json!([
                field(r, "credential_slug"),
                field(r, "host"),
                field(r, "pins")
            ])
        })
        .collect();
    assert_eq!(got, vec![json!(["demo", "api.example.com", 2])]);
    assert!(t
        .all_secrets()
        .unwrap()
        .iter()
        .any(|x| av_core::secret::ExposeSecret::expose_secret(&x.secret) == SECRET));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_restore_refuses_pins_it_could_not_store_whole_and_records_only_the_refusal() {
    let (_t, mut t) = target();
    let cred = json!({ "slug": "demo", "kind": "http", "connector": { "host": "api.example.com" }, "created_at": "x",
                        "fields": [{ "name": "token", "value": SECRET, "sites": [] }], "scrub_patterns": [], "expires_at": null });
    let (a, b, c) = (pin('A'), pin('B'), pin('C'));
    for (pins, rule_) in [
        (
            json!({ "api.example.com": ["sha256/short="] }),
            "pin_format",
        ),
        (
            json!({ "api.example.com": [a.clone(), b.clone(), c.clone(), pin('D'), pin('E')] }),
            "pin_format",
        ),
        (json!({ "evil.example": [a.clone()] }), "pin_host"),
        (json!({ "api.example.com": "x" }), "backup_format"),
        (json!([a.clone()]), "backup_format"),
    ] {
        let mut cc = cred.clone();
        cc["pins"] = pins;
        let bundle = v1_bundle(&json!({ "credentials": [cc], "templates": [] }), RECOVERY);
        refused_with_one_record(
            &mut t,
            |t| restore_backup(t, &bundle, &s(RECOVERY), ConflictMode::Skip),
            ("AV_POLICY_DENIED", rule_),
        );
        assert_eq!(
            field(records(&t, "backup.refused").last().unwrap(), "reason"),
            &json!(rule_)
        );
    }
    let mut ok = cred.clone();
    ok["pins"] = json!({ "API.example.com.": [a.clone()], "other.example": [] });
    let bundle = v1_bundle(&json!({ "credentials": [ok], "templates": [] }), RECOVERY);
    restore_backup(&mut t, &bundle, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert_eq!(pins_of(&t, "demo"), table(&[("api.example.com", vec![a])]));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_pinned_quarantined_credential_comes_back_both_pinned_and_quarantined() {
    let mut fx = fresh();
    let (_t, mut t) = target();
    fx.vault
        .set_pins("demo", "api.example.com", &[pin('A')])
        .unwrap();
    fx.vault
        .set_quarantine(
            "demo",
            QuarantineOptions {
                reason: Some("leaked".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let bundle =
        serde_json::to_value(export_backup(&mut fx.vault, &s(RECOVERY)).unwrap().bundle).unwrap();
    restore_backup(&mut t, &bundle, &s(RECOVERY), ConflictMode::Skip).unwrap();
    let demo = t.find_credential("demo").unwrap().unwrap();
    assert_eq!(demo.pins, table(&[("api.example.com", vec![pin('A')])]));
    assert_eq!(
        demo.quarantine.as_ref().unwrap().by,
        crate::model::QuarantineBy::Control
    );
    assert_eq!(code_of(t.reveal_field(&demo.id, "token")), "AV_QUARANTINED");
}
