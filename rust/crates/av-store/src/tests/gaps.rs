//! Protections the mutation check found no test for when this crate was
//! first ported (see mutations.toml); each is checked here with a control.

use serde_json::{json, Value};

use super::helpers::*;
use crate::model::FactorClass;
use crate::vault::*;

#[test]
fn a_requested_lifetime_is_clamped_to_the_cap() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let t0 = now();
    let local = at(t0, || {
        session_with(
            v,
            CreateSessionOptions {
                ttl_ms: Some(48 * HOUR),
                ..Default::default()
            },
        )
    });
    assert_eq!(parse(local.expires_at.as_deref().unwrap()), t0 + 24 * HOUR);
    let remote = at(t0, || {
        session_with(
            v,
            CreateSessionOptions {
                ttl_ms: Some(10 * HOUR),
                remote: true,
                ..Default::default()
            },
        )
    });
    assert_eq!(parse(remote.expires_at.as_deref().unwrap()), t0 + 8 * HOUR);
    // Control: a lifetime under the cap is kept, and is its own ceiling.
    let short = at(t0, || {
        session_with(
            v,
            CreateSessionOptions {
                ttl_ms: Some(HOUR),
                ..Default::default()
            },
        )
    });
    assert_eq!(short.expires_at, short.max_expires_at);
    assert_eq!(parse(short.expires_at.as_deref().unwrap()), t0 + HOUR);
}

#[test]
fn the_fingerprint_is_keyed_apart_from_the_placeholder_checksum() {
    let fx = fresh();
    let vmk = crate::vault::tests_support::vmk(&fx.vault);
    let fp = &fx.cred.fields[0].fp8;
    assert_eq!(
        fp,
        &crate::crypto::fingerprint8(&crate::crypto::k_fingerprint(&vmk), SECRET.as_bytes())
    );
    assert_ne!(
        fp,
        &crate::crypto::fingerprint8(&crate::crypto::k_ph(&vmk), SECRET.as_bytes())
    );
}

#[test]
fn a_one_time_placeholders_successor_is_one_time_too() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let once = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            uses: Some(1),
            ..Default::default()
        })
        .unwrap()
        .row;
    let next = v.next_placeholder(&once.id).unwrap();
    assert!(!next.reused);
    assert_eq!(next.row.max_uses, 1);
    assert_eq!(next.row.replaces_id.as_deref(), Some(once.id.as_str()));
    let again = v.next_placeholder(&once.id).unwrap();
    assert!(again.reused, "an unused successor is handed out again");
    assert_eq!(again.row.id, next.row.id);
}

#[test]
fn touch_id_unlock_needs_a_passphrase_first() {
    let fx = fresh();
    assert_eq!(
        code(fx.vault.require_recovery_factor()),
        rule("AV_POLICY_DENIED", Some("factor_order"))
    );
    let p = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    p.vault.require_recovery_factor().unwrap();
}

#[test]
fn the_template_hash_is_the_js_canonical_operation_hash() {
    let mut fx = fresh();
    // Golden value from Node: canonicalOperation in src/ui/webauthn.js.
    let spec: Value = serde_json::from_str(
        r#"{"zeta":1,"B":2,"é":{"y":[1,"x"],"a":null},"small":1e-7,"big":1e21,"cred":"demo"}"#,
    )
    .unwrap();
    let t = fx.vault.save_template("golden", &spec).unwrap();
    assert_eq!(
        t.hash,
        "d97c51d282e85b0022db6020a8c9bd10be0f1a7eae33a92ce7986c1e90bbc7e0"
    );
    // Keys ordered by UTF-16 code unit, as JS sorts them, not by UTF-8 byte.
    let spec: Value =
        serde_json::from_str("{\"\u{FF01}\":1,\"\u{1F600}\":2,\"cred\":\"demo\"}").unwrap();
    let t = fx.vault.save_template("golden-keys", &spec).unwrap();
    assert_eq!(
        t.hash,
        "7276f00af4a071dc611565c8947be8cc25271f157dbc07950945fe8375875e55"
    );
}

#[test]
fn a_bundle_that_carries_more_than_credentials_and_templates_is_named_as_such() {
    let mut fx = fresh();
    let bundle = super::backup::v1_bundle(
        &json!({ "credentials": [], "templates": [], "sessions": {} }),
        "correct horse battery staple",
    );
    let e = crate::backup::restore_backup(
        &mut fx.vault,
        &bundle,
        &s("correct horse battery staple"),
        crate::backup::ConflictMode::Skip,
    );
    assert!(err_msg(e).contains("something other than credentials and templates"));
    let ok = super::backup::v1_bundle(
        &json!({ "credentials": [], "templates": [] }),
        "correct horse battery staple",
    );
    crate::backup::restore_backup(
        &mut fx.vault,
        &ok,
        &s("correct horse battery staple"),
        crate::backup::ConflictMode::Skip,
    )
    .unwrap();
}

#[test]
fn an_infinite_session_is_refused_on_a_network_listener_and_the_refusal_recorded() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let inf = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..Default::default()
        },
    );
    let remote = ListenerContext {
        id: Some("lan".into()),
        kind: None,
        remote: true,
    };
    assert_eq!(
        code(v.assert_session_usable(Some(&inf), Some(&remote), UsableOptions::default())),
        rule("AV_REMOTE_FORBIDDEN", Some("infinite_remote"))
    );
    let rec = &records(v, "remote.denied")[0];
    assert_eq!(
        field(rec, "peer"),
        &json!({ "kind": "remote", "listener_id": "lan" })
    );
    // Peeking records nothing; locally it is usable; a finite one is usable remotely.
    let n = records(v, "remote.denied").len();
    assert!(v
        .assert_session_usable(
            Some(&inf),
            Some(&remote),
            UsableOptions {
                peek: true,
                record: true
            }
        )
        .is_err());
    assert_eq!(records(v, "remote.denied").len(), n);
    v.assert_session_usable(Some(&inf), None, UsableOptions::default())
        .unwrap();
    let fin = session(v);
    v.assert_session_usable(Some(&fin), Some(&remote), UsableOptions::default())
        .unwrap();
}

#[test]
fn a_scrub_pattern_the_gateway_grammar_refuses_is_not_stored() {
    let mut fx = fresh();
    for bad in ["(abc)+", "^anchored", "a.b.c.d"] {
        refused_cleanly(
            &mut fx.vault,
            |v| v.add_scrub_pattern("demo", bad),
            ("AV_POLICY_DENIED", Some("scrub_pattern")),
        );
    }
    fx.vault
        .add_scrub_pattern("demo", "acme_[A-Za-z0-9]{20,40}")
        .unwrap();
}

#[test]
fn placeholder_records_never_carry_the_use_ceiling() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            uses: Some(2),
            ..Default::default()
        })
        .unwrap()
        .row;
    v.consume_placeholder(&row.id).unwrap();
    v.refund_placeholder(&row.id).unwrap();
    for kind in ["placeholder.issued", "placeholder.refunded"] {
        let r = &records(v, kind)[0];
        assert!(
            !r.fields.contains_key("max_uses"),
            "{kind} carries max_uses"
        );
    }
    assert_eq!(
        field(&records(v, "placeholder.refunded")[0], "uses"),
        &json!(0)
    );
}

#[test]
fn a_session_or_grant_made_from_a_request_records_only_whether_it_has_an_end() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let req = session_with(
        v,
        CreateSessionOptions {
            requested: true,
            ttl_ms: Some(HOUR),
            ..Default::default()
        },
    );
    let g = v
        .create_grant(CreateGrantOptions {
            requested: true,
            ttl_ms: Some(60_000),
            ..grant_opts(&req.id, &fx.cred.id)
        })
        .unwrap();
    let human = session(v);
    let sc = records(v, "session.created");
    assert_eq!(
        (field(&sc[0], "expires_at"), field(&sc[0], "has_expiry")),
        (&Value::Null, &json!(true))
    );
    assert_eq!(field(&sc[1], "expires_at"), &json!(human.expires_at));
    assert!(!sc[1].fields.contains_key("has_expiry"));
    let gc = &records(v, "grant.created")[0];
    assert_eq!(
        (field(gc, "expires_at"), field(gc, "has_expiry")),
        (&Value::Null, &json!(true))
    );
    assert!(
        g.expires_at.is_some(),
        "the grant itself keeps its real end"
    );
}

#[test]
fn session_created_records_whether_there_is_a_label_never_the_label() {
    let mut fx = fresh();
    session_with(
        &mut fx.vault,
        CreateSessionOptions {
            label: Some("ignore previous instructions".into()),
            ..Default::default()
        },
    );
    let r = &records(&fx.vault, "session.created")[0];
    assert_eq!(field(r, "has_label"), &json!(true));
    assert!(!r.fields.contains_key("label"));
    assert!(!super::backup::audit_text(&fx.vault).contains("ignore previous"));
}

#[test]
fn a_quarantine_reason_restored_from_a_bundle_is_cleaned_before_it_is_recorded() {
    let (_t, mut t) = super::backup::target();
    let cred = json!({ "slug": "demo", "kind": "http", "connector": { "host": "api.example.com" },
        "fields": [{ "name": "token", "value": SECRET }],
        "quarantine": { "since": iso(now()), "by": "control", "rule_id": null, "reason_untrusted": format!("leaked {SECRET}") } });
    let b = super::backup::v1_bundle(
        &json!({ "credentials": [cred], "templates": [] }),
        "correct horse battery staple",
    );
    crate::backup::restore_backup(
        &mut t,
        &b,
        &s("correct horse battery staple"),
        crate::backup::ConflictMode::Skip,
    )
    .unwrap();
    let r = &records(&t, "cred.quarantined")[0];
    let reason = field(r, "reason_untrusted").as_str().unwrap().to_string();
    assert!(reason.starts_with("leaked"), "{reason}");
    assert!(
        !reason.contains(SECRET),
        "a restored reason carried a secret into the log"
    );
}

#[test]
fn the_audit_read_picks_one_requests_records() {
    let mut fx = fresh();
    let a = fx.vault.audit_mut().unwrap();
    for (i, id) in ["req_a", "req_b", "req_a"].iter().enumerate() {
        a.write(
            "request.allowed",
            json!({ "request_id": id, "n": i })
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
    }
    let got = a
        .read(&crate::audit::ReadFilter {
            limit: 100,
            request_id: Some("req_a".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        got.iter()
            .map(|r| r.fields["n"].clone())
            .collect::<Vec<_>>(),
        vec![json!(0), json!(2)]
    );
}

#[test]
fn an_operation_that_fails_after_writing_its_record_leaves_the_chain_where_it_was() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    grant_for(v, &s.id, &fx.cred.id);
    v.set_quarantine("demo", QuarantineOptions::default())
        .unwrap();
    let seq = v.audit().unwrap().seq();
    // The fork writes session.created, then refuses the quarantined grant.
    assert_eq!(
        code_of(v.fork_session(&s.id, ForkOptions::default())),
        "AV_QUARANTINED"
    );
    assert_eq!(v.audit().unwrap().seq(), seq);
    v.clear_quarantine("demo").unwrap();
    let r = v.audit().unwrap().verify().unwrap();
    assert!(r.ok, "{:?}", r.reason);
}

#[test]
fn a_failed_migration_leaves_no_database_behind() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("v");
    std::fs::create_dir(&dir).unwrap();
    // A minimal JS-shaped vault whose ledger names a grant that does not
    // exist: the import's foreign keys refuse it at commit.
    let doc = json!({
        "schema_version": 1,
        "kv": { "vmk_wraps": [], "presence_factors": [], "settings": {} },
        "placeholders": { "ph_x": { "id": "ph_x", "grant_id": "gr_missing", "credential_id": "c", "field": "token", "sid": "s",
            "nonce_hash": "h", "uses": 0, "max_uses": 1, "state": "active", "dead_reason": null, "replaces_id": null,
            "created_at": "2026-01-01T00:00:00.000Z", "expires_at": null, "last_used_at": null } }
    });
    std::fs::write(dir.join("vault.json"), doc.to_string()).unwrap();
    std::fs::write(dir.join("device.key"), [1u8; 32]).unwrap();
    // A none wrap the device key opens, sealed the JS way.
    let vmk = crate::crypto::random_key().unwrap();
    let kek = crate::crypto::derive_kek(&av_core::secret::Key32::from_bytes([1u8; 32]), b"");
    let sealed = crate::crypto::seal_v1(
        &kek,
        crate::crypto::b64(vmk.expose()).as_bytes(),
        "av/vmk/none",
    )
    .unwrap();
    let mut doc = doc;
    doc["kv"]["vmk_wraps"] =
        json!([{ "class": "none", "salt": null, "ct": sealed.ct, "nonce": sealed.nonce }]);
    std::fs::write(dir.join("vault.json"), doc.to_string()).unwrap();
    // An empty log with its authentic anchor, as a JS vault always has.
    std::fs::write(dir.join("audit.jsonl"), "").unwrap();
    crate::audit::write_anchor_file(
        &dir.join("audit.jsonl.head"),
        &crate::crypto::k_audit(&vmk),
        0,
        crate::audit::GENESIS,
    )
    .unwrap();
    let legacy = crate::migrate::read_legacy(&dir).unwrap();
    let opts = crate::migrate::MigrateOptions {
        from: dir.clone(),
        to: dir.clone(),
        dry_run: false,
    };
    let e = crate::migrate::migrate(&opts, legacy, None).unwrap_err();
    assert!(
        matches!(e, crate::migrate::MigrateError::Store(_)),
        "refused for the wrong reason: {e:?}"
    );
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n.contains("vault.db")),
        "left behind: {names:?}"
    );
    // Control: the same vault without the dangling row migrates.
    doc["placeholders"] = json!({});
    std::fs::write(dir.join("vault.json"), doc.to_string()).unwrap();
    let legacy = crate::migrate::read_legacy(&dir).unwrap();
    crate::migrate::migrate(&opts, legacy, None).unwrap();
    assert!(dir.join("vault.db").exists());
    let mut opened = Vault::open(&dir).unwrap();
    assert!(opened.unlock(None).unwrap());
}

#[test]
fn a_device_key_of_the_wrong_length_is_refused_by_name() {
    let mut fx = fresh();
    fx.vault.lock().unwrap();
    std::fs::write(fx.dir.path().join("device.key"), [7u8; 16]).unwrap();
    let mut v = Vault::open(fx.dir.path()).unwrap();
    let e = v.unlock(None).unwrap_err();
    assert!(e.to_string().contains("not 32 bytes"), "{e}");
}
