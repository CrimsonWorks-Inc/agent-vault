//! Ports `test/security/store-backup.test.js`. The JS exports version 1
//! (scrypt + ChaCha20); the port exports version 2 (Argon2id + XChaCha20)
//! and restores both, so the envelope assertions are for v2 and a v1 bundle
//! is built here exactly as the JS builds one.

use serde_json::{json, Value};

use super::helpers::*;
use crate::backup::*;
use crate::crypto;
use crate::vault::*;

const RECOVERY: &str = "correct horse battery staple";

pub(super) fn v1_bundle(plain: &Value, pass: &str) -> Value {
    let mut salt = [0u8; 16];
    crypto::fill_random(&mut salt).unwrap();
    let created_at = iso(now());
    let key = crypto::scrypt_key(
        &s(pass),
        &salt,
        &crypto::ScryptParams {
            log_n: 17,
            r: 8,
            p: 1,
            keylen: 32,
            maxmem: MAXMEM,
        },
    )
    .unwrap();
    let aad = format!("{BACKUP_FORMAT}|1|{created_at}");
    let sealed = crypto::seal_v1(&key, plain.to_string().as_bytes(), &aad).unwrap();
    json!({
        "format": BACKUP_FORMAT, "version": 1, "created_at": created_at,
        "kdf": { "name": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": crypto::b64(&salt) },
        "cipher": "chacha20-poly1305", "nonce": sealed.nonce, "ct": sealed.ct
    })
}

fn plaintext_of(bundle: &Value) -> Value {
    let p = open_bundle(bundle, &s(RECOVERY)).unwrap();
    serde_json::to_value(&p).unwrap()
}

pub(super) fn target() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::create(dir.path(), CreateOptions::default()).unwrap();
    (dir, v)
}

struct Populated {
    fx: Fx,
    token: String,
}

fn populated() -> Populated {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.add_scrub_pattern("demo", "acme_[A-Za-z0-9]{20,40}")
        .unwrap();
    v.set_credential_expiry("demo", Some("2031-01-01")).unwrap();
    v.save_template(
        "gh-read",
        &json!({ "cred": "demo", "methods": ["GET"], "spend_usd": 0.5 }),
    )
    .unwrap();
    let created = v
        .create_session(CreateSessionOptions {
            label: Some("live".into()),
            ..Default::default()
        })
        .unwrap();
    let g = grant_for(v, &created.session.id, &fx.cred.id);
    issue(v, &g.id);
    let token = av_core::secret::ExposeSecret::expose_secret(&created.token).to_string();
    Populated { fx, token }
}

fn bundle_of(r: &ExportResult) -> Value {
    serde_json::to_value(&r.bundle).unwrap()
}

pub(super) fn audit_text(v: &Vault) -> String {
    let c = v.conn();
    let mut stmt = c.prepare("SELECT record FROM audit").unwrap();
    let lines: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    lines.join("\n")
}

/// The JS `refusedCleanlyAsync(..., { audited: 1 })`: refused, nothing
/// changed but one audit record.
pub(super) fn refused_with_one_record<T>(
    v: &mut Vault,
    f: impl FnOnce(&mut Vault) -> crate::error::Result<T>,
    expected: (&str, &str),
) {
    let before = snapshot(v);
    assert_eq!(code(f(v)), rule(expected.0, Some(expected.1)));
    let after = snapshot(v);
    assert_eq!(after.0, before.0, "a refusal changed the vault");
    assert_eq!(
        after.1,
        before.1 + 1,
        "a refusal wrote more than its own record"
    );
}

#[test]
fn an_export_seals_everything_holds_no_secret_in_the_clear_and_is_logged_by_digest_only() {
    let mut p = populated();
    let out = export_backup(&mut p.fx.vault, &s(RECOVERY)).unwrap();
    let b = bundle_of(&out);
    let mut keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "cipher",
            "created_at",
            "ct",
            "format",
            "kdf",
            "nonce",
            "version"
        ]
    );
    let kdf = backup_kdf_v2();
    assert_eq!(b["kdf"]["alg"], json!("argon2id"));
    assert_eq!(
        (
            b["kdf"]["m"].as_u64(),
            b["kdf"]["t"].as_u64(),
            b["kdf"]["p"].as_u64()
        ),
        (Some(kdf.m as u64), Some(kdf.t as u64), Some(kdf.p as u64))
    );
    assert_eq!(
        crypto::b64_strict(b["kdf"]["salt"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    assert_eq!(b["cipher"], json!("xchacha20poly1305"));
    assert_eq!(b["version"], json!(2));
    assert_eq!((out.summary.credentials, out.summary.templates), (2, 1));
    assert_eq!(out.summary.created_at, b["created_at"].as_str().unwrap());
    assert_eq!(out.bundle_sha256, bundle_digest(&b));
    let text = b.to_string();
    for sec in [SECRET, OTHER_SECRET] {
        assert!(
            !text.contains(sec)
                && !text.contains(&crypto::b64(sec.as_bytes()))
                && !text.contains(&crypto::hex(sec.as_bytes()))
        );
    }
    let rec = &records(&p.fx.vault, "backup.exported")[0];
    assert_eq!(
        (
            field(rec, "credentials"),
            field(rec, "templates"),
            field(rec, "bundle_sha256")
        ),
        (&json!(2), &json!(1), &json!(out.bundle_sha256))
    );
    assert!(!audit_text(&p.fx.vault).contains(&b["ct"].as_str().unwrap()[..32]));
}

#[test]
fn the_plaintext_is_credentials_and_templates_only() {
    let mut p = populated();
    let v = &mut p.fx.vault;
    v.rotate_credential(
        "demo",
        RotateOptions {
            field: None,
            value: s("ghp_ROTATEDBACKUP00112233445566778899aa"),
            mode: RotateMode::Keep,
            retire_ms: DAY_MS,
            expires_at: None,
        },
    )
    .unwrap();
    let b = bundle_of(&export_backup(v, &s(RECOVERY)).unwrap());
    let plain = plaintext_of(&b);
    let mut keys: Vec<&String> = plain.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["credentials", "templates"]);
    let demo = plain["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["slug"] == "demo")
        .unwrap();
    let mut dk: Vec<&String> = demo.as_object().unwrap().keys().collect();
    dk.sort();
    assert_eq!(
        dk,
        vec![
            "connector",
            "created_at",
            "expires_at",
            "fields",
            "kind",
            "pins",
            "quarantine",
            "scrub_patterns",
            "slug"
        ]
    );
    assert_eq!(
        demo["fields"][0]["value"],
        json!("ghp_ROTATEDBACKUP00112233445566778899aa")
    );
    assert!(
        !plain.to_string().contains(SECRET),
        "a retired value was exported"
    );
    assert_eq!(
        plain["templates"],
        json!([{ "name": "gh-read", "spec": { "cred": "demo", "methods": ["GET"], "spend_usd": 0.5 } }])
    );
}

#[test]
fn inspect_lists_what_a_bundle_holds_without_a_single_value() {
    let mut p = populated();
    let b = bundle_of(&export_backup(&mut p.fx.vault, &s(RECOVERY)).unwrap());
    let seq = p.fx.vault.audit().unwrap().seq();
    let out = inspect_backup(&b, &s(RECOVERY)).unwrap();
    assert_eq!(out.created_at, b["created_at"].as_str().unwrap());
    let demo = out.credentials.iter().find(|c| c.slug == "demo").unwrap();
    assert_eq!(
        serde_json::to_value(demo).unwrap(),
        json!({ "slug": "demo", "kind": "http", "host": "api.example.com", "fields": ["token"],
                "has_scrub_patterns": true, "has_pins": false, "expires_at": "2031-01-01T00:00:00.000Z", "quarantined": false })
    );
    assert_eq!(out.templates, vec!["gh-read".to_string()]);
    assert!(!serde_json::to_string(&out).unwrap().contains(SECRET));
    assert_eq!(
        p.fx.vault.audit().unwrap().seq(),
        seq,
        "inspect touches no vault"
    );
}

#[test]
fn a_restore_brings_back_credentials_patterns_expiry_and_templates_and_no_session() {
    let mut p = populated();
    let (_t, mut t) = target();
    let b = bundle_of(&export_backup(&mut p.fx.vault, &s(RECOVERY)).unwrap());
    let wraps_before = t
        .conn()
        .query_row("SELECT group_concat(sealed) FROM vmk_wraps", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    let out = restore_backup(&mut t, &b, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert_eq!(
        serde_json::to_value(&out).unwrap(),
        json!({ "restored": ["demo", "other"], "skipped": [], "renamed": [], "templates": { "restored": ["gh-read"], "skipped": [] } })
    );
    let demo = t.find_credential("demo").unwrap().unwrap();
    assert_eq!(
        av_core::secret::ExposeSecret::expose_secret(&t.reveal_field(&demo.id, "token").unwrap()),
        SECRET
    );
    let other = t.find_credential("other").unwrap().unwrap();
    assert_eq!(
        av_core::secret::ExposeSecret::expose_secret(&t.reveal_field(&other.id, "token").unwrap()),
        OTHER_SECRET
    );
    assert_eq!(
        demo.fields[0].sites,
        vec!["header:authorization:Bearer".to_string()]
    );
    assert_eq!(
        demo.scrub_patterns
            .iter()
            .map(|p| p.source.clone())
            .collect::<Vec<_>>(),
        vec!["acme_[A-Za-z0-9]{20,40}"]
    );
    assert_eq!(demo.expires_at.as_deref(), Some("2031-01-01T00:00:00.000Z"));
    assert_eq!(
        t.get_template("gh-read").unwrap().unwrap().hash,
        p.fx.vault.get_template("gh-read").unwrap().unwrap().hash
    );
    assert!(
        t.sessions().unwrap().is_empty()
            && t.grants().unwrap().is_empty()
            && t.list_placeholders(None).unwrap().is_empty()
    );
    assert!(t.session_by_token(&p.token).unwrap().is_none());
    let wraps_after = t
        .conn()
        .query_row("SELECT group_concat(sealed) FROM vmk_wraps", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    assert_eq!(wraps_before, wraps_after, "a restore touched the factors");
    let rec = &records(&t, "backup.restored")[0];
    assert_eq!(field(rec, "restored"), &json!(["demo", "other"]));
    assert_eq!(field(rec, "bundle_sha256"), &json!(bundle_digest(&b)));
    assert!(!audit_text(&t).contains(SECRET));
}

#[test]
fn conflicts_skip_by_default_rename_within_24_characters_and_fail_writes_nothing() {
    let mut p = populated();
    let v = &mut p.fx.vault;
    v.add_credential(new_cred(
        "a-very-long-slug-of-24ch",
        "http",
        "long.example",
        &[("token", "tok_LONGSLUG0011223344556677")],
    ))
    .unwrap();
    let b = bundle_of(&export_backup(v, &s(RECOVERY)).unwrap());
    let skip = restore_backup(v, &b, &s(RECOVERY), ConflictMode::Skip).unwrap();
    assert!(skip.restored.is_empty());
    let mut skipped = skip.skipped.clone();
    skipped.sort();
    assert_eq!(skipped, vec!["a-very-long-slug-of-24ch", "demo", "other"]);
    assert_eq!(skip.templates.skipped, vec!["gh-read".to_string()]);
    let once = restore_backup(v, &b, &s(RECOVERY), ConflictMode::Rename).unwrap();
    let mut renames: Vec<(String, String)> = once
        .renamed
        .iter()
        .map(|r| (r.from.clone(), r.to.clone()))
        .collect();
    renames.sort();
    assert_eq!(
        renames,
        vec![
            (
                "a-very-long-slug-of-24ch".into(),
                "a-very-long-slu-restored".into()
            ),
            ("demo".into(), "demo-restored".into()),
            ("other".into(), "other-restored".into()),
        ]
    );
    let twice = restore_backup(v, &b, &s(RECOVERY), ConflictMode::Rename).unwrap();
    assert!(twice.renamed.iter().any(|r| r.to == "demo-restored-2"));
    let id = v.find_credential("demo-restored-2").unwrap().unwrap().id;
    assert_eq!(
        av_core::secret::ExposeSecret::expose_secret(&v.reveal_field(&id, "token").unwrap()),
        SECRET
    );
    refused_with_one_record(
        v,
        |v| restore_backup(v, &b, &s(RECOVERY), ConflictMode::Fail),
        ("AV_POLICY_DENIED", "backup_conflict"),
    );
    assert_eq!(
        field(records(v, "backup.refused").last().unwrap(), "reason"),
        &json!("backup_conflict")
    );
}

#[test]
fn a_wrong_passphrase_or_an_altered_bundle_is_one_answer_and_a_restore_writes_nothing_but_the_refusal(
) {
    let mut p = populated();
    let (_t, mut t) = target();
    let b = bundle_of(&export_backup(&mut p.fx.vault, &s(RECOVERY)).unwrap());
    let flip = |x: &str| {
        let mut raw = crypto::b64_strict(x).unwrap();
        raw[3] ^= 1;
        crypto::b64(&raw)
    };
    let mut ct = b.clone();
    ct["ct"] = json!(flip(b["ct"].as_str().unwrap()));
    let mut created = b.clone();
    created["created_at"] = json!(iso(0));
    let mut salt = b.clone();
    salt["kdf"]["salt"] = json!(flip(b["kdf"]["salt"].as_str().unwrap()));
    for (label, bundle, pass) in [
        ("wrong passphrase", b.clone(), "not the right passphrase"),
        ("altered ciphertext", ct, RECOVERY),
        ("altered created_at", created, RECOVERY),
        ("altered salt", salt, RECOVERY),
    ] {
        assert_eq!(
            code(inspect_backup(&bundle, &s(pass))),
            rule("AV_PRESENCE_DENIED", Some("backup_auth")),
            "{label}"
        );
        refused_with_one_record(
            &mut t,
            |t| restore_backup(t, &bundle, &s(pass), ConflictMode::Skip),
            ("AV_PRESENCE_DENIED", "backup_auth"),
        );
    }
    let reasons: Vec<Value> = records(&t, "backup.refused")
        .iter()
        .map(|r| field(r, "reason").clone())
        .collect();
    assert_eq!(reasons, vec![json!("backup_auth"); 4]);
}

#[test]
fn an_envelope_that_is_not_this_format_is_refused_before_any_key_is_derived() {
    let mut p = populated();
    let (_t, mut t) = target();
    let b = bundle_of(&export_backup(&mut p.fx.vault, &s(RECOVERY)).unwrap());
    let with = |path: &[&str], val: Value| {
        let mut x = b.clone();
        let mut cur = &mut x;
        for k in &path[..path.len() - 1] {
            cur = &mut cur[*k];
        }
        cur[path[path.len() - 1]] = val;
        x
    };
    let bad = vec![
        Value::Null,
        json!([]),
        json!("bundle"),
        with(&["format"], json!("other")),
        with(&["version"], json!(3)),
        with(&["kdf", "m"], json!(1u64 << 20)),
        with(&["kdf", "p"], json!(64)),
        with(&["kdf", "alg"], json!("pbkdf2")),
        with(&["kdf", "salt"], json!("c2hvcnQ=")),
        with(&["cipher"], json!("aes-256-gcm")),
        with(&["nonce"], json!("AAAA")),
        with(&["ct"], json!("x".repeat(16 * 1024 * 1024 + 1))),
    ];
    for bundle in bad {
        let started = std::time::Instant::now();
        assert_eq!(
            code(inspect_backup(&bundle, &s(RECOVERY))),
            rule("AV_POLICY_DENIED", Some("backup_format"))
        );
        // The 16 MiB case spends its time measuring itself, not deriving.
        let oversize = bundle["ct"]
            .as_str()
            .is_some_and(|c| c.len() > MAX_BUNDLE_BYTES);
        assert!(
            oversize || started.elapsed().as_millis() < 1000,
            "a malformed envelope cost a key derivation"
        );
        refused_with_one_record(
            &mut t,
            |t| restore_backup(t, &bundle, &s(RECOVERY), ConflictMode::Skip),
            ("AV_POLICY_DENIED", "backup_format"),
        );
    }
    for pass in ["short", ""] {
        assert_eq!(
            code(export_backup(&mut p.fx.vault, &s(pass))),
            rule("AV_POLICY_DENIED", Some("recovery_passphrase"))
        );
        assert_eq!(
            code(inspect_backup(&b, &s(pass))),
            rule("AV_POLICY_DENIED", Some("recovery_passphrase"))
        );
    }
}

fn plain_cred() -> Value {
    json!({ "slug": "demo", "kind": "http", "connector": { "host": "api.example.com" }, "created_at": "x",
            "fields": [{ "name": "token", "value": SECRET, "sites": [] }], "scrub_patterns": [], "pins": {}, "expires_at": null })
}

#[test]
fn a_correctly_sealed_bundle_that_carries_anything_outside_the_list_is_refused_whole() {
    let (_t, mut t) = target();
    let cred = plain_cred();
    let good = v1_bundle(
        &json!({ "credentials": [cred.clone()], "templates": [] }),
        RECOVERY,
    );
    let with = |k: &str, val: Value| {
        let mut c = cred.clone();
        c[k] = val;
        c
    };
    for plain in [
        json!({ "credentials": [cred.clone()], "templates": [], "sessions": { "s": { "token_hash": "x" } } }),
        json!({ "credentials": [cred.clone()], "templates": [], "kv": { "vmk_wraps": [{ "class": "none" }] } }),
        json!({ "credentials": [with("vmk_wraps", json!([]))], "templates": [] }),
        json!({ "credentials": [with("fields", json!([{ "name": "token", "value": SECRET, "sites": [], "retired": [] }]))], "templates": [] }),
        json!({ "credentials": [with("slug", json!("Not A Slug"))], "templates": [] }),
        json!({ "credentials": [with("fields", json!([]))], "templates": [] }),
        json!({ "credentials": [with("expires_at", json!("garbage"))], "templates": [] }),
        json!({ "credentials": [cred.clone()], "templates": [{ "name": "Bad Name", "spec": {} }] }),
        json!({ "credentials": [cred.clone()], "templates": [{ "name": "ok", "spec": { "presence": { "passphrase": "x" } } }] }),
        json!({ "credentials": [cred.clone()] }),
    ] {
        let b = v1_bundle(&plain, RECOVERY);
        refused_with_one_record(
            &mut t,
            |t| restore_backup(t, &b, &s(RECOVERY), ConflictMode::Skip),
            ("AV_POLICY_DENIED", "backup_format"),
        );
    }
    assert_eq!(
        restore_backup(&mut t, &good, &s(RECOVERY), ConflictMode::Skip)
            .unwrap()
            .restored,
        vec!["demo".to_string()]
    );
}

#[test]
fn a_scrub_pattern_in_a_bundle_that_would_carry_a_secret_into_this_vault_is_refused() {
    let (_t, mut t) = target();
    let mut cred = plain_cred();
    cred["scrub_patterns"] = json!([{ "source": format!("x{SECRET}") }]);
    let b = v1_bundle(&json!({ "credentials": [cred], "templates": [] }), RECOVERY);
    refused_with_one_record(
        &mut t,
        |t| restore_backup(t, &b, &s(RECOVERY), ConflictMode::Skip),
        ("AV_POLICY_DENIED", "scrub_pattern"),
    );
    assert_eq!(
        field(records(&t, "backup.refused").last().unwrap(), "reason"),
        &json!("scrub_pattern")
    );
}

#[test]
fn a_locked_vault_neither_exports_nor_restores() {
    let mut p = populated();
    let v = &mut p.fx.vault;
    let b = bundle_of(&export_backup(v, &s(RECOVERY)).unwrap());
    v.lock().unwrap();
    assert_eq!(code_of(export_backup(v, &s(RECOVERY))), "AV_LOCKED");
    assert_eq!(
        code_of(restore_backup(v, &b, &s(RECOVERY), ConflictMode::Skip)),
        "AV_LOCKED"
    );
}

#[test]
fn a_v1_bundle_restores_and_a_v2_bundle_round_trips() {
    let (_t, mut t) = target();
    let b1 = v1_bundle(
        &json!({ "credentials": [plain_cred()], "templates": [] }),
        RECOVERY,
    );
    assert!(matches!(check_envelope(&b1).unwrap(), Bundle::V1(_)));
    restore_backup(&mut t, &b1, &s(RECOVERY), ConflictMode::Skip).unwrap();
    let b2 = bundle_of(&export_backup(&mut t, &s(RECOVERY)).unwrap());
    assert!(matches!(check_envelope(&b2).unwrap(), Bundle::V2(_)));
    let (_u, mut u) = target();
    assert_eq!(
        restore_backup(&mut u, &b2, &s(RECOVERY), ConflictMode::Skip)
            .unwrap()
            .restored,
        vec!["demo".to_string()]
    );
}

#[test]
fn renamed_trims_to_24_characters_and_counts_up() {
    let mut taken = std::collections::HashSet::new();
    assert_eq!(renamed("demo", &taken), "demo-restored");
    taken.insert("demo-restored".to_string());
    assert_eq!(renamed("demo", &taken), "demo-restored-2");
    assert_eq!(
        renamed("a-very-long-slug-of-24ch", &taken),
        "a-very-long-slu-restored"
    );
}
