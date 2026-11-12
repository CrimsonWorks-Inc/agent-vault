//! Ports `test/security/store-rotate.test.js`.

use av_core::secret::ExposeSecret;
use serde_json::{json, Value};

use super::backup::audit_text;
use super::helpers::*;
use crate::model::GrantState;
use crate::vault::*;

const NEW: &str = "ghp_ROTATEDNEW00112233445566778899aabbcc";

fn rot(value: &str) -> RotateOptions {
    RotateOptions {
        field: None,
        value: s(value),
        mode: RotateMode::Keep,
        retire_ms: DAY_MS,
        expires_at: None,
    }
}

fn live_grant(v: &mut Vault, cred_id: &str) -> crate::model::GrantRecord {
    let sess = session(v);
    grant_for(v, &sess.id, cred_id)
}

fn secrets_for(v: &Vault, slug: &str) -> Vec<(String, bool)> {
    v.all_secrets()
        .unwrap()
        .into_iter()
        .filter(|x| x.label == slug)
        .map(|x| (x.secret.expose_secret().to_string(), x.retired))
        .collect()
}

fn reveal(v: &Vault, id: &str) -> String {
    v.reveal_field(id, "token")
        .unwrap()
        .expose_secret()
        .to_string()
}

#[test]
fn keep_mode_the_new_value_is_substituted_at_once_and_placeholders_already_handed_out_keep_working()
{
    let mut fx = fresh();
    let v = &mut fx.vault;
    let g = live_grant(v, &fx.cred.id);
    let row = issue(v, &g.id);
    let before = v
        .list_credentials()
        .unwrap()
        .into_iter()
        .find(|c| c.slug == "demo")
        .unwrap()
        .fields[0]
        .clone();
    let out = v.rotate_credential("demo", rot(NEW)).unwrap();
    assert_eq!(reveal(v, &fx.cred.id), NEW);
    v.consume_placeholder(&row.id).unwrap();
    assert_eq!(grant_row(v, &g.id).state, GrantState::Active);
    let r = &out.rotated;
    assert_eq!(
        (r.field.as_str(), r.version, r.mode, r.revoked_grants),
        ("token", 2, RotateMode::Keep, 0)
    );
    assert_eq!(r.previous_fp8, before.fp8);
    assert_ne!(r.fp8, before.fp8);
    assert_ne!(r.fp8, crate::crypto::sha256_hex(NEW.as_bytes())[..8]);
    assert_eq!(out.credential.fields[0].version, 2);
    assert!(out.credential.fields[0].rotated_at.is_some());
    assert!((parse(&r.retire_until) - (now() + DAY)).abs() < 2000);
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    assert_eq!(reveal(&again, &fx.cred.id), NEW);
}

#[test]
fn the_rotation_is_audited_with_fingerprints_and_counts_never_a_value() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let out = v
        .rotate_credential(
            "demo",
            RotateOptions {
                retire_ms: HOUR,
                ..rot(NEW)
            },
        )
        .unwrap();
    let rec = &records(v, "cred.rotated")[0];
    let want = serde_json::to_value(&out.rotated).unwrap();
    for k in [
        "field",
        "version",
        "previous_fp8",
        "fp8",
        "mode",
        "revoked_grants",
        "retire_until",
    ] {
        assert_eq!(field(rec, k), &want[k], "{k}");
    }
    assert_eq!(field(rec, "credential_slug"), &json!("demo"));
    let log = audit_text(v);
    for x in [
        SECRET.to_string(),
        NEW.to_string(),
        crate::crypto::b64(NEW.as_bytes()),
    ] {
        assert!(!log.contains(&x), "a value reached the audit log");
    }
    let disk = snapshot(v).0;
    assert!(
        !disk.contains(SECRET) && !disk.contains(NEW),
        "a value reached the database unsealed"
    );
}

#[test]
fn the_old_value_is_still_scrubbed_within_the_retire_window_and_not_after_it() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.rotate_credential(
        "demo",
        RotateOptions {
            retire_ms: HOUR,
            ..rot(NEW)
        },
    )
    .unwrap();
    assert_eq!(
        secrets_for(v, "demo"),
        vec![(NEW.to_string(), false), (SECRET.to_string(), true)]
    );
    let later = now() + 2 * HOUR;
    assert_eq!(
        at(later, || secrets_for(v, "demo")),
        vec![(NEW.to_string(), false)]
    );
    assert_eq!(
        v.find_credential("demo").unwrap().unwrap().fields[0]
            .retired
            .len(),
        1
    );
    at(later, || {
        v.rotate_credential("demo", rot("ghp_THIRD00112233445566778899aabbccdd"))
    })
    .unwrap();
    let versions: Vec<u32> = v.find_credential("demo").unwrap().unwrap().fields[0]
        .retired
        .iter()
        .map(|r| r.key_version)
        .collect();
    assert_eq!(versions, vec![2]);
    assert_eq!(
        reveal(v, &fx.cred.id),
        "ghp_THIRD00112233445566778899aabbccdd"
    );
}

#[test]
fn a_zero_retire_window_keeps_nothing_of_the_old_value() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.rotate_credential(
        "demo",
        RotateOptions {
            retire_ms: 0,
            ..rot(NEW)
        },
    )
    .unwrap();
    assert!(v.find_credential("demo").unwrap().unwrap().fields[0]
        .retired
        .is_empty());
    assert_eq!(secrets_for(v, "demo"), vec![(NEW.to_string(), false)]);
}

#[test]
fn a_retired_value_still_counts_as_a_stored_value_for_scrub_patterns() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.rotate_credential("demo", rot(NEW)).unwrap();
    let src = format!("x{SECRET}");
    refused_cleanly(
        v,
        |v| v.add_scrub_pattern("other", &src),
        ("AV_POLICY_DENIED", Some("scrub_pattern")),
    );
}

#[test]
fn revoke_mode_revokes_the_credentials_grants_and_kills_their_placeholders_and_nobody_elses() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let a = live_grant(v, &fx.cred.id);
    let b = live_grant(v, &fx.cred.id);
    let mine = issue(v, &a.id);
    let theirs = live_grant(v, &fx.other.id);
    let other_row = issue(v, &theirs.id);
    let out = v
        .rotate_credential(
            "demo",
            RotateOptions {
                mode: RotateMode::Revoke,
                ..rot(NEW)
            },
        )
        .unwrap();
    assert_eq!(out.rotated.revoked_grants, 2);
    assert_eq!(grant_row(v, &a.id).state, GrantState::Revoked);
    assert_eq!(grant_row(v, &b.id).state, GrantState::Revoked);
    assert_eq!(code_of(v.consume_placeholder(&mine.id)), "AV_PH_REPLAY");
    let reasons: Vec<Value> = records(v, "grant.revoked")
        .iter()
        .map(|r| field(r, "reason").clone())
        .collect();
    assert_eq!(
        reasons,
        vec![json!("credential_rotated"), json!("credential_rotated")]
    );
    assert_eq!(grant_row(v, &theirs.id).state, GrantState::Active);
    v.consume_placeholder(&other_row.id).unwrap();
}

#[test]
fn the_expiry_is_cleared_by_default_and_set_when_given() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.set_credential_expiry("demo", Some("2030-01-01")).unwrap();
    v.rotate_credential("demo", rot(NEW)).unwrap();
    assert_eq!(v.find_credential("demo").unwrap().unwrap().expires_at, None);
    v.rotate_credential(
        "demo",
        RotateOptions {
            expires_at: Some("2031-02-03".into()),
            ..rot(&format!("{NEW}x"))
        },
    )
    .unwrap();
    assert_eq!(
        v.find_credential("demo")
            .unwrap()
            .unwrap()
            .expires_at
            .as_deref(),
        Some("2031-02-03T00:00:00.000Z")
    );
    v.rotate_credential("demo", rot(&format!("{NEW}y")))
        .unwrap();
    assert_eq!(v.find_credential("demo").unwrap().unwrap().expires_at, None);
}

#[test]
fn a_bad_rotation_is_refused_before_anything_changes_revoke_mode_included() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    live_grant(v, &fx.cred.id);
    let g = live_grant(v, &fx.cred.id);
    issue(v, &g.id);
    let revoke = |o: RotateOptions| RotateOptions {
        mode: RotateMode::Revoke,
        ..o
    };
    let cases: Vec<(RotateOptions, (&str, Option<&str>))> = vec![
        (rot(SECRET), ("AV_POLICY_DENIED", Some("rotate_same_value"))),
        (
            revoke(RotateOptions {
                retire_ms: -1,
                ..rot(NEW)
            }),
            ("AV_POLICY_DENIED", Some("retire_window")),
        ),
        (
            revoke(RotateOptions {
                retire_ms: 7 * DAY_MS + 1,
                ..rot(NEW)
            }),
            ("AV_POLICY_DENIED", Some("retire_window")),
        ),
        (
            revoke(RotateOptions {
                expires_at: Some("garbage".into()),
                ..rot(NEW)
            }),
            ("AV_POLICY_DENIED", Some("expires_at")),
        ),
        (rot(""), ("AV_POLICY_DENIED", Some("value_empty"))),
        (
            RotateOptions {
                field: Some("nope".into()),
                ..rot(NEW)
            },
            ("AV_NOT_FOUND", None),
        ),
    ];
    for (opts, expected) in cases {
        refused_cleanly(v, |v| v.rotate_credential("demo", opts), expected);
    }
    refused_cleanly(
        v,
        |v| v.rotate_credential("nope", rot(NEW)),
        ("AV_NOT_FOUND", None),
    );
    v.rotate_credential(
        "demo",
        RotateOptions {
            retire_ms: 7 * DAY_MS,
            ..rot(NEW)
        },
    )
    .unwrap();
    v.rotate_credential(
        "other",
        RotateOptions {
            retire_ms: 0,
            ..rot(&format!("{OTHER_SECRET}2"))
        },
    )
    .unwrap();
    v.lock().unwrap();
    assert_eq!(
        code_of(v.rotate_credential("demo", rot("x-new-value"))),
        "AV_LOCKED"
    );
}
