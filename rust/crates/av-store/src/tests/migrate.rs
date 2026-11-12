//! The migrate library (rust/PLAN.md, "`agent-vault migrate`"), against a
//! JS vault that the JS store code builds in a temp dir at test time
//! (`fixtures/make-js-vault.mjs`; never the real vault).

use std::path::{Path, PathBuf};

use av_core::secret::ExposeSecret;
use serde_json::{json, Value};

use super::helpers::*;
use crate::audit::ReadFilter;
use crate::migrate::*;
use crate::model::{FactorClass, PlaceholderState};
use crate::vault::*;

struct JsVault {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    out: Value,
}

fn repo_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src")
        .canonicalize()
        .expect("the JS reference at src/")
}

/// Build a JS vault with the JS store (`node`, required: the fixture is the
/// JS code itself).
fn js_vault(factor: &str) -> JsVault {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let out = tmp.path().join("out.json");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/fixtures/make-js-vault.mjs");
    let status = std::process::Command::new("node")
        .arg(&script)
        .arg(repo_src())
        .arg(&dir)
        .arg(factor)
        .arg(&out)
        .status()
        .expect("node is needed to build the JS fixture vault");
    assert!(status.success(), "the JS fixture script failed");
    let out: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    JsVault {
        _tmp: tmp,
        dir,
        out,
    }
}

fn opts(from: &Path, to: &Path, dry_run: bool) -> MigrateOptions {
    MigrateOptions {
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        dry_run,
    }
}

/// Every file in a dir with its bytes, to prove what was or was not touched.
fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    out.sort();
    out
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

fn reveal(v: &Vault, slug: &str) -> String {
    let id = v.find_credential(slug).unwrap().unwrap().id;
    v.reveal_field(&id, "token")
        .map(|s| s.expose_secret().to_string())
        .unwrap_or_else(|e| format!("refused: {e}"))
}

#[test]
fn a_js_vault_migrates_and_everything_minted_before_still_works_after() {
    let js = js_vault("none");
    let legacy_before = listing(&js.dir);
    preflight(&opts(&js.dir, &js.dir, false)).unwrap();
    let legacy = read_legacy(&js.dir).unwrap();
    assert!(!needs_passphrase(&legacy));
    let report = migrate(&opts(&js.dir, &js.dir, false), legacy, None).unwrap();
    assert!(!report.dry_run && !report.already_migrated);
    assert_eq!(
        report.written.as_deref(),
        Some(js.dir.join("vault.db").as_path())
    );
    assert_eq!(report.counts["credentials"], 3);
    assert_eq!(report.counts["sessions"], 2);
    assert_eq!(report.counts["grants"], 3);
    assert_eq!(report.counts["templates"], 1);
    assert_eq!(report.counts["listeners"], 1);
    assert_eq!(report.counts["workspaces"], 1);
    assert_eq!(report.counts["pins"], 1);
    assert_eq!(report.counts["tripwires"], 1);
    assert_eq!(report.counts["notify"], 1);
    assert_eq!(report.counts["session_requests"], 1);
    assert_eq!(report.audit_head.as_deref(), Some(str_of(&js.out, "head")));
    assert!(report.dropped.is_empty());
    assert!(report
        .legacy_files
        .iter()
        .any(|p| p.ends_with("vault.json")));

    // The JS files are untouched, byte for byte.
    let after: Vec<(String, Vec<u8>)> = listing(&js.dir)
        .into_iter()
        .filter(|(n, _)| legacy_before.iter().any(|(m, _)| m == n))
        .collect();
    assert_eq!(after, legacy_before, "migrate modified a legacy file");

    let mut v = Vault::open(&js.dir).unwrap();
    v.unlock(None).unwrap();
    let secrets = &js.out["secrets"];
    assert_eq!(reveal(&v, "demo"), str_of(secrets, "demo"));
    assert_eq!(reveal(&v, "gh"), str_of(secrets, "gh"));
    assert!(
        reveal(&v, "other").contains("AV_QUARANTINED"),
        "a quarantine was released by migrating"
    );
    // The retired value is still scrubbed, re-sealed under the same key.
    assert!(v
        .all_secrets()
        .unwrap()
        .iter()
        .any(|x| x.retired && x.secret.expose_secret() == str_of(secrets, "gh_old")));

    // A session token and a placeholder minted by the JS daemon still work.
    let token = str_of(&js.out, "token");
    let sess = v
        .session_by_token(token)
        .unwrap()
        .expect("the JS session token resolves");
    assert_eq!(sess.id, str_of(&js.out, "session_id"));
    v.assert_session_live(Some(&sess)).unwrap();
    let parsed = av_core::placeholder::parse_at(str_of(&js.out, "placeholder"), 0).unwrap();
    assert!(
        av_core::placeholder::verify(&v.k_ph().unwrap(), &parsed),
        "the JS placeholder's checksum no longer verifies"
    );
    let row = v
        .resolve_placeholder(&parsed)
        .unwrap()
        .expect("the JS ledger row came across");
    assert_eq!(row.id, str_of(&js.out, "row_id"));
    assert_eq!(row.uses, 1);
    assert_eq!(v.consume_placeholder(&row.id).unwrap().uses, 2);
    let gh = av_core::placeholder::parse_at(str_of(&js.out, "gh_placeholder"), 0).unwrap();
    assert!(av_core::placeholder::verify(&v.k_ph().unwrap(), &gh));
    // The revoked session stays revoked, its placeholders dead.
    let ended = v
        .session(str_of(&js.out, "ended_session_id"))
        .unwrap()
        .unwrap();
    assert_eq!(
        code_of(v.assert_session_live(Some(&ended))),
        "AV_SESSION_REVOKED"
    );

    // Everything else came across with ids unchanged.
    let demo = v.find_credential("demo").unwrap().unwrap();
    assert_eq!(demo.expires_at.as_deref(), Some("2031-01-01T00:00:00.000Z"));
    assert_eq!(
        demo.pins.get("api.example.com"),
        Some(&vec![str_of(&js.out, "pin").to_string()])
    );
    assert_eq!(demo.scrub_patterns.len(), 1);
    assert_eq!(
        demo.health.as_ref().map(|h| h.status),
        Some(crate::model::HealthStatus::Ok)
    );
    let hook = v.get_notify_webhook().unwrap().unwrap();
    assert_eq!(hook.url.expose_secret(), str_of(&js.out, "webhook"));
    assert_eq!(
        v.get_template("gh-read").unwrap().unwrap().spec["spend_usd"],
        json!(0.5)
    );
    assert_eq!(
        v.find_workspace("team").unwrap().unwrap().id,
        str_of(&js.out, "workspace_id")
    );
    assert_eq!(v.list_listeners().unwrap()[0].id, "lan");
    assert_eq!(v.get_settings().unwrap()["retention_days"], json!(30));
    assert_eq!(
        v.session_requests().unwrap()[0].id,
        "sr_FIXTURE0000000000000000000"
    );
    assert_eq!(
        v.ui_origins().unwrap(),
        vec!["http://127.0.0.1:7777".to_string()]
    );
    let pk = v.presence_key().unwrap().unwrap();
    assert_eq!(
        pk.credential_id,
        str_of(&js.out["presence"], "credentialId")
    );
    assert_eq!(pk.sign_count, 7);

    // The audit log came across whole, and vault.migrated chains to its head.
    let audit = v.audit().unwrap();
    let report2 = audit.verify().unwrap();
    assert!(report2.ok, "{:?}", report2.reason);
    let rows = audit
        .read(&ReadFilter {
            limit: 0,
            ..Default::default()
        })
        .unwrap();
    let migrated = rows
        .iter()
        .find(|r| r.kind == "vault.migrated")
        .expect("a vault.migrated record");
    assert_eq!(migrated.prev_hash, str_of(&js.out, "head"));
    assert_eq!(migrated.seq, js.out["seq"].as_u64().unwrap() + 1);
    // A witness checkpoint the JS issued still verifies: same key, same id.
    let w = js.out["witness"].clone();
    let out = v.audit_mut().unwrap().verify_witness(&[w]).unwrap();
    assert!(out.ok, "{out:?}");
    assert!(out.other_vault.is_empty());
}

#[test]
fn a_passphrase_vault_needs_its_passphrase_and_its_touch_id_wrap_is_dropped_and_reported() {
    let js = js_vault("passphrase");
    let legacy = read_legacy(&js.dir).unwrap();
    assert!(needs_passphrase(&legacy));
    assert!(matches!(
        migrate(
            &opts(&js.dir, &js.dir, false),
            read_legacy(&js.dir).unwrap(),
            None
        ),
        Err(MigrateError::PassphraseRequired)
    ));
    assert!(matches!(
        migrate(
            &opts(&js.dir, &js.dir, false),
            read_legacy(&js.dir).unwrap(),
            Some(&s("not-the-passphrase"))
        ),
        Err(MigrateError::WrongPassphrase)
    ));
    assert!(
        !js.dir.join("vault.db").exists(),
        "a refused migration wrote something"
    );
    let pass = s(str_of(&js.out, "passphrase"));
    let report = migrate(&opts(&js.dir, &js.dir, false), legacy, Some(&pass)).unwrap();
    assert_eq!(report.dropped.len(), 1);
    assert!(report.dropped[0].what.contains("webauthn-prf"));
    assert_eq!(report.dropped[0].next, "agent-vault ui");
    let mut v = Vault::open(&js.dir).unwrap();
    assert_eq!(v.factors().unwrap(), vec![FactorClass::Passphrase]);
    assert!(!v.has_webauthn_unlock().unwrap());
    assert_eq!(code_of(v.unlock(None)), "AV_LOCKED");
    assert!(v.unlock(Some(&pass)).unwrap());
    // Re-wrapped under Argon2id, parameters beside the wrap.
    let wrap = crate::rows::wraps_get(&v.conn())
        .unwrap()
        .into_iter()
        .find(|w| w.class == FactorClass::Passphrase)
        .unwrap();
    assert_eq!(wrap.kdf.unwrap().alg, crate::crypto::ArgonAlg::Argon2id);
    assert_eq!(wrap.sealed.alg, "xchacha20poly1305");
    assert_eq!(reveal(&v, "demo"), str_of(&js.out["secrets"], "demo"));
    let migrated = v
        .audit()
        .unwrap()
        .read(&ReadFilter {
            limit: 0,
            kind: Some("vault.migrated".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(migrated.len(), 1);
    assert_eq!(
        migrated[0].fields["dropped"],
        json!(["webauthn-prf unlock wrap"])
    );
}

fn rewrite_audit(dir: &Path, f: impl FnOnce(&mut Vec<String>)) {
    let path = dir.join("audit.jsonl");
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    f(&mut lines);
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
}

#[test]
fn a_tampered_audit_log_is_refused_and_nothing_is_written() {
    // An edited record: the chain breaks there.
    let js = js_vault("none");
    rewrite_audit(&js.dir, |lines| {
        let mut rec: Value = serde_json::from_str(&lines[3]).unwrap();
        rec["ts"] = json!("2020-01-01T00:00:00.000Z");
        lines[3] = rec.to_string();
    });
    let before = listing(&js.dir);
    let legacy = read_legacy(&js.dir).unwrap();
    match migrate(&opts(&js.dir, &js.dir, false), legacy, None) {
        Err(MigrateError::AuditBroken { at, reason }) => {
            assert_eq!(at, "seq 4");
            assert!(reason.contains("hash mismatch"), "{reason}");
        }
        other => panic!("not refused: {other:?}"),
    }
    assert_eq!(
        listing(&js.dir),
        before,
        "a refused migration wrote something"
    );

    // Records cut from the end: the anchor says where the log should end.
    let js = js_vault("none");
    rewrite_audit(&js.dir, |lines| {
        lines.truncate(lines.len() - 3);
    });
    let legacy = read_legacy(&js.dir).unwrap();
    match migrate(&opts(&js.dir, &js.dir, false), legacy, None) {
        Err(MigrateError::AuditBroken { reason, .. }) => {
            assert!(reason.contains("removed from the end"), "{reason}")
        }
        other => panic!("not refused: {other:?}"),
    }
    assert!(!js.dir.join("vault.db").exists());

    // A record removed from the middle: refused before any key is used.
    let js = js_vault("none");
    rewrite_audit(&js.dir, |lines| {
        lines.remove(5);
    });
    assert!(matches!(
        read_legacy(&js.dir),
        Err(MigrateError::AuditBroken { .. })
    ));

    // The anchor removed as well: the end of the log cannot be trusted.
    let js = js_vault("none");
    std::fs::remove_file(js.dir.join("audit.jsonl.head")).unwrap();
    let legacy = read_legacy(&js.dir).unwrap();
    assert!(matches!(
        migrate(&opts(&js.dir, &js.dir, false), legacy, None),
        Err(MigrateError::AuditBroken { .. })
    ));
    assert!(!js.dir.join("vault.db").exists());
}

#[test]
fn a_second_run_is_a_no_op() {
    let js = js_vault("none");
    migrate(
        &opts(&js.dir, &js.dir, false),
        read_legacy(&js.dir).unwrap(),
        None,
    )
    .unwrap();
    let before = listing(&js.dir);
    assert!(matches!(
        preflight(&opts(&js.dir, &js.dir, false)),
        Err(MigrateError::AlreadyMigrated(_))
    ));
    assert!(matches!(
        migrate(
            &opts(&js.dir, &js.dir, false),
            read_legacy(&js.dir).unwrap(),
            None
        ),
        Err(MigrateError::AlreadyMigrated(_))
    ));
    assert_eq!(listing(&js.dir), before, "a second run changed something");
}

#[test]
fn dry_run_writes_nothing_and_reports_the_same_counts() {
    let js = js_vault("none");
    let before = listing(&js.dir);
    let dry = migrate(
        &opts(&js.dir, &js.dir, true),
        read_legacy(&js.dir).unwrap(),
        None,
    )
    .unwrap();
    assert!(dry.dry_run);
    assert_eq!(dry.written, None);
    assert_eq!(listing(&js.dir), before, "a dry run wrote something");
    let real = migrate(
        &opts(&js.dir, &js.dir, false),
        read_legacy(&js.dir).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(dry.counts, real.counts);
    assert_eq!(dry.audit_head, real.audit_head);
    assert_eq!(
        (dry.audit_first_seq, dry.audit_last_seq),
        (Some(1), js.out["seq"].as_u64())
    );
    // The report is data for --json.
    let j = serde_json::to_value(&dry).unwrap();
    assert_eq!(j["dry_run"], json!(true));
}

#[test]
fn a_migration_into_another_directory_brings_the_device_key_and_leaves_the_source_alone() {
    let js = js_vault("none");
    let to = js._tmp.path().join("new");
    let before = listing(&js.dir);
    migrate(
        &opts(&js.dir, &to, false),
        read_legacy(&js.dir).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(listing(&js.dir), before);
    assert_eq!(
        std::fs::read(to.join("device.key")).unwrap(),
        std::fs::read(js.dir.join("device.key")).unwrap()
    );
    let mut v = Vault::open(&to).unwrap();
    v.unlock(None).unwrap();
    assert_eq!(reveal(&v, "demo"), str_of(&js.out["secrets"], "demo"));
    // A target holding another vault's device key is refused.
    let other = js._tmp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("device.key"), [9u8; 32]).unwrap();
    assert!(migrate(
        &opts(&js.dir, &other, false),
        read_legacy(&js.dir).unwrap(),
        None
    )
    .is_err());
    assert!(!other.join("vault.db").exists());
}

#[test]
fn a_running_js_daemon_is_detected_and_a_missing_vault_is_named() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!js_daemon_running(tmp.path()));
    assert!(matches!(
        read_legacy(tmp.path()),
        Err(MigrateError::NoLegacyVault(_))
    ));
    let _listener =
        std::os::unix::net::UnixListener::bind(tmp.path().join("control.sock")).unwrap();
    assert!(js_daemon_running(tmp.path()));
    match preflight(&opts(tmp.path(), tmp.path(), false)) {
        Err(MigrateError::DaemonRunning { next, .. }) => assert!(next.contains("stop")),
        other => panic!("not refused: {other:?}"),
    }
}

#[test]
fn a_backup_the_js_daemon_made_restores_into_the_rust_vault() {
    let js = js_vault("none");
    let (_t, mut t) = super::backup::target();
    let bundle = js.out["bundle"].clone();
    assert_eq!(bundle["version"], json!(1));
    let out = crate::backup::restore_backup(
        &mut t,
        &bundle,
        &s(str_of(&js.out, "recovery")),
        crate::backup::ConflictMode::Skip,
    )
    .unwrap();
    let mut restored = out.restored.clone();
    restored.sort();
    assert_eq!(restored, vec!["demo", "gh", "other"]);
    assert_eq!(reveal(&t, "demo"), str_of(&js.out["secrets"], "demo"));
    assert!(reveal(&t, "other").contains("AV_QUARANTINED"));
    assert_eq!(
        t.get_template("gh-read").unwrap().unwrap().spec["cred"],
        json!("gh")
    );
    let _ = PlaceholderState::Active;
}

#[test]
fn migrate_never_writes_vault_db_in_place_the_finished_file_is_renamed() {
    let js = js_vault("none");
    let opts = opts(&js.dir, &js.dir, false);
    crate::migrate::test_hook::STOP_BEFORE_RENAME.with(|c| c.set(true));
    let stopped = migrate(&opts, read_legacy(&js.dir).unwrap(), None);
    crate::migrate::test_hook::STOP_BEFORE_RENAME.with(|c| c.set(false));
    assert!(stopped.is_err(), "the hook did not stop the migration");
    // The whole database is written, under another name, and vault.db does
    // not exist until the rename.
    assert!(
        !js.dir.join("vault.db").exists(),
        "vault.db was written in place"
    );
    let temp = js.dir.join(".vault.db.migrating");
    assert!(temp.exists(), "the finished temp database is missing");
    let c = rusqlite::Connection::open(&temp).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3, "the temp database is not the finished one");
    drop(c);
    // Control: the same run without the hook renames it into place.
    std::fs::remove_file(&temp).unwrap();
    migrate(&opts, read_legacy(&js.dir).unwrap(), None).unwrap();
    assert!(js.dir.join("vault.db").exists());
    assert!(!temp.exists());
}
