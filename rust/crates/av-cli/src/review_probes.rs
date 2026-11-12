//! Review probes (review-cli-1). Hardening regression tests: each names an
//! input shape and pairs it with an ordinary control.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::commands::{as_rpc, parent_env_kept};
use crate::setup::{copy_dereference, refuses_self_install};

// ---- exec scrub: a URL password that is not the first `://` in the value.

#[test]
fn probe_exec_scrub_drops_a_second_url_with_a_password() {
    // JS urlHasPassword -> true (regex matches anywhere in the value).
    assert!(
        !parent_env_kept("DB_URLS", "http://cache.local postgres://app:pw@db/app"),
        "a second URL with a password reached the exec child"
    );
}

#[test]
fn probe_exec_scrub_drops_a_url_whose_first_authority_has_no_password() {
    // JS -> true.
    assert!(
        !parent_env_kept("MIRRORS", "x://a@b y://u:pw@h"),
        "a later user:password@ reached the exec child"
    );
}

#[test]
fn probe_exec_scrub_drops_a_password_with_a_space() {
    // JS: the regex misses it, `new URL(v).password` is "p%20w" -> true.
    assert!(
        !parent_env_kept("UPSTREAM", "https://u:p w@h"),
        "a password with a space reached the exec child"
    );
}

#[test]
fn probe_exec_scrub_control_keeps_ordinary_values() {
    assert!(parent_env_kept("HOME", "/Users/someone"));
    assert!(parent_env_kept("SITE", "https://example.com/a@b"));
    assert!(!parent_env_kept("DATABASE_URL", "postgres://app:pw@db"));
}

#[test]
fn probe_exec_scrub_drops_non_special_scheme_with_a_space_in_the_host() {
    // JS `new URL("foo://u:p w@h st")` throws, so urlHasPassword keeps the
    // value. Rust re-parses spaces as %20 and then sees a password. Dropping
    // it is the safe direction; the difference is accepted, not a bug.
    assert!(crate::commands::looks_like_credential(
        "PLAIN",
        "foo://u:p w@h st"
    ));
}

// ---- installer: self-install guard compared after canonicalize.

#[test]
fn probe_self_install_guard_survives_a_symlinked_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir_all(real.join("app")).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // What checkout_from does with --from, against what app_dir() returns.
    let app = link.join("app");
    let source = app.canonicalize().unwrap();
    assert!(
        refuses_self_install(&source, &app),
        "--from {} names the app dir through a symlinked prefix and is not refused",
        app.display()
    );
}

#[test]
fn probe_self_install_control_same_spelling_is_refused() {
    let p = PathBuf::from("/var/db/agent-vault/app");
    assert!(refuses_self_install(&p, &p));
}

#[test]
#[cfg(target_os = "macos")]
fn probe_var_is_a_symlink_on_macos() {
    // The install root /var/db/agent-vault canonicalizes to /private/var/...
    assert_eq!(
        Path::new("/var/db").canonicalize().unwrap(),
        PathBuf::from("/private/var/db")
    );
}

// ---- installer: the copy keeps setuid/setgid bits.

#[test]
fn probe_copy_strips_setuid_bits() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tool");
    std::fs::write(&src, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let dst = tmp.path().join("copy");
    copy_dereference(&src, &dst).unwrap();
    let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o7000,
        0,
        "the installer copy kept mode {:o}; root's chown -R then makes it a root setuid file",
        mode & 0o7777
    );
}

#[test]
fn probe_copy_control_ordinary_file() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("plain");
    std::fs::write(&src, b"x").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
    let dst = tmp.path().join("copy");
    copy_dereference(&src, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), b"x");
}

// ---- installer: service units keep the JS hardening (source probe, the
// JS tests are source greps too).

const SETUP_SRC: &str = include_str!("setup.rs");

#[test]
fn probe_service_units_keep_the_js_hardening() {
    let missing: Vec<&str> = [
        "SoftResourceLimits",
        "LimitCORE=0",
        "SupplementaryGroups=",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=",
        "WantedBy=multi-user.target",
        "RuntimeDirectory=",
    ]
    .into_iter()
    .filter(|needle| !SETUP_SRC.contains(needle))
    .collect();
    assert!(missing.is_empty(), "service unit lost: {missing:?}");
}

/// The non-dry half of `write_root_file`: everything after the dry-run return.
fn write_root_file_non_dry() -> &'static str {
    let start = SETUP_SRC
        .find("fn write_root_file(")
        .expect("write_root_file");
    let rest = &SETUP_SRC[start..];
    let end = rest.find("\nfn ").expect("function after write_root_file");
    let body = &rest[..end];
    let dry = body.find("return Ok(());").expect("dry-run return");
    &body[dry + "return Ok(());".len()..]
}

#[test]
fn write_root_file_non_dry_sets_0644_and_chowns_root() {
    let body = write_root_file_non_dry();
    assert!(
        body.contains("set_mode(0o644)"),
        "the non-dry write does not set 0644:\n{body}"
    );
    assert!(
        body.contains("[\"0:0\""),
        "the non-dry write does not chown 0:0:\n{body}"
    );
}

#[test]
fn probe_service_units_control_label_present() {
    assert!(SETUP_SRC.contains("com.agentvault.daemon"));
}

// ---- mcp bridge: the JSON-RPC error data omits absent fields as JS does.

#[test]
fn probe_mcp_error_data_omits_absent_hint_and_next() {
    let out = as_rpc(
        r#"{"code":"AV_SESSION_EXPIRED","detail":"gone"}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#,
        401,
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let data = &v["error"]["data"];
    assert_eq!(
        data,
        &serde_json::json!({"http_status": 401}),
        "JS JSON.stringify drops undefined hint/next; got {data}"
    );
}

#[test]
fn probe_mcp_control_message_passes_through() {
    let body = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    assert_eq!(as_rpc(body, "{}", 200), body);
}
