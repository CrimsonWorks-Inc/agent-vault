//! Review probes (review-cli-1) that drive the built binaries.

use assert_cmd::cargo::cargo_bin;
use std::process::Command;

#[test]
fn probe_migrate_refuses_a_foreign_vault_db_instead_of_calling_it_done() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("vault.db"), b"not a database").unwrap();
    let out = Command::new(cargo_bin("agent-vault"))
        .args(["migrate", "--json", "--from"])
        .arg(tmp.path())
        .arg("--to")
        .arg(tmp.path())
        .env("AGENT_VAULT_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success() && !stdout.contains("\"already_migrated\": true"),
        "a garbage vault.db was reported as a completed migration: exit {:?} {stdout}",
        out.status.code()
    );
}

#[test]
fn probe_migrate_control_empty_dir_is_not_already_migrated() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(cargo_bin("agent-vault"))
        .args(["migrate", "--json", "--dry-run", "--from"])
        .arg(tmp.path())
        .env("AGENT_VAULT_DIR", tmp.path())
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn probe_dry_run_checks_the_root_chain_so_the_row_is_testable() {
    // PORTED.md says the root-chain refusal is "not applicable" because it
    // runs only on the root path. It runs under --dry-run too.
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(cargo_bin("agent-vault-setup"))
        .args(["install", "--dry-run"])
        .env("AGENT_VAULT_SETUP_DRY_ROOT", tmp.path().join("root"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("root must not execute from it"), "{stderr}");
}

#[test]
fn probe_dry_run_control_default_root_plans() {
    let out = Command::new(cargo_bin("agent-vault-setup"))
        .args(["install", "--dry-run"])
        .env_remove("AGENT_VAULT_SETUP_DRY_ROOT")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn probe_migrate_refuses_a_daemon_socket_under_av_run_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("from");
    let run = tmp.path().join("run");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(run.join("control.sock")).unwrap();
    let out = Command::new(cargo_bin("agent-vault"))
        .args(["migrate", "--from"])
        .arg(&from)
        .env("AGENT_VAULT_DIR", &from)
        .env("AV_RUN_DIR", &run)
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    drop(listener);
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("daemon"), "{err}");
    assert!(err.contains("stop the daemon"), "{err}");
    assert!(!from.join("vault.db").exists());
}

#[test]
fn probe_dry_run_uninstall_says_the_service_user_stays() {
    // PORTED.md marks this "not applicable"; the dry-run text shows it.
    let out = Command::new(cargo_bin("agent-vault-setup"))
        .args(["uninstall", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("removing it would free its uid for reuse")
    );
}
