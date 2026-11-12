//! Review probes (review-cli-1) that drive the built binaries.

use assert_cmd::cargo::cargo_bin;
use std::os::unix::fs::PermissionsExt;
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
    // Not `<from>/../run`: that path is the old parent/run candidate, so this
    // probe used to pass with the AV_RUN_DIR half reverted.
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("a").join("from");
    let run = tmp.path().join("b").join("elsewhere");
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
fn probe_migrate_refuses_the_cli_socket_path() {
    // AGENT_VAULT_DIR names a different dir than --from; its control.sock is live.
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("a").join("from");
    let dev = tmp.path().join("c").join("dev");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::create_dir_all(&dev).unwrap();
    let sock = dev.join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let out = Command::new(cargo_bin("agent-vault"))
        .args(["migrate", "--from"])
        .arg(&from)
        .env("AGENT_VAULT_DIR", &dev)
        .env_remove("AV_RUN_DIR")
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
    assert!(err.contains("stop the daemon"), "{err}");
    assert!(
        err.contains(&sock.display().to_string()),
        "the refusal names the wrong vault, not the socket that answered: {err}"
    );
    assert!(
        !err.contains(&format!("against {}", from.display())),
        "the refusal names --from instead of the socket: {err}"
    );
}

#[test]
fn probe_uninstall_dry_run_lists_what_state_json_recorded() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let app = root.join("app");
    let state = format!(
        r#"{{"created":[{{"kind":"dir","id":"{}"}},{{"kind":"dir","id":"{}"}},{{"kind":"file","id":"/nonexistent/review2.plist"}}],"version":1}}"#,
        root.display(),
        app.display()
    );
    std::fs::write(root.join("state.json"), state).unwrap();
    let out = Command::new(cargo_bin("agent-vault-setup"))
        .args(["uninstall", "--dry-run"])
        .env("AGENT_VAULT_SETUP_DRY_ROOT", &root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("removed {}", app.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains("removed /nonexistent/review2.plist"),
        "{stdout}"
    );
    assert!(
        root.join("state.json").exists(),
        "dry run deleted state.json"
    );
}

#[test]
fn probe_install_rejects_a_bad_port_before_any_change() {
    let out = Command::new(cargo_bin("agent-vault-setup"))
        .args(["install", "--dry-run", "--port", "80<x>"])
        .env_remove("AGENT_VAULT_SETUP_DRY_ROOT")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "{stdout}{stderr}");
    assert!(stderr.contains("--port must be an integer"), "{stderr}");
    assert!(!stdout.contains("mkdir"), "{stdout}");
    assert!(!stdout.contains("service user"), "{stdout}");
    assert!(!stdout.contains("copied the daemon"), "{stdout}");
}

#[test]
fn probe_installed_setup_does_not_ask_for_from_when_from_was_passed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let bin_dir = root.join("app/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let installed = bin_dir.join("agent-vault-setup");
    std::fs::copy(cargo_bin("agent-vault-setup"), &installed).unwrap();
    let mut perms = std::fs::metadata(&installed).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&installed, perms).unwrap();
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("src")).unwrap();
    std::fs::create_dir_all(checkout.join("bin")).unwrap();
    std::fs::write(checkout.join("package.json"), "{}").unwrap();
    let out = Command::new(&installed)
        .args(["install", "--dry-run", "--from"])
        .arg(&checkout)
        .env("AGENT_VAULT_SETUP_DRY_ROOT", &root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "{stdout}{stderr}");
    assert!(stderr.contains("installed copy"), "{stderr}");
    assert!(
        !stderr.contains("Pass --from"),
        "refused with a hint that does not fit --from already being set: {stderr}"
    );
    assert!(!stdout.contains("mkdir"), "{stdout}");
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
