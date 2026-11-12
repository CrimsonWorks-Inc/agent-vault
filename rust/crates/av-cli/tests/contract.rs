//! Behavior the JS CLI tests lock down, driven through the Rust binaries.
//! Nothing here touches `/var/db/agent-vault` or a real vault: every path is
//! a temp directory, and `AGENT_VAULT_DIR` is always set to one.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;

fn bin(name: &str) -> PathBuf {
    cargo_bin(name)
}

fn repo_root() -> PathBuf {
    if let Ok(src) = std::env::var("AV_JS_SRC_DIR") {
        return PathBuf::from(src)
            .parent()
            .expect("AV_JS_SRC_DIR is the src directory")
            .to_path_buf();
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn js_src() -> PathBuf {
    if let Ok(src) = std::env::var("AV_JS_SRC_DIR") {
        PathBuf::from(src)
    } else {
        repo_root().join("src")
    }
}

/// Run `agent-vault` with a private vault dir and no color.
fn av(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin("agent-vault"))
        .args(args)
        .env("AGENT_VAULT_DIR", dir)
        .env("NO_COLOR", "1")
        .env_remove("AGENT_VAULT_ALLOW_ROOT")
        .output()
        .expect("agent-vault")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn js_vault(factor: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let out = tmp.path().join("out.json");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../av-store/src/tests/fixtures/make-js-vault.mjs");
    let status = Command::new("node")
        .arg(&script)
        .arg(js_src())
        .arg(&dir)
        .arg(factor)
        .arg(&out)
        .status()
        .expect("node is needed to build the JS fixture vault");
    assert!(status.success(), "JS fixture vault failed");
    (tmp, dir)
}

const HELP: &str = "\
agent-vault - a local credential proxy for agents

setup
  setup [--dev] [--print-only]         install properly (--dev skips the uid boundary)
  upgrade                              reinstall the daemon from this checkout
  daemon [--port N]                    run the daemon (gateway + control socket)
  status | doctor | profiles           what is running, and what is configured

guided                               (run these with no arguments)
  quickstart                           credential, session, and what to give the agent
  cred add                             walks you through storing a credential
  session create                       walks you through scoping a session

credentials                          (the value is read from the terminal, never argv)
  cred add <slug> --kind <kind> [--host H] [--expires YYYY-MM-DD]
  cred list | cred rm <slug>
  cred rotate <slug> [--field F] [--revoke] [--retire-hours N]
                                       replace the value; sessions keep working
  cred test [<slug> | --all]           run the connector's read-only probe
  cred expiry <slug> <YYYY-MM-DD|none> record when the token expires
  cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]
                                       extra token shapes to redact from responses
  cred pin <slug> --host H [--add sha256/...] [--rm sha256/... | --clear] [--live]
                                       refuse any TLS key you did not pin
  cred quarantine <slug> [--reason T]  stop all use at once; cred release <slug> undoes it

sessions and placeholders
  session create --cred <slug>[,<slug>...] [--methods GET,POST] [--paths \"/repos/**\"]
                 [--budget N] [--uses N] [--approval each|on-write|first-use|auto]
                 [--ttl HOURS | --infinite] [--label TEXT] [--grants-file F]
                 [--template NAME] [--rate 60/min] [--concurrency N] [--quota 1000/day]
                 [--route GET:/repos/**]... [--payload-file F] [--graphql query]
                 [--redirects N] [--spend-tokens N] [--spend-usd X] [--grant-ttl MIN]
                                       --approval auto or first-use with writes,
                                       and --infinite, ask for your passphrase
                                       every time
  session list | session revoke [<sid>]
  session narrow [<sid>] [--cred S] [any limit above] [--ttl MIN]
                                       tighten a live session; it can never widen
  session show [<sid>] [--markdown]    what it may do, and what it did
  template save <name> --cred <slug> [session flags] | template list
  template show <name> | template rm <name>
  ph next <cred> [--uses N]            issue a placeholder
  ph check <placeholder> | ph pattern  validate one, or print the scanner regex
  env [--out F [--force]] [--map NAME=<slug>[:base_url]]... [--map-file F] [--profile-vars]
                                       placeholders for your tools; the file is 0600 and
                                       never replaced unless you say so
  exec [--map NAME=<slug>]... -- <command>
                                       run a command with a scrubbed environment
  preflight --cred S --method M --path P [--body-file F]
                                       would this request pass? nothing is sent

approvals, audit, listeners
  approvals [--show <id>] | approve <id> | deny <id>
  watch [--no-notify] [--open]         tell you the moment something is waiting
  notify set | notify show | notify off | notify test
                                       an optional webhook for the same signal
  panic [--lock] [--reason T]          revoke every session, deny everything waiting
  tripwire show | tripwire on | tripwire off | tripwire set --rule ID ...
  lock | unlock                        stop and resume every proxied request
  passphrase set | passphrase remove   make the lock cryptographic (or undo it)
  audit tail [--limit N] | audit verify [--witness F]
  audit export [--since-seq N] [--out F] [--follow] | audit witness [--out F]
  report [--since 7d] [--markdown]     access review across every session
  backup export --out F | backup inspect F | backup restore F [--on-conflict skip|rename|fail]
  listen add <id> --address <iface:port> [--surfaces gateway,mcp]
                 [--tls managed | --tls-cert F --tls-key F]
  listen list | listen rm <id>
  tls setup [--port 7443]              certificate for the loopback MCP listener
  tls status                           fingerprint and expiry

ui
  ui [--port N] [--no-open] [--idle 30] open the web UI (single-use link, no secrets rendered)

mcp
  mcp                                  stdio transport (for an MCP client)
  mcp url                              the Streamable HTTP endpoint and header
  mcp install --agent <claude-code|cursor|gemini|codex> [--scope project|user]
                                       merge the server into that tool's config
                                       (--print shows the block instead)
              [--transport http --tls] a custom connector; the URL must be https

docs
  docs [section]                       open the docs, written against this install
                                       how | start | connect | models | locking
                                       | safety | refused | commands

--json on any command prints a machine-readable envelope.
";

#[test]
fn help_matches_the_contract_and_scrub_help_names_the_grammar() {
    let tmp = tempfile::tempdir().unwrap();
    let help = av(tmp.path(), &["help"]);
    assert_eq!(help.status.code(), Some(0), "{}", text(&help.stderr));
    assert_eq!(text(&help.stdout), HELP);
    let json = av(tmp.path(), &["help", "--json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(
        format!("{}\n", parsed["data"]["help"].as_str().unwrap()),
        HELP
    );
    let scrub = av(tmp.path(), &["cred", "scrub", "--help"]);
    let out = text(&scrub.stdout);
    assert!(out.contains("at most one ? or {n,m}"), "{out}");
    assert!(out.contains("request_ambiguous"), "{out}");
}

#[test]
fn secret_flags_are_refused_and_not_echoed() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = "s3cret-fixture-not-real";
    let out = av(
        tmp.path(),
        &["cred", "add", "demo", "--kind", "http", "--value", secret],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let combined = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(combined.contains("secrets are read from the terminal or stdin"));
    assert!(!combined.contains(secret), "the secret was echoed");
}

#[test]
fn markdown_takes_no_value() {
    let tmp = tempfile::tempdir().unwrap();
    let out = av(tmp.path(), &["session", "show", "--markdown=yes"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--markdown takes no value"));
}

#[test]
fn unknown_flag_on_status_is_ignored_and_a_down_daemon_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let out = av(tmp.path(), &["status", "--frob"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("agent-vault daemon"));
}

#[test]
fn setup_dev_creates_a_mode_0700_vault_and_says_what_it_does_not_protect() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let out = av(&dir, &["setup", "--dev"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("created"), "{stdout}");
    assert!(stdout.contains("0700"), "{stdout}");
    assert!(stdout.contains("Dev mode"), "{stdout}");
    assert!(dir.join("vault.db").is_file(), "rust vault was not created");
    let again = av(&dir, &["setup", "--dev"]);
    assert!(
        text(&again.stdout).contains("already"),
        "{}",
        text(&again.stdout)
    );
}

#[test]
fn setup_plan_names_one_program_and_does_not_sudo() {
    let tmp = tempfile::tempdir().unwrap();
    let out = av(tmp.path(), &["setup"]);
    let combined = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{combined}");
    assert!(
        combined.contains("root will run exactly one program"),
        "{combined}"
    );
    assert!(combined.contains("No terminal here"), "{combined}");
    assert!(combined.contains("agent-vault-setup"), "{combined}");
    assert!(!combined.contains("agent-vault-setup.js"), "{combined}");
    let only = av(tmp.path(), &["setup", "--print-only"]);
    let line = text(&only.stdout);
    assert!(line.starts_with("sudo "), "{line}");
    assert!(line.contains("install --from "), "{line}");
    assert!(!line.contains("node"), "{line}");
}

#[test]
fn installer_dry_run_names_the_boundary_without_root() {
    let out = Command::new(bin("agent-vault-setup"))
        .args(["install", "--dry-run"])
        .env_remove("AGENT_VAULT_SETUP_DRY_ROOT")
        .output()
        .unwrap();
    let combined = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{combined}");
    assert!(
        combined.contains("dry run: nothing will change"),
        "{combined}"
    );
    assert!(combined.contains("this is the boundary"), "{combined}");
    assert!(combined.contains("0700"), "{combined}");
    assert!(combined.contains("owner 399:399"), "{combined}");
    assert!(combined.contains("mkdir -m 02750"), "{combined}");
    assert!(
        combined.contains("_agentvault to _agentvault_users"),
        "{combined}"
    );
    assert!(combined.contains("Permission denied"), "{combined}");
    assert!(combined.contains("To remove everything:"), "{combined}");
    assert!(!combined.contains("runtime/node"), "{combined}");
    assert!(!combined.contains("agent-vault-setup.js"), "{combined}");
    let check = combined.lines().find(|l| l.contains("Check it")).unwrap();
    assert!(!check.contains("sudo"), "{check}");
}

#[test]
fn installer_refuses_a_symlinked_checkout_and_plans_a_clean_one() {
    let dirty = tempfile::tempdir().unwrap();
    fs::create_dir_all(dirty.path().join("src/store")).unwrap();
    fs::create_dir_all(dirty.path().join("bin")).unwrap();
    fs::write(dirty.path().join("package.json"), "{}").unwrap();
    fs::write(dirty.path().join("bin/agent-vault.js"), "// real").unwrap();
    std::os::unix::fs::symlink(
        "/tmp/agent-owned.js",
        dirty.path().join("src/store/vault.js"),
    )
    .unwrap();
    let refused = Command::new(bin("agent-vault-setup"))
        .args(["install", "--dry-run", "--from"])
        .arg(dirty.path())
        .env_remove("AGENT_VAULT_SETUP_DRY_ROOT")
        .output()
        .unwrap();
    let out = format!("{}{}", text(&refused.stdout), text(&refused.stderr));
    assert_ne!(refused.status.code(), Some(0), "{out}");
    assert!(out.to_lowercase().contains("symbolic link"), "{out}");
    assert!(out.contains("src/store/vault.js"), "{out}");
    assert!(out.contains("/tmp/agent-owned.js"), "{out}");
    assert!(!out.contains("would copied the daemon"), "{out}");

    let clean = tempfile::tempdir().unwrap();
    fs::create_dir_all(clean.path().join("src/store")).unwrap();
    fs::create_dir_all(clean.path().join("bin")).unwrap();
    fs::write(clean.path().join("package.json"), "{}").unwrap();
    fs::write(clean.path().join("bin/agent-vault.js"), "// real").unwrap();
    fs::write(clean.path().join("src/store/vault.js"), "// real").unwrap();
    let planned = Command::new(bin("agent-vault-setup"))
        .args(["install", "--dry-run", "--from"])
        .arg(clean.path())
        .env_remove("AGENT_VAULT_SETUP_DRY_ROOT")
        .output()
        .unwrap();
    let out = format!("{}{}", text(&planned.stdout), text(&planned.stderr));
    assert_eq!(planned.status.code(), Some(0), "{out}");
    assert!(out.contains("would copied the daemon"), "{out}");
    assert!(!out.to_lowercase().contains("symbolic link"), "{out}");
}

#[test]
fn installer_unknown_verb_is_help_and_a_flag_is_not_the_verb() {
    let unknown = Command::new(bin("agent-vault-setup"))
        .arg("frobnicate")
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(0));
    assert!(text(&unknown.stdout).contains("privileged installer"));
    let swapped = Command::new(bin("agent-vault-setup"))
        .args(["--user", "alice", "install", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(swapped.status.code(), Some(0), "{}", text(&swapped.stderr));
    assert!(text(&swapped.stdout).contains("privileged installer"));
    assert!(!text(&swapped.stdout).contains("dry run"));
}

#[test]
fn migrate_moves_a_js_vault_refuses_tampering_and_dry_run_writes_nothing() {
    let (_keep, dir) = js_vault("none");
    let before = listing(&dir);
    let dry = av(
        &dir,
        &[
            "migrate",
            "--from",
            &dir.display().to_string(),
            "--dry-run",
            "--json",
        ],
    );
    assert_eq!(dry.status.code(), Some(0), "{}", text(&dry.stderr));
    assert_eq!(listing(&dir), before, "dry-run wrote something");
    assert!(!dir.join("vault.db").exists());
    let dry_json: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry_json["ok"], true);
    assert_eq!(dry_json["data"]["dry_run"], true);

    let done = av(
        &dir,
        &["migrate", "--from", &dir.display().to_string(), "--json"],
    );
    assert_eq!(done.status.code(), Some(0), "{}", text(&done.stderr));
    let report: serde_json::Value = serde_json::from_slice(&done.stdout).unwrap();
    assert_eq!(report["data"]["counts"]["credentials"], 3);
    assert!(dir.join("vault.db").is_file());
    assert!(dir.join("vault.json").is_file(), "vault.json must stay");
    let human = av(&dir, &["migrate", "--from", &dir.display().to_string()]);
    assert_eq!(human.status.code(), Some(0), "{}", text(&human.stderr));
    assert!(
        text(&human.stdout).contains("nothing to do") || text(&human.stdout).contains("already")
    );

    let again = av(
        &dir,
        &["migrate", "--from", &dir.display().to_string(), "--json"],
    );
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    let again_json: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again_json["data"]["already_migrated"], true);
}

#[test]
fn migrate_refuses_a_tampered_audit_and_a_live_socket() {
    let (_keep, dir) = js_vault("none");
    let audit = dir.join("audit.jsonl");
    let mut bytes = fs::read(&audit).unwrap();
    if let Some(byte) = bytes.iter_mut().find(|b| b.is_ascii_alphanumeric()) {
        *byte = b'Z';
    }
    fs::write(&audit, &bytes).unwrap();
    let refused = av(
        &dir,
        &["migrate", "--from", &dir.display().to_string(), "--json"],
    );
    assert_ne!(refused.status.code(), Some(0));
    assert!(
        !dir.join("vault.db").exists(),
        "a refused migrate wrote vault.db"
    );

    let (_keep2, live) = js_vault("none");
    let sock = live.join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let blocked = av(&live, &["migrate", "--from", &live.display().to_string()]);
    drop(listener);
    let err = format!("{}{}", text(&blocked.stdout), text(&blocked.stderr));
    assert_ne!(blocked.status.code(), Some(0), "{err}");
    assert!(err.contains("stop the daemon"), "{err}");
    assert!(!live.join("vault.db").exists());
}

#[test]
fn migrate_prompts_the_passphrase_and_never_takes_it_as_a_flag() {
    let (_keep, dir) = js_vault("passphrase");
    let mut child = Command::new(bin("agent-vault"))
        .args(["migrate", "--from"])
        .arg(&dir)
        .env("AGENT_VAULT_DIR", &dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"test-passphrase-not-real\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(dir.join("vault.db").is_file());
    assert!(!text(&out.stdout).contains("test-passphrase-not-real"));
    assert!(!text(&out.stderr).contains("test-passphrase-not-real"));
}

#[test]
fn status_against_a_js_daemon_in_a_temp_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    fs::create_dir_all(&dir).unwrap();
    let log = tmp.path().join("daemon.log");
    let log_file = fs::File::create(&log).unwrap();
    let mut child = Command::new("node")
        .arg(repo_root().join("bin/agent-vault-daemon.js"))
        .env("AV_VAULT_DIR", &dir)
        .env("AV_RUN_DIR", &dir)
        .env("AV_PORT", "0")
        .env_remove("AGENT_VAULT_DIR")
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("node daemon");
    let sock = dir.join("control.sock");
    let started = Instant::now();
    while !sock.exists() {
        if started.elapsed() > Duration::from_secs(8) {
            let _ = child.kill();
            panic!(
                "daemon did not listen: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        if let Ok(Some(_)) = child.try_wait() {
            panic!(
                "daemon exited: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = av(&dir, &["status", "--json"]);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["locked"], false);
}

fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    out.sort();
    out
}
