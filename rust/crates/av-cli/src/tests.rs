//! Scaffold tests for the command trees: clap's own consistency checks, and
//! that real command lines from the JS help parse into the right shapes.

use clap::{CommandFactory, Parser};

use crate::cli::{
    AuditCommand, Cli, Command, CredCommand, ListenCommand, McpCommand, SessionCommand,
};
use crate::setup::{SetupCli, SetupCommand};
use crate::COMMAND_NAMES;

fn parse(line: &str) -> Cli {
    let argv = std::iter::once("agent-vault").chain(line.split_whitespace());
    Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{line:?} did not parse: {e}"))
}

#[test]
fn agent_vault_tree_is_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn setup_tree_is_consistent() {
    SetupCli::command().debug_assert();
}

#[test]
fn every_command_name_parses_bare() {
    for name in COMMAND_NAMES {
        parse(name);
    }
    assert!(matches!(parse("help").command, Some(Command::Help { .. })));
    assert!(parse("").command.is_none());
}

#[test]
fn migrate_dry_run_json_parses() {
    let cli = parse("migrate --dry-run --json");
    assert!(cli.json);
    let Some(Command::Migrate(m)) = cli.command else {
        panic!("not migrate")
    };
    assert!(m.dry_run);
    assert_eq!((m.from, m.to), (None, None));

    let cli = parse("--json migrate --from /tmp/a --to=/tmp/b");
    assert!(cli.json);
    let Some(Command::Migrate(m)) = cli.command else {
        panic!("not migrate")
    };
    assert_eq!(m.from.as_deref(), Some("/tmp/a"));
    assert_eq!(m.to.as_deref(), Some("/tmp/b"));
    assert!(!m.dry_run);
}

#[test]
fn session_create_from_help_parses() {
    let cli = parse(
        "session create --cred gh,slack --methods GET,POST --paths /repos/** --budget 50 --approval on-write \
         --ttl 2 --rate 60/min --quota 1000/day --route GET:/repos/** --route POST:/issues --spend-usd 1.5",
    );
    let Some(Command::Session {
        command: SessionCommand::Create(s),
    }) = cli.command
    else {
        panic!("not session create")
    };
    assert_eq!(s.cred.as_deref(), Some("gh,slack"));
    assert_eq!(s.grant.methods.as_deref(), Some("GET,POST"));
    assert_eq!(s.grant.route, ["GET:/repos/**", "POST:/issues"]);
    assert_eq!(s.grant.spend_usd.as_deref(), Some("1.5"));
    assert_eq!(s.ttl.as_deref(), Some("2"));
    assert!(!s.infinite);
}

#[test]
fn cred_pin_and_scrub_from_help_parse() {
    let cli = parse("cred pin gh --host api.github.com --add sha256/a --add sha256/b --live");
    let Some(Command::Cred {
        command: CredCommand::Pin(p),
    }) = cli.command
    else {
        panic!("not cred pin")
    };
    assert_eq!(p.slug.as_deref(), Some("gh"));
    assert_eq!(p.add, ["sha256/a", "sha256/b"]);
    assert!(p.live && !p.clear);

    let cli = parse("cred scrub gh --add abc[0-9]{4} --sample abc1234");
    let Some(Command::Cred {
        command: CredCommand::Scrub(s),
    }) = cli.command
    else {
        panic!("not cred scrub")
    };
    assert_eq!(s.add, ["abc[0-9]{4}"]);
    assert_eq!(s.sample.as_deref(), Some("abc1234"));
}

#[test]
fn listen_add_tls_is_bare_or_managed() {
    let cli = parse("listen add lan --address 0.0.0.0:7443 --tls");
    let Some(Command::Listen {
        command: ListenCommand::Add(a),
    }) = cli.command
    else {
        panic!("not listen add")
    };
    assert_eq!(a.tls, Some(None));
    let cli = parse("listen add lan --address 0.0.0.0:7443 --tls managed --allow-cidr 10.0.0.0/8");
    let Some(Command::Listen {
        command: ListenCommand::Add(a),
    }) = cli.command
    else {
        panic!("not listen add")
    };
    assert_eq!(a.tls, Some(Some("managed".to_owned())));
    assert_eq!(a.allow_cidr.as_deref(), Some("10.0.0.0/8"));
}

#[test]
fn mcp_alone_install_and_url() {
    let prepared = crate::prepare(&["agent-vault".into(), "mcp".into()]).expect("bare mcp");
    assert_eq!(prepared.argv, ["agent-vault", "mcp"]);
    let Some(Command::Mcp(m)) = parse("mcp").command else {
        panic!("not mcp")
    };
    assert!(m.command.is_none());
    let Some(Command::Mcp(m)) = parse("mcp url").command else {
        panic!("not mcp")
    };
    assert!(matches!(m.command, Some(McpCommand::Url)));
    let Some(Command::Mcp(m)) =
        parse("mcp install --agent codex --transport http --tls --print").command
    else {
        panic!("not mcp")
    };
    let Some(McpCommand::Install(i)) = m.command else {
        panic!("not mcp install")
    };
    assert_eq!(i.agent.as_deref(), Some("codex"));
    assert!(i.tls && i.print);
}

#[test]
fn exec_takes_everything_after_double_dash() {
    let Some(Command::Exec(e)) = parse("exec --map GH_TOKEN=gh -- gh api --json user").command
    else {
        panic!("not exec")
    };
    assert_eq!(e.map, ["GH_TOKEN=gh"]);
    assert_eq!(e.command, ["gh", "api", "--json", "user"]);
}

#[test]
fn json_and_help_are_global_and_last_value_wins() {
    let cli = parse("audit tail --limit 5 --json --limit 7 --help");
    assert!(cli.json && cli.help);
    let Some(Command::Audit {
        command: AuditCommand::Tail(t),
    }) = cli.command
    else {
        panic!("not audit tail")
    };
    assert_eq!(t.limit.as_deref(), Some("7"));
}

#[test]
fn secret_flags_parse_so_they_can_be_refused() {
    assert!(parse("cred add gh --value hunter2")
        .secret_traps
        .value
        .is_some());
    assert!(parse("notify set --webhook_url")
        .secret_traps
        .webhook_url_underscore
        .is_some());
}

#[test]
fn approve_keeps_each_spelling_apart() {
    let Some(Command::Approve(a)) =
        parse("approve ap_1 --ttl-minutes 5 --ttl_minutes 6 --infinite").command
    else {
        panic!("not approve")
    };
    assert_eq!(a.ttl_minutes.as_deref(), Some("5"));
    assert_eq!(a.ttl_minutes_underscore.as_deref(), Some("6"));
    assert!(a.infinite);
}

#[test]
fn setup_verbs_parse() {
    let cli = SetupCli::try_parse_from([
        "agent-vault-setup",
        "install",
        "--user",
        "alice",
        "--port",
        "7411",
        "--dry-run",
    ])
    .expect("install parses");
    assert!(cli.dry_run);
    let Some(SetupCommand::Install(i)) = cli.command else {
        panic!("not install")
    };
    assert_eq!(i.user.as_deref(), Some("alice"));
    let cli = SetupCli::try_parse_from(["agent-vault-setup", "uninstall", "--purge"])
        .expect("uninstall parses");
    assert!(matches!(cli.command, Some(SetupCommand::Uninstall(u)) if u.purge));
}

fn refused(line: &str) -> bool {
    let argv = std::iter::once("agent-vault").chain(line.split_whitespace());
    Cli::try_parse_from(argv).is_err()
}

#[test]
fn env_takes_session_and_uses() {
    // resolveMappings in src/cli/index.js reads both, for env and exec.
    let Some(Command::Env(e)) = parse("env --session S --uses 3").command else {
        panic!("not env")
    };
    assert_eq!(e.session.as_deref(), Some("S"));
    assert_eq!(e.uses.as_deref(), Some("3"));
}

#[test]
fn exec_takes_session_and_uses() {
    let Some(Command::Exec(e)) = parse("exec --session S --uses 3 -- cmd").command else {
        panic!("not exec")
    };
    assert_eq!(e.session.as_deref(), Some("S"));
    assert_eq!(e.uses.as_deref(), Some("3"));
    assert_eq!(e.command, ["cmd"]);
}

#[test]
fn bare_uses_and_session_are_refused() {
    // The JS refuses a valueless --uses / --session with EXIT.USAGE.
    assert!(refused("env --uses"), "env --uses");
    assert!(refused("env --session"), "env --session");
    assert!(refused("exec --uses -- cmd"), "exec --uses");
    assert!(refused("exec --session -- cmd"), "exec --session");
}

#[test]
fn boolean_flag_rejects_a_value_and_empty_means_set() {
    assert!(crate::policy_input::boolean_flag(Some(""), "force").unwrap());
    assert!(!crate::policy_input::boolean_flag(None, "force").unwrap());
    let err = crate::policy_input::boolean_flag(Some("false"), "force").unwrap_err();
    assert!(err.message.contains("--force takes no value"));
}

#[test]
fn optional_number_rejects_a_missing_value() {
    let err = crate::policy_input::optional_number(
        Some(""),
        "uses",
        crate::policy_input::NumberLimits::default(),
    )
    .unwrap_err();
    assert!(err.message.contains("--uses needs a value"));
}

#[test]
fn number_flag_rejects_a_fraction_when_an_integer_is_required() {
    let err = crate::policy_input::number_flag(
        Some("1.5"),
        "--uses",
        crate::policy_input::NumberLimits::default(),
    )
    .unwrap_err();
    assert!(err.message.contains("whole number"), "{}", err.message);
}

#[test]
fn known_flags_refuses_an_unknown_limit() {
    let err = crate::policy_input::known_flags(&["remote"], &["cred", "approval"], "session")
        .unwrap_err();
    assert_eq!(
        err.message,
        "session does not take --remote; nothing was sent"
    );
    assert!(crate::policy_input::known_flags(&["cred"], &["cred", "approval"], "session").is_ok());
}

#[test]
fn approve_rate_stays_a_string() {
    let cli = parse("approve ap_1 --rate 60/min");
    let Some(Command::Approve(args)) = cli.command else {
        panic!("not approve")
    };
    let body = crate::policy_input::approval_overrides(&args).unwrap();
    assert_eq!(body.get("rate").and_then(|v| v.as_str()), Some("60/min"));
}

#[test]
fn clean_text_drops_controls_and_bidi_and_keeps_tab_and_newline() {
    let cleaned = crate::control_commands::clean_text("a\u{202e}b\n\tc\u{0007}d\r\u{2028}");
    assert_eq!(cleaned, "ab\n\tcd");
}

#[test]
fn approval_preview_bounds_the_body_and_names_the_agent() {
    let preview = serde_json::json!({
        "content_type": "text/plain",
        "body": { "bytes": 3, "text": "one\ntwo\nthree\nfour\nfive\nsix\nseven" }
    });
    let short = crate::control_commands::approval_preview_lines(&preview, false);
    assert!(short.iter().any(|l| l.contains("sends: text/plain")));
    assert!(short.iter().any(|l| l.contains("3 bytes")));
    let full = crate::control_commands::approval_preview_lines(&preview, true);
    assert!(full
        .iter()
        .any(|l| l.contains("written by the agent, not verified")));
}

#[test]
fn elevation_names_infinite_and_unreadable_grants() {
    let infinite = serde_json::json!({ "infinite": true, "approval": "each", "methods": ["GET"] });
    assert!(crate::commands::elevation_of(&infinite).contains(&"infinite"));
    let bad = serde_json::json!({ "grants": { "nope": true } });
    assert!(crate::commands::elevation_of(&bad).contains(&"approval_auto_writes"));
}

#[test]
fn resolve_bin_is_absolute_and_refuses_path_fallback() {
    for cmd in ["id", "launchctl", "chmod", "sleep", "curl", "setfacl"] {
        match crate::setup::resolve_bin(cmd) {
            Ok(path) => {
                assert!(path.is_absolute(), "{cmd}");
                assert!(path.exists(), "{cmd}");
            }
            Err(message) => {
                assert!(
                    message.contains("Refusing to fall back to PATH")
                        || message.contains("not in the allow-list"),
                    "{cmd}: {message}"
                );
            }
        }
    }
    let err = crate::setup::resolve_bin("curl").unwrap_err();
    assert!(err.contains("not in the allow-list"), "{err}");
}

#[test]
fn copy_dereference_writes_the_target_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real.txt");
    std::fs::write(&real, "fixture-bytes").unwrap();
    let link = tmp.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let dest = tmp.path().join("out.txt");
    crate::setup::copy_dereference(&link, &dest).unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "fixture-bytes");
    assert!(!std::fs::symlink_metadata(&dest)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn self_install_and_systemd_restart_and_from_probe() {
    assert!(crate::setup::refuses_self_install(
        std::path::Path::new("/var/db/agent-vault/app"),
        std::path::Path::new("/var/db/agent-vault/app")
    ));
    assert!(!crate::setup::refuses_self_install(
        std::path::Path::new("/tmp/checkout"),
        std::path::Path::new("/var/db/agent-vault/app")
    ));
    assert_eq!(
        crate::setup::systemd_start_args(),
        ["restart", "agent-vault.service"]
    );
    assert!(!crate::commands::installer_supports_from(b"no marker here"));
    assert!(crate::commands::installer_supports_from(b"value('from')"));
    assert!(crate::commands::installer_supports_from(
        b"install --from /tmp"
    ));
    let err = crate::commands::choose_upgrade_installer(
        std::path::Path::new("/no/such/installer"),
        std::path::Path::new("/checkout/agent-vault-setup"),
        std::path::Path::new("/checkout"),
    )
    .unwrap_err();
    assert_eq!(err.next.as_deref(), Some("cargo build --release first"));
    assert!(
        !err.message.contains("agent-vault-setup"),
        "a missing installer was named: {}",
        err.message
    );
}

#[test]
fn upgrade_print_only_names_an_installer_and_source_install_app_accepts() {
    let tmp = tempfile::tempdir().unwrap();
    let app = tmp.path().join("app");
    let root_owned = app.join("bin/agent-vault-setup");
    std::fs::create_dir_all(root_owned.parent().unwrap()).unwrap();
    // The installed Rust installer contains the `--from` marker. It is the
    // one upgrade prints: an agent cannot edit a root-owned binary, and
    // install_app copies `<--from>/rust/target/release` rather than the
    // directory the installer itself lives in.
    std::fs::write(&root_owned, b"#!/bin/sh\n--from\n").unwrap();
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::create_dir_all(checkout.join("rust/target/release")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let release = checkout.join("rust/target/release/agent-vault-setup");
    std::fs::write(&release, b"checkout-setup").unwrap();
    let (cmd, installer, using_root) =
        crate::commands::format_upgrade_command(&root_owned, &release, &checkout)
            .expect("root-owned installer");
    assert!(
        using_root,
        "the root-owned installer was not selected: {cmd}"
    );
    assert!(cmd.starts_with("sudo "), "{cmd}");
    assert!(cmd.contains(" install --from "), "{cmd}");
    let rest = cmd.strip_prefix("sudo ").unwrap();
    let (named_installer, named_source) = rest.split_once(" install --from ").unwrap();
    assert_eq!(named_installer, root_owned.display().to_string(), "{cmd}");
    assert_eq!(named_source, checkout.display().to_string(), "{cmd}");
    assert_eq!(installer, root_owned);
    assert!(
        crate::setup::install_app_accepts(&installer, &checkout, &app),
        "upgrade --print-only named an installer install_app refuses: {cmd}"
    );
    assert!(
        !crate::setup::install_app_accepts(&root_owned, &app, &app),
        "installing the app over itself must stay refused"
    );
}

#[test]
fn upgrade_bootstraps_from_the_checkout_release_installer() {
    let tmp = tempfile::tempdir().unwrap();
    let root_owned = tmp.path().join("app/bin/agent-vault-setup");
    std::fs::create_dir_all(root_owned.parent().unwrap()).unwrap();
    std::fs::write(&root_owned, b"old installer without the flag").unwrap();
    let checkout = tmp.path().join("checkout");
    let release = checkout.join("rust/target/release/agent-vault-setup");
    std::fs::create_dir_all(release.parent().unwrap()).unwrap();
    std::fs::write(&release, b"release").unwrap();
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let debug = checkout.join("rust/target/debug/agent-vault-setup");
    std::fs::create_dir_all(debug.parent().unwrap()).unwrap();
    std::fs::write(&debug, b"debug").unwrap();
    let (path, using_root) =
        crate::commands::choose_upgrade_installer(&root_owned, &debug, &checkout)
            .expect("release installer");
    assert!(!using_root, "a too-old install was treated as root-owned");
    assert_eq!(path, release);
}

#[test]
fn upgrade_does_not_name_a_missing_release_installer() {
    let tmp = tempfile::tempdir().unwrap();
    let root_owned = tmp.path().join("app/bin/agent-vault-setup");
    std::fs::create_dir_all(root_owned.parent().unwrap()).unwrap();
    std::fs::write(&root_owned, b"old installer without the flag").unwrap();
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    let release = checkout.join("rust/target/release/agent-vault-setup");
    let missing =
        crate::commands::choose_upgrade_installer(&root_owned, &root_owned, &checkout).unwrap_err();
    let missing_text = format!(
        "{} {}",
        missing.message,
        missing.next.clone().unwrap_or_default()
    );
    assert!(
        missing_text.contains("cargo build --release first"),
        "{missing_text}"
    );
    assert!(
        !missing_text.contains(&release.display().to_string()),
        "a release path that is not on disk was named: {missing_text}"
    );

    let debug = checkout.join("rust/target/debug/agent-vault-setup");
    std::fs::create_dir_all(debug.parent().unwrap()).unwrap();
    std::fs::write(&debug, b"debug").unwrap();
    let debug_err =
        crate::commands::choose_upgrade_installer(&root_owned, &debug, &checkout).unwrap_err();
    let debug_text = format!(
        "{} {}",
        debug_err.message,
        debug_err.next.clone().unwrap_or_default()
    );
    assert!(
        debug_text.contains("cargo build --release first"),
        "{debug_text}"
    );
    assert!(
        !debug_text.contains(&debug.display().to_string()),
        "the debug installer was named: {debug_text}"
    );
    assert!(
        !debug_text.contains("target/release"),
        "a missing release installer was named: {debug_text}"
    );
}

#[test]
fn checkout_root_refuses_the_installed_app() {
    let tmp = tempfile::tempdir().unwrap();
    // A checkout whose directory is named app is still a checkout.
    let named = tmp.path().join("named").join("app");
    std::fs::create_dir_all(named.join("rust/crates/av-cli")).unwrap();
    std::fs::write(named.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let found = crate::commands::resolve_checkout_root(&[named.join("rust")]).unwrap();
    assert_eq!(found, named);
    assert!(!crate::commands::is_installed_app(&named));

    // The real installed app, both spellings. This only stats that tree.
    let via_var = std::path::PathBuf::from("/var/db/agent-vault/app");
    let via_private = std::path::PathBuf::from("/private/var/db/agent-vault/app");
    assert!(
        crate::commands::is_installed_app(&via_var),
        "the /var spelling was not the installed app"
    );
    assert!(
        crate::commands::is_installed_app(&via_private),
        "the /private/var spelling was not the installed app"
    );
    assert_eq!(
        crate::setup::canonical_prefix(&via_var),
        crate::setup::canonical_prefix(&via_private)
    );
    for start in [via_var.join("bin"), via_private.join("bin")] {
        let err = crate::commands::resolve_checkout_root(std::slice::from_ref(&start)).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("run agent-vault upgrade from your checkout, or from the new release"),
            "{start:?}: {text}"
        );
    }

    // The installed app is skipped, so a later start is the checkout.
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let found =
        crate::commands::resolve_checkout_root(&[via_var.join("bin"), checkout.join("rust")])
            .unwrap();
    assert_eq!(found, checkout);
}

#[test]
fn exe_outside_the_checkout_is_not_a_debug_installer() {
    let tmp = tempfile::tempdir().unwrap();
    let checkout = tmp.path().join("checkout");
    let release = checkout.join("rust/target/release/agent-vault-setup");
    let debug = checkout.join("rust/target/debug/agent-vault-setup");
    assert!(crate::setup::exe_is_checkout_debug_installer(
        &debug, &checkout
    ));
    assert!(!crate::setup::exe_is_checkout_debug_installer(
        &release, &checkout
    ));
    assert!(!crate::setup::exe_is_checkout_debug_installer(
        &tmp.path().join("app/bin/agent-vault-setup"),
        &checkout
    ));
}

#[test]
fn copy_rust_bins_copies_the_checkout_release_not_the_running_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let checkout = tmp.path().join("checkout");
    let release = checkout.join("rust/target/release");
    std::fs::create_dir_all(&release).unwrap();
    for name in ["agent-vault", "agent-vault-daemon", "agent-vault-setup"] {
        std::fs::write(release.join(name), format!("from-checkout-{name}")).unwrap();
    }
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let app = tmp.path().join("app");
    crate::setup::copy_rust_bins(&checkout, &app).unwrap();
    for name in ["agent-vault", "agent-vault-daemon", "agent-vault-setup"] {
        let got = std::fs::read(app.join("bin").join(name)).unwrap();
        assert_eq!(got, format!("from-checkout-{name}").into_bytes(), "{name}");
    }
}

#[test]
fn install_dry_run_records_and_saves_state() {
    let tmp = tempfile::tempdir().unwrap();
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::create_dir_all(checkout.join("rust/target/release")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::write(
        checkout.join("rust/target/release/agent-vault-daemon"),
        b"daemon",
    )
    .unwrap();
    let recorded = crate::setup::dry_run_recorded_install(&checkout).expect("dry-run install");
    assert!(
        !recorded.read_host_state,
        "the ordering check read the host state.json"
    );
    let app = recorded
        .created
        .iter()
        .find(|(kind, id)| kind == "dir" && id.ends_with("/app"));
    assert!(
        app.is_some(),
        "app was not recorded: {:?}",
        recorded.created
    );
    let service = recorded.created.iter().find(|(kind, id)| {
        kind == "file"
            && (id.ends_with("com.agentvault.daemon.plist") || id.ends_with("agent-vault.service"))
    });
    assert!(
        service.is_some(),
        "the service file was not recorded: {:?}",
        recorded.created
    );
    let service_id = &service.unwrap().1;
    assert!(
        recorded.saved_ids.iter().any(|id| id == service_id),
        "save_state ran before install_service, or not at all: saved {:?} created {:?}",
        recorded.saved_ids,
        recorded.created
    );
    assert_eq!(
        recorded.saved_ids.len(),
        recorded.created.len(),
        "save_state did not see the full record"
    );
    assert!(
        recorded.service_step > 0 && recorded.save_step > recorded.service_step,
        "save_state ran before install_service: save {} service {}",
        recorded.save_step,
        recorded.service_step
    );
}

#[test]
fn append_refuses_a_fifo_without_hanging() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("witness");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    // A missing O_NONBLOCK blocks in open until a reader appears. The check
    // runs on another thread so this test fails in 2s instead of holding the
    // process until the mutation runner's timeout. Process exit ends the
    // blocked open.
    let path = fifo.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = crate::files::append_line_exclusive(&path, "line");
        let _ = tx.send(result.map_err(|err| err.to_string()));
    });
    let err = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(result) => result.expect_err("a fifo was appended"),
        Err(_) => panic!("fifo open hung"),
    };
    assert!(err.contains("is not a regular file"), "{err}");
}

#[test]
fn retired_vault_path_is_outside_the_install_root() {
    let retired = crate::setup::retired_vault_path();
    let text = retired.display().to_string();
    assert!(text.contains("agent-vault-retired-"), "{text}");
    assert!(
        !text.contains("/var/db/agent-vault/agent-vault-retired"),
        "{text}"
    );
}

fn ph_text(sid: &str) -> String {
    format!("av1.{sid}.demo_token.aaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa")
}

#[test]
fn env_quotes_exported_values() {
    assert_eq!(crate::commands::shell_quote("a b"), "'a b'");
    assert_eq!(crate::commands::shell_quote("a'b"), "'a'\\''b'");
}

#[test]
fn env_unsets_a_placeholder_the_shell_already_holds() {
    let lines = crate::commands::legacy_env_lines("tok", 9, None);
    assert!(lines.iter().any(|l| l == "unset AGENT_VAULT_PLACEHOLDER"));
    assert!(lines
        .iter()
        .any(|l| l == "export AGENT_VAULT_SESSION='tok'"));
}

#[test]
fn exec_drops_credentials_and_generated_vars() {
    assert!(
        !crate::commands::parent_env_kept("DATABASE_PASSWORD", "x"),
        "a password name must not reach the child"
    );
    assert!(
        !crate::commands::parent_env_kept("AGENT_VAULT_SESSION", "planted"),
        "a generated variable must not be inherited"
    );
    assert!(crate::commands::looks_like_credential(
        "AGENT_VAULT_TOKEN",
        "x"
    ));
    assert!(crate::commands::looks_like_credential(
        "PLAIN_URL",
        "http://:s3cret@example.test"
    ));
    // The empty user is not the whole value, so only the anywhere-scan
    // matches it. The URL-parser fallback never sees a string that does not
    // start with a scheme.
    assert!(crate::commands::looks_like_credential(
        "NOTE",
        "see http://:s3cret@example.test later"
    ));
    assert!(crate::commands::parent_env_kept("PATH", "/usr/bin"));
    assert!(!crate::commands::looks_like_credential(
        "AGENT_VAULT_DIR",
        "/tmp/vault"
    ));
}

#[test]
fn bridge_wraps_a_non_protocol_body() {
    let out = crate::commands::as_rpc("plain", r#"{"jsonrpc":"2.0","id":7,"method":"x"}"#, 500);
    assert!(out.contains("\"jsonrpc\""), "{out}");
    assert!(!out.starts_with("plain"), "{out}");
}

#[test]
fn dead_launch_token_includes_the_session_header() {
    assert!(crate::commands::launch_token_dead(200, true));
    assert!(crate::commands::launch_token_dead(401, false));
    assert!(!crate::commands::launch_token_dead(200, false));
}

#[test]
fn bridge_resends_only_the_refused_call() {
    let line = serde_json::json!([
        {"jsonrpc": "2.0", "id": 1, "method": "a"},
        {"jsonrpc": "2.0", "id": 2, "method": "b"}
    ])
    .to_string();
    let answers = serde_json::json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": "{\"error\":\"this tool needs a live session\"}"
                }]
            }
        },
        {"jsonrpc": "2.0", "id": 2, "result": {"ok": true}}
    ])
    .to_string();
    let retry = crate::session_retry(&line, &answers).expect("the refused call is resent");
    assert!(retry.line.contains("\"id\":1"), "{}", retry.line);
    assert!(!retry.line.contains("\"id\":2"), "{}", retry.line);
    let merged = retry.merge(
        &serde_json::json!([{
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "listed" }] }
        }])
        .to_string(),
    );
    assert!(merged.contains("listed"), "{merged}");
    assert!(
        merged.contains("\"ok\":true") || merged.contains("\"ok\": true"),
        "{merged}"
    );
}

#[test]
fn bridge_leaves_a_batch_alone_when_the_phrase_is_only_text() {
    let mention = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "content": [{ "type": "text", "text": "this tool needs a live session" }] }
    });
    assert!(crate::session_retry(
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "x"}).to_string(),
        &mention.to_string(),
    )
    .is_none());
    let embedded = serde_json::json!([{
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "content": [{ "type": "text", "text": "{\"error\":\"this tool needs a live session\"}" }] }
    }]);
    assert!(crate::session_retry(
        &serde_json::json!([{"jsonrpc": "2.0", "id": 1, "method": "x"}]).to_string(),
        &embedded.to_string(),
    )
    .is_none());
}

#[test]
fn template_hash_is_bound_onto_the_session_body() {
    let mut body = serde_json::Map::new();
    crate::commands::bind_template_hash(&mut body, &serde_json::json!({ "hash": "abc" }));
    assert_eq!(
        body.get("template_hash").and_then(|v| v.as_str()),
        Some("abc")
    );
}

#[test]
fn approve_prints_what_was_granted() {
    let answered = serde_json::json!({
        "summary": "the agent asked for everything",
        "granted": { "cred": "demo", "methods": ["GET"] }
    });
    let line = crate::commands::approval_human(&answered);
    assert!(line.contains("session for demo"), "{line}");
    assert!(!line.contains("asked for everything"), "{line}");
}

#[test]
fn env_file_refuses_an_existing_path() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(".env");
    crate::files::write_file_exclusive(&path, "one", false, 0o600).unwrap();
    let err = crate::files::write_file_exclusive(&path, "two", false, 0o600).unwrap_err();
    assert!(err.to_string().contains("exists"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
}

#[test]
fn force_refuses_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::write(&real, "secret").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = crate::files::write_file_exclusive(&link, "x", true, 0o600).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("not a regular file") || text.contains("symbolic"),
        "{text}"
    );
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "secret");
}

#[test]
fn append_tightens_the_mode_to_0600() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("note");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&path)
        .unwrap();
    drop(file);
    crate::files::append_line_exclusive(&path, "line").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
}

#[test]
fn placeholder_for_another_session_is_refused() {
    let good = crate::files::EnvEntry {
        name: "TOKEN".into(),
        value: ph_text("aaaaaaaaaaaa"),
        cred: "demo".into(),
    };
    let slugs = vec!["demo".into()];
    assert!(crate::files::assert_placeholder_only(
        std::slice::from_ref(&good),
        "aaaaaaaaaaaa",
        1,
        &slugs
    )
    .is_ok());
    let err =
        crate::files::assert_placeholder_only(&[good], "bbbbbbbbbbbb", 1, &slugs).unwrap_err();
    assert!(err.to_string().contains("not a placeholder"), "{err}");
}

#[test]
fn a_batch_value_that_is_not_a_placeholder_is_refused() {
    let bad = crate::files::EnvEntry {
        name: "TOKEN".into(),
        value: "secret-value".into(),
        cred: "demo".into(),
    };
    let err = crate::files::assert_placeholder_only(&[bad], "aaaaaaaaaaaa", 1, &["demo".into()])
        .unwrap_err();
    assert!(err.to_string().contains("not a placeholder"), "{err}");
}

#[test]
fn server_name_cannot_rewrite_a_config() {
    assert!(crate::mcp_install::server_name_ok("agent-vault"));
    assert!(!crate::mcp_install::server_name_ok("]"));
    assert!(!crate::mcp_install::server_name_ok("a b"));
}

#[test]
fn watch_strips_controls_and_bidi() {
    assert_eq!(crate::watch::watch_clean("a\u{0007}b"), "ab");
    assert_eq!(crate::watch::watch_clean("a\u{202e}b"), "ab");
    assert_eq!(crate::watch::watch_clean("a\u{2028}b"), "ab");
}

#[test]
fn watch_scrubs_a_placeholder_in_the_headline() {
    let entry = serde_json::json!({
        "kind": "request",
        "id": "id1",
        "headline": "see av1.abc_def now",
        "reason": "secret"
    });
    let safe = crate::watch::safe_entry(&entry).unwrap();
    let headline = safe.get("headline").and_then(|v| v.as_str()).unwrap();
    assert!(headline.contains("[placeholder]"), "{headline}");
    assert!(!headline.contains("av1."), "{headline}");
    assert!(safe.get("reason").is_none());
}

#[test]
fn watch_json_uses_cleaned_fields() {
    let raw = serde_json::json!({
        "kind": "request",
        "id": "id1",
        "headline": "ok",
        "reason": "the agent's ask"
    });
    let data = crate::watch::event_data("pending", &raw).unwrap();
    assert!(data.get("reason").is_none(), "{data}");
    assert_eq!(data.get("id").and_then(|v| v.as_str()), Some("id1"));
}

#[test]
fn notify_script_passes_text_as_argv() {
    let script = crate::watch::macos_notify_script().join("\n");
    assert!(script.contains("item 1 of argv"), "{script}");
    assert!(!script.contains("${"), "{script}");
}

#[test]
fn approval_preview_strips_controls_in_the_body() {
    let preview = serde_json::json!({ "body": { "text": "a\u{0007}b" } });
    let joined = crate::control_commands::approval_preview_lines(&preview, false).join("\n");
    assert!(!joined.contains('\u{0007}'), "{joined}");
}

#[test]
fn approve_refuses_a_bad_payload_before_sending() {
    let Some(crate::cli::Command::Approve(args)) = parse("approve ap_1 --payload nope").command
    else {
        panic!("not approve");
    };
    let err = crate::policy_input::approval_overrides(&args).unwrap_err();
    assert!(err.message.contains("not valid JSON"), "{}", err.message);
}

#[test]
fn approve_refuses_two_spellings_of_one_field() {
    let Some(crate::cli::Command::Approve(args)) =
        parse("approve ap_1 --spend-usd 1 --spend_usd 2").command
    else {
        panic!("not approve");
    };
    let err = crate::policy_input::approval_overrides(&args).unwrap_err();
    assert!(err.message.contains("give only one"), "{}", err.message);
}

#[test]
fn approve_refuses_a_bare_value_flag() {
    let args = crate::cli::ApproveArgs {
        rate: Some(String::new()),
        ..Default::default()
    };
    let err = crate::policy_input::approval_overrides(&args).unwrap_err();
    assert!(
        err.message.contains("needs a value; nothing was sent"),
        "{}",
        err.message
    );
}

#[test]
fn session_create_refuses_remote() {
    crate::policy_input::set_extra_flags(&["remote".into()]);
    let args = crate::cli::SessionSpecArgs {
        cred: Some("demo".into()),
        ..crate::cli::SessionSpecArgs::default()
    };
    let err = crate::policy_input::session_input(&args).unwrap_err();
    crate::policy_input::set_extra_flags(&[]);
    assert!(
        err.message.contains("does not take --remote"),
        "{}",
        err.message
    );
}

#[test]
fn prepare_refuses_markdown_equals_yes() {
    let err = match crate::prepare(&[
        "agent-vault".into(),
        "session".into(),
        "show".into(),
        "--markdown=yes".into(),
    ]) {
        Err(err) => err,
        Ok(_) => panic!("--markdown=yes was accepted"),
    };
    assert!(
        err.message.contains("--markdown takes no value"),
        "{}",
        err.message
    );
}

#[test]
fn probe_decisions_are_strict() {
    assert!(!crate::control_commands::probe_ok(&serde_json::json!({
        "ok": 1
    })));
    assert!(crate::control_commands::probe_ok(&serde_json::json!({
        "ok": true
    })));
    assert!(crate::control_commands::probe_skipped(
        true,
        &serde_json::json!({ "rule": "no_probe" })
    ));
    assert!(!crate::control_commands::probe_skipped(
        true,
        &serde_json::json!({ "rule": "upstream" })
    ));
}

#[test]
fn audit_verify_requires_boolean_ok() {
    assert!(!crate::control_commands::chain_is_ok(&serde_json::json!({
        "ok": false
    })));
    assert!(!crate::control_commands::witness_is_ok(
        &serde_json::json!({ "ok": 1 })
    ));
    assert!(crate::control_commands::chain_is_ok(&serde_json::json!({
        "ok": true
    })));
}

#[test]
fn tripwire_null_rules_use_defaults() {
    let listed = crate::control_commands::tripwire_listed_rules(&serde_json::json!({
        "rules": null,
        "defaults": [{ "id": "replay" }]
    }));
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert!(crate::control_commands::tripwire_on_sends_defaults(
        &serde_json::json!({ "rules_saved": false, "rules": null })
    ));
}

#[test]
fn preflight_sends_a_placeholder_assumption() {
    let mut body = serde_json::Map::new();
    crate::control_commands::assume_placeholder(&mut body);
    assert_eq!(
        body.get("assume_placeholder"),
        Some(&serde_json::Value::Bool(true))
    );
}

#[test]
fn witness_append_keeps_earlier_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("witness.jsonl");
    let shown = path.to_str().unwrap();
    crate::control_commands::append_exclusive(shown, "one").unwrap();
    crate::control_commands::append_exclusive(shown, "two").unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("one\n"), "{text}");
    assert!(text.contains("two\n"), "{text}");
}

#[test]
fn backup_export_does_not_replace_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("backup.json");
    std::fs::write(&path, "keep").unwrap();
    let ctx = crate::Context::new(true);
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::control_commands::write_exclusive(
            &ctx,
            path.to_str().unwrap(),
            "new",
            false,
        ))
        .unwrap_err();
    assert!(err.message.contains("exists"), "{}", err.message);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
}

#[test]
fn session_narrow_refuses_uses_before_the_daemon() {
    let ctx = crate::Context::new(true);
    let args = crate::cli::SessionNarrowArgs {
        grant: crate::cli::GrantFlags {
            uses: Some("1".into()),
            ..crate::cli::GrantFlags::default()
        },
        ..crate::cli::SessionNarrowArgs::default()
    };
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::control_commands::session_narrow(&ctx, &args))
        .unwrap_err();
    assert!(
        err.message.contains("cannot change --uses"),
        "{}",
        err.message
    );
}

#[test]
fn approve_refuses_an_unreadable_narrowing_before_the_daemon() {
    let Some(crate::cli::Command::Approve(args)) = parse("approve ap_1 --payload nope").command
    else {
        panic!("not approve");
    };
    let mut ctx = crate::Context::new(true);
    ctx.socket = std::env::temp_dir().join("av-cli-no-such-control.sock");
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::commands::decide(
            &ctx,
            args.id.as_deref(),
            true,
            Some(&args),
        ))
        .unwrap_err();
    assert!(err.message.contains("not valid JSON"), "{}", err.message);
}

#[test]
fn wizards_match_the_js_policy_tables() {
    use crate::wizards::{
        budget_choices, build_policy, paths_for_scope, scope_presets, suggest_slug, PolicyAnswers,
        ACCESS_LEVELS,
    };
    let read = build_policy(&PolicyAnswers {
        kind: "github".into(),
        access: "read".into(),
        paths: vec!["/user".into()],
        budget: Some(100),
        ttl_hours: Some("8".into()),
    })
    .unwrap();
    assert_eq!(read["methods"], serde_json::json!(["GET", "HEAD"]));
    assert_eq!(read["approval"], "auto");
    let write = build_policy(&PolicyAnswers {
        kind: "github".into(),
        access: "write".into(),
        paths: vec!["/**".into()],
        budget: Some(500),
        ..PolicyAnswers::default()
    })
    .unwrap();
    assert_eq!(write["approval"], "on-write");
    assert!(write["methods"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == "POST"));
    assert!(!write["methods"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == "DELETE"));
    let full = build_policy(&PolicyAnswers {
        kind: "github".into(),
        access: "full".into(),
        ..PolicyAnswers::default()
    })
    .unwrap();
    assert!(full["methods"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == "DELETE"));
    assert_eq!(full["approval"], "auto");
    let unknown = build_policy(&PolicyAnswers {
        kind: "github".into(),
        access: "admin".into(),
        ..PolicyAnswers::default()
    });
    assert!(unknown.unwrap_err().contains("unknown access level"));
    let anthropic = build_policy(&PolicyAnswers {
        kind: "anthropic".into(),
        access: "read".into(),
        ..PolicyAnswers::default()
    })
    .unwrap();
    assert_eq!(anthropic["budget"], serde_json::json!(20000));
    let generic = build_policy(&PolicyAnswers {
        kind: "http".into(),
        access: "read".into(),
        ..PolicyAnswers::default()
    })
    .unwrap();
    assert_eq!(generic["budget"], serde_json::json!(500));
    assert_eq!(suggest_slug("github", &[]), "github");
    assert_eq!(suggest_slug("github", &["github".into()]), "github-2");
    assert_eq!(
        suggest_slug("github", &["github".into(), "github-2".into()]),
        "github-3"
    );
    for kind in ["github", "google-genai", "Weird Name!", ""] {
        let slug = suggest_slug(kind, &[]);
        assert!(
            !slug.is_empty()
                && slug.len() <= 24
                && slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{kind} -> {slug}"
        );
    }
    let repo = paths_for_scope("github", "repo", Some("frozencrow/agent-vault"));
    assert!(repo.iter().any(|p| p == "/repos/frozencrow/agent-vault"));
    assert!(repo.iter().any(|p| p == "/repos/frozencrow/agent-vault/**"));
    assert!(!repo.iter().any(|p| p == "/**"));
    let owner = paths_for_scope("github", "owner", Some("frozencrow"));
    assert!(owner.iter().any(|p| p == "/repos/frozencrow/**"));
    assert!(owner.iter().any(|p| p == "/orgs/frozencrow/**"));
    assert!(!owner.iter().any(|p| p == "/**"));
    assert_eq!(
        paths_for_scope("http", "custom", Some("/a/** , /b")),
        vec!["/a/**".to_string(), "/b".to_string()]
    );
    for kind in ["github", "slack", "anthropic", "http", "unknown-kind"] {
        let presets = scope_presets(kind);
        assert!(presets.len() >= 2, "{kind}");
        assert!(presets.iter().any(|p| p.0 == "custom"), "{kind}");
    }
    assert_eq!(budget_choices("anthropic")[0].0, Some(20000));
    assert_eq!(budget_choices("github")[0].0, Some(500));
    for level in ACCESS_LEVELS {
        assert!(level.label.len() > 3, "{}", level.key);
        assert!(level.hint.len() > 10, "{}", level.key);
        assert!(!level.methods.is_empty(), "{}", level.key);
    }
}

#[test]
fn mcp_merge_keeps_neighbours_and_refuses_a_bad_name() {
    use crate::mcp_install::{agent, merge_json, merge_toml, server_entry, target_path, EntrySpec};
    assert!(agent("claude-code").is_some());
    assert!(agent("nope").is_none());
    for spec in crate::mcp_install::AGENTS {
        assert!(!spec.format.is_empty());
        assert!(spec.project_path.is_some() || spec.user_path.is_some());
    }
    let home = std::path::Path::new("/tmp/home");
    let cwd = std::path::Path::new("/tmp/proj");
    let env = std::collections::BTreeMap::from([("CODEX_HOME".into(), "/tmp/codex-home".into())]);
    let codex = target_path("codex", "user", cwd, home, &env).unwrap();
    assert_eq!(
        codex,
        std::path::PathBuf::from("/tmp/codex-home/config.toml")
    );
    let err = target_path(
        "codex",
        "project",
        cwd,
        home,
        &std::collections::BTreeMap::new(),
    );
    assert!(err.is_err(), "codex has no project scope");
    let entry = serde_json::json!({"command": "agent-vault", "args": ["mcp"]});
    let (text, unchanged) =
        merge_json("{\"theme\":1}\n", "mcpServers", "agent-vault", &entry).unwrap();
    assert!(text.contains("\"theme\""), "{text}");
    assert!(!unchanged);
    let (again, same) = merge_json(&text, "mcpServers", "agent-vault", &entry).unwrap();
    assert!(same);
    assert_eq!(again, text);
    assert!(merge_json("not json", "mcpServers", "agent-vault", &entry).is_err());
    let toml = merge_toml(
        "# keep\n[other]\nx = 1\n",
        "mcp_servers",
        "agent-vault",
        &entry,
    )
    .unwrap();
    assert!(toml.contains("# keep"), "{toml}");
    assert!(toml.contains("[other]"), "{toml}");
    assert!(toml.contains("[mcp_servers.agent-vault]"), "{toml}");
    let second = merge_toml(&toml, "mcp_servers", "agent-vault", &entry).unwrap();
    assert_eq!(
        second.matches("[mcp_servers.agent-vault]").count(),
        1,
        "{second}"
    );
    let stdio = server_entry(&EntrySpec {
        command: Some("agent-vault".into()),
        args: vec!["mcp".into()],
        ..EntrySpec::default()
    });
    assert!(stdio.get("env").is_none() || !stdio.to_string().contains("session_token"));
    let http = server_entry(&EntrySpec {
        transport: "http".into(),
        url: Some("http://127.0.0.1:1/mcp".into()),
        ..EntrySpec::default()
    });
    let http_text = http.to_string();
    assert!(http_text.contains("AGENT_VAULT_SESSION"), "{http_text}");
    assert!(!http_text.contains("av1."), "{http_text}");
    let claude = target_path(
        "claude-code",
        "project",
        cwd,
        home,
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(claude, cwd.join(".mcp.json"));
    let cursor = target_path(
        "cursor",
        "user",
        cwd,
        home,
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(cursor, home.join(".cursor/mcp.json"));
    let stale = merge_toml(
        "# keep\n[mcp_servers.agent-vault]\ncommand = \"old\"\n\n[after]\ny = 2\n",
        "mcp_servers",
        "agent-vault",
        &entry,
    )
    .unwrap();
    assert!(stale.contains("[after]"), "{stale}");
    assert!(stale.contains("y = 2"), "{stale}");
    assert!(!stale.contains("command = \"old\""), "{stale}");
    assert_eq!(stale.matches("[mcp_servers.agent-vault]").count(), 1);
}

#[test]
fn mcp_install_prints_backs_up_and_creates_the_parent() {
    use crate::mcp_install::{install, server_entry, EntrySpec, InstallSpec};
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("proj");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let entry = server_entry(&EntrySpec {
        command: Some("agent-vault".into()),
        args: vec!["mcp".into()],
        ..EntrySpec::default()
    });
    let spec = InstallSpec {
        agent: "claude-code".into(),
        scope: "project".into(),
        name: "agent-vault".into(),
        entry,
        print: true,
        cwd: cwd.clone(),
        home: home.clone(),
        ..InstallSpec::default()
    };
    let printed = install(&spec).unwrap();
    assert!(!printed.wrote);
    assert!(printed.block.contains("mcpServers"), "{}", printed.block);
    assert!(!cwd.join(".mcp.json").exists());
    let bad = InstallSpec {
        name: "a]\n[evil]".into(),
        ..spec.clone()
    };
    assert!(install(&bad).is_err());
    let wrote = install(&InstallSpec {
        print: false,
        ..spec.clone()
    })
    .unwrap();
    assert!(wrote.wrote);
    assert!(wrote.backup.is_none());
    assert!(cwd.join(".mcp.json").is_file());
    let again = install(&InstallSpec {
        print: false,
        ..spec
    })
    .unwrap();
    let bak = again.backup.expect("a second install keeps the old file");
    assert!(std::fs::read_to_string(bak)
        .unwrap()
        .contains("agent-vault"));
}

#[test]
fn mcp_launch_is_portable_for_a_project_and_absolute_for_the_system_install() {
    let (cmd, args) = crate::commands::mcp_launch(
        true,
        Some("agent-vault"),
        false,
        "/var/db/agent-vault/app/bin/agent-vault",
        "/tmp/checkout/agent-vault",
    );
    assert_eq!(cmd, "agent-vault");
    assert_eq!(args, vec!["mcp".to_string()]);
    assert!(!cmd.contains('/'));
    let (sys, _) = crate::commands::mcp_launch(
        false,
        None,
        true,
        "/var/db/agent-vault/app/bin/agent-vault",
        "/tmp/checkout/agent-vault",
    );
    assert_eq!(sys, "/var/db/agent-vault/app/bin/agent-vault");
    assert!(!sys.contains("runtime/node"));
}

#[test]
fn no_factor_is_named_in_status_and_doctor() {
    let lines = crate::commands::no_factor_status_lines(false, false).unwrap();
    assert!(lines[0].contains("no human factor is enrolled"));
    assert!(crate::commands::no_factor_status_lines(true, false).is_none());
    let (ok, note) = crate::commands::doctor_factor_note(false, false);
    assert!(!ok);
    assert!(note.contains("agent-vault passphrase set"), "{note}");
    let (enrolled, named) = crate::commands::doctor_factor_note(true, true);
    assert!(enrolled);
    assert_eq!(named, "passphrase + authenticator");
}

#[test]
fn doctor_names_the_audit_chain() {
    let (name, ok) = crate::commands::doctor_audit_check(&serde_json::json!({ "ok": true }));
    assert_eq!(name, "audit chain intact");
    assert!(ok);
    let (_, bad) = crate::commands::doctor_audit_check(&serde_json::json!({ "ok": 1 }));
    assert!(!bad);
}

#[test]
fn cred_list_names_the_fingerprint_and_the_site() {
    let line = crate::commands::cred_field_label("abcd1234", "header:authorization:Bearer");
    assert!(line.contains("fp:abcd1234"), "{line}");
    assert!(line.contains("header:authorization:Bearer"), "{line}");
    assert!(!line.contains("secret-value"));
}

#[test]
fn gateway_port_ignores_a_tampered_value() {
    let ctx = crate::Context::new(true);
    for evil in [
        "1@attacker.example",
        "7411/../@evil.test",
        "x",
        "-1",
        "99999",
    ] {
        let state = serde_json::json!({
            "gateway_port": evil,
            "base_url": format!("http://127.0.0.1:{evil}/")
        });
        assert_eq!(ctx.gateway_port_of(&state), 7411, "{evil}");
    }
    assert_eq!(
        ctx.gateway_port_of(&serde_json::json!({ "gateway_port": 8123 })),
        8123
    );
    let followed = ctx.gateway_port_of(&serde_json::json!({
        "base_url": "http://127.0.0.1:7420/p/demo"
    }));
    assert_eq!(followed, 7420);
    let lines = crate::commands::legacy_env_lines("avs1.abcdefghijkl.c2VjcmV0", followed, None);
    assert!(
        lines.iter().any(|l| l.contains("http://127.0.0.1:7420")),
        "{lines:?}"
    );
    assert_eq!(
        crate::commands::mcp_endpoint(followed),
        "http://127.0.0.1:7420/mcp"
    );
}

#[test]
fn watch_backoff_caps_at_30_seconds() {
    use std::time::Duration;
    assert_eq!(
        crate::watch::next_backoff(Duration::from_secs(1)),
        Duration::from_secs(2)
    );
    assert_eq!(
        crate::watch::next_backoff(Duration::from_secs(16)),
        Duration::from_secs(30)
    );
    assert_eq!(
        crate::watch::next_backoff(Duration::from_secs(30)),
        Duration::from_secs(30)
    );
}

#[test]
fn watch_old_daemon_is_version_skew() {
    use av_core::errors::Exit;
    let skew = crate::watch::stream_refusal(
        404,
        &serde_json::json!({ "detail": "no control route /v1/pending/stream" }),
    );
    assert_eq!(skew.exit, Exit::VersionSkew);
    assert!(skew.message.contains("older than this command"));
    assert!(skew.next.unwrap().contains("agent-vault daemon"));
    let denied = crate::watch::stream_refusal(
        403,
        &serde_json::json!({ "code": "AV_POLICY_DENIED", "detail": "no" }),
    );
    assert_eq!(denied.exit, Exit::PolicyDenied);
    assert!(!denied.skew);
}

#[test]
fn fresh_backup_without_a_terminal_does_not_open_a_window() {
    let pass = crate::presence_without_a_terminal(&["passphrase".into()]);
    assert!(pass.next.is_none(), "{:?}", pass.next);
    assert!(pass.message.contains("no terminal"));
    let both = crate::presence_without_a_terminal(&["passphrase".into(), "authenticator".into()]);
    let next = both.next.unwrap();
    assert!(next.contains("agent-vault ui"), "{next}");
}

#[test]
fn session_detail_names_spend_lifetime_and_incomplete_history() {
    let detail = serde_json::json!({
        "session": { "id": "test", "label": "example", "infinite": false },
        "grants": [{
            "cred": "demo",
            "grant_id": "g1",
            "expires_at": "2030-01-01",
            "effective": { "methods": ["GET"], "payload": [] },
            "budget": { "limit": 5, "used": 2 },
            "spend": {
                "tokens_used": 1234,
                "limit_tokens": 50000,
                "usd_micros_used": 420000,
                "limit_usd_micros": 5000000
            },
            "placeholders": [{ "id": "ledger", "state": "active" }]
        }],
        "activity": {
            "complete": false,
            "note": "anchor missing",
            "requests": { "allowed": 1 },
            "approvals": { "requested": 1 },
            "paths": [{ "count": 1, "method": "GET", "path": "/ok" }],
            "denials": [{ "count": 1, "code": "AV_POLICY_DENIED", "rule": "methods" }]
        }
    });
    for markdown in [false, true] {
        let text = crate::control_commands::session_summary(&detail, markdown);
        assert!(text.contains("1,234 / 50,000 tokens"), "{text}");
        assert!(text.contains("$0.42 / $5.00"), "{text}");
        assert!(text.contains("2030-01-01"), "{text}");
        assert!(text.contains("GET"), "{text}");
        assert!(text.contains("/ok"), "{text}");
    }
    assert_eq!(
        crate::control_commands::activity_incomplete_note(detail.get("activity")).as_deref(),
        Some("anchor missing")
    );
}

#[test]
fn report_labels_incomplete_history_in_the_tables() {
    let data = serde_json::json!({
        "since": "24h",
        "generated_at": "now",
        "complete": false,
        "credentials": [{ "slug": "demo", "requests": 3, "denials": 2 }],
        "sessions": [{ "id": "sid", "label": "test", "state": "active", "unused_methods": ["POST"] }]
    });
    for markdown in [false, true] {
        let text = crate::control_commands::report_summary(&data, markdown);
        assert!(text.contains("Credentials"), "{text}");
        assert!(text.contains("Sessions"), "{text}");
        assert!(text.contains("POST"), "{text}");
        assert!(text.contains("history is incomplete"), "{text}");
    }
}

#[test]
fn try_command_puts_the_token_where_it_cannot_collide() {
    let lines = crate::commands::try_command_lines(
        "http://127.0.0.1:7411",
        "/",
        "avs1.demo.secret",
        "Authorization: Bearer av1.demo.placeholder",
    );
    let text = lines.join("\n");
    assert_eq!(text.matches("Authorization").count(), 1, "{text}");
    assert!(text.contains("-H \"AV-Session: avs1."), "{text}");
    assert!(text.contains("-H \"Authorization: Bearer av1."), "{text}");
}

#[test]
fn ui_warns_when_the_origin_is_not_trusted() {
    let origin = "http://127.0.0.1:9";
    assert!(crate::commands::origin_is_untrusted(&[], origin));
    assert!(!crate::commands::origin_is_untrusted(
        &[serde_json::json!(origin)],
        origin
    ));
    let warning = crate::commands::untrusted_origin_warning(origin);
    assert!(warning.contains("is not a trusted UI origin"), "{warning}");
}

#[test]
fn fresh_presence_without_a_factor_says_to_set_one() {
    use av_core::errors::Exit;
    let err = crate::factor_required(None);
    assert_eq!(err.exit, Exit::Presence);
    assert_eq!(err.exit.code(), 5);
    let next = err.next.unwrap();
    assert!(next.contains("agent-vault passphrase set"), "{next}");
}

#[test]
fn exec_reports_a_signal_as_a_failure_and_a_missing_binary_as_an_error() {
    let killed = std::process::Command::new("sh")
        .args(["-c", "kill -TERM $$"])
        .status()
        .unwrap();
    let code = crate::commands::child_status_code(killed);
    assert_ne!(code, 0);
    assert!(code >= 128, "{code}");
    let ordinary = std::process::Command::new("sh")
        .args(["-c", "exit 3"])
        .status()
        .unwrap();
    assert_eq!(crate::commands::child_status_code(ordinary), 3);
    let missing = std::process::Command::new("definitely-not-a-command-av-fc")
        .status()
        .unwrap_err();
    assert_eq!(crate::commands::spawn_error_code(missing.kind()), 127);
}

#[test]
fn rotate_body_carries_the_options_and_not_an_argv_secret() {
    let secret = "fake-rotation-secret-for-cli-tests";
    let body = crate::control_commands::rotate_body(
        "demo",
        secret,
        "keep",
        Some("token"),
        Some(24.0),
        Some(Some("2030-02-28T00:00:00.000Z".into())),
    );
    assert_eq!(body.get("slug").and_then(|v| v.as_str()), Some("demo"));
    assert_eq!(body.get("value").and_then(|v| v.as_str()), Some(secret));
    assert_eq!(body.get("mode").and_then(|v| v.as_str()), Some("keep"));
    assert_eq!(body.get("field").and_then(|v| v.as_str()), Some("token"));
    assert_eq!(body.get("retire_hours").and_then(|v| v.as_i64()), Some(24));
    assert_eq!(
        body.get("expires_at").and_then(|v| v.as_str()),
        Some("2030-02-28T00:00:00.000Z")
    );
    let revoked = crate::control_commands::rotate_body(
        "demo",
        "fake-second-value",
        "revoke",
        None,
        None,
        None,
    );
    assert_eq!(revoked.get("mode").and_then(|v| v.as_str()), Some("revoke"));
    assert!(revoked.get("field").is_none());
}

#[test]
fn scrub_and_pin_bodies_match_the_routes() {
    let add = crate::control_commands::scrub_add_body("demo", "fake_[a-z]{4}", Some("fake_abcd"));
    assert_eq!(add.get("slug").and_then(|v| v.as_str()), Some("demo"));
    assert_eq!(
        add.get("pattern").and_then(|v| v.as_str()),
        Some("fake_[a-z]{4}")
    );
    assert_eq!(
        add.get("sample").and_then(|v| v.as_str()),
        Some("fake_abcd")
    );
    assert_eq!(
        crate::control_commands::scrub_delete_query("demo", "pattern /?&"),
        "slug=demo&id=pattern+%2F%3F%26"
    );
    let pins = vec!["sha256/one".into(), "sha256/two".into()];
    let pin = crate::control_commands::pin_add_body("demo", "api.example.test", &pins);
    assert_eq!(
        pin.get("host").and_then(|v| v.as_str()),
        Some("api.example.test")
    );
    assert_eq!(
        pin.get("pins").and_then(|v| v.as_array()).map(|a| a.len()),
        Some(2)
    );
}

#[test]
fn expiry_refuses_a_non_calendar_date_and_accepts_none() {
    use crate::policy_input::expiry_input;
    for date in ["2030-02-30", "2030-13-01", "tomorrow"] {
        assert!(expiry_input(Some(date)).is_err(), "{date}");
    }
    assert_eq!(expiry_input(Some("none")).unwrap(), None);
    assert_eq!(
        expiry_input(Some("2030-02-28")).unwrap().as_deref(),
        Some("2030-02-28T00:00:00.000Z")
    );
}

#[test]
fn conflict_mode_is_skip_rename_or_fail() {
    use crate::control_commands::conflict_mode;
    assert_eq!(conflict_mode(None).unwrap(), "skip");
    assert_eq!(conflict_mode(Some("rename")).unwrap(), "rename");
    assert_eq!(conflict_mode(Some("fail")).unwrap(), "fail");
    assert!(conflict_mode(Some("merge")).is_err());
}

#[test]
fn watch_parses_a_crlf_field_and_a_split_character() {
    assert_eq!(
        crate::watch::sse_line(b"event: snapshot\r\n"),
        "event: snapshot"
    );
    let raw = b"data: \"caf\xc3\xa9\"\r\n";
    assert_eq!(crate::watch::sse_line(raw), "data: \"caf\u{e9}\"");
}

#[test]
fn watch_shows_an_id_once() {
    let mut seen = std::collections::BTreeSet::new();
    assert!(crate::watch::first_time(&mut seen, "req-1"));
    assert!(!crate::watch::first_time(&mut seen, "req-1"));
    assert!(!crate::watch::first_time(&mut seen, ""));
    assert!(crate::watch::first_time(&mut seen, "req-2"));
}

#[test]
fn append_refuses_a_fifo_a_reader_is_waiting_on() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("witness");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let started = std::time::Instant::now();
    let err = crate::files::append_line_exclusive(&fifo, "fake-line").unwrap_err();
    assert!(started.elapsed().as_secs() < 2, "fifo open hung");
    assert!(err.to_string().contains("is not a regular file"), "{err}");
    let mut buf = [0u8; 64];
    match reader.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("the reader got bytes: {other:?}"),
    }
}

#[test]
fn write_refuses_a_fifo_with_and_without_force() {
    use std::os::unix::fs::FileTypeExt;
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("planted");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let plain = crate::files::write_file_exclusive(&fifo, "fake-text", false, 0o600).unwrap_err();
    assert!(plain.to_string().contains("exists"), "{plain}");
    let forced = crate::files::write_file_exclusive(&fifo, "fake-text", true, 0o600).unwrap_err();
    assert!(
        forced.to_string().contains("is not a regular file"),
        "{forced}"
    );
    let meta = std::fs::symlink_metadata(&fifo).unwrap();
    assert!(meta.file_type().is_fifo());
}

#[test]
fn unknown_command_names_itself() {
    let err = match crate::prepare(&["agent-vault".into(), "frobnicate".into()]) {
        Err(err) => err,
        Ok(_) => panic!("an unknown command was accepted"),
    };
    assert!(
        err.message.contains("unknown command \"frobnicate\""),
        "{}",
        err.message
    );
}

#[test]
fn root_is_allowed_treats_an_empty_value_and_an_unknown_uid_as_refused() {
    assert!(!crate::root_is_allowed(None, Some(0)));
    assert!(!crate::root_is_allowed(Some(""), Some(0)));
    assert!(!crate::root_is_allowed(None, None));
    assert!(crate::root_is_allowed(Some("1"), Some(0)));
    assert!(crate::root_is_allowed(None, Some(1)));
}

#[test]
fn socket_read_timeout_matches_the_js_client() {
    assert!(crate::http_client::socket_read_timeout().is_none());
}

#[test]
fn utf8_pair_drops_a_non_utf8_value() {
    use std::os::unix::ffi::OsStrExt;
    let bad = std::ffi::OsStr::from_bytes(b"va\xfflue");
    assert!(crate::commands::utf8_pair(std::ffi::OsStr::new("OK"), bad).is_none());
    assert_eq!(
        crate::commands::utf8_pair(std::ffi::OsStr::new("HOME"), std::ffi::OsStr::new("/tmp")),
        Some(("HOME".into(), "/tmp".into()))
    );
}

#[test]
fn daemon_passphrase_is_not_discarded() {
    let secret = av_core::secret::SecretString::from("test-secret-not-real".to_string());
    assert!(crate::commands::passphrase_for_daemon(true, Some(secret)).is_some());
    let ignored = av_core::secret::SecretString::from("test-secret-not-real".to_string());
    assert!(crate::commands::passphrase_for_daemon(false, Some(ignored)).is_none());
}

#[test]
fn service_port_rejects_anything_but_an_integer_port() {
    assert_eq!(crate::setup::service_port(None).unwrap(), "7411");
    assert_eq!(crate::setup::service_port(Some("1")).unwrap(), "1");
    assert_eq!(crate::setup::service_port(Some("65535")).unwrap(), "65535");
    assert!(crate::setup::service_port(Some("0")).is_err());
    assert!(crate::setup::service_port(Some("65536")).is_err());
    assert!(crate::setup::service_port(Some("74 11")).is_err());
    assert!(crate::setup::service_port(Some("80\nInjected=yes")).is_err());
}

#[test]
fn launchd_plist_matches_the_js_template() {
    let program = std::path::Path::new("/opt/bin/agent-vault-daemon");
    let vault = std::path::Path::new("/var/db/agent-vault/vault");
    let run = std::path::Path::new("/var/db/agent-vault/run");
    let got = crate::setup::launchd_plist(program, vault, run, 501, "7411");
    let expected = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key><string>com.agentvault.daemon</string>
  <key>ProgramArguments</key>
  <array><string>/opt/bin/agent-vault-daemon</string></array>
  <key>UserName</key><string>_agentvault</string>
  <key>GroupName</key><string>_agentvault</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Adaptive</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AV_VAULT_DIR</key><string>/var/db/agent-vault/vault</string>
    <key>AV_RUN_DIR</key><string>/var/db/agent-vault/run</string>
    <key>AV_ENROLLED_UID</key><string>501</string>
    <key>AV_CLIENT_GROUP</key><string>_agentvault_users</string>
    <key>AV_PORT</key><string>7411</string>
  </dict>
  <key>StandardOutPath</key><string>/var/db/agent-vault/vault/daemon.out</string>
  <key>StandardErrorPath</key><string>/var/db/agent-vault/vault/daemon.err</string>
  <key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
</dict>
</plist>
";
    assert_eq!(got, expected);
}

#[test]
fn systemd_unit_matches_the_js_template() {
    let program = std::path::Path::new("/opt/bin/agent-vault-daemon");
    let vault = std::path::Path::new("/var/lib/agent-vault");
    let run = std::path::Path::new("/run/agent-vault");
    let got = crate::setup::systemd_unit(program, vault, run, 501, "7411");
    let expected = "\
[Unit]
Description=agent-vault daemon
After=network.target

[Service]
Type=simple
User=_agentvault
Group=_agentvault
SupplementaryGroups=_agentvault_users
ExecStart=/opt/bin/agent-vault-daemon
Environment=AV_VAULT_DIR=/var/lib/agent-vault
Environment=AV_RUN_DIR=/run/agent-vault
Environment=AV_ENROLLED_UID=501
Environment=AV_CLIENT_GROUP=_agentvault_users
Environment=AV_PORT=7411
RuntimeDirectory=agent-vault
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/agent-vault /run/agent-vault
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
MemoryDenyWriteExecute=yes
LockPersonality=yes
LimitCORE=0
Restart=always

[Install]
WantedBy=multi-user.target
";
    assert_eq!(got, expected);
}

#[test]
fn state_document_keeps_the_js_key_order() {
    let doc = crate::setup::state_document(&[("dir".into(), "/tmp/app".into())], 1, None);
    let kind = doc.find("\"kind\"").unwrap();
    let id = doc.find("\"id\"").unwrap();
    let created = doc.find("\"created\"").unwrap();
    let version = doc.find("\"version\"").unwrap();
    assert!(created < kind && kind < id && id < version, "{doc}");
    assert!(!doc.contains("retired"), "{doc}");
    assert!(!doc.ends_with('\n'), "{doc}");
    let retired = crate::setup::state_document(&[], 1, Some("/tmp/retired"));
    assert!(
        retired.find("\"version\"").unwrap() < retired.find("\"retired\"").unwrap(),
        "{retired}"
    );
}

#[test]
fn delete_recorded_removes_files_and_leaves_the_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    let file = tmp.path().join("unit");
    let vault = tmp.path().join("vault");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(&file, b"x").unwrap();
    let items = vec![
        ("dir".into(), dir.display().to_string()),
        ("dir".into(), vault.display().to_string()),
        ("file".into(), file.display().to_string()),
    ];
    let removed = crate::setup::delete_recorded(false, &items, &vault);
    assert!(!dir.exists());
    assert!(vault.exists(), "uninstall removed the vault");
    assert!(!file.exists());
    assert_eq!(removed.len(), 2, "{removed:?}");
    let planned = crate::setup::delete_recorded(true, &items, &vault);
    assert_eq!(planned.len(), 2);
}

#[test]
fn require_regular_daemon_rejects_a_missing_file_and_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("agent-vault-daemon");
    let err = crate::setup::require_regular_daemon(&missing).unwrap_err();
    assert!(err.message.contains("missing"), "{}", err.message);
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&missing, &link).unwrap();
    let err = crate::setup::require_regular_daemon(&link).unwrap_err();
    assert!(err.message.contains("symbolic link"), "{}", err.message);
}

#[cfg(target_os = "macos")]
#[test]
fn refuses_self_install_treats_var_and_private_var_as_the_same_directory() {
    let spelled = std::path::Path::new("/var/db/agent-vault/app");
    let private = std::path::Path::new("/private/var/db/agent-vault/app");
    assert!(crate::setup::refuses_self_install(spelled, private));
    assert!(crate::setup::refuses_self_install(private, spelled));
}

/// A release directory (a download or a Homebrew keg): the three binaries.
fn release_dir(root: &std::path::Path) -> std::path::PathBuf {
    let dir = root.join("agent-vault-0.3.0/bin");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["agent-vault", "agent-vault-daemon", "agent-vault-setup"] {
        std::fs::write(dir.join(name), b"binary").unwrap();
    }
    dir
}

#[test]
fn a_release_directory_is_an_install_source_and_links_resolve_to_it() {
    let tmp = tempfile::tempdir().unwrap();
    let real = release_dir(tmp.path()).canonicalize().unwrap();
    assert!(crate::setup::is_install_source(&real));
    assert_eq!(crate::setup::release_dir_of(&real), real);

    // Homebrew's bin directory holds links into the keg; the source is the
    // keg, whose files are regular, never the directory of links.
    let links = tmp.path().join("homebrew/bin");
    std::fs::create_dir_all(&links).unwrap();
    for name in ["agent-vault", "agent-vault-daemon", "agent-vault-setup"] {
        std::os::unix::fs::symlink(real.join(name), links.join(name)).unwrap();
    }
    let via_link = links.join("agent-vault");
    assert_eq!(
        crate::setup::release_dir_beside(&via_link),
        Some(real.clone())
    );

    // Outside a checkout, setup and upgrade install from that keg.
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let found = crate::commands::install_source_from(Ok(elsewhere), Some(&via_link)).unwrap();
    assert_eq!(found, real);

    // Inside a checkout, the checkout wins.
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("rust/crates/av-cli")).unwrap();
    std::fs::write(checkout.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
    let found =
        crate::commands::install_source_from(Ok(checkout.clone()), Some(&via_link)).unwrap();
    assert_eq!(found, checkout);
    assert_eq!(
        crate::setup::release_dir_of(&checkout),
        checkout.join("rust/target/release")
    );

    // A directory with only one of the binaries is not a release.
    let half = tmp.path().join("half");
    std::fs::create_dir_all(&half).unwrap();
    std::fs::write(half.join("agent-vault"), b"binary").unwrap();
    assert!(!crate::setup::is_install_source(&half));
    assert_eq!(
        crate::setup::release_dir_beside(&half.join("agent-vault")),
        None
    );
}

#[test]
fn upgrade_from_a_release_directory_names_the_root_owned_installer() {
    let tmp = tempfile::tempdir().unwrap();
    let release = release_dir(tmp.path()).canonicalize().unwrap();
    let app = tmp.path().join("root/app");
    let root_owned = app.join("bin/agent-vault-setup");
    std::fs::create_dir_all(root_owned.parent().unwrap()).unwrap();
    std::fs::write(&root_owned, b"#!/bin/sh\n--from\n").unwrap();
    let (cmd, installer, using_root) =
        crate::commands::format_upgrade_command(&root_owned, &root_owned, &release).unwrap();
    assert!(using_root);
    assert_eq!(installer, root_owned);
    assert_eq!(
        cmd,
        format!(
            "sudo {} install --from {}",
            root_owned.display(),
            release.display()
        )
    );
    assert!(crate::setup::install_app_accepts(
        &installer, &release, &app
    ));

    // An installed copy too old for --from: the release's own installer.
    std::fs::write(&root_owned, b"old installer without the flag").unwrap();
    let (_, installer, using_root) =
        crate::commands::format_upgrade_command(&root_owned, &root_owned, &release).unwrap();
    assert!(!using_root);
    assert_eq!(installer, release.join("agent-vault-setup"));

    // A release directory inside the installed app is the app itself.
    assert!(!crate::setup::install_app_accepts(
        &root_owned,
        &app.join("bin"),
        &app
    ));
}
