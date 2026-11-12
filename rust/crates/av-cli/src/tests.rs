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
    let cleaned = crate::control_commands::clean_text("a\u{202e}b\n\tc\u{0007}d\r");
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
    let (path, root) = crate::commands::choose_upgrade_installer(
        std::path::Path::new("/no/such/installer"),
        std::path::Path::new("/checkout/agent-vault-setup"),
    );
    assert!(!root);
    assert_eq!(
        path,
        std::path::PathBuf::from("/checkout/agent-vault-setup")
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
    let started = std::time::Instant::now();
    let err = crate::files::append_line_exclusive(&fifo, "line").unwrap_err();
    assert!(started.elapsed().as_secs() < 2, "fifo open hung");
    let text = err.to_string();
    assert!(text.contains("is not a regular file"), "{text}");
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
