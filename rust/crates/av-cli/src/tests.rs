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
