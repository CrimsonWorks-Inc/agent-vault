//! Rewrite `argv` so clap sees what `parseArgs` in `src/cli/index.js` would
//! have kept. Unknown flags are dropped (and recorded for the commands that
//! refuse them). A boolean flag with a value is a usage error here, before
//! clap turns it into a positional.

use std::cell::RefCell;

use av_core::errors::Exit;

use crate::policy_input::set_extra_flags;
use crate::CliError;

thread_local! {
    static BARE_TRUE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Whether `parseArgs` stored boolean `true` for this flag (no value). The
/// mcp-install `--port` handler needs that: `Number(true)` is 1, and the JS
/// refuses it as `not true` rather than defaulting the port.
pub fn was_bare(flag: &str) -> bool {
    BARE_TRUE.with(|c| c.borrow().iter().any(|f| f == flag))
}

fn usage(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit: Exit::Usage,
        next: Some("agent-vault help".into()),
        problem: None,
        skew: false,
    }
}

/// Argv clap should parse, including argv0. `json` is the exact `--json`
/// token (`--json=true` is ignored, as in the JS, where only that token sets
/// `JSON_OUT`).
pub struct Prepared {
    /// Rewritten argv.
    pub argv: Vec<String>,
    /// `--json` was an exact token before `--`.
    pub json: bool,
}

const GROUPS: &[(&str, &[&str])] = &[
    (
        "cred",
        &[
            "add",
            "list",
            "rm",
            "rotate",
            "test",
            "expiry",
            "scrub",
            "pin",
            "quarantine",
            "release",
        ],
    ),
    ("session", &["create", "list", "revoke", "narrow", "show"]),
    ("ph", &["next", "check", "pattern"]),
    ("audit", &["tail", "verify", "export", "witness"]),
    ("listen", &["add", "list", "rm"]),
    ("mcp", &["url", "install"]),
    ("passphrase", &["set", "remove"]),
    ("tls", &["setup", "status"]),
    ("template", &["save", "list", "show", "rm"]),
    ("backup", &["export", "inspect", "restore"]),
    ("tripwire", &["show", "on", "off", "set"]),
    ("notify", &["set", "show", "off", "test"]),
];

const COMMANDS: &[&str] = &[
    "setup",
    "daemon",
    "upgrade",
    "quickstart",
    "status",
    "env",
    "exec",
    "approvals",
    "approve",
    "deny",
    "watch",
    "panic",
    "lock",
    "unlock",
    "ui",
    "docs",
    "profiles",
    "doctor",
    "preflight",
    "migrate",
    "help",
    "report",
];

const SECRET_FLAGS: &[&str] = &[
    "value",
    "webhook-url",
    "webhook_url",
    "recovery-passphrase",
    "recovery_passphrase",
];

/// Flags `booleanFlag` refuses a value for, keyed by the command words.
fn bool_flags(path: &[&str]) -> &'static [&'static str] {
    match path {
        ["setup"] => &["dev", "print-only", "passphrase"],
        ["upgrade"] => &["print-only"],
        ["daemon"] => &["passphrase"],
        ["cred", "rotate"] => &["revoke"],
        ["cred", "test"] => &["all"],
        ["cred", "pin"] => &["clear", "live"],
        ["session", "create"] | ["template", "save"] => &["infinite"],
        ["env"] => &["force", "profile-vars"],
        ["exec"] => &["profile-vars"],
        ["watch"] => &["no-notify", "open", "quiet"],
        ["panic"] => &["lock"],
        ["audit", "export"] => &["follow", "force"],
        ["backup", "export"] => &["force"],
        ["tls", "setup"] => &["force"],
        ["ui"] | ["docs"] => &["no-open", "open"],
        ["mcp", "install"] => &["tls", "print"],
        ["migrate"] => &["dry-run"],
        ["session", "show"] | ["report"] => &["markdown"],
        _ => &[],
    }
}

fn declared_flags(path: &[&str]) -> Vec<String> {
    use clap::CommandFactory;
    let mut cmd = crate::cli::Cli::command();
    for name in path {
        let Some(sub) = cmd.find_subcommand(name).cloned() else {
            return Vec::new();
        };
        cmd = sub;
    }
    let mut names = Vec::new();
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long() {
            names.push(long.to_string());
        }
    }
    names
}

fn strict(path: &[&str]) -> bool {
    matches!(
        path,
        ["session", "create"] | ["session", "narrow"] | ["approve"] | ["template", "save"]
    )
}

struct Flag {
    name: String,
    /// `None` is boolean true (no value token). `Some` is the value.
    value: Option<String>,
}

/// Ports the flag scan of `parseArgs` plus the dispatch of `main` that
/// clap cannot do alone (unknown flags ignored, `mcp <other>` is the
/// bridge, boolean values refused).
pub fn prepare(argv: &[String]) -> Result<Prepared, CliError> {
    BARE_TRUE.with(|c| c.borrow_mut().clear());
    set_extra_flags(&[]);
    let argv0 = argv
        .first()
        .cloned()
        .unwrap_or_else(|| "agent-vault".into());
    let args = if argv.is_empty() { &[] } else { &argv[1..] };
    let mut json = false;
    let mut help = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut flags: Vec<Flag> = Vec::new();
    let mut passthrough = false;
    let mut trailing: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if passthrough {
            trailing.push(a.clone());
            i += 1;
            continue;
        }
        if a == "--" {
            passthrough = true;
            i += 1;
            continue;
        }
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--json=") {
            // Not the exact token. Ignored, not an error, and not JSON mode.
            let _ = rest;
            i += 1;
            continue;
        }
        if let Some(stripped) = a.strip_prefix("--") {
            let (name, value, consumed) = if let Some((name, value)) = stripped.split_once('=') {
                (name.to_string(), Some(value.to_string()), 1)
            } else {
                let next = args.get(i + 1);
                if next.is_some_and(|n| !n.starts_with('-')) {
                    (stripped.to_string(), Some(next.unwrap().clone()), 2)
                } else {
                    (stripped.to_string(), None, 1)
                }
            };
            if name == "help" {
                help = true;
            } else {
                flags.push(Flag { name, value });
            }
            i += consumed;
            continue;
        }
        positionals.push(a.clone());
        i += 1;
    }

    if positionals.first().map(String::as_str) == Some("help") {
        help = true;
        positionals.clear();
    }

    let (path, rest) = resolve(&positionals)?;
    if help {
        let mut out = vec![argv0];
        if json {
            out.push("--json".into());
        }
        // `cred scrub --help` is the one command whose help is not the top page.
        if path == ["cred", "scrub"] {
            out.push("cred".into());
            out.push("scrub".into());
        }
        out.push("--help".into());
        return Ok(Prepared { argv: out, json });
    }
    if path.is_empty() {
        let mut out = vec![argv0];
        if json {
            out.push("--json".into());
        }
        out.push("--help".into());
        return Ok(Prepared { argv: out, json });
    }

    let bools = bool_flags(&path);
    let known = declared_flags(&path);
    let mut extras = Vec::new();
    let mut kept: Vec<Flag> = Vec::new();
    for flag in flags {
        if SECRET_FLAGS.contains(&flag.name.as_str()) {
            kept.push(flag);
            continue;
        }
        if bools.contains(&flag.name.as_str()) {
            if flag.value.as_ref().is_some_and(|v| !v.is_empty()) {
                return Err(usage(format!("--{} takes no value", flag.name)));
            }
            kept.push(Flag {
                name: flag.name,
                value: None,
            });
            continue;
        }
        let declared = known.iter().any(|k| k == &flag.name);
        if !declared {
            if strict(&path) {
                extras.push(flag.name);
            }
            continue;
        }
        if flag.value.is_none() && path == ["mcp", "install"] && flag.name == "port" {
            BARE_TRUE.with(|c| c.borrow_mut().push("port".into()));
            continue;
        }
        if flag.value.is_none() && path == ["env"] && flag.name == "out" {
            return Err(CliError {
                message: "--out needs a file name".into(),
                exit: Exit::Usage,
                next: None,
                problem: None,
                skew: false,
            });
        }
        kept.push(flag);
    }
    set_extra_flags(&extras);

    let mut out = vec![argv0];
    if json {
        out.push("--json".into());
    }
    for word in &path {
        out.push((*word).to_string());
    }
    for flag in &kept {
        match &flag.value {
            None => out.push(format!("--{}", flag.name)),
            Some(v) if v.is_empty() => out.push(format!("--{}=", flag.name)),
            Some(v) => out.push(format!("--{}={v}", flag.name)),
        }
    }
    let positional_budget = positional_budget(&path);
    let keep_n = if positional_budget == usize::MAX {
        rest.len()
    } else {
        rest.len().min(positional_budget)
    };
    for p in rest.iter().take(keep_n) {
        out.push(p.clone());
    }
    if path == ["exec"] {
        if passthrough || !trailing.is_empty() {
            out.push("--".into());
        }
        out.extend(trailing);
    }
    Ok(Prepared { argv: out, json })
}

fn positional_budget(path: &[&str]) -> usize {
    match path {
        ["exec"] => usize::MAX,
        ["cred", "expiry"] => 2,
        ["cred", "add"]
        | ["cred", "rm"]
        | ["cred", "rotate"]
        | ["cred", "test"]
        | ["cred", "scrub"]
        | ["cred", "pin"]
        | ["cred", "quarantine"]
        | ["cred", "release"]
        | ["session", "revoke"]
        | ["session", "narrow"]
        | ["session", "show"]
        | ["ph", "next"]
        | ["ph", "check"]
        | ["approve"]
        | ["deny"]
        | ["template", "save"]
        | ["template", "show"]
        | ["template", "rm"]
        | ["backup", "inspect"]
        | ["backup", "restore"]
        | ["listen", "add"]
        | ["listen", "rm"]
        | ["docs"]
        | ["mcp", "install"] => 1,
        _ => 0,
    }
}

fn resolve(positionals: &[String]) -> Result<(Vec<&'static str>, Vec<String>), CliError> {
    let Some(first) = positionals.first() else {
        return Ok((Vec::new(), Vec::new()));
    };
    if let Some((_, subs)) = GROUPS.iter().find(|(g, _)| *g == first.as_str()) {
        if let Some(second) = positionals.get(1) {
            if let Some(sub) = subs.iter().find(|s| **s == second.as_str()) {
                let path = match first.as_str() {
                    "cred" => vec!["cred", *sub],
                    "session" => vec!["session", *sub],
                    "ph" => vec!["ph", *sub],
                    "audit" => vec!["audit", *sub],
                    "listen" => vec!["listen", *sub],
                    "mcp" => vec!["mcp", *sub],
                    "passphrase" => vec!["passphrase", *sub],
                    "tls" => vec!["tls", *sub],
                    "template" => vec!["template", *sub],
                    "backup" => vec!["backup", *sub],
                    "tripwire" => vec!["tripwire", *sub],
                    "notify" => vec!["notify", *sub],
                    _ => vec![*sub],
                };
                return Ok((path, positionals[2..].to_vec()));
            }
        }
        // Bare `mcp`, and `mcp <anything else>`, is the stdio bridge.
        // `mcp url` and `mcp install` already returned above. Every other
        // group with an unknown second word is `unknown command "<group>"`.
        if first == "mcp" {
            return Ok((vec!["mcp"], Vec::new()));
        }
        return Err(usage(format!("unknown command \"{first}\"")));
    }
    if let Some(name) = COMMANDS.iter().find(|c| **c == first.as_str()) {
        return Ok((vec![*name], positionals[1..].to_vec()));
    }
    Err(usage(format!("unknown command \"{first}\"")))
}
