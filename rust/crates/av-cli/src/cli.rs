//! The `agent-vault` command tree (also installed as `av`), declared with
//! clap. Ports the hand-written `parseArgs`, the `COMMANDS` table and the
//! `GROUPS` dispatch of `src/cli/index.js`, plus the handlers merged in from
//! `controlCommands` in `src/cli/control-commands.js`.
//!
//! Flag spellings are the JS spellings exactly. Every value flag is a
//! `String` (not a number): the JS validates numbers itself
//! (`numberFlag`/`optionalNumber` in `src/cli/policy-input.js`) with exact
//! messages and ranges, and the handlers must keep doing that. Positionals
//! are `Option` for the same reason: the JS prints its own usage line when
//! one is missing (and some commands start a wizard instead).
//!
//! # JS parsing quirks clap does not reproduce on its own
//!
//! The runner ([`crate::run`] and [`crate::clap_failure`]) owns these:
//!
//! 1. **`--help`.** In the JS, `--help` anywhere before `--`, and the bare
//!    `help` command, and no command at all, print the one top-level help
//!    text (`printHelp`), except `cred scrub --help`, which prints
//!    `SCRUB_HELP`. With `--json` it is `{ok:true,data:{help}}`. Clap's
//!    generated help is disabled (`disable_help_flag`,
//!    `disable_help_subcommand`); `--help` is a global flag here and `help`
//!    a command, and the runner prints the JS text. `-h` is not special in
//!    the JS (it is a positional), and is not here either.
//! 2. **Errors.** A clap parse error must become the JS failure envelope
//!    (`{ok:false,error:{message,...}}` under `--json`, `error <message>` on
//!    stderr otherwise) with `EXIT.USAGE`, not clap's own rendering. The
//!    message text differs from the JS in these cases, all of which exit
//!    USAGE in both:
//!    - unknown flags where `knownFlags` refuses them (`session create`,
//!      `session narrow`, `template save`, `approve`): the JS says
//!      `<command> does not take --<flag>; nothing was sent`;
//!    - a value flag given with no value (`--out` alone): the JS stores
//!      `true` and later says `--out needs a value` / `needs a file name`;
//!    - unknown subcommands: `cred frob` is `unknown command "cred"` in the
//!      JS. **Exception:** `mcp <anything>` that is not `url`/`install` runs
//!      the stdio bridge in the JS (extra positionals are ignored); clap
//!      refuses it.
//!    - extra positionals are ignored by the JS and refused by clap.
//!
//!    **Not the same exit code: unknown flags everywhere else.** The JS
//!    parser (`parseArgs`) stores any `--flag` and every other command simply
//!    never reads it, so `agent-vault status --frob` or `deny <id> --route r`
//!    runs and exits as usual, while clap refuses them with USAGE. The CLI
//!    worker must decide how to keep the JS behavior (e.g. pre-strip flags a
//!    command does not declare, or `ignore_errors`); the JS is the contract.
//! 3. **Flag values that look like flags.** The JS takes the next token as a
//!    flag's value only when it does not start with `-`; otherwise the flag
//!    is `true`. So `--reason -x` is a usage error in the JS ("needs a
//!    value"), and clap reports `-x` as an unknown argument. Same exit code.
//! 4. **A boolean flag followed by a word.** The JS gives `--all foo` the
//!    value `foo`, and `booleanFlag` then refuses it ("--all takes no
//!    value"). Clap sets `--all` and treats `foo` as a positional. The CLI
//!    worker should decide whether to pre-scan for this; the JS behavior is
//!    the contract.
//! 5. **Repeated flags.** The JS keeps the last value of a non-repeatable
//!    flag; `args_override_self` (global) does the same here. The repeatable
//!    flags are exactly `--map`, `--route`, `--header`, `--add`
//!    (`REPEATABLE`); they are `Vec<String>`.
//! 6. **Secret flags.** `--value`, `--webhook-url`, `--webhook_url`,
//!    `--recovery-passphrase`, `--recovery_passphrase` on any command are
//!    refused with `secrets are read from the terminal or stdin, never
//!    command-line flags` (USAGE) before the handler runs. They are declared
//!    as hidden global flags ([`SecretFlagTraps`]) so the runner can emit that
//!    exact message instead of an unknown-flag error.
//! 7. **`--json`** is honored anywhere before `--` (global flag), and is a
//!    plain argument after it (`exec ... -- cmd --json`).
//! 8. **`exec`** takes every positional, before or after `--`, as the command
//!    line. Without `--`, the JS still parses later `--flags` as its own
//!    flags; with `trailing_var_arg` clap passes them to the command once the
//!    first positional is seen. The documented form uses `--`.
//! 9. **Approval override spellings.** `approve` accepts several spellings
//!    of one field (`--ttl-minutes`/`--ttl_minutes`, `--spend-usd`/
//!    `--spend_usd`, …) and refuses two of them together with `give only one
//!    of --a, --b; nothing was sent`. They are separate fields here (not
//!    aliases) so the handler can still say that.
//! 10. **`ui --open`** is accepted and ignored (`args.open !== false` is
//!     always true for a parsed flag); only `--no-open` suppresses the
//!     browser.
//! 11. **`listen add --tls`** is either a bare flag or `--tls managed`; both
//!     mean the managed certificate.
//! 12. **The root refusal** (uid 0 without `AGENT_VAULT_ALLOW_ROOT`) happens
//!     before any parsing, so even a malformed command line under sudo gets
//!     the "Do not run agent-vault under sudo" text ([`crate::refuse_root`]).

use clap::{Args, Parser, Subcommand};

/// `agent-vault`: the top level. Ports `main(argv)` and `parseArgs(argv)` in
/// `src/cli/index.js`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "agent-vault",
    about = "agent-vault - a local credential proxy for agents",
    disable_help_flag = true,
    disable_help_subcommand = true,
    disable_version_flag = true,
    args_override_self = true
)]
pub struct Cli {
    /// Print a machine-readable envelope. Ports `JSON_OUT` (`--json`
    /// anywhere before `--`) in `src/cli/index.js`.
    #[arg(long, global = true)]
    pub json: bool,

    /// Print the help text (`printHelp`, or `SCRUB_HELP` for `cred scrub`).
    /// Ports `args.help` in `main` in `src/cli/index.js`.
    #[arg(long, global = true)]
    pub help: bool,

    /// Flags that would carry a secret on argv; always refused.
    #[command(flatten)]
    pub secret_traps: SecretFlagTraps,

    /// The command; none prints the help. Ports the `COMMANDS` dispatch in
    /// `main` in `src/cli/index.js`.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Secret-carrying flags the JS refuses on every command: `['value',
/// 'webhook-url', 'webhook_url', 'recovery-passphrase',
/// 'recovery_passphrase']` in `main` in `src/cli/index.js`. Any of them
/// present is a usage error before the handler runs.
#[derive(Debug, Clone, Default, Args)]
pub struct SecretFlagTraps {
    /// `--value`
    #[arg(long = "value", global = true, hide = true, num_args = 0..=1)]
    pub value: Option<Option<String>>,
    /// `--webhook-url`
    #[arg(long = "webhook-url", global = true, hide = true, num_args = 0..=1)]
    pub webhook_url_dash: Option<Option<String>>,
    /// `--webhook_url`
    #[arg(long = "webhook_url", global = true, hide = true, num_args = 0..=1)]
    pub webhook_url_underscore: Option<Option<String>>,
    /// `--recovery-passphrase`
    #[arg(long = "recovery-passphrase", global = true, hide = true, num_args = 0..=1)]
    pub recovery_passphrase_dash: Option<Option<String>>,
    /// `--recovery_passphrase`
    #[arg(long = "recovery_passphrase", global = true, hide = true, num_args = 0..=1)]
    pub recovery_passphrase_underscore: Option<Option<String>>,
}

impl SecretFlagTraps {
    /// Whether any secret flag was given. Ports the
    /// `Object.hasOwn(args, key)` check in `main` in `src/cli/index.js`.
    pub fn any(&self) -> bool {
        self.value.is_some()
            || self.webhook_url_dash.is_some()
            || self.webhook_url_underscore.is_some()
            || self.recovery_passphrase_dash.is_some()
            || self.recovery_passphrase_underscore.is_some()
    }
}

/// Every command. Ports the keys of `COMMANDS` in `src/cli/index.js`
/// (two-word keys such as `cred:add` are the subcommand enums below).
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Install properly (`--dev` skips the uid boundary). Ports
    /// `COMMANDS.setup` in `src/cli/index.js`.
    Setup(SetupArgs),
    /// Reinstall the daemon from this checkout. Ports `COMMANDS.upgrade` in
    /// `src/cli/index.js`.
    Upgrade(UpgradeArgs),
    /// Run the daemon (gateway + control socket). Ports `COMMANDS.daemon`
    /// in `src/cli/index.js`.
    Daemon(DaemonArgs),
    /// What is running. Ports `COMMANDS.status` in `src/cli/index.js`.
    Status,
    /// What is configured, and what is wrong. Ports `COMMANDS.doctor` in
    /// `src/cli/index.js`.
    Doctor,
    /// The connector profiles. Ports `COMMANDS.profiles` in
    /// `src/cli/index.js`.
    Profiles,
    /// Credential, session, and what to give the agent. Ports
    /// `COMMANDS.quickstart` in `src/cli/index.js` (`quickstart` in
    /// `src/cli/wizards.js`).
    Quickstart,
    /// Credentials. Ports the `cred:*` handlers in `src/cli/index.js` and
    /// `src/cli/control-commands.js`.
    Cred {
        /// The `cred` subcommand.
        #[command(subcommand)]
        command: CredCommand,
    },
    /// Sessions. Ports the `session:*` handlers in `src/cli/index.js` and
    /// `src/cli/control-commands.js`.
    Session {
        /// The `session` subcommand.
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Session templates. Ports the `template:*` handlers in
    /// `src/cli/control-commands.js`.
    Template {
        /// The `template` subcommand.
        #[command(subcommand)]
        command: TemplateCommand,
    },
    /// Placeholders. Ports the `ph:*` handlers in `src/cli/index.js`.
    Ph {
        /// The `ph` subcommand.
        #[command(subcommand)]
        command: PhCommand,
    },
    /// Placeholders for your tools, as an env file or on stdout. Ports
    /// `COMMANDS.env` in `src/cli/index.js`.
    Env(EnvArgs),
    /// Run a command with a scrubbed environment. Ports `COMMANDS.exec` in
    /// `src/cli/index.js`.
    Exec(ExecArgs),
    /// Would this request pass? Nothing is sent. Ports `preflight` in
    /// `src/cli/control-commands.js`.
    Preflight(PreflightArgs),
    /// What is waiting for a decision. Ports `COMMANDS.approvals` in
    /// `src/cli/index.js`.
    Approvals(ApprovalsArgs),
    /// Approve one waiting item, optionally narrowed. Ports
    /// `COMMANDS.approve` (`decide(args, true)`, `approvalOverrides`) in
    /// `src/cli/index.js`.
    Approve(ApproveArgs),
    /// Deny one waiting item. Ports `COMMANDS.deny` (`decide(args, false)`)
    /// in `src/cli/index.js`.
    Deny(DenyArgs),
    /// Tell you the moment something is waiting. Ports `COMMANDS.watch` in
    /// `src/cli/index.js` (`watchApprovals` in `src/cli/watch.js`).
    Watch(WatchArgs),
    /// An optional webhook for the same signal. Ports the `notify:*`
    /// handlers in `src/cli/control-commands.js`.
    Notify {
        /// The `notify` subcommand.
        #[command(subcommand)]
        command: NotifyCommand,
    },
    /// Revoke every session, deny everything waiting. Ports `panic` in
    /// `src/cli/control-commands.js`.
    Panic(PanicArgs),
    /// Rules that end a session after suspicious denials. Ports the
    /// `tripwire:*` handlers in `src/cli/control-commands.js`.
    Tripwire {
        /// The `tripwire` subcommand.
        #[command(subcommand)]
        command: TripwireCommand,
    },
    /// Stop every proxied request. Ports `COMMANDS.lock` in
    /// `src/cli/index.js`.
    Lock,
    /// Resume. Ports `COMMANDS.unlock` in `src/cli/index.js`.
    Unlock,
    /// Make the lock cryptographic, or undo it. Ports the `passphrase:*`
    /// handlers in `src/cli/index.js`.
    Passphrase {
        /// The `passphrase` subcommand.
        #[command(subcommand)]
        command: PassphraseCommand,
    },
    /// The audit log. Ports `audit:tail` in `src/cli/index.js` and the
    /// other `audit:*` handlers in `src/cli/control-commands.js`.
    Audit {
        /// The `audit` subcommand.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Access review across every session. Ports `report` in
    /// `src/cli/control-commands.js`.
    Report(ReportArgs),
    /// Encrypted backups. Ports the `backup:*` handlers in
    /// `src/cli/control-commands.js`.
    Backup {
        /// The `backup` subcommand.
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Extra network listeners. Ports the `listen:*` handlers in
    /// `src/cli/index.js`.
    Listen {
        /// The `listen` subcommand.
        #[command(subcommand)]
        command: ListenCommand,
    },
    /// The loopback MCP listener's certificate. Ports the `tls:*` handlers
    /// in `src/cli/index.js`.
    Tls {
        /// The `tls` subcommand.
        #[command(subcommand)]
        command: TlsCommand,
    },
    /// Open the web UI (single-use link, no secrets rendered). Ports
    /// `COMMANDS.ui` in `src/cli/index.js`.
    Ui(UiArgs),
    /// The MCP bridge (stdio with no subcommand), its URL, or installing it
    /// into an agent's config. Ports `COMMANDS.mcp`, `mcp:url` and
    /// `mcp:install` in `src/cli/index.js`.
    Mcp(McpArgs),
    /// Open the docs, written against this install. Ports `COMMANDS.docs` in
    /// `src/cli/index.js`.
    Docs(DocsArgs),
    /// Convert a JSON vault (`vault.json`) into the SQLite one. New in the
    /// Rust port (PLAN.md, "`agent-vault migrate`"); no JS handler.
    Migrate(MigrateArgs),
    /// Print the help text. Ports `first === 'help'` in `main` in
    /// `src/cli/index.js`; any further words are ignored.
    Help {
        /// Ignored, as in the JS.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        rest: Vec<String>,
    },
}

/// `setup [--dev] [--print-only] [--port N] [--passphrase]`. Ports the flags
/// read by `COMMANDS.setup` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct SetupArgs {
    /// Dev vault in the home directory; no uid boundary.
    #[arg(long)]
    pub dev: bool,
    /// Print the privileged command instead of running it.
    #[arg(long = "print-only")]
    pub print_only: bool,
    /// Gateway port for the install (1-65535).
    #[arg(long)]
    pub port: Option<String>,
    /// Create the dev vault with a passphrase (read from the terminal).
    #[arg(long)]
    pub passphrase: bool,
}

/// `upgrade [--print-only]`. Ports the flags read by `COMMANDS.upgrade` in
/// `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct UpgradeArgs {
    /// Print the command instead of running it.
    #[arg(long = "print-only")]
    pub print_only: bool,
}

/// `daemon [--port N] [--passphrase]`. Ports the flags read by
/// `COMMANDS.daemon` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct DaemonArgs {
    /// Gateway port (0-65535); default `AGENT_VAULT_PORT` or 7411.
    #[arg(long)]
    pub port: Option<String>,
    /// Unlock with a passphrase read from the terminal.
    #[arg(long)]
    pub passphrase: bool,
}

/// `cred ...`. Ports the `cred:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum CredCommand {
    /// Store a credential; no slug and a terminal start the wizard. Ports
    /// `COMMANDS['cred:add']` in `src/cli/index.js`.
    Add(CredAddArgs),
    /// List credentials. Ports `COMMANDS['cred:list']` in
    /// `src/cli/index.js`.
    List,
    /// Delete a credential. Ports `COMMANDS['cred:rm']` in
    /// `src/cli/index.js`.
    Rm(SlugArg),
    /// Replace the value; sessions keep working. Ports `'cred:rotate'` in
    /// `src/cli/control-commands.js`.
    Rotate(CredRotateArgs),
    /// Run the connector's read-only probe. Ports `'cred:test'` in
    /// `src/cli/control-commands.js`.
    Test(CredTestArgs),
    /// Record when the token expires. Ports `'cred:expiry'` in
    /// `src/cli/control-commands.js`.
    Expiry(CredExpiryArgs),
    /// Extra token shapes to redact from responses. Ports `'cred:scrub'` in
    /// `src/cli/control-commands.js`.
    Scrub(CredScrubArgs),
    /// Refuse any TLS key you did not pin. Ports `'cred:pin'` in
    /// `src/cli/control-commands.js`.
    Pin(CredPinArgs),
    /// Stop all use at once. Ports `'cred:quarantine'` in
    /// `src/cli/control-commands.js`.
    Quarantine(CredQuarantineArgs),
    /// Undo a quarantine. Ports `'cred:release'` in
    /// `src/cli/control-commands.js`.
    Release(SlugArg),
}

/// A single optional `<slug>` positional (`args._[0]`).
#[derive(Debug, Clone, Default, Args)]
pub struct SlugArg {
    /// The credential slug.
    pub slug: Option<String>,
}

/// `cred add [<slug>] [--kind K] [--host H] [--scheme S] [--expires D]`.
/// Ports the flags read by `COMMANDS['cred:add']` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredAddArgs {
    /// The new credential's slug; absent starts the wizard on a terminal.
    pub slug: Option<String>,
    /// Connector kind (default `http`).
    #[arg(long)]
    pub kind: Option<String>,
    /// Upstream host.
    #[arg(long)]
    pub host: Option<String>,
    /// Auth scheme.
    #[arg(long)]
    pub scheme: Option<String>,
    /// `YYYY-MM-DD` or `none`.
    #[arg(long)]
    pub expires: Option<String>,
}

/// `cred rotate <slug> [--field F] [--revoke] [--retire-hours N]
/// [--expires D]`. Ports the flags read by `'cred:rotate'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredRotateArgs {
    /// The credential slug.
    pub slug: Option<String>,
    /// Which field to rotate.
    #[arg(long)]
    pub field: Option<String>,
    /// Revoke grants instead of keeping them.
    #[arg(long)]
    pub revoke: bool,
    /// Hours the old value stays scrubbed (0-168).
    #[arg(long = "retire-hours")]
    pub retire_hours: Option<String>,
    /// New expiry, `YYYY-MM-DD` or `none`.
    #[arg(long)]
    pub expires: Option<String>,
}

/// `cred test [<slug> | --all]`. Ports the flags read by `'cred:test'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredTestArgs {
    /// The credential slug (exactly one of this and `--all`).
    pub slug: Option<String>,
    /// Probe every credential.
    #[arg(long)]
    pub all: bool,
}

/// `cred expiry <slug> <YYYY-MM-DD|none>`. Ports the positionals read by
/// `'cred:expiry'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredExpiryArgs {
    /// The credential slug.
    pub slug: Option<String>,
    /// `YYYY-MM-DD` or `none`.
    pub date: Option<String>,
}

/// `cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]`. Ports the
/// flags read by `'cred:scrub'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredScrubArgs {
    /// The credential slug.
    pub slug: Option<String>,
    /// Pattern to add (repeatable; `REPEATABLE` has `add`).
    #[arg(long)]
    pub add: Vec<String>,
    /// Sample text to test the pattern on (needs `--add`).
    #[arg(long)]
    pub sample: Option<String>,
    /// Pattern id to remove.
    #[arg(long)]
    pub rm: Option<String>,
}

/// `cred pin <slug> --host H [--add sha256/...] [--rm sha256/... | --clear]
/// [--live]`. Ports the flags read by `'cred:pin'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredPinArgs {
    /// The credential slug.
    pub slug: Option<String>,
    /// The upstream host the pins are for.
    #[arg(long)]
    pub host: Option<String>,
    /// Pin to add (repeatable).
    #[arg(long)]
    pub add: Vec<String>,
    /// Pin to remove.
    #[arg(long)]
    pub rm: Option<String>,
    /// Remove every pin for the host.
    #[arg(long)]
    pub clear: bool,
    /// Fetch and show the host's current chain first.
    #[arg(long)]
    pub live: bool,
}

/// `cred quarantine <slug> [--reason T]`. Ports the flags read by
/// `'cred:quarantine'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct CredQuarantineArgs {
    /// The credential slug.
    pub slug: Option<String>,
    /// Why, for the audit log.
    #[arg(long)]
    pub reason: Option<String>,
}

/// Every flag `grantInput` reads. Ports `GRANT_FLAGS` and `grantInput(args)`
/// in `src/cli/policy-input.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct GrantFlags {
    /// Comma list of hosts.
    #[arg(long)]
    pub hosts: Option<String>,
    /// Comma list of methods.
    #[arg(long)]
    pub methods: Option<String>,
    /// Comma list of path globs.
    #[arg(long)]
    pub paths: Option<String>,
    /// Comma list of denied path globs.
    #[arg(long = "deny-paths")]
    pub deny_paths: Option<String>,
    /// `each`, `on-write`, `first-use` or `auto`.
    #[arg(long)]
    pub approval: Option<String>,
    /// Request budget (>= 0).
    #[arg(long)]
    pub budget: Option<String>,
    /// Placeholder uses (>= 1).
    #[arg(long)]
    pub uses: Option<String>,
    /// Max concurrent requests (>= 1).
    #[arg(long)]
    pub concurrency: Option<String>,
    /// Redirects followed (0-5).
    #[arg(long)]
    pub redirects: Option<String>,
    /// Model-token spend limit.
    #[arg(long = "spend-tokens")]
    pub spend_tokens: Option<String>,
    /// Grant lifetime in minutes (>= 1).
    #[arg(long = "grant-ttl")]
    pub grant_ttl: Option<String>,
    /// `N/s|sec|second|m|min|minute|h|hour`.
    #[arg(long)]
    pub rate: Option<String>,
    /// `N/h|hour|d|day`.
    #[arg(long)]
    pub quota: Option<String>,
    /// USD spend limit, at most 6 decimals.
    #[arg(long = "spend-usd")]
    pub spend_usd: Option<String>,
    /// `METHODS:/path` (repeatable).
    #[arg(long)]
    pub route: Vec<String>,
    /// JSON payload rules file.
    #[arg(long = "payload-file")]
    pub payload_file: Option<String>,
    /// `query`, `mutation`, `subscription` (comma list).
    #[arg(long)]
    pub graphql: Option<String>,
}

/// The flags `sessionInput` reads: [`GrantFlags`] plus `label`, `ttl`,
/// `infinite`, `cred`, `grants-file`, `template`. Ports
/// `sessionInput(args)` in `src/cli/policy-input.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct SessionSpecArgs {
    /// The per-grant limits.
    #[command(flatten)]
    pub grant: GrantFlags,
    /// Session label.
    #[arg(long)]
    pub label: Option<String>,
    /// Session lifetime in hours (> 0, fractional allowed).
    #[arg(long)]
    pub ttl: Option<String>,
    /// No expiry (asks for your passphrase every time).
    #[arg(long)]
    pub infinite: bool,
    /// Comma list of credential slugs.
    #[arg(long)]
    pub cred: Option<String>,
    /// JSON array of grant specs.
    #[arg(long = "grants-file")]
    pub grants_file: Option<String>,
    /// Template name.
    #[arg(long)]
    pub template: Option<String>,
}

/// `session ...`. Ports the `session:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum SessionCommand {
    /// Create a session; no flags and a terminal start the wizard. Ports
    /// `COMMANDS['session:create']` in `src/cli/index.js`.
    Create(SessionSpecArgs),
    /// List sessions. Ports `COMMANDS['session:list']` in
    /// `src/cli/index.js`.
    List,
    /// Revoke a session (default: the current one). Ports
    /// `COMMANDS['session:revoke']` in `src/cli/index.js`.
    Revoke(SidArg),
    /// Tighten a live session; it can never widen. Ports `'session:narrow'`
    /// in `src/cli/control-commands.js`.
    Narrow(SessionNarrowArgs),
    /// What it may do, and what it did. Ports `'session:show'` in
    /// `src/cli/control-commands.js`.
    Show(SessionShowArgs),
}

/// A single optional `<sid>` positional; absent means the session in the
/// client state file.
#[derive(Debug, Clone, Default, Args)]
pub struct SidArg {
    /// Session id.
    pub sid: Option<String>,
}

/// `session narrow [<sid>] [--cred S] [any limit] [--ttl MIN]`. Ports the
/// flags read by `'session:narrow'` in `src/cli/control-commands.js`
/// (`knownFlags(args, [...GRANT_FLAGS, 'cred', 'ttl'])`; `--uses` is
/// accepted by the parser and refused by the handler with `session narrow
/// cannot change --uses; nothing was sent`).
#[derive(Debug, Clone, Default, Args)]
pub struct SessionNarrowArgs {
    /// Session id.
    pub sid: Option<String>,
    /// The limits to tighten.
    #[command(flatten)]
    pub grant: GrantFlags,
    /// Only this credential's grant.
    #[arg(long)]
    pub cred: Option<String>,
    /// New session lifetime in minutes (>= 1).
    #[arg(long)]
    pub ttl: Option<String>,
}

/// `session show [<sid>] [--markdown]`. Ports the flags read by
/// `'session:show'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct SessionShowArgs {
    /// Session id.
    pub sid: Option<String>,
    /// Markdown output.
    #[arg(long)]
    pub markdown: bool,
}

/// `template ...`. Ports the `template:*` keys of `controlCommands`.
#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
pub enum TemplateCommand {
    /// Save a template from session flags or a file. Ports
    /// `'template:save'` in `src/cli/control-commands.js`.
    Save(TemplateSaveArgs),
    /// List templates. Ports `'template:list'` in
    /// `src/cli/control-commands.js`.
    List,
    /// Show one template. Ports `'template:show'` in
    /// `src/cli/control-commands.js`.
    Show(NameArg),
    /// Delete one template. Ports `'template:rm'` in
    /// `src/cli/control-commands.js`.
    Rm(NameArg),
}

/// A single optional `<name>` positional.
#[derive(Debug, Clone, Default, Args)]
pub struct NameArg {
    /// Template name.
    pub name: Option<String>,
}

/// `template save <name> (--from-file F | [session flags])`. Ports the
/// flags read by `'template:save'` in `src/cli/control-commands.js`
/// (`--from-file` cannot be combined with session flags).
#[derive(Debug, Clone, Default, Args)]
pub struct TemplateSaveArgs {
    /// Template name.
    pub name: Option<String>,
    /// A JSON session spec.
    #[arg(long = "from-file")]
    pub from_file: Option<String>,
    /// The session spec as flags.
    #[command(flatten)]
    pub spec: SessionSpecArgs,
}

/// `ph ...`. Ports the `ph:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum PhCommand {
    /// Issue a placeholder. Ports `COMMANDS['ph:next']` in
    /// `src/cli/index.js`.
    Next(PhNextArgs),
    /// Validate one (read from the terminal when absent). Ports
    /// `COMMANDS['ph:check']` in `src/cli/index.js`.
    Check(PhCheckArgs),
    /// Print the scanner regex. Ports `COMMANDS['ph:pattern']` in
    /// `src/cli/index.js`.
    Pattern,
}

/// `ph next <cred> [--uses N] [--session SID]`. Ports the flags read by
/// `COMMANDS['ph:next']` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct PhNextArgs {
    /// Credential slug.
    pub cred: Option<String>,
    /// Uses (>= 1).
    #[arg(long)]
    pub uses: Option<String>,
    /// Session id (default: the current one).
    #[arg(long)]
    pub session: Option<String>,
}

/// `ph check [<placeholder>]`. Ports `COMMANDS['ph:check']` in
/// `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct PhCheckArgs {
    /// The placeholder text.
    pub placeholder: Option<String>,
}

/// `env [--out F [--force]] [--map NAME=<slug>[:base_url]]... [--map-file F]
/// [--profile-vars] [--format dotenv|shell] [--session S] [--uses N]`. Ports
/// the flags read by `COMMANDS.env`, `wantsMapping`, `parseMappings` and
/// `resolveMappings` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvArgs {
    /// Write to this file (0600, never replaced without `--force`).
    #[arg(long)]
    pub out: Option<String>,
    /// Replace an existing `--out`.
    #[arg(long)]
    pub force: bool,
    /// `NAME=SPEC` (repeatable).
    #[arg(long)]
    pub map: Vec<String>,
    /// A file of `NAME=SPEC` lines.
    #[arg(long = "map-file")]
    pub map_file: Option<String>,
    /// Map each profile's conventional variable names.
    #[arg(long = "profile-vars")]
    pub profile_vars: bool,
    /// `dotenv` (default) or `shell`.
    #[arg(long)]
    pub format: Option<String>,
    /// Session id (default: the current one). A bare `--session` is a usage
    /// error, as in `resolveMappings` (`src/cli/index.js`).
    #[arg(long)]
    pub session: Option<String>,
    /// Uses per minted placeholder (a whole number, 1 or more). A bare
    /// `--uses` is a usage error, as in `resolveMappings`.
    #[arg(long)]
    pub uses: Option<String>,
}

/// `exec [--map NAME=<slug>]... [--map-file F] [--profile-vars] [--session S]
/// [--uses N] -- <command>`. Ports the flags read by `COMMANDS.exec` and
/// `resolveMappings` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ExecArgs {
    /// `NAME=SPEC` (repeatable).
    #[arg(long)]
    pub map: Vec<String>,
    /// A file of `NAME=SPEC` lines.
    #[arg(long = "map-file")]
    pub map_file: Option<String>,
    /// Map each profile's conventional variable names.
    #[arg(long = "profile-vars")]
    pub profile_vars: bool,
    /// Session id (default: the current one). A bare `--session` is a usage
    /// error, as in `resolveMappings` (`src/cli/index.js`).
    #[arg(long)]
    pub session: Option<String>,
    /// Uses per minted placeholder (a whole number, 1 or more). A bare
    /// `--uses` is a usage error, as in `resolveMappings`.
    #[arg(long)]
    pub uses: Option<String>,
    /// The command line to run.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// `preflight --cred S --method M --path P [--body-file F] [--header 'K: V']...
/// [--query Q]`. Ports the flags read by `preflight` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct PreflightArgs {
    /// Credential slug.
    #[arg(long)]
    pub cred: Option<String>,
    /// HTTP method.
    #[arg(long)]
    pub method: Option<String>,
    /// Upstream path, beginning `/`.
    #[arg(long)]
    pub path: Option<String>,
    /// Body to judge.
    #[arg(long = "body-file")]
    pub body_file: Option<String>,
    /// `K: V` (repeatable).
    #[arg(long)]
    pub header: Vec<String>,
    /// Query string.
    #[arg(long)]
    pub query: Option<String>,
}

/// `approvals [--show <id>]`. Ports the flags read by `COMMANDS.approvals`
/// in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ApprovalsArgs {
    /// Show one item in full.
    #[arg(long)]
    pub show: Option<String>,
}

/// `approve <id> [narrowing]`. Every spelling in `APPROVAL_FLAGS`
/// (`src/cli/policy-input.js`) is its own field, so the handler can refuse
/// two spellings of one field together, as the JS does. Ports the flags read
/// by `COMMANDS.approve` / `approvalOverrides` in `src/cli/index.js` and
/// `src/cli/policy-input.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ApproveArgs {
    /// The waiting item's id.
    pub id: Option<String>,
    /// `--hosts`
    #[arg(long)]
    pub hosts: Option<String>,
    /// `--methods`
    #[arg(long)]
    pub methods: Option<String>,
    /// `--paths`
    #[arg(long)]
    pub paths: Option<String>,
    /// `--deny-paths`
    #[arg(long = "deny-paths")]
    pub deny_paths: Option<String>,
    /// `--approval` (owner-only)
    #[arg(long)]
    pub approval: Option<String>,
    /// `--infinite` (owner-only)
    #[arg(long)]
    pub infinite: bool,
    /// `--budget`
    #[arg(long)]
    pub budget: Option<String>,
    /// `--uses`
    #[arg(long)]
    pub uses: Option<String>,
    /// `--ttl_minutes`
    #[arg(long = "ttl_minutes")]
    pub ttl_minutes_underscore: Option<String>,
    /// `--ttl-minutes`
    #[arg(long = "ttl-minutes")]
    pub ttl_minutes: Option<String>,
    /// `--concurrency`
    #[arg(long)]
    pub concurrency: Option<String>,
    /// `--max_concurrent`
    #[arg(long = "max_concurrent")]
    pub max_concurrent: Option<String>,
    /// `--redirects`
    #[arg(long)]
    pub redirects: Option<String>,
    /// `--spend-tokens`
    #[arg(long = "spend-tokens")]
    pub spend_tokens: Option<String>,
    /// `--spend_tokens`
    #[arg(long = "spend_tokens")]
    pub spend_tokens_underscore: Option<String>,
    /// `--spend-usd`
    #[arg(long = "spend-usd")]
    pub spend_usd: Option<String>,
    /// `--spend_usd`
    #[arg(long = "spend_usd")]
    pub spend_usd_underscore: Option<String>,
    /// `--grant-ttl`
    #[arg(long = "grant-ttl")]
    pub grant_ttl: Option<String>,
    /// `--grant_ttl`
    #[arg(long = "grant_ttl")]
    pub grant_ttl_underscore: Option<String>,
    /// `--grant_ttl_minutes`
    #[arg(long = "grant_ttl_minutes")]
    pub grant_ttl_minutes: Option<String>,
    /// `--rate`
    #[arg(long)]
    pub rate: Option<String>,
    /// `--quota`
    #[arg(long)]
    pub quota: Option<String>,
    /// `--route` (repeatable)
    #[arg(long)]
    pub route: Vec<String>,
    /// `--routes`
    #[arg(long)]
    pub routes: Option<String>,
    /// `--payload` (JSON text)
    #[arg(long)]
    pub payload: Option<String>,
    /// `--payload-file`
    #[arg(long = "payload-file")]
    pub payload_file: Option<String>,
    /// `--graphql`
    #[arg(long)]
    pub graphql: Option<String>,
}

/// `deny <id>`. Ports `COMMANDS.deny` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct DenyArgs {
    /// The waiting item's id.
    pub id: Option<String>,
}

/// `watch [--no-notify] [--open] [--quiet]`. Ports the flags read by
/// `COMMANDS.watch` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct WatchArgs {
    /// No desktop notification.
    #[arg(long = "no-notify")]
    pub no_notify: bool,
    /// Open the UI on the first item.
    #[arg(long)]
    pub open: bool,
    /// Less output.
    #[arg(long)]
    pub quiet: bool,
}

/// `notify ...`. Ports the `notify:*` keys of `controlCommands`.
#[derive(Debug, Clone, Subcommand)]
pub enum NotifyCommand {
    /// Set the webhook (URL read from the terminal). Ports `'notify:set'`
    /// in `src/cli/control-commands.js`.
    Set(NotifySetArgs),
    /// Show the webhook. Ports `'notify:show'` in
    /// `src/cli/control-commands.js`.
    Show,
    /// Remove the webhook. Ports `'notify:off'` in
    /// `src/cli/control-commands.js`.
    Off,
    /// Send a test event. Ports `'notify:test'` in
    /// `src/cli/control-commands.js`.
    Test,
}

/// `notify set [--detail minimal|headline]`. Ports the flags read by
/// `'notify:set'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct NotifySetArgs {
    /// `minimal` (default) or `headline`.
    #[arg(long)]
    pub detail: Option<String>,
}

/// `panic [--lock] [--reason T]`. Ports the flags read by `panic` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct PanicArgs {
    /// Lock the vault too.
    #[arg(long)]
    pub lock: bool,
    /// Why, for the audit log.
    #[arg(long)]
    pub reason: Option<String>,
}

/// `tripwire ...`. Ports the `tripwire:*` keys of `controlCommands`.
#[derive(Debug, Clone, Subcommand)]
pub enum TripwireCommand {
    /// Show the rules. Ports `'tripwire:show'` in
    /// `src/cli/control-commands.js`.
    Show,
    /// Turn tripwires on. Ports `'tripwire:on'` in
    /// `src/cli/control-commands.js`.
    On,
    /// Turn tripwires off. Ports `'tripwire:off'` in
    /// `src/cli/control-commands.js`.
    Off,
    /// Add or replace one rule. Ports `'tripwire:set'` in
    /// `src/cli/control-commands.js`.
    Set(TripwireSetArgs),
}

/// `tripwire set --rule ID --window 10m --action A --threshold N (--codes
/// C,... | --rule-prefix P)`. Ports the flags read by `'tripwire:set'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct TripwireSetArgs {
    /// Rule id.
    #[arg(long)]
    pub rule: Option<String>,
    /// `<n>(s|m|h|d)`, 10 s to 1 day.
    #[arg(long)]
    pub window: Option<String>,
    /// `revoke_session`, `quarantine_credential` or `panic`.
    #[arg(long)]
    pub action: Option<String>,
    /// Denials that trip it (1-1000).
    #[arg(long)]
    pub threshold: Option<String>,
    /// Comma list of `AV_*` codes.
    #[arg(long)]
    pub codes: Option<String>,
    /// Denial rule-name prefix.
    #[arg(long = "rule-prefix")]
    pub rule_prefix: Option<String>,
}

/// `passphrase ...`. Ports the `passphrase:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum PassphraseCommand {
    /// Set or change it. Ports `COMMANDS['passphrase:set']` in
    /// `src/cli/index.js`.
    Set,
    /// Remove it. Ports `COMMANDS['passphrase:remove']` in
    /// `src/cli/index.js`.
    Remove,
}

/// `audit ...`. Ports the `audit:*` keys of `COMMANDS` and
/// `controlCommands`.
#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// The last records. Ports `COMMANDS['audit:tail']` in
    /// `src/cli/index.js`.
    Tail(AuditTailArgs),
    /// Verify the chain, and optionally a witness file. Ports
    /// `'audit:verify'` in `src/cli/control-commands.js`.
    Verify(AuditVerifyArgs),
    /// Export records as JSONL. Ports `'audit:export'` in
    /// `src/cli/control-commands.js`.
    Export(AuditExportArgs),
    /// Append a checkpoint to a witness file. Ports `'audit:witness'` in
    /// `src/cli/control-commands.js`.
    Witness(AuditWitnessArgs),
}

/// `audit tail [--limit N]`. Ports the flags read by `'audit:tail'` in
/// `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct AuditTailArgs {
    /// Records (>= 1; default 20).
    #[arg(long)]
    pub limit: Option<String>,
}

/// `audit verify [--witness F]`. Ports the flags read by `'audit:verify'`
/// in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct AuditVerifyArgs {
    /// A witness JSONL file.
    #[arg(long)]
    pub witness: Option<String>,
}

/// `audit export [--since-seq N] [--out F [--force]] [--follow]`. Ports the
/// flags read by `'audit:export'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct AuditExportArgs {
    /// Start after this sequence number.
    #[arg(long = "since-seq")]
    pub since_seq: Option<String>,
    /// Write to this file.
    #[arg(long)]
    pub out: Option<String>,
    /// Keep following until SIGINT.
    #[arg(long)]
    pub follow: bool,
    /// Replace an existing `--out`.
    #[arg(long)]
    pub force: bool,
}

/// `audit witness [--out F]`. Ports the flags read by `'audit:witness'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct AuditWitnessArgs {
    /// Witness file (default `<state dir>/witness.jsonl`).
    #[arg(long)]
    pub out: Option<String>,
}

/// `report [--since 7d] [--markdown]`. Ports the flags read by `report` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ReportArgs {
    /// Window (default `7d`).
    #[arg(long)]
    pub since: Option<String>,
    /// Markdown output.
    #[arg(long)]
    pub markdown: bool,
}

/// `backup ...`. Ports the `backup:*` keys of `controlCommands`.
#[derive(Debug, Clone, Subcommand)]
pub enum BackupCommand {
    /// Write an encrypted backup. Ports `'backup:export'` in
    /// `src/cli/control-commands.js`.
    Export(BackupExportArgs),
    /// List what a backup holds. Ports `'backup:inspect'` in
    /// `src/cli/control-commands.js`.
    Inspect(BackupFileArg),
    /// Restore a backup. Ports `'backup:restore'` in
    /// `src/cli/control-commands.js`.
    Restore(BackupRestoreArgs),
}

/// `backup export --out F [--force]`. Ports the flags read by
/// `'backup:export'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct BackupExportArgs {
    /// Backup file.
    #[arg(long)]
    pub out: Option<String>,
    /// Replace an existing file.
    #[arg(long)]
    pub force: bool,
}

/// `backup inspect <file>`. Ports `'backup:inspect'` in
/// `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct BackupFileArg {
    /// Backup file.
    pub file: Option<String>,
}

/// `backup restore <file> [--on-conflict skip|rename|fail]`. Ports the flags
/// read by `'backup:restore'` in `src/cli/control-commands.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct BackupRestoreArgs {
    /// Backup file.
    pub file: Option<String>,
    /// `skip` (default), `rename` or `fail`.
    #[arg(long = "on-conflict")]
    pub on_conflict: Option<String>,
}

/// `listen ...`. Ports the `listen:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum ListenCommand {
    /// Add a listener. Ports `COMMANDS['listen:add']` in
    /// `src/cli/index.js`.
    Add(ListenAddArgs),
    /// List listeners. Ports `COMMANDS['listen:list']` in
    /// `src/cli/index.js`.
    List,
    /// Remove a listener. Ports `COMMANDS['listen:rm']` in
    /// `src/cli/index.js`.
    Rm(ListenIdArg),
}

/// `listen add <id> --address <iface:port> [--surfaces gateway,mcp]
/// [--advertise A,...] [--allow-cidr C,...] [--tls [managed] | --tls-cert F
/// --tls-key F]`. Ports the flags read by `COMMANDS['listen:add']` in
/// `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ListenAddArgs {
    /// Listener id.
    pub id: Option<String>,
    /// `iface:port`, `ip:port` or `[v6]:port`.
    #[arg(long)]
    pub address: Option<String>,
    /// Comma list (default `gateway,mcp`).
    #[arg(long)]
    pub surfaces: Option<String>,
    /// Comma list of advertised URLs.
    #[arg(long)]
    pub advertise: Option<String>,
    /// Comma list of CIDR blocks.
    #[arg(long = "allow-cidr")]
    pub allow_cidr: Option<String>,
    /// The managed certificate: bare `--tls` or `--tls managed`.
    #[arg(long, num_args = 0..=1)]
    pub tls: Option<Option<String>>,
    /// Certificate file (with `--tls-key`).
    #[arg(long = "tls-cert")]
    pub tls_cert: Option<String>,
    /// Key file (with `--tls-cert`).
    #[arg(long = "tls-key")]
    pub tls_key: Option<String>,
}

/// `listen rm <id>`. Ports `COMMANDS['listen:rm']` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct ListenIdArg {
    /// Listener id.
    pub id: Option<String>,
}

/// `tls ...`. Ports the `tls:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum TlsCommand {
    /// Certificate for the loopback MCP listener. Ports
    /// `COMMANDS['tls:setup']` in `src/cli/index.js`.
    Setup(TlsSetupArgs),
    /// Fingerprint and expiry. Ports `COMMANDS['tls:status']` in
    /// `src/cli/index.js`.
    Status,
}

/// `tls setup [--port 7443] [--force]`. Ports the flags read by
/// `COMMANDS['tls:setup']` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct TlsSetupArgs {
    /// Listener port (1-65535; default 7443).
    #[arg(long)]
    pub port: Option<String>,
    /// Regenerate the certificate.
    #[arg(long)]
    pub force: bool,
}

/// `ui [--port N] [--no-open] [--idle 30] [--allow-origin]`. Ports the flags
/// read by `COMMANDS.ui` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct UiArgs {
    /// Port (0-65535; default the daemon's trusted UI port).
    #[arg(long)]
    pub port: Option<String>,
    /// Do not open a browser.
    #[arg(long = "no-open")]
    pub no_open: bool,
    /// Accepted and ignored, as in the JS (quirk 10 above).
    #[arg(long, hide = true)]
    pub open: bool,
    /// Idle minutes before exit (>= 1, fractional allowed; default 30).
    #[arg(long)]
    pub idle: Option<String>,
    /// Trust this UI's origin for WebAuthn (asks for your passphrase).
    #[arg(long = "allow-origin")]
    pub allow_origin: bool,
}

/// `mcp [url | install ...]`. Ports `COMMANDS.mcp` (no subcommand: the stdio
/// bridge) in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct McpArgs {
    /// `url` or `install`; none runs the stdio bridge.
    #[command(subcommand)]
    pub command: Option<McpCommand>,
}

/// `mcp ...`. Ports the `mcp:*` keys of `COMMANDS`.
#[derive(Debug, Clone, Subcommand)]
pub enum McpCommand {
    /// The Streamable HTTP endpoint and header. Ports `COMMANDS['mcp:url']`
    /// in `src/cli/index.js`.
    Url,
    /// Merge the server into an agent's config. Ports
    /// `COMMANDS['mcp:install']` in `src/cli/index.js`.
    Install(McpInstallArgs),
}

/// `mcp install [<agent>] [--agent claude-code|cursor|gemini|codex]
/// [--scope project|user] [--transport stdio|http] [--tls] [--port N]
/// [--name N] [--print]`. Ports the flags read by `COMMANDS['mcp:install']`
/// in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct McpInstallArgs {
    /// The agent, positionally (`--agent` wins).
    pub agent_positional: Option<String>,
    /// `claude-code`, `cursor`, `gemini` or `codex`.
    #[arg(long)]
    pub agent: Option<String>,
    /// `project` or `user` (default per agent).
    #[arg(long)]
    pub scope: Option<String>,
    /// `stdio` (default) or `http`.
    #[arg(long)]
    pub transport: Option<String>,
    /// Server name (default `agent-vault`).
    #[arg(long)]
    pub name: Option<String>,
    /// HTTPS listener (required for `--transport http`).
    #[arg(long)]
    pub tls: bool,
    /// HTTPS port (1-65535; default 7443).
    #[arg(long)]
    pub port: Option<String>,
    /// Print the block instead of writing it.
    #[arg(long)]
    pub print: bool,
}

/// `docs [section]` plus the `ui` flags (it opens the UI). Ports the
/// arguments read by `COMMANDS.docs` in `src/cli/index.js`.
#[derive(Debug, Clone, Default, Args)]
pub struct DocsArgs {
    /// `how`, `start`, `connect`, `models`, `locking`, `safety`, `refused`
    /// or `commands`.
    pub section: Option<String>,
    /// The UI flags, passed through to `ui`.
    #[command(flatten)]
    pub ui: UiArgs,
}

/// `migrate [--from <dir>] [--to <dir>] [--dry-run] [--json]`. New in the
/// Rust port (PLAN.md, "`agent-vault migrate`"); `--json` is the global
/// flag.
#[derive(Debug, Clone, Default, Args)]
pub struct MigrateArgs {
    /// The JSON vault dir (default: the installed vault dir).
    #[arg(long)]
    pub from: Option<String>,
    /// Where `vault.db` goes (default: the same dir).
    #[arg(long)]
    pub to: Option<String>,
    /// Steps 1-7 in memory; print the report; write nothing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}
