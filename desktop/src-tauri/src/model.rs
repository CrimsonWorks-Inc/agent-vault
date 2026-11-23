//! What the menu shows, worked out from the CLI's JSON. Pure: no I/O, no Tauri,
//! so every rule here is covered by the tests at the bottom.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// Agents the vault can write itself into, as `mcp install --agent` names them.
pub const AGENTS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code"),
    ("codex", "Codex"),
    ("cursor", "Cursor"),
    ("gemini", "Gemini CLI"),
];

/// Why there is no vault to talk to.
#[derive(Debug, Clone, PartialEq)]
pub enum Missing {
    /// Nothing installed: the companion can start the installer.
    NotInstalled,
    /// Something is there but it is not a root-owned install; never run it.
    Untrusted(String),
    /// The vault does not run on this operating system.
    Unsupported,
}

/// How far the companion got in reaching the vault.
#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    /// Nothing checked yet.
    Loading,
    /// No trustworthy agent-vault install on this computer.
    Missing(Missing),
    /// Installed, but the daemon did not answer.
    Down(String),
    /// Answering.
    Up(Status),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub version: String,
    pub locked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    pub label: String,
    pub creds: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub infinite: bool,
    /// One plain sentence on what agents may do with it.
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub id: String,
    pub kind: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Health {
    Ok,
    Problem,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    pub slug: String,
    pub service: String,
    pub health: Health,
    pub stopped: bool,
    pub expiring: bool,
}

/// What `doctor` says about the human factor. `None` means not known.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Setup {
    pub passphrase: Option<bool>,
    pub touch_id: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentLink {
    pub id: String,
    pub name: String,
    pub connected: bool,
}

/// The user's choices, kept between launches.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prefs {
    pub notifications: bool,
    pub autostart: bool,
    /// The first-run welcome has been shown.
    pub welcomed: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            notifications: true,
            autostart: false,
            welcomed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub reach: Reach,
    pub sessions: Vec<Session>,
    pub pending: Vec<Pending>,
    pub templates: Vec<String>,
    pub keys: Vec<Key>,
    pub setup: Setup,
    /// Agents found on this computer, connected or not.
    pub agents: Vec<AgentLink>,
    /// Lists the CLI failed to return. Shown as "couldn't read", never as an
    /// empty list: "no open sessions" must mean exactly that.
    pub unread: Unread,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Unread {
    pub sessions: bool,
    pub pending: bool,
    pub templates: bool,
    pub keys: bool,
}

impl Snapshot {
    pub fn loading() -> Self {
        Self::only(Reach::Loading)
    }

    pub fn only(reach: Reach) -> Self {
        Snapshot {
            reach,
            sessions: Vec::new(),
            pending: Vec::new(),
            templates: Vec::new(),
            keys: Vec::new(),
            setup: Setup::default(),
            agents: Vec::new(),
            unread: Unread::default(),
        }
    }

    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }

    pub fn in_use(&self, slug: &str) -> bool {
        self.sessions
            .iter()
            .any(|s| s.creds.iter().any(|c| c == slug))
    }
}

/// Everything a menu click can ask for.
///
/// There is deliberately no variant that approves, denies, creates a session,
/// saves a template, adds or releases a credential, or unlocks: those widen
/// access and need the human's proof. The `…InUi` variants only open the page
/// of the vault's web UI where that proof is given, and the two `…InTerminal`
/// variants open Terminal on a fixed command the human then completes.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    ReviewInUi(String),
    StartInUi(String),
    NewSessionInUi,
    AddKeyInUi,
    ReleaseKeyInUi,
    TouchIdInUi,
    OpenUi,
    UnlockInUi,
    Revoke(String),
    StopKey(String),
    TestKeys,
    Connect(String),
    Lock,
    Panic,
    InstallInTerminal,
    PassphraseInTerminal,
    ExportInTerminal,
    RestoreInTerminal,
    ToggleNotifications,
    ToggleAutostart,
    Refresh,
    Quit,
}

pub struct Confirm {
    pub title: String,
    pub body: String,
    pub ok: String,
}

impl Action {
    pub fn id(&self) -> String {
        match self {
            Action::ReviewInUi(id) => format!("review:{id}"),
            Action::StartInUi(name) => format!("start:{name}"),
            Action::NewSessionInUi => "new-session".into(),
            Action::AddKeyInUi => "new-key".into(),
            Action::ReleaseKeyInUi => "release-key".into(),
            Action::TouchIdInUi => "touch-id".into(),
            Action::OpenUi => "open".into(),
            Action::UnlockInUi => "unlock".into(),
            Action::Revoke(sid) => format!("revoke:{sid}"),
            Action::StopKey(slug) => format!("stop-key:{slug}"),
            Action::TestKeys => "test-keys".into(),
            Action::Connect(agent) => format!("connect:{agent}"),
            Action::Lock => "lock".into(),
            Action::Panic => "panic".into(),
            Action::InstallInTerminal => "install".into(),
            Action::PassphraseInTerminal => "set-passphrase".into(),
            Action::ExportInTerminal => "export-keys".into(),
            Action::RestoreInTerminal => "restore-keys".into(),
            Action::ToggleNotifications => "toggle-notifications".into(),
            Action::ToggleAutostart => "toggle-autostart".into(),
            Action::Refresh => "refresh".into(),
            Action::Quit => "quit".into(),
        }
    }

    /// The reverse of `id`. Anything that does not round-trip to a safe id is
    /// refused, so a menu id can never smuggle an odd value into a CLI call.
    pub fn parse(id: &str) -> Option<Action> {
        let action = match id {
            "new-session" => Action::NewSessionInUi,
            "new-key" => Action::AddKeyInUi,
            "release-key" => Action::ReleaseKeyInUi,
            "touch-id" => Action::TouchIdInUi,
            "open" => Action::OpenUi,
            "unlock" => Action::UnlockInUi,
            "test-keys" => Action::TestKeys,
            "lock" => Action::Lock,
            "panic" => Action::Panic,
            "install" => Action::InstallInTerminal,
            "set-passphrase" => Action::PassphraseInTerminal,
            "export-keys" => Action::ExportInTerminal,
            "restore-keys" => Action::RestoreInTerminal,
            "toggle-notifications" => Action::ToggleNotifications,
            "toggle-autostart" => Action::ToggleAutostart,
            "refresh" => Action::Refresh,
            "quit" => Action::Quit,
            _ => {
                let (head, rest) = id.split_once(':')?;
                if !safe_id(rest) {
                    return None;
                }
                match head {
                    "review" => Action::ReviewInUi(rest.into()),
                    "start" => Action::StartInUi(rest.into()),
                    "revoke" => Action::Revoke(rest.into()),
                    "stop-key" => Action::StopKey(rest.into()),
                    "connect" if AGENTS.iter().any(|(id, _)| *id == rest) => {
                        Action::Connect(rest.into())
                    }
                    _ => return None,
                }
            }
        };
        Some(action)
    }

    /// The web UI page to open, as a URL fragment the UI's router reads.
    pub fn ui_fragment(&self) -> Option<String> {
        match self {
            Action::ReviewInUi(id) => Some(format!("#approvals/{}", encode_component(id))),
            Action::StartInUi(name) => Some(format!(
                "#sessions/{}",
                encode_component(&format!("new:{name}"))
            )),
            Action::NewSessionInUi => Some("#sessions/new".into()),
            Action::AddKeyInUi => Some("#credentials".into()),
            Action::ReleaseKeyInUi => Some("#containment".into()),
            Action::TouchIdInUi | Action::UnlockInUi => Some("#settings".into()),
            Action::OpenUi => Some(String::new()),
            _ => None,
        }
    }

    /// The exact CLI command an action runs, if it runs one. Every command
    /// here is one the daemon lets an unproven caller run: it narrows access
    /// (revoke, stop a key, lock, panic), checks keys against their own
    /// service, or writes the vault's entry into an agent's own config file.
    pub fn cli_args(&self) -> Option<Vec<String>> {
        let words: Vec<&str> = match self {
            Action::Revoke(sid) => vec!["session", "revoke", sid],
            Action::StopKey(slug) => vec![
                "cred",
                "quarantine",
                slug,
                "--reason",
                "stopped from the menu bar companion",
            ],
            Action::TestKeys => vec!["cred", "test", "--all"],
            Action::Connect(agent) => vec!["mcp", "install", "--agent", agent, "--scope", "user"],
            Action::Lock => vec!["lock"],
            Action::Panic => vec!["panic", "--reason", "panic from the menu bar companion"],
            _ => return None,
        };
        Some(words.into_iter().map(String::from).collect())
    }

    /// A fixed command for Terminal: no part of it comes from the vault, an
    /// agent or the menu. The human types their password and passphrase there.
    ///
    /// Terminal starts the user's own shell, so each program is run through
    /// `env -i`: whatever the shell profile exports (`AGENT_VAULT_DIR`, a
    /// different `PATH`, installer switches) does not reach it.
    pub fn terminal_script(&self) -> Option<String> {
        const ENV: &str =
            "/usr/bin/env -i HOME=$HOME USER=$USER TERM=$TERM PATH=/usr/bin:/bin:/usr/sbin:/sbin";
        const VAULT: &str = "/var/db/agent-vault/app/bin/agent-vault";
        const FILE: &str = "~/Desktop/agent-vault-backup.json";
        Some(match self {
            // The installer unpacks the release and prints the one privileged
            // command; `setup --print-only` prints it again on its own line, and
            // that line is what runs under sudo. Then the passphrase, at once:
            // a vault with no passphrase belongs to whoever sets the first one.
            Action::InstallInTerminal => format!(
                "clear; echo 'Setting up agent-vault. This takes about a minute.'; echo; \
                 /usr/bin/curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh \
                 | {ENV}:/opt/homebrew/bin:/usr/local/bin /bin/sh \
                 && echo && echo 'Enter your Mac password to finish installing.' \
                 && {ENV} ~/.local/bin/agent-vault setup --print-only | /usr/bin/grep '^sudo ' | {ENV} /bin/sh \
                 && echo && echo 'Now choose a passphrase. You will need it to approve what agents may do.' \
                 && {ENV} {VAULT} passphrase set \
                 && echo && echo 'Finished. You can close this window.' \
                 || echo 'Setup did not finish. Choose Set up agent-vault from the menu to try again.'"
            ),
            Action::PassphraseInTerminal => format!(
                "clear; echo 'Choose a passphrase for agent-vault. You will need it to approve what agents may do.'; echo; \
                 {ENV} {VAULT} passphrase set \
                 && echo && echo 'Finished. You can close this window.' \
                 || echo 'The passphrase was not set. Choose it from the menu to try again.'"
            ),
            // The vault encrypts the file under a recovery passphrase it asks
            // for, and wants fresh proof of the human before it writes one.
            Action::ExportInTerminal => format!(
                "clear; echo 'Saving your keys to an encrypted file on your Desktop.'; \
                 echo 'You will choose a recovery passphrase (12 or more characters). You need it to open the file on the other computer.'; echo; \
                 {ENV} {VAULT} backup export --out {FILE} \
                 && echo && echo 'Saved. Move agent-vault-backup.json to the other computer and bring it in there. Delete it once your keys are there.' \
                 || echo 'No file was saved.'"
            ),
            Action::RestoreInTerminal => format!(
                "clear; echo 'Bringing in keys from agent-vault-backup.json on your Desktop.'; \
                 echo 'It asks for the recovery passphrase you chose when you saved the file. Keys you already have here are left as they are.'; echo; \
                 {ENV} {VAULT} backup restore {FILE} --on-conflict skip \
                 && echo && echo 'Done. Check your keys in the menu, then delete the file from your Desktop.' \
                 || echo 'Nothing was brought in. Keep the file and try again.'"
            ),
            _ => return None,
        })
    }

    /// What to ask before doing it, for the actions that take access away at once.
    pub fn confirm(&self, snap: &Snapshot) -> Option<Confirm> {
        match self {
            Action::Revoke(sid) => {
                let label = snap
                    .session(sid)
                    .map(|s| s.label.clone())
                    .unwrap_or_else(|| sid.clone());
                Some(Confirm {
                    title: "Revoke this session?".into(),
                    body: format!("“{label}” ends now. Any agent using it loses access straight away."),
                    ok: "Revoke".into(),
                })
            }
            Action::StopKey(slug) => Some(Confirm {
                title: "Stop all use of this key?".into(),
                body: format!("Agents lose “{slug}” immediately, in every session. Allowing it again needs your confirmation in the vault."),
                ok: "Stop this key".into(),
            }),
            Action::Panic => Some(Confirm {
                title: "Revoke everything?".into(),
                body: "Every session ends and every waiting request is denied. Agents lose all access until you open a new session.".into(),
                ok: "Revoke everything".into(),
            }),
            _ => None,
        }
    }

    /// What to say once it worked. `None` when the next refresh says it better.
    pub fn done(&self, snap: &Snapshot) -> Option<String> {
        match self {
            Action::Revoke(sid) => {
                let label = snap
                    .session(sid)
                    .map(|s| s.label.clone())
                    .unwrap_or_else(|| sid.clone());
                Some(format!("Revoked “{label}”."))
            }
            Action::Panic => {
                Some("Every session is revoked and everything waiting was denied.".into())
            }
            Action::Connect(agent) => {
                let name = agent_name(agent);
                Some(format!(
                    "{name} is connected. Restart {name} so it picks up the vault."
                ))
            }
            _ => None,
        }
    }
}

/// What to say the first time the companion ever runs: where it lives, what
/// it found, and the one thing to do next.
pub struct Welcome {
    pub title: String,
    pub body: String,
    /// Offered as the main button, when there is something to do.
    pub next: Option<(String, Action)>,
}

pub fn welcome(snap: &Snapshot) -> Option<Welcome> {
    let home = "The companion lives in your menu bar, at the top right of the screen: look for the hexagon with a keyhole.";
    match &snap.reach {
        Reach::Loading => None,
        Reach::Missing(Missing::NotInstalled) => Some(Welcome {
            title: "Welcome to agent-vault".into(),
            body: format!(
                "agent-vault keeps your API keys where AI agents can use them but never see them.\n\nIt is not set up on this computer yet. Setting it up takes about a minute: Terminal opens, asks for your Mac password, then asks you to choose a passphrase.\n\n{home}"
            ),
            next: Some(("Set up now".into(), Action::InstallInTerminal)),
        }),
        Reach::Missing(_) | Reach::Down(_) => Some(Welcome {
            title: "agent-vault companion".into(),
            body: format!("The companion could not reach agent-vault on this computer. Its menu says why.\n\n{home}"),
            next: None,
        }),
        Reach::Up(_) => {
            let found = if snap.unread.keys {
                "Found your vault on this computer.".to_string()
            } else if snap.keys.is_empty() {
                "Found your vault on this computer. It has no keys yet.".to_string()
            } else {
                format!("Found your vault on this computer, with {}.", count(snap.keys.len(), "key"))
            };
            let first = setup_steps(snap).into_iter().find_map(|i| match i {
                Item::Action { action, text } => Some((text, action)),
                _ => None,
            });
            let next_line = if first.is_some() {
                "\n\nOne thing is left to finish setting up; the button below starts it."
            } else {
                ""
            };
            Some(Welcome {
                title: "agent-vault companion is running".into(),
                body: format!("{found}\n\n{home} It shows what agents can use, tells you when one is waiting for you, and lets you stop access with a click.{next_line}"),
                next: first.map(|(text, action)| (text.replace("… (opens Terminal)", "").trim_end_matches('…').to_string(), action)),
            })
        }
    }
}

pub fn agent_name(id: &str) -> &'static str {
    AGENTS
        .iter()
        .find(|(a, _)| *a == id)
        .map(|(_, n)| *n)
        .unwrap_or("The agent")
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Text(String),
    Action {
        action: Action,
        text: String,
    },
    Check {
        action: Action,
        text: String,
        on: bool,
    },
    Separator,
    Submenu {
        text: String,
        items: Vec<Item>,
    },
}

fn act(action: Action, text: impl Into<String>) -> Item {
    Item::Action {
        action,
        text: text.into(),
    }
}

// ---- parsing ------------------------------------------------------------

fn time(v: Option<&Value>) -> Option<DateTime<Utc>> {
    let s = v?.as_str()?;
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn parse_status(data: &Value) -> Option<Status> {
    Some(Status {
        version: clean_text(data.get("daemon_version")?.as_str()?, 20),
        locked: data.get("locked").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Live sessions only. The daemon can still list a session as `active` after
/// its expiry has passed, so the companion checks the clock itself.
pub fn parse_sessions(data: &Value, now: DateTime<Utc>) -> Vec<Session> {
    let Some(rows) = data.as_array() else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?;
            if !safe_id(id) || row.get("state").and_then(Value::as_str) != Some("active") {
                return None;
            }
            let infinite = row
                .get("infinite")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let expires_at = time(row.get("expires_at"));
            if !infinite && expires_at.is_some_and(|t| t <= now) {
                return None;
            }
            let grants = row.get("creds").and_then(Value::as_array);
            let creds = grants
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| c.get("slug").and_then(Value::as_str))
                        .map(|s| clean_text(s, 32))
                        .collect()
                })
                .unwrap_or_default();
            let label = row
                .get("label")
                .and_then(Value::as_str)
                .map(|l| clean_text(l, 32))
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| id.to_string());
            Some(Session {
                id: id.into(),
                label,
                creds,
                expires_at,
                infinite,
                mode: session_mode(grants.map(Vec::as_slice).unwrap_or(&[])),
            })
        })
        .collect()
}

/// One sentence on what agents may do, from the session's grants. When the
/// grants differ, the most permissive one is the one worth telling.
fn session_mode(grants: &[Value]) -> String {
    let read_only = |g: &Value| {
        g.get("methods")
            .and_then(Value::as_array)
            .is_some_and(|ms| {
                !ms.is_empty()
                    && ms
                        .iter()
                        .all(|m| matches!(m.as_str().unwrap_or(""), "GET" | "HEAD" | "OPTIONS"))
            })
    };
    if grants.is_empty() {
        return "Access details unknown".into();
    }
    if grants.iter().all(read_only) {
        return "Agents can only read".into();
    }
    let approvals: Vec<&str> = grants
        .iter()
        .filter(|g| !read_only(g))
        .map(|g| g.get("approval").and_then(Value::as_str).unwrap_or(""))
        .collect();
    if approvals.contains(&"auto") {
        "Agents can make changes without asking".into()
    } else if approvals.contains(&"first-use") {
        "Agents ask you once, then make changes".into()
    } else if approvals.iter().all(|a| matches!(*a, "on-write" | "each")) {
        "Agents ask you before every change".into()
    } else {
        "Access details unknown".into()
    }
}

/// Ids, kinds and ages only. `headline` and `claim` are left behind on
/// purpose: the claim is written by the agent and is never shown.
pub fn parse_pending(data: &Value) -> Vec<Pending> {
    let Some(rows) = data.as_array() else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?;
            if !safe_id(id) {
                return None;
            }
            Some(Pending {
                id: id.into(),
                kind: row
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                created_at: time(row.get("created_at")),
            })
        })
        .collect()
}

pub fn parse_templates(data: &Value) -> Vec<String> {
    data.as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .filter(|n| safe_id(n))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Names, services and health. Never a value: the CLI's list has none.
pub fn parse_keys(data: &Value) -> Vec<Key> {
    let Some(rows) = data.as_array() else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let slug = row.get("slug")?.as_str()?;
            if !safe_id(slug) {
                return None;
            }
            let kind = row.get("kind").and_then(Value::as_str).unwrap_or("");
            let host = row
                .get("connector")
                .and_then(|c| c.get("host"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let health = match row
                .get("health")
                .and_then(|h| h.get("status"))
                .and_then(Value::as_str)
            {
                Some("ok") => Health::Ok,
                Some(_) => Health::Problem,
                None => Health::Unknown,
            };
            Some(Key {
                slug: slug.into(),
                service: service_name(kind, host),
                health,
                stopped: row.get("quarantine").is_some_and(|q| !q.is_null()),
                expiring: row.get("expiry_warning").is_some_and(|w| !w.is_null()),
            })
        })
        .collect()
}

pub fn service_name(kind: &str, host: &str) -> String {
    match kind {
        "anthropic" => "Anthropic".into(),
        "openai" => "OpenAI".into(),
        "google-genai" => "Google Gemini".into(),
        "github" => "GitHub".into(),
        "slack" => "Slack".into(),
        _ => {
            let host = clean_text(host, 40);
            if host.is_empty() {
                "Other service".into()
            } else {
                host
            }
        }
    }
}

/// `doctor`'s "human factor enrolled" line: whether it holds, and its note
/// ("passphrase", "passphrase + authenticator").
pub fn parse_setup(doctor: &Value) -> Setup {
    let Some(rows) = doctor.as_array() else {
        return Setup::default();
    };
    let Some(row) = rows
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("human factor enrolled"))
    else {
        return Setup::default();
    };
    let ok = row.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let note = row.get("note").and_then(Value::as_str).unwrap_or("");
    Setup {
        passphrase: Some(ok && note.contains("passphrase")),
        touch_id: Some(ok && note.contains("authenticator")),
    }
}

/// What one key's check came to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Probe {
    Passed,
    Failed,
    /// The vault has no test for this kind of service.
    Untestable,
    /// The key is stopped, so the vault refused to use it.
    Stopped,
    /// The vault's own limits refused the check for now.
    Limited,
}

/// The results of `cred test --all`, from that run itself. `None` when the
/// reply has no results to read.
pub fn parse_key_test(data: &Value) -> Option<Vec<(String, Probe)>> {
    let rows = data.get("results")?.as_array()?;
    Some(
        rows.iter()
            .filter_map(|r| {
                let slug = r.get("slug")?.as_str()?;
                if !safe_id(slug) {
                    return None;
                }
                let probe = if r.get("ok") == Some(&Value::Bool(true)) {
                    Probe::Passed
                } else if r.get("rule").and_then(Value::as_str) == Some("no_probe") {
                    Probe::Untestable
                } else {
                    match r.get("error").and_then(Value::as_str) {
                        Some("AV_QUARANTINED") => Probe::Stopped,
                        Some("AV_QUOTA_EXCEEDED") => Probe::Limited,
                        _ => Probe::Failed,
                    }
                };
                Some((slug.to_string(), probe))
            })
            .collect(),
    )
}

pub fn key_report(results: &[(String, Probe)]) -> String {
    let names = |want: Probe| -> Vec<&str> {
        results
            .iter()
            .filter(|(_, p)| *p == want)
            .map(|(s, _)| s.as_str())
            .collect()
    };
    let tested = results
        .iter()
        .filter(|(_, p)| matches!(p, Probe::Passed | Probe::Failed))
        .count();
    let mut lines = Vec::new();
    if tested == 0 {
        lines.push("No key could be checked.".to_string());
    } else {
        lines.push(format!(
            "{} of {} passed.",
            names(Probe::Passed).len(),
            count(tested, "checked key")
        ));
    }
    let failed = names(Probe::Failed);
    if !failed.is_empty() {
        lines.push(format!(
            "Failed: {}. A failed key may have expired or been revoked.",
            failed.join(", ")
        ));
    }
    let untestable = names(Probe::Untestable);
    if !untestable.is_empty() {
        lines.push(format!(
            "No automatic check exists for: {}.",
            untestable.join(", ")
        ));
    }
    let stopped = names(Probe::Stopped);
    if !stopped.is_empty() {
        lines.push(format!("Stopped, so not checked: {}.", stopped.join(", ")));
    }
    let limited = names(Probe::Limited);
    if !limited.is_empty() {
        lines.push(format!(
            "Not checked this time (the vault limits how often): {}.",
            limited.join(", ")
        ));
    }
    lines.join("\n")
}

/// Whether `mcp install --print` reports the vault as already written into an
/// agent's config.
pub fn parse_connected(data: &Value) -> Option<bool> {
    data.get("unchanged").and_then(Value::as_bool)
}

// ---- the menu -----------------------------------------------------------

/// Text beside the icon: the number waiting, or nothing.
pub fn tray_title(snap: &Snapshot) -> Option<String> {
    if snap.unread.pending && matches!(snap.reach, Reach::Up(_)) {
        return Some("?".into());
    }
    (!snap.pending.is_empty()).then(|| snap.pending.len().to_string())
}

pub fn tooltip(snap: &Snapshot) -> String {
    match &snap.reach {
        Reach::Up(_) if !snap.pending.is_empty() => {
            format!("agent-vault: {} waiting for you", snap.pending.len())
        }
        Reach::Up(s) if s.locked => "agent-vault: locked".into(),
        Reach::Up(_) if !snap.sessions.is_empty() => {
            format!(
                "agent-vault: {} open",
                count(snap.sessions.len(), "session")
            )
        }
        Reach::Up(_) => "agent-vault".into(),
        Reach::Down(_) => "agent-vault: not reachable".into(),
        Reach::Missing(_) => "agent-vault: not set up".into(),
        Reach::Loading => "agent-vault".into(),
    }
}

pub fn menu(snap: &Snapshot, prefs: Prefs, now: DateTime<Utc>) -> Vec<Item> {
    let mut items = Vec::new();
    match &snap.reach {
        Reach::Loading => items.push(Item::Text("Checking agent-vault…".into())),
        Reach::Missing(Missing::NotInstalled) => {
            items.push(Item::Text(
                "agent-vault is not set up on this computer".into(),
            ));
            items.push(act(
                Action::InstallInTerminal,
                "Set up agent-vault… (opens Terminal)",
            ));
            items.push(Item::Text(
                "It asks for your Mac password, then a new passphrase".into(),
            ));
        }
        Reach::Missing(Missing::Unsupported) => {
            items.push(Item::Text(
                "agent-vault does not run on this operating system yet".into(),
            ));
        }
        Reach::Missing(Missing::Untrusted(why)) => {
            items.push(Item::Text(
                "This agent-vault install cannot be trusted".into(),
            ));
            items.push(Item::Text(clean_text(why, 70)));
        }
        Reach::Down(why) => {
            items.push(Item::Text("agent-vault is not answering".into()));
            items.push(Item::Text(clean_text(why, 60)));
        }
        Reach::Up(status) => up_menu(&mut items, snap, status, now),
    }
    items.push(Item::Separator);
    items.push(Item::Submenu {
        text: "Settings".into(),
        items: settings_menu(snap, prefs),
    });
    items.push(act(Action::Refresh, "Refresh"));
    items.push(act(Action::Quit, "Quit companion"));
    items
}

fn settings_menu(snap: &Snapshot, prefs: Prefs) -> Vec<Item> {
    let mut items = vec![
        Item::Check {
            action: Action::ToggleNotifications,
            text: "Show notifications".into(),
            on: prefs.notifications,
        },
        Item::Check {
            action: Action::ToggleAutostart,
            text: "Start at login".into(),
            on: prefs.autostart,
        },
    ];
    if matches!(snap.reach, Reach::Up(_)) {
        let agents = if snap.agents.is_empty() {
            vec![Item::Text(
                "No supported agents found on this computer".into(),
            )]
        } else {
            snap.agents
                .iter()
                .map(|a| {
                    if a.connected {
                        Item::Text(format!("{} · connected", a.name))
                    } else {
                        act(Action::Connect(a.id.clone()), format!("Connect {}", a.name))
                    }
                })
                .collect()
        };
        items.push(Item::Submenu {
            text: "Connect agents".into(),
            items: agents,
        });
    }
    items
}

/// What is still left to do before the vault is useful and safe, most
/// important first. Empty when everything is in place.
pub fn setup_steps(snap: &Snapshot) -> Vec<Item> {
    let mut steps = Vec::new();
    if snap.setup.passphrase == Some(false) {
        steps.push(act(
            Action::PassphraseInTerminal,
            "Set your passphrase… (opens Terminal)",
        ));
    } else if snap.setup.touch_id == Some(false) {
        steps.push(act(Action::TouchIdInUi, "Turn on Touch ID approvals…"));
    }
    if snap.keys.is_empty() && !snap.unread.keys {
        steps.push(act(Action::AddKeyInUi, "Add your first key…"));
    }
    if !snap.agents.is_empty() && snap.agents.iter().all(|a| !a.connected) {
        for a in &snap.agents {
            steps.push(act(
                Action::Connect(a.id.clone()),
                format!("Connect {}", a.name),
            ));
        }
    }
    steps
}

fn up_menu(items: &mut Vec<Item>, snap: &Snapshot, status: &Status, now: DateTime<Utc>) {
    let state = if status.locked { "Locked" } else { "Unlocked" };
    items.push(Item::Text(format!(
        "agent-vault {} · {state}",
        status.version
    )));
    items.push(Item::Separator);

    let steps = setup_steps(snap);
    if !steps.is_empty() {
        items.push(Item::Text(format!(
            "Finish setting up ({} left)",
            steps.len()
        )));
        items.extend(steps);
        items.push(Item::Separator);
    }

    // Waiting for the human.
    if snap.unread.pending {
        items.push(Item::Text("Couldn't check what is waiting".into()));
    } else if snap.pending.is_empty() {
        items.push(Item::Text("Nothing waiting for you".into()));
    } else {
        items.push(Item::Text(format!(
            "Waiting for you ({})",
            snap.pending.len()
        )));
        for p in &snap.pending {
            let what = match p.kind.as_str() {
                "session" => "An agent is asking for access",
                "request" => "An agent wants to make a change",
                _ => "Something needs your decision",
            };
            let when = p
                .created_at
                .map(|t| format!(" ({})", ago(t, now)))
                .unwrap_or_default();
            items.push(act(
                Action::ReviewInUi(p.id.clone()),
                format!("{what}{when}: review…"),
            ));
        }
    }
    items.push(Item::Separator);

    // Sessions: what agents can use right now.
    if snap.unread.sessions {
        items.push(Item::Text("Couldn't read open sessions".into()));
    } else if snap.sessions.is_empty() {
        items.push(Item::Text(
            "No open sessions: agents cannot use any key".into(),
        ));
    } else {
        items.push(Item::Text(format!(
            "Open sessions ({}): what agents can use now",
            snap.sessions.len()
        )));
        for s in &snap.sessions {
            let ends = if s.infinite {
                "no expiry".to_string()
            } else {
                s.expires_at
                    .map(|t| until(t, now))
                    .unwrap_or_else(|| "expiry unknown".into())
            };
            let keys = if s.creds.is_empty() {
                "No keys listed".to_string()
            } else {
                format!("Keys: {}", s.creds.join(", "))
            };
            items.push(Item::Submenu {
                text: format!("{} · {} · {ends}", s.label, count(s.creds.len(), "key")),
                items: vec![
                    Item::Text(keys),
                    Item::Text(s.mode.clone()),
                    Item::Separator,
                    act(Action::Revoke(s.id.clone()), "Revoke this session…"),
                ],
            });
        }
    }
    let mut start: Vec<Item> = snap
        .templates
        .iter()
        .map(|t| act(Action::StartInUi(t.clone()), format!("From “{t}”…")))
        .collect();
    if !start.is_empty() {
        start.push(Item::Separator);
    }
    start.push(act(Action::NewSessionInUi, "Choose keys and limits…"));
    items.push(Item::Submenu {
        text: "Start a session".into(),
        items: start,
    });
    items.push(Item::Separator);

    // Keys.
    if snap.unread.keys {
        items.push(Item::Text("Couldn't read your keys".into()));
    } else if snap.keys.is_empty() {
        items.push(Item::Text("No keys stored yet".into()));
    } else {
        items.push(Item::Text(format!("Keys ({})", snap.keys.len())));
        for k in &snap.keys {
            items.push(key_item(k, snap.in_use(&k.slug)));
        }
    }
    items.push(act(Action::AddKeyInUi, "Add a key…"));
    if !snap.keys.is_empty() {
        items.push(act(Action::TestKeys, "Check that all keys still work"));
    }
    items.push(Item::Separator);

    items.push(Item::Submenu {
        text: "Move keys to another computer".into(),
        items: vec![
            Item::Text("Uses an encrypted file on your Desktop".into()),
            act(
                Action::ExportInTerminal,
                "Save my keys to an encrypted file… (opens Terminal)",
            ),
            act(
                Action::RestoreInTerminal,
                "Bring in keys from that file… (opens Terminal)",
            ),
        ],
    });
    items.push(act(Action::OpenUi, "Open the vault…"));
    if status.locked {
        items.push(act(Action::UnlockInUi, "Unlock in the vault…"));
    } else {
        items.push(act(Action::Lock, "Lock the vault"));
    }
    items.push(act(Action::Panic, "Panic: revoke everything…"));
}

fn key_item(k: &Key, in_use: bool) -> Item {
    let (mark, tail, detail) = if k.stopped {
        ("⏸ ", "stopped", "Stopped: no agent can use this key")
    } else if k.health == Health::Problem {
        (
            "⚠ ",
            "last check failed",
            "The last check of this key failed",
        )
    } else if k.expiring {
        ("⚠ ", "expires soon", "This key expires soon")
    } else if in_use {
        ("", "in use", "In use by an open session")
    } else if k.health == Health::Ok {
        (
            "",
            "ready",
            "Working at its last check; not in any open session",
        )
    } else {
        (
            "",
            "not checked yet",
            "Not checked yet; not in any open session",
        )
    };
    let action = if k.stopped {
        act(
            Action::ReleaseKeyInUi,
            "Allow this key again… (in the vault)",
        )
    } else {
        act(Action::StopKey(k.slug.clone()), "Stop all use of this key…")
    };
    Item::Submenu {
        text: format!("{mark}{} · {} · {tail}", k.slug, k.service),
        items: vec![Item::Text(detail.into()), Item::Separator, action],
    }
}

// ---- small helpers ------------------------------------------------------

/// Ids, slugs and template names the companion is willing to pass on. They
/// must start with a letter, digit or underscore, so one can never be read as
/// a command-line flag.
pub fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0] != b'-'
        && s.as_bytes()[0] != b'.'
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Text that came from the vault (labels, slugs, versions), made safe to show:
/// control and bidirectional-override characters removed, length capped.
pub fn clean_text(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() && !is_bidi(*c))
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.chars().count() <= max {
        cleaned.to_string()
    } else {
        let cut: String = cleaned.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{061C}')
}

/// encodeURIComponent, which is what the web UI's router decodes.
pub fn encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

pub fn until(t: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let s = (t - now).num_seconds();
    if s <= 0 {
        "ending now".into()
    } else if s < 3600 {
        format!("ends in {}m", (s + 59) / 60)
    } else if s < 86_400 {
        format!("ends in {}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("ends in {}d", s / 86_400)
    }
}

pub fn ago(t: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let s = (now - t).num_seconds().max(0);
    if s < 60 {
        "just now".into()
    } else if s < 3600 {
        format!("{} min ago", s / 60)
    } else {
        format!("{} h ago", s / 3600)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-20T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    pub fn actions(items: &[Item]) -> Vec<Action> {
        let mut out = Vec::new();
        for i in items {
            match i {
                Item::Action { action, .. } | Item::Check { action, .. } => {
                    out.push(action.clone())
                }
                Item::Submenu { items, .. } => out.extend(actions(items)),
                _ => {}
            }
        }
        out
    }

    fn texts(items: &[Item]) -> String {
        let mut out = String::new();
        for i in items {
            match i {
                Item::Text(t) | Item::Action { text: t, .. } | Item::Check { text: t, .. } => {
                    out.push_str(t);
                    out.push('\n');
                }
                Item::Submenu { text, items } => {
                    out.push_str(text);
                    out.push('\n');
                    out.push_str(&texts(items));
                }
                Item::Separator => {}
            }
        }
        out
    }

    pub fn up(locked: bool) -> Reach {
        Reach::Up(Status {
            version: "0.3.2".into(),
            locked,
        })
    }

    fn done_setup() -> Setup {
        Setup {
            passphrase: Some(true),
            touch_id: Some(true),
        }
    }

    /// A vault with a bit of everything in it.
    pub fn busy() -> Snapshot {
        let mut snap = Snapshot::only(up(false));
        snap.sessions = parse_sessions(
            &json!([{"id":"s1","label":"keys-models","state":"active","expires_at":"2026-11-20T15:12:00Z",
                "creds":[{"slug":"openai-api","approval":"auto","methods":["GET","POST"]}]}]),
            now(),
        );
        snap.pending = parse_pending(&json!([
            {"id":"sr_1","kind":"session","created_at":"2026-11-20T11:58:00Z"},
            {"id":"ap_2","kind":"request"}
        ]));
        snap.templates = vec!["keys-all".into(), "key-openai".into()];
        snap.keys = parse_keys(&json!([
            {"slug":"openai-api","kind":"openai","health":{"status":"ok"},"quarantine":null},
            {"slug":"anthropic-api","kind":"anthropic","health":{"status":"error"},"quarantine":null},
            {"slug":"hf","kind":"http","connector":{"host":"huggingface.co"},"health":null,"quarantine":{"reason":"x"}}
        ]));
        snap.setup = done_setup();
        snap.agents = vec![
            AgentLink {
                id: "claude-code".into(),
                name: "Claude Code".into(),
                connected: true,
            },
            AgentLink {
                id: "codex".into(),
                name: "Codex".into(),
                connected: false,
            },
        ];
        snap
    }

    fn all_menus() -> Vec<Vec<Item>> {
        let mut fresh = Snapshot::only(up(true));
        fresh.setup = Setup {
            passphrase: Some(false),
            touch_id: Some(false),
        };
        fresh.agents = vec![AgentLink {
            id: "cursor".into(),
            name: "Cursor".into(),
            connected: false,
        }];
        [
            busy(),
            fresh,
            Snapshot::only(Reach::Missing(Missing::NotInstalled)),
            Snapshot::only(Reach::Missing(Missing::Untrusted("x".into()))),
            Snapshot::only(Reach::Down("x".into())),
            Snapshot::loading(),
        ]
        .iter()
        .map(|s| menu(s, Prefs::default(), now()))
        .collect()
    }

    #[test]
    fn sessions_past_expiry_are_dropped_even_if_listed_active() {
        let data = json!([
            {"id":"live1","label":"keys-all","state":"active","expires_at":"2026-11-20T15:30:00Z","infinite":false,
             "creds":[{"slug":"openai-api"},{"slug":"azure-api"}]},
            {"id":"old1","label":"key-test","state":"active","expires_at":"2026-11-13T05:53:41.361Z","infinite":false,"creds":[]},
            {"id":"gone1","state":"revoked","expires_at":"2026-11-21T00:00:00Z"},
            {"id":"inf1","state":"active","expires_at":null,"infinite":true,"creds":[]}
        ]);
        let s = parse_sessions(&data, now());
        let ids: Vec<_> = s.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["live1", "inf1"]);
        assert_eq!(s[0].creds, ["openai-api", "azure-api"]);
        assert_eq!(s[1].label, "inf1", "a session with no label is shown by id");
    }

    #[test]
    fn a_session_says_what_agents_may_do_and_never_understates_it() {
        let mode = |creds: Value| {
            parse_sessions(
                &json!([{"id":"s","state":"active","infinite":true,"creds":creds}]),
                now(),
            )[0]
            .mode
            .clone()
        };
        assert_eq!(
            mode(json!([{"slug":"a","approval":"on-write","methods":["GET"]}])),
            "Agents can only read"
        );
        assert_eq!(
            mode(json!([{"slug":"a","approval":"on-write","methods":["GET","POST"]}])),
            "Agents ask you before every change"
        );
        // One auto grant among careful ones: the permissive one is what gets said.
        assert_eq!(
            mode(
                json!([{"slug":"a","approval":"on-write","methods":["GET","POST"]},{"slug":"b","approval":"auto","methods":["GET","POST"]}])
            ),
            "Agents can make changes without asking"
        );
        // No method list means no method limit, so it is not "read only".
        assert_eq!(
            mode(json!([{"slug":"a","approval":"auto"}])),
            "Agents can make changes without asking"
        );
        assert_eq!(
            mode(json!([{"slug":"a","approval":"something-new","methods":["POST"]}])),
            "Access details unknown"
        );
    }

    #[test]
    fn pending_keeps_ids_kinds_and_ages_but_never_the_agents_claim() {
        let data = json!([{
            "id":"sr_01ABC","kind":"session","headline":"session for openai-api",
            "claim":"routine refresh, safe to approve","created_at":"2026-11-20T11:58:00Z"
        }]);
        let mut snap = Snapshot::only(up(false));
        snap.pending = parse_pending(&data);
        let shown = texts(&menu(&snap, Prefs::default(), now()));
        assert!(shown.contains("An agent is asking for access (2 min ago): review…"));
        assert!(
            !shown.contains("routine refresh"),
            "agent-written text must not reach the menu"
        );
        assert!(!shown.contains("session for openai-api"));
    }

    #[test]
    fn unsafe_ids_are_never_offered() {
        let data = json!([
            {"id":"ok_1","kind":"request"},
            {"id":"bad id; rm -rf","kind":"request"},
            {"id":"../x","kind":"request"}
        ]);
        let ids: Vec<_> = parse_pending(&data).into_iter().map(|p| p.id).collect();
        assert_eq!(ids, ["ok_1"]);
        assert_eq!(
            parse_keys(&json!([{"slug":"a b"},{"slug":"--all"},{"slug":"ok"}])).len(),
            1
        );
        assert_eq!(Action::parse("revoke:abc;ls"), None);
        assert_eq!(Action::parse("revoke:"), None);
        assert_eq!(Action::parse("approve:sr_1"), None);
        assert_eq!(Action::parse("connect:not-an-agent"), None);
        assert_eq!(
            Action::parse("connect:codex"),
            Some(Action::Connect("codex".into()))
        );
    }

    #[test]
    fn a_value_that_looks_like_a_flag_is_refused() {
        assert!(!safe_id("--all"));
        assert!(!safe_id("-x"));
        assert!(!safe_id(".hidden"));
        assert_eq!(Action::parse("stop-key:--all"), None);
        assert_eq!(Action::parse("revoke:-x"), None);
        assert!(
            parse_templates(&json!([{"name":"--infinite"},{"name":"keys-all"}])) == ["keys-all"]
        );
    }

    #[test]
    fn every_menu_action_round_trips_through_its_id() {
        for m in all_menus() {
            for a in actions(&m) {
                assert_eq!(Action::parse(&a.id()), Some(a.clone()), "{a:?}");
            }
        }
    }

    #[test]
    fn the_menu_runs_only_commands_the_daemon_allows_without_proof() {
        const ALLOWED: &[&[&str]] = &[
            &["session", "revoke"],
            &["cred", "quarantine"],
            &["cred", "test"],
            &["mcp", "install"],
            &["lock"],
            &["panic"],
        ];
        let mut ran = 0;
        for m in all_menus() {
            for a in actions(&m) {
                let Some(args) = a.cli_args() else { continue };
                ran += 1;
                assert!(
                    ALLOWED
                        .iter()
                        .any(|w| args.len() >= w.len()
                            && args.iter().zip(w.iter()).all(|(a, b)| a == b)),
                    "{args:?}"
                );
                // Never a command that grants, decides or reveals.
                for word in [
                    "approve",
                    "deny",
                    "create",
                    "save",
                    "add",
                    "rm",
                    "rotate",
                    "release",
                    "unlock",
                    "passphrase",
                    "env",
                    "exec",
                    "ph",
                ] {
                    assert!(args.iter().take(2).all(|a| a != word), "{args:?}");
                }
            }
        }
        assert!(ran >= 5, "the test menus should exercise the commands");
    }

    #[test]
    fn terminal_commands_are_fixed_and_use_absolute_paths() {
        let all = [
            Action::InstallInTerminal,
            Action::PassphraseInTerminal,
            Action::ExportInTerminal,
            Action::RestoreInTerminal,
        ];
        for a in &all {
            let s = a.terminal_script().unwrap();
            // The only variables are the three handed to `env -i`.
            let bare = s
                .replace("$HOME", "")
                .replace("$USER", "")
                .replace("$TERM", "");
            assert!(
                !bare.contains('$') && !s.contains('"') && !s.contains('\\') && !s.contains('`'),
                "{s}"
            );
            // Every quoted message closes: an odd count would swallow the command.
            assert_eq!(s.matches('\'').count() % 2, 0, "{s}");
            // Every program runs by absolute path, in a cleared environment.
            for word in s.split_whitespace() {
                if word.ends_with("/agent-vault")
                    || word.ends_with("/sh")
                    || word.ends_with("/curl")
                    || word.ends_with("/grep")
                    || word.ends_with("/env")
                {
                    assert!(word.starts_with('/') || word.starts_with("~/"), "{word}");
                }
            }
            assert!(s.contains("/usr/bin/env -i HOME=$HOME USER=$USER TERM=$TERM PATH=/usr/bin:/bin:/usr/sbin:/sbin"));
            // Success and failure are told apart: no "finished" after a failure.
            assert!(s.contains(" && echo") && s.contains(" || echo"), "{s}");
        }
        let install = Action::InstallInTerminal.terminal_script().unwrap();
        assert!(install.contains("/usr/bin/curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh"));
        // The privileged step is the one line setup prints, and nothing else it prints.
        assert!(install
            .contains("~/.local/bin/agent-vault setup --print-only | /usr/bin/grep '^sudo ' |"));
        assert!(install.contains("/var/db/agent-vault/app/bin/agent-vault passphrase set"));
        assert!(Action::ExportInTerminal
            .terminal_script()
            .unwrap()
            .contains("backup export --out ~/Desktop/agent-vault-backup.json"));
        assert!(Action::RestoreInTerminal
            .terminal_script()
            .unwrap()
            .contains("backup restore ~/Desktop/agent-vault-backup.json --on-conflict skip"));
        assert_eq!(Action::Lock.terminal_script(), None);
    }

    /// The shells Terminal is likely to start must parse each command as written.
    #[cfg(unix)]
    #[test]
    fn terminal_commands_parse_in_sh_and_zsh() {
        for a in [
            Action::InstallInTerminal,
            Action::PassphraseInTerminal,
            Action::ExportInTerminal,
            Action::RestoreInTerminal,
        ] {
            let script = a.terminal_script().unwrap();
            for shell in ["/bin/sh", "/bin/zsh", "/bin/bash"] {
                if !std::path::Path::new(shell).exists() {
                    continue;
                }
                let out = std::process::Command::new(shell)
                    .args(["-n", "-c", &script])
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{shell} rejects {a:?}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }

    #[test]
    fn a_key_check_reports_that_runs_results() {
        let data = json!({"results":[
            {"slug":"openai-api","ok":true,"http_status":200},
            {"slug":"anthropic-api","ok":false,"http_status":400},
            {"slug":"hf","ok":false,"rule":"no_probe"},
            {"slug":"old","ok":false,"error":"AV_QUARANTINED"},
            {"slug":"busy","ok":false,"error":"AV_QUOTA_EXCEEDED"},
            {"slug":"bad slug","ok":true}
        ]});
        let r = parse_key_test(&data).unwrap();
        assert_eq!(r.len(), 5);
        let text = key_report(&r);
        assert!(text.contains("1 of 2 checked keys passed."), "{text}");
        assert!(text.contains("Failed: anthropic-api."));
        assert!(text.contains("No automatic check exists for: hf."));
        assert!(text.contains("Stopped, so not checked: old."));
        assert!(text.contains("Not checked this time (the vault limits how often): busy."));
        assert!(parse_key_test(&json!({})).is_none());
        assert!(
            key_report(&[("hf".into(), Probe::Untestable)]).starts_with("No key could be checked.")
        );
    }

    #[test]
    fn keys_show_their_state_and_the_right_action() {
        let snap = busy();
        let m = menu(&snap, Prefs::default(), now());
        let shown = texts(&m);
        assert!(shown.contains("openai-api · OpenAI · in use"));
        assert!(shown.contains("⚠ anthropic-api · Anthropic · last check failed"));
        assert!(shown.contains("⏸ hf · huggingface.co · stopped"));
        let a = actions(&m);
        assert!(a.contains(&Action::StopKey("openai-api".into())));
        assert!(
            !a.contains(&Action::StopKey("hf".into())),
            "a stopped key is not stopped again"
        );
        assert!(a.contains(&Action::ReleaseKeyInUi));
    }

    #[test]
    fn setup_steps_lead_with_the_passphrase() {
        let mut snap = Snapshot::only(up(false));
        snap.setup = Setup {
            passphrase: Some(false),
            touch_id: Some(false),
        };
        snap.agents = vec![AgentLink {
            id: "codex".into(),
            name: "Codex".into(),
            connected: false,
        }];
        assert_eq!(
            actions(&setup_steps(&snap)),
            [
                Action::PassphraseInTerminal,
                Action::AddKeyInUi,
                Action::Connect("codex".into())
            ]
        );
        snap.setup.passphrase = Some(true);
        assert_eq!(actions(&setup_steps(&snap))[0], Action::TouchIdInUi);
        assert!(
            setup_steps(&busy()).is_empty(),
            "a finished setup shows no checklist"
        );
        // Unknown is not "missing": no nagging when doctor could not be read.
        let mut unknown = busy();
        unknown.setup = Setup::default();
        assert!(setup_steps(&unknown).is_empty());
    }

    #[test]
    fn setup_is_read_from_doctor() {
        let d =
            |ok: bool, note: &str| json!([{"name":"human factor enrolled","ok":ok,"note":note}]);
        assert_eq!(
            parse_setup(&d(true, "passphrase + authenticator")),
            Setup {
                passphrase: Some(true),
                touch_id: Some(true)
            }
        );
        assert_eq!(
            parse_setup(&d(true, "passphrase")),
            Setup {
                passphrase: Some(true),
                touch_id: Some(false)
            }
        );
        assert_eq!(
            parse_setup(&d(false, "none")),
            Setup {
                passphrase: Some(false),
                touch_id: Some(false)
            }
        );
        assert_eq!(parse_setup(&json!([])), Setup::default());
    }

    #[test]
    fn a_missing_vault_offers_setup_and_an_untrusted_one_does_not() {
        let a = actions(&menu(
            &Snapshot::only(Reach::Missing(Missing::NotInstalled)),
            Prefs::default(),
            now(),
        ));
        assert!(a.contains(&Action::InstallInTerminal));
        let a = actions(&menu(
            &Snapshot::only(Reach::Missing(Missing::Untrusted("x".into()))),
            Prefs::default(),
            now(),
        ));
        assert!(!a.contains(&Action::InstallInTerminal));
    }

    #[test]
    fn the_first_run_welcome_says_what_was_found_and_what_to_do() {
        let w = welcome(&Snapshot::only(Reach::Missing(Missing::NotInstalled))).unwrap();
        assert_eq!(w.next.unwrap().1, Action::InstallInTerminal);
        let w = welcome(&busy()).unwrap();
        assert!(w.body.contains("with 3 keys"));
        assert!(w.next.is_none(), "nothing left to set up");
        let mut fresh = Snapshot::only(up(false));
        fresh.setup = Setup {
            passphrase: Some(true),
            touch_id: Some(false),
        };
        let w = welcome(&fresh).unwrap();
        assert!(w.body.contains("no keys yet"));
        let (label, action) = w.next.unwrap();
        assert_eq!(action, Action::TouchIdInUi);
        assert_eq!(label, "Turn on Touch ID approvals");
        assert!(welcome(&Snapshot::loading()).is_none());
    }

    #[test]
    fn locked_vault_offers_unlock_in_the_ui_not_lock() {
        let a = actions(&menu(&Snapshot::only(up(true)), Prefs::default(), now()));
        assert!(a.contains(&Action::UnlockInUi));
        assert!(!a.contains(&Action::Lock));
        let a = actions(&menu(&Snapshot::only(up(false)), Prefs::default(), now()));
        assert!(a.contains(&Action::Lock));
        assert!(!a.contains(&Action::UnlockInUi));
    }

    #[test]
    fn ui_fragments_match_the_web_routers_format() {
        assert_eq!(
            Action::ReviewInUi("sr_01ABC".into()).ui_fragment().unwrap(),
            "#approvals/sr_01ABC"
        );
        // formatHash('sessions', `new:${name}`) in web/src/lib/router.js
        assert_eq!(
            Action::StartInUi("keys-all".into()).ui_fragment().unwrap(),
            "#sessions/new%3Akeys-all"
        );
        assert_eq!(
            Action::NewSessionInUi.ui_fragment().unwrap(),
            "#sessions/new"
        );
        assert_eq!(Action::AddKeyInUi.ui_fragment().unwrap(), "#credentials");
        assert_eq!(Action::OpenUi.ui_fragment().unwrap(), "");
        assert_eq!(Action::Panic.ui_fragment(), None);
    }

    #[test]
    fn labels_are_cleaned_of_control_and_bidi_characters() {
        assert_eq!(clean_text("ok\u{202E}evil\u{0007}", 40), "okevil");
        assert_eq!(clean_text("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn badge_counts_what_is_waiting() {
        let mut snap = Snapshot::only(up(false));
        assert_eq!(tray_title(&snap), None);
        snap.pending = parse_pending(&json!([{"id":"a"},{"id":"b"}]));
        assert_eq!(tray_title(&snap).as_deref(), Some("2"));
    }

    #[test]
    fn a_failed_read_is_never_shown_as_an_empty_list() {
        let mut snap = Snapshot::only(up(false));
        snap.unread = Unread {
            sessions: true,
            pending: true,
            templates: true,
            keys: true,
        };
        let shown = texts(&menu(&snap, Prefs::default(), now()));
        assert!(shown.contains("Couldn't read open sessions"));
        assert!(shown.contains("Couldn't check what is waiting"));
        assert!(shown.contains("Couldn't read your keys"));
        assert!(!shown.contains("No open sessions"));
        assert!(!shown.contains("Nothing waiting"));
        assert!(!shown.contains("No keys stored"));
        assert!(!shown.contains("Add your first key"));
        assert_eq!(tray_title(&snap).as_deref(), Some("?"));
    }

    #[test]
    fn settings_reflect_the_users_choices() {
        let m = menu(
            &busy(),
            Prefs {
                notifications: false,
                autostart: true,
                welcomed: true,
            },
            now(),
        );
        let checks: Vec<(Action, bool)> = fn_checks(&m);
        assert!(checks.contains(&(Action::ToggleNotifications, false)));
        assert!(checks.contains(&(Action::ToggleAutostart, true)));
        let shown = texts(&m);
        assert!(shown.contains("Claude Code · connected"));
        assert!(shown.contains("Connect Codex"));
    }

    fn fn_checks(items: &[Item]) -> Vec<(Action, bool)> {
        let mut out = Vec::new();
        for i in items {
            match i {
                Item::Check { action, on, .. } => out.push((action.clone(), *on)),
                Item::Submenu { items, .. } => out.extend(fn_checks(items)),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn times_read_naturally() {
        let n = now();
        assert_eq!(until(n + chrono::Duration::minutes(5), n), "ends in 5m");
        assert_eq!(
            until(n + chrono::Duration::minutes(192), n),
            "ends in 3h 12m"
        );
        assert_eq!(ago(n - chrono::Duration::seconds(10), n), "just now");
        assert_eq!(ago(n - chrono::Duration::minutes(7), n), "7 min ago");
        assert_eq!(count(1, "key"), "1 key");
        assert_eq!(count(3, "key"), "3 keys");
    }

    #[test]
    fn unreachable_vault_still_offers_settings_refresh_and_quit() {
        let snap = Snapshot::only(Reach::Down("the daemon is not running".into()));
        let a = actions(&menu(&snap, Prefs::default(), now()));
        assert_eq!(
            a,
            [
                Action::ToggleNotifications,
                Action::ToggleAutostart,
                Action::Refresh,
                Action::Quit
            ]
        );
    }
}
