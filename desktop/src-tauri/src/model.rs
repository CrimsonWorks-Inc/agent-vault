//! What the menu shows, worked out from the CLI's JSON. Pure: no I/O, no Tauri,
//! so every rule here is covered by the tests at the bottom.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// How far the companion got in reaching the vault.
#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    /// Nothing checked yet.
    Loading,
    /// No trustworthy agent-vault install on this computer.
    Missing(String),
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub id: String,
    pub kind: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub reach: Reach,
    pub sessions: Vec<Session>,
    pub pending: Vec<Pending>,
    pub templates: Vec<String>,
    /// Lists the CLI failed to return. Shown as "couldn't read", never as an
    /// empty list: "no open sessions" must mean exactly that.
    pub unread: Unread,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Unread {
    pub sessions: bool,
    pub pending: bool,
    pub templates: bool,
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
            unread: Unread::default(),
        }
    }

    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }
}

/// Everything a menu click can ask for. There is deliberately no variant that
/// approves, denies, creates a session, saves a template, adds a credential or
/// unlocks: those widen access and need the human's proof, which the web UI
/// collects. `ReviewInUi`, `StartInUi` and `OpenUi` only open that page.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    ReviewInUi(String),
    StartInUi(String),
    OpenUi,
    UnlockInUi,
    Revoke(String),
    Lock,
    Panic,
    Refresh,
    Quit,
}

impl Action {
    pub fn id(&self) -> String {
        match self {
            Action::ReviewInUi(id) => format!("review:{id}"),
            Action::StartInUi(name) => format!("start:{name}"),
            Action::OpenUi => "open".into(),
            Action::UnlockInUi => "unlock".into(),
            Action::Revoke(sid) => format!("revoke:{sid}"),
            Action::Lock => "lock".into(),
            Action::Panic => "panic".into(),
            Action::Refresh => "refresh".into(),
            Action::Quit => "quit".into(),
        }
    }

    /// The reverse of `id`. Anything that does not round-trip to a safe id is
    /// refused, so a menu id can never smuggle an odd value into a CLI call.
    pub fn parse(id: &str) -> Option<Action> {
        let action = match id {
            "open" => Action::OpenUi,
            "unlock" => Action::UnlockInUi,
            "lock" => Action::Lock,
            "panic" => Action::Panic,
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
            Action::StartInUi(name) => {
                Some(format!("#sessions/{}", encode_component(&format!("new:{name}"))))
            }
            Action::OpenUi => Some(String::new()),
            Action::UnlockInUi => Some("#settings".into()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Text(String),
    Action { action: Action, text: String },
    Separator,
    Submenu { text: String, items: Vec<Item> },
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
            let infinite = row.get("infinite").and_then(Value::as_bool).unwrap_or(false);
            let expires_at = time(row.get("expires_at"));
            if !infinite && expires_at.is_some_and(|t| t <= now) {
                return None;
            }
            let creds = row
                .get("creds")
                .and_then(Value::as_array)
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
            })
        })
        .collect()
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
        Reach::Up(_) => "agent-vault".into(),
        Reach::Down(_) => "agent-vault: not reachable".into(),
        Reach::Missing(_) => "agent-vault: not installed".into(),
        Reach::Loading => "agent-vault".into(),
    }
}

pub fn menu(snap: &Snapshot, now: DateTime<Utc>) -> Vec<Item> {
    let mut items = Vec::new();
    match &snap.reach {
        Reach::Loading => items.push(Item::Text("Checking agent-vault…".into())),
        Reach::Missing(why) => {
            items.push(Item::Text("agent-vault is not installed here".into()));
            items.push(Item::Text(clean_text(why, 60)));
        }
        Reach::Down(why) => {
            items.push(Item::Text("agent-vault is not answering".into()));
            items.push(Item::Text(clean_text(why, 60)));
        }
        Reach::Up(status) => up_menu(&mut items, snap, status, now),
    }
    items.push(Item::Separator);
    items.push(act(Action::Refresh, "Refresh"));
    items.push(act(Action::Quit, "Quit companion"));
    items
}

fn up_menu(items: &mut Vec<Item>, snap: &Snapshot, status: &Status, now: DateTime<Utc>) {
    let state = if status.locked { "Locked" } else { "Unlocked" };
    items.push(Item::Text(format!("agent-vault {} · {state}", status.version)));
    items.push(Item::Separator);

    if snap.unread.pending {
        items.push(Item::Text("Couldn't check what is waiting".into()));
    } else if snap.pending.is_empty() {
        items.push(Item::Text("Nothing waiting for you".into()));
    } else {
        items.push(Item::Text(format!("Waiting for you ({})", snap.pending.len())));
        for p in &snap.pending {
            let what = match p.kind.as_str() {
                "session" => "Session request",
                "request" => "Held request",
                _ => "Waiting item",
            };
            let when = p.created_at.map(|t| ago(t, now)).unwrap_or_default();
            let text = if when.is_empty() {
                format!("Review {what} in the vault…")
            } else {
                format!("Review {what} ({when}) in the vault…")
            };
            items.push(act(Action::ReviewInUi(p.id.clone()), text));
        }
    }
    items.push(Item::Separator);

    if snap.unread.sessions {
        items.push(Item::Text("Couldn't read open sessions".into()));
    } else if snap.sessions.is_empty() {
        items.push(Item::Text("No open sessions".into()));
    } else {
        items.push(Item::Text(format!("Open sessions ({})", snap.sessions.len())));
        for s in &snap.sessions {
            let ends = if s.infinite {
                "no expiry".to_string()
            } else {
                s.expires_at
                    .map(|t| until(t, now))
                    .unwrap_or_else(|| "expiry unknown".into())
            };
            let keys = if s.creds.is_empty() {
                String::new()
            } else {
                format!(" · {}", s.creds.join(", "))
            };
            items.push(Item::Submenu {
                text: format!("{}{keys} · {ends}", s.label),
                items: vec![act(Action::Revoke(s.id.clone()), "Revoke this session…")],
            });
        }
    }
    items.push(Item::Separator);

    if !snap.templates.is_empty() {
        items.push(Item::Submenu {
            text: "Start a session from a template".into(),
            items: snap
                .templates
                .iter()
                .map(|t| act(Action::StartInUi(t.clone()), format!("{t}…")))
                .collect(),
        });
    }
    items.push(act(Action::OpenUi, "Open the vault…"));
    if status.locked {
        items.push(act(Action::UnlockInUi, "Unlock in the vault…"));
    } else {
        items.push(act(Action::Lock, "Lock the vault"));
    }
    items.push(act(Action::Panic, "Panic: revoke everything…"));
}

// ---- small helpers ------------------------------------------------------

/// Ids, slugs and template names the companion is willing to pass on.
pub fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s
            .bytes()
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
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-20T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn actions(items: &[Item]) -> Vec<Action> {
        let mut out = Vec::new();
        for i in items {
            match i {
                Item::Action { action, .. } => out.push(action.clone()),
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
                Item::Text(t) | Item::Action { text: t, .. } => {
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

    fn up(locked: bool) -> Reach {
        Reach::Up(Status {
            version: "0.3.2".into(),
            locked,
        })
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
    fn pending_keeps_ids_kinds_and_ages_but_never_the_agents_claim() {
        let data = json!([{
            "id":"sr_01ABC","kind":"session","headline":"session for openai-api",
            "claim":"routine refresh, safe to approve","created_at":"2026-11-20T11:58:00Z"
        }]);
        let p = parse_pending(&data);
        assert_eq!(p.len(), 1);
        let snap = Snapshot { reach: up(false), pending: p, sessions: vec![], templates: vec![], unread: Unread::default() };
        let shown = texts(&menu(&snap, now()));
        assert!(shown.contains("Session request (2 min ago)"));
        assert!(!shown.contains("routine refresh"), "agent-written text must not reach the menu");
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
        assert_eq!(Action::parse("revoke:abc;ls"), None);
        assert_eq!(Action::parse("revoke:"), None);
        assert_eq!(Action::parse("approve:sr_1"), None);
    }

    #[test]
    fn every_menu_action_round_trips_through_its_id() {
        let snap = Snapshot {
            reach: up(false),
            sessions: parse_sessions(&json!([{"id":"s1","state":"active","expires_at":"2026-11-20T13:00:00Z"}]), now()),
            pending: parse_pending(&json!([{"id":"sr_1","kind":"session"}])),
            templates: vec!["keys-all".into()], unread: Unread::default()
        };
        for a in actions(&menu(&snap, now())) {
            assert_eq!(Action::parse(&a.id()), Some(a.clone()), "{a:?}");
        }
    }

    #[test]
    fn nothing_in_the_menu_grants_access() {
        // Every action is either a page opener or one that only narrows access.
        let snap = Snapshot {
            reach: up(true),
            sessions: parse_sessions(&json!([{"id":"s1","state":"active","infinite":true}]), now()),
            pending: parse_pending(&json!([{"id":"sr_1","kind":"session"},{"id":"ap_2","kind":"request"}])),
            templates: vec!["keys-all".into(), "key-openai".into()], unread: Unread::default()
        };
        for a in actions(&menu(&snap, now())) {
            let allowed = matches!(
                a,
                Action::ReviewInUi(_) | Action::StartInUi(_) | Action::OpenUi | Action::UnlockInUi
                    | Action::Revoke(_) | Action::Lock | Action::Panic | Action::Refresh | Action::Quit
            );
            assert!(allowed);
            let id = a.id();
            for word in ["approve", "deny", "create", "save", "add", "passphrase"] {
                assert!(!id.contains(word), "{id}");
            }
        }
    }

    #[test]
    fn locked_vault_offers_unlock_in_the_ui_not_lock() {
        let snap = Snapshot::only(up(true));
        let a = actions(&menu(&snap, now()));
        assert!(a.contains(&Action::UnlockInUi));
        assert!(!a.contains(&Action::Lock));
        let snap = Snapshot::only(up(false));
        let a = actions(&menu(&snap, now()));
        assert!(a.contains(&Action::Lock));
        assert!(!a.contains(&Action::UnlockInUi));
    }

    #[test]
    fn ui_fragments_match_the_web_routers_format() {
        assert_eq!(Action::ReviewInUi("sr_01ABC".into()).ui_fragment().unwrap(), "#approvals/sr_01ABC");
        // formatHash('sessions', `new:${name}`) in web/src/lib/router.js
        assert_eq!(Action::StartInUi("keys-all".into()).ui_fragment().unwrap(), "#sessions/new%3Akeys-all");
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
        snap.unread = Unread { sessions: true, pending: true, templates: true };
        let shown = texts(&menu(&snap, now()));
        assert!(shown.contains("Couldn't read open sessions"));
        assert!(shown.contains("Couldn't check what is waiting"));
        assert!(!shown.contains("No open sessions"));
        assert!(!shown.contains("Nothing waiting"));
        assert_eq!(tray_title(&snap).as_deref(), Some("?"));
    }

    #[test]
    fn times_read_naturally() {
        let n = now();
        assert_eq!(until(n + chrono::Duration::minutes(5), n), "ends in 5m");
        assert_eq!(until(n + chrono::Duration::minutes(192), n), "ends in 3h 12m");
        assert_eq!(ago(n - chrono::Duration::seconds(10), n), "just now");
        assert_eq!(ago(n - chrono::Duration::minutes(7), n), "7 min ago");
    }

    #[test]
    fn unreachable_vault_still_offers_refresh_and_quit() {
        let snap = Snapshot::only(Reach::Down("the daemon is not running".into()));
        let a = actions(&menu(&snap, now()));
        assert_eq!(a, [Action::Refresh, Action::Quit]);
    }
}
