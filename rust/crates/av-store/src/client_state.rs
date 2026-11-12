//! Ports `src/client-state.js`: the state on the human's side of the
//! boundary (`cli-state.json`). It holds capabilities, never a credential
//! value: a session token, the placeholder issued with it, the gateway port.
//! Anything running as the human (an agent included) can edit it, so every
//! field is dropped on load unless it has the one shape it can have.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Result;

/// The file name (kept from when the CLI owned it). Ports the
/// `'cli-state.json'` literal in `statePath` in `src/client-state.js`.
pub const STATE_FILE: &str = "cli-state.json";
/// The home-relative default dir. Ports the `'.agent-vault'` literal in
/// `stateDir` in `src/client-state.js`.
pub const DEFAULT_STATE_DIR: &str = ".agent-vault";

/// The shape a `token` must have. Ports `SHAPES.token` in
/// `src/client-state.js` (matched by hand; no backtracking).
pub const TOKEN_SHAPE: &str = r"^avs1\.[A-Za-z0-9]+\.[A-Za-z0-9_-]+$";
/// The shape a `placeholder` must have. Ports `SHAPES.placeholder` in
/// `src/client-state.js`.
pub const PLACEHOLDER_SHAPE: &str = r"^av1\.[A-Za-z0-9._-]+$";
/// The shape a `session_id` must have. Ports `SHAPES.session_id` in
/// `src/client-state.js`.
pub const SESSION_ID_SHAPE: &str = r"^[A-Za-z0-9_-]+$";
/// The shape a `base_url` must have. Ports `SHAPES.base_url` in
/// `src/client-state.js`.
pub const BASE_URL_SHAPE: &str = r"^http://127\.0\.0\.1:\d{1,5}/p/[A-Za-z0-9._-]+$";

/// The client state. The token is a bearer capability, so `Debug` is
/// redacted. Unknown keys are kept as they were. Ports the object
/// `loadState` returns in `src/client-state.js`.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientState {
    /// The current session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Its token `avs1.<sid>.<secret>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The placeholder issued with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// The loopback gateway URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The gateway port, 1..=65535.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_port: Option<u16>,
    /// Every other key.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl std::fmt::Debug for ClientState {
    /// Redacted: never the token. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientState").finish_non_exhaustive()
    }
}

/// What `remember_session` records. Ports the argument of `rememberSession`
/// in `src/client-state.js`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RememberedSession {
    /// Session id.
    pub session_id: Option<String>,
    /// Token (nothing is written without one).
    pub token: Option<String>,
    /// Placeholder.
    pub placeholder: Option<String>,
    /// Base URL.
    pub base_url: Option<String>,
}

impl std::fmt::Debug for RememberedSession {
    /// Redacted: never the token. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RememberedSession").finish_non_exhaustive()
    }
}

/// `$AGENT_VAULT_DIR`, else `~/.agent-vault`. Every writer should pass its
/// own path instead. Ports `stateDir` in `src/client-state.js`.
pub fn state_dir() -> PathBuf {
    match std::env::var_os("AGENT_VAULT_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            home.join(DEFAULT_STATE_DIR)
        }
    }
}

/// `<dir>/cli-state.json`. Ports `statePath` in `src/client-state.js`.
pub fn state_path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

/// Whether `s` is `[A-Za-z0-9]+` (`alnum`), with `extra` allowed too.
fn all_of(s: &str, extra: &[u8]) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// [`TOKEN_SHAPE`]: `avs1.<alnum>.<base64url>`.
fn is_token(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("avs1.") else {
        return false;
    };
    let Some((sid, secret)) = rest.split_once('.') else {
        return false;
    };
    all_of(sid, b"") && all_of(secret, b"_-")
}

/// [`PLACEHOLDER_SHAPE`]: `av1.` then URL-safe characters.
fn is_placeholder(s: &str) -> bool {
    s.strip_prefix("av1.").is_some_and(|r| all_of(r, b"._-"))
}

/// [`SESSION_ID_SHAPE`].
fn is_session_id(s: &str) -> bool {
    all_of(s, b"_-")
}

/// [`BASE_URL_SHAPE`]: the loopback gateway, `http://127.0.0.1:<1-5
/// digits>/p/<slug>`.
fn is_base_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some((port, tail)) = rest.split_once('/') else {
        return false;
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    tail.strip_prefix("p/").is_some_and(|slug| all_of(slug, b"._-"))
}

/// `Number(v)` as the JS port check reads it, for the values JSON can hold.
fn js_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                Some(0.0)
            } else {
                t.parse::<f64>().ok().filter(|n| n.is_finite())
            }
        }
        _ => None,
    }
}

/// Read the state; a missing, truncated or non-object file is empty, and a
/// field without its legitimate shape is dropped. Never fails. Ports
/// `loadState` in `src/client-state.js`.
pub fn load_state(path: &Path) -> ClientState {
    let Ok(text) = std::fs::read_to_string(path) else {
        return ClientState::default();
    };
    let Ok(Value::Object(mut raw)) = serde_json::from_str::<Value>(&text) else {
        return ClientState::default();
    };
    // The port went straight into a URL, so a value of `1@attacker.example`
    // made the attacker's name the host. Only a whole number in range stays.
    if let Some(v) = raw.get("gateway_port").cloned() {
        match js_number(&v) {
            Some(n) if n.fract() == 0.0 && (1.0..=65535.0).contains(&n) => {
                raw.insert("gateway_port".into(), Value::from(n as u64));
            }
            _ => {
                raw.remove("gateway_port");
            }
        }
    }
    // `agent-vault env` is meant for `eval`, so each field is dropped unless
    // it has the one shape it can legitimately have.
    let shapes: [(&str, fn(&str) -> bool); 4] = [
        ("token", is_token),
        ("placeholder", is_placeholder),
        ("session_id", is_session_id),
        ("base_url", is_base_url),
    ];
    for (field, ok) in shapes {
        if let Some(v) = raw.get(field) {
            if !v.as_str().is_some_and(ok) {
                raw.remove(field);
            }
        }
    }
    serde_json::from_value(Value::Object(raw)).unwrap_or_default()
}

/// Merge `patch` over the current state and write it (dir 0700, file
/// written exclusively, replacing). Ports `saveState` in
/// `src/client-state.js`.
pub fn save_state(patch: &ClientState, path: &Path) -> Result<()> {
    let mut merged = match serde_json::to_value(load_state(path))? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    if let Value::Object(p) = serde_json::to_value(patch)? {
        for (k, v) in p {
            merged.insert(k, v);
        }
    }
    write_state(&merged, path)
}

/// Write the merged object: a new file beside the target, then a rename over
/// it, refusing a target that is not a regular file this user owns. Ports
/// `writeFileExclusive(path, text, { force: true })` in `src/cli/files.js`.
fn write_state(state: &Map<String, Value>, path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let text = serde_json::to_string_pretty(&Value::Object(state.clone()))?;
    let mut suffix = [0u8; 4];
    crate::crypto::fill_random(&mut suffix)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| STATE_FILE.to_string());
    let tmp = dir.join(format!(".{name}.av-{}", crate::crypto::hex(&suffix)));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let mine = f.metadata()?.uid();
    let done = (|| -> std::io::Result<()> {
        if let Ok(st) = std::fs::symlink_metadata(path) {
            if !st.file_type().is_file() || st.uid() != mine {
                return Err(std::io::Error::other(format!(
                    "{} is not a regular file you own",
                    path.display()
                )));
            }
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = done {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Record a session for every local client (CLI, `env`, the MCP stdio
/// bridge); nothing without a token. Ports `rememberSession` in
/// `src/client-state.js`.
pub fn remember_session(session: &RememberedSession, path: &Path) -> Result<()> {
    let Some(token) = session.token.as_ref().filter(|t| !t.is_empty()) else {
        return Ok(());
    };
    let mut merged = match serde_json::to_value(load_state(path))? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    // The JS spreads `session_id: undefined` over the old one, which drops it.
    match &session.session_id {
        Some(sid) => merged.insert("session_id".into(), Value::from(sid.clone())),
        None => merged.remove("session_id"),
    };
    merged.insert("token".into(), Value::from(token.clone()));
    if let Some(p) = session.placeholder.as_ref().filter(|p| !p.is_empty()) {
        merged.insert("placeholder".into(), Value::from(p.clone()));
    }
    if let Some(u) = session.base_url.as_ref().filter(|u| !u.is_empty()) {
        merged.insert("base_url".into(), Value::from(u.clone()));
    }
    write_state(&merged, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "avs1.abc123def456.AAAA_bbbb-cccc";

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = state_path(d.path());
        (d, p)
    }

    #[test]
    fn missing_or_garbage_is_empty() {
        let (_d, p) = tmp();
        assert_eq!(load_state(&p), ClientState::default());
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(load_state(&p), ClientState::default());
        std::fs::write(&p, "42").unwrap();
        assert_eq!(load_state(&p), ClientState::default());
    }

    #[test]
    fn a_port_with_a_host_in_it_is_dropped() {
        let (_d, p) = tmp();
        std::fs::write(&p, r#"{"gateway_port":"1@attacker.example"}"#).unwrap();
        assert_eq!(load_state(&p).gateway_port, None);
        std::fs::write(&p, r#"{"gateway_port":70000}"#).unwrap();
        assert_eq!(load_state(&p).gateway_port, None);
        // Control: an ordinary port, as a number or the string the JS coerces.
        std::fs::write(&p, r#"{"gateway_port":"8443"}"#).unwrap();
        assert_eq!(load_state(&p).gateway_port, Some(8443));
        std::fs::write(&p, r#"{"gateway_port":17321}"#).unwrap();
        assert_eq!(load_state(&p).gateway_port, Some(17321));
    }

    #[test]
    fn shell_payloads_in_fields_are_dropped() {
        let (_d, p) = tmp();
        std::fs::write(
            &p,
            r#"{"token":"x; rm -rf ~ #","placeholder":"$(id)","session_id":"a b","base_url":"http://evil.example/p/x","other":1}"#,
        )
        .unwrap();
        let s = load_state(&p);
        assert!(s.token.is_none() && s.placeholder.is_none());
        assert!(s.session_id.is_none() && s.base_url.is_none());
        assert_eq!(s.extra.get("other"), Some(&Value::from(1)));
    }

    #[test]
    fn legitimate_values_survive() {
        let (_d, p) = tmp();
        let ph = "av1.0123456789ab.demo_token.0123456789abcdefghjkmnpqrs.abcdef";
        std::fs::write(
            &p,
            serde_json::json!({
                "token": TOKEN, "placeholder": ph, "session_id": "0123456789ab",
                "base_url": "http://127.0.0.1:17321/p/demo"
            })
            .to_string(),
        )
        .unwrap();
        let s = load_state(&p);
        assert_eq!(s.token.as_deref(), Some(TOKEN));
        assert_eq!(s.placeholder.as_deref(), Some(ph));
        assert_eq!(s.session_id.as_deref(), Some("0123456789ab"));
        assert_eq!(s.base_url.as_deref(), Some("http://127.0.0.1:17321/p/demo"));
    }

    #[test]
    fn remember_writes_only_with_a_token_and_merges() {
        let (d, p) = tmp();
        remember_session(&RememberedSession::default(), &p).unwrap();
        assert!(!p.exists());
        save_state(
            &ClientState {
                gateway_port: Some(9000),
                ..Default::default()
            },
            &p,
        )
        .unwrap();
        remember_session(
            &RememberedSession {
                session_id: Some("0123456789ab".into()),
                token: Some(TOKEN.into()),
                placeholder: None,
                base_url: None,
            },
            &p,
        )
        .unwrap();
        let s = load_state(&p);
        assert_eq!(s.gateway_port, Some(9000));
        assert_eq!(s.token.as_deref(), Some(TOKEN));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // No temp file left behind.
        let left: Vec<_> = std::fs::read_dir(d.path()).unwrap().collect();
        assert_eq!(left.len(), 1);
    }

    #[test]
    fn a_symlinked_state_file_is_replaced_not_followed() {
        let (d, p) = tmp();
        let target = d.path().join("elsewhere");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        let r = save_state(&ClientState::default(), &p);
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn debug_never_shows_the_token() {
        let s = ClientState {
            token: Some(TOKEN.into()),
            ..Default::default()
        };
        assert!(!format!("{s:?}").contains("AAAA"));
    }

    #[test]
    fn state_dir_follows_the_env() {
        // Read only: the variable is process-wide, so compare what is set now.
        let d = state_dir();
        match std::env::var_os("AGENT_VAULT_DIR") {
            Some(v) if !v.is_empty() => assert_eq!(d, PathBuf::from(v)),
            _ => assert!(d.ends_with(DEFAULT_STATE_DIR)),
        }
    }
}
