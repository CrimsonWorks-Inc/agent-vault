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
        todo!()
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
        todo!()
    }
}

/// `$AGENT_VAULT_DIR`, else `~/.agent-vault`. Every writer should pass its
/// own path instead. Ports `stateDir` in `src/client-state.js`.
pub fn state_dir() -> PathBuf {
    todo!()
}

/// `<dir>/cli-state.json`. Ports `statePath` in `src/client-state.js`.
pub fn state_path(dir: &Path) -> PathBuf {
    todo!()
}

/// Read the state; a missing, truncated or non-object file is empty, and a
/// field without its legitimate shape is dropped. Never fails. Ports
/// `loadState` in `src/client-state.js`.
pub fn load_state(path: &Path) -> ClientState {
    todo!()
}

/// Merge `patch` over the current state and write it (dir 0700, file
/// written exclusively, replacing). Ports `saveState` in
/// `src/client-state.js`.
pub fn save_state(patch: &ClientState, path: &Path) -> Result<()> {
    todo!()
}

/// Record a session for every local client (CLI, `env`, the MCP stdio
/// bridge); nothing without a token. Ports `rememberSession` in
/// `src/client-state.js`.
pub fn remember_session(session: &RememberedSession, path: &Path) -> Result<()> {
    todo!()
}
