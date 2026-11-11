//! `agent-vault watch`: follow the daemon's pending stream and notify.
//! Ports `src/cli/watch.js`.

use std::path::PathBuf;

use serde_json::Value;

use crate::CliError;

/// The four display fields of one stream entry, cleaned (controls stripped,
/// placeholders replaced, query strings dropped from the headline); `None`
/// for an entry that is not one. Never the agent's reason or body. Ports
/// `safeEntry(entry)` in `src/cli/watch.js`.
pub fn safe_entry(entry: &Value) -> Option<Value> {
    todo!()
}

/// Options for [`watch_approvals`]. Ports the options of
/// `watchApprovals({ socketPath, json, notify, open, onEvent, quiet, deps })`
/// in `src/cli/watch.js` (`deps` is the test seam; the CLI worker chooses the
/// Rust equivalent).
#[derive(Debug, Clone, Default)]
pub struct WatchOptions {
    /// The control socket.
    pub socket_path: PathBuf,
    /// One JSON line per item.
    pub json: bool,
    /// Desktop notification per item.
    pub notify: bool,
    /// Open the UI on the first item.
    pub open: bool,
    /// Less output.
    pub quiet: bool,
}

/// Watch the local approval stream until SIGINT, reconnecting with backoff.
/// Ports `watchApprovals(...)` in `src/cli/watch.js`.
pub async fn watch_approvals(opts: WatchOptions) -> Result<(), CliError> {
    todo!()
}
