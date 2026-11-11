//! The library behind `agent-vault migrate` (rust/PLAN.md, "`agent-vault
//! migrate`"): converts a JS vault (`vault.json`, the device key and the audit
//! log) into `vault.db`, keeping the same VMK and every id. The CLI owns the
//! command, prompting and output; this module owns the steps.
//!
//! No JS source: new in the Rust port. It reads the formats written by
//! `src/store/vault.js`, `src/store/crypto.js` and `src/store/audit.js`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use av_core::secret::SecretString;
use serde::Serialize;

use crate::model::LegacyDocument;

/// Inputs to a migration. No JS source: PLAN, "`agent-vault migrate`".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateOptions {
    /// `--from`: the JS vault dir (defaults to the installed vault dir).
    pub from: PathBuf,
    /// `--to`: where `vault.db` is written (defaults to `from`).
    pub to: PathBuf,
    /// `--dry-run`: run steps 1–7 in memory and write nothing.
    pub dry_run: bool,
}

/// Why a migration stopped. Nothing has been written when any of these is
/// returned. No JS source: PLAN, "`agent-vault migrate`", steps 1–4.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// Step 1: `vault.db` already exists at the target. A completed earlier
    /// migration is reported by the CLI as success (exit 0).
    #[error("vault.db already exists at {0}")]
    AlreadyMigrated(PathBuf),
    /// Step 2: the JS daemon is running against `--from`. `next` says how to
    /// stop it.
    #[error("the agent-vault daemon is running against {dir}")]
    DaemonRunning {
        /// The vault dir in use.
        dir: PathBuf,
        /// The command that stops it.
        next: String,
    },
    /// Step 3: no JS vault (no `vault.json`) at `--from`.
    #[error("no vault.json at {0}")]
    NoLegacyVault(PathBuf),
    /// Step 3: the audit chain or its anchor does not verify. `at` names where
    /// it breaks (a sequence number, or the anchor).
    #[error("the audit log does not verify: {reason} (at {at})")]
    AuditBroken {
        /// Where the chain breaks.
        at: String,
        /// What is wrong, never a secret.
        reason: String,
    },
    /// Step 4: the vault needs a passphrase and none was given.
    #[error("this vault needs its passphrase to migrate")]
    PassphraseRequired,
    /// Step 4: the passphrase (or device key) does not open the VMK.
    #[error("the passphrase did not open the vault")]
    WrongPassphrase,
    /// Any store failure (SQLite, I/O, JSON, crypto) in steps 3–8.
    #[error(transparent)]
    Store(#[from] crate::error::Error),
}

/// Something the migration leaves behind, with how to restore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dropped {
    /// What was dropped, e.g. `"webauthn-prf unlock wrap"`.
    pub what: String,
    /// Why it cannot be migrated.
    pub why: String,
    /// The command that re-creates it.
    pub next: String,
}

/// The report `migrate` prints, and `--json` returns as `data`. No JS source:
/// PLAN, "`agent-vault migrate`", `--dry-run` and `--json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrateReport {
    /// True when step 1 found a completed migration and nothing was done.
    pub already_migrated: bool,
    /// True for `--dry-run`: nothing was written.
    pub dry_run: bool,
    /// Rows per entity (credentials, sessions, grants, placeholders,
    /// approvals, workspaces, listeners, templates, clients, settings,
    /// presence_factors, pins, tripwires, notify), keyed by entity name.
    pub counts: BTreeMap<String, u64>,
    /// First audit sequence number imported.
    pub audit_first_seq: Option<u64>,
    /// Last audit sequence number imported (before `vault.migrated`).
    pub audit_last_seq: Option<u64>,
    /// The old head hash, which the `vault.migrated` record's `prev` names.
    pub audit_head: Option<String>,
    /// What could not be migrated (a PRF unlock wrap), with the re-enroll
    /// command.
    pub dropped: Vec<Dropped>,
    /// The new database, when one was written.
    pub written: Option<PathBuf>,
    /// The old files left untouched (`vault.json`, device key, audit files),
    /// for the "delete these once satisfied" message.
    pub legacy_files: Vec<PathBuf>,
}

/// The JS vault as read from disk (step 3), before unlocking. Holds no
/// plaintext secret: the device key is wrapped in a redacting type.
pub struct LegacyVault {
    /// The parsed `vault.json`.
    pub document: LegacyDocument,
    /// The device key file's 32 bytes.
    pub device_key: av_core::secret::Key32,
    /// The audit log lines, exactly as on disk.
    pub audit_lines: Vec<String>,
    /// The audit head anchor file, if present.
    pub audit_anchor: Option<String>,
    /// The files read, for [`MigrateReport::legacy_files`].
    pub files: Vec<PathBuf>,
}

impl std::fmt::Debug for LegacyVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyVault")
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

/// Steps 1 and 2: refuse if `vault.db` exists at `to`
/// ([`MigrateError::AlreadyMigrated`]) or the JS daemon is running against
/// `from` ([`MigrateError::DaemonRunning`]). No JS source.
pub fn preflight(opts: &MigrateOptions) -> Result<(), MigrateError> {
    todo!()
}

/// Whether a JS daemon is serving the vault at `dir` (its control socket
/// answers). No JS source; mirrors how `src/cli/index.js` finds the socket.
pub fn js_daemon_running(dir: &Path) -> bool {
    todo!()
}

/// Step 3: read `vault.json`, the device key and the audit log from `from`,
/// and verify the audit chain and anchor (as `AuditLog.verify` in
/// `src/store/audit.js` does). No JS source.
pub fn read_legacy(from: &Path) -> Result<LegacyVault, MigrateError> {
    todo!()
}

/// Whether unlocking `legacy` needs a passphrase (its wraps include a
/// `passphrase` class and no `none` class). The CLI prompts only then; the
/// passphrase is never an argument. No JS source.
pub fn needs_passphrase(legacy: &LegacyVault) -> bool {
    todo!()
}

/// Steps 4–9: unlock with `passphrase` (or the device key alone for a
/// factor-`none` vault) keeping the same VMK, re-wrap it under Argon2id,
/// re-seal every field and sealed setting as v2, copy every entity with ids
/// unchanged, import the audit log and append `vault.migrated` (whose `prev`
/// is the old head), and write it all in one transaction to a temp file that
/// is fsynced and renamed to `vault.db`. With `opts.dry_run`, the same work
/// is done in memory ([`crate::db::open_in_memory`]) and nothing is written.
/// The legacy files are never modified. No JS source.
pub fn migrate(
    opts: &MigrateOptions,
    legacy: LegacyVault,
    passphrase: Option<&SecretString>,
) -> Result<MigrateReport, MigrateError> {
    todo!()
}
