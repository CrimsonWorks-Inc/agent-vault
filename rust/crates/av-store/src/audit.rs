//! Ports `src/store/audit.js`: the append-only, hash-chained, keyed audit
//! log, its authenticated head anchor, and witness checkpoints (F9).
//!
//! Chain, anchor and witness semantics are frozen (rust/PLAN.md, "Frozen
//! external contract" item 8). Each record's hash is
//! `HMAC(K_audit, "<seq>|<ts>|<kind>|<canonical(record minus hash)>|<prev>")`;
//! the anchor MAC is `HMAC(K_audit, "<seq>|<hash>")`; a checkpoint record's
//! `mac` is `HMAC(K_audit, prev_hash)`; a witness MAC is
//! `HMAC(K_audit, "witness|<vault_id>|<seq>|<head>|<ts>")`.
//!
//! Never written here: credential values in any encoding, full placeholders,
//! bodies, query strings, or Authorization values.

use std::path::{Path, PathBuf};

use av_core::secret::Key32;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Result;

/// The fields `write` sets itself; a caller's field may never carry one.
/// Ports `CHAIN_FIELDS` in `src/store/audit.js`.
pub const CHAIN_FIELDS: [&str; 5] = ["seq", "ts", "kind", "prev_hash", "hash"];
/// A `checkpoint` record every this many records. Ports `CHECKPOINT_EVERY`
/// in `src/store/audit.js`.
pub const CHECKPOINT_EVERY: u64 = 1000;
/// The `prev_hash` of record 1. Ports `GENESIS` in `src/store/audit.js`.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Most rows one export page returns. Ports `MAX_EXPORT_ROWS` in
/// `src/store/audit.js`.
pub const MAX_EXPORT_ROWS: usize = 5000;
/// Most checkpoints one witness verification takes. Ports
/// `MAX_WITNESS_CHECKPOINTS` in `src/store/audit.js`.
pub const MAX_WITNESS_CHECKPOINTS: usize = 10_000;
/// The anchor file's suffix (`<path>.head`). Ports `this.anchorPath` in the
/// `AuditLog` constructor in `src/store/audit.js`.
pub const ANCHOR_SUFFIX: &str = ".head";

/// One audit record. Serialized in the JS order: `seq, ts, kind, ...fields,
/// prev_hash, hash`. Ports the `record` built in `AuditLog.prototype.write`
/// in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// 1-based position in the chain.
    pub seq: u64,
    /// ISO time written.
    pub ts: String,
    /// Record kind (`session.created`, `checkpoint`, ...).
    pub kind: String,
    /// The caller's fields, after `recordable`.
    #[serde(flatten)]
    pub fields: Map<String, Value>,
    /// Previous record's hash (hex), or [`GENESIS`].
    pub prev_hash: String,
    /// This record's hash (hex).
    pub hash: String,
}

/// One line of the log as read: a record, or a line that could not be read.
/// Ports the `{ unreadable: true, line }` rows of `#rows` in
/// `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq)]
pub enum AuditRow {
    /// A well-formed record.
    Record(AuditRecord),
    /// Line `line` (1-based) did not parse or lacked the chain fields.
    Unreadable {
        /// 1-based line number.
        line: usize,
    },
}

/// The authenticated head anchor (`audit.jsonl.head`). Ports the body
/// `#anchor` writes in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Last seq.
    pub seq: u64,
    /// Last hash.
    pub hash: String,
    /// `HMAC(K_audit, "<seq>|<hash>")`, hex.
    pub mac: String,
}

/// The log came back shorter than its anchor says. Ports `this.truncation`
/// in `src/store/audit.js` (also the fields of `audit.truncation_detected`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncation {
    /// Where the anchor says the log ends.
    pub expected_seq: u64,
    /// Where it actually ends.
    pub found_seq: u64,
    /// The anchor's hash, when the log is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
}

/// A non-empty log with no authentic anchor. Ports `this.anchorMissing` in
/// `src/store/audit.js` (also the fields of `audit.anchor_missing`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorMissing {
    /// Where the log ends.
    pub found_seq: u64,
    /// Whether the vault was known to keep an anchor (tampering, not an
    /// upgrade).
    pub was_anchored: bool,
}

/// Unreadable lines found at open. Ports `this.corruption` in
/// `src/store/audit.js` (also the fields of `audit.corruption_detected`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corruption {
    /// The first 20 bad line numbers.
    pub lines: Vec<usize>,
    /// How many there are.
    pub count: usize,
}

/// What the vault knows about the log, kept in the vault rather than beside
/// the log so removing the anchor does not remove the knowledge that there
/// was one. Ports the `stamp` object `#anchorStamp` builds in
/// `src/store/vault.js` and `AuditLog` consumes in `src/store/audit.js`.
///
/// The vault implements this over its own storage (`VaultMeta`
/// `audit_anchored` and `vault_id`).
pub trait AnchorStamp: Send {
    /// Whether this vault is known to keep an anchor. Read live. Ports
    /// `stamp.anchored`.
    fn anchored(&self) -> bool;
    /// Record that it does (durably). Ports `stamp.markAnchored`.
    fn mark_anchored(&mut self) -> Result<()>;
    /// The vault's stable id, created and stored durably on first use. Ports
    /// `stamp.vaultId`.
    fn vault_id(&mut self) -> Result<Option<String>>;
}

/// Filter for [`AuditLog::read`]. Ports the options of
/// `AuditLog.prototype.read` in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFilter {
    /// Newest `limit` matching records. Default 100.
    pub limit: usize,
    /// `kind` itself or any `kind.*`.
    pub kind: Option<String>,
    /// Only this session's records.
    pub session_id: Option<String>,
    /// Only records with `ts >= since` (string compare, as the JS).
    pub since: Option<String>,
    /// Only this request's records.
    pub request_id: Option<String>,
}

impl Default for ReadFilter {
    /// Ports the defaults of `AuditLog.prototype.read` (`limit = 100`).
    fn default() -> Self {
        ReadFilter {
            limit: 100,
            kind: None,
            session_id: None,
            since: None,
            request_id: None,
        }
    }
}

/// The result of a chain walk. Field names as the JS returns them (note
/// `brokenAt`). Ports the objects `AuditLog.prototype.verify` returns in
/// `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Intact and anchored.
    pub ok: bool,
    /// Lines walked.
    pub count: u64,
    /// The first record (or line) that does not match.
    #[serde(rename = "brokenAt", default, skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<u64>,
    /// Why not ok, or why only partly provable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The head hash, when ok.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// For a pre-anchor vault: records before this seq are unanchored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unanchored_before: Option<u64>,
    /// A benign note (pre-anchor history).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Options for [`AuditLog::export`]. Ports the options of
/// `AuditLog.prototype.export` in `src/store/audit.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Records with seq above this. Default 0.
    pub since_seq: u64,
    /// Clamped to `1..=MAX_EXPORT_ROWS`. Default `MAX_EXPORT_ROWS`.
    pub limit: usize,
}

impl Default for ExportOptions {
    /// Ports the defaults of `AuditLog.prototype.export`.
    fn default() -> Self {
        ExportOptions {
            since_seq: 0,
            limit: MAX_EXPORT_ROWS,
        }
    }
}

/// Where the log has got to. Ports the `head` object in
/// `AuditLog.prototype.export` in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// Last seq.
    pub seq: u64,
    /// Last hash.
    pub hash: String,
}

/// One export page. Ports the return value of `AuditLog.prototype.export`
/// in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportPage {
    /// Records, chain fields and all.
    pub rows: Vec<AuditRecord>,
    /// Pass as `since_seq` for the next page.
    pub next_seq: u64,
    /// The head the page was read against.
    pub head: Head,
}

/// A witness checkpoint (F9). Ports the return value of
/// `AuditLog.prototype.checkpoint` in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessCheckpoint {
    /// The vault it belongs to.
    pub vault_id: String,
    /// Seq at issue.
    pub seq: u64,
    /// Head hash at issue.
    pub head: String,
    /// ISO time of issue.
    pub ts: String,
    /// `HMAC(K_audit, "witness|<vault_id>|<seq>|<head>|<ts>")`, hex.
    pub mac: String,
}

/// The result of checking witness checkpoints. Ports the `out` object of
/// `AuditLog.prototype.verifyWitness` in `src/store/audit.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WitnessReport {
    /// No forged, ahead or mismatched checkpoint.
    pub ok: bool,
    /// How many were checked.
    pub checked: usize,
    /// Seqs past the end of the log (it was cut back).
    pub ahead: Vec<u64>,
    /// Seqs whose record now has a different hash.
    pub mismatched: Vec<u64>,
    /// Indexes whose MAC (or shape) does not verify.
    pub forged: Vec<usize>,
    /// Indexes for another vault.
    pub other_vault: Vec<usize>,
}

/// The audit log. Holds `K_audit`; dropping it zeroizes the key (the JS
/// `crypt.wipe(this.audit.key)` in `Vault.prototype.lock`). Ports `class
/// AuditLog` in `src/store/audit.js`.
///
/// rust/PLAN.md, "Storage contract", allows the log to stay an append-only
/// file or move into the database; this type hides which.
#[allow(dead_code)] // scaffold: fields are read once the bodies exist
pub struct AuditLog {
    path: PathBuf,
    key: Key32,
    stamp: Option<Box<dyn AnchorStamp>>,
    seq: u64,
    prev_hash: String,
    since_checkpoint: u64,
    truncation: Option<Truncation>,
    anchor_missing: Option<AnchorMissing>,
    corruption: Option<Corruption>,
}

impl std::fmt::Debug for AuditLog {
    /// Redacted: never the key. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl AuditLog {
    /// Open (or create, mode 0600) the log at `path`, repair a torn tail,
    /// recover `seq`/`prev_hash`, compare with the anchor, and record any
    /// corruption, truncation or missing anchor into the chain at once.
    /// Ports the `AuditLog` constructor in `src/store/audit.js`.
    pub fn open(path: &Path, key: Key32, stamp: Option<Box<dyn AnchorStamp>>) -> Result<AuditLog> {
        todo!()
    }

    /// The log file. Ports `this.path` in `src/store/audit.js`.
    pub fn path(&self) -> &Path {
        todo!()
    }

    /// Last seq written. Ports `this.seq` in `src/store/audit.js`.
    pub fn seq(&self) -> u64 {
        todo!()
    }

    /// Last hash written. Ports the `head` getter in `src/store/audit.js`.
    pub fn head(&self) -> &str {
        todo!()
    }

    /// Set when the log came back shorter than the anchor. Ports
    /// `this.truncation` in `src/store/audit.js`.
    pub fn truncation(&self) -> Option<&Truncation> {
        todo!()
    }

    /// Set when a non-empty log had no authentic anchor. Ports
    /// `this.anchorMissing` in `src/store/audit.js`.
    pub fn anchor_missing(&self) -> Option<&AnchorMissing> {
        todo!()
    }

    /// Set when lines could not be read. Ports `this.corruption` in
    /// `src/store/audit.js`.
    pub fn corruption(&self) -> Option<&Corruption> {
        todo!()
    }

    /// Append one record: `fields` made recordable, refused (AV_INTERNAL) if
    /// it sets a chain field, then chained, appended, checkpointed every
    /// 1000, and anchored after the append. Ports `AuditLog.prototype.write`
    /// in `src/store/audit.js`.
    pub fn write(&mut self, kind: &str, fields: Map<String, Value>) -> Result<AuditRecord> {
        todo!()
    }

    /// Records, newest last, filtered. Ports `AuditLog.prototype.read` in
    /// `src/store/audit.js`.
    pub fn read(&self, filter: &ReadFilter) -> Result<Vec<AuditRecord>> {
        todo!()
    }

    /// Every line, as records or unreadable markers (for activity reports
    /// and migrate). Ports `#rows` in `src/store/audit.js`.
    pub fn rows(&self) -> Result<Vec<AuditRow>> {
        todo!()
    }

    /// Recompute the whole chain and compare with the anchor and the
    /// recorded findings. MACs compared in constant time. Ports
    /// `AuditLog.prototype.verify` in `src/store/audit.js`.
    pub fn verify(&self) -> Result<VerifyReport> {
        todo!()
    }

    /// A page of the log as on disk; records `audit.exported` after reading.
    /// Ports `AuditLog.prototype.export` in `src/store/audit.js`.
    pub fn export(&mut self, opts: ExportOptions) -> Result<ExportPage> {
        todo!()
    }

    /// Issue a witness checkpoint; records `audit.checkpoint_issued`. Ports
    /// `AuditLog.prototype.checkpoint` in `src/store/audit.js`.
    pub fn checkpoint(&mut self) -> Result<WitnessCheckpoint> {
        todo!()
    }

    /// Check witness checkpoints against the log on disk (shape-checked
    /// here, so each is raw JSON; MACs compared in constant time); records
    /// `audit.witness_verified`. Refuses more than
    /// [`MAX_WITNESS_CHECKPOINTS`]. Ports `AuditLog.prototype.verifyWitness`
    /// in `src/store/audit.js`.
    pub fn verify_witness(&mut self, checkpoints: &[Value]) -> Result<WitnessReport> {
        todo!()
    }
}

/// Whether a parsed line has the shape of a record. Ports `isRecord` in
/// `src/store/audit.js`.
pub fn is_record(row: &Value) -> bool {
    todo!()
}

/// Fields as the chain can hold them: a non-integer number becomes its
/// decimal string; integers, strings, booleans and null pass unchanged; an
/// undefined (absent) array slot becomes null. Ports `recordable` in
/// `src/store/audit.js`.
pub fn recordable(value: &Value) -> Value {
    todo!()
}

/// The chain hash of `record` given the previous hash. Ports `#hash` in
/// `src/store/audit.js` (canonical form via av-core `canon`).
pub fn record_hash(key: &Key32, record: &AuditRecord, prev_hash: &str) -> String {
    todo!()
}
