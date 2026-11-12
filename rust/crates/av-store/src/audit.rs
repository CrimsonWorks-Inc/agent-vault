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
use std::sync::{Arc, Mutex};

use av_core::secret::Key32;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto;
use crate::error::{Error, Result};
use crate::util;
use av_core::{deny, DenyExtra, ErrorCode};

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

/// The vault's connection, shared by the vault and its audit log so a change
/// and its record commit in one transaction.
pub(crate) type SharedConn = Arc<Mutex<rusqlite::Connection>>;

/// Lock a shared connection, surviving a poisoned mutex (a panic elsewhere
/// does not make the database unusable; SQLite rolled the transaction back).
pub(crate) fn lock_conn(conn: &SharedConn) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    conn.lock().unwrap_or_else(|e| e.into_inner())
}

/// The audit log. Holds `K_audit`; dropping it zeroizes the key (the JS
/// `crypt.wipe(this.audit.key)` in `Vault.prototype.lock`). Ports `class
/// AuditLog` in `src/store/audit.js`.
///
/// rust/PLAN.md, "Storage contract", allows the log to stay an append-only
/// file or move into the database. It lives in the `audit` table of
/// `vault.db` (insert-only triggers), so a vault change and its record commit
/// in one transaction. The authenticated head anchor stays a file beside the
/// database (`vault.db.head`), and the vault's stamp (`audit_anchored`) stays
/// in the vault, so the three are still in different places, as in the JS.
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
    conn: SharedConn,
    anchor_path: Option<PathBuf>,
    saved: Option<(u64, String, u64)>,
}

impl std::fmt::Debug for AuditLog {
    /// Redacted: never the key. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

const HEX64_LEN: usize = 64;

fn is_hex64(s: &str) -> bool {
    s.len() == HEX64_LEN && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn internal(e: impl std::fmt::Display) -> Error {
    Error::Invariant(e.to_string())
}

fn range_refusal(detail: String) -> Error {
    deny(
        ErrorCode::PolicyDenied,
        detail,
        DenyExtra {
            rule: Some("audit_range".into()),
            ..Default::default()
        },
    )
    .into()
}

impl AuditLog {
    /// Open (or create, mode 0600) the log at `path`, repair a torn tail,
    /// recover `seq`/`prev_hash`, compare with the anchor, and record any
    /// corruption, truncation or missing anchor into the chain at once.
    /// Ports the `AuditLog` constructor in `src/store/audit.js`.
    ///
    /// `path` is the vault database (`vault.db`); the anchor is
    /// `<path>.head`. (A database has no torn tail: a write is a transaction.)
    pub fn open(path: &Path, key: Key32, stamp: Option<Box<dyn AnchorStamp>>) -> Result<AuditLog> {
        let conn = crate::db::open(path)?;
        Self::open_shared(Arc::new(Mutex::new(conn)), path, key, stamp)
    }

    /// Open over a connection the vault already holds. Must not be called
    /// while that connection's mutex is held.
    pub(crate) fn open_shared(
        conn: SharedConn,
        path: &Path,
        key: Key32,
        stamp: Option<Box<dyn AnchorStamp>>,
    ) -> Result<AuditLog> {
        let anchor_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(ANCHOR_SUFFIX);
            PathBuf::from(p)
        };
        let mut log = AuditLog {
            path: path.to_path_buf(),
            key,
            stamp,
            seq: 0,
            prev_hash: GENESIS.to_string(),
            since_checkpoint: 0,
            truncation: None,
            anchor_missing: None,
            corruption: None,
            conn,
            anchor_path: Some(anchor_path),
            saved: None,
        };
        log.recover()?;
        // Recorded into the chain itself, at once: the next write moves the
        // anchor and would otherwise destroy the only evidence.
        if let Some(c) = log.corruption.clone() {
            log.write("audit.corruption_detected", to_map(&c)?)?;
        }
        if let Some(t) = log.truncation.clone() {
            log.write("audit.truncation_detected", to_map(&t)?)?;
        } else if let Some(m) = log.anchor_missing.clone() {
            log.write("audit.anchor_missing", to_map(&m)?)?;
        } else if log.corruption.is_none() {
            log.anchor()?;
        }
        // From here on this vault is known to keep an anchor.
        if let Some(stamp) = log.stamp.as_mut() {
            stamp.mark_anchored()?;
        }
        Ok(log)
    }

    /// The log file. Ports `this.path` in `src/store/audit.js`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Last seq written. Ports `this.seq` in `src/store/audit.js`.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Last hash written. Ports the `head` getter in `src/store/audit.js`.
    pub fn head(&self) -> &str {
        &self.prev_hash
    }

    /// Set when the log came back shorter than the anchor. Ports
    /// `this.truncation` in `src/store/audit.js`.
    pub fn truncation(&self) -> Option<&Truncation> {
        self.truncation.as_ref()
    }

    /// Set when a non-empty log had no authentic anchor. Ports
    /// `this.anchorMissing` in `src/store/audit.js`.
    pub fn anchor_missing(&self) -> Option<&AnchorMissing> {
        self.anchor_missing.as_ref()
    }

    /// Set when lines could not be read. Ports `this.corruption` in
    /// `src/store/audit.js`.
    pub fn corruption(&self) -> Option<&Corruption> {
        self.corruption.as_ref()
    }

    /// `HMAC(K_audit, "<seq>|<hash>")`.
    fn anchor_mac(&self, seq: u64, hash: &str) -> String {
        crypto::hex(&crypto::hmac_sha256(&self.key, format!("{seq}|{hash}").as_bytes()))
    }

    /// Write the anchor: a temp file renamed over the old one.
    fn anchor(&self) -> Result<()> {
        let Some(path) = &self.anchor_path else {
            return Ok(());
        };
        let body = Anchor {
            seq: self.seq,
            hash: self.prev_hash.clone(),
            mac: self.anchor_mac(self.seq, &self.prev_hash),
        };
        write_file_0600_atomic(path, serde_json::to_string(&body)?.as_bytes(), false)
    }

    /// The anchor, or none when absent or not authentic.
    fn read_anchor(&self) -> Option<Anchor> {
        let text = std::fs::read_to_string(self.anchor_path.as_ref()?).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        let seq = v.get("seq")?.as_u64()?;
        let hash = v.get("hash")?.as_str()?.to_string();
        let mac = v.get("mac")?.as_str()?.to_string();
        let want = self.anchor_mac(seq, &hash);
        crypto::constant_time_eq(mac.as_bytes(), want.as_bytes()).then_some(Anchor { seq, hash, mac })
    }

    fn recover(&mut self) -> Result<()> {
        let rows = self.rows()?;
        let unreadable: Vec<usize> = rows
            .iter()
            .filter_map(|r| match r {
                AuditRow::Unreadable { line } => Some(*line),
                _ => None,
            })
            .collect();
        if !unreadable.is_empty() {
            self.corruption = Some(Corruption {
                lines: unreadable.iter().take(20).copied().collect(),
                count: unreadable.len(),
            });
        }
        let last = rows.iter().rev().find_map(|r| match r {
            AuditRow::Record(r) => Some(r.clone()),
            _ => None,
        });
        let anchor = self.read_anchor();
        let anchored = self.stamp.as_ref().is_some_and(|s| s.anchored());
        let Some(last) = last else {
            if let Some(a) = anchor.as_ref().filter(|a| a.seq > 0) {
                self.truncation = Some(Truncation {
                    expected_seq: a.seq,
                    found_seq: 0,
                    expected_head: None,
                });
            } else if anchor.is_none() && anchored {
                self.anchor_missing = Some(AnchorMissing {
                    found_seq: 0,
                    was_anchored: true,
                });
            }
            return Ok(());
        };
        self.seq = last.seq;
        self.prev_hash = last.hash.clone();
        self.since_checkpoint = self.seq % CHECKPOINT_EVERY;
        match anchor {
            Some(a) if a.seq > last.seq => {
                self.truncation = Some(Truncation {
                    expected_seq: a.seq,
                    found_seq: last.seq,
                    expected_head: Some(a.hash),
                });
            }
            Some(_) => {}
            None => {
                self.anchor_missing = Some(AnchorMissing {
                    found_seq: last.seq,
                    was_anchored: anchored,
                });
            }
        }
        Ok(())
    }

    /// Append one record: `fields` made recordable, refused (AV_INTERNAL) if
    /// it sets a chain field, then chained, appended, checkpointed every
    /// 1000, and anchored after the append. Ports `AuditLog.prototype.write`
    /// in `src/store/audit.js`.
    pub fn write(&mut self, kind: &str, fields: Map<String, Value>) -> Result<AuditRecord> {
        let conn = Arc::clone(&self.conn);
        let mut guard = lock_conn(&conn);
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        self.begin();
        let out = self.write_in(&tx, kind, fields);
        match out {
            Ok(rec) => match tx.commit() {
                Ok(()) => {
                    self.finish()?;
                    Ok(rec)
                }
                Err(e) => {
                    self.rollback();
                    Err(e.into())
                }
            },
            Err(e) => {
                drop(tx);
                self.rollback();
                Err(e)
            }
        }
    }

    /// Remember where the chain is, before a transaction that may write.
    pub(crate) fn begin(&mut self) {
        self.saved = Some((self.seq, self.prev_hash.clone(), self.since_checkpoint));
    }

    /// The transaction rolled back: forget what it wrote.
    pub(crate) fn rollback(&mut self) {
        if let Some((seq, prev, since)) = self.saved.take() {
            self.seq = seq;
            self.prev_hash = prev;
            self.since_checkpoint = since;
        }
    }

    /// The transaction committed: move the anchor to the new head. After the
    /// commit, never before, so a crash in between leaves the anchor behind
    /// (benign) rather than ahead (a false truncation).
    pub(crate) fn finish(&mut self) -> Result<()> {
        let moved = self
            .saved
            .take()
            .is_none_or(|(seq, _, _)| seq != self.seq);
        if moved {
            self.anchor()?;
        }
        Ok(())
    }

    /// Append inside a transaction the caller commits.
    pub(crate) fn write_in(
        &mut self,
        conn: &rusqlite::Connection,
        kind: &str,
        fields: Map<String, Value>,
    ) -> Result<AuditRecord> {
        let own = match recordable(&Value::Object(fields)) {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        if let Some(reserved) = CHAIN_FIELDS.iter().find(|k| own.contains_key(**k)) {
            return Err(deny(
                ErrorCode::Internal,
                format!("audit record {kind} sets the chain field {reserved}; name it something else"),
                DenyExtra::default(),
            )
            .into());
        }
        let mut record = AuditRecord {
            seq: self.seq + 1,
            ts: util::now_iso(),
            kind: kind.to_string(),
            fields: own,
            prev_hash: self.prev_hash.clone(),
            hash: String::new(),
        };
        record.hash = record_hash(&self.key, &record, &self.prev_hash);
        insert_record(conn, &record)?;
        self.seq = record.seq;
        self.prev_hash = record.hash.clone();
        self.since_checkpoint += 1;
        if self.since_checkpoint >= CHECKPOINT_EVERY {
            self.since_checkpoint = 0;
            let mut fields = Map::new();
            fields.insert(
                "mac".into(),
                Value::from(crypto::hex(&crypto::hmac_sha256(&self.key, self.prev_hash.as_bytes()))),
            );
            let mut cp = AuditRecord {
                seq: self.seq + 1,
                ts: util::now_iso(),
                kind: "checkpoint".into(),
                fields,
                prev_hash: self.prev_hash.clone(),
                hash: String::new(),
            };
            cp.hash = record_hash(&self.key, &cp, &self.prev_hash);
            insert_record(conn, &cp)?;
            self.seq = cp.seq;
            self.prev_hash = cp.hash;
        }
        Ok(record)
    }

    /// Records, newest last, filtered. Ports `AuditLog.prototype.read` in
    /// `src/store/audit.js`.
    pub fn read(&self, filter: &ReadFilter) -> Result<Vec<AuditRecord>> {
        let field = |r: &AuditRecord, k: &str| r.fields.get(k).cloned();
        let rows: Vec<AuditRecord> = self
            .rows()?
            .into_iter()
            .filter_map(|r| match r {
                AuditRow::Record(r) => Some(r),
                _ => None,
            })
            .filter(|r| {
                filter
                    .request_id
                    .as_ref()
                    .is_none_or(|id| field(r, "request_id") == Some(Value::from(id.clone())))
            })
            .filter(|r| {
                filter.kind.as_ref().filter(|k| !k.is_empty()).is_none_or(|k| {
                    r.kind == *k || r.kind.starts_with(&format!("{k}."))
                })
            })
            .filter(|r| {
                filter
                    .session_id
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .is_none_or(|s| field(r, "session_id") == Some(Value::from(s.clone())))
            })
            .filter(|r| {
                filter
                    .since
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .is_none_or(|s| r.ts.as_str() >= s.as_str())
            })
            .collect();
        // `slice(-limit)`: a limit of 0 is `slice(0)`, every row.
        let skip = if filter.limit == 0 {
            0
        } else {
            rows.len().saturating_sub(filter.limit)
        };
        Ok(rows.into_iter().skip(skip).collect())
    }

    /// Every line, as records or unreadable markers (for activity reports
    /// and migrate). Ports `#rows` in `src/store/audit.js`.
    pub fn rows(&self) -> Result<Vec<AuditRow>> {
        let conn = lock_conn(&self.conn);
        read_rows(&conn)
    }

    /// Recompute the whole chain and compare with the anchor and the
    /// recorded findings. MACs compared in constant time. Ports
    /// `AuditLog.prototype.verify` in `src/store/audit.js`.
    pub fn verify(&self) -> Result<VerifyReport> {
        let rows = self.rows()?;
        let anchor = self.read_anchor();
        Ok(verify_rows(&self.key, &rows, anchor.as_ref()))
    }

    /// A page of the log as on disk; records `audit.exported` after reading.
    /// Ports `AuditLog.prototype.export` in `src/store/audit.js`.
    pub fn export(&mut self, opts: ExportOptions) -> Result<ExportPage> {
        if opts.since_seq > av_core::policy::MAX_SAFE_INTEGER {
            return Err(range_refusal(
                "since_seq must be a whole number, 0 or more".into(),
            ));
        }
        let take = opts.limit.clamp(1, MAX_EXPORT_ROWS);
        let rows: Vec<AuditRecord> = self
            .rows()?
            .into_iter()
            .filter_map(|r| match r {
                AuditRow::Record(r) if r.seq > opts.since_seq => Some(r),
                _ => None,
            })
            .take(take)
            .collect();
        let head = Head {
            seq: self.seq,
            hash: self.prev_hash.clone(),
        };
        let next_seq = rows.last().map_or(opts.since_seq, |r| r.seq);
        let mut f = Map::new();
        f.insert("from_seq".into(), rows.first().map_or(Value::Null, |r| r.seq.into()));
        f.insert(
            "to_seq".into(),
            if rows.is_empty() { Value::Null } else { next_seq.into() },
        );
        f.insert("rows".into(), rows.len().into());
        self.write("audit.exported", f)?;
        Ok(ExportPage {
            rows,
            next_seq,
            head,
        })
    }

    /// Issue a witness checkpoint; records `audit.checkpoint_issued`. Ports
    /// `AuditLog.prototype.checkpoint` in `src/store/audit.js`.
    pub fn checkpoint(&mut self) -> Result<WitnessCheckpoint> {
        let vault_id = self.vault_id()?;
        let seq = self.seq;
        let head = self.prev_hash.clone();
        let ts = util::now_iso();
        let mac = self.witness_mac(&vault_id, seq, &head, &ts);
        let mut f = Map::new();
        f.insert("checkpoint_seq".into(), seq.into());
        self.write("audit.checkpoint_issued", f)?;
        Ok(WitnessCheckpoint {
            vault_id,
            seq,
            head,
            ts,
            mac,
        })
    }

    /// Check witness checkpoints against the log on disk (shape-checked
    /// here, so each is raw JSON; MACs compared in constant time); records
    /// `audit.witness_verified`. Refuses more than
    /// [`MAX_WITNESS_CHECKPOINTS`]. Ports `AuditLog.prototype.verifyWitness`
    /// in `src/store/audit.js`.
    pub fn verify_witness(&mut self, checkpoints: &[Value]) -> Result<WitnessReport> {
        if checkpoints.len() > MAX_WITNESS_CHECKPOINTS {
            return Err(range_refusal(format!(
                "checkpoints must be a list of at most {MAX_WITNESS_CHECKPOINTS}"
            )));
        }
        let vault_id = self.vault_id()?;
        let mut hash_at = std::collections::HashMap::new();
        hash_at.insert(0u64, GENESIS.to_string());
        let mut last = 0u64;
        for r in self.rows()? {
            if let AuditRow::Record(r) = r {
                last = last.max(r.seq);
                hash_at.insert(r.seq, r.hash);
            }
        }
        let mut out = WitnessReport {
            ok: true,
            checked: checkpoints.len(),
            ..Default::default()
        };
        for (i, c) in checkpoints.iter().enumerate() {
            let shaped = (|| {
                let vid = c.get("vault_id")?.as_str()?;
                let seq = c.get("seq")?.as_u64()?;
                if seq > av_core::policy::MAX_SAFE_INTEGER {
                    return None;
                }
                let head = c.get("head")?.as_str().filter(|h| is_hex64(h))?;
                let ts = c.get("ts")?.as_str()?;
                let mac = c.get("mac")?.as_str().filter(|m| is_hex64(m))?;
                Some((vid, seq, head, ts, mac))
            })();
            let Some((vid, seq, head, ts, mac)) = shaped else {
                out.forged.push(i);
                continue;
            };
            let want = self.witness_mac(vid, seq, head, ts);
            if !crypto::constant_time_eq(mac.as_bytes(), want.as_bytes()) {
                out.forged.push(i);
            } else if vid != vault_id {
                out.other_vault.push(i);
            } else if seq > last {
                out.ahead.push(seq);
            } else if hash_at.get(&seq).map(String::as_str) != Some(head) {
                out.mismatched.push(seq);
            }
        }
        out.ok = out.forged.is_empty() && out.ahead.is_empty() && out.mismatched.is_empty();
        let mut f = Map::new();
        f.insert("ok".into(), out.ok.into());
        f.insert("checked".into(), out.checked.into());
        f.insert("ahead".into(), out.ahead.len().into());
        f.insert("mismatched".into(), out.mismatched.len().into());
        f.insert("forged".into(), out.forged.len().into());
        self.write("audit.witness_verified", f)?;
        Ok(out)
    }

    fn witness_mac(&self, vault_id: &str, seq: u64, head: &str, ts: &str) -> String {
        crypto::hex(&crypto::hmac_sha256(
            &self.key,
            format!("witness|{vault_id}|{seq}|{head}|{ts}").as_bytes(),
        ))
    }

    fn vault_id(&mut self) -> Result<String> {
        let id = match self.stamp.as_mut() {
            Some(s) => s.vault_id()?,
            None => None,
        };
        id.filter(|s| !s.is_empty()).ok_or_else(|| {
            Error::Invariant("this audit log belongs to no vault id, so it cannot be witnessed".into())
        })
    }
}

fn to_map<T: Serialize>(v: &T) -> Result<Map<String, Value>> {
    match serde_json::to_value(v)? {
        Value::Object(m) => Ok(m),
        _ => Ok(Map::new()),
    }
}

/// Insert one record row. The `record` column is the line as the JS would
/// have written it.
pub(crate) fn insert_record(conn: &rusqlite::Connection, record: &AuditRecord) -> Result<()> {
    let line = serde_json::to_string(record)?;
    insert_line(conn, record.seq, &record.ts, &record.kind, &record.prev_hash, &record.hash, &line)
}

/// Insert one line exactly as given (migrate imports the JS log unchanged).
pub(crate) fn insert_line(
    conn: &rusqlite::Connection,
    seq: u64,
    ts: &str,
    kind: &str,
    prev_hash: &str,
    hash: &str,
    line: &str,
) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO audit (seq, ts, kind, prev_hash, hash, record) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(rusqlite::params![seq as i64, ts, kind, prev_hash, hash, line])?;
    Ok(())
}

/// Every row of the `audit` table, in seq order, as records or unreadable
/// markers.
pub(crate) fn read_rows(conn: &rusqlite::Connection) -> Result<Vec<AuditRow>> {
    let mut stmt = conn.prepare_cached("SELECT record FROM audit ORDER BY seq")?;
    let lines = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(parse_lines(lines.iter().map(String::as_str)))
}

/// Lines of a JS `audit.jsonl` (or the table's `record` column) as rows.
/// Ports `#rows` in `src/store/audit.js`: an unparseable last line is a torn
/// write and is dropped, anything else unreadable is reported.
pub(crate) fn parse_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<AuditRow> {
    let mut lines: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    if let Some(last) = lines.last() {
        if serde_json::from_str::<Value>(last).is_err() {
            lines.pop();
        }
    }
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str::<Value>(l)
                .ok()
                .filter(is_record)
                .and_then(|v| serde_json::from_value::<AuditRecord>(v).ok())
                .map_or(AuditRow::Unreadable { line: i + 1 }, AuditRow::Record)
        })
        .collect()
}

/// The chain walk and anchor comparison of `AuditLog.prototype.verify`, over
/// rows already read. Shared with migrate, which verifies the JS log before
/// it imports it.
pub(crate) fn verify_rows(key: &Key32, rows: &[AuditRow], anchor: Option<&Anchor>) -> VerifyReport {
    let count = rows.len() as u64;
    let fail = |broken_at: Option<u64>, reason: String| VerifyReport {
        ok: false,
        count,
        broken_at,
        reason: Some(reason),
        ..Default::default()
    };
    let mut prev = GENESIS.to_string();
    let mut records = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let AuditRow::Record(r) = row else {
            return fail(Some(i as u64 + 1), "unreadable record".into());
        };
        if r.prev_hash != prev {
            return fail(Some(r.seq), "prev_hash mismatch".into());
        }
        let expected = record_hash(key, r, &prev);
        if !crypto::constant_time_eq(expected.as_bytes(), r.hash.as_bytes()) {
            return fail(Some(r.seq), "hash mismatch".into());
        }
        if r.seq != i as u64 + 1 {
            return fail(Some(r.seq), "sequence gap".into());
        }
        prev = r.hash.clone();
        records.push(r);
    }
    let Some(anchor) = anchor else {
        return fail(
            None,
            if count > 0 {
                "the head anchor is missing or not authentic, so the end of the log cannot be trusted"
            } else {
                "the head anchor is missing"
            }
            .into(),
        );
    };
    if anchor.seq > count {
        return fail(
            Some(count + 1),
            format!(
                "the log ends at record {count} but should end at {}: {} record(s) were removed from the end",
                anchor.seq,
                anchor.seq - count
            ),
        );
    }
    if anchor.seq == count && anchor.hash != prev {
        return fail(
            Some(anchor.seq),
            "the last record does not match the head anchor".into(),
        );
    }
    let num = |r: &AuditRecord, k: &str| match r.fields.get(k) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "undefined".into(),
    };
    if let Some(cut) = records.iter().find(|r| r.kind == "audit.truncation_detected") {
        return fail(
            Some(cut.seq),
            format!(
                "records were removed from the end: the log restarted at {} where it should have been at {}",
                num(cut, "found_seq"),
                num(cut, "expected_seq")
            ),
        );
    }
    let was = |r: &AuditRecord| r.fields.get("was_anchored").is_some_and(truthy);
    let absences: Vec<&AuditRecord> = records
        .iter()
        .copied()
        .filter(|r| r.kind == "audit.anchor_missing")
        .collect();
    let no_anchor = absences
        .iter()
        .copied()
        .find(|r| was(r))
        .or(absences.first().copied());
    if let Some(n) = no_anchor {
        if was(n) {
            return fail(
                Some(n.seq),
                format!(
                    "the head anchor was removed from a vault that kept one: at record {} the log was found without it, so records may have been removed from the end",
                    n.seq
                ),
            );
        }
        return VerifyReport {
            ok: true,
            count,
            head: Some(prev),
            unanchored_before: Some(n.seq),
            note: Some(format!(
                "the log had no head anchor when it was opened at record {}, so nothing proves how many records preceded that point; everything from there on is anchored",
                n.seq
            )),
            ..Default::default()
        };
    }
    VerifyReport {
        ok: true,
        count,
        head: Some(prev),
        ..Default::default()
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// Read and authenticate a JS anchor file (`audit.jsonl.head`) under `key`.
pub(crate) fn read_anchor_file(path: &Path, key: &Key32) -> Option<Anchor> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let seq = v.get("seq")?.as_u64()?;
    let hash = v.get("hash")?.as_str()?.to_string();
    let mac = v.get("mac")?.as_str()?.to_string();
    let want = crypto::hex(&crypto::hmac_sha256(key, format!("{seq}|{hash}").as_bytes()));
    crypto::constant_time_eq(mac.as_bytes(), want.as_bytes()).then_some(Anchor { seq, hash, mac })
}

/// Write the anchor body for `(seq, hash)` under `key` to `path`.
pub(crate) fn write_anchor_file(path: &Path, key: &Key32, seq: u64, hash: &str) -> Result<()> {
    let body = Anchor {
        seq,
        hash: hash.to_string(),
        mac: crypto::hex(&crypto::hmac_sha256(key, format!("{seq}|{hash}").as_bytes())),
    };
    write_file_0600_atomic(path, serde_json::to_string(&body)?.as_bytes(), true)
}

/// A temp file beside `path`, mode 0600, renamed over it.
pub(crate) fn write_file_0600_atomic(path: &Path, bytes: &[u8], durable: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(bytes)?;
    if durable {
        f.sync_all()?;
    }
    drop(f);
    std::fs::rename(&tmp, path).map_err(internal)?;
    Ok(())
}

/// Whether a parsed line has the shape of a record. Ports `isRecord` in
/// `src/store/audit.js`.
pub fn is_record(row: &Value) -> bool {
    let Value::Object(o) = row else {
        return false;
    };
    let seq_ok = o
        .get("seq")
        .and_then(Value::as_u64)
        .is_some_and(|s| (1..=av_core::policy::MAX_SAFE_INTEGER).contains(&s));
    seq_ok
        && o.get("ts").is_some_and(Value::is_string)
        && o.get("kind").is_some_and(Value::is_string)
        && o.get("hash").and_then(Value::as_str).is_some_and(is_hex64)
        && o.get("prev_hash").and_then(Value::as_str).is_some_and(is_hex64)
}

/// Fields as the chain can hold them: a non-integer number becomes its
/// decimal string; integers, strings, booleans and null pass unchanged; an
/// undefined (absent) array slot becomes null. Ports `recordable` in
/// `src/store/audit.js`.
pub fn recordable(value: &Value) -> Value {
    match value {
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                value.clone()
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                if f.fract() == 0.0 && f.abs() <= av_core::policy::MAX_SAFE_INTEGER as f64 {
                    Value::from(f as i64)
                } else {
                    Value::from(util::js_number_string(f))
                }
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(recordable).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), recordable(v))).collect()),
        other => other.clone(),
    }
}

/// The chain hash of `record` given the previous hash. Ports `#hash` in
/// `src/store/audit.js` (canonical form via av-core `canon`).
pub fn record_hash(key: &Key32, record: &AuditRecord, prev_hash: &str) -> String {
    let mut rest = record.fields.clone();
    rest.insert("seq".into(), record.seq.into());
    rest.insert("ts".into(), record.ts.clone().into());
    rest.insert("kind".into(), record.kind.clone().into());
    rest.insert("prev_hash".into(), record.prev_hash.clone().into());
    let Ok(canon) = av_core::canon::canonicalize(&Value::Object(rest)) else {
        // A record the canonical form cannot hold matches no hash.
        return String::new();
    };
    let msg = format!("{}|{}|{}|{}|{}", record.seq, record.ts, record.kind, canon, prev_hash);
    crypto::hex(&crypto::hmac_sha256(key, msg.as_bytes()))
}
