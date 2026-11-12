//! The library behind `agent-vault migrate` (rust/PLAN.md, "`agent-vault
//! migrate`"): converts a JS vault (`vault.json`, the device key and the audit
//! log) into `vault.db`, keeping the same VMK and every id. The CLI owns the
//! command, prompting and output; this module owns the steps.
//!
//! No JS source: new in the Rust port. It reads the formats written by
//! `src/store/vault.js`, `src/store/crypto.js` and `src/store/audit.js`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use av_core::secret::{ExposeSecret, Key32, SecretString};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::audit::{self, AuditLog, AuditRow};
use crate::crypto::{self, SealedV1, SealedV2};
use crate::error::{CryptoError, Error};
use crate::model::{
    CredentialField, CredentialRecord, FactorClass, FactorState, LegacyDocument, NotifyRecord,
    PresenceFactor, RetiredValue, SessionState, VmkWrap,
};
use crate::rows;
use crate::util;
use crate::vault::{
    assert_factor_invariant, AUDIT_FILE, DEVICE_KEY_FILE, LEGACY_VAULT_FILE, SCHEMA_VERSION,
    VAULT_DB_FILE,
};

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
    if opts.to.join(VAULT_DB_FILE).exists() {
        return Err(MigrateError::AlreadyMigrated(opts.to.clone()));
    }
    if js_daemon_running(&opts.from) {
        return Err(MigrateError::DaemonRunning {
            dir: opts.from.clone(),
            next: "stop the daemon first (installed: sudo launchctl bootout system/com.agentvault.daemon; dev: stop the `agent-vault daemon` process), then run agent-vault migrate again".into(),
        });
    }
    Ok(())
}

/// Whether a JS daemon is serving the vault at `dir` (its control socket
/// answers). No JS source; mirrors how `src/cli/index.js` finds the socket.
pub fn js_daemon_running(dir: &Path) -> bool {
    // A dev vault keeps its socket in the vault dir; the installed one keeps
    // it in `<root>/run` beside `<root>/vault`.
    let mut candidates = vec![dir.join("control.sock")];
    if let Some(root) = dir.parent() {
        candidates.push(root.join("run").join("control.sock"));
    }
    candidates
        .iter()
        .any(|p| std::os::unix::net::UnixStream::connect(p).is_ok())
}

fn broken(at: impl Into<String>, reason: impl Into<String>) -> MigrateError {
    MigrateError::AuditBroken {
        at: at.into(),
        reason: reason.into(),
    }
}

/// The audit file's anchor (`audit.jsonl.head`).
fn anchor_path(from: &Path) -> PathBuf {
    from.join(format!("{AUDIT_FILE}{}", audit::ANCHOR_SUFFIX))
}

/// Step 3: read `vault.json`, the device key and the audit log from `from`,
/// and verify the audit chain and anchor (as `AuditLog.verify` in
/// `src/store/audit.js` does). No JS source.
///
/// The chain's MACs are keyed from the VMK, which needs the unlock of step
/// 4, so this checks what it can without a key (every line readable, each
/// `prev_hash` the previous `hash`, no sequence gap); [`migrate`] checks every
/// MAC and the anchor before it writes anything.
pub fn read_legacy(from: &Path) -> Result<LegacyVault, MigrateError> {
    let json_path = from.join(LEGACY_VAULT_FILE);
    let text = match std::fs::read_to_string(&json_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(MigrateError::NoLegacyVault(from.to_path_buf()))
        }
        Err(e) => return Err(Error::from(e).into()),
    };
    let document: LegacyDocument = serde_json::from_str(&text).map_err(Error::from)?;
    if document.schema_version > SCHEMA_VERSION {
        return Err(Error::Invariant(format!(
            "vault schema {} is newer than this build ({SCHEMA_VERSION}); upgrade agent-vault",
            document.schema_version
        ))
        .into());
    }
    let key_path = from.join(DEVICE_KEY_FILE);
    let raw = Zeroizing::new(std::fs::read(&key_path).map_err(Error::from)?);
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invariant("the device key is not 32 bytes".into()))?;
    let device_key = Key32::from_bytes(arr);
    let audit_path = from.join(AUDIT_FILE);
    let audit_text = match std::fs::read_to_string(&audit_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::from(e).into()),
    };
    let audit_lines: Vec<String> = audit_text
        .split('\n')
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let anchor_file = anchor_path(from);
    let audit_anchor = std::fs::read_to_string(&anchor_file).ok();
    // The structure of the chain, without its key.
    let rows = audit::parse_lines(audit_lines.iter().map(String::as_str));
    let mut prev = audit::GENESIS.to_string();
    for (i, row) in rows.iter().enumerate() {
        let AuditRow::Record(r) = row else {
            return Err(broken(format!("line {}", i + 1), "unreadable record"));
        };
        if r.prev_hash != prev {
            return Err(broken(format!("seq {}", r.seq), "prev_hash mismatch"));
        }
        if r.seq != i as u64 + 1 {
            return Err(broken(format!("seq {}", r.seq), "sequence gap"));
        }
        prev = r.hash.clone();
    }
    let mut files = vec![json_path, key_path];
    if audit_path.exists() {
        files.push(audit_path);
    }
    if anchor_file.exists() {
        files.push(anchor_file);
    }
    Ok(LegacyVault {
        document,
        device_key,
        audit_lines,
        audit_anchor,
        files,
    })
}

/// Whether unlocking `legacy` needs a passphrase (its wraps include a
/// `passphrase` class and no `none` class). The CLI prompts only then; the
/// passphrase is never an argument. No JS source.
pub fn needs_passphrase(legacy: &LegacyVault) -> bool {
    let wraps = &legacy.document.kv.vmk_wraps;
    wraps.iter().any(|w| w.class == FactorClass::Passphrase)
        && !wraps.iter().any(|w| w.class == FactorClass::None)
}

/// Open the JS VMK: the `none` wrap with the device key alone, else the
/// passphrase wrap (scrypt, as the JS derives it).
fn unlock_legacy(
    legacy: &LegacyVault,
    passphrase: Option<&SecretString>,
) -> Result<Key32, MigrateError> {
    let open = |wrap: &VmkWrap<SealedV1>, factor_key: &[u8]| -> Option<Key32> {
        let kek = crypto::derive_kek(&legacy.device_key, factor_key);
        let class = crate::vault::class_name(wrap.class);
        let bytes = crypto::open_v1(&kek, &wrap.sealed, &crypto::vmk_aad(class)).ok()?;
        let text = Zeroizing::new(bytes.expose_secret().to_vec());
        let raw = Zeroizing::new(crypto::b64_decode(std::str::from_utf8(&text).ok()?)?);
        let arr: [u8; 32] = raw.as_slice().try_into().ok()?;
        Some(Key32::from_bytes(arr))
    };
    for wrap in &legacy.document.kv.vmk_wraps {
        if wrap.class == FactorClass::None {
            if let Some(k) = open(wrap, &[]) {
                return Ok(k);
            }
        }
    }
    let pass_wrap = legacy
        .document
        .kv
        .vmk_wraps
        .iter()
        .find(|w| w.class == FactorClass::Passphrase);
    match (pass_wrap, passphrase) {
        (Some(_), None) => Err(MigrateError::PassphraseRequired),
        (Some(w), Some(p)) => {
            let salt = w
                .salt
                .as_deref()
                .and_then(crypto::b64_decode)
                .ok_or(MigrateError::WrongPassphrase)?;
            let fk = crypto::passphrase_factor_v1(p, &salt).map_err(MigrateError::Store)?;
            open(w, fk.expose()).ok_or(MigrateError::WrongPassphrase)
        }
        (None, _) => Err(MigrateError::WrongPassphrase),
    }
}

fn reseal(key: &Key32, sealed: &SealedV1, aad: &str) -> Result<SealedV2, Error> {
    let plain = crypto::open_v1(key, sealed, aad)?;
    crypto::seal(key, plain.expose_secret(), aad)
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
    if opts.to.join(VAULT_DB_FILE).exists() {
        return Err(MigrateError::AlreadyMigrated(opts.to.clone()));
    }
    // Step 4: the same VMK.
    let vmk = unlock_legacy(&legacy, passphrase)?;
    let k_audit = crypto::k_audit(&vmk);

    // Step 3, keyed: every MAC and the anchor, before anything is written.
    let rows = audit::parse_lines(legacy.audit_lines.iter().map(String::as_str));
    let anchor = legacy.audit_anchor.as_ref().and_then(|text| {
        let dir = tempfile_anchor(text)?;
        audit::read_anchor_file(&dir.1, &k_audit)
    });
    let report = audit::verify_rows(&k_audit, &rows, anchor.as_ref());
    if !report.ok {
        let at = report
            .broken_at
            .map_or_else(|| "the head anchor".to_string(), |s| format!("seq {s}"));
        return Err(broken(
            at,
            report.reason.unwrap_or_else(|| "does not verify".into()),
        ));
    }
    let records: Vec<audit::AuditRecord> = rows
        .into_iter()
        .filter_map(|r| match r {
            AuditRow::Record(r) => Some(r),
            AuditRow::Unreadable { .. } => None,
        })
        .collect();
    let old_head = records.last().map(|r| r.hash.clone());
    let last_seq = records.last().map_or(0, |r| r.seq);

    let doc = &legacy.document;
    let now = util::now_iso();

    // Step 5: re-wrap under Argon2id; a PRF wrap cannot come along.
    let mut dropped = Vec::new();
    let mut wraps: Vec<VmkWrap> = Vec::new();
    let mut prev_state_wraps: Vec<VmkWrap> = Vec::new();
    for w in &doc.kv.vmk_wraps {
        let stub = VmkWrap {
            class: w.class,
            salt: w.salt.clone(),
            kdf: (w.class == FactorClass::Passphrase).then(crate::vault::passphrase_params),
            sealed: SealedV2 {
                v: crypto::SEALED_V2,
                alg: crypto::V2_ALG.into(),
                n: String::new(),
                c: String::new(),
            },
            credential_id: w.credential_id.clone(),
        };
        prev_state_wraps.push(stub);
        match w.class {
            FactorClass::None => wraps.push(new_wrap(&legacy.device_key, &vmk, None)?),
            FactorClass::Passphrase => {
                let p = passphrase.ok_or(MigrateError::PassphraseRequired)?;
                wraps.push(new_wrap(&legacy.device_key, &vmk, Some(p))?);
            }
            FactorClass::WebauthnPrf => dropped.push(Dropped {
                what: "webauthn-prf unlock wrap".into(),
                why: "a Touch ID unlock is sealed under a secret only the authenticator can produce, so it cannot be re-wrapped; the passphrase is kept".into(),
                next: "agent-vault ui".into(),
            }),
        }
    }
    assert_factor_invariant(
        &FactorState {
            vmk_wraps: prev_state_wraps,
            webauthn: doc.kv.webauthn.clone(),
        },
        &FactorState {
            vmk_wraps: wraps.clone(),
            webauthn: doc.kv.webauthn.clone(),
        },
    )?;

    // Step 5: every sealed value as v2, under the same keys and AADs.
    let mut credentials: Vec<CredentialRecord> = Vec::new();
    for c in doc.credentials.values() {
        let key = crypto::dek(&vmk, &c.id);
        let mut fields = Vec::new();
        for f in &c.fields {
            let aad = crypto::field_aad(&c.id, &f.name, f.key_version);
            let mut retired = Vec::new();
            for r in &f.retired {
                retired.push(RetiredValue {
                    sealed: reseal(
                        &key,
                        &r.sealed,
                        &crypto::field_aad(&c.id, &f.name, r.key_version),
                    )?,
                    key_version: r.key_version,
                    retired_at: r.retired_at.clone(),
                    retire_until: r.retire_until.clone(),
                });
            }
            fields.push(CredentialField {
                name: f.name.clone(),
                sealed: reseal(&key, &f.sealed, &aad)?,
                key_version: f.key_version,
                sites: f.sites.clone(),
                fp8: f.fp8.clone(),
                length: f.length,
                rotated_at: f.rotated_at.clone(),
                retired,
            });
        }
        credentials.push(CredentialRecord {
            id: c.id.clone(),
            slug: c.slug.clone(),
            connector_kind: c.connector_kind.clone(),
            connector: c.connector.clone(),
            fields,
            created_at: c.created_at.clone(),
            expires_at: c.expires_at.clone(),
            health: c.health.clone(),
            quarantine: c.quarantine.clone(),
            scrub_patterns: c.scrub_patterns.clone(),
            pins: c.pins.clone(),
        });
    }
    let notify = match &doc.kv.notify {
        None => None,
        Some(n) => Some(NotifyRecord {
            sealed: reseal(
                &crypto::dek(&vmk, crypto::NOTIFY_DEK_ID),
                &n.sealed,
                crypto::NOTIFY_AAD,
            )?,
            host: n.host.clone(),
            detail: n.detail,
            configured_at: n.configured_at.clone(),
        }),
    };

    // Counts for the report.
    let mut counts = BTreeMap::new();
    let mut put = |k: &str, n: usize| {
        counts.insert(k.to_string(), n as u64);
    };
    put("credentials", credentials.len());
    put("sessions", doc.sessions.len());
    put("grants", doc.grants.len());
    put("placeholders", doc.placeholders.len());
    put("approvals", doc.approvals.len());
    put("workspaces", doc.workspaces.len());
    put("listeners", doc.listeners.len());
    put("templates", doc.templates.len());
    put("clients", doc.clients.len());
    put("settings", doc.kv.settings.len());
    put("presence_factors", doc.kv.presence_factors.len());
    put(
        "pins",
        credentials
            .iter()
            .map(|c| c.pins.values().map(Vec::len).sum::<usize>())
            .sum(),
    );
    put(
        "tripwires",
        doc.kv
            .settings
            .get("tripwires")
            .and_then(|t| t.get("rules"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    );
    put("notify", usize::from(notify.is_some()));
    put("session_requests", doc.kv.session_requests.len());
    put("audit_records", records.len());

    // Steps 6–8: one transaction into a new database.
    let to = &opts.to;
    let temp_path = to.join(format!(".{VAULT_DB_FILE}.migrating"));
    let conn = if opts.dry_run {
        crate::db::open_in_memory().map_err(Error::from)?
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(to)
            .map_err(Error::from)?;
        // A device key already at the target must be this vault's.
        let target_key = to.join(DEVICE_KEY_FILE);
        if target_key.exists() {
            let have = Zeroizing::new(std::fs::read(&target_key).map_err(Error::from)?);
            if !crypto::constant_time_eq(&have, legacy.device_key.expose()) {
                return Err(Error::Invariant(format!(
                    "{} holds a different device key; migrate into an empty directory",
                    to.display()
                ))
                .into());
            }
        }
        remove_temp(&temp_path);
        crate::db::open(&temp_path).map_err(Error::from)?
    };
    let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
    let outcome = (|| -> Result<(u64, String), Error> {
        let mut guard = audit::lock_conn(&shared);
        let tx = guard
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(Error::from)?;
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")
            .map_err(Error::from)?;
        write_entities(&tx, doc, &credentials, &wraps, notify.as_ref(), &now)?;
        // Step 7: the JS log, line for line, then `vault.migrated`.
        for (line, r) in legacy.audit_lines.iter().zip(records.iter()) {
            audit::insert_line(&tx, r.seq, &r.ts, &r.kind, &r.prev_hash, &r.hash, line)?;
        }
        let mut log = AuditLog::detached(
            std::sync::Arc::clone(&shared),
            &to.join(VAULT_DB_FILE),
            k_audit.clone(),
            last_seq,
            old_head
                .clone()
                .unwrap_or_else(|| audit::GENESIS.to_string()),
        );
        let fields = json!({
            "from": LEGACY_VAULT_FILE,
            "to": VAULT_DB_FILE,
            "from_schema_version": doc.schema_version,
            "records_imported": records.len(),
            "dropped": dropped.iter().map(|d| d.what.clone()).collect::<Vec<_>>(),
        });
        let rec = log.write_in(&tx, "vault.migrated", obj(fields))?;
        debug_assert_eq!(
            rec.prev_hash,
            old_head
                .clone()
                .unwrap_or_else(|| audit::GENESIS.to_string())
        );
        let (seq, head) = (log.seq(), log.head().to_string());
        tx.commit().map_err(Error::from)?;
        crate::vault::checkpoint_truncate(&guard)?;
        Ok((seq, head))
    })();
    drop(shared);
    // A migration that failed leaves no half-written database behind.
    let (new_seq, new_head) = match outcome {
        Ok(v) => v,
        Err(e) => {
            if !opts.dry_run {
                remove_temp(&temp_path);
            }
            return Err(e.into());
        }
    };

    let mut written = None;
    if !opts.dry_run {
        // Step 8: the anchor and the device key first, then the rename that
        // makes vault.db exist.
        let anchor_new = to.join(format!("{VAULT_DB_FILE}{}", audit::ANCHOR_SUFFIX));
        audit::write_anchor_file(&anchor_new, &k_audit, new_seq, &new_head)?;
        let target_key = to.join(DEVICE_KEY_FILE);
        if !target_key.exists() {
            audit::write_file_0600_atomic(&target_key, legacy.device_key.expose(), true)?;
        }
        std::fs::File::open(&temp_path)
            .and_then(|f| f.sync_all())
            .map_err(Error::from)?;
        let final_path = to.join(VAULT_DB_FILE);
        std::fs::rename(&temp_path, &final_path).map_err(Error::from)?;
        if let Ok(d) = std::fs::File::open(to) {
            let _ = d.sync_all();
        }
        written = Some(final_path);
    }
    Ok(MigrateReport {
        already_migrated: false,
        dry_run: opts.dry_run,
        counts,
        audit_first_seq: records.first().map(|r| r.seq),
        audit_last_seq: records.last().map(|r| r.seq),
        audit_head: old_head,
        dropped,
        written,
        legacy_files: legacy.files.clone(),
    })
}

use std::os::unix::fs::DirBuilderExt as _;

/// Remove a temp database and its WAL and shared-memory files.
fn remove_temp(temp_path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut p = temp_path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

fn obj(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

/// The JS anchor text, authenticated: written to a private temp file only so
/// the one reader of anchor files reads it. Returns the dir guard and path.
fn tempfile_anchor(text: &str) -> Option<(TempDirGuard, PathBuf)> {
    let guard = TempDirGuard::new().ok()?;
    let path = guard.0.join("anchor");
    std::fs::write(&path, text).ok()?;
    Some((guard, path))
}

/// A private temp dir removed on drop.
struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new() -> std::io::Result<TempDirGuard> {
        let mut r = [0u8; 8];
        crypto::fill_random(&mut r).map_err(|_| std::io::Error::other("random source failed"))?;
        let p = std::env::temp_dir().join(format!("av-migrate-{}", crypto::hex(&r)));
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(TempDirGuard(p))
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn new_wrap(
    device_key: &Key32,
    vmk: &Key32,
    passphrase: Option<&SecretString>,
) -> Result<VmkWrap, Error> {
    let (class, factor_key, salt, kdf) = match passphrase {
        None => (FactorClass::None, Zeroizing::new(Vec::new()), None, None),
        Some(p) => {
            let mut salt = [0u8; crypto::SALT_LEN];
            crypto::fill_random(&mut salt)?;
            let params = crate::vault::passphrase_params();
            let k = crypto::passphrase_factor(p, &salt, &params)?;
            (
                FactorClass::Passphrase,
                Zeroizing::new(k.expose().to_vec()),
                Some(crypto::b64(&salt)),
                Some(params),
            )
        }
    };
    let kek = crypto::derive_kek(device_key, &factor_key);
    let text = Zeroizing::new(crypto::b64(vmk.expose()));
    let sealed = crypto::seal(
        &kek,
        text.as_bytes(),
        &crypto::vmk_aad(crate::vault::class_name(class)),
    )?;
    Ok(VmkWrap {
        class,
        salt,
        kdf,
        sealed,
        credential_id: None,
    })
}

/// Step 6: every entity, ids unchanged.
fn write_entities(
    c: &Connection,
    doc: &LegacyDocument,
    credentials: &[CredentialRecord],
    wraps: &[VmkWrap],
    notify: Option<&NotifyRecord>,
    now: &str,
) -> Result<(), Error> {
    let kv = &doc.kv;
    let meta = &kv.meta;
    rows::kv_set(
        c,
        "created_at",
        &json!(meta.created_at.clone().unwrap_or_else(|| now.to_string())),
    )?;
    rows::kv_set(c, "locked", &Value::Bool(meta.locked))?;
    // The new log is anchored (the anchor is written beside vault.db).
    rows::kv_set(c, "audit_anchored", &Value::Bool(true))?;
    if let Some(id) = &meta.vault_id {
        rows::kv_set(c, "vault_id", &json!(id))?;
    }
    if let Some(s) = &meta.prf_salt {
        rows::kv_set(c, "prf_salt", &json!(s))?;
    }
    if !meta.ui_origins.is_empty() {
        rows::kv_set(c, "ui_origins", &json!(meta.ui_origins))?;
    }
    for (k, v) in &kv.settings {
        rows::settings_put(c, k, v)?;
    }
    rows::wraps_replace(c, wraps, now)?;
    let factors: Vec<PresenceFactor> = {
        let mut out: Vec<PresenceFactor> = Vec::new();
        for w in wraps {
            if out.iter().any(|f| f.class == w.class) {
                continue;
            }
            out.push(
                kv.presence_factors
                    .iter()
                    .find(|f| f.class == w.class)
                    .cloned()
                    .unwrap_or(PresenceFactor {
                        class: w.class,
                        enrolled_at: now.to_string(),
                    }),
            );
        }
        out
    };
    rows::factors_replace(c, &factors)?;
    rows::webauthn_put(c, kv.webauthn.as_ref())?;
    rows::notify_put(c, notify)?;
    for w in doc.workspaces.values() {
        rows::workspace_insert(c, w)?;
    }
    for cred in credentials {
        rows::credential_insert(c, cred)?;
    }
    for s in doc.sessions.values() {
        // An ended session's end is dated now: the JS kept no date, and
        // pruning counts its retention from here.
        rows::session_put(c, s, now)?;
        let _ = SessionState::Active;
    }
    for g in doc.grants.values() {
        rows::grant_put(c, g)?;
    }
    for p in doc.placeholders.values() {
        rows::ph_insert(c, p)?;
    }
    for a in doc.approvals.values() {
        rows::approval_put(c, a)?;
    }
    for cl in doc.clients.values() {
        rows::client_put(c, cl)?;
    }
    for l in doc.listeners.values() {
        rows::listener_put(c, l)?;
    }
    for t in doc.templates.values() {
        rows::template_put(c, t)?;
    }
    rows::session_requests_replace(c, &kv.session_requests)?;
    let _ = CryptoError::Malformed;
    Ok(())
}
