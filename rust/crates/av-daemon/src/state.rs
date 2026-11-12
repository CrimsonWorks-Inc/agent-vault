//! The one lock the daemon's state lives behind.
//!
//! The JavaScript daemon is one thread: every synchronous stretch of a
//! handler, between two `await`s, runs alone, and the security properties
//! lean on that (an approval moves to `consumed` in the same stretch that
//! checks it; a placeholder is consumed in the stretch that substitutes it).
//! Here the vault and every in-memory table the daemon keeps sit behind one
//! mutex, [`Shared::run`] is the only way in, and each call to it is one of
//! those stretches. It runs on tokio's blocking pool (`spawn_blocking`), so
//! SQLite and the work done under the lock never stall the async runtime,
//! and nothing slow is done while holding it: the upstream request, reading
//! a response, decompressing and scrubbing it, and every Argon2 passphrase
//! check (on [`Shared::verifier`], a second handle on the same vault) happen
//! outside it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use av_core::errors::{deny, DenyExtra, ErrorCode, VaultError};
use av_store::vault::Vault;
use serde_json::{Map, Value};

use crate::notify::Notifier;
use crate::pipeline::PipelineState;
use crate::server::DaemonState;
use crate::session_requests::SessionRequestStore;
use crate::tripwire::TripwireState;

/// Everything the lock guards.
pub struct Core {
    /// The open vault.
    pub vault: Vault,
    /// The pipeline's in-memory tables (approvals, buckets, denials, ...).
    pub pl: PipelineState,
    /// The daemon's own (presence window, op challenges, throttle, ...).
    pub dm: DaemonState,
    /// Agent-proposed sessions waiting for a human.
    pub sr: SessionRequestStore,
    /// Tripwire counters.
    pub tw: TripwireState,
    /// Who is told when something starts waiting.
    pub notifier: Option<Arc<Notifier>>,
    /// The gateway's bound port, once started.
    pub gateway_port: u16,
    /// How many times the pipeline decrypted every vault secret (tests).
    #[cfg(test)]
    pub secret_reads: std::cell::Cell<usize>,
}

impl Core {
    /// A new core around an open vault.
    pub fn new(vault: Vault) -> Core {
        let sr = SessionRequestStore::load(&vault);
        Core {
            vault,
            pl: PipelineState::default(),
            dm: DaemonState::default(),
            sr,
            tw: TripwireState::default(),
            notifier: None,
            gateway_port: 0,
            #[cfg(test)]
            secret_reads: std::cell::Cell::new(0),
        }
    }

    /// `this.vault.audit?.write(kind, fields)`: recorded when the vault is
    /// unlocked, nothing otherwise; a failure to write is swallowed, as the
    /// optional-chained JS writes are.
    pub fn audit_opt(&mut self, kind: &str, fields: Value) {
        let _ = self.audit_try(kind, fields);
    }

    /// `this.vault.audit.write(kind, fields)`: must be recorded. A locked
    /// vault (the JS dereferences a null handle) or a failed write is an
    /// error the caller propagates.
    pub fn audit(&mut self, kind: &str, fields: Value) -> Result<(), VaultError> {
        self.audit_try(kind, fields)
    }

    fn audit_try(&mut self, kind: &str, fields: Value) -> Result<(), VaultError> {
        let map = match fields {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let Some(log) = self.vault.audit_mut() else {
            return Err(deny(
                ErrorCode::Locked,
                "the vault is locked",
                DenyExtra::default(),
            ));
        };
        log.write(kind, map).map(|_| ()).map_err(store_err)
    }
}

/// An av-store error as the `VaultError` the JS would have thrown: a
/// refusal as itself, anything else as the `AV_INTERNAL` every JS handler
/// makes of a plain `Error` (its message carries no secret).
pub fn store_err(e: av_store::error::Error) -> VaultError {
    match e {
        av_store::error::Error::Vault(v) => *v,
        other => deny(ErrorCode::Internal, other.to_string(), DenyExtra::default()),
    }
}

/// `.v()` on an av-store result: the error as a [`VaultError`].
pub trait StoreResult<T> {
    /// Convert the error.
    fn v(self) -> Result<T, VaultError>;
}

impl<T> StoreResult<T> for av_store::error::Result<T> {
    fn v(self) -> Result<T, VaultError> {
        self.map_err(store_err)
    }
}

/// The lock and the side handle.
pub struct Shared {
    core: Mutex<Core>,
    verifier: Mutex<Option<Vault>>,
    dir: PathBuf,
}

/// The handle every daemon component is built with. Replaces the scaffold's
/// stand-in.
pub type VaultRef = Arc<Shared>;

impl Shared {
    /// Wrap an open vault.
    pub fn new(vault: Vault) -> Arc<Shared> {
        let dir = vault.dir().to_path_buf();
        Arc::new(Shared {
            core: Mutex::new(Core::new(vault)),
            verifier: Mutex::new(None),
            dir,
        })
    }

    /// The vault directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Run one synchronous stretch under the lock, on the blocking pool. A
    /// panic inside it is reported as an internal error, never a crash: the
    /// lock is taken back from a poisoned state, which is safe because every
    /// vault write is its own transaction.
    pub async fn run<R, F>(self: &Arc<Self>, f: F) -> Result<R, VaultError>
    where
        F: FnOnce(&mut Core) -> R + Send + 'static,
        R: Send + 'static,
    {
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut guard = me.core.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut guard)
        })
        .await
        .map_err(|_| {
            deny(
                ErrorCode::Internal,
                "the request could not be handled",
                DenyExtra::default(),
            )
        })
    }

    /// The same, for code already on a blocking thread (tests, startup).
    pub fn run_sync<R>(&self, f: impl FnOnce(&mut Core) -> R) -> R {
        let mut guard = self.core.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut guard)
    }

    /// Check a passphrase against the stored wrap without the main lock:
    /// Argon2id is deliberately slow, and holding the lock across it would
    /// make every guess a stall of the whole daemon. Runs on the blocking
    /// pool on a second, read-only handle to the same database.
    pub async fn verify_passphrase(
        self: &Arc<Self>,
        passphrase: av_core::secret::SecretString,
    ) -> bool {
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut side = me.verifier.lock().unwrap_or_else(|p| p.into_inner());
            if side.is_none() {
                *side = Vault::open(&me.dir).ok();
            }
            side.as_ref()
                .and_then(|v| v.verify_passphrase(&passphrase).ok())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
}

/// A map of short-lived counters keyed by string, swept by the caller.
pub type Counters<T> = HashMap<String, T>;
