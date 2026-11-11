//! The store's error type. No JS source: new in the Rust port (rust/PLAN.md,
//! "Storage contract"). The JS throws two kinds of thing: a `VaultError` from
//! `deny(...)` (`src/core/errors.js`), which an agent may see, and a plain
//! `Error` for broken preconditions and I/O. [`Error::Vault`] is the first;
//! every other variant is the second.

use av_core::errors::VaultError;

/// Everything an av-store operation can fail with. No JS source: replaces the
/// mix of `deny(...)` and `throw new Error(...)` in `src/store/*.js`.
///
/// Refusals the JS raises with `deny(code, ...)` surface as [`Error::Vault`]
/// with the same code, rule, hint and next, so the control API and gateway
/// answer exactly as the JS does. The `VaultError` is boxed so `Result<T>`
/// stays small.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A refusal an agent may see: the JS `deny(...)`.
    #[error(transparent)]
    Vault(Box<VaultError>),
    /// SQLite failed (open, statement, constraint, trigger).
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The filesystem failed (device key, audit file, backup temp file).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A stored or supplied document is not the JSON it should be.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// A cryptographic operation failed. Never carries key or plaintext bytes.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// A broken precondition: the JS `throw new Error(message)` (for example
    /// "a factor change must leave at least one way to open the vault", or
    /// "a vault already exists at <dir>"). Never contains a secret.
    #[error("{0}")]
    Invariant(String),
}

impl From<VaultError> for Error {
    /// Ports the JS `throw deny(...)`: a `VaultError` becomes [`Error::Vault`].
    fn from(e: VaultError) -> Self {
        Error::Vault(Box::new(e))
    }
}

impl Error {
    /// The `VaultError` inside, when this is a refusal an agent may see. No
    /// JS source: the JS checks `e instanceof VaultError` / `e.code`.
    pub fn as_vault(&self) -> Option<&VaultError> {
        todo!()
    }
}

/// Why a crypto primitive failed. No JS source: the JS lets Node's crypto
/// throw. Deliberately coarse: an AEAD open failure never says whether the
/// key, the nonce, the AAD or the ciphertext was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// AEAD authentication failed (wrong key, wrong AAD, tampered blob).
    #[error("authentication failed")]
    Open,
    /// A sealed value is malformed (bad base64, wrong nonce length, unknown
    /// `v` or `alg`).
    #[error("malformed sealed value")]
    Malformed,
    /// A key or secret has the wrong length (e.g. a PRF secret under 32 bytes).
    #[error("wrong key length")]
    KeyLength,
    /// A KDF (Argon2id, scrypt, HKDF) rejected its parameters or failed.
    #[error("key derivation failed")]
    Kdf,
    /// The OS random source failed.
    #[error("random source failed")]
    Rng,
}

/// `Result` with the store's [`Error`]. No JS source.
pub type Result<T> = std::result::Result<T, Error>;
