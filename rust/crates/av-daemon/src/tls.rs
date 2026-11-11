//! The managed loopback TLS certificate. Ports `src/daemon/tls.js`; `rcgen`
//! replaces the `openssl` subprocess.

use std::path::{Path, PathBuf};

/// Leaf lifetime in days (the longest macOS trusts). Ports `DAYS`
/// (module-private) in `src/daemon/tls.js`.
pub const DAYS: u32 = 825;

/// Where the managed key and certificate live. Ports the
/// `{ dir, key, cert }` result of `tlsPaths(dir)` in `src/daemon/tls.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    /// `<dir>/tls`
    pub dir: PathBuf,
    /// `<dir>/tls/localhost-key.pem`
    pub key: PathBuf,
    /// `<dir>/tls/localhost.pem`
    pub cert: PathBuf,
}

/// Ports `tlsPaths(dir)` in `src/daemon/tls.js`.
pub fn tls_paths(dir: &Path) -> TlsPaths {
    todo!()
}

/// What [`ensure_certificate`] reports. Ports the
/// `{cert, key, pem, fingerprint, notAfter, created}` result of
/// `ensureCertificate` in `src/daemon/tls.js`.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate path.
    pub cert: PathBuf,
    /// Key path.
    pub key: PathBuf,
    /// The certificate PEM.
    pub pem: String,
    /// SHA-256 fingerprint, colon-separated hex.
    pub fingerprint: String,
    /// Expiry, ISO 8601.
    pub not_after: String,
    /// Whether this call generated it.
    pub created: bool,
}

/// Generate the certificate if it is missing, expired, or `force`. Ports
/// `ensureCertificate(dir, { force })` in `src/daemon/tls.js`.
pub fn ensure_certificate(dir: &Path, force: bool) -> std::io::Result<CertificateInfo> {
    todo!()
}

/// Cert and key bytes for a listener. Ports the `{cert, key}` result of
/// `loadMaterial` in `src/daemon/tls.js`.
pub struct TlsMaterial {
    /// Certificate chain PEM.
    pub cert: Vec<u8>,
    /// Private key PEM (zeroize on drop in the real implementation).
    pub key: av_core::secret::SecretBytes,
}

/// Read a listener's cert and key, refusing a key readable by group or
/// others. Ports `loadMaterial({ cert, key })` in `src/daemon/tls.js`.
pub fn load_material(cert: &Path, key: &Path) -> std::io::Result<TlsMaterial> {
    todo!()
}
