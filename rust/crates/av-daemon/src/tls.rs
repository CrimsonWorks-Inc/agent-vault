//! The managed loopback TLS certificate. Ports `src/daemon/tls.js`; `rcgen`
//! replaces the `openssl` subprocess (an ECDSA P-256 key instead of RSA
//! 2048; the same names, extensions, lifetime and file layout).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::util::iso_of_ms;

/// Leaf lifetime in days (the longest macOS trusts). Ports `DAYS`.
pub const DAYS: u32 = 825;

/// Where the managed key and certificate live. Ports `tlsPaths(dir)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    /// `<dir>/tls`
    pub dir: PathBuf,
    /// `<dir>/tls/localhost-key.pem`
    pub key: PathBuf,
    /// `<dir>/tls/localhost.pem`
    pub cert: PathBuf,
}

/// Ports `tlsPaths(dir)`.
pub fn tls_paths(dir: &Path) -> TlsPaths {
    let d = dir.join("tls");
    TlsPaths {
        key: d.join("localhost-key.pem"),
        cert: d.join("localhost.pem"),
        dir: d,
    }
}

/// What [`ensure_certificate`] reports. Ports the result of
/// `ensureCertificate`.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate path.
    pub cert: PathBuf,
    /// Key path.
    pub key: PathBuf,
    /// The certificate PEM.
    pub pem: String,
    /// SHA-256 fingerprint, colon-separated upper-case hex.
    pub fingerprint: String,
    /// Expiry, ISO 8601 (`None` when the certificate cannot be read).
    pub not_after: Option<String>,
    /// Whether this call generated it.
    pub created: bool,
}

/// The DER of the first certificate in a PEM file, as the JS reads it (all
/// base64 between the markers).
fn der_of(pem: &str) -> Vec<u8> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----") {
            inside = !inside || line.contains("BEGIN");
            continue;
        }
        body.push_str(line.trim());
    }
    crate::util::b64_lenient(&body)
}

/// `describe(certPath)`.
fn describe(cert: &Path) -> std::io::Result<(String, String, Option<String>)> {
    let pem = std::fs::read_to_string(cert)?;
    let der = der_of(&pem);
    let digest = crate::util::sha256_hex(&der).to_uppercase();
    let fingerprint = digest
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(":");
    let not_after = x509_parser::parse_x509_certificate(&der)
        .ok()
        .map(|(_, c)| iso_of_ms(c.validity().not_after.timestamp() * 1000));
    Ok((pem, fingerprint, not_after))
}

/// True when the certificate is gone, unreadable, or within 30 days of expiry.
fn is_expiring(cert: &Path) -> bool {
    match describe(cert) {
        Ok((_, _, Some(na))) => crate::util::parse_iso_ms(&na)
            .is_none_or(|ms| ms - crate::util::now_ms() < 30 * 86_400_000),
        _ => true,
    }
}

/// Generate the certificate if it is missing, expiring, or `force`. Ports
/// `ensureCertificate(dir, { force })`.
pub fn ensure_certificate(dir: &Path, force: bool) -> std::io::Result<CertificateInfo> {
    let p = tls_paths(dir);
    if !force && p.cert.exists() && p.key.exists() && !is_expiring(&p.cert) {
        let (pem, fingerprint, not_after) = describe(&p.cert)?;
        return Ok(CertificateInfo {
            cert: p.cert,
            key: p.key,
            pem,
            fingerprint,
            not_after,
            created: false,
        });
    }
    std::fs::create_dir_all(&p.dir)?;
    let _ = std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700));
    let fail =
        |e: rcgen::Error| std::io::Error::other(format!("could not generate a certificate: {e}"));
    let key = rcgen::KeyPair::generate().map_err(fail)?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(fail)?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().expect("ip")));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("::1".parse().expect("ip")));
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "agent-vault localhost");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::days(DAYS as i64);
    let cert = params.self_signed(&key).map_err(fail)?;
    // The key is written 0600 from the start: never readable by others, not
    // even between the write and a chmod.
    write_private(&p.key, key.serialize_pem().as_bytes())?;
    std::fs::write(&p.cert, cert.pem())?;
    std::fs::set_permissions(&p.cert, std::fs::Permissions::from_mode(0o644))?;
    let (pem, fingerprint, not_after) = describe(&p.cert)?;
    Ok(CertificateInfo {
        cert: p.cert,
        key: p.key,
        pem,
        fingerprint,
        not_after,
        created: true,
    })
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Cert and key bytes for a listener. Ports the result of `loadMaterial`.
pub struct TlsMaterial {
    /// Certificate chain PEM.
    pub cert: Vec<u8>,
    /// Private key PEM.
    pub key: av_core::secret::SecretBytes,
}

/// Read a listener's cert and key, refusing a key readable by group or
/// others. Ports `loadMaterial({ cert, key })`.
pub fn load_material(cert: &Path, key: &Path) -> std::io::Result<TlsMaterial> {
    for p in [cert, key] {
        if !p.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("tls file not found: {}", p.display()),
            ));
        }
    }
    let mode = std::fs::metadata(key)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "tls key {} is mode {:o}; it must not be readable by others",
            key.display(),
            mode
        )));
    }
    Ok(TlsMaterial {
        cert: std::fs::read(cert)?,
        key: av_core::secret::SecretBytes::from(std::fs::read(key)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_a_loopback_certificate_once_and_keeps_its_key_private() {
        let dir = tempfile::tempdir().unwrap();
        let a = ensure_certificate(dir.path(), false).unwrap();
        assert!(a.created);
        assert!(a.pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(a.fingerprint.split(':').count(), 32);
        let mode = std::fs::metadata(&a.key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let na = crate::util::parse_iso_ms(a.not_after.as_deref().unwrap()).unwrap();
        assert!(na - crate::util::now_ms() > 800 * 86_400_000);
        let b = ensure_certificate(dir.path(), false).unwrap();
        assert!(!b.created);
        assert_eq!(a.fingerprint, b.fingerprint);
        let c = ensure_certificate(dir.path(), true).unwrap();
        assert!(c.created);
        assert_ne!(a.fingerprint, c.fingerprint);
        assert!(load_material(&c.cert, &c.key).is_ok());
    }

    #[test]
    fn hardening_a_group_readable_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let info = ensure_certificate(dir.path(), false).unwrap();
        std::fs::set_permissions(&info.key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let e = load_material(&info.cert, &info.key).err().unwrap();
        assert!(e.to_string().contains("must not be readable by others"));
    }
}
