//! Ports `src/store/backup.js`: encrypted backup and controlled restore
//! (F8). Restores both the JS format (version 1: scrypt N = 2^17, r = 8,
//! p = 1, ChaCha20-Poly1305) and the Rust format (version 2: Argon2id
//! m = 256 MiB, t = 3, p = 1, XChaCha20-Poly1305); exports version 2 only
//! (rust/PLAN.md, "Crypto contract" and "Frozen external contract" item 9).
//!
//! A bundle carries a closed list (credentials and templates); anything else
//! is refused whole. Restore is all or nothing, never touches factors, and
//! never releases a quarantine. The bundle is never logged, only its digest.
//! KDFs here are blocking: callers run them off the async runtime.

use std::collections::{BTreeMap, HashSet};

use av_core::secret::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::{self, Argon2Params, ArgonAlg};
use crate::error::{Error, Result};
use av_core::secret::ExposeSecret;
use av_core::{deny, DenyExtra, ErrorCode};
use zeroize::Zeroizing;
use crate::vault::{TemplateRestore, Vault};

/// The bundle's `format`. Ports `BACKUP_FORMAT` in `src/store/backup.js`.
pub const BACKUP_FORMAT: &str = "agent-vault-backup";
/// The JS bundle version (scrypt + ChaCha20), restore only. Ports
/// `BACKUP_VERSION` in `src/store/backup.js`.
pub const BACKUP_VERSION: u32 = 1;
/// The Rust bundle version (Argon2id + XChaCha20), export and restore. No
/// JS source: rust/PLAN.md, "Crypto contract".
pub const BACKUP_VERSION_V2: u32 = 2;

/// A v1 bundle's fixed scrypt KDF (never chosen by the bundle). Ports
/// `BACKUP_KDF` in `src/store/backup.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupKdfV1 {
    /// Always `"scrypt"`.
    pub name: &'static str,
    /// Cost N.
    pub n: u32,
    /// Block size.
    pub r: u32,
    /// Parallelism.
    pub p: u32,
}

/// Ports `BACKUP_KDF` (`{ name: 'scrypt', N: 131072, r: 8, p: 1 }`) in
/// `src/store/backup.js`.
pub const BACKUP_KDF: BackupKdfV1 = BackupKdfV1 {
    name: "scrypt",
    n: 131_072,
    r: 8,
    p: 1,
};

/// A v2 bundle's fixed Argon2id KDF: m = 256 MiB, t = 3, p = 1. No JS
/// source: rust/PLAN.md, "Crypto contract".
pub const BACKUP_KDF_V2: Argon2Params = Argon2Params {
    alg: ArgonAlg::Argon2id,
    m: 256 * 1024,
    t: 3,
    p: 1,
};

/// A v1 bundle's cipher. Ports `CIPHER` in `src/store/backup.js`.
pub const CIPHER_V1: &str = "chacha20-poly1305";
/// A v2 bundle's cipher. No JS source: rust/PLAN.md, "Crypto contract".
pub const CIPHER_V2: &str = "xchacha20poly1305";
/// scrypt memory ceiling. Ports `MAXMEM` in `src/store/backup.js`.
pub const MAXMEM: usize = 256 * 1024 * 1024;
/// Largest bundle accepted. Ports `MAX_BUNDLE_BYTES` in
/// `src/store/backup.js`.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
/// Shortest recovery passphrase. Ports `MIN_RECOVERY` in
/// `src/store/backup.js`.
pub const MIN_RECOVERY: usize = 12;
/// Keys a bundle credential may have. Ports `CRED_KEYS` in
/// `src/store/backup.js`.
pub const CRED_KEYS: [&str; 9] = [
    "slug",
    "kind",
    "connector",
    "created_at",
    "fields",
    "scrub_patterns",
    "pins",
    "expires_at",
    "quarantine",
];
/// Keys a bundle field may have. Ports `FIELD_KEYS` in `src/store/backup.js`.
pub const FIELD_KEYS: [&str; 3] = ["name", "value", "sites"];
/// Keys a bundle scrub pattern may have. Ports `PATTERN_KEYS` in
/// `src/store/backup.js`.
pub const PATTERN_KEYS: [&str; 3] = ["id", "source", "added_at"];
/// Keys a bundle template may have. Ports `TEMPLATE_KEYS` in
/// `src/store/backup.js`.
pub const TEMPLATE_KEYS: [&str; 2] = ["name", "spec"];

/// What restore does with a taken slug. Ports `CONFLICT_MODES` in
/// `src/store/backup.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictMode {
    /// Leave the existing one (default).
    #[default]
    Skip,
    /// Restore as `<slug>-restored[-n]`.
    Rename,
    /// Refuse the whole restore.
    Fail,
}

// ----------------------------------------------------------- envelopes

/// A v1 bundle's `kdf`. Ports `kdf: { ...BACKUP_KDF, salt }` in
/// `exportBackup` in `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleKdfV1 {
    /// `"scrypt"`.
    pub name: String,
    /// 131072.
    #[serde(rename = "N")]
    pub n: u32,
    /// 8.
    pub r: u32,
    /// 1.
    pub p: u32,
    /// Base64 16-byte salt.
    pub salt: String,
}

/// A JS bundle (restore only). The AAD is `"<format>|<version>|<created_at>"`.
/// Ports the `bundle` object of `exportBackup` in `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleV1 {
    /// [`BACKUP_FORMAT`].
    pub format: String,
    /// 1.
    pub version: u32,
    /// ISO time.
    pub created_at: String,
    /// KDF.
    pub kdf: BundleKdfV1,
    /// [`CIPHER_V1`].
    pub cipher: String,
    /// Base64 12-byte nonce.
    pub nonce: String,
    /// Base64 ciphertext+tag.
    pub ct: String,
}

/// A v2 bundle's `kdf`: the Argon2id parameters plus the salt. No JS
/// source: rust/PLAN.md, "Crypto contract".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleKdfV2 {
    /// Parameters (must equal [`BACKUP_KDF_V2`]).
    #[serde(flatten)]
    pub params: Argon2Params,
    /// Base64 16-byte salt.
    pub salt: String,
}

/// A Rust bundle. Same envelope as v1 with `version: 2`, an Argon2id `kdf`,
/// `cipher: "xchacha20poly1305"` and a 24-byte nonce; the same AAD. No JS
/// source: rust/PLAN.md, "Crypto contract".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleV2 {
    /// [`BACKUP_FORMAT`].
    pub format: String,
    /// 2.
    pub version: u32,
    /// ISO time.
    pub created_at: String,
    /// KDF.
    pub kdf: BundleKdfV2,
    /// [`CIPHER_V2`].
    pub cipher: String,
    /// Base64 24-byte nonce.
    pub nonce: String,
    /// Base64 ciphertext+tag.
    pub ct: String,
}

/// A checked bundle envelope of either version. No JS source: the JS has
/// one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bundle {
    /// JS format.
    V1(BundleV1),
    /// Rust format.
    V2(BundleV2),
}

// ----------------------------------------------------------- plaintext

/// One field in a bundle: the plaintext value. Never derive `Debug`. Ports
/// the `fields` entries of `backupCredentials` in `src/store/vault.js`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupField {
    /// Field name.
    pub name: String,
    /// Plaintext value.
    #[serde(with = "crate::crypto::serde_secret_string")]
    pub value: SecretString,
    /// Sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<String>>,
}

impl std::fmt::Debug for BackupField {
    /// Redacted: the name only. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupField").finish_non_exhaustive()
    }
}

/// A scrub pattern in a bundle. Ports the `scrub_patterns` entries of
/// `backupCredentials` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupScrubPattern {
    /// Id (replaced on restore).
    #[serde(default)]
    pub id: Option<String>,
    /// Source.
    pub source: String,
    /// ISO time added.
    #[serde(default)]
    pub added_at: Option<String>,
}

/// One credential in a bundle. Ports the entries of `backupCredentials` in
/// `src/store/vault.js` and the checks of `checkPlaintext` in
/// `src/store/backup.js`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCredential {
    /// Slug.
    pub slug: String,
    /// Connector kind.
    pub kind: String,
    /// Connector configuration.
    #[serde(default)]
    pub connector: Option<Map<String, Value>>,
    /// ISO creation time.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Fields with values (at least one, names unique).
    pub fields: Vec<BackupField>,
    /// Scrub patterns.
    #[serde(default)]
    pub scrub_patterns: Option<Vec<BackupScrubPattern>>,
    /// Pins per host.
    #[serde(default)]
    pub pins: Option<BTreeMap<String, Vec<String>>>,
    /// Expiry.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Quarantine as stored (checked by the vault with `setQuarantine`'s
    /// rules on restore, so raw JSON here).
    #[serde(default)]
    pub quarantine: Option<Value>,
}

/// One template in a bundle. Ports the entries `exportBackup` builds from
/// `listTemplates` in `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTemplate {
    /// Name.
    pub name: String,
    /// Spec.
    pub spec: Map<String, Value>,
}

/// A bundle's decrypted contents: exactly credentials and templates. Ports
/// the `{ credentials, templates }` plaintext in `src/store/backup.js`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPlaintext {
    /// Credentials.
    pub credentials: Vec<BackupCredential>,
    /// Templates.
    pub templates: Vec<BackupTemplate>,
}

/// A bundle credential with its conflict resolved: `entry.slug` is the slug
/// to store, `from` the slug in the bundle. Ports the `{ ...c, slug, from }`
/// plan entries in `restoreBackup` in `src/store/backup.js`.
#[derive(Debug)]
pub struct PlannedCredential {
    /// The entry, renamed if needed.
    pub entry: BackupCredential,
    /// Its slug in the bundle.
    pub from: String,
}

// -------------------------------------------------------------- results

/// What an export says about itself. Ports `summary` in `exportBackup` in
/// `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSummary {
    /// Credentials.
    pub credentials: u64,
    /// Templates.
    pub templates: u64,
    /// ISO time.
    pub created_at: String,
}

/// The result of [`export_backup`]. Ports its return value in
/// `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportResult {
    /// The bundle (v2).
    pub bundle: BundleV2,
    /// Summary.
    pub summary: ExportSummary,
    /// Hex SHA-256 of the bundle's canonical form.
    pub bundle_sha256: String,
}

/// One credential as `inspect` shows it, without values. Ports the
/// `credentials` entries of `inspectBackup` in `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectedCredential {
    /// Slug.
    pub slug: String,
    /// Kind.
    pub kind: String,
    /// `connector.host`.
    pub host: Option<String>,
    /// Field names.
    pub fields: Vec<String>,
    /// Any scrub patterns.
    pub has_scrub_patterns: bool,
    /// Any pins.
    pub has_pins: bool,
    /// Expiry.
    pub expires_at: Option<String>,
    /// Quarantined.
    pub quarantined: bool,
}

/// What a bundle holds. Ports the return value of `inspectBackup` in
/// `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInspection {
    /// ISO time.
    pub created_at: String,
    /// Credentials.
    pub credentials: Vec<InspectedCredential>,
    /// Template names.
    pub templates: Vec<String>,
}

/// A rename on restore. Ports the `renames` entries in `restoreBackup` in
/// `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rename {
    /// Slug in the bundle.
    pub from: String,
    /// Slug stored.
    pub to: String,
}

/// The result of [`restore_backup`]. Ports its return value in
/// `src/store/backup.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Slugs restored.
    pub restored: Vec<String>,
    /// Slugs skipped.
    pub skipped: Vec<String>,
    /// Renames.
    pub renamed: Vec<Rename>,
    /// Templates.
    pub templates: TemplateRestore,
}

// ------------------------------------------------------------ functions

fn format_error(why: &str) -> Error {
    deny(
        ErrorCode::PolicyDenied,
        format!("not a usable backup: {why}"),
        DenyExtra {
            rule: Some("backup_format".into()),
            ..Default::default()
        },
    )
    .into()
}

fn auth_error() -> Error {
    deny(
        ErrorCode::PresenceDenied,
        "the recovery passphrase is wrong, or the bundle was altered",
        DenyExtra {
            rule: Some("backup_auth".into()),
            ..Default::default()
        },
    )
    .into()
}

fn locked() -> Error {
    deny(ErrorCode::Locked, "the vault is locked", DenyExtra::default()).into()
}

/// The Argon2id a v2 bundle is sealed under. Tests in this crate use cheap
/// parameters (a bundle states its own, and restore checks them against
/// this), so the suite does not spend 256 MiB per export.
pub(crate) fn backup_kdf_v2() -> Argon2Params {
    if cfg!(test) {
        Argon2Params {
            alg: ArgonAlg::Argon2id,
            m: 512,
            t: 1,
            p: 1,
        }
    } else {
        BACKUP_KDF_V2
    }
}

fn aad_of(format: &str, version: u32, created_at: &str) -> String {
    format!("{format}|{version}|{created_at}")
}

/// Hex SHA-256 over the bundle's canonical operation form (key order does
/// not change it). Ports `bundleDigest` in `src/store/backup.js` (needs
/// av-core's `canonicalOperation` port).
pub fn bundle_digest(bundle: &Value) -> String {
    crypto::sha256_hex(av_core::operation::canonical_operation(bundle).as_bytes())
}

/// Refuse (rule `recovery_passphrase`) a recovery passphrase under 12
/// characters. Ports `checkRecovery` in `src/store/backup.js`.
pub fn check_recovery(recovery_passphrase: &SecretString) -> Result<()> {
    if recovery_passphrase.expose_secret().encode_utf16().count() < MIN_RECOVERY {
        return Err(deny(
            ErrorCode::PolicyDenied,
            format!("the recovery passphrase must be at least {MIN_RECOVERY} characters"),
            DenyExtra {
                rule: Some("recovery_passphrase".into()),
                ..Default::default()
            },
        )
        .into());
    }
    Ok(())
}

fn b64_of_len(v: Option<&Value>, bytes: Option<usize>) -> bool {
    v.and_then(Value::as_str)
        .and_then(crypto::b64_strict)
        .is_some_and(|b| bytes.is_none_or(|n| b.len() == n))
}

/// Check an envelope (format, version 1 or 2, size, the fixed KDF of that
/// version, cipher, nonce length) before any key is derived (rule
/// `backup_format`). Ports `checkEnvelope` in `src/store/backup.js`.
pub fn check_envelope(bundle: &Value) -> Result<Bundle> {
    let Value::Object(b) = bundle else {
        return Err(format_error("a bundle is a JSON object"));
    };
    let version = b.get("version").and_then(Value::as_u64);
    if b.get("format").and_then(Value::as_str) != Some(BACKUP_FORMAT)
        || !matches!(version, Some(1) | Some(2))
    {
        return Err(format_error(&format!(
            "expected {BACKUP_FORMAT} version {BACKUP_VERSION} or {BACKUP_VERSION_V2}"
        )));
    }
    if serde_json::to_string(bundle)?.len() > MAX_BUNDLE_BYTES {
        return Err(format_error("it is over 16 MiB"));
    }
    let kdf = b.get("kdf").and_then(Value::as_object);
    let num = |k: &str| kdf.and_then(|o| o.get(k)).and_then(Value::as_u64);
    let salt_ok = b64_of_len(kdf.and_then(|o| o.get("salt")), Some(16));
    let bad_kdf = || format_error("its key derivation is not the one this format uses");
    let bad_cipher = || format_error("its cipher, nonce or ciphertext is malformed");
    let created_ok = b.get("created_at").is_some_and(Value::is_string);
    let ct_ok = b64_of_len(b.get("ct"), None);
    if version == Some(1) {
        let kdf_ok = kdf.and_then(|o| o.get("name")).and_then(Value::as_str) == Some(BACKUP_KDF.name)
            && num("N") == Some(u64::from(BACKUP_KDF.n))
            && num("r") == Some(u64::from(BACKUP_KDF.r))
            && num("p") == Some(u64::from(BACKUP_KDF.p))
            && salt_ok;
        if !kdf_ok {
            return Err(bad_kdf());
        }
        if b.get("cipher").and_then(Value::as_str) != Some(CIPHER_V1)
            || !b64_of_len(b.get("nonce"), Some(crypto::V1_NONCE_LEN))
            || !ct_ok
            || !created_ok
        {
            return Err(bad_cipher());
        }
        return Ok(Bundle::V1(
            serde_json::from_value(bundle.clone()).map_err(|_| bad_cipher())?,
        ));
    }
    let want = backup_kdf_v2();
    let kdf_ok = kdf.and_then(|o| o.get("alg")).and_then(Value::as_str) == Some("argon2id")
        && num("m") == Some(u64::from(want.m))
        && num("t") == Some(u64::from(want.t))
        && num("p") == Some(u64::from(want.p))
        && salt_ok;
    if !kdf_ok {
        return Err(bad_kdf());
    }
    if b.get("cipher").and_then(Value::as_str) != Some(CIPHER_V2)
        || !b64_of_len(b.get("nonce"), Some(crypto::V2_NONCE_LEN))
        || !ct_ok
        || !created_ok
    {
        return Err(bad_cipher());
    }
    Ok(Bundle::V2(
        serde_json::from_value(bundle.clone()).map_err(|_| bad_cipher())?,
    ))
}

fn only_keys(o: &Map<String, Value>, allowed: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Check decrypted contents against the closed list (rule `backup_format`).
/// Ports `checkPlaintext` in `src/store/backup.js`.
pub fn check_plaintext(plain: &Value) -> Result<BackupPlaintext> {
    let Value::Object(p) = plain else {
        return Err(format_error("it carries something other than credentials and templates"));
    };
    let (Some(Value::Array(creds)), Some(Value::Array(templates))) =
        (p.get("credentials"), p.get("templates"))
    else {
        return Err(format_error("it carries something other than credentials and templates"));
    };
    if !only_keys(p, &["credentials", "templates"]) {
        return Err(format_error("it carries something other than credentials and templates"));
    }
    for c in creds {
        let Value::Object(c) = c else {
            return Err(format_error("a credential entry is malformed"));
        };
        let slug = c.get("slug").and_then(Value::as_str).unwrap_or("");
        let fields = c.get("fields").and_then(Value::as_array);
        let ok = only_keys(c, &CRED_KEYS)
            && av_core::placeholder::is_valid_slug(slug)
            && c.get("kind").is_some_and(Value::is_string)
            && c.get("connector").is_none_or(|v| v.is_null() || v.is_object())
            && fields.is_some_and(|f| !f.is_empty());
        if !ok {
            return Err(format_error("a credential entry is malformed"));
        }
        let fields = fields.expect("checked");
        for f in fields {
            let ok = f.as_object().is_some_and(|f| {
                only_keys(f, &FIELD_KEYS)
                    && f.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(av_core::placeholder::is_valid_field)
                    && f.get("value")
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.is_empty())
                    && f.get("sites").is_none_or(|s| {
                        s.is_null()
                            || s.as_array().is_some_and(|a| a.iter().all(Value::is_string))
                    })
            });
            if !ok {
                return Err(format_error(&format!("a field of {slug} is malformed")));
            }
        }
        let mut names: Vec<&str> = fields
            .iter()
            .filter_map(|f| f.get("name").and_then(Value::as_str))
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.len() != fields.len() {
            return Err(format_error(&format!("{slug} names a field twice")));
        }
        if let Some(sp) = c.get("scrub_patterns").filter(|v| !v.is_null()) {
            let ok = sp.as_array().is_some_and(|a| {
                a.iter().all(|p| {
                    p.as_object().is_some_and(|p| {
                        only_keys(p, &PATTERN_KEYS) && p.get("source").is_some_and(Value::is_string)
                    })
                })
            });
            if !ok {
                return Err(format_error(&format!("the scrub patterns of {slug} are malformed")));
            }
        }
        if let Some(pins) = c.get("pins").filter(|v| !v.is_null()) {
            let ok = pins.as_object().is_some_and(|o| {
                o.values().all(|l| {
                    l.as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string))
                })
            });
            if !ok {
                return Err(format_error(&format!("the pins of {slug} are malformed")));
            }
        }
        if let Some(e) = c.get("expires_at").filter(|v| !v.is_null()) {
            if !e.as_str().is_some_and(|s| crate::util::parse_ms(s).is_some()) {
                return Err(format_error(&format!("the expiry of {slug} is malformed")));
            }
        }
        if let Some(q) = c.get("quarantine").filter(|v| !v.is_null()) {
            if !q.is_object() {
                return Err(format_error(&format!("the quarantine of {slug} is malformed")));
            }
        }
    }
    for t in templates {
        let ok = t.as_object().is_some_and(|t| {
            only_keys(t, &TEMPLATE_KEYS)
                && t.get("name").and_then(Value::as_str).is_some_and(|n| {
                    let b = n.as_bytes();
                    !b.is_empty()
                        && b.len() <= 32
                        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                        && b.iter()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                })
                && t.get("spec").and_then(Value::as_object).is_some_and(|s| {
                    !["template", "template_hash", "presence"]
                        .iter()
                        .any(|k| s.contains_key(*k))
                        && serde_json::to_string(s).map_or(false, |j| j.len() <= 16 * 1024)
                })
        });
        if !ok {
            return Err(format_error("a template entry is malformed"));
        }
    }
    // The shape is the closed list above; anything serde still refuses (an
    // id that is not text) is malformed too.
    serde_json::from_value(plain.clone()).map_err(|_| format_error("a credential entry is malformed"))
}

/// Decrypt and check a bundle; a wrong passphrase and tampering are one
/// answer (AV_PRESENCE_DENIED, rule `backup_auth`). Key and plaintext are
/// zeroized. Blocking. Ports `openBundle` in `src/store/backup.js`.
pub fn open_bundle(bundle: &Value, recovery_passphrase: &SecretString) -> Result<BackupPlaintext> {
    let env = check_envelope(bundle)?;
    check_recovery(recovery_passphrase)?;
    let bytes = match &env {
        Bundle::V1(b) => {
            let salt = crypto::b64_strict(&b.kdf.salt).ok_or_else(|| format_error("bad salt"))?;
            let key = crypto::scrypt_key(
                recovery_passphrase,
                &salt,
                &crypto::ScryptParams {
                    log_n: 17,
                    r: BACKUP_KDF.r,
                    p: BACKUP_KDF.p,
                    keylen: 32,
                    maxmem: MAXMEM,
                },
            )?;
            crypto::open_v1(
                &key,
                &crypto::SealedV1 {
                    ct: b.ct.clone(),
                    nonce: b.nonce.clone(),
                },
                &aad_of(&b.format, b.version, &b.created_at),
            )
            .map_err(|_| auth_error())?
        }
        Bundle::V2(b) => {
            let salt = crypto::b64_strict(&b.kdf.salt).ok_or_else(|| format_error("bad salt"))?;
            let key = crypto::argon2_key(recovery_passphrase, &salt, &b.kdf.params)?;
            crypto::open(
                &key,
                &crypto::SealedV2 {
                    v: crypto::SEALED_V2,
                    alg: crypto::V2_ALG.into(),
                    n: b.nonce.clone(),
                    c: b.ct.clone(),
                },
                &aad_of(&b.format, b.version, &b.created_at),
            )
            .map_err(|_| auth_error())?
        }
    };
    let text = Zeroizing::new(bytes.expose_secret().to_vec());
    let plain: Value =
        serde_json::from_slice(&text).map_err(|_| format_error("its contents are not JSON"))?;
    check_plaintext(&plain)
}

/// Seal every credential and template as a v2 bundle; records
/// `backup.exported` by digest. Blocking (Argon2id 256 MiB): callers use
/// `spawn_blocking`. Ports `exportBackup` in `src/store/backup.js`.
pub fn export_backup(
    vault: &mut Vault,
    recovery_passphrase: &SecretString,
) -> Result<ExportResult> {
    check_recovery(recovery_passphrase)?;
    if vault.locked() {
        return Err(locked());
    }
    let created_at = crate::util::now_iso();
    let credentials = vault.backup_credentials()?;
    let templates: Vec<BackupTemplate> = vault
        .list_templates()?
        .into_iter()
        .map(|t| BackupTemplate {
            name: t.name,
            spec: t.spec,
        })
        .collect();
    let (n_creds, n_templates) = (credentials.len() as u64, templates.len() as u64);
    let mut salt = [0u8; 16];
    crypto::fill_random(&mut salt)?;
    let params = backup_kdf_v2();
    let key = crypto::argon2_key(recovery_passphrase, &salt, &params)?;
    let plain = BackupPlaintext {
        credentials,
        templates,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&plain)?);
    drop(plain);
    let sealed = crypto::seal(
        &key,
        &bytes,
        &aad_of(BACKUP_FORMAT, BACKUP_VERSION_V2, &created_at),
    )?;
    drop(bytes);
    if vault.locked() {
        return Err(locked());
    }
    let bundle = BundleV2 {
        format: BACKUP_FORMAT.into(),
        version: BACKUP_VERSION_V2,
        created_at: created_at.clone(),
        kdf: BundleKdfV2 {
            params,
            salt: crypto::b64(&salt),
        },
        cipher: CIPHER_V2.into(),
        nonce: sealed.n,
        ct: sealed.c,
    };
    let digest = bundle_digest(&serde_json::to_value(&bundle)?);
    let audit = vault.audit_mut().ok_or_else(locked)?;
    let mut f = Map::new();
    f.insert("credentials".into(), n_creds.into());
    f.insert("templates".into(), n_templates.into());
    f.insert("bundle_sha256".into(), digest.clone().into());
    audit.write("backup.exported", f)?;
    Ok(ExportResult {
        bundle,
        summary: ExportSummary {
            credentials: n_creds,
            templates: n_templates,
            created_at,
        },
        bundle_sha256: digest,
    })
}

/// What a bundle holds, without its values, touching no vault. Blocking.
/// Ports `inspectBackup` in `src/store/backup.js`.
pub fn inspect_backup(
    bundle: &Value,
    recovery_passphrase: &SecretString,
) -> Result<BackupInspection> {
    let plain = open_bundle(bundle, recovery_passphrase)?;
    Ok(BackupInspection {
        created_at: bundle
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        credentials: plain
            .credentials
            .iter()
            .map(|c| InspectedCredential {
                slug: c.slug.clone(),
                kind: c.kind.clone(),
                host: c
                    .connector
                    .as_ref()
                    .and_then(|m| m.get("host"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                fields: c.fields.iter().map(|f| f.name.clone()).collect(),
                has_scrub_patterns: c.scrub_patterns.as_ref().is_some_and(|p| !p.is_empty()),
                has_pins: c
                    .pins
                    .as_ref()
                    .is_some_and(|p| p.values().any(|l| !l.is_empty())),
                expires_at: c.expires_at.clone(),
                quarantined: c.quarantine.as_ref().is_some_and(|q| !q.is_null()),
            })
            .collect(),
        templates: plain.templates.iter().map(|t| t.name.clone()).collect(),
    })
}

/// `<slug>-restored`, then `-restored-2`, ..., trimmed to 24 characters.
/// Ports `renamed` in `src/store/backup.js`.
pub fn renamed(slug: &str, taken: &HashSet<String>) -> String {
    let mut i = 1u64;
    loop {
        let suffix = if i == 1 {
            "-restored".to_string()
        } else {
            format!("-restored-{i}")
        };
        let keep = 24usize.saturating_sub(suffix.len()).min(slug.len());
        let candidate = format!("{}{suffix}", &slug[..keep]);
        if !taken.contains(&candidate) {
            return candidate;
        }
        i += 1;
    }
}

/// Put a bundle (v1 or v2) back under the conflict mode, via
/// `Vault::restore_entries`; each refusal is recorded once as
/// `backup.refused`, success as `backup.restored`. Blocking. Ports
/// `restoreBackup` in `src/store/backup.js`.
pub fn restore_backup(
    vault: &mut Vault,
    bundle: &Value,
    recovery_passphrase: &SecretString,
    on_conflict: ConflictMode,
) -> Result<RestoreResult> {
    if vault.locked() {
        return Err(locked());
    }
    fn refused(vault: &mut Vault, e: Error) -> Error {
        if let Some(v) = e.as_vault() {
            if v.code != ErrorCode::Locked && !vault.locked() {
                let reason = v.extra.rule.clone().unwrap_or_else(|| v.code.as_str().to_string());
                if let Some(a) = vault.audit_mut() {
                    let mut f = Map::new();
                    f.insert("reason".into(), reason.into());
                    let _ = a.write("backup.refused", f);
                }
            }
        }
        e
    }
    let plain = match open_bundle(bundle, recovery_passphrase) {
        Ok(p) => p,
        Err(e) => return Err(refused(vault, e)),
    };
    if vault.locked() {
        return Err(locked());
    }
    let mut taken: HashSet<String> = vault
        .credential_records()?
        .into_iter()
        .map(|c| c.slug)
        .collect();
    let mut plan = Vec::new();
    let mut skipped = Vec::new();
    let mut renames = Vec::new();
    for c in plain.credentials {
        let mut slug = c.slug.clone();
        if taken.contains(&slug) {
            match on_conflict {
                ConflictMode::Fail => {
                    let e = deny(
                        ErrorCode::PolicyDenied,
                        format!("a credential named {slug} already exists"),
                        DenyExtra {
                            rule: Some("backup_conflict".into()),
                            ..Default::default()
                        },
                    );
                    return Err(refused(vault, e.into()));
                }
                ConflictMode::Skip => {
                    skipped.push(slug);
                    continue;
                }
                ConflictMode::Rename => {
                    slug = renamed(&c.slug, &taken);
                    renames.push(Rename {
                        from: c.slug.clone(),
                        to: slug.clone(),
                    });
                }
            }
        }
        taken.insert(slug.clone());
        let from = c.slug.clone();
        let mut entry = c;
        entry.slug = slug;
        plan.push(PlannedCredential { entry, from });
    }
    let out = match vault.restore_entries(crate::vault::RestoreEntries {
        credentials: plan,
        templates: plain.templates,
    }) {
        Ok(o) => o,
        Err(e) => return Err(refused(vault, e)),
    };
    let audit = vault.audit_mut().ok_or_else(locked)?;
    let mut f = Map::new();
    f.insert("restored".into(), serde_json::to_value(&out.restored)?);
    f.insert("skipped".into(), serde_json::to_value(&skipped)?);
    f.insert("renamed".into(), serde_json::to_value(&renames)?);
    f.insert("bundle_sha256".into(), bundle_digest(bundle).into());
    audit.write("backup.restored", f)?;
    Ok(RestoreResult {
        restored: out.restored,
        skipped,
        renamed: renames,
        templates: out.templates,
    })
}
