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

use crate::crypto::{Argon2Params, ArgonAlg};
use crate::error::Result;
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
        todo!()
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

/// Hex SHA-256 over the bundle's canonical operation form (key order does
/// not change it). Ports `bundleDigest` in `src/store/backup.js` (needs
/// av-core's `canonicalOperation` port).
pub fn bundle_digest(bundle: &Value) -> String {
    todo!()
}

/// Refuse (rule `recovery_passphrase`) a recovery passphrase under 12
/// characters. Ports `checkRecovery` in `src/store/backup.js`.
pub fn check_recovery(recovery_passphrase: &SecretString) -> Result<()> {
    todo!()
}

/// Check an envelope (format, version 1 or 2, size, the fixed KDF of that
/// version, cipher, nonce length) before any key is derived (rule
/// `backup_format`). Ports `checkEnvelope` in `src/store/backup.js`.
pub fn check_envelope(bundle: &Value) -> Result<Bundle> {
    todo!()
}

/// Check decrypted contents against the closed list (rule `backup_format`).
/// Ports `checkPlaintext` in `src/store/backup.js`.
pub fn check_plaintext(plain: &Value) -> Result<BackupPlaintext> {
    todo!()
}

/// Decrypt and check a bundle; a wrong passphrase and tampering are one
/// answer (AV_PRESENCE_DENIED, rule `backup_auth`). Key and plaintext are
/// zeroized. Blocking. Ports `openBundle` in `src/store/backup.js`.
pub fn open_bundle(bundle: &Value, recovery_passphrase: &SecretString) -> Result<BackupPlaintext> {
    todo!()
}

/// Seal every credential and template as a v2 bundle; records
/// `backup.exported` by digest. Blocking (Argon2id 256 MiB): callers use
/// `spawn_blocking`. Ports `exportBackup` in `src/store/backup.js`.
pub fn export_backup(
    vault: &mut Vault,
    recovery_passphrase: &SecretString,
) -> Result<ExportResult> {
    todo!()
}

/// What a bundle holds, without its values, touching no vault. Blocking.
/// Ports `inspectBackup` in `src/store/backup.js`.
pub fn inspect_backup(
    bundle: &Value,
    recovery_passphrase: &SecretString,
) -> Result<BackupInspection> {
    todo!()
}

/// `<slug>-restored`, then `-restored-2`, ..., trimmed to 24 characters.
/// Ports `renamed` in `src/store/backup.js`.
pub fn renamed(slug: &str, taken: &HashSet<String>) -> String {
    todo!()
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
    todo!()
}
