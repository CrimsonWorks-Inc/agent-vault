//! Ports `src/store/vault.js`: the vault API over entities, sealed
//! credential fields and the placeholder ledger, backed by SQLite
//! (`vault.db`, rust/PLAN.md "Storage contract") instead of `vault.json`.
//!
//! Every mutating method is one transaction (`&mut self`): it commits once
//! or not at all, and a refusal leaves the database as it was. After any
//! change to unlock factors, VMK wraps, the WebAuthn factor or a credential
//! secret the store runs `PRAGMA wal_checkpoint(TRUNCATE)`. A change that
//! cannot be written to the audit log must not happen: mutations refuse with
//! AV_LOCKED while locked. Entity records live in [`crate::model`].

use std::path::{Path, PathBuf};

use av_core::placeholder::ParsedPlaceholder;
use av_core::policy::Policy;
use av_core::secret::{Key32, SecretBytes, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::audit::AuditLog;
use crate::backup::{BackupCredential, BackupTemplate, PlannedCredential};
use crate::error::Result;
use crate::model::{
    CredentialRecord, FactorClass, FactorState, GrantRecord, HealthRecord, ListenerRecord,
    ListenerTls, NotifyDetail, PlaceholderRow, PresenceKey, QuarantineBy, QuarantineRecord,
    ScrubPattern, SessionRecord, SessionRequestRecord, Settings, TemplateRecord, WorkspaceRecord,
};

// -------------------------------------------------------------- constants

/// The `vault.json` document version this port reads (`migrate` refuses a
/// newer one). The SQLite schema's own version lives in [`crate::schema`].
/// Ports `SCHEMA_VERSION` in `src/store/vault.js`.
pub const SCHEMA_VERSION: u32 = 1;
/// The SQLite file. No JS source: rust/PLAN.md, "Storage contract".
pub const VAULT_DB_FILE: &str = "vault.db";
/// The legacy JSON vault `migrate` reads. Ports `this.dbPath` in the `Vault`
/// constructor in `src/store/vault.js`.
pub const LEGACY_VAULT_FILE: &str = "vault.json";
/// The device key file (32 bytes, 0600). Ports `this.deviceKeyPath` in the
/// `Vault` constructor in `src/store/vault.js`.
pub const DEVICE_KEY_FILE: &str = "device.key";
/// The audit log file. Ports `this.auditPath` in the `Vault` constructor in
/// `src/store/vault.js`.
pub const AUDIT_FILE: &str = "audit.jsonl";
/// How close an expiry has to be before a credential is flagged (F10). Ports
/// `EXPIRY_WARN_DAYS` in `src/store/vault.js`.
pub const EXPIRY_WARN_DAYS: i64 = 7;
/// One day in ms. Ports `DAY_MS` in `src/store/vault.js`.
pub const DAY_MS: i64 = 86_400_000;
/// Longest scrub pattern source. Ports `MAX_SCRUB_SOURCE` in
/// `src/store/vault.js`.
pub const MAX_SCRUB_SOURCE: usize = 256;
/// Shortest scrub pattern source. Ports the `source.length < 3` check in
/// `#checkScrubSource` in `src/store/vault.js`.
pub const MIN_SCRUB_SOURCE: usize = 3;
/// Most scrub patterns per credential. Ports `MAX_SCRUB_PER_CRED` in
/// `src/store/vault.js`.
pub const MAX_SCRUB_PER_CRED: usize = 16;
/// Most scrub patterns in the vault. Ports `MAX_SCRUB_TOTAL` in
/// `src/store/vault.js`.
pub const MAX_SCRUB_TOTAL: usize = 64;
/// Template name grammar (implemented by hand; no backtracking). Ports
/// `TEMPLATE_NAME` in `src/store/vault.js`.
pub const TEMPLATE_NAME_PATTERN: &str = "^[a-z0-9][a-z0-9-]{0,31}$";
/// Largest template spec, bytes of JSON. Ports `MAX_TEMPLATE_BYTES` in
/// `src/store/vault.js`.
pub const MAX_TEMPLATE_BYTES: usize = 16 * 1024;
/// Most templates. Ports `MAX_TEMPLATES` in `src/store/vault.js`.
pub const MAX_TEMPLATES: usize = 64;
/// Keys a template spec may not carry. Ports the list in `#checkTemplate` in
/// `src/store/vault.js`.
pub const TEMPLATE_FORBIDDEN_KEYS: [&str; 3] = ["template", "template_hash", "presence"];
/// What may elevate a session (C3). Ports `ELEVATIONS` in
/// `src/store/vault.js`.
pub const ELEVATIONS: [&str; 2] = ["approval_auto_writes", "infinite"];
/// Keys a tripwire rule may have. Ports `RULE_KEYS` in `src/store/vault.js`.
pub const RULE_KEYS: [&str; 6] = [
    "id",
    "codes",
    "rule_prefix",
    "threshold",
    "window_s",
    "action",
];
/// Most tripwire rules. Ports `MAX_TRIPWIRE_RULES` in `src/store/vault.js`.
pub const MAX_TRIPWIRE_RULES: usize = 32;
/// Most pinned hosts per credential. Ports `MAX_PIN_HOSTS` in
/// `src/store/vault.js`.
pub const MAX_PIN_HOSTS: usize = 4;
/// Ledger rows kept before the oldest dead ones are dropped. Ports
/// `MAX_PLACEHOLDER_ROWS` in `src/store/vault.js`.
pub const MAX_PLACEHOLDER_ROWS: usize = 512;
/// Active placeholders per grant+field when the policy names none. Ports the
/// `: 8` default in `issuePlaceholder` in `src/store/vault.js`.
pub const DEFAULT_MAX_ACTIVE: u64 = 8;
/// A placeholder's use ceiling when the budget is unlimited or unreadable.
/// Ports the `1000` in `issuePlaceholder` in `src/store/vault.js`.
pub const DEFAULT_PLACEHOLDER_USES: u64 = 1000;
/// Shortest passphrase. Ports the `newPassphrase.length < 8` check in
/// `setPassphrase` in `src/store/vault.js`.
pub const MIN_PASSPHRASE_LEN: usize = 8;
/// A session's default lifetime. Ports `8 * 3600_000` in `createSession` in
/// `src/store/vault.js`.
pub const DEFAULT_SESSION_TTL_MS: i64 = 8 * 3_600_000;
/// The cap on a local session's lifetime. Ports `24 * 3600_000` in
/// `createSession` in `src/store/vault.js`.
pub const LOCAL_SESSION_CAP_MS: i64 = 24 * 3_600_000;
/// The cap on a remote session's lifetime. Ports `8 * 3600_000` in
/// `createSession` in `src/store/vault.js`.
pub const REMOTE_SESSION_CAP_MS: i64 = 8 * 3_600_000;
/// A local session's idle extension. Ports `2 * 3600_000` in
/// `createSession` in `src/store/vault.js`.
pub const LOCAL_IDLE_TIMEOUT_MS: u64 = 2 * 3_600_000;
/// A remote session's idle extension. Ports `1 * 3600_000` in
/// `createSession` in `src/store/vault.js`.
pub const REMOTE_IDLE_TIMEOUT_MS: u64 = 3_600_000;
/// Longest rotation retire window. Ports `7 * DAY_MS` in `rotateCredential`
/// in `src/store/vault.js`.
pub const MAX_RETIRE_MS: i64 = 7 * DAY_MS;
/// Surfaces that may never be bound off loopback. Ports `FORBIDDEN` in
/// `addListener` in `src/store/vault.js`.
pub const NON_NETWORKABLE_SURFACES: [&str; 3] = ["control", "approver", "l4"];
/// How long revoked or expired sessions and their grants are kept. No JS
/// source: rust/PLAN.md, "Intended changes" (setting `retention_days`).
pub const RETENTION_DAYS_DEFAULT: u32 = 30;
/// The settings key for [`RETENTION_DAYS_DEFAULT`]. No JS source:
/// rust/PLAN.md, "Intended changes".
pub const RETENTION_DAYS_SETTING: &str = "retention_days";

// -------------------------------------------------------- free functions

/// When something stamped with `iso` stops being valid, as epoch ms: absent
/// is `f64::INFINITY`; anything that does not parse is
/// `f64::NEG_INFINITY` (already past), so a corrupt date only ends access
/// early. Ports `expiryMs` in `src/store/vault.js`.
pub fn expiry_ms(iso: Option<&str>) -> f64 {
    todo!()
}

/// When a session ends: infinite only with `infinite == true` and
/// `expires_at` null; any other missing date is already past. Ports
/// `sessionExpiryMs` in `src/store/vault.js`.
pub fn session_expiry_ms(session: &SessionRecord) -> f64 {
    todo!()
}

/// The furthest a session could live, idle extension included. Ports
/// `sessionCeilingMs` in `src/store/vault.js`.
pub fn session_ceiling_ms(session: &SessionRecord) -> f64 {
    todo!()
}

/// A ledger row's end: exactly null never expires. Ports `rowExpiryMs` in
/// `src/store/vault.js`.
pub fn row_expiry_ms(row: &PlaceholderRow) -> f64 {
    todo!()
}

/// A credential's expiry flag (F10). Ports the return values of
/// `expiryWarning` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExpiryWarning {
    /// Already past.
    Expired,
    /// Within [`EXPIRY_WARN_DAYS`].
    Soon,
}

/// `expired`, `soon` or none: the sooner of the human's date and the
/// observed one wins. Ports `expiryWarning` in `src/store/vault.js`.
pub fn expiry_warning(cred: &CredentialRecord, now_ms: i64) -> Option<ExpiryWarning> {
    todo!()
}

/// A presence authenticator as the vault stores it, or a refusal
/// (AV_POLICY_DENIED, rule `presence_key`): a base64url credential id of
/// 16..=1023 bytes that round-trips, a base64 DER SPKI that parses as a
/// P-256 key, and a 32-bit `signCount` (default 0). Only those fields are
/// kept. Takes raw JSON because the type checks are part of the contract.
/// Ports `presenceKeyRecord` in `src/store/vault.js`.
pub fn presence_key_record(input: &Value) -> Result<PresenceKey> {
    todo!()
}

/// The human factors a factor state holds (`passphrase`, `authenticator`).
/// Ports `humanFactors` in `src/store/vault.js`.
pub fn human_factors(state: &FactorState) -> Vec<&'static str> {
    todo!()
}

/// The factor invariant, and the one place it is enforced: (1) a vault with
/// a human factor is never left without one; (2) a `webauthn-prf` wrap
/// never exists without the passphrase wrap; (3) a presence authenticator is
/// only replaced by one that `presence_key_record` accepts. At least one
/// wrap must remain ([`crate::error::Error::Invariant`]). Every factor change
/// calls this on the state it is about to commit, before writing. Ports
/// `assertFactorInvariant` in `src/store/vault.js`.
pub fn assert_factor_invariant(prev: &FactorState, next: &FactorState) -> Result<()> {
    todo!()
}

/// What `tripwires` in a settings patch is wrong with, or none. Ports
/// `tripwireProblem` in `src/store/vault.js`.
pub fn tripwire_problem(tripwires: &Value) -> Option<String> {
    todo!()
}

/// A coarse size label (`short` < 16, `typical` < 60, `long`, `unknown`), so
/// exact length never leaves the daemon. Ports `sizeBucket` in
/// `src/store/vault.js`.
pub fn size_bucket(len: Option<u64>) -> &'static str {
    todo!()
}

/// Whether a listener address stays on this machine (`unix:`,
/// `127.0.0.1:`, `[::1]:`, `localhost:`). Ports `isLoopbackSpec` in
/// `src/store/vault.js`.
pub fn is_loopback_spec(address: &str) -> bool {
    todo!()
}

// ------------------------------------------------------- argument types

/// Options for [`Vault::create`]. Ports the options of `Vault.create` in
/// `src/store/vault.js` (`factor = 'none'`, `passphrase = null`).
#[derive(Default)]
pub struct CreateOptions {
    /// The first unlock factor (default `none`); `webauthn-prf` alone is
    /// refused.
    pub factor: FactorClass,
    /// Required for the passphrase factor.
    pub passphrase: Option<SecretString>,
}

impl std::fmt::Debug for CreateOptions {
    /// Redacted. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// Unlock material: a passphrase or a WebAuthn PRF secret. Ports the
/// `material` argument (`{passphrase}` / `{prfSecret}`) of `unlockWith` in
/// `src/store/vault.js`.
#[derive(Default)]
pub struct UnlockMaterial {
    /// A passphrase.
    pub passphrase: Option<SecretString>,
    /// The authenticator's PRF output (at least 32 bytes).
    pub prf_secret: Option<SecretBytes>,
}

impl std::fmt::Debug for UnlockMaterial {
    /// Redacted. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// The credential as anything outside the daemon may see it: never a value,
/// never an exact length, pin counts not pins. Ports the return value of
/// `Vault.prototype.publicCredential` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicCredential {
    /// Id.
    pub id: String,
    /// Slug.
    pub slug: String,
    /// Connector kind.
    pub kind: String,
    /// Connector configuration.
    pub connector: Map<String, Value>,
    /// The human's expiry.
    pub expires_at: Option<String>,
    /// Health.
    pub health: Option<HealthRecord>,
    /// Expiry flag.
    pub expiry_warning: Option<ExpiryWarning>,
    /// Quarantine.
    pub quarantine: Option<QuarantineRecord>,
    /// Scrub patterns (id, source, added_at).
    pub scrub_patterns: Vec<ScrubPattern>,
    /// Pin count per host.
    pub pins: std::collections::BTreeMap<String, u64>,
    /// Fields, without values.
    pub fields: Vec<PublicField>,
    /// The profile's read-only probe path (from av-core `profiles`).
    pub probe_path: Option<String>,
    /// ISO creation time.
    pub created_at: String,
}

/// A field as [`PublicCredential`] shows it. Ports the `fields` entries of
/// `publicCredential` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicField {
    /// Name.
    pub name: String,
    /// Substitution sites.
    pub sites: Vec<String>,
    /// Fingerprint.
    pub fp8: String,
    /// [`size_bucket`] of the length.
    pub size: String,
    /// Key version.
    pub version: u32,
    /// ISO time of the last rotation.
    pub rotated_at: Option<String>,
}

/// A new credential: plaintext values, sealed at once and never kept. Ports
/// the argument of `addCredential` / `#sealCredential` in
/// `src/store/vault.js`.
pub struct NewCredential {
    /// `[a-z0-9-]{1,24}`.
    pub slug: String,
    /// Connector kind.
    pub kind: String,
    /// Connector configuration.
    pub connector: Map<String, Value>,
    /// Field name -> plaintext value, in order.
    pub fields: Vec<(String, SecretString)>,
    /// Field name -> sites.
    pub sites: std::collections::BTreeMap<String, Vec<String>>,
}

impl std::fmt::Debug for NewCredential {
    /// Redacted: names only. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// One unsealed value, for the scrubber's match set. Ports the entries of
/// `allSecrets` in `src/store/vault.js`.
pub struct StoredSecret {
    /// The plaintext.
    pub secret: SecretString,
    /// The credential slug.
    pub label: String,
    /// The field.
    pub field: String,
    /// A rotated-out value still inside its retire window.
    pub retired: bool,
}

impl std::fmt::Debug for StoredSecret {
    /// Redacted. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// Options for [`Vault::set_quarantine`]. Ports the options of
/// `setQuarantine` in `src/store/vault.js` (`by = 'control'`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineOptions {
    /// Who.
    pub by: QuarantineBy,
    /// The tripwire rule.
    pub rule_id: Option<String>,
    /// Caller's reason (truncated to 200; stored as untrusted).
    pub reason: Option<String>,
}

/// The result of [`Vault::set_pins`]. Ports the return value of `setPins` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinsSet {
    /// Slug.
    pub slug: String,
    /// Canonical host key.
    pub host: String,
    /// How many pins it now has.
    pub pins: u64,
}

/// `keep` or `revoke` the credential's grants on rotation. Ports the `mode`
/// values of `rotateCredential` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotateMode {
    /// Keep grants (default).
    #[default]
    Keep,
    /// Revoke them.
    Revoke,
}

/// Options for [`Vault::rotate_credential`]. Ports the options of
/// `rotateCredential` in `src/store/vault.js` (`field = null` is the first
/// field, `mode = 'keep'`, `retireMs = DAY_MS`, `expiresAt` absent clears).
pub struct RotateOptions {
    /// The field, or the first.
    pub field: Option<String>,
    /// The new value (non-empty, not the current one).
    pub value: SecretString,
    /// Grants.
    pub mode: RotateMode,
    /// How long the old value is still scrubbed, 0..=7 days.
    pub retire_ms: i64,
    /// The new value's expiry; none clears it.
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for RotateOptions {
    /// Redacted. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// What a rotation did (also the `cred.rotated` audit fields). Ports
/// `rotated` in `rotateCredential` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationSummary {
    /// Field.
    pub field: String,
    /// New key version.
    pub version: u32,
    /// Old fingerprint.
    pub previous_fp8: String,
    /// New fingerprint.
    pub fp8: String,
    /// Mode.
    pub mode: RotateMode,
    /// Grants revoked.
    pub revoked_grants: u64,
    /// ISO end of the retire window.
    pub retire_until: String,
}

/// The result of [`Vault::rotate_credential`]. Ports its return value in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotateResult {
    /// The credential after.
    pub credential: PublicCredential,
    /// What happened.
    pub rotated: RotationSummary,
}

/// The notify webhook as the daemon uses it. Daemon-internal: nothing in it
/// may reach a response. Ports the return value of `getNotifyWebhook` in
/// `src/store/vault.js`.
pub struct NotifyWebhook {
    /// The URL (a bearer credential).
    pub url: SecretString,
    /// Its host.
    pub host: String,
    /// Detail level.
    pub detail: NotifyDetail,
}

impl std::fmt::Debug for NotifyWebhook {
    /// Redacted: host and detail only. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// What anyone may see of the webhook. Ports the return value of
/// `notifyConfig` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Host.
    pub host: String,
    /// Detail level.
    pub detail: NotifyDetail,
    /// ISO time configured.
    pub configured_at: String,
}

/// What [`Vault::restore_entries`] puts back. Ports the argument of
/// `restoreEntries` in `src/store/vault.js`.
#[derive(Debug, Default)]
pub struct RestoreEntries {
    /// Credentials, conflicts already resolved.
    pub credentials: Vec<PlannedCredential>,
    /// Templates (a taken name is skipped).
    pub templates: Vec<BackupTemplate>,
}

/// Templates restored and skipped. Ports `templates` in the return value of
/// `restoreEntries` in `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRestore {
    /// Names restored.
    pub restored: Vec<String>,
    /// Names skipped (already taken).
    pub skipped: Vec<String>,
}

/// The result of [`Vault::restore_entries`]. Ports its return value in
/// `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreEntriesResult {
    /// Slugs restored.
    pub restored: Vec<String>,
    /// Templates.
    pub templates: TemplateRestore,
}

/// Options for [`Vault::create_session`]. Ports the options of
/// `createSession` in `src/store/vault.js`. `peer_uid` defaults to none here;
/// callers pass the peer's uid (the JS defaults to `process.getuid()`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreateSessionOptions {
    /// Workspace.
    pub workspace_id: Option<String>,
    /// Label (default `session`).
    pub label: Option<String>,
    /// A lifetime asked for (positive), capped; none takes the default.
    pub ttl_ms: Option<i64>,
    /// R3: never expires (not with `ttl_ms`, never remote).
    pub infinite: bool,
    /// C3 elevations, each one of [`ELEVATIONS`].
    pub elevated: Vec<String>,
    /// F17 template (with `template_version`, or neither).
    pub template: Option<String>,
    /// F17 template version (>= 1).
    pub template_version: Option<u32>,
    /// Session policy layer.
    pub policy: Policy,
    /// Creating peer's uid.
    pub peer_uid: Option<u32>,
    /// For network use.
    pub remote: bool,
    /// Client name.
    pub client_name: Option<String>,
    /// From an agent's session request (C25): the audit record keeps only
    /// whether it has an end.
    pub requested: bool,
}

/// A new session and its bearer token, which exists in plaintext only here.
/// Ports the return value of `createSession` / `forkSession` in
/// `src/store/vault.js`.
pub struct CreatedSession {
    /// The stored session (token hash only).
    pub session: SessionRecord,
    /// `avs1.<sid>.<base64url 33 random bytes>`.
    pub token: SecretString,
}

impl std::fmt::Debug for CreatedSession {
    /// Redacted: never the token. No JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// The listener a request arrived on, for [`Vault::assert_session_usable`].
/// Ports the `listener` argument (`{id, kind, remote}`) in
/// `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerContext {
    /// Listener id.
    pub id: Option<String>,
    /// Peer kind for the audit record (default `remote`).
    pub kind: Option<String>,
    /// A network listener.
    pub remote: bool,
}

/// Options for [`Vault::assert_session_usable`]. Ports `{ peek = false,
/// record = true }` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsableOptions {
    /// Answer without side effects.
    pub peek: bool,
    /// Record a C12 refusal as `remote.denied`.
    pub record: bool,
}

impl Default for UsableOptions {
    /// Ports the defaults (`peek = false, record = true`).
    fn default() -> Self {
        UsableOptions {
            peek: false,
            record: true,
        }
    }
}

/// Options for [`Vault::fork_session`]. Ports the options of `forkSession`
/// in `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ForkOptions {
    /// Label (default `<parent label> (fork)`).
    pub label: Option<String>,
    /// Narrowing intersected into every copied grant.
    pub narrow: Policy,
    /// Lifetime, never past the parent's.
    pub ttl_ms: Option<i64>,
}

/// Options for [`Vault::create_grant`]. Ports the options of `createGrant`
/// in `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreateGrantOptions {
    /// Session.
    pub session_id: String,
    /// Credential id.
    pub credential_id: String,
    /// Fields covered; none is every field.
    pub fields: Option<Vec<String>>,
    /// Grant policy layer.
    pub policy: Policy,
    /// Intersected in when non-empty.
    pub narrow: Option<Policy>,
    /// F18 lifetime of its own (positive), never past the session's.
    pub ttl_ms: Option<i64>,
    /// From an agent's session request (C25).
    pub requested: bool,
}

/// Options for [`Vault::issue_placeholder`]. Ports the options of
/// `issuePlaceholder` in `src/store/vault.js`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueOptions {
    /// Grant.
    pub grant_id: String,
    /// Field; none is the grant's first.
    pub field: Option<String>,
    /// Uses asked for (capped by the grant's ceiling; < 1 is the ceiling).
    pub uses: Option<u64>,
    /// Lifetime asked for (capped by the grant's `placeholder_policy.ttl`).
    pub ttl_ms: Option<i64>,
}

/// A minted placeholder and its ledger row. The placeholder text is a
/// capability handed to the agent, not a credential value. Ports the return
/// value of `issuePlaceholder` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedPlaceholder {
    /// `av1.…` text.
    pub placeholder: String,
    /// Its ledger row.
    pub row: PlaceholderRow,
}

/// The result of [`Vault::next_placeholder`]. Ports its return value in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextPlaceholder {
    /// The text, or none when an unused successor already existed.
    pub placeholder: Option<String>,
    /// The successor row.
    pub row: PlaceholderRow,
    /// Whether it already existed.
    pub reused: bool,
}

/// A listener to add. Ports the `entry` argument of `addListener` in
/// `src/store/vault.js` (as `listen add` builds it in `src/cli/index.js`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewListener {
    /// Id.
    pub id: String,
    /// Address.
    pub address: String,
    /// Surfaces.
    #[serde(default)]
    pub surfaces: Vec<String>,
    /// Advertised names.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Client auth.
    #[serde(default)]
    pub client_auth: Option<String>,
    /// Allowed CIDRs.
    #[serde(default)]
    pub allow_cidr: Vec<String>,
    /// TLS.
    #[serde(default)]
    pub tls: Option<ListenerTls>,
}

/// History pruned by [`Vault::prune_history`]. No JS source: rust/PLAN.md,
/// "Intended changes" (history pruning).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Sessions deleted.
    pub sessions: u64,
    /// Grants deleted.
    pub grants: u64,
    /// Placeholder rows deleted.
    pub placeholders: u64,
}

/// Counts for status. Ports the return value of `stats` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStats {
    /// Credentials.
    pub credentials: u64,
    /// Workspaces.
    pub workspaces: u64,
    /// Credentials with an expiry warning.
    pub credentials_expiring: u64,
    /// Active, unexpired sessions.
    pub sessions_active: u64,
    /// Active grants.
    pub grants_active: u64,
    /// Active placeholder rows.
    pub placeholders_live: u64,
    /// Listeners.
    pub listeners: u64,
    /// Audit records, or none while locked (never 0).
    pub audit_records: Option<u64>,
    /// Locked.
    pub locked: bool,
}

/// Options for [`Vault::save`]. Ports `{ durable = true }` of `#persist` /
/// `save` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaveOptions {
    /// fsync (SQLite `synchronous=FULL`) rather than a cheaper commit.
    pub durable: bool,
}

impl Default for SaveOptions {
    /// Ports `durable = true`.
    fn default() -> Self {
        SaveOptions { durable: true }
    }
}

// ------------------------------------------------------------------ Vault

/// The vault. Holds the SQLite connection, the VMK while unlocked (in
/// `mlock`ed memory; [`None`] means locked) and the audit log, whose key is
/// derived from the VMK and dropped with it. Ports `class Vault` in
/// `src/store/vault.js`.
#[allow(dead_code)] // scaffold: fields are read once the bodies exist
pub struct Vault {
    dir: PathBuf,
    conn: rusqlite::Connection,
    vmk: Option<Key32>,
    audit: Option<AuditLog>,
}

impl std::fmt::Debug for Vault {
    /// Redacted: the dir and whether it is locked, never key material. No
    /// JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Vault {
    // ---------------------------------------------------------- setup

    /// Create the vault dir (0700), the device key (0600, fsynced first),
    /// `vault.db` (via `crate::db::open`) and the first wrap; checks the
    /// factor invariant before touching disk; records `vault.created`.
    /// Refuses an existing vault. Ports `Vault.create` in
    /// `src/store/vault.js`.
    pub fn create(dir: &Path, opts: CreateOptions) -> Result<Vault> {
        todo!()
    }

    /// Open an existing vault, locked (AV_NOT_FOUND "no vault at <dir>;
    /// run: agent-vault setup" when absent; refuses a newer schema). Ports
    /// `Vault.open` in `src/store/vault.js`.
    pub fn open(dir: &Path) -> Result<Vault> {
        todo!()
    }

    /// The vault dir. Ports `this.dir` in `src/store/vault.js`.
    pub fn dir(&self) -> &Path {
        todo!()
    }

    /// Whether the VMK is absent. Ports the `locked` getter in
    /// `src/store/vault.js`.
    pub fn locked(&self) -> bool {
        todo!()
    }

    /// Unlock with whatever material was supplied; installs the VMK and
    /// audit log only once both worked; records `vault.unlock`. Returns the
    /// factor that opened it, or AV_LOCKED naming the factors. Ports
    /// `Vault.prototype.unlockWith` in `src/store/vault.js`.
    pub fn unlock_with(&mut self, material: &UnlockMaterial) -> Result<FactorClass> {
        todo!()
    }

    /// Unlock with a passphrase (or nothing, for the `none` factor). Ports
    /// `Vault.prototype.unlock` in `src/store/vault.js`.
    pub fn unlock(&mut self, passphrase: Option<&SecretString>) -> Result<bool> {
        todo!()
    }

    /// Add or replace the passphrase factor (at least 8 characters; the
    /// current one is required to change it, else AV_LOCKED); drops the
    /// `none` wrap; records `presence.factor_added`. Ports
    /// `Vault.prototype.setPassphrase` in `src/store/vault.js`.
    pub fn set_passphrase(
        &mut self,
        new_passphrase: &SecretString,
        current_passphrase: Option<&SecretString>,
    ) -> Result<()> {
        todo!()
    }

    /// Refuse (rule `factor_order`) unless a passphrase is set. Ports
    /// `Vault.prototype.requireRecoveryFactor` in `src/store/vault.js`.
    pub fn require_recovery_factor(&self) -> Result<()> {
        todo!()
    }

    /// Add a Touch ID (WebAuthn PRF) unlock wrap; needs the passphrase
    /// (factor invariant). Ports `Vault.prototype.addWebauthnUnlock` in
    /// `src/store/vault.js`.
    pub fn add_webauthn_unlock(
        &mut self,
        credential_id: &str,
        prf_secret: &SecretBytes,
    ) -> Result<()> {
        todo!()
    }

    /// Remove the PRF wrap (downgrading to `none` rather than leaving no
    /// wrap). Returns whether there was one. Ports
    /// `Vault.prototype.removeWebauthnUnlock` in `src/store/vault.js`.
    pub fn remove_webauthn_unlock(&mut self) -> Result<bool> {
        todo!()
    }

    /// Whether a PRF wrap exists. Ports the `hasWebauthnUnlock` getter in
    /// `src/store/vault.js`.
    pub fn has_webauthn_unlock(&self) -> Result<bool> {
        todo!()
    }

    /// The PRF wrap's credential id. Ports the `webauthnUnlockCredentialId`
    /// getter in `src/store/vault.js`.
    pub fn webauthn_unlock_credential_id(&self) -> Result<Option<String>> {
        todo!()
    }

    /// Enrol or replace the presence authenticator, validated completely
    /// first (raw JSON input, see [`presence_key_record`]); records
    /// `presence.factor_added`. Returns whether one was replaced. Ports
    /// `Vault.prototype.setPresenceKey` in `src/store/vault.js`.
    pub fn set_presence_key(&mut self, input: &Value) -> Result<bool> {
        todo!()
    }

    /// The enrolled presence authenticator. No JS method: replaces the
    /// daemon's direct read of `vault.db.kv.webauthn` in
    /// `src/daemon/server.js`.
    pub fn presence_key(&self) -> Result<Option<PresenceKey>> {
        todo!()
    }

    /// Store an authenticator's newer signature counter. No JS method:
    /// replaces `enrolled.signCount = result.signCount; this.vault.save()`
    /// in `src/daemon/server.js`.
    pub fn record_presence_sign_count(&mut self, sign_count: u32) -> Result<()> {
        todo!()
    }

    /// The stable PRF salt (base64 32 bytes), created on first call. Ports
    /// `Vault.prototype.prfSalt` in `src/store/vault.js`.
    pub fn prf_salt(&mut self) -> Result<String> {
        todo!()
    }

    /// Drop the passphrase (the current one is required, else AV_LOCKED),
    /// falling back to a `none` wrap if it was the only one; the invariant
    /// refuses removing the last human factor. Returns false when none was
    /// set. Ports `Vault.prototype.removePassphrase` in `src/store/vault.js`.
    pub fn remove_passphrase(&mut self, current_passphrase: &SecretString) -> Result<bool> {
        todo!()
    }

    /// Whether a passphrase wrap exists. Ports the `hasPassphrase` getter in
    /// `src/store/vault.js`.
    pub fn has_passphrase(&self) -> Result<bool> {
        todo!()
    }

    /// Confirm a passphrase without changing anything; false if none is set
    /// or it is wrong. Blocking (Argon2id). Ports
    /// `Vault.prototype.verifyPassphrase` in `src/store/vault.js`.
    pub fn verify_passphrase(&self, passphrase: &SecretString) -> Result<bool> {
        todo!()
    }

    /// Record `vault.lock`, drop the VMK and the audit key, and persist the
    /// lock. Ports `Vault.prototype.lock` in `src/store/vault.js`.
    pub fn lock(&mut self) -> Result<()> {
        todo!()
    }

    /// Whether the vault was locked and not unlocked since. Ports the
    /// `lockedOnDisk` getter in `src/store/vault.js`.
    pub fn locked_on_disk(&self) -> Result<bool> {
        todo!()
    }

    /// Come up in the state the vault was left in: a vault recorded as
    /// locked is opened only to record `vault.started_locked`, then
    /// relocked. Returns whether it is unlocked. Ports
    /// `Vault.prototype.startInRecordedState` in `src/store/vault.js`.
    pub fn start_in_recorded_state(&mut self, passphrase: Option<&SecretString>) -> Result<bool> {
        todo!()
    }

    /// The placeholder checksum key (AV_LOCKED while locked). Ports the
    /// `kPh` getter in `src/store/vault.js`.
    pub fn k_ph(&self) -> Result<Key32> {
        todo!()
    }

    /// The fingerprint key (AV_LOCKED while locked). Ports the
    /// `kFingerprint` getter in `src/store/vault.js`.
    pub fn k_fingerprint(&self) -> Result<Key32> {
        todo!()
    }

    /// The session-token key (AV_LOCKED while locked). No JS method: ports
    /// `crypt.kToken(vault.vmk)` as the daemon would call it.
    pub fn k_token(&self) -> Result<Key32> {
        todo!()
    }

    /// The audit log, while unlocked. Ports `this.audit` in
    /// `src/store/vault.js`.
    pub fn audit(&self) -> Option<&AuditLog> {
        todo!()
    }

    /// The audit log, mutably, while unlocked (the daemon writes its own
    /// records). Ports `this.audit` in `src/store/vault.js`.
    pub fn audit_mut(&mut self) -> Option<&mut AuditLog> {
        todo!()
    }

    // ---------------------------------------------------- credentials

    /// Store a credential, every value sealed; records `cred.added`.
    /// AV_NOT_FOUND for a taken or invalid slug or field name. Ports
    /// `Vault.prototype.addCredential` in `src/store/vault.js`.
    pub fn add_credential(&mut self, input: NewCredential) -> Result<PublicCredential> {
        todo!()
    }

    /// A credential by slug. Ports `Vault.prototype.findCredential` in
    /// `src/store/vault.js`.
    pub fn find_credential(&self, slug: &str) -> Result<Option<CredentialRecord>> {
        todo!()
    }

    /// A credential by id. No JS method: replaces `vault.db.credentials[id]`
    /// in `src/daemon/*.js`.
    pub fn credential(&self, cred_id: &str) -> Result<Option<CredentialRecord>> {
        todo!()
    }

    /// Every credential record (sealed). No JS method: replaces
    /// `Object.values(vault.db.credentials)` in `src/daemon/*.js`.
    pub fn credential_records(&self) -> Result<Vec<CredentialRecord>> {
        todo!()
    }

    /// The credential as anything outside the daemon may see it. Pure.
    /// Ports `Vault.prototype.publicCredential` in `src/store/vault.js`.
    pub fn public_credential(&self, cred: &CredentialRecord) -> PublicCredential {
        todo!()
    }

    /// Every credential, public view. Ports
    /// `Vault.prototype.listCredentials` in `src/store/vault.js`.
    pub fn list_credentials(&self) -> Result<Vec<PublicCredential>> {
        todo!()
    }

    /// Decrypt one field for a request: the pipeline's only path to a
    /// plaintext. Refuses a quarantined credential (AV_QUARANTINED). Ports
    /// `Vault.prototype.revealField` in `src/store/vault.js`.
    pub fn reveal_field(&self, cred_id: &str, field: &str) -> Result<SecretString> {
        todo!()
    }

    /// `untrustedText` over this vault's stored secrets (placeholders and
    /// the bound only, while locked). Ports `Vault.prototype.untrustedText`
    /// in `src/store/vault.js`.
    pub fn untrusted_text(&self, text: &str, max: usize) -> Result<String> {
        todo!()
    }

    /// Every unsealed value, retired ones inside their window included, for
    /// the scrubber. Ports `Vault.prototype.allSecrets` in
    /// `src/store/vault.js`.
    pub fn all_secrets(&self) -> Result<Vec<StoredSecret>> {
        todo!()
    }

    /// Set or clear (none) the human's expiry note; records
    /// `cred.expiry_set`. Ports `Vault.prototype.setCredentialExpiry` in
    /// `src/store/vault.js`.
    pub fn set_credential_expiry(
        &mut self,
        slug: &str,
        iso: Option<&str>,
    ) -> Result<PublicCredential> {
        todo!()
    }

    /// Merge an observation (raw JSON patch; only typed keys are kept);
    /// records `cred.health_recorded` only on a change of status or observed
    /// expiry. None while locked or for an unknown credential. Ports
    /// `Vault.prototype.recordHealth` in `src/store/vault.js`.
    pub fn record_health(
        &mut self,
        cred_id_or_slug: &str,
        patch: &Value,
    ) -> Result<Option<HealthRecord>> {
        todo!()
    }

    /// Quarantine a credential (a second call keeps the first record);
    /// records `cred.quarantined`. Ports `Vault.prototype.setQuarantine` in
    /// `src/store/vault.js`.
    pub fn set_quarantine(
        &mut self,
        slug: &str,
        opts: QuarantineOptions,
    ) -> Result<QuarantineRecord> {
        todo!()
    }

    /// Release a quarantine; false if there was none. Ports
    /// `Vault.prototype.clearQuarantine` in `src/store/vault.js`.
    pub fn clear_quarantine(&mut self, slug: &str) -> Result<bool> {
        todo!()
    }

    /// The owner settings (open while locked). Ports
    /// `Vault.prototype.getSettings` in `src/store/vault.js`.
    pub fn get_settings(&self) -> Result<Settings> {
        todo!()
    }

    /// Shallow-merge a settings patch (raw JSON object; key grammar and
    /// `tripwires` checked whole first); records `settings.changed`. Ports
    /// `Vault.prototype.updateSettings` in `src/store/vault.js`.
    pub fn update_settings(&mut self, patch: &Value) -> Result<Settings> {
        todo!()
    }

    /// Add a scrub pattern (F4): bounds, no placeholder, no stored value,
    /// compiles under the gateway's grammar; records its digest only. Ports
    /// `Vault.prototype.addScrubPattern` in `src/store/vault.js`.
    pub fn add_scrub_pattern(&mut self, slug: &str, source: &str) -> Result<ScrubPattern> {
        todo!()
    }

    /// Remove a scrub pattern; false (nothing recorded) if absent. Ports
    /// `Vault.prototype.removeScrubPattern` in `src/store/vault.js`.
    pub fn remove_scrub_pattern(&mut self, slug: &str, pattern_id: &str) -> Result<bool> {
        todo!()
    }

    /// Pin a host this credential reaches to 1..=4 SPKI digests, replacing
    /// its list (at most 4 hosts). Ports `Vault.prototype.setPins` in
    /// `src/store/vault.js`.
    pub fn set_pins(&mut self, slug: &str, host: &str, pins: &[String]) -> Result<PinsSet> {
        todo!()
    }

    /// Remove one pin of a host, or all (`spki` none). Returns how many
    /// stay. Ports `Vault.prototype.clearPins` in `src/store/vault.js`.
    pub fn clear_pins(&mut self, slug: &str, host: &str, spki: Option<&str>) -> Result<u64> {
        todo!()
    }

    /// Replace a field's value (F7); the old one is retired, compared in
    /// constant time to refuse the same value. Ports
    /// `Vault.prototype.rotateCredential` in `src/store/vault.js`.
    pub fn rotate_credential(&mut self, slug: &str, opts: RotateOptions) -> Result<RotateResult> {
        todo!()
    }

    // ------------------------------------------------------- notify

    /// Configure the approval webhook (https, or http to loopback; no
    /// userinfo; at most 2048 chars); sealed at rest. Ports
    /// `Vault.prototype.setNotifyWebhook` in `src/store/vault.js`.
    pub fn set_notify_webhook(
        &mut self,
        url: &SecretString,
        detail: NotifyDetail,
    ) -> Result<NotifyConfig> {
        todo!()
    }

    /// The URL itself. Daemon-internal. Ports
    /// `Vault.prototype.getNotifyWebhook` in `src/store/vault.js`.
    pub fn get_notify_webhook(&self) -> Result<Option<NotifyWebhook>> {
        todo!()
    }

    /// What anyone may see: host, detail, time. Ports
    /// `Vault.prototype.notifyConfig` in `src/store/vault.js`.
    pub fn notify_config(&self) -> Result<Option<NotifyConfig>> {
        todo!()
    }

    /// Remove the webhook; false if none. Ports
    /// `Vault.prototype.clearNotifyWebhook` in `src/store/vault.js`.
    pub fn clear_notify_webhook(&mut self) -> Result<bool> {
        todo!()
    }

    // ---------------------------------------------------- templates

    /// Save a named session shape (raw JSON spec; hashed over its canonical
    /// operation form). Ports `Vault.prototype.saveTemplate` in
    /// `src/store/vault.js`.
    pub fn save_template(&mut self, name: &str, spec: &Value) -> Result<TemplateRecord> {
        todo!()
    }

    /// A template by name. Ports `Vault.prototype.getTemplate` in
    /// `src/store/vault.js`.
    pub fn get_template(&self, name: &str) -> Result<Option<TemplateRecord>> {
        todo!()
    }

    /// Every template, by name. Ports `Vault.prototype.listTemplates` in
    /// `src/store/vault.js`.
    pub fn list_templates(&self) -> Result<Vec<TemplateRecord>> {
        todo!()
    }

    /// Remove a template; false if absent. Ports
    /// `Vault.prototype.deleteTemplate` in `src/store/vault.js`.
    pub fn delete_template(&mut self, name: &str) -> Result<bool> {
        todo!()
    }

    // ------------------------------------------------------- backup

    /// Every credential as a backup carries it, values unsealed. Only the
    /// export calls this, behind a fresh proof of presence. Ports
    /// `Vault.prototype.backupCredentials` in `src/store/vault.js`.
    pub fn backup_credentials(&self) -> Result<Vec<BackupCredential>> {
        todo!()
    }

    /// Put a backup's credentials and templates back, all or nothing, never
    /// releasing a quarantine. Ports `Vault.prototype.restoreEntries` in
    /// `src/store/vault.js`.
    pub fn restore_entries(&mut self, entries: RestoreEntries) -> Result<RestoreEntriesResult> {
        todo!()
    }

    /// Delete a credential, revoking its grants. Ports
    /// `Vault.prototype.deleteCredential` in `src/store/vault.js`.
    pub fn delete_credential(&mut self, slug: &str) -> Result<()> {
        todo!()
    }

    // --------------------------------------------------- workspaces

    /// Add a workspace; records `policy.approved`. Ports
    /// `Vault.prototype.addWorkspace` in `src/store/vault.js`.
    pub fn add_workspace(&mut self, name: &str, policy: Policy) -> Result<WorkspaceRecord> {
        todo!()
    }

    /// A workspace by id or name. Ports `Vault.prototype.findWorkspace` in
    /// `src/store/vault.js`.
    pub fn find_workspace(&self, name_or_id: &str) -> Result<Option<WorkspaceRecord>> {
        todo!()
    }

    /// Every workspace. No JS method: replaces
    /// `Object.values(vault.db.workspaces)` in `src/daemon/*.js`.
    pub fn workspaces(&self) -> Result<Vec<WorkspaceRecord>> {
        todo!()
    }

    // ----------------------------------------------------- sessions

    /// Create a session (every argument checked first; lifetime clamped to
    /// the cap). Ports `Vault.prototype.createSession` in
    /// `src/store/vault.js`.
    pub fn create_session(&mut self, opts: CreateSessionOptions) -> Result<CreatedSession> {
        todo!()
    }

    /// A session by sid. No JS method: replaces `vault.db.sessions[sid]` in
    /// `src/daemon/*.js`.
    pub fn session(&self, sid: &str) -> Result<Option<SessionRecord>> {
        todo!()
    }

    /// Every session. No JS method: replaces
    /// `Object.values(vault.db.sessions)` in `src/daemon/*.js`.
    pub fn sessions(&self) -> Result<Vec<SessionRecord>> {
        todo!()
    }

    /// The session a bearer token names (by SHA-256, compared in constant
    /// time), in any state. Ports `Vault.prototype.sessionByToken` in
    /// `src/store/vault.js`.
    pub fn session_by_token(&self, token: &str) -> Result<Option<SessionRecord>> {
        todo!()
    }

    /// Refuse a missing, revoked or ended session; mark one past its end
    /// expired (and its placeholders dead). Returns the session as stored.
    /// Ports `Vault.prototype.assertSessionLive` in `src/store/vault.js`.
    pub fn assert_session_live(
        &mut self,
        session: Option<&SessionRecord>,
    ) -> Result<SessionRecord> {
        todo!()
    }

    /// C12 then liveness: an infinite session is refused on a network
    /// listener (recorded as `remote.denied` unless `peek` or not `record`).
    /// Ports `Vault.prototype.assertSessionUsable` in `src/store/vault.js`.
    pub fn assert_session_usable(
        &mut self,
        session: Option<&SessionRecord>,
        listener: Option<&ListenerContext>,
        opts: UsableOptions,
    ) -> Result<SessionRecord> {
        todo!()
    }

    /// Idle extension, never past the ceiling; false when nothing was
    /// touched. Ports `Vault.prototype.touchSession` in `src/store/vault.js`.
    pub fn touch_session(&mut self, sid: &str) -> Result<bool> {
        todo!()
    }

    /// Bring a session's end closer (never later); an infinite one becomes
    /// finite; its live placeholders come down with it. Ports
    /// `Vault.prototype.shortenSession` in `src/store/vault.js`.
    pub fn shorten_session(&mut self, sid: &str, ttl_ms: i64) -> Result<SessionRecord> {
        todo!()
    }

    /// Revoke a session, its grants and its placeholders. Ports
    /// `Vault.prototype.revokeSession` in `src/store/vault.js` (`reason`
    /// defaults to `revoked`).
    pub fn revoke_session(&mut self, sid: &str, reason: &str) -> Result<()> {
        todo!()
    }

    /// Fork a live session: grants copied with policy intersected, never
    /// outliving their originals. Ports `Vault.prototype.forkSession` in
    /// `src/store/vault.js`.
    pub fn fork_session(&mut self, parent_sid: &str, opts: ForkOptions) -> Result<CreatedSession> {
        todo!()
    }

    /// Delete revoked or expired sessions (and their grants and
    /// placeholder rows) older than `retention_days`. The audit log keeps
    /// their history. No JS source: rust/PLAN.md, "Intended changes".
    pub fn prune_history(&mut self, now_ms: i64) -> Result<PruneReport> {
        todo!()
    }

    // ------------------------------------------------------- grants

    /// Create a grant on a live session for an unquarantined credential.
    /// Ports `Vault.prototype.createGrant` in `src/store/vault.js`.
    pub fn create_grant(&mut self, opts: CreateGrantOptions) -> Result<GrantRecord> {
        todo!()
    }

    /// A grant by id. No JS method: replaces `vault.db.grants[id]` in
    /// `src/daemon/*.js`.
    pub fn grant(&self, grant_id: &str) -> Result<Option<GrantRecord>> {
        todo!()
    }

    /// Every grant. No JS method: replaces `Object.values(vault.db.grants)`
    /// in `src/daemon/*.js`.
    pub fn grants(&self) -> Result<Vec<GrantRecord>> {
        todo!()
    }

    /// The newest grant for a session and credential, in any state. Ports
    /// `Vault.prototype.findGrant` in `src/store/vault.js`.
    pub fn find_grant(&self, sid: &str, cred_id: &str) -> Result<Option<GrantRecord>> {
        todo!()
    }

    /// The one place a grant's lifetime is decided (AV_NO_GRANT /
    /// AV_GRANT_EXPIRED); noticing the end kills it and its placeholders.
    /// Ports `Vault.prototype.assertGrantLive` in `src/store/vault.js`.
    pub fn assert_grant_live(&mut self, grant: Option<&GrantRecord>) -> Result<GrantRecord> {
        todo!()
    }

    /// A session's active grants. Ports `Vault.prototype.grantsForSession`
    /// in `src/store/vault.js`.
    pub fn grants_for_session(&self, sid: &str) -> Result<Vec<GrantRecord>> {
        todo!()
    }

    /// Charge `n` requests that spend no placeholder use (F6); false and
    /// nothing charged when over budget or unreadable. Ports
    /// `Vault.prototype.chargeGrant` in `src/store/vault.js`.
    pub fn charge_grant(&mut self, grant_id: &str, n: u64) -> Result<bool> {
        todo!()
    }

    /// Revoke a grant and its placeholders (no-op if absent). Ports
    /// `Vault.prototype.revokeGrant` in `src/store/vault.js`.
    pub fn revoke_grant(&mut self, grant_id: &str, reason: &str) -> Result<()> {
        todo!()
    }

    /// Bring a grant's end closer. Ports `Vault.prototype.shortenGrant` in
    /// `src/store/vault.js`.
    pub fn shorten_grant(&mut self, grant_id: &str, ttl_ms: i64) -> Result<GrantRecord> {
        todo!()
    }

    /// Narrow a grant by intersection (raw JSON layer; `redirects` may only
    /// be turned off). Ports `Vault.prototype.narrowGrant` in
    /// `src/store/vault.js`.
    pub fn narrow_grant(&mut self, grant_id: &str, narrow: &Value) -> Result<GrantRecord> {
        todo!()
    }

    // ------------------------------------------------- placeholders

    /// Issue a placeholder against a live grant, rotating the oldest active
    /// ones past `max_active`. Ports `Vault.prototype.issuePlaceholder` in
    /// `src/store/vault.js`.
    pub fn issue_placeholder(&mut self, opts: IssueOptions) -> Result<IssuedPlaceholder> {
        todo!()
    }

    /// The ledger row for a parsed placeholder, by nonce hash compared in
    /// constant time. Ports `Vault.prototype.resolvePlaceholder` in
    /// `src/store/vault.js`.
    pub fn resolve_placeholder(
        &self,
        parsed: &ParsedPlaceholder,
    ) -> Result<Option<PlaceholderRow>> {
        todo!()
    }

    /// Spend one use before any upstream byte (AV_PH_EXHAUSTED, AV_PH_STALE
    /// or AV_PH_REPLAY on a dead row). Ports
    /// `Vault.prototype.consumePlaceholder` in `src/store/vault.js`.
    pub fn consume_placeholder(&mut self, row_id: &str) -> Result<PlaceholderRow> {
        todo!()
    }

    /// Give back a use and a budget unit when nothing reached the upstream,
    /// only into a still-live grant and session; recorded either way. Ports
    /// `Vault.prototype.refundPlaceholder` in `src/store/vault.js`.
    pub fn refund_placeholder(&mut self, row_id: &str) -> Result<()> {
        todo!()
    }

    /// Kill a placeholder (`reason` defaults to `burned`). Ports
    /// `Vault.prototype.burnPlaceholder` in `src/store/vault.js`.
    pub fn burn_placeholder(&mut self, row_id: &str, reason: &str) -> Result<PlaceholderRow> {
        todo!()
    }

    /// Idempotent successor inheriting the predecessor's `max_uses`. Ports
    /// `Vault.prototype.nextPlaceholder` in `src/store/vault.js`.
    pub fn next_placeholder(&mut self, row_id: &str) -> Result<NextPlaceholder> {
        todo!()
    }

    /// Ledger rows, for one session or all. Ports
    /// `Vault.prototype.listPlaceholders` in `src/store/vault.js`.
    pub fn list_placeholders(&self, sid: Option<&str>) -> Result<Vec<PlaceholderRow>> {
        todo!()
    }

    // ---------------------------------------------------- listeners

    /// Add a listener; refuses non-networkable surfaces off loopback
    /// (AV_REMOTE_FORBIDDEN, recorded as `listen.refused`). Ports
    /// `Vault.prototype.addListener` in `src/store/vault.js`.
    pub fn add_listener(&mut self, entry: NewListener) -> Result<ListenerRecord> {
        todo!()
    }

    /// Remove a listener. Ports `Vault.prototype.removeListener` in
    /// `src/store/vault.js`.
    pub fn remove_listener(&mut self, lid: &str) -> Result<()> {
        todo!()
    }

    /// Every listener. Ports `Vault.prototype.listListeners` in
    /// `src/store/vault.js`.
    pub fn list_listeners(&self) -> Result<Vec<ListenerRecord>> {
        todo!()
    }

    // -------------------------------------------- daemon-owned state

    /// Persisted session requests. No JS method: replaces the read of
    /// `vault.db.kv.session_requests` in `src/daemon/session-requests.js`.
    pub fn session_requests(&self) -> Result<Vec<SessionRequestRecord>> {
        todo!()
    }

    /// Replace the persisted session requests (questions only, never a
    /// result). No JS method: replaces `#save` in
    /// `src/daemon/session-requests.js`.
    pub fn save_session_requests(&mut self, rows: &[SessionRequestRecord]) -> Result<()> {
        todo!()
    }

    /// Extra UI origins. No JS method: replaces reads of
    /// `vault.db.kv.ui_origins` in `src/daemon/server.js`.
    pub fn ui_origins(&self) -> Result<Vec<String>> {
        todo!()
    }

    /// Add a UI origin (kept once). No JS method: replaces the write of
    /// `vault.db.kv.ui_origins` in `src/daemon/server.js`.
    pub fn add_ui_origin(&mut self, origin: &str) -> Result<()> {
        todo!()
    }

    // ---------------------------------------------------------- misc

    /// Flush. Every operation already commits its own transaction, so this
    /// only forces a durable checkpoint when asked. Ports
    /// `Vault.prototype.save` in `src/store/vault.js`.
    pub fn save(&mut self, opts: SaveOptions) -> Result<()> {
        todo!()
    }

    /// The enrolled factor classes. Ports the `factors` getter in
    /// `src/store/vault.js`.
    pub fn factors(&self) -> Result<Vec<FactorClass>> {
        todo!()
    }

    /// Counts for status. Ports `Vault.prototype.stats` in
    /// `src/store/vault.js`.
    pub fn stats(&self) -> Result<VaultStats> {
        todo!()
    }
}
