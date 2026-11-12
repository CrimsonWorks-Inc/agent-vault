//! The vault's entity records. Ports the shapes the JS keeps in `vault.json`
//! (`EMPTY` and every record built in `src/store/vault.js`, plus the rows
//! `src/daemon/pipeline.js`, `src/daemon/session-requests.js` and
//! `src/daemon/server.js` keep in `vault.db.kv`).
//!
//! Field names equal the JS JSON keys, so `serde_json` reads a JS record
//! as-is and the SQLite columns can be named the same. Secrets appear only
//! sealed: never a plaintext value, a VMK or a token.
//!
//! Records that hold a sealed value are generic over the sealed format: `S =
//! SealedV2` in the SQLite vault, `S = SealedV1` when `migrate` reads
//! `vault.json` ([`LegacyDocument`]).

use std::collections::BTreeMap;

use av_core::policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::{Argon2Params, SealedV1, SealedV2};

// ---------------------------------------------------------------- factors

/// An unlock factor class. Ports `FACTOR_CLASSES` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum FactorClass {
    /// The UID boundary alone; the device key opens the vault. The default.
    #[default]
    #[serde(rename = "none")]
    None,
    /// A passphrase.
    #[serde(rename = "passphrase")]
    Passphrase,
    /// A WebAuthn PRF (Touch ID) secret. Never on its own: the passphrase is
    /// its recovery.
    #[serde(rename = "webauthn-prf")]
    WebauthnPrf,
}

/// One VMK wrap: the VMK sealed under a KEK derived from the device key and
/// one factor. Ports the object `#wrapVmk` returns in `src/store/vault.js`
/// (`{class, salt, ...sealed, credential_id?}`), with `kdf` added by
/// rust/PLAN.md, "Crypto contract" (Argon2id parameters stored next to the
/// wrap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct VmkWrap<S = SealedV2> {
    /// Which factor opens it.
    pub class: FactorClass,
    /// Base64 16-byte KDF salt for a passphrase wrap, else null.
    pub salt: Option<String>,
    /// The passphrase KDF's parameters (v2 only; absent in a JS wrap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Argon2Params>,
    /// The sealed VMK (base64 of the 32 raw bytes, sealed under the KEK with
    /// AAD `av/vmk/<class>`).
    #[serde(flatten)]
    pub sealed: S,
    /// The WebAuthn credential a `webauthn-prf` wrap belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

/// An enrolled factor, kept in step with the wraps. Ports the
/// `kv.presence_factors` entries (`{class, enrolled_at}`) in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceFactor {
    /// The factor class.
    pub class: FactorClass,
    /// ISO time it was enrolled.
    pub enrolled_at: String,
}

/// The presence authenticator (`kv.webauthn`): the ES256 key every presence
/// gate verifies signatures from. Public key material only. Keys are
/// camelCase, as the JS writes them. Ports the record `presenceKeyRecord`
/// returns in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceKey {
    /// Base64url WebAuthn credential id (16..=1023 bytes).
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    /// Base64 DER SPKI of a P-256 public key.
    #[serde(rename = "publicKeySpki")]
    pub public_key_spki: String,
    /// The authenticator's signature counter.
    #[serde(rename = "signCount")]
    pub sign_count: u32,
    /// ISO time of enrolment.
    #[serde(rename = "enrolledAt")]
    pub enrolled_at: String,
}

/// The factor state the invariant is checked on: `{ vmk_wraps, webauthn }`.
/// Ports the `prev`/`next` argument shape of `assertFactorInvariant` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FactorState {
    /// Every VMK wrap.
    pub vmk_wraps: Vec<VmkWrap>,
    /// The presence authenticator, if enrolled.
    pub webauthn: Option<PresenceKey>,
}

// ------------------------------------------------------------- vault meta

/// The vault's own singleton metadata (the scalar keys of `kv`). Ports
/// `kv.created_at`, `kv.locked`, `kv.audit_anchored`, `kv.vault_id`,
/// `kv.prf_salt` and `kv.ui_origins` in `src/store/vault.js` and
/// `src/daemon/server.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VaultMeta {
    /// ISO creation time.
    #[serde(default)]
    pub created_at: Option<String>,
    /// True while locked on disk (a lock survives a restart).
    #[serde(default)]
    pub locked: bool,
    /// True once this vault is known to keep an audit head anchor.
    #[serde(default)]
    pub audit_anchored: bool,
    /// Stable `vlt_` id that witness checkpoints name; created on first use.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// Base64 32-byte salt the WebAuthn PRF is evaluated against.
    #[serde(default)]
    pub prf_salt: Option<String>,
    /// Extra web UI origins the daemon accepts assertions from.
    #[serde(default)]
    pub ui_origins: Vec<String>,
}

// --------------------------------------------------------------- settings

/// Owner settings (`kv.settings`): a shallow map of `[a-z][a-z0-9_]{0,31}`
/// keys to JSON values. Typed readers: [`TripwireSettings`] under
/// `tripwires`, and `retention_days` (rust/PLAN.md, "Intended changes").
/// Ports `kv.settings` in `src/store/vault.js`.
pub type Settings = Map<String, Value>;

/// `settings.tripwires` (F16). Ports the shape `tripwireProblem` checks in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireSettings {
    /// Whether the rules run.
    pub enabled: bool,
    /// At most `MAX_TRIPWIRE_RULES` rules.
    pub rules: Vec<TripwireRule>,
}

/// One tripwire rule. Ports `RULE_KEYS` and the checks in `tripwireProblem`
/// in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireRule {
    /// `[a-z0-9_-]{1,32}`, unique.
    pub id: String,
    /// 1..=16 `AV_*` codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<Vec<String>>,
    /// `[a-z0-9_:.-]{1,64}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_prefix: Option<String>,
    /// 1..=1000.
    pub threshold: u32,
    /// 10..=86400.
    pub window_s: u32,
    /// What fires.
    pub action: TripwireAction,
}

/// A tripwire's action. Ports `RULE_ACTIONS` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireAction {
    /// Revoke the offending session.
    RevokeSession,
    /// Quarantine the credential.
    QuarantineCredential,
    /// Panic: revoke everything.
    Panic,
}

// ----------------------------------------------------------------- notify

/// How much an approval notification says. Ports the `detail` values
/// checked in `setNotifyWebhook` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyDetail {
    /// Only that something is waiting.
    Minimal,
    /// The headline too.
    Headline,
}

/// The approval-notification webhook (`kv.notify`, F14). The URL is a
/// bearer credential, so it is only ever sealed (DEK `notify`, AAD
/// `av/notify/webhook`); only the host is shown. Ports the object
/// `setNotifyWebhook` stores in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct NotifyRecord<S = SealedV2> {
    /// The sealed URL.
    pub sealed: S,
    /// `host[:port]` of the URL.
    pub host: String,
    /// Detail level.
    pub detail: NotifyDetail,
    /// ISO time configured.
    pub configured_at: String,
}

// ------------------------------------------------------------- workspaces

/// A workspace. Ports the object `addWorkspace` builds in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    /// `ws_<ulid>`.
    pub id: String,
    /// Display name (also a lookup key).
    pub name: String,
    /// Default policy layer.
    pub default_policy: Policy,
    /// Hex SHA-256 of `JSON.stringify(policy)` at creation.
    pub policy_sha256: String,
    /// Always `active` today.
    pub state: String,
    /// ISO creation time.
    pub created_at: String,
}

// ------------------------------------------------------------ credentials

/// A stored credential. Ports the record `#sealCredential` builds, and the
/// keys later operations add (`expires_at`, `health`, `quarantine`,
/// `scrub_patterns`, `pins`), in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct CredentialRecord<S = SealedV2> {
    /// `cred_<ulid>`.
    pub id: String,
    /// `[a-z0-9-]{1,24}`, unique.
    pub slug: String,
    /// Connector kind (a `PROFILES` key).
    pub connector_kind: String,
    /// Connector configuration (host, auth scheme, ...). No secrets.
    #[serde(default)]
    pub connector: Map<String, Value>,
    /// Sealed fields.
    pub fields: Vec<CredentialField<S>>,
    /// ISO creation time.
    pub created_at: String,
    /// The human's note of when it stops working (F10).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// What was last observed (F10).
    #[serde(default)]
    pub health: Option<HealthRecord>,
    /// Set while quarantined (F16).
    #[serde(default)]
    pub quarantine: Option<QuarantineRecord>,
    /// Extra scrub patterns (F4).
    #[serde(default)]
    pub scrub_patterns: Vec<ScrubPattern>,
    /// SPKI pins per canonical host (F11): host -> `sha256/<b64>` list.
    #[serde(default)]
    pub pins: BTreeMap<String, Vec<String>>,
}

/// One sealed credential field. AAD `<cred_id>|<name>|<key_version>`. Ports
/// the `stored.push({...})` object in `#sealCredential` and the
/// `Object.assign(f, ...)` in `rotateCredential` in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct CredentialField<S = SealedV2> {
    /// Field name.
    pub name: String,
    /// The sealed value.
    #[serde(flatten)]
    pub sealed: S,
    /// Starts at 1, +1 per rotation.
    pub key_version: u32,
    /// Substitution sites (site spec strings).
    #[serde(default)]
    pub sites: Vec<String>,
    /// `fingerprint8` under `k_fingerprint`.
    pub fp8: String,
    /// Plaintext length (JS `value.length`, UTF-16 units). Never shown
    /// exactly; see `size_bucket`.
    pub length: u64,
    /// ISO time of the last rotation.
    #[serde(default)]
    pub rotated_at: Option<String>,
    /// Rotated-out values still scrubbed until `retire_until` (F7).
    #[serde(default)]
    pub retired: Vec<RetiredValue<S>>,
}

/// A rotated-out field value, kept sealed only so an echo of it is still
/// scrubbed. Ports the object pushed into `retired` in `rotateCredential` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>"))]
pub struct RetiredValue<S = SealedV2> {
    /// The sealed old value.
    #[serde(flatten)]
    pub sealed: S,
    /// Its key version (part of the AAD).
    pub key_version: u32,
    /// ISO time it was retired.
    pub retired_at: String,
    /// ISO time after which it is dropped.
    pub retire_until: String,
}

/// A credential's observed health (F10). Ports the object `recordHealth`
/// builds in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRecord {
    /// Last status.
    pub status: HealthStatus,
    /// HTTP status, 100..=599.
    pub http_status: Option<u16>,
    /// ISO time checked.
    pub checked_at: String,
    /// Where it was observed.
    pub source: HealthSource,
    /// An expiry the upstream reported.
    pub observed_expires_at: Option<String>,
    /// Scopes the upstream reported (at most 64, each at most 128 chars).
    pub scopes: Option<Vec<String>>,
}

/// Ports `HEALTH_STATUS` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Worked.
    Ok,
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// Could not connect.
    Unreachable,
    /// Anything else.
    Error,
    /// Not known yet.
    Unknown,
}

/// Ports `HEALTH_SOURCE` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthSource {
    /// A read-only probe.
    Probe,
    /// The headers of a proxied response.
    Response,
}

/// A credential's quarantine (F16). Ports the object `setQuarantine` stores
/// in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    /// ISO time it started.
    pub since: String,
    /// Who set it.
    pub by: QuarantineBy,
    /// The tripwire rule, when `by` is `tripwire`.
    pub rule_id: Option<String>,
    /// Caller-written reason, at most 200 chars. Untrusted text.
    pub reason_untrusted: Option<String>,
}

/// Who quarantined a credential. Ports the `by` values checked in
/// `setQuarantine` in `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineBy {
    /// The control API (default).
    #[default]
    Control,
    /// A tripwire rule.
    Tripwire,
}

/// A scrub pattern (F4). Stored in clear and listed. Ports the object
/// `addScrubPattern` stores in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubPattern {
    /// `sp_<ulid>`.
    pub id: String,
    /// The pattern source, 3..=256 chars.
    pub source: String,
    /// ISO time added.
    pub added_at: String,
}

// --------------------------------------------------------------- sessions

/// A session's state. Ports the `state` values `src/store/vault.js` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Live (subject to its dates).
    Active,
    /// Noticed past its end. Final.
    Expired,
    /// Revoked. Final.
    Revoked,
}

/// A session. Only the token's hash is stored. Ports the object
/// `createSession` builds (and `parent_sid` from `forkSession`) in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The sid (`ph.newSid()`, 12 base32 chars).
    pub id: String,
    /// Owning workspace.
    pub workspace_id: Option<String>,
    /// Free text from whoever created it (never audited).
    pub label: String,
    /// Hex SHA-256 of the bearer token `avs1.<sid>.<secret>`.
    pub token_hash: String,
    /// Session policy layer.
    pub policy: Policy,
    /// Uid of the creating peer.
    pub owner_uid: Option<u32>,
    /// Created for network use.
    pub remote: bool,
    /// Client name, if given.
    pub client_name: Option<String>,
    /// State.
    pub state: SessionState,
    /// ISO creation time.
    pub created_at: String,
    /// ISO end; null only for an infinite session.
    pub expires_at: Option<String>,
    /// ISO ceiling for idle extension; null when infinite.
    pub max_expires_at: Option<String>,
    /// Idle extension step; null when infinite.
    pub idle_timeout_ms: Option<u64>,
    /// R3: never expires (only with `expires_at` null). Sessions written
    /// before R3 have no such field; JS reads them as not infinite
    /// (`s.infinite === true`).
    #[serde(default)]
    pub infinite: bool,
    /// C3 elevations it was created with (`approval_auto_writes`,
    /// `infinite`).
    #[serde(default)]
    pub elevated: Vec<String>,
    /// F17 template name.
    #[serde(default)]
    pub template: Option<String>,
    /// F17 template version.
    #[serde(default)]
    pub template_version: Option<u32>,
    /// ISO time last used.
    pub last_seen_at: String,
    /// The parent, for a fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_sid: Option<String>,
}

// ----------------------------------------------------------------- grants

/// A grant's state. Ports the `state` values `src/store/vault.js` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantState {
    /// Live (subject to `expires_at`).
    Active,
    /// Past its own end (F18).
    Expired,
    /// Revoked.
    Revoked,
}

/// Per-grant counters. Ports `counters` in `createGrant` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrantCounters {
    /// Requests charged.
    pub requests: u64,
    /// Denials counted.
    pub denials: u64,
}

/// A grant: one credential's fields, under a policy, for one session. Ports
/// the object `createGrant` builds in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantRecord {
    /// `gr_<ulid>`.
    pub id: String,
    /// Owning session.
    pub session_id: String,
    /// The credential.
    pub credential_id: String,
    /// Field names it covers.
    pub fields: Vec<String>,
    /// Grant policy layer.
    pub policy: Policy,
    /// Requests charged against the budget.
    pub budget_used: u64,
    /// Counters.
    #[serde(default)]
    pub counters: GrantCounters,
    /// State.
    pub state: GrantState,
    /// ISO creation time.
    pub created_at: String,
    /// ISO end of its own (F18); null lives as long as the session.
    pub expires_at: Option<String>,
}

/// A grant's runtime state, which the JS pipeline keeps on the grant object
/// in `vault.json` beside `policy`: the rolling quota window
/// (`grant.quota_state`, `{window_ms, start, count, prev}`, set by `#quota`
/// in `src/daemon/pipeline.js`) and the spend ledger (`grant.spend`,
/// `{tokens_used, usd_micros_used, reserved: {<request_id>: {tokens,
/// usd_micros, at}}}`, set by `#checkSpend`, `#settleSpend`, `#refundSpend`
/// and `#recoverSpend`). Both are kept as the JSON the JS wrote; `None` is
/// the JS default (a fresh window, zero spend).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GrantRuntime {
    /// `grant.quota_state`, or `None` before the first charge.
    pub quota_state: Option<serde_json::Value>,
    /// `grant.spend`, or `None` before the first reservation.
    pub spend: Option<serde_json::Value>,
}

// ----------------------------------------------------------- placeholders

/// A ledger row's state. Ports the `state` values `src/store/vault.js` sets.
/// A dead row never returns to active except by `refundPlaceholder` (an
/// `exhausted` row; the SQLite trigger must allow exactly that).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaceholderState {
    /// Usable.
    Active,
    /// Not usable; see `dead_reason`.
    Dead,
}

/// Why a placeholder died. Ports the `dead_reason` strings in
/// `src/store/vault.js` (`burnPlaceholder` also stores any caller reason).
pub mod dead_reason {
    /// Uses spent.
    pub const EXHAUSTED: &str = "exhausted";
    /// Its own end passed, or its grant's.
    pub const EXPIRED: &str = "expired";
    /// Its session ended or was revoked.
    pub const SESSION_ENDED: &str = "session_ended";
    /// Replaced under `max_active`.
    pub const ROTATED: &str = "rotated";
    /// Its grant was revoked.
    pub const REVOKED: &str = "revoked";
    /// `burnPlaceholder` default.
    pub const BURNED: &str = "burned";
}

/// A placeholder ledger row: the only thing that authorizes an injection.
/// Only the nonce's hash is stored. Ports the `row` object
/// `issuePlaceholder` builds in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceholderRow {
    /// `ph_<ulid>`.
    pub id: String,
    /// The grant it spends.
    pub grant_id: String,
    /// The credential.
    pub credential_id: String,
    /// The field.
    pub field: String,
    /// The session id.
    pub sid: String,
    /// `ph.hashNonce(nonce)`.
    pub nonce_hash: String,
    /// Uses spent.
    pub uses: u64,
    /// Use ceiling.
    pub max_uses: u64,
    /// State.
    pub state: PlaceholderState,
    /// Why dead (see [`dead_reason`]).
    pub dead_reason: Option<String>,
    /// The row this one succeeds (`nextPlaceholder`).
    pub replaces_id: Option<String>,
    /// ISO creation time.
    pub created_at: String,
    /// ISO end; null never expires (infinite session, no grant end).
    pub expires_at: Option<String>,
    /// ISO time last used.
    pub last_used_at: Option<String>,
}

// -------------------------------------------------------------- approvals

/// A held request's state. Ports the `state` values in
/// `src/daemon/pipeline.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalState {
    /// Waiting for a human.
    Pending,
    /// Approved.
    Granted,
    /// Refused.
    Denied,
    /// Approved and executed once (exactly-once).
    Consumed,
}

/// A request held for human approval. The JS keeps these in memory
/// (`pipeline.approvals`) and `vault.json` has an always-empty `approvals`
/// map; the Rust port may persist them (rust/PLAN.md, "agent-vault migrate"
/// step 6). The upstream `result` is never stored. Ports the `approval`
/// object built in `Pipeline.prototype` (`#hold`) in `src/daemon/pipeline.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// `ap_<ulid>`.
    pub id: String,
    /// Hash of the held request (the map key in the JS).
    pub request_hash: String,
    /// The grant it would spend.
    pub grant_id: String,
    /// Scrubbed one-line summary.
    pub summary: String,
    /// Agent-written reason, scrubbed. Untrusted text.
    pub reason: Option<String>,
    /// Scrubbed preview of what would be sent (F13).
    #[serde(default)]
    pub preview: Option<Value>,
    /// State.
    pub state: ApprovalState,
    /// ISO creation time.
    pub created_at: String,
    /// ISO decision time.
    #[serde(default)]
    pub decided_at: Option<String>,
    /// Why denied.
    #[serde(default)]
    pub denied_reason: Option<String>,
    /// ISO time the approved request ran.
    #[serde(default)]
    pub executed_at: Option<String>,
}

/// A session request's state. Ports the `state` values in
/// `src/daemon/session-requests.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionRequestState {
    /// Waiting for a human.
    Pending,
    /// Approved (the result lives in memory only).
    Approved,
    /// Refused.
    Denied,
    /// Approved but never collected in time.
    Expired,
}

/// An agent's request for a session (C25), as persisted in
/// `kv.session_requests`: never the `result`, which carries a token. Ports
/// the `record` built in `SessionRequests.prototype.create` and written by
/// `#save` in `src/daemon/session-requests.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRequestRecord {
    /// `sr_<ulid>`.
    pub id: String,
    /// Hex SHA-256 of the asker's collect secret.
    pub collect_hash: String,
    /// The proposal as the agent sent it.
    pub proposal: Value,
    /// Fingerprint of the proposal.
    pub fingerprint: String,
    /// Human-readable summary.
    pub summary: String,
    /// Agent-written reason. Untrusted text.
    pub reason_untrusted: Option<String>,
    /// State.
    pub state: SessionRequestState,
    /// ISO creation time.
    pub created_at: String,
    /// ISO decision time.
    pub decided_at: Option<String>,
}

// ---------------------------------------------------------------- clients

/// A registered client. The JS declares `clients: {}` in `EMPTY` and the
/// `cl_` id prefix but never writes a record, so the shape is open: the id
/// plus whatever keys a record carries. Ports `EMPTY.clients` in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// `cl_<ulid>`.
    pub id: String,
    /// Every other key, as stored.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// -------------------------------------------------------------- listeners

/// A listener's TLS configuration. Ports `entry.tls` built by `listen add`
/// in `src/cli/index.js` (`{managed: true}` or `{cert, key}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerTls {
    /// The daemon's own certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    /// Absolute path of a certificate (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// Absolute path of its key (PEM). A path, never key material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// A configured network listener. Ports the record `addListener` stores
/// (`{...entry, created_at, state: 'configured'}`) in `src/store/vault.js`,
/// with the entry keys `listen add` sends in `src/cli/index.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerRecord {
    /// Caller-chosen id.
    pub id: String,
    /// `host:port` or `unix:<path>`.
    pub address: String,
    /// Surfaces served (`gateway`, `mcp`, ...).
    #[serde(default)]
    pub surfaces: Vec<String>,
    /// Advertised names.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Always `bearer` today.
    #[serde(default)]
    pub client_auth: Option<String>,
    /// Allowed source CIDRs.
    #[serde(default)]
    pub allow_cidr: Vec<String>,
    /// TLS, required off loopback.
    #[serde(default)]
    pub tls: Option<ListenerTls>,
    /// ISO creation time.
    pub created_at: String,
    /// Always `configured` today.
    pub state: String,
}

// -------------------------------------------------------------- templates

/// A saved session shape (F17). Ports the object `#templateRecord` builds in
/// `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateRecord {
    /// `[a-z0-9][a-z0-9-]{0,31}`.
    pub name: String,
    /// Starts at 1, +1 per save.
    pub version: u32,
    /// The session-create spec, as JSON.
    pub spec: Map<String, Value>,
    /// Hex SHA-256 of `canonicalOperation(spec)`.
    pub hash: String,
    /// ISO first save.
    pub created_at: String,
    /// ISO last save.
    pub updated_at: String,
}

// ------------------------------------------------------- legacy vault.json

/// `vault.json`'s `kv` as the JS writes it. Read only, by `migrate`. Ports
/// `EMPTY.kv` and every key added to it in `src/store/vault.js`,
/// `src/daemon/server.js` and `src/daemon/session-requests.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyKv {
    /// VMK wraps in the v1 sealed format.
    pub vmk_wraps: Vec<VmkWrap<SealedV1>>,
    /// Enrolled factors.
    #[serde(default)]
    pub presence_factors: Vec<PresenceFactor>,
    /// Owner settings.
    #[serde(default)]
    pub settings: Settings,
    /// Scalar metadata (`created_at`, `locked`, `audit_anchored`,
    /// `vault_id`, `prf_salt`, `ui_origins`).
    #[serde(flatten)]
    pub meta: VaultMeta,
    /// Presence authenticator.
    #[serde(default)]
    pub webauthn: Option<PresenceKey>,
    /// Notify webhook in the v1 sealed format.
    #[serde(default)]
    pub notify: Option<NotifyRecord<SealedV1>>,
    /// Waiting session requests.
    #[serde(default)]
    pub session_requests: Vec<SessionRequestRecord>,
}

/// The whole `vault.json` document. Read only, by `migrate`. Ports `EMPTY`
/// (plus `templates`) in `src/store/vault.js`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyDocument {
    /// Must be <= `vault::SCHEMA_VERSION`.
    pub schema_version: u32,
    /// Factors, settings and metadata.
    pub kv: LegacyKv,
    /// Workspaces by id.
    #[serde(default)]
    pub workspaces: BTreeMap<String, WorkspaceRecord>,
    /// Credentials by id, v1 sealed.
    #[serde(default)]
    pub credentials: BTreeMap<String, CredentialRecord<SealedV1>>,
    /// Sessions by sid.
    #[serde(default)]
    pub sessions: BTreeMap<String, SessionRecord>,
    /// Grants by id.
    #[serde(default)]
    pub grants: BTreeMap<String, GrantRecord>,
    /// Each grant's `quota_state` and `spend`, by grant id, read beside
    /// `grants` (they are siblings of `policy` on the JS grant object).
    #[serde(skip)]
    pub grant_runtime: BTreeMap<String, GrantRuntime>,
    /// Placeholder ledger by id.
    #[serde(default)]
    pub placeholders: BTreeMap<String, PlaceholderRow>,
    /// Always empty in the JS (approvals live in memory).
    #[serde(default)]
    pub approvals: BTreeMap<String, ApprovalRecord>,
    /// Always empty in the JS.
    #[serde(default)]
    pub clients: BTreeMap<String, ClientRecord>,
    /// Listeners by id.
    #[serde(default)]
    pub listeners: BTreeMap<String, ListenerRecord>,
    /// Templates by name (absent until the first save).
    #[serde(default)]
    pub templates: BTreeMap<String, TemplateRecord>,
}
