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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use av_core::pins::PinListState;
use av_core::placeholder::ParsedPlaceholder;
use av_core::policy::{BudgetLimit, Policy};
use av_core::secret::{ExposeSecret, Key32, SecretBytes, SecretString};
use av_core::{deny, DenyExtra, ErrorCode};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::audit::{lock_conn, AnchorStamp, AuditLog, SharedConn};
use crate::backup::{
    BackupCredential, BackupField, BackupScrubPattern, BackupTemplate, PlannedCredential,
};
use crate::crypto;
use crate::error::{CryptoError, Error, Result};
use crate::ids;
use crate::mlock::LockedKey;
use crate::model::{
    dead_reason, CredentialField, CredentialRecord, FactorClass, FactorState, GrantCounters,
    GrantRecord, GrantState, HealthRecord, HealthSource, HealthStatus, ListenerRecord,
    ListenerTls, NotifyDetail, NotifyRecord, PlaceholderRow, PlaceholderState, PresenceFactor,
    PresenceKey, QuarantineBy, QuarantineRecord, RetiredValue, ScrubPattern, SessionRecord,
    SessionRequestRecord, SessionState, Settings, TemplateRecord, VmkWrap, WorkspaceRecord,
};
use crate::rows;
use crate::util;

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
    match iso {
        None => f64::INFINITY,
        Some(s) => util::parse_ms(s).map_or(f64::NEG_INFINITY, |ms| ms as f64),
    }
}

/// When a session ends: infinite only with `infinite == true` and
/// `expires_at` null; any other missing date is already past. Ports
/// `sessionExpiryMs` in `src/store/vault.js`.
pub fn session_expiry_ms(session: &SessionRecord) -> f64 {
    match session.expires_at.as_deref() {
        None if session.infinite => f64::INFINITY,
        None => f64::NEG_INFINITY,
        Some(s) => expiry_ms(Some(s)),
    }
}

/// The furthest a session could live, idle extension included. Ports
/// `sessionCeilingMs` in `src/store/vault.js`.
pub fn session_ceiling_ms(session: &SessionRecord) -> f64 {
    let ends = session_expiry_ms(session);
    if ends == f64::INFINITY || ends <= f64::NEG_INFINITY {
        return ends;
    }
    match session.max_expires_at.as_deref() {
        None => ends,
        Some(m) => ends.max(expiry_ms(Some(m))),
    }
}

/// A ledger row's end: exactly null never expires. Ports `rowExpiryMs` in
/// `src/store/vault.js`.
pub fn row_expiry_ms(row: &PlaceholderRow) -> f64 {
    expiry_ms(row.expires_at.as_deref())
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
    let dates: Vec<&str> = [
        cred.expires_at.as_deref(),
        cred.health
            .as_ref()
            .and_then(|h| h.observed_expires_at.as_deref()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if dates.is_empty() {
        return None;
    }
    let ends = dates
        .iter()
        .map(|d| expiry_ms(Some(d)))
        .fold(f64::INFINITY, f64::min);
    let now = now_ms as f64;
    if ends <= now {
        return Some(ExpiryWarning::Expired);
    }
    (ends < now + (EXPIRY_WARN_DAYS * DAY_MS) as f64).then_some(ExpiryWarning::Soon)
}

fn presence_refusal(why: &str) -> Error {
    deny(
        ErrorCode::PolicyDenied,
        format!("not a usable presence authenticator: {why}"),
        DenyExtra {
            rule: Some("presence_key".into()),
            hint: Some("Nothing was changed, and the authenticator already enrolled (if any) still works. Enrol the new one from the web UI: agent-vault ui".into()),
            next: Some("agent-vault ui".into()),
            ..Default::default()
        },
    )
    .into()
}

/// A presence authenticator as the vault stores it, or a refusal
/// (AV_POLICY_DENIED, rule `presence_key`): a base64url credential id of
/// 16..=1023 bytes that round-trips, a base64 DER SPKI that parses as a
/// P-256 key, and a 32-bit `signCount` (default 0). Only those fields are
/// kept. Takes raw JSON because the type checks are part of the contract.
/// Ports `presenceKeyRecord` in `src/store/vault.js`.
pub fn presence_key_record(input: &Value) -> Result<PresenceKey> {
    use base64::Engine as _;
    use p256::pkcs8::DecodePublicKey as _;
    let obj = match input {
        Value::Object(o) => o,
        // An array passes the JS `typeof === 'object'` check and then has
        // no credentialId.
        Value::Array(_) => return Err(presence_refusal("credentialId must be a base64url string")),
        _ => return Err(presence_refusal("no credential was given")),
    };
    let credential_id = match obj.get("credentialId") {
        Some(Value::String(s))
            if !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') =>
        {
            s.clone()
        }
        _ => return Err(presence_refusal("credentialId must be a base64url string")),
    };
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&credential_id)
        .ok();
    let ok_id = raw.as_ref().is_some_and(|r| {
        (16..=1023).contains(&r.len())
            && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r) == credential_id
    });
    if !ok_id {
        return Err(presence_refusal("credentialId is not a WebAuthn credential id"));
    }
    let spki = match obj.get("publicKeySpki") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(presence_refusal("publicKeySpki is missing")),
    };
    let Some(der) = crypto::b64_strict(&spki) else {
        return Err(presence_refusal("publicKeySpki is not base64"));
    };
    if p256::PublicKey::from_public_key_der(&der).is_err() {
        // Node tells "not a key" from "a key of another curve"; both refuse.
        let any_key = der.len() > 20 && der[0] == 0x30;
        return Err(presence_refusal(if any_key {
            "only ES256 (P-256) authenticators can be verified"
        } else {
            "publicKeySpki is not a public key"
        }));
    }
    let sign_count = match obj.get("signCount") {
        None => 0,
        Some(v) => match v.as_u64() {
            Some(n) if n <= 0xffff_ffff => n as u32,
            _ => match v.as_f64() {
                Some(f) if f.fract() == 0.0 && (0.0..=4_294_967_295.0).contains(&f) => f as u32,
                _ => return Err(presence_refusal("signCount must be a 32-bit counter")),
            },
        },
    };
    Ok(PresenceKey {
        credential_id,
        public_key_spki: spki,
        sign_count,
        enrolled_at: util::now_iso(),
    })
}

fn usable_presence_key(k: &PresenceKey) -> bool {
    serde_json::to_value(k)
        .ok()
        .is_some_and(|v| presence_key_record(&v).is_ok())
}

/// The human factors a factor state holds (`passphrase`, `authenticator`).
/// Ports `humanFactors` in `src/store/vault.js`.
pub fn human_factors(state: &FactorState) -> Vec<&'static str> {
    let mut out = Vec::new();
    if state
        .vmk_wraps
        .iter()
        .any(|w| w.class == FactorClass::Passphrase)
    {
        out.push("passphrase");
    }
    if state.webauthn.as_ref().is_some_and(usable_presence_key) {
        out.push("authenticator");
    }
    out
}

fn recovery_refusal() -> Error {
    deny(
        ErrorCode::PolicyDenied,
        "set a passphrase first; it is the recovery factor if the authenticator is lost",
        DenyExtra {
            rule: Some("factor_order".into()),
            hint: Some("Touch ID unlock needs a passphrase to fall back on if the authenticator is lost. Set one, then enable Touch ID unlock again: agent-vault passphrase set".into()),
            next: Some("agent-vault passphrase set".into()),
            ..Default::default()
        },
    )
    .into()
}

/// The factor invariant, and the one place it is enforced: (1) a vault with
/// a human factor is never left without one; (2) a `webauthn-prf` wrap
/// never exists without the passphrase wrap; (3) a presence authenticator is
/// only replaced by one that `presence_key_record` accepts. At least one
/// wrap must remain ([`crate::error::Error::Invariant`]). Every factor change
/// calls this on the state it is about to commit, before writing. Ports
/// `assertFactorInvariant` in `src/store/vault.js`.
pub fn assert_factor_invariant(prev: &FactorState, next: &FactorState) -> Result<()> {
    if next.vmk_wraps.is_empty() {
        return Err(Error::Invariant(
            "a factor change must leave at least one way to open the vault".into(),
        ));
    }
    if let Some(k) = next.webauthn.as_ref() {
        if prev.webauthn.as_ref() != Some(k) {
            presence_key_record(&serde_json::to_value(k)?)?;
        }
    }
    let has_passphrase = |s: &FactorState| {
        s.vmk_wraps
            .iter()
            .any(|w| w.class == FactorClass::Passphrase)
    };
    if next
        .vmk_wraps
        .iter()
        .any(|w| w.class == FactorClass::WebauthnPrf)
        && !has_passphrase(next)
    {
        if !has_passphrase(prev) {
            return Err(recovery_refusal());
        }
        return Err(deny(
            ErrorCode::PolicyDenied,
            "remove Touch ID unlock first; the passphrase is its recovery factor",
            DenyExtra {
                rule: Some("last_factor".into()),
                hint: Some("Touch ID unlock needs the passphrase to recover the vault if the authenticator is lost. Turn off Touch ID unlock in the web UI first (agent-vault ui), then remove the passphrase.".into()),
                next: Some("agent-vault ui".into()),
                ..Default::default()
            },
        )
        .into());
    }
    let had = human_factors(prev);
    if !had.is_empty() && human_factors(next).is_empty() {
        let losing = had.join(" and ");
        let pass = had.contains(&"passphrase");
        return Err(deny(
            ErrorCode::PolicyDenied,
            format!("the {losing} is this vault's last human factor; enrol another before removing it"),
            DenyExtra {
                rule: Some("last_factor".into()),
                hint: Some(if pass {
                    "Without a passphrase or an authenticator, anyone who reaches the control socket could widen access. Enrol a presence authenticator in the web UI first (agent-vault ui), then remove the passphrase."
                } else {
                    "Without an authenticator or a passphrase, anyone who reaches the control socket could widen access. Set a passphrase first: agent-vault passphrase set"
                }
                .into()),
                next: Some(if pass { "agent-vault ui" } else { "agent-vault passphrase set" }.into()),
                ..Default::default()
            },
        )
        .into());
    }
    Ok(())
}

fn js_key(k: &str) -> String {
    Value::from(k).to_string()
}

fn is_integer_in(v: Option<&Value>, lo: f64, hi: f64) -> bool {
    v.and_then(Value::as_f64)
        .is_some_and(|f| f.fract() == 0.0 && f >= lo && f <= hi)
}

fn all_chars(s: &str, min: usize, max: usize, ok: impl Fn(u8) -> bool) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(ok)
}

fn rule_id_ok(s: &str) -> bool {
    all_chars(s, 1, 32, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'
    })
}

/// What `tripwires` in a settings patch is wrong with, or none. Ports
/// `tripwireProblem` in `src/store/vault.js`.
pub fn tripwire_problem(tripwires: &Value) -> Option<String> {
    let Value::Object(tw) = tripwires else {
        return Some("tripwires must be an object".into());
    };
    for k in tw.keys() {
        if k != "enabled" && k != "rules" {
            return Some(format!("tripwires has an unknown key {}", js_key(k)));
        }
    }
    if !tw.get("enabled").is_some_and(Value::is_boolean) {
        return Some("tripwires.enabled must be true or false".into());
    }
    let Some(Value::Array(rules)) = tw.get("rules") else {
        return Some("tripwires.rules must be a list".into());
    };
    if rules.len() > MAX_TRIPWIRE_RULES {
        return Some(format!("at most {MAX_TRIPWIRE_RULES} tripwire rules"));
    }
    let mut ids = std::collections::HashSet::new();
    for r in rules {
        let Value::Object(r) = r else {
            return Some("a tripwire rule must be an object".into());
        };
        for k in r.keys() {
            if !RULE_KEYS.contains(&k.as_str()) {
                return Some(format!("a tripwire rule has an unknown key {}", js_key(k)));
            }
        }
        let id = match r.get("id") {
            Some(Value::String(s)) if rule_id_ok(s) => s.clone(),
            _ => return Some("a tripwire rule id must match [a-z0-9_-]{1,32}".into()),
        };
        if !ids.insert(id.clone()) {
            return Some(format!("tripwire rule {id} appears twice"));
        }
        if let Some(codes) = r.get("codes") {
            let ok = codes.as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.len() <= 16
                    && a.iter().all(|c| {
                        c.as_str().is_some_and(|c| {
                            c.strip_prefix("AV_").is_some_and(|rest| {
                                all_chars(rest, 1, 40, |b| {
                                    b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
                                })
                            })
                        })
                    })
            });
            if !ok {
                return Some(format!(
                    "tripwire rule {id}: codes must be a non-empty list of AV_* codes"
                ));
            }
        }
        if let Some(p) = r.get("rule_prefix") {
            let ok = p.as_str().is_some_and(|p| {
                all_chars(p, 1, 64, |b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b'_' | b':' | b'.' | b'-')
                })
            });
            if !ok {
                return Some(format!(
                    "tripwire rule {id}: rule_prefix must be 1-64 characters of [a-z0-9_:.-]"
                ));
            }
        }
        if r.get("codes").is_none() && r.get("rule_prefix").is_none() {
            return Some(format!(
                "tripwire rule {id} matches nothing: give codes or rule_prefix"
            ));
        }
        if !is_integer_in(r.get("threshold"), 1.0, 1000.0) {
            return Some(format!(
                "tripwire rule {id}: threshold must be an integer 1-1000"
            ));
        }
        if !is_integer_in(r.get("window_s"), 10.0, 86_400.0) {
            return Some(format!(
                "tripwire rule {id}: window_s must be an integer 10-86400"
            ));
        }
        let action_ok = matches!(
            r.get("action").and_then(Value::as_str),
            Some("revoke_session" | "quarantine_credential" | "panic")
        );
        if !action_ok {
            return Some(format!(
                "tripwire rule {id}: action must be revoke_session, quarantine_credential or panic"
            ));
        }
    }
    None
}

/// A coarse size label (`short` < 16, `typical` < 60, `long`, `unknown`), so
/// exact length never leaves the daemon. Ports `sizeBucket` in
/// `src/store/vault.js`.
pub fn size_bucket(len: Option<u64>) -> &'static str {
    match len {
        None => "unknown",
        Some(n) if n < 16 => "short",
        Some(n) if n < 60 => "typical",
        Some(_) => "long",
    }
}

/// Whether a listener address stays on this machine (`unix:`,
/// `127.0.0.1:`, `[::1]:`, `localhost:`). Ports `isLoopbackSpec` in
/// `src/store/vault.js`.
pub fn is_loopback_spec(address: &str) -> bool {
    ["unix:", "127.0.0.1:", "[::1]:", "localhost:"]
        .iter()
        .any(|p| address.starts_with(p))
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
        f.debug_struct("CreateOptions").finish_non_exhaustive()
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
        f.debug_struct("UnlockMaterial").finish_non_exhaustive()
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
        f.debug_struct("NewCredential").finish_non_exhaustive()
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
        f.debug_struct("StoredSecret").finish_non_exhaustive()
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
        f.debug_struct("RotateOptions").finish_non_exhaustive()
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
        f.debug_struct("NotifyWebhook").finish_non_exhaustive()
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
        f.debug_struct("CreatedSession").finish_non_exhaustive()
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
pub struct Vault {
    dir: PathBuf,
    conn: SharedConn,
    vmk: Option<LockedKey>,
    audit: Option<AuditLog>,
}

impl std::fmt::Debug for Vault {
    /// Redacted: the dir and whether it is locked, never key material. No
    /// JS source.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.dir)
            .field("locked", &self.vmk.is_none())
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------- internals

/// One operation's transaction: the connection inside it, the audit log (so
/// a change and its record commit together), and the VMK while unlocked.
struct Tx<'a> {
    c: &'a Connection,
    audit: Option<&'a mut AuditLog>,
    vmk: Option<Key32>,
    /// Commit even though the operation returns an error: the JS persists
    /// some changes (an expiry noticed, a refusal recorded) and then throws.
    keep: bool,
    /// Key material or a credential secret changed: checkpoint the WAL.
    checkpoint: bool,
    now: i64,
}

impl Tx<'_> {
    /// Append an audit record inside this transaction (skipped while locked,
    /// as the JS `this.audit?.write`).
    fn audit(&mut self, kind: &str, fields: Value) -> Result<()> {
        if let Some(a) = self.audit.as_deref_mut() {
            a.write_in(self.c, kind, obj(fields))?;
        }
        Ok(())
    }

    /// Append an audit record that must be written: refuses while locked.
    fn audit_required(&mut self, kind: &str, fields: Value) -> Result<()> {
        if self.audit.is_none() {
            return Err(locked_error());
        }
        self.audit(kind, fields)
    }

    fn vmk(&self) -> Result<&Key32> {
        self.vmk.as_ref().ok_or_else(locked_error)
    }

    fn require_unlocked(&self) -> Result<()> {
        self.vmk().map(|_| ())
    }

    fn now_iso(&self) -> String {
        util::iso(self.now)
    }
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn locked_error() -> Error {
    deny(ErrorCode::Locked, "the vault is locked", DenyExtra::default()).into()
}

fn refuse(code: ErrorCode, detail: impl Into<String>, rule: &str) -> Error {
    deny(
        code,
        detail,
        DenyExtra {
            rule: Some(rule.to_string()),
            ..Default::default()
        },
    )
    .into()
}

fn plain(code: ErrorCode, detail: impl Into<String>) -> Error {
    deny(code, detail, DenyExtra::default()).into()
}

fn quarantined(cred: &CredentialRecord) -> Error {
    deny(
        ErrorCode::Quarantined,
        format!("{} is quarantined", cred.slug),
        DenyExtra {
            rule: Some("quarantine".into()),
            hint: Some(format!(
                "A human can release it: agent-vault cred release {}",
                cred.slug
            )),
            ..Default::default()
        },
    )
    .into()
}

fn budget_spent(limit: BudgetLimit) -> Error {
    let detail = match limit {
        BudgetLimit::Limit(n) => format!("grant budget of {n} requests is spent"),
        _ => "this grant has a budget that cannot be read, so no request can be counted against it"
            .to_string(),
    };
    deny(
        ErrorCode::PolicyDenied,
        detail,
        DenyExtra {
            rule: Some("budget".into()),
            hint: Some("A human must widen the grant or start a new session.".into()),
            ..Default::default()
        },
    )
    .into()
}

fn scrub_refusal(why: &str) -> Error {
    refuse(
        ErrorCode::PolicyDenied,
        format!("scrub pattern refused: {why}"),
        "scrub_pattern",
    )
}

fn backup_format(why: &str) -> Error {
    refuse(
        ErrorCode::PolicyDenied,
        format!("not a usable backup: {why}"),
        "backup_format",
    )
}

/// JS `string.length`: UTF-16 code units.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The first `n` UTF-16 units of `s` (JS `slice(0, n)`), never splitting a
/// character.
fn js_slice(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for ch in s.chars() {
        units += ch.len_utf16();
        if units > n {
            break;
        }
        out.push(ch);
    }
    out
}

/// `min(current, now + ttl)` as an ISO date, or `now` when that is behind us.
/// Ports `shortenedIso` in `src/store/vault.js`.
fn shortened_iso(current: f64, now: i64, ttl_ms: i64) -> String {
    let at = current.min((now + ttl_ms) as f64);
    util::iso(if at > now as f64 { at as i64 } else { now })
}

/// A session's or grant's end as its creation record keeps it. Ports
/// `expiryForAudit` in `src/store/vault.js`.
fn expiry_for_audit(map: &mut Map<String, Value>, expires_at: Option<&str>, requested: bool) {
    if requested {
        map.insert("expires_at".into(), Value::Null);
        map.insert("has_expiry".into(), Value::Bool(expires_at.is_some()));
    } else {
        map.insert("expires_at".into(), expires_at.map_or(Value::Null, Value::from));
    }
}

/// The policy as the JSON the JS reads its keys from.
fn policy_json(p: &Policy) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

fn budget_of(p: &Policy) -> BudgetLimit {
    av_core::policy::budget_limit(p.budget.as_ref())
}

/// `phPolicy.max_active`: a safe integer of at least 1, else 8.
fn max_active_of(pp: &Value) -> u64 {
    pp.get("max_active")
        .and_then(Value::as_u64)
        .filter(|n| *n >= 1 && *n <= av_core::policy::MAX_SAFE_INTEGER)
        .unwrap_or(DEFAULT_MAX_ACTIVE)
}

/// `phPolicy.max_uses` when it is a finite number.
fn ph_max_uses(pp: &Value) -> Option<f64> {
    pp.get("max_uses").and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// A positive finite number, else no limit.
fn positive(n: Option<f64>) -> f64 {
    match n {
        Some(n) if n.is_finite() && n > 0.0 => n,
        _ => f64::INFINITY,
    }
}

fn read_device_key(dir: &Path) -> Result<Key32> {
    let bytes = Zeroizing::new(std::fs::read(dir.join(DEVICE_KEY_FILE))?);
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invariant("the device key is not 32 bytes".into()))?;
    Ok(Key32::from_bytes(arr))
}

/// What unlocks a wrap: a passphrase, a PRF secret, or nothing.
enum WrapMaterial<'a> {
    None,
    Passphrase(&'a SecretString),
    Prf(&'a [u8]),
}

/// The VMK sealed under the KEK for `class`. Ports `#wrapVmk` in
/// `src/store/vault.js`, with the passphrase under Argon2id.
fn wrap_vmk(device_key: &Key32, vmk: &Key32, material: WrapMaterial<'_>) -> Result<VmkWrap> {
    let (class, factor_key, salt, kdf) = match material {
        WrapMaterial::None => (FactorClass::None, Zeroizing::new(Vec::new()), None, None),
        WrapMaterial::Passphrase(p) => {
            let mut salt = [0u8; crypto::SALT_LEN];
            crypto::fill_random(&mut salt)?;
            let params = passphrase_params();
            let k = crypto::passphrase_factor(p, &salt, &params)?;
            (
                FactorClass::Passphrase,
                Zeroizing::new(k.expose().to_vec()),
                Some(crypto::b64(&salt)),
                Some(params),
            )
        }
        WrapMaterial::Prf(secret) => {
            if secret.len() < 32 {
                return Err(Error::Invariant("webauthn PRF secret must be 32 bytes".into()));
            }
            (
                FactorClass::WebauthnPrf,
                Zeroizing::new(secret.to_vec()),
                None,
                None,
            )
        }
    };
    let kek = crypto::derive_kek(device_key, &factor_key);
    let text = Zeroizing::new(crypto::b64(vmk.expose()));
    let sealed = crypto::seal(&kek, text.as_bytes(), &crypto::vmk_aad(class_name(class)))?;
    Ok(VmkWrap {
        class,
        salt,
        kdf,
        sealed,
        credential_id: None,
    })
}

/// The Argon2id parameters a new passphrase wrap is made with. Tests in this
/// crate use cheap ones; the parameters are stored beside each wrap, so
/// verifying reads whatever the wrap says.
pub(crate) fn passphrase_params() -> crypto::Argon2Params {
    if cfg!(test) {
        crypto::Argon2Params {
            alg: crypto::ArgonAlg::Argon2id,
            m: 256,
            t: 1,
            p: 1,
        }
    } else {
        crypto::PASSPHRASE_ARGON2
    }
}

pub(crate) fn class_name(c: FactorClass) -> &'static str {
    match c {
        FactorClass::None => "none",
        FactorClass::Passphrase => "passphrase",
        FactorClass::WebauthnPrf => "webauthn-prf",
    }
}

/// The factor key for a wrap given the material, or none when the material
/// cannot satisfy it. Ports `#factorKeyFor` in `src/store/vault.js`.
fn factor_key_for(wrap: &VmkWrap, material: &UnlockMaterial) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match wrap.class {
        FactorClass::Passphrase => {
            let Some(p) = material.passphrase.as_ref() else {
                return Ok(None);
            };
            let salt = wrap
                .salt
                .as_deref()
                .and_then(crypto::b64_decode)
                .ok_or(CryptoError::Malformed)?;
            let params = wrap.kdf.ok_or(CryptoError::Malformed)?;
            let k = crypto::passphrase_factor(p, &salt, &params)?;
            Ok(Some(Zeroizing::new(k.expose().to_vec())))
        }
        FactorClass::WebauthnPrf => {
            let Some(s) = material.prf_secret.as_ref() else {
                return Ok(None);
            };
            let bytes = s.expose_secret();
            Ok((bytes.len() >= 32).then(|| Zeroizing::new(bytes.to_vec())))
        }
        FactorClass::None => Ok(Some(Zeroizing::new(Vec::new()))),
    }
}

/// Open a wrap to the VMK.
fn open_wrap(device_key: &Key32, wrap: &VmkWrap, factor_key: &[u8]) -> Result<Key32> {
    let kek = crypto::derive_kek(device_key, factor_key);
    let text = crypto::open_string(&kek, &wrap.sealed, &crypto::vmk_aad(class_name(wrap.class)))?;
    let raw = Zeroizing::new(crypto::b64_decode(text.expose_secret()).ok_or(CryptoError::Malformed)?);
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(Key32::from_bytes(arr))
}

/// Whether `passphrase` opens the passphrase wrap. Blocking (Argon2id).
fn passphrase_opens(device_key: &Key32, wrap: &VmkWrap, passphrase: &SecretString) -> bool {
    let material = UnlockMaterial {
        passphrase: Some(passphrase.clone()),
        prf_secret: None,
    };
    matches!(factor_key_for(wrap, &material), Ok(Some(k)) if open_wrap(device_key, wrap, &k).is_ok())
}

/// The vault's stamp for its audit log: `audit_anchored` and `vault_id` in
/// `kv`. Ports `#anchorStamp` in `src/store/vault.js`.
struct VaultStamp {
    conn: SharedConn,
}

impl AnchorStamp for VaultStamp {
    fn anchored(&self) -> bool {
        let c = lock_conn(&self.conn);
        rows::kv_bool(&c, "audit_anchored").unwrap_or(false)
    }

    fn mark_anchored(&mut self) -> Result<()> {
        let c = lock_conn(&self.conn);
        if !rows::kv_bool(&c, "audit_anchored")? {
            rows::kv_set(&c, "audit_anchored", &Value::Bool(true))?;
        }
        Ok(())
    }

    fn vault_id(&mut self) -> Result<Option<String>> {
        let c = lock_conn(&self.conn);
        if let Some(id) = rows::kv_str(&c, "vault_id")?.filter(|s| !s.is_empty()) {
            return Ok(Some(id));
        }
        let id = ids::id::vault();
        rows::kv_set(&c, "vault_id", &Value::from(id.clone()))?;
        Ok(Some(id))
    }
}

/// `a` is `b`, or a restored copy of it, or `b` is one of `a`. Ports
/// `sameCredential` in `src/store/vault.js`.
fn same_credential(a: &str, b: &str) -> bool {
    fn copy_of(slug: &str, base: &str) -> bool {
        let Some(at) = slug.rfind("-restored") else {
            return false;
        };
        let tail = &slug[at + "-restored".len()..];
        let ok_tail = tail.is_empty()
            || tail
                .strip_prefix('-')
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()));
        if !ok_tail {
            return false;
        }
        let suffix_len = slug.len() - at;
        let keep = 24usize.saturating_sub(suffix_len).min(base.len());
        slug[..at] == base[..keep]
    }
    a == b || copy_of(a, b) || copy_of(b, a)
}

/// A bundle's quarantine record, checked by `setQuarantine`'s rules, or the
/// whole restore refused. Ports `restoredQuarantine` in `src/store/vault.js`.
fn restored_quarantine(q: &Value) -> Result<QuarantineRecord> {
    let bad = || backup_format("a quarantine record is malformed");
    let Value::Object(o) = q else {
        return Err(bad());
    };
    if !o
        .keys()
        .all(|k| ["since", "by", "rule_id", "reason_untrusted"].contains(&k.as_str()))
    {
        return Err(bad());
    }
    let since = o.get("since").and_then(Value::as_str).ok_or_else(bad)?;
    if util::parse_ms(since).is_none() {
        return Err(bad());
    }
    let by = match o.get("by").and_then(Value::as_str) {
        Some("control") => QuarantineBy::Control,
        Some("tripwire") => QuarantineBy::Tripwire,
        _ => return Err(bad()),
    };
    let rule_id = match o.get("rule_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if rule_id_ok(s) => Some(s.clone()),
        _ => return Err(bad()),
    };
    let reason = match o.get("reason_untrusted") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if js_len(s) <= 200 => Some(s.clone()),
        _ => return Err(bad()),
    };
    Ok(QuarantineRecord {
        since: since.to_string(),
        by,
        rule_id,
        reason_untrusted: reason,
    })
}

fn template_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A template's name and spec, checked; returns the spec's JSON. Ports
/// `#checkTemplate` in `src/store/vault.js`.
fn check_template(name: &str, spec: &Value) -> Result<String> {
    if !template_name_ok(name) {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "a template name is 1-32 characters of [a-z0-9-], starting with a letter or digit",
            "template_name",
        ));
    }
    let Value::Object(o) = spec else {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "a template spec is a session-create object",
            "session_shape",
        ));
    };
    for k in TEMPLATE_FORBIDDEN_KEYS {
        if o.contains_key(k) {
            return Err(refuse(
                ErrorCode::PolicyDenied,
                format!("a template spec cannot carry {k}"),
                "session_shape",
            ));
        }
    }
    let text = serde_json::to_string(spec)?;
    if text.len() > MAX_TEMPLATE_BYTES {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            format!("a template spec is at most {MAX_TEMPLATE_BYTES} bytes of JSON"),
            "template_size",
        ));
    }
    Ok(text)
}

/// Ports `#templateRecord` in `src/store/vault.js`.
fn template_record(name: &str, text: &str, old: Option<&TemplateRecord>, now: &str) -> Result<TemplateRecord> {
    let stored: Value = serde_json::from_str(text)?;
    let hash = crypto::sha256_hex(av_core::operation::canonical_operation(&stored).as_bytes());
    Ok(TemplateRecord {
        name: name.to_string(),
        version: old.map_or(1, |o| o.version + 1),
        spec: obj(stored),
        hash,
        created_at: old.map_or_else(|| now.to_string(), |o| o.created_at.clone()),
        updated_at: now.to_string(),
    })
}

/// F11: 1 to 4 pins of the one format, each kept once, or refused. Ports
/// `pinList` in `src/store/vault.js`.
fn pin_list(pins: &[String]) -> Result<Vec<String>> {
    let v = serde_json::to_value(pins)?;
    if av_core::pins::pin_list_state(Some(&v)) != PinListState::Pinned {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "pins are 1 to 4 values of the form sha256/<base64 of 32 bytes>",
            "pin_format",
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for p in pins {
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    Ok(out)
}

/// A copy of a pin table without any key that names `key`'s host. Ports
/// `pinTableOf` in `src/store/vault.js`.
fn pin_table_of(pins: &BTreeMap<String, Vec<String>>, key: &str) -> BTreeMap<String, Vec<String>> {
    pins.iter()
        .filter(|(k, _)| av_core::pins::url_host_of(k).as_deref() != Some(key))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The canonical pin key for `host`, refused unless this credential can
/// reach it. Ports `#pinHost` in `src/store/vault.js`.
fn pin_host(cred: &CredentialRecord, host: &str) -> Result<String> {
    let key = av_core::pins::url_host_of(host);
    let profile_hosts: Vec<String> = av_core::profiles::get_profile(&cred.connector_kind)
        .map(|p| p.hosts.iter().map(|h| h.to_string()).collect())
        .unwrap_or_default();
    let connector_host = cred.connector.get("host").and_then(Value::as_str);
    let ceiling = av_core::policy::credential_host_ceiling(connector_host, &profile_hosts);
    match key {
        Some(k)
            if ceiling.iter().any(|h| {
                av_core::pins::url_host_of(h).as_deref() == Some(k.as_str())
                    || av_core::policy::match_host(h, &k)
            }) =>
        {
            Ok(k)
        }
        _ => Err(refuse(
            ErrorCode::PolicyDenied,
            format!("{host} is not a host this credential reaches"),
            "pin_host",
        )),
    }
}

fn check_pin_hosts(pins: &BTreeMap<String, Vec<String>>) -> Result<()> {
    if pins.len() > MAX_PIN_HOSTS {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            format!("at most {MAX_PIN_HOSTS} hosts can be pinned"),
            "pin_host",
        ));
    }
    Ok(())
}

/// The source rules shared by add and restore. Ports `#checkScrubSource` in
/// `src/store/vault.js`.
fn check_scrub_source(source: &str, secrets: &[SecretString]) -> Result<()> {
    let n = js_len(source);
    if !(MIN_SCRUB_SOURCE..=MAX_SCRUB_SOURCE).contains(&n) {
        return Err(scrub_refusal(&format!(
            "a pattern is 3 to {MAX_SCRUB_SOURCE} characters"
        )));
    }
    if !av_core::placeholder::find_all(source).is_empty() {
        return Err(scrub_refusal("it contains a placeholder"));
    }
    for s in secrets {
        let s = s.expose_secret();
        if !s.is_empty() && source.contains(s) {
            return Err(scrub_refusal("it contains a stored credential value"));
        }
    }
    av_core::scrub::compile_scrub_pattern(source).map_err(Error::from)?;
    Ok(())
}

fn scrub_audit(t: &mut Tx<'_>, cred: &CredentialRecord, p: &ScrubPattern) -> Result<()> {
    t.audit_required(
        "cred.scrub_pattern_added",
        json!({
            "credential_slug": cred.slug,
            "pattern_id": p.id,
            "pattern_sha256": crypto::sha256_hex(p.source.as_bytes()),
            "length": js_len(&p.source),
        }),
    )
}

/// The value of one field, quarantined or not. Ports `#unseal`.
fn unseal(vmk: &Key32, cred: &CredentialRecord, field: &str) -> Result<SecretString> {
    let f = cred.fields.iter().find(|f| f.name == field).ok_or_else(|| {
        plain(
            ErrorCode::NotFound,
            format!("credential {} has no field {field}", cred.slug),
        )
    })?;
    let key = crypto::dek(vmk, &cred.id);
    crypto::open_string(&key, &f.sealed, &crypto::field_aad(&cred.id, &f.name, f.key_version))
}

/// Every unsealed value, retired ones in their window included. Ports
/// `allSecrets`.
fn all_secrets_in(c: &Connection, vmk: &Key32, now: i64) -> Result<Vec<StoredSecret>> {
    let mut out = Vec::new();
    for cred in rows::credentials_all(c)? {
        let key = crypto::dek(vmk, &cred.id);
        for f in &cred.fields {
            if let Ok(secret) = unseal(vmk, &cred, &f.name) {
                out.push(StoredSecret {
                    secret,
                    label: cred.slug.clone(),
                    field: f.name.clone(),
                    retired: false,
                });
            }
            for r in &f.retired {
                if expiry_ms(Some(&r.retire_until)) <= now as f64 {
                    continue;
                }
                if let Ok(secret) = crypto::open_string(
                    &key,
                    &r.sealed,
                    &crypto::field_aad(&cred.id, &f.name, r.key_version),
                ) {
                    out.push(StoredSecret {
                        secret,
                        label: cred.slug.clone(),
                        field: f.name.clone(),
                        retired: true,
                    });
                }
            }
        }
    }
    Ok(out)
}

fn core_secrets(list: &[StoredSecret]) -> Vec<av_core::scrub::StoredSecret> {
    list.iter()
        .map(|s| av_core::scrub::StoredSecret {
            secret: s.secret.clone(),
            label: s.label.clone(),
        })
        .collect()
}

/// A new credential record, every value sealed, not yet stored. Ports
/// `#sealCredential` in `src/store/vault.js`.
fn seal_credential(
    vmk: &Key32,
    slug: &str,
    kind: &str,
    connector: Map<String, Value>,
    fields: &[(String, SecretString)],
    sites: &BTreeMap<String, Vec<String>>,
    now: &str,
) -> Result<CredentialRecord> {
    if !av_core::placeholder::is_valid_slug(slug) {
        return Err(plain(
            ErrorCode::NotFound,
            format!("invalid slug \"{slug}\": use [a-z0-9-], 1-24 characters"),
        ));
    }
    let cred_id = ids::id::credential();
    let key = crypto::dek(vmk, &cred_id);
    let kfp = crypto::k_fingerprint(vmk);
    let mut stored = Vec::new();
    for (name, value) in fields {
        if !av_core::placeholder::is_valid_field(name) {
            return Err(plain(
                ErrorCode::NotFound,
                format!("invalid field name \"{name}\""),
            ));
        }
        let v = value.expose_secret();
        stored.push(CredentialField {
            name: name.clone(),
            sealed: crypto::seal(&key, v.as_bytes(), &crypto::field_aad(&cred_id, name, 1))?,
            key_version: 1,
            sites: sites.get(name).cloned().unwrap_or_default(),
            fp8: crypto::fingerprint8(&kfp, v.as_bytes()),
            length: js_len(v) as u64,
            rotated_at: None,
            retired: Vec::new(),
        });
    }
    Ok(CredentialRecord {
        id: cred_id,
        slug: slug.to_string(),
        connector_kind: kind.to_string(),
        connector,
        fields: stored,
        created_at: now.to_string(),
        expires_at: None,
        health: None,
        quarantine: None,
        scrub_patterns: Vec::new(),
        pins: BTreeMap::new(),
    })
}

/// The credential as anything outside the daemon may see it. Ports
/// `publicCredential`.
fn public_of(cred: &CredentialRecord, now: i64) -> PublicCredential {
    PublicCredential {
        id: cred.id.clone(),
        slug: cred.slug.clone(),
        kind: cred.connector_kind.clone(),
        connector: cred.connector.clone(),
        expires_at: cred.expires_at.clone(),
        health: cred.health.clone(),
        expiry_warning: expiry_warning(cred, now),
        quarantine: cred.quarantine.clone(),
        scrub_patterns: cred.scrub_patterns.clone(),
        pins: cred
            .pins
            .iter()
            .map(|(k, v)| (k.clone(), v.len() as u64))
            .collect(),
        fields: cred
            .fields
            .iter()
            .map(|f| PublicField {
                name: f.name.clone(),
                sites: f.sites.clone(),
                fp8: f.fp8.clone(),
                size: size_bucket(Some(f.length)).to_string(),
                version: f.key_version,
                rotated_at: f.rotated_at.clone(),
            })
            .collect(),
        probe_path: av_core::profiles::get_profile(&cred.connector_kind)
            .ok()
            .and_then(|p| p.probe.as_ref().map(|pr| pr.path.to_string())),
        created_at: cred.created_at.clone(),
    }
}

fn find_cred(c: &Connection, slug: &str) -> Result<CredentialRecord> {
    rows::credential_by_slug(c, slug)?
        .ok_or_else(|| plain(ErrorCode::NotFound, format!("no credential {slug}")))
}

/// Keep `presence_factors` in step with the wraps. Ports `#syncFactors`.
fn sync_factors(prev: &[PresenceFactor], wraps: &[VmkWrap], now: &str) -> Vec<PresenceFactor> {
    let mut classes: Vec<FactorClass> = Vec::new();
    for w in wraps {
        if !classes.contains(&w.class) {
            classes.push(w.class);
        }
    }
    classes
        .into_iter()
        .map(|c| {
            prev.iter()
                .find(|f| f.class == c)
                .cloned()
                .unwrap_or(PresenceFactor {
                    class: c,
                    enrolled_at: now.to_string(),
                })
        })
        .collect()
}

/// Commit a change to the factors: the wraps, the presence authenticator, or
/// both, after the factor invariant accepts the whole new state. Every
/// factor change in this crate goes through here. Ports `#commitFactors`.
fn commit_factors(
    t: &mut Tx<'_>,
    vmk_wraps: Option<Vec<VmkWrap>>,
    webauthn: Option<Option<PresenceKey>>,
) -> Result<()> {
    let prev = FactorState {
        vmk_wraps: rows::wraps_get(t.c)?,
        webauthn: rows::webauthn_get(t.c)?,
    };
    let next = FactorState {
        vmk_wraps: vmk_wraps.unwrap_or_else(|| prev.vmk_wraps.clone()),
        webauthn: webauthn.unwrap_or_else(|| prev.webauthn.clone()),
    };
    assert_factor_invariant(&prev, &next)?;
    let now = t.now_iso();
    rows::wraps_replace(t.c, &next.vmk_wraps, &now)?;
    if next.webauthn != prev.webauthn {
        rows::webauthn_put(t.c, next.webauthn.as_ref())?;
    }
    let factors = sync_factors(&rows::factors_get(t.c)?, &next.vmk_wraps, &now);
    rows::factors_replace(t.c, &factors)?;
    t.checkpoint = true;
    Ok(())
}

/// Ports `assertSessionLive` over a transaction.
fn session_live_in(t: &mut Tx<'_>, session: Option<&SessionRecord>) -> Result<SessionRecord> {
    let Some(s) = session else {
        return Err(plain(ErrorCode::SessionRequired, "no session"));
    };
    if s.state == SessionState::Revoked {
        return Err(plain(
            ErrorCode::SessionRevoked,
            format!("session {} was revoked", s.id),
        ));
    }
    if s.state != SessionState::Active {
        return Err(plain(
            ErrorCode::SessionExpired,
            format!("session {} has ended", s.id),
        ));
    }
    if session_expiry_ms(s) <= t.now as f64 {
        // Ended is final, and its placeholders die with it.
        if let Some(mut stored) = rows::session_get(t.c, &s.id)? {
            if stored.state == SessionState::Active {
                stored.state = SessionState::Expired;
                rows::session_put(t.c, &stored, &t.now_iso())?;
                rows::ph_kill_where(t.c, Some(&s.id), None, dead_reason::SESSION_ENDED)?;
                t.keep = true;
            }
        }
        return Err(plain(
            ErrorCode::SessionExpired,
            format!(
                "session {} expired at {}",
                s.id,
                s.expires_at.as_deref().unwrap_or("null")
            ),
        ));
    }
    Ok(s.clone())
}

/// Ports `assertGrantLive` over a transaction.
fn grant_live_in(t: &mut Tx<'_>, grant: Option<&GrantRecord>) -> Result<GrantRecord> {
    let g = match grant {
        Some(g) if g.state == GrantState::Active => g,
        other => {
            let id = other.map(|g| g.id.as_str()).unwrap_or("");
            return Err(plain(
                ErrorCode::NoGrant,
                format!("no active grant {id}").trim().to_string(),
            ));
        }
    };
    if expiry_ms(g.expires_at.as_deref()) <= t.now as f64 {
        let expired = plain(
            ErrorCode::GrantExpired,
            format!(
                "grant {} expired at {}",
                g.id,
                g.expires_at.as_deref().unwrap_or("null")
            ),
        );
        if t.vmk.is_none() {
            return Err(expired);
        }
        let mut stored = rows::grant_get(t.c, &g.id)?.unwrap_or_else(|| g.clone());
        stored.state = GrantState::Expired;
        rows::grant_put(t.c, &stored)?;
        rows::ph_kill_where(t.c, None, Some(&g.id), dead_reason::EXPIRED)?;
        t.audit(
            "grant.expired",
            json!({ "grant_id": g.id, "session_id": g.session_id }),
        )?;
        t.keep = true;
        return Err(expired);
    }
    Ok(g.clone())
}

/// Ports `revokeGrant` over a transaction.
fn revoke_grant_in(t: &mut Tx<'_>, grant_id: &str, reason: &str) -> Result<()> {
    t.require_unlocked()?;
    let Some(mut g) = rows::grant_get(t.c, grant_id)? else {
        return Ok(());
    };
    g.state = GrantState::Revoked;
    rows::grant_put(t.c, &g)?;
    rows::ph_kill_where(t.c, None, Some(grant_id), dead_reason::REVOKED)?;
    t.audit_required(
        "grant.revoked",
        json!({ "grant_id": grant_id, "reason": reason }),
    )
}

/// Ports `createSession` over a transaction.
fn create_session_in(t: &mut Tx<'_>, opts: &CreateSessionOptions) -> Result<CreatedSession> {
    use base64::Engine as _;
    t.require_unlocked()?;
    let ttl_rule = |d: &str| refuse(ErrorCode::PolicyDenied, d, "ttl");
    if opts.ttl_ms.is_some_and(|v| v <= 0) {
        return Err(ttl_rule("a session lifetime must be a positive number"));
    }
    if opts.infinite && opts.ttl_ms.is_some() {
        return Err(ttl_rule("an infinite session has no lifetime to set"));
    }
    if opts.infinite && opts.remote {
        return Err(refuse(
            ErrorCode::RemoteForbidden,
            "an infinite session can never be reached from the network",
            "infinite_remote",
        ));
    }
    if opts.elevated.len() > ELEVATIONS.len()
        || !opts.elevated.iter().all(|e| ELEVATIONS.contains(&e.as_str()))
    {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "elevated must list only approval_auto_writes and infinite",
            "elevation_invalid",
        ));
    }
    let template_ok = match (&opts.template, opts.template_version) {
        (None, None) => true,
        (Some(name), Some(v)) => template_name_ok(name) && v >= 1,
        _ => false,
    };
    if !template_ok {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "a session names its template and version together, or neither",
            "template_name",
        ));
    }
    let sid = av_core::placeholder::new_sid();
    let mut secret = Zeroizing::new([0u8; 33]);
    crypto::fill_random(secret.as_mut())?;
    let token = SecretString::from(format!(
        "avs1.{sid}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.as_ref())
    ));
    let now = t.now;
    let cap = if opts.remote {
        REMOTE_SESSION_CAP_MS
    } else {
        LOCAL_SESSION_CAP_MS
    };
    let life = opts.ttl_ms.unwrap_or(DEFAULT_SESSION_TTL_MS).min(cap);
    let ceiling = if opts.ttl_ms.is_none() { cap } else { life };
    let mut elevated: Vec<String> = Vec::new();
    for e in &opts.elevated {
        if !elevated.contains(e) {
            elevated.push(e.clone());
        }
    }
    let session = SessionRecord {
        id: sid.clone(),
        workspace_id: opts.workspace_id.clone().filter(|w| !w.is_empty()),
        label: opts
            .label
            .clone()
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| "session".into()),
        token_hash: crypto::sha256_hex(token.expose_secret().as_bytes()),
        policy: opts.policy.clone(),
        owner_uid: opts.peer_uid,
        remote: opts.remote,
        client_name: opts.client_name.clone(),
        state: SessionState::Active,
        created_at: util::iso(now),
        expires_at: (!opts.infinite).then(|| util::iso(now + life)),
        max_expires_at: (!opts.infinite).then(|| util::iso(now + ceiling)),
        idle_timeout_ms: (!opts.infinite).then_some(if opts.remote {
            REMOTE_IDLE_TIMEOUT_MS
        } else {
            LOCAL_IDLE_TIMEOUT_MS
        }),
        infinite: opts.infinite,
        elevated,
        template: opts.template.clone(),
        template_version: opts.template_version,
        last_seen_at: util::iso(now),
        parent_sid: None,
    };
    rows::session_put(t.c, &session, &t.now_iso())?;
    let mut f = Map::new();
    f.insert("session_id".into(), sid.clone().into());
    if let Some(w) = &opts.workspace_id {
        f.insert("workspace_id".into(), w.clone().into());
    }
    f.insert(
        "has_label".into(),
        opts.label.as_ref().is_some_and(|l| !l.is_empty()).into(),
    );
    f.insert("remote".into(), opts.remote.into());
    f.insert("infinite".into(), opts.infinite.into());
    expiry_for_audit(&mut f, session.expires_at.as_deref(), opts.requested);
    f.insert("elevated".into(), json!(session.elevated));
    f.insert("template".into(), json!(opts.template));
    f.insert("template_version".into(), json!(opts.template_version));
    t.audit_required("session.created", Value::Object(f))?;
    Ok(CreatedSession { session, token })
}

/// Ports `createGrant` over a transaction.
fn create_grant_in(t: &mut Tx<'_>, opts: &CreateGrantOptions) -> Result<GrantRecord> {
    t.require_unlocked()?;
    let session = rows::session_get(t.c, &opts.session_id)?.ok_or_else(|| {
        plain(
            ErrorCode::NotFound,
            format!("no session {}", opts.session_id),
        )
    })?;
    let cred = rows::credential_by_id(t.c, &opts.credential_id)?.ok_or_else(|| {
        plain(
            ErrorCode::NotFound,
            format!("no credential {}", opts.credential_id),
        )
    })?;
    if opts.ttl_ms.is_some_and(|v| v <= 0) {
        return Err(refuse(
            ErrorCode::PolicyDenied,
            "a grant lifetime must be a positive number",
            "grant_ttl",
        ));
    }
    session_live_in(t, Some(&session))?;
    if cred.quarantine.is_some() {
        return Err(quarantined(&cred));
    }
    let expires_at = opts.ttl_ms.map(|ttl| {
        let end = ((t.now + ttl) as f64).min(session_expiry_ms(&session));
        util::iso(end as i64)
    });
    let policy = match &opts.narrow {
        Some(n) if *n != Policy::default() => {
            av_core::policy::intersect(&[Some(&opts.policy), Some(n)])
        }
        _ => opts.policy.clone(),
    };
    let grant = GrantRecord {
        id: ids::id::grant(),
        session_id: opts.session_id.clone(),
        credential_id: opts.credential_id.clone(),
        fields: opts
            .fields
            .clone()
            .unwrap_or_else(|| cred.fields.iter().map(|f| f.name.clone()).collect()),
        policy,
        budget_used: 0,
        counters: GrantCounters::default(),
        state: GrantState::Active,
        created_at: t.now_iso(),
        expires_at,
    };
    rows::grant_put(t.c, &grant)?;
    let mut f = Map::new();
    f.insert("grant_id".into(), grant.id.clone().into());
    f.insert("session_id".into(), grant.session_id.clone().into());
    f.insert("credential_slug".into(), cred.slug.clone().into());
    expiry_for_audit(&mut f, grant.expires_at.as_deref(), opts.requested);
    t.audit_required("grant.created", Value::Object(f))?;
    Ok(grant)
}

/// Forget the oldest dead placeholders past [`MAX_PLACEHOLDER_ROWS`]. Ports
/// `#collectDeadPlaceholders`.
fn collect_dead_placeholders(t: &mut Tx<'_>) -> Result<()> {
    let total = rows::ph_count(t.c)? as usize;
    if total <= MAX_PLACEHOLDER_ROWS {
        return Ok(());
    }
    let now = t.now as f64;
    let mut dead: Vec<PlaceholderRow> = rows::ph_all(t.c)?
        .into_iter()
        .filter(|p| p.state != PlaceholderState::Active || row_expiry_ms(p) <= now)
        .collect();
    dead.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    for p in dead.iter().take(total - MAX_PLACEHOLDER_ROWS) {
        rows::ph_delete(t.c, &p.id)?;
    }
    Ok(())
}

/// Ports `issuePlaceholder` over a transaction.
fn issue_in(t: &mut Tx<'_>, opts: &IssueOptions) -> Result<IssuedPlaceholder> {
    t.require_unlocked()?;
    let grant = match rows::grant_get(t.c, &opts.grant_id)? {
        Some(g) if g.state == GrantState::Active => g,
        _ => {
            return Err(plain(
                ErrorCode::NoGrant,
                format!("no active grant {}", opts.grant_id),
            ))
        }
    };
    let grant = grant_live_in(t, Some(&grant))?;
    let stored = rows::session_get(t.c, &grant.session_id)?;
    let session = session_live_in(t, stored.as_ref())?;
    let cred = rows::credential_by_id(t.c, &grant.credential_id)?.ok_or_else(|| {
        plain(
            ErrorCode::NoGrant,
            format!("no credential {}", grant.credential_id),
        )
    })?;
    let field = opts
        .field
        .clone()
        .filter(|f| !f.is_empty())
        .or_else(|| grant.fields.first().cloned())
        .unwrap_or_default();
    if !grant.fields.contains(&field) {
        return Err(plain(
            ErrorCode::NoGrant,
            format!("grant does not cover field {field}"),
        ));
    }
    if cred.quarantine.is_some() {
        return Err(quarantined(&cred));
    }
    let limit = budget_of(&grant.policy);
    if limit == BudgetLimit::Limit(0) {
        return Err(budget_spent(limit));
    }
    let use_limit = match limit {
        BudgetLimit::Limit(n) => n,
        _ => DEFAULT_PLACEHOLDER_USES,
    };
    let pp = policy_json(&grant.policy)
        .get("placeholder_policy")
        .cloned()
        .unwrap_or(Value::Null);
    let max_active = max_active_of(&pp);
    // Rotate rather than refuse: unused first, oldest first; then least
    // recently used.
    let mut active: Vec<PlaceholderRow> = rows::ph_of_grant(t.c, &grant.id)?
        .into_iter()
        .filter(|p| p.field == field && p.state == PlaceholderState::Active)
        .collect();
    active.sort_by(|a, b| {
        let key = |p: &PlaceholderRow| {
            (
                u8::from(p.uses != 0),
                p.last_used_at.clone().unwrap_or_else(|| p.created_at.clone()),
            )
        };
        key(a).cmp(&key(b))
    });
    let excess = (active.len() as u64 + 1).saturating_sub(max_active) as usize;
    for p in active.iter_mut().take(excess) {
        p.state = PlaceholderState::Dead;
        p.dead_reason = Some(dead_reason::ROTATED.into());
        rows::ph_update(t.c, p)?;
    }
    let ceiling = ph_max_uses(&pp).unwrap_or(use_limit as f64);
    let max_uses_f = match opts.uses {
        Some(asked) if asked >= 1 => (asked as f64).min(ceiling),
        _ => ceiling,
    };
    let max_uses = if max_uses_f <= 0.0 {
        0
    } else {
        max_uses_f.ceil() as u64
    };
    let ttl = positive(opts.ttl_ms.map(|v| v as f64))
        .min(positive(pp.get("ttl").and_then(Value::as_f64).map(|s| s * 1000.0)));
    let expires = (t.now as f64 + ttl)
        .min(session_ceiling_ms(&session))
        .min(expiry_ms(grant.expires_at.as_deref()));
    collect_dead_placeholders(t)?;
    let k_ph = crypto::k_ph(t.vmk()?);
    let minted = av_core::placeholder::mint(&av_core::placeholder::MintInput {
        k_ph: &k_ph,
        sid: &session.id,
        slug: &cred.slug,
        field: &field,
    })
    .map_err(|e| Error::Invariant(format!("placeholder: {e}")))?;
    let row = PlaceholderRow {
        id: ids::id::placeholder(),
        grant_id: grant.id.clone(),
        credential_id: cred.id.clone(),
        field: field.clone(),
        sid: session.id.clone(),
        nonce_hash: minted.nonce_hash.clone(),
        uses: 0,
        max_uses,
        state: PlaceholderState::Active,
        dead_reason: None,
        replaces_id: None,
        created_at: t.now_iso(),
        expires_at: expires.is_finite().then(|| util::iso(expires as i64)),
        last_used_at: None,
    };
    rows::ph_insert(t.c, &row)?;
    t.audit_required(
        "placeholder.issued",
        json!({
            "placeholder_id": row.id,
            "grant_id": grant.id,
            "session_id": session.id,
            "credential_slug": cred.slug,
            "field": field,
        }),
    )?;
    Ok(IssuedPlaceholder {
        placeholder: minted.text.clone(),
        row,
    })
}

fn ph_next_hint() -> DenyExtra {
    DenyExtra::default()
}

impl Vault {
    // ------------------------------------------------------ plumbing

    fn db_path(&self) -> PathBuf {
        self.dir.join(VAULT_DB_FILE)
    }

    /// Run one operation in one IMMEDIATE transaction. Commits when it
    /// returns Ok (or asked to keep its changes), rolls back otherwise, and
    /// moves the audit anchor only after a commit.
    fn run<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let conn = Arc::clone(&self.conn);
        let mut guard = lock_conn(&conn);
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(a) = self.audit.as_mut() {
            a.begin();
        }
        let vmk = self.vmk.as_ref().map(LockedKey::key);
        let (res, keep, checkpoint) = {
            let mut t = Tx {
                c: &tx,
                audit: self.audit.as_mut(),
                vmk,
                keep: false,
                checkpoint: false,
                now: util::now_ms(),
            };
            let r = f(&mut t);
            (r, t.keep, t.checkpoint)
        };
        if res.is_ok() || keep {
            if let Err(e) = tx.commit() {
                if let Some(a) = self.audit.as_mut() {
                    a.rollback();
                }
                return Err(e.into());
            }
            if let Some(a) = self.audit.as_mut() {
                a.finish()?;
            }
            if checkpoint {
                checkpoint_truncate(&guard)?;
            }
        } else {
            drop(tx);
            if let Some(a) = self.audit.as_mut() {
                a.rollback();
            }
        }
        res
    }

    /// Read with the connection.
    fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = lock_conn(&self.conn);
        f(&guard)
    }

    fn vmk_key(&self) -> Result<Key32> {
        self.vmk.as_ref().map(LockedKey::key).ok_or_else(locked_error)
    }

    fn install(&mut self, vmk: &Key32) -> Result<()> {
        let audit = AuditLog::open_shared(
            Arc::clone(&self.conn),
            &self.db_path(),
            crypto::k_audit(vmk),
            Some(Box::new(VaultStamp {
                conn: Arc::clone(&self.conn),
            })),
        )?;
        self.vmk = Some(LockedKey::new(vmk));
        self.audit = Some(audit);
        Ok(())
    }

    fn drop_keys(&mut self) {
        self.vmk = None;
        self.audit = None;
    }

    // ---------------------------------------------------------- setup

    /// Create the vault dir (0700), the device key (0600, fsynced first),
    /// `vault.db` (via `crate::db::open`) and the first wrap; checks the
    /// factor invariant before touching disk; records `vault.created`.
    /// Refuses an existing vault. Ports `Vault.create` in
    /// `src/store/vault.js`.
    pub fn create(dir: &Path, opts: CreateOptions) -> Result<Vault> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let probe = VmkWrap {
            class: opts.factor,
            salt: None,
            kdf: None,
            sealed: crypto::SealedV2 {
                v: crypto::SEALED_V2,
                alg: crypto::V2_ALG.into(),
                n: String::new(),
                c: String::new(),
            },
            credential_id: None,
        };
        assert_factor_invariant(
            &FactorState::default(),
            &FactorState {
                vmk_wraps: vec![probe],
                webauthn: None,
            },
        )?;
        if opts.factor == FactorClass::Passphrase && opts.passphrase.is_none() {
            return Err(Error::Invariant("the passphrase factor needs a passphrase".into()));
        }
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        // A JS vault (vault.json) in the same dir is one too: its device key
        // must never be overwritten. That vault is migrated, not recreated.
        if dir.join(VAULT_DB_FILE).exists() || dir.join(LEGACY_VAULT_FILE).exists() {
            return Err(Error::Invariant(format!(
                "a vault already exists at {}",
                dir.display()
            )));
        }
        let device_key = crypto::random_key()?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(dir.join(DEVICE_KEY_FILE))?;
            f.write_all(device_key.expose())?;
            f.sync_all()?;
        }
        let vmk = crypto::random_key()?;
        let material = match opts.factor {
            FactorClass::None => WrapMaterial::None,
            FactorClass::Passphrase => WrapMaterial::Passphrase(
                opts.passphrase
                    .as_ref()
                    .ok_or_else(|| Error::Invariant("the passphrase factor needs a passphrase".into()))?,
            ),
            FactorClass::WebauthnPrf => return Err(recovery_refusal()),
        };
        let wrap = wrap_vmk(&device_key, &vmk, material)?;
        let conn = crate::db::open(&dir.join(VAULT_DB_FILE))?;
        let mut v = Vault {
            dir: dir.to_path_buf(),
            conn: Arc::new(Mutex::new(conn)),
            vmk: None,
            audit: None,
        };
        let now = util::now_iso();
        v.read(|c| {
            rows::wraps_replace(c, std::slice::from_ref(&wrap), &now)?;
            rows::factors_replace(
                c,
                &[PresenceFactor {
                    class: opts.factor,
                    enrolled_at: now.clone(),
                }],
            )?;
            rows::kv_set(c, "created_at", &Value::from(now.clone()))?;
            rows::kv_set(c, "locked", &Value::Bool(false))?;
            Ok(())
        })?;
        v.install(&vmk)?;
        let factor = class_name(opts.factor);
        v.run(|t| {
            t.audit_required(
                "vault.created",
                json!({ "factor": factor, "schema_version": SCHEMA_VERSION }),
            )
        })?;
        Ok(v)
    }

    /// Open an existing vault, locked (AV_NOT_FOUND "no vault at <dir>;
    /// run: agent-vault setup" when absent; refuses a newer schema). Ports
    /// `Vault.open` in `src/store/vault.js`.
    pub fn open(dir: &Path) -> Result<Vault> {
        let path = dir.join(VAULT_DB_FILE);
        if !path.exists() {
            return Err(plain(
                ErrorCode::NotFound,
                format!("no vault at {}; run: agent-vault setup", dir.display()),
            ));
        }
        let conn = crate::db::open(&path)?;
        Ok(Vault {
            dir: dir.to_path_buf(),
            conn: Arc::new(Mutex::new(conn)),
            vmk: None,
            audit: None,
        })
    }

    /// The vault dir. Ports `this.dir` in `src/store/vault.js`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the VMK is absent. Ports the `locked` getter in
    /// `src/store/vault.js`.
    pub fn locked(&self) -> bool {
        self.vmk.is_none()
    }

    /// Open the VMK with whatever material was supplied. Ports `#openWith`.
    fn open_with(&mut self, material: &UnlockMaterial, unlock: bool) -> Result<FactorClass> {
        let device_key = read_device_key(&self.dir)?;
        let wraps = self.read(rows::wraps_get)?;
        for wrap in &wraps {
            let attempt = (|| -> Result<Option<Key32>> {
                let Some(fk) = factor_key_for(wrap, material)? else {
                    return Ok(None);
                };
                Ok(Some(open_wrap(&device_key, wrap, &fk)?))
            })();
            let Ok(Some(vmk)) = attempt else { continue };
            // Nothing is installed until the whole unlock has worked.
            if self.install(&vmk).is_err() {
                self.drop_keys();
                continue;
            }
            if unlock {
                let class = class_name(wrap.class);
                let done = self.run(|t| {
                    if rows::kv_bool(t.c, "locked")? {
                        rows::kv_set(t.c, "locked", &Value::Bool(false))?;
                    }
                    t.audit_required("vault.unlock", json!({ "factor": class }))
                });
                if done.is_err() {
                    self.drop_keys();
                    continue;
                }
            }
            return Ok(wrap.class);
        }
        let wants: Vec<&str> = self
            .factors()?
            .into_iter()
            .filter(|f| *f != FactorClass::None)
            .map(class_name)
            .collect();
        Err(deny(
            ErrorCode::Locked,
            if wants.is_empty() {
                "vault is locked".to_string()
            } else {
                format!("unlock needs one of: {}", wants.join(", "))
            },
            DenyExtra {
                hint: Some("No enrolled factor could be satisfied.".into()),
                ..Default::default()
            },
        )
        .into())
    }

    /// Unlock with whatever material was supplied; installs the VMK and
    /// audit log only once both worked; records `vault.unlock`. Returns the
    /// factor that opened it, or AV_LOCKED naming the factors. Ports
    /// `Vault.prototype.unlockWith` in `src/store/vault.js`.
    pub fn unlock_with(&mut self, material: &UnlockMaterial) -> Result<FactorClass> {
        self.open_with(material, true)
    }

    /// Unlock with a passphrase (or nothing, for the `none` factor). Ports
    /// `Vault.prototype.unlock` in `src/store/vault.js`.
    pub fn unlock(&mut self, passphrase: Option<&SecretString>) -> Result<bool> {
        let material = UnlockMaterial {
            passphrase: passphrase.cloned(),
            prf_secret: None,
        };
        self.unlock_with(&material).map(|_| true)
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
        let vmk = self.vmk_key()?;
        if js_len(new_passphrase.expose_secret()) < MIN_PASSPHRASE_LEN {
            return Err(plain(
                ErrorCode::PolicyDenied,
                "a passphrase must be at least 8 characters",
            ));
        }
        let device_key = read_device_key(&self.dir)?;
        let wraps = self.read(rows::wraps_get)?;
        let existing = wraps.iter().find(|w| w.class == FactorClass::Passphrase);
        let had = existing.is_some();
        if let Some(w) = existing {
            let empty = SecretString::from(String::new());
            if !passphrase_opens(&device_key, w, current_passphrase.unwrap_or(&empty)) {
                return Err(plain(
                    ErrorCode::Locked,
                    "the current passphrase is required to change it",
                ));
            }
        }
        let wrap = wrap_vmk(&device_key, &vmk, WrapMaterial::Passphrase(new_passphrase))?;
        let mut next: Vec<VmkWrap> = wraps
            .into_iter()
            .filter(|w| w.class != FactorClass::Passphrase && w.class != FactorClass::None)
            .collect();
        next.push(wrap);
        self.run(|t| {
            commit_factors(t, Some(next), None)?;
            t.audit_required(
                "presence.factor_added",
                json!({ "class": "passphrase", "replaced": had }),
            )
        })
    }

    /// Refuse (rule `factor_order`) unless a passphrase is set. Ports
    /// `Vault.prototype.requireRecoveryFactor` in `src/store/vault.js`.
    pub fn require_recovery_factor(&self) -> Result<()> {
        if self.has_passphrase()? {
            Ok(())
        } else {
            Err(recovery_refusal())
        }
    }

    /// Add a Touch ID (WebAuthn PRF) unlock wrap; needs the passphrase
    /// (factor invariant). Ports `Vault.prototype.addWebauthnUnlock` in
    /// `src/store/vault.js`.
    pub fn add_webauthn_unlock(
        &mut self,
        credential_id: &str,
        prf_secret: &SecretBytes,
    ) -> Result<()> {
        let vmk = self.vmk_key()?;
        let device_key = read_device_key(&self.dir)?;
        let mut wrap = wrap_vmk(&device_key, &vmk, WrapMaterial::Prf(prf_secret.expose_secret()))?;
        wrap.credential_id = Some(credential_id.to_string());
        let mut next: Vec<VmkWrap> = self
            .read(rows::wraps_get)?
            .into_iter()
            .filter(|w| w.class != FactorClass::WebauthnPrf && w.class != FactorClass::None)
            .collect();
        next.push(wrap);
        self.run(|t| {
            commit_factors(t, Some(next), None)?;
            t.audit_required(
                "presence.factor_added",
                json!({ "class": "webauthn-prf", "credential_id": credential_id }),
            )
        })
    }

    /// Remove the PRF wrap (downgrading to `none` rather than leaving no
    /// wrap). Returns whether there was one. Ports
    /// `Vault.prototype.removeWebauthnUnlock` in `src/store/vault.js`.
    pub fn remove_webauthn_unlock(&mut self) -> Result<bool> {
        let vmk = self.vmk_key()?;
        let wraps = self.read(rows::wraps_get)?;
        let had = wraps.iter().any(|w| w.class == FactorClass::WebauthnPrf);
        let mut next: Vec<VmkWrap> = wraps
            .into_iter()
            .filter(|w| w.class != FactorClass::WebauthnPrf)
            .collect();
        let downgraded = next.is_empty();
        if downgraded {
            let device_key = read_device_key(&self.dir)?;
            next.push(wrap_vmk(&device_key, &vmk, WrapMaterial::None)?);
        }
        self.run(|t| {
            commit_factors(t, Some(next), None)?;
            if downgraded {
                t.audit_required(
                    "presence.factor_downgraded",
                    json!({
                        "class": "none",
                        "reason": "removing the last wrap would have made the vault unopenable",
                    }),
                )?;
            }
            if had {
                t.audit_required("presence.factor_removed", json!({ "class": "webauthn-prf" }))?;
            }
            Ok(had)
        })
    }

    /// Whether a PRF wrap exists. Ports the `hasWebauthnUnlock` getter in
    /// `src/store/vault.js`.
    pub fn has_webauthn_unlock(&self) -> Result<bool> {
        Ok(self
            .read(rows::wraps_get)?
            .iter()
            .any(|w| w.class == FactorClass::WebauthnPrf))
    }

    /// The PRF wrap's credential id. Ports the `webauthnUnlockCredentialId`
    /// getter in `src/store/vault.js`.
    pub fn webauthn_unlock_credential_id(&self) -> Result<Option<String>> {
        Ok(self
            .read(rows::wraps_get)?
            .into_iter()
            .find(|w| w.class == FactorClass::WebauthnPrf)
            .and_then(|w| w.credential_id)
            .filter(|c| !c.is_empty()))
    }

    /// Enrol or replace the presence authenticator, validated completely
    /// first (raw JSON input, see [`presence_key_record`]); records
    /// `presence.factor_added`. Returns whether one was replaced. Ports
    /// `Vault.prototype.setPresenceKey` in `src/store/vault.js`.
    pub fn set_presence_key(&mut self, input: &Value) -> Result<bool> {
        self.vmk_key()?;
        let record = presence_key_record(input)?;
        self.run(|t| {
            let replaced = rows::webauthn_get(t.c)?.is_some();
            let cid = record.credential_id.clone();
            commit_factors(t, None, Some(Some(record)))?;
            t.audit_required(
                "presence.factor_added",
                json!({
                    "class": "webauthn-platform",
                    "credential_id": cid,
                    "replaced_existing": replaced,
                }),
            )?;
            Ok(replaced)
        })
    }

    /// The enrolled presence authenticator. No JS method: replaces the
    /// daemon's direct read of `vault.db.kv.webauthn` in
    /// `src/daemon/server.js`.
    pub fn presence_key(&self) -> Result<Option<PresenceKey>> {
        self.read(rows::webauthn_get)
    }

    /// Store an authenticator's newer signature counter. No JS method:
    /// replaces `enrolled.signCount = result.signCount; this.vault.save()`
    /// in `src/daemon/server.js`.
    pub fn record_presence_sign_count(&mut self, sign_count: u32) -> Result<()> {
        self.run(|t| {
            if let Some(mut k) = rows::webauthn_get(t.c)? {
                k.sign_count = sign_count;
                rows::webauthn_put(t.c, Some(&k))?;
            }
            Ok(())
        })
    }

    /// The stable PRF salt (base64 32 bytes), created on first call. Ports
    /// `Vault.prototype.prfSalt` in `src/store/vault.js`.
    pub fn prf_salt(&mut self) -> Result<String> {
        self.run(|t| {
            if let Some(s) = rows::kv_str(t.c, "prf_salt")?.filter(|s| !s.is_empty()) {
                return Ok(s);
            }
            let mut salt = [0u8; 32];
            crypto::fill_random(&mut salt)?;
            let s = crypto::b64(&salt);
            rows::kv_set(t.c, "prf_salt", &Value::from(s.clone()))?;
            Ok(s)
        })
    }

    /// Drop the passphrase (the current one is required, else AV_LOCKED),
    /// falling back to a `none` wrap if it was the only one; the invariant
    /// refuses removing the last human factor. Returns false when none was
    /// set. Ports `Vault.prototype.removePassphrase` in `src/store/vault.js`.
    pub fn remove_passphrase(&mut self, current_passphrase: &SecretString) -> Result<bool> {
        let vmk = self.vmk_key()?;
        let wraps = self.read(rows::wraps_get)?;
        let Some(w) = wraps.iter().find(|w| w.class == FactorClass::Passphrase) else {
            return Ok(false);
        };
        let device_key = read_device_key(&self.dir)?;
        if !passphrase_opens(&device_key, w, current_passphrase) {
            return Err(plain(
                ErrorCode::Locked,
                "the current passphrase is required to remove it",
            ));
        }
        let mut next: Vec<VmkWrap> = wraps
            .iter()
            .filter(|w| w.class != FactorClass::Passphrase)
            .cloned()
            .collect();
        if next.is_empty() {
            next.push(wrap_vmk(&device_key, &vmk, WrapMaterial::None)?);
        }
        self.run(|t| {
            commit_factors(t, Some(next), None)?;
            t.audit_required("presence.factor_removed", json!({ "class": "passphrase" }))?;
            Ok(true)
        })
    }

    /// Whether a passphrase wrap exists. Ports the `hasPassphrase` getter in
    /// `src/store/vault.js`.
    pub fn has_passphrase(&self) -> Result<bool> {
        Ok(self
            .read(rows::wraps_get)?
            .iter()
            .any(|w| w.class == FactorClass::Passphrase))
    }

    /// Confirm a passphrase without changing anything; false if none is set
    /// or it is wrong. Blocking (Argon2id). Ports
    /// `Vault.prototype.verifyPassphrase` in `src/store/vault.js`.
    pub fn verify_passphrase(&self, passphrase: &SecretString) -> Result<bool> {
        let wraps = self.read(rows::wraps_get)?;
        let Some(w) = wraps.iter().find(|w| w.class == FactorClass::Passphrase) else {
            return Ok(false);
        };
        let Ok(device_key) = read_device_key(&self.dir) else {
            return Ok(false);
        };
        Ok(passphrase_opens(&device_key, w, passphrase))
    }

    /// Record `vault.lock`, drop the VMK and the audit key, and persist the
    /// lock. Ports `Vault.prototype.lock` in `src/store/vault.js`.
    pub fn lock(&mut self) -> Result<()> {
        let r = self.run(|t| {
            t.audit("vault.lock", json!({}))?;
            rows::kv_set(t.c, "locked", &Value::Bool(true))
        });
        self.drop_keys();
        r
    }

    /// Whether the vault was locked and not unlocked since. Ports the
    /// `lockedOnDisk` getter in `src/store/vault.js`.
    pub fn locked_on_disk(&self) -> Result<bool> {
        self.read(|c| rows::kv_bool(c, "locked"))
    }

    /// Come up in the state the vault was left in: a vault recorded as
    /// locked is opened only to record `vault.started_locked`, then
    /// relocked. Returns whether it is unlocked. Ports
    /// `Vault.prototype.startInRecordedState` in `src/store/vault.js`.
    pub fn start_in_recorded_state(&mut self, passphrase: Option<&SecretString>) -> Result<bool> {
        let was_locked = self.locked_on_disk()?;
        let material = UnlockMaterial {
            passphrase: passphrase.cloned(),
            prf_secret: None,
        };
        let opened = self.open_with(&material, !was_locked).is_ok();
        if !opened || was_locked {
            self.vmk = None;
            let r = self.run(|t| {
                if !rows::kv_bool(t.c, "locked")? {
                    rows::kv_set(t.c, "locked", &Value::Bool(true))?;
                }
                t.audit("vault.started_locked", json!({}))
            });
            self.drop_keys();
            r?;
            return Ok(false);
        }
        Ok(true)
    }

    /// The placeholder checksum key (AV_LOCKED while locked). Ports the
    /// `kPh` getter in `src/store/vault.js`.
    pub fn k_ph(&self) -> Result<Key32> {
        Ok(crypto::k_ph(&self.vmk_key()?))
    }

    /// The fingerprint key (AV_LOCKED while locked). Ports the
    /// `kFingerprint` getter in `src/store/vault.js`.
    pub fn k_fingerprint(&self) -> Result<Key32> {
        Ok(crypto::k_fingerprint(&self.vmk_key()?))
    }

    /// The session-token key (AV_LOCKED while locked). No JS method: ports
    /// `crypt.kToken(vault.vmk)` (`src/store/crypto.js`) as the daemon would call it.
    pub fn k_token(&self) -> Result<Key32> {
        Ok(crypto::k_token(&self.vmk_key()?))
    }

    /// The audit log, while unlocked. Ports `this.audit` in
    /// `src/store/vault.js`.
    pub fn audit(&self) -> Option<&AuditLog> {
        self.audit.as_ref()
    }

    /// The audit log, mutably, while unlocked (the daemon writes its own
    /// records). Ports `this.audit` in `src/store/vault.js`.
    pub fn audit_mut(&mut self) -> Option<&mut AuditLog> {
        self.audit.as_mut()
    }

    // ---------------------------------------------------- credentials

    /// Store a credential, every value sealed; records `cred.added`.
    /// AV_NOT_FOUND for a taken or invalid slug or field name. Ports
    /// `Vault.prototype.addCredential` in `src/store/vault.js`.
    pub fn add_credential(&mut self, input: NewCredential) -> Result<PublicCredential> {
        self.run(|t| {
            let vmk = t.vmk()?.clone();
            if rows::credential_by_slug(t.c, &input.slug)?.is_some() {
                return Err(plain(
                    ErrorCode::NotFound,
                    format!("credential {} already exists", input.slug),
                ));
            }
            let cred = seal_credential(
                &vmk,
                &input.slug,
                &input.kind,
                input.connector.clone(),
                &input.fields,
                &input.sites,
                &t.now_iso(),
            )?;
            rows::credential_insert(t.c, &cred)?;
            t.checkpoint = true;
            t.audit_required(
                "cred.added",
                json!({
                    "credential_slug": cred.slug,
                    "connector": cred.connector_kind,
                    "fields": cred.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
                }),
            )?;
            Ok(public_of(&cred, t.now))
        })
    }

    /// A credential by slug. Ports `Vault.prototype.findCredential` in
    /// `src/store/vault.js`.
    pub fn find_credential(&self, slug: &str) -> Result<Option<CredentialRecord>> {
        self.read(|c| rows::credential_by_slug(c, slug))
    }

    /// A credential by id. No JS method: replaces `vault.db.credentials[id]`
    /// in `src/daemon/*.js`.
    pub fn credential(&self, cred_id: &str) -> Result<Option<CredentialRecord>> {
        self.read(|c| rows::credential_by_id(c, cred_id))
    }

    /// Every credential record (sealed). No JS method: replaces
    /// `Object.values(vault.db.credentials)` in `src/daemon/*.js`.
    pub fn credential_records(&self) -> Result<Vec<CredentialRecord>> {
        self.read(rows::credentials_all)
    }

    /// The credential as anything outside the daemon may see it. Pure.
    /// Ports `Vault.prototype.publicCredential` in `src/store/vault.js`.
    pub fn public_credential(&self, cred: &CredentialRecord) -> PublicCredential {
        public_of(cred, util::now_ms())
    }

    /// Every credential, public view. Ports
    /// `Vault.prototype.listCredentials` in `src/store/vault.js`.
    pub fn list_credentials(&self) -> Result<Vec<PublicCredential>> {
        let now = util::now_ms();
        Ok(self
            .credential_records()?
            .iter()
            .map(|c| public_of(c, now))
            .collect())
    }

    /// Decrypt one field for a request: the pipeline's only path to a
    /// plaintext. Refuses a quarantined credential (AV_QUARANTINED). Ports
    /// `Vault.prototype.revealField` in `src/store/vault.js`.
    pub fn reveal_field(&self, cred_id: &str, field: &str) -> Result<SecretString> {
        let vmk = self.vmk_key()?;
        let cred = self
            .credential(cred_id)?
            .ok_or_else(|| plain(ErrorCode::NotFound, format!("no credential {cred_id}")))?;
        if cred.quarantine.is_some() {
            return Err(quarantined(&cred));
        }
        unseal(&vmk, &cred, field)
    }

    /// `untrustedText` over this vault's stored secrets (placeholders and
    /// the bound only, while locked). Ports `Vault.prototype.untrustedText`
    /// in `src/store/vault.js`.
    pub fn untrusted_text(&self, text: &str, max: usize) -> Result<String> {
        let secrets = if self.locked() {
            Vec::new()
        } else {
            self.all_secrets()?
        };
        Ok(av_core::scrub::untrusted_text(Some(text), &core_secrets(&secrets), max).unwrap_or_default())
    }

    /// Every unsealed value, retired ones inside their window included, for
    /// the scrubber. Ports `Vault.prototype.allSecrets` in
    /// `src/store/vault.js`.
    pub fn all_secrets(&self) -> Result<Vec<StoredSecret>> {
        let vmk = self.vmk_key()?;
        self.read(|c| all_secrets_in(c, &vmk, util::now_ms()))
    }

    /// Set or clear (none) the human's expiry note; records
    /// `cred.expiry_set`. Ports `Vault.prototype.setCredentialExpiry` in
    /// `src/store/vault.js`.
    pub fn set_credential_expiry(
        &mut self,
        slug: &str,
        iso: Option<&str>,
    ) -> Result<PublicCredential> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            let expires = match iso {
                None => None,
                Some(s) => Some(util::iso_normalized(s).ok_or_else(|| {
                    refuse(
                        ErrorCode::PolicyDenied,
                        "expires_at must be an ISO date, or null to clear it",
                        "expires_at",
                    )
                })?),
            };
            cred.expires_at = expires.clone();
            rows::credential_update_meta(t.c, &cred)?;
            t.audit_required(
                "cred.expiry_set",
                json!({ "credential_slug": cred.slug, "expires_at": expires }),
            )?;
            Ok(public_of(&cred, t.now))
        })
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
        if self.locked() {
            return Ok(None);
        }
        self.run(|t| {
            let cred = match rows::credential_by_id(t.c, cred_id_or_slug)? {
                Some(c) => Some(c),
                None => rows::credential_by_slug(t.c, cred_id_or_slug)?,
            };
            let (Some(mut cred), Value::Object(p)) = (cred, patch) else {
                return Ok(None);
            };
            let status = p
                .get("status")
                .and_then(|v| serde_json::from_value::<HealthStatus>(v.clone()).ok());
            let http_status = match p.get("http_status") {
                Some(Value::Null) => Some(None),
                Some(v) => v
                    .as_u64()
                    .filter(|n| (100..=599).contains(n))
                    .map(|n| Some(n as u16)),
                None => None,
            };
            let checked_at = p
                .get("checked_at")
                .and_then(Value::as_str)
                .and_then(util::iso_normalized);
            let source = p
                .get("source")
                .and_then(|v| serde_json::from_value::<HealthSource>(v.clone()).ok());
            let observed = match p.get("observed_expires_at") {
                Some(Value::Null) => Some(None),
                Some(Value::String(s)) => util::iso_normalized(s).map(Some),
                _ => None,
            };
            let scopes = match p.get("scopes") {
                Some(Value::Null) => Some(None),
                Some(Value::Array(a))
                    if a.len() <= 64
                        && a.iter().all(|s| s.as_str().is_some_and(|s| js_len(s) <= 128)) =>
                {
                    Some(Some(
                        a.iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .collect(),
                    ))
                }
                _ => None,
            };
            let before = cred.health.clone();
            let base = before.clone().unwrap_or(HealthRecord {
                status: HealthStatus::Unknown,
                http_status: None,
                checked_at: t.now_iso(),
                source: HealthSource::Response,
                observed_expires_at: None,
                scopes: None,
            });
            let health = HealthRecord {
                status: status.unwrap_or(base.status),
                http_status: http_status.unwrap_or(base.http_status),
                checked_at: checked_at.unwrap_or(base.checked_at),
                source: source.unwrap_or(base.source),
                observed_expires_at: observed.unwrap_or(base.observed_expires_at),
                scopes: scopes.unwrap_or(base.scopes),
            };
            cred.health = Some(health.clone());
            rows::credential_update_meta(t.c, &cred)?;
            let changed = before.as_ref().map(|b| b.status) != Some(health.status)
                || health.observed_expires_at
                    != before.as_ref().and_then(|b| b.observed_expires_at.clone());
            if changed {
                t.audit_required(
                    "cred.health_recorded",
                    json!({
                        "credential_slug": cred.slug,
                        "status": health.status,
                        "http_status": health.http_status,
                        "source": health.source,
                        "observed_expires_at": health.observed_expires_at,
                    }),
                )?;
            }
            Ok(Some(health))
        })
    }

    /// Quarantine a credential (a second call keeps the first record);
    /// records `cred.quarantined`. Ports `Vault.prototype.setQuarantine` in
    /// `src/store/vault.js`.
    pub fn set_quarantine(
        &mut self,
        slug: &str,
        opts: QuarantineOptions,
    ) -> Result<QuarantineRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            if let Some(r) = &opts.rule_id {
                if !rule_id_ok(r) {
                    return Err(refuse(
                        ErrorCode::PolicyDenied,
                        "a tripwire rule id must match [a-z0-9_-]{1,32}",
                        "quarantine",
                    ));
                }
            }
            if let Some(q) = &cred.quarantine {
                return Ok(q.clone());
            }
            let reason = opts
                .reason
                .as_ref()
                .filter(|r| !r.is_empty())
                .map(|r| js_slice(r, 200));
            let q = QuarantineRecord {
                since: t.now_iso(),
                by: opts.by,
                rule_id: opts.rule_id.clone(),
                reason_untrusted: reason.clone(),
            };
            cred.quarantine = Some(q.clone());
            rows::credential_update_meta(t.c, &cred)?;
            t.audit_required(
                "cred.quarantined",
                json!({
                    "credential_slug": cred.slug,
                    "by": q.by,
                    "rule_id": q.rule_id,
                    "reason_untrusted": reason,
                }),
            )?;
            Ok(q)
        })
    }

    /// Release a quarantine; false if there was none. Ports
    /// `Vault.prototype.clearQuarantine` in `src/store/vault.js`.
    pub fn clear_quarantine(&mut self, slug: &str) -> Result<bool> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            if cred.quarantine.is_none() {
                return Ok(false);
            }
            cred.quarantine = None;
            rows::credential_update_meta(t.c, &cred)?;
            t.audit_required("cred.released", json!({ "credential_slug": cred.slug }))?;
            Ok(true)
        })
    }

    /// The owner settings (open while locked). Ports
    /// `Vault.prototype.getSettings` in `src/store/vault.js`.
    pub fn get_settings(&self) -> Result<Settings> {
        self.read(rows::settings_get)
    }

    /// Shallow-merge a settings patch (raw JSON object; key grammar and
    /// `tripwires` checked whole first); records `settings.changed`. Ports
    /// `Vault.prototype.updateSettings` in `src/store/vault.js`.
    pub fn update_settings(&mut self, patch: &Value) -> Result<Settings> {
        self.run(|t| {
            t.require_unlocked()?;
            let Value::Object(p) = patch else {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "settings must be an object",
                    "policy_invalid",
                ));
            };
            for k in p.keys() {
                let b = k.as_bytes();
                let ok = !b.is_empty()
                    && b.len() <= 32
                    && b[0].is_ascii_lowercase()
                    && b.iter()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
                if !ok {
                    return Err(refuse(
                        ErrorCode::PolicyDenied,
                        "a setting name must match [a-z][a-z0-9_]{0,31}",
                        "policy_invalid",
                    ));
                }
            }
            if let Some(tw) = p.get("tripwires") {
                if let Some(problem) = tripwire_problem(tw) {
                    return Err(refuse(ErrorCode::PolicyDenied, problem, "tripwire_rule"));
                }
            }
            for (k, v) in p {
                rows::settings_put(t.c, k, v)?;
            }
            let keys: Vec<&String> = p.keys().collect();
            t.audit_required("settings.changed", json!({ "keys": keys }))?;
            rows::settings_get(t.c)
        })
    }

    /// Add a scrub pattern (F4): bounds, no placeholder, no stored value,
    /// compiles under the gateway's grammar; records its digest only. Ports
    /// `Vault.prototype.addScrubPattern` in `src/store/vault.js`.
    pub fn add_scrub_pattern(&mut self, slug: &str, source: &str) -> Result<ScrubPattern> {
        self.run(|t| {
            let vmk = t.vmk()?.clone();
            let mut cred = find_cred(t.c, slug)?;
            let secrets: Vec<SecretString> = all_secrets_in(t.c, &vmk, t.now)?
                .into_iter()
                .map(|s| s.secret)
                .collect();
            check_scrub_source(source, &secrets)?;
            if cred.scrub_patterns.len() >= MAX_SCRUB_PER_CRED {
                return Err(scrub_refusal(&format!(
                    "at most {MAX_SCRUB_PER_CRED} patterns per credential"
                )));
            }
            let total: usize = rows::credentials_all(t.c)?
                .iter()
                .map(|c| c.scrub_patterns.len())
                .sum();
            if total >= MAX_SCRUB_TOTAL {
                return Err(scrub_refusal(&format!(
                    "at most {MAX_SCRUB_TOTAL} patterns in the vault"
                )));
            }
            let pattern = ScrubPattern {
                id: ids::id::scrub_pattern(),
                source: source.to_string(),
                added_at: t.now_iso(),
            };
            cred.scrub_patterns.push(pattern.clone());
            rows::credential_update_meta(t.c, &cred)?;
            scrub_audit(t, &cred, &pattern)?;
            Ok(pattern)
        })
    }

    /// Remove a scrub pattern; false (nothing recorded) if absent. Ports
    /// `Vault.prototype.removeScrubPattern` in `src/store/vault.js`.
    pub fn remove_scrub_pattern(&mut self, slug: &str, pattern_id: &str) -> Result<bool> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            if !cred.scrub_patterns.iter().any(|p| p.id == pattern_id) {
                return Ok(false);
            }
            cred.scrub_patterns.retain(|p| p.id != pattern_id);
            rows::credential_update_meta(t.c, &cred)?;
            t.audit_required(
                "cred.scrub_pattern_removed",
                json!({ "credential_slug": cred.slug, "pattern_id": pattern_id }),
            )?;
            Ok(true)
        })
    }

    /// Pin a host this credential reaches to 1..=4 SPKI digests, replacing
    /// its list (at most 4 hosts). Ports `Vault.prototype.setPins` in
    /// `src/store/vault.js`.
    pub fn set_pins(&mut self, slug: &str, host: &str, pins: &[String]) -> Result<PinsSet> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            let key = pin_host(&cred, host)?;
            let list = pin_list(pins)?;
            let mut table = pin_table_of(&cred.pins, &key);
            table.insert(key.clone(), list.clone());
            check_pin_hosts(&table)?;
            cred.pins = table;
            rows::pins_write(t.c, &cred)?;
            t.audit_required(
                "cred.pins_set",
                json!({ "credential_slug": cred.slug, "host": key, "pins": list.len() }),
            )?;
            Ok(PinsSet {
                slug: cred.slug.clone(),
                host: key,
                pins: list.len() as u64,
            })
        })
    }

    /// Remove one pin of a host, or all (`spki` none). Returns how many
    /// stay. Ports `Vault.prototype.clearPins` in `src/store/vault.js`.
    pub fn clear_pins(&mut self, slug: &str, host: &str, spki: Option<&str>) -> Result<u64> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut cred = find_cred(t.c, slug)?;
            if let Some(s) = spki {
                let one = json!([s]);
                if av_core::pins::pin_list_state(Some(&one)) != PinListState::Pinned {
                    return Err(refuse(
                        ErrorCode::PolicyDenied,
                        "a pin is sha256/<base64 of 32 bytes>",
                        "pin_format",
                    ));
                }
            }
            let key = av_core::pins::url_host_of(host).ok_or_else(|| {
                refuse(
                    ErrorCode::PolicyDenied,
                    format!("{host} is not a host name"),
                    "pin_host",
                )
            })?;
            let current: Vec<String> = cred
                .pins
                .iter()
                .filter(|(k, _)| av_core::pins::url_host_of(k).as_deref() == Some(key.as_str()))
                .flat_map(|(_, v)| v.iter().cloned())
                .collect();
            let mut unique: Vec<String> = Vec::new();
            for p in &current {
                if !unique.contains(p) {
                    unique.push(p.clone());
                }
            }
            let remaining: Vec<String> = match spki {
                None => Vec::new(),
                Some(s) => unique.iter().filter(|p| p.as_str() != s).cloned().collect(),
            };
            let removed = unique.len() - remaining.len();
            if removed == 0 {
                return Ok(remaining.len() as u64);
            }
            let mut table = pin_table_of(&cred.pins, &key);
            if !remaining.is_empty() {
                table.insert(key.clone(), remaining.clone());
            }
            cred.pins = table;
            rows::pins_write(t.c, &cred)?;
            t.audit_required(
                "cred.pins_removed",
                json!({ "credential_slug": cred.slug, "host": key, "pins": removed }),
            )?;
            Ok(remaining.len() as u64)
        })
    }

    /// Replace a field's value (F7); the old one is retired, compared in
    /// constant time to refuse the same value. Ports
    /// `Vault.prototype.rotateCredential` in `src/store/vault.js`.
    pub fn rotate_credential(&mut self, slug: &str, opts: RotateOptions) -> Result<RotateResult> {
        self.run(|t| {
            let vmk = t.vmk()?.clone();
            let mut cred = find_cred(t.c, slug)?;
            let idx = match &opts.field {
                None => (!cred.fields.is_empty()).then_some(0),
                Some(name) => cred.fields.iter().position(|f| &f.name == name),
            };
            let Some(idx) = idx else {
                return Err(plain(
                    ErrorCode::NotFound,
                    format!(
                        "credential {slug} has no field {}",
                        opts.field.as_deref().unwrap_or("null")
                    ),
                ));
            };
            let value = opts.value.expose_secret();
            if value.is_empty() {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "the new value must be a non-empty string",
                    "value_empty",
                ));
            }
            if !(0..=MAX_RETIRE_MS).contains(&opts.retire_ms) {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "the retire window is a whole number of milliseconds, at most 7 days",
                    "retire_window",
                ));
            }
            let expires = match &opts.expires_at {
                None => None,
                Some(s) => Some(util::iso_normalized(s).ok_or_else(|| {
                    refuse(
                        ErrorCode::PolicyDenied,
                        "expires_at must be an ISO date, or null",
                        "expires_at",
                    )
                })?),
            };
            let name = cred.fields[idx].name.clone();
            let current = unseal(&vmk, &cred, &name)?;
            if crypto::constant_time_eq(current.expose_secret().as_bytes(), value.as_bytes()) {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "that is the value already stored",
                    "rotate_same_value",
                ));
            }
            let now = t.now;
            let f = &mut cred.fields[idx];
            let version = f.key_version + 1;
            let sealed = crypto::seal(
                &crypto::dek(&vmk, &cred.id),
                value.as_bytes(),
                &crypto::field_aad(&cred.id, &name, version),
            )?;
            let retire_until = util::iso(now + opts.retire_ms);
            let mut retired: Vec<RetiredValue> = f
                .retired
                .iter()
                .filter(|r| expiry_ms(Some(&r.retire_until)) > now as f64)
                .cloned()
                .collect();
            if opts.retire_ms > 0 {
                retired.push(RetiredValue {
                    sealed: f.sealed.clone(),
                    key_version: f.key_version,
                    retired_at: util::iso(now),
                    retire_until: retire_until.clone(),
                });
            }
            let previous_fp8 = f.fp8.clone();
            f.sealed = sealed;
            f.key_version = version;
            f.retired = retired;
            f.fp8 = crypto::fingerprint8(&crypto::k_fingerprint(&vmk), value.as_bytes());
            f.length = js_len(value) as u64;
            f.rotated_at = Some(util::iso(now));
            let new_fp8 = f.fp8.clone();
            cred.expires_at = expires;
            let mut revoked = 0u64;
            if opts.mode == RotateMode::Revoke {
                for g in rows::grants_of_credential(t.c, &cred.id)? {
                    if g.state == GrantState::Active {
                        revoke_grant_in(t, &g.id, "credential_rotated")?;
                        revoked += 1;
                    }
                }
            }
            rows::fields_write(t.c, &cred)?;
            rows::credential_update_meta(t.c, &cred)?;
            t.checkpoint = true;
            let rotated = RotationSummary {
                field: name,
                version,
                previous_fp8,
                fp8: new_fp8,
                mode: opts.mode,
                revoked_grants: revoked,
                retire_until,
            };
            let mut fields = obj(serde_json::to_value(&rotated)?);
            fields.insert("credential_slug".into(), cred.slug.clone().into());
            t.audit_required("cred.rotated", Value::Object(fields))?;
            Ok(RotateResult {
                credential: public_of(&cred, t.now),
                rotated,
            })
        })
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
        let refuse_url = |why: &str| {
            refuse(
                ErrorCode::PolicyDenied,
                format!("webhook refused: {why}"),
                "webhook_url",
            )
        };
        self.run(|t| {
            let vmk = t.vmk()?.clone();
            let text = url.expose_secret();
            if text.is_empty() || js_len(text) > 2048 {
                return Err(refuse_url("give an https URL of at most 2048 characters"));
            }
            let parsed = url::Url::parse(text).map_err(|_| refuse_url("not a URL"))?;
            let hostname = parsed.host_str().unwrap_or("");
            let loopback = ["localhost", "127.0.0.1", "[::1]"].contains(&hostname);
            let scheme = parsed.scheme();
            if !(scheme == "https" || (scheme == "http" && loopback)) {
                return Err(refuse_url("it must be https (or http to this machine)"));
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(refuse_url("it must not carry a user name or password"));
            }
            let host = match parsed.port() {
                Some(p) => format!("{hostname}:{p}"),
                None => hostname.to_string(),
            };
            let sealed = crypto::seal(
                &crypto::dek(&vmk, crypto::NOTIFY_DEK_ID),
                text.as_bytes(),
                crypto::NOTIFY_AAD,
            )?;
            let record = NotifyRecord {
                sealed,
                host: host.clone(),
                detail,
                configured_at: t.now_iso(),
            };
            rows::notify_put(t.c, Some(&record))?;
            t.checkpoint = true;
            t.audit_required(
                "notify.configured",
                json!({ "host": host, "detail": detail }),
            )?;
            Ok(NotifyConfig {
                host: record.host,
                detail,
                configured_at: record.configured_at,
            })
        })
    }

    /// The URL itself. Daemon-internal. Ports
    /// `Vault.prototype.getNotifyWebhook` in `src/store/vault.js`.
    pub fn get_notify_webhook(&self) -> Result<Option<NotifyWebhook>> {
        let vmk = self.vmk_key()?;
        let Some(n) = self.read(rows::notify_get)? else {
            return Ok(None);
        };
        let url = crypto::open_string(
            &crypto::dek(&vmk, crypto::NOTIFY_DEK_ID),
            &n.sealed,
            crypto::NOTIFY_AAD,
        )?;
        Ok(Some(NotifyWebhook {
            url,
            host: n.host,
            detail: n.detail,
        }))
    }

    /// What anyone may see: host, detail, time. Ports
    /// `Vault.prototype.notifyConfig` in `src/store/vault.js`.
    pub fn notify_config(&self) -> Result<Option<NotifyConfig>> {
        Ok(self.read(rows::notify_get)?.map(|n| NotifyConfig {
            host: n.host,
            detail: n.detail,
            configured_at: n.configured_at,
        }))
    }

    /// Remove the webhook; false if none. Ports
    /// `Vault.prototype.clearNotifyWebhook` in `src/store/vault.js`.
    pub fn clear_notify_webhook(&mut self) -> Result<bool> {
        self.run(|t| {
            t.require_unlocked()?;
            if rows::notify_get(t.c)?.is_none() {
                return Ok(false);
            }
            rows::notify_put(t.c, None)?;
            t.checkpoint = true;
            t.audit_required("notify.removed", json!({}))?;
            Ok(true)
        })
    }

    // ---------------------------------------------------- templates

    /// Save a named session shape (raw JSON spec; hashed over its canonical
    /// operation form). Ports `Vault.prototype.saveTemplate` in
    /// `src/store/vault.js`.
    pub fn save_template(&mut self, name: &str, spec: &Value) -> Result<TemplateRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let text = check_template(name, spec)?;
            let old = rows::template_get(t.c, name)?;
            if old.is_none() && rows::templates_all(t.c)?.len() >= MAX_TEMPLATES {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    format!("at most {MAX_TEMPLATES} templates"),
                    "template_size",
                ));
            }
            let rec = template_record(name, &text, old.as_ref(), &t.now_iso())?;
            rows::template_put(t.c, &rec)?;
            t.audit_required(
                "template.saved",
                json!({ "name": name, "version": rec.version, "template_hash": rec.hash }),
            )?;
            Ok(rec)
        })
    }

    /// A template by name. Ports `Vault.prototype.getTemplate` in
    /// `src/store/vault.js`.
    pub fn get_template(&self, name: &str) -> Result<Option<TemplateRecord>> {
        self.read(|c| rows::template_get(c, name))
    }

    /// Every template, by name. Ports `Vault.prototype.listTemplates` in
    /// `src/store/vault.js`.
    pub fn list_templates(&self) -> Result<Vec<TemplateRecord>> {
        self.read(rows::templates_all)
    }

    /// Remove a template; false if absent. Ports
    /// `Vault.prototype.deleteTemplate` in `src/store/vault.js`.
    pub fn delete_template(&mut self, name: &str) -> Result<bool> {
        self.run(|t| {
            t.require_unlocked()?;
            let Some(old) = rows::template_get(t.c, name)? else {
                return Ok(false);
            };
            rows::template_delete(t.c, name)?;
            t.audit_required(
                "template.deleted",
                json!({ "name": name, "version": old.version }),
            )?;
            Ok(true)
        })
    }

    // ------------------------------------------------------- backup

    /// Every credential as a backup carries it, values unsealed. Only the
    /// export calls this, behind a fresh proof of presence. Ports
    /// `Vault.prototype.backupCredentials` in `src/store/vault.js`.
    pub fn backup_credentials(&self) -> Result<Vec<BackupCredential>> {
        let vmk = self.vmk_key()?;
        let mut out = Vec::new();
        for c in self.credential_records()? {
            let mut fields = Vec::new();
            for f in &c.fields {
                fields.push(BackupField {
                    name: f.name.clone(),
                    value: unseal(&vmk, &c, &f.name)?,
                    sites: Some(f.sites.clone()),
                });
            }
            out.push(BackupCredential {
                slug: c.slug.clone(),
                kind: c.connector_kind.clone(),
                connector: Some(c.connector.clone()),
                created_at: Some(c.created_at.clone()),
                fields,
                scrub_patterns: Some(
                    c.scrub_patterns
                        .iter()
                        .map(|p| BackupScrubPattern {
                            id: Some(p.id.clone()),
                            source: p.source.clone(),
                            added_at: Some(p.added_at.clone()),
                        })
                        .collect(),
                ),
                pins: Some(c.pins.clone()),
                expires_at: c.expires_at.clone(),
                quarantine: c.quarantine.as_ref().map(serde_json::to_value).transpose()?,
            });
        }
        Ok(out)
    }

    /// Put a backup's credentials and templates back, all or nothing, never
    /// releasing a quarantine. Ports `Vault.prototype.restoreEntries` in
    /// `src/store/vault.js`.
    pub fn restore_entries(&mut self, entries: RestoreEntries) -> Result<RestoreEntriesResult> {
        let r = self.run(|t| {
            let vmk = t.vmk()?.clone();
            let now = t.now_iso();
            let existing = rows::credentials_all(t.c)?;
            let mut taken: Vec<String> = existing.iter().map(|c| c.slug.clone()).collect();
            let mut secrets: Vec<SecretString> = all_secrets_in(t.c, &vmk, t.now)?
                .into_iter()
                .map(|s| s.secret)
                .collect();
            for c in &entries.credentials {
                for f in &c.entry.fields {
                    secrets.push(f.value.clone());
                }
            }
            let mut pattern_total: usize = existing.iter().map(|c| c.scrub_patterns.len()).sum();
            let mut staged: Vec<CredentialRecord> = Vec::new();
            for planned in &entries.credentials {
                let c = &planned.entry;
                if c.fields.is_empty() {
                    return Err(backup_format("a credential entry is malformed"));
                }
                if taken.contains(&c.slug) {
                    return Err(plain(
                        ErrorCode::NotFound,
                        format!("credential {} already exists", c.slug),
                    ));
                }
                taken.push(c.slug.clone());
                let mut names: Vec<&str> = c.fields.iter().map(|f| f.name.as_str()).collect();
                names.sort_unstable();
                names.dedup();
                if c.fields.iter().any(|f| f.value.expose_secret().is_empty())
                    || names.len() != c.fields.len()
                {
                    return Err(backup_format(&format!("the fields of {} are malformed", c.slug)));
                }
                let fields: Vec<(String, SecretString)> = c
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), f.value.clone()))
                    .collect();
                let sites: BTreeMap<String, Vec<String>> = c
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), f.sites.clone().unwrap_or_default()))
                    .collect();
                let mut cred = seal_credential(
                    &vmk,
                    &c.slug,
                    &c.kind,
                    c.connector.clone().unwrap_or_default(),
                    &fields,
                    &sites,
                    &now,
                )?;
                for (host, list) in c.pins.clone().unwrap_or_default() {
                    if list.is_empty() {
                        continue;
                    }
                    let key = pin_host(&cred, &host)?;
                    let mut table = pin_table_of(&cred.pins, &key);
                    table.insert(key, pin_list(&list)?);
                    cred.pins = table;
                }
                check_pin_hosts(&cred.pins)?;
                if let Some(e) = &c.expires_at {
                    cred.expires_at = Some(util::iso_normalized(e).ok_or_else(|| {
                        refuse(
                            ErrorCode::PolicyDenied,
                            "expires_at must be an ISO date, or null to clear it",
                            "expires_at",
                        )
                    })?);
                }
                let patterns = c.scrub_patterns.clone().unwrap_or_default();
                if patterns.len() > MAX_SCRUB_PER_CRED {
                    return Err(scrub_refusal(&format!(
                        "at most {MAX_SCRUB_PER_CRED} patterns per credential"
                    )));
                }
                pattern_total += patterns.len();
                if pattern_total > MAX_SCRUB_TOTAL {
                    return Err(scrub_refusal(&format!(
                        "at most {MAX_SCRUB_TOTAL} patterns in the vault"
                    )));
                }
                for p in &patterns {
                    check_scrub_source(&p.source, &secrets)?;
                }
                cred.scrub_patterns = patterns
                    .iter()
                    .map(|p| ScrubPattern {
                        id: ids::id::scrub_pattern(),
                        source: p.source.clone(),
                        added_at: now.clone(),
                    })
                    .collect();
                match &c.quarantine {
                    Some(q) if !q.is_null() => cred.quarantine = Some(restored_quarantine(q)?),
                    _ => {
                        // The earliest, as setQuarantine keeps the first.
                        let names = [planned.from.as_str(), c.slug.as_str()];
                        cred.quarantine = existing
                            .iter()
                            .filter(|h| {
                                h.quarantine.is_some()
                                    && names.iter().any(|n| same_credential(&h.slug, n))
                            })
                            .filter_map(|h| h.quarantine.clone())
                            .min_by(|a, b| {
                                expiry_ms(Some(&a.since))
                                    .partial_cmp(&expiry_ms(Some(&b.since)))
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            });
                    }
                }
                staged.push(cred);
            }
            let mut template_names: Vec<String> = rows::templates_all(t.c)?
                .into_iter()
                .map(|t| t.name)
                .collect();
            let mut restored_templates = Vec::new();
            let mut skipped_templates = Vec::new();
            let mut new_templates = Vec::new();
            for tpl in &entries.templates {
                let text = check_template(&tpl.name, &Value::Object(tpl.spec.clone()))?;
                if template_names.contains(&tpl.name) {
                    skipped_templates.push(tpl.name.clone());
                    continue;
                }
                if template_names.len() >= MAX_TEMPLATES {
                    return Err(refuse(
                        ErrorCode::PolicyDenied,
                        format!("at most {MAX_TEMPLATES} templates"),
                        "template_size",
                    ));
                }
                template_names.push(tpl.name.clone());
                new_templates.push(template_record(&tpl.name, &text, None, &now)?);
                restored_templates.push(tpl.name.clone());
            }
            // Nothing above can reach a factor; said on the state stored.
            let factors = FactorState {
                vmk_wraps: rows::wraps_get(t.c)?,
                webauthn: rows::webauthn_get(t.c)?,
            };
            assert_factor_invariant(&factors, &factors)?;
            for cred in &staged {
                rows::credential_insert(t.c, cred)?;
            }
            for tpl in &new_templates {
                rows::template_put(t.c, tpl)?;
            }
            t.checkpoint = true;
            let mut label_secrets = all_secrets_in(t.c, &vmk, t.now)?;
            label_secrets.retain(|s| !s.secret.expose_secret().is_empty());
            let scrub_set = core_secrets(&label_secrets);
            for cred in &staged {
                t.audit_required(
                    "cred.added",
                    json!({
                        "credential_slug": cred.slug,
                        "connector": cred.connector_kind,
                        "fields": cred.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
                    }),
                )?;
                // The JS records an expiry whenever the key exists (it
                // starts undefined, so only one the bundle set).
                if cred.expires_at.is_some() {
                    t.audit_required(
                        "cred.expiry_set",
                        json!({ "credential_slug": cred.slug, "expires_at": cred.expires_at }),
                    )?;
                }
                for p in &cred.scrub_patterns {
                    scrub_audit(t, cred, p)?;
                }
                for (host, list) in &cred.pins {
                    t.audit_required(
                        "cred.pins_set",
                        json!({ "credential_slug": cred.slug, "host": host, "pins": list.len() }),
                    )?;
                }
                if let Some(q) = &cred.quarantine {
                    let reason = q.reason_untrusted.as_deref().and_then(|r| {
                        av_core::scrub::untrusted_text(Some(r), &scrub_set, 200)
                    });
                    t.audit_required(
                        "cred.quarantined",
                        json!({
                            "credential_slug": cred.slug,
                            "by": q.by,
                            "rule_id": q.rule_id,
                            "reason_untrusted": reason,
                            "since": q.since,
                            "restored": true,
                        }),
                    )?;
                }
            }
            for tpl in &new_templates {
                t.audit_required(
                    "template.saved",
                    json!({ "name": tpl.name, "version": tpl.version, "template_hash": tpl.hash }),
                )?;
            }
            Ok(RestoreEntriesResult {
                restored: staged.iter().map(|c| c.slug.clone()).collect(),
                templates: TemplateRestore {
                    restored: restored_templates,
                    skipped: skipped_templates,
                },
            })
        });
        r.map_err(|e| match e {
            Error::Sqlite(_) | Error::Io(_) => deny(
                ErrorCode::Internal,
                "the restore could not be written, so nothing was restored",
                DenyExtra {
                    rule: Some("backup_persist".into()),
                    ..Default::default()
                },
            )
            .into(),
            other => other,
        })
    }

    /// Delete a credential, revoking its grants. Ports
    /// `Vault.prototype.deleteCredential` in `src/store/vault.js`.
    pub fn delete_credential(&mut self, slug: &str) -> Result<()> {
        self.run(|t| {
            t.require_unlocked()?;
            let cred = find_cred(t.c, slug)?;
            for g in rows::grants_of_credential(t.c, &cred.id)? {
                revoke_grant_in(t, &g.id, "credential_deleted")?;
            }
            rows::credential_delete(t.c, &cred.id)?;
            t.checkpoint = true;
            t.audit_required("cred.deleted", json!({ "credential_slug": slug }))
        })
    }

    // --------------------------------------------------- workspaces

    /// Add a workspace; records `policy.approved`. Ports
    /// `Vault.prototype.addWorkspace` in `src/store/vault.js`.
    pub fn add_workspace(&mut self, name: &str, policy: Policy) -> Result<WorkspaceRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let ws = WorkspaceRecord {
                id: ids::id::workspace(),
                name: name.to_string(),
                policy_sha256: crypto::sha256_hex(serde_json::to_string(&policy)?.as_bytes()),
                default_policy: policy,
                state: "active".into(),
                created_at: t.now_iso(),
            };
            rows::workspace_insert(t.c, &ws)?;
            t.audit_required(
                "policy.approved",
                json!({ "workspace_id": ws.id, "name": name, "policy_sha256": ws.policy_sha256 }),
            )?;
            Ok(ws)
        })
    }

    /// A workspace by id or name. Ports `Vault.prototype.findWorkspace` in
    /// `src/store/vault.js`.
    pub fn find_workspace(&self, name_or_id: &str) -> Result<Option<WorkspaceRecord>> {
        let all = self.workspaces()?;
        Ok(all
            .iter()
            .find(|w| w.id == name_or_id)
            .or_else(|| all.iter().find(|w| w.name == name_or_id))
            .cloned())
    }

    /// Every workspace. No JS method: replaces
    /// `Object.values(vault.db.workspaces)` in `src/daemon/*.js`.
    pub fn workspaces(&self) -> Result<Vec<WorkspaceRecord>> {
        self.read(rows::workspaces_all)
    }

    // ----------------------------------------------------- sessions

    /// Create a session (every argument checked first; lifetime clamped to
    /// the cap). Ports `Vault.prototype.createSession` in
    /// `src/store/vault.js`.
    pub fn create_session(&mut self, opts: CreateSessionOptions) -> Result<CreatedSession> {
        self.run(|t| create_session_in(t, &opts))
    }

    /// A session by sid. No JS method: replaces `vault.db.sessions[sid]` in
    /// `src/daemon/*.js`.
    pub fn session(&self, sid: &str) -> Result<Option<SessionRecord>> {
        self.read(|c| rows::session_get(c, sid))
    }

    /// Every session. No JS method: replaces
    /// `Object.values(vault.db.sessions)` in `src/daemon/*.js`.
    pub fn sessions(&self) -> Result<Vec<SessionRecord>> {
        self.read(rows::sessions_all)
    }

    /// The session a bearer token names (by SHA-256, compared in constant
    /// time), in any state. Ports `Vault.prototype.sessionByToken` in
    /// `src/store/vault.js`.
    pub fn session_by_token(&self, token: &str) -> Result<Option<SessionRecord>> {
        if token.is_empty() {
            return Ok(None);
        }
        let hash = crypto::sha256_hex(token.as_bytes());
        let found = self.read(|c| rows::session_by_token_hash(c, &hash))?;
        Ok(found.filter(|s| crypto::constant_time_eq(s.token_hash.as_bytes(), hash.as_bytes())))
    }

    /// Refuse a missing, revoked or ended session; mark one past its end
    /// expired (and its placeholders dead). Returns the session as stored.
    /// Ports `Vault.prototype.assertSessionLive` in `src/store/vault.js`.
    pub fn assert_session_live(
        &mut self,
        session: Option<&SessionRecord>,
    ) -> Result<SessionRecord> {
        self.run(|t| session_live_in(t, session))
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
        if let (Some(s), Some(l)) = (session, listener) {
            if s.infinite && l.remote {
                let e = deny(
                    ErrorCode::RemoteForbidden,
                    "a session without expiry cannot be used from a network listener",
                    DenyExtra {
                        rule: Some("infinite_remote".into()),
                        hint: Some("Use it on this machine, or start a session with an expiry for remote use.".into()),
                        ..Default::default()
                    },
                );
                if opts.record && !opts.peek {
                    let kind = e.audit_kind();
                    let fields = json!({
                        "decision": "deny",
                        "reason_code": e.code,
                        "rule": "infinite_remote",
                        "session_id": s.id,
                        "peer": {
                            "kind": l.kind.clone().unwrap_or_else(|| "remote".into()),
                            "listener_id": l.id,
                        },
                    });
                    self.run(|t| t.audit(kind, fields))?;
                }
                return Err(e.into());
            }
        }
        if !opts.peek || session.is_none() {
            return self.assert_session_live(session);
        }
        let s = session.expect("checked above");
        if s.state == SessionState::Revoked {
            return Err(plain(
                ErrorCode::SessionRevoked,
                format!("session {} was revoked", s.id),
            ));
        }
        if s.state != SessionState::Active || session_expiry_ms(s) <= util::now_ms() as f64 {
            return Err(plain(
                ErrorCode::SessionExpired,
                format!("session {} has expired", s.id),
            ));
        }
        Ok(s.clone())
    }

    /// Idle extension, never past the ceiling; false when nothing was
    /// touched. Ports `Vault.prototype.touchSession` in `src/store/vault.js`.
    pub fn touch_session(&mut self, sid: &str) -> Result<bool> {
        self.run(|t| {
            let Some(mut s) = rows::session_get(t.c, sid)? else {
                return Ok(false);
            };
            let now = t.now;
            if s.state != SessionState::Active || session_expiry_ms(&s) <= now as f64 {
                return Ok(false);
            }
            if !s.infinite {
                let idle = s.idle_timeout_ms.unwrap_or(0) as f64;
                let extended = (now as f64 + idle).min(session_ceiling_ms(&s));
                if extended > session_expiry_ms(&s) {
                    s.expires_at = Some(util::iso(extended as i64));
                }
            }
            s.last_seen_at = util::iso(now);
            rows::session_put(t.c, &s, &t.now_iso())?;
            Ok(true)
        })
    }

    /// Bring a session's end closer (never later); an infinite one becomes
    /// finite; its live placeholders come down with it. Ports
    /// `Vault.prototype.shortenSession` in `src/store/vault.js`.
    pub fn shorten_session(&mut self, sid: &str, ttl_ms: i64) -> Result<SessionRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut s = rows::session_get(t.c, sid)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no session {sid}")))?;
            if s.state == SessionState::Revoked {
                return Err(plain(
                    ErrorCode::SessionRevoked,
                    format!("session {} was revoked", s.id),
                ));
            }
            if ttl_ms <= 0 {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "a session lifetime must be a positive number",
                    "ttl",
                ));
            }
            let now = t.now;
            let was_infinite = s.infinite && s.expires_at.is_none();
            let ceiling = session_ceiling_ms(&s);
            let expires_at = shortened_iso(session_expiry_ms(&s), now, ttl_ms);
            let max_expires_at = shortened_iso(ceiling, now, ttl_ms);
            s.expires_at = Some(expires_at.clone());
            s.max_expires_at = Some(max_expires_at.clone());
            s.infinite = false;
            s.idle_timeout_ms = Some(if s.remote {
                REMOTE_IDLE_TIMEOUT_MS
            } else {
                LOCAL_IDLE_TIMEOUT_MS
            });
            let bound = expiry_ms(Some(&max_expires_at));
            for mut p in rows::ph_of_session(t.c, &s.id)? {
                if p.state == PlaceholderState::Active && row_expiry_ms(&p) > bound {
                    p.expires_at = Some(max_expires_at.clone());
                    rows::ph_update(t.c, &p)?;
                }
            }
            rows::session_put(t.c, &s, &t.now_iso())?;
            t.audit_required(
                "session.shortened",
                json!({ "session_id": s.id, "expires_at": expires_at, "was_infinite": was_infinite }),
            )?;
            Ok(s)
        })
    }

    /// Revoke a session, its grants and its placeholders. Ports
    /// `Vault.prototype.revokeSession` in `src/store/vault.js` (`reason`
    /// defaults to `revoked`).
    pub fn revoke_session(&mut self, sid: &str, reason: &str) -> Result<()> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut s = rows::session_get(t.c, sid)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no session {sid}")))?;
            s.state = SessionState::Revoked;
            rows::session_put(t.c, &s, &t.now_iso())?;
            for mut g in rows::grants_of_session(t.c, sid)? {
                g.state = GrantState::Revoked;
                rows::grant_put(t.c, &g)?;
            }
            rows::ph_kill_where(t.c, Some(sid), None, dead_reason::SESSION_ENDED)?;
            t.audit_required(
                "session.revoked",
                json!({ "session_id": sid, "reason": reason }),
            )
        })
    }

    /// Fork a live session: grants copied with policy intersected, never
    /// outliving their originals. Ports `Vault.prototype.forkSession` in
    /// `src/store/vault.js`.
    pub fn fork_session(&mut self, parent_sid: &str, opts: ForkOptions) -> Result<CreatedSession> {
        self.run(|t| {
            t.require_unlocked()?;
            let stored = rows::session_get(t.c, parent_sid)?;
            let parent = session_live_in(t, stored.as_ref())?;
            let now = t.now;
            let parent_ends = session_expiry_ms(&parent);
            let parent_ttl = (parent_ends != f64::INFINITY).then(|| (parent_ends - now as f64) as i64);
            let ttl = match parent_ttl {
                None => opts.ttl_ms,
                Some(p) => Some(opts.ttl_ms.unwrap_or(p).min(p)),
            };
            let created = create_session_in(
                t,
                &CreateSessionOptions {
                    workspace_id: parent.workspace_id.clone(),
                    label: Some(
                        opts.label
                            .clone()
                            .filter(|l| !l.is_empty())
                            .unwrap_or_else(|| format!("{} (fork)", parent.label)),
                    ),
                    ttl_ms: ttl,
                    policy: parent.policy.clone(),
                    peer_uid: parent.owner_uid,
                    remote: parent.remote,
                    client_name: parent.client_name.clone(),
                    ..Default::default()
                },
            )?;
            let mut session = created.session;
            session.parent_sid = Some(parent_sid.to_string());
            rows::session_put(t.c, &session, &t.now_iso())?;
            for g in rows::grants_of_session(t.c, parent_sid)? {
                if g.state != GrantState::Active {
                    continue;
                }
                let ends = expiry_ms(g.expires_at.as_deref());
                if ends <= now as f64 {
                    continue;
                }
                let ttl_ms = (ends != f64::INFINITY).then(|| (ends - now as f64) as i64);
                create_grant_in(
                    t,
                    &CreateGrantOptions {
                        session_id: session.id.clone(),
                        credential_id: g.credential_id.clone(),
                        fields: Some(g.fields.clone()),
                        policy: g.policy.clone(),
                        narrow: Some(opts.narrow.clone()),
                        ttl_ms,
                        requested: false,
                    },
                )?;
            }
            t.audit_required(
                "session.forked",
                json!({ "session_id": session.id, "parent_session_id": parent_sid }),
            )?;
            Ok(CreatedSession {
                session,
                token: created.token,
            })
        })
    }

    /// Delete revoked or expired sessions (and their grants and
    /// placeholder rows) older than `retention_days`. The audit log keeps
    /// their history. No JS source: rust/PLAN.md, "Intended changes".
    pub fn prune_history(&mut self, now_ms: i64) -> Result<PruneReport> {
        self.run(|t| {
            t.require_unlocked()?;
            let days = rows::settings_get(t.c)?
                .get(RETENTION_DAYS_SETTING)
                .and_then(Value::as_u64)
                .unwrap_or(u64::from(RETENTION_DAYS_DEFAULT));
            let cutoff = now_ms as f64 - days as f64 * DAY_MS as f64;
            let ended_at = |sid: &str| -> Result<Option<String>> {
                Ok(t.c
                    .prepare_cached("SELECT ended_at FROM sessions WHERE id = ?1")?
                    .query_row([sid], |r| r.get(0))?)
            };
            let mut report = PruneReport::default();
            for s in rows::sessions_all(t.c)? {
                let gone = match s.state {
                    SessionState::Active => !s.infinite && session_expiry_ms(&s) < cutoff,
                    _ => {
                        let at = ended_at(&s.id)?;
                        // An end with no date (written before pruning existed) is
                        // dated by the session's own last activity.
                        let ended = expiry_ms(at.as_deref().or(Some(&s.last_seen_at)));
                        ended < cutoff
                    }
                };
                if !gone {
                    continue;
                }
                report.grants += rows::grants_of_session(t.c, &s.id)?.len() as u64;
                report.placeholders += rows::ph_of_session(t.c, &s.id)?.len() as u64;
                report.sessions += 1;
                t.c.prepare_cached("DELETE FROM sessions WHERE id = ?1")?
                    .execute([&s.id])?;
            }
            if report.sessions > 0 {
                t.audit_required(
                    "history.pruned",
                    json!({
                        "sessions": report.sessions,
                        "grants": report.grants,
                        "placeholders": report.placeholders,
                        "retention_days": days,
                    }),
                )?;
            }
            Ok(report)
        })
    }

    // ------------------------------------------------------- grants

    /// Create a grant on a live session for an unquarantined credential.
    /// Ports `Vault.prototype.createGrant` in `src/store/vault.js`.
    pub fn create_grant(&mut self, opts: CreateGrantOptions) -> Result<GrantRecord> {
        self.run(|t| create_grant_in(t, &opts))
    }

    /// A grant by id. No JS method: replaces `vault.db.grants[id]` in
    /// `src/daemon/*.js`.
    pub fn grant(&self, grant_id: &str) -> Result<Option<GrantRecord>> {
        self.read(|c| rows::grant_get(c, grant_id))
    }

    /// Every grant. No JS method: replaces `Object.values(vault.db.grants)`
    /// in `src/daemon/*.js`.
    pub fn grants(&self) -> Result<Vec<GrantRecord>> {
        self.read(rows::grants_all)
    }

    /// The newest grant for a session and credential, in any state. Ports
    /// `Vault.prototype.findGrant` in `src/store/vault.js`.
    pub fn find_grant(&self, sid: &str, cred_id: &str) -> Result<Option<GrantRecord>> {
        let mut newest: Option<GrantRecord> = None;
        for g in self.read(|c| rows::grants_of_session(c, sid))? {
            if g.credential_id != cred_id {
                continue;
            }
            let newer = match &newest {
                None => true,
                Some(n) => g.created_at > n.created_at || (g.created_at == n.created_at && g.id > n.id),
            };
            if newer {
                newest = Some(g);
            }
        }
        Ok(newest)
    }

    /// The one place a grant's lifetime is decided (AV_NO_GRANT /
    /// AV_GRANT_EXPIRED); noticing the end kills it and its placeholders.
    /// Ports `Vault.prototype.assertGrantLive` in `src/store/vault.js`.
    pub fn assert_grant_live(&mut self, grant: Option<&GrantRecord>) -> Result<GrantRecord> {
        self.run(|t| grant_live_in(t, grant))
    }

    /// A session's active grants. Ports `Vault.prototype.grantsForSession`
    /// in `src/store/vault.js`.
    pub fn grants_for_session(&self, sid: &str) -> Result<Vec<GrantRecord>> {
        Ok(self
            .read(|c| rows::grants_of_session(c, sid))?
            .into_iter()
            .filter(|g| g.state == GrantState::Active)
            .collect())
    }

    /// Charge `n` requests that spend no placeholder use (F6); false and
    /// nothing charged when over budget or unreadable. Ports
    /// `Vault.prototype.chargeGrant` in `src/store/vault.js`.
    pub fn charge_grant(&mut self, grant_id: &str, n: u64) -> Result<bool> {
        if self.locked() {
            return Ok(false);
        }
        self.run(|t| {
            let Some(mut g) = rows::grant_get(t.c, grant_id)? else {
                return Ok(false);
            };
            if g.state != GrantState::Active || expiry_ms(g.expires_at.as_deref()) <= t.now as f64 {
                return Ok(false);
            }
            if n < 1 || n > av_core::policy::MAX_SAFE_INTEGER {
                return Ok(false);
            }
            let used = g.budget_used;
            match budget_of(&g.policy) {
                BudgetLimit::Unreadable => return Ok(false),
                BudgetLimit::Limit(l) if used + n > l => return Ok(false),
                _ => {}
            }
            g.budget_used = used + n;
            g.counters.requests += n;
            rows::grant_put(t.c, &g)?;
            Ok(true)
        })
    }

    /// Revoke a grant and its placeholders (no-op if absent). Ports
    /// `Vault.prototype.revokeGrant` in `src/store/vault.js`.
    pub fn revoke_grant(&mut self, grant_id: &str, reason: &str) -> Result<()> {
        self.run(|t| revoke_grant_in(t, grant_id, reason))
    }

    /// Bring a grant's end closer. Ports `Vault.prototype.shortenGrant` in
    /// `src/store/vault.js`.
    pub fn shorten_grant(&mut self, grant_id: &str, ttl_ms: i64) -> Result<GrantRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut g = rows::grant_get(t.c, grant_id)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no grant {grant_id}")))?;
            if g.state != GrantState::Active {
                return Err(plain(
                    ErrorCode::NoGrant,
                    format!("no active grant {grant_id}"),
                ));
            }
            if ttl_ms <= 0 {
                return Err(refuse(
                    ErrorCode::PolicyDenied,
                    "a grant lifetime must be a positive number",
                    "grant_ttl",
                ));
            }
            let expires_at = shortened_iso(expiry_ms(g.expires_at.as_deref()), t.now, ttl_ms);
            let bound = expiry_ms(Some(&expires_at));
            g.expires_at = Some(expires_at.clone());
            for mut p in rows::ph_of_grant(t.c, &g.id)? {
                if p.state == PlaceholderState::Active && row_expiry_ms(&p) > bound {
                    p.expires_at = Some(expires_at.clone());
                    rows::ph_update(t.c, &p)?;
                }
            }
            rows::grant_put(t.c, &g)?;
            t.audit_required(
                "grant.shortened",
                json!({ "grant_id": g.id, "expires_at": expires_at }),
            )?;
            Ok(g)
        })
    }

    /// Narrow a grant by intersection (raw JSON layer; `redirects` may only
    /// be turned off). Ports `Vault.prototype.narrowGrant` in
    /// `src/store/vault.js`.
    pub fn narrow_grant(&mut self, grant_id: &str, narrow: &Value) -> Result<GrantRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut g = rows::grant_get(t.c, grant_id)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no grant {grant_id}")))?;
            let invalid = || {
                refuse(
                    ErrorCode::PolicyDenied,
                    "a narrowing must be a policy layer",
                    "policy_invalid",
                )
            };
            let Value::Object(n) = narrow else {
                return Err(invalid());
            };
            if let Some(r) = n.get("redirects") {
                let zero = r
                    .get("max")
                    .and_then(Value::as_f64)
                    .is_some_and(|m| m == 0.0);
                if !zero {
                    return Err(refuse(
                        ErrorCode::PolicyDenied,
                        "a narrowing can only turn redirect following off",
                        "narrow_widens",
                    ));
                }
            }
            let layer: Policy = serde_json::from_value(narrow.clone()).map_err(|_| invalid())?;
            g.policy = av_core::policy::intersect(&[Some(&g.policy), Some(&layer)]);
            rows::grant_put(t.c, &g)?;
            let keys: Vec<&String> = n.keys().collect();
            t.audit_required(
                "grant.narrowed",
                json!({ "grant_id": grant_id, "session_id": g.session_id, "fields": keys }),
            )?;
            Ok(g)
        })
    }

    // ------------------------------------------------- placeholders

    /// Issue a placeholder against a live grant, rotating the oldest active
    /// ones past `max_active`. Ports `Vault.prototype.issuePlaceholder` in
    /// `src/store/vault.js`.
    pub fn issue_placeholder(&mut self, opts: IssueOptions) -> Result<IssuedPlaceholder> {
        self.run(|t| issue_in(t, &opts))
    }

    /// The ledger row for a parsed placeholder, by nonce hash compared in
    /// constant time. Ports `Vault.prototype.resolvePlaceholder` in
    /// `src/store/vault.js`.
    pub fn resolve_placeholder(
        &self,
        parsed: &ParsedPlaceholder,
    ) -> Result<Option<PlaceholderRow>> {
        let hash = av_core::placeholder::hash_nonce(&parsed.nonce);
        let row = self.read(|c| rows::ph_by_nonce_hash(c, &hash))?;
        Ok(row.filter(|r| crypto::constant_time_eq(r.nonce_hash.as_bytes(), hash.as_bytes())))
    }

    /// Spend one use before any upstream byte (AV_PH_EXHAUSTED, AV_PH_STALE
    /// or AV_PH_REPLAY on a dead row). Ports
    /// `Vault.prototype.consumePlaceholder` in `src/store/vault.js`.
    pub fn consume_placeholder(&mut self, row_id: &str) -> Result<PlaceholderRow> {
        self.run(|t| {
            let mut row = rows::ph_get(t.c, row_id)?
                .ok_or_else(|| plain(ErrorCode::PhReplay, "unknown placeholder"))?;
            if row.state != PlaceholderState::Active {
                let reason = row.dead_reason.clone().unwrap_or_default();
                let code = match reason.as_str() {
                    dead_reason::EXHAUSTED => ErrorCode::PhExhausted,
                    dead_reason::EXPIRED | dead_reason::SESSION_ENDED | dead_reason::ROTATED => {
                        ErrorCode::PhStale
                    }
                    _ => ErrorCode::PhReplay,
                };
                let shown = if reason.is_empty() { "dead".to_string() } else { reason };
                return Err(deny(code, format!("placeholder is {shown}"), ph_next_hint()).into());
            }
            let session = rows::session_get(t.c, &row.sid)?;
            session_live_in(t, session.as_ref())?;
            let grant = rows::grant_get(t.c, &row.grant_id)?;
            let mut grant = grant_live_in(t, grant.as_ref())?;
            let cred = rows::credential_by_id(t.c, &row.credential_id)?.ok_or_else(|| {
                plain(
                    ErrorCode::NoGrant,
                    format!("no credential {}", row.credential_id),
                )
            })?;
            if cred.quarantine.is_some() {
                return Err(quarantined(&cred));
            }
            let die = |t: &mut Tx<'_>, row: &mut PlaceholderRow, reason: &str| -> Result<()> {
                row.state = PlaceholderState::Dead;
                row.dead_reason = Some(reason.into());
                rows::ph_update(t.c, row)?;
                t.keep = true;
                Ok(())
            };
            if row_expiry_ms(&row) <= t.now as f64 {
                die(t, &mut row, dead_reason::EXPIRED)?;
                return Err(deny(ErrorCode::PhStale, "placeholder expired", ph_next_hint()).into());
            }
            if row.uses >= row.max_uses {
                die(t, &mut row, dead_reason::EXHAUSTED)?;
                return Err(deny(
                    ErrorCode::PhExhausted,
                    format!("placeholder used {}/{} times", row.uses, row.max_uses),
                    ph_next_hint(),
                )
                .into());
            }
            let pp = policy_json(&grant.policy)
                .get("placeholder_policy")
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(ph_max) = ph_max_uses(&pp) {
                if row.uses as f64 >= ph_max {
                    die(t, &mut row, dead_reason::EXHAUSTED)?;
                    return Err(deny(
                        ErrorCode::PhExhausted,
                        format!(
                            "placeholder used {}/{} times",
                            row.uses,
                            util::js_number_string(ph_max)
                        ),
                        ph_next_hint(),
                    )
                    .into());
                }
            }
            let limit = budget_of(&grant.policy);
            let over = match limit {
                BudgetLimit::Unreadable => true,
                BudgetLimit::Limit(l) => grant.budget_used + 1 > l,
                BudgetLimit::Unlimited => false,
            };
            if over {
                return Err(budget_spent(limit));
            }
            row.uses += 1;
            row.last_used_at = Some(t.now_iso());
            if row.uses >= row.max_uses {
                row.state = PlaceholderState::Dead;
                row.dead_reason = Some(dead_reason::EXHAUSTED.into());
            }
            grant.budget_used += 1;
            grant.counters.requests += 1;
            rows::ph_update(t.c, &row)?;
            rows::grant_put(t.c, &grant)?;
            Ok(row)
        })
    }

    /// Give back a use and a budget unit when nothing reached the upstream,
    /// only into a still-live grant and session; recorded either way. Ports
    /// `Vault.prototype.refundPlaceholder` in `src/store/vault.js`.
    pub fn refund_placeholder(&mut self, row_id: &str) -> Result<()> {
        self.run(|t| {
            let Some(mut row) = rows::ph_get(t.c, row_id)? else {
                return Ok(());
            };
            let grant = rows::grant_get(t.c, &row.grant_id)?;
            let session = rows::session_get(t.c, &row.sid)?;
            let live = grant.as_ref().is_some_and(|g| g.state == GrantState::Active)
                && session.as_ref().is_some_and(|s| s.state == SessionState::Active);
            if !live {
                let state_of = |v: Option<String>| v.unwrap_or_else(|| "missing".into());
                t.audit(
                    "placeholder.refund_refused",
                    json!({
                        "placeholder_id": row_id,
                        "grant_state": state_of(grant.map(|g| rows_state(&g.state))),
                        "session_state": state_of(session.map(|s| rows_state(&s.state))),
                    }),
                )?;
                return Ok(());
            }
            let mut grant = grant.expect("live implies present");
            if row.uses > 0 {
                row.uses -= 1;
            }
            if row.state == PlaceholderState::Dead
                && row.dead_reason.as_deref() == Some(dead_reason::EXHAUSTED)
            {
                row.state = PlaceholderState::Active;
                row.dead_reason = None;
            }
            if grant.budget_used > 0 {
                grant.budget_used -= 1;
            }
            rows::ph_update(t.c, &row)?;
            rows::grant_put(t.c, &grant)?;
            t.audit(
                "placeholder.refunded",
                json!({ "placeholder_id": row_id, "grant_id": row.grant_id, "uses": row.uses }),
            )
        })
    }

    /// Kill a placeholder (`reason` defaults to `burned`). Ports
    /// `Vault.prototype.burnPlaceholder` in `src/store/vault.js`.
    pub fn burn_placeholder(&mut self, row_id: &str, reason: &str) -> Result<PlaceholderRow> {
        self.run(|t| {
            t.require_unlocked()?;
            let mut row = rows::ph_get(t.c, row_id)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no placeholder {row_id}")))?;
            row.state = PlaceholderState::Dead;
            row.dead_reason = Some(reason.to_string());
            rows::ph_update(t.c, &row)?;
            t.audit_required(
                "placeholder.burned",
                json!({ "placeholder_id": row_id, "reason": reason }),
            )?;
            Ok(row)
        })
    }

    /// Idempotent successor inheriting the predecessor's `max_uses`. Ports
    /// `Vault.prototype.nextPlaceholder` in `src/store/vault.js`.
    pub fn next_placeholder(&mut self, row_id: &str) -> Result<NextPlaceholder> {
        self.run(|t| {
            let old = rows::ph_get(t.c, row_id)?
                .ok_or_else(|| plain(ErrorCode::NotFound, format!("no placeholder {row_id}")))?;
            let existing = rows::ph_of_grant(t.c, &old.grant_id)?.into_iter().find(|p| {
                p.replaces_id.as_deref() == Some(row_id)
                    && p.state == PlaceholderState::Active
                    && p.uses == 0
            });
            if let Some(row) = existing {
                return Ok(NextPlaceholder {
                    placeholder: None,
                    row,
                    reused: true,
                });
            }
            let issued = issue_in(
                t,
                &IssueOptions {
                    grant_id: old.grant_id.clone(),
                    field: Some(old.field.clone()),
                    uses: Some(old.max_uses),
                    ttl_ms: None,
                },
            )?;
            let mut row = issued.row;
            row.replaces_id = Some(row_id.to_string());
            rows::ph_update(t.c, &row)?;
            Ok(NextPlaceholder {
                placeholder: Some(issued.placeholder),
                row,
                reused: false,
            })
        })
    }

    /// Ledger rows, for one session or all. Ports
    /// `Vault.prototype.listPlaceholders` in `src/store/vault.js`.
    pub fn list_placeholders(&self, sid: Option<&str>) -> Result<Vec<PlaceholderRow>> {
        match sid.filter(|s| !s.is_empty()) {
            Some(s) => self.read(|c| rows::ph_of_session(c, s)),
            None => self.read(rows::ph_all),
        }
    }

    // ---------------------------------------------------- listeners

    /// Add a listener; refuses non-networkable surfaces off loopback
    /// (AV_REMOTE_FORBIDDEN, recorded as `listen.refused`). Ports
    /// `Vault.prototype.addListener` in `src/store/vault.js`.
    pub fn add_listener(&mut self, entry: NewListener) -> Result<ListenerRecord> {
        self.run(|t| {
            t.require_unlocked()?;
            if rows::listener_exists(t.c, &entry.id)? {
                return Err(plain(
                    ErrorCode::NotFound,
                    format!("listener {} already exists", entry.id),
                ));
            }
            let bad: Vec<&String> = entry
                .surfaces
                .iter()
                .filter(|s| NON_NETWORKABLE_SURFACES.contains(&s.as_str()))
                .collect();
            if !bad.is_empty() && !is_loopback_spec(&entry.address) {
                t.audit(
                    "listen.refused",
                    json!({
                        "listener_id": entry.id,
                        "reason": "surface_not_networkable",
                        "surfaces": bad,
                    }),
                )?;
                t.keep = true;
                let names: Vec<&str> = bad.iter().map(|s| s.as_str()).collect();
                return Err(deny(
                    ErrorCode::RemoteForbidden,
                    format!(
                        "surfaces {} can never be bound to a network address",
                        names.join(", ")
                    ),
                    DenyExtra {
                        hint: Some("The control API, the approver socket and the database listeners stay on loopback and Unix sockets.".into()),
                        ..Default::default()
                    },
                )
                .into());
            }
            let rec = ListenerRecord {
                id: entry.id.clone(),
                address: entry.address.clone(),
                surfaces: entry.surfaces.clone(),
                advertise: entry.advertise.clone(),
                client_auth: entry.client_auth.clone(),
                allow_cidr: entry.allow_cidr.clone(),
                tls: entry.tls.clone(),
                created_at: t.now_iso(),
                state: "configured".into(),
            };
            rows::listener_put(t.c, &rec)?;
            t.audit_required(
                "listen.bound",
                json!({ "listener_id": rec.id, "address": rec.address, "surfaces": rec.surfaces }),
            )?;
            Ok(rec)
        })
    }

    /// Remove a listener. Ports `Vault.prototype.removeListener` in
    /// `src/store/vault.js`.
    pub fn remove_listener(&mut self, lid: &str) -> Result<()> {
        self.run(|t| {
            t.require_unlocked()?;
            if !rows::listener_exists(t.c, lid)? {
                return Err(plain(ErrorCode::NotFound, format!("no listener {lid}")));
            }
            rows::listener_delete(t.c, lid)?;
            t.audit_required("listen.removed", json!({ "listener_id": lid }))
        })
    }

    /// Every listener. Ports `Vault.prototype.listListeners` in
    /// `src/store/vault.js`.
    pub fn list_listeners(&self) -> Result<Vec<ListenerRecord>> {
        self.read(rows::listeners_all)
    }

    // -------------------------------------------- daemon-owned state

    /// Persisted session requests. No JS method: replaces the read of
    /// `vault.db.kv.session_requests` in `src/daemon/session-requests.js`.
    pub fn session_requests(&self) -> Result<Vec<SessionRequestRecord>> {
        self.read(rows::session_requests_all)
    }

    /// Replace the persisted session requests (questions only, never a
    /// result). No JS method: replaces `#save` in
    /// `src/daemon/session-requests.js`.
    pub fn save_session_requests(&mut self, rows: &[SessionRequestRecord]) -> Result<()> {
        self.run(|t| rows::session_requests_replace(t.c, rows))
    }

    /// Extra UI origins. No JS method: replaces reads of
    /// `vault.db.kv.ui_origins` in `src/daemon/server.js`.
    pub fn ui_origins(&self) -> Result<Vec<String>> {
        Ok(self
            .read(|c| rows::kv_get(c, "ui_origins"))?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default())
    }

    /// Add a UI origin (kept once). No JS method: replaces the write of
    /// `vault.db.kv.ui_origins` in `src/daemon/server.js`.
    pub fn add_ui_origin(&mut self, origin: &str) -> Result<()> {
        self.run(|t| {
            let mut list: Vec<String> = rows::kv_get(t.c, "ui_origins")?
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            if !list.iter().any(|o| o == origin) {
                list.push(origin.to_string());
                rows::kv_set(t.c, "ui_origins", &json!(list))?;
            }
            Ok(())
        })
    }

    // ---------------------------------------------------------- misc

    /// Flush. Every operation already commits its own transaction, so this
    /// only forces a durable checkpoint when asked. Ports
    /// `Vault.prototype.save` in `src/store/vault.js`.
    pub fn save(&mut self, opts: SaveOptions) -> Result<()> {
        if opts.durable {
            let guard = lock_conn(&self.conn);
            checkpoint_truncate(&guard)?;
        }
        Ok(())
    }

    /// The enrolled factor classes. Ports the `factors` getter in
    /// `src/store/vault.js`.
    pub fn factors(&self) -> Result<Vec<FactorClass>> {
        Ok(self
            .read(rows::factors_get)?
            .into_iter()
            .map(|f| f.class)
            .collect())
    }

    /// Counts for status. Ports `Vault.prototype.stats` in
    /// `src/store/vault.js`.
    pub fn stats(&self) -> Result<VaultStats> {
        let now = util::now_ms();
        let (creds, ws, sessions, grants, phs, listeners) = self.read(|c| {
            Ok((
                rows::credentials_all(c)?,
                rows::count(c, "workspaces")?,
                rows::sessions_all(c)?,
                rows::grants_all(c)?,
                rows::ph_all(c)?,
                rows::count(c, "listeners")?,
            ))
        })?;
        Ok(VaultStats {
            credentials: creds.len() as u64,
            workspaces: ws,
            credentials_expiring: creds
                .iter()
                .filter(|c| expiry_warning(c, now).is_some())
                .count() as u64,
            sessions_active: sessions
                .iter()
                .filter(|s| s.state == SessionState::Active && session_expiry_ms(s) > now as f64)
                .count() as u64,
            grants_active: grants
                .iter()
                .filter(|g| g.state == GrantState::Active)
                .count() as u64,
            placeholders_live: phs
                .iter()
                .filter(|p| p.state == PlaceholderState::Active)
                .count() as u64,
            listeners,
            audit_records: self.audit.as_ref().map(AuditLog::seq),
            locked: self.locked(),
        })
    }
}

fn rows_state<T: Serialize>(s: &T) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// `PRAGMA wal_checkpoint(TRUNCATE)`: no old page survives in the WAL.
pub(crate) fn checkpoint_truncate(c: &Connection) -> Result<()> {
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(()),
            e => Err(e),
        })?;
    Ok(())
}
