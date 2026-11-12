//! Entity rows: how each record in [`crate::model`] maps onto the tables of
//! [`crate::schema`]. Every statement here is a prepared statement with bound
//! parameters; no SQL text is ever built from a value (a test greps for it).
//!
//! No JS source: this replaces reading and writing `vault.json`'s `db`
//! object in `src/store/vault.js`.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::crypto::{Argon2Params, SealedV2};
use crate::error::Result;
use crate::model::{
    ApprovalRecord, ClientRecord, CredentialField, CredentialRecord, FactorClass, GrantRecord,
    GrantRuntime, GrantState, ListenerRecord, NotifyRecord, PlaceholderRow, PlaceholderState,
    PresenceFactor, PresenceKey, RetiredValue, SessionRecord, SessionRequestRecord, SessionState,
    Settings, TemplateRecord, VmkWrap, WorkspaceRecord,
};

pub(crate) fn json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}

fn parse<T: DeserializeOwned>(text: &str) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_opt<T: DeserializeOwned>(text: Option<String>) -> rusqlite::Result<Option<T>> {
    text.map(|t| parse(&t)).transpose()
}

fn class_str(c: FactorClass) -> &'static str {
    match c {
        FactorClass::None => "none",
        FactorClass::Passphrase => "passphrase",
        FactorClass::WebauthnPrf => "webauthn-prf",
    }
}

fn class_of(s: &str) -> rusqlite::Result<FactorClass> {
    parse(&Value::from(s).to_string())
}

fn session_state_str(s: SessionState) -> &'static str {
    match s {
        SessionState::Active => "active",
        SessionState::Expired => "expired",
        SessionState::Revoked => "revoked",
    }
}

fn grant_state_str(s: GrantState) -> &'static str {
    match s {
        GrantState::Active => "active",
        GrantState::Expired => "expired",
        GrantState::Revoked => "revoked",
    }
}

fn enum_of<T: DeserializeOwned>(s: &str) -> rusqlite::Result<T> {
    parse(&Value::from(s).to_string())
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

// ------------------------------------------------------------------- kv

pub(crate) fn kv_get(c: &Connection, key: &str) -> Result<Option<Value>> {
    let v: Option<String> = c
        .prepare_cached("SELECT value FROM kv WHERE key = ?1")?
        .query_row([key], |r| r.get(0))
        .optional()?;
    Ok(v.map(|t| serde_json::from_str(&t)).transpose()?)
}

pub(crate) fn kv_set(c: &Connection, key: &str, value: &Value) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )?
    .execute(params![key, value.to_string()])?;
    Ok(())
}

pub(crate) fn kv_bool(c: &Connection, key: &str) -> Result<bool> {
    Ok(kv_get(c, key)?.is_some_and(|v| v == Value::Bool(true)))
}

pub(crate) fn kv_str(c: &Connection, key: &str) -> Result<Option<String>> {
    Ok(kv_get(c, key)?.and_then(|v| v.as_str().map(str::to_string)))
}

// ------------------------------------------------------------- settings

pub(crate) fn settings_get(c: &Connection) -> Result<Settings> {
    let mut stmt = c.prepare_cached("SELECT key, value FROM settings ORDER BY key")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Map::new();
    for (k, v) in rows {
        out.insert(k, serde_json::from_str(&v)?);
    }
    Ok(out)
}

pub(crate) fn settings_put(c: &Connection, key: &str, value: &Value) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )?
    .execute(params![key, value.to_string()])?;
    Ok(())
}

// --------------------------------------------------------------- factors

pub(crate) fn wraps_get(c: &Connection) -> Result<Vec<VmkWrap>> {
    let mut stmt = c.prepare_cached(
        "SELECT class, salt, kdf, sealed, credential_id FROM vmk_wraps ORDER BY created_at, class",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let kdf: Option<String> = r.get(2)?;
            let sealed: String = r.get(3)?;
            Ok(VmkWrap {
                class: class_of(&r.get::<_, String>(0)?)?,
                salt: r.get(1)?,
                kdf: parse_opt::<Argon2Params>(kdf)?,
                sealed: parse::<SealedV2>(&sealed)?,
                credential_id: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Replace every wrap. Rows that stay keep their `created_at`, so the order
/// the JS array had (oldest first) survives.
pub(crate) fn wraps_replace(c: &Connection, wraps: &[VmkWrap], now: &str) -> Result<()> {
    let keep: Vec<&str> = wraps.iter().map(|w| class_str(w.class)).collect();
    let existing = wraps_get(c)?;
    for w in &existing {
        if !keep.contains(&class_str(w.class)) {
            c.prepare_cached("DELETE FROM vmk_wraps WHERE class = ?1")?
                .execute([class_str(w.class)])?;
        }
    }
    for w in wraps {
        if existing.iter().any(|e| e == w) {
            continue;
        }
        let kdf = w.kdf.map(|k| json(&k)).transpose()?;
        c.prepare_cached(
            "INSERT INTO vmk_wraps (class, salt, kdf, sealed, credential_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (class) DO UPDATE SET salt = excluded.salt, kdf = excluded.kdf,
                 sealed = excluded.sealed, credential_id = excluded.credential_id,
                 created_at = excluded.created_at",
        )?
        .execute(params![
            class_str(w.class),
            w.salt,
            kdf,
            json(&w.sealed)?,
            w.credential_id,
            now
        ])?;
    }
    Ok(())
}

pub(crate) fn factors_get(c: &Connection) -> Result<Vec<PresenceFactor>> {
    let mut stmt = c.prepare_cached(
        "SELECT class, enrolled_at FROM presence_factors ORDER BY enrolled_at, class",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(PresenceFactor {
                class: class_of(&r.get::<_, String>(0)?)?,
                enrolled_at: r.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn factors_replace(c: &Connection, factors: &[PresenceFactor]) -> Result<()> {
    c.prepare_cached("DELETE FROM presence_factors")?
        .execute([])?;
    for f in factors {
        c.prepare_cached("INSERT INTO presence_factors (class, enrolled_at) VALUES (?1, ?2)")?
            .execute(params![class_str(f.class), f.enrolled_at])?;
    }
    Ok(())
}

pub(crate) fn webauthn_get(c: &Connection) -> Result<Option<PresenceKey>> {
    Ok(c.prepare_cached(
        "SELECT credential_id, public_key_spki, sign_count, enrolled_at FROM webauthn WHERE id = 1",
    )?
    .query_row([], |r| {
        Ok(PresenceKey {
            credential_id: r.get(0)?,
            public_key_spki: r.get(1)?,
            sign_count: r.get(2)?,
            enrolled_at: r.get(3)?,
        })
    })
    .optional()?)
}

pub(crate) fn webauthn_put(c: &Connection, k: Option<&PresenceKey>) -> Result<()> {
    match k {
        None => {
            c.prepare_cached("DELETE FROM webauthn")?.execute([])?;
        }
        Some(k) => {
            c.prepare_cached(
                "INSERT INTO webauthn (id, credential_id, public_key_spki, sign_count, enrolled_at)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT (id) DO UPDATE SET credential_id = excluded.credential_id,
                     public_key_spki = excluded.public_key_spki, sign_count = excluded.sign_count,
                     enrolled_at = excluded.enrolled_at",
            )?
            .execute(params![
                k.credential_id,
                k.public_key_spki,
                k.sign_count,
                k.enrolled_at
            ])?;
        }
    }
    Ok(())
}

pub(crate) fn notify_get(c: &Connection) -> Result<Option<NotifyRecord>> {
    Ok(
        c.prepare_cached("SELECT sealed, host, detail, configured_at FROM notify WHERE id = 1")?
            .query_row([], |r| {
                Ok(NotifyRecord {
                    sealed: parse(&r.get::<_, String>(0)?)?,
                    host: r.get(1)?,
                    detail: enum_of(&r.get::<_, String>(2)?)?,
                    configured_at: r.get(3)?,
                })
            })
            .optional()?,
    )
}

pub(crate) fn notify_put(c: &Connection, n: Option<&NotifyRecord>) -> Result<()> {
    match n {
        None => {
            c.prepare_cached("DELETE FROM notify")?.execute([])?;
        }
        Some(n) => {
            c.prepare_cached(
                "INSERT INTO notify (id, sealed, host, detail, configured_at) VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT (id) DO UPDATE SET sealed = excluded.sealed, host = excluded.host,
                     detail = excluded.detail, configured_at = excluded.configured_at",
            )?
            .execute(params![json(&n.sealed)?, n.host, enum_str(&n.detail), n.configured_at])?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------ workspaces

fn workspace_row(r: &Row<'_>) -> rusqlite::Result<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        default_policy: parse(&r.get::<_, String>(2)?)?,
        policy_sha256: r.get(3)?,
        state: r.get(4)?,
        created_at: r.get(5)?,
    })
}

pub(crate) fn workspace_insert(c: &Connection, w: &WorkspaceRecord) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO workspaces (id, name, default_policy, policy_sha256, state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        w.id,
        w.name,
        json(&w.default_policy)?,
        w.policy_sha256,
        w.state,
        w.created_at
    ])?;
    Ok(())
}

pub(crate) fn workspaces_all(c: &Connection) -> Result<Vec<WorkspaceRecord>> {
    let mut stmt = c.prepare_cached(
        "SELECT id, name, default_policy, policy_sha256, state, created_at FROM workspaces ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], workspace_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ------------------------------------------------------------ credentials

fn cred_head(r: &Row<'_>) -> rusqlite::Result<CredentialRecord> {
    Ok(CredentialRecord {
        id: r.get(0)?,
        slug: r.get(1)?,
        connector_kind: r.get(2)?,
        connector: parse(&r.get::<_, String>(3)?)?,
        fields: Vec::new(),
        created_at: r.get(4)?,
        expires_at: r.get(5)?,
        health: parse_opt(r.get(6)?)?,
        quarantine: parse_opt(r.get(7)?)?,
        scrub_patterns: parse(&r.get::<_, String>(8)?)?,
        pins: BTreeMap::new(),
    })
}

fn cred_fill(c: &Connection, cred: &mut CredentialRecord) -> Result<()> {
    let mut stmt = c.prepare_cached(
        "SELECT name, sealed, key_version, sites, fp8, length, rotated_at
         FROM credential_fields WHERE credential_id = ?1 ORDER BY position",
    )?;
    cred.fields = stmt
        .query_map([&cred.id], |r| {
            Ok(CredentialField {
                name: r.get(0)?,
                sealed: parse(&r.get::<_, String>(1)?)?,
                key_version: r.get(2)?,
                sites: parse(&r.get::<_, String>(3)?)?,
                fp8: r.get(4)?,
                length: r.get::<_, i64>(5)? as u64,
                rotated_at: r.get(6)?,
                retired: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = c.prepare_cached(
        "SELECT field, sealed, key_version, retired_at, retire_until
         FROM retired_values WHERE credential_id = ?1 ORDER BY id",
    )?;
    let retired = stmt
        .query_map([&cred.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                RetiredValue {
                    sealed: parse(&r.get::<_, String>(1)?)?,
                    key_version: r.get(2)?,
                    retired_at: r.get(3)?,
                    retire_until: r.get(4)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (field, rv) in retired {
        if let Some(f) = cred.fields.iter_mut().find(|f| f.name == field) {
            f.retired.push(rv);
        }
    }
    let mut stmt = c.prepare_cached(
        "SELECT host, spki FROM pins WHERE credential_id = ?1 ORDER BY host, position",
    )?;
    let pins = stmt
        .query_map([&cred.id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (host, spki) in pins {
        cred.pins.entry(host).or_default().push(spki);
    }
    Ok(())
}

pub(crate) fn credential_by_id(c: &Connection, id: &str) -> Result<Option<CredentialRecord>> {
    let mut cred = c
        .prepare_cached(
            "SELECT id, slug, connector_kind, connector, created_at, expires_at, health, quarantine, scrub_patterns
             FROM credentials WHERE id = ?1",
        )?
        .query_row([id], cred_head)
        .optional()?;
    if let Some(cred) = cred.as_mut() {
        cred_fill(c, cred)?;
    }
    Ok(cred)
}

pub(crate) fn credential_by_slug(c: &Connection, slug: &str) -> Result<Option<CredentialRecord>> {
    let mut cred = c
        .prepare_cached(
            "SELECT id, slug, connector_kind, connector, created_at, expires_at, health, quarantine, scrub_patterns
             FROM credentials WHERE slug = ?1",
        )?
        .query_row([slug], cred_head)
        .optional()?;
    if let Some(cred) = cred.as_mut() {
        cred_fill(c, cred)?;
    }
    Ok(cred)
}

pub(crate) fn credentials_all(c: &Connection) -> Result<Vec<CredentialRecord>> {
    let mut stmt = c.prepare_cached(
        "SELECT id, slug, connector_kind, connector, created_at, expires_at, health, quarantine, scrub_patterns
         FROM credentials ORDER BY id",
    )?;
    let mut all = stmt
        .query_map([], cred_head)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for cred in all.iter_mut() {
        cred_fill(c, cred)?;
    }
    Ok(all)
}

/// Insert a whole credential (fields, retired values, pins).
pub(crate) fn credential_insert(c: &Connection, cred: &CredentialRecord) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO credentials (id, slug, connector_kind, connector, created_at, expires_at, health, quarantine, scrub_patterns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?
    .execute(params![
        cred.id,
        cred.slug,
        cred.connector_kind,
        json(&cred.connector)?,
        cred.created_at,
        cred.expires_at,
        cred.health.as_ref().map(json).transpose()?,
        cred.quarantine.as_ref().map(json).transpose()?,
        json(&cred.scrub_patterns)?,
    ])?;
    fields_write(c, cred)?;
    pins_write(c, cred)?;
    Ok(())
}

/// Update the credential's own columns (not fields or pins).
pub(crate) fn credential_update_meta(c: &Connection, cred: &CredentialRecord) -> Result<()> {
    c.prepare_cached(
        "UPDATE credentials SET connector = ?2, expires_at = ?3, health = ?4, quarantine = ?5, scrub_patterns = ?6
         WHERE id = ?1",
    )?
    .execute(params![
        cred.id,
        json(&cred.connector)?,
        cred.expires_at,
        cred.health.as_ref().map(json).transpose()?,
        cred.quarantine.as_ref().map(json).transpose()?,
        json(&cred.scrub_patterns)?,
    ])?;
    Ok(())
}

/// Rewrite a credential's fields and their retired values.
pub(crate) fn fields_write(c: &Connection, cred: &CredentialRecord) -> Result<()> {
    c.prepare_cached("DELETE FROM retired_values WHERE credential_id = ?1")?
        .execute([&cred.id])?;
    c.prepare_cached("DELETE FROM credential_fields WHERE credential_id = ?1")?
        .execute([&cred.id])?;
    for (pos, f) in cred.fields.iter().enumerate() {
        c.prepare_cached(
            "INSERT INTO credential_fields (credential_id, name, position, sealed, key_version, sites, fp8, length, rotated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?
        .execute(params![
            cred.id,
            f.name,
            pos as i64,
            json(&f.sealed)?,
            f.key_version,
            json(&f.sites)?,
            f.fp8,
            f.length as i64,
            f.rotated_at,
        ])?;
        for r in &f.retired {
            c.prepare_cached(
                "INSERT INTO retired_values (credential_id, field, sealed, key_version, retired_at, retire_until)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![cred.id, f.name, json(&r.sealed)?, r.key_version, r.retired_at, r.retire_until])?;
        }
    }
    Ok(())
}

/// Rewrite a credential's pins.
pub(crate) fn pins_write(c: &Connection, cred: &CredentialRecord) -> Result<()> {
    c.prepare_cached("DELETE FROM pins WHERE credential_id = ?1")?
        .execute([&cred.id])?;
    for (host, list) in &cred.pins {
        for (pos, spki) in list.iter().enumerate() {
            c.prepare_cached(
                "INSERT OR IGNORE INTO pins (credential_id, host, spki, position) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![cred.id, host, spki, pos as i64])?;
        }
    }
    Ok(())
}

pub(crate) fn credential_delete(c: &Connection, id: &str) -> Result<()> {
    c.prepare_cached("DELETE FROM credentials WHERE id = ?1")?
        .execute([id])?;
    Ok(())
}

// --------------------------------------------------------------- sessions

const SESSION_SELECT: &str = "SELECT id, workspace_id, label, token_hash, policy, owner_uid, remote, client_name,
        state, created_at, expires_at, max_expires_at, idle_timeout_ms, infinite, elevated, template,
        template_version, parent_sid, last_seen_at FROM sessions";

fn session_row(r: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        id: r.get(0)?,
        workspace_id: r.get(1)?,
        label: r.get(2)?,
        token_hash: r.get(3)?,
        policy: parse(&r.get::<_, String>(4)?)?,
        owner_uid: r.get(5)?,
        remote: r.get(6)?,
        client_name: r.get(7)?,
        state: enum_of(&r.get::<_, String>(8)?)?,
        created_at: r.get(9)?,
        expires_at: r.get(10)?,
        max_expires_at: r.get(11)?,
        idle_timeout_ms: r.get::<_, Option<i64>>(12)?.map(|v| v as u64),
        infinite: r.get(13)?,
        elevated: parse(&r.get::<_, String>(14)?)?,
        template: r.get(15)?,
        template_version: r.get(16)?,
        parent_sid: r.get(17)?,
        last_seen_at: r.get::<_, Option<String>>(18)?.unwrap_or_default(),
    })
}

pub(crate) fn session_get(c: &Connection, sid: &str) -> Result<Option<SessionRecord>> {
    let sql = [SESSION_SELECT, " WHERE id = ?1"].concat();
    Ok(c.prepare_cached(&sql)?
        .query_row([sid], session_row)
        .optional()?)
}

pub(crate) fn session_by_token_hash(c: &Connection, hash: &str) -> Result<Option<SessionRecord>> {
    let sql = [SESSION_SELECT, " WHERE token_hash = ?1"].concat();
    Ok(c.prepare_cached(&sql)?
        .query_row([hash], session_row)
        .optional()?)
}

pub(crate) fn sessions_all(c: &Connection) -> Result<Vec<SessionRecord>> {
    let sql = [SESSION_SELECT, " ORDER BY created_at, id"].concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([], session_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Insert or replace a session. `ended_at` is kept when already set and
/// stamped `now` when the session first leaves `active`.
pub(crate) fn session_put(c: &Connection, s: &SessionRecord, now: &str) -> Result<()> {
    let ended: Option<&str> = (s.state != SessionState::Active).then_some(now);
    c.prepare_cached(
        "INSERT INTO sessions (id, workspace_id, label, token_hash, policy, owner_uid, remote, client_name,
             state, end_reason, created_at, expires_at, max_expires_at, idle_timeout_ms, infinite, elevated,
             template, template_version, parent_sid, last_seen_at, ended_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
         ON CONFLICT (id) DO UPDATE SET workspace_id = excluded.workspace_id, label = excluded.label,
             policy = excluded.policy, owner_uid = excluded.owner_uid, remote = excluded.remote,
             client_name = excluded.client_name, state = excluded.state, expires_at = excluded.expires_at,
             max_expires_at = excluded.max_expires_at, idle_timeout_ms = excluded.idle_timeout_ms,
             infinite = excluded.infinite, elevated = excluded.elevated, template = excluded.template,
             template_version = excluded.template_version, parent_sid = excluded.parent_sid,
             last_seen_at = excluded.last_seen_at,
             ended_at = COALESCE(sessions.ended_at, excluded.ended_at)",
    )?
    .execute(params![
        s.id,
        s.workspace_id,
        s.label,
        s.token_hash,
        json(&s.policy)?,
        s.owner_uid,
        s.remote,
        s.client_name,
        session_state_str(s.state),
        s.created_at,
        s.expires_at,
        s.max_expires_at,
        s.idle_timeout_ms.map(|v| v as i64),
        s.infinite,
        json(&s.elevated)?,
        s.template,
        s.template_version,
        s.parent_sid,
        s.last_seen_at,
        ended,
    ])?;
    Ok(())
}

// ----------------------------------------------------------------- grants

const GRANT_SELECT: &str =
    "SELECT id, session_id, credential_id, fields, policy, budget_used, counters, state,
        created_at, expires_at FROM grants";

fn grant_row(r: &Row<'_>) -> rusqlite::Result<GrantRecord> {
    Ok(GrantRecord {
        id: r.get(0)?,
        session_id: r.get(1)?,
        credential_id: r.get(2)?,
        fields: parse(&r.get::<_, String>(3)?)?,
        policy: parse(&r.get::<_, String>(4)?)?,
        budget_used: r.get::<_, i64>(5)? as u64,
        counters: parse(&r.get::<_, String>(6)?)?,
        state: enum_of(&r.get::<_, String>(7)?)?,
        created_at: r.get(8)?,
        expires_at: r.get(9)?,
    })
}

pub(crate) fn grant_get(c: &Connection, id: &str) -> Result<Option<GrantRecord>> {
    let sql = [GRANT_SELECT, " WHERE id = ?1"].concat();
    Ok(c.prepare_cached(&sql)?
        .query_row([id], grant_row)
        .optional()?)
}

pub(crate) fn grants_all(c: &Connection) -> Result<Vec<GrantRecord>> {
    let sql = [GRANT_SELECT, " ORDER BY created_at, id"].concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([], grant_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn grants_of_session(c: &Connection, sid: &str) -> Result<Vec<GrantRecord>> {
    let sql = [
        GRANT_SELECT,
        " WHERE session_id = ?1 ORDER BY created_at, id",
    ]
    .concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([sid], grant_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn grants_of_credential(c: &Connection, cred_id: &str) -> Result<Vec<GrantRecord>> {
    let sql = [
        GRANT_SELECT,
        " WHERE credential_id = ?1 ORDER BY created_at, id",
    ]
    .concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([cred_id], grant_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn grant_put(c: &Connection, g: &GrantRecord) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO grants (id, session_id, credential_id, fields, policy, budget_used, counters, state,
             end_reason, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10)
         ON CONFLICT (id) DO UPDATE SET fields = excluded.fields, policy = excluded.policy,
             budget_used = excluded.budget_used, counters = excluded.counters, state = excluded.state,
             expires_at = excluded.expires_at",
    )?
    .execute(params![
        g.id,
        g.session_id,
        g.credential_id,
        json(&g.fields)?,
        json(&g.policy)?,
        g.budget_used as i64,
        json(&g.counters)?,
        grant_state_str(g.state),
        g.created_at,
        g.expires_at,
    ])?;
    Ok(())
}

/// A grant's runtime state; `None` when there is no such grant.
pub(crate) fn grant_runtime_get(c: &Connection, id: &str) -> Result<Option<GrantRuntime>> {
    let row: Option<(Option<String>, Option<String>)> = c
        .prepare_cached("SELECT quota_state, spend FROM grants WHERE id = ?1")?
        .query_row([id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((quota_state, spend)) = row else {
        return Ok(None);
    };
    Ok(Some(GrantRuntime {
        quota_state: quota_state.as_deref().map(parse).transpose()?,
        spend: spend.as_deref().map(parse).transpose()?,
    }))
}

/// Replace a grant's runtime state; false when there is no such grant.
pub(crate) fn grant_runtime_set(c: &Connection, id: &str, rt: &GrantRuntime) -> Result<bool> {
    let quota_state = rt.quota_state.as_ref().map(json).transpose()?;
    let spend = rt.spend.as_ref().map(json).transpose()?;
    let n = c
        .prepare_cached("UPDATE grants SET quota_state = ?2, spend = ?3 WHERE id = ?1")?
        .execute(params![id, quota_state, spend])?;
    Ok(n == 1)
}

// ----------------------------------------------------------- placeholders

const PH_SELECT: &str =
    "SELECT id, grant_id, credential_id, field, sid, nonce_hash, uses, max_uses, state,
        dead_reason, replaces_id, created_at, expires_at, last_used_at FROM placeholders";

fn ph_row(r: &Row<'_>) -> rusqlite::Result<PlaceholderRow> {
    Ok(PlaceholderRow {
        id: r.get(0)?,
        grant_id: r.get(1)?,
        credential_id: r.get(2)?,
        field: r.get(3)?,
        sid: r.get(4)?,
        nonce_hash: r.get(5)?,
        uses: r.get::<_, i64>(6)? as u64,
        max_uses: r.get::<_, i64>(7)? as u64,
        state: enum_of(&r.get::<_, String>(8)?)?,
        dead_reason: r.get(9)?,
        replaces_id: r.get(10)?,
        created_at: r.get(11)?,
        expires_at: r.get(12)?,
        last_used_at: r.get(13)?,
    })
}

pub(crate) fn ph_get(c: &Connection, id: &str) -> Result<Option<PlaceholderRow>> {
    let sql = [PH_SELECT, " WHERE id = ?1"].concat();
    Ok(c.prepare_cached(&sql)?.query_row([id], ph_row).optional()?)
}

pub(crate) fn ph_by_nonce_hash(c: &Connection, hash: &str) -> Result<Option<PlaceholderRow>> {
    let sql = [PH_SELECT, " WHERE nonce_hash = ?1"].concat();
    Ok(c.prepare_cached(&sql)?
        .query_row([hash], ph_row)
        .optional()?)
}

pub(crate) fn ph_all(c: &Connection) -> Result<Vec<PlaceholderRow>> {
    let sql = [PH_SELECT, " ORDER BY created_at, id"].concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([], ph_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn ph_of_session(c: &Connection, sid: &str) -> Result<Vec<PlaceholderRow>> {
    let sql = [PH_SELECT, " WHERE sid = ?1 ORDER BY created_at, id"].concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([sid], ph_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn ph_of_grant(c: &Connection, grant_id: &str) -> Result<Vec<PlaceholderRow>> {
    let sql = [PH_SELECT, " WHERE grant_id = ?1 ORDER BY created_at, id"].concat();
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt
        .query_map([grant_id], ph_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn ph_count(c: &Connection) -> Result<u64> {
    Ok(c.prepare_cached("SELECT count(*) FROM placeholders")?
        .query_row([], |r| r.get::<_, i64>(0))? as u64)
}

pub(crate) fn ph_insert(c: &Connection, p: &PlaceholderRow) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO placeholders (id, grant_id, credential_id, field, sid, nonce_hash, uses, max_uses, state,
             dead_reason, replaces_id, created_at, expires_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )?
    .execute(params![
        p.id,
        p.grant_id,
        p.credential_id,
        p.field,
        p.sid,
        p.nonce_hash,
        p.uses as i64,
        p.max_uses as i64,
        enum_str(&p.state),
        p.dead_reason,
        p.replaces_id,
        p.created_at,
        p.expires_at,
        p.last_used_at,
    ])?;
    Ok(())
}

/// Update the mutable columns of a ledger row. Identity columns are never
/// written (a trigger refuses it anyway).
pub(crate) fn ph_update(c: &Connection, p: &PlaceholderRow) -> Result<()> {
    c.prepare_cached(
        "UPDATE placeholders SET uses = ?2, max_uses = ?3, state = ?4, dead_reason = ?5, replaces_id = ?6,
             expires_at = ?7, last_used_at = ?8 WHERE id = ?1",
    )?
    .execute(params![
        p.id,
        p.uses as i64,
        p.max_uses as i64,
        enum_str(&p.state),
        p.dead_reason,
        p.replaces_id,
        p.expires_at,
        p.last_used_at,
    ])?;
    Ok(())
}

/// Kill every active row matching `sid` or `grant_id` with `reason`.
pub(crate) fn ph_kill_where(
    c: &Connection,
    sid: Option<&str>,
    grant_id: Option<&str>,
    reason: &str,
) -> Result<()> {
    c.prepare_cached(
        "UPDATE placeholders SET state = 'dead', dead_reason = ?3
         WHERE state = 'active' AND (?1 IS NULL OR sid = ?1) AND (?2 IS NULL OR grant_id = ?2)",
    )?
    .execute(params![sid, grant_id, reason])?;
    Ok(())
}

pub(crate) fn ph_delete(c: &Connection, id: &str) -> Result<()> {
    c.prepare_cached("DELETE FROM placeholders WHERE id = ?1")?
        .execute([id])?;
    Ok(())
}

// -------------------------------------------------------------- listeners

pub(crate) fn listener_put(c: &Connection, l: &ListenerRecord) -> Result<()> {
    let mut entry = match serde_json::to_value(l)? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    for k in ["id", "address", "surfaces", "state", "created_at"] {
        entry.remove(k);
    }
    c.prepare_cached(
        "INSERT INTO listeners (id, address, surfaces, state, created_at, entry) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![l.id, l.address, json(&l.surfaces)?, l.state, l.created_at, Value::Object(entry).to_string()])?;
    Ok(())
}

pub(crate) fn listeners_all(c: &Connection) -> Result<Vec<ListenerRecord>> {
    let mut stmt = c.prepare_cached(
        "SELECT id, address, surfaces, state, created_at, entry FROM listeners ORDER BY created_at, id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let mut entry: Map<String, Value> = parse(&r.get::<_, String>(5)?)?;
            entry.insert("id".into(), Value::from(r.get::<_, String>(0)?));
            entry.insert("address".into(), Value::from(r.get::<_, String>(1)?));
            entry.insert("surfaces".into(), parse(&r.get::<_, String>(2)?)?);
            entry.insert("state".into(), Value::from(r.get::<_, String>(3)?));
            entry.insert("created_at".into(), Value::from(r.get::<_, String>(4)?));
            serde_json::from_value(Value::Object(entry)).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn listener_exists(c: &Connection, id: &str) -> Result<bool> {
    Ok(
        c.prepare_cached("SELECT EXISTS (SELECT 1 FROM listeners WHERE id = ?1)")?
            .query_row([id], |r| r.get(0))?,
    )
}

pub(crate) fn listener_delete(c: &Connection, id: &str) -> Result<()> {
    c.prepare_cached("DELETE FROM listeners WHERE id = ?1")?
        .execute([id])?;
    Ok(())
}

// -------------------------------------------------------------- templates

fn template_row(r: &Row<'_>) -> rusqlite::Result<TemplateRecord> {
    Ok(TemplateRecord {
        name: r.get(0)?,
        version: r.get(1)?,
        spec: parse(&r.get::<_, String>(2)?)?,
        hash: r.get(3)?,
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
    })
}

pub(crate) fn template_get(c: &Connection, name: &str) -> Result<Option<TemplateRecord>> {
    Ok(c.prepare_cached(
        "SELECT name, version, spec, hash, created_at, updated_at FROM templates WHERE name = ?1",
    )?
    .query_row([name], template_row)
    .optional()?)
}

pub(crate) fn templates_all(c: &Connection) -> Result<Vec<TemplateRecord>> {
    let mut stmt = c.prepare_cached(
        "SELECT name, version, spec, hash, created_at, updated_at FROM templates ORDER BY name",
    )?;
    let rows = stmt
        .query_map([], template_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn template_put(c: &Connection, t: &TemplateRecord) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO templates (name, version, spec, hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (name) DO UPDATE SET version = excluded.version, spec = excluded.spec,
             hash = excluded.hash, updated_at = excluded.updated_at",
    )?
    .execute(params![t.name, t.version, Value::Object(t.spec.clone()).to_string(), t.hash, t.created_at, t.updated_at])?;
    Ok(())
}

pub(crate) fn template_delete(c: &Connection, name: &str) -> Result<()> {
    c.prepare_cached("DELETE FROM templates WHERE name = ?1")?
        .execute([name])?;
    Ok(())
}

// ------------------------------------------------------- session requests

pub(crate) fn session_requests_all(c: &Connection) -> Result<Vec<SessionRequestRecord>> {
    let mut stmt = c.prepare_cached(
        "SELECT id, collect_hash, proposal, fingerprint, summary, reason_untrusted, state, created_at, decided_at
         FROM session_requests ORDER BY created_at, id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(SessionRequestRecord {
                id: r.get(0)?,
                collect_hash: r.get(1)?,
                proposal: parse(&r.get::<_, String>(2)?)?,
                fingerprint: r.get(3)?,
                summary: r.get(4)?,
                reason_untrusted: r.get(5)?,
                state: enum_of(&r.get::<_, String>(6)?)?,
                created_at: r.get(7)?,
                decided_at: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn session_requests_replace(
    c: &Connection,
    rows: &[SessionRequestRecord],
) -> Result<()> {
    c.prepare_cached("DELETE FROM session_requests")?
        .execute([])?;
    for r in rows {
        c.prepare_cached(
            "INSERT INTO session_requests (id, collect_hash, proposal, fingerprint, summary, reason_untrusted,
                 state, created_at, decided_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?
        .execute(params![
            r.id,
            r.collect_hash,
            r.proposal.to_string(),
            r.fingerprint,
            r.summary,
            r.reason_untrusted,
            enum_str(&r.state),
            r.created_at,
            r.decided_at,
        ])?;
    }
    Ok(())
}

// ------------------------------------------------- approvals and clients

pub(crate) fn approval_put(c: &Connection, a: &ApprovalRecord) -> Result<()> {
    c.prepare_cached(
        "INSERT INTO approvals (id, state, created_at, doc) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (id) DO UPDATE SET state = excluded.state, doc = excluded.doc",
    )?
    .execute(params![a.id, enum_str(&a.state), a.created_at, json(a)?])?;
    Ok(())
}

pub(crate) fn client_put(c: &Connection, cl: &ClientRecord) -> Result<()> {
    let created = cl
        .extra
        .get("created_at")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    c.prepare_cached(
        "INSERT INTO clients (id, created_at, doc) VALUES (?1, ?2, ?3)
         ON CONFLICT (id) DO UPDATE SET doc = excluded.doc",
    )?
    .execute(params![cl.id, created, json(cl)?])?;
    Ok(())
}

/// Rows in a table, for counts. `table` must be one of [`crate::schema::TABLES`].
pub(crate) fn count(c: &Connection, table: &str) -> Result<u64> {
    if !crate::schema::TABLES.contains(&table) {
        return Err(crate::error::Error::Invariant(format!(
            "unknown table {table}"
        )));
    }
    // A table name cannot be a bound parameter; it comes from the fixed list
    // above, never from a caller.
    let sql = ["SELECT count(*) FROM ", table].concat();
    Ok(c.prepare(&sql)?.query_row([], |r| r.get::<_, i64>(0))? as u64)
}

#[allow(dead_code)]
pub(crate) fn placeholder_state_str(s: PlaceholderState) -> String {
    enum_str(&s)
}
