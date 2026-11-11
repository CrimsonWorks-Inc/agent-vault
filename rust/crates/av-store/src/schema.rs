//! The SQLite schema for `vault.db` (rust/PLAN.md, "Storage contract").
//!
//! Every table holds one of the collections the JS keeps in `vault.json`'s
//! `db` object (`EMPTY` and the records built in `src/store/vault.js`):
//!
//! | `vault.json` | table(s) |
//! |---|---|
//! | `schema_version` | `schema_version` (the SQLite schema's own version) |
//! | `kv.vault_id`, `kv.created_at`, `kv.locked`, `kv.audit_anchored`, `kv.prf_salt`, `kv.ui_origins`, anchors | `kv` |
//! | `kv.settings` (incl. `tripwires`, `retention_days`) | `settings` |
//! | `kv.vmk_wraps` | `vmk_wraps` |
//! | `kv.presence_factors` | `presence_factors` |
//! | `kv.webauthn` (presence key) | `webauthn` |
//! | `kv.notify` | `notify` |
//! | `workspaces` | `workspaces` |
//! | `credentials` (+ `fields`, `fields[].retired`, `pins`) | `credentials`, `credential_fields`, `retired_values`, `pins` |
//! | `sessions` | `sessions` |
//! | `grants` | `grants` |
//! | `placeholders` | `placeholders` |
//! | `approvals` | `approvals` |
//! | `kv.session_requests` | `session_requests` |
//! | `clients` | `clients` |
//! | `listeners` | `listeners` |
//! | `templates` | `templates` |
//! | `audit.jsonl` (when kept in the database) | `audit` |
//!
//! Columns carry the JS JSON key names. Nested objects that the JS treats as
//! one value (a policy, a connector config, a health record) are JSON text with
//! a `json_valid` check. Sealed values are the v2 JSON envelope from
//! `crate::crypto` (`{"v":2,"alg":"xchacha20poly1305","n":…,"c":…}`); no
//! column ever holds a plaintext secret.
//!
//! Triggers enforce what the PLAN calls insert-only: audit rows are never
//! updated or deleted, and a placeholder that is dead never becomes active
//! again, except the one refund the JS performs (`Vault.refundPlaceholder`:
//! an `exhausted` row given back exactly one use while its grant and session
//! are still active, nothing else changed; approved by the coordinator). A placeholder's identity (nonce hash, session, grant,
//! credential, field) never changes after insert.
//!
//! Migrations are forward-only: [`MIGRATIONS`] is append-only, and each entry
//! moves the schema from its index to the next version.

/// The version of this SQLite schema, stored in the `schema_version` row.
/// No JS source: the JS `SCHEMA_VERSION` in `src/store/vault.js` versions
/// `vault.json`, which this replaces.
pub const DB_SCHEMA_VERSION: u32 = 1;

/// Version 1 of the schema.
pub const SCHEMA_SQL: &str = r#"
-- The schema's own version. Exactly one row.
CREATE TABLE schema_version (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL CHECK (version >= 1),
    migrated_at TEXT    NOT NULL
) STRICT;

-- Scalar vault state from vault.json's kv: vault_id, created_at, locked,
-- audit_anchored, prf_salt, audit head anchors. Values are JSON.
CREATE TABLE kv (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL CHECK (json_valid(value))
) STRICT, WITHOUT ROWID;

-- kv.settings, one row per top-level key (tripwires, retention_days, ...).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL CHECK (json_valid(value))
) STRICT, WITHOUT ROWID;

-- kv.vmk_wraps: the VMK sealed under each unlock factor's KEK.
-- At most one wrap per class; the factor invariant decides which may coexist.
CREATE TABLE vmk_wraps (
    class      TEXT PRIMARY KEY NOT NULL
               CHECK (class IN ('none', 'passphrase', 'webauthn-prf')),
    salt       TEXT,                          -- base64, passphrase only
    kdf        TEXT CHECK (kdf IS NULL OR json_valid(kdf)),  -- Argon2id params
    sealed     TEXT NOT NULL CHECK (json_valid(sealed)),     -- v2 envelope
    credential_id TEXT,                       -- webauthn-prf only
    created_at TEXT NOT NULL,
    CHECK ((class = 'passphrase') = (salt IS NOT NULL AND kdf IS NOT NULL)),
    CHECK ((class = 'webauthn-prf') = (credential_id IS NOT NULL))
) STRICT, WITHOUT ROWID;

-- kv.presence_factors: which human factors are enrolled, and since when.
CREATE TABLE presence_factors (
    class       TEXT PRIMARY KEY NOT NULL,
    enrolled_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- kv.webauthn: the presence authenticator (public key only). Zero or one row.
-- (A PRF unlock's credential id lives on its vmk_wraps row.)
CREATE TABLE webauthn (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    credential_id          TEXT NOT NULL,
    public_key_spki        TEXT NOT NULL,      -- base64 SPKI DER, ES256
    sign_count             INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    enrolled_at            TEXT NOT NULL
) STRICT;

-- kv.notify: the sealed webhook URL (F14).
CREATE TABLE notify (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    sealed        TEXT NOT NULL CHECK (json_valid(sealed)),
    host          TEXT NOT NULL,
    detail        TEXT NOT NULL CHECK (detail IN ('minimal', 'headline')),
    configured_at TEXT NOT NULL
) STRICT;

CREATE TABLE workspaces (
    id             TEXT PRIMARY KEY NOT NULL,
    name           TEXT NOT NULL,
    default_policy TEXT NOT NULL CHECK (json_valid(default_policy)),
    policy_sha256  TEXT NOT NULL,
    state          TEXT NOT NULL,
    created_at     TEXT NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX workspaces_name ON workspaces (name);

CREATE TABLE credentials (
    id             TEXT PRIMARY KEY NOT NULL,
    slug           TEXT NOT NULL UNIQUE,
    connector_kind TEXT NOT NULL,
    connector      TEXT NOT NULL CHECK (json_valid(connector)),
    created_at     TEXT NOT NULL,
    expires_at     TEXT,
    health         TEXT CHECK (health IS NULL OR json_valid(health)),
    quarantine     TEXT CHECK (quarantine IS NULL OR json_valid(quarantine)),
    scrub_patterns TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scrub_patterns))
) STRICT, WITHOUT ROWID;

-- credentials[].fields: each field's current sealed value.
CREATE TABLE credential_fields (
    credential_id TEXT NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    position      INTEGER NOT NULL,                 -- order in the JS array
    sealed        TEXT NOT NULL CHECK (json_valid(sealed)),
    key_version   INTEGER NOT NULL CHECK (key_version >= 1),
    sites         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sites)),
    fp8           TEXT NOT NULL,
    length        INTEGER NOT NULL CHECK (length >= 0),
    rotated_at    TEXT,
    PRIMARY KEY (credential_id, name)
) STRICT, WITHOUT ROWID;

-- credentials[].fields[].retired: old values kept for scrubbing until
-- retire_until, after a rotation.
CREATE TABLE retired_values (
    id            INTEGER PRIMARY KEY,
    credential_id TEXT NOT NULL,
    field         TEXT NOT NULL,
    sealed        TEXT NOT NULL CHECK (json_valid(sealed)),
    key_version   INTEGER NOT NULL CHECK (key_version >= 1),
    retired_at    TEXT NOT NULL,
    retire_until  TEXT NOT NULL,
    FOREIGN KEY (credential_id, field)
        REFERENCES credential_fields (credential_id, name) ON DELETE CASCADE
) STRICT;
CREATE INDEX retired_values_field ON retired_values (credential_id, field);

-- credentials[].pins (F11): host -> SPKI pins.
CREATE TABLE pins (
    credential_id TEXT NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    spki          TEXT NOT NULL,                   -- sha256/<base64 of 32 bytes>
    PRIMARY KEY (credential_id, host, spki)
) STRICT, WITHOUT ROWID;

CREATE TABLE sessions (
    id               TEXT PRIMARY KEY NOT NULL,
    workspace_id     TEXT REFERENCES workspaces (id),
    label            TEXT NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,
    policy           TEXT NOT NULL CHECK (json_valid(policy)),
    owner_uid        INTEGER,
    remote           INTEGER NOT NULL CHECK (remote IN (0, 1)),
    client_name      TEXT,
    state            TEXT NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
    end_reason       TEXT,
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    max_expires_at   TEXT,
    idle_timeout_ms  INTEGER,
    infinite         INTEGER NOT NULL CHECK (infinite IN (0, 1)),
    elevated         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(elevated)),
    template         TEXT,
    template_version INTEGER,
    parent_sid       TEXT,                          -- forkSession
    last_seen_at     TEXT,
    ended_at         TEXT,                          -- for retention pruning
    CHECK ((template IS NULL) = (template_version IS NULL)),
    CHECK (infinite = 0 OR (expires_at IS NULL AND remote = 0))
) STRICT, WITHOUT ROWID;
CREATE INDEX sessions_state ON sessions (state, ended_at);

CREATE TABLE grants (
    id            TEXT PRIMARY KEY NOT NULL,
    session_id    TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    fields        TEXT NOT NULL CHECK (json_valid(fields)),
    policy        TEXT NOT NULL CHECK (json_valid(policy)),
    budget_used   INTEGER NOT NULL DEFAULT 0 CHECK (budget_used >= 0),
    counters      TEXT NOT NULL DEFAULT '{"requests":0,"denials":0}' CHECK (json_valid(counters)),
    state         TEXT NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
    end_reason    TEXT,
    created_at    TEXT NOT NULL,
    expires_at    TEXT
) STRICT, WITHOUT ROWID;
CREATE INDEX grants_session ON grants (session_id);
CREATE INDEX grants_credential ON grants (credential_id);

-- The placeholder ledger. The nonce itself is never stored, only its hash.
CREATE TABLE placeholders (
    id            TEXT PRIMARY KEY NOT NULL,
    grant_id      TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    field         TEXT NOT NULL,
    sid           TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    nonce_hash    TEXT NOT NULL UNIQUE,
    uses          INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    max_uses      INTEGER NOT NULL CHECK (max_uses >= 1),
    state         TEXT NOT NULL CHECK (state IN ('active', 'dead')),
    dead_reason   TEXT,
    replaces_id   TEXT,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT,
    CHECK ((state = 'dead') = (dead_reason IS NOT NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX placeholders_grant ON placeholders (grant_id, state);
CREATE INDEX placeholders_sid ON placeholders (sid);
CREATE INDEX placeholders_replaces ON placeholders (replaces_id);

-- A dead placeholder stays dead. The single exception is the JS refund
-- (Vault.refundPlaceholder): an `exhausted` row given back exactly one use
-- while its grant and its session are both still active, with nothing else
-- about the row changed.
CREATE TRIGGER placeholders_no_resurrect
BEFORE UPDATE ON placeholders
WHEN OLD.state = 'dead' AND NEW.state = 'active'
     AND NOT (
         OLD.dead_reason = 'exhausted'
         AND NEW.dead_reason IS NULL
         AND NEW.uses = OLD.uses - 1
         AND NEW.max_uses = OLD.max_uses
         AND NEW.replaces_id IS OLD.replaces_id
         AND NEW.created_at = OLD.created_at
         AND NEW.expires_at IS OLD.expires_at
         AND NEW.last_used_at IS OLD.last_used_at
         AND (SELECT state FROM grants WHERE id = OLD.grant_id) = 'active'
         AND (SELECT state FROM sessions WHERE id = OLD.sid) = 'active'
     )
BEGIN
    SELECT RAISE(ABORT, 'a dead placeholder cannot become active again');
END;

-- What a placeholder is bound to never changes after it is minted.
CREATE TRIGGER placeholders_identity_fixed
BEFORE UPDATE OF id, grant_id, credential_id, field, sid, nonce_hash ON placeholders
BEGIN
    SELECT RAISE(ABORT, 'a placeholder''s identity is fixed at mint');
END;

-- In-memory in the JS (Pipeline.approvals); the table exists so vault.json's
-- `approvals` collection has a home. One JSON document per approval.
CREATE TABLE approvals (
    id         TEXT PRIMARY KEY NOT NULL,
    state      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    doc        TEXT NOT NULL CHECK (json_valid(doc))
) STRICT, WITHOUT ROWID;

-- kv.session_requests (src/daemon/session-requests.js): sessions an agent
-- asked for, waiting on a human.
CREATE TABLE session_requests (
    id               TEXT PRIMARY KEY NOT NULL,
    collect_hash     TEXT NOT NULL,
    proposal         TEXT NOT NULL CHECK (json_valid(proposal)),
    fingerprint      TEXT NOT NULL,
    summary          TEXT NOT NULL,
    reason_untrusted TEXT,
    state            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    decided_at       TEXT
) STRICT, WITHOUT ROWID;

-- vault.json's `clients` collection (empty in the JS today).
CREATE TABLE clients (
    id         TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    doc        TEXT NOT NULL CHECK (json_valid(doc))
) STRICT, WITHOUT ROWID;

CREATE TABLE listeners (
    id         TEXT PRIMARY KEY NOT NULL,
    address    TEXT NOT NULL,
    surfaces   TEXT NOT NULL CHECK (json_valid(surfaces)),
    state      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    entry      TEXT NOT NULL CHECK (json_valid(entry))   -- the rest of the entry
) STRICT, WITHOUT ROWID;

-- Session templates (F17).
CREATE TABLE templates (
    name       TEXT PRIMARY KEY NOT NULL,
    version    INTEGER NOT NULL CHECK (version >= 1),
    spec       TEXT NOT NULL CHECK (json_valid(spec)),
    hash       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- The audit chain, if kept in the database (the PLAN allows either). One row
-- per record; `record` is the exact canonical line the hash covers.
CREATE TABLE audit (
    seq       INTEGER PRIMARY KEY CHECK (seq >= 1),
    ts        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL UNIQUE,
    record    TEXT NOT NULL CHECK (json_valid(record))
) STRICT;
CREATE INDEX audit_kind ON audit (kind);

CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;

CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;
"#;

/// Forward-only migrations. Entry `i` moves the schema from version `i` to
/// `i + 1` (entry 0 creates version 1 on an empty database). Append only;
/// never edit a shipped entry. No JS source: new with SQLite.
pub const MIGRATIONS: &[&str] = &[SCHEMA_SQL];

/// Every table [`SCHEMA_SQL`] creates, for tests and `migrate --dry-run`
/// counts. No JS source: new with SQLite.
pub const TABLES: &[&str] = &[
    "schema_version",
    "kv",
    "settings",
    "vmk_wraps",
    "presence_factors",
    "webauthn",
    "notify",
    "workspaces",
    "credentials",
    "credential_fields",
    "retired_values",
    "pins",
    "sessions",
    "grants",
    "placeholders",
    "approvals",
    "session_requests",
    "clients",
    "listeners",
    "templates",
    "audit",
];
