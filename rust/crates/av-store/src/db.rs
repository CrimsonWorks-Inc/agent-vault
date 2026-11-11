//! Opening `vault.db` (rust/PLAN.md, "Storage contract").
//!
//! [`open`] is the only way the store gets a connection. It creates the file
//! `0600` before SQLite touches it, sets every PRAGMA the PLAN lists, keeps
//! extension loading off, turns on SQLite's defensive mode, and brings the
//! schema up to [`DB_SCHEMA_VERSION`] with forward-only migrations.
//!
//! No JS source: this replaces `#persist` / `Vault.open`'s `vault.json` read in
//! `src/store/vault.js`.

use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use crate::schema::{DB_SCHEMA_VERSION, MIGRATIONS};

/// The file name of the database inside the vault dir.
pub const DB_FILE: &str = "vault.db";

/// The PRAGMAs every connection runs with, in order, and the value each must
/// read back as. `journal_mode` reads back as text, the rest as integers
/// (`synchronous=FULL` is 2).
pub const PRAGMAS: &[(&str, &str)] = &[
    ("journal_mode", "WAL"),
    ("synchronous", "FULL"),
    ("secure_delete", "ON"),
    ("trusted_schema", "OFF"),
    ("foreign_keys", "ON"),
    ("cell_size_check", "ON"),
];

/// Open (creating if needed) the vault database at `path`, mode `0600`, with
/// every PRAGMA in [`PRAGMAS`] applied and the schema migrated to
/// [`DB_SCHEMA_VERSION`]. The containing directory must already exist with
/// mode `0700` (the vault creates it).
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    // Create the file ourselves, 0600, so there is no window in which SQLite
    // has made it with the process umask.
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io_err)?;

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    // NOFOLLOW refuses a symlink anywhere in the path, and on macOS the temp
    // and /var directories are reached through one, so resolve it first. The
    // file itself was just created by us above.
    let real = std::fs::canonicalize(path).map_err(io_err)?;
    let conn = Connection::open_with_flags(&real, flags)?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// An in-memory database with the same settings, for tests and
/// `migrate --dry-run`. `journal_mode` reads back as `memory` here, since an
/// in-memory database cannot use WAL.
pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// Apply the PLAN's connection settings to `conn`.
fn configure(conn: &Connection) -> rusqlite::Result<()> {
    // Defensive mode blocks writable_schema and other ways to corrupt the
    // file from SQL. trusted_schema is also set through the PRAGMA below.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    // Extension loading: rusqlite is built without its `load_extension`
    // feature, so nothing can turn it on, and SQLite's default is off. The
    // pragma test asserts that `load_extension()` is refused.
    for (name, value) in PRAGMAS {
        // PRAGMA arguments cannot be bound parameters. These are compile-time
        // constants from PRAGMAS, never values from a caller.
        let sql = ["PRAGMA ", name, " = ", value].concat();
        conn.query_row(&sql, [], |_| Ok(())).or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(()),
            e => Err(e),
        })?;
    }
    Ok(())
}

/// Bring the schema up to [`DB_SCHEMA_VERSION`], one migration per
/// transaction. Forward-only: a database newer than this build is refused.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let current = schema_version(conn)?;
    if current > DB_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "vault.db schema version {current} is newer than this build ({DB_SCHEMA_VERSION})"
        )));
    }
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let to = index as u32 + 1;
        let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_version (id, version, migrated_at)
             VALUES (1, ?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT (id) DO UPDATE SET version = excluded.version,
                                            migrated_at = excluded.migrated_at",
            [to],
        )?;
        tx.commit()?;
    }
    Ok(())
}

/// The schema version recorded in the database, or 0 for an empty one.
pub fn schema_version(conn: &Connection) -> rusqlite::Result<u32> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(0);
    }
    conn.query_row("SELECT version FROM schema_version WHERE id = 1", [], |r| {
        r.get(0)
    })
}

fn io_err(e: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::TABLES;

    fn temp_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join(DB_FILE)).unwrap();
        (dir, conn)
    }

    fn pragma_text(conn: &Connection, name: &str) -> String {
        let sql = ["PRAGMA ", name].concat();
        conn.query_row(&sql, [], |r| {
            let v: rusqlite::types::Value = r.get(0)?;
            Ok(match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
        })
        .unwrap()
    }

    #[test]
    fn pragmas_are_set_after_open() {
        let (_dir, conn) = temp_db();
        assert_eq!(pragma_text(&conn, "journal_mode"), "wal");
        assert_eq!(pragma_text(&conn, "synchronous"), "2", "synchronous=FULL");
        assert_eq!(pragma_text(&conn, "secure_delete"), "1");
        assert_eq!(pragma_text(&conn, "trusted_schema"), "0");
        assert_eq!(pragma_text(&conn, "foreign_keys"), "1");
        assert_eq!(pragma_text(&conn, "cell_size_check"), "1");
    }

    #[test]
    fn pragmas_hold_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE);
        drop(open(&path).unwrap());
        let conn = open(&path).unwrap();
        assert_eq!(pragma_text(&conn, "journal_mode"), "wal");
        assert_eq!(pragma_text(&conn, "secure_delete"), "1");
        assert_eq!(pragma_text(&conn, "foreign_keys"), "1");
        assert_eq!(schema_version(&conn).unwrap(), DB_SCHEMA_VERSION);
    }

    #[test]
    fn extension_loading_is_off() {
        let (_dir, conn) = temp_db();
        let err = conn
            .query_row("SELECT load_extension('av-no-such-extension')", [], |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[test]
    fn defensive_mode_blocks_writable_schema() {
        let (_dir, conn) = temp_db();
        conn.execute_batch("PRAGMA writable_schema = ON").unwrap();
        let r = conn.execute("DELETE FROM sqlite_schema WHERE name = 'audit'", []);
        assert!(r.is_err(), "defensive mode refuses schema edits");
    }

    #[test]
    fn file_is_0600() {
        let (dir, _conn) = temp_db();
        let mode = std::fs::metadata(dir.path().join(DB_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn every_table_exists_and_version_is_recorded() {
        let (_dir, conn) = temp_db();
        for t in TABLES {
            let n: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table {t}");
        }
        assert_eq!(schema_version(&conn).unwrap(), DB_SCHEMA_VERSION);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE);
        let conn = open(&path).unwrap();
        conn.execute(
            "UPDATE schema_version SET version = ?1",
            [DB_SCHEMA_VERSION + 1],
        )
        .unwrap();
        drop(conn);
        assert!(open(&path).is_err());
    }

    // ------------------------------------------------------------- triggers

    fn seed(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO credentials (id, slug, connector_kind, connector, created_at)
               VALUES ('cred_1', 'demo', 'generic', '{}', '2026-01-01T00:00:00.000Z');
             INSERT INTO credential_fields (credential_id, name, position, sealed, key_version, fp8, length)
               VALUES ('cred_1', 'token', 0, '{\"v\":2}', 1, 'fp8fp8fp', 20);
             INSERT INTO sessions (id, label, token_hash, policy, remote, state, created_at, infinite)
               VALUES ('sid000000001', 'session', 'th1', '{}', 0, 'active', '2026-01-01T00:00:00.000Z', 0);
             INSERT INTO grants (id, session_id, credential_id, fields, policy, state, created_at)
               VALUES ('grant_1', 'sid000000001', 'cred_1', '[\"token\"]', '{}', 'active', '2026-01-01T00:00:00.000Z');",
        )
        .unwrap();
    }

    fn dead_row(conn: &Connection, id: &str, reason: &str, uses: i64) {
        conn.execute(
            "INSERT INTO placeholders (id, grant_id, credential_id, field, sid, nonce_hash, uses, max_uses,
                                       state, dead_reason, created_at)
             VALUES (?1, 'grant_1', 'cred_1', 'token', 'sid000000001', ?1 || '-nh', ?3, 3,
                     'dead', ?2, '2026-01-01T00:00:00.000Z')",
            rusqlite::params![id, reason, uses],
        )
        .unwrap();
    }

    fn refund(conn: &Connection, id: &str, new_uses: i64) -> rusqlite::Result<usize> {
        conn.execute(
            "UPDATE placeholders SET state = 'active', dead_reason = NULL, uses = ?2 WHERE id = ?1",
            rusqlite::params![id, new_uses],
        )
    }

    #[test]
    fn an_exhausted_placeholder_can_be_refunded_one_use() {
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_ok", "exhausted", 3);
        assert_eq!(refund(&conn, "ph_ok", 2).unwrap(), 1);
    }

    #[test]
    fn no_other_dead_reason_comes_back() {
        let (_dir, conn) = temp_db();
        seed(&conn);
        for reason in ["revoked", "expired", "burned", "session_ended", "replaced"] {
            let id = format!("ph_{reason}");
            dead_row(&conn, &id, reason, 3);
            let err = refund(&conn, &id, 2).unwrap_err();
            assert!(
                err.to_string().contains("cannot become active"),
                "{reason}: {err}"
            );
        }
    }

    #[test]
    fn a_refund_returns_exactly_one_use() {
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_two", "exhausted", 3);
        assert!(refund(&conn, "ph_two", 1).is_err(), "two uses at once");
        assert!(refund(&conn, "ph_two", 3).is_err(), "no use returned");
        // Nothing else may change in the refund.
        let r = conn.execute(
            "UPDATE placeholders SET state = 'active', dead_reason = NULL, uses = 2, max_uses = 9
             WHERE id = 'ph_two'",
            [],
        );
        assert!(r.is_err(), "max_uses changed during a refund");
    }

    #[test]
    fn no_refund_into_a_revoked_grant_or_session() {
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_g", "exhausted", 3);
        conn.execute(
            "UPDATE grants SET state = 'revoked' WHERE id = 'grant_1'",
            [],
        )
        .unwrap();
        assert!(refund(&conn, "ph_g", 2).is_err(), "grant revoked");
        conn.execute(
            "UPDATE grants SET state = 'active' WHERE id = 'grant_1'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE sessions SET state = 'revoked' WHERE id = 'sid000000001'",
            [],
        )
        .unwrap();
        assert!(refund(&conn, "ph_g", 2).is_err(), "session revoked");
    }

    #[test]
    fn a_placeholder_identity_is_fixed() {
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_id", "burned", 0);
        let r = conn.execute(
            "UPDATE placeholders SET nonce_hash = 'other' WHERE id = 'ph_id'",
            [],
        );
        assert!(r.is_err());
    }

    #[test]
    fn audit_rows_are_append_only() {
        let (_dir, conn) = temp_db();
        conn.execute(
            "INSERT INTO audit (seq, ts, kind, prev_hash, hash, record)
             VALUES (1, '2026-01-01T00:00:00.000Z', 'vault.created', '0', 'h1', '{}')",
            [],
        )
        .unwrap();
        let up = conn
            .execute("UPDATE audit SET kind = 'x' WHERE seq = 1", [])
            .unwrap_err();
        assert!(up.to_string().contains("append-only"), "{up}");
        let del = conn
            .execute("DELETE FROM audit WHERE seq = 1", [])
            .unwrap_err();
        assert!(del.to_string().contains("append-only"), "{del}");
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let (_dir, conn) = temp_db();
        let r = conn.execute(
            "INSERT INTO grants (id, session_id, credential_id, fields, policy, state, created_at)
             VALUES ('g', 'no-such-session', 'no-such-cred', '[]', '{}', 'active', 'now')",
            [],
        );
        assert!(r.is_err());
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn deleting_a_credential_keeps_its_grants_and_placeholders() {
        // deleteCredential in src/store/vault.js revokes the grants and
        // deletes only the credential; the ledger must survive so an old
        // placeholder replays as dead, not unknown.
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_kept", "revoked", 1);
        conn.execute("DELETE FROM credentials WHERE id = 'cred_1'", [])
            .unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM grants WHERE id = 'grant_1'"),
            1
        );
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM placeholders WHERE id = 'ph_kept'"
            ),
            1
        );
        // The credential's own parts still go with it.
        assert_eq!(count(&conn, "SELECT count(*) FROM credential_fields"), 0);
    }

    #[test]
    fn a_grant_may_name_a_credential_that_no_longer_exists() {
        // The migrate case: a JS vault that ever deleted a credential holds
        // grants whose credential_id names nothing.
        let (_dir, conn) = temp_db();
        seed(&conn);
        conn.execute(
            "INSERT INTO grants (id, session_id, credential_id, fields, policy, state, created_at)
             VALUES ('grant_orphan', 'sid000000001', 'cred_deleted', '[]', '{}', 'revoked', 'now')",
            [],
        )
        .unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM grants WHERE id = 'grant_orphan'"
            ),
            1
        );
    }

    #[test]
    fn no_refund_when_the_grant_or_session_row_is_missing() {
        // A missing row makes the subquery NULL; the trigger must still refuse.
        // Foreign keys are switched off only to make the missing row possible.
        let (_dir, conn) = temp_db();
        seed(&conn);
        dead_row(&conn, "ph_nogrant", "exhausted", 3);
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        conn.execute("DELETE FROM grants WHERE id = 'grant_1'", [])
            .unwrap();
        let err = refund(&conn, "ph_nogrant", 2).unwrap_err();
        assert!(
            err.to_string().contains("cannot become active"),
            "grant missing: {err}"
        );

        let (_dir2, conn2) = temp_db();
        seed(&conn2);
        dead_row(&conn2, "ph_nosession", "exhausted", 3);
        conn2.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        conn2
            .execute("DELETE FROM sessions WHERE id = 'sid000000001'", [])
            .unwrap();
        let err = refund(&conn2, "ph_nosession", 2).unwrap_err();
        assert!(
            err.to_string().contains("cannot become active"),
            "session missing: {err}"
        );
    }
}
