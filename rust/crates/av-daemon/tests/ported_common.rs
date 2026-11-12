//! Closed-database fixture seeding; never use with a live Vault or daemon.
#![forbid(unsafe_code)]

/// Mirrors gateway-routing.test.js assigning expires_at while retaining the
/// session's original max_expires_at. Caller must drop the Vault first.
pub fn seed_session_expiry(dir: &std::path::Path, sid: &str, expiry: &str) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
                rusqlite::params![expiry, sid]
            )
            .unwrap(),
        1
    );
    // Dropping closes the connection before the public Vault is reopened.
}

/// Mirrors the closed-on-disk legacy/tampered rows in gateway-w2-pipeline
/// and gateway-w2-seams: policy, expiry, state, and quota fixture mutations.
/// Both patch objects have a fixed whitelist; no schema or PRAGMA changes.
pub fn seed_gateway_rows(
    dir: &std::path::Path,
    sid: &str,
    gid: &str,
    session: &serde_json::Value,
    grant: &serde_json::Value,
) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    for (table, id, patch, columns) in [
        ("sessions", sid, session, &["expires_at", "infinite"][..]),
        (
            "grants",
            gid,
            grant,
            &["expires_at", "state", "policy", "quota_state"][..],
        ),
    ] {
        let mut assignments = Vec::new();
        let mut parameters = Vec::new();
        for (column, value) in patch.as_object().unwrap() {
            assert!(columns.contains(&column.as_str()));
            let value = match value {
                serde_json::Value::Null => rusqlite::types::Value::Null,
                serde_json::Value::Bool(b) => rusqlite::types::Value::Integer(i64::from(*b)),
                serde_json::Value::String(s) => rusqlite::types::Value::Text(s.clone()),
                other => rusqlite::types::Value::Text(other.to_string()),
            };
            assignments.push(format!("{column} = ?"));
            parameters.push(value);
        }
        if !assignments.is_empty() {
            parameters.push(rusqlite::types::Value::Text(id.to_string()));
            assert_eq!(
                connection
                    .execute(
                        &format!("UPDATE {table} SET {} WHERE id = ?", assignments.join(", ")),
                        rusqlite::params_from_iter(parameters)
                    )
                    .unwrap(),
                1
            );
        }
    }
}

/// Mirrors gateway-w2-seams assigning an unreadable rules list: the
/// fallback rules must still protect an authenticated session.
pub fn seed_tripwires(dir: &std::path::Path, value: &serde_json::Value) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    connection.execute("INSERT INTO settings(key,value) VALUES('tripwires',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [value.to_string()]).unwrap();
}
