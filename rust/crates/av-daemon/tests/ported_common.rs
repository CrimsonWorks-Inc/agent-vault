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
