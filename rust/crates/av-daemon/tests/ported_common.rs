//! Closed-database fixture seeding; never use with a live Vault or daemon.
#![forbid(unsafe_code)]

/// Mirrors gateway-routing.test.js and revocation.test.js assigning expires_at while retaining the
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

/// Mirrors gateway-w2-pipeline corrupting scrub_patterns on a credential
/// other than the routed one. The public pipeline must still fail closed.
pub fn seed_scrub_patterns(dir: &std::path::Path, slug: &str, patterns: &serde_json::Value) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE credentials SET scrub_patterns=?1 WHERE slug=?2",
                rusqlite::params![patterns.to_string(), slug]
            )
            .unwrap(),
        1
    );
}

/// Mirrors gateway-w2-seams' unavailable session-request side system with
/// a real deserialization failure in a referenced credential. All values
/// satisfy SQLite's JSON constraints; the public panic must report partial.
pub fn seed_panic_side_system_failure(dir: &std::path::Path) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE credentials SET quarantine=?1 WHERE slug='broken-health'",
                ["\"unreadable legacy marker\""]
            )
            .unwrap(),
        1
    );
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    connection.execute("INSERT INTO session_requests(id,collect_hash,proposal,fingerprint,summary,state,created_at) VALUES(?1,?2,?3,?4,?5,'pending',?6)",rusqlite::params!["sr_fixture_partial","fake-collect-hash","{\"cred\":\"broken-health\"}","fake-fingerprint","fixture pending request",now]).unwrap();
}

/// Real lock contention for gateway-w2-seams health recording; no row writes,
/// schema edits, or PRAGMA changes. Dropping always releases the lock.
pub struct TempWriteLock(rusqlite::Connection);
impl TempWriteLock {
    pub fn acquire(dir: &std::path::Path) -> Self {
        assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
        let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        Self(connection)
    }
}
impl Drop for TempWriteLock {
    fn drop(&mut self) {
        let _ = self.0.execute_batch("ROLLBACK");
    }
}

/// A deterministic, obviously fake ES256 platform authenticator for the
/// widening.test.js fixture. Its counter stays zero, like the JS fixture,
/// so replay tests exercise challenge consumption rather than counter checks.
pub struct FakeAuthenticator {
    key: p256::ecdsa::SigningKey,
    id: Vec<u8>,
}
impl FakeAuthenticator {
    pub fn new(seed: u8) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
            id: vec![seed; 16],
        }
    }
    pub fn id(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.id)
    }
    pub fn register(&self, challenge: &str, origin: &str) -> serde_json::Value {
        use base64::Engine;
        use ciborium::value::Value as C;
        use sha2::{Digest, Sha256};
        let point = self.key.verifying_key().to_sec1_point(false);
        let cose = C::Map(vec![
            (C::Integer(1.into()), C::Integer(2.into())),
            (C::Integer(3.into()), C::Integer((-7).into())),
            (C::Integer((-1).into()), C::Integer(1.into())),
            (
                C::Integer((-2).into()),
                C::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                C::Integer((-3).into()),
                C::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&cose, &mut cose_bytes).unwrap();
        let mut data = Sha256::digest(b"localhost").to_vec();
        data.push(0x45);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend(cose_bytes);
        let att = C::Map(vec![
            (C::Text("fmt".into()), C::Text("none".into())),
            (C::Text("attStmt".into()), C::Map(vec![])),
            (C::Text("authData".into()), C::Bytes(data)),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&att, &mut bytes).unwrap();
        let client = serde_json::to_vec(
            &serde_json::json!({"type":"webauthn.create","challenge":challenge,"origin":origin}),
        )
        .unwrap();
        serde_json::json!({"attestationObject":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),"clientDataJSON":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client)})
    }
    pub fn assertion(&self, challenge: &str, origin: &str) -> serde_json::Value {
        self.assertion_options(challenge, origin, true, 0, "webauthn.get")
    }
    pub fn assertion_options(
        &self,
        challenge: &str,
        origin: &str,
        uv: bool,
        count: u32,
        kind: &str,
    ) -> serde_json::Value {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};
        let client = serde_json::to_vec(
            &serde_json::json!({"type":kind,"challenge":challenge,"origin":origin}),
        )
        .unwrap();
        let mut data = Sha256::digest(b"localhost").to_vec();
        data.push(if uv { 0x05 } else { 0x01 });
        data.extend_from_slice(&count.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature: p256::ecdsa::Signature = self.key.sign(&signed);
        let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        serde_json::json!({"credentialId":self.id(),"authenticatorData":b64.encode(data),"clientDataJSON":b64.encode(client),"signature":b64.encode(signature.to_der().as_bytes())})
    }
}

/// A session that exists on disk without a creation record, like the JS
/// activity fixture. Copy through SQLite's typed values and preserve every
/// constraint and trigger; only its id and (unused, fake) token hash differ.
/// Caller must close every Vault and daemon before this function runs.
pub fn seed_unaudited_session(dir: &std::path::Path, sid: &str, ghost: &str) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    let mut query = connection
        .prepare("SELECT * FROM sessions WHERE id = ?1")
        .unwrap();
    let columns = query.column_names().map(str::to_owned).collect::<Vec<_>>();
    assert!(columns
        .iter()
        .all(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')));
    let mut values = query
        .query_row([sid], |row| {
            (0..columns.len())
                .map(|i| row.get::<_, rusqlite::types::Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    values[columns.iter().position(|c| c == "id").unwrap()] =
        rusqlite::types::Value::Text(ghost.into());
    values[columns.iter().position(|c| c == "token_hash").unwrap()] =
        rusqlite::types::Value::Text("f".repeat(64));
    drop(query);
    let placeholders = vec!["?"; columns.len()].join(",");
    assert_eq!(
        connection
            .execute(
                &format!(
                    "INSERT INTO sessions ({}) VALUES ({placeholders})",
                    columns.join(",")
                ),
                rusqlite::params_from_iter(values)
            )
            .unwrap(),
        1
    );
}

/// Legacy connector pin tables, written only after the test vault is closed.
pub fn seed_credential_pins(dir: &std::path::Path, slug: &str, pins: &serde_json::Value) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    let id: String = connection
        .query_row("SELECT id FROM credentials WHERE slug=?1", [slug], |row| {
            row.get(0)
        })
        .unwrap();
    connection
        .execute("DELETE FROM pins WHERE credential_id=?1", [&id])
        .unwrap();
    for (host, list) in pins.as_object().unwrap() {
        for (position, pin) in list.as_array().unwrap().iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO pins(credential_id,host,spki,position) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![id, host, pin.as_str().unwrap(), position as i64],
                )
                .unwrap();
        }
    }
}

/// Legacy health metadata is tolerated as absent; only the closed test vault.
pub fn seed_legacy_health_shape(dir: &std::path::Path) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let connection = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE credentials SET health=?1 WHERE slug='broken-health'",
                ["\"legacy health shape\""]
            )
            .unwrap(),
        1
    );
}

/// Append an audit tail to the closed temporary DB without weakening constraints.
pub fn seed_audit_tail(dir: &std::path::Path, record: &str) -> Result<u64, rusqlite::Error> {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let conn = rusqlite::Connection::open(dir.join("vault.db"))?;
    let (seq, previous): (i64, String) = conn.query_row(
        "SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let next = seq + 1;
    let hash = format!("{next:064x}");
    conn.execute(
        "INSERT INTO audit(seq,ts,kind,prev_hash,hash,record) VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            next,
            "2026-11-12T00:00:00.000Z",
            "fixture.tail",
            previous,
            hash,
            record
        ],
    )?;
    Ok(next as u64)
}
/// Bulk copies of a session for the complete-list fixture. The original stays
/// usable as an ordinary-traffic control; fake hashes are never authenticators.
/// Call only after every Vault and daemon has closed the temporary database.
pub fn seed_complete_sessions(dir: &std::path::Path, count: usize) {
    assert!(dir.starts_with("/tmp") || dir.starts_with(std::env::temp_dir()));
    let mut conn = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    let mut q = conn.prepare("SELECT * FROM sessions LIMIT 1").unwrap();
    let columns = q.column_names().map(str::to_owned).collect::<Vec<_>>();
    assert!(columns
        .iter()
        .all(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')));
    let template = q
        .query_row([], |r| {
            (0..columns.len())
                .map(|i| r.get::<_, rusqlite::types::Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    drop(q);
    let id = columns.iter().position(|s| s == "id").unwrap();
    let label = columns.iter().position(|s| s == "label").unwrap();
    let hash = columns.iter().position(|s| s == "token_hash").unwrap();
    let sql = format!(
        "INSERT INTO sessions ({}) VALUES ({})",
        columns.join(","),
        vec!["?"; columns.len()].join(",")
    );
    let tx = conn.transaction().unwrap();
    for i in 0..count {
        let mut row = template.clone();
        row[id] = rusqlite::types::Value::Text(format!("s_many_{i:05}"));
        row[label] = rusqlite::types::Value::Text(format!("s_many_{i:05}"));
        row[hash] = rusqlite::types::Value::Text(format!("{i:064x}"));
        tx.execute(&sql, rusqlite::params_from_iter(row)).unwrap();
    }
    tx.commit().unwrap();
}
