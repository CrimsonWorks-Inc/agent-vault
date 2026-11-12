//! Shared fixtures: ports `test/security/store-helpers.js`.

use std::collections::BTreeMap;

use av_core::policy::Policy;
use av_core::secret::SecretString;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::audit::{AuditRecord, ReadFilter};
use crate::error::{Error, Result};
use crate::model::{FactorClass, GrantRecord, PlaceholderRow, SessionRecord};
use crate::vault::{
    CreateGrantOptions, CreateOptions, CreateSessionOptions, IssueOptions, NewCredential,
    PublicCredential, Vault,
};

pub const SECRET: &str = "ghp_STOREHELPER00112233445566778899aabb";
pub const OTHER_SECRET: &str = "tok_OTHERHELPER00112233445566778899";
pub const HOUR: i64 = 3_600_000;
pub const DAY: i64 = 24 * HOUR;

pub fn policy() -> Policy {
    policy_from(json!({
        "hosts": ["api.example.com"], "methods": ["GET"], "paths": ["/**"],
        "budget": { "unit": "requests", "limit": 100 }, "approval": "on-write"
    }))
}

pub fn policy_from(v: Value) -> Policy {
    serde_json::from_value(v).expect("a policy layer")
}

/// The POLICY with `budget` replaced (or removed for `Value::Null`... use
/// `policy_without_budget`).
pub fn policy_with_budget(budget: Value) -> Policy {
    let mut p = serde_json::to_value(policy()).unwrap();
    p["budget"] = budget;
    policy_from(p)
}

pub fn policy_without_budget() -> Policy {
    let mut p = serde_json::to_value(policy()).unwrap();
    p.as_object_mut().unwrap().remove("budget");
    policy_from(p)
}

pub fn s(v: &str) -> SecretString {
    SecretString::from(v.to_string())
}

pub struct Fx {
    pub dir: tempfile::TempDir,
    pub vault: Vault,
    pub cred: PublicCredential,
    pub other: PublicCredential,
}

pub fn new_cred(slug: &str, kind: &str, host: &str, fields: &[(&str, &str)]) -> NewCredential {
    let mut connector = serde_json::Map::new();
    connector.insert("host".into(), Value::from(host));
    connector.insert("scheme".into(), Value::from("https"));
    NewCredential {
        slug: slug.into(),
        kind: kind.into(),
        connector,
        fields: fields.iter().map(|(n, v)| (n.to_string(), s(v))).collect(),
        sites: fields
            .iter()
            .map(|(n, _)| (n.to_string(), vec!["header:authorization:Bearer".to_string()]))
            .collect::<BTreeMap<_, _>>(),
    }
}

/// A throwaway vault with two credentials.
pub fn fresh() -> Fx {
    fresh_with(FactorClass::None, None)
}

pub fn fresh_with(factor: FactorClass, passphrase: Option<&str>) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::create(
        dir.path(),
        CreateOptions {
            factor,
            passphrase: passphrase.map(s),
        },
    )
    .unwrap();
    let cred = vault
        .add_credential(new_cred("demo", "http", "api.example.com", &[("token", SECRET)]))
        .unwrap();
    let other = vault
        .add_credential(new_cred(
            "other",
            "http",
            "api.other.example",
            &[("token", OTHER_SECRET)],
        ))
        .unwrap();
    Fx {
        dir,
        vault,
        cred,
        other,
    }
}

/// `{ code, rule }` of a refusal, or `("none", None)`.
pub fn code<T>(r: Result<T>) -> (String, Option<String>) {
    match r {
        Ok(_) => ("none".into(), None),
        Err(e) => match e.as_vault() {
            Some(v) => (v.code.as_str().to_string(), v.extra.rule.clone()),
            None => (format!("error: {e}"), None),
        },
    }
}

pub fn code_of<T>(r: Result<T>) -> String {
    code(r).0
}

pub fn rule(c: &str, r: Option<&str>) -> (String, Option<String>) {
    (c.to_string(), r.map(str::to_string))
}

pub fn err_msg<T>(r: Result<T>) -> String {
    match r {
        Ok(_) => String::new(),
        Err(Error::Vault(v)) => v.detail.clone(),
        Err(e) => e.to_string(),
    }
}

pub fn records(v: &Vault, kind: &str) -> Vec<AuditRecord> {
    v.audit()
        .expect("unlocked")
        .read(&ReadFilter {
            limit: 0,
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == kind)
        .collect()
}

pub fn field<'a>(r: &'a AuditRecord, k: &str) -> &'a Value {
    r.fields.get(k).unwrap_or(&Value::Null)
}

/// Every entity row (not the audit log), as text, and the audit length.
pub fn snapshot(v: &Vault) -> (String, i64) {
    let c = v.conn();
    let mut out = String::new();
    for t in crate::schema::TABLES {
        if *t == "audit" || *t == "schema_version" {
            continue;
        }
        let sql = ["SELECT * FROM ", t].concat();
        let mut stmt = c.prepare(&sql).unwrap();
        let n = stmt.column_count();
        let rows = stmt
            .query_map([], |r| {
                let mut line = String::new();
                for i in 0..n {
                    let val: rusqlite::types::Value = r.get(i)?;
                    line.push_str(&format!("{val:?}|"));
                }
                Ok(line)
            })
            .unwrap();
        out.push_str(t);
        for l in rows {
            out.push_str(&l.unwrap());
            out.push('\n');
        }
    }
    let n: i64 = c
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    (out, n)
}

/// Asserts `f` is refused with `expected` and changed nothing anywhere.
pub fn refused_cleanly<T>(
    v: &mut Vault,
    f: impl FnOnce(&mut Vault) -> Result<T>,
    expected: (&str, Option<&str>),
) {
    let before = snapshot(v);
    let seq = v.audit().map(|a| a.seq());
    assert_eq!(code(f(v)), rule(expected.0, expected.1));
    let after = snapshot(v);
    assert_eq!(after.0, before.0, "a refusal changed the vault");
    assert_eq!(after.1, before.1, "a refusal wrote to the audit log");
    assert_eq!(v.audit().map(|a| a.seq()), seq, "a refusal moved the chain");
}

pub fn session_with(v: &mut Vault, opts: CreateSessionOptions) -> SessionRecord {
    v.create_session(opts).unwrap().session
}

pub fn session(v: &mut Vault) -> SessionRecord {
    session_with(v, CreateSessionOptions::default())
}

pub fn grant_opts(sid: &str, cred_id: &str) -> CreateGrantOptions {
    CreateGrantOptions {
        session_id: sid.into(),
        credential_id: cred_id.into(),
        fields: Some(vec!["token".into()]),
        policy: policy(),
        ..Default::default()
    }
}

pub fn grant_for(v: &mut Vault, sid: &str, cred_id: &str) -> GrantRecord {
    v.create_grant(grant_opts(sid, cred_id)).unwrap()
}

pub fn issue(v: &mut Vault, grant_id: &str) -> PlaceholderRow {
    v.issue_placeholder(IssueOptions {
        grant_id: grant_id.into(),
        ..Default::default()
    })
    .unwrap()
    .row
}

pub fn ph_row(v: &Vault, id: &str) -> PlaceholderRow {
    v.list_placeholders(None)
        .unwrap()
        .into_iter()
        .find(|p| p.id == id)
        .expect("row")
}

pub fn grant_row(v: &Vault, id: &str) -> GrantRecord {
    v.grant(id).unwrap().expect("grant")
}

pub fn session_row(v: &Vault, id: &str) -> SessionRecord {
    v.session(id).unwrap().expect("session")
}

/// Run one statement against the vault's database (to corrupt a row as the
/// JS tests do by editing the object in memory).
pub fn exec(v: &Vault, sql: &str, params: &[&dyn rusqlite::ToSql]) {
    let c: std::sync::MutexGuard<'_, Connection> = v.conn();
    c.execute(sql, params).unwrap();
}

pub fn now() -> i64 {
    crate::util::now_ms()
}

pub fn iso(ms: i64) -> String {
    crate::util::iso(ms)
}

pub fn parse(s: &str) -> i64 {
    crate::util::parse_ms(s).expect("a date")
}

pub fn at<T>(ms: i64, f: impl FnOnce() -> T) -> T {
    crate::util::at(ms, f)
}

/// Public keys only (no secret): three P-256 keys, an Ed25519 and a P-384.
pub const P256_A: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV8JGtbpbLXO8XiHU7WZK6RPV1LVwmD7mmko+IHBUQ0RVtSI24dXTyl/HF2Bc5ho1yABqfeLIoCAhQMYZ8L7cxA==";
pub const P256_B: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX+Ko54Qd52pn7p8FU61Y5S6DZmg/j0m7tI/L2Q3PbcXGF7brHirZ43VubJGAzRbWlfY8L5aqmr2U9MLqS2V+sQ==";
pub const P256_C: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFfKFSrO68/Ksdo4AiG2zx+O6NyvkY0hbV4rF+ACNh1/jfHCdLddVUfRiGSsOXzN9+b6s1Osxiho4P/5hYtsljQ==";
pub const ED25519: &str = "MCowBQYDK2VwAyEANKHnyqArQEggFNewEh0DeGGhdkEXN6EqPRccdq5NGPY=";
pub const P384: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUdowsFF/At70p0OS5B1WmL45lPct9GSkIcvVrL/GRlJ3jz0rjHLUbBYWYJyKbK6CEeepfbOjPjsSQjUHyHp9ALK/p+0t7CQQNnzuMIWczU7Kox8hFtzHiEdWrYq/lsyo";

/// A random base64url credential id of `n` bytes.
pub fn cred_id(n: usize) -> String {
    use base64::Engine as _;
    let mut b = vec![0u8; n];
    crate::crypto::fill_random(&mut b).unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A presence authenticator record, as `makeAuthenticator().record`.
pub fn authenticator(spki: &str) -> Value {
    json!({ "credentialId": cred_id(32), "publicKeySpki": spki, "signCount": 0 })
}

pub fn prf_secret() -> av_core::secret::SecretBytes {
    let mut b = vec![0u8; 32];
    crate::crypto::fill_random(&mut b).unwrap();
    av_core::secret::SecretBytes::from(b)
}

pub const PASSPHRASE: &str = "correct horse battery staple";
