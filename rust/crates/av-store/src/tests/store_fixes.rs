//! Ports `test/security/fix-control-store.test.js`.

use av_core::policy::{evaluate_http, needs_approval, ApprovalQuery, HttpTarget, Policy};
use serde_json::{json, Value};

use super::helpers::*;
use crate::model::PlaceholderState;
use crate::vault::*;

fn base() -> Value {
    json!({
        "hosts": ["api.example.com"], "methods": ["GET", "POST"], "paths": ["/repos/**"],
        "budget": { "unit": "requests", "limit": 100 }, "approval": "on-write"
    })
}

fn wider() -> Value {
    json!({
        "methods": ["DELETE"], "paths": ["/admin/**"], "approval": "auto",
        "hosts": ["evil.example"], "budget": { "unit": "requests", "limit": 1_000_000_000u64 }
    })
}

const METHODS: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
const HOSTS: [&str; 5] = [
    "api.example.com",
    "API.Example.com",
    "evil.example",
    "sub.api.example.com",
    "example.com",
];
const PATHS: [&str; 8] = [
    "/repos/a",
    "/repos/a/b/c",
    "/repos",
    "/admin/x",
    "/admin",
    "/",
    "/other/thing",
    "/repos/../admin/x",
];
const STRICTNESS: [&str; 4] = ["auto", "first-use", "on-write", "each"];

fn allows(p: &Policy, method: &str, host: &str, path: &str) -> bool {
    evaluate_http(
        p,
        &HttpTarget {
            method: Some(method),
            host,
            path,
        },
    )
    .is_ok()
}

/// `after` permits nothing `before` refused, by behaviour.
fn no_wider(after: &Policy) -> std::result::Result<(), String> {
    let before = policy_from(base());
    let a = serde_json::to_value(after).unwrap();
    let b = base();
    for k in ["methods", "paths", "hosts"] {
        if b[k].is_array() && !a[k].is_array() {
            return Err(format!("{k} is no longer restricted"));
        }
    }
    for m in METHODS {
        for h in HOSTS {
            for p in PATHS {
                if !allows(&before, m, h, p) && allows(after, m, h, p) {
                    return Err(format!("{m} {h}{p} was refused before and is allowed now"));
                }
                if allows(after, m, h, p) {
                    for first_use in [true, false] {
                        let q = ApprovalQuery {
                            method: Some(m),
                            first_use,
                        };
                        if needs_approval(&before, &q) && !needs_approval(after, &q) {
                            return Err(format!("{m} no longer needs approval"));
                        }
                    }
                }
            }
        }
    }
    let rank = |v: &Value| {
        STRICTNESS
            .iter()
            .position(|s| Some(*s) == v.as_str())
            .unwrap_or(0)
    };
    if rank(&a["approval"]) < rank(&b["approval"]) {
        return Err("approval loosened".into());
    }
    match a["budget"]["limit"].as_f64() {
        Some(l) if l <= 100.0 => Ok(()),
        other => Err(format!("budget widened or unbounded: {other:?}")),
    }
}

fn grant_on(fx: &mut Fx) -> (crate::model::SessionRecord, crate::model::GrantRecord) {
    let s = session_with(
        &mut fx.vault,
        CreateSessionOptions {
            label: Some("parent".into()),
            ..Default::default()
        },
    );
    let g = fx
        .vault
        .create_grant(CreateGrantOptions {
            policy: policy_from(base()),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    (s, g)
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_no_wider_check_itself_refuses_a_result_that_dropped_a_constraint() {
    let with = |k: &str, v: Value| {
        let mut p = base();
        if v.is_null() {
            p.as_object_mut().unwrap().remove(k);
        } else {
            p[k] = v;
        }
        policy_from(p)
    };
    for broken in [
        with("methods", Value::Null),
        with("paths", Value::Null),
        with("hosts", Value::Null),
        with("approval", Value::Null),
        with("budget", Value::Null),
        with("methods", json!(["GET", "PUT"])),
        with("paths", json!(["/**"])),
        with("hosts", json!(["*.example.com"])),
        with("approval", json!("first-use")),
    ] {
        assert!(
            no_wider(&broken).is_err(),
            "passed: {}",
            serde_json::to_string(&broken).unwrap()
        );
    }
    no_wider(&policy_from(base())).unwrap();
    let mut honest = base();
    honest["methods"] = json!(["GET"]);
    honest["paths"] = json!(["/repos/a/**"]);
    honest["approval"] = json!("each");
    honest["budget"] = json!({ "unit": "requests", "limit": 3 });
    no_wider(&policy_from(honest)).unwrap();
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn narrow_grant_can_only_intersect_never_widen() {
    let mut fx = fresh();
    let (_, g) = grant_on(&mut fx);
    let p = fx.vault.narrow_grant(&g.id, &wider()).unwrap().policy;
    no_wider(&p).unwrap();
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn narrow_grant_still_narrows() {
    let mut fx = fresh();
    let (_, g) = grant_on(&mut fx);
    let p = fx
        .vault
        .narrow_grant(
            &g.id,
            &json!({ "methods": ["GET"], "paths": ["/repos/mine/**"], "approval": "each", "budget": { "unit": "requests", "limit": 5 } }),
        )
        .unwrap()
        .policy;
    let p = serde_json::to_value(p).unwrap();
    assert_eq!(p["methods"], json!(["GET"]));
    assert_eq!(p["paths"], json!(["/repos/mine/**"]));
    assert_eq!(p["approval"], json!("each"));
    assert_eq!(p["budget"]["limit"], json!(5));
    assert_eq!(p["hosts"], json!(["api.example.com"]));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_forked_session_can_only_narrow_its_parents_grants() {
    let mut fx = fresh();
    let (s, _) = grant_on(&mut fx);
    let v = &mut fx.vault;
    let child = v
        .fork_session(
            &s.id,
            ForkOptions {
                narrow: policy_from(wider()),
                ..Default::default()
            },
        )
        .unwrap();
    let g = &v.grants_for_session(&child.session.id).unwrap()[0];
    no_wider(&g.policy).unwrap();
    let narrowed = v
        .fork_session(
            &s.id,
            ForkOptions {
                narrow: policy_from(json!({ "methods": ["GET"] })),
                ..Default::default()
            },
        )
        .unwrap();
    let n = serde_json::to_value(&v.grants_for_session(&narrowed.session.id).unwrap()[0].policy)
        .unwrap();
    assert_eq!(n["methods"], json!(["GET"]));
    assert_eq!(n["paths"], json!(["/repos/**"]));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_expired_session_takes_its_placeholders_with_it() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            label: Some("short".into()),
            ttl_ms: Some(2000),
            ..Default::default()
        },
    );
    let g = v
        .create_grant(CreateGrantOptions {
            policy: policy_from(base()),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    issue(v, &g.id);
    let later = parse(s.expires_at.as_deref().unwrap()) + 50;
    let e = at(later, || v.assert_session_live(Some(&s)));
    assert!(err_msg(e).contains("expired"));
    assert!(v
        .list_placeholders(Some(&s.id))
        .unwrap()
        .iter()
        .all(|p| p.state == PlaceholderState::Dead));
    assert_eq!(v.stats().unwrap().placeholders_live, 0);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_ledger_bound_collects_active_rows_whose_time_has_passed() {
    let mut fx = fresh();
    let (s, g) = grant_on(&mut fx);
    let v = &mut fx.vault;
    let past = iso(now() - 1000);
    {
        let c = v.conn();
        for i in 0..600 {
            c.execute(
                "INSERT INTO placeholders (id, grant_id, credential_id, field, sid, nonce_hash, uses, max_uses, state, created_at, expires_at)
                 VALUES (?1, ?2, ?3, 'token', ?4, ?5, 1, 10, 'active', ?6, ?6)",
                rusqlite::params![format!("ph_old{i}"), g.id, fx.cred.id, s.id, format!("x{i}"), past],
            )
            .unwrap();
        }
    }
    issue(v, &g.id);
    let n = v.list_placeholders(None).unwrap().len();
    assert!(n <= 513, "{n} rows kept");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_placeholder_lives_as_long_as_its_session_idle_extension_included() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            label: Some("idle".into()),
            ..Default::default()
        },
    );
    let g = v
        .create_grant(CreateGrantOptions {
            policy: policy_from(base()),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    let t0 = now();
    exec(
        v,
        "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
        &[&iso(t0 + 300), &s.id],
    );
    let row = at(t0, || issue(v, &g.id));
    at(t0, || v.touch_session(&s.id)).unwrap();
    let s2 = session_row(v, &s.id);
    at(t0 + 400, || v.assert_session_live(Some(&s2))).unwrap();
    at(t0 + 400, || v.consume_placeholder(&row.id))
        .expect("the placeholder died before its session");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_placeholder_with_its_own_ttl_still_expires_on_time() {
    let mut fx = fresh();
    let (_, g) = grant_on(&mut fx);
    let v = &mut fx.vault;
    let row = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            ttl_ms: Some(200),
            ..Default::default()
        })
        .unwrap()
        .row;
    let e = at(now() + 300, || v.consume_placeholder(&row.id));
    assert!(err_msg(e).contains("expired"));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn booting_a_locked_vault_does_not_record_an_unlock_nobody_performed() {
    let mut fx = fresh();
    fx.vault.lock().unwrap();
    let mut booted = Vault::open(fx.dir.path()).unwrap();
    assert!(
        !booted.start_in_recorded_state(None).unwrap(),
        "it must come up locked"
    );
    assert!(booted.audit().is_none(), "and holding no audit key");
    assert!(Vault::open(fx.dir.path())
        .unwrap()
        .locked_on_disk()
        .unwrap());
    booted.unlock_with(&UnlockMaterial::default()).unwrap();
    let kinds: Vec<String> = records_all(&booted);
    let from = kinds.iter().rposition(|k| k == "vault.lock").unwrap();
    assert_eq!(
        &kinds[from..],
        &["vault.lock", "vault.started_locked", "vault.unlock"]
    );
}

fn records_all(v: &Vault) -> Vec<String> {
    v.audit()
        .unwrap()
        .read(&crate::audit::ReadFilter {
            limit: 50,
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .map(|r| r.kind)
        .collect()
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn booting_an_unlocked_vault_still_unlocks_it() {
    let fx = fresh();
    let mut booted = Vault::open(fx.dir.path()).unwrap();
    assert!(booted.start_in_recorded_state(None).unwrap());
    assert!(!booted.locked());
    assert!(records_all(&booted).iter().any(|k| k == "vault.unlock"));
}
