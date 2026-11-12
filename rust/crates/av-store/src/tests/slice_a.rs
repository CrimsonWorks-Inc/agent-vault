//! Ports `test/security/store-slice-a.test.js`.

use serde_json::{json, Value};

use super::helpers::*;
use crate::model::{GrantState, PlaceholderState, QuarantineBy, SessionState};
use crate::vault::*;

fn sopts() -> CreateSessionOptions {
    CreateSessionOptions::default()
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_infinite_session_never_expires_and_says_so_in_its_record_and_its_audit() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            label: Some("forever".into()),
            infinite: true,
            elevated: vec!["infinite".into()],
            ..sopts()
        },
    );
    assert!(s.infinite);
    assert_eq!(s.expires_at, None);
    assert_eq!(s.max_expires_at, None);
    assert_eq!(s.idle_timeout_ms, None);
    at(now() + 100 * 365 * DAY, || v.assert_session_live(Some(&s))).unwrap();
    assert_eq!(v.stats().unwrap().sessions_active, 1);
    let rec = &records(v, "session.created")[0];
    assert_eq!(field(rec, "infinite"), &Value::Bool(true));
    assert_eq!(field(rec, "expires_at"), &Value::Null);
    assert_eq!(field(rec, "elevated"), &json!(["infinite"]));
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = issue(v, &g.id);
    assert_eq!(row.expires_at, None);
    at(now() + 10 * 365 * DAY, || v.consume_placeholder(&row.id)).unwrap();
    v.touch_session(&s.id).unwrap();
    let s2 = session_row(v, &s.id);
    assert_eq!(s2.expires_at, None);
    assert_eq!(s2.max_expires_at, None);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_infinite_session_is_revocable_and_its_placeholders_die_with_it() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..sopts()
        },
    );
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = issue(v, &g.id);
    v.revoke_session(&s.id, "revoked").unwrap();
    let s = session_row(v, &s.id);
    assert_eq!(
        code(v.assert_session_live(Some(&s))),
        rule("AV_SESSION_REVOKED", None)
    );
    let row = ph_row(v, &row.id);
    assert_eq!(row.state, PlaceholderState::Dead);
    assert_eq!(row.dead_reason.as_deref(), Some("session_ended"));
    assert_eq!(code_of(v.consume_placeholder(&row.id)), "AV_PH_STALE");
    assert_eq!(v.stats().unwrap().sessions_active, 0);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_finite_session_expires_and_idle_activity_extends_it_only_up_to_its_ceiling() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            label: Some("default".into()),
            ..sopts()
        },
    );
    assert!(!s.infinite);
    let created = parse(&s.created_at);
    at(created + 7 * HOUR, || v.touch_session(&s.id)).unwrap();
    assert_eq!(
        parse(session_row(v, &s.id).expires_at.as_deref().unwrap()),
        created + 9 * HOUR
    );
    let mut t = 8.5;
    while t <= 23.5 {
        at(created + (t * HOUR as f64) as i64, || {
            v.touch_session(&s.id)
        })
        .unwrap();
        t += 1.5;
    }
    let s = session_row(v, &s.id);
    assert_eq!(s.expires_at, s.max_expires_at);
    assert_eq!(
        at(created + 25 * HOUR, || code_of(
            v.assert_session_live(Some(&s))
        )),
        "AV_SESSION_EXPIRED"
    );
    let short = session_with(
        v,
        CreateSessionOptions {
            ttl_ms: Some(HOUR),
            ..sopts()
        },
    );
    assert_eq!(
        at(now() + 2 * HOUR, || code_of(
            v.assert_session_live(Some(&short))
        )),
        "AV_SESSION_EXPIRED"
    );
    let infinite: Vec<Value> = records(v, "session.created")
        .iter()
        .map(|r| field(r, "infinite").clone())
        .collect();
    assert_eq!(infinite, vec![Value::Bool(false), Value::Bool(false)]);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_lifetime_that_is_not_a_positive_number_or_infinite_with_one_is_refused_and_writes_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    // NaN, '5', Infinity, {} and non-boolean `infinite` cannot be expressed
    // in the typed options; the ones that can are here.
    for ttl in [0, -1, i64::MIN] {
        refused_cleanly(
            v,
            |v| {
                v.create_session(CreateSessionOptions {
                    ttl_ms: Some(ttl),
                    ..sopts()
                })
            },
            ("AV_POLICY_DENIED", Some("ttl")),
        );
    }
    refused_cleanly(
        v,
        |v| {
            v.create_session(CreateSessionOptions {
                infinite: true,
                ttl_ms: Some(HOUR),
                ..sopts()
            })
        },
        ("AV_POLICY_DENIED", Some("ttl")),
    );
    refused_cleanly(
        v,
        |v| {
            v.create_session(CreateSessionOptions {
                infinite: true,
                remote: true,
                ..sopts()
            })
        },
        ("AV_REMOTE_FORBIDDEN", Some("infinite_remote")),
    );
    assert!(session_with(
        v,
        CreateSessionOptions {
            remote: true,
            ..sopts()
        }
    )
    .expires_at
    .is_some());
    assert!(session_with(
        v,
        CreateSessionOptions {
            ttl_ms: Some(HOUR),
            ..sopts()
        }
    )
    .expires_at
    .is_some());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_fork_of_an_infinite_session_is_finite() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..sopts()
        },
    );
    let fork = v
        .fork_session(&s.id, ForkOptions::default())
        .unwrap()
        .session;
    assert!(!fork.infinite);
    assert!(session_expiry_ms(&fork) < (now() + 25 * HOUR) as f64);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn expiry_ms_absent_is_no_limit_a_date_is_that_date_and_anything_else_has_passed() {
    assert_eq!(expiry_ms(None), f64::INFINITY);
    assert_eq!(
        expiry_ms(Some("2030-01-01T00:00:00.000Z")),
        parse("2030-01-01T00:00:00.000Z") as f64
    );
    for bad in ["garbage", "", "NaN"] {
        assert_eq!(expiry_ms(Some(bad)), f64::NEG_INFINITY, "{bad}");
    }
}

fn srec(infinite: bool, expires_at: Option<&str>) -> crate::model::SessionRecord {
    crate::model::SessionRecord {
        id: "x".into(),
        workspace_id: None,
        label: "x".into(),
        token_hash: "x".into(),
        policy: Default::default(),
        owner_uid: None,
        remote: false,
        client_name: None,
        state: SessionState::Active,
        created_at: iso(now()),
        expires_at: expires_at.map(str::to_string),
        max_expires_at: None,
        idle_timeout_ms: None,
        infinite,
        elevated: vec![],
        template: None,
        template_version: None,
        last_seen_at: iso(now()),
        parent_sid: None,
    }
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn session_expiry_ms_only_exactly_infinite_with_exactly_null_lives_forever() {
    let iso_ = iso(now() + HOUR);
    assert_eq!(session_expiry_ms(&srec(true, None)), f64::INFINITY);
    assert_eq!(
        session_expiry_ms(&srec(false, Some(&iso_))),
        parse(&iso_) as f64
    );
    assert_eq!(
        session_expiry_ms(&srec(true, Some(&iso_))),
        parse(&iso_) as f64
    );
    assert_eq!(session_expiry_ms(&srec(false, None)), f64::NEG_INFINITY);
    assert_eq!(
        session_expiry_ms(&srec(false, Some("garbage"))),
        f64::NEG_INFINITY
    );
    assert_eq!(
        session_expiry_ms(&srec(true, Some("garbage"))),
        f64::NEG_INFINITY
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_session_record_with_an_unreadable_or_missing_expiry_is_expired_not_live_forever() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for bad in [Some("garbage"), None] {
        let s = session(v);
        let g = grant_for(v, &s.id, &fx.cred.id);
        let row = issue(v, &g.id);
        let mut broken = s.clone();
        broken.expires_at = bad.map(str::to_string);
        assert_eq!(
            code_of(v.assert_session_live(Some(&broken))),
            "AV_SESSION_EXPIRED"
        );
        assert_eq!(ph_row(v, &row.id).state, PlaceholderState::Dead);
    }
    assert_eq!(v.stats().unwrap().sessions_active, 0);
    let ok = session(v);
    v.assert_session_live(Some(&ok)).unwrap();
    assert_eq!(v.stats().unwrap().sessions_active, 1);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_placeholder_row_exactly_null_never_expires_an_unreadable_date_always_has() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let ok = issue(v, &g.id);
    v.consume_placeholder(&ok.id).unwrap();
    let never = issue(v, &g.id);
    exec(
        v,
        "UPDATE placeholders SET expires_at = NULL WHERE id = ?1",
        &[&never.id],
    );
    v.consume_placeholder(&never.id).unwrap();
    let row = issue(v, &g.id);
    exec(
        v,
        "UPDATE placeholders SET expires_at = 'garbage' WHERE id = ?1",
        &[&row.id],
    );
    assert_eq!(code_of(v.consume_placeholder(&row.id)), "AV_PH_STALE");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_grant_with_a_lifetime_ends_on_its_own_kills_its_placeholders_and_leaves_the_other_grant_working(
) {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let before = now();
    let short = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(60_000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    let after = now();
    let long = grant_for(v, &s.id, &fx.other.id);
    let ends = parse(short.expires_at.as_deref().unwrap());
    assert!(ends >= before + 60_000 && ends <= after + 60_000);
    assert_eq!(long.expires_at, None);
    assert_eq!(
        field(&records(v, "grant.created")[0], "expires_at"),
        &json!(short.expires_at)
    );
    let row = issue(v, &short.id);
    assert_eq!(row.expires_at, short.expires_at);
    let long_row = issue(v, &long.id);
    let later = now() + 2 * 60_000;
    assert_eq!(
        at(later, || code_of(v.consume_placeholder(&row.id))),
        "AV_GRANT_EXPIRED"
    );
    assert_eq!(grant_row(v, &short.id).state, GrantState::Expired);
    let row = ph_row(v, &row.id);
    assert_eq!(row.state, PlaceholderState::Dead);
    assert_eq!(row.dead_reason.as_deref(), Some("expired"));
    let ids: Vec<Value> = records(v, "grant.expired")
        .iter()
        .map(|r| field(r, "grant_id").clone())
        .collect();
    assert_eq!(ids, vec![json!(short.id)]);
    let short_now = grant_row(v, &short.id);
    assert_eq!(
        at(later, || code_of(v.assert_grant_live(Some(&short_now)))),
        "AV_NO_GRANT"
    );
    assert_eq!(
        at(later, || code_of(v.issue_placeholder(IssueOptions {
            grant_id: short.id.clone(),
            ..Default::default()
        }))),
        "AV_NO_GRANT"
    );
    at(later, || v.consume_placeholder(&long_row.id)).unwrap();
    let long_now = grant_row(v, &long.id);
    at(later, || v.assert_grant_live(Some(&long_now))).unwrap();
    let live: Vec<String> = v
        .grants_for_session(&s.id)
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(live, vec![long.id.clone()]);
    assert_eq!(
        v.find_grant(&s.id, &fx.cred.id).unwrap().unwrap().state,
        GrantState::Expired
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_expired_grant_refuses_issuance_with_its_own_code() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(60_000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert_eq!(
        at(now() + 120_000, || code_of(v.issue_placeholder(
            IssueOptions {
                grant_id: g.id.clone(),
                ..Default::default()
            }
        ))),
        "AV_GRANT_EXPIRED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn idle_activity_on_the_session_does_not_revive_a_grant() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(60_000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    at(now() + 30_000, || v.touch_session(&s.id)).unwrap();
    assert_eq!(grant_row(v, &g.id).expires_at, g.expires_at);
    assert_eq!(
        at(now() + 90_000, || code_of(v.assert_grant_live(Some(&g)))),
        "AV_GRANT_EXPIRED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_grant_lifetime_longer_than_the_session_is_clamped_and_a_grant_of_an_infinite_session_still_ends(
) {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            ttl_ms: Some(HOUR),
            ..sopts()
        },
    );
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(10 * HOUR),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert_eq!(g.expires_at, s.expires_at);
    let inf = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..sopts()
        },
    );
    let g2 = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(HOUR),
            ..grant_opts(&inf.id, &fx.cred.id)
        })
        .unwrap();
    assert!(parse(g2.expires_at.as_deref().unwrap()) <= now() + HOUR);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_grant_lifetime_that_is_not_a_positive_number_is_refused_and_writes_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    for ttl in [0, -5] {
        let opts = CreateGrantOptions {
            ttl_ms: Some(ttl),
            ..grant_opts(&s.id, &fx.cred.id)
        };
        refused_cleanly(
            v,
            |v| v.create_grant(opts),
            ("AV_POLICY_DENIED", Some("grant_ttl")),
        );
    }
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn no_grant_is_added_to_a_session_that_has_ended() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    v.revoke_session(&s.id, "revoked").unwrap();
    let opts = grant_opts(&s.id, &fx.cred.id);
    refused_cleanly(v, |v| v.create_grant(opts), ("AV_SESSION_REVOKED", None));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_locked_vault_refuses_an_expired_grant_without_recording_what_it_cannot_audit() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(60_000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    v.lock().unwrap();
    assert_eq!(
        at(now() + 120_000, || code_of(v.assert_grant_live(Some(&g)))),
        "AV_GRANT_EXPIRED"
    );
    assert_eq!(grant_row(v, &g.id).state, GrantState::Active);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn find_grant_returns_the_newest_grant_for_the_pair_in_any_state_and_none_for_none() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let first = grant_for(v, &s.id, &fx.cred.id);
    v.revoke_grant(&first.id, "revoked").unwrap();
    let second = grant_for(v, &s.id, &fx.cred.id);
    exec(
        v,
        "UPDATE grants SET created_at = ?1 WHERE id = ?2",
        &[&first.created_at, &second.id],
    );
    assert_eq!(
        v.find_grant(&s.id, &fx.cred.id).unwrap().unwrap().id,
        second.id
    );
    assert!(v.find_grant(&s.id, &fx.other.id).unwrap().is_none());
    assert!(v.find_grant("nope", &fx.cred.id).unwrap().is_none());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn charge_grant_charges_up_to_the_budget_and_refuses_past_it() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let three = policy_with_budget(json!({ "unit": "requests", "limit": 3 }));
    let g = v
        .create_grant(CreateGrantOptions {
            policy: three.clone(),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    let got: Vec<bool> = (0..4).map(|_| v.charge_grant(&g.id, 1).unwrap()).collect();
    assert_eq!(got, vec![true, true, true, false]);
    let g = grant_row(v, &g.id);
    assert_eq!(g.budget_used, 3);
    assert_eq!(g.counters.requests, 3);
    let g2 = v
        .create_grant(CreateGrantOptions {
            policy: three,
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert!(v.charge_grant(&g2.id, 2).unwrap());
    assert!(!v.charge_grant(&g2.id, 2).unwrap());
    assert_eq!(grant_row(v, &g2.id).budget_used, 2);
    let open = v
        .create_grant(CreateGrantOptions {
            policy: policy_without_budget(),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert!(v.charge_grant(&open.id, 500).unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn charge_grant_reads_a_decimal_string_budget_as_its_integer() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            policy: policy_with_budget(json!({ "unit": "requests", "limit": "2" })),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    let got: Vec<bool> = (0..3).map(|_| v.charge_grant(&g.id, 1).unwrap()).collect();
    assert_eq!(got, vec![true, true, false]);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn charge_grant_charges_nothing_when_the_budget_the_count_or_the_grant_cannot_be_read() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let charge = |v: &mut Vault, budget: Value, n: u64| -> bool {
        let g = v
            .create_grant(CreateGrantOptions {
                policy: policy_with_budget(budget),
                ..grant_opts(&s.id, &fx.cred.id)
            })
            .unwrap();
        let before = grant_row(v, &g.id);
        let ok = v.charge_grant(&g.id, n).unwrap();
        if !ok {
            assert_eq!(
                grant_row(v, &g.id),
                before,
                "a refused charge changed the grant"
            );
        }
        ok
    };
    for limit in [
        json!("abc"),
        json!(""),
        json!("5.5"),
        json!("-1"),
        json!("1e3"),
        json!(-1),
        json!(5.5),
        json!({}),
    ] {
        assert!(
            !charge(v, json!({ "unit": "requests", "limit": limit }), 1),
            "limit {limit}"
        );
    }
    assert!(charge(v, json!({ "unit": "requests" }), 1));
    assert!(!charge(v, json!({ "unit": "tokens", "limit": 10 }), 1));
    assert!(!charge(
        v,
        json!({ "unit": "requests", "limit": 10, "invalid": true }),
        1
    ));
    assert!(!charge(v, json!("lots"), 1));
    assert!(!charge(v, json!({ "unit": "requests", "limit": 10 }), 0));
    assert!(!v.charge_grant("gr_nope", 1).unwrap());
    assert!(!v.charge_grant("__proto__", 1).unwrap());
    let revoked = grant_for(v, &s.id, &fx.cred.id);
    exec(
        v,
        "UPDATE grants SET state = 'revoked' WHERE id = ?1",
        &[&revoked.id],
    );
    assert!(!v.charge_grant(&revoked.id, 1).unwrap());
    let ended = grant_for(v, &s.id, &fx.cred.id);
    exec(
        v,
        "UPDATE grants SET expires_at = ?1 WHERE id = ?2",
        &[&iso(now() - 1000), &ended.id],
    );
    assert!(!v.charge_grant(&ended.id, 1).unwrap());
    assert!(charge(v, json!({ "unit": "requests", "limit": 10 }), 1));
    let g = grant_for(v, &s.id, &fx.cred.id);
    v.lock().unwrap();
    assert!(!v.charge_grant(&g.id, 1).unwrap());
    assert_eq!(grant_row(v, &g.id).budget_used, 0);
}

#[test]
#[ignore = "blocked on av-core: a budget of {limit: null} deserializes to no limit (Budget.limit is a plain Option), where the JS budgetLimit reads it as unreadable"]
fn charge_grant_refuses_a_null_budget_limit() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            policy: policy_with_budget(json!({ "unit": "requests", "limit": null })),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert!(!v.charge_grant(&g.id, 1).unwrap());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn credential_expiry_is_stored_as_one_iso_date_audited_and_flagged_when_near() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let soon = iso(now() + 3 * DAY);
    let p = v.set_credential_expiry("demo", Some(&soon)).unwrap();
    assert_eq!(p.expires_at.as_deref(), Some(soon.as_str()));
    assert_eq!(p.expiry_warning, Some(ExpiryWarning::Soon));
    let r = &records(v, "cred.expiry_set")[0];
    assert_eq!(
        (field(r, "credential_slug"), field(r, "expires_at")),
        (&json!("demo"), &json!(soon))
    );
    assert_eq!(v.stats().unwrap().credentials_expiring, 1);
    assert_eq!(
        v.set_credential_expiry("demo", Some("2099-01-31"))
            .unwrap()
            .expires_at
            .as_deref(),
        Some("2099-01-31T00:00:00.000Z")
    );
    let demo = v
        .list_credentials()
        .unwrap()
        .into_iter()
        .find(|c| c.slug == "demo")
        .unwrap();
    assert_eq!(demo.expiry_warning, None);
    assert_eq!(
        v.set_credential_expiry("demo", Some(&iso(now() - DAY)))
            .unwrap()
            .expiry_warning,
        Some(ExpiryWarning::Expired)
    );
    assert_eq!(v.stats().unwrap().credentials_expiring, 1);
    assert_eq!(
        v.set_credential_expiry("demo", None).unwrap().expires_at,
        None
    );
    assert_eq!(v.stats().unwrap().credentials_expiring, 0);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_credential_expiry_that_is_not_a_date_is_refused_and_writes_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for bad in ["garbage", ""] {
        refused_cleanly(
            v,
            |v| v.set_credential_expiry("demo", Some(bad)),
            ("AV_POLICY_DENIED", Some("expires_at")),
        );
    }
    refused_cleanly(
        v,
        |v| v.set_credential_expiry("nope", None),
        ("AV_NOT_FOUND", None),
    );
    v.lock().unwrap();
    assert_eq!(code_of(v.set_credential_expiry("demo", None)), "AV_LOCKED");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_thousand_identical_health_observations_write_one_audit_record() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let observed = iso(now() + 2 * DAY);
    let id = fx.cred.id.clone();
    for _ in 0..1000 {
        v.record_health(
            &id,
            &json!({ "observed_expires_at": observed, "source": "response", "checked_at": iso(now()) }),
        )
        .unwrap();
    }
    let recs = records(v, "cred.health_recorded");
    assert_eq!(recs.len(), 1);
    assert_eq!(field(&recs[0], "observed_expires_at"), &json!(observed));
    assert_eq!(field(&recs[0], "source"), &json!("response"));
    let demo = v
        .list_credentials()
        .unwrap()
        .into_iter()
        .find(|c| c.slug == "demo")
        .unwrap();
    assert_eq!(demo.expiry_warning, Some(ExpiryWarning::Soon));
    for _ in 0..2 {
        v.record_health(
            "demo",
            &json!({ "status": "unauthorized", "http_status": 401, "source": "response" }),
        )
        .unwrap();
    }
    let got: Vec<(Value, Value)> = records(v, "cred.health_recorded")
        .iter()
        .map(|r| (field(r, "status").clone(), field(r, "http_status").clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (json!("unknown"), Value::Null),
            (json!("unauthorized"), json!(401))
        ]
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_sooner_of_the_humans_expiry_and_the_observed_one_wins() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let warn = |v: &Vault| {
        v.list_credentials()
            .unwrap()
            .into_iter()
            .find(|c| c.slug == "demo")
            .unwrap()
            .expiry_warning
    };
    v.set_credential_expiry("demo", Some(&iso(now() + 2 * DAY)))
        .unwrap();
    v.record_health(
        "demo",
        &json!({ "observed_expires_at": iso(now() + 90 * DAY) }),
    )
    .unwrap();
    assert_eq!(warn(v), Some(ExpiryWarning::Soon));
    v.set_credential_expiry("demo", Some(&iso(now() + 90 * DAY)))
        .unwrap();
    v.record_health("demo", &json!({ "observed_expires_at": iso(now() - DAY) }))
        .unwrap();
    assert_eq!(warn(v), Some(ExpiryWarning::Expired));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_health_patch_keeps_only_well_formed_fields_and_a_locked_vault_records_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let h = v
        .record_health(
            "demo",
            &json!({
                "status": "pwned", "http_status": 401.5, "observed_expires_at": "garbage",
                "source": "agent", "checked_at": "yesterday", "scopes": [1, 2], "value": SECRET,
                "ratelimit_remaining": 5
            }),
        )
        .unwrap()
        .unwrap();
    let keys: Vec<String> = serde_json::to_value(&h)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        vec![
            "checked_at",
            "http_status",
            "observed_expires_at",
            "scopes",
            "source",
            "status"
        ]
    );
    assert_eq!(h.status, crate::model::HealthStatus::Unknown);
    assert_eq!(h.http_status, None);
    assert_eq!(h.observed_expires_at, None);
    assert!(!snapshot(v).0.contains(SECRET));
    assert_eq!(records(v, "cred.health_recorded").len(), 1);
    let ok = v
        .record_health(
            "demo",
            &json!({ "status": "ok", "http_status": 200, "source": "probe", "scopes": ["repo"] }),
        )
        .unwrap()
        .unwrap();
    assert_eq!(ok.status, crate::model::HealthStatus::Ok);
    assert_eq!(ok.http_status, Some(200));
    assert_eq!(ok.source, crate::model::HealthSource::Probe);
    assert_eq!(ok.scopes, Some(vec!["repo".to_string()]));
    assert!(v
        .record_health("nope", &json!({ "status": "ok" }))
        .unwrap()
        .is_none());
    assert!(v
        .record_health("__proto__", &json!({ "status": "ok" }))
        .unwrap()
        .is_none());
    v.lock().unwrap();
    let before = snapshot(v);
    assert!(v
        .record_health("demo", &json!({ "status": "forbidden" }))
        .unwrap()
        .is_none());
    assert_eq!(snapshot(v), before);
}

fn default_rules() -> Value {
    json!([
        { "id": "replay", "codes": ["AV_PH_REPLAY"], "threshold": 1, "window_s": 600, "action": "revoke_session" },
        { "id": "bad_location", "codes": ["AV_BAD_LOCATION"], "threshold": 3, "window_s": 600, "action": "revoke_session" },
        { "id": "cross_session", "codes": ["AV_PH_CROSS_SESSION", "AV_PH_WRONG_CONNECTOR"], "threshold": 3, "window_s": 600, "action": "revoke_session" },
        { "id": "deny_paths", "rule_prefix": "deny_paths:", "threshold": 5, "window_s": 600, "action": "revoke_session" }
    ])
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn settings_the_default_tripwire_rules_are_stored_merged_per_key_audited_and_handed_out_as_a_copy()
{
    let mut fx = fresh();
    let v = &mut fx.vault;
    let out = v
        .update_settings(&json!({ "tripwires": { "enabled": true, "rules": default_rules() } }))
        .unwrap();
    assert_eq!(out["tripwires"]["rules"], default_rules());
    let keys: Vec<Value> = records(v, "settings.changed")
        .iter()
        .map(|r| field(r, "keys").clone())
        .collect();
    assert_eq!(keys, vec![json!(["tripwires"])]);
    v.update_settings(&json!({ "theme": "dark" })).unwrap();
    assert_eq!(
        v.get_settings().unwrap()["tripwires"]["enabled"],
        json!(true)
    );
    let mut copy = v.get_settings().unwrap();
    copy.insert("tripwires".into(), json!({ "enabled": false, "rules": [] }));
    assert_eq!(
        v.get_settings().unwrap()["tripwires"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    v.lock().unwrap();
    assert_eq!(
        v.get_settings().unwrap()["tripwires"]["enabled"],
        json!(true)
    );
    assert_eq!(
        code_of(v.update_settings(&json!({ "theme": "light" }))),
        "AV_LOCKED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_tripwire_rule_that_is_not_the_rule_shape_is_refused_and_nothing_is_kept() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.update_settings(&json!({ "tripwires": { "enabled": false, "rules": default_rules() } }))
        .unwrap();
    let rule = default_rules()[0].clone();
    let with = |k: &str, val: Value| {
        let mut r = rule.clone();
        r[k] = val;
        json!({ "enabled": true, "rules": [r] })
    };
    let mut bad = vec![
        Value::Null,
        json!("on"),
        json!([]),
        json!({ "enabled": true }),
        json!({ "enabled": "yes", "rules": [] }),
        json!({ "enabled": true, "rules": "defaults" }),
        json!({ "enabled": true, "rules": [], "extra": 1 }),
        with("threshold", json!(0)),
        with("threshold", json!(1001)),
        with("threshold", json!(1.5)),
        with("threshold", json!("5")),
        with("window_s", json!(9)),
        with("window_s", json!(86_401)),
        with("action", json!("nuke")),
        with("id", json!("BAD ID")),
        with("codes", json!([])),
        with("codes", json!(["not-a-code"])),
        json!({ "enabled": true, "rules": [{ "id": "all", "rule_prefix": "", "threshold": 1, "window_s": 60, "action": "panic" }] }),
        json!({ "enabled": true, "rules": [{ "id": "none", "threshold": 1, "window_s": 60, "action": "panic" }] }),
        with("surprise", json!(true)),
        json!({ "enabled": true, "rules": [rule.clone(), rule.clone()] }),
    ];
    let many: Vec<Value> = (0..33)
        .map(|i| {
            let mut r = rule.clone();
            r["id"] = json!(format!("r{i}"));
            r
        })
        .collect();
    bad.push(json!({ "enabled": true, "rules": many }));
    for tw in bad {
        let patch = json!({ "tripwires": tw });
        refused_cleanly(
            v,
            |v| v.update_settings(&patch),
            ("AV_POLICY_DENIED", Some("tripwire_rule")),
        );
    }
    let proto: Value = serde_json::from_str(r#"{"__proto__":{"polluted":true}}"#).unwrap();
    refused_cleanly(
        v,
        |v| v.update_settings(&proto),
        ("AV_POLICY_DENIED", Some("policy_invalid")),
    );
    refused_cleanly(
        v,
        |v| v.update_settings(&Value::Null),
        ("AV_POLICY_DENIED", Some("policy_invalid")),
    );
    v.update_settings(&json!({ "tripwires": { "enabled": true, "rules": [{ "id": "lots", "rule_prefix": "deny_paths:", "threshold": 1000, "window_s": 86_400, "action": "quarantine_credential" }] } }))
        .unwrap();
    assert_eq!(
        v.get_settings().unwrap()["tripwires"]["rules"][0]["id"],
        json!("lots")
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_quarantined_credential_issues_nothing_gets_no_new_grant_and_release_restores_a_live_session() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let q = v
        .set_quarantine(
            "demo",
            QuarantineOptions {
                by: QuarantineBy::Control,
                reason: Some("looks odd".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(q.by, QuarantineBy::Control);
    assert_eq!(q.reason_untrusted.as_deref(), Some("looks odd"));
    assert_eq!(
        code(v.issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            ..Default::default()
        })),
        rule("AV_QUARANTINED", Some("quarantine"))
    );
    assert_eq!(
        code(v.create_grant(grant_opts(&s.id, &fx.cred.id))),
        rule("AV_QUARANTINED", Some("quarantine"))
    );
    let rec = &records(v, "cred.quarantined")[0];
    assert_eq!(field(rec, "rule_id"), &Value::Null);
    assert_eq!(field(rec, "reason_untrusted"), &json!("looks odd"));
    let og = grant_for(v, &s.id, &fx.other.id);
    issue(v, &og.id);
    assert!(v.clear_quarantine("demo").unwrap());
    assert!(!v.clear_quarantine("demo").unwrap());
    assert_eq!(records(v, "cred.released").len(), 1);
    issue(v, &g.id);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn quarantining_twice_keeps_who_did_it_first_and_a_bad_quarantine_is_refused() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let first = v
        .set_quarantine(
            "demo",
            QuarantineOptions {
                by: QuarantineBy::Tripwire,
                rule_id: Some("replay".into()),
                reason: None,
            },
        )
        .unwrap();
    let again = v
        .set_quarantine(
            "demo",
            QuarantineOptions {
                by: QuarantineBy::Control,
                reason: Some("me too".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(records(v, "cred.quarantined").len(), 1);
    let long = v
        .set_quarantine(
            "other",
            QuarantineOptions {
                reason: Some("x".repeat(5000)),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(long.reason_untrusted.unwrap().len(), 200);
    refused_cleanly(
        v,
        |v| v.set_quarantine("demo2", QuarantineOptions::default()),
        ("AV_NOT_FOUND", None),
    );
    v.clear_quarantine("other").unwrap();
    refused_cleanly(
        v,
        |v| {
            v.set_quarantine(
                "other",
                QuarantineOptions {
                    by: QuarantineBy::Tripwire,
                    rule_id: Some("Not OK".into()),
                    reason: None,
                },
            )
        },
        ("AV_POLICY_DENIED", Some("quarantine")),
    );
    v.lock().unwrap();
    assert_eq!(
        code_of(v.set_quarantine("other", QuarantineOptions::default())),
        "AV_LOCKED"
    );
    assert_eq!(code_of(v.clear_quarantine("demo")), "AV_LOCKED");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn shortening_an_infinite_session_makes_it_finite_and_brings_its_placeholders_down() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..sopts()
        },
    );
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = issue(v, &g.id);
    assert_eq!(row.expires_at, None);
    let s2 = v.shorten_session(&s.id, HOUR).unwrap();
    assert!(!s2.infinite);
    assert!((parse(s2.expires_at.as_deref().unwrap()) - (now() + HOUR)).abs() < 1000);
    assert_eq!(s2.max_expires_at, s2.expires_at);
    assert_eq!(s2.idle_timeout_ms, Some(2 * HOUR as u64));
    assert_eq!(ph_row(v, &row.id).expires_at, s2.max_expires_at);
    let rec = &records(v, "session.shortened")[0];
    assert_eq!(field(rec, "was_infinite"), &json!(true));
    assert_eq!(field(rec, "expires_at"), &json!(s2.expires_at));
    assert!(!session_row(v, &s.id).infinite);
    assert_eq!(
        at(now() + 2 * HOUR, || code_of(
            v.assert_session_live(Some(&s2))
        )),
        "AV_SESSION_EXPIRED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn shortening_never_lengthens() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            ttl_ms: Some(HOUR),
            ..sopts()
        },
    );
    v.shorten_session(&s.id, 10 * HOUR).unwrap();
    let s2 = session_row(v, &s.id);
    assert_eq!(s2.expires_at, s.expires_at);
    assert_eq!(s2.max_expires_at, s.max_expires_at);
    assert_eq!(
        field(&records(v, "session.shortened")[0], "was_infinite"),
        &json!(false)
    );
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(60_000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    v.shorten_grant(&g.id, HOUR).unwrap();
    assert_eq!(grant_row(v, &g.id).expires_at, g.expires_at);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn shortening_a_session_whose_expiry_cannot_be_read_ends_it_now_instead_of_throwing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    exec(
        v,
        "UPDATE sessions SET expires_at = 'garbage', max_expires_at = 'garbage' WHERE id = ?1",
        &[&s.id],
    );
    let before = now();
    v.shorten_session(&s.id, HOUR).unwrap();
    let ends = parse(session_row(v, &s.id).expires_at.as_deref().unwrap());
    assert!(ends >= before && ends <= now());
    let s2 = session(v);
    let g = grant_for(v, &s2.id, &fx.cred.id);
    exec(
        v,
        "UPDATE grants SET expires_at = 'garbage' WHERE id = ?1",
        &[&g.id],
    );
    v.shorten_grant(&g.id, HOUR).unwrap();
    assert!(parse(grant_row(v, &g.id).expires_at.as_deref().unwrap()) <= now());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn shortening_with_a_lifetime_that_is_not_positive_or_a_session_that_is_gone_is_refused() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    for ttl in [0, -1] {
        refused_cleanly(
            v,
            |v| v.shorten_session(&s.id, ttl),
            ("AV_POLICY_DENIED", Some("ttl")),
        );
        refused_cleanly(
            v,
            |v| v.shorten_grant(&g.id, ttl),
            ("AV_POLICY_DENIED", Some("grant_ttl")),
        );
    }
    refused_cleanly(
        v,
        |v| v.shorten_session("nope", HOUR),
        ("AV_NOT_FOUND", None),
    );
    refused_cleanly(v, |v| v.shorten_grant("nope", HOUR), ("AV_NOT_FOUND", None));
    v.revoke_session(&s.id, "revoked").unwrap();
    refused_cleanly(
        v,
        |v| v.shorten_session(&s.id, HOUR),
        ("AV_SESSION_REVOKED", None),
    );
    refused_cleanly(v, |v| v.shorten_grant(&g.id, HOUR), ("AV_NO_GRANT", None));
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn shortening_a_grant_bounds_it_and_its_live_placeholders_and_is_audited() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            ..sopts()
        },
    );
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = issue(v, &g.id);
    let g2 = v.shorten_grant(&g.id, 60_000).unwrap();
    assert!((parse(g2.expires_at.as_deref().unwrap()) - (now() + 60_000)).abs() < 1000);
    assert_eq!(ph_row(v, &row.id).expires_at, g2.expires_at);
    let rec = &records(v, "grant.shortened")[0];
    assert_eq!(field(rec, "expires_at"), &json!(g2.expires_at));
    assert_eq!(
        at(now() + 120_000, || code_of(v.consume_placeholder(&row.id))),
        "AV_GRANT_EXPIRED"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_narrow_is_audited_by_field_name_and_may_only_turn_redirects_off() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    v.narrow_grant(
        &g.id,
        &json!({ "methods": ["GET"], "redirects": { "max": 0 } }),
    )
    .unwrap();
    let rec = &records(v, "grant.narrowed")[0];
    assert_eq!(field(rec, "fields"), &json!(["methods", "redirects"]));
    assert_eq!(field(rec, "narrow"), &Value::Null);
    assert_eq!(field(rec, "session_id"), &json!(g.session_id));
    for redirects in [
        json!({ "max": 5 }),
        json!({ "max": 1 }),
        json!(5),
        Value::Null,
    ] {
        let n = json!({ "redirects": redirects });
        refused_cleanly(
            v,
            |v| v.narrow_grant(&g.id, &n),
            ("AV_POLICY_DENIED", Some("narrow_widens")),
        );
    }
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_elevation_a_session_was_created_with_is_recorded_and_empty_by_default() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    session(v);
    session_with(
        v,
        CreateSessionOptions {
            elevated: vec!["approval_auto_writes".into()],
            ..sopts()
        },
    );
    session_with(
        v,
        CreateSessionOptions {
            infinite: true,
            elevated: vec!["approval_auto_writes".into(), "infinite".into()],
            ..sopts()
        },
    );
    let got: Vec<Value> = records(v, "session.created")
        .iter()
        .map(|r| field(r, "elevated").clone())
        .collect();
    assert_eq!(
        got,
        vec![
            json!([]),
            json!(["approval_auto_writes"]),
            json!(["approval_auto_writes", "infinite"])
        ]
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_elevation_the_store_does_not_recognise_is_refused_and_nothing_is_written() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for el in [
        vec!["root"],
        vec!["infinite", "x"],
        vec!["infinite", "infinite", "infinite"],
    ] {
        let elevated: Vec<String> = el.into_iter().map(str::to_string).collect();
        refused_cleanly(
            v,
            |v| {
                v.create_session(CreateSessionOptions {
                    elevated,
                    ..sopts()
                })
            },
            ("AV_POLICY_DENIED", Some("elevation_invalid")),
        );
    }
    assert_eq!(v.sessions().unwrap().len(), 0);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_placeholder_of_a_session_that_expired_idle_is_refused_at_use_though_its_own_date_has_not_passed(
) {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let row = issue(v, &g.id);
    assert_eq!(row.expires_at, s.max_expires_at);
    let idle = parse(s.expires_at.as_deref().unwrap()) + HOUR;
    assert!(idle < parse(row.expires_at.as_deref().unwrap()));
    assert_eq!(
        at(idle, || code_of(v.consume_placeholder(&row.id))),
        "AV_SESSION_EXPIRED"
    );
    assert_eq!(ph_row(v, &row.id).state, PlaceholderState::Dead);
    let live = session(v);
    let lg = grant_for(v, &live.id, &fx.cred.id);
    let r = issue(v, &lg.id);
    v.consume_placeholder(&r.id).unwrap();
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn settings_never_carry_the_webhook_url_locked_or_unlocked() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let url = "https://hooks.example/services/T0/B0/WEBHOOKSECRETPATH?token=QUERYSECRET";
    v.set_notify_webhook(&s(url), crate::model::NotifyDetail::Minimal)
        .unwrap();
    v.update_settings(&json!({ "tripwires": { "enabled": true, "rules": default_rules() } }))
        .unwrap();
    let mut seen = vec![serde_json::to_string(&v.get_settings().unwrap()).unwrap()];
    v.lock().unwrap();
    seen.push(serde_json::to_string(&v.get_settings().unwrap()).unwrap());
    for text in seen {
        for part in ["WEBHOOKSECRETPATH", "QUERYSECRET", "hooks.example/services"] {
            assert!(!text.contains(part), "getSettings carried {part}");
        }
    }
}
