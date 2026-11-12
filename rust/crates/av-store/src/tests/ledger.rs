//! Ports the store-level parts of `test/security/fix-control-ledger.test.js`.
//! The JS drives these through MCP and the gateway; the ledger rules they
//! check are the vault's, exercised here directly. The wire half is the
//! daemon's and conformance's.

use serde_json::json;

use super::helpers::*;
use crate::model::PlaceholderState;
use crate::vault::*;

fn setup() -> (Fx, String, String) {
    let mut fx = fresh();
    let s = session(&mut fx.vault);
    let g = grant_for(&mut fx.vault, &s.id, &fx.cred.id);
    (fx, s.id, g.id)
}

fn live(v: &Vault, sid: &str, gid: &str) -> usize {
    v.list_placeholders(Some(sid))
        .unwrap()
        .iter()
        .filter(|p| p.state == PlaceholderState::Active && p.grant_id == gid)
        .count()
}

fn set_pp(v: &Vault, gid: &str, pp: serde_json::Value) {
    exec(
        v,
        "UPDATE grants SET policy = json_set(policy, '$.placeholder_policy', json(?1)) WHERE id = ?2",
        &[&pp.to_string(), &gid],
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn asking_for_a_placeholder_and_using_it_over_and_over_stays_within_max_active() {
    let (mut fx, sid, gid) = setup();
    for _ in 0..12 {
        let row = issue(&mut fx.vault, &gid);
        fx.vault.consume_placeholder(&row.id).unwrap();
    }
    let n = live(&fx.vault, &sid, &gid);
    assert!(n <= 8, "{n} live placeholders on a grant with max_active 8");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_max_active_that_is_not_a_number_is_not_an_unbounded_ledger() {
    let (mut fx, sid, gid) = setup();
    set_pp(&fx.vault, &gid, json!({ "max_active": "lots" }));
    for _ in 0..12 {
        issue(&mut fx.vault, &gid);
    }
    assert!(live(&fx.vault, &sid, &gid) <= 8);
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_placeholder_in_use_keeps_working_while_fewer_than_max_active_are_live() {
    let (mut fx, _sid, gid) = setup();
    let kept = issue(&mut fx.vault, &gid);
    fx.vault.consume_placeholder(&kept.id).unwrap();
    for _ in 0..6 {
        issue(&mut fx.vault, &gid);
    }
    for i in 0..5 {
        fx.vault
            .consume_placeholder(&kept.id)
            .unwrap_or_else(|e| panic!("reuse {i}: {e}"));
    }
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_rotated_placeholder_says_to_ask_again_and_the_newest_still_works() {
    let (mut fx, _sid, gid) = setup();
    let first = issue(&mut fx.vault, &gid);
    fx.vault.consume_placeholder(&first.id).unwrap();
    let mut newest = first.clone();
    for _ in 0..8 {
        newest = issue(&mut fx.vault, &gid);
        fx.vault.consume_placeholder(&newest.id).unwrap();
    }
    assert_eq!(
        code_of(fx.vault.consume_placeholder(&first.id)),
        "AV_PH_STALE"
    );
    fx.vault.consume_placeholder(&newest.id).unwrap();
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_explicit_placeholder_ttl_cannot_outlast_the_grants() {
    let (mut fx, _sid, gid) = setup();
    set_pp(&fx.vault, &gid, json!({ "ttl": 1 }));
    let before = now();
    let row = fx
        .vault
        .issue_placeholder(IssueOptions {
            grant_id: gid.clone(),
            ttl_ms: Some(3_600_000),
            ..Default::default()
        })
        .unwrap()
        .row;
    let lasts = parse(row.expires_at.as_deref().unwrap()) - before;
    assert!(lasts <= 2000, "the row lives {lasts} ms");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn an_explicit_placeholder_ttl_shorter_than_the_grants_is_kept() {
    let (mut fx, _sid, gid) = setup();
    set_pp(&fx.vault, &gid, json!({ "ttl": 3600 }));
    let before = now();
    let row = fx
        .vault
        .issue_placeholder(IssueOptions {
            grant_id: gid.clone(),
            ttl_ms: Some(5000),
            ..Default::default()
        })
        .unwrap()
        .row;
    let lasts = parse(row.expires_at.as_deref().unwrap()) - before;
    assert!((4000..=6000).contains(&lasts), "{lasts}");
    let plain = issue(&mut fx.vault, &gid);
    let span = parse(plain.expires_at.as_deref().unwrap()) - before;
    assert!(span > 3_500_000 && span <= 3_601_000, "{span}");
}
