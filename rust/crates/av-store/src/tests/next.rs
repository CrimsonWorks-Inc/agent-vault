//! Every `next` the JS store sends, compared to its shape there
//! (`src/store/vault.js`): an agent acts on these, so they are frozen.

use serde_json::{json, Value};

use super::helpers::*;
use crate::model::FactorClass;
use crate::vault::*;

fn next_of<T>(r: crate::error::Result<T>) -> Value {
    match r {
        Err(e) => e
            .as_vault()
            .and_then(|v| v.extra.next.clone())
            .unwrap_or(Value::Null),
        Ok(_) => panic!("not refused"),
    }
}

fn ph_next() -> Value {
    json!({ "cli": ["agent-vault ph next <cred>"], "mcp": { "tool": "vault_get_placeholder" } })
}

#[test]
fn a_dead_expired_or_exhausted_placeholder_says_where_to_get_another() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let burned = issue(v, &g.id);
    v.burn_placeholder(&burned.id, "burned").unwrap();
    assert_eq!(next_of(v.consume_placeholder(&burned.id)), ph_next());
    let once = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            uses: Some(1),
            ..Default::default()
        })
        .unwrap()
        .row;
    v.consume_placeholder(&once.id).unwrap();
    assert_eq!(next_of(v.consume_placeholder(&once.id)), ph_next());
    let short = v
        .issue_placeholder(IssueOptions {
            grant_id: g.id.clone(),
            ttl_ms: Some(100),
            ..Default::default()
        })
        .unwrap()
        .row;
    assert_eq!(
        at(now() + 1000, || next_of(v.consume_placeholder(&short.id))),
        ph_next()
    );
    let capped = issue(v, &g.id);
    v.consume_placeholder(&capped.id).unwrap();
    v.narrow_grant(&g.id, &json!({ "placeholder_policy": { "max_uses": 1 } }))
        .unwrap();
    assert_eq!(next_of(v.consume_placeholder(&capped.id)), ph_next());
}

#[test]
fn no_session_says_how_to_get_one_and_an_ended_grant_says_to_ask_again() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    assert_eq!(
        next_of(v.assert_session_live(None)),
        json!({ "cli": ["agent-vault session create --cred <slug>"], "mcp": { "tool": "vault_request_session" } })
    );
    let s = session(v);
    let g = v
        .create_grant(CreateGrantOptions {
            ttl_ms: Some(1000),
            ..grant_opts(&s.id, &fx.cred.id)
        })
        .unwrap();
    assert_eq!(
        at(now() + 5000, || next_of(v.assert_grant_live(Some(&g)))),
        json!({ "mcp": { "tool": "vault_request_session" } })
    );
}

#[test]
fn the_factor_refusals_name_the_command_that_fixes_them() {
    let mut fx = fresh_with(FactorClass::Passphrase, Some(PASSPHRASE));
    assert_eq!(
        next_of(fx.vault.remove_passphrase(&s(PASSPHRASE))),
        json!("agent-vault ui")
    );
    assert_eq!(
        next_of(fx.vault.set_presence_key(&json!({}))),
        json!("agent-vault ui")
    );
    let none = fresh();
    assert_eq!(
        next_of(none.vault.require_recovery_factor()),
        json!("agent-vault passphrase set")
    );
}
