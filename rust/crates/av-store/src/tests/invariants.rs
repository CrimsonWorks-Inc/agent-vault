//! Ports the store-level parts of `test/security/invariants.test.js`. The
//! random-request fuzz through the gateway is the daemon's and conformance's;
//! what the vault itself must guarantee under that traffic is checked here:
//! a placeholder is never spent past its uses, and the audit log holds no
//! secret, no placeholder and no token, and still verifies.

use super::helpers::*;
use crate::model::PlaceholderState;
use crate::vault::*;

fn rng(seed: u64) -> impl FnMut() -> f64 {
    let mut s = seed;
    move || {
        s = (s.wrapping_mul(1_103_515_245).wrapping_add(12_345)) & 0x7fff_ffff;
        s as f64 / 0x7fff_ffff as f64
    }
}

#[test]
fn a_placeholder_was_never_spent_more_times_than_it_had_uses() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let s = session(v);
    let g = grant_for(v, &s.id, &fx.cred.id);
    let one = v
        .issue_placeholder(IssueOptions { grant_id: g.id.clone(), uses: Some(3), ..Default::default() })
        .unwrap()
        .row;
    let mut rnd = rng(20_260_921);
    for _ in 0..200 {
        if rnd() < 0.3 {
            v.refund_placeholder(&one.id).unwrap();
        } else {
            let _ = v.consume_placeholder(&one.id);
        }
        let row = ph_row(v, &one.id);
        assert!(row.uses <= row.max_uses, "spent {} of {}", row.uses, row.max_uses);
        assert_eq!(row.max_uses, 3);
        if row.uses >= row.max_uses {
            assert_eq!(row.state, PlaceholderState::Dead, "an exhausted placeholder must not stay active");
        }
    }
}

#[test]
fn nothing_sensitive_reached_the_audit_log_and_its_chain_still_verifies() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let created = v.create_session(CreateSessionOptions::default()).unwrap();
    let token = av_core::secret::ExposeSecret::expose_secret(&created.token).to_string();
    let g = grant_for(v, &created.session.id, &fx.cred.id);
    let mut placeholders = Vec::new();
    for _ in 0..520 {
        let p = v
            .issue_placeholder(IssueOptions { grant_id: g.id.clone(), ..Default::default() })
            .unwrap();
        let _ = v.consume_placeholder(&p.row.id);
        placeholders.push(p.placeholder);
    }
    let raw: String = {
        let c = v.conn();
        let mut stmt = c.prepare("SELECT record FROM audit ORDER BY seq").unwrap();
        let lines: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        lines.join("\n")
    };
    for secret in [SECRET, OTHER_SECRET] {
        assert!(!raw.contains(secret), "a credential value is in the audit log");
    }
    for p in &placeholders {
        assert!(!raw.contains(p.as_str()), "a full placeholder is in the audit log");
    }
    assert!(!raw.contains(&token), "a session token is in the audit log");
    let report = v.audit().unwrap().verify().unwrap();
    assert!(report.ok, "the chain did not verify after {} records: {:?}", report.count, report.reason);
    assert!(report.count > 500, "expected a busy log, got {}", report.count);
}
