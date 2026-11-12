//! Ports `test/core/integrity-fuzz.test.js`: the integrity properties the
//! vault relies on (a placeholder verifies only under its own key and only
//! unaltered; an operation canonicalises uniquely), exercised through
//! av-core's public API. The substitution-site case is av-core's alone (see
//! PORTED.md).

use std::collections::HashMap;

use av_core::operation::canonical_operation;
use av_core::placeholder::{mint, new_sid, parse_at, verify, MintInput};
use av_core::secret::Key32;
use serde_json::json;

fn rng(seed: u64) -> impl FnMut() -> f64 {
    let mut s = seed;
    move || {
        s = (s.wrapping_mul(1_103_515_245).wrapping_add(12_345)) & 0x7fff_ffff;
        s as f64 / 0x7fff_ffff as f64
    }
}

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn key() -> Key32 {
    crate::crypto::random_key().unwrap()
}

fn mint_one(k: &Key32, rnd: &mut impl FnMut() -> f64) -> String {
    let n = (rnd() * 8.0) as usize;
    let slug: String = std::iter::once("ab".to_string())
        .chain((0..n).map(|_| (LETTERS[(rnd() * LETTERS.len() as f64) as usize % LETTERS.len()] as char).to_string()))
        .collect();
    let sid = new_sid();
    mint(&MintInput { k_ph: k, sid: &sid, slug: &slug, field: "token" }).unwrap().text
}

#[test]
fn a_minted_placeholder_always_verifies_under_its_own_key() {
    let k = key();
    let mut rnd = rng(1);
    for _ in 0..3000 {
        let p = mint_one(&k, &mut rnd);
        let parsed = parse_at(&p, 0).unwrap_or_else(|| panic!("did not parse: {p}"));
        assert!(verify(&k, &parsed), "did not verify: {p}");
    }
}

#[test]
fn changing_any_single_character_makes_a_placeholder_unusable() {
    let k = key();
    let mut rnd = rng(7);
    let alphabet: Vec<char> = "0123456789abcdefghjkmnpqrstvwxyz._-".chars().collect();
    let mut mutations = 0;
    for _ in 0..1200 {
        let p: Vec<char> = mint_one(&k, &mut rnd).chars().collect();
        for _ in 0..6 {
            let at = (rnd() * p.len() as f64) as usize % p.len();
            let repl = alphabet[(rnd() * alphabet.len() as f64) as usize % alphabet.len()];
            if repl == p[at] {
                continue;
            }
            let mut m = p.clone();
            m[at] = repl;
            let mutated: String = m.into_iter().collect();
            mutations += 1;
            if let Some(parsed) = parse_at(&mutated, 0) {
                assert!(!verify(&k, &parsed), "a one-character change still verified: {mutated}");
            }
        }
    }
    assert!(mutations > 5000, "{mutations}");
}

#[test]
fn a_placeholder_never_verifies_under_a_different_key() {
    let k = key();
    let other = key();
    let mut rnd = rng(42);
    for _ in 0..3000 {
        let parsed = parse_at(&mint_one(&k, &mut rnd), 0).unwrap();
        assert!(!verify(&other, &parsed));
    }
}

#[test]
fn random_text_is_never_mistaken_for_a_placeholder() {
    let k = key();
    let mut rnd = rng(99);
    let chars: Vec<char> = "av1.0123456789abcdefghjkmnpqrstvwxyz_-".chars().collect();
    for _ in 0..20_000 {
        let len = 40 + (rnd() * 60.0) as usize;
        let junk: String = std::iter::once("av1.".to_string())
            .chain((0..len).map(|_| chars[(rnd() * chars.len() as f64) as usize % chars.len()].to_string()))
            .collect();
        if let Some(parsed) = parse_at(&junk, 0) {
            assert!(!verify(&k, &parsed), "random text verified: {junk}");
        }
    }
}

#[test]
fn operations_that_differ_in_any_way_canonicalise_differently() {
    let mut rnd = rng(2024);
    let ops = ["session.create", "cred.add", "cred.remove", "approval.approve", "listener.add"];
    let creds = ["prod", "prod2", "staging", "prod-key", ""];
    let methods = [json!(["GET"]), json!(["GET", "POST"]), json!(["POST"]), json!(["GET", "POST", "DELETE"]), json!([])];
    let paths = [json!(["/**"]), json!(["/v1/**"]), json!(["/user"]), json!(["/**", "/user"]), json!([])];
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut pairs = 0;
    for _ in 0..40_000 {
        let mut pick = |n: usize| (rnd() * n as f64) as usize % n;
        let op = json!({ "op": ops[pick(5)], "cred": creds[pick(5)], "methods": methods[pick(5)], "paths": paths[pick(5)] });
        let text = canonical_operation(&op);
        let key = serde_json::to_string(&[&op["op"], &op["cred"], &op["methods"], &op["paths"]]).unwrap();
        match seen.get(&text) {
            Some(prev) => {
                pairs += 1;
                assert_eq!(prev, &key, "two different operations canonicalised identically: {text}");
            }
            None => {
                seen.insert(text, key);
            }
        }
    }
    assert!(pairs > 100);
}

#[test]
fn key_order_and_absent_fields_do_not_change_the_canonical_form() {
    assert_eq!(
        canonical_operation(&json!({ "op": "session.create", "cred": "prod", "methods": ["GET"] })),
        canonical_operation(&json!({ "methods": ["GET"], "cred": "prod", "op": "session.create" }))
    );
    assert_ne!(
        canonical_operation(&json!({ "op": "cred.add", "kind": null })),
        canonical_operation(&json!({ "op": "cred.add" }))
    );
    assert_ne!(
        canonical_operation(&json!({ "op": "x", "methods": ["GET", "POST"] })),
        canonical_operation(&json!({ "op": "x", "methods": ["POST", "GET"] }))
    );
}
