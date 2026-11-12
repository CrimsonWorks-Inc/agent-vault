//! Ports `test/security/store-scrub.test.js`.

use serde_json::json;

use super::backup::audit_text;
use super::helpers::*;
use crate::vault::*;

const PATTERN: &str = "acme_[A-Za-z0-9]{20,40}";

#[test]
fn a_scrub_pattern_is_added_listed_persisted_and_audited_by_digest_only() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let p = v.add_scrub_pattern("demo", PATTERN).unwrap();
    assert!(p.id.starts_with("sp_") && p.id.len() == 29);
    assert_eq!(p.source, PATTERN);
    assert!(crate::util::parse_ms(&p.added_at).is_some());
    let list = v.list_credentials().unwrap();
    assert_eq!(list.iter().find(|c| c.slug == "demo").unwrap().scrub_patterns, vec![p.clone()]);
    assert!(list.iter().find(|c| c.slug == "other").unwrap().scrub_patterns.is_empty());
    let r = &records(v, "cred.scrub_pattern_added")[0];
    assert_eq!(
        (field(r, "credential_slug"), field(r, "pattern_id"), field(r, "pattern_sha256"), field(r, "length")),
        (&json!("demo"), &json!(p.id), &json!(crate::crypto::sha256_hex(PATTERN.as_bytes())), &json!(PATTERN.len()))
    );
    assert!(!audit_text(v).contains(PATTERN));
}

#[test]
fn removing_a_pattern_removes_that_one_once() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let a = v.add_scrub_pattern("demo", PATTERN).unwrap();
    let b = v.add_scrub_pattern("demo", "xoxb-[0-9]{10,13}").unwrap();
    assert!(v.remove_scrub_pattern("demo", &a.id).unwrap());
    assert!(!v.remove_scrub_pattern("demo", &a.id).unwrap());
    assert!(!v.remove_scrub_pattern("demo", "sp_nope").unwrap());
    let ids: Vec<String> = v.find_credential("demo").unwrap().unwrap().scrub_patterns.into_iter().map(|p| p.id).collect();
    assert_eq!(ids, vec![b.id]);
    let got: Vec<serde_json::Value> = records(v, "cred.scrub_pattern_removed").iter().map(|r| json!([field(r, "credential_slug"), field(r, "pattern_id")])).collect();
    assert_eq!(got, vec![json!(["demo", a.id])]);
}

#[test]
fn a_pattern_that_is_too_short_or_too_long_is_refused() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let long = "x".repeat(257);
    for source in ["ab", "", long.as_str()] {
        refused_cleanly(v, |v| v.add_scrub_pattern("demo", source), ("AV_POLICY_DENIED", Some("scrub_pattern")));
    }
    v.add_scrub_pattern("demo", "abc").unwrap();
    v.add_scrub_pattern("demo", &"y".repeat(256)).unwrap();
}

#[test]
fn a_pattern_that_contains_a_stored_credential_value_or_a_placeholder_is_refused() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for source in [SECRET.to_string(), format!("prefix{SECRET}"), format!("{OTHER_SECRET}|abc")] {
        refused_cleanly(v, |v| v.add_scrub_pattern("demo", &source), ("AV_POLICY_DENIED", Some("scrub_pattern")));
    }
    let sess = session(v);
    let g = grant_for(v, &sess.id, &fx.cred.id);
    let p = v.issue_placeholder(IssueOptions { grant_id: g.id, ..Default::default() }).unwrap().placeholder;
    let src = format!("Bearer {p}");
    refused_cleanly(v, |v| v.add_scrub_pattern("demo", &src), ("AV_POLICY_DENIED", Some("scrub_pattern")));
    assert!(err_msg(v.add_scrub_pattern("demo", &src)).contains("it contains a placeholder"));
    v.add_scrub_pattern("demo", "ghp_[A-Za-z0-9]{36}").unwrap();
}

#[test]
fn at_most_16_patterns_per_credential_and_64_in_the_vault() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    for i in 0..16 {
        v.add_scrub_pattern("demo", &format!("aaa{i}")).unwrap();
    }
    refused_cleanly(v, |v| v.add_scrub_pattern("demo", "aaa-one-more"), ("AV_POLICY_DENIED", Some("scrub_pattern")));
    for slug in ["c3", "c4", "c5"] {
        v.add_credential(new_cred(slug, "http", &format!("{slug}.example"), &[("token", &format!("tok_{slug}_0011223344556677"))])).unwrap();
        for i in 0..16 {
            v.add_scrub_pattern(slug, &format!("bbb{slug}{i}")).unwrap();
        }
    }
    refused_cleanly(v, |v| v.add_scrub_pattern("other", "ccc-sixty-five"), ("AV_POLICY_DENIED", Some("scrub_pattern")));
    let first = v.find_credential("c5").unwrap().unwrap().scrub_patterns[0].id.clone();
    v.remove_scrub_pattern("c5", &first).unwrap();
    v.add_scrub_pattern("other", "ccc-sixty-four").unwrap();
}

#[test]
fn scrub_pattern_writes_need_the_credential_to_exist_and_the_vault_to_be_unlocked() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    refused_cleanly(v, |v| v.add_scrub_pattern("nope", PATTERN), ("AV_NOT_FOUND", None));
    refused_cleanly(v, |v| v.remove_scrub_pattern("nope", "sp_x"), ("AV_NOT_FOUND", None));
    let p = v.add_scrub_pattern("demo", PATTERN).unwrap();
    v.lock().unwrap();
    assert_eq!(code_of(v.add_scrub_pattern("demo", "abcdef")), "AV_LOCKED");
    assert_eq!(code_of(v.remove_scrub_pattern("demo", &p.id)), "AV_LOCKED");
    assert_eq!(v.find_credential("demo").unwrap().unwrap().scrub_patterns.len(), 1);
}
