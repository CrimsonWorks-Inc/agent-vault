//! Ports `test/security/store-notify.test.js`.

use serde_json::json;

use super::backup::audit_text;
use super::helpers::*;
use crate::model::NotifyDetail;
use crate::vault::*;

const URL_SECRET: &str =
    "https://hooks.example/services/T000/B000/XXXXSECRETPATHXXXX?token=QUERYSECRET";

fn url_of(v: &Vault) -> String {
    av_core::secret::ExposeSecret::expose_secret(&v.get_notify_webhook().unwrap().unwrap().url)
        .to_string()
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_webhook_is_sealed_at_rest_and_only_its_host_is_shown_or_audited() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    let view = v
        .set_notify_webhook(&s(URL_SECRET), NotifyDetail::Minimal)
        .unwrap();
    let mut keys: Vec<String> = serde_json::to_value(&view)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(keys, vec!["configured_at", "detail", "host"]);
    assert_eq!(view.host, "hooks.example");
    assert_eq!(view.detail, NotifyDetail::Minimal);
    assert_eq!(v.notify_config().unwrap(), Some(view.clone()));
    let w = v.get_notify_webhook().unwrap().unwrap();
    assert_eq!(
        (url_of(v), w.host, w.detail),
        (
            URL_SECRET.to_string(),
            "hooks.example".to_string(),
            NotifyDetail::Minimal
        )
    );
    for place in [
        snapshot(v).0,
        audit_text(v),
        serde_json::to_string(&v.notify_config().unwrap()).unwrap(),
    ] {
        for part in ["XXXXSECRETPATHXXXX", "QUERYSECRET", "/services/"] {
            assert!(!place.contains(part), "{part} leaked");
        }
    }
    let r = &records(v, "notify.configured")[0];
    assert_eq!(
        (field(r, "host"), field(r, "detail")),
        (&json!("hooks.example"), &json!("minimal"))
    );
    let mut again = Vault::open(fx.dir.path()).unwrap();
    again.unlock(None).unwrap();
    assert_eq!(url_of(&again), URL_SECRET);
    assert_eq!(
        again.notify_config().unwrap().unwrap().host,
        "hooks.example"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn loopback_http_and_the_headline_detail_are_accepted() {
    let mut fx = fresh();
    for url in [
        "http://127.0.0.1:9000/hook",
        "http://localhost/hook",
        "http://[::1]:8080/x",
        "https://hooks.example:8443/a",
    ] {
        let out = fx
            .vault
            .set_notify_webhook(&s(url), NotifyDetail::Headline)
            .unwrap();
        assert_eq!(out.detail, NotifyDetail::Headline, "{url}");
    }
    assert_eq!(
        fx.vault.notify_config().unwrap().unwrap().host,
        "hooks.example:8443"
    );
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn a_webhook_that_is_not_https_has_userinfo_or_is_not_a_url_is_refused_and_nothing_is_kept() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.set_notify_webhook(&s("https://hooks.example/keep"), NotifyDetail::Minimal)
        .unwrap();
    let long = format!("https://hooks.example/{}", "a".repeat(2048));
    for url in [
        "http://example.com/hook",
        "http://127.0.0.1.evil.example/hook",
        "ftp://hooks.example/x",
        "javascript:alert(1)",
        "not a url",
        "",
        "https://user:pw@hooks.example/x",
        "https://user@hooks.example/x",
        long.as_str(),
    ] {
        refused_cleanly(
            v,
            |v| v.set_notify_webhook(&s(url), NotifyDetail::Minimal),
            ("AV_POLICY_DENIED", Some("webhook_url")),
        );
    }
    assert_eq!(url_of(v), "https://hooks.example/keep");
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn the_sealed_url_is_bound_to_what_it_is_a_credentials_ciphertext_does_not_open_as_one() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.set_notify_webhook(&s(URL_SECRET), NotifyDetail::Minimal)
        .unwrap();
    exec(
        v,
        "UPDATE notify SET sealed = (SELECT sealed FROM credential_fields WHERE credential_id = ?1)",
        &[&fx.cred.id],
    );
    assert!(v.get_notify_webhook().is_err());
}

#[test]
#[ignore = "blocked on av-core todo!() on rust-port (placeholder, policy, scrub, pins, profiles, canon, errors); passes against rust-port-core in a throwaway copy"]
fn clearing_the_webhook_removes_it_once_and_a_locked_vault_reveals_nothing() {
    let mut fx = fresh();
    let v = &mut fx.vault;
    v.set_notify_webhook(&s(URL_SECRET), NotifyDetail::Minimal)
        .unwrap();
    assert!(v.clear_notify_webhook().unwrap());
    assert!(!v.clear_notify_webhook().unwrap());
    assert_eq!(records(v, "notify.removed").len(), 1);
    assert!(v.get_notify_webhook().unwrap().is_none());
    assert!(v.notify_config().unwrap().is_none());
    v.set_notify_webhook(&s(URL_SECRET), NotifyDetail::Minimal)
        .unwrap();
    v.lock().unwrap();
    assert_eq!(code_of(v.get_notify_webhook()), "AV_LOCKED");
    assert_eq!(
        code_of(v.set_notify_webhook(&s("https://hooks.example/y"), NotifyDetail::Minimal)),
        "AV_LOCKED"
    );
    assert_eq!(code_of(v.clear_notify_webhook()), "AV_LOCKED");
    assert_eq!(v.notify_config().unwrap().unwrap().host, "hooks.example");
}
