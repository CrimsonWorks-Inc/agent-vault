//! `connectors-health.test.js`, through av-daemon's public profile API.
#![forbid(unsafe_code)]
use av_daemon::connectors::profiles::{extract_health, get_profile, list_profiles, PROFILES};
use serde_json::{json, Value};
fn health(headers: &[(&str, &str)]) -> Option<Value> {
    let h = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>();
    extract_health(get_profile("github").ok(), &h).map(|v| serde_json::to_value(v).unwrap())
}
#[test]
fn provider_health_dates_rates_scopes_and_offsets_are_strict_with_ordinary_controls() {
    assert_eq!(
        health(&[
            (
                "github-authentication-token-expiration",
                "2027-01-31 00:00:00 UTC"
            ),
            ("x-oauth-scopes", "repo, user"),
            ("x-ratelimit-remaining", "42")
        ]),
        Some(
            json!({"observed_expires_at":"2027-01-31T00:00:00.000Z","scopes":["repo","user"],"ratelimit_remaining":42})
        )
    );
    for (input, want) in [
        ("2027-06-15T13:45:30Z", "2027-06-15T13:45:30.000Z"),
        ("Sun, 31 Jan 2027 00:00:00 GMT", "2027-01-31T00:00:00.000Z"),
        ("2027-03-01", "2027-03-01T00:00:00.000Z"),
        ("2027-01-31T00:00:00+01:00", "2027-01-30T23:00:00.000Z"),
        ("2027-01-31T00:00:00-0530", "2027-01-31T05:30:00.000Z"),
        ("2027-01-01T00:30:00+01:00", "2026-12-31T23:30:00.000Z"),
        ("2027-01-31T00:00:00+14:00", "2027-01-30T10:00:00.000Z"),
        ("2027-01-31T00:00:00+00:00", "2027-01-31T00:00:00.000Z"),
        ("2027-01-31T00:00:00Z", "2027-01-31T00:00:00.000Z"),
    ] {
        assert_eq!(
            health(&[("GitHub-Authentication-Token-Expiration", input)]).unwrap()
                ["observed_expires_at"],
            want,
            "{input}"
        );
    }
    for raw in [
        "not-a-date",
        "2027-02-31 00:00:00 UTC",
        "yesterday",
        "2027-02-30T00:00:00+01:00",
        "2027-02-29T00:00:00-05:00",
        "2027-04-31T12:00:00+0200",
        "2027-01-31T25:00:00+01:00",
        "2027-01-31T23:59:60+01:00",
        "2027-01-31T00:00:00+99:99",
        "2027-01-31T00:00:00+14:01",
        "2027-01-31T00:00:00-15:00",
        "2027-01-31T00:00:00+01:60",
        "2027-02-29T00:00:00Z",
        "0000-01-01T00:00:00+01:00",
        "+275760-09-13T00:00:00Z",
    ] {
        assert!(
            health(&[("github-authentication-token-expiration", raw)]).is_none(),
            "{raw}"
        );
    }
    assert_eq!(
        health(&[
            ("github-authentication-token-expiration", "nope"),
            ("x-oauth-scopes", "gist")
        ]),
        Some(json!({"scopes":["gist"]}))
    );
    assert_eq!(
        health(&[("x-ratelimit-remaining", "0")]).unwrap()["ratelimit_remaining"],
        0
    );
    for raw in ["nope", "-1", "1.5", "1e2"] {
        assert!(health(&[("x-ratelimit-remaining", raw)]).is_none(), "{raw}");
    }
    assert!(health(&[
        ("date", "Sun, 31 Jan 2027 00:00:00 GMT"),
        ("server", "GitHub.com")
    ])
    .is_none());
}
#[test]
fn provider_health_declared_headers_only_typed_repeats_and_no_embedded_profile_pins() {
    let h = vec![
        (
            "github-authentication-token-expiration".into(),
            "2027-01-31 00:00:00 UTC".into(),
        ),
        ("x-oauth-scopes".into(), "repo".into()),
        ("x-ratelimit-remaining".into(), "7".into()),
    ];
    for profile in PROFILES.iter().filter(|p| p.kind != "github") {
        assert!(profile.health.is_none(), "{}", profile.kind);
        assert!(
            extract_health(Some(profile), &h).is_none(),
            "{}",
            profile.kind
        );
    }
    let gh = get_profile("github").unwrap().health.unwrap();
    assert!(
        gh.expiry_header.is_some()
            && gh.scopes_header.is_some()
            && gh.ratelimit_remaining_header.is_some()
    );
    assert_eq!(format!("{gh:?}").matches("_header:").count(), 3);
    for p in PROFILES {
        assert!(
            !format!("{p:?}").contains("sha256/"),
            "{} has an embedded SPKI pin",
            p.kind
        );
    }
    for p in serde_json::to_value(list_profiles())
        .unwrap()
        .as_array()
        .unwrap()
    {
        assert!(p.get("pins").is_none());
    }
    // Rust's canonical header representation replaces JS array/get adapters:
    // repeated field lines and the already-joined getter value must agree.
    assert_eq!(
        health(&[("x-oauth-scopes", "repo"), ("x-oauth-scopes", "read:org")]).unwrap()["scopes"],
        json!(["repo", "read:org"])
    );
    assert_eq!(
        health(&[("x-oauth-scopes", "repo"), ("x-oauth-scopes", "read:org")]),
        health(&[("x-oauth-scopes", "repo, read:org")])
    );
    assert_eq!(
        health(&[("x-ratelimit-remaining", "9")]).unwrap()["ratelimit_remaining"],
        9
    );
}
