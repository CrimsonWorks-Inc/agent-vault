//! Built-in connector profiles: the pure, I/O-free parts of
//! `src/connectors/profiles.js`.
//!
//! A profile is a ceiling, not a default: its deny lists apply even under a
//! grant of `/**`, and its host list is the outer bound of anything a policy
//! can allow.

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

/// The sites a field of an unknown kind or field defaults to. Ports the
/// fallback of `defaultSites` in `src/connectors/profiles.js`.
pub const DEFAULT_SITES: &[&str] = &["header:authorization:Bearer"];

/// The field an unknown kind defaults to. Ports the fallback of
/// `defaultField` in `src/connectors/profiles.js`.
pub const DEFAULT_FIELD: &str = "token";

/// One credential field a profile declares. Ports the `fields` entries
/// `{ <name>: { sites } }` of `PROFILES` in `src/connectors/profiles.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileField {
    /// Field name.
    pub name: &'static str,
    /// Default substitution sites.
    pub sites: &'static [&'static str],
}

/// The request a connection probe sends. Ports `probe` in `PROFILES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// Method.
    pub method: &'static str,
    /// Path.
    pub path: &'static str,
}

/// Documented provider health headers. Ports `health` in `PROFILES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthHeaders {
    /// Header carrying the credential's expiry.
    pub expiry_header: Option<&'static str>,
    /// Header carrying its scopes.
    pub scopes_header: Option<&'static str>,
    /// Header carrying the remaining rate limit.
    pub ratelimit_remaining_header: Option<&'static str>,
}

/// A profile's default grant budget. Ports `defaultBudget` in `PROFILES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultBudget {
    /// `requests` (or `sessions` for L4).
    pub unit: &'static str,
    /// The limit.
    pub limit: u64,
}

/// Environment variable names an agent tool reads. Ports `env` in
/// `PROFILES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvNames {
    /// Base-URL variable.
    pub base: &'static str,
    /// API-key variable.
    pub key: &'static str,
}

/// A built-in connector profile. Ports the values of `PROFILES` in
/// `src/connectors/profiles.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Connector kind.
    pub kind: &'static str,
    /// `false` only where the JS sets `implemented: false`.
    pub implemented: bool,
    /// Hosts the credential may reach (empty: must name its own).
    pub hosts: &'static [&'static str],
    /// Fields, in declaration order (the first is the default field).
    pub fields: &'static [ProfileField],
    /// Connection probe, if any.
    pub probe: Option<Probe>,
    /// Health headers, if the provider documents any.
    pub health: Option<HealthHeaders>,
    /// Paths denied under any grant.
    pub deny_paths: &'static [&'static str],
    /// Extra derived-token scrub patterns (regex-crate syntax).
    pub scrub: &'static [&'static str],
    /// Default grant budget (`defaultBudget`).
    pub default_budget: DefaultBudget,
    /// Agent environment variable names, if any.
    pub env: Option<EnvNames>,
    /// An L4 (non-HTTP) connector.
    pub l4: bool,
}

const BEARER: &str = "header:authorization:Bearer";

/// Every built-in profile, verbatim and in the JS key order. Ports
/// `PROFILES` in `src/connectors/profiles.js`.
pub const PROFILES: &[Profile] = &[
    Profile {
        kind: "github",
        implemented: true,
        hosts: &["api.github.com", "uploads.github.com", "github.com"],
        fields: &[ProfileField {
            name: "token",
            sites: &[BEARER, "header:authorization:token", "basic:pass"],
        }],
        probe: Some(Probe {
            method: "GET",
            path: "/user",
        }),
        health: Some(HealthHeaders {
            expiry_header: Some("github-authentication-token-expiration"),
            scopes_header: Some("x-oauth-scopes"),
            ratelimit_remaining_header: Some("x-ratelimit-remaining"),
        }),
        deny_paths: &[
            "/user/keys",
            "/user/keys/**",
            "/user/gpg_keys",
            "/user/gpg_keys/**",
            "/authorizations/**",
            "/applications/**",
            "/repos/*/*/hooks",
            "/repos/*/*/hooks/**",
            "/orgs/*/hooks",
            "/orgs/*/hooks/**",
            "/repos/*/*/keys",
            "/repos/*/*/keys/**",
            "/repos/*/*/actions/secrets/**",
            "/orgs/*/actions/secrets/**",
            "/repos/*/*/collaborators/**",
            "/settings/**",
        ],
        scrub: &["gh[pousr]_[A-Za-z0-9]{20,}", "github_pat_[A-Za-z0-9_]{40,}"],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 500,
        },
        env: None,
        l4: false,
    },
    Profile {
        kind: "slack",
        implemented: true,
        hosts: &["slack.com", "files.slack.com", "www.slack.com"],
        fields: &[ProfileField {
            name: "token",
            sites: &[BEARER, "form:token"],
        }],
        probe: Some(Probe {
            method: "POST",
            path: "/api/auth.test",
        }),
        health: None,
        deny_paths: &[
            "/api/admin.*",
            "/api/oauth.*",
            "/api/apps.connections.open",
            "/api/apps.manifest.*",
            "/api/users.profile.set",
        ],
        scrub: &["xox[abpors]-[0-9A-Za-z-]{10,}"],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 500,
        },
        env: None,
        l4: false,
    },
    Profile {
        kind: "anthropic",
        implemented: true,
        hosts: &["api.anthropic.com"],
        fields: &[ProfileField {
            name: "key",
            sites: &["header:x-api-key"],
        }],
        probe: Some(Probe {
            method: "GET",
            path: "/v1/models",
        }),
        health: None,
        deny_paths: &["/v1/organizations/**", "/v1/admin/**", "/v1/api_keys/**"],
        scrub: &["sk-ant-[A-Za-z0-9_-]{20,}"],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 20000,
        },
        env: Some(EnvNames {
            base: "ANTHROPIC_BASE_URL",
            key: "ANTHROPIC_API_KEY",
        }),
        l4: false,
    },
    Profile {
        kind: "openai",
        implemented: true,
        hosts: &["api.openai.com"],
        fields: &[ProfileField {
            name: "key",
            sites: &[BEARER],
        }],
        probe: Some(Probe {
            method: "GET",
            path: "/v1/models",
        }),
        health: None,
        deny_paths: &["/v1/organization/**", "/v1/admin/**"],
        scrub: &["sk-(?:proj-)?[A-Za-z0-9_-]{20,}"],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 20000,
        },
        env: Some(EnvNames {
            base: "OPENAI_BASE_URL",
            key: "OPENAI_API_KEY",
        }),
        l4: false,
    },
    Profile {
        kind: "google-genai",
        implemented: true,
        hosts: &["generativelanguage.googleapis.com"],
        fields: &[ProfileField {
            name: "key",
            sites: &["header:x-goog-api-key"],
        }],
        probe: Some(Probe {
            method: "GET",
            path: "/v1beta/models",
        }),
        health: None,
        deny_paths: &[],
        scrub: &["AIza[0-9A-Za-z_-]{35}"],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 20000,
        },
        env: Some(EnvNames {
            base: "GOOGLE_GEMINI_BASE_URL",
            key: "GEMINI_API_KEY",
        }),
        l4: false,
    },
    Profile {
        kind: "http",
        implemented: true,
        // a generic credential must name its own exact host
        hosts: &[],
        fields: &[ProfileField {
            name: "token",
            sites: &[BEARER],
        }],
        probe: None,
        health: None,
        deny_paths: &[],
        scrub: &[],
        default_budget: DefaultBudget {
            unit: "requests",
            limit: 500,
        },
        env: None,
        l4: false,
    },
    // The profile is the design; the L4 proxy that would carry it is not
    // built, so a credential of this kind is refused at creation.
    Profile {
        kind: "postgres",
        implemented: false,
        hosts: &[],
        fields: &[ProfileField {
            name: "password",
            sites: &["url:userinfo"],
        }],
        probe: None,
        health: None,
        deny_paths: &[],
        scrub: &[],
        default_budget: DefaultBudget {
            unit: "sessions",
            limit: 20,
        },
        env: None,
        l4: true,
    },
];

/// An unknown connector kind. Ports the `Error` thrown by `getProfile` in
/// `src/connectors/profiles.js`
/// (`unknown connector kind: <kind>. Known: github, slack, …`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown connector kind: {0}. Known: github, slack, anthropic, openai, google-genai, http, postgres")]
pub struct UnknownKind(pub String);

/// Fetch a profile. Its policy ceiling is [`Profile::policy_ceiling`]. Ports
/// `getProfile` in `src/connectors/profiles.js`.
pub fn get_profile(kind: &str) -> Result<&'static Profile, UnknownKind> {
    PROFILES
        .iter()
        .find(|p| p.kind == kind)
        .ok_or_else(|| UnknownKind(kind.into()))
}

impl Profile {
    /// The profile's policy ceiling layer: `{ kind, hosts (None when empty),
    /// deny_paths }`. Ports the `policyCeiling` that `getProfile` in
    /// `src/connectors/profiles.js` precomputes.
    pub fn policy_ceiling(&self) -> Policy {
        use crate::policy::Checked;
        Policy {
            kind: Some(Checked::Valid(self.kind.into())),
            hosts: (!self.hosts.is_empty())
                .then(|| Checked::Valid(self.hosts.iter().map(|s| s.to_string()).collect())),
            deny_paths: Some(Checked::Valid(
                self.deny_paths.iter().map(|s| s.to_string()).collect(),
            )),
            ..Default::default()
        }
    }
}

/// One row of [`list_profiles`]. Ports the objects returned by
/// `listProfiles` in `src/connectors/profiles.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// Connector kind.
    pub kind: String,
    /// Hosts.
    pub hosts: Vec<String>,
    /// Field names.
    pub fields: Vec<String>,
    /// L4 connector.
    pub l4: bool,
    /// Implemented.
    pub implemented: bool,
}

/// Every profile summarized, in table order. Ports `listProfiles` in
/// `src/connectors/profiles.js`.
pub fn list_profiles() -> Vec<ProfileSummary> {
    PROFILES
        .iter()
        .map(|p| ProfileSummary {
            kind: p.kind.into(),
            hosts: p.hosts.iter().map(|s| s.to_string()).collect(),
            fields: p.fields.iter().map(|f| f.name.to_string()).collect(),
            l4: p.l4,
            implemented: p.implemented,
        })
        .collect()
}

/// Default sites for a field, or [`DEFAULT_SITES`] for an unknown kind or
/// field. Ports `defaultSites` in `src/connectors/profiles.js`.
pub fn default_sites(kind: &str, field: &str) -> &'static [&'static str] {
    get_profile(kind)
        .ok()
        .and_then(|p| p.fields.iter().find(|f| f.name == field))
        .map_or(DEFAULT_SITES, |f| f.sites)
}

/// The first field of the kind's profile, or [`DEFAULT_FIELD`]. Ports
/// `defaultField` in `src/connectors/profiles.js`.
pub fn default_field(kind: &str) -> &'static str {
    get_profile(kind)
        .ok()
        .and_then(|p| p.fields.first())
        .map_or(DEFAULT_FIELD, |f| f.name)
}

/// Month abbreviations for RFC 1123 dates. Ports `MONTHS` in
/// `src/connectors/profiles.js`.
pub const MONTHS: &[(&str, u32)] = &[
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];

/// What a response's health headers said. Ports the object returned by
/// `extractHealth` in `src/connectors/profiles.js`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Health {
    /// Expiry as an ISO 8601 UTC timestamp (`Date#toISOString` form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_expires_at: Option<String>,
    /// Scopes, trimmed, empty ones dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Remaining rate limit (a safe integer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimit_remaining: Option<u64>,
}

/// Read the profile's documented health headers (case-insensitive; repeats
/// joined with `, `). An unparseable value is omitted, a header the profile
/// does not name is never read; `None` when the profile has no health block
/// or nothing parsed. Ports `extractHealth` in `src/connectors/profiles.js`.
pub fn extract_health(profile: Option<&Profile>, headers: &[(String, String)]) -> Option<Health> {
    let h = profile?.health?;
    let header = |name: Option<&str>| -> Option<String> {
        let name = name?;
        let found: Vec<_> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (!found.is_empty()).then(|| found.join(", "))
    };
    let observed_expires_at = header(h.expiry_header).and_then(|s| parse_expiry(&s));
    let scopes = header(h.scopes_header).and_then(|s| {
        let scopes: Vec<_> = s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        (!scopes.is_empty()).then_some(scopes)
    });
    let ratelimit_remaining = header(h.ratelimit_remaining_header).and_then(|s| {
        let s = s.trim();
        if s.len() > 16 {
            return None;
        }
        crate::policy::budget_integer(&serde_json::Value::String(s.into()))
    });
    if observed_expires_at.is_none() && scopes.is_none() && ratelimit_remaining.is_none() {
        None
    } else {
        Some(Health {
            observed_expires_at,
            scopes,
            ratelimit_remaining,
        })
    }
}

fn parse_expiry(raw: &str) -> Option<String> {
    let s = raw.trim();
    let iso=regex::Regex::new(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2}))?$").ok()?;
    let github =
        regex::Regex::new(r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) UTC$").ok()?;
    let rfc = regex::Regex::new(
        r"^(?:[A-Za-z]{3}, )?(\d{1,2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$",
    )
    .ok()?;
    let (year, month, day, hour, minute, second, offset) =
        if let Some(c) = iso.captures(s).or_else(|| github.captures(s)) {
            let n = |i| c.get(i).and_then(|m| m.as_str().parse::<i32>().ok());
            (
                n(1)?,
                n(2)?,
                n(3)?,
                n(4).unwrap_or(0),
                n(5).unwrap_or(0),
                n(6).unwrap_or(0),
                c.get(8).map(|m| m.as_str()).unwrap_or("Z").to_owned(),
            )
        } else if let Some(c) = rfc.captures(s) {
            let n = |i: usize| c[i].parse::<i32>().ok();
            (
                n(3)?,
                MONTHS.iter().find(|(m, _)| *m == c[2].to_lowercase())?.1 as i32,
                n(1)?,
                n(4)?,
                n(5)?,
                n(6)?,
                "Z".into(),
            )
        } else {
            return None;
        };
    // Date.UTC treats years 0..99 as 1900..1999, which fails JS's roundtrip.
    if year < 100 {
        return None;
    }
    let date = time::Date::from_calendar_date(
        year,
        time::Month::try_from(u8::try_from(month).ok()?).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()?;
    let clock = time::Time::from_hms(
        u8::try_from(hour).ok()?,
        u8::try_from(minute).ok()?,
        u8::try_from(second).ok()?,
    )
    .ok()?;
    let mut date = time::PrimitiveDateTime::new(date, clock).assume_utc();
    if offset != "Z" {
        let digits = offset[1..].replace(':', "");
        let hours = digits[..2].parse::<i64>().ok()?;
        let minutes = digits[2..].parse::<i64>().ok()?;
        if hours > 14 || minutes > 59 || (hours == 14 && minutes > 0) {
            return None;
        }
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        date = date.checked_sub(time::Duration::minutes(sign * (hours * 60 + minutes)))?;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        date.year(),
        date.month() as u8,
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn js_profiles_and_health_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/profile-vectors.json")).unwrap();
        assert_eq!(
            serde_json::to_value(list_profiles()).unwrap(),
            v["profiles"]
        );
        for d in v["defaults"].as_array().unwrap() {
            let k = d["kind"].as_str().unwrap();
            assert_eq!(default_field(k), d["field"]);
            assert_eq!(
                serde_json::to_value(default_sites(k, default_field(k))).unwrap(),
                d["sites"]
            );
            assert!(crate::policy::validate(
                &get_profile(k).unwrap().policy_ceiling(),
                &Default::default()
            )
            .is_empty());
        }
        for h in v["health"].as_array().unwrap() {
            let headers = vec![
                (
                    "GitHub-Authentication-Token-Expiration".into(),
                    h["date"].as_str().unwrap().into(),
                ),
                ("X-OAuth-Scopes".into(), "repo, user, ".into()),
                ("X-Ratelimit-Remaining".into(), "0".into()),
            ];
            assert_eq!(
                serde_json::to_value(extract_health(get_profile("github").ok(), &headers)).unwrap(),
                h["result"],
                "{}",
                h["date"]
            );
        }
    }
}
