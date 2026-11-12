//! The guided flows (`quickstart`, `cred add` and `session create` with no
//! arguments): pure decisions first, then the interactive flows. Ports
//! `src/cli/wizards.js`.

use serde_json::Value;

use crate::{Context, Outcome};

/// One access level the session wizard offers. Ports the values of
/// `ACCESS_LEVELS` in `src/cli/wizards.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessLevel {
    /// The key (`read`, `write`, `full`).
    pub key: &'static str,
    /// Shown label.
    pub label: &'static str,
    /// Shown hint.
    pub hint: &'static str,
    /// Methods allowed.
    pub methods: &'static [&'static str],
    /// Approval mode.
    pub approval: &'static str,
}

/// Ports `ACCESS_LEVELS` in `src/cli/wizards.js`.
pub const ACCESS_LEVELS: [AccessLevel; 3] = [
    AccessLevel {
        key: "read",
        label: "Read only",
        hint: "GET and HEAD, nothing can be changed",
        methods: &["GET", "HEAD"],
        approval: "auto",
    },
    AccessLevel {
        key: "write",
        label: "Read, and write with your approval",
        hint: "you are asked before anything is created or changed",
        methods: &["GET", "HEAD", "POST", "PATCH", "PUT"],
        approval: "on-write",
    },
    AccessLevel {
        key: "full",
        label: "Read and write freely, including delete",
        hint: "no approval prompts; only for things you can afford to lose; asks for your passphrase every time",
        methods: &["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"],
        approval: "auto",
    },
];

/// The lifetime choice that means a session never expires. Ports
/// `NO_EXPIRY` in `src/cli/wizards.js`.
pub const NO_EXPIRY: &str = "never";

/// Wizard answers. Ports the argument of
/// `buildPolicy({ kind, access, paths, budget, ttlHours })` in
/// `src/cli/wizards.js`.
#[derive(Debug, Clone, Default)]
pub struct PolicyAnswers {
    /// Connector kind.
    pub kind: String,
    /// An [`ACCESS_LEVELS`] key.
    pub access: String,
    /// Path globs (default `/**`).
    pub paths: Vec<String>,
    /// Request budget (default: the profile's, else 500).
    pub budget: Option<u64>,
    /// Hours, or [`NO_EXPIRY`] (default 8).
    pub ttl_hours: Option<String>,
}

/// Turn wizard answers into the policy the daemon stores. Ports
/// `buildPolicy(...)` in `src/cli/wizards.js`.
pub fn build_policy(answers: &PolicyAnswers) -> Result<Value, String> {
    let level = ACCESS_LEVELS
        .iter()
        .find(|l| l.key == answers.access)
        .ok_or_else(|| format!("unknown access level: {}", answers.access))?;
    let budget = answers.budget.unwrap_or_else(|| {
        av_core::profiles::get_profile(&answers.kind)
            .map(|p| p.default_budget.limit)
            .unwrap_or(500)
    });
    let infinite = answers.ttl_hours.as_deref() == Some(NO_EXPIRY);
    let mut policy = serde_json::Map::new();
    policy.insert(
        "methods".into(),
        Value::from(
            level
                .methods
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>(),
        ),
    );
    let paths = if answers.paths.is_empty() {
        vec!["/**".to_string()]
    } else {
        answers.paths.clone()
    };
    policy.insert("paths".into(), Value::from(paths));
    policy.insert("budget".into(), Value::from(budget));
    policy.insert("approval".into(), Value::from(level.approval));
    if infinite {
        policy.insert("infinite".into(), Value::Bool(true));
    } else {
        let hours = answers
            .ttl_hours
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(8);
        policy.insert("ttl_hours".into(), Value::from(hours));
    }
    Ok(Value::Object(policy))
}

/// A slug that is valid, descriptive, and not already taken. Ports
/// `suggestSlug(kind, existing)` in `src/cli/wizards.js`.
pub fn suggest_slug(kind: &str, existing: &[String]) -> String {
    let mut base: String = kind
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(20)
        .collect();
    if base.is_empty() {
        base = "cred".into();
    }
    if !existing.iter().any(|s| s == &base) {
        return base;
    }
    for i in 2..100 {
        let candidate = format!("{base}-{i}");
        if !existing.iter().any(|s| s == &candidate) {
            return candidate;
        }
    }
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut n = millis;
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut encoded = String::new();
    if n == 0 {
        encoded.push('0');
    }
    while n > 0 {
        encoded.insert(0, digits[(n % 36) as usize] as char);
        n /= 36;
    }
    let tail = if encoded.len() > 4 {
        &encoded[encoded.len() - 4..]
    } else {
        encoded.as_str()
    };
    format!("{base}-{tail}")
}

/// One scope option: `(value, label, hint)`. Ports the entries returned by
/// `scopePresets` in `src/cli/wizards.js`.
pub type ScopePreset = (&'static str, &'static str, Option<&'static str>);

/// Scope options worth offering for a connector kind. Ports
/// `scopePresets(kind)` in `src/cli/wizards.js`.
pub fn scope_presets(kind: &str) -> Vec<ScopePreset> {
    match kind {
        "github" => vec![
            ("repo", "One repository", Some("the narrowest useful scope")),
            (
                "owner",
                "Everything under one owner",
                Some("all repos for a user or org"),
            ),
            (
                "all",
                "Everything this token can reach",
                Some("still bounded by the profile deny list"),
            ),
            ("custom", "Custom path patterns", None),
        ],
        "slack" => vec![
            ("all", "Every API this token can reach", None),
            ("custom", "Custom path patterns", None),
        ],
        "anthropic" | "openai" | "google-genai" => vec![
            (
                "all",
                "The model API",
                Some("admin and key-management paths are denied by the profile"),
            ),
            ("custom", "Custom path patterns", None),
        ],
        _ => vec![
            ("all", "Every path on this host", None),
            ("custom", "Custom path patterns", None),
        ],
    }
}

/// Expand a chosen scope into path globs. Ports
/// `pathsForScope(kind, scope, detail)` in `src/cli/wizards.js`.
pub fn paths_for_scope(kind: &str, scope: &str, detail: Option<&str>) -> Vec<String> {
    if scope == "all" {
        return vec!["/**".into()];
    }
    if scope == "custom" {
        let raw = detail.unwrap_or("/**");
        let paths: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        return if paths.is_empty() {
            vec!["/**".into()]
        } else {
            paths
        };
    }
    if kind == "github" {
        if scope == "repo" {
            let detail = detail.unwrap_or("");
            let (owner, repo) = detail.split_once('/').unwrap_or((detail, ""));
            return vec![
                "/user".into(),
                format!("/repos/{owner}/{repo}"),
                format!("/repos/{owner}/{repo}/**"),
            ];
        }
        if scope == "owner" {
            let detail = detail.unwrap_or("");
            return vec![
                "/user".into(),
                format!("/repos/{detail}/**"),
                format!("/orgs/{detail}/**"),
            ];
        }
    }
    vec!["/**".into()]
}

/// One budget option: a request count, or `None` for "Something else".
/// Ports the entries returned by `BUDGET_CHOICES` in `src/cli/wizards.js`.
pub type BudgetChoice = (Option<u64>, &'static str, Option<&'static str>);

/// Budget options for a connector kind (larger for LLM kinds). Ports
/// `BUDGET_CHOICES(kind)` in `src/cli/wizards.js`.
pub fn budget_choices(kind: &str) -> Vec<BudgetChoice> {
    let llm = matches!(kind, "anthropic" | "openai" | "google-genai");
    if llm {
        vec![
            (
                Some(20000),
                "20,000 requests",
                Some("a long working session"),
            ),
            (Some(5000), "5,000 requests", None),
            (Some(500), "500 requests", None),
            (None, "Something else", None),
        ]
    } else {
        vec![
            (Some(500), "500 requests", Some("a normal task")),
            (Some(100), "100 requests", Some("a small, focused task")),
            (Some(5000), "5,000 requests", Some("a long run")),
            (None, "Something else", None),
        ]
    }
}

fn host_ok(v: &str) -> bool {
    let (name, port) = match v.rsplit_once(':') {
        Some((n, p))
            if !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && n.contains(|c: char| c.is_ascii_alphabetic() || c == '.') =>
        {
            (n, true)
        }
        _ => (v, false),
    };
    let _ = port;
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn slug_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 24
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn repo_ok(v: &str) -> bool {
    let Some((owner, repo)) = v.split_once('/') else {
        return false;
    };
    let part = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    };
    part(owner) && part(repo) && !v[owner.len() + 1..].contains('/')
}

/// Walk someone through storing a credential. Ports
/// `credentialWizard(control, { slug })` in `src/cli/wizards.js`.
pub async fn credential_wizard(ctx: &Context, preset: Option<&str>) -> Outcome {
    use crate::prompt::{self, Choice, TextOptions};
    use av_core::secret::ExposeSecret;
    let creds = ctx.control("GET", "/v1/credentials", None).await?;
    let existing: Vec<String> = creds
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            c.get("slug")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    prompt::step(1, 4, "What are you connecting to?");
    let profiles = av_core::profiles::list_profiles();
    let mut choices: Vec<Choice<String>> = profiles
        .iter()
        .filter(|p| !p.l4 && p.kind != "http")
        .map(|p| Choice {
            value: p.kind.clone(),
            label: p.kind.clone(),
            hint: p.hosts.first().cloned(),
        })
        .collect();
    choices.push(Choice {
        value: "http".into(),
        label: "Something else".into(),
        hint: Some("any HTTP API, you name the host".into()),
    });
    let kind = prompt::select("Service", &choices, 0)?;
    let mut host: Option<String> = None;
    let mut sites: Option<Vec<String>> = None;
    if kind == "http" {
        host = Some(prompt::text(
            "Host",
            TextOptions {
                placeholder: Some("api.example.com"),
                validate: Some(&|v| {
                    if host_ok(v) {
                        None
                    } else {
                        Some("that does not look like a hostname".into())
                    }
                }),
                ..TextOptions::default()
            },
        )?);
        let site_choices = [
            (
                "header:authorization:Bearer",
                "Authorization: Bearer <token>",
                Some("the common one"),
            ),
            ("header:x-api-key", "X-API-Key: <token>", None),
            (
                "header:authorization:token",
                "Authorization: token <token>",
                None,
            ),
            ("basic:pass", "HTTP basic auth password", None),
            (
                "query:key",
                "A query parameter named key",
                Some("ends up in server logs"),
            ),
        ];
        let site_choices: Vec<Choice<String>> = site_choices
            .iter()
            .map(|(v, l, h)| Choice {
                value: (*v).into(),
                label: (*l).into(),
                hint: h.map(|s| s.to_string()),
            })
            .collect();
        sites = Some(vec![prompt::select(
            "Where does the token go in a request?",
            &site_choices,
            0,
        )?]);
    }
    prompt::step(2, 4, "Name it");
    let suggested = suggest_slug(&kind, &existing);
    let slug = if let Some(preset) = preset {
        preset.to_string()
    } else {
        let existing_ref = existing.clone();
        prompt::text(
            "Name",
            TextOptions {
                default_value: Some(&suggested),
                validate: Some(&|v| {
                    if !slug_ok(v) {
                        return Some(
                            "lowercase letters, numbers and dashes, up to 24 characters".into(),
                        );
                    }
                    if existing_ref.iter().any(|s| s == v) {
                        return Some(format!("{v} already exists"));
                    }
                    None
                }),
                ..TextOptions::default()
            },
        )?
    };
    prompt::step(3, 4, "The value");
    prompt::note(&[
        "It is read without echoing, never appears in your shell history,",
        "and is encrypted before it touches disk. You will not see it again.",
    ]);
    let label = if kind == "http" {
        "token".to_string()
    } else {
        format!("{kind} token")
    };
    let value = prompt::secret(&format!("Paste the {label}:"))?;
    if value.expose_secret().is_empty() {
        return Err(crate::policy_input::usage("no value entered"));
    }
    prompt::step(4, 4, "Confirm");
    let field = av_core::profiles::default_field(&kind);
    let site_list = sites.clone().unwrap_or_else(|| {
        av_core::profiles::default_sites(&kind, field)
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });
    let profile_host = av_core::profiles::get_profile(&kind)
        .ok()
        .and_then(|p| p.hosts.first().copied())
        .unwrap_or("—");
    let host_shown = host.clone().unwrap_or_else(|| profile_host.to_string());
    let ending = value
        .expose_secret()
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    let value_row = format!(
        "{} characters, ending …{ending}",
        value.expose_secret().len()
    );
    let sites_row = site_list.join(", ");
    prompt::summary(
        "About to store",
        &[
            ("name", slug.as_str()),
            ("service", kind.as_str()),
            ("host", host_shown.as_str()),
            ("injected at", sites_row.as_str()),
            ("value", value_row.as_str()),
        ],
    );
    if !prompt::confirm("Store it?", true)? {
        return Err(prompt::cancelled());
    }
    let mut body = serde_json::Map::new();
    body.insert("slug".into(), Value::from(slug.clone()));
    body.insert("kind".into(), Value::from(kind.clone()));
    if let Some(host) = &host {
        body.insert("host".into(), Value::from(host.clone()));
    }
    body.insert("value".into(), Value::from(value.expose_secret()));
    if let Some(sites) = &sites {
        body.insert("sites".into(), Value::from(sites.clone()));
    }
    let created = ctx
        .control_with_presence("POST", "/v1/credentials", Some(&Value::Object(body)))
        .await?;
    let fp = created
        .pointer("/fields/0/fp8")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let c = prompt::Colors::detect();
    println!(
        "\n{} {slug} {}",
        c.green("stored"),
        c.dim(&format!("fingerprint {fp}"))
    );
    Ok(0)
}

/// Walk someone through scoping a session. Ports
/// `sessionWizard(control, { cred })` in `src/cli/wizards.js`.
pub async fn session_wizard(ctx: &Context, preset: Option<&str>) -> Outcome {
    use crate::prompt::{self, Choice, TextOptions};
    let creds_value = ctx.control("GET", "/v1/credentials", None).await?;
    let creds = creds_value.as_array().cloned().unwrap_or_default();
    if creds.is_empty() {
        return Err(crate::policy_input::usage(
            "no credentials yet; run \"agent-vault cred add\" first",
        ));
    }
    prompt::step(1, 5, "Which credential?");
    let slug = if let Some(preset) = preset {
        preset.to_string()
    } else {
        let choices: Vec<Choice<String>> = creds
            .iter()
            .map(|c| {
                let slug = c.get("slug").and_then(|s| s.as_str()).unwrap_or("");
                let kind = c.get("kind").and_then(|s| s.as_str()).unwrap_or("");
                let host = c
                    .pointer("/connector/host")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                Choice {
                    value: slug.to_string(),
                    label: slug.to_string(),
                    hint: Some(format!("{kind} · {host}")),
                }
            })
            .collect();
        prompt::select("Credential", &choices, 0)?
    };
    let cred = creds
        .iter()
        .find(|c| c.get("slug").and_then(|s| s.as_str()) == Some(slug.as_str()))
        .cloned()
        .ok_or_else(|| crate::policy_input::usage(format!("no credential named {slug}")))?;
    let kind = cred
        .get("kind")
        .and_then(|s| s.as_str())
        .unwrap_or("http")
        .to_string();
    prompt::step(2, 5, "What should the agent be able to do?");
    let access_choices: Vec<Choice<String>> = ACCESS_LEVELS
        .iter()
        .map(|l| Choice {
            value: l.key.to_string(),
            label: l.label.to_string(),
            hint: Some(l.hint.to_string()),
        })
        .collect();
    let access = prompt::select("Access", &access_choices, 0)?;
    if access == "full" {
        prompt::note(&[
            "Nothing will pause for you. The budget and the expiry are the only limits.",
        ]);
        if !prompt::confirm("Are you sure?", false)? {
            return Err(prompt::cancelled());
        }
    }
    prompt::step(3, 5, "How much of it?");
    let scope_choices: Vec<Choice<String>> = scope_presets(&kind)
        .into_iter()
        .map(|(v, l, h)| Choice {
            value: v.to_string(),
            label: l.to_string(),
            hint: h.map(|s| s.to_string()),
        })
        .collect();
    let scope = prompt::select("Scope", &scope_choices, 0)?;
    let detail = if scope == "repo" {
        Some(prompt::text(
            "Repository",
            TextOptions {
                placeholder: Some("owner/name"),
                validate: Some(&|v| {
                    if repo_ok(v) {
                        None
                    } else {
                        Some("use the owner/name form".into())
                    }
                }),
                ..TextOptions::default()
            },
        )?)
    } else if scope == "owner" {
        Some(prompt::text(
            "Owner",
            TextOptions {
                placeholder: Some("an org or user name"),
                ..TextOptions::default()
            },
        )?)
    } else if scope == "custom" {
        prompt::note(&["Comma separated. * matches one path segment, ** matches many."]);
        Some(prompt::text(
            "Paths",
            TextOptions {
                default_value: Some("/**"),
                ..TextOptions::default()
            },
        )?)
    } else {
        None
    };
    let paths = paths_for_scope(&kind, &scope, detail.as_deref());
    prompt::step(4, 5, "Limits");
    let budget_rows = budget_choices(&kind);
    let budget_choices_ui: Vec<Choice<Option<u64>>> = budget_rows
        .iter()
        .map(|(v, l, h)| Choice {
            value: *v,
            label: (*l).to_string(),
            hint: h.map(|s| s.to_string()),
        })
        .collect();
    let mut budget = prompt::select("Budget", &budget_choices_ui, 0)?;
    if budget.is_none() {
        let text = prompt::text(
            "How many requests?",
            TextOptions {
                default_value: Some("500"),
                validate: Some(&|v| {
                    if v.chars().all(|c| c.is_ascii_digit())
                        && v.parse::<u64>().ok().filter(|n| *n > 0).is_some()
                    {
                        None
                    } else {
                        Some("a whole number greater than zero".into())
                    }
                }),
                ..TextOptions::default()
            },
        )?;
        budget = text.parse().ok();
    }
    let ttl_choices = vec![
        Choice {
            value: "8".to_string(),
            label: "8 hours".into(),
            hint: Some("a working day".into()),
        },
        Choice {
            value: "1".to_string(),
            label: "1 hour".into(),
            hint: Some("a quick task".into()),
        },
        Choice {
            value: "24".to_string(),
            label: "24 hours".into(),
            hint: None,
        },
        Choice {
            value: NO_EXPIRY.into(),
            label: "No expiry (asks for your passphrase)".into(),
            hint: Some("lasts until you revoke it".into()),
        },
    ];
    let ttl_hours = prompt::select("Expires in", &ttl_choices, 0)?;
    prompt::step(5, 5, "Confirm");
    let policy = build_policy(&PolicyAnswers {
        kind: kind.clone(),
        access: access.clone(),
        paths: paths.clone(),
        budget,
        ttl_hours: Some(ttl_hours),
    })
    .map_err(crate::policy_input::usage)?;
    let methods = policy
        .get("methods")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let path_text = policy
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n                  ")
        })
        .unwrap_or_default();
    let budget_text = format!(
        "{} requests",
        policy.get("budget").and_then(|v| v.as_u64()).unwrap_or(0)
    );
    let writes = if policy.get("approval").and_then(|v| v.as_str()) == Some("on-write") {
        "ask me first"
    } else {
        "no approval"
    };
    let expires = if policy.get("infinite").and_then(|v| v.as_bool()) == Some(true) {
        "never; revoke it when you are done".to_string()
    } else {
        format!(
            "{}h from now",
            policy
                .get("ttl_hours")
                .and_then(|v| v.as_u64())
                .unwrap_or(8)
        )
    };
    prompt::summary(
        "About to create",
        &[
            ("credential", slug.as_str()),
            ("can call", methods.as_str()),
            ("on paths", path_text.as_str()),
            ("budget", budget_text.as_str()),
            ("writes", writes),
            ("expires", expires.as_str()),
        ],
    );
    if !prompt::confirm("Create the session?", true)? {
        return Err(prompt::cancelled());
    }
    let mut body = serde_json::Map::new();
    body.insert("cred".into(), Value::from(slug.clone()));
    body.insert("label".into(), Value::from(format!("{slug} {access}")));
    if let Some(v) = policy.get("methods") {
        body.insert("methods".into(), v.clone());
    }
    if let Some(v) = policy.get("paths") {
        body.insert("paths".into(), v.clone());
    }
    if let Some(v) = policy.get("budget") {
        body.insert("budget".into(), v.clone());
    }
    if let Some(v) = policy.get("approval") {
        body.insert("approval".into(), v.clone());
    }
    if policy.get("infinite").and_then(|v| v.as_bool()) == Some(true) {
        body.insert("infinite".into(), Value::Bool(true));
    } else if let Some(v) = policy.get("ttl_hours") {
        body.insert("ttl_hours".into(), v.clone());
    }
    let session = ctx
        .control_with_presence("POST", "/v1/sessions", Some(&Value::Object(body)))
        .await?;
    let c = prompt::Colors::detect();
    let sid = session
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!("\n{} {}", c.green("session created"), c.dim(sid));
    println!("\n  {}\n", c.bold("Give the agent these two things:"));
    let base = session
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let placeholder = session
        .get("placeholder")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!("    base url     {}", c.cyan(base));
    println!("    placeholder  {}\n", c.cyan(placeholder));
    println!(
        "  {}",
        c.dim("It puts the placeholder here, and nowhere else:")
    );
    if let Some(usage) = session.get("usage").and_then(|v| v.as_array()) {
        for u in usage {
            if let Some(s) = u.as_str() {
                println!("    {s}");
            }
        }
    }
    println!("\n  {}", c.dim("Or hand it the whole environment:"));
    println!("    {}", c.cyan("eval \"$(agent-vault env)\""));
    if let Some(lint) = session.get("lint").and_then(|v| v.as_array()) {
        for problem in lint {
            let level = problem.get("level").and_then(|v| v.as_str()).unwrap_or("");
            let message = problem
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tag = if level == "error" {
                c.red("lint")
            } else {
                c.yellow("lint")
            };
            println!("  {tag} {message}");
        }
    }
    let _ = crate::remember_created(&session);
    Ok(0)
}

/// Credential, session, and what to give the agent. Ports
/// `quickstart(control)` in `src/cli/wizards.js`.
pub async fn quickstart(ctx: &Context) -> Outcome {
    use crate::prompt::{self, Choice};
    let c = prompt::Colors::detect();
    println!("\n{}", c.bold("agent-vault quickstart"));
    prompt::note(&["Three steps: store a credential, scope a session, hand it to your agent."]);
    let creds_value = ctx.control("GET", "/v1/credentials", None).await?;
    let creds = creds_value.as_array().cloned().unwrap_or_default();
    let mut chosen: Option<String> = None;
    if !creds.is_empty() {
        let names = creds
            .iter()
            .filter_map(|c| c.get("slug").and_then(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        if prompt::confirm(
            &format!("Use a credential you already have ({names})?"),
            true,
        )? {
            if creds.len() == 1 {
                chosen = creds
                    .first()
                    .and_then(|c| c.get("slug").and_then(|s| s.as_str()))
                    .map(|s| s.to_string());
            } else {
                let choices: Vec<Choice<String>> = creds
                    .iter()
                    .map(|row| {
                        let slug = row.get("slug").and_then(|s| s.as_str()).unwrap_or("");
                        let kind = row.get("kind").and_then(|s| s.as_str()).unwrap_or("");
                        Choice {
                            value: slug.to_string(),
                            label: slug.to_string(),
                            hint: Some(kind.to_string()),
                        }
                    })
                    .collect();
                chosen = Some(prompt::select("Which one?", &choices, 0)?);
            }
        }
    }
    let slug = if let Some(slug) = chosen {
        slug
    } else {
        credential_wizard(ctx, None).await?;
        return finish_after_new_cred(ctx).await;
    };
    session_wizard(ctx, Some(&slug)).await?;
    println!(
        "\n{}  {} {}",
        c.green("ready"),
        c.dim("watch what the agent does with:"),
        c.cyan("agent-vault audit tail")
    );
    Ok(0)
}

async fn finish_after_new_cred(ctx: &Context) -> Outcome {
    let creds = ctx.control("GET", "/v1/credentials", None).await?;
    let slug = creds
        .as_array()
        .and_then(|a| a.last())
        .and_then(|c| c.get("slug"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    session_wizard(ctx, Some(&slug)).await?;
    let c = crate::prompt::Colors::detect();
    println!(
        "\n{}  {} {}",
        c.green("ready"),
        c.dim("watch what the agent does with:"),
        c.cyan("agent-vault audit tail")
    );
    Ok(0)
}
