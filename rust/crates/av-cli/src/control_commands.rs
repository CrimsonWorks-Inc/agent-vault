//! Control-plane commands. Authentication remains the daemon's decision;
//! every widening call uses the same presence flow as session creation.
//! Ports `src/cli/control-commands.js`: each key of the object
//! `controlCommands(ctx)` returns is one function here.

use std::io::IsTerminal;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use av_core::errors::Exit;
use av_core::model_usage::PRICES_VERSION;
use av_core::secret::ExposeSecret;
use av_store::client_state::{self, state_dir};

use crate::cli::{
    AuditExportArgs, AuditVerifyArgs, AuditWitnessArgs, BackupExportArgs, BackupFileArg,
    BackupRestoreArgs, CredExpiryArgs, CredPinArgs, CredQuarantineArgs, CredRotateArgs,
    CredScrubArgs, CredTestArgs, NameArg, NotifySetArgs, PanicArgs, PreflightArgs, ReportArgs,
    SessionNarrowArgs, SessionShowArgs, SlugArg, TemplateSaveArgs, TripwireSetArgs,
};
use crate::files::{self, FileError};
use crate::policy_input::{
    self, boolean_flag, expiry_input, grant_input, json_number, known_flags, list_flag,
    number_flag, read_json, session_given, session_input, text_flag, usage, NumberLimits,
    GRANT_FLAGS,
};
use crate::{client_state_path, CliError, Context, Outcome};

/// The `cred scrub --help` text. Ports `SCRUB_HELP` in
/// `src/cli/control-commands.js`.
pub const SCRUB_HELP: &str = "cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]
  Patterns are 3\u{2013}256 characters, with at most 16 alternation branches.
  Start each branch with at least 3 literal characters. Atoms may be literals,
  escaped characters or classes. Exact {n} quantifiers are allowed before the
  optional variable quantifier: at most one ? or {n,m} with n < m per branch,
  and only literal characters after it. Bounds are at most 256 and the maximum
  match length is 512. No *, +, {n,}, groups, backreferences, lookarounds or
  anchors. Patterns matching ordinary text, secrets or placeholders are refused.
  Request-name safety (C15/C16): query, form, multipart names and top-level JSON
  keys must be nonempty ASCII without controls or surrounding whitespace.
  Non-JSON names must start with a letter, digit, _, -, . or $. Array syntax
  a[], a[n], a[k] is a list; single-value rules check every element. Ambiguous
  spellings are refused as request_ambiguous; scrub patterns do not change that.";

/// Remove C0/C1 controls (keeping `\t` and `\n`), bidi embeddings,
/// overrides and isolates (U+202A-202E, U+2066-2069) and U+2028/2029. Ports
/// `cleanText(value)` in `src/cli/control-commands.js`.
pub fn clean_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let u = ch as u32;
        let drop = u <= 0x08
            || (0x0b..=0x1f).contains(&u)
            || (0x7f..=0x9f).contains(&u)
            || (0x202a..=0x202e).contains(&u)
            || (0x2066..=0x2069).contains(&u)
            || u == 0x2028
            || u == 0x2029;
        if !drop {
            out.push(ch);
        }
    }
    out
}

/// Terminal lines for the daemon's scrubbed, still-untrusted preview of a
/// held request. Ports `approvalPreviewLines(p, full)` in
/// `src/cli/control-commands.js`.
pub fn approval_preview_lines(preview: &Value, full: bool) -> Vec<String> {
    let kind = preview
        .get("content_type")
        .and_then(js_present_str)
        .or_else(|| {
            preview
                .get("body")
                .and_then(|b| b.get("kind"))
                .and_then(js_present_str)
        })
        .unwrap_or("none");
    let bytes = preview
        .get("body")
        .and_then(|b| b.get("bytes"))
        .map(js_or_zero)
        .unwrap_or_else(|| "0".into());
    let mut lines = vec![format!("  sends: {} · {bytes} bytes", clean_text(kind))];
    if full {
        for key in ["query", "headers", "placeholders"] {
            let value = match preview.get(key) {
                Some(v) if js_truthy(v) => v.clone(),
                _ => Value::Array(Vec::new()),
            };
            lines.push(format!("    {key}: {}", clean_text(&value.to_string())));
        }
    }
    let body = clean_text(
        preview
            .get("body")
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or(""),
    );
    let shown: Vec<String> = if full {
        let raw = body.as_bytes();
        let cut = raw.len().min(4096);
        String::from_utf8_lossy(&raw[..cut])
            .split('\n')
            .map(str::to_string)
            .collect()
    } else {
        body.split('\n').take(6).map(str::to_string).collect()
    };
    for line in shown {
        lines.push(format!("    {line}"));
    }
    lines.push("  (written by the agent, not verified)".into());
    lines
}

/// Ports `'cred:rotate'` in `src/cli/control-commands.js`.
pub async fn cred_rotate(ctx: &Context, args: &CredRotateArgs) -> Outcome {
    let slug = text_flag(args.slug.as_deref(), "credential")?;
    let mode = if boolean_flag(args.revoke.then_some(""), "revoke")? {
        "revoke"
    } else {
        "keep"
    };
    let mut body = Map::new();
    body.insert("slug".into(), Value::from(slug));
    let value = ctx.read_secret(&format!("new value for {slug} (not echoed): "))?;
    if value.expose_secret().is_empty() {
        return Err(usage("no value given"));
    }
    body.insert(
        "value".into(),
        Value::from(value.expose_secret().to_string()),
    );
    body.insert("mode".into(), Value::from(mode));
    if let Some(field) = args.field.as_deref() {
        body.insert(
            "field".into(),
            Value::from(text_flag(Some(field), "--field")?),
        );
    }
    if let Some(hours) = args.retire_hours.as_deref() {
        let n = number_flag(
            Some(hours),
            "--retire-hours",
            NumberLimits {
                max: 168.0,
                ..NumberLimits::default()
            },
        )?;
        body.insert("retire_hours".into(), json_number(n));
    }
    if args.expires.is_some() {
        let expires = expiry_input(args.expires.as_deref())?;
        body.insert(
            "expires_at".into(),
            expires.map(Value::from).unwrap_or(Value::Null),
        );
    }
    let r = ctx
        .control_with_presence("POST", "/v1/credentials/rotate", Some(&Value::Object(body)))
        .await?;
    let rotated = r.get("rotated").cloned().unwrap_or(Value::Null);
    let detail = if mode == "revoke" {
        format!(
            "{} grants revoked",
            js_interp(rotated.get("revoked_grants"))
        )
    } else {
        format!(
            "sessions keep working; the old value is still scrubbed until {}",
            js_interp(rotated.get("retire_until"))
        )
    };
    let human = format!(
        "{} {slug} {}\n  {detail}\n  {} held requests were denied",
        ctx.paint("32", "rotated"),
        ctx.paint(
            "2",
            &format!(
                "v{}, fingerprint {} → {}",
                js_interp(rotated.get("version")),
                js_interp(rotated.get("previous_fp8")),
                js_interp(rotated.get("fp8"))
            )
        ),
        js_interp(r.get("invalidated_approvals"))
    );
    output(ctx, &r, &human);
    if let Some(warnings) = r.get("warnings").and_then(|w| w.as_array()) {
        for warning in warnings {
            if let Some(text) = warning.as_str() {
                note(ctx, text);
            }
        }
    }
    Ok(0)
}

/// Ports `'cred:expiry'` in `src/cli/control-commands.js`.
pub async fn cred_expiry(ctx: &Context, args: &CredExpiryArgs) -> Outcome {
    let slug = text_flag(args.slug.as_deref(), "credential")?;
    let expires = expiry_input(args.date.as_deref())?;
    let mut body = Map::new();
    body.insert("slug".into(), Value::from(slug));
    body.insert(
        "expires_at".into(),
        expires.map(Value::from).unwrap_or(Value::Null),
    );
    let r = ctx
        .control_with_presence("POST", "/v1/credentials/expiry", Some(&Value::Object(body)))
        .await?;
    let when = r
        .get("expires_at")
        .and_then(js_present_str)
        .unwrap_or("none");
    output(
        ctx,
        &r,
        &format!(
            "{} {}  {when}",
            ctx.paint("32", "expiry set"),
            js_interp(r.get("slug"))
        ),
    );
    Ok(0)
}

/// Ports `'cred:scrub'` in `src/cli/control-commands.js`.
pub async fn cred_scrub(ctx: &Context, args: &CredScrubArgs) -> Outcome {
    let slug = text_flag(args.slug.as_deref(), "credential")?;
    if !args.add.is_empty() && args.rm.is_some() {
        return Err(usage("--add and --rm cannot be combined"));
    }
    if args.sample.is_some() && args.add.is_empty() {
        return Err(usage("--sample requires --add"));
    }
    if !args.add.is_empty() {
        let mut results = Vec::new();
        for pattern in &args.add {
            let mut body = Map::new();
            body.insert("slug".into(), Value::from(slug));
            body.insert(
                "pattern".into(),
                Value::from(text_flag(Some(pattern), "--add")?),
            );
            if args.sample.is_some() {
                body.insert(
                    "sample".into(),
                    Value::from(text_flag(args.sample.as_deref(), "--sample")?),
                );
            }
            results.push(
                ctx.control_with_presence(
                    "POST",
                    "/v1/credentials/scrub",
                    Some(&Value::Object(body)),
                )
                .await?,
            );
        }
        let human = results
            .iter()
            .map(scrub_line)
            .collect::<Vec<_>>()
            .join("\n");
        let data = if results.len() == 1 {
            results[0].clone()
        } else {
            Value::Array(results)
        };
        output(ctx, &data, &human);
        return Ok(0);
    }
    if args.rm.is_some() {
        let id = text_flag(args.rm.as_deref(), "--rm")?;
        let path = format!(
            "/v1/credentials/scrub?{}",
            query(&[("slug", Some(slug)), ("id", Some(id))])
        );
        let r = ctx.control_with_presence("DELETE", &path, None).await?;
        output(ctx, &r, "scrub pattern removed");
        return Ok(0);
    }
    let cred = credential(ctx, slug).await?;
    let patterns = cred
        .get("scrub_patterns")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let human = if patterns.is_empty() {
        "no scrub patterns".into()
    } else {
        patterns
            .iter()
            .map(|p| {
                format!(
                    "{}  {}  added {}",
                    js_interp(p.get("id")),
                    js_interp(p.get("source")),
                    js_interp(p.get("added_at"))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    output(ctx, &Value::Array(patterns), &human);
    Ok(0)
}

/// Ports `'cred:pin'` in `src/cli/control-commands.js`.
pub async fn cred_pin(ctx: &Context, args: &CredPinArgs) -> Outcome {
    let slug = text_flag(args.slug.as_deref(), "credential")?;
    let host = text_flag(args.host.as_deref(), "--host")?;
    let choices = usize::from(!args.add.is_empty())
        + usize::from(args.rm.is_some())
        + usize::from(args.clear);
    if choices > 1 {
        return Err(usage("choose --add, --rm or --clear"));
    }
    let _ = boolean_flag(args.clear.then_some(""), "clear")?;
    let live = boolean_flag(args.live.then_some(""), "live")?;
    if live {
        let pins = fetch_chain_pins(host)?;
        let human = format!(
            "{}\nverify these out of band before pinning",
            pins.iter()
                .map(|p| format!(
                    "{}  {}  expires {}",
                    show(p.get("subject").unwrap_or(&Value::Null)),
                    js_interp(p.get("spki")),
                    js_interp(p.get("not_after"))
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        if args.add.is_empty() && args.rm.is_none() && !args.clear {
            output(ctx, &Value::Array(pins), &human);
            return Ok(0);
        }
        if !ctx.json {
            note(ctx, &human);
        }
    }
    if !args.add.is_empty() {
        let pins: Result<Vec<String>, CliError> = args
            .add
            .iter()
            .map(|p| text_flag(Some(p), "--add").map(str::to_string))
            .collect();
        let mut body = Map::new();
        body.insert("slug".into(), Value::from(slug));
        body.insert("host".into(), Value::from(host));
        body.insert(
            "pins".into(),
            Value::Array(pins?.into_iter().map(Value::from).collect()),
        );
        let r = ctx
            .control_with_presence("POST", "/v1/credentials/pins", Some(&Value::Object(body)))
            .await?;
        output(ctx, &r, &format!("pinned {slug} {host}"));
        return Ok(0);
    }
    if args.rm.is_some() || args.clear {
        let spki = args
            .rm
            .as_deref()
            .map(|v| text_flag(Some(v), "--rm"))
            .transpose()?;
        let path = format!(
            "/v1/credentials/pins?{}",
            query(&[("slug", Some(slug)), ("host", Some(host)), ("spki", spki)])
        );
        let r = ctx.control_with_presence("DELETE", &path, None).await?;
        output(ctx, &r, &format!("pins removed {slug} {host}"));
        return Ok(0);
    }
    let cred = credential(ctx, slug).await?;
    let pins = cred
        .get("pins")
        .and_then(|p| p.get(host))
        .filter(|v| js_truthy(v))
        .cloned()
        .unwrap_or(json!(0));
    let shown = show(&pins);
    output(
        ctx,
        &json!({ "slug": slug, "host": host, "pins": pins }),
        &format!("{slug}  pinned: {host} ({shown})"),
    );
    Ok(0)
}

/// Ports `'cred:test'` in `src/cli/control-commands.js`.
pub async fn cred_test(ctx: &Context, args: &CredTestArgs) -> Outcome {
    let all = boolean_flag(args.all.then_some(""), "all")?;
    let named = args.slug.as_deref().is_some_and(|s| !s.is_empty());
    if named == all {
        return Err(usage("usage: agent-vault cred test <slug> | --all"));
    }
    let body = if all {
        json!({ "all": true })
    } else {
        json!({ "slug": text_flag(args.slug.as_deref(), "credential")? })
    };
    let r = ctx
        .control("POST", "/v1/credentials/test", Some(&body))
        .await?;
    let results: Vec<Value> = if all {
        r.get("results")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    } else {
        let mut row = Map::new();
        row.insert(
            "slug".into(),
            Value::from(args.slug.clone().unwrap_or_default()),
        );
        if let Value::Object(map) = r.clone() {
            for (k, v) in map {
                row.insert(k, v);
            }
        }
        vec![Value::Object(row)]
    };
    let human = results
        .iter()
        .map(|v| {
            let ok = v.get("ok") == Some(&Value::Bool(true));
            let skipped = all && v.get("rule").and_then(|r| r.as_str()) == Some("no_probe");
            let mark = if ok {
                ctx.paint("32", "ok  ")
            } else if skipped {
                ctx.paint("2", "skip")
            } else {
                ctx.paint("33", "warn")
            };
            let slug = v.get("slug").and_then(|s| s.as_str()).unwrap_or("");
            let detail = if skipped {
                "no probe for this kind".to_string()
            } else if let Some(error) = js_or_text(v.get("error")) {
                error
            } else {
                let scopes = v
                    .get("scopes")
                    .and_then(|s| s.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|s| js_interp(Some(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                format!(
                    "{} · {}ms · scopes: {scopes}",
                    js_interp(v.get("http_status")),
                    js_interp(v.get("latency_ms"))
                )
            };
            format!("{mark} {slug:<26} {detail}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    output(ctx, &r, &human);
    let failing = results.iter().filter(|v| {
        let ok = v.get("ok") == Some(&Value::Bool(true));
        let skipped = all && v.get("rule").and_then(|r| r.as_str()) == Some("no_probe");
        !ok && !skipped
    });
    let mut any = false;
    let mut policy = false;
    for v in failing {
        any = true;
        if matches!(
            v.get("error").and_then(|e| e.as_str()),
            Some("AV_QUOTA_EXCEEDED" | "AV_QUARANTINED")
        ) {
            policy = true;
        }
    }
    if any {
        Ok(if policy {
            Exit::PolicyDenied.code()
        } else {
            Exit::Upstream.code()
        })
    } else {
        Ok(0)
    }
}

/// Ports `'cred:quarantine'` in `src/cli/control-commands.js`.
pub async fn cred_quarantine(ctx: &Context, args: &CredQuarantineArgs) -> Outcome {
    let mut body = Map::new();
    body.insert(
        "slug".into(),
        Value::from(text_flag(args.slug.as_deref(), "credential")?),
    );
    if args.reason.is_some() {
        body.insert(
            "reason".into(),
            Value::from(text_flag(args.reason.as_deref(), "--reason")?),
        );
    }
    let r = ctx
        .control(
            "POST",
            "/v1/credentials/quarantine",
            Some(&Value::Object(body)),
        )
        .await?;
    output(
        ctx,
        &r,
        &format!(
            "{} {} · {} held requests denied",
            ctx.paint("33", "quarantined"),
            js_interp(r.get("slug")),
            js_interp(r.get("denied_approvals"))
        ),
    );
    Ok(0)
}

/// Ports `'cred:release'` in `src/cli/control-commands.js`.
pub async fn cred_release(ctx: &Context, args: &SlugArg) -> Outcome {
    let body = json!({ "slug": text_flag(args.slug.as_deref(), "credential")? });
    let r = ctx
        .control_with_presence("POST", "/v1/credentials/release", Some(&body))
        .await?;
    output(
        ctx,
        &r,
        &format!(
            "{} {}",
            ctx.paint("32", "released"),
            js_interp(r.get("slug"))
        ),
    );
    Ok(0)
}

/// Ports `panic` in `src/cli/control-commands.js`.
pub async fn panic(ctx: &Context, args: &PanicArgs) -> Outcome {
    let lock = boolean_flag(args.lock.then_some(""), "lock")?;
    let mut body = Map::new();
    body.insert("lock".into(), Value::Bool(lock));
    if args.reason.is_some() {
        body.insert(
            "reason".into(),
            Value::from(text_flag(args.reason.as_deref(), "--reason")?),
        );
    }
    let r = ctx
        .control("POST", "/v1/panic", Some(&Value::Object(body)))
        .await?;
    let locked = r.get("locked") == Some(&Value::Bool(true));
    output(
        ctx,
        &r,
        &format!(
            "{} {} sessions revoked · {} held requests denied · {} session requests denied{}",
            ctx.paint("31", "panic"),
            js_or_zero_text(r.get("revoked_sessions")),
            js_or_zero_text(r.get("denied_approvals")),
            js_nullish(r.get("denied_session_requests"), "unknown"),
            if locked { " · vault locked" } else { "" }
        ),
    );
    if r.get("already") == Some(&Value::Bool(true)) {
        Ok(Exit::Locked.code())
    } else {
        Ok(0)
    }
}

/// Ports `'tripwire:show'` in `src/cli/control-commands.js`.
pub async fn tripwire_show(ctx: &Context) -> Outcome {
    let r = ctx.control("GET", "/v1/tripwires", None).await?;
    let rules_arr = r.get("rules").and_then(|v| v.as_array());
    let saved = rules_arr.is_some() && r.get("rules_saved") != Some(&Value::Bool(false));
    let rules = rules_arr
        .cloned()
        .or_else(|| r.get("defaults").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default();
    let enabled = r.get("enabled") == Some(&Value::Bool(true));
    let which = if saved {
        ""
    } else if enabled {
        " (the default rules)"
    } else {
        " (the default rules, used when you turn them on)"
    };
    let listed = if rules.is_empty() {
        "no rules".into()
    } else {
        rules
            .iter()
            .map(|v| {
                let codes = v
                    .get("codes")
                    .and_then(|c| c.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .filter(|s| !s.is_empty());
                let match_on = codes.unwrap_or_else(|| js_interp(v.get("rule_prefix")));
                format!(
                    "{}  {match_on}  {} in {}s  → {}",
                    js_interp(v.get("id")),
                    js_interp(v.get("threshold")),
                    js_interp(v.get("window_s")),
                    js_interp(v.get("action"))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    output(
        ctx,
        &r,
        &format!(
            "tripwires {}{which}\n{listed}",
            if enabled { "on" } else { "off" }
        ),
    );
    Ok(0)
}

/// Ports `'tripwire:on'` in `src/cli/control-commands.js`.
pub async fn tripwire_on(ctx: &Context) -> Outcome {
    let current = ctx.control("GET", "/v1/tripwires", None).await?;
    let stored = current.get("rules_saved") != Some(&Value::Bool(false))
        && current
            .get("rules")
            .and_then(|r| r.as_array())
            .is_some_and(|a| !a.is_empty());
    let mut body = Map::new();
    body.insert("enabled".into(), Value::Bool(true));
    if !stored {
        body.insert("rules".into(), Value::from("defaults"));
    }
    let r = ctx
        .control_with_presence("POST", "/v1/tripwires", Some(&Value::Object(body)))
        .await?;
    output(ctx, &r, "tripwires on");
    Ok(0)
}

/// Ports `'tripwire:off'` in `src/cli/control-commands.js`.
pub async fn tripwire_off(ctx: &Context) -> Outcome {
    let body = json!({ "enabled": false });
    let r = ctx
        .control_with_presence("POST", "/v1/tripwires", Some(&body))
        .await?;
    output(ctx, &r, "tripwires off");
    Ok(0)
}

/// Ports `'tripwire:set'` in `src/cli/control-commands.js`.
pub async fn tripwire_set(ctx: &Context, args: &TripwireSetArgs) -> Outcome {
    let id = text_flag(args.rule.as_deref(), "--rule")?;
    let window = text_flag(args.window.as_deref(), "--window")?;
    let Some((count, unit)) = parse_duration(window) else {
        return Err(usage("--window must be a duration such as 10m"));
    };
    let mult = match unit {
        's' => 1.0,
        'm' => 60.0,
        'h' => 3600.0,
        'd' => 86400.0,
        _ => 0.0,
    };
    let seconds = format!("{}", (count as f64 * mult) as i64);
    let window_s = number_flag(
        Some(&seconds),
        "--window",
        NumberLimits {
            min: 10.0,
            max: 86400.0,
            integer: true,
        },
    )?;
    let action = args.action.as_deref().unwrap_or("");
    if !matches!(action, "revoke_session" | "quarantine_credential" | "panic") {
        return Err(usage("invalid --action"));
    }
    if args.codes.is_some() == args.rule_prefix.is_some() {
        return Err(usage("choose --codes or --rule-prefix"));
    }
    let mut rule = Map::new();
    rule.insert("id".into(), Value::from(id));
    rule.insert(
        "threshold".into(),
        json_number(number_flag(
            args.threshold.as_deref(),
            "--threshold",
            NumberLimits {
                min: 1.0,
                max: 1000.0,
                integer: true,
            },
        )?),
    );
    rule.insert("window_s".into(), json_number(window_s));
    rule.insert("action".into(), Value::from(action));
    if args.codes.is_some() {
        rule.insert(
            "codes".into(),
            Value::Array(
                list_flag(args.codes.as_deref(), "--codes")?
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        );
    } else {
        rule.insert(
            "rule_prefix".into(),
            Value::from(text_flag(args.rule_prefix.as_deref(), "--rule-prefix")?),
        );
    }
    let current = ctx.control("GET", "/v1/tripwires", None).await?;
    let existing = current
        .get("rules")
        .filter(|v| js_truthy(v))
        .or_else(|| current.get("defaults"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rules: Vec<Value> = existing
        .into_iter()
        .filter(|v| v.get("id").and_then(|i| i.as_str()) != Some(id))
        .collect();
    rules.push(Value::Object(rule));
    let body = json!({ "rules": rules });
    let r = ctx
        .control_with_presence("POST", "/v1/tripwires", Some(&body))
        .await?;
    output(ctx, &r, &format!("tripwire {id} set"));
    Ok(0)
}

/// Ports `'notify:set'` in `src/cli/control-commands.js`.
pub async fn notify_set(ctx: &Context, args: &NotifySetArgs) -> Outcome {
    let detail = args.detail.as_deref().unwrap_or("minimal");
    if detail != "minimal" && detail != "headline" {
        return Err(usage("--detail is minimal or headline"));
    }
    let webhook_url = ctx.read_secret("webhook URL (not echoed): ")?;
    if webhook_url.expose_secret().is_empty() {
        return Err(usage("no webhook URL given"));
    }
    let body = json!({
        "webhook_url": webhook_url.expose_secret(),
        "detail": detail,
    });
    let r = ctx
        .control_with_presence("POST", "/v1/notify", Some(&body))
        .await?;
    output(
        ctx,
        &r,
        &webhook_line(&r).unwrap_or_else(|| "no webhook".into()),
    );
    Ok(0)
}

/// Ports `'notify:show'` in `src/cli/control-commands.js`.
pub async fn notify_show(ctx: &Context) -> Outcome {
    let r = ctx.control("GET", "/v1/notify", None).await?;
    output(
        ctx,
        &r,
        &webhook_line(&r).unwrap_or_else(|| "no webhook".into()),
    );
    Ok(0)
}

/// Ports `'notify:off'` in `src/cli/control-commands.js`.
pub async fn notify_off(ctx: &Context) -> Outcome {
    let r = ctx.control("DELETE", "/v1/notify", None).await?;
    output(ctx, &r, "webhook off");
    Ok(0)
}

/// Ports `'notify:test'` in `src/cli/control-commands.js`.
pub async fn notify_test(ctx: &Context) -> Outcome {
    let r = ctx.control("POST", "/v1/notify/test", None).await?;
    output(ctx, &r, &pretty(&r));
    Ok(0)
}

/// Ports `'template:save'` in `src/cli/control-commands.js`.
pub async fn template_save(ctx: &Context, args: &TemplateSaveArgs) -> Outcome {
    let name = text_flag(args.name.as_deref(), "template name")?;
    let other = !session_given(&args.spec).is_empty() || !policy_input::extra_flags().is_empty();
    if args.from_file.is_some() && other {
        return Err(usage("--from-file cannot be combined with session flags"));
    }
    let spec = if args.from_file.is_some() {
        read_json(args.from_file.as_deref(), "--from-file")?
    } else {
        session_input(&args.spec)?
    };
    if !spec.is_object() {
        return Err(usage("template spec must be an object"));
    }
    let body = json!({ "name": name, "spec": spec });
    let r = ctx
        .control_with_presence("POST", "/v1/templates", Some(&body))
        .await?;
    output(
        ctx,
        &r,
        &format!(
            "{} template {} v{}",
            ctx.paint("32", "saved"),
            js_interp(r.get("name")),
            js_interp(r.get("version"))
        ),
    );
    if let Some(lint) = r.get("lint").and_then(|v| v.as_array()) {
        for item in lint {
            if let Some(message) = item.get("message").and_then(|m| m.as_str()) {
                note(ctx, message);
            }
        }
    }
    Ok(0)
}

/// Ports `'template:list'` in `src/cli/control-commands.js`.
pub async fn template_list(ctx: &Context) -> Outcome {
    let r = ctx.control("GET", "/v1/templates", None).await?;
    let rows = r.as_array().cloned().unwrap_or_default();
    let human = if rows.is_empty() {
        "no templates".into()
    } else {
        rows.iter()
            .map(|t| {
                let elevated = t
                    .get("elevated")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| !a.is_empty());
                let creds = t
                    .get("creds")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|c| js_interp(Some(c)))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                format!(
                    "{}  v{}  {} {}creds:{creds} updated:{}",
                    js_interp(t.get("name")),
                    js_interp(t.get("version")),
                    js_interp(t.get("summary")),
                    if elevated { "elevated " } else { "" },
                    js_interp(t.get("updated_at"))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    output(ctx, &r, &human);
    Ok(0)
}

/// Ports `'template:show'` in `src/cli/control-commands.js`.
pub async fn template_show(ctx: &Context, args: &NameArg) -> Outcome {
    let name = text_flag(args.name.as_deref(), "template name")?;
    let path = format!("/v1/templates?{}", query(&[("name", Some(name))]));
    let r = ctx.control("GET", &path, None).await?;
    output(ctx, &r, &pretty(&r));
    Ok(0)
}

/// Ports `'template:rm'` in `src/cli/control-commands.js`.
pub async fn template_rm(ctx: &Context, args: &NameArg) -> Outcome {
    let name = text_flag(args.name.as_deref(), "template name")?;
    let path = format!("/v1/templates?{}", query(&[("name", Some(name))]));
    let r = ctx.control("DELETE", &path, None).await?;
    output(ctx, &r, "template removed");
    Ok(0)
}

/// Ports `'session:narrow'` in `src/cli/control-commands.js`.
pub async fn session_narrow(ctx: &Context, args: &SessionNarrowArgs) -> Outcome {
    if args.grant.uses.is_some() {
        return Err(usage(
            "session narrow cannot change --uses; nothing was sent",
        ));
    }
    let mut given = narrow_given(args);
    for extra in policy_input::extra_flags() {
        if !given.iter().any(|g| g == &extra) {
            given.push(extra);
        }
    }
    let refs: Vec<&str> = given.iter().map(String::as_str).collect();
    let mut allowed: Vec<&str> = GRANT_FLAGS.to_vec();
    allowed.extend(["cred", "ttl"]);
    known_flags(&refs, &allowed, "session narrow")?;
    let sid = sid_of(args.sid.as_deref())?;
    let mut narrow = match grant_input(&args.grant)? {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    let grant_ttl = narrow.remove("grant_ttl_minutes");
    let session_ttl = if args.ttl.is_some() {
        Some(number_flag(
            args.ttl.as_deref(),
            "--ttl",
            NumberLimits {
                min: 1.0,
                ..NumberLimits::default()
            },
        )?)
    } else {
        None
    };
    if narrow.is_empty() && session_ttl.is_none() && grant_ttl.is_none() {
        return Err(usage("session narrow needs at least one limit"));
    }
    let mut body = Map::new();
    body.insert("sid".into(), Value::from(sid));
    if args.cred.is_some() {
        body.insert(
            "cred".into(),
            Value::from(text_flag(args.cred.as_deref(), "--cred")?),
        );
    }
    body.insert("narrow".into(), Value::Object(narrow));
    if let Some(n) = session_ttl {
        body.insert("session_ttl_minutes".into(), json_number(n));
    }
    if let Some(ttl) = grant_ttl {
        body.insert("grant_ttl_minutes".into(), ttl);
    }
    let r = ctx
        .control("POST", "/v1/sessions/narrow", Some(&Value::Object(body)))
        .await?;
    let grants = r
        .get("grants")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::new();
    for g in &grants {
        let changed = g
            .get("after")
            .and_then(|a| a.as_object())
            .map(|after| {
                after
                    .iter()
                    .filter(|(k, v)| {
                        g.get("before")
                            .and_then(|b| b.get(*k))
                            .map(|before| before != *v)
                            .unwrap_or(true)
                    })
                    .map(|(k, v)| {
                        format!(
                            "{k}: {} → {}",
                            show(
                                g.get("before")
                                    .and_then(|b| b.get(k))
                                    .unwrap_or(&Value::Null)
                            ),
                            show(v)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" · ")
            })
            .unwrap_or_default();
        let mut line = format!(
            "{} {}  {changed}",
            ctx.paint("32", "narrowed"),
            js_interp(g.get("cred"))
        );
        if let Some(expires) = g.get("expires_at").and_then(js_present_str) {
            line.push_str(&format!(" · expires {expires}"));
        }
        lines.push(line);
    }
    if session_ttl.is_some() {
        lines.push(format!("  expires {}", js_interp(r.get("expires_at"))));
    }
    output(ctx, &r, &lines.join("\n"));
    Ok(0)
}

/// Ports `'session:show'` in `src/cli/control-commands.js`.
pub async fn session_show(ctx: &Context, args: &SessionShowArgs) -> Outcome {
    let markdown = boolean_flag(args.markdown.then_some(""), "markdown")?;
    let sid = sid_of(args.sid.as_deref())?;
    let path = format!("/v1/sessions/detail?{}", query(&[("sid", Some(&sid))]));
    let r = ctx.control("GET", &path, None).await?;
    output(ctx, &r, &session_summary(&r, markdown));
    if !ctx.json && r.get("activity").and_then(|a| a.get("complete")) == Some(&Value::Bool(false)) {
        let text = r
            .get("activity")
            .and_then(|a| a.get("note"))
            .and_then(|n| n.as_str())
            .unwrap_or("history is incomplete");
        note(ctx, text);
    }
    Ok(0)
}

/// Ports `report` in `src/cli/control-commands.js`.
pub async fn report(ctx: &Context, args: &ReportArgs) -> Outcome {
    let markdown = boolean_flag(args.markdown.then_some(""), "markdown")?;
    let since = if args.since.is_some() {
        text_flag(args.since.as_deref(), "--since")?
    } else {
        "7d"
    };
    let path = format!("/v1/report/access?{}", query(&[("since", Some(since))]));
    let r = ctx.control("GET", &path, None).await?;
    output(ctx, &r, &report_summary(&r, markdown));
    if !ctx.json && r.get("complete") == Some(&Value::Bool(false)) {
        note(ctx, "history is incomplete");
    }
    Ok(0)
}

/// Ports `'backup:export'` in `src/cli/control-commands.js`.
pub async fn backup_export(ctx: &Context, args: &BackupExportArgs) -> Outcome {
    let path = text_flag(args.out.as_deref(), "--out")?;
    let force = boolean_flag(args.force.then_some(""), "force")?;
    let first = ctx.read_secret("recovery passphrase (not your vault passphrase): ")?;
    let again = ctx.read_secret("again: ")?;
    if first.expose_secret() != again.expose_secret() {
        return Err(usage("recovery passphrases differ"));
    }
    let body = json!({ "recovery_passphrase": first.expose_secret() });
    let r = ctx
        .control_with_presence("POST", "/v1/backup/export", Some(&body))
        .await?;
    let bundle = r.get("bundle").cloned().unwrap_or(Value::Null);
    let text = format!("{}\n", pretty(&bundle));
    let replaced = write_exclusive(ctx, path, &text, force).await?;
    if replaced {
        eprintln!("replaced {path}");
    }
    let mut data = Map::new();
    data.insert("path".into(), Value::from(path));
    if let Some(Value::Object(summary)) = r.get("summary") {
        for (k, v) in summary {
            data.insert(k.clone(), v.clone());
        }
    }
    if let Some(sha) = r.get("bundle_sha256") {
        data.insert("bundle_sha256".into(), sha.clone());
    }
    data.insert("mode".into(), Value::from("0600"));
    data.insert("replaced".into(), Value::Bool(replaced));
    let creds = r
        .get("summary")
        .and_then(|s| s.get("credentials"))
        .map(|v| js_interp(Some(v)))
        .unwrap_or_else(|| "undefined".into());
    output(
        ctx,
        &Value::Object(data),
        &format!(
            "{} {creds} credentials to {path} (encrypted; keep the recovery passphrase somewhere else)",
            ctx.paint("32", "backed up")
        ),
    );
    Ok(0)
}

/// Ports `'backup:inspect'` in `src/cli/control-commands.js`.
pub async fn backup_inspect(ctx: &Context, args: &BackupFileArg) -> Outcome {
    let input = backup_input(ctx, args.file.as_deref()).await?;
    let r = ctx
        .control("POST", "/v1/backup/inspect", Some(&input))
        .await?;
    output(ctx, &r, &credential_lines(&r));
    Ok(0)
}

/// Ports `'backup:restore'` in `src/cli/control-commands.js`.
pub async fn backup_restore(ctx: &Context, args: &BackupRestoreArgs) -> Outcome {
    let on_conflict = args.on_conflict.as_deref().unwrap_or("skip");
    if !matches!(on_conflict, "skip" | "rename" | "fail") {
        return Err(usage("--on-conflict is skip, rename or fail"));
    }
    let input = backup_input(ctx, args.file.as_deref()).await?;
    let inspection = ctx
        .control("POST", "/v1/backup/inspect", Some(&input))
        .await?;
    if std::io::stdin().is_terminal() && !ctx.json {
        println!("{}", clean_text(&credential_lines(&inspection)));
        let answer = ctx.ask(&format!(
            "Restore {} credentials? [y/N] ",
            inspection
                .get("credentials")
                .and_then(|c| c.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        ))?;
        let yes = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !yes {
            let data = json!({ "restored": [], "cancelled": true });
            output(ctx, &data, "restore cancelled");
            return Ok(0);
        }
    }
    let mut body = match input {
        Value::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("bundle".into(), other);
            map
        }
    };
    body.insert("on_conflict".into(), Value::from(on_conflict));
    let r = ctx
        .control_with_presence("POST", "/v1/backup/restore", Some(&Value::Object(body)))
        .await?;
    output(ctx, &r, &pretty(&r));
    Ok(0)
}

/// Ports `'audit:export'` in `src/cli/control-commands.js`.
pub async fn audit_export(ctx: &Context, args: &AuditExportArgs) -> Outcome {
    let mut since = if args.since_seq.is_some() {
        number_flag(
            args.since_seq.as_deref(),
            "--since-seq",
            NumberLimits::default(),
        )?
    } else {
        0.0
    };
    let follow = boolean_flag(args.follow.then_some(""), "follow")?;
    let force = boolean_flag(args.force.then_some(""), "force")?;
    if force && args.out.is_none() {
        return Err(usage("--force requires --out"));
    }
    if args.out.is_some() {
        text_flag(args.out.as_deref(), "--out")?;
    }
    let mut first = true;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    if follow {
        tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_millis(0)) => {}
            _ = &mut ctrl_c => return Ok(0),
        }
    }
    loop {
        let path = format!(
            "/v1/audit/export?{}",
            query(&[
                ("since_seq", Some(format!("{}", since as i64).as_str())),
                ("limit", Some("5000")),
            ])
        );
        let r = ctx.control("GET", &path, None).await?;
        let rows = r
            .get("rows")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if let Some(out) = args.out.as_deref() {
            if first {
                let mut text = rows
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                if !rows.is_empty() {
                    text.push('\n');
                }
                let replaced = write_exclusive(ctx, out, &text, force).await?;
                if replaced {
                    eprintln!("replaced {out}");
                }
            } else {
                for row in &rows {
                    append_exclusive(out, &row.to_string())?;
                }
            }
        } else if !ctx.json {
            for row in &rows {
                println!("{row}");
            }
        }
        if ctx.json {
            output(ctx, &r, &pretty(&r));
        }
        first = false;
        let previous = since;
        since = r
            .get("next_seq")
            .and_then(|v| v.as_f64())
            .unwrap_or(previous);
        if rows.len() >= 5000 && since > previous {
            continue;
        }
        if !follow {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = &mut ctrl_c => break,
        }
    }
    Ok(0)
}

/// Ports `'audit:witness'` in `src/cli/control-commands.js`.
pub async fn audit_witness(ctx: &Context, args: &AuditWitnessArgs) -> Outcome {
    let path = if let Some(out) = args.out.as_deref() {
        text_flag(Some(out), "--out")?.to_string()
    } else {
        let dir = state_dir();
        std::fs::create_dir_all(&dir).map_err(|e| io_err(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&dir) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(&dir, perms);
            }
        }
        dir.join("witness.jsonl").display().to_string()
    };
    let r = ctx.control("GET", "/v1/audit/checkpoint", None).await?;
    append_exclusive(&path, &r.to_string())?;
    let head = r
        .get("head")
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .chars()
        .take(16)
        .collect::<String>();
    output(
        ctx,
        &r,
        &format!(
            "{} record {}, head {head}\u{2026}",
            ctx.paint("32", "witnessed"),
            js_interp(r.get("seq"))
        ),
    );
    Ok(0)
}

/// Ports `'audit:verify'` in `src/cli/control-commands.js`. A broken chain
/// or witness is a failure envelope (`error.problem` holds the result),
/// never data inside `{ok:true}`.
pub async fn audit_verify(ctx: &Context, args: &AuditVerifyArgs) -> Outcome {
    let chain = ctx.control("GET", "/v1/audit/verify", None).await?;
    let witness = if let Some(path) = args.witness.as_deref() {
        let path = text_flag(Some(path), "--witness")?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| usage(format!("cannot read --witness: {}", errno_name(&e))))?;
        let mut checkpoints = Vec::new();
        for line in text.split('\n') {
            let line = line.trim_end_matches('\r').trim();
            if line.is_empty() {
                continue;
            }
            let row = serde_json::from_str::<Value>(line)
                .map_err(|_| usage("cannot read --witness: not JSONL"))?;
            checkpoints.push(row);
        }
        Some(
            ctx.control(
                "POST",
                "/v1/audit/verify-witness",
                Some(&json!({ "checkpoints": checkpoints })),
            )
            .await?,
        )
    } else {
        None
    };
    let chain_ok = chain.get("ok") == Some(&Value::Bool(true));
    let witness_ok = witness
        .as_ref()
        .is_none_or(|w| w.get("ok") == Some(&Value::Bool(true)));
    let ok = chain_ok && witness_ok;
    let result = if let Some(w) = &witness {
        let mut obj = match chain.clone() {
            Value::Object(map) => map,
            other => {
                let mut map = Map::new();
                map.insert("value".into(), other);
                map
            }
        };
        obj.insert("ok".into(), Value::Bool(ok));
        obj.insert("witness".into(), w.clone());
        Value::Object(obj)
    } else {
        chain.clone()
    };
    if !chain_ok {
        let message = if chain.get("brokenAt").is_some_and(js_truthy) {
            format!(
                "chain broken at record {}: {}",
                js_interp(chain.get("brokenAt")),
                js_interp(chain.get("reason"))
            )
        } else {
            format!(
                "the audit log cannot be trusted: {}",
                js_interp(chain.get("reason"))
            )
        };
        return fail_problem(ctx, &message, &result);
    }
    if let Some(w) = &witness {
        if w.get("ok") != Some(&Value::Bool(true)) {
            let message = format!(
                "the audit log does not match the witness: {} ahead of the log (records were removed) · {} mismatched · {} forged · {} other vault",
                arr_len(w, "ahead"),
                arr_len(w, "mismatched"),
                arr_len(w, "forged"),
                arr_len(w, "other_vault")
            );
            return fail_problem(ctx, &message, &result);
        }
    }
    let head = match chain.get("head") {
        Some(Value::String(s)) => s.chars().take(16).collect::<String>(),
        None | Some(Value::Null) => "undefined".into(),
        Some(other) => other.to_string(),
    };
    let mut human = format!(
        "chain intact {} records, head {head}...",
        js_interp(chain.get("count"))
    );
    if let Some(w) = &witness {
        human.push_str(&format!(
            "\nwitness ok {} checkpoints",
            js_interp(w.get("checked"))
        ));
    }
    output(ctx, &result, &human);
    Ok(0)
}

/// Ports `preflight` in `src/cli/control-commands.js`.
pub async fn preflight(ctx: &Context, args: &PreflightArgs) -> Outcome {
    let cred = text_flag(args.cred.as_deref(), "--cred")?;
    let method = text_flag(args.method.as_deref(), "--method")?.to_ascii_uppercase();
    let path = text_flag(args.path.as_deref(), "--path")?;
    if !is_slug(cred) || !path.starts_with('/') {
        return Err(usage("--cred must be a slug and --path must begin with /"));
    }
    let mut headers = Vec::new();
    for header in &args.header {
        let header = text_flag(Some(header), "--header")?;
        if header.contains('\r') || header.contains('\n') {
            return Err(usage("--header must be K: V without line breaks"));
        }
        let Some((name, value)) = split_header(header) else {
            return Err(usage("--header must be K: V without line breaks"));
        };
        headers.push(Value::Array(vec![Value::from(name), Value::from(value)]));
    }
    let st = client_state::load_state(&client_state_path());
    let Some(token) = st.token.clone() else {
        return Err(session_missing());
    };
    let state = crate::load_client_state();
    let port = ctx.gateway_port_of(&state);
    let mut body = Map::new();
    body.insert("method".into(), Value::from(method));
    body.insert("path".into(), Value::from(format!("/p/{cred}{path}")));
    body.insert("headers".into(), Value::Array(headers));
    body.insert("assume_placeholder".into(), Value::Bool(true));
    if args.query.is_some() {
        body.insert(
            "query".into(),
            Value::from(text_flag(args.query.as_deref(), "--query")?),
        );
    }
    if args.body_file.is_some() {
        let file = text_flag(args.body_file.as_deref(), "--body-file")?;
        let bytes = std::fs::read(file).map_err(|e| io_err(e.to_string()))?;
        body.insert("body_base64".into(), Value::from(base64_encode(&bytes)));
    }
    let r = gateway_preflight(port, &token, &Value::Object(body))?;
    let would = r.get("would").and_then(|v| v.as_str()).unwrap_or("");
    let mark = match would {
        "allow" => ctx.paint("32", "would allow"),
        "hold" => ctx.paint("33", "would hold for approval"),
        _ => ctx.paint("31", "would refuse"),
    };
    let checks = r
        .get("checks")
        .and_then(|c| c.as_array())
        .map(|rows| {
            rows.iter()
                .map(|v| {
                    let ok = v.get("ok") == Some(&Value::Bool(true));
                    format!(
                        "{} {:<26} {} {}",
                        if ok { "ok  " } else { "warn" },
                        v.get("stage").and_then(|s| s.as_str()).unwrap_or(""),
                        v.get("code").and_then(|s| s.as_str()).unwrap_or(""),
                        v.get("rule").and_then(|s| s.as_str()).unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    output(
        ctx,
        &r,
        &format!("{mark}\n{checks}\n{}", js_interp(r.get("advisory"))),
    );
    let code = match would {
        "allow" => 0,
        "hold" => Exit::Approval.code(),
        _ => Exit::PolicyDenied.code(),
    };
    Ok(code)
}

fn output(ctx: &Context, data: &Value, human: &str) {
    ctx.out(Some(&preserve_sgr(human)), data);
}

fn note(ctx: &Context, text: &str) {
    eprintln!("{} {}", ctx.paint("33", "note"), clean_text(text));
}

/// `fail(message, FAILURE, { problem })`: the whole result is
/// `error.problem`, not flattened into `code` / `detail`.
fn fail_problem(ctx: &Context, message: &str, problem: &Value) -> Outcome {
    let message = clean_text(message);
    if ctx.json {
        let mut error = Map::new();
        error.insert("message".into(), Value::from(message));
        error.insert("problem".into(), problem.clone());
        let envelope = json!({ "ok": false, "error": Value::Object(error) });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".into())
        );
    } else {
        eprintln!("{} {message}", ctx.paint("31", "error"));
    }
    Ok(Exit::Failure.code())
}

fn preserve_sgr(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('\u{1b}') {
        out.push_str(&clean_text(&rest[..start]));
        let after = &rest[start..];
        if let Some(len) = sgr_len(after) {
            out.push_str(&after[..len]);
            rest = &after[len..];
        } else {
            let ch = after.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&clean_text(&after[..ch]));
            rest = &after[ch..];
        }
    }
    out.push_str(&clean_text(rest));
    out
}

fn sgr_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.len() < 3 || bytes[0] != 0x1b || bytes[1] != b'[' {
        return None;
    }
    let mut i = 2;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b';') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'm' {
        Some(i + 1)
    } else {
        None
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".into())
}

fn show(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// `${value}` in a JS template. Missing is `undefined`; null is `null`.
fn js_interp(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(v) => show(v),
    }
}

fn js_present_str(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty())
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn js_or_zero(value: &Value) -> String {
    if js_truthy(value) {
        show(value)
    } else {
        "0".into()
    }
}

fn js_or_zero_text(value: Option<&Value>) -> String {
    match value {
        Some(v) if !v.is_null() => show(v),
        _ => "0".into(),
    }
}

fn js_nullish(value: Option<&Value>, fallback: &str) -> String {
    match value {
        Some(v) if !v.is_null() => show(v),
        _ => fallback.into(),
    }
}

fn js_or_text(value: Option<&Value>) -> Option<String> {
    value.filter(|v| js_truthy(v)).map(show)
}

fn query(pairs: &[(&str, Option<&str>)]) -> String {
    pairs
        .iter()
        .filter_map(|(k, v)| v.map(|v| format!("{}={}", form_encode(k), form_encode(v))))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn sid_of(explicit: Option<&str>) -> Result<String, CliError> {
    if let Some(sid) = explicit.filter(|s| !s.is_empty()) {
        return Ok(sid.to_string());
    }
    client_state::load_state(&client_state_path())
        .session_id
        .filter(|s| !s.is_empty())
        .ok_or_else(session_missing)
}

fn session_missing() -> CliError {
    CliError {
        message: "no session selected".into(),
        exit: Exit::Session,
        next: Some("agent-vault session create --cred <slug>".into()),
        problem: None,
        skew: false,
    }
}

async fn credential(ctx: &Context, slug: &str) -> Result<Value, CliError> {
    let creds = ctx.control("GET", "/v1/credentials", None).await?;
    creds
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|c| c.get("slug").and_then(|s| s.as_str()) == Some(slug))
                .cloned()
        })
        .ok_or_else(|| CliError {
            message: "credential not found".into(),
            exit: Exit::NotFound,
            next: None,
            problem: None,
            skew: false,
        })
}

fn scrub_line(v: &Value) -> String {
    let mut line = format!(
        "{}  {}  added {}",
        js_interp(v.get("id")),
        js_interp(v.get("source")),
        js_interp(v.get("added_at"))
    );
    if let Some(sample) = v.get("sample").filter(|s| js_truthy(s)) {
        line.push_str(&format!(
            "\n  {} ({} matches)",
            js_interp(sample.get("redacted")),
            js_interp(sample.get("matches"))
        ));
    }
    line
}

fn narrow_given(args: &SessionNarrowArgs) -> Vec<String> {
    let mut out = Vec::new();
    let g = &args.grant;
    for (name, present) in [
        ("hosts", g.hosts.is_some()),
        ("methods", g.methods.is_some()),
        ("paths", g.paths.is_some()),
        ("deny-paths", g.deny_paths.is_some()),
        ("approval", g.approval.is_some()),
        ("budget", g.budget.is_some()),
        ("uses", g.uses.is_some()),
        ("concurrency", g.concurrency.is_some()),
        ("redirects", g.redirects.is_some()),
        ("spend-tokens", g.spend_tokens.is_some()),
        ("grant-ttl", g.grant_ttl.is_some()),
        ("rate", g.rate.is_some()),
        ("quota", g.quota.is_some()),
        ("spend-usd", g.spend_usd.is_some()),
        ("route", !g.route.is_empty()),
        ("payload-file", g.payload_file.is_some()),
        ("graphql", g.graphql.is_some()),
        ("cred", args.cred.is_some()),
        ("ttl", args.ttl.is_some()),
    ] {
        if present {
            out.push(name.into());
        }
    }
    out
}

fn webhook_line(r: &Value) -> Option<String> {
    let hook = r.get("webhook")?;
    if !js_truthy(hook) {
        return None;
    }
    Some(format!(
        "webhook  {}  {}  since {}",
        js_interp(hook.get("host")),
        js_interp(hook.get("detail")),
        js_interp(hook.get("configured_at"))
    ))
}

fn credential_lines(r: &Value) -> String {
    r.get("credentials")
        .and_then(|c| c.as_array())
        .map(|rows| {
            rows.iter()
                .map(|c| {
                    let host = c.get("host").and_then(js_present_str).unwrap_or("");
                    format!(
                        "{}  {}  {host}",
                        js_interp(c.get("slug")),
                        js_interp(c.get("kind"))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

async fn backup_input(ctx: &Context, file: Option<&str>) -> Result<Value, CliError> {
    let path = text_flag(file, "backup file")?;
    let bundle = read_json(Some(path), "backup file")?;
    let passphrase = ctx.read_secret("recovery passphrase (not your vault passphrase): ")?;
    Ok(json!({
        "bundle": bundle,
        "recovery_passphrase": passphrase.expose_secret(),
    }))
}

async fn write_exclusive(
    ctx: &Context,
    path: &str,
    text: &str,
    mut force: bool,
) -> Result<bool, CliError> {
    text_flag(Some(path), "--out")?;
    match files::write_file_exclusive(Path::new(path), text, force, 0o600) {
        Ok(replaced) => Ok(replaced),
        Err(FileError::Exists(_)) if !force && std::io::stdin().is_terminal() && !ctx.json => {
            let answer = ctx.ask(&format!("{path} exists. Replace it? [y/N] "))?;
            let yes = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
            if !yes {
                return Err(file_err(FileError::Exists(path.into())));
            }
            force = true;
            files::write_file_exclusive(Path::new(path), text, force, 0o600).map_err(file_err)
        }
        Err(e) => Err(file_err(e)),
    }
}

fn append_exclusive(path: &str, line: &str) -> Result<(), CliError> {
    files::append_line_exclusive(Path::new(path), line).map_err(file_err)
}

fn file_err(error: FileError) -> CliError {
    let conflict = matches!(
        error,
        FileError::Exists(_) | FileError::NotRegular(_) | FileError::Symlink(_)
    );
    let exit = if conflict {
        Exit::Conflict
    } else if matches!(error, FileError::NotPlaceholder) {
        Exit::Internal
    } else {
        Exit::Failure
    };
    CliError {
        message: error.to_string(),
        exit,
        next: None,
        problem: None,
        skew: false,
    }
}

fn io_err(message: String) -> CliError {
    CliError {
        message,
        exit: Exit::Failure,
        next: None,
        problem: None,
        skew: false,
    }
}

fn errno_name(err: &std::io::Error) -> &'static str {
    match err.raw_os_error() {
        Some(n) if n == libc::ENOENT => "ENOENT",
        Some(n) if n == libc::EACCES => "EACCES",
        Some(n) if n == libc::EPERM => "EPERM",
        Some(n) if n == libc::EISDIR => "EISDIR",
        Some(n) if n == libc::ENOTDIR => "ENOTDIR",
        Some(n) if n == libc::ELOOP => "ELOOP",
        Some(n) if n == libc::ENAMETOOLONG => "ENAMETOOLONG",
        _ => "not JSONL",
    }
}

fn arr_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

fn is_slug(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        }
        _ => false,
    }
}

fn split_header(value: &str) -> Option<(&str, &str)> {
    let colon = value.find(':')?;
    let name = &value[..colon];
    if name.is_empty() || name.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    let rest = &value[colon + 1..];
    let value = rest.trim_start_matches([' ', '\t']);
    Some((name, value))
}

fn parse_duration(text: &str) -> Option<(u64, char)> {
    let unit = text.chars().last()?;
    if !matches!(unit, 's' | 'm' | 'h' | 'd') {
        return None;
    }
    let digits = &text[..text.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, unit))
}

fn session_summary(r: &Value, markdown: bool) -> String {
    let mut lines = Vec::new();
    let id = r.get("session").and_then(|s| s.get("id"));
    lines.push(if markdown {
        format!("# Session {}", js_interp(id))
    } else {
        format!("session {}", js_interp(id))
    });
    if let Some(session) = r.get("session").and_then(|s| s.as_object()) {
        for (k, v) in session {
            field(&mut lines, markdown, k, v);
        }
    }
    if let Some(grants) = r.get("grants").and_then(|g| g.as_array()) {
        for g in grants {
            lines.push(format!(
                "\n{} {} {}",
                if markdown { "##" } else { "grant" },
                js_interp(g.get("cred")),
                js_interp(g.get("grant_id"))
            ));
            if let Some(effective) = g.get("effective").and_then(|e| e.as_object()) {
                for (k, v) in effective {
                    field(&mut lines, markdown, k, v);
                }
            }
            for key in ["state", "budget", "limits", "counters"] {
                if let Some(v) = g.get(key) {
                    field(&mut lines, markdown, key, v);
                }
            }
            let expires = g
                .get("expires_at")
                .and_then(js_present_str)
                .unwrap_or("session lifetime");
            field(&mut lines, markdown, "expires", &Value::from(expires));
            if let Some(spend) = g.get("spend") {
                if js_truthy(spend) {
                    let prices = spend
                        .get("prices_version")
                        .and_then(js_present_str)
                        .unwrap_or(PRICES_VERSION);
                    let text = format!(
                        "{} / {} tokens · {} / {} (estimate, prices {prices})",
                        count_or_unlimited(spend.get("tokens_used")),
                        count_or_unlimited(spend.get("limit_tokens")),
                        usd_or_unlimited(spend.get("usd_micros_used")),
                        usd_or_unlimited(spend.get("limit_usd_micros"))
                    );
                    field(&mut lines, markdown, "spend", &Value::from(text));
                    let reserved = json!({
                        "tokens": spend.get("reserved_tokens").cloned().unwrap_or(Value::Null),
                        "usd_micros": spend.get("reserved_usd_micros").cloned().unwrap_or(Value::Null),
                    });
                    field(&mut lines, markdown, "reserved", &reserved);
                }
            }
            if let Some(placeholders) = g.get("placeholders") {
                field(&mut lines, markdown, "placeholders", placeholders);
            }
        }
    }
    let activity = r.get("activity").cloned().unwrap_or(Value::Null);
    lines.push(format!("\n{} Activity", if markdown { "##" } else { "" }));
    field(
        &mut lines,
        markdown,
        "requests",
        activity.get("requests").unwrap_or(&Value::Null),
    );
    field(
        &mut lines,
        markdown,
        "approvals",
        activity.get("approvals").unwrap_or(&Value::Null),
    );
    if let Some(paths) = activity.get("paths").and_then(|p| p.as_array()) {
        for p in paths {
            lines.push(format!(
                "  {}  {} {}",
                js_interp(p.get("count")),
                js_interp(p.get("method")),
                js_interp(p.get("path"))
            ));
        }
    }
    if let Some(denials) = activity.get("denials").and_then(|d| d.as_array()) {
        for d in denials {
            lines.push(format!(
                "  {}  {}  {}",
                js_interp(d.get("count")),
                js_interp(d.get("code")),
                js_interp(d.get("rule"))
            ));
        }
    }
    field(
        &mut lines,
        markdown,
        "tripwires",
        activity.get("tripwires").unwrap_or(&Value::Null),
    );
    if activity.get("complete") == Some(&Value::Bool(false)) {
        let note = activity
            .get("note")
            .and_then(|n| n.as_str())
            .unwrap_or("history is incomplete");
        field(&mut lines, markdown, "note", &Value::from(note));
    }
    lines.join("\n")
}

fn field(lines: &mut Vec<String>, markdown: bool, key: &str, value: &Value) {
    let shown = show(value);
    if markdown {
        lines.push(format!("- **{key}**: {shown}"));
    } else {
        lines.push(format!("  {key:<15}{shown}"));
    }
}

fn count_or_unlimited(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "unlimited".into(),
        Some(Value::Number(n)) => locale_int(n.as_f64().unwrap_or(0.0)),
        Some(other) => show(other),
    }
}

fn usd_or_unlimited(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "unlimited".into(),
        Some(Value::Number(n)) => format!("${:.2}", n.as_f64().unwrap_or(0.0) / 1_000_000.0),
        Some(other) => show(other),
    }
}

fn locale_int(n: f64) -> String {
    let neg = n < 0.0;
    let whole = n.abs() as u64;
    let digits = whole.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

fn report_summary(r: &Value, markdown: bool) -> String {
    let mut lines = vec![
        if markdown {
            "# Access review".into()
        } else {
            "access review".into()
        },
        format!(
            "since {} · generated {}",
            js_interp(r.get("since")),
            js_interp(r.get("generated_at"))
        ),
    ];
    table(
        &mut lines,
        markdown,
        "Credentials",
        r.get("credentials").and_then(|v| v.as_array()),
        &[
            "slug",
            "sessions_active",
            "sessions_total",
            "requests",
            "denials",
            "last_used_at",
            "expiry_warning",
            "health_status",
            "quarantined",
        ],
    );
    table(
        &mut lines,
        markdown,
        "Sessions",
        r.get("sessions").and_then(|v| v.as_array()),
        &[
            "id",
            "label",
            "state",
            "creds",
            "requests",
            "denials",
            "last_seen_at",
            "elevated",
            "unused_methods",
        ],
    );
    if r.get("complete") == Some(&Value::Bool(false)) {
        lines.push("note: history is incomplete".into());
    }
    lines.join("\n")
}

fn table(
    lines: &mut Vec<String>,
    markdown: bool,
    title: &str,
    rows: Option<&Vec<Value>>,
    columns: &[&str],
) {
    lines.push(format!("\n{}{title}", if markdown { "## " } else { "" }));
    let sep = if markdown { " | " } else { "  " };
    lines.push(columns.join(sep));
    if markdown {
        lines.push(
            columns
                .iter()
                .map(|_| "---")
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }
    let Some(rows) = rows else {
        return;
    };
    for row in rows {
        let cells = columns
            .iter()
            .map(|key| {
                let shown = match row.get(*key) {
                    None => "none".into(),
                    Some(v) => show(v),
                };
                clean_text(&shown).replace('|', "\\|").replace('\n', " ")
            })
            .collect::<Vec<_>>();
        lines.push(cells.join(sep));
    }
}

fn gateway_preflight(port: u16, token: &str, body: &Value) -> Result<Value, CliError> {
    let bytes = serde_json::to_vec(body).map_err(|e| io_err(e.to_string()))?;
    let response = crate::http_client::request_tcp(
        port,
        "POST",
        "/v1/preflight",
        Some(&bytes),
        &[("av-session", token)],
    )
    .map_err(|e| CliError {
        message: e.to_string(),
        exit: Exit::DaemonUnreachable,
        next: None,
        problem: None,
        skew: false,
    })?;
    let parsed: Value = serde_json::from_str(&response.text())
        .map_err(|_| io_err("invalid preflight response".into()))?;
    if response.status >= 400 {
        let message = parsed
            .get("detail")
            .and_then(|d| d.as_str())
            .unwrap_or("preflight refused")
            .to_string();
        let exit = parsed
            .get("code")
            .and_then(|c| c.as_str())
            .and_then(av_core::errors::ErrorCode::parse)
            .map(|c| c.spec().exit)
            .unwrap_or(Exit::Failure);
        return Err(CliError {
            message,
            exit,
            next: None,
            problem: Some(Box::new(parsed)),
            skew: false,
        });
    }
    Ok(parsed)
}

fn fetch_chain_pins(host: &str) -> Result<Vec<Value>, CliError> {
    let mut cmd = std::process::Command::new("openssl");
    cmd.args(["s_client", "-connect", &format!("{host}:443"), "-showcerts"]);
    if wants_servername(host) {
        cmd.args(["-servername", host]);
    }
    cmd.stdin(std::process::Stdio::null());
    let output = cmd.output().map_err(|e| io_err(e.to_string()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut pems = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            break;
        };
        let pem = &after[..end + "-----END CERTIFICATE-----".len()];
        pems.push(pem.to_string());
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    if pems.is_empty() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(io_err(if err.trim().is_empty() {
            "could not read the certificate chain".into()
        } else {
            err.trim().to_string()
        }));
    }
    let mut rows = Vec::new();
    let mut seen = Vec::new();
    for pem in pems.iter().take(8) {
        let subject = openssl_name(pem, "subject").unwrap_or_default();
        let id = subject.clone();
        if seen.iter().any(|s: &String| s == &id) && !id.is_empty() {
            break;
        }
        seen.push(id);
        let issuer = openssl_name(pem, "issuer").unwrap_or_default();
        let spki = openssl_spki(pem).unwrap_or_default();
        let not_after = openssl_not_after(pem);
        rows.push(json!({
            "subject": subject,
            "issuer": issuer,
            "spki": spki,
            "not_after": not_after,
        }));
    }
    Ok(rows)
}

fn wants_servername(host: &str) -> bool {
    if host.starts_with('[') || !host.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty())
    {
        return false;
    }
    true
}

fn openssl_name(pem: &str, which: &str) -> Option<String> {
    let output = std::process::Command::new("openssl")
        .args([
            "x509",
            "-noout",
            &format!("-{which}"),
            "-nameopt",
            "RFC2253",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut()?.write_all(pem.as_bytes()).ok()?;
            drop(child.stdin.take());
            child.wait_with_output().ok()
        })?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?.trim();
    let value = line
        .split_once('=')
        .map(|(_, rest)| rest.trim())
        .unwrap_or(line);
    Some(value.to_string())
}

fn openssl_spki(pem: &str) -> Option<String> {
    let pub_out = std::process::Command::new("openssl")
        .args(["x509", "-pubkey", "-noout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut()?.write_all(pem.as_bytes()).ok()?;
            drop(child.stdin.take());
            child.wait_with_output().ok()
        })?;
    let der = std::process::Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut()?.write_all(&pub_out.stdout).ok()?;
            drop(child.stdin.take());
            child.wait_with_output().ok()
        })?;
    let digest = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut()?.write_all(&der.stdout).ok()?;
            drop(child.stdin.take());
            child.wait_with_output().ok()
        })?;
    Some(format!("sha256/{}", base64_encode(&digest.stdout)))
}

fn openssl_not_after(pem: &str) -> Value {
    let output = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-enddate"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut()?.write_all(pem.as_bytes()).ok()?;
            drop(child.stdin.take());
            child.wait_with_output().ok()
        });
    let Some(output) = output else {
        return Value::Null;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(date) = text.trim().strip_prefix("notAfter=") else {
        return Value::Null;
    };
    asn1_to_iso(date).map(Value::from).unwrap_or(Value::Null)
}

fn asn1_to_iso(text: &str) -> Option<String> {
    // `Nov 11 12:00:00 2026 GMT`
    let mut parts = text.split_whitespace();
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u32 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let year: i32 = parts.next()?.parse().ok()?;
    let mut clock = time.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let min: u32 = clock.next()?.parse().ok()?;
    let sec: u32 = clock.next()?.parse().ok()?;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.000Z"
    ))
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let rest = data.len() - i;
        let n = if rest == 1 {
            (data[i] as u32) << 16
        } else {
            ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8)
        };
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if rest == 1 {
            out.push('=');
            out.push('=');
        } else {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
    }
    out
}
