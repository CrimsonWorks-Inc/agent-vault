//! One parser for create, template, narrow and owner approval overrides:
//! turns the (string-valued) flags into the daemon's JSON with the JS's
//! exact usage messages. Ports `src/cli/policy-input.js`.
//!
//! Every failure is a [`CliError`] with `Exit::Usage` (the JS `usage()`).

use std::cell::RefCell;

use serde_json::{Map, Value};

use av_core::errors::Exit;
use av_store::pending;

use crate::cli::{ApproveArgs, GrantFlags, SessionSpecArgs};
use crate::CliError;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

thread_local! {
    /// Flags clap does not declare, recorded by [`crate::prepare`] so
    /// `known_flags` still sees them (the JS parser kept every `--flag`).
    static EXTRA_FLAGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Record undeclared flags for the next [`session_input`] /
/// [`approval_overrides`] call. The runner sets this once per process.
pub fn set_extra_flags(flags: &[String]) {
    EXTRA_FLAGS.with(|c| *c.borrow_mut() = flags.to_vec());
}

pub(crate) fn extra_flags() -> Vec<String> {
    EXTRA_FLAGS.with(|c| c.borrow().clone())
}

/// A usage error (`EXIT.USAGE`) with this message. Ports `usage(message)` in
/// `src/cli/policy-input.js`.
pub fn usage(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        exit: Exit::Usage,
        next: None,
        problem: None,
        skew: false,
    }
}

/// A nonblank value, or `<name> needs a value`. The returned text is the
/// original, not the trimmed form (JS `textFlag` only *tests* the trim).
/// Ports `textFlag(value, name)` in `src/cli/policy-input.js`.
pub fn text_flag<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, CliError> {
    match value {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(usage(format!("{name} needs a value"))),
    }
}

/// A flag that is there or not; any value is refused (`--<flag> takes no
/// value`). `None` is absent, `Some("")` is the bare flag, anything else is
/// a value. Ports `booleanFlag(args, flag)` in `src/cli/policy-input.js`.
pub fn boolean_flag(value: Option<&str>, flag: &str) -> Result<bool, CliError> {
    // `!== undefined && !== true` is a value, including the string "false".
    if value.is_some_and(|v| !v.is_empty()) {
        return Err(usage(format!("--{flag} takes no value")));
    }
    Ok(value.is_some())
}

/// Limits for [`number_flag`]. Ports the `{ min, max, integer }` options in
/// `src/cli/policy-input.js`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NumberLimits {
    /// Default 0.
    pub min: f64,
    /// Default `Number.MAX_SAFE_INTEGER`.
    pub max: f64,
    /// Default true.
    pub integer: bool,
}

impl Default for NumberLimits {
    fn default() -> Self {
        Self {
            min: 0.0,
            max: MAX_SAFE,
            integer: true,
        }
    }
}

/// A number in range, or `<name> must be a whole number between <min> and
/// <max>` (JS `Number()` semantics on the text). Ports
/// `numberFlag(value, name, { min, max, integer })` in
/// `src/cli/policy-input.js`.
pub fn number_flag(value: Option<&str>, name: &str, limits: NumberLimits) -> Result<f64, CliError> {
    let text = text_flag(value, name)?;
    let n = js_number(text);
    let ok = n.is_some_and(|n| {
        n.is_finite()
            && n >= limits.min
            && n <= limits.max
            && (!limits.integer || is_safe_integer(n))
    });
    if !ok {
        let kind = if limits.integer {
            "a whole number"
        } else {
            "a number"
        };
        return Err(usage(format!(
            "{name} must be {kind} between {} and {}",
            js_number_text(limits.min),
            js_number_text(limits.max)
        )));
    }
    Ok(n.expect("checked"))
}

/// [`number_flag`] for a flag that may be absent. A present value that is
/// not a number in range is a usage error, never `Number(true)` (which is
/// 1). Ports `optionalNumber(args, flag, limits)` in `src/cli/policy-input.js`.
pub fn optional_number(
    value: Option<&str>,
    flag: &str,
    limits: NumberLimits,
) -> Result<Option<f64>, CliError> {
    match value {
        None => Ok(None),
        Some(_) => number_flag(value, &format!("--{flag}"), limits).map(Some),
    }
}

/// Read a JSON file, or `cannot read <name>: <code or 'not JSON'>`. Ports
/// `readJson(path, name)` in `src/cli/policy-input.js`.
pub fn read_json(path: Option<&str>, name: &str) -> Result<Value, CliError> {
    let path = text_flag(path, name)?;
    match std::fs::read_to_string(path) {
        Ok(text) => {
            serde_json::from_str(&text).map_err(|_| usage(format!("cannot read {name}: not JSON")))
        }
        Err(e) => {
            let code = e
                .raw_os_error()
                .map(io_code)
                .unwrap_or_else(|| "not JSON".into());
            Err(usage(format!("cannot read {name}: {code}")))
        }
    }
}

/// A comma list, trimmed, empties dropped. Ports `listFlag(value, name)` in
/// `src/cli/policy-input.js`.
pub fn list_flag(value: Option<&str>, name: &str) -> Result<Vec<String>, CliError> {
    Ok(text_flag(value, name)?
        .split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect())
}

/// `none` (null) or a real `YYYY-MM-DD` as an ISO timestamp at UTC
/// midnight. Ports `expiryInput(value)` in `src/cli/policy-input.js`.
pub fn expiry_input(value: Option<&str>) -> Result<Option<String>, CliError> {
    let value = value.unwrap_or("");
    if value == "none" {
        return Ok(None);
    }
    if !is_ymd_shape(value) {
        return Err(usage("expiry must be YYYY-MM-DD or none"));
    }
    let y: i32 = value[0..4].parse().unwrap_or(0);
    let m: u32 = value[5..7].parse().unwrap_or(0);
    let d: u32 = value[8..10].parse().unwrap_or(0);
    // `new Date(value+'T00:00:00.000Z').toISOString().slice(0,10) === value`
    // is the calendar check: an overflowed day would not round-trip.
    if !calendar_ymd(y, m, d) {
        return Err(usage("expiry must be a valid calendar date"));
    }
    Ok(Some(format!("{value}T00:00:00.000Z")))
}

/// The grant spec the flags describe. Ports `grantInput(args)` in
/// `src/cli/policy-input.js`.
pub fn grant_input(args: &GrantFlags) -> Result<Value, CliError> {
    let mut spec = Map::new();
    for (flag, field, raw) in [
        ("hosts", "hosts", args.hosts.as_deref()),
        ("methods", "methods", args.methods.as_deref()),
        ("paths", "paths", args.paths.as_deref()),
        ("deny-paths", "deny_paths", args.deny_paths.as_deref()),
    ] {
        if raw.is_none() {
            continue;
        }
        let list = list_flag(raw, &format!("--{flag}"))?;
        if list.is_empty() {
            return Err(usage(format!("--{flag} needs a nonempty list")));
        }
        let list = if flag == "methods" {
            list.into_iter().map(|v| v.to_uppercase()).collect()
        } else {
            list
        };
        spec.insert(field.into(), Value::from(list));
    }
    if let Some(approval) = args.approval.as_deref() {
        if !["each", "on-write", "first-use", "auto"].contains(&approval) {
            return Err(usage(
                "--approval is one of: each, on-write, first-use, auto",
            ));
        }
        spec.insert("approval".into(), Value::from(approval));
    }
    for (flag, field, raw, min, max) in [
        ("budget", "budget", args.budget.as_deref(), 0.0, MAX_SAFE),
        ("uses", "uses", args.uses.as_deref(), 1.0, MAX_SAFE),
        (
            "concurrency",
            "max_concurrent",
            args.concurrency.as_deref(),
            1.0,
            MAX_SAFE,
        ),
        (
            "redirects",
            "redirects",
            args.redirects.as_deref(),
            0.0,
            5.0,
        ),
        (
            "spend-tokens",
            "spend_tokens",
            args.spend_tokens.as_deref(),
            0.0,
            MAX_SAFE,
        ),
        (
            "grant-ttl",
            "grant_ttl_minutes",
            args.grant_ttl.as_deref(),
            1.0,
            MAX_SAFE,
        ),
    ] {
        if raw.is_none() {
            continue;
        }
        let n = number_flag(
            raw,
            &format!("--{flag}"),
            NumberLimits {
                min,
                max,
                integer: true,
            },
        )?;
        spec.insert(field.into(), json_number(n));
    }
    if let Some(raw) = args.rate.as_deref() {
        spec.insert("rate".into(), interval_flag(raw, "rate")?);
    }
    if let Some(raw) = args.quota.as_deref() {
        spec.insert("quota".into(), interval_flag(raw, "quota")?);
    }
    if let Some(raw) = args.spend_usd.as_deref() {
        let v = text_flag(Some(raw), "--spend-usd")?;
        if !spend_usd_text(v) {
            return Err(usage(
                "--spend-usd needs a nonnegative amount with at most 6 decimals",
            ));
        }
        let n = number_flag(
            Some(v),
            "--spend-usd",
            NumberLimits {
                min: 0.0,
                max: MAX_SAFE / 1e6,
                integer: false,
            },
        )?;
        spec.insert("spend_usd".into(), json_number(n));
    }
    if !args.route.is_empty() {
        let mut routes = Vec::new();
        for value in &args.route {
            let value = text_flag(Some(value), "--route")?;
            let Some((methods, path)) = route_pair(value) else {
                return Err(usage("--route must be METHODS:/path"));
            };
            let mut row = Map::new();
            row.insert(
                "methods".into(),
                Value::from(
                    methods
                        .split(',')
                        .map(|m| m.to_uppercase())
                        .collect::<Vec<_>>(),
                ),
            );
            row.insert("paths".into(), Value::from(vec![path.to_string()]));
            routes.push(Value::Object(row));
        }
        spec.insert("routes".into(), Value::Array(routes));
    }
    if args.payload_file.is_some() {
        let payload = read_json(args.payload_file.as_deref(), "--payload-file")?;
        if !payload.is_object() {
            return Err(usage("--payload-file must hold an object"));
        }
        spec.insert("payload".into(), payload);
    }
    if args.graphql.is_some() {
        let operations = list_flag(args.graphql.as_deref(), "--graphql")?;
        if operations.is_empty()
            || operations
                .iter()
                .any(|v| !["query", "mutation", "subscription"].contains(&v.as_str()))
        {
            return Err(usage("--graphql is query, mutation or subscription"));
        }
        let mut payload = match spec.remove("payload") {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        let mut graphql = match payload.remove("graphql") {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        graphql.insert("operations".into(), Value::from(operations));
        payload.insert("graphql".into(), Value::Object(graphql));
        spec.insert("payload".into(), Value::Object(payload));
    }
    Ok(Value::Object(spec))
}

/// Every flag `grantInput` reads. Ports `GRANT_FLAGS` in
/// `src/cli/policy-input.js`.
pub const GRANT_FLAGS: [&str; 17] = [
    "hosts",
    "methods",
    "paths",
    "deny-paths",
    "approval",
    "budget",
    "uses",
    "concurrency",
    "redirects",
    "spend-tokens",
    "grant-ttl",
    "rate",
    "quota",
    "spend-usd",
    "route",
    "payload-file",
    "graphql",
];

/// Refuse a flag outside `allowed` with `<command> does not take --<flag>;
/// nothing was sent`. Ports `knownFlags(args, allowed, command)` in
/// `src/cli/policy-input.js`.
pub fn known_flags(given: &[&str], allowed: &[&str], command: &str) -> Result<(), CliError> {
    for flag in given {
        if *flag != "_" && !allowed.contains(flag) {
            return Err(usage(format!(
                "{command} does not take --{flag}; nothing was sent"
            )));
        }
    }
    Ok(())
}

/// Each flag `approve` reads and the override field it becomes. Ports
/// `APPROVAL_FLAGS` in `src/cli/policy-input.js`.
pub const APPROVAL_FLAGS: [(&str, &str); 27] = [
    ("hosts", "hosts"),
    ("methods", "methods"),
    ("paths", "paths"),
    ("deny-paths", "deny_paths"),
    ("approval", "approval"),
    ("infinite", "infinite"),
    ("budget", "budget"),
    ("uses", "uses"),
    ("ttl_minutes", "ttl_minutes"),
    ("ttl-minutes", "ttl_minutes"),
    ("concurrency", "max_concurrent"),
    ("max_concurrent", "max_concurrent"),
    ("redirects", "redirects"),
    ("spend-tokens", "spend_tokens"),
    ("spend_tokens", "spend_tokens"),
    ("spend-usd", "spend_usd"),
    ("spend_usd", "spend_usd"),
    ("grant-ttl", "grant_ttl_minutes"),
    ("grant_ttl", "grant_ttl_minutes"),
    ("grant_ttl_minutes", "grant_ttl_minutes"),
    ("rate", "rate"),
    ("quota", "quota"),
    ("route", "routes"),
    ("routes", "routes"),
    ("payload", "payload"),
    ("payload-file", "payload"),
    ("graphql", "payload"),
];

/// The owner's narrowing of an approval. Ports `approvalOverrides(args, parse)`
/// in `src/cli/policy-input.js`.
pub fn approval_overrides(args: &ApproveArgs) -> Result<Value, CliError> {
    let mut given = approve_given(args);
    for extra in extra_flags() {
        if !given.iter().any(|g| g == &extra) {
            given.push(extra);
        }
    }
    let refs: Vec<&str> = given.iter().map(String::as_str).collect();
    let allowed: Vec<&str> = APPROVAL_FLAGS.iter().map(|(f, _)| *f).collect();
    known_flags(&refs, &allowed, "approve")?;
    // A bare value flag is the JS `true`. `--infinite` is the one boolean.
    for flag in &given {
        if *flag != "infinite" && approve_raw(args, flag).is_some_and(|v| v.is_empty()) {
            return Err(usage(format!("--{flag} needs a value; nothing was sent")));
        }
    }
    let mut fields: Vec<&str> = Vec::new();
    for flag in &given {
        if let Some((_, field)) = APPROVAL_FLAGS.iter().find(|(f, _)| f == flag) {
            if !fields.contains(field) {
                fields.push(field);
            }
        }
    }
    for field in &fields {
        let flags: Vec<&str> = given
            .iter()
            .filter_map(|flag| {
                APPROVAL_FLAGS
                    .iter()
                    .find(|(f, mapped)| f == flag && mapped == field)
                    .map(|(f, _)| *f)
            })
            .collect();
        let merged =
            flags.len() == 2 && flags.contains(&"payload-file") && flags.contains(&"graphql");
        if flags.len() > 1 && !merged {
            let listed = flags
                .iter()
                .map(|f| format!("--{f}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(usage(format!(
                "give only one of {listed}; nothing was sent"
            )));
        }
    }

    let grant = grant_flags_from_approve(args);
    let shared = grant_input(&grant)?;
    let typed_args = override_map(args);
    let typed = match pending::parse_overrides(&typed_args) {
        Ok(o) => o,
        Err(e) => {
            let why = e.why.trim();
            let why = if why.is_empty() {
                "not a valid value"
            } else {
                why
            };
            return Err(usage(format!("--{}: {why}; nothing was sent", e.field)));
        }
    };
    // parseOverrides wins where both read a field (C21): the page signs the
    // text, so `--rate 60/min` stays the text, not grantInput's object.
    let mut overrides = match shared {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let typed_value = serde_json::to_value(&typed).unwrap_or(Value::Null);
    if let Value::Object(typed_obj) = typed_value {
        for (k, v) in typed_obj {
            overrides.insert(k, v);
        }
    }
    for flag in &given {
        let Some((_, field)) = APPROVAL_FLAGS.iter().find(|(f, _)| f == flag) else {
            continue;
        };
        if !overrides.contains_key(*field) {
            return Err(usage(format!(
                "--{flag} was given but narrows nothing; nothing was sent"
            )));
        }
    }
    for (field, v) in &overrides {
        if let Some(n) = v.as_f64() {
            if !n.is_finite() {
                return Err(usage(format!(
                    "--{field} must be a number; nothing was sent"
                )));
            }
        }
    }
    Ok(Value::Object(overrides))
}

/// The session-create body. Ports `sessionInput(args)` in
/// `src/cli/policy-input.js`.
pub fn session_input(args: &SessionSpecArgs) -> Result<Value, CliError> {
    // No --remote (R3): the CLI talks to the local socket, and an infinite
    // session can never be remote.
    let mut given = session_given(args);
    for extra in extra_flags() {
        if !given.iter().any(|g| g == &extra) {
            given.push(extra);
        }
    }
    let refs: Vec<&str> = given.iter().map(String::as_str).collect();
    let mut allowed: Vec<&str> = GRANT_FLAGS.to_vec();
    allowed.extend([
        "label",
        "ttl",
        "infinite",
        "cred",
        "grants-file",
        "template",
    ]);
    known_flags(&refs, &allowed, "session")?;
    let shared = grant_input(&args.grant)?;
    if args.infinite && args.ttl.is_some() {
        return Err(usage("--ttl and --infinite cannot be combined"));
    }
    let mut body = Map::new();
    if let Some(label) = args.label.as_deref() {
        body.insert(
            "label".into(),
            Value::from(text_flag(Some(label), "--label")?),
        );
    }
    if args.ttl.is_some() {
        // JS Number.MIN_VALUE is 5e-324 (the smallest positive f64), not the
        // smallest normal. 0 fails; a subnormal still counts.
        let n = js_number(text_flag(args.ttl.as_deref(), "--ttl")?)
            .filter(|n| n.is_finite() && *n >= 5e-324_f64 && *n <= MAX_SAFE);
        let Some(n) = n else {
            return Err(usage(format!(
                "--ttl must be a number between {} and {}",
                js_number_text(5e-324),
                js_number_text(MAX_SAFE)
            )));
        };
        body.insert("ttl_hours".into(), json_number(n));
    }
    if args.infinite {
        body.insert("infinite".into(), Value::Bool(true));
    }
    let cred_set = args.cred.is_some();
    let file_set = args.grants_file.is_some();
    let template_set = args.template.is_some();
    if usize::from(cred_set) + usize::from(file_set) + usize::from(template_set) != 1 {
        return Err(usage(
            "send exactly one of --cred, --grants-file or --template",
        ));
    }
    if let Some(template) = args.template.as_deref() {
        let mut out = body;
        if let Value::Object(shared) = shared {
            for (k, v) in shared {
                out.insert(k, v);
            }
        }
        out.insert(
            "template".into(),
            Value::from(text_flag(Some(template), "--template")?),
        );
        return Ok(Value::Object(out));
    }
    if args.grants_file.is_some() {
        if let Value::Object(shared) = &shared {
            if !shared.is_empty() {
                return Err(usage(
                    "with --grants-file, put each credential's limits in the file",
                ));
            }
        }
        let grants = read_json(args.grants_file.as_deref(), "--grants-file")?;
        if !grants.is_array() {
            return Err(usage("--grants-file must hold a JSON array of grant specs"));
        }
        body.insert("grants".into(), grants);
        return Ok(Value::Object(body));
    }
    let creds = list_flag(args.cred.as_deref(), "--cred")?;
    if creds.is_empty() {
        return Err(usage("--cred needs a credential"));
    }
    if creds.len() == 1 {
        body.insert("cred".into(), Value::from(creds[0].clone()));
        if let Value::Object(shared) = shared {
            for (k, v) in shared {
                body.insert(k, v);
            }
        }
        return Ok(Value::Object(body));
    }
    let shared_obj = match shared {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let grants: Vec<Value> = creds
        .into_iter()
        .map(|cred| {
            let mut row = Map::new();
            row.insert("cred".into(), Value::from(cred));
            for (k, v) in &shared_obj {
                row.insert(k.clone(), v.clone());
            }
            Value::Object(row)
        })
        .collect();
    body.insert("grants".into(), Value::Array(grants));
    Ok(Value::Object(body))
}

pub(crate) fn session_given(args: &SessionSpecArgs) -> Vec<String> {
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
        ("label", args.label.is_some()),
        ("ttl", args.ttl.is_some()),
        ("infinite", args.infinite),
        ("cred", args.cred.is_some()),
        ("grants-file", args.grants_file.is_some()),
        ("template", args.template.is_some()),
    ] {
        if present {
            out.push(name.into());
        }
    }
    out
}

fn approve_given(args: &ApproveArgs) -> Vec<String> {
    let mut out = Vec::new();
    for (name, present) in [
        ("hosts", args.hosts.is_some()),
        ("methods", args.methods.is_some()),
        ("paths", args.paths.is_some()),
        ("deny-paths", args.deny_paths.is_some()),
        ("approval", args.approval.is_some()),
        ("infinite", args.infinite),
        ("budget", args.budget.is_some()),
        ("uses", args.uses.is_some()),
        ("ttl_minutes", args.ttl_minutes_underscore.is_some()),
        ("ttl-minutes", args.ttl_minutes.is_some()),
        ("concurrency", args.concurrency.is_some()),
        ("max_concurrent", args.max_concurrent.is_some()),
        ("redirects", args.redirects.is_some()),
        ("spend-tokens", args.spend_tokens.is_some()),
        ("spend_tokens", args.spend_tokens_underscore.is_some()),
        ("spend-usd", args.spend_usd.is_some()),
        ("spend_usd", args.spend_usd_underscore.is_some()),
        ("grant-ttl", args.grant_ttl.is_some()),
        ("grant_ttl", args.grant_ttl_underscore.is_some()),
        ("grant_ttl_minutes", args.grant_ttl_minutes.is_some()),
        ("rate", args.rate.is_some()),
        ("quota", args.quota.is_some()),
        ("route", !args.route.is_empty()),
        ("routes", args.routes.is_some()),
        ("payload", args.payload.is_some()),
        ("payload-file", args.payload_file.is_some()),
        ("graphql", args.graphql.is_some()),
    ] {
        if present {
            out.push(name.into());
        }
    }
    out
}

fn approve_raw<'a>(args: &'a ApproveArgs, flag: &str) -> Option<&'a str> {
    match flag {
        "hosts" => args.hosts.as_deref(),
        "methods" => args.methods.as_deref(),
        "paths" => args.paths.as_deref(),
        "deny-paths" => args.deny_paths.as_deref(),
        "approval" => args.approval.as_deref(),
        "infinite" => args.infinite.then_some(""),
        "budget" => args.budget.as_deref(),
        "uses" => args.uses.as_deref(),
        "ttl_minutes" => args.ttl_minutes_underscore.as_deref(),
        "ttl-minutes" => args.ttl_minutes.as_deref(),
        "concurrency" => args.concurrency.as_deref(),
        "max_concurrent" => args.max_concurrent.as_deref(),
        "redirects" => args.redirects.as_deref(),
        "spend-tokens" => args.spend_tokens.as_deref(),
        "spend_tokens" => args.spend_tokens_underscore.as_deref(),
        "spend-usd" => args.spend_usd.as_deref(),
        "spend_usd" => args.spend_usd_underscore.as_deref(),
        "grant-ttl" => args.grant_ttl.as_deref(),
        "grant_ttl" => args.grant_ttl_underscore.as_deref(),
        "grant_ttl_minutes" => args.grant_ttl_minutes.as_deref(),
        "rate" => args.rate.as_deref(),
        "quota" => args.quota.as_deref(),
        "routes" => args.routes.as_deref(),
        "payload" => args.payload.as_deref(),
        "payload-file" => args.payload_file.as_deref(),
        "graphql" => args.graphql.as_deref(),
        _ => None,
    }
}

fn grant_flags_from_approve(args: &ApproveArgs) -> GrantFlags {
    GrantFlags {
        hosts: args.hosts.clone(),
        methods: args.methods.clone(),
        paths: args.paths.clone(),
        deny_paths: args.deny_paths.clone(),
        approval: args.approval.clone(),
        budget: args.budget.clone(),
        uses: args.uses.clone(),
        concurrency: args.concurrency.clone(),
        redirects: args.redirects.clone(),
        spend_tokens: args.spend_tokens.clone(),
        grant_ttl: args.grant_ttl.clone(),
        rate: args.rate.clone(),
        quota: args.quota.clone(),
        spend_usd: args.spend_usd.clone(),
        route: args.route.clone(),
        payload_file: args.payload_file.clone(),
        graphql: args.graphql.clone(),
    }
}

/// The subset of approve flags `parseOverrides` reads (`OVERRIDE_KEYS`).
fn override_map(args: &ApproveArgs) -> Map<String, Value> {
    let mut map = Map::new();
    let put = |map: &mut Map<String, Value>, key: &str, value: &Option<String>| {
        if let Some(v) = value {
            if !v.is_empty() {
                map.insert(key.into(), Value::from(v.clone()));
            }
        }
    };
    put(&mut map, "methods", &args.methods);
    put(&mut map, "paths", &args.paths);
    put(&mut map, "budget", &args.budget);
    put(&mut map, "uses", &args.uses);
    put(&mut map, "ttl_minutes", &args.ttl_minutes_underscore);
    put(&mut map, "ttl-minutes", &args.ttl_minutes);
    put(&mut map, "grant_ttl_minutes", &args.grant_ttl_minutes);
    put(&mut map, "grant-ttl", &args.grant_ttl);
    put(&mut map, "grant_ttl", &args.grant_ttl_underscore);
    put(&mut map, "max_concurrent", &args.max_concurrent);
    put(&mut map, "concurrency", &args.concurrency);
    put(&mut map, "redirects", &args.redirects);
    put(&mut map, "spend_tokens", &args.spend_tokens_underscore);
    put(&mut map, "spend-tokens", &args.spend_tokens);
    put(&mut map, "spend_usd", &args.spend_usd_underscore);
    put(&mut map, "spend-usd", &args.spend_usd);
    put(&mut map, "rate", &args.rate);
    put(&mut map, "quota", &args.quota);
    put(&mut map, "routes", &args.routes);
    if !args.route.is_empty() {
        map.insert(
            "route".into(),
            Value::Array(args.route.iter().cloned().map(Value::from).collect()),
        );
    }
    put(&mut map, "payload", &args.payload);
    put(&mut map, "approval", &args.approval);
    if args.infinite {
        map.insert("infinite".into(), Value::Bool(true));
    }
    map
}

fn interval_flag(raw: &str, flag: &str) -> Result<Value, CliError> {
    let text = text_flag(Some(raw), &format!("--{flag}"))?;
    let Some((count, unit)) = text.split_once('/') else {
        return Err(usage(format!("invalid --{flag} interval")));
    };
    if !count.bytes().all(|b| b.is_ascii_digit()) || count.is_empty() || unit.is_empty() {
        return Err(usage(format!("invalid --{flag} interval")));
    }
    let units: &[(&str, &str)] = if flag == "rate" {
        &[
            ("s", "second"),
            ("sec", "second"),
            ("second", "second"),
            ("m", "minute"),
            ("min", "minute"),
            ("minute", "minute"),
            ("h", "hour"),
            ("hour", "hour"),
        ]
    } else {
        &[
            ("h", "hour"),
            ("hour", "hour"),
            ("d", "day"),
            ("day", "day"),
        ]
    };
    let Some((_, name)) = units.iter().find(|(k, _)| *k == unit) else {
        return Err(usage(format!("invalid --{flag} interval")));
    };
    let n = number_flag(
        Some(count),
        &format!("--{flag}"),
        NumberLimits {
            min: 1.0,
            ..NumberLimits::default()
        },
    )?;
    let mut obj = Map::new();
    obj.insert("count".into(), json_number(n));
    obj.insert(
        if flag == "rate" { "per" } else { "window" }.into(),
        Value::from(*name),
    );
    Ok(Value::Object(obj))
}

/// `^([A-Za-z]+(?:,[A-Za-z]+)*):(/[^\r\n]*)$`
fn route_pair(value: &str) -> Option<(&str, &str)> {
    let (methods, path) = value.split_once(':')?;
    if !path.starts_with('/') || path.bytes().any(|b| b == b'\r' || b == b'\n') {
        return None;
    }
    if methods.is_empty() {
        return None;
    }
    for part in methods.split(',') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
    }
    Some((methods, path))
}

/// `^\d+(?:\.\d{1,6})?$`
fn spend_usd_text(v: &str) -> bool {
    let mut parts = v.split('.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match frac {
        None => true,
        Some(f) => (1..=6).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn is_ymd_shape(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

fn calendar_ymd(y: i32, m: u32, d: u32) -> bool {
    if !(1..=12).contains(&m) || d == 0 {
        return false;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    d <= dim[m as usize]
}

/// `Number(s)` for a non-empty string: decimal (with exponent), `0x`/`0o`/`0b`
/// integers, and `Infinity`. Whitespace is trimmed, as `Number` does.
pub(crate) fn js_number(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0.0);
    }
    let radix = |p: &str, r: u32| u64::from_str_radix(p, r).ok().map(|n| n as f64);
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return if h.is_empty() { None } else { radix(h, 16) };
    }
    if let Some(o) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        return if o.is_empty() { None } else { radix(o, 8) };
    }
    if let Some(b) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        return if b.is_empty() { None } else { radix(b, 2) };
    }
    match s {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    if s.bytes()
        .any(|c| c.is_ascii_alphabetic() && c != b'e' && c != b'E')
    {
        return None;
    }
    s.parse::<f64>().ok()
}

fn is_safe_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_SAFE
}

/// How JS stringifies the limit numbers tests compare.
pub(crate) fn js_number_text(n: f64) -> String {
    if n == MAX_SAFE {
        return "9007199254740991".into();
    }
    if (n - MAX_SAFE / 1e6).abs() < 1e-6 {
        return "9007199254.740992".into();
    }
    if n > 0.0 && n <= 1e-320 {
        return "5e-324".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{}", n as i64);
    }
    let s = format!("{n}");
    s
}

pub(crate) fn json_number(n: f64) -> Value {
    if is_safe_integer(n) {
        Value::Number((n as i64).into())
    } else {
        Value::Number(serde_json::Number::from_f64(n).unwrap_or(0.into()))
    }
}

fn io_code(n: i32) -> String {
    let name = match n {
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EISDIR => "EISDIR",
        libc::ENOTDIR => "ENOTDIR",
        libc::ELOOP => "ELOOP",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOTSUP => "ENOTSUP",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::EROFS => "EROFS",
        libc::ENOSPC => "ENOSPC",
        _ => return "not JSON".into(),
    };
    name.into()
}
