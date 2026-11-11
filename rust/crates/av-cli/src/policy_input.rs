//! One parser for create, template, narrow and owner approval overrides:
//! turns the (string-valued) flags into the daemon's JSON with the JS's
//! exact usage messages. Ports `src/cli/policy-input.js`.
//!
//! Every failure is a [`CliError`] with `Exit::Usage` (the JS `usage()`).

use serde_json::Value;

use crate::cli::{ApproveArgs, GrantFlags, SessionSpecArgs};
use crate::CliError;

/// A usage error (`EXIT.USAGE`) with this message. Ports `usage(message)` in
/// `src/cli/policy-input.js`.
pub fn usage(message: impl Into<String>) -> CliError {
    todo!()
}

/// A nonblank value, or `<name> needs a value`. Ports
/// `textFlag(value, name)` in `src/cli/policy-input.js`.
pub fn text_flag<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, CliError> {
    todo!()
}

/// A flag that is there or not; any value is refused (`--<flag> takes no
/// value`). With clap, a boolean flag cannot carry a value, so this only
/// matters for the quirk in [`crate::cli`] item 4. Ports
/// `booleanFlag(args, flag)` in `src/cli/policy-input.js`.
pub fn boolean_flag(value: Option<&str>, flag: &str) -> Result<bool, CliError> {
    todo!()
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
            max: 9_007_199_254_740_991.0,
            integer: true,
        }
    }
}

/// A number in range, or `<name> must be a whole number between <min> and
/// <max>` (JS `Number()` semantics on the text). Ports
/// `numberFlag(value, name, { min, max, integer })` in
/// `src/cli/policy-input.js`.
pub fn number_flag(value: Option<&str>, name: &str, limits: NumberLimits) -> Result<f64, CliError> {
    todo!()
}

/// [`number_flag`] for a flag that may be absent. Ports
/// `optionalNumber(args, flag, limits)` in `src/cli/policy-input.js`.
pub fn optional_number(
    value: Option<&str>,
    flag: &str,
    limits: NumberLimits,
) -> Result<Option<f64>, CliError> {
    todo!()
}

/// Read a JSON file, or `cannot read <name>: <code or 'not JSON'>`. Ports
/// `readJson(path, name)` in `src/cli/policy-input.js`.
pub fn read_json(path: Option<&str>, name: &str) -> Result<Value, CliError> {
    todo!()
}

/// A comma list, trimmed, empties dropped. Ports `listFlag(value, name)` in
/// `src/cli/policy-input.js`.
pub fn list_flag(value: Option<&str>, name: &str) -> Result<Vec<String>, CliError> {
    todo!()
}

/// `none` (null) or a real `YYYY-MM-DD` as an ISO timestamp at UTC
/// midnight. Ports `expiryInput(value)` in `src/cli/policy-input.js`.
pub fn expiry_input(value: Option<&str>) -> Result<Option<String>, CliError> {
    todo!()
}

/// The grant spec the flags describe (`hosts`, `methods`, `paths`,
/// `deny_paths`, `approval`, `budget`, `uses`, `max_concurrent`,
/// `redirects`, `spend_tokens`, `grant_ttl_minutes`, `rate`, `quota`,
/// `spend_usd`, `routes`, `payload`). Ports `grantInput(args)` in
/// `src/cli/policy-input.js`.
pub fn grant_input(args: &GrantFlags) -> Result<Value, CliError> {
    todo!()
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
/// nothing was sent`. Clap now rejects unknown flags itself (with its own
/// wording; see [`crate::cli`] item 2); kept for the runner to reproduce
/// the JS message. Ports `knownFlags(args, allowed, command)` in
/// `src/cli/policy-input.js`.
pub fn known_flags(given: &[&str], allowed: &[&str], command: &str) -> Result<(), CliError> {
    todo!()
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

/// The owner's narrowing of an approval: `parseOverrides` (pending.js) over
/// the flags it reads, merged over [`grant_input`]; every typed flag must
/// arrive in the overrides, two spellings of one field are refused, and
/// nothing is sent on any problem. Ports `approvalOverrides(args, parse)` in
/// `src/cli/policy-input.js`.
pub fn approval_overrides(args: &ApproveArgs) -> Result<Value, CliError> {
    todo!()
}

/// The session-create body: exactly one of `--cred`, `--grants-file`,
/// `--template`; `--ttl` and `--infinite` exclusive. Ports
/// `sessionInput(args)` in `src/cli/policy-input.js`.
pub fn session_input(args: &SessionSpecArgs) -> Result<Value, CliError> {
    todo!()
}
