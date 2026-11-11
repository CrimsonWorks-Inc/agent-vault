//! Control-plane commands. Authentication remains the daemon's decision;
//! every widening call uses the same presence flow as session creation.
//! Ports `src/cli/control-commands.js`: each key of the object
//! `controlCommands(ctx)` returns is one function here.

use serde_json::Value;

use crate::cli::{
    AuditExportArgs, AuditVerifyArgs, AuditWitnessArgs, BackupExportArgs, BackupFileArg,
    BackupRestoreArgs, CredExpiryArgs, CredPinArgs, CredQuarantineArgs, CredRotateArgs,
    CredScrubArgs, CredTestArgs, NameArg, NotifySetArgs, PanicArgs, PreflightArgs, ReportArgs,
    SessionNarrowArgs, SessionShowArgs, SlugArg, TemplateSaveArgs, TripwireSetArgs,
};
use crate::{Context, Outcome};

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
    todo!()
}

/// Terminal lines for the daemon's scrubbed, still-untrusted preview of a
/// held request. Ports `approvalPreviewLines(p, full)` in
/// `src/cli/control-commands.js`.
pub fn approval_preview_lines(preview: &Value, full: bool) -> Vec<String> {
    todo!()
}

/// Ports `'cred:rotate'` in `src/cli/control-commands.js`.
pub async fn cred_rotate(ctx: &Context, args: &CredRotateArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:expiry'` in `src/cli/control-commands.js`.
pub async fn cred_expiry(ctx: &Context, args: &CredExpiryArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:scrub'` in `src/cli/control-commands.js`.
pub async fn cred_scrub(ctx: &Context, args: &CredScrubArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:pin'` in `src/cli/control-commands.js`.
pub async fn cred_pin(ctx: &Context, args: &CredPinArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:test'` in `src/cli/control-commands.js` (exit
/// `EXIT.UPSTREAM`, or `EXIT.POLICY_DENIED` for quota/quarantine, when a
/// probe fails).
pub async fn cred_test(ctx: &Context, args: &CredTestArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:quarantine'` in `src/cli/control-commands.js`.
pub async fn cred_quarantine(ctx: &Context, args: &CredQuarantineArgs) -> Outcome {
    todo!()
}

/// Ports `'cred:release'` in `src/cli/control-commands.js`.
pub async fn cred_release(ctx: &Context, args: &SlugArg) -> Outcome {
    todo!()
}

/// Ports `panic` in `src/cli/control-commands.js` (exit `EXIT.LOCKED` when
/// it was already locked).
pub async fn panic(ctx: &Context, args: &PanicArgs) -> Outcome {
    todo!()
}

/// Ports `'tripwire:show'` in `src/cli/control-commands.js`.
pub async fn tripwire_show(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'tripwire:on'` in `src/cli/control-commands.js`.
pub async fn tripwire_on(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'tripwire:off'` in `src/cli/control-commands.js`.
pub async fn tripwire_off(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'tripwire:set'` in `src/cli/control-commands.js`.
pub async fn tripwire_set(ctx: &Context, args: &TripwireSetArgs) -> Outcome {
    todo!()
}

/// Ports `'notify:set'` in `src/cli/control-commands.js`.
pub async fn notify_set(ctx: &Context, args: &NotifySetArgs) -> Outcome {
    todo!()
}

/// Ports `'notify:show'` in `src/cli/control-commands.js`.
pub async fn notify_show(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'notify:off'` in `src/cli/control-commands.js`.
pub async fn notify_off(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'notify:test'` in `src/cli/control-commands.js`.
pub async fn notify_test(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'template:save'` in `src/cli/control-commands.js`.
pub async fn template_save(ctx: &Context, args: &TemplateSaveArgs) -> Outcome {
    todo!()
}

/// Ports `'template:list'` in `src/cli/control-commands.js`.
pub async fn template_list(ctx: &Context) -> Outcome {
    todo!()
}

/// Ports `'template:show'` in `src/cli/control-commands.js`.
pub async fn template_show(ctx: &Context, args: &NameArg) -> Outcome {
    todo!()
}

/// Ports `'template:rm'` in `src/cli/control-commands.js`.
pub async fn template_rm(ctx: &Context, args: &NameArg) -> Outcome {
    todo!()
}

/// Ports `'session:narrow'` in `src/cli/control-commands.js`.
pub async fn session_narrow(ctx: &Context, args: &SessionNarrowArgs) -> Outcome {
    todo!()
}

/// Ports `'session:show'` (with `sessionSummary`) in
/// `src/cli/control-commands.js`.
pub async fn session_show(ctx: &Context, args: &SessionShowArgs) -> Outcome {
    todo!()
}

/// Ports `report` (with `reportSummary`) in `src/cli/control-commands.js`.
pub async fn report(ctx: &Context, args: &ReportArgs) -> Outcome {
    todo!()
}

/// Ports `'backup:export'` in `src/cli/control-commands.js`.
pub async fn backup_export(ctx: &Context, args: &BackupExportArgs) -> Outcome {
    todo!()
}

/// Ports `'backup:inspect'` in `src/cli/control-commands.js`.
pub async fn backup_inspect(ctx: &Context, args: &BackupFileArg) -> Outcome {
    todo!()
}

/// Ports `'backup:restore'` in `src/cli/control-commands.js`.
pub async fn backup_restore(ctx: &Context, args: &BackupRestoreArgs) -> Outcome {
    todo!()
}

/// Ports `'audit:export'` in `src/cli/control-commands.js`.
pub async fn audit_export(ctx: &Context, args: &AuditExportArgs) -> Outcome {
    todo!()
}

/// Ports `'audit:witness'` in `src/cli/control-commands.js`.
pub async fn audit_witness(ctx: &Context, args: &AuditWitnessArgs) -> Outcome {
    todo!()
}

/// Ports `'audit:verify'` in `src/cli/control-commands.js`.
pub async fn audit_verify(ctx: &Context, args: &AuditVerifyArgs) -> Outcome {
    todo!()
}

/// Ports `preflight` (with `gatewayPreflight`) in
/// `src/cli/control-commands.js` (exit 0 allow, `EXIT.APPROVAL` hold,
/// `EXIT.POLICY_DENIED` refuse).
pub async fn preflight(ctx: &Context, args: &PreflightArgs) -> Outcome {
    todo!()
}
