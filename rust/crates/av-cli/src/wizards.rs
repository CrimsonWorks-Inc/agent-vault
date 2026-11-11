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
    todo!()
}

/// A slug that is valid, descriptive, and not already taken. Ports
/// `suggestSlug(kind, existing)` in `src/cli/wizards.js`.
pub fn suggest_slug(kind: &str, existing: &[String]) -> String {
    todo!()
}

/// One scope option: `(value, label, hint)`. Ports the entries returned by
/// `scopePresets` in `src/cli/wizards.js`.
pub type ScopePreset = (&'static str, &'static str, Option<&'static str>);

/// Scope options worth offering for a connector kind. Ports
/// `scopePresets(kind)` in `src/cli/wizards.js`.
pub fn scope_presets(kind: &str) -> Vec<ScopePreset> {
    todo!()
}

/// Expand a chosen scope into path globs. Ports
/// `pathsForScope(kind, scope, detail)` in `src/cli/wizards.js`.
pub fn paths_for_scope(kind: &str, scope: &str, detail: Option<&str>) -> Vec<String> {
    todo!()
}

/// One budget option: a request count, or `None` for "Something else".
/// Ports the entries returned by `BUDGET_CHOICES` in `src/cli/wizards.js`.
pub type BudgetChoice = (Option<u64>, &'static str, Option<&'static str>);

/// Budget options for a connector kind (larger for LLM kinds). Ports
/// `BUDGET_CHOICES(kind)` in `src/cli/wizards.js`.
pub fn budget_choices(kind: &str) -> Vec<BudgetChoice> {
    todo!()
}

/// Walk someone through storing a credential. Ports
/// `credentialWizard(control, { slug })` in `src/cli/wizards.js`.
pub async fn credential_wizard(ctx: &Context, slug: Option<&str>) -> Outcome {
    todo!()
}

/// Walk someone through scoping a session. Ports
/// `sessionWizard(control, { cred })` in `src/cli/wizards.js`.
pub async fn session_wizard(ctx: &Context, cred: Option<&str>) -> Outcome {
    todo!()
}

/// Credential, session, and what to give the agent. Ports
/// `quickstart(control)` in `src/cli/wizards.js`.
pub async fn quickstart(ctx: &Context) -> Outcome {
    todo!()
}
