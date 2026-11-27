//! Agent-proposed credentials, held for a human to finish. The agent says
//! what the credential is (its name, its kind, and for a generic `http`
//! credential the host and where the key goes); it never sees or sends the
//! key. The human checks every host the key could be sent to, then types the
//! key. No JS source: new with credential proposals.
//!
//! The one thing an agent could abuse here is the host, so a proposal never
//! widens it: a kind whose profile names its hosts takes no other, and the
//! hosts a human confirms are the credential's host ceiling exactly as the
//! gateway will enforce it ([`policy::credential_host_ceiling`]).

use av_core::errors::VaultError;
use av_core::policy;
use av_core::sites::SiteKind;
use av_store::vault::Vault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::err::{d, dr, DenyExt, C};
use crate::state::{Core, StoreResult};
use crate::util::{ct_eq, iso_now, js_string, now_ms, parse_iso_ms, random_b64url, sha256_hex};

/// Proposals pending at once.
pub const MAX_PENDING: usize = 16;
/// A pending proposal nobody finished expires after this.
pub const PENDING_TTL_MS: u64 = 30 * 60_000;
/// Settled proposals stay visible to the agent's poll for this long.
pub const SETTLED_TTL_MS: u64 = 30 * 60_000;
/// Proposals stored at once, any state.
pub const MAX_ITEMS: usize = MAX_PENDING * 4;
/// Longest reason kept, in UTF-16 units.
pub const MAX_REASON: usize = 300;
/// Most substitution sites a proposal may name.
pub const MAX_SITES: usize = 4;

/// The fields an agent may propose.
pub const FIELDS: [&str; 6] = ["slug", "kind", "host", "field", "sites", "expires_at"];
/// What else a proposal call may carry: the reason, how long to wait for
/// the answer and, to poll, the id and its secret.
pub const CALL_FIELDS: [&str; 4] = ["reason", "wait_seconds", "poll_id", "poll_secret"];
/// Names a key goes under that an agent might reach for. A proposal carrying
/// one is refused with a pointed message, not a generic one.
const KEY_FIELDS: [&str; 8] = [
    "value",
    "key",
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "credential",
];
/// Where an agent may say a key goes: never the L4 or proxy sites.
const PROPOSABLE_SITES: [SiteKind; 5] = [
    SiteKind::Header,
    SiteKind::Basic,
    SiteKind::Query,
    SiteKind::Json,
    SiteKind::Form,
];

/// Key shapes that belong to one provider (by [`av_core::scrub`] shape
/// name), how to say whose they are, and the domains that provider serves
/// them from. OpenAI's plain `sk-` is shared with other providers, so only
/// its distinct prefixes are checked ([`OPENAI_PREFIXES`]).
const KEY_HOMES: [(&str, &str, &[&str]); 6] = [
    (
        "github",
        "a GitHub",
        &["github.com", "githubusercontent.com"],
    ),
    (
        "github-pat",
        "a GitHub",
        &["github.com", "githubusercontent.com"],
    ),
    ("slack", "a Slack", &["slack.com"]),
    (
        "google-oauth",
        "a Google",
        &["googleapis.com", "google.com"],
    ),
    ("google-api", "a Google", &["googleapis.com"]),
    ("anthropic", "an Anthropic", &["anthropic.com"]),
];
/// Prefixes only OpenAI's keys carry.
const OPENAI_PREFIXES: [&str; 3] = ["sk-proj-", "sk-svcacct-", "sk-admin-"];

type R<T> = Result<T, VaultError>;

fn refuse(detail: impl Into<String>, rule: &str) -> VaultError {
    dr(C::PolicyDenied, detail, rule)
}

/// A hostname a human can read back: lowercase DNS labels with a letter in
/// the last one (no IP literal, no single label like `localhost`), and an
/// optional port.
pub fn plain_host(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host, None),
    };
    if let Some(p) = port {
        let ok = !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
        if !ok {
            return false;
        }
    }
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|t| t.bytes().any(|b| b.is_ascii_lowercase()))
}

/// Every string in `v`, at any depth (keys included).
fn strings_in<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| strings_in(x, out)),
        Value::Object(m) => {
            for (k, x) in m {
                out.push(k);
                strings_in(x, out);
            }
        }
        _ => {}
    }
}

/// Refuse a call that carries anything shaped like a key: a proposal is
/// stored and shown, so a key in it would sit in the vault in clear.
pub fn refuse_key_shapes(call: &Value) -> R<()> {
    let mut all = Vec::new();
    strings_in(call, &mut all);
    if let Some(shape) = all.iter().find_map(|s| av_core::scrub::key_shape_in(s)) {
        return Err(refuse(
            format!("that proposal holds something shaped like a {shape} key, so it was not kept"),
            "proposal_secret",
        )
        .hinted("A proposal never carries the key: the human types it when they approve. If the key was pasted into the chat, it should be replaced at the provider, since it has been seen."));
    }
    Ok(())
}

/// Whose key `value` looks like and where that provider serves it, when its
/// shape says so.
pub fn key_home(value: &str) -> Option<(&'static str, &'static [&'static str])> {
    if OPENAI_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Some(("an OpenAI", &["openai.com"]));
    }
    let shape = av_core::scrub::key_shape_in(value)?;
    KEY_HOMES
        .iter()
        .find(|(name, _, _)| *name == shape)
        .map(|(_, who, domains)| (*who, *domains))
}

/// Whether `host` is one of `domains` or under one.
fn under(host: &str, domains: &[&str]) -> bool {
    domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Refuse a key whose shape names a provider none of `hosts` belongs to:
/// the case where a human was shown a host and did not read it.
pub fn refuse_misdirected_key(value: &str, hosts: &[String]) -> R<()> {
    if let Some((who, domains)) = key_home(value) {
        if !hosts.iter().any(|h| under(h, domains)) {
            return Err(refuse(
                format!(
                    "that looks like {who} key, but this credential would send it to {}; nothing was saved",
                    hosts.join(", ")
                ),
                "proposal_key_host",
            )
            .hinted("Deny this proposal, or add the key yourself with the right kind: agent-vault cred add"));
        }
    }
    Ok(())
}

/// A proposal as it is kept: the agent's fields, checked and filled in, and
/// the hosts the key could be sent to. Fails on anything a human should not
/// be asked to approve.
pub fn normalize(input: &Value, vault: &Vault) -> R<(Value, Vec<String>)> {
    let Value::Object(m) = input else {
        return Err(refuse(
            "a credential proposal is an object",
            "proposal_shape",
        ));
    };
    for k in m.keys() {
        if KEY_FIELDS.contains(&k.to_lowercase().as_str()) {
            return Err(refuse(
                format!("a credential proposal cannot carry {k}"),
                "proposal_secret",
            )
            .hinted("A proposal never carries the key: the human types it when they approve. Do not ask them for it."));
        }
        if !FIELDS.contains(&k.as_str()) && !CALL_FIELDS.contains(&k.as_str()) {
            return Err(refuse(
                format!("a credential proposal cannot carry {k}"),
                "proposal_shape",
            )
            .hinted(format!("A proposal names: {}.", FIELDS.join(", "))));
        }
    }
    refuse_key_shapes(input)?;
    let text = |k: &str| -> R<Option<String>> {
        match m.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
            Some(_) => Err(refuse(format!("{k} must be a string"), "proposal_shape")),
        }
    };
    let slug = text("slug")?.unwrap_or_default();
    if !av_core::placeholder::is_valid_slug(&slug) {
        return Err(refuse(
            format!(
                "{} is not a credential name: use [a-z0-9-], 1-24 characters",
                js_string(&Value::from(slug))
            ),
            "proposal_slug",
        ));
    }
    if vault.find_credential(&slug).v()?.is_some() {
        return Err(refuse(
            format!("a credential named {slug} already exists"),
            "proposal_slug",
        )
        .hinted(
            "A proposal only adds a new credential. Pick another name, or use the one that exists.",
        ));
    }
    let kind = text("kind")?
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| "http".into());
    let profile = av_core::profiles::get_profile(&kind)
        .map_err(|e| refuse(e.to_string(), "proposal_kind"))?;
    if !profile.implemented || profile.l4 {
        return Err(refuse(
            format!("a {kind} credential cannot be proposed"),
            "proposal_kind",
        ));
    }
    let asked_host = text("host")?
        .map(|h| h.to_lowercase())
        .map(|h| h.strip_suffix('.').map(str::to_string).unwrap_or(h))
        .filter(|h| !h.is_empty());
    let host = if profile.hosts.is_empty() {
        let Some(h) = asked_host else {
            return Err(refuse(
                format!("a {kind} credential must name its host"),
                "proposal_host",
            )
            .hinted("Give the exact API host, such as api.example.com."));
        };
        if !plain_host(&h) {
            return Err(refuse(
                format!("{} is not a host a human can check", js_string(&Value::from(h))),
                "proposal_host",
            )
            .hinted("Give a DNS name such as api.example.com, with an optional port: no scheme, path, IP address or single label."));
        }
        h
    } else {
        match asked_host {
            None => profile.hosts[0].to_string(),
            Some(h) if profile.hosts.contains(&h.as_str()) => h,
            Some(_) => {
                return Err(refuse(
                    format!("a {kind} key only goes to {}", profile.hosts.join(", ")),
                    "proposal_host",
                )
                .hinted("Leave host out: the profile already names where this kind of key goes."));
            }
        }
    };
    let field = match text("field")?.filter(|f| !f.is_empty()) {
        None => av_core::profiles::default_field(&kind).to_string(),
        Some(f) => {
            let named = profile.fields.iter().any(|pf| pf.name == f);
            if !av_core::placeholder::is_valid_field(&f) || (!profile.hosts.is_empty() && !named) {
                return Err(refuse(
                    format!(
                        "{} is not a field a {kind} credential has",
                        js_string(&Value::from(f))
                    ),
                    "proposal_field",
                ));
            }
            f
        }
    };
    let sites: Vec<String> = match m.get("sites").filter(|s| !s.is_null()) {
        None => av_core::profiles::default_sites(&kind, &field)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        Some(_) if !profile.hosts.is_empty() => {
            return Err(refuse(
                format!("the {kind} profile already says where its key goes"),
                "proposal_sites",
            )
            .hinted("Leave sites out for this kind."));
        }
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_SITES => {
            let mut out = Vec::new();
            for s in a {
                let Some(spec) = s.as_str() else {
                    return Err(refuse("each site is a string", "proposal_sites"));
                };
                if let Some(problem) = av_core::sites::chosen_site_problem(spec) {
                    return Err(refuse(problem, "proposal_sites"));
                }
                let site = av_core::sites::parse_site(spec)
                    .map_err(|e| refuse(e.0, "proposal_sites"))?;
                if !PROPOSABLE_SITES.contains(&site.kind) {
                    return Err(refuse(
                        format!("a proposal cannot put a key at {spec}"),
                        "proposal_sites",
                    ));
                }
                out.push(spec.to_string());
            }
            out
        }
        Some(_) => {
            return Err(refuse(
                format!("sites is a list of 1 to {MAX_SITES} places the key goes, such as header:authorization:Bearer"),
                "proposal_sites",
            ))
        }
    };
    let expires_at = text("expires_at")?.filter(|e| !e.is_empty());
    if expires_at
        .as_deref()
        .is_some_and(|e| parse_iso_ms(e).is_none())
    {
        return Err(refuse(
            "expires_at must be a date, YYYY-MM-DD",
            "proposal_expiry",
        ));
    }
    let hosts = policy::credential_host_ceiling(
        Some(&host),
        &profile
            .hosts
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );
    let mut proposal =
        json!({"slug": slug, "kind": kind, "host": host, "field": field, "sites": sites});
    if let Some(e) = expires_at {
        proposal["expires_at"] = e.into();
    }
    Ok((proposal, hosts))
}

/// `credential stripe (http) · sent only to api.stripe.com`.
pub fn summarize(proposal: &Value, hosts: &[String]) -> String {
    format!(
        "credential {} ({}) · sent only to {}",
        js_string(&proposal["slug"]),
        js_string(&proposal["kind"]),
        hosts.join(", ")
    )
}

/// One proposal. Holds no secret, so all of it is persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpRecord {
    /// `cp_<ulid>`.
    pub id: String,
    /// SHA-256 of the poll secret only the proposing agent holds.
    pub poll_hash: String,
    /// The checked proposal ([`normalize`]).
    pub proposal: Value,
    /// Every host the key could be sent to.
    pub hosts: Vec<String>,
    /// [`summarize`].
    pub summary: String,
    /// The agent's reason: shown, never believed.
    #[serde(default)]
    pub reason_untrusted: Option<String>,
    /// `pending | approved | denied | expired`.
    pub state: String,
    /// ISO.
    pub created_at: String,
    /// ISO.
    #[serde(default)]
    pub decided_at: Option<String>,
    /// The credential made, once approved.
    #[serde(default)]
    pub cred: Option<String>,
}

impl CpRecord {
    /// What a human (or the UI) is shown.
    pub fn redact(&self) -> Value {
        json!({
            "id": self.id, "summary": self.summary, "proposal": self.proposal, "hosts": self.hosts,
            "agent_reason_untrusted": self.reason_untrusted, "state": self.state,
            "created_at": self.created_at, "decided_at": self.decided_at,
        })
    }

    /// Whether `secret` is this proposal's poll secret.
    pub fn may_poll(&self, secret: Option<&str>) -> bool {
        let Some(secret) = secret.filter(|s| !s.is_empty()) else {
            return false;
        };
        !self.poll_hash.is_empty()
            && ct_eq(
                self.poll_hash.as_bytes(),
                sha256_hex(secret.as_bytes()).as_bytes(),
            )
    }
}

/// The store.
#[derive(Debug, Default)]
pub struct CredProposalStore {
    items: Vec<CpRecord>,
    saved: Option<String>,
}

impl CredProposalStore {
    /// Read back the persisted proposals; a row that does not read is dropped.
    pub fn load(vault: &Vault) -> CredProposalStore {
        let items = match vault.cred_proposals() {
            Ok(Value::Array(rows)) => rows
                .into_iter()
                .filter_map(|r| serde_json::from_value::<CpRecord>(r).ok())
                .collect(),
            _ => Vec::new(),
        };
        let mut s = CredProposalStore { items, saved: None };
        s.saved = Some(s.snapshot());
        s
    }

    fn snapshot(&self) -> String {
        serde_json::to_string(&self.items).unwrap_or_default()
    }
}

impl Core {
    fn cp_save(&mut self) {
        let now = self.cp.snapshot();
        if self.cp.saved.as_deref() == Some(now.as_str()) {
            return;
        }
        let rows = serde_json::to_value(&self.cp.items).unwrap_or(Value::Array(Vec::new()));
        if self.vault.save_cred_proposals(&rows).is_ok() {
            self.cp.saved = Some(now);
        }
    }

    fn cp_sweep(&mut self) {
        let now = now_ms();
        let mut expired = Vec::new();
        let before = self.cp.items.len();
        self.cp.items.retain_mut(|r| {
            let age = now - parse_iso_ms(&r.created_at).unwrap_or(0);
            if r.state == "pending" && age > PENDING_TTL_MS as i64 {
                r.state = "expired".into();
                r.decided_at = Some(iso_now());
                expired.push(r.id.clone());
                return true;
            }
            let settled_for =
                now - parse_iso_ms(r.decided_at.as_deref().unwrap_or(&r.created_at)).unwrap_or(0);
            r.state == "pending" || settled_for <= SETTLED_TTL_MS as i64
        });
        for id in &expired {
            self.audit_opt("cred_proposal.expired", json!({"request_id": id}));
        }
        if !expired.is_empty() || self.cp.items.len() != before {
            self.cp_save();
        }
    }

    /// Open a proposal for a human: returns the record and the one-time poll
    /// secret.
    pub fn cp_propose(&mut self, input: &Value) -> R<(CpRecord, String)> {
        let (proposal, hosts) = normalize(input, &self.vault)?;
        self.cp_sweep();
        let slug = proposal["slug"].clone();
        let pending: Vec<&CpRecord> = self
            .cp
            .items
            .iter()
            .filter(|r| r.state == "pending")
            .collect();
        if pending.iter().any(|r| r.proposal["slug"] == slug) {
            return Err(refuse(
                format!("{} is already waiting for a human", js_string(&slug)),
                "proposal_slug",
            )
            .hinted("Poll the proposal you already made instead of making another."));
        }
        if pending.len() >= MAX_PENDING {
            return Err(refuse(
                "too many credential proposals are already waiting",
                "cred_proposals",
            ));
        }
        while self.cp.items.len() >= MAX_ITEMS {
            let Some(pos) = self.cp.items.iter().position(|r| r.state != "pending") else {
                break;
            };
            self.cp.items.remove(pos);
        }
        let reason = match input.get("reason") {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(String::from_utf16_lossy(
                &s.trim().encode_utf16().take(MAX_REASON).collect::<Vec<_>>(),
            )),
            _ => None,
        };
        let secret = random_b64url(24);
        let record = CpRecord {
            id: av_store::ids::id::cred_proposal(),
            poll_hash: sha256_hex(secret.as_bytes()),
            summary: summarize(&proposal, &hosts),
            proposal,
            hosts,
            reason_untrusted: reason,
            state: "pending".into(),
            created_at: iso_now(),
            decided_at: None,
            cred: None,
        };
        self.cp.items.push(record.clone());
        self.cp_save();
        self.audit_opt(
            "cred_proposal.opened",
            json!({
                // `kind` is the audit chain's own field.
                "request_id": record.id, "actor": "agent", "slug": record.proposal["slug"],
                "connector": record.proposal["kind"], "hosts": record.hosts,
            }),
        );
        self.notify_pending(json!({"kind": "credential", "id": record.id, "headline": record.summary, "created_at": record.created_at}));
        Ok((record, secret))
    }

    /// A proposal by id, after a sweep.
    pub fn cp_get(&mut self, id: &str) -> Option<CpRecord> {
        self.cp_sweep();
        self.cp.items.iter().find(|r| r.id == id).cloned()
    }

    /// Every pending proposal, oldest first.
    pub fn cp_pending(&mut self) -> Vec<CpRecord> {
        self.cp_sweep();
        self.cp
            .items
            .iter()
            .filter(|r| r.state == "pending")
            .cloned()
            .collect()
    }

    /// What the proposing agent learns when it polls.
    pub fn cp_poll(&mut self, id: &str, secret: Option<&str>) -> Value {
        let Some(record) = self.cp_get(id) else {
            return json!({"error": format!("no credential proposal {id}")});
        };
        if !record.may_poll(secret) {
            return json!({"error": "poll_secret does not match this proposal; only the agent that proposed it can poll it"});
        }
        match record.state.as_str() {
            "pending" => {
                json!({"state": "pending", "detail": "a human has not finished this yet. To keep waiting instead of ending your turn, poll again with wait_seconds; or carry on without it. Do not ask them for the key."})
            }
            "approved" => json!({
                "state": "approved", "cred": record.cred,
                "detail": "the credential exists now, with the key the human typed. To use it, ask for a session on it with vault_request_session.",
            }),
            "denied" => {
                json!({"state": "denied", "detail": "a human declined; do not propose the same credential again"})
            }
            other => {
                json!({"state": other, "detail": "nobody finished this in time; propose again only if it is still needed"})
            }
        }
    }

    /// The pending proposal a decision is about, or why there is none.
    pub fn cp_waiting(&mut self, id: &str) -> R<CpRecord> {
        let record = self
            .cp_get(id)
            .ok_or_else(|| d(C::NotFound, format!("no credential proposal {id}")))?;
        if record.state != "pending" {
            return Err(refuse(
                format!("that proposal was already {}", record.state),
                "cred_proposals",
            ));
        }
        Ok(record)
    }

    /// The `cred add` input an approval makes, after the checks only the
    /// approval can make: the human confirmed exactly these hosts, and the
    /// key's own shape does not say it belongs somewhere else.
    pub fn cp_approval_input(&mut self, record: &CpRecord, decision: &Value) -> R<Value> {
        let confirmed: Option<Vec<&str>> = decision
            .get("hosts")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect());
        let shown: Vec<&str> = record.hosts.iter().map(String::as_str).collect();
        if confirmed.as_ref() != Some(&shown) {
            return Err(refuse(
                "the hosts confirmed are not the hosts this key would be sent to; nothing was saved",
                "proposal_hosts",
            )
            .hinted("Show the human the proposal's hosts and send back exactly those."));
        }
        let value = match decision.get("value") {
            Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
            _ => return Err(refuse("type the key to save it", "proposal_value")),
        };
        refuse_misdirected_key(&value, &record.hosts)?;
        let mut input = record.proposal.clone();
        input["value"] = value.into();
        Ok(input)
    }

    /// Record an approval that made `cred`.
    pub fn cp_settle_approved(&mut self, id: &str, cred: &str) {
        if let Some(r) = self.cp.items.iter_mut().find(|r| r.id == id) {
            r.state = "approved".into();
            r.decided_at = Some(iso_now());
            r.cred = Some(cred.to_string());
        }
        self.cp_save();
        self.audit_opt(
            "cred_proposal.approved",
            json!({"request_id": id, "actor": "human", "slug": cred}),
        );
        self.decided();
    }

    /// Deny one proposal.
    pub fn cp_settle_denied(&mut self, id: &str, actor: &str) {
        if let Some(r) = self.cp.items.iter_mut().find(|r| r.id == id) {
            r.state = "denied".into();
            r.decided_at = Some(iso_now());
        }
        self.cp_save();
        self.audit_opt(
            "cred_proposal.denied",
            json!({"request_id": id, "actor": actor}),
        );
        self.decided();
    }

    /// Deny every pending proposal (a panic). Returns how many.
    pub fn cp_deny_all(&mut self, actor: &str) -> usize {
        let ids: Vec<String> = self.cp_pending().into_iter().map(|r| r.id).collect();
        for id in &ids {
            self.cp_settle_denied(id, actor);
        }
        ids.len()
    }
}

/// Fields of a decision: `{ id, granted, hosts?, value? }`.
pub const DECISION_FIELDS: [&str; 5] = ["id", "granted", "hosts", "value", "presence"];

/// Why a decision body cannot be used, or none.
pub fn decision_problem(input: &Value) -> Option<String> {
    let Value::Object(m) = input else {
        return Some("a decision is an object".into());
    };
    if let Some(k) = m.keys().find(|k| !DECISION_FIELDS.contains(&k.as_str())) {
        return Some(format!("a decision cannot carry {k}"));
    }
    if !m
        .get("id")
        .is_some_and(|i| i.as_str().is_some_and(|s| !s.is_empty()))
    {
        return Some("name the proposal to answer".into());
    }
    match m.get("granted") {
        Some(Value::Bool(true)) => None,
        Some(Value::Bool(false)) => m
            .get("value")
            .is_some()
            .then(|| "a denial carries no key".into()),
        _ => Some("the verdict must be true or false".into()),
    }
}
