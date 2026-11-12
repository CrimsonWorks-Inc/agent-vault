//! The gateway request pipeline: authenticate the session, route to a grant,
//! check policy, budget, spend, rate and quota, hold for approval, consume,
//! substitute, proxy upstream, scrub the response. Ports
//! `src/daemon/pipeline.js`.
//!
//! The two invariants the security tests assert hold here as in the JS:
//! every denial returns before an upstream connection exists, and a use is
//! consumed before the first upstream byte. Each synchronous stretch of the
//! JS (`Shared::run`) is one stretch here; the upstream request, reading the
//! response, decompressing and scrubbing it run outside the lock.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use av_core::errors::VaultError;
use av_core::policy::{self, Checked, HttpDecision, Policy};
use av_core::profiles::Profile;
use av_core::request_view::{
    query_params, request_view, QuerySeparator, RequestInput, RequestView,
};
use av_core::scrub::{ExtraPattern, ScrubEntry, Scrubber, ScrubberOptions};
use av_core::secret::{ExposeSecret, SecretString};
use av_core::substitute::{self as sub, Occurrence, ProxyRequest, Region};
use av_store::model::{
    CredentialRecord, GrantRecord, GrantState, PlaceholderRow, SessionRecord, SessionState,
};
use av_store::vault::{ListenerContext, UsableOptions};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;

use crate::err::{d, dr, internal, rule_of, DenyExt, C};
use crate::preview::{approval_preview, preview_part, PreviewDecision, PreviewRequest, PreviewSub};
use crate::state::{Core, Shared, StoreResult, VaultRef};
use crate::upstream::{Body, Pins, Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};
use crate::util::{
    as_integer, iso_now, js_f64, js_pretty, latin1_bytes, latin1_string, now_ms, num, parse_iso_ms,
};
use av_store::model::GrantRuntime;

/// Hosts the gateway accepts in `Host`. Ports `ALLOWED_HOSTS`
/// (module-private) in `src/daemon/pipeline.js`.
pub const ALLOWED_HOSTS: [&str; 6] = [
    "127.0.0.1",
    "localhost",
    "::1",
    "[::1]",
    "host.docker.internal",
    "host.containers.internal",
];

/// Request headers the gateway consumes and never forwards. Ports `CONSUMED`
/// (module-private) in `src/daemon/pipeline.js`.
pub const CONSUMED: [&str; 3] = ["av-session", "av-reason", "av-expect-placeholders"];

/// Hop-by-hop headers, never forwarded either way. Ports `HOP_BY_HOP`.
pub const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// A held request nobody answered is denied after this. Ports
/// `PENDING_TTL_MS` (module-private) in `src/daemon/pipeline.js`.
pub const PENDING_TTL_MS: u64 = 15 * 60_000;
/// Replay window for an approved request. Ports `REPLAY_TTL_MS`.
pub const REPLAY_TTL_MS: u64 = 5 * 60_000;
/// How long decided approvals stay visible. Ports `DECIDED_TTL_MS`.
pub const DECIDED_TTL_MS: u64 = 60 * 60_000;
/// Approvals held at once. Ports `MAX_APPROVALS`.
pub const MAX_APPROVALS: usize = 1000;
/// Denials remembered for `explainDenial`. Ports `MAX_DENIALS`.
pub const MAX_DENIALS: usize = 1000;
/// How long a denial stays explainable. Ports `DENIAL_TTL_MS`.
pub const DENIAL_TTL_MS: u64 = 60 * 60_000;
/// Largest decompressed response the scrubber reads. Ports `MAX_DECOMPRESSED`.
pub const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
/// Largest buffered upstream response. Ports `MAX_RESPONSE_BYTES`.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Largest single SSE event. Ports `MAX_EVENT_BYTES`.
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
/// SSE runs tracked for split-secret reassembly. Ports `MAX_SSE_PATHS`.
pub const MAX_SSE_PATHS: usize = 1024;
/// SSE index fields tracked per string. Ports `MAX_SSE_INDEXES`.
pub const MAX_SSE_INDEXES: usize = 4;
/// Largest approval preview. Ports `PREVIEW_MAX`.
pub const PREVIEW_MAX: usize = 8192;

/// Upstream failures that happen before any byte could have reached the
/// server, so the use is refunded. Ports `PRE_CONNECT_ERRORS`.
pub const PRE_CONNECT_ERRORS: [&str; 11] = [
    "ENOTFOUND",
    "EAI_AGAIN",
    "ECONNREFUSED",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "EADDRNOTAVAIL",
    "ERR_TLS_CERT_ALTNAME_INVALID",
    "CERT_HAS_EXPIRED",
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "SELF_SIGNED_CERT_IN_CHAIN",
];

const SESSION_TOKEN: &str = r"avs1\.[0-9a-z]{12}\.[A-Za-z0-9_-]{20,}";
const AUDIT_METHODS: [&str; 9] = [
    "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT",
];
const AUDIT_ENCODINGS: [&str; 6] = ["identity", "gzip", "x-gzip", "deflate", "br", "zstd"];
const HOP_FORWARDED: [&str; 14] = [
    "accept",
    "user-agent",
    "accept-language",
    "cache-control",
    "if-none-match",
    "if-modified-since",
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
    "openai-organization",
    "openai-project",
    "x-api-version",
    "api-version",
    "x-github-api-version",
];
const SINGLE_VALUED: [&str; 5] = [
    "content-type",
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "authorization",
];

fn hop_never(lower: &str) -> bool {
    av_core::request_view::METHOD_OVERRIDE_HEADERS.contains(&lower)
        || [
            "host",
            "accept-encoding",
            "content-type",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "expect",
        ]
        .contains(&lower)
}

/// `auditMethod(m)`.
pub fn audit_method(m: &str) -> String {
    let up = m.to_uppercase();
    if AUDIT_METHODS.contains(&up.as_str()) {
        up
    } else {
        "OTHER".into()
    }
}

/// `auditEncoding(e)`.
pub fn audit_encoding(e: &str) -> Value {
    if e.is_empty() {
        Value::Null
    } else if AUDIT_ENCODINGS.contains(&e) {
        e.into()
    } else {
        "other".into()
    }
}

// ------------------------------------------------------------ the request

/// The listener a request arrived on. Ports the `req.listener` object the
/// daemon builds in `#bindListener` (`{ id, kind, remote, advertise }`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerInfo {
    /// Listener id.
    pub id: String,
    /// `tls` or `tcp`.
    pub kind: String,
    /// Off loopback.
    pub remote: bool,
    /// Extra host names it answers to.
    pub advertise: Vec<String>,
}

impl ListenerInfo {
    fn ctx(&self) -> ListenerContext {
        ListenerContext {
            id: Some(self.id.clone()),
            kind: Some(self.kind.clone()),
            remote: self.remote,
        }
    }
}

/// One proxied request as the gateway received it. Ports the `req` argument
/// shape `{method, path, query, headers, body, listener?}` of
/// `Pipeline.handle` in `src/daemon/pipeline.js`.
#[derive(Debug, Clone, Default)]
pub struct GatewayRequest {
    /// HTTP method.
    pub method: String,
    /// Path, beginning `/p/<slug>/`.
    pub path: String,
    /// Raw query string, without `?`.
    pub query: String,
    /// Headers in arrival order (as Node's `req.headers` gives them).
    pub headers: Vec<(String, String)>,
    /// Request body; `None` when empty.
    pub body: Option<Vec<u8>>,
    /// The listener it arrived on, if not the loopback gateway.
    pub listener: Option<ListenerInfo>,
}

impl GatewayRequest {
    fn proxy(&self) -> ProxyRequest {
        ProxyRequest {
            method: self.method.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }

    fn listener_ctx(&self) -> Option<ListenerContext> {
        self.listener.as_ref().map(ListenerInfo::ctx)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A streamed (SSE) response body: scrubbed frames.
pub type FrameStream = mpsc::Receiver<Vec<u8>>;

/// The gateway's answer. Ports the `{status, headers, body, requestId}`
/// result of `Pipeline.handle`; a streamed response has `stream` instead.
#[derive(Debug, Default)]
pub struct GatewayResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers (unique names, in order).
    pub headers: Vec<(String, String)>,
    /// Scrubbed response body.
    pub body: Vec<u8>,
    /// A streamed body, when the upstream sent an event stream.
    pub stream: Option<FrameStream>,
    /// The request id the agent can pass to `vault_explain_denial`.
    pub request_id: Option<String>,
    /// The denial, when it was one (`error` in the JS result).
    pub error: Option<VaultError>,
}

impl GatewayResponse {
    /// The first header named `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn set_header(h: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some(e) = h.iter_mut().find(|(n, _)| n == name) {
        e.1 = value;
    } else {
        h.push((name.to_string(), value));
    }
}

/// Construction options. Ports the `opts` of `new Pipeline(vault, opts)`.
#[derive(Clone, Default)]
pub struct PipelineOptions {
    /// Override for [`ALLOWED_HOSTS`]. Ports `opts.allowedHosts`.
    pub allowed_hosts: Option<Vec<String>>,
    /// Scrubber nested-view budget override. Ports `opts.scrubBudget`.
    pub scrub_budget: Option<(Option<usize>, Option<usize>)>,
    /// The network. Ports `opts.fetchImpl`.
    pub upstream: Option<Arc<dyn Upstream>>,
}

// ----------------------------------------------------------- approvals

/// One held request. Ports the approval objects of `#approval`.
#[derive(Debug, Clone)]
pub struct Approval {
    /// `ap_<ulid>`.
    pub id: String,
    /// The request hash it is keyed by.
    pub request_hash: String,
    /// The grant.
    pub grant_id: String,
    /// What the human sees.
    pub summary: String,
    /// The agent's reason, cleaned.
    pub reason: Option<String>,
    /// F13 preview.
    pub preview: Value,
    /// `pending | granted | consumed | denied`.
    pub state: String,
    /// ISO.
    pub created_at: String,
    /// ISO, once decided.
    pub decided_at: Option<String>,
    /// Why it was denied in bulk.
    pub denied_reason: Option<String>,
    /// ISO, once it ran.
    pub executed_at: Option<String>,
    /// The stored response, for a replay.
    pub result: Option<StoredResult>,
}

impl Approval {
    /// The approval as the JS object reads, without `result` (`approvalView`).
    pub fn view(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("request_hash".into(), self.request_hash.clone().into());
        m.insert("grant_id".into(), self.grant_id.clone().into());
        m.insert("summary".into(), self.summary.clone().into());
        m.insert(
            "reason".into(),
            self.reason.clone().map_or(Value::Null, Value::from),
        );
        m.insert("preview".into(), self.preview.clone());
        m.insert("state".into(), self.state.clone().into());
        m.insert("created_at".into(), self.created_at.clone().into());
        if let Some(v) = &self.decided_at {
            m.insert("decided_at".into(), v.clone().into());
        }
        if let Some(v) = &self.denied_reason {
            m.insert("denied_reason".into(), v.clone().into());
        }
        if let Some(v) = &self.executed_at {
            m.insert("executed_at".into(), v.clone().into());
        }
        Value::Object(m)
    }
}

/// A buffered response kept for an approved request's replay.
#[derive(Debug, Clone)]
pub struct StoredResult {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    host: String,
    path_rule: Option<usize>,
    route_rule: Option<usize>,
    audit_path: Option<String>,
    redactions: usize,
    spend: Option<Value>,
}

#[derive(Debug, Clone)]
struct Denial {
    at: i64,
    session_id: Option<String>,
    detail: Option<String>,
    hint: Option<String>,
}

/// The pipeline's in-memory tables. Ports the private fields of
/// `class Pipeline` and `this.approvals`.
pub struct PipelineState {
    /// Request hash → approval, in insertion order.
    pub approvals: Vec<(String, Approval)>,
    buckets: HashMap<String, (f64, Instant)>,
    in_flight: HashMap<String, u64>,
    preflight_buckets: HashMap<String, (u32, Instant)>,
    denials: Vec<(String, Denial)>,
    spend_recovered: bool,
    allowed_hosts: Vec<String>,
    scrub_budget: (Option<usize>, Option<usize>),
}

impl Default for PipelineState {
    fn default() -> Self {
        PipelineState {
            approvals: Vec::new(),
            buckets: HashMap::new(),
            in_flight: HashMap::new(),
            preflight_buckets: HashMap::new(),
            denials: Vec::new(),
            spend_recovered: false,
            allowed_hosts: ALLOWED_HOSTS.iter().map(|s| s.to_string()).collect(),
            scrub_budget: (None, None),
        }
    }
}

// ------------------------------------------------------------- routing

#[derive(Debug, Clone)]
struct RouteInfo {
    slug: String,
    cred: CredentialRecord,
    grant: GrantRecord,
    host: String,
    port: Option<String>,
    scheme: String,
    path: String,
    profile: &'static Profile,
}

fn profile_of(kind: &str) -> Result<&'static Profile, VaultError> {
    av_core::profiles::get_profile(kind).map_err(|e| internal(e.to_string()))
}

fn grant_expired(slug: Option<&str>) -> VaultError {
    dr(
        C::GrantExpired,
        format!(
            "this session's grant for {} expired",
            slug.unwrap_or("this credential")
        ),
        "grant_ttl",
    )
    .next(json!({"mcp": {"tool": "vault_request_session"}}))
}

fn effective_of(route: &RouteInfo, session: &SessionRecord) -> Policy {
    let ceiling = route.profile.policy_ceiling();
    policy::intersect(&[
        Some(&ceiling),
        Some(&session.policy),
        Some(&route.grant.policy),
    ])
}

/// The preflight stage recorder (`stage(next)` in `preflight`).
#[derive(Default)]
struct Stages {
    on: bool,
    current: String,
    checks: Vec<Value>,
}

impl Stages {
    fn stage(&mut self, next: &str) {
        if !self.on || next == self.current {
            return;
        }
        self.checks.push(json!({"stage": self.current, "ok": true}));
        self.current = next.to_string();
    }
}

// ------------------------------------------------------- one request's state

#[derive(Debug, Clone)]
struct Spending {
    kind: String,
    meter: av_core::model_usage::Meter,
    reservation: av_core::model_usage::Charge,
    grant_id: String,
    rid: String,
    request_id: String,
    settled: bool,
}

#[derive(Debug, Default)]
struct Resources {
    release: Option<String>,
    quota: Option<Value>,
    spend: Option<Spending>,
}

/// What `handle()` keeps across its stretches.
struct Ctx {
    request_id: String,
    started: i64,
    method: String,
    path: String,
    listener: Option<ListenerInfo>,
    consumed: Vec<String>,
    upstream_opened: bool,
    spent_approval: Option<String>,
    session: Option<SessionRecord>,
    route: Option<RouteInfo>,
    resources: Resources,
    presented: Vec<String>,
}

/// A check that passed and what goes upstream.
struct Plan {
    effective: Policy,
    decision: HttpDecision,
    overrides: Vec<String>,
    headers: Vec<(String, Vec<String>)>,
    body: Option<Vec<u8>>,
    url: String,
    credential_headers: HashSet<String>,
    injected: Vec<ScrubEntry>,
    last_row: String,
    approved_request_hash: Option<String>,
}

/// A finished proxy step, as `#proxy` returns it.
struct Proxied {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    stream: Option<FrameStream>,
    host: String,
    path_rule: Option<usize>,
    route_rule: Option<usize>,
    audit_path: Option<String>,
    redactions: usize,
    spend: Option<Value>,
}

impl From<StoredResult> for Proxied {
    fn from(r: StoredResult) -> Self {
        Proxied {
            status: r.status,
            headers: r.headers,
            body: r.body,
            stream: None,
            host: r.host,
            path_rule: r.path_rule,
            route_rule: r.route_rule,
            audit_path: r.audit_path,
            redactions: r.redactions,
            spend: r.spend,
        }
    }
}

enum Checked1 {
    /// Answered without an upstream (202, replay).
    Done(Proxied),
    /// Go upstream.
    Send(Box<Plan>),
    /// Preflight's verdict.
    Would(&'static str, Option<String>),
}

// ------------------------------------------------------------- Core: steps

impl Core {
    fn pl_effective_for(&self, grant: &GrantRecord) -> R<Policy> {
        let cred = self
            .vault
            .credential(&grant.credential_id)
            .v()?
            .ok_or_else(|| {
                internal("Cannot read properties of undefined (reading 'connector_kind')")
            })?;
        let session = self.vault.session(&grant.session_id).v()?;
        let ceiling = profile_of(&cred.connector_kind)?.policy_ceiling();
        Ok(policy::intersect(&[
            Some(&ceiling),
            session.as_ref().map(|s| &s.policy),
            Some(&grant.policy),
        ]))
    }

    fn rt(&self, grant_id: &str) -> GrantRuntime {
        // A grant with no row reads as the JS defaults (a fresh window,
        // zero spend), as `grant.quota_state` / `grant.spend` do in the JS.
        self.vault
            .grant_runtime(grant_id)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    fn rt_set(&mut self, grant_id: &str, rt: GrantRuntime) {
        // The JS sets the field on the grant object and saves with
        // `durable: false`; a grant that has gone away has nowhere to keep it.
        let _ = self.vault.set_grant_runtime(grant_id, &rt);
    }

    /// `#refuseBrowsers(req)`.
    fn pl_refuse_browsers(&self, req: &GatewayRequest) -> R<()> {
        let h = |n: &str| req.header(n).filter(|v| !v.is_empty());
        if h("origin").is_some() || h("sec-fetch-site").is_some() {
            return Err(dr(C::BrowserOrigin, "requests carrying Origin or Sec-Fetch-Site are refused", "browser_origin")
                .hinted("This endpoint is not reachable from a web page. A DNS-rebinding attack looks exactly like this."));
        }
        let host = h("host")
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        let advertised = req
            .listener
            .as_ref()
            .is_some_and(|l| l.advertise.contains(&host));
        if !host.is_empty() && !self.pl.allowed_hosts.contains(&host) && !advertised {
            return Err(dr(
                C::BrowserOrigin,
                format!("Host header {host} is not an allowed gateway host"),
                "allowed_hosts",
            ));
        }
        Ok(())
    }

    /// `#authenticate(req, { touch })`.
    fn pl_authenticate(&mut self, req: &GatewayRequest, touch: bool) -> R<SessionRecord> {
        let explicit = sub::get_header(&req.proxy(), "av-session")
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        let auth = sub::get_header(&req.proxy(), "authorization")
            .unwrap_or("")
            .to_string();
        let bearer_re = av_core::jsre::compile(r"(?i)^bearer\s+(avs1\.\S+)$").expect("bearer");
        let bearer = bearer_re
            .captures(&auth)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        let token = explicit.or(bearer);
        let opts = UsableOptions {
            peek: !touch,
            record: false,
        };
        if let Some(token) = token {
            let session = self
                .vault
                .session_by_token(js_trim(&token))
                .v()?
                .ok_or_else(|| d(C::SessionRequired, "session token is not recognised"))?;
            self.vault
                .assert_session_usable(Some(&session), req.listener_ctx().as_ref(), opts)
                .v()?;
            if touch {
                self.vault.touch_session(&session.id).v()?;
            }
            return Ok(session);
        }
        let located = sub::locate(&req.proxy());
        let carrier = located
            .occurrences
            .iter()
            .find(|o| matches!(o.location.region, Region::Header | Region::Basic));
        if let Some(carrier) = carrier {
            if req.listener.as_ref().is_some_and(|l| l.remote) {
                return Err(dr(
                    C::SessionRequired,
                    "a placeholder alone does not authorize on a network listener",
                    "remote_carrier",
                )
                .hinted(
                    "Send the session token in Authorization: Bearer as well as the placeholder.",
                ));
            }
            let session = self
                .vault
                .session(&carrier.parsed.sid)
                .v()?
                .ok_or_else(|| {
                    d(
                        C::PhCrossSession,
                        "the placeholder names a session that does not exist",
                    )
                })?;
            let k_ph = self.vault.k_ph().v()?;
            if !av_core::placeholder::verify(&k_ph, &carrier.parsed) {
                return Err(malformed(&carrier.location));
            }
            if self
                .vault
                .resolve_placeholder(&carrier.parsed)
                .v()?
                .is_none()
            {
                return Err(unknown_placeholder(&carrier.location));
            }
            self.vault
                .assert_session_usable(Some(&session), req.listener_ctx().as_ref(), opts)
                .v()?;
            if touch {
                self.vault.touch_session(&session.id).v()?;
            }
            return Ok(session);
        }
        Err(d(C::SessionRequired, "no session carrier on this request")
            .next(json!({"cli": ["agent-vault session create --cred <slug>"], "mcp": {"tool": "vault_request_session"}}))
            .hinted("Send Authorization: Bearer <session token>, or a placeholder at a declared header site."))
    }

    fn pl_check_quarantine(cred: &CredentialRecord) -> R<()> {
        if cred.quarantine.is_some() {
            return Err(dr(
                C::Quarantined,
                format!("{} is quarantined", cred.slug),
                "quarantine",
            )
            .hinted("A human can release it: agent-vault cred release <slug>"));
        }
        Ok(())
    }

    /// `#peekGrant(grant)`.
    fn pl_peek_grant(&self, grant: &GrantRecord) -> R<()> {
        let slug = self
            .vault
            .credential(&grant.credential_id)
            .v()?
            .map(|c| c.slug);
        if grant.state == GrantState::Expired {
            return Err(grant_expired(slug.as_deref()));
        }
        if grant.state != GrantState::Active {
            return Err(d(C::NoGrant, "this grant is no longer active"));
        }
        // Written so that an expiry that does not parse (NaN) refuses.
        let live =
            av_store::vault::expiry_ms(grant.expires_at.as_deref()).partial_cmp(&(now_ms() as f64));
        if live != Some(std::cmp::Ordering::Greater) {
            return Err(grant_expired(slug.as_deref()));
        }
        Ok(())
    }

    /// `#route(req, session, stage, peek)`.
    fn pl_route(
        &mut self,
        req: &GatewayRequest,
        session: &SessionRecord,
        st: &mut Stages,
        peek: bool,
    ) -> R<RouteInfo> {
        let path = if req.path.is_empty() {
            "/"
        } else {
            req.path.as_str()
        };
        if let Some(rest) = path.strip_prefix("/p/") {
            let (slug, upstream_path) = match rest.find('/') {
                None => (rest.to_string(), "/".to_string()),
                Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            };
            let cred = self.vault.find_credential(&slug).v()?.ok_or_else(|| {
                d(C::NotFound, format!("no credential named {slug}")).next(
                    json!({"cli": ["agent-vault cred list"], "mcp": {"tool": "vault_list_creds"}}),
                )
            })?;
            st.stage("quarantine");
            Self::pl_check_quarantine(&cred)?;
            st.stage("grant");
            let grant = self
                .vault
                .grants_for_session(&session.id)
                .v()?
                .into_iter()
                .find(|g| g.credential_id == cred.id);
            let Some(grant) = grant else {
                if self
                    .vault
                    .find_grant(&session.id, &cred.id)
                    .v()?
                    .is_some_and(|g| g.state == GrantState::Expired)
                {
                    return Err(grant_expired(Some(&slug)));
                }
                return Err(d(C::NoGrant, format!("this session has no grant for {slug}"))
                    .next(json!({"cli": ["agent-vault cred list --available"], "mcp": {"tool": "vault_list_creds"}})));
            };
            let grant = if peek {
                self.pl_peek_grant(&grant)?;
                grant
            } else {
                self.vault.assert_grant_live(Some(&grant)).v()?
            };
            let profile = profile_of(&cred.connector_kind)?;
            let raw = conn_str(&cred, "host")
                .unwrap_or_else(|| profile.hosts.first().copied().unwrap_or("").to_string());
            let (host, port) = split_port(&raw);
            let scheme = conn_str(&cred, "scheme").unwrap_or_else(|| "https".into());
            return Ok(RouteInfo {
                slug,
                cred,
                grant,
                host,
                port,
                scheme,
                path: upstream_path,
                profile,
            });
        }
        if let Some(rest) = path.strip_prefix("/t/") {
            let mut parts: Vec<&str> = rest.split('/').collect();
            let scheme = if parts.is_empty() {
                ""
            } else {
                parts.remove(0)
            }
            .to_string();
            let raw_host = if parts.is_empty() {
                ""
            } else {
                parts.remove(0)
            }
            .to_string();
            let upstream_path = format!("/{}", parts.join("/"));
            if scheme.is_empty() || raw_host.is_empty() {
                return Err(d(
                    C::NotFound,
                    "generic target form is /t/<scheme>/<host>/<path>",
                ));
            }
            let host = policy::host_only(&raw_host);
            for g in self.vault.grants_for_session(&session.id).v()? {
                let cred = self
                    .vault
                    .credential(&g.credential_id)
                    .v()?
                    .ok_or_else(|| {
                        internal("Cannot read properties of undefined (reading 'connector_kind')")
                    })?;
                let profile = profile_of(&cred.connector_kind)?;
                let ceiling = profile.policy_ceiling();
                let eff =
                    policy::intersect(&[Some(&ceiling), Some(&session.policy), Some(&g.policy)]);
                let hosts = match &eff.hosts {
                    Some(Checked::Valid(h)) => h.clone(),
                    _ => Vec::new(),
                };
                if !hosts.iter().any(|p| policy::match_host(p, &host)) {
                    continue;
                }
                st.stage("quarantine");
                Self::pl_check_quarantine(&cred)?;
                st.stage("grant");
                let g = if peek {
                    self.pl_peek_grant(&g)?;
                    g
                } else {
                    self.vault.assert_grant_live(Some(&g)).v()?
                };
                let cred_raw = conn_str(&cred, "host").unwrap_or_default();
                let cred_host = policy::host_only(&cred_raw);
                let cred_port = if cred_host == host {
                    split_port(&cred_raw).1
                } else {
                    None
                };
                let cred_scheme = conn_str(&cred, "scheme").unwrap_or_else(|| "https".into());
                if scheme != cred_scheme && cred_scheme == "https" {
                    return Err(dr(
                        C::PolicyDenied,
                        format!(
                            "{} is an https credential; {scheme} would send it in the clear",
                            cred.slug
                        ),
                        "scheme_downgrade",
                    )
                    .hinted(format!(
                        "Use /t/https/{host}/... or the credential's own route, /p/{}/...",
                        cred.slug
                    )));
                }
                let use_scheme = if scheme == "https" {
                    "https".to_string()
                } else {
                    cred_scheme
                };
                return Ok(RouteInfo {
                    slug: cred.slug.clone(),
                    cred,
                    grant: g,
                    host,
                    port: cred_port,
                    path: upstream_path,
                    scheme: use_scheme,
                    profile,
                });
            }
            return Err(d(
                C::NoGrant,
                format!(
                    "no grant in this session allows host {}",
                    policy::host_only(&raw_host)
                ),
            ));
        }
        Err(d(C::NotFound, format!("unknown route {path}")).hinted(
            "Use /p/<credential>/<path> for a configured credential, or /t/<scheme>/<host>/<path>.",
        ))
    }

    // -------------------------------------------------------- the limits

    /// `#budget(grant, effective)`.
    fn pl_budget(&self, grant: &GrantRecord, effective: &Policy) -> R<()> {
        match policy::budget_limit(effective.budget.as_ref()) {
            policy::BudgetLimit::Unlimited => Ok(()),
            policy::BudgetLimit::Unreadable => Err(dr(
                C::PolicyDenied,
                "this grant has a budget whose limit is not a whole number of requests, so no request can be counted against it",
                "budget_invalid",
            )
            .hinted("Recreate the grant with a numeric budget limit.")),
            policy::BudgetLimit::Limit(limit) => {
                if grant.budget_used > policy::MAX_SAFE_INTEGER {
                    return Err(dr(
                        C::PolicyDenied,
                        "this grant has a budget whose limit is not a whole number of requests, so no request can be counted against it",
                        "budget_invalid",
                    )
                    .hinted("Recreate the grant with a numeric budget limit."));
                }
                if grant.budget_used >= limit {
                    return Err(dr(C::PolicyDenied, format!("grant budget of {limit} requests is spent"), "budget")
                        .hinted("A human must widen the grant or start a new session."));
                }
                Ok(())
            }
        }
    }

    /// `#validLimit(effective, field)`.
    fn pl_valid_limit(effective: &Policy, field: &str) -> R<()> {
        let v = serde_json::to_value(effective).unwrap_or(Value::Null);
        let Some(value) = v.get(field) else {
            return Ok(());
        };
        let mut layer = Map::new();
        layer.insert(field.into(), value.clone());
        if !policy::validate_json(&Value::Object(layer), &Default::default()).is_empty() {
            return Err(dr(
                C::PolicyDenied,
                format!("the {field} limit is invalid"),
                &format!("{field}_invalid"),
            ));
        }
        Ok(())
    }

    fn pl_prune_grants_map<T>(&self, map: &mut HashMap<String, T>, sessions: bool) {
        let now = now_ms() as f64;
        let live: HashSet<String> = if sessions {
            self.vault
                .sessions()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| {
                    s.state == SessionState::Active
                        && s.expires_at
                            .as_deref()
                            .is_none_or(|e| parse_iso_ms(e).is_some_and(|ms| ms as f64 > now))
                })
                .map(|s| s.id)
                .collect()
        } else {
            self.vault
                .grants()
                .unwrap_or_default()
                .into_iter()
                .filter(|g| {
                    g.state == GrantState::Active
                        && g.expires_at
                            .as_deref()
                            .is_none_or(|e| parse_iso_ms(e).is_some_and(|ms| ms as f64 > now))
                })
                .map(|g| g.id)
                .collect()
        };
        if map.len() > live.len() {
            map.retain(|k, _| live.contains(k));
        }
    }

    /// `#rate(grant, effective, peek)`.
    fn pl_rate(&mut self, grant: &GrantRecord, effective: &Policy, peek: bool) -> R<Option<f64>> {
        Self::pl_valid_limit(effective, "rate")?;
        let Some(Checked::Valid(rate)) = &effective.rate else {
            return Ok(None);
        };
        let count = rate.count as f64;
        let per = per_ms(&serde_json::to_value(rate.per).unwrap_or(Value::Null));
        let now = Instant::now();
        let tokens = match self.pl.buckets.get(&grant.id) {
            Some((t, at)) => {
                count.min(t + now.duration_since(*at).as_secs_f64() * 1000.0 * count / per)
            }
            None => count,
        };
        if !tokens.is_finite() || tokens < 0.0 {
            return Err(dr(C::PolicyDenied, "rate state is invalid", "rate_invalid"));
        }
        if tokens < 1.0 {
            let wait = ((1.0 - tokens) * per / count / 1000.0).ceil().max(1.0) as u64;
            return Err(
                dr(C::QuotaExceeded, "the grant rate limit was reached", "rate").retry(wait),
            );
        }
        if !peek {
            self.pl
                .buckets
                .insert(grant.id.clone(), (tokens - 1.0, now));
            let mut b = std::mem::take(&mut self.pl.buckets);
            self.pl_prune_grants_map(&mut b, false);
            self.pl.buckets = b;
        }
        Ok(Some(tokens))
    }

    /// `#quota(grant, effective, enforce)`: the window state, not yet saved.
    fn pl_quota(&self, grant: &GrantRecord, effective: &Policy, enforce: bool) -> R<Option<Value>> {
        Self::pl_valid_limit(effective, "quota")?;
        let Some(Checked::Valid(q)) = &effective.quota else {
            return Ok(None);
        };
        let window_ms = window_ms(&serde_json::to_value(q.window).unwrap_or(Value::Null)) as i64;
        let now = now_ms();
        let stored = self.rt(&grant.id).quota_state;
        let mut state = stored.clone().unwrap_or_else(
            || json!({"window_ms": window_ms, "start": now, "count": 0, "prev": 0}),
        );
        let get = |s: &Value, k: &str| s.get(k).and_then(as_integer);
        let (Some(w), Some(start), Some(count), Some(prev)) = (
            get(&state, "window_ms"),
            get(&state, "start"),
            get(&state, "count"),
            get(&state, "prev"),
        ) else {
            return Err(dr(
                C::PolicyDenied,
                "quota state is invalid",
                "quota_invalid",
            ));
        };
        if w <= 0 || count < 0 || prev < 0 {
            return Err(dr(
                C::PolicyDenied,
                "quota state is invalid",
                "quota_invalid",
            ));
        }
        let (mut start, mut count, mut prev) = (start, count, prev);
        if w != window_ms {
            start = now.max(start);
            count += prev;
            prev = 0;
        }
        if now >= start + window_ms {
            prev = if now >= start + 2 * window_ms {
                0
            } else {
                count
            };
            start += window_ms * ((now - start) / window_ms);
            count = 0;
        }
        let estimate =
            prev as f64 * (1.0 - ((now - start).max(0) as f64 / window_ms as f64)) + count as f64;
        if enforce && estimate + 1.0 > q.count as f64 {
            let wait = (((start + window_ms - now) as f64) / 1000.0)
                .ceil()
                .max(1.0) as u64;
            return Err(dr(C::QuotaExceeded, "the rolling quota was reached", "quota").retry(wait));
        }
        state = json!({"window_ms": window_ms, "start": start, "count": count, "prev": prev});
        Ok(Some(state))
    }

    /// `#acquire(grant, effective)`: returns the grant id to release.
    fn pl_acquire(&mut self, grant: &GrantRecord, effective: &Policy) -> R<String> {
        Self::pl_valid_limit(effective, "max_concurrent")?;
        let n = *self.pl.in_flight.get(&grant.id).unwrap_or(&0);
        if let Some(Checked::Valid(max)) = &effective.max_concurrent {
            if n >= *max {
                return Err(dr(
                    C::QuotaExceeded,
                    "the concurrency limit was reached",
                    "max_concurrent",
                )
                .retry(1));
            }
        }
        self.pl.in_flight.insert(grant.id.clone(), n + 1);
        let mut m = std::mem::take(&mut self.pl.in_flight);
        self.pl_prune_grants_map(&mut m, false);
        self.pl.in_flight = m;
        Ok(grant.id.clone())
    }

    /// The release function `#acquire` returns.
    fn pl_release(&mut self, grant_id: &str) {
        let count = *self.pl.in_flight.get(grant_id).unwrap_or(&0);
        if count <= 1 {
            self.pl.in_flight.remove(grant_id);
        } else {
            self.pl.in_flight.insert(grant_id.to_string(), count - 1);
        }
    }

    // ------------------------------------------------------------ spend

    /// `#spendState(grant)`.
    fn pl_spend_state(&self, grant_id: &str) -> R<Value> {
        let state = self
            .rt(grant_id)
            .spend
            .unwrap_or_else(|| json!({"tokens_used": 0, "usd_micros_used": 0, "reserved": {}}));
        let bad = || dr(C::PolicyDenied, "spend state is invalid", "spend_invalid");
        let whole = |k: &str| state.get(k).and_then(as_integer).filter(|n| *n >= 0);
        if whole("tokens_used").is_none()
            || whole("usd_micros_used").is_none()
            || !state.get("reserved").is_some_and(Value::is_object)
        {
            return Err(bad());
        }
        for r in state["reserved"]
            .as_object()
            .map(|m| m.values().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            let ok = ["tokens", "usd_micros", "at"]
                .iter()
                .all(|k| r.get(*k).and_then(as_integer).is_some())
                && r["tokens"].as_i64().unwrap_or(-1) >= 0
                && r["usd_micros"].as_i64().unwrap_or(-1) >= 0;
            if !ok {
                return Err(dr(
                    C::PolicyDenied,
                    "spend reservation is invalid",
                    "spend_invalid",
                ));
            }
        }
        Ok(state)
    }

    /// `#checkSpend(grant, effective, route, view, decision)`.
    fn pl_check_spend(
        &self,
        grant: &GrantRecord,
        effective: &Policy,
        route: &RouteInfo,
        view: &RequestView<'_>,
        decision: &HttpDecision,
    ) -> R<Option<Spending>> {
        let kind = route.cred.connector_kind.clone();
        if effective.spend.is_none()
            || !av_core::model_usage::METERED_KINDS.contains(&kind.as_str())
        {
            return Ok(None);
        }
        let limit = match &effective.spend {
            Some(Checked::Valid(s))
                if s.tokens.is_none_or(|t| t <= policy::MAX_SAFE_INTEGER)
                    && s.usd_micros.is_none_or(|t| t <= policy::MAX_SAFE_INTEGER) =>
            {
                *s
            }
            _ => {
                return Err(dr(
                    C::PolicyDenied,
                    "this grant has a spend limit that is not a whole number",
                    "spend_invalid",
                ))
            }
        };
        let meter = av_core::model_usage::meter_request(
            &kind,
            &av_core::model_usage::MeterInput {
                method: Some(&decision.method),
                path: Some(&decision.path),
                content_type: Some(&view.content_type),
                body: view.body,
            },
        )?;
        if meter.unmodeled {
            return Err(dr(
                C::PolicyDenied,
                format!("{} {} is not an endpoint whose cost can be bounded, so it cannot run under a spend limit", decision.method, decision.path),
                "spend_unmodeled",
            ));
        }
        if !meter.metered || meter.free {
            return Ok(None);
        }
        let reservation = av_core::model_usage::reservation_for(
            &kind,
            &meter,
            av_core::model_usage::ReservationOptions {
                usd: limit.usd_micros.is_some(),
            },
        )?;
        let state = self.pl_spend_state(&grant.id)?;
        let reserved = |key: &str| -> i64 {
            state["reserved"].as_object().map_or(0, |m| {
                m.values().map(|r| r[key].as_i64().unwrap_or(0)).sum()
            })
        };
        for (key, lim, add) in [
            ("tokens", limit.tokens, reservation.tokens),
            ("usd_micros", limit.usd_micros, reservation.usd_micros),
        ] {
            let committed = state[format!("{key}_used")].as_i64().unwrap_or(0) + reserved(key);
            let total = committed as i128 + add as i128;
            if total > policy::MAX_SAFE_INTEGER as i128 {
                return Err(dr(
                    C::PolicyDenied,
                    "this grant's spend counters are not whole numbers",
                    "spend_invalid",
                ));
            }
            if let Some(lim) = lim {
                if total > lim as i128 {
                    let left = (lim as i64 - committed).max(0);
                    let say = if key == "tokens" {
                        format!("{left} more tokens")
                    } else {
                        format!("${:.2} more", left as f64 / 1e6)
                    };
                    let could = if key == "tokens" {
                        format!("{} tokens", reservation.tokens)
                    } else {
                        format!("${:.2}", reservation.usd_micros as f64 / 1e6)
                    };
                    return Err(dr(
                        C::PolicyDenied,
                        "this call could cost more than the spend limit has left",
                        "spend",
                    )
                    .hinted(format!(
                        "This grant may spend {say}; this call could cost up to {could}."
                    )));
                }
            }
        }
        Ok(Some(Spending {
            kind,
            meter,
            reservation,
            grant_id: grant.id.clone(),
            rid: String::new(),
            request_id: String::new(),
            settled: false,
        }))
    }

    /// `#recoverSpend()`.
    pub(crate) fn pl_recover_spend(&mut self) {
        if self.vault.locked() {
            return;
        }
        self.pl.spend_recovered = true;
        let grant_ids: Vec<String> = self
            .vault
            .grants()
            .map(|gs| gs.into_iter().map(|g| g.id).collect())
            .unwrap_or_default();
        for grant_id in grant_ids {
            let Ok(mut state) = self.pl_spend_state(&grant_id) else {
                continue;
            };
            let reserved: Vec<(String, Value)> = state["reserved"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            if reserved.is_empty() {
                continue;
            }
            for (rid, r) in reserved {
                self.audit_opt(
                    "spend.reservation_charged",
                    json!({"grant_id": grant_id, "reservation_id": rid, "reason": "restart"}),
                );
                state["tokens_used"] = json!(
                    state["tokens_used"].as_i64().unwrap_or(0) + r["tokens"].as_i64().unwrap_or(0)
                );
                state["usd_micros_used"] = json!(
                    state["usd_micros_used"].as_i64().unwrap_or(0)
                        + r["usd_micros"].as_i64().unwrap_or(0)
                );
                if let Some(m) = state["reserved"].as_object_mut() {
                    m.remove(&rid);
                }
            }
            let mut rt = self.rt(&grant_id);
            rt.spend = Some(state);
            self.rt_set(&grant_id, rt);
        }
    }

    fn pl_refund_spend(&mut self, sp: &mut Spending) {
        if sp.settled {
            return;
        }
        let mut rt = self.rt(&sp.grant_id);
        if let Some(m) = rt
            .spend
            .as_mut()
            .and_then(|s| s.get_mut("reserved"))
            .and_then(Value::as_object_mut)
        {
            m.remove(&sp.rid);
        }
        sp.settled = true;
        self.rt_set(&sp.grant_id.clone(), rt);
    }

    fn pl_settle_spend(
        &mut self,
        sp: Option<&mut Spending>,
        usage: Option<av_core::model_usage::Usage>,
        streamed: bool,
    ) -> Option<Value> {
        let sp = sp?;
        if sp.settled {
            return None;
        }
        let charge =
            av_core::model_usage::charge_for(&sp.kind, &sp.meter, &sp.reservation, usage.as_ref())
                .unwrap_or(sp.reservation);
        let settled = if usage.is_some() {
            "usage"
        } else {
            "reservation"
        };
        let result = json!({"reserved_tokens": sp.reservation.tokens, "charged_tokens": charge.tokens, "charged_usd_micros": charge.usd_micros, "settled": settled});
        if streamed {
            let _ = self.audit("spend.settled", json!({"request_id": sp.request_id, "grant_id": sp.grant_id, "charged_tokens": charge.tokens, "charged_usd_micros": charge.usd_micros, "settled": settled}));
        }
        let mut rt = self.rt(&sp.grant_id);
        let mut state = rt
            .spend
            .take()
            .unwrap_or_else(|| json!({"tokens_used": 0, "usd_micros_used": 0, "reserved": {}}));
        state["tokens_used"] =
            json!(state["tokens_used"].as_i64().unwrap_or(0) + charge.tokens as i64);
        state["usd_micros_used"] =
            json!(state["usd_micros_used"].as_i64().unwrap_or(0) + charge.usd_micros as i64);
        if let Some(m) = state.get_mut("reserved").and_then(Value::as_object_mut) {
            m.remove(&sp.rid);
        }
        rt.spend = Some(state);
        sp.settled = true;
        self.rt_set(&sp.grant_id.clone(), rt);
        Some(result)
    }

    /// `Pipeline.spendFor(grantId)`.
    pub fn pl_spend_for(&self, grant_id: &str) -> R<Option<Value>> {
        let Some(grant) = self.vault.grant(grant_id).v()? else {
            return Ok(None);
        };
        let effective = self.pl_effective_for(&grant)?;
        let Some(limit) = &effective.spend else {
            return Ok(None);
        };
        let state = self.pl_spend_state(grant_id)?;
        let (lt, lu) = match limit {
            Checked::Valid(s) => (s.tokens.map(Value::from), s.usd_micros.map(Value::from)),
            Checked::Invalid(v) => (v.get("tokens").cloned(), v.get("usd_micros").cloned()),
        };
        let sum = |k: &str| -> i64 {
            state["reserved"]
                .as_object()
                .map_or(0, |m| m.values().map(|r| r[k].as_i64().unwrap_or(0)).sum())
        };
        Ok(Some(json!({
            "tokens_used": state["tokens_used"], "usd_micros_used": state["usd_micros_used"],
            "reserved_tokens": sum("tokens"), "reserved_usd_micros": sum("usd_micros"),
            "limit_tokens": lt.unwrap_or(Value::Null), "limit_usd_micros": lu.unwrap_or(Value::Null),
            "prices_version": av_core::model_usage::PRICES_VERSION,
        })))
    }

    /// `Pipeline.limitsFor(grantId)`.
    pub fn pl_limits_for(&self, grant_id: &str) -> R<Option<Value>> {
        let Some(grant) = self.vault.grant(grant_id).v()? else {
            return Ok(None);
        };
        let effective = self.pl_effective_for(&grant)?;
        let rate = match &effective.rate {
            Some(Checked::Valid(r)) if Self::pl_valid_limit(&effective, "rate").is_ok() => {
                let per = per_ms(&serde_json::to_value(r.per).unwrap_or(Value::Null));
                let count = r.count as f64;
                let tokens = match self.pl.buckets.get(grant_id) {
                    Some((t, at)) => {
                        count.min(t + at.elapsed().as_secs_f64() * 1000.0 * count / per)
                    }
                    None => count,
                };
                let mut v = serde_json::to_value(r).unwrap_or(json!({}));
                v["tokens_now"] = num(tokens);
                v
            }
            _ => Value::Null,
        };
        let quota = match self.pl_quota(&grant, &effective, false) {
            Ok(Some(state)) => {
                let mut v = serde_json::to_value(&effective.quota).unwrap_or(json!({}));
                let w = state["window_ms"].as_f64().unwrap_or(1.0);
                let est = state["prev"].as_f64().unwrap_or(0.0)
                    * (1.0
                        - ((now_ms() as f64 - state["start"].as_f64().unwrap_or(0.0)).max(0.0)
                            / w))
                    + state["count"].as_f64().unwrap_or(0.0);
                v["estimate"] = num(est);
                v
            }
            _ => Value::Null,
        };
        let limit = match &effective.max_concurrent {
            Some(Checked::Valid(n)) => Value::from(*n),
            Some(Checked::Invalid(v)) => v.clone(),
            None => Value::Null,
        };
        Ok(Some(json!({
            "rate": rate,
            "max_concurrent": {"limit": limit, "in_flight": self.pl.in_flight.get(grant_id).copied().unwrap_or(0)},
            "quota": quota,
        })))
    }

    // ------------------------------------------------------- scrubbing

    /// `#extraPatterns()`: every stored scrub pattern, checked.
    fn pl_extra_patterns(&self) -> R<Vec<ExtraPattern>> {
        let mut out = Vec::new();
        for cred in self.vault.credential_records().v()? {
            for p in &cred.scrub_patterns {
                if av_core::scrub::compile_scrub_pattern(&p.source).is_err() {
                    return Err(dr(
                        C::Unscannable,
                        "a stored scrub pattern is invalid",
                        "scrub_pattern_invalid",
                    ));
                }
                out.push(ExtraPattern {
                    name: p.id.clone(),
                    source: p.source.clone(),
                });
            }
        }
        Ok(out)
    }

    fn pl_scrub_opts(&self) -> R<ScrubberOptions> {
        Ok(ScrubberOptions {
            extra_patterns: self.pl_extra_patterns()?,
            nested_views: self.pl.scrub_budget.0,
            nested_bytes: self.pl.scrub_budget.1,
        })
    }

    /// `#errorScrubber()`.
    pub(crate) fn pl_error_scrubber(&self) -> R<Scrubber> {
        let entries: Vec<ScrubEntry> = self
            .vault
            .all_secrets()
            .v()?
            .into_iter()
            .map(|s| ScrubEntry {
                secret: s.secret,
                label: s.label,
                replacement: None,
                always: true,
            })
            .collect();
        Scrubber::new(&entries, &self.pl_scrub_opts()?)
    }

    /// `#redactPlaceholders(text)`.
    pub(crate) fn redact_placeholders(text: &str) -> String {
        let mut out = text.to_string();
        for hit in av_core::placeholder::find_all(text) {
            out = out.replace(&hit.text, &format!("av1.<{}_{}>", hit.slug, hit.field));
        }
        out
    }

    /// `#safeMessage(e, scrubber)`.
    pub(crate) fn pl_safe_message(&self, raw: &str, scrubber: Option<&mut Scrubber>) -> String {
        let text = Self::redact_placeholders(raw);
        if self.vault.locked() {
            return text;
        }
        match scrubber {
            Some(s) => s.scrub(&text).text,
            None => match self.pl_error_scrubber() {
                Ok(mut s) => s.scrub(&text).text,
                Err(_) => "internal error".into(),
            },
        }
    }

    fn pl_safe_path(&self, p: &str, scrubber: Option<&mut Scrubber>) -> String {
        self.pl_safe_message(p.split('?').next().unwrap_or(""), scrubber)
    }

    // ------------------------------------------------------------ denials

    fn pl_remember_denial(
        &mut self,
        request_id: &str,
        session_id: Option<String>,
        err: &VaultError,
    ) {
        let now = now_ms();
        while let Some((_, first)) = self.pl.denials.first() {
            if self.pl.denials.len() < MAX_DENIALS && now - first.at < DENIAL_TTL_MS as i64 {
                break;
            }
            self.pl.denials.remove(0);
        }
        self.pl.denials.retain(|(id, _)| id != request_id);
        self.pl.denials.push((
            request_id.to_string(),
            Denial {
                at: now,
                session_id,
                detail: Some(err.detail.clone()),
                hint: Some(err.hint().to_string()),
            },
        ));
    }

    /// `Pipeline.explainDenial(requestId, sessionId)`.
    pub fn pl_explain_denial(&self, request_id: &str, session_id: Option<&str>) -> Option<Value> {
        let (_, d) = self.pl.denials.iter().find(|(id, _)| id == request_id)?;
        if now_ms() - d.at >= DENIAL_TTL_MS as i64 || d.session_id.as_deref() != session_id {
            return None;
        }
        Some(json!({"detail": d.detail, "hint": d.hint}))
    }

    // ---------------------------------------------------------- approvals

    fn pl_sweep_approvals(&mut self) {
        let now = now_ms();
        self.pl.approvals.retain_mut(|(_, a)| {
            let age = now - parse_iso_ms(&a.created_at).unwrap_or(0);
            if a.state == "pending" && age > PENDING_TTL_MS as i64 {
                return false;
            }
            let decided =
                parse_iso_ms(a.decided_at.as_deref().unwrap_or(&a.created_at)).unwrap_or(0);
            if a.result.is_some() && now - decided > REPLAY_TTL_MS as i64 {
                a.result = None;
            }
            !(a.state != "pending" && age > DECIDED_TTL_MS as i64)
        });
    }

    fn approval_by_hash(&mut self, hash: &str) -> Option<&mut Approval> {
        self.pl
            .approvals
            .iter_mut()
            .find(|(h, _)| h == hash)
            .map(|(_, a)| a)
    }

    fn approval_by_id(&mut self, id: &str) -> Option<&mut Approval> {
        self.pl
            .approvals
            .iter_mut()
            .find(|(_, a)| a.id == id)
            .map(|(_, a)| a)
    }

    /// `Pipeline.approvalStatus(approvalId)`.
    pub fn pl_approval_status(&self, id: &str) -> Option<Value> {
        let (_, a) = self.pl.approvals.iter().find(|(_, a)| a.id == id)?;
        let next = match a.state.as_str() {
            "granted" => Value::from("resend the request; it will execute exactly once"),
            "pending" => Value::from("a human has not answered yet"),
            _ => Value::Null,
        };
        Some(json!({
            "approval_id": a.id, "state": a.state, "request_hash": a.request_hash,
            "created_at": a.created_at, "decided_at": a.decided_at, "next": next,
        }))
    }

    /// `Pipeline.decideApproval(approvalId, granted)`.
    pub fn pl_decide_approval(&mut self, id: &str, granted: bool) -> R<Value> {
        let Some(a) = self.approval_by_id(id) else {
            return Err(d(C::NotFound, format!("no approval {id}")));
        };
        if a.state != "pending" {
            return Err(dr(
                C::PolicyDenied,
                format!("already {}", a.state),
                "approval",
            ));
        }
        a.state = if granted { "granted" } else { "denied" }.into();
        a.decided_at = Some(iso_now());
        let view = a.view();
        self.audit(
            if granted {
                "approval.granted"
            } else {
                "approval.denied"
            },
            json!({"approval_id": id}),
        )?;
        Ok(view)
    }

    /// `Pipeline.pendingApprovals()`.
    pub fn pl_pending_approvals(&self) -> Vec<Value> {
        self.pl
            .approvals
            .iter()
            .filter(|(_, a)| a.state == "pending")
            .map(|(_, a)| a.view())
            .collect()
    }

    /// Whether an approval with this id is held.
    pub fn pl_has_approval(&self, id: &str) -> bool {
        self.pl.approvals.iter().any(|(_, a)| a.id == id)
    }

    /// `Pipeline.denyApprovals(filter, reason)`.
    pub fn pl_deny_approvals(&mut self, filter: &ApprovalFilter, reason: &str) -> R<usize> {
        if self.vault.locked() || self.vault.audit().is_none() {
            return Err(d(C::Locked, "unlock the vault before denying approvals"));
        }
        let mut count = 0;
        let ids: Vec<(String, String)> = self
            .pl
            .approvals
            .iter()
            .map(|(_, a)| (a.id.clone(), a.grant_id.clone()))
            .collect();
        for (id, grant_id) in ids {
            let Some(a) = self.approval_by_id(&id) else {
                continue;
            };
            if a.state != "pending" && !(a.state == "granted" && a.result.is_none()) {
                continue;
            }
            if !filter.all {
                let grant = self.vault.grant(&grant_id).v()?;
                if let Some(sid) = &filter.session_id {
                    if grant.as_ref().map(|g| &g.session_id) != Some(sid) {
                        continue;
                    }
                }
                if let Some(cid) = &filter.credential_id {
                    if grant.as_ref().map(|g| &g.credential_id) != Some(cid) {
                        continue;
                    }
                }
                if let Some(ids) = &filter.grant_ids {
                    if !ids.contains(&grant_id) {
                        continue;
                    }
                }
            }
            self.audit(
                "approval.denied",
                json!({"approval_id": id, "reason": reason}),
            )?;
            if let Some(a) = self.approval_by_id(&id) {
                a.state = "denied".into();
                a.decided_at = Some(iso_now());
                a.denied_reason = Some(reason.to_string());
            }
            count += 1;
        }
        Ok(count)
    }

    /// `Pipeline.panic({ reason, lock })`. The daemon's session requests are
    /// denied here too (the JS `onPanic` hook).
    pub fn pl_panic(&mut self, reason: Option<String>, lock: bool) -> R<Value> {
        if self.vault.locked() {
            return Err(d(
                C::Locked,
                "the vault is already locked, so nothing can be revoked",
            ));
        }
        let denied_approvals = self.pl_deny_approvals(
            &ApprovalFilter {
                all: true,
                ..Default::default()
            },
            "panic",
        )?;
        let mut revoked = 0u64;
        for s in self.vault.sessions().v()? {
            if s.state != SessionState::Active {
                continue;
            }
            self.vault.revoke_session(&s.id, "panic").v()?;
            self.tw_reset(&s.id);
            revoked += 1;
        }
        let session_requests = match self.dm_deny_pending_session_requests("panic") {
            Ok(n) => Value::from(n as u64),
            Err(_) => {
                self.audit(
                    "tripwire.panic_partial",
                    json!({"step": "session_requests"}),
                )?;
                Value::Null
            }
        };
        let reason_text = match &reason {
            Some(r) => {
                let safe = self.pl_safe_message(r, None);
                Value::from(self.vault.untrusted_text(&safe, 200).v()?)
            }
            None => Value::Null,
        };
        self.audit(
            "panic.triggered",
            json!({"revoked_sessions": revoked, "denied_approvals": denied_approvals, "denied_session_requests": session_requests, "locked": lock, "reason_untrusted": reason_text}),
        )?;
        if lock {
            self.vault.lock().v()?;
        }
        Ok(
            json!({"revoked_sessions": revoked, "denied_approvals": denied_approvals, "denied_session_requests": session_requests, "locked": lock}),
        )
    }

    /// `#approval(requestHash, ...)`: the state machine.
    #[allow(clippy::too_many_arguments)]
    fn pl_approval(
        &mut self,
        request_hash: &str,
        grant: &GrantRecord,
        decision: &HttpDecision,
        overrides: &[String],
        request_id: &str,
        req: &GatewayRequest,
        subs: &[Sub],
        reason: Option<&str>,
    ) -> R<(String, String)> {
        if let Some(existing) = self.approval_by_hash(request_hash) {
            match existing.state.as_str() {
                "granted" => {
                    existing.state = "consumed".into();
                    return Ok(("granted".into(), existing.id.clone()));
                }
                "consumed" => {
                    if existing.result.is_some() {
                        return Ok(("replay".into(), existing.id.clone()));
                    }
                    if existing.executed_at.is_none() {
                        return Ok(("pending".into(), existing.id.clone()));
                    }
                    let id = existing.id.clone();
                    if let Some(pos) = self
                        .pl
                        .approvals
                        .iter()
                        .position(|(h, _)| h == request_hash)
                    {
                        let (_, a) = self.pl.approvals.remove(pos);
                        self.pl.approvals.push((format!("{request_hash}:{id}"), a));
                    }
                }
                "denied" => return Ok(("denied".into(), existing.id.clone())),
                _ => return Ok(("pending".into(), existing.id.clone())),
            }
        }
        self.pl_sweep_approvals();
        if self.pl.approvals.len() >= MAX_APPROVALS {
            return Err(dr(
                C::PolicyDenied,
                format!(
                    "too many requests are waiting for approval ({})",
                    self.pl.approvals.len()
                ),
                "approval",
            )
            .hinted("Approve or deny the waiting requests, or wait for them to expire."));
        }
        let summary = if overrides.is_empty() {
            format!("{} {}{}", decision.method, decision.host, decision.path)
        } else {
            format!(
                "{} (overridden to {}) {}{}",
                decision.method,
                overrides.join(", "),
                decision.host,
                decision.path
            )
        };
        let reason = match reason.filter(|r| !r.is_empty()) {
            Some(r) => {
                let safe = self.pl_safe_message(r, None);
                Some(self.vault.untrusted_text(&safe, 200).v()?)
            }
            None => None,
        };
        let preview = self.pl_preview(req, subs, decision)?;
        let summary = self.pl_safe_message(&summary, None);
        let approval = Approval {
            id: av_store::ids::id::approval(),
            request_hash: request_hash.to_string(),
            grant_id: grant.id.clone(),
            summary,
            reason,
            preview,
            state: "pending".into(),
            created_at: iso_now(),
            decided_at: None,
            denied_reason: None,
            executed_at: None,
            result: None,
        };
        let (id, summary, created) = (
            approval.id.clone(),
            approval.summary.clone(),
            approval.created_at.clone(),
        );
        let reason_v = approval.reason.clone();
        self.pl.approvals.push((request_hash.to_string(), approval));
        self.audit(
            "approval.requested",
            json!({"request_id": request_id, "approval_id": id, "grant_id": grant.id, "summary": summary, "agent_reason_untrusted": reason_v}),
        )?;
        self.notify_pending(
            json!({"kind": "request", "id": id, "headline": summary, "created_at": created}),
        );
        Ok(("pending".into(), id))
    }

    fn pl_preview(&self, req: &GatewayRequest, subs: &[Sub], decision: &HttpDecision) -> R<Value> {
        let mut scrubber = self.pl_error_scrubber()?;
        let mut psubs = Vec::new();
        for s in subs {
            let slug = self
                .vault
                .credential(&s.row.credential_id)
                .v()?
                .map(|c| c.slug)
                .unwrap_or_default();
            psubs.push(PreviewSub {
                text: s.occ.text.clone(),
                label: format!("{slug}.{}", s.row.field),
                location: sub::describe_location(&s.occ.location),
                part: preview_part(s.occ.location.region),
            });
        }
        let mut scrub = |text: &str| {
            let r = scrubber.scrub(text);
            if r.unscannable {
                "[withheld: unscannable]".to_string()
            } else {
                r.text
            }
        };
        Ok(approval_preview(
            &PreviewRequest {
                query: &req.query,
                headers: &req.headers,
                body: req.body.as_deref(),
            },
            &PreviewDecision {
                method: &decision.method,
                host: &decision.host,
                path: &decision.path,
            },
            &psubs,
            &mut scrub,
        ))
    }

    /// Tell the notifier something is waiting.
    pub(crate) fn notify_pending(&mut self, event: Value) {
        if let Some(n) = self.notifier.clone() {
            n.pending(self, &event);
        }
    }
}

/// `filter` of `denyApprovals`.
#[derive(Debug, Clone, Default)]
pub struct ApprovalFilter {
    /// Every held approval.
    pub all: bool,
    /// Only this session's.
    pub session_id: Option<String>,
    /// Only this credential's.
    pub credential_id: Option<String>,
    /// Only these grants'.
    pub grant_ids: Option<Vec<String>>,
}

type R<T> = Result<T, VaultError>;

struct Sub {
    occ: Occurrence,
    row: PlaceholderRow,
    site: av_core::sites::Site,
}

fn malformed(loc: &sub::Location) -> VaultError {
    dr(
        C::PhMalformed,
        format!(
            "that placeholder was not minted by this vault ({})",
            sub::describe_location(loc)
        ),
        "checksum",
    )
    .hinted("Ask for a placeholder with vault_get_placeholder, or agent-vault ph next.")
}

fn unknown_placeholder(loc: &sub::Location) -> VaultError {
    dr(
        C::PhReplay,
        format!("unknown placeholder at {}", sub::describe_location(loc)),
        "placeholder_unknown",
    )
    .hinted("This placeholder was never issued by this vault, or it was garbage-collected.")
}

/// JS `String.prototype.trim`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    })
}

fn conn_str(cred: &CredentialRecord, key: &str) -> Option<String> {
    cred.connector
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `host:port` when the part after the last colon is digits.
fn split_port(raw: &str) -> (String, Option<String>) {
    if let Some(colon) = raw.rfind(':') {
        let tail = &raw[colon + 1..];
        if colon > 0 && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return (raw[..colon].to_string(), Some(tail.to_string()));
        }
    }
    (raw.to_string(), None)
}

fn per_ms(per: &Value) -> f64 {
    let p = per.as_str().unwrap_or("");
    policy::PER_MS
        .iter()
        .find(|(k, _)| *k == p)
        .map_or(f64::NAN, |(_, v)| *v as f64)
}

fn window_ms(w: &Value) -> u64 {
    let p = w.as_str().unwrap_or("");
    policy::WINDOW_MS
        .iter()
        .find(|(k, _)| *k == p)
        .map_or(0, |(_, v)| *v)
}

/// `foldHeaders(headers)`.
pub fn fold_headers(headers: &[(String, String)]) -> R<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut first: HashMap<String, (String, String)> = HashMap::new();
    for (name, value) in headers {
        let lower = name.to_lowercase();
        if !SINGLE_VALUED.contains(&lower.as_str()) {
            out.push((name.clone(), value.clone()));
            continue;
        }
        let prior = first.get(&lower);
        let differs = prior.is_some_and(|(pn, pv)| pv != value || pn != name);
        if differs {
            return Err(dr(
                C::PolicyDenied,
                format!("the {lower} header appears more than once, so the upstream could read a different one from the one checked"),
                "header_duplicate",
            )
            .hinted(format!("Send {lower} once.")));
        }
        if prior.is_some() {
            continue;
        }
        first.insert(lower, (name.clone(), value.clone()));
        out.push((name.clone(), value.clone()));
    }
    Ok(out)
}

/// `checkOverrides(effective, view, { host, path })`.
fn check_overrides(effective: &Policy, view: &RequestView<'_>, host: &str, path: &str) -> R<()> {
    for m in &view.overrides.headers {
        if let Some(Checked::Valid(methods)) = &effective.methods {
            if !methods.contains(m) {
                let allowed = if methods.is_empty() {
                    "none".to_string()
                } else {
                    methods.join(", ")
                };
                return Err(dr(
                    C::PolicyDenied,
                    format!("method {m}, asked for in a method-override header, is not allowed"),
                    "methods",
                )
                .hinted(format!("Allowed methods: {allowed}.")));
            }
        }
        let mut p = effective.clone();
        p.methods = None;
        policy::evaluate_http(
            &p,
            &policy::HttpTarget {
                method: Some(m),
                host,
                path,
            },
        )?;
    }
    for value in &view.overrides.fields {
        if value.to_uppercase() != view.method {
            return Err(dr(
                C::PolicyDenied,
                format!(
                    "a method-override field (such as _method) asks for a method other than {}",
                    view.method
                ),
                "method_override",
            )
            .hinted(
                "Send the method you mean on the request line, without a method-override field.",
            ));
        }
    }
    Ok(())
}

/// Replace every occurrence of `from` with `to` in a byte string.
fn replace_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

// ----------------------------------------------------------- phase A

impl Core {
    /// Stages 1 to 10 of a request: everything up to the moment the request
    /// is ready to go upstream, under the lock, with nothing spent unless
    /// it passes. Ports `handle`'s try block up to `#proxy`'s upstream call.
    fn pl_phase_a(&mut self, req: GatewayRequest, ctx: &mut Ctx) -> R<(GatewayRequest, Checked1)> {
        if !self.pl.spend_recovered {
            self.pl_recover_spend();
        }
        self.pl_refuse_browsers(&req)?;
        let mut req = req;
        req.headers = fold_headers(&req.headers)?;
        let session = self.pl_authenticate(&req, true)?;
        ctx.session = Some(session.clone());
        let mut st = Stages::default();
        let route = self.pl_route(&req, &session, &mut st, false)?;
        ctx.route = Some(route.clone());
        let out = self.pl_proxy_checks(&req, &session, &route, ctx, false, false, &mut st)?;
        Ok((req, out))
    }

    /// `#proxy` up to the upstream call (and the whole of it for preflight).
    #[allow(clippy::too_many_arguments)]
    fn pl_proxy_checks(
        &mut self,
        req: &GatewayRequest,
        session: &SessionRecord,
        route: &RouteInfo,
        ctx: &mut Ctx,
        preflight: bool,
        assume_placeholder: bool,
        st: &mut Stages,
    ) -> R<Checked1> {
        let cred = &route.cred;
        let grant = &route.grant;
        let effective = effective_of(route, session);
        let preq = req.proxy();

        st.stage("placeholders");
        let located = sub::locate(&preq);
        if let Some(why) = &located.unscannable {
            return Err(dr(C::Unscannable, why.clone(), "body_size"));
        }
        if sub::get_header(&preq, "content-encoding").is_some_and(|v| !v.is_empty()) {
            return Err(dr(
                C::EncodedBody,
                "compressed request bodies cannot be scanned for placeholders",
                "content_encoding",
            )
            .hinted("Send the body with identity encoding."));
        }

        let k_ph = self.vault.k_ph().v()?;
        let mut subs: Vec<Sub> = Vec::new();
        for occ in &located.occurrences {
            if !av_core::placeholder::verify(&k_ph, &occ.parsed) {
                return Err(malformed(&occ.location));
            }
            let Some(row) = self.vault.resolve_placeholder(&occ.parsed).v()? else {
                return Err(unknown_placeholder(&occ.location));
            };
            if row.sid != session.id {
                return Err(dr(
                    C::PhCrossSession,
                    format!(
                        "that placeholder belongs to session {}, not {}",
                        row.sid, session.id
                    ),
                    "placeholder_session",
                ));
            }
            if row.grant_id != grant.id {
                return Err(dr(
                    C::PhWrongConnector,
                    "that placeholder was issued under a different grant",
                    "placeholder_grant",
                )
                .hinted("Use a placeholder issued under the grant that covers this route."));
            }
            let ph_cred = self
                .vault
                .credential(&row.credential_id)
                .v()?
                .ok_or_else(|| internal("Cannot read properties of undefined (reading 'id')"))?;
            if ph_cred.id != cred.id {
                return Err(dr(
                    C::PhWrongConnector,
                    format!(
                        "that placeholder is for {}, but the route is {}",
                        ph_cred.slug, cred.slug
                    ),
                    "placeholder_connector",
                )
                .hinted(format!("Send it to /p/{}/... instead.", ph_cred.slug)));
            }
            let field = ph_cred
                .fields
                .iter()
                .find(|f| f.name == row.field)
                .ok_or_else(|| internal("Cannot read properties of undefined (reading 'sites')"))?;
            let declared = av_core::sites::parse_sites(&field.sites).map_err(|e| internal(e.0))?;
            let Some(site) = declared
                .iter()
                .find(|s| sub::matches_site(&occ.location, s))
                .cloned()
            else {
                let list = declared
                    .iter()
                    .map(|s| {
                        av_core::sites::describe_site(s, av_core::sites::DEFAULT_PLACEHOLDER_HINT)
                    })
                    .collect::<Vec<_>>()
                    .join(" | ");
                return Err(dr(
                    C::BadLocation,
                    format!("a placeholder for {}.{} appeared in {}, which is not a declared injection site", ph_cred.slug, row.field, sub::describe_location(&occ.location)),
                    "injection_site",
                )
                .hinted(format!("This credential is only ever injected at: {list}.")));
            };
            subs.push(Sub {
                occ: occ.clone(),
                row,
                site,
            });
        }

        if subs.is_empty() && !assume_placeholder {
            let sites = cred
                .fields
                .iter()
                .map(|f| {
                    f.sites
                        .iter()
                        .map(|s| {
                            av_core::sites::parse_site(s)
                                .map(|x| {
                                    av_core::sites::describe_site(
                                        &x,
                                        av_core::sites::DEFAULT_PLACEHOLDER_HINT,
                                    )
                                })
                                .unwrap_or_default()
                        })
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .collect::<Vec<_>>()
                .join(" | ");
            return Err(dr(C::SessionRequired, "no placeholder in this request", "no_placeholder")
                .hinted(format!("Put a placeholder at: {sites}. Get one with: agent-vault ph next {}", cred.slug))
                .next(json!({"cli": [format!("agent-vault ph next {}", cred.slug)], "mcp": {"tool": "vault_get_placeholder", "args": {"cred": cred.slug}}})));
        }

        st.stage("policy");
        let view = request_view(&RequestInput {
            method: Some(&req.method),
            query: Some(&req.query),
            headers: &req.headers,
            body: req.body.as_deref(),
            content_type: None,
        });
        let decision = policy::evaluate_http(
            &effective,
            &policy::HttpTarget {
                method: Some(&view.method),
                host: &route.host,
                path: &route.path,
            },
        )?;
        st.stage("payload");
        if view.unsendable {
            return Err(dr(C::PolicyDenied, "the query string contains a character a URL cannot carry as written (#, a tab, a line break, or trailing whitespace)", "query_unsendable")
                .hinted("Percent-encode it, as %23, %09, %0A, %0D or %20."));
        }
        check_overrides(&effective, &view, &route.host, &route.path)?;
        if view.stray_name {
            return Err(dr(C::PolicyDenied, "a parameter name is empty, holds a control character, a non-ASCII character or a space at either end, or starts with punctuation such as [, which servers read differently", "request_ambiguous")
                .hinted("Name each parameter in printable ASCII, starting with a letter, a digit, _, -, . or $, without a space at either end."));
        }
        let payload_sets = policy::describe_effective(&effective).payload;
        av_core::payload::evaluate_payload(
            Some(&payload_sets),
            &av_core::payload::PayloadInput {
                view: &view,
                path: &decision.path,
            },
        )?;
        let overrides = view.overrides.headers.clone();
        st.stage("budget");
        self.pl_budget(grant, &effective)?;
        st.stage("spend");
        let spending = self.pl_check_spend(grant, &effective, route, &view, &decision)?;
        st.stage("rate");
        self.pl_rate(grant, &effective, preflight)?;
        st.stage("quota");
        self.pl_quota(grant, &effective, true)?;

        // The request hash, over what the human is shown.
        let canonical: Vec<(String, String)> = subs
            .iter()
            .map(|s| {
                (
                    s.occ.text.clone(),
                    format!("<av:{}:{}>", s.row.grant_id, s.row.field),
                )
            })
            .collect();
        let stable = |value: &str| -> String {
            let mut out = value.replace('<', "<<");
            for (text, marker) in &canonical {
                out = out.replace(text, marker);
            }
            out
        };
        let stable_bytes = |value: &[u8]| -> Vec<u8> {
            let mut out = replace_bytes(value, b"<", b"<<");
            for (text, marker) in &canonical {
                out = replace_bytes(&out, text.as_bytes(), marker.as_bytes());
            }
            out
        };
        let basic_re = av_core::jsre::compile(r"(?i)^(basic\s+)(\S+)(\s*)$").expect("basic");
        let stable_header = |name: &str, value: &str| -> String {
            if name.eq_ignore_ascii_case("authorization") {
                if let Some(c) = basic_re.captures(value) {
                    let enc = c.get(2).map_or("", |m| m.as_str());
                    let decoded =
                        String::from_utf8_lossy(&crate::util::b64_lenient(enc)).into_owned();
                    if crate::util::b64(decoded.as_bytes()) == enc {
                        return format!(
                            "{}{}{}",
                            &c[1],
                            crate::util::b64(stable(&decoded).as_bytes()),
                            &c[3]
                        );
                    }
                }
            }
            stable(value)
        };
        let body_sha = view
            .body
            .filter(|b| !b.is_empty())
            .map(|b| av_core::canon::sha256(&stable_bytes(b)))
            .unwrap_or_default();
        let creds: Vec<String> = subs
            .iter()
            .map(|s| format!("{}:{}", s.row.grant_id, s.row.field))
            .collect();
        let hash_headers: Vec<(String, String)> = view
            .headers
            .iter()
            .filter(|(n, _)| {
                let l = n.to_lowercase();
                !HOP_BY_HOP.contains(&l.as_str())
                    && !CONSUMED.contains(&l.as_str())
                    && !l.starts_with("av-")
            })
            .map(|(n, v)| (n.clone(), stable_header(n, v)))
            .collect();
        let stable_query = stable(&view.query);
        let request_hash = av_core::canon::request_hash(&av_core::canon::RequestHashInput {
            method: Some(&decision.method),
            host: Some(&decision.host),
            path: Some(&decision.path),
            query: Some(&stable_query),
            body_sha256: Some(&body_sha),
            credentials: &creds,
            headers: &hash_headers,
        });

        st.stage("approval");
        let first_use = grant.counters.requests == 0;
        let needs_human = std::iter::once(decision.method.as_str())
            .chain(overrides.iter().map(String::as_str))
            .any(|m| {
                policy::needs_approval(
                    &effective,
                    &policy::ApprovalQuery {
                        method: Some(m),
                        first_use,
                    },
                )
            });
        if preflight {
            let held = self
                .pl
                .approvals
                .iter()
                .find(|(h, _)| *h == request_hash)
                .map(|(_, a)| a.clone());
            if needs_human && held.as_ref().is_some_and(|a| a.state == "denied") {
                return Err(dr(
                    C::PolicyDenied,
                    "a human denied this request",
                    "approval",
                ));
            }
            let allowed = !needs_human
                || held.as_ref().is_some_and(|a| {
                    a.state == "granted" || (a.state == "consumed" && a.result.is_some())
                });
            return Ok(Checked1::Would(
                if allowed { "allow" } else { "hold" },
                held.map(|a| a.state),
            ));
        }
        let mut approved_request_hash = None;
        if needs_human {
            let reason = sub::get_header(&preq, "av-reason").map(str::to_string);
            let (status, id) = self.pl_approval(
                &request_hash,
                grant,
                &decision,
                &overrides,
                &ctx.request_id,
                req,
                &subs,
                reason.as_deref(),
            )?;
            match status.as_str() {
                "pending" => {
                    let body = json!({
                        "type": "https://agent-vault.dev/errors/AV_APPROVAL_PENDING",
                        "code": "AV_APPROVAL_PENDING",
                        "approval_id": id,
                        "request_hash": request_hash,
                        "detail": "A human must approve this request.",
                        "retry_after": 5,
                        "resend": "resend the byte-identical request; it will execute exactly once",
                        "next": {"cli": [format!("agent-vault approve {id}")], "mcp": {"tool": "vault_approval_status", "args": {"approval_id": id}}},
                    });
                    return Ok(Checked1::Done(Proxied {
                        status: 202,
                        headers: vec![
                            ("content-type".into(), "application/problem+json".into()),
                            ("av-decision".into(), "pending".into()),
                            ("av-approval-id".into(), id),
                            ("retry-after".into(), "5".into()),
                        ],
                        body: js_pretty(&body).into_bytes(),
                        stream: None,
                        host: decision.host.clone(),
                        path_rule: decision.path_rule,
                        route_rule: decision.route_rule,
                        audit_path: None,
                        redactions: 0,
                        spend: None,
                    }));
                }
                "denied" => {
                    return Err(dr(
                        C::PolicyDenied,
                        "a human denied this request",
                        "approval",
                    ))
                }
                "replay" => {
                    self.audit(
                        "approval.replayed",
                        json!({"approval_id": id, "request_id": ctx.request_id}),
                    )?;
                    let stored = self
                        .approval_by_id(&id)
                        .and_then(|a| a.result.clone())
                        .ok_or_else(|| internal("no stored result"))?;
                    let mut p = Proxied::from(stored);
                    set_header(&mut p.headers, "av-replayed", "true".into());
                    return Ok(Checked1::Done(p));
                }
                _ => {
                    approved_request_hash = Some(request_hash.clone());
                    ctx.spent_approval = Some(id);
                }
            }
        }

        ctx.resources.release = Some(self.pl_acquire(grant, &effective)?);
        // Consume, then substitute.
        let mut injected = Vec::new();
        let mut outgoing = ProxyRequest {
            method: view.method.clone(),
            path: decision.path.clone(),
            query: view.query.clone(),
            headers: view.headers.to_vec(),
            body: view.body.map(<[u8]>::to_vec),
        };
        for s in &subs {
            let row = self.vault.consume_placeholder(&s.row.id).v()?;
            ctx.consumed.push(row.id.clone());
            let secret = self
                .vault
                .reveal_field(&s.row.credential_id, &s.row.field)
                .v()?;
            injected.push(ScrubEntry {
                secret: SecretString::from(secret.expose_secret().to_string()),
                label: cred.slug.clone(),
                replacement: None,
                always: true,
            });
            outgoing = sub::apply(&outgoing, &s.occ.location, &s.occ.text, &secret)?;
            self.audit(
                "placeholder.resolved",
                json!({"request_id": ctx.request_id, "placeholder_id": row.id, "session_id": session.id, "credential_slug": cred.slug, "field": s.row.field, "site": s.site.spec, "uses": row.uses, "max_uses": row.max_uses}),
            )?;
        }
        if let Some(mut quota) = self.pl_quota(grant, &effective, true)? {
            quota["count"] = json!(quota["count"].as_i64().unwrap_or(0) + 1);
            let mut rt = self.rt(&grant.id);
            rt.quota_state = Some(quota.clone());
            self.rt_set(&grant.id, rt);
            ctx.resources.quota = Some(quota);
        }
        if let Some(mut sp) = spending {
            let rid = av_store::ids::id::request();
            let mut rt = self.rt(&grant.id);
            let mut state = rt
                .spend
                .take()
                .unwrap_or_else(|| json!({"tokens_used": 0, "usd_micros_used": 0, "reserved": {}}));
            if let Some(m) = state.get_mut("reserved").and_then(Value::as_object_mut) {
                m.insert(rid.clone(), json!({"tokens": sp.reservation.tokens, "usd_micros": sp.reservation.usd_micros, "at": now_ms()}));
            }
            rt.spend = Some(state);
            self.rt_set(&grant.id, rt);
            sp.rid = rid;
            sp.request_id = ctx.request_id.clone();
            ctx.resources.spend = Some(sp);
        }
        let nonces: Vec<String> = subs.iter().map(|s| s.occ.parsed.nonce.clone()).collect();
        if let Some(left) = sub::unsubstituted(&outgoing, &nonces) {
            return Err(dr(C::BadLocation, format!("a placeholder would have reached the upstream unsubstituted, in {}", sub::describe_location(&left.location)), "injection_site")
                .hinted("Put each placeholder once, at a declared injection site, and nowhere a parser could read it twice."));
        }
        let sent = query_params(&outgoing.query, QuerySeparator::AmpersandOrSemicolon);
        if sent.len() != view.params.len()
            || sent
                .iter()
                .zip(&view.params)
                .any(|(a, b)| a.raw_name != b.raw_name)
        {
            return Err(dr(
                C::PolicyDenied,
                "the query would have gone upstream with parameters other than the ones checked",
                "request_ambiguous",
            ));
        }

        // Forward.
        let token_re = av_core::jsre::compile(SESSION_TOKEN).expect("token pattern");
        let mut headers: Vec<(String, Vec<String>)> = Vec::new();
        for (n, v) in &outgoing.headers {
            let lower = n.to_lowercase();
            if HOP_BY_HOP.contains(&lower.as_str())
                || CONSUMED.contains(&lower.as_str())
                || lower.starts_with("av-")
            {
                continue;
            }
            if lower.starts_with("x-forwarded-") || lower == "forwarded" {
                continue;
            }
            if token_re.is_match(v) {
                continue;
            }
            if let Some(e) = headers.iter_mut().find(|(k, _)| k.to_lowercase() == lower) {
                e.1.push(v.clone());
            } else {
                headers.push((n.clone(), vec![v.clone()]));
            }
        }
        let authority = match &route.port {
            Some(p) => format!("{}:{p}", decision.host),
            None => decision.host.clone(),
        };
        put_header(&mut headers, "host", authority.clone());
        put_header(&mut headers, "accept-encoding", "identity".into());
        if let Some(b) = outgoing.body.as_ref().filter(|b| !b.is_empty()) {
            put_header(&mut headers, "content-length", b.len().to_string());
        }
        let wire_path = policy::encode_path_for_wire(&decision.path);
        let scheme = if route.scheme == "http" {
            "http"
        } else {
            "https"
        };
        let url = if outgoing.query.is_empty() {
            format!("{scheme}://{authority}{wire_path}")
        } else {
            format!("{scheme}://{authority}{wire_path}?{}", outgoing.query)
        };
        let credential_headers: HashSet<String> = subs
            .iter()
            .filter_map(|s| match s.occ.location.region {
                Region::Header => s.occ.location.name.clone(),
                Region::Basic => Some("authorization".into()),
                _ => None,
            })
            .collect();
        let last_row = subs.last().map(|s| s.row.id.clone()).unwrap_or_default();
        Ok(Checked1::Send(Box::new(Plan {
            effective,
            decision,
            overrides,
            headers,
            body: outgoing.body.filter(|b| !b.is_empty()),
            url,
            credential_headers,
            injected,
            last_row,
            approved_request_hash,
        })))
    }

    /// The pins for a URL.
    fn pl_pins_for(cred: &CredentialRecord, url: &str) -> Pins {
        let Ok(u) = url::Url::parse(url) else {
            return Pins::None;
        };
        let table = serde_json::to_value(&cred.pins).ok();
        let table = table.filter(|t| t.as_object().is_some_and(|m| !m.is_empty()));
        Pins::from_lookup(av_core::pins::pins_for(
            table.as_ref(),
            &av_core::pins::url_identity(&u),
        ))
    }
}

fn put_header(headers: &mut Vec<(String, Vec<String>)>, name: &str, value: String) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), vec![value]));
}

/// `defaultUpstream`'s folding: a list header as one line.
fn lines(headers: &[(String, Vec<String>)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(n, v)| {
            (
                n.clone(),
                v.join(if n.eq_ignore_ascii_case("cookie") {
                    "; "
                } else {
                    ", "
                }),
            )
        })
        .collect()
}

// -------------------------------------------------- the failure path

impl Core {
    /// `handle()`'s catch block.
    fn pl_fail(&mut self, ctx: &mut Ctx, e: VaultError) -> GatewayResponse {
        let mut scrubber = if self.vault.locked() {
            None
        } else {
            self.pl_error_scrubber().ok()
        };
        let mut err = e;
        let detail = self.pl_safe_message(&err.detail, scrubber.as_mut());
        let hint = self.pl_safe_message(err.hint(), scrubber.as_mut());
        err.detail = detail;
        err.extra.hint = Some(hint);
        if let Some(aid) = &ctx.spent_approval {
            let aid = aid.clone();
            let opened = ctx.upstream_opened;
            let mut returned = false;
            if let Some(a) = self.approval_by_id(&aid) {
                if a.state == "consumed" && a.result.is_none() {
                    if !opened {
                        a.state = "granted".into();
                        returned = true;
                    } else {
                        a.executed_at = Some(iso_now());
                    }
                }
            }
            if returned {
                self.audit_opt("approval.returned", json!({"approval_id": aid, "request_id": ctx.request_id, "reason": "the request never reached the upstream"}));
            }
        }
        err.extra.request_id = Some(ctx.request_id.clone());
        if self.vault.audit().is_some() {
            let mut f = Map::new();
            f.insert("request_id".into(), ctx.request_id.clone().into());
            f.insert("decision".into(), "deny".into());
            f.insert("reason_code".into(), err.code.as_str().into());
            if let Some(r) = rule_of(&err) {
                f.insert("rule".into(), r.into());
            }
            if let Some(ra) = err.extra.retry_after {
                f.insert("retry_after".into(), ra.into());
            }
            if err.code == C::PinMismatch {
                f.insert(
                    "presented_spki".into(),
                    json!(std::mem::take(&mut ctx.presented)),
                );
            }
            f.insert(
                "session_id".into(),
                ctx.session
                    .as_ref()
                    .map_or(Value::Null, |s| s.id.clone().into()),
            );
            f.insert(
                "credential_slug".into(),
                ctx.route
                    .as_ref()
                    .map_or(Value::Null, |r| r.slug.clone().into()),
            );
            f.insert(
                "grant_id".into(),
                ctx.route
                    .as_ref()
                    .map_or(Value::Null, |r| r.grant.id.clone().into()),
            );
            let path = self.pl_safe_path(&ctx.path, scrubber.as_mut());
            f.insert(
                "req".into(),
                json!({"method": audit_method(&ctx.method), "path": path}),
            );
            f.insert("peer".into(), peer_of(ctx.listener.as_ref()));
            self.audit_opt(err.audit_kind(), Value::Object(f));
        }
        self.pl_remember_denial(
            &ctx.request_id,
            ctx.session.as_ref().map(|s| s.id.clone()),
            &err,
        );
        if !ctx.upstream_opened {
            for row in std::mem::take(&mut ctx.consumed) {
                let _ = self.vault.refund_placeholder(&row);
            }
            if let (Some(q), Some(route), Some(session)) =
                (&ctx.resources.quota, &ctx.route, &ctx.session)
            {
                let grant_live = self
                    .vault
                    .grant(&route.grant.id)
                    .ok()
                    .flatten()
                    .is_some_and(|g| g.state == GrantState::Active);
                let session_live = self
                    .vault
                    .session(&session.id)
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.state == SessionState::Active);
                if grant_live && session_live {
                    let mut rt = self.rt(&route.grant.id);
                    if let Some(state) = rt.quota_state.as_mut() {
                        if state["window_ms"] == q["window_ms"] {
                            let w = state["window_ms"].as_i64().unwrap_or(0);
                            if state["start"] == q["start"] {
                                state["count"] =
                                    json!((state["count"].as_i64().unwrap_or(0) - 1).max(0));
                            } else if state["start"].as_i64() == q["start"].as_i64().map(|s| s + w)
                            {
                                state["prev"] =
                                    json!((state["prev"].as_i64().unwrap_or(0) - 1).max(0));
                            }
                        }
                    }
                    self.rt_set(&route.grant.id.clone(), rt);
                }
            }
            if let Some(mut sp) = ctx.resources.spend.take() {
                self.pl_refund_spend(&mut sp);
            }
        } else if let Some(mut sp) = ctx.resources.spend.take() {
            self.pl_settle_spend(Some(&mut sp), None, false);
        }
        let observation = crate::tripwire::Observation {
            session_id: ctx
                .session
                .as_ref()
                .map(|s| s.id.clone())
                .unwrap_or_default(),
            credential_id: ctx.route.as_ref().map(|r| r.cred.id.clone()),
            code: err.code.as_str().to_string(),
            rule: rule_of(&err).map(str::to_string),
            preflight: false,
        };
        let _ = self.tw_observe(&observation);
        let mut headers = vec![
            (
                "content-type".to_string(),
                "application/problem+json".to_string(),
            ),
            ("av-decision".to_string(), "deny".to_string()),
            ("av-request-id".to_string(), ctx.request_id.clone()),
        ];
        if err.http() == 429 {
            headers.push((
                "retry-after".into(),
                err.extra.retry_after.unwrap_or(1).to_string(),
            ));
        }
        GatewayResponse {
            status: err.http(),
            headers,
            body: js_pretty(&err.to_problem()).into_bytes(),
            stream: None,
            request_id: Some(ctx.request_id.clone()),
            error: Some(err),
        }
    }

    /// `request.allowed` for a request that got an answer, and the release
    /// of a non-streaming request's concurrency slot.
    fn pl_allowed(&mut self, ctx: &mut Ctx, p: &Proxied) -> R<()> {
        let session = ctx.session.clone().ok_or_else(|| internal("no session"))?;
        let route = ctx.route.clone().ok_or_else(|| internal("no route"))?;
        let held = p
            .headers
            .iter()
            .any(|(n, v)| n == "av-decision" && v == "pending");
        self.audit(
            "request.allowed",
            json!({
                "request_id": ctx.request_id, "session_id": session.id, "grant_id": route.grant.id,
                "credential_slug": route.slug,
                "req": {
                    "host": p.host, "method": audit_method(&ctx.method), "path_rule": p.path_rule, "route_rule": p.route_rule,
                    "status": p.status, "path": p.audit_path, "bytes_down": if p.stream.is_some() { Value::Null } else { Value::from(p.body.len() as u64) },
                    "streamed": p.stream.is_some(), "redactions": p.redactions,
                },
                "spend": p.spend,
                "decision": if held { "held" } else { "allow" },
                "peer": peer_of(ctx.listener.as_ref()),
                "duration_ms": now_ms() - ctx.started,
            }),
        )
    }
}

fn peer_of(l: Option<&ListenerInfo>) -> Value {
    json!({"kind": l.map_or("loopback", |l| l.kind.as_str()), "listener_id": l.map_or("local", |l| l.id.as_str())})
}

// --------------------------------------------------------- the response

/// What the response stage needs, built under the lock.
struct ScrubKit {
    framing: Scrubber,
    check: Scrubber,
}

impl Core {
    fn pl_scrub_kit(&self, injected: &[ScrubEntry]) -> R<ScrubKit> {
        let mut entries: Vec<ScrubEntry> = injected.to_vec();
        for s in self.vault.all_secrets().v()? {
            if injected
                .iter()
                .any(|i| i.secret.expose_secret() == s.secret.expose_secret())
            {
                continue;
            }
            entries.push(ScrubEntry {
                secret: s.secret,
                label: s.label,
                replacement: None,
                always: true,
            });
        }
        let opts = self.pl_scrub_opts()?;
        Ok(ScrubKit {
            framing: Scrubber::new(&entries, &opts)?,
            check: Scrubber::new(&entries, &opts)?,
        })
    }

    /// `#observeHealth(route, res)`.
    fn pl_observe_health(&mut self, route: &RouteInfo, status: u16, headers: &[(String, String)]) {
        let health = av_core::profiles::extract_health(Some(route.profile), headers);
        let mut patch = Map::new();
        patch.insert("source".into(), "response".into());
        patch.insert("checked_at".into(), iso_now().into());
        if let Some(e) = health.as_ref().and_then(|h| h.observed_expires_at.clone()) {
            patch.insert("observed_expires_at".into(), e.into());
        }
        if status == 401 || status == 403 {
            patch.insert(
                "status".into(),
                if status == 401 {
                    "unauthorized"
                } else {
                    "forbidden"
                }
                .into(),
            );
            patch.insert("http_status".into(), status.into());
        }
        if patch.contains_key("status") || patch.contains_key("observed_expires_at") {
            let _ = self
                .vault
                .record_health(&route.cred.id, &Value::Object(patch));
        }
    }

    /// `#redirects`' checks for one hop: the reason to stop, or the hop.
    #[allow(clippy::too_many_arguments)]
    fn pl_hop_check(
        &mut self,
        route: &RouteInfo,
        plan: &Plan,
        status: u16,
        location: Option<&str>,
        current: &str,
        hops: u64,
        request_id: &str,
    ) -> R<Result<Hop, String>> {
        let effective = &plan.effective;
        let max = match &effective.redirects {
            Some(Checked::Valid(r)) => Some(r.max as i64),
            Some(Checked::Invalid(v)) => v.get("max").and_then(as_integer),
            None => None,
        };
        let method = if status == 307 || status == 308 || plan.decision.method == "HEAD" {
            plan.decision.method.clone()
        } else {
            "GET".into()
        };
        let mut asked = vec![plan.decision.method.clone()];
        asked.extend(plan.overrides.iter().cloned());
        asked.push(method.clone());
        let mut reason: Option<&str> = None;
        if asked.iter().any(|m| {
            !["GET", "HEAD"].contains(&m.as_str())
                || policy::needs_approval(
                    effective,
                    &policy::ApprovalQuery {
                        method: Some(m),
                        first_use: false,
                    },
                )
        }) {
            reason = Some("approval");
        } else if !max.is_some_and(|m| (0..=5).contains(&m) && (hops as i64) < m) {
            reason = Some("max");
        }
        let mut next: Option<url::Url> = None;
        if reason.is_none() {
            next =
                location.and_then(|l| url::Url::parse(current).ok().and_then(|b| b.join(l).ok()));
            if next.is_none() {
                reason = Some("host");
            }
        }
        if reason.is_none() {
            let n = next.as_ref().expect("next");
            if !n.username().is_empty() || n.password().is_some() {
                reason = Some("host");
            }
        }
        if reason.is_none() {
            let n = next.as_ref().expect("next");
            if !["http", "https"].contains(&n.scheme())
                || (route.scheme == "https" && n.scheme() != "https")
            {
                reason = Some("scheme");
            }
        }
        let mut hop: Option<HttpDecision> = None;
        let mut hop_headers: Vec<(String, String)> = Vec::new();
        let mut hop_query = String::new();
        let mut hop_method = method.clone();
        if reason.is_none() {
            let n = next.as_ref().expect("next");
            let host_port = url_host_port(n);
            hop_headers = hop_headers_of(&plan.headers, &plan.credential_headers, &host_port);
            let search = n.query().map(|q| format!("?{q}")).unwrap_or_default();
            let hv = request_view(&RequestInput {
                method: Some(&method),
                query: Some(&search),
                headers: &hop_headers,
                body: None,
                content_type: None,
            });
            hop_query = hv.query.clone();
            hop_method = hv.method.clone();
            match policy::evaluate_http(
                effective,
                &policy::HttpTarget {
                    method: Some(&hv.method),
                    host: &url_hostname(n),
                    path: n.path(),
                },
            ) {
                Ok(h) => hop = Some(h),
                Err(e) => {
                    reason = Some(if rule_of(&e) == Some("hosts") {
                        "host"
                    } else {
                        "path"
                    })
                }
            }
            if reason.is_none() {
                let h = hop.as_ref().expect("hop");
                let cred_host =
                    policy::host_only(&conn_str(&route.cred, "host").unwrap_or_default());
                let cred_port = if route.port.is_some() && cred_host == h.host {
                    route.port.clone().unwrap_or_default()
                } else {
                    String::new()
                };
                let next_port = n.port().map(|p| p.to_string()).unwrap_or_default();
                if next_port != cred_port {
                    reason = Some("host");
                }
            }
            if reason.is_none() {
                let h = hop.as_ref().expect("hop");
                let sets = policy::describe_effective(effective).payload;
                if av_core::payload::evaluate_payload(
                    Some(&sets),
                    &av_core::payload::PayloadInput {
                        view: &hv,
                        path: &h.path,
                    },
                )
                .is_err()
                {
                    reason = Some("path");
                }
                if check_overrides(effective, &hv, &h.host, &h.path).is_err() {
                    reason = Some("path");
                }
                if hv.overrides.headers.iter().any(|m| *m != hv.method) {
                    reason = Some("path");
                }
                if hv.stray_name {
                    reason = Some("path");
                }
            }
        }
        if reason.is_none() && self.pl_budget(&route.grant, effective).is_err() {
            reason = Some("budget");
        }
        if reason.is_none() && self.pl_rate(&route.grant, effective, false).is_err() {
            reason = Some("rate");
        }
        let mut quota = None;
        if reason.is_none() {
            match self.pl_quota(&route.grant, effective, true) {
                Ok(q) => quota = q,
                Err(_) => reason = Some("quota"),
            }
        }
        let hop_pins = if reason.is_none() {
            let n = next.as_ref().expect("next");
            Self::pl_pins_for(&route.cred, n.as_str())
        } else {
            Pins::None
        };
        if reason.is_none()
            && hop_pins.is_some()
            && next.as_ref().is_some_and(|n| n.scheme() != "https")
        {
            reason = Some("pins");
        }
        if reason.is_none() && !self.vault.charge_grant(&route.grant.id, 1).v()? {
            reason = Some("budget");
        }
        if let Some(reason) = reason {
            self.audit("request.redirect_returned", json!({"request_id": request_id, "hop": hops, "status": status, "to_host": hop.as_ref().map(|h| h.host.clone()), "reason": reason}))?;
            return Ok(Err(reason.to_string()));
        }
        if let Some(mut q) = quota {
            q["count"] = json!(q["count"].as_i64().unwrap_or(0) + 1);
            let mut rt = self.rt(&route.grant.id);
            rt.quota_state = Some(q);
            self.rt_set(&route.grant.id.clone(), rt);
        }
        let n = next.expect("next");
        let h = hop.expect("hop");
        let hop_url = format!(
            "{}://{}{}{}",
            n.scheme(),
            url_host_port(&n),
            policy::encode_path_for_wire(&h.path),
            if hop_query.is_empty() {
                String::new()
            } else {
                format!("?{hop_query}")
            }
        );
        Ok(Ok(Hop {
            url: hop_url,
            method: hop_method,
            headers: hop_headers,
            pins: hop_pins,
            host: h.host,
            path: h.path,
        }))
    }
}

/// One redirect hop that may be followed.
struct Hop {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    pins: Pins,
    host: String,
    path: String,
}

fn url_hostname(u: &url::Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

fn url_host_port(u: &url::Url) -> String {
    match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
        None => u.host_str().unwrap_or("").to_string(),
    }
}

/// `#hopHeaders(headers, credentialHeaders, host)`.
fn hop_headers_of(
    headers: &[(String, Vec<String>)],
    cred_headers: &HashSet<String>,
    host: &str,
) -> Vec<(String, String)> {
    let mut out = vec![
        ("host".to_string(), host.to_string()),
        ("accept-encoding".to_string(), "identity".to_string()),
    ];
    for (name, value) in lines(headers) {
        let lower = name.to_lowercase();
        if hop_never(&lower) {
            continue;
        }
        if HOP_FORWARDED.contains(&lower.as_str()) || cred_headers.contains(&lower) {
            if let Some(e) = out.iter_mut().find(|(n, _)| *n == name) {
                e.1 = value;
            } else {
                out.push((name, value));
            }
        }
    }
    out
}

// ----------------------------------------------------------- Pipeline

/// The gateway pipeline. Ports `class Pipeline` in `src/daemon/pipeline.js`.
pub struct Pipeline {
    shared: VaultRef,
    upstream: Arc<dyn Upstream>,
}

impl Pipeline {
    /// Ports `new Pipeline(vault, opts)`.
    pub fn new(shared: VaultRef, opts: PipelineOptions) -> Self {
        shared.run_sync(|core| {
            if let Some(h) = &opts.allowed_hosts {
                core.pl.allowed_hosts = h.clone();
            }
            if let Some(b) = opts.scrub_budget {
                core.pl.scrub_budget = b;
            }
            core.pl_recover_spend();
        });
        Pipeline {
            shared,
            upstream: opts
                .upstream
                .unwrap_or_else(|| Arc::new(crate::connectors::pinning::PinnedUpstream)),
        }
    }

    /// The shared state.
    pub fn shared(&self) -> &VaultRef {
        &self.shared
    }

    /// Handle one proxied request end to end. Ports `Pipeline.handle(req)`.
    pub async fn handle(&self, req: GatewayRequest) -> GatewayResponse {
        let mut ctx = Ctx {
            request_id: av_store::ids::id::request(),
            started: now_ms(),
            method: req.method.clone(),
            path: req.path.clone(),
            listener: req.listener.clone(),
            consumed: Vec::new(),
            upstream_opened: false,
            spent_approval: None,
            session: None,
            route: None,
            resources: Resources::default(),
            presented: Vec::new(),
        };
        let (mut ctx, out) = match self
            .shared
            .run(move |core| {
                let r = core.pl_phase_a(req, &mut ctx);
                (ctx, r)
            })
            .await
        {
            Ok(x) => x,
            Err(e) => return internal_response(e),
        };
        let result = match out {
            Err(e) => Err(e),
            Ok((_, Checked1::Would(..))) => Err(internal("preflight result in handle")),
            Ok((_, Checked1::Done(p))) => Ok(p),
            Ok((req, Checked1::Send(plan))) => self.send_and_scrub(&mut ctx, &req, *plan).await,
        };
        self.finish(ctx, result).await
    }

    async fn finish(&self, ctx: Ctx, result: R<Proxied>) -> GatewayResponse {
        self.shared
            .run(move |core| {
                let mut ctx = ctx;
                let resp = match result {
                    Ok(p) => match core.pl_allowed(&mut ctx, &p) {
                        Ok(()) => {
                            let streaming = p.stream.is_some();
                            if !streaming {
                                if let Some(g) = ctx.resources.release.take() {
                                    core.pl_release(&g);
                                }
                            }
                            GatewayResponse {
                                status: p.status,
                                headers: p.headers,
                                body: p.body,
                                stream: p.stream,
                                request_id: Some(ctx.request_id.clone()),
                                error: None,
                            }
                        }
                        Err(e) => core.pl_fail(&mut ctx, e),
                    },
                    Err(e) => core.pl_fail(&mut ctx, e),
                };
                if resp.stream.is_none() {
                    if let Some(g) = ctx.resources.release.take() {
                        core.pl_release(&g);
                    }
                }
                resp
            })
            .await
            .unwrap_or_else(internal_response)
    }

    /// The upstream call, redirects, and the response.
    async fn send_and_scrub(&self, ctx: &mut Ctx, req: &GatewayRequest, plan: Plan) -> R<Proxied> {
        let route = ctx.route.clone().ok_or_else(|| internal("no route"))?;
        let pins = Core::pl_pins_for(&route.cred, &plan.url);
        let first = UpstreamRequest {
            url: plan.url.clone(),
            method: plan.decision.method.clone(),
            headers: lines(&plan.headers),
            body: plan.body.clone(),
            pins,
        };
        let mut res = match self.upstream.send(first).await {
            Ok(r) => {
                ctx.upstream_opened = true;
                r
            }
            Err(e) => return Err(self.upstream_failure(ctx, e, &plan.decision.host).await),
        };
        let _ = req;
        // Redirects (F6).
        let mut current = plan.url.clone();
        let mut hops = 0u64;
        let mut stopped: Option<String> = None;
        while [301, 302, 303, 307, 308].contains(&res.status) {
            let status = res.status;
            let location = res.header("location").map(str::to_string);
            let (route_c, plan_c, cur, rid) = (
                route.clone(),
                PlanRef::of(&plan),
                current.clone(),
                ctx.request_id.clone(),
            );
            let check = self
                .shared
                .run(move |core| {
                    let plan = plan_c.plan();
                    core.pl_hop_check(
                        &route_c,
                        &plan,
                        status,
                        location.as_deref(),
                        &cur,
                        hops,
                        &rid,
                    )
                })
                .await??;
            match check {
                Err(reason) => {
                    stopped = Some(reason);
                    break;
                }
                Ok(hop) => {
                    let Hop {
                        url: hop_url,
                        method: hop_method,
                        headers: hop_headers,
                        pins: hop_pins,
                        host: to_host,
                        path: to_path,
                    } = hop;
                    let sent = self
                        .upstream
                        .send(UpstreamRequest {
                            url: hop_url.clone(),
                            method: hop_method,
                            headers: hop_headers,
                            body: None,
                            pins: hop_pins,
                        })
                        .await;
                    match sent {
                        Ok(next) => {
                            drop(res);
                            hops += 1;
                            let rid = ctx.request_id.clone();
                            self.shared
                                .run(move |core| {
                                    let path = core.pl_safe_path(&to_path, None);
                                    core.audit("request.redirect_followed", json!({"request_id": rid, "hop": hops, "status": status, "to_host": to_host, "to_path": path}))
                                })
                                .await??;
                            res = next;
                            current = hop_url;
                        }
                        Err(e) if e.code == "AV_PIN_MISMATCH" => {
                            let rid = ctx.request_id.clone();
                            self.shared
                                .run(move |core| core.audit("request.redirect_returned", json!({"request_id": rid, "hop": hops, "status": status, "to_host": to_host, "reason": "pins"})))
                                .await??;
                            stopped = Some("pins".into());
                            break;
                        }
                        Err(_) => {
                            return Err(dr(
                                C::UpstreamUnreachable,
                                format!("could not reach {to_host} while following a redirect"),
                                "upstream",
                            )
                            .refunded(false));
                        }
                    }
                }
            }
        }
        self.respond(ctx, &route, plan, res, stopped).await
    }

    async fn upstream_failure(&self, ctx: &mut Ctx, e: UpstreamError, host: &str) -> VaultError {
        if e.code == "AV_PIN_MISMATCH" {
            let rule = if e.reason.as_deref() == Some("plaintext") {
                "pin_plaintext"
            } else {
                "spki_pin"
            };
            ctx.presented = e.presented.clone();
            return dr(
                C::PinMismatch,
                format!("{host} presented no pinned key"),
                rule,
            )
            .refunded(true);
        }
        if let Some(v) = e.vault.as_ref().filter(|v| v.code == C::PolicyDenied) {
            let mut out = d(C::PolicyDenied, v.detail.clone()).refunded(true);
            out.extra.rule = v.extra.rule.clone();
            return out;
        }
        let pre = PRE_CONNECT_ERRORS.contains(&e.code.as_str());
        if !pre {
            ctx.upstream_opened = true;
        }
        dr(
            C::UpstreamUnreachable,
            format!("could not reach {host}: {}", e.message),
            "upstream",
        )
        .refunded(pre)
    }

    /// The response half of `#proxy`: headers, then stream or buffer.
    async fn respond(
        &self,
        ctx: &mut Ctx,
        route: &RouteInfo,
        plan: Plan,
        res: UpstreamResponse,
        stopped: Option<String>,
    ) -> R<Proxied> {
        let injected = plan.injected.clone();
        let decision_path = plan.decision.path.clone();
        let status = res.status;
        let up_headers = res.headers.clone();
        let content_type = res.header("content-type").unwrap_or("").to_string();
        let encoding = res
            .header("content-encoding")
            .unwrap_or("")
            .to_lowercase()
            .trim()
            .to_string();
        let is_sse =
            content_type.starts_with("text/event-stream") && matches!(res.body, Body::Stream(_));
        let (route_c, rid, approved, sp_kind) = (
            route.clone(),
            ctx.request_id.clone(),
            plan.approved_request_hash.clone(),
            ctx.resources.spend.as_ref().map(|s| s.kind.clone()),
        );
        let enc_c = encoding.clone();
        let stopped_c = stopped.clone();
        let (kit, out_headers, header_redactions, audit_path) = self
            .shared
            .run(move |core| -> R<_> {
                let mut kit = core.pl_scrub_kit(&injected)?;
                let audit_path = Core::redact_placeholders(&kit.check.scrub(decision_path.split('?').next().unwrap_or("")).text);
                let mut out_headers: Vec<(String, String)> = Vec::new();
                if let Some(s) = &stopped_c {
                    out_headers.push(("av-redirect-stopped".into(), s.clone()));
                }
                let mut header_redactions = 0usize;
                for (n, v) in &up_headers {
                    let lower = n.to_lowercase();
                    if lower.starts_with("av-") || lower == "set-cookie" {
                        continue;
                    }
                    if HOP_BY_HOP.contains(&lower.as_str()) || lower == "content-encoding" || lower == "content-length" {
                        continue;
                    }
                    if kit.check.scrub(&lower).redactions > 0 || kit.check.contains_ignoring_case(&lower) {
                        header_redactions += 1;
                        continue;
                    }
                    let s = kit.check.scrub(v);
                    header_redactions += s.redactions;
                    set_header(&mut out_headers, &lower, s.text);
                }
                if is_sse {
                    core.audit("response.streamed", json!({"request_id": rid, "content_type": "text/event-stream", "content_encoding": audit_encoding(&enc_c)}))?;
                    if let Some(h) = &approved {
                        if let Some(a) = core.approval_by_hash(h) {
                            a.executed_at = Some(iso_now());
                        }
                    }
                    core.pl_observe_health(&route_c, status, &up_headers);
                }
                Ok((kit, out_headers, header_redactions, audit_path))
            })
            .await??;

        if is_sse {
            let Body::Stream(rx) = res.body else {
                unreachable!()
            };
            let compressed = !encoding.is_empty() && encoding != "identity";
            let decoder = if compressed {
                match crate::decode::StreamDecoder::new(&encoding, usize::MAX) {
                    Some(dcd) => Some(dcd),
                    None => {
                        return Err(dr(C::Unscannable, format!("upstream sent a {encoding} event stream that could not be decoded, so it could not be scrubbed"), "content_encoding")
                            .hinted("The response was discarded rather than passed through unread."))
                    }
                }
            } else {
                None
            };
            let stream = self.spawn_stream(rx, decoder, kit, compressed, ctx, sp_kind);
            let spend = ctx.resources.spend.as_ref().map(|s| json!({"reserved_tokens": s.reservation.tokens, "charged_tokens": 0, "charged_usd_micros": 0, "settled": "pending"}));
            return Ok(Proxied {
                status,
                headers: out_headers,
                body: Vec::new(),
                stream: Some(stream),
                host: plan.decision.host.clone(),
                path_rule: plan.decision.path_rule,
                route_rule: plan.decision.route_rule,
                audit_path: Some(audit_path),
                redactions: header_redactions,
                spend,
            });
        }

        // Buffered.
        let raw = match res.body {
            Body::Full(b) => b,
            Body::Stream(mut rx) => {
                let mut buf = Vec::new();
                loop {
                    match rx.recv().await {
                        None => break,
                        Some(Ok(c)) => {
                            buf.extend_from_slice(&c);
                            if buf.len() > MAX_RESPONSE_BYTES {
                                return Err(dr(C::Unscannable, format!("the upstream sent more than {} MiB, which is more than can be buffered and scanned", MAX_RESPONSE_BYTES / 1024 / 1024), "response_size")
                                    .hinted("The response was discarded rather than passed through unread."));
                            }
                        }
                        Some(Err(m)) => {
                            return Err(dr(
                                C::UpstreamUnreachable,
                                format!(
                                    "{} failed while sending its response: {m}",
                                    plan.decision.host
                                ),
                                "upstream",
                            )
                            .refunded(false));
                        }
                    }
                }
                buf
            }
        };
        let mut check = kit.check;
        let enc = encoding.clone();
        let scrubbed = tokio::task::spawn_blocking(move || -> R<(av_core::scrub::ScrubResult, Scrubber)> {
            let raw = if !enc.is_empty() && enc != "identity" {
                crate::decode::decompress(&raw, &enc).map_err(|_| {
                    dr(C::Unscannable, format!("upstream sent {enc} that could not be decoded, so it could not be scrubbed"), "content_encoding")
                        .hinted("The response was discarded rather than passed through unread.")
                })?
            } else {
                raw
            };
            let r = check.scrub(&latin1_string(&raw));
            Ok((r, check))
        })
        .await
        .map_err(|_| internal("the response could not be scrubbed"))??;
        let (scrubbed, _check) = scrubbed;
        if scrubbed.unscannable {
            return Err(dr(C::Unscannable, "the response nested encodings deeper than could be decoded within budget, so it could not be fully scrubbed", "scrub_budget")
                .hinted("The response was discarded rather than passed through part-scanned."));
        }
        let body = latin1_bytes(&scrubbed.text);
        let redactions = scrubbed.redactions + header_redactions;
        let route_c = route.clone();
        let (rid, last_row, approved) = (
            ctx.request_id.clone(),
            plan.last_row.clone(),
            plan.approved_request_hash.clone(),
        );
        let mut spend = ctx.resources.spend.take();
        let up_headers2 = out_headers.clone();
        let decision = plan.decision.clone();
        let raw_headers_for_health = up_headers_for_health(&out_headers);
        let (result, spend_back) = self
            .shared
            .run(move |core| -> R<(Proxied, Option<Spending>)> {
                let mut h = up_headers2;
                set_header(&mut h, "av-request-id", rid.clone());
                set_header(&mut h, "av-decision", "allow".into());
                set_header(&mut h, "av-grant", route_c.grant.id.clone());
                if redactions > 0 {
                    set_header(&mut h, "av-redacted", redactions.to_string());
                }
                if let Some(row) = core
                    .vault
                    .list_placeholders(None)
                    .v()?
                    .into_iter()
                    .find(|r| r.id == last_row)
                {
                    set_header(
                        &mut h,
                        "av-placeholder-uses-remaining",
                        row.max_uses.saturating_sub(row.uses).to_string(),
                    );
                    if row.state != av_store::model::PlaceholderState::Active {
                        let succ = core.vault.next_placeholder(&row.id).v()?;
                        if let Some(p) = succ.placeholder {
                            set_header(&mut h, "av-placeholder-next", p);
                        }
                    }
                }
                if redactions > 0 {
                    core.audit(
                        "response.scrubbed",
                        json!({"request_id": rid, "redactions": redactions}),
                    )?;
                }
                let usage = serde_json::from_str::<Value>(&String::from_utf8_lossy(&body))
                    .ok()
                    .and_then(|v| {
                        av_core::model_usage::usage_from_body(&route_c.cred.connector_kind, &v)
                    });
                let spent = core.pl_settle_spend(spend.as_mut(), usage, false);
                core.pl_observe_health(&route_c, status, &raw_headers_for_health);
                let result = StoredResult {
                    status,
                    headers: h,
                    body,
                    host: decision.host.clone(),
                    path_rule: decision.path_rule,
                    route_rule: decision.route_rule,
                    audit_path: Some(audit_path),
                    redactions,
                    spend: spent,
                };
                if let Some(hh) = &approved {
                    if let Some(a) = core.approval_by_hash(hh) {
                        a.result = Some(result.clone());
                        a.executed_at = Some(iso_now());
                    }
                }
                Ok((Proxied::from(result), spend))
            })
            .await??;
        ctx.resources.spend = spend_back;
        Ok(result)
    }

    /// Start the SSE scrubber: an async reader, a blocking scrubber, and the
    /// frames the agent reads. When the stream ends however it ends, the
    /// spend is settled and the concurrency slot released (`closeAware`).
    fn spawn_stream(
        &self,
        mut rx: mpsc::Receiver<Result<Vec<u8>, String>>,
        mut decoder: Option<crate::decode::StreamDecoder>,
        kit: ScrubKit,
        compressed: bool,
        ctx: &mut Ctx,
        sp_kind: Option<String>,
    ) -> FrameStream {
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(16);
        let (in_tx, in_rx) = std::sync::mpsc::sync_channel::<crate::sse::Input>(16);
        tokio::spawn(async move {
            loop {
                let item = match rx.recv().await {
                    None => {
                        let tail = decoder.as_mut().map(|d| d.finish());
                        if let Some(Ok(t)) = &tail {
                            if !t.is_empty()
                                && in_tx.send(crate::sse::Input::Chunk(t.clone())).is_err()
                            {
                                return;
                            }
                        }
                        if matches!(tail, Some(Err(_))) {
                            crate::sse::Input::Failed
                        } else {
                            crate::sse::Input::End
                        }
                    }
                    Some(Err(_)) => crate::sse::Input::Failed,
                    Some(Ok(c)) => match decoder.as_mut() {
                        None => crate::sse::Input::Chunk(c),
                        Some(d) => match d.push(&c) {
                            Ok(out) => crate::sse::Input::Chunk(out),
                            Err(_) => crate::sse::Input::Failed,
                        },
                    },
                };
                let last = !matches!(item, crate::sse::Input::Chunk(_));
                if in_tx.send(item).is_err() || last {
                    return;
                }
            }
        });
        let shared = self.shared.clone();
        let rid = ctx.request_id.clone();
        let release = ctx.resources.release.take();
        let spend = ctx.resources.spend.take();
        let max_bytes = if compressed {
            MAX_DECOMPRESSED
        } else {
            usize::MAX
        };
        tokio::task::spawn_blocking(move || {
            let mut cut = false;
            let mut usage: Option<av_core::model_usage::Usage> = None;
            let mut failed = false;
            let mut partial = String::new();
            let kind = sp_kind.clone();
            let complete = crate::sse::run(
                kit.framing,
                kit.check,
                max_bytes,
                || in_rx.recv().unwrap_or(crate::sse::Input::End),
                |frame| {
                    if let Some(kind) = &kind {
                        if !failed {
                            partial.push_str(
                                &latin1_string(&frame)
                                    .replace("\r\n", "\n")
                                    .replace('\r', "\n"),
                            );
                            while let Some(b) = partial.find("\n\n") {
                                let event = partial[..b].to_string();
                                partial = partial[b + 2..].to_string();
                                // `/^event: error$/m`: any line of the event.
                                if event.split('\n').any(|l| l == "event: error") {
                                    failed = true;
                                }
                                let data: Vec<&str> = event
                                    .split('\n')
                                    .filter(|l| l.starts_with("data:"))
                                    .map(|l| l[5..].strip_prefix(' ').unwrap_or(&l[5..]))
                                    .collect();
                                let data = data.join("\n");
                                usage = av_core::model_usage::usage_from_event(
                                    kind,
                                    av_core::model_usage::SseEventData::Raw(&latin1_bytes(&data)),
                                    usage,
                                );
                            }
                            if partial.len() > MAX_EVENT_BYTES {
                                failed = true;
                                partial.clear();
                            }
                        }
                    }
                    out_tx.blocking_send(frame).is_ok()
                },
                |reason| {
                    cut = true;
                    let (s, r, why) = (shared.clone(), rid.clone(), reason.to_string());
                    s.run_sync(|core| {
                        core.audit_opt(
                            "response.stream_cut",
                            json!({"request_id": r, "reason": why}),
                        )
                    });
                },
            );
            drop(in_rx);
            let use_usage = if complete && !failed && !cut {
                usage
            } else {
                None
            };
            shared.run_sync(|core| {
                if let Some(mut sp) = spend {
                    core.pl_settle_spend(Some(&mut sp), use_usage, true);
                }
                if let Some(g) = release {
                    core.pl_release(&g);
                }
            });
        });
        out_rx
    }

    /// Would this request pass? Runs every check, sends nothing. Ports
    /// `Pipeline.preflight(req, { assumePlaceholder })`.
    pub async fn preflight(&self, req: GatewayRequest, assume_placeholder: bool) -> R<Value> {
        self.shared
            .run(move |core| core.pl_preflight(req, assume_placeholder))
            .await?
    }

    /// Ports `Pipeline.explainDenial(requestId, sessionId)`.
    pub async fn explain_denial(
        &self,
        request_id: String,
        session_id: Option<String>,
    ) -> Option<Value> {
        self.shared
            .run(move |core| core.pl_explain_denial(&request_id, session_id.as_deref()))
            .await
            .ok()
            .flatten()
    }

    /// Ports `Pipeline.approvalStatus(approvalId)`.
    pub async fn approval_status(&self, id: String) -> Option<Value> {
        self.shared
            .run(move |core| core.pl_approval_status(&id))
            .await
            .ok()
            .flatten()
    }

    /// Ports `Pipeline.pendingApprovals()`.
    pub async fn pending_approvals(&self) -> Vec<Value> {
        self.shared
            .run(|core| core.pl_pending_approvals())
            .await
            .unwrap_or_default()
    }

    /// Ports `Pipeline.decideApproval(approvalId, granted)`.
    pub async fn decide_approval(&self, id: String, granted: bool) -> R<Value> {
        self.shared
            .run(move |core| core.pl_decide_approval(&id, granted))
            .await?
    }

    /// Ports `Pipeline.denyApprovals(filter, reason)`.
    pub async fn deny_approvals(&self, filter: ApprovalFilter, reason: String) -> R<usize> {
        self.shared
            .run(move |core| core.pl_deny_approvals(&filter, &reason))
            .await?
    }

    /// Ports `Pipeline.denyAllPending(reason)`.
    pub async fn deny_all_pending(&self, reason: String) -> R<usize> {
        self.deny_approvals(
            ApprovalFilter {
                all: true,
                ..Default::default()
            },
            reason,
        )
        .await
    }

    /// Ports `Pipeline.panic({ reason, lock })`.
    pub async fn panic(&self, reason: Option<String>, lock: bool) -> R<Value> {
        self.shared
            .run(move |core| core.pl_panic(reason, lock))
            .await?
    }

    /// Ports `Pipeline.limitsFor(grantId)`.
    pub async fn limits_for(&self, grant_id: String) -> Option<Value> {
        self.shared
            .run(move |core| core.pl_limits_for(&grant_id))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    }

    /// Ports `Pipeline.spendFor(grantId)`.
    pub async fn spend_for(&self, grant_id: String) -> R<Option<Value>> {
        self.shared
            .run(move |core| core.pl_spend_for(&grant_id))
            .await?
    }
}

/// The plan, cloned for a hop check (the parts it reads).
struct PlanRef {
    effective: Policy,
    decision: HttpDecision,
    overrides: Vec<String>,
    headers: Vec<(String, Vec<String>)>,
    credential_headers: HashSet<String>,
}

impl PlanRef {
    fn of(p: &Plan) -> PlanRef {
        PlanRef {
            effective: p.effective.clone(),
            decision: p.decision.clone(),
            overrides: p.overrides.clone(),
            headers: p.headers.clone(),
            credential_headers: p.credential_headers.clone(),
        }
    }

    fn plan(self) -> Plan {
        Plan {
            effective: self.effective,
            decision: self.decision,
            overrides: self.overrides,
            headers: self.headers,
            body: None,
            url: String::new(),
            credential_headers: self.credential_headers,
            injected: Vec::new(),
            last_row: String::new(),
            approved_request_hash: None,
        }
    }
}

fn up_headers_for_health(h: &[(String, String)]) -> Vec<(String, String)> {
    h.to_vec()
}

fn internal_response(e: VaultError) -> GatewayResponse {
    GatewayResponse {
        status: 500,
        headers: vec![("content-type".into(), "application/problem+json".into())],
        body: crate::util::js_stringify(
            &json!({"code": "AV_INTERNAL", "detail": "the request could not be handled"}),
        )
        .into_bytes(),
        stream: None,
        request_id: None,
        error: Some(e),
    }
}

// ------------------------------------------------------------ preflight

impl Core {
    /// `Pipeline.preflight`.
    fn pl_preflight(&mut self, req: GatewayRequest, assume_placeholder: bool) -> R<Value> {
        if !self.pl.spend_recovered {
            self.pl_recover_spend();
        }
        let request_id = av_store::ids::id::request();
        self.pl_refuse_browsers(&req)?;
        let mut req = req;
        req.headers = fold_headers(&req.headers)?;
        let session = self.pl_authenticate(&req, false)?;
        let now = Instant::now();
        let bucket = match self.pl.preflight_buckets.get(&session.id) {
            Some((c, at)) if now.duration_since(*at).as_millis() < 1000 => (*c, *at),
            _ => (0, now),
        };
        if bucket.0 >= 10 {
            return Err(dr(
                C::QuotaExceeded,
                "preflight rate limit was reached",
                "preflight_rate",
            )
            .retry(1));
        }
        self.pl
            .preflight_buckets
            .insert(session.id.clone(), (bucket.0 + 1, bucket.1));
        let mut m = std::mem::take(&mut self.pl.preflight_buckets);
        self.pl_prune_grants_map(&mut m, true);
        self.pl.preflight_buckets = m;
        if req.body.as_ref().is_some_and(|b| b.len() > 1024 * 1024) {
            return Err(dr(
                C::PolicyDenied,
                "a preflight body may be at most 1 MiB",
                "preflight_size",
            ));
        }
        let mut st = Stages {
            on: true,
            current: "session".into(),
            checks: Vec::new(),
        };
        let mut ctx = Ctx {
            request_id: request_id.clone(),
            started: now_ms(),
            method: req.method.clone(),
            path: req.path.clone(),
            listener: req.listener.clone(),
            consumed: Vec::new(),
            upstream_opened: false,
            spent_approval: None,
            session: Some(session.clone()),
            route: None,
            resources: Resources::default(),
            presented: Vec::new(),
        };
        let mut route_slug: Option<String> = None;
        let mut effective = Value::Null;
        let attempt = self.pl_preflight_run(
            &req,
            &session,
            &mut ctx,
            &mut st,
            assume_placeholder,
            &mut route_slug,
            &mut effective,
        );
        let (would, code, rule, approval_state) = match attempt {
            Ok((w, s)) => (w, None, None, s),
            Err(e) => {
                let mut scrubber = self.pl_error_scrubber().ok();
                let detail = self.pl_safe_message(&e.detail, scrubber.as_mut());
                let mut check = Map::new();
                check.insert("stage".into(), st.current.clone().into());
                check.insert("ok".into(), false.into());
                check.insert("code".into(), e.code.as_str().into());
                check.insert("rule".into(), rule_of(&e).map_or(Value::Null, Value::from));
                check.insert("detail".into(), detail.into());
                let hint = e.hint().to_string();
                if !hint.is_empty() {
                    let h = self.pl_safe_message(&hint, scrubber.as_mut());
                    check.insert("hint".into(), h.into());
                }
                st.checks.push(Value::Object(check));
                (
                    "deny".to_string(),
                    Some(e.code.as_str().to_string()),
                    rule_of(&e).map(str::to_string),
                    None,
                )
            }
        };
        self.audit(
            "request.preflighted",
            json!({"request_id": request_id, "session_id": session.id, "credential_slug": route_slug, "would": would, "code": code, "rule": rule}),
        )?;
        let mut out = Map::new();
        out.insert("would".into(), would.into());
        out.insert("request_id".into(), request_id.into());
        out.insert("checks".into(), Value::Array(st.checks));
        out.insert("effective".into(), effective);
        if let Some(s) = approval_state {
            out.insert("approval_state".into(), s.into());
        }
        out.insert("advisory".into(), "A prediction, not a permission. The real request is checked again and can still be refused.".into());
        Ok(Value::Object(out))
    }
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    fn pl_preflight_run(
        &mut self,
        req: &GatewayRequest,
        session: &SessionRecord,
        ctx: &mut Ctx,
        st: &mut Stages,
        assume_placeholder: bool,
        route_slug: &mut Option<String>,
        effective: &mut Value,
    ) -> R<(String, Option<String>)> {
        st.stage("route");
        let route = self.pl_route(req, session, st, true)?;
        *route_slug = Some(route.slug.clone());
        *effective =
            serde_json::to_value(policy::describe_effective(&effective_of(&route, session)))
                .unwrap_or(Value::Null);
        let r = self.pl_proxy_checks(req, session, &route, ctx, true, assume_placeholder, st)?;
        st.checks.push(json!({"stage": st.current, "ok": true}));
        match r {
            Checked1::Would(w, s) => Ok((w.to_string(), s)),
            _ => Err(internal("preflight could not finish")),
        }
    }
}

/// Approval preview in the skeleton's shape: re-exported for callers.
pub fn approval_preview_for(
    req: &GatewayRequest,
    method: &str,
    host: &str,
    path: &str,
    scrub: &mut dyn FnMut(&str) -> String,
) -> Value {
    approval_preview(
        &PreviewRequest {
            query: &req.query,
            headers: &req.headers,
            body: req.body.as_deref(),
        },
        &PreviewDecision { method, host, path },
        &[],
        scrub,
    )
}

/// `js_f64` re-exported for the spend hints' tests.
pub fn fmt_number(x: f64) -> String {
    js_f64(x)
}

/// Unused-import guard for BTreeMap (kept for the skeleton's signature).
pub type Substitutions = BTreeMap<String, Value>;

#[allow(dead_code)]
fn shared_type_check(_: &Shared) {}
